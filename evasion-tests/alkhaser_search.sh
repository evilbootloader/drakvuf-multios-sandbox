#!/usr/bin/env bash
# Runs al-khaser (build/al-khaser_x64.exe, see build_al_khaser.sh) in the Windows sandbox under
# DRAKVUF for every variant of a variants file, the way rdtsc_search.sh runs the Linux detector,
# and records which of its checks detect the sandbox. README.md has the setup.
#
# First it checks that dom0's checkout of the drakvuf submodule is this one's and builds DRAKVUF
# and libvmi there (search_common.sh, prepare_drakvuf): the benchmarks run that build.
# Per variant:
#   1. Build and install the variant's Xen and boot it once, as rdtsc_search.sh does
#      (search_common.sh). A variant whose Xen dom0 already runs goes straight to the tests.
#   2. A test is one run of dev-syscalls and one of dev-all, at the same time on two Windows VMs
#      (WINDOWS_VM2), swapping VMs every test. The first test of a Xen boot presses xl debug-keys d
#      first (once per boot). al-khaser starts from explorer.exe with ALKHASER_ARGS and has
#      DRAKVUF_TIMEOUT seconds to finish.
#   3. al-khaser gives each check a code (category * 1000 + position, e.g. 5012 is VBOX's 12th)
#      and runs it on a thread of its own: a check that does not return within --check-timeout
#      (120 s) is blocked, and the run goes on. It marks every check's start, detection and
#      block as they happen with an event "al-khaser <code> <start|detected|blocked> <check>",
#      and every detection (block) with a thread exiting with the code (100000 + code); its
#      exit code is the first detection. The syscall log of a run has all of them
#      (NtCreateEvent, NtTerminateThread, NtTerminateProcess). A configuration run is clean
#      (finished, nothing detected), detected (some check detected the sandbox or blocked),
#      unfinished (al-khaser did not exit in time: the last check it started is where it
#      hangs), crashed (it exited with something that is not a code) or none (no log,
#      DRAKVUF failed, not injected, benchmark hung).
#   4. A variant passes when every configuration run of TESTS tests is clean. Otherwise the
#      ranking (alkhaser_rank.py) orders variants by the checks that detected the sandbox in any
#      run, the union, and names each check.
#
# Usage: ./alkhaser_search.sh   (run it in tmux on another machine: a variant with a new Xen
# reboots dom0 twice)
#   TESTS=3 ONLY="baseline" ./alkhaser_search.sh
# Results: <RESULTS_BASE>/alkhaser-search/<timestamp>/ (results.csv per configuration run,
# tests.csv, variants.csv, codes.tsv with the name of every check al-khaser started, ranking.txt,
# one directory per variant). The full DRAKVUF logs stay gzipped on dom0 under REMOTE_OUT. When
# the search ends, however it ends, dom0 is put back as make xen left it: sources, package, Xen
# as the GRUB default (search_common.sh, search_end).
set -Eeuo pipefail
IFS=$'\n\t'
export LC_ALL=C

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# The host settings, see site.conf.example
SITE_CONF=${SITE_CONF:-$SCRIPT_DIR/site.conf}
# shellcheck source=/dev/null
[[ ! -e "$SITE_CONF" ]] || source "$SITE_CONF"
source "$SCRIPT_DIR/search_common.sh"

TESTS=${TESTS:-3}
# Consecutive no-result or build-failed variants before giving up: then the sandbox or the
# build is broken, not the variant
NO_RESULT_VARIANTS=${NO_RESULT_VARIANTS:-3}
VARIANTS=${VARIANTS:-$SCRIPT_DIR/variants/alkhaser.txt}
START_AT=${START_AT-}
ONLY=${ONLY-}
STAMP=$(date +%Y%m%d-%H%M%S)
RESULTS=${RESULTS:-$RESULTS_BASE/alkhaser-search/$STAMP}
# dom0: benchmark output, tens of GB per run: put REMOTE_OUT_BASE on a disk with room
REMOTE_OUT=${REMOTE_OUT:-$REMOTE_OUT_BASE/alkhaser-search/$STAMP}
# al-khaser: the local build, its copy on dom0, where it goes in the guest and its arguments.
# The timing checks sleep --sleep seconds each (9 of them), accelerated_sleep 60 s.
ALKHASER=${ALKHASER:-$SCRIPT_DIR/build/al-khaser_x64.exe}
REMOTE_ALKHASER=${REMOTE_ALKHASER:-$REMOTE_STATE/al-khaser_x64.exe}
ALKHASER_ARGS=${ALKHASER_ARGS:---sleep 1}
# A run takes a few minutes, plus up to --check-timeout per blocked check. Measured on the
# i9-13900KF dom0 (run 20261102-003810): al-khaser finished at 423-433 s in dev-syscalls and
# 583-676 s in dev-all (3 blocked checks)
DRAKVUF_TIMEOUT=${DRAKVUF_TIMEOUT:-1000}
# 0 runs without hidsim, so that you can use the VMs in the VNC viewers
HIDSIM=${HIDSIM:-0}
# Plugins left out of every run: memdump's and fileextractor's dumps filled dom0's disk
DISABLE_PLUGINS=${DISABLE_PLUGINS-memdump fileextractor}
# Environment of the benchmarks; prepare_drakvuf adds DRAKVUF and BENCH_EXTRA_ENV
BENCH_ENV="GUEST=windows DRAKVUF_TIMEOUT=$DRAKVUF_TIMEOUT HIDSIM=$HIDSIM WORKLOAD=$REMOTE_ALKHASER"
BENCH_ENV+=" DISABLE_PLUGINS='$DISABLE_PLUGINS'"
BENCH_ENV+=" WORKLOAD_DST='C:\\Users\\Public\\al-khaser_x64.exe' WORKLOAD_CMD_ARGS='$ALKHASER_ARGS'"
CONFIG_LIST=(dev-syscalls dev-all)
# The analysis VMs, each its CFG and CLONE_NAME (README.md, "Test VMs"). With a second VM both
# configurations run at the same time, one per VM; empty runs them one after the other on the
# first. A VM's vCPUs must match the Windows save, or xl restore refuses it ("Unable to restore
# HVM context").
VM1_ENV=${VM1_ENV-${WINDOWS_VM1-}}
VM2_ENV=${VM2_ENV-${WINDOWS_VM2-}}
# The VNC viewers are open for input when hidsim does not run
VNC_VIEW_ONLY=${VNC_VIEW_ONLY:-$HIDSIM}
# Time limits of a test in seconds, see search_common.sh: a test takes DRAKVUF_TIMEOUT plus the
# restore and teardown of the VMs, a few minutes.
BENCH_LIMIT=${BENCH_LIMIT:-$((DRAKVUF_TIMEOUT + 900))}
BENCH_STALL=${BENCH_STALL:-$((DRAKVUF_TIMEOUT + 600))}

# Reads the logs of one configuration. Arguments: configuration, output directories.
# Prints: logs syscalls injected finished exit_code detected blocked last_started idle
# (detected and blocked comma separated, - for none; last_started is the code of the last check
# or category al-khaser marked as started, idle the seconds from al-khaser's last mark to the end
# of the log), then one "<code>\t<check>" line per check named.
read -r -d '' ALKHASER_PARSER <<'EOF' || true
import glob, json, os, re, sys

config = sys.argv[1]
logs = []
for d in sys.argv[2:]:
    logs += sorted(glob.glob(os.path.join(d, '*-%s.log' % config)))
syscalls = injected = 0
finished = False
exit_code = last_started = last_mark = log_end = None
detected, blocked, names = [], [], {}
stamp = re.compile(r'"TimeStamp":"([0-9.]+)"')

def number(value):
    try:
        return int(str(value), 0)
    except ValueError:
        return None

def is_code(n):
    return n is not None and 1000 < n < 17000 and n % 1000 != 0

def add(found, n):
    if n not in found:
        found.append(n)

for path in logs:
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            m = stamp.search(line)
            if m:
                log_end = float(m.group(1))
            if '"Plugin":"syscall"' not in line:
                # {"Plugin": "inject", ..., "Method": "ShellExec", "Status": "Success", ...}
                if '"inject"' in line and 'ShellExec' in line:
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    if r.get('Method') == 'ShellExec' and r.get('Status') == 'Success':
                        injected += 1
                continue
            syscalls += 1
            if 'al-khaser' not in line.lower():
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if not str(r.get('ProcessName', '')).lower().endswith('al-khaser_x64.exe'):
                continue
            method = r.get('Method')
            if method == 'NtTerminateThread':
                n = number(r.get('ExitStatus', '0'))
                if is_code(n):
                    add(detected, n)
                elif n is not None and is_code(n - 100000):
                    add(blocked, n - 100000)
            elif method == 'NtTerminateProcess':
                if not finished:
                    exit_code = number(r.get('ExitStatus', '0'))
                finished = True
            elif method == 'NtCreateEvent':
                # "al-khaser <code> <category|start|detected|blocked> <check>"
                m = re.search(r'al-khaser (\d+) (category|start|detected|blocked) ?(.*)',
                              str(r.get('ObjectAttributes', '')))
                if not m:
                    continue
                code, kind, text = int(m.group(1)), m.group(2), m.group(3).strip()
                last_mark = log_end
                if text:
                    names[code] = text
                if kind in ('category', 'start'):
                    last_started = code
                elif kind == 'detected' and is_code(code):
                    add(detected, code)
                elif kind == 'blocked' and is_code(code):
                    add(blocked, code)
print(len(logs), syscalls, injected, int(finished), '-' if exit_code is None else exit_code,
      ','.join(map(str, detected)) or '-', ','.join(map(str, blocked)) or '-',
      '-' if last_started is None else last_started,
      '-' if last_mark is None or log_end is None else int(log_end - last_mark))
for code, name in sorted(names.items()):
    print('%d\t%s' % (code, name.replace('\t', ' ')))
EOF

# Judges one configuration of a test. Sets VERDICT to clean, detected (some check detected the
# sandbox or did not return in time), unfinished, crashed or none (no result), and REASON.
# Arguments: variant, test, configuration, job log, job exit status, output dirs...
judge_config() {
    local name=$1 test=$2 config=$3 log=$4 job_rc=$5 rc=1 out first logs syscalls injected finished
    local exit_code detected blocked last idle found expected
    shift 5
    # Exit status of DRAKVUF in this configuration's run, as the benchmark reports it
    if grep -q "] $config: status=0," "$log" 2>/dev/null; then
        rc=0
    fi
    out=$(rsh_stdin "python3 - $config $(join_by ' ' "$@")" <<<"$ALKHASER_PARSER") || out="0 0 0 0 - - - - -"
    first=${out%%$'\n'*}
    IFS=' ' read -r logs syscalls injected finished exit_code detected blocked last idle <<<"$first"
    # Names of the codes, kept for every run
    if [[ "$out" == *$'\n'* ]]; then
        printf '%s\n' "${out#*$'\n'}" >>"$RESULTS/codes.tsv"
    fi
    # al-khaser's exit code: the first detection, else 100000 + the first blocked check, else 0
    expected=0
    if [[ "$detected" != - ]]; then
        expected=${detected%%,*}
    elif [[ "$blocked" != - ]]; then
        expected=$((100000 + ${blocked%%,*}))
    fi
    found=
    [[ "$detected" == - ]] || found+="detected by ${detected//,/ }"
    [[ "$blocked" == - ]] || found+="${found:+; }blocked in ${blocked//,/ }"
    VERDICT=none
    if (( job_rc == 124 )); then
        REASON="benchmark hung and was killed"
    elif (( logs == 0 )); then
        REASON="no DRAKVUF log"
    elif (( rc != 0 )); then
        REASON="DRAKVUF failed"
    elif (( injected == 0 )); then
        REASON="al-khaser not injected"
    elif (( ! finished )); then
        VERDICT=unfinished
        # The watchdog ends a check after 120 s: much longer without a mark is a hang outside it
        if [[ "$idle" =~ ^[0-9]+$ ]] && (( idle > 150 )); then
            REASON="al-khaser hung in $last, no progress for its last $idle s${found:+; $found}"
        else
            REASON="al-khaser ran out of time in $last ($DRAKVUF_TIMEOUT s)${found:+; $found}"
        fi
    elif [[ "$exit_code" != "$expected" ]]; then
        # Not the exit code al-khaser returns: it crashed (detections before it still count)
        VERDICT=crashed
        REASON="exit code $(printf '%#x' "$exit_code" 2>/dev/null || echo "$exit_code") after $last${found:+; $found}"
    elif [[ -n "$found" ]]; then
        VERDICT=detected
        REASON=$found
    else
        VERDICT=clean
        REASON="nothing detected"
    fi
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$name" "$test" "$config" "$VERDICT" "$exit_code" \
        "${detected//,/ }" "${blocked//,/ }" "$last" "$idle" "$syscalls" "$rc" "$REASON" "$(join_by ' ' "$@")" \
        >>"$RESULTS/results.csv"
    say "$name test $test $config: $VERDICT ($REASON), syscalls=$syscalls, status=$rc"
}

# Runs one test: both configurations at the same time, one per VM (they swap VMs every test),
# or without VM2_ENV one benchmark_drakvuf.sh with both. The first test of a Xen boot presses
# xl debug-keys d first. Sets VERDICT to the worst verdict of its configurations (none,
# crashed, unfinished, detected, clean) and TEST_DIRS to the output directories on dom0.
run_test() {
    local name=$1 test=$2 vdir=$3 tag out config dir verdicts=() job_rc=0 first second press=
    local -A config_dir=()
    TEST_DIRS=()
    tag=$(printf 't%02d' "$test")
    out=$REMOTE_OUT/$name/$tag
    if ! d_pressed; then
        mark_d_pressed
        press="xl debug-keys d; sleep 1; xl dmesg | grep RDTSC_POC | tail -1"
        say "$name test $test: pressing xl debug-keys d, the first test of this Xen boot"
    fi
    if [[ -n "$VM2_ENV" ]]; then
        first=${CONFIG_LIST[test % 2]}
        second=${CONFIG_LIST[(test + 1) % 2]}
        # Each benchmark's lines are prefixed with its VM; the status lines still end in "] <config>: status="
        remote_job "$name-$tag" "$vdir/$tag.log" "$BENCH_LIMIT" "$BENCH_STALL" "cd $REMOTE_BENCH_DIR && mkdir -p $out
${press}
{ env $BENCH_ENV $VM1_ENV CONFIGS=$first OUT_DIR=$out/vm1 ./benchmark_drakvuf.sh 2>&1; echo \$? > $out/vm1.rc; } | sed -u 's/^/[vm1] /' &
{ env $BENCH_ENV $VM2_ENV CONFIGS=$second OUT_DIR=$out/vm2 ./benchmark_drakvuf.sh 2>&1; echo \$? > $out/vm2.rc; } | sed -u 's/^/[vm2] /' &
wait
exit \$(( \$(cat $out/vm1.rc 2>/dev/null || echo 1) | \$(cat $out/vm2.rc 2>/dev/null || echo 1) ))" \
            || job_rc=$?
        TEST_DIRS=("$out/vm1" "$out/vm2")
        config_dir[$first]=$out/vm1
        config_dir[$second]=$out/vm2
    else
        remote_job "$name-$tag" "$vdir/$tag.log" "$BENCH_LIMIT" "$BENCH_STALL" "cd $REMOTE_BENCH_DIR
${press}
env $BENCH_ENV $VM1_ENV CONFIGS='$(join_by ' ' "${CONFIG_LIST[@]}")' OUT_DIR=$out ./benchmark_drakvuf.sh" \
            || job_rc=$?
        TEST_DIRS=("$out")
    fi
    for config in "${CONFIG_LIST[@]}"; do
        if [[ -n "${config_dir[$config]-}" ]]; then
            judge_config "$name" "$test" "$config" "$vdir/$tag.log" "$job_rc" "${config_dir[$config]}"
        else
            judge_config "$name" "$test" "$config" "$vdir/$tag.log" "$job_rc" "${TEST_DIRS[@]}"
        fi
        verdicts+=("$VERDICT")
    done
    # Keep the small files, gzip the DRAKVUF logs on dom0
    mkdir -p "$vdir/$tag"
    for dir in "${TEST_DIRS[@]}"; do
        mkdir -p "$vdir/$tag/$(basename "$dir")"
        rsh "cd $dir && tar cf - --exclude='*.log' --exclude='*.gz' --exclude=dumps ." \
            | tar xf - -C "$vdir/$tag/$(basename "$dir")" || true
        rsh "gzip -f1 $dir/*.log" || true
    done
    for VERDICT in none crashed unfinished detected clean; do
        [[ " $(join_by ' ' "${verdicts[@]}") " != *" $VERDICT "* ]] || break
    done
}

# Runs all TESTS tests. Sets RESULT to pass (every configuration run clean), detected (some
# detection, every run finished), the worst other verdict (crashed, unfinished) or no-result
# (no test gave a result).
test_variant() {
    local name=$1 vdir=$2 test=0 no_result=0 worst=clean
    while (( test < TESTS )); do
        test=$((test + 1))
        run_test "$name" "$test" "$vdir"
        [[ "$VERDICT" != none ]] || no_result=$((no_result + 1))
        case "$VERDICT:$worst" in
            crashed:* | unfinished:clean | unfinished:detected | detected:clean) worst=$VERDICT ;;
        esac
        printf '%s,%s,%s,%s\n' "$name" "$test" "$VERDICT" "$(join_by ' ' "${TEST_DIRS[@]}")" \
            >>"$RESULTS/tests.csv"
        say "$name: test $test $VERDICT"
    done
    if (( no_result >= test )); then
        RESULT=no-result
    elif [[ "$worst" == clean ]]; then
        RESULT=pass
    else
        RESULT=$worst
    fi
}

[[ -r "$SSH_KEY" ]] || die "Missing SSH key $SSH_KEY"
[[ -r "$VARIANTS" ]] || die "Missing $VARIANTS"
[[ -r "$ALKHASER" ]] || die "Missing $ALKHASER, build it with build_al_khaser.sh"
[[ "$TESTS" =~ ^[1-9][0-9]*$ ]] || die 'TESTS must be a positive integer.'
[[ "$DRAKVUF_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die 'DRAKVUF_TIMEOUT must be a positive integer.'
[[ "$BUILD_TRIES" =~ ^[1-9][0-9]*$ ]] || die 'BUILD_TRIES must be a positive integer.'
[[ "$VNC" == 0 || "$VNC" == 1 ]] || die 'VNC must be 0 or 1.'
[[ "$HIDSIM" == 0 || "$HIDSIM" == 1 ]] || die 'HIDSIM must be 0 or 1.'
[[ "$ALKHASER_ARGS" != *\'* ]] || die 'ALKHASER_ARGS must not contain single quotes.'
[[ -n "$VM1_ENV" ]] || die 'Set WINDOWS_VM1 (CFG=... CLONE_NAME=...) in site.conf, see README.md "Test VMs".'
rsh true || die "Cannot reach $DOM0"
# The benchmark on dom0 must know WORKLOAD_CMD_ARGS and DISABLE_PLUGINS (REMOTE_BENCH_DIR may hold an older copy)
rsh "grep -q WORKLOAD_CMD_ARGS $REMOTE_BENCH_DIR/benchmark_drakvuf.sh && grep -q 'DISABLE_PLUGINS=' $REMOTE_BENCH_DIR/benchmark_drakvuf.sh" \
    || die "$DOM0:$REMOTE_BENCH_DIR/benchmark_drakvuf.sh is missing or does not know WORKLOAD_CMD_ARGS or DISABLE_PLUGINS: update it from $SCRIPT_DIR/benchmark_drakvuf.sh"
for vm_env in "$VM1_ENV" "$VM2_ENV"; do
    vm_cfg=$(sed -n 's/.*CFG=\([^ ]*\).*/\1/p' <<<"$vm_env")
    [[ -z "$vm_cfg" ]] || rsh "test -r $vm_cfg" || die "Missing the VM config $vm_cfg on dom0"
done
if [[ -n "$VM2_ENV" ]]; then
    (( ${#CONFIG_LIST[@]} == 2 )) || die 'Two VMs run exactly two configurations.'
fi
mkdir -p "$RESULTS"
prepare_xen_sources
prepare_drakvuf
if [[ "$(md5sum <"$ALKHASER" | cut -c1-32)" != "$(rsh "md5sum < $REMOTE_ALKHASER 2>/dev/null" | cut -c1-32)" ]]; then
    rsh "mkdir -p $(dirname "$REMOTE_ALKHASER")"
    rcp_to "$ALKHASER" "$REMOTE_ALKHASER"
    say "Uploaded $ALKHASER to $REMOTE_ALKHASER"
fi
cp "$ALKHASER" "$RESULTS/"
echo 'variant,test,config,verdict,exit_code,detected,blocked,last_started,idle,syscalls,drakvuf_status,reason,outdirs' \
    >"$RESULTS/results.csv"
echo 'variant,test,verdict,outdirs' >"$RESULTS/tests.csv"
echo 'variant,result,tests,sha' >"$RESULTS/variants.csv"
: >"$RESULTS/codes.tsv"
say "Results in $RESULTS, dom0 output in $REMOTE_OUT"
say "Xen sources: ${LOCAL_XEN:-$DOM0:$REMOTE_XEN as make xen left it}; files a variant uploads: $(join_by ' ' "${MODIFIED[@]}")"
say "al-khaser $(sha256sum <"$ALKHASER" | cut -c1-16) with '$ALKHASER_ARGS', DRAKVUF_TIMEOUT=$DRAKVUF_TIMEOUT, HIDSIM=$HIDSIM, disabled plugins: ${DISABLE_PLUGINS:-none}"
search_begin
start_vnc "5900${VM2_ENV:+ 5901}" "$VNC_VIEW_ONLY"

mapfile -t VARIANT_LINES < <(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$VARIANTS")
if [[ -n "$START_AT" ]]; then
    printf '%s\n' "${VARIANT_LINES[@]}" | grep -q "^[[:space:]]*$START_AT\([[:space:]]\|$\)" \
        || die "No variant $START_AT in $VARIANTS"
fi
started=0
[[ -n "$START_AT" ]] || started=1
no_result_streak=0
winners=()
# Gives up after NO_RESULT_VARIANTS no-result or build-failed variants in a row
count_no_result() {
    if [[ "$1" == no-result || "$1" == build-failed ]]; then
        no_result_streak=$((no_result_streak + 1))
        if (( no_result_streak >= NO_RESULT_VARIANTS )); then
            die "$no_result_streak variants in a row gave no result or did not build; check the sandbox and the build"
        fi
    else
        no_result_streak=0
    fi
}
for line in "${VARIANT_LINES[@]}"; do
    IFS=$' \t' read -r -a fields <<<"$line"
    name=${fields[0]}
    if [[ "$name" == "$START_AT" ]]; then
        started=1
    fi
    (( started )) || continue
    [[ -z "$ONLY" || " $ONLY " == *" $name "* ]] || continue

    vdir=$RESULTS/$name
    apply_variant "$vdir" "${fields[@]:1}"
    sha=$(variant_sha "$vdir")
    say "===== Variant $name ($sha): $(join_by ' ' "${fields[@]:1}")"

    if [[ "$(running_variant "$sha")" == yes ]]; then
        say "$name: dom0 already runs this Xen, going straight to the tests"
    else
        reboot_to native
        upload_variant "$vdir"
        rc=0
        build_variant "$name" "$vdir" "$sha" || rc=$?
        if (( rc != 0 )); then
            echo "$name,build-failed,0,$sha" >>"$RESULTS/variants.csv"
            say "Variant $name: the build failed (status $rc), see $vdir/build*.log"
            count_no_result build-failed
            continue
        fi
        reboot_to xen
        [[ "$(running_variant "$sha")" == yes ]] || die "$name: dom0 does not run the Xen just installed"
    fi
    rsh 'xl info | grep -E "^(xen_version|xen_commandline)"; xl dmesg | grep RDTSC_POC | head -5' \
        >"$vdir/xen-info.txt" 2>&1 || true

    test_variant "$name" "$vdir"
    tests_run=$(grep -c "^$name," "$RESULTS/tests.csv" || true)
    echo "$name,$RESULT,$tests_run,$sha" >>"$RESULTS/variants.csv"
    say "Variant $name: $RESULT after $tests_run tests"
    [[ "$RESULT" != pass ]] || winners+=("$name")
    count_no_result "$RESULT"
done

search_end
python3 "$SCRIPT_DIR/alkhaser_rank.py" "$RESULTS" | tee "$RESULTS/ranking.txt" || true
if (( ${#winners[@]} == 0 )); then
    say "No variant left al-khaser without detections in $TESTS tests, see $RESULTS/ranking.txt"
    exit 1
fi
say "Clean: $(join_by ' ' "${winners[@]}"), see $RESULTS/ranking.txt"
