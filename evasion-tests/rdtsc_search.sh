#!/usr/bin/env bash
# Searches the parameters of Xen's RDTSC compensation (automation/xen-rdtsc-poc.patch,
# docs/architecture/rdtsc-poc.md) on dom0. Tests every variant of a variants file and lists as
# winners those for which the red pill detector (detector.c) returns false (exit_group status 0)
# in TESTS consecutive tests of both dev-syscalls and dev-all. README.md has the setup.
#
# First it checks that dom0's checkout of the drakvuf submodule is this one's and builds DRAKVUF
# and libvmi there (search_common.sh, prepare_drakvuf): the benchmarks run that build.
# Per variant:
#   1. Write the variant's defines into vmx.c/vmcs.h (search_common.sh, prepare_xen_sources).
#   2. Boot dom0 without Xen (XEN_OVERRIDE_GRUB_DEFAULT=0), upload the modified files, build and
#      install Xen (OVMF sed, configure, dist-xen, dist-tools, debball, dpkg -i), boot with Xen
#      again (#XEN_OVERRIDE_GRUB_DEFAULT=0). A build whose log stops growing for BUILD_STALL s
#      (EDK2's build.py deadlocks now and then) is killed and run again, up to BUILD_TRIES times.
#      A variant that does not build is marked build-failed. A variant whose Xen dom0 already
#      runs goes straight to the tests.
#   3. A test is one run of dev-syscalls and one of dev-all, and passes only when both pass. The
#      first test of a Xen boot presses xl debug-keys d first (once per boot; make xen's
#      xen-rdtsc-poc.service normally has). With LINUX_VM2 the two configurations run at the
#      same time on two VMs, swapping VMs every test.
#   4. Every detector exit_group in the syscall log of a run: status 0 = false = correct,
#      anything else = true = detected. Any true fails the variant. The workload runs the
#      detector every 5 s from 5 s on, about 10 times in a 55 s run of a healthy guest. A guest
#      that runs it fewer than MIN_RUNS times although it was injected, has fewer than
#      MIN_SYSCALLS syscall records or hangs the benchmark has been made unstable by the Xen
#      variant (its clock runs slow): the variant is unstable and ends there. A configuration
#      passes with no true, DRAKVUF status 0 and at least MIN_RUNS detector exits. A run without
#      log, with DRAKVUF failed or without the workload injected has no result: the streak of
#      consecutive tests starts again from 0, and NO_RESULT_LIMIT of them make the variant
#      no-result.
#
# Usage: ./rdtsc_search.sh   (run it in tmux on another machine: it reboots dom0 twice per variant)
#   TESTS=10 START_AT=pure ./rdtsc_search.sh       starts at that variant
#   ONLY="baseline pure" ./rdtsc_search.sh         only those variants
# Results: <RESULTS_BASE>/rdtsc-search/<timestamp>/ (results.csv per configuration run, tests.csv
# per test, variants.csv, one directory per variant, WINNERS.txt, ranking.txt from rdtsc_rank.py).
# The full DRAKVUF logs stay gzipped on dom0 under REMOTE_OUT. dom0 ends up running the last
# variant built.
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
# Tests without a result (no log, DRAKVUF failed, workload not injected) a variant may have
# before it is given up as no-result. Each one also restarts the streak of TESTS consecutive tests.
NO_RESULT_LIMIT=${NO_RESULT_LIMIT:-5}
# A run with fewer syscall records hung the guest. One with fewer detector exits slowed the
# guest's clock: the injected sleep 5 lasted much longer. A healthy 55 s run with the detector
# loop has 10 detector exits (from 5 s on, every 5 s) and about 1.2 million syscall records
# (most of them the detector's). Slowed guests ran it 1-3 times, some not at all.
MIN_SYSCALLS=${MIN_SYSCALLS:-50000}
MIN_RUNS=${MIN_RUNS:-8}
# Consecutive no-result or build-failed variants before giving up: then the sandbox or the
# build is broken, not the variant
NO_RESULT_VARIANTS=${NO_RESULT_VARIANTS:-3}
VARIANTS=${VARIANTS:-$SCRIPT_DIR/variants/rdtsc.txt}
START_AT=${START_AT-}
ONLY=${ONLY-}
STAMP=$(date +%Y%m%d-%H%M%S)
RESULTS=${RESULTS:-$RESULTS_BASE/rdtsc-search/$STAMP}
# dom0: benchmark output
REMOTE_OUT=${REMOTE_OUT:-$REMOTE_OUT_BASE/rdtsc-search/$STAMP}
# The detector: its source here, the binary on dom0 and where it goes in the guest. Its name
# must end in /detector, the parser looks for that process. BUILD_DETECTOR=1 uploads the source
# and builds it on dom0 whenever it changed; 0 uses REMOTE_DETECTOR as it is.
DETECTOR_SRC=${DETECTOR_SRC:-$SCRIPT_DIR/detector.c}
REMOTE_DETECTOR=${REMOTE_DETECTOR:-$REMOTE_STATE/detector}
DETECTOR_DST=${DETECTOR_DST:-/tmp/detector}
BUILD_DETECTOR=${BUILD_DETECTOR:-1}
# Seconds DRAKVUF traces each run: the detector runs every 5 s from 5 s on
DRAKVUF_TIMEOUT=${DRAKVUF_TIMEOUT:-55}
# Environment of the benchmarks
# Environment of the benchmarks; prepare_drakvuf adds DRAKVUF and BENCH_EXTRA_ENV
BENCH_ENV="GUEST=linux DRAKVUF_TIMEOUT=$DRAKVUF_TIMEOUT WORKLOAD=$REMOTE_DETECTOR WORKLOAD_DST=$DETECTOR_DST"
CONFIG_LIST=(dev-syscalls dev-all)
# The analysis VMs, each its CFG and CLONE_NAME (README.md, "Test VMs"). With a second VM the
# two configurations run at the same time, one per VM; empty runs them one after the other on
# the first.
VM1_ENV=${VM1_ENV-${LINUX_VM1-}}
VM2_ENV=${VM2_ENV-${LINUX_VM2-}}
# Time limits of a test in seconds, see search_common.sh: a test takes about 2.5 min.
BENCH_LIMIT=${BENCH_LIMIT:-1200}
BENCH_STALL=${BENCH_STALL:-600}

# Counts the syscall records, the detector exits and the workload injections in the logs of one
# configuration. Arguments: configuration, output directories.
# Prints: logs false_n true_n syscalls injected
read -r -d '' DETECTOR_PARSER <<'EOF' || true
import glob, json, os, sys

config = sys.argv[1]
logs = []
for d in sys.argv[2:]:
    logs += sorted(glob.glob(os.path.join(d, '*-%s.log' % config)))
false_n = true_n = syscalls = injected = 0
for path in logs:
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            if '"Plugin":"syscall"' not in line:
                # {"Plugin": "inject", ..., "Method": "ExecProc", "Status": "Success", ...}
                if '"inject"' in line and 'ExecProc' in line:
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    if r.get('Method') == 'ExecProc' and r.get('Status') == 'Success':
                        injected += 1
                continue
            syscalls += 1
            if 'exit_group' not in line or '/detector"' not in line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get('Method') != 'exit_group' or not str(r.get('ProcessName', '')).endswith('/detector'):
                continue
            if int(str(r.get('status', '0')), 0):
                true_n += 1
            else:
                false_n += 1
print(len(logs), false_n, true_n, syscalls, injected)
EOF


# Judges one configuration of a test. Sets VERDICT to pass, fail (detected), unstable (guest hung
# or slowed) or none (no result), and REASON.
# Arguments: variant, test, configuration, job log, job exit status, output dirs...
judge_config() {
    local name=$1 test=$2 config=$3 log=$4 job_rc=$5 rc=1 counts logs false_n true_n syscalls injected
    shift 5
    # Exit status of DRAKVUF in this configuration's run, as the benchmark reports it
    if grep -q "] $config: status=0," "$log" 2>/dev/null; then
        rc=0
    fi
    counts=$(rsh_stdin "python3 - $config $(join_by ' ' "$@")" <<<"$DETECTOR_PARSER") || counts="0 0 0 0 0"
    IFS=' ' read -r logs false_n true_n syscalls injected <<<"$counts"
    VERDICT=none
    if (( true_n > 0 )); then
        VERDICT=fail
        REASON="detector returned true $true_n times"
    elif (( job_rc == 124 )); then
        VERDICT=unstable
        REASON="benchmark hung and was killed"
    elif (( logs == 0 )); then
        REASON="no DRAKVUF log"
    elif (( rc != 0 )); then
        REASON="DRAKVUF failed"
    elif (( injected == 0 )); then
        REASON="workload not injected"
    elif (( syscalls < MIN_SYSCALLS )); then
        VERDICT=unstable
        REASON="guest unresponsive: $syscalls syscall records"
    elif (( false_n < MIN_RUNS )); then
        VERDICT=unstable
        REASON="guest slowed: detector ran $false_n times, at least $MIN_RUNS expected"
    else
        VERDICT=pass
        REASON="detector returned false $false_n times"
    fi
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$name" "$test" "$config" \
        "$false_n" "$true_n" "$syscalls" "$rc" "$VERDICT" "$REASON" "$(join_by ' ' "$@")" \
        >>"$RESULTS/results.csv"
    say "$name test $test $config: detector false=$false_n true=$true_n, syscalls=$syscalls, status=$rc -> $VERDICT ($REASON)"
}

# Runs one test: with VM2_ENV both configurations at the same time, one per VM (they swap VMs
# every test), else one benchmark_drakvuf.sh with both. The first test of a Xen boot presses
# xl debug-keys d first. Sets VERDICT to the worst verdict of its configurations (fail,
# unstable, none, pass) and TEST_DIRS to the output directories on dom0.
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
rc=\$(( \$(cat $out/vm1.rc 2>/dev/null || echo 1) | \$(cat $out/vm2.rc 2>/dev/null || echo 1) ))
echo; echo '===== RDTSC_POC after the run'; xl debug-keys t; sleep 0.2; xl dmesg | grep 'RDTSC_POC:' | tail -n 400
exit \$rc" || job_rc=$?
        TEST_DIRS=("$out/vm1" "$out/vm2")
        config_dir[$first]=$out/vm1
        config_dir[$second]=$out/vm2
    else
        remote_job "$name-$tag" "$vdir/$tag.log" "$BENCH_LIMIT" "$BENCH_STALL" "cd $REMOTE_BENCH_DIR
${press}
env $BENCH_ENV $VM1_ENV CONFIGS='$(join_by ' ' "${CONFIG_LIST[@]}")' OUT_DIR=$out ./benchmark_drakvuf.sh; rc=\$?
echo; echo '===== RDTSC_POC after the run'; xl debug-keys t; sleep 0.2; xl dmesg | grep 'RDTSC_POC:' | tail -n 400
exit \$rc" || job_rc=$?
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
    for VERDICT in fail unstable none pass; do
        [[ " $(join_by ' ' "${verdicts[@]}") " != *" $VERDICT "* ]] || break
    done
}

# Runs all TESTS tests: the early stop below is off, so every variant gives the same data.
# A test that does not pass restarts the streak. Sets RESULT to pass (every test passed), the
# worst verdict of any test (fail, then unstable), no-result (no test gave a result) or incomplete
# (the others passed, but some test gave no result), and STREAK to the consecutive tests passed
# at the end.
test_variant() {
    local name=$1 vdir=$2 test=0 no_result=0 worst=pass
    STREAK=0
    while (( test < TESTS )); do
        test=$((test + 1))
        run_test "$name" "$test" "$vdir"
        case "$VERDICT" in
            pass)
                STREAK=$((STREAK + 1))
                say "$name: test $test passed, $STREAK of $TESTS in a row"
                ;;
            none)
                STREAK=0
                no_result=$((no_result + 1))
                say "$name: test $test gave no result, the streak starts again ($no_result of $NO_RESULT_LIMIT)"
                ;;
            *)
                STREAK=0
                ;;
        esac
        case "$VERDICT:$worst" in
            fail:* | unstable:none | unstable:pass | none:pass) worst=$VERDICT ;;
        esac
        printf '%s,%s,%s,%s,%s\n' "$name" "$test" "$VERDICT" "$STREAK" "$(join_by ' ' "${TEST_DIRS[@]}")" \
            >>"$RESULTS/tests.csv"
        #if [[ "$VERDICT" == fail || "$VERDICT" == unstable ]]; then
        #    RESULT=$VERDICT
        #    return
        #fi
        #if (( no_result >= NO_RESULT_LIMIT )); then
        #    RESULT=no-result
        #    return
        #fi
    done
    if (( STREAK >= TESTS )); then
        RESULT=pass
    elif [[ "$worst" != none ]]; then
        RESULT=$worst
    elif (( no_result >= test )); then
        RESULT=no-result
    else
        RESULT=incomplete
    fi
}

[[ -r "$SSH_KEY" ]] || die "Missing SSH key $SSH_KEY"
[[ -r "$VARIANTS" ]] || die "Missing $VARIANTS"
[[ "$TESTS" =~ ^[1-9][0-9]*$ ]] || die 'TESTS must be a positive integer.'
[[ "$NO_RESULT_LIMIT" =~ ^[1-9][0-9]*$ ]] || die 'NO_RESULT_LIMIT must be a positive integer.'
[[ "$MIN_RUNS" =~ ^[1-9][0-9]*$ ]] || die 'MIN_RUNS must be a positive integer: a pass needs the detector to have run.'
[[ "$BUILD_TRIES" =~ ^[1-9][0-9]*$ ]] || die 'BUILD_TRIES must be a positive integer.'
[[ "$DRAKVUF_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die 'DRAKVUF_TIMEOUT must be a positive integer.'
[[ "$VNC" == 0 || "$VNC" == 1 ]] || die 'VNC must be 0 or 1.'
[[ "$BUILD_DETECTOR" == 0 || "$BUILD_DETECTOR" == 1 ]] || die 'BUILD_DETECTOR must be 0 or 1.'
[[ "$REMOTE_DETECTOR" == */detector && "$DETECTOR_DST" == */detector ]] \
    || die 'REMOTE_DETECTOR and DETECTOR_DST must end in /detector: the parser looks for that process name.'
[[ -n "$VM1_ENV" ]] || die 'Set LINUX_VM1 (CFG=... CLONE_NAME=...) in site.conf, see README.md "Test VMs".'
rsh true || die "Cannot reach $DOM0"
mkdir -p "$RESULTS"
prepare_xen_sources
prepare_drakvuf
if (( BUILD_DETECTOR )); then
    [[ -r "$DETECTOR_SRC" ]] || die "Missing $DETECTOR_SRC"
    if [[ "$(md5sum <"$DETECTOR_SRC" | cut -c1-32)" != "$(rsh "md5sum < $REMOTE_DETECTOR.c 2>/dev/null" | cut -c1-32)" ]] \
        || ! rsh "test -x $REMOTE_DETECTOR"; then
        rsh "mkdir -p $(dirname "$REMOTE_DETECTOR")"
        rcp_to "$DETECTOR_SRC" "$REMOTE_DETECTOR.c"
        # No -O: the measured detector's rdtsc() was not inlined (both reads at one RIP)
        rsh "gcc -o $REMOTE_DETECTOR $REMOTE_DETECTOR.c" || die "Could not build $REMOTE_DETECTOR on dom0"
        say "Built $REMOTE_DETECTOR on dom0 from $DETECTOR_SRC"
    fi
fi
rsh "test -x $REMOTE_DETECTOR" || die "Missing $DOM0:$REMOTE_DETECTOR (BUILD_DETECTOR=1 builds it from $DETECTOR_SRC)"
rsh "test -x $REMOTE_BENCH_DIR/benchmark_drakvuf.sh" || die "Missing $DOM0:$REMOTE_BENCH_DIR/benchmark_drakvuf.sh (REMOTE_BENCH_DIR)"
for vm_env in "$VM1_ENV" "$VM2_ENV"; do
    vm_cfg=$(sed -n 's/.*CFG=\([^ ]*\).*/\1/p' <<<"$vm_env")
    [[ -z "$vm_cfg" ]] || rsh "test -r $vm_cfg" || die "Missing the VM config $vm_cfg on dom0"
done
if [[ -n "$VM2_ENV" ]]; then
    (( ${#CONFIG_LIST[@]} == 2 )) || die 'Two VMs run exactly two configurations.'
fi
echo 'variant,test,config,detector_false,detector_true,syscalls,drakvuf_status,verdict,reason,outdirs' \
    >"$RESULTS/results.csv"
echo 'variant,test,verdict,streak,outdirs' >"$RESULTS/tests.csv"
echo 'variant,result,streak,tests,sha,runs_mean,runs_min' >"$RESULTS/variants.csv"
say "Results in $RESULTS, dom0 output in $REMOTE_OUT"
say "Xen sources: ${LOCAL_XEN:-$DOM0:$REMOTE_XEN as make xen left it}; files a variant uploads: $(join_by ' ' "${MODIFIED[@]}")"
start_vnc "5900${VM2_ENV:+ 5901}" 1

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
            reboot_to xen
            die "$no_result_streak variants in a row gave no result or did not build; check the sandbox, the build and the detector"
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
            echo "$name,build-failed,0,0,$sha,," >>"$RESULTS/variants.csv"
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
    # Detector runs per configuration run: 10 in a healthy guest
    runs=$(awk -F, -v n="$name" '$1 == n { r = $4 + $5; s += r; c++; if (c == 1 || r < m) m = r }
                                 END { if (c) printf "%.1f,%d", s / c, m; else printf "," }' "$RESULTS/results.csv")
    echo "$name,$RESULT,$STREAK,$tests_run,$sha,$runs" >>"$RESULTS/variants.csv"
    say "Variant $name: $RESULT, $STREAK consecutive tests passed of $tests_run run, detector runs mean,min $runs"
    if [[ "$RESULT" == pass ]]; then
        winners+=("$name")
        {
            echo "===== Variant: $name ($sha)"
            echo "Defines: $(join_by ' ' "${fields[@]:1}")"
            echo "Passed $TESTS consecutive tests of $(join_by ' ' "${CONFIG_LIST[@]}") ($tests_run tests run)."
            echo
            grep "^$name," "$RESULTS/tests.csv"
            echo
            grep "^$name," "$RESULTS/results.csv"
            echo
            cat "$vdir/variant.diff"
            echo
        } >>"$RESULTS/WINNERS.txt"
    fi
    count_no_result "$RESULT"
done

# The last variant may have left dom0 without Xen
reboot_to xen
python3 "$SCRIPT_DIR/rdtsc_rank.py" "$RESULTS" --expected "$(( DRAKVUF_TIMEOUT / 5 ))" --min-runs "$MIN_RUNS" | tee "$RESULTS/ranking.txt" || true
if (( ${#winners[@]} == 0 )); then
    say "No variant passed $TESTS consecutive tests, see $RESULTS/variants.csv"
    exit 1
fi
say "Winners: $(join_by ' ' "${winners[@]}"), see $RESULTS/WINNERS.txt and $RESULTS/ranking.txt; dom0 runs the last variant built"
