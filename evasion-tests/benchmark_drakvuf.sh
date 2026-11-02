#!/usr/bin/env bash
# DRAKVUF benchmark: compares configurations (baseline build, dev build per sysret mode,
# syscalls only or all plugins) using a fresh Xen RAM restore + LVM thin snapshot for every run.
# IMPORTANT: The saved Xen state must correspond to the origin LV's disk contents.
# Runs on dom0, as root, from this repository's evasion-tests directory: the saved states,
# profiles, hook lists and the explorer.exe PID come from the checkout (SANDBOX), and the DRAKVUF
# it runs (DEV_BIN, DEV_LIBVMI) is the one built in its drakvuf submodule. rdtsc_search.sh and
# alkhaser_search.sh run it; README.md has the setup, "Test VMs" the CFG it needs.
#
# Usage: ./benchmark_drakvuf.sh [ROUNDS]
#   Every round runs each configuration once, the order rotates between rounds.
#   GUEST selects the guest (windows, the default, or linux), CONFIGS the configurations, e.g.
#   GUEST=linux CONFIGS="baseline dev-per-call dev-kernel" DRAKVUF_TIMEOUT=60 ./benchmark_drakvuf.sh 5
#   ABLATE adds a dev-all-x-<plugin> configuration per plugin, all plugins but that one:
#   GUEST=linux ABLATE="libmon filetracer" ./benchmark_drakvuf.sh 3
#   stats-* configurations run the debug build (build-stats, meson --buildtype=debugoptimized),
#   which prints trap statistics when it exits; they are copied to <log>.trap-stats.txt.
#   DEBUG_FILTER runs DRAKVUF with -v and keeps the debug lines matching that extended regular
#   expression in <log>.debug, with the trap statistics, the other standard error lines are dropped. Only debug builds
#   print them, so run it with DEV_BIN=$STATS_BIN, e.g.
#   DEV_BIN=$SANDBOX/drakvuf/build-stats/drakvuf DEBUG_FILTER='FILEEXTRACTOR|USERHOOK' ...
#   DLL_HOOKS_LIST replaces the Windows hook list of apimon and the other user mode hooks.
#   Every run starts the same workload in the guest (workload-<guest>.* next to this script)
#   with DRAKVUF's injector, WORKLOAD= turns that off. On Linux it runs in a loop for the whole
#   run (WORKLOAD_DELAY, WORKLOAD_INTERVAL), e.g. WORKLOAD=/root/evasion-tests/detector.
#   After each run check_sysret_pairing.py (next to this script) checks that the
#   sysret records close the syscall records of their thread, PAIRING_CHECK=0 skips it.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export LC_ALL=C

say() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
# IFS is newline and tab, so "${array[*]}" would join with newlines
join() { local IFS=' '; printf '%s' "$*"; }

# Editable settings. Environment variables override these defaults.
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# This repository's checkout on dom0
SANDBOX=${SANDBOX:-$(cd "$SCRIPT_DIR/.." && pwd)}
[[ -f "$SANDBOX/sandboxd/config.py" ]] \
    || die "$SANDBOX is not a checkout of the sandbox repository: set SANDBOX to dom0's checkout"
# The guest selects the defaults of the guest specific settings, which can still be set one by one.
GUEST=${GUEST:-windows}
case "$GUEST" in
    windows)
        default_origin_name=windows_sandbox
        default_state=$SANDBOX/state/windows_sandbox.bak
        default_cfg=/root/evasion-tests/windows_test1.cfg
        default_profile=$SANDBOX/profiles/windows.json
        default_win32k_profile=$SANDBOX/profiles/win32k.json
        # The workload is started from explorer.exe, the restored guest always has the same PIDs:
        # setup_hooks_windows records it in sandboxd/config.py when it saves the state
        default_workload=workload-windows.cmd
        default_workload_pid=$(sed -n 's/^INJECTION_PID_WINDOWS = \([1-9][0-9]*\)$/\1/p' \
                               "$SANDBOX/sandboxd/config.py" 2>/dev/null)
        default_workload_dst='C:\Users\Public\drakvuf-workload.cmd'
        ;;
    linux)
        default_origin_name=ubuntu_sandbox
        default_state=$SANDBOX/state/ubuntu_sandbox.bak
        default_cfg=/root/evasion-tests/ubuntu_test1.cfg
        default_profile=$SANDBOX/profiles/linux.json
        default_win32k_profile=
        # gnome-shell makes syscalls all the time, so the injection starts right away
        default_workload=workload-linux.sh
        default_workload_pid=1
        default_workload_dst=/tmp/drakvuf-workload.sh
        ;;
    *)
        die "GUEST must be windows or linux, not '$GUEST'."
        ;;
esac
VG=${VG:-vg-root}
ORIGIN_NAME=${ORIGIN_NAME:-$default_origin_name}
# A thin snapshot of the origin, made for each run: the CFG's disk must name it
CLONE_NAME=${CLONE_NAME:-$ORIGIN_NAME-test1}
ORIGIN="/dev/$VG/$ORIGIN_NAME"
CLONE="/dev/$VG/$CLONE_NAME"
STATE=${STATE:-$default_state}
CFG=${CFG:-$default_cfg}
PROFILE=${PROFILE:-$default_profile}
# The DRAKVUF under test: the build make sandboxd configured in this repository's drakvuf
# submodule, and the libvmi built beside it (its .libs, not the copy installed in /usr/local/lib)
DEV_BIN=${DEV_BIN:-$SANDBOX/drakvuf/build/drakvuf}
# Debug build of the same tree, prints the trap statistics: meson setup build-stats --buildtype=debugoptimized
STATS_BIN=${STATS_BIN:-$SANDBOX/drakvuf/build-stats/drakvuf}
# The baseline-* and upstream-* configurations: the build make sandboxd installed, unless set to
# an upstream DRAKVUF build to compare against
BASE_BIN=${BASE_BIN:-/usr/local/bin/drakvuf}
# The libvmi each build runs on. The development libvmi keeps the ABI of upstream's, so the
# baseline runs on it too. BASE_LIBVMI=<dir> runs the baseline on another libvmi instead;
# configure both with the same options to compare them.
DEV_LIBVMI=${DEV_LIBVMI:-$SANDBOX/drakvuf/libvmi/libvmi/.libs}
BASE_LIBVMI=${BASE_LIBVMI:-$DEV_LIBVMI}
# Upstream's libvmi, for the upstream-* configurations: upstream DRAKVUF as upstream ships it
UPSTREAM_LIBVMI=${UPSTREAM_LIBVMI:-/usr/local/lib}
DRAKVUF_TIMEOUT=${DRAKVUF_TIMEOUT:-20}
DESTROY_TIMEOUT=${DESTROY_TIMEOUT:-60}
# Arguments passed to every configuration, space separated
COMMON_ARGS=${COMMON_ARGS:--F}
DEBUG_FILTER=${DEBUG_FILTER-}
# 1 keeps what fileextractor and memdump write to $OUT_DIR/dumps, otherwise it is deleted after each run
KEEP_DUMPS=${KEEP_DUMPS:-0}
# Seconds DRAKVUF waits at the end for plugins with injected calls in flight (fileextractor).
# Without the wait it removes their traps anyway, and the guest crashes when such a call returns.
# 0 turns it off.
STOP_WAIT=${STOP_WAIT:-30}
# Seconds fileextractor keeps extracting once stopping. Below STOP_WAIT, so it ends its injected
# calls before DRAKVUF exits. 0 leaves it out (no limit).
FILEEXTRACTOR_TIMEOUT=${FILEEXTRACTOR_TIMEOUT:-20}
# 1 makes hidsim click and double-click at random (--hid-random-clicks) where it runs, 0 only
# moves the mouse. Left out for a build without the option.
HID_RANDOM_CLICKS=${HID_RANDOM_CLICKS:-1}
# 0 runs no hidsim at all, so that a person can use the VM over VNC: leaves -a hidsim out and
# excludes it (-x hidsim) where all plugins run
HIDSIM=${HIDSIM:-1}
# 1 passes -s, DRAKVUF's "Hide Hypervisor bits and signature in CPUID"; 0 for a guest whose
# config hides them itself (cpuid = 'host,hypervisor=0', sandbox_project guest-identity.md),
# which is the default for such a CFG
if [[ -z "${CPUID_STEALTH-}" ]]; then
    if grep -Eqs "^cpuid *= *['\"][^'\"]*hypervisor=0" "$CFG"; then
        CPUID_STEALTH=0
    else
        CPUID_STEALTH=1
    fi
fi
# Plugins to leave out, space separated, e.g. "memdump fileextractor" (their dumps fill the disk):
# their -a is dropped, and they are excluded (-x) where all plugins run
DISABLE_PLUGINS=${DISABLE_PLUGINS-}
# Empty runs no default configuration, only what ABLATE and ONLY add
CONFIGS=${CONFIGS:-dev-syscalls dev-all}
# Plugins to leave out one at a time, space separated: adds dev-all-x-<plugin> to CONFIGS
ABLATE=${ABLATE-}
# Windows only: win32k profile, without it the GUI syscalls (NtUser*, NtGdi*) are not traced.
# Empty skips them.
WIN32K_PROFILE=${WIN32K_PROFILE-$default_win32k_profile}
# json has the thread IDs the pairing check needs, the default format doesn't
OUTPUT_FORMAT=${OUTPUT_FORMAT:-json}
PAIRING_CHECK=${PAIRING_CHECK:-1}
CHECKER=${CHECKER:-$SCRIPT_DIR/check_sysret_pairing.py}
# Guest workload: copied into the guest with --write-file and started from WORKLOAD_PID.
# Empty runs without a workload.
WORKLOAD=${WORKLOAD-$SCRIPT_DIR/$default_workload}
WORKLOAD_PID=${WORKLOAD_PID:-$default_workload_pid}
WORKLOAD_DST=${WORKLOAD_DST:-$default_workload_dst}
# Windows: arguments of the workload, e.g. WORKLOAD_CMD_ARGS='--sleep 1' for al-khaser
WORKLOAD_CMD_ARGS=${WORKLOAD_CMD_ARGS-}

# Seconds the injection may take, it normally takes well under one. A run whose injection
# times out starts over, up to WORKLOAD_ATTEMPTS times.
WORKLOAD_TIMEOUT=${WORKLOAD_TIMEOUT:-30}
WORKLOAD_ATTEMPTS=${WORKLOAD_ATTEMPTS:-3}
# Linux: the workload runs again and again until the run ends, the first time WORKLOAD_DELAY
# seconds after the injection (the plugins and Xen's RDTSC baseline are up by then), then every
# WORKLOAD_INTERVAL seconds after the previous one ends
WORKLOAD_DELAY=${WORKLOAD_DELAY:-5}
WORKLOAD_INTERVAL=${WORKLOAD_INTERVAL:-5}
ROUNDS=${1:-1}
OUT_DIR=${OUT_DIR:-$HOME/drakvuf-benchmark-$GUEST-$(date +%Y%m%d-%H%M%S)}

# Available configurations: binary, libvmi and the arguments added to COMMON_ARGS.
# Without -a, DRAKVUF starts all plugins.
declare -A CONFIG_BIN=(
    [baseline]="$BASE_BIN"
    [dev-serial]="$DEV_BIN"
    [dev-per-call]="$DEV_BIN"
    [dev-kernel]="$DEV_BIN"
    [baseline-nosysret]="$BASE_BIN"
    [dev-kernel-serial]="$DEV_BIN"
    [dev-parallel-nosysret]="$DEV_BIN"
    [baseline-all]="$BASE_BIN"
    [upstream-all]="$BASE_BIN"
    [dev-syscalls]="$DEV_BIN"
    [dev-all]="$DEV_BIN"
    [stats-syscalls]="$STATS_BIN"
    [stats-all]="$STATS_BIN"
    [stats-all-serial]="$STATS_BIN"
)
declare -A CONFIG_LIB=(
    [baseline]="$BASE_LIBVMI"
    [dev-serial]="$DEV_LIBVMI"
    [dev-per-call]="$DEV_LIBVMI"
    [dev-kernel]="$DEV_LIBVMI"
    [baseline-nosysret]="$BASE_LIBVMI"
    [dev-kernel-serial]="$DEV_LIBVMI"
    [dev-parallel-nosysret]="$DEV_LIBVMI"
    [baseline-all]="$BASE_LIBVMI"
    [upstream-all]="$UPSTREAM_LIBVMI"
    [dev-syscalls]="$DEV_LIBVMI"
    [dev-all]="$DEV_LIBVMI"
    [stats-syscalls]="$DEV_LIBVMI"
    [stats-all]="$DEV_LIBVMI"
    [stats-all-serial]="$DEV_LIBVMI"
)
declare -A CONFIG_ARGS=(
    [baseline]="-a syscalls"
    [dev-serial]="-a syscalls --sysret-mode per-call"
    [dev-per-call]="-a syscalls --parallel-events --sysret-mode per-call"
    [dev-kernel]="-a syscalls --parallel-events --sysret-mode kernel"
    # Isolation: upstream at full guest speed, kernel mode single threaded, parallel without returns
    [baseline-nosysret]="-a syscalls --disable-sysret"
    [dev-kernel-serial]="-a syscalls --sysret-mode kernel"
    [dev-parallel-nosysret]="-a syscalls --parallel-events --disable-sysret"
    # Plugin overhead: the parallel build with syscalls only against all plugins
    [baseline-all]=""
    [upstream-all]=""
    [dev-syscalls]="-a syscalls -a cpuidmon -a hidsim --parallel-events --sysret-mode kernel"
    [dev-all]="--parallel-events --sysret-mode kernel"
    [stats-syscalls]="-a syscalls --parallel-events --sysret-mode kernel"
    [stats-all]="--parallel-events --sysret-mode kernel"
    [stats-all-serial]="--sysret-mode kernel"
)
# An entry can leave out several plugins together, joined with +: apimon+socketmon
IFS=' ' read -r -a ablated <<<"$ABLATE"
for group in "${ablated[@]}"; do
    [[ "$group" =~ ^[a-z0-9]+(\+[a-z0-9]+)*$ ]] || die "ABLATE has an invalid plugin name: '$group'"
    CONFIG_BIN[dev-all-x-$group]="$DEV_BIN"
    CONFIG_LIB[dev-all-x-$group]="$DEV_LIBVMI"
    CONFIG_ARGS[dev-all-x-$group]="--parallel-events --sysret-mode kernel -x ${group//+/ -x }"
    CONFIGS+=" dev-all-x-$group"
done
# Plugins to run on their own, groups joined with + like ABLATE: adds dev-only-<n> to CONFIGS,
# the development build with only that group's plugins. For narrowing down a plugin.
IFS=' ' read -r -a only_groups <<<"${ONLY-}"
only_n=0
for group in "${only_groups[@]}"; do
    [[ "$group" =~ ^[a-z0-9]+(\+[a-z0-9]+)*$ ]] || die "ONLY has an invalid plugin name: '$group'"
    only_n=$((only_n + 1))
    CONFIG_BIN[dev-only-$only_n]="$DEV_BIN"
    CONFIG_LIB[dev-only-$only_n]="$DEV_LIBVMI"
    CONFIG_ARGS[dev-only-$only_n]="--parallel-events --sysret-mode kernel -a ${group//+/ -a }"
    CONFIGS+=" dev-only-$only_n"
done

# LVM warns about every inherited descriptor, including the lock file below.
export LVM_SUPPRESS_FD_WARNINGS=1
# CPU time reported by `time`: user and system seconds of DRAKVUF
TIMEFORMAT='%3U %3S'

[[ ${EUID} -eq 0 ]] || die 'Run this as root on the Xen Dom0 host.'
[[ "$ROUNDS" =~ ^[1-9][0-9]*$ ]] || die 'Argument must be the number of rounds (positive integer).'
[[ "$DRAKVUF_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die 'DRAKVUF_TIMEOUT must be a positive integer.'
[[ "$DESTROY_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die 'DESTROY_TIMEOUT must be a positive integer.'
# Leave DRAKVUF time to restore the guest and exit after its own timeout.
WATCHDOG_SECONDS=${WATCHDOG_SECONDS:-$((DRAKVUF_TIMEOUT + 120))}
[[ "$WATCHDOG_SECONDS" =~ ^[1-9][0-9]*$ ]] || die 'WATCHDOG_SECONDS must be a positive integer.'
(( WATCHDOG_SECONDS > DRAKVUF_TIMEOUT + 30 )) \
    || die "WATCHDOG_SECONDS ($WATCHDOG_SECONDS) must exceed DRAKVUF_TIMEOUT + 30."
[[ "$ORIGIN" != "$CLONE" ]] || die 'Origin and clone must differ.'
[[ "$OUTPUT_FORMAT" == json || "$OUTPUT_FORMAT" == default ]] || die 'OUTPUT_FORMAT must be json or default.'
[[ "$PAIRING_CHECK" == 0 || "$PAIRING_CHECK" == 1 ]] || die 'PAIRING_CHECK must be 0 or 1.'
[[ "$HID_RANDOM_CLICKS" == 0 || "$HID_RANDOM_CLICKS" == 1 ]] || die 'HID_RANDOM_CLICKS must be 0 or 1.'
[[ "$HIDSIM" == 0 || "$HIDSIM" == 1 ]] || die 'HIDSIM must be 0 or 1.'
[[ "$CPUID_STEALTH" == 0 || "$CPUID_STEALTH" == 1 ]] || die 'CPUID_STEALTH must be 0 or 1.'
[[ "$DISABLE_PLUGINS" =~ ^[a-z0-9\ ]*$ ]] || die "DISABLE_PLUGINS has an invalid plugin name: '$DISABLE_PLUGINS'"
if (( PAIRING_CHECK )); then
    [[ "$OUTPUT_FORMAT" == json ]] \
        || die 'The pairing check needs OUTPUT_FORMAT=json (the default format has no thread IDs); or set PAIRING_CHECK=0.'
    command -v python3 >/dev/null || die 'The pairing check needs python3; or set PAIRING_CHECK=0.'
    [[ -r "$CHECKER" ]] || die "Missing pairing checker: $CHECKER"
fi
for cmd in xl lvcreate lvchange lvremove lvs flock timeout stdbuf awk grep wc date ldd nm pkill xargs sort; do
    command -v "$cmd" >/dev/null || die "Missing tool: $cmd"
done
[[ -s "$STATE" ]] || die "Missing or empty Xen save file: $STATE"
[[ -f "$CFG" ]] || die "Missing Xen config: $CFG"
# The restored guest writes to the disk the CFG names: it must be the clone, never the origin,
# which the saved state belongs to (a cfg copied from misc/xen-vms names the origin)
grep -Eq "^[[:space:]]*disk[[:space:]]*=.*[\"',:=]${CLONE}[\"',]" "$CFG" \
    || die "$CFG's disk is not the clone $CLONE: restoring onto another LV would write to it (README.md, Test VMs)"
[[ -s "$PROFILE" ]] || die "Missing profile: $PROFILE"
[[ -z "$WIN32K_PROFILE" || "$GUEST" == windows ]] \
    || die "WIN32K_PROFILE only applies to Windows guests, unset it for GUEST=$GUEST."
[[ -z "$WIN32K_PROFILE" || -s "$WIN32K_PROFILE" ]] \
    || die "Missing win32k profile: $WIN32K_PROFILE (WIN32K_PROFILE= skips win32k syscalls)"
lvs "$ORIGIN" >/dev/null 2>&1 || die "Missing origin LV: $ORIGIN"
[[ "$(lvs --noheadings -o lv_attr "$ORIGIN" | tr -d '[:space:]' | cut -c1)" == 'V' ]] \
    || die "Origin is not an LVM thin volume: $ORIGIN"

IFS=' ' read -r -a configs <<<"$CONFIGS"
(( ${#configs[@]} > 0 )) || die 'CONFIGS is empty.'
for config in "${configs[@]}"; do
    [[ -n "${CONFIG_BIN[$config]+x}" ]] \
        || die "Unknown configuration '$config', available: $(join "${!CONFIG_BIN[@]}")"
done

# Use the *configured* Xen name, `name = '...'` or `name = "..."` in the CFG.
DOMAIN=${DOMAIN:-$(awk -F "[\"']" '/^[[:space:]]*name[[:space:]]*=/ {print $2; exit}' "$CFG")}
[[ -n "$DOMAIN" ]] || die "Could not determine Xen domain name from $CFG; set DOMAIN=..."

# Each binary must load its own libvmi: drakvuf links it dynamically, so a
# libvmi installed system wide would be shared by both builds.
check_libvmi() {
    local so
    so=$(LD_LIBRARY_PATH="$2" ldd "$1" | awk '/libvmi\.so/ {print $3}')
    [[ "$so" == "$2"/* ]] || die "$1 would load libvmi from '$so', expected $2"
    say "$1 uses $so"
}

# awk reads all of nm's output: with pipefail, `grep -q` would make the
# pipeline fail by closing it early (nm gets SIGPIPE).
exports_symbol() {
    nm -D --defined-only "$1" | awk -v sym="$2" '$NF == sym { found = 1 } END { exit !found }'
}

uses_base=0
declare -A dev_bins=()
for config in "${configs[@]}"; do
    if [[ "${CONFIG_BIN[$config]}" == "$BASE_BIN" ]]; then uses_base=1; else dev_bins[${CONFIG_BIN[$config]}]=1; fi
done

# The development and the stats build
for bin in "${!dev_bins[@]}"; do
    [[ -x "$bin" ]] || die "Development binary is missing or not executable: $bin"
    check_libvmi "$bin" "$DEV_LIBVMI"
    exports_symbol "$DEV_LIBVMI/libvmi.so" vmi_events_set_parallel \
        || die "$DEV_LIBVMI is not the parallel libvmi"
    dev_help=$(LD_LIBRARY_PATH="$DEV_LIBVMI" "$bin" -h 2>&1 || true)
    [[ "$dev_help" == *--sysret-mode* ]] || die "$bin has no --sysret-mode option, rebuild it"
done
if [[ -n "$WORKLOAD" ]]; then
    [[ -r "$WORKLOAD" ]] || die "Missing workload: $WORKLOAD (WORKLOAD= runs without one)"
    [[ "$WORKLOAD_PID" =~ ^[1-9][0-9]*$ ]] || die 'WORKLOAD_PID must be the PID of a guest process.'
    [[ "$WORKLOAD_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die 'WORKLOAD_TIMEOUT must be a positive integer.'
    [[ "$WORKLOAD_ATTEMPTS" =~ ^[1-9][0-9]*$ ]] || die 'WORKLOAD_ATTEMPTS must be a positive integer.'
    [[ "$WORKLOAD_DELAY" =~ ^[0-9]+$ ]] || die 'WORKLOAD_DELAY must be a number of seconds.'
    [[ "$WORKLOAD_INTERVAL" =~ ^[0-9]+$ ]] || die 'WORKLOAD_INTERVAL must be a number of seconds.'
    [[ "$WORKLOAD_DST" != *\'* ]] || die 'WORKLOAD_DST must not contain single quotes.'
fi
if (( uses_base )); then
    [[ -x "$BASE_BIN" ]] || die "Baseline binary is missing or not executable: $BASE_BIN"
    # Each configuration of the baseline binary against the libvmi it runs on
    for config in "${configs[@]}"; do
        if [[ "${CONFIG_BIN[$config]}" == "$BASE_BIN" ]]; then
            check_libvmi "$BASE_BIN" "${CONFIG_LIB[$config]}"
        fi
    done
fi

mkdir -p "$OUT_DIR"
mkdir -p "$OUT_DIR/dumps"
case "$GUEST" in
    linux)
        GUEST_ARGS=(--so-hooks-list "$SANDBOX/sandboxd/data/so-hooks-linux.txt")
        ;;
    windows)
        # etwmon: this ntoskrnl has no EtwCpuPartitionProvRegHandle, which it requires
        GUEST_ARGS=(-x etwmon --dll-hooks-list "${DLL_HOOKS_LIST:-$SANDBOX/sandboxd/data/hooks.txt}"
                    --json-wow-kernel32 "$SANDBOX/profiles/kernel32wow.json")
        # win32k comes from WIN32K_PROFILE
        for lib in wow tcpip sspicli kernel32 kernelbase ntdll iphlpapi ole32 clr mscorwks \
                   hal fwpkclnt fltmgr ci netio ndis services; do
            GUEST_ARGS+=("--json-$lib" "$SANDBOX/profiles/$lib.json")
        done
        ;;
esac
# The injection runs before the plugins start, the workload waits a few seconds for them
WORKLOAD_ARGS=()
if [[ -n "$WORKLOAD" ]]; then
    WORKLOAD_ARGS=(-i "$WORKLOAD_PID" -j "$WORKLOAD_TIMEOUT" --write-file-timeout "$WORKLOAD_TIMEOUT"
                   --write-file "$WORKLOAD" "$WORKLOAD_DST")
    if [[ "$GUEST" == linux ]]; then
        # execproc: -e is argv[0], every -f one more argument
        WORKLOAD_ARGS+=(-m execproc -e /bin/sh -f -c
                        -f "sleep $WORKLOAD_DELAY; while :; do '$WORKLOAD_DST'; sleep $WORKLOAD_INTERVAL; done")
    else
        # shellexec, as sandboxd does: its -f carries the arguments, which createproc cannot take
        WORKLOAD_ARGS+=(-m shellexec -e "C:\\Windows\\System32\\cmd.exe" -f "/c C:\\Windows\\System32\\PING.EXE -n 10 127.0.0.1 >nul & $WORKLOAD_DST${WORKLOAD_CMD_ARGS:+ $WORKLOAD_CMD_ARGS}")
    fi
fi

# One benchmark per guest: two on one domain would recreate the same clone under each other.
# Benchmarks of different guests (CFG with another name, another CLONE_NAME) can run together.
exec 9>"/run/lock/drakvuf-benchmark-$DOMAIN.lock"
flock -n 9 || die "Another benchmark of $DOMAIN already holds the lock."
SUMMARY="$OUT_DIR/summary.csv"
# plugin_records: records per plugin, plugin=count separated by spaces
# guest_crash: Xen's console reported a guest crash (Windows bugcheck) during the run
printf '%s\n' "run,round,config,status,wall_seconds,cpu_seconds,syscall,sysret,us_per_event,total_lines,pair_innermost,pair_outer,pair_abandoned,pair_unmatched,pair_open,pair_cross_vcpu,log,plugin_records,guest_crash,api_calls,api_returns" >"$SUMMARY"

SNAP_OWNED=0
VM_OWNED=0
GUEST_DOMID=

# `xl domid` looks the domain up by name, which Xen drops as soon as the
# domain starts dying. Track the numeric ID until Xen has freed the domain.
domain_present() {
    xl list | awk -v id="$1" 'NR > 1 && $2 == id { found = 1 } END { exit !found }'
}

destroy_vm() {
    local domid i dm_pattern
    if ! domid=$(xl domid "$DOMAIN" 2>/dev/null); then
        VM_OWNED=0
        return 0
    fi
    dm_pattern="qemu-system-[^ ]* -xen-domid $domid( |\$)"
    say "Destroying Xen domain $DOMAIN (id $domid)"
    xl destroy "$domid" || return 1
    for ((i = 0; i < DESTROY_TIMEOUT; i++)); do
        if ! domain_present "$domid"; then
            VM_OWNED=0
            return 0
        fi
        # xl destroy can leave the device model running, its guest mappings keep the domain alive
        if (( i == 3 )) && pkill -TERM -f "$dm_pattern"; then
            say "Device model of domain $domid survived xl destroy; terminating it"
        fi
        if (( i == 8 )); then
            pkill -KILL -f "$dm_pattern" || true
        fi
        sleep 1
    done
    say "Domain $domid is still dying after ${DESTROY_TIMEOUT}s:"
    xl list | awk -v id="$domid" 'NR == 1 || $2 == id'
    ps -eo pid,stat,wchan:32,etime,args | grep -E '[q]emu|[d]rakvuf' || true
    return 1
}

clone_open() {
    [[ "$(lvs --noheadings -o lv_attr "$CLONE" | tr -d '[:space:]' | cut -c6)" == o ]]
}

remove_clone() {
    local i actual_origin
    if lvs "$CLONE" >/dev/null 2>&1; then
        actual_origin=$(lvs --noheadings -o origin "$CLONE" | xargs)
        [[ "$actual_origin" == "$ORIGIN_NAME" ]] || die \
            "Refusing to remove $CLONE: its origin is '$actual_origin', not '$ORIGIN_NAME'."
        # 6th lv_attr character is 'o' while a backend still has the volume open
        for ((i = 0; i < 30; i++)); do
            clone_open || break
            sleep 1
        done
        ! clone_open || die "$CLONE is still open; refusing to remove it."
        say "Removing previous thin snapshot $CLONE"
        lvremove -y -f "$CLONE"
    fi
    SNAP_OWNED=0
}

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    set +e
    # Only clean up a VM we tried to restore, not an unrelated VM on early failure.
    if (( VM_OWNED )); then destroy_vm; fi
    if (( SNAP_OWNED )); then remove_clone; fi
    if (( rc != 0 )); then say "Benchmark stopped (status $rc); logs in $OUT_DIR"; fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Initial check: an existing domain of this name is intentionally destroyed.
# Never remove a clone with a different origin.
if lvs "$CLONE" >/dev/null 2>&1; then
    existing_origin=$(lvs --noheadings -o origin "$CLONE" | xargs)
    [[ "$existing_origin" == "$ORIGIN_NAME" ]] || die \
        "Refusing to replace $CLONE: origin is '$existing_origin'."
fi
say "Guest: $GUEST | Output directory: $OUT_DIR | CPUID_STEALTH=$CPUID_STEALTH | WORKLOAD_PID=$WORKLOAD_PID"
say "Domain: $DOMAIN | Origin: $ORIGIN | Clone: $CLONE"
say "Rounds: $ROUNDS | Configurations: $(join "${configs[@]}")"
say "DRAKVUF timeout: ${DRAKVUF_TIMEOUT}s | watchdog: ${WATCHDOG_SECONDS}s | common arguments: $COMMON_ARGS"
say "Output format: $OUTPUT_FORMAT | pairing check: $( (( PAIRING_CHECK )) && echo "$CHECKER" || echo off)"
if [[ "$GUEST" == windows ]]; then
    say "win32k profile: ${WIN32K_PROFILE:-none, GUI syscalls are not traced}"
fi
for config in "${configs[@]}"; do
    say "  $config: ${CONFIG_BIN[$config]} ${CONFIG_ARGS[$config]:-(no extra arguments)}"
done

reset_guest() {
    destroy_vm || die "Unable to destroy $DOMAIN; refusing to touch the clone."
    remove_clone

    say "Creating fresh thin snapshot: $ORIGIN -> $CLONE"
    lvcreate --snapshot --name "$CLONE_NAME" "$ORIGIN"
    SNAP_OWNED=1
    lvchange -ay -K "$CLONE"

    say "Restoring saved Xen state (paused): $STATE"
    # -e: exit after successful restore; -p: remain paused for DRAKVUF to attach.
    # Pass CFG explicitly so the restored guest uses CLONE, not ORIGIN.
    VM_OWNED=1
    xl restore -p -e "$CFG" "$STATE" >>"$OUT_DIR/xen-restore.log" 2>&1 \
        || die "xl restore failed; see $OUT_DIR/xen-restore.log"
    GUEST_DOMID=$(xl domid "$DOMAIN" 2>/dev/null) \
        || die "Restored guest not found as '$DOMAIN' (check name in $CFG)."
    # DRAKVUF starts the guest from the paused checkpoint after hooking traps.
}

run_one() {
    local run_number=$1 round=$2 config=$3
    local executable=${CONFIG_BIN[$config]} libdir=${CONFIG_LIB[$config]}
    local log="$OUT_DIR/$(printf '%02d' "$run_number")-${config}.log"
    local cpu_file="$log.cpu"
    local start end wall cpu us_per_event rc entries returns lines
    local pairing=",,,,," innermost outer abandoned unmatched open cross_vcpu
    local -a args=()

    IFS=' ' read -r -a args <<<"$COMMON_ARGS ${CONFIG_ARGS[$config]}"
    local -a disabled=()
    IFS=' ' read -r -a disabled <<<"$DISABLE_PLUGINS"
    (( HIDSIM )) || disabled+=(hidsim)
    if (( ${#disabled[@]} )); then
        local -a kept=()
        local i plugin
        for (( i = 0; i < ${#args[@]}; i++ )); do
            if [[ "${args[i]}" == -a && " $(join "${disabled[@]}") " == *" ${args[i + 1]-} "* ]]; then
                i=$((i + 1))
                continue
            fi
            kept+=("${args[i]}")
        done
        args=("${kept[@]}")
        if [[ " $(join "${args[@]}") " != *" -a "* ]]; then
            for plugin in "${disabled[@]}"; do
                args+=(-x "$plugin")
            done
        fi
    fi
    # libmon is only in the development build, upstream DRAKVUF rejects its option
    local -a guest_args=("${GUEST_ARGS[@]}")
    local help
    help=$(LD_LIBRARY_PATH="$libdir" "$executable" -h 2>&1 || true)
    if [[ "${guest_args[0]-}" == --so-hooks-list && "$help" != *--so-hooks-list* ]]; then
        guest_args=("${guest_args[@]:2}")
    fi
    if [[ -n "$WIN32K_PROFILE" ]]; then
        args+=(--json-win32k "$WIN32K_PROFILE")
    fi
    [[ -z "$DEBUG_FILTER" ]] || args+=(-v)
    if (( STOP_WAIT > 0 )) && [[ "$help" == *--wait-stop-plugins* ]]; then
        args+=(--wait-stop-plugins "$STOP_WAIT")
    fi
    if (( FILEEXTRACTOR_TIMEOUT > 0 )) && [[ "$help" == *--fileextractor-timeout* &&
          " $(join "${disabled[@]}") " != *" fileextractor "* ]]; then
        args+=(--fileextractor-timeout "$FILEEXTRACTOR_TIMEOUT")
    fi
    if (( HIDSIM && HID_RANDOM_CLICKS )) && [[ "$help" == *--hid-random-clicks* ]]; then
        args+=(--hid-random-clicks)
    fi

    say "=== Run $run_number: $config (round $round) ==="
    local attempt
    for ((attempt = 1; ; attempt++)); do
        reset_guest
        say "Launching $executable -o $OUTPUT_FORMAT $(join "${args[@]}") $(join "${WORKLOAD_ARGS[@]}")"
        # Standard error goes to the log, or with DEBUG_FILTER through grep to <log>.debug
        local err_fd=1 debug_pid=
        if [[ -n "$DEBUG_FILTER" ]]; then
            exec {err_fd}> >(grep --line-buffered -E "($DEBUG_FILTER)|^\[TRAP-STATS\]" >"$log.debug" || true)
            debug_pid=$!
        fi
        start=$(date +%s.%N)
        # Run from the checkout root, matching the original ./build/drakvuf calls.
        # The watchdog sends SIGTERM first so DRAKVUF can restore the guest, SIGKILL 15s later.
        # `time` counts DRAKVUF's CPU time too: every process in between waited for it.
        # Its report goes to the outer stderr, so DRAKVUF's output is redirected in the inner group.
    # Start Xen diagnostic sampler independently.
    (
        for delay in 1 1 3 5 5 5 5 5 5 5; do
            sleep "$delay"

            domid=$(xl domid "$DOMAIN" 2>/dev/null || true)
            [ -n "$domid" ] || continue

            echo "===== $(date -Ins) dom=$domid ====="

            xl debug-keys t
            sleep 0.2

            xl dmesg |
                grep -F "RDTSC_POC: dom=$domid vcpu=" |
                grep -E 'big_gate=|guest_delta_' |
                tail -8

            xl vcpu-list "$DOMAIN"
        done
    ) > "${log}.rdtsc-diagnostics" 2>&1 &

    diag_pid=$!

    stealth_args=()
    (( CPUID_STEALTH )) && stealth_args=(-s)

    # Run and time the actual DRAKVUF process.
    if {
        time (
            cd "$(dirname "$(dirname "$executable")")" || exit 1

            exec timeout -k 15 "$WATCHDOG_SECONDS" \
            stdbuf -oL -eL "$executable" \
            -r "$PROFILE" \
            -d "$DOMAIN" \
            "${stealth_args[@]}" -t "$DRAKVUF_TIMEOUT" \
            -D "$OUT_DIR/dumps" \
            --memdump-dir "$OUT_DIR/dumps" \
            -o "$OUTPUT_FORMAT" \
            "${args[@]}" \
            "${guest_args[@]}" \
            "${WORKLOAD_ARGS[@]}"
            ) >"$log" 2>&"$err_fd"
        } 2>"$cpu_file"; then
        rc=0
        else
            rc=$?
        fi

        kill "$diag_pid" 2>/dev/null || true
        wait "$diag_pid" 2>/dev/null || true
        # The red pill pairs and program reads go with the domain: keep their last state
        domid=$(xl domid "$DOMAIN" 2>/dev/null || true)
        if [ -n "$domid" ]; then
            {
                echo "===== $(date -Ins) dom=$domid after DRAKVUF ====="
                xl debug-keys t
                sleep 0.2
                xl dmesg |
                    grep -E "RDTSC_POC: dom=$domid (pair |pairs=|pure |pure_cpu |vcpu=[0-9]+ prog_)" |
                    awk '/ pairs=/ { last = "" } { last = last $0 "\n" } END { printf "%s", last }'
            } >>"${log}.rdtsc-diagnostics" 2>&1
        fi
        end=$(date +%s.%N)
        if (( err_fd != 1 )); then
            exec {err_fd}>&-
            # The filter writes the rest of <log>.debug after DRAKVUF is gone
            while kill -0 "$debug_pid" 2>/dev/null; do sleep 0.2; done
        fi
        # The workload is started from a guest process, which may not run before the injection times
        # out (2: injection, 5: file write). Start over from the saved state.
        if [[ -n "$WORKLOAD" ]] && (( (rc == 2 || rc == 5) && attempt < WORKLOAD_ATTEMPTS )); then
            say "$config: the workload injection timed out (status $rc), attempt $((attempt + 1)) of $WORKLOAD_ATTEMPTS"
            mv -f "$log" "$log.failed-$attempt"
            continue
        fi
        break
    done
    wall=$(awk -v a="$start" -v b="$end" 'BEGIN {printf "%.3f", b-a}')
    cpu=$(awk 'NF >= 2 {printf "%.3f", $1 + $2; found = 1} END {if (!found) printf "0"}' "$cpu_file")
    rm -f "$cpu_file"

    # The records are counted in the -t window only, from the first record on. During the stop
    # wait (STOP_WAIT) the plugins still running go on recording, syscalls included: its stop()
    # leaves the hooks of the per-OS plugin to the end. Only json records carry a time stamp.
    local counted=$log
    if [[ "$OUTPUT_FORMAT" == json ]]; then
        counted=$log.window
        awk -v t="$DRAKVUF_TIMEOUT" 'match($0, /^\{"Plugin":"[^"]*","TimeStamp":"[0-9.]+"/) {
                ts = substr($0, RSTART, RLENGTH)
                sub(/.*"TimeStamp":"/, "", ts)
                sub(/"$/, "", ts)
                if (start == "")
                    start = ts
                if (ts - start > t)
                    next
            }
            { print }' "$log" >"$counted"
    fi

    # Strict record tags, not grep 'syscall' (which also matches fields in SYSRET).
    local all_entries all_returns
    if [[ "$OUTPUT_FORMAT" == json ]]; then
        entries=$(grep -c '^{"Plugin":"syscall",' "$counted" || true)
        returns=$(grep -c '^{"Plugin":"sysret",' "$counted" || true)
        all_entries=$(grep -c '^{"Plugin":"syscall",' "$log" || true)
        all_returns=$(grep -c '^{"Plugin":"sysret",' "$log" || true)
    else
        entries=$(grep -c '^\[SYSCALL\]' "$log" || true)
        returns=$(grep -c '^\[SYSRET\]' "$log" || true)
        all_entries=$entries
        all_returns=$returns
    fi
    lines=$(wc -l <"$log" | tr -d '[:space:]')
    # DRAKVUF's CPU time per syscall and sysret record, start-up and shutdown included, so over
    # the records of the whole run
    us_per_event=$(awk -v c="$cpu" -v e="$all_entries" -v r="$all_returns" \
        'BEGIN {printf "%.1f", (e + r) ? c * 1000000 / (e + r) : 0}')

    if (( PAIRING_CHECK )); then
        if ! pairing=$(python3 -I "$CHECKER" --csv --report "$log.pairing.txt" "$counted"); then
            say "Pairing check failed for $log"
            pairing=",,,,,"
        fi
    fi
    IFS=, read -r innermost outer abandoned unmatched open cross_vcpu <<<"$pairing"

    # Records per plugin, json only: the default format names plugins differently per record
    local plugin_records=
    if [[ "$OUTPUT_FORMAT" == json ]]; then
        plugin_records=$(awk 'match($0, /^\{"Plugin":"[^"]*"/) { n[substr($0, 12, RLENGTH - 12)]++ }
            END { for (p in n) printf "%s=%d\n", p, n[p] }' "$counted" | sort | tr '\n' ' ')
        plugin_records=${plugin_records% }
    fi
    # Calls apimon and libmon reported with their return value: a lost return shows up here
    local api_calls=0 api_returns=0
    if [[ "$OUTPUT_FORMAT" == json ]]; then
        IFS=' ' read -r api_calls api_returns < <(awk '/^\{"Plugin":"(apimon|libmon)",/ && /"Event":"api_called"/ \
            { n++; if (/"ReturnValue":"0x/) r++ } END { printf "%d %d\n", n, r }' "$counted")
    fi
    [[ "$counted" == "$log" ]] || rm -f "$counted"
    # The debug build prints trap statistics when it exits
    local -a stats_from=("$log")
    [[ ! -f "$log.debug" ]] || stats_from+=("$log.debug")
    if grep -q '^\[TRAP-STATS\]' "${stats_from[@]}"; then
        grep -h '^\[TRAP-STATS\]' "${stats_from[@]}" >"$log.trap-stats.txt"
        say "$config: trap statistics in $log.trap-stats.txt"
    fi

    # Windows reports a bugcheck to Xen through the Hyper-V crash MSRs: "dNvM VIRIDIAN GUEST_CRASH: ..."
    local crash
    crash=$(xl dmesg | awk -v d="(XEN) d${GUEST_DOMID}v" 'index($0, d) && /GUEST_CRASH/ { sub(/.*GUEST_CRASH: */, ""); c = $0 } END { print c }')
    if [[ -n "$crash" ]]; then
        say "$config: the guest crashed: $crash"
        xl dmesg | grep -F "(XEN) d${GUEST_DOMID}v" >"$log.xen-console.txt" || true
    fi

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$run_number" "$round" "$config" "$rc" "$wall" "$cpu" "$entries" "$returns" "$us_per_event" "$lines" \
        "$pairing" "$log" "$plugin_records" "$crash" "$api_calls" "$api_returns" >>"$SUMMARY"
    say "$config: status=$rc, wall=${wall}s, cpu=${cpu}s, SYSCALL=$entries, SYSRET=$returns, ${us_per_event}us/record, lines=$lines"

    # For a post-mortem: stop at the first crash and leave the domain and its clone in place.
    # Needs on_crash = 'preserve' in CFG, or Xen destroys the domain at the bugcheck.
    if [[ -n "$crash" && "${KEEP_CRASHED:-0}" == 1 ]]; then
        VM_OWNED=0
        SNAP_OWNED=0
        say "Keeping crashed domain $DOMAIN (id $GUEST_DOMID) and $CLONE; xl destroy and lvremove them when done"
        exit 0
    fi
    # The files the plugins extracted and dumped, up to several GB a run, are not counted
    (( KEEP_DUMPS )) || find "$OUT_DIR/dumps" -mindepth 1 -delete
    [[ -z "$plugin_records" ]] || say "$config: records per plugin: $plugin_records"
    # hidsim writes no records, only its errors on standard error (in the log without DEBUG_FILTER):
    # its own start with [HIDSIM] (its -v debug lines start with a timestamp), the QMP ones don't
    local hidsim_errors
    hidsim_errors=$( { grep -a -h -E '^\[HIDSIM\]|qmp-libxl-[0-9]+.* failed|^(Opening socket|Fetching QMP greeting banner|Entering command mode) failed' \
                       "$log" "$log.debug" 2>/dev/null || true; } | wc -l)
    (( hidsim_errors == 0 )) || say "$config: WARNING: $hidsim_errors hidsim errors (mouse/keyboard injection), see $log"
    (( api_calls == 0 )) || say "$config: apimon/libmon calls with a return value: $api_returns of $api_calls"
    if (( PAIRING_CHECK )) && [[ -n "$innermost" ]]; then
        say "$config: sysret pairing: innermost=$innermost outer=$outer (left open: $abandoned)" \
            "unmatched=$unmatched open_at_end=$open other_vcpu=$cross_vcpu; see $log.pairing.txt"
    fi

    # 7: a plugin had not stopped by the end of the stop wait. The run itself is complete, and
    # the summary keeps the status.
    if (( rc == 7 )); then
        say "$config: a plugin did not stop within ${STOP_WAIT}s (status 7)"
    elif (( rc != 0 )); then
        die "DRAKVUF exited with status $rc; see $log (124: watchdog SIGTERM, 137: watchdog SIGKILL)."
    fi
    if (( entries == 0 )); then
        die "No syscall-entry records in $log; refusing to continue with invalid results."
    fi
}

# One line per configuration. Medians are robust against runs where the guest stalled.
summarize() {
    awk -F, -v order="$(join "${configs[@]}")" '
        function median(c, col,    n, i, j, t, a) {
            n = runs[c]
            if (!n)
                return 0
            for (i = 1; i <= n; i++)
                a[i] = val[c, col, i] + 0
            for (i = 2; i <= n; i++) {
                t = a[i]
                for (j = i - 1; j >= 1 && a[j] > t; j--)
                    a[j + 1] = a[j]
                a[j + 1] = t
            }
            return (n % 2) ? a[(n + 1) / 2] : (a[n / 2] + a[n / 2 + 1]) / 2
        }
        NR > 1 && $4 == 0 {
            c = $3
            n = ++runs[c]
            val[c, 6, n] = $6
            val[c, 7, n] = $7
            val[c, 9, n] = $9
            if (n == 1 || $7 + 0 < lo[c]) lo[c] = $7 + 0
            if (n == 1 || $7 + 0 > hi[c]) hi[c] = $7 + 0
            calls[c] += $7
            rets[c] += $8
            if ($11 != "") {
                checked[c] = 1
                matched[c] += $11 + $12
                notinner[c] += $12 + $14
                cross[c] += $16
            }
            if ($19 != "")
                crashes[c]++
            api[c] += $20
            apiret[c] += $21
            # plugin_records: plugin=count separated by spaces
            np = split($18, recs, " ")
            for (i = 1; i <= np; i++) {
                split(recs[i], kv, "=")
                plugins[kv[1]] = 1
                prec[c, kv[1], n] = kv[2]
            }
        }
        function median_records(c, p,    n, i, j, t, a) {
            n = runs[c]
            for (i = 1; i <= n; i++)
                a[i] = prec[c, p, i] + 0
            for (i = 2; i <= n; i++) {
                t = a[i]
                for (j = i - 1; j >= 1 && a[j] > t; j--)
                    a[j + 1] = a[j]
                a[j + 1] = t
            }
            return (n % 2) ? a[(n + 1) / 2] : (a[n / 2] + a[n / 2 + 1]) / 2
        }
        END {
            count = split(order, list, " ")
            # The reference: upstream if it ran, otherwise the parallel build with syscalls only
            ref = ("baseline" in runs) ? "baseline" : ("dev-syscalls" in runs) ? "dev-syscalls" : \
                ("stats-syscalls" in runs) ? "stats-syscalls" : ""
            base = ref ? median(ref, 7) : 0
            fmt = "%-24s %4s %11s %11s %11s %8s %8s %9s %9s %10s %10s\n"
            printf fmt, "config", "runs", "syscall_med", "syscall_min", "syscall_max", "vs_ref", \
                "cpu_s", "us/record", "ret/call", "not_inner", "other_vcpu"
            for (k = 1; k <= count; k++) {
                c = list[k]
                if (!(c in runs)) {
                    printf fmt, c, 0, "-", "-", "-", "-", "-", "-", "-", "-", "-"
                    continue
                }
                med = median(c, 7)
                printf fmt, c, runs[c], sprintf("%.0f", med), lo[c], hi[c], \
                    (base > 0) ? sprintf("%.2fx", med / base) : "-", \
                    sprintf("%.1f", median(c, 6)), sprintf("%.1f", median(c, 9)), \
                    calls[c] ? sprintf("%.1f%%", 100 * rets[c] / calls[c]) : "-", \
                    (checked[c] && rets[c]) ? sprintf("%.2f%%", 100 * notinner[c] / rets[c]) : "-", \
                    (checked[c] && matched[c]) ? sprintf("%.1f%%", 100 * cross[c] / matched[c]) : "-"
            }
            print ""
            print "syscall_*:  syscall records per run (median, minimum, maximum), vs_ref: median against " (ref ? ref : "-")
            print "cpu_s:      median DRAKVUF CPU seconds (user + system, start-up included), us/record: median per record"
            print "ret/call:   sysret records per syscall record"
            print "not_inner:  sysrets that do not close the innermost open call of their thread, see *.pairing.txt"
            print "other_vcpu: matched sysrets on another vCPU than their syscall"
            for (k = 1; k <= count; k++)
                if (api[list[k]])
                    printf "api calls with a return value: %s %.2f%% (%d of %d)\n", list[k], \
                        100 * apiret[list[k]] / api[list[k]], apiret[list[k]], api[list[k]]
            for (k = 1; k <= count; k++)
                if (crashes[list[k]])
                    printf "guest crashes: %s in %d of %d runs, see *.xen-console.txt\n", list[k], crashes[list[k]], runs[list[k]]

            np = 0
            for (p in plugins)
                names[++np] = p
            if (!np)
                exit
            # Plugin names in alphabetical order
            for (i = 2; i <= np; i++) {
                t = names[i]
                for (j = i - 1; j >= 1 && names[j] > t; j--)
                    names[j + 1] = names[j]
                names[j + 1] = t
            }
            print ""
            print "Median records per plugin:"
            for (k = 1; k <= count; k++) {
                c = list[k]
                if (!(c in runs))
                    continue
                line = sprintf("%-24s", c)
                for (i = 1; i <= np; i++) {
                    m = median_records(c, names[i])
                    if (m > 0)
                        line = line sprintf(" %s=%.0f", names[i], m)
                }
                print line
            }
        }' "$SUMMARY"
}

run_no=0
for ((round = 1; round <= ROUNDS; round++)); do
    # Rotate the order so every configuration runs in every position equally often
    offset=$(( (round - 1) % ${#configs[@]} ))
    order=("${configs[@]:offset}" "${configs[@]:0:offset}")

    for config in "${order[@]}"; do
        ((run_no += 1))
        run_one "$run_no" "$round" "$config"
    done
done

say "All $run_no runs finished. CSV: $SUMMARY"
say "Results per configuration (${DRAKVUF_TIMEOUT}s runs):"
summarize | tee "$OUT_DIR/summary.txt"
