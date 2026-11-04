# shellcheck shell=bash
# Shared by rdtsc_search.sh and alkhaser_search.sh, which source it after site.conf: the host
# settings, logging, dom0 access, detached dom0 jobs, the grub switch between Xen and the plain
# kernel, and the Xen variants (the defines they may set, building and installing them).
# README.md, "Adapting it to your hardware", explains each setting.

say() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
# IFS is newline and tab, so "$*" would join with newlines
join_by() { local IFS=$1; shift; printf '%s' "$*"; }

REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
# dom0, as ssh reaches it as root, and the key that logs in without a password
DOM0=${DOM0-}
[[ -n "$DOM0" ]] || die "Set DOM0 (e.g. root@192.0.2.10) in $SCRIPT_DIR/site.conf, see site.conf.example"
SSH_KEY=${SSH_KEY:-$HOME/.ssh/id_ed25519}
# dom0's checkout of this repository: make xen built its Xen in drakvuf/xen, and the benchmark
# runs from its evasion-tests
REMOTE_REPO=${REMOTE_REPO:-/root/drakvuf-multios-sandbox}
REMOTE_BENCH_DIR=${REMOTE_BENCH_DIR:-$REMOTE_REPO/evasion-tests}
REMOTE_XEN=${REMOTE_XEN:-$REMOTE_REPO/drakvuf/xen}
# A Xen tree of your own to build the variants from (every file changed from XEN_BASE is
# uploaded to REMOTE_XEN). Empty: a variant changes only vmx.c and vmcs.h of dom0's make xen tree.
LOCAL_XEN=${LOCAL_XEN-}
XEN_BASE=${XEN_BASE:-RELEASE-4.20.1}
# dom0: job logs, installed variant, originals of the overwritten sources, uploaded test programs
REMOTE_STATE=${REMOTE_STATE:-/root/evasion-tests}
# dom0: the benchmarks' output, DRAKVUF logs included: tens of GB per al-khaser run
REMOTE_OUT_BASE=${REMOTE_OUT_BASE:-$REMOTE_STATE/out}
# Here: the results of each search, <base>/rdtsc-search/<timestamp> and alkhaser-search/...
RESULTS_BASE=${RESULTS_BASE:-$SCRIPT_DIR/results}
# The DRAKVUF the benchmarks run: built in dom0's checkout of this repository's drakvuf submodule
# (make sandboxd configured it), with the libvmi built beside it, not the one installed in
# /usr/local/lib. Each search checks that its source is this checkout's drakvuf and builds it there.
REMOTE_DRAKVUF=${REMOTE_DRAKVUF:-$REMOTE_REPO/drakvuf}
# 1: dom0's drakvuf and libvmi must be at this checkout's commits with the same uncommitted
# changes to tracked files; 0 skips the check (the build still runs)
DRAKVUF_SOURCE_CHECK=${DRAKVUF_SOURCE_CHECK:-1}
DRAKVUF_BUILD_LIMIT=${DRAKVUF_BUILD_LIMIT:-3600}
# Added to every benchmark's environment after the DRAKVUF above, so it can replace it, e.g.
# "DEV_BIN=/opt/drakvuf/bin/drakvuf DEV_LIBVMI=/opt/libvmi/lib"
BENCH_EXTRA_ENV=${BENCH_EXTRA_ENV-}
# 1 shows the VMs in VNC viewers (rdtsc_vnc.sh) while the search runs; they connect to VNC_HOST
VNC=${VNC:-0}
VNC_HOST=${VNC_HOST:-${DOM0#*@}}
GRUB_XEN_CFG=/etc/default/grub.d/xen.cfg
GRUB_ENV=/boot/grub/grubenv
# Time limits in seconds: a job is killed when it runs longer than its limit or its log does
# not grow for its stall limit. A build takes 2-3 min.
BUILD_LIMIT=${BUILD_LIMIT:-3600}
BUILD_STALL=${BUILD_STALL:-600}
BUILD_TRIES=${BUILD_TRIES:-3}
# CPUs the Xen build runs on (taskset list), empty for all. The i9-13900KF this was written on
# crashed gcc and as at random under full 32-thread builds (2026-11-01); its E-cores (16-31)
# built cleanly
BUILD_CPUS=${BUILD_CPUS-}
BOOT_LIMIT=${BOOT_LIMIT:-1800}

VMX=xen/arch/x86/hvm/vmx/vmx.c
VMCS_H=xen/arch/x86/include/asm/hvm/vmx/vmcs.h
RDTSC_PATCH=$REPO_ROOT/automation/xen-rdtsc-poc.patch

SSH_OPTS=(-i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=10
          -o ServerAliveInterval=30 -o ServerAliveCountMax=4 -o StrictHostKeyChecking=accept-new)
# ssh reads standard input: only rsh_stdin passes it on
rsh() { ssh "${SSH_OPTS[@]}" "$DOM0" "$@" </dev/null; }
rsh_stdin() { ssh "${SSH_OPTS[@]}" "$DOM0" "$@"; }
rcp_to() { scp -q "${SSH_OPTS[@]}" "$1" "$DOM0:$2"; }
rcp_from() { scp -q "${SSH_OPTS[@]}" "$DOM0:$1" "$2"; }

# Sets XEN_SRC_DIR, the local tree the variants' vmx.c and vmcs.h start from, and MODIFIED, the
# files of the Xen tree a variant uploads to REMOTE_XEN and that make up its sha.
# With LOCAL_XEN: that tree, and every file it changed from XEN_BASE.
# Without: vmx.c and vmcs.h as make xen made them on dom0, i.e. the pinned commit of dom0's
# drakvuf/xen with automation/xen-rdtsc-poc.patch, rebuilt in <results>/xen-base. dom0's other
# files stay as make xen left them, the guest identity's strings in hvmloader and libacpi too.
prepare_xen_sources() {
    local modified rel
    if [[ -n "$LOCAL_XEN" ]]; then
        XEN_SRC_DIR=$LOCAL_XEN
        mapfile -t MODIFIED < <(git -C "$LOCAL_XEN" diff --name-only "$XEN_BASE")
        modified=" $(join_by ' ' "${MODIFIED[@]}") "
        [[ "$modified" == *" $VMX "* && "$modified" == *" $VMCS_H "* ]] \
            || die "$LOCAL_XEN has no changes from $XEN_BASE in $VMX and $VMCS_H"
        return
    fi
    [[ -r "$RDTSC_PATCH" ]] || die "Missing $RDTSC_PATCH"
    [[ "$(md5sum <"$RDTSC_PATCH" | cut -c1-32)" == \
       "$(rsh "md5sum < $REMOTE_REPO/automation/xen-rdtsc-poc.patch" 2>/dev/null | cut -c1-32)" ]] \
        || die "$RDTSC_PATCH differs from $DOM0:$REMOTE_REPO/automation/xen-rdtsc-poc.patch: check out the same commit on both and run make xen on dom0"
    mkdir -p "$RESULTS/xen-base"
    XEN_SRC_DIR=$(cd "$RESULTS/xen-base" && pwd)
    MODIFIED=("$VMX" "$VMCS_H")
    for rel in "${MODIFIED[@]}"; do
        mkdir -p "$XEN_SRC_DIR/$(dirname "$rel")"
        rsh "git -C $REMOTE_XEN show HEAD:$rel" >"$XEN_SRC_DIR/$rel" \
            || die "Cannot read $rel at HEAD of $DOM0:$REMOTE_XEN (REMOTE_XEN)"
    done
    # Outside any repository: inside one (results/ is in this one) git apply would take the
    # patch's paths from the repository's top and skip them
    (cd "$XEN_SRC_DIR" && GIT_CEILING_DIRECTORIES=$(dirname "$XEN_SRC_DIR") \
        git apply --include="$VMX" --include="$VMCS_H" "$RDTSC_PATCH") \
        || die "$RDTSC_PATCH does not apply to $VMX and $VMCS_H at HEAD of $DOM0:$REMOTE_XEN"
}

# Prints the source state of a drakvuf checkout (argument: its directory), one line each for
# drakvuf and its libvmi: commit, and a hash of the uncommitted changes to tracked files. A
# nested submodule's own changes are left out (make xen patches drakvuf/xen); its commit is not.
# volatility3 and dwarf2json are left out: they make profiles, not DRAKVUF, and make sandboxd
# moves volatility3 to a pull request's commit. Untracked files are not compared.
read -r -d '' DRAKVUF_STATE_CMD <<'EOF' || true
cd "$1" || exit 1
printf '. %s %s\n' "$(git rev-parse HEAD)" \
    "$(git diff --no-ext-diff --no-color --ignore-submodules=dirty HEAD -- . ':(exclude)volatility3' ':(exclude)dwarf2json' | sha256sum | cut -c1-16)"
printf 'libvmi %s %s\n' "$(git -C libvmi rev-parse HEAD)" \
    "$(git -C libvmi diff --no-ext-diff --no-color HEAD | sha256sum | cut -c1-16)"
EOF

# Makes sure the benchmarks run this checkout's DRAKVUF: compares dom0's drakvuf checkout with
# this one (DRAKVUF_SOURCE_CHECK), builds drakvuf and libvmi there, and adds DEV_BIN and
# DEV_LIBVMI, then BENCH_EXTRA_ENV, to BENCH_ENV.
prepare_drakvuf() {
    local here there
    if (( DRAKVUF_SOURCE_CHECK )); then
        [[ -e "$REPO_ROOT/drakvuf/.git" && -e "$REPO_ROOT/drakvuf/libvmi/.git" ]] \
            || die "$REPO_ROOT/drakvuf is not checked out: git submodule update --init --recursive"
        here=$(bash -c "$DRAKVUF_STATE_CMD" _ "$REPO_ROOT/drakvuf") || die "Cannot read $REPO_ROOT/drakvuf"
        there=$(rsh "bash -c $(printf '%q' "$DRAKVUF_STATE_CMD") _ $REMOTE_DRAKVUF") \
            || die "Cannot read $DOM0:$REMOTE_DRAKVUF (REMOTE_DRAKVUF)"
        if [[ "$here" != "$there" ]]; then
            printf 'here (%s):\n%s\ndom0 (%s):\n%s\n' "$REPO_ROOT/drakvuf" "$here" "$REMOTE_DRAKVUF" "$there" >&2
            die "dom0's drakvuf source is not this checkout's (columns: tree, commit, hash of uncommitted changes). Check out the same commits on both, with the same changes or none, or set DRAKVUF_SOURCE_CHECK=0"
        fi
        say "DRAKVUF source, the same on both sides: ${here//$'\n'/; }"
    fi
    rsh "test -f $REMOTE_DRAKVUF/build/build.ninja && test -f $REMOTE_DRAKVUF/libvmi/Makefile" \
        || die "$DOM0:$REMOTE_DRAKVUF has no configured build (build/, libvmi/Makefile): run make sandboxd there first"
    say "Building drakvuf and libvmi in $DOM0:$REMOTE_DRAKVUF (log: $RESULTS/drakvuf-build.log)"
    remote_job drakvuf-build "$RESULTS/drakvuf-build.log" "$DRAKVUF_BUILD_LIMIT" "$BUILD_STALL" "set -ex
make -C $REMOTE_DRAKVUF/libvmi -j\$(nproc)
ninja -C $REMOTE_DRAKVUF/build -j\$(nproc)" \
        || die "Building drakvuf on dom0 failed, see $RESULTS/drakvuf-build.log"
    BENCH_ENV+=" DEV_BIN=$REMOTE_DRAKVUF/build/drakvuf DEV_LIBVMI=$REMOTE_DRAKVUF/libvmi/libvmi/.libs"
    [[ -z "$BENCH_EXTRA_ENV" ]] || BENCH_ENV+=" $BENCH_EXTRA_ENV"
}

# Runs a command on dom0 detached from this connection and waits for it. The job is a session
# of its own: when it runs past its time limit or its log does not grow for its stall limit,
# the whole session is killed. Arguments: job name, local copy of its log, time limit, stall
# limit, command. Returns its exit status, or 124 when it was killed.
remote_job() {
    local name=$1 log=$2 limit=$3 stall=$4 cmd=$5 rc state size last_size=-1 grown_at deadline
    deadline=$((SECONDS + limit))
    grown_at=$SECONDS
    # Only the job goes to the background, in braces: a backgrounded && list would run in a
    # subshell that waits for the job and keeps ssh's output open, so ssh would not return.
    rsh "mkdir -p $REMOTE_STATE && rm -f $REMOTE_STATE/$name.rc && cd / &&" \
        "{ nohup setsid bash -c $(printf '%q' "echo \$\$ > $REMOTE_STATE/$name.sid
(
$cmd
)
echo \$? > $REMOTE_STATE/$name.rc.tmp && mv $REMOTE_STATE/$name.rc.tmp $REMOTE_STATE/$name.rc")" \
        ">$REMOTE_STATE/$name.log 2>&1 </dev/null & }" \
        || die "Could not start $name on dom0"
    while :; do
        sleep 15
        if ! state=$(rsh "cat $REMOTE_STATE/$name.rc 2>/dev/null || stat -c 'running %s' $REMOTE_STATE/$name.log"); then
            (( SECONDS < deadline )) || die "dom0 unreachable while $name runs, see $DOM0:$REMOTE_STATE/$name.log"
            continue
        fi
        if [[ "$state" != running* ]]; then
            rc=$state
            break
        fi
        size=${state#running }
        if [[ "$size" != "$last_size" ]]; then
            last_size=$size
            grown_at=$SECONDS
        fi
        if (( SECONDS >= deadline || SECONDS - grown_at >= stall )); then
            say "$name hung (no end within $limit s, or no output for $stall s): killing it"
            rsh "pkill -KILL -s \$(cat $REMOTE_STATE/$name.sid)" || true
            rc=124
            break
        fi
    done
    rcp_from "$REMOTE_STATE/$name.log" "$log" || say "Could not copy $REMOTE_STATE/$name.log"
    return "$rc"
}

boot_mode() {
    rsh 'if grep -qs control_d /proc/xen/capabilities && xl info >/dev/null 2>&1; then echo xen; else echo native; fi'
}

# The GRUB default entry on dom0: xen (XEN_OVERRIDE_GRUB_DEFAULT=0 commented out in make xen's
# xen.cfg) or native (uncommented: entry 0 of /etc/default/grub, the plain kernel).
grub_default() {
    rsh "if grep -q '^XEN_OVERRIDE_GRUB_DEFAULT=0' $GRUB_XEN_CFG; then echo native; else echo xen; fi"
}

# Makes the plain kernel (native) or Xen (xen) the default entry, for every boot from now on.
# While a search runs the default is native (search_begin), so that a variant that panics at
# boot (Xen reboots after a panic), a crash of this script or a power cut leaves dom0 reachable
# on its plain kernel, not looping on an unreviewed Xen; each variant's Xen is booted one boot
# at a time (grub_boot_xen_once). search_end gives Xen the default back (review M-9, 2026-11-04).
set_grub_default() {
    local want=$1 expr check
    [[ "$(grub_default)" != "$want" ]] || return 0
    if [[ "$want" == native ]]; then
        expr='s/^#XEN_OVERRIDE_GRUB_DEFAULT=0/XEN_OVERRIDE_GRUB_DEFAULT=0/'
        check="grep -q '^XEN_OVERRIDE_GRUB_DEFAULT=0' $GRUB_XEN_CFG"
    else
        expr='s/^XEN_OVERRIDE_GRUB_DEFAULT=0/#XEN_OVERRIDE_GRUB_DEFAULT=0/'
        check="grep -q '^#XEN_OVERRIDE_GRUB_DEFAULT=0' $GRUB_XEN_CFG"
    fi
    rsh "sed -i '$expr' $GRUB_XEN_CFG && $check && update-grub2" >>"$RESULTS/grub.log" 2>&1 \
        || die "Could not make $want the default GRUB entry on dom0, see $RESULTS/grub.log"
    say "GRUB default on dom0: $want"
}

# Boots Xen at the next boot only (grub-reboot, next_entry in grubenv, which GRUB clears as it
# boots it): the default entry stays the plain kernel. The entry is the one xen.cfg makes the
# default, read from grub.cfg as GRUB names it.
grub_boot_xen_once() {
    local title
    title=$(rsh "sed -n \"s/^menuentry '\([^']*with Xen hypervisor\)'.*/\1/p\" /boot/grub/grub.cfg | head -1")
    [[ -n "$title" ]] || die "No 'with Xen hypervisor' entry in $DOM0:/boot/grub/grub.cfg: run make xen on dom0"
    rsh "grub-reboot $(printf '%q' "$title") && grub-editenv $GRUB_ENV list | grep -q '^next_entry='" \
        >>"$RESULTS/grub.log" 2>&1 || die "grub-reboot failed on dom0, see $RESULTS/grub.log"
}

# Reboots dom0 into the plain kernel (native) or Xen (xen). Xen while it is not the default
# entry is booted once, see set_grub_default.
reboot_to() {
    local want=$1 old_boot new_boot deadline booted_at=0
    if [[ "$(boot_mode)" == "$want" ]]; then
        say "dom0 already runs $want"
        return
    fi
    if [[ "$want" == native ]]; then
        set_grub_default native
        # A one-shot entry still set (grubenv GRUB could not write) would boot Xen again
        rsh "grub-editenv $GRUB_ENV unset next_entry" >>"$RESULTS/grub.log" 2>&1 || true
    elif [[ "$(grub_default)" != xen ]]; then
        grub_boot_xen_once
    fi
    old_boot=$(rsh cat /proc/sys/kernel/random/boot_id)
    say "Rebooting dom0 into $want"
    rsh 'nohup sh -c "sleep 2; systemctl reboot" >/dev/null 2>&1 </dev/null &' || true
    deadline=$((SECONDS + BOOT_LIMIT))
    while :; do
        sleep 20
        (( SECONDS < deadline )) || die "dom0 did not come back into $want within $BOOT_LIMIT s"
        new_boot=$(rsh cat /proc/sys/kernel/random/boot_id 2>/dev/null) || continue
        [[ "$new_boot" != "$old_boot" ]] || continue
        # Xen's toolstack may start after sshd
        (( booted_at )) || booted_at=$SECONDS
        if [[ "$(boot_mode)" == "$want" ]]; then
            break
        fi
        if (( SECONDS - booted_at > 300 )); then
            die "dom0 booted, but not into $want"
        fi
    done
    say "dom0 runs $want"
}

# Writes the variant's sources to <variant dir>/src. Arguments: variant dir, KEY=VALUE...
# KEY is any #define of vmx.c or vmcs.h, defined exactly once in the two.
apply_variant() {
    local vdir=$1 kv key value dst n f
    shift
    mkdir -p "$vdir/src"
    cp "$XEN_SRC_DIR/$VMX" "$vdir/src/vmx.c"
    cp "$XEN_SRC_DIR/$VMCS_H" "$vdir/src/vmcs.h"
    for kv in "$@"; do
        key=${kv%%=*}
        value=${kv#*=}
        [[ "$key" =~ ^[A-Z_][A-Z0-9_]*$ && "$kv" == *=* ]] || die "Bad entry $kv in $VARIANTS: KEY=VALUE expected"
        [[ "$value" =~ ^(0x[0-9a-fA-F]+|[0-9]+)(U|ULL)?$ ]] || die "Bad value $kv in $VARIANTS"
        dst=
        n=0
        for f in "$vdir/src/vmx.c" "$vdir/src/vmcs.h"; do
            if grep -q "^#define $key " "$f"; then
                n=$((n + $(grep -c "^#define $key " "$f")))
                dst=$f
            fi
        done
        (( n == 1 )) || die "#define $key found $n times in $VMX and $VMCS_H, exactly once expected ($VARIANTS)"
        sed -i "s|^#define $key .*|#define $key $value|" "$dst"
    done
    { diff -u "$XEN_SRC_DIR/$VMX" "$vdir/src/vmx.c"; diff -u "$XEN_SRC_DIR/$VMCS_H" "$vdir/src/vmcs.h"; } \
        >"$vdir/variant.diff" || true
    printf '%s\n' "$@" >"$vdir/params.txt"
}

# Local source of a modified file of the Xen tree: the variant's copy or the local tree's.
source_of() {
    local vdir=$1 rel=$2
    case "$rel" in
        "$VMX") echo "$vdir/src/vmx.c" ;;
        "$VMCS_H") echo "$vdir/src/vmcs.h" ;;
        *) echo "$XEN_SRC_DIR/$rel" ;;
    esac
}

variant_sha() {
    local vdir=$1 rel
    for rel in "${MODIFIED[@]}"; do cat "$(source_of "$vdir" "$rel")"; done | sha256sum | cut -c1-16
}

# Copies the files that differ to dom0, keeping the original of each under REMOTE_STATE/orig,
# at its path in the tree, until search_end puts it back.
upload_variant() {
    local vdir=$1 rel src lsum rsum
    for rel in "${MODIFIED[@]}"; do
        src=$(source_of "$vdir" "$rel")
        lsum=$(md5sum <"$src" | cut -c1-32)
        rsum=$(rsh "md5sum < $REMOTE_XEN/$rel" | cut -c1-32)
        if [[ "$lsum" != "$rsum" ]]; then
            rsh "f=$REMOTE_STATE/orig/$rel && mkdir -p \$(dirname \$f) &&" \
                "{ [ -e \$f ] || cp -p $REMOTE_XEN/$rel \$f; }" \
                || die "Could not keep the original of $rel on dom0"
            rcp_to "$src" "$REMOTE_XEN/$rel"
            say "Uploaded $rel"
        fi
    done
}

# Prints yes when dom0 runs, booted after the install, the Xen built from this sha.
running_variant() {
    rsh "[ \"\$(cat $REMOTE_STATE/installed.sha 2>/dev/null)\" = $1 ] &&" \
        "[ \$(( \$(date +%s) - \$(cut -d. -f1 /proc/uptime) )) -gt \$(stat -c %Y $REMOTE_STATE/installed.sha) ] &&" \
        "grep -qs control_d /proc/xen/capabilities && echo yes || true"
}

# Builds and installs Xen. A build that hangs is killed and run again; one that fails is not.
build_variant() {
    local name=$1 vdir=$2 sha=$3 try rc pin=
    if [[ -n "$BUILD_CPUS" ]]; then
        pin="taskset -cp $BUILD_CPUS \$BASHPID || echo 'BUILD_CPUS $BUILD_CPUS not on this boot: building on every CPU'"
    fi
    for (( try = 1; try <= BUILD_TRIES; try++ )); do
        say "$name: building and installing Xen, try $try of $BUILD_TRIES (log: $vdir/build.log)"
        rc=0
        remote_job "build-$name" "$vdir/build.log" "$BUILD_LIMIT" "$BUILD_STALL" "set -ex; cd $REMOTE_XEN
$pin
sed -i -e 's|^OVMF_UPSTREAM_URL ?= .*|OVMF_UPSTREAM_URL ?= https://github.com/tianocore/edk2.git|' \
       -e 's|^OVMF_UPSTREAM_REVISION ?= .*|OVMF_UPSTREAM_REVISION ?= 4dfdca63a93497203f197ec98ba20e2327e4afe4|' Config.mk
./configure --enable-githttp --enable-systemd --enable-ovmf --disable-pvshim
make -j\$(nproc) dist-xen
make -j\$(nproc) dist-tools
rm -f dist/xen-upstream-*.deb
make -j\$(nproc) debball
dpkg -i dist/xen-upstream-*.deb
ldconfig
echo $sha > $REMOTE_STATE/installed.sha" || rc=$?
        (( rc == 124 )) || return "$rc"
        mv "$vdir/build.log" "$vdir/build-hung-$try.log" 2>/dev/null || true
    done
    return "$rc"
}

# xl debug-keys d may be pressed only once per Xen boot
d_pressed() {
    local answer
    answer=$(rsh "if [ -e $REMOTE_STATE/d-pressed.\$(cat /proc/sys/kernel/random/boot_id) ] ||" \
                 "xl dmesg | grep -q 'RDTSC_POC: compensation enabled'; then echo yes; else echo no; fi") \
        || die "Cannot reach $DOM0"
    [[ "$answer" == yes ]]
}

mark_d_pressed() {
    rsh "mkdir -p $REMOTE_STATE && touch $REMOTE_STATE/d-pressed.\$(cat /proc/sys/kernel/random/boot_id)"
}

# Starts the VNC viewers when VNC=1, on VNC_PORTS if set. Arguments: the VMs' VNC ports
# (vncdisplay 0 and 1 of their cfgs), view only (1) or not (0).
start_vnc() {
    local ports=${VNC_PORTS:-$1}
    (( VNC )) || return 0
    VNC_HOST=$VNC_HOST VNC_PORTS=$ports VNC_VIEW_ONLY=$2 "$SCRIPT_DIR/rdtsc_vnc.sh" >"$RESULTS/vnc.log" 2>&1 &
    vnc_pid=$!    # killed by on_exit
    say "VNC viewers on ports $ports of $VNC_HOST (log: $RESULTS/vnc.log)"
}

# What a search changes on dom0 and search_end puts back: the sources a variant overwrites
# (REMOTE_STATE/orig), the Xen package (REMOTE_STATE/known-good, the one make xen installed,
# taken from REMOTE_XEN/dist) and the GRUB default entry. Before the first variant.
SEARCH_BEGUN=0
SEARCH_ENDED=0
search_begin() {
    local state
    trap on_exit EXIT
    # The search reboots dom0: not under the orchestrator, whose clones and jobs it would kill
    state=$(rsh 'command -v fuser >/dev/null || { echo nofuser; exit 0; }
if fuser -s /run/lock/sandboxd.lock 2>/dev/null; then echo busy; else echo idle; fi') \
        || die "Cannot reach $DOM0"
    case "$state" in
        idle) ;;
        busy) die "sandboxd runs on dom0 (it holds /run/lock/sandboxd.lock): stop it first, the search reboots dom0" ;;
        *) die "dom0 has no fuser to check for a running sandboxd: apt-get install psmisc there" ;;
    esac
    # GRUB cannot clear a one-shot entry on a grubenv it cannot write (LVM, RAID): every boot
    # would then be the variant's
    state=$(rsh "grub-probe --target=abstraction $GRUB_ENV 2>/dev/null || echo unknown")
    [[ -z "$state" ]] || die "GRUB cannot write $GRUB_ENV on dom0 (grub-probe: $state): the search boots Xen with grub-reboot, which needs /boot on a plain partition"
    state=$(rsh "set -e
mkdir -p $REMOTE_STATE
if [ -e $REMOTE_STATE/known-good ] || [ -e $REMOTE_STATE/orig ]; then echo leftover; exit 0; fi
d=\$(ls -t $REMOTE_XEN/dist/xen-upstream-*.deb 2>/dev/null | head -1)
[ -n \"\$d\" ] || { echo nodeb; exit 0; }
if [ -e $REMOTE_STATE/installed.sha ] && ! [ \"\$d\" -nt $REMOTE_STATE/installed.sha ]; then echo variant; exit 0; fi
mkdir -p $REMOTE_STATE/known-good && cp -p \"\$d\" $REMOTE_STATE/known-good/ && rm -f $REMOTE_STATE/installed.sha
echo \"saved \$(sha256sum \"\$d\" | cut -c1-16)\"") || die "Could not keep the Xen package on dom0"
    case "$state" in
        saved*)
            say "Xen package make xen installed, kept to put back: $REMOTE_XEN/dist (${state#saved })" ;;
        leftover)
            die "A previous search did not put dom0 back ($REMOTE_STATE/known-good or $REMOTE_STATE/orig exists): run $SCRIPT_DIR/restore_dom0.sh, or delete them if make xen has been run on dom0 since (README.md, \"If a search stops\")" ;;
        nodeb)
            die "No package in $DOM0:$REMOTE_XEN/dist: run make xen on dom0 first, its package is what the search puts back" ;;
        variant)
            die "dom0's Xen is a search variant ($REMOTE_STATE/installed.sha is newer than the package in $REMOTE_XEN/dist): run make xen on dom0 first" ;;
        *) die "Unexpected answer from dom0: $state" ;;
    esac
    SEARCH_BEGUN=1
    set_grub_default native
}

# Puts dom0 back as make xen left it, in the order a failure leaves the safest state: the
# sources, then the package (installed on the plain kernel, as the variants are), then Xen as
# the default entry, booted. Runs when a search ends, however it ends (on_exit); on its own
# from restore_dom0.sh. Stops at the first failure and says what is left to do.
search_end() {
    (( ! SEARCH_ENDED )) || return 0
    SEARCH_ENDED=1
    say "Putting dom0 back as make xen left it"
    rsh true || die "dom0 is unreachable. When it is back, run $SCRIPT_DIR/restore_dom0.sh (README.md, \"If a search stops\")"
    # The package is installed on the plain kernel, as the variants are; nothing to install
    # (restore_dom0.sh after a search that got that far) skips that boot
    [[ -z "$(rsh "ls $REMOTE_STATE/known-good/xen-upstream-*.deb 2>/dev/null")" ]] || reboot_to native
    rsh "set -e; cd $REMOTE_STATE/orig 2>/dev/null || exit 0
for f in \$(find . -type f); do cp -p \"\$f\" \"$REMOTE_XEN/\$f\"; done
cd / && rm -r $REMOTE_STATE/orig" \
        || die "Could not put the sources back from $DOM0:$REMOTE_STATE/orig into $REMOTE_XEN. Left to do: that, then dpkg -i $REMOTE_STATE/known-good/*.deb, then Xen as the GRUB default (README.md, \"If a search stops\")"
    say "Sources in $REMOTE_XEN as make xen left them"
    rsh "set -e; d=\$(ls $REMOTE_STATE/known-good/xen-upstream-*.deb 2>/dev/null | head -1); [ -n \"\$d\" ] || exit 0
dpkg -i \"\$d\" && ldconfig
cp -p \"\$d\" $REMOTE_XEN/dist/ && rm -f $REMOTE_STATE/installed.sha && rm -r $REMOTE_STATE/known-good" \
        >>"$RESULTS/restore.log" 2>&1 \
        || die "Could not install $DOM0:$REMOTE_STATE/known-good/*.deb, see $RESULTS/restore.log. Left to do: that, then Xen as the GRUB default (README.md, \"If a search stops\")"
    say "make xen's Xen package installed again"
    set_grub_default xen
    reboot_to xen
    say "dom0 runs make xen's Xen, the default entry again"
}

on_exit() {
    local rc=$?
    trap - EXIT
    [[ -z "${vnc_pid-}" ]] || kill "$vnc_pid" 2>/dev/null || true
    if (( SEARCH_BEGUN )); then
        search_end
    fi
    exit "$rc"
}