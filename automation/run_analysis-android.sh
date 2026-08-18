#!/bin/bash
#
# Top-level entry point for the Android (BlissOS) analysis pipeline.
#
# The Android counterpart of run_analysis-ubuntu.sh, and deliberately as
# close to it as the two targets allow: everything that differs comes from
# pipeline-android.env, so the two launchers should stay diffable. A
# divergence between them that is not explained in a comment is a defect.
#
# Runnable from any directory and from a checkout at any path: every
# repository-owned asset is resolved from this script's own location, not
# from $PWD, ~, or a deployment path baked in at authoring time.
#
# DO NOT RUN THIS ALONGSIDE run_analysis-ubuntu.sh. See the concurrency
# guard below -- it is a real collision, not a caution.

# Real line-1 shebang, so this genuinely runs under bash -- unlike the
# worker scripts, whose shebangs sit below the DRAKVUF license header.
# $0 is used anyway so the idiom is identical across the launchers.
SCRIPT_DIR="$(
    cd -- "$(dirname -- "$0")" &&
    pwd
)"

REPO_ROOT="$(
    cd -- "$SCRIPT_DIR/.." &&
    pwd
)"

# Host-global values first, per-OS second, so a pipeline-<os>.env that
# wrongly redefines one of them would at least be visibly last-wins rather
# than silently first-wins. C4 forbids it defining any of them at all;
# this ordering is a backstop, not the check.
# shellcheck source=automation/platform.env
. "$SCRIPT_DIR/platform.env"

# shellcheck source=automation/pipeline-android.env
. "$SCRIPT_DIR/pipeline-android.env"

# clone.pl is Perl and reads no config file: it takes its 3 arguments from
# dirwatch's fixed CLONE_CMD contract and everything else from the
# environment, so these have to be exported to reach it.
#
# CLONE_LV_SIZE matters more here than it does for Ubuntu. clone.pl's
# fallback is 64G, which is Ubuntu's correct value and twice what an
# Android clone needs -- so if this export is ever dropped the clone still
# works and merely over-allocates. It fails silently, which is why the
# check after a first run is `lvs` showing 32,00g rather than "the clone
# came up".
export CLONE_LV_SIZE VG_NAME ANALYSIS_BRIDGE

# Fail before starting anything rather than after a clone is already
# running. A missing profile or saved state would otherwise surface as an
# opaque `xl restore` error several steps into a per-sample run.
#
# profiles/*.json and state/*.bak are NOT git-tracked, so a fresh checkout
# has neither and this is where that shows up.
for asset in "$DOMAIN_CONFIG" "$KERNEL_PROFILE" "$SAVED_STATE"; do
    if [ ! -r "$asset" ]; then
        echo "run_analysis-android.sh: missing or unreadable: $asset" >&2
        echo "  (repo root resolved to: $REPO_ROOT)" >&2
        exit 1
    fi
done

# The two Android worker scripts, which DRAFT-016 owns. Checked here
# because dirwatch does not: it takes their paths as strings and a missing
# script surfaces as a spawn failure per sample, once per clone, forever.
for worker in "$SCRIPT_DIR/preconfig-android.sh" "$SCRIPT_DIR/drakvuf-android.sh"; do
    if [ ! -x "$worker" ]; then
        echo "run_analysis-android.sh: missing or not executable: $worker" >&2
        echo "  Android's worker scripts are DRAFT-016. Until they exist," >&2
        echo "  this launcher has nothing to run per sample." >&2
        exit 1
    fi
done

# --- Concurrency guard --------------------------------------------------
#
# KNOWN GAP (DRAFT-036), enforced here rather than documented and hoped
# for. dirwatch derives each clone's VLAN from its worker-slot index and
# the slot array is process-local, so a second dirwatch allocates VLANs
# 1..MAX_CLONES exactly as the first one did. Two pipelines then share
# gateway addresses, VLAN sub-interfaces and isolation rules, and the only
# symptom is analyses that interfere with each other.
#
# Nothing in dirwatch detects this. A pgrep is a weak check -- it races,
# and it cannot see a watcher on another host -- but the failure it
# prevents is silent cross-contamination between two malware analyses,
# which is worth a weak check rather than none. Remove it when DRAFT-036
# lands a host-global VLAN allocator, not before.
if pgrep -f "[d]irwatch .* $REPO_ROOT/automation/clone.pl" >/dev/null 2>&1; then
    echo "run_analysis-android.sh: another dirwatch is already running from" >&2
    echo "  this checkout. Its clones use VLANs 1..MAX_CLONES and so would" >&2
    echo "  these -- they would collide on gateway addresses and isolation" >&2
    echo "  rules, and nothing would report it (DRAFT-036)." >&2
    echo "  Stop the running launcher first." >&2
    exit 1
fi

# Runtime data directories, one level per target OS. Created here so a
# fresh Dom0 needs no manual mkdir beyond the three top-level /malware_*
# directories from the setup guide.
mkdir -p -- "$WATCH_FOLDER" "$SERVE_FOLDER" "$OUTPUT_FOLDER" || exit 1

ip link set "$ANALYSIS_BRIDGE" up

# The argument here is the VLAN/clone count and MUST match the max-clones
# argument to dirwatch below: it sizes the worker pool on one side and the
# number of <bridge>.<n> sub-interfaces that must already exist on the
# other. Both come from MAX_CLONES so they cannot be raised independently.
#
# The exit status is checked: a half-provisioned analysis network is worse
# than none, because it looks like a working one -- clones would run with
# no inter-clone isolation, no LAN block and no Dom0 protection, and
# nothing would say so.
if ! "$SCRIPT_DIR/network-setup.sh" "$MAX_CLONES"; then
    echo "run_analysis-android.sh: network provisioning failed; refusing to start dirwatch" >&2
    exit 1
fi

# dirwatch takes 14 positional arguments in a fixed order and validates
# only the count. There are no flags and no defaults, so every value below
# is required and order-sensitive. The order is identical to Ubuntu's --
# it is dirwatch's contract, not a per-OS choice.
#
# Argument 10 is the SHARED clone.pl, not a clone-android.pl: the clone
# step holds no OS-specific value, and pointing a per-OS launcher at a
# shared script is a per-OS decision made in a per-OS file, so nothing
# becomes OS-aware (DRAFT-015; C1/C2 in analysis-pipeline.md).
dirwatch "$WATCH_MODE" \
    "$SANDBOX_DOMAIN" \
    "$DOMAIN_CONFIG" \
    "$KERNEL_PROFILE" \
    "$INJECTION_PID" \
    "$WATCH_FOLDER" \
    "$SERVE_FOLDER" \
    "$OUTPUT_FOLDER" \
    "$MAX_CLONES" \
    "$SCRIPT_DIR/clone.pl" \
    "$SCRIPT_DIR/preconfig-android.sh" \
    "$SCRIPT_DIR/drakvuf-android.sh" \
    "$SCRIPT_DIR/cleanup.sh" \
    "$SCRIPT_DIR/tcpdump.sh"

# In order, the arguments above are:
#
#   1   watch mode: 1 = inotify poll, 0 = 1s sleep loop
#   2   origin domain -- the sandbox TEMPLATE (android_sandbox), not the
#       golden android. dirwatch hard-codes one origin per invocation,
#       which IS the OS-selection mechanism (issue #3).
#   3   Xen config for that origin, used by clone.pl
#   4   LibVMI kernel profile, passed straight through to drakvuf/injector
#       as -r. Clone domains have no /etc/libvmi.conf stanza, so this
#       argument is the only way the profile is ever resolved.
#   5   injection PID: a long-lived process already running inside the
#       saved memory image, which injector attaches to. It is a property
#       of android_sandbox.bak, not of this script -- re-saving the
#       template almost certainly changes it, and a stale value fails
#       silently. See pipeline-android.env.
#   6   watch folder    (samples land here)
#   7   serve folder    (sample moved here for the duration of the run)
#   8   output folder   (results at <sha256>/<utime>-<vlan>, one
#       directory per RUN rather than per sample -- see preconfig-ubuntu.sh)
#   9   max clones -- see the network-setup.sh note above
#  10   clone script     ) called per sample in this order, with
#  11   preconfig script ) tcpdump started on a side thread.
#  12   drakvuf script   ) 60s timeout guards preconfig, 180s guards the
#  13   cleanup script   ) trace; either fires cleanup and a fresh clone.
#  14   tcpdump script   )
#
# Full contract: docs/architecture/analysis-pipeline.md.