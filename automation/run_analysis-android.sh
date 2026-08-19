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
# Running this alongside run_analysis-ubuntu.sh is SUPPORTED as of
# DRAFT-036's VLAN lease -- it was previously refused outright. See the
# concurrency note below for the one thing that is still per-watcher.

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

# dirwatch reads its VLAN pool from the environment rather than argv: the
# 15-argument contract is per-watcher and TOTAL_VLANS is host-global, so it
# does not belong in a positional slot every launcher sets independently.
# Same mechanism clone.pl already uses for VG_NAME (DRAFT-036).
#
# DRAKVUF_ANALYSIS_BRIDGE lets dirwatch check that a leased VLAN's
# sub-interface actually exists before a clone is attached to it.
DRAKVUF_TOTAL_VLANS="$TOTAL_VLANS"
DRAKVUF_ANALYSIS_BRIDGE="$ANALYSIS_BRIDGE"
export DRAKVUF_TOTAL_VLANS DRAKVUF_ANALYSIS_BRIDGE

# This clone's configured memory, read from the .cfg so admission cannot
# disagree with what the domain is built with. Identical to Ubuntu's --
# see run_analysis-ubuntu.sh for why it is parsed here rather than in C.
DRAKVUF_CLONE_MEMORY_MIB="$(
    awk -F= '/^[[:space:]]*memory[[:space:]]*=/ {
        gsub(/[^0-9]/, "", $2); print $2; exit
    }' "$DOMAIN_CONFIG"
)"
export DRAKVUF_CLONE_MEMORY_MIB

if [ -z "$DRAKVUF_CLONE_MEMORY_MIB" ]; then
    echo "run_analysis-android.sh: could not read 'memory =' from $DOMAIN_CONFIG;" >&2
    echo "  starting WITHOUT memory admission -- clones will be limited only" >&2
    echo "  by MAX_CLONES, and concurrent watchers can overcommit the host." >&2
fi

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

# --- Concurrency ---------------------------------------------------------
#
# The pgrep guard that stood here is REMOVED, and its removal is the point
# of DRAFT-036's first half rather than a relaxation of it. Kept identical
# to Ubuntu's, since the two launchers are meant to stay diffable -- see
# run_analysis-ubuntu.sh for the full reasoning and for what remains open
# (memory admission, still per-watcher and still able to overcommit).
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
if ! "$SCRIPT_DIR/network-setup.sh" "$TOTAL_VLANS"; then
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