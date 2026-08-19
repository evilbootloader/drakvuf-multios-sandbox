#!/bin/bash
#
# Top-level entry point for the Ubuntu analysis pipeline.
#
# Runnable from any directory and from a checkout at any path: every
# repository-owned asset below is resolved from this script's own
# location, not from $PWD, ~, or a deployment path baked in at authoring
# time (issue #4). The previous version hard-coded six
# /home/user/drakvuf-tools/... arguments and a bare /root/linux.json,
# none of which matched where this repository actually lives.

# This script does have a real line-1 shebang and so genuinely runs under
# bash -- unlike its siblings, whose shebangs sit below the DRAKVUF
# license header (see preconfig-ubuntu.sh). $0 is used anyway, so the
# idiom is identical in all four files and nobody has to remember which
# ones may use bash-only syntax.
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

# shellcheck source=automation/pipeline-ubuntu.env
. "$SCRIPT_DIR/pipeline-ubuntu.env"

# clone.pl is Perl and reads no config file: it takes its 3 arguments from
# dirwatch's fixed CLONE_CMD contract and everything else from the
# environment. Sourcing the file above makes CLONE_LV_SIZE a shell
# variable in THIS process only -- it has to be exported to reach a child
# (DRAFT-015).
#
# Nothing fails loudly if these are deleted. clone.pl falls back to its own
# defaults, which are correct for Ubuntu and silently wrong for every other
# pipeline, so the regression would first appear as an over-sized Android
# snapshot rather than as an error.
#
# VG_NAME and ANALYSIS_BRIDGE come from platform.env and are host-global;
# CLONE_LV_SIZE comes from pipeline-ubuntu.env and is per-OS. All three are
# exported together because clone.pl reads all three the same way.
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

# Memory admission needs this clone's configured size. It is READ FROM THE
# .cfg rather than configured separately, so the Xen config stays the
# single source of truth: nobody types the number twice, and admission
# cannot disagree with what the domain is actually built with.
#
# Parsed here rather than in dirwatch.c because that would mean a Xen
# config parser in C for one integer, and the shell already has the file
# open. dirwatch treats an empty or zero value as "admission disabled"
# rather than as "zero memory", so a .cfg this fails to match degrades to
# the old slot-count behaviour instead of refusing every clone.
DRAKVUF_CLONE_MEMORY_MIB="$(
    awk -F= '/^[[:space:]]*memory[[:space:]]*=/ {
        gsub(/[^0-9]/, "", $2); print $2; exit
    }' "$DOMAIN_CONFIG"
)"
export DRAKVUF_CLONE_MEMORY_MIB

if [ -z "$DRAKVUF_CLONE_MEMORY_MIB" ]; then
    echo "run_analysis-ubuntu.sh: could not read 'memory =' from $DOMAIN_CONFIG;" >&2
    echo "  starting WITHOUT memory admission -- clones will be limited only" >&2
    echo "  by MAX_CLONES, and concurrent watchers can overcommit the host." >&2
fi

# Fail before starting anything rather than after a clone is already
# running. A missing profile or saved state used to surface as an opaque
# `xl restore` error several steps into a per-sample run; the launcher is
# the cheapest place to catch it, and these are exactly the paths issue
# #4 moved, so a stale deployment shows up here first.
for asset in "$DOMAIN_CONFIG" "$KERNEL_PROFILE" "$SAVED_STATE"; do
    if [ ! -r "$asset" ]; then
        echo "run_analysis-ubuntu.sh: missing or unreadable: $asset" >&2
        echo "  (repo root resolved to: $REPO_ROOT)" >&2
        exit 1
    fi
done

# --- Concurrency ---------------------------------------------------------
#
# The pgrep guard that stood here is REMOVED, and its removal is the point
# of DRAFT-036's first half rather than a relaxation of it. It refused to
# start when another dirwatch was running, because the worker-slot index
# was the VLAN and a second watcher re-allocated VLAN 1: two clones on one
# segment, sharing 172.16.1.2, with no rule between them and no symptom in
# any log. Its own comment said "remove it when DRAFT-036 lands a
# host-global VLAN allocator, not before" -- that allocator is now the
# flock'd lease pool under $DRAKVUF_LEASE_DIR, and VLANs no longer collide.
#
# WHAT IS STILL OPEN, so this is not read as "concurrency is solved":
# admission is still a fixed per-watcher MAX_CLONES rather than host memory
# (DRAFT-036's second half, gated on measuring whether a clone is bounded
# by its .cfg at all). Two watchers can therefore still overcommit the host
# between them. That failure is loud and local -- a failed or OOM-killed
# `xl restore` on one clone -- rather than silent cross-contamination
# between two analyses, which is why it does not warrant blocking a launch
# the way the VLAN collision did. Keep the sum of every running watcher's
# MAX_CLONES within what the host can afford until admission lands.
# Runtime data directories, one level per target OS. Created here so a
# fresh Dom0 needs no manual mkdir beyond the three top-level
# /malware_* directories from the setup guide. Not repo-relative and
# deliberately not made configurable -- see pipeline-ubuntu.env.
mkdir -p -- "$WATCH_FOLDER" "$SERVE_FOLDER" "$OUTPUT_FOLDER" || exit 1

ip link set "$ANALYSIS_BRIDGE" up

# The argument is TOTAL_VLANS, not MAX_CLONES, as of DRAFT-036. It used to
# have to match dirwatch's max-clones exactly, because the worker-slot
# index WAS the VLAN. It no longer is: dirwatch leases a VLAN from a
# host-global pool, so what must exist is one sub-interface per pool entry,
# independent of how many workers any single watcher runs.
#
# This is also what lets two launchers coexist. Both provision the same
# 1..TOTAL_VLANS -- the loop is idempotent by reuse, and every isolation
# rule matches the `<bridge>.+` wildcard rather than a specific id, so the
# second run neither duplicates interfaces nor narrows the first's rules.
#
# The exit status is checked as of DRAFT-028. It was previously discarded,
# which mattered because network-setup.sh could not fail: it had no
# `set -e` and checked nothing, so a rejected iptables rule left the
# analysis network half-provisioned and the pipeline started anyway. A
# half-provisioned analysis network is worse than none, because it looks
# like a working one -- clones would run with no inter-clone isolation, no
# LAN block and no Dom0 protection, and nothing would say so.
if ! "$SCRIPT_DIR/network-setup.sh" "$TOTAL_VLANS"; then
    echo "run_analysis-ubuntu.sh: network provisioning failed; refusing to start dirwatch" >&2
    exit 1
fi

# dirwatch takes 14 positional arguments in a fixed order and validates
# only the count -- `argc != 15` at automation/dirwatch.c:453, which counts
# argv[0] and is where the docs' "15-argument contract" phrasing comes
# from. There are no flags and no defaults, so every value below is
# required and order-sensitive. Issue #4 changed only the values, never
# the contract or the order.
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
    "$SCRIPT_DIR/preconfig-ubuntu.sh" \
    "$SCRIPT_DIR/drakvuf-ubuntu.sh" \
    "$SCRIPT_DIR/cleanup.sh" \
    "$SCRIPT_DIR/tcpdump.sh"

# In order, the arguments above are:
#
#   1   watch mode: 1 = inotify poll, 0 = 1s sleep loop
#   2   origin domain -- the sandbox TEMPLATE (ubuntu_sandbox), not the
#       golden ubuntu. dirwatch hard-codes one origin per invocation, so a
#       second OS pipeline means a second dirwatch process, launched from
#       its own run_analysis-<os>.sh and its own pipeline-<os>.env.
#   3   Xen config for that origin, used by clone.pl
#   4   LibVMI kernel profile, passed straight through to drakvuf/injector
#       as -r. Clone domains have no /etc/libvmi.conf stanza, so this
#       argument is the only way the profile is ever resolved.
#   5   injection PID: a long-lived process already running inside the
#       saved memory image, which injector attaches to. It is a property of
#       ubuntu_sandbox.bak, not of this script -- re-saving the template
#       almost certainly changes it.
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