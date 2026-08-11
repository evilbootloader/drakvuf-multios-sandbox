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

# shellcheck source=automation/pipeline-ubuntu.env
. "$SCRIPT_DIR/pipeline-ubuntu.env"

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

# Runtime data directories, one level per target OS. Created here so a
# fresh Dom0 needs no manual mkdir beyond the three top-level
# /malware_* directories from the setup guide. Not repo-relative and
# deliberately not made configurable -- see pipeline-ubuntu.env.
mkdir -p -- "$WATCH_FOLDER" "$SERVE_FOLDER" "$OUTPUT_FOLDER" || exit 1

ip link set "$ANALYSIS_BRIDGE" up

# The argument here is the VLAN/clone count and MUST match the max-clones
# argument to dirwatch below: it sizes the worker pool on one side and the
# number of xenbr1.<n> sub-interfaces that must already exist on the other.
# Raise one without the other and clones are handed a VLAN with no gateway.
# Both now come from MAX_CLONES so they cannot be raised independently.
#
# The exit status is checked as of DRAFT-028. It was previously discarded,
# which mattered because network-setup.sh could not fail: it had no
# `set -e` and checked nothing, so a rejected iptables rule left the
# analysis network half-provisioned and the pipeline started anyway. A
# half-provisioned analysis network is worse than none, because it looks
# like a working one -- clones would run with no inter-clone isolation, no
# LAN block and no Dom0 protection, and nothing would say so.
if ! "$SCRIPT_DIR/network-setup.sh" "$MAX_CLONES"; then
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
    "$SCRIPT_DIR/clone-ubuntu.pl" \
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
#   3   Xen config for that origin, used by clone-ubuntu.pl
#   4   LibVMI kernel profile, passed straight through to drakvuf/injector
#       as -r. Clone domains have no /etc/libvmi.conf stanza, so this
#       argument is the only way the profile is ever resolved.
#   5   injection PID: a long-lived process already running inside the
#       saved memory image, which injector attaches to. It is a property of
#       ubuntu_sandbox.bak, not of this script -- re-saving the template
#       almost certainly changes it.
#   6   watch folder    (samples land here)
#   7   serve folder    (sample moved here for the duration of the run)
#   8   output folder   (per-sample results, keyed by MD5)
#   9   max clones -- see the network-setup.sh note above
#  10   clone script     ) called per sample in this order, with
#  11   preconfig script ) tcpdump started on a side thread.
#  12   drakvuf script   ) 60s timeout guards preconfig, 180s guards the
#  13   cleanup script   ) trace; either fires cleanup and a fresh clone.
#  14   tcpdump script   )
#
# Full contract: docs/architecture/analysis-pipeline.md.