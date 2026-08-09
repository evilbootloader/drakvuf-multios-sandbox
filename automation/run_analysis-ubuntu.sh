#!/bin/bash


ip link set xenbr1 up
# The argument here is the VLAN/clone count and MUST match the max-clones
# argument to dirwatch below: it sizes the worker pool on one side and the
# number of xenbr1.<n> sub-interfaces that must already exist on the other.
# Raise one without the other and clones are handed a VLAN with no gateway.
/home/user/drakvuf-tools/network-setup.sh 2

# dirwatch takes 14 positional arguments in a fixed order and validates
# only the count -- `argc != 15` at automation/dirwatch.c:453, which counts
# argv[0] and is where the docs' "15-argument contract" phrasing comes
# from. There are no flags and no defaults, so every value below is
# required and order-sensitive.
dirwatch 1 \
    ubuntu_sandbox \
    /home/user/drakvuf-tools/ubuntu_sandbox.cfg \
    /root/linux.json \
    1415 \
    /malware_incoming \
    /malware_processing \
    /malware_finished \
    2 \
    /home/user/drakvuf-tools/clone-ubuntu.pl \
    /home/user/drakvuf-tools/preconfig-ubuntu.sh \
    /home/user/drakvuf-tools/drakvuf-ubuntu.sh \
    /home/user/drakvuf-tools/cleanup.sh \
    /home/user/drakvuf-tools/tcpdump.sh

# In order, the arguments above are:
#
#   1   watch mode: 1 = inotify poll, 0 = 1s sleep loop
#   2   origin domain -- the sandbox TEMPLATE (ubuntu_sandbox), not the
#       golden ubuntu. dirwatch hard-codes one origin per invocation, so a
#       second OS pipeline means a second dirwatch process.
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
