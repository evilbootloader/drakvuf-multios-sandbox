#!/bin/sh
#********************IMPORTANT DRAKVUF LICENSE TERMS*********************#
#                                                                        #
# DRAKVUF (C) 2014-2024 Tamas K Lengyel.                                 #
# Tamas K Lengyel is hereinafter referred to as the author.              #
# This program is free software; you may redistribute and/or modify it   #
# under the terms of the GNU General Public License as published by the  #
# Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE  #
# CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your  #
# right to use, modify, and redistribute this software under certain     #
# conditions.  If you wish to embed DRAKVUF technology into proprietary  #
# software, alternative licenses can be aquired from the author.         #
#                                                                        #
# Note that the GPL places important restrictions on "derivative works", #
# yet it does not provide a detailed definition of that term.  To avoid  #
# misunderstandings, we interpret that term as broadly as copyright law  #
# allows.  For example, we consider an application to constitute a       #
# derivative work for the purpose of this license if it does any of the  #
# following with any software or content covered by this license         #
# ("Covered Software"):                                                  #
#                                                                        #
# o Integrates source code from Covered Software.                        #
#                                                                        #
# o Reads or includes copyrighted data files.                            #
#                                                                        #
# o Is designed specifically to execute Covered Software and parse the   #
# results (as opposed to typical shell or execution-menu apps, which will#
# execute anything you tell them to).                                    #
#                                                                        #
# o Includes Covered Software in a proprietary executable installer.  The#
# installers produced by InstallShield are an example of this.  Including#
# DRAKVUF with other software in compressed or archival form does not    #
# trigger this provision, provided appropriate open source decompression #
# or de-archiving software is widely available for no charge.  For the   #
# purposes of this license, an installer is considered to include Covered#
# Software even if it actually retrieves a copy of Covered Software from #
# another source during runtime (such as by downloading it from the      #
# Internet).                                                             #
#                                                                        #
# o Links (statically or dynamically) to a library which does any of the #
# above.                                                                 #
#                                                                        #
# o Executes a helper program, module, or script to do any of the above. #
#                                                                        #
# This list is not exclusive, but is meant to clarify our interpretation #
# of derived works with some common examples.  Other people may interpret#
# the plain GPL differently, so we consider this a special exception to  #
# the GPL that we apply to Covered Software.  Works which meet any of    #
# these conditions must conform to all of the terms of this license,     #
# particularly including the GPL Section 3 requirements of providing     #
# source code and allowing free redistribution of the work as a whole.   #
#                                                                        #
# Any redistribution of Covered Software, including any derived works,   #
# must obey and carry forward all of the terms of this license, including#
# obeying all GPL rules and restrictions.  For example, source code of   #
# the whole work must be provided and free redistribution must be        #
# allowed.  All GPL references to "this License", are to be treated as   #
# including the terms and conditions of this license text as well.       #
#                                                                        #
# Because this license imposes special exceptions to the GPL, Covered    #
# Work may not be combined (even as part of a larger work) with plain GPL#
# software.  The terms, conditions, and exceptions of this license must  #
# be included as well.  This license is incompatible with some other open#
# source licenses as well.  In some cases we can relicense portions of   #
# DRAKVUF or grant special permissions to use it in other open source    #
# software.  Please contact tamas.k.lengyel@gmail.com with any such      #
# requests.  Similarly, we don't incorporate incompatible open source    #
# software into Covered Software without special permission from the     #
# copyright holders.                                                     #
#                                                                        #
# If you have any questions about the licensing restrictions on using    #
# DRAKVUF in other works, are happy to help.  As mentioned above,        #
# alternative license can be requested from the author to integrate      #
# DRAKVUF into proprietary applications and appliances.  Please email    #
# tamas.k.lengyel@gmail.com for further information.                     #
#                                                                        #
# If you have received a written license agreement or contract for       #
# Covered Software stating terms other than these, you may choose to use #
# and redistribute Covered Software under those terms instead of these.  #
#                                                                        #
# Source is provided to this software because we believe users have a    #
# right to know exactly what a program is going to do before they run it.#
# This also allows you to audit the software for security holes.         #
#                                                                        #
# Source code also allows you to port DRAKVUF to new platforms, fix bugs,#
# and add new features.  You are highly encouraged to submit your changes#
# on https://github.com/tklengyel/drakvuf, or by other methods.          #
# By sending these changes, it is understood (unless you specify         #
# otherwise) that you are offering unlimited, non-exclusive right to     #
# reuse, modify, and relicense the code.  DRAKVUF will always be         #
# available Open Source, but this is important because the inability to  #
# relicense code has caused devastating problems for other Free Software #
# projects (such as KDE and NASM).                                       #
# To specify special license conditions of your contributions, just say  #
# so when you send them.                                                 #
#                                                                        #
# This program is distributed in the hope that it will be useful, but    #
# WITHOUT ANY WARRANTY; without even the implied warranty of             #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF  #
# license file for more details (it's in a COPYING file included with    #
# DRAKVUF, and also available from                                       #
# https://github.com/tklengyel/drakvuf/COPYING)                          #
#                                                                        #
#************************************************************************#
#
# Provisions the per-clone analysis network: one VLAN sub-interface of
# xenbr1 per clone slot, each with its own /24 gateway.
#
# It does NOT create the OVS bridge. xenbr1 is created once at install
# time (`ovs-vsctl add-br xenbr1`); this script only brings it up, and
# fails with a clear message if it is missing.
#
# xenbr0 (uplink) and xenbr1 (analysis bridge) are project-wide fixed
# names, hard-coded across clone-ubuntu.pl, preconfig-ubuntu.sh,
# tcpdump.sh, all four misc/*.cfg and CLAUDE.md's naming tables.
# Renaming them here alone is not enough.
#
# Shared by all three OS pipelines -- a defect here is a defect in the
# Ubuntu, Android and Windows analysis networks simultaneously.
#
# The containment posture it installs, as of DRAFT-028 (2026-08-11):
#
#   clone -> clone            DROP  (two independent rules)
#   clone -> LAN / RFC1918    DROP  (incl. the router's admin interface)
#   clone -> link-local       DROP  (incl. 169.254.169.254 metadata)
#   clone -> Dom0 itself      DROP  (INPUT chain; replies to Dom0-initiated
#                                    traffic still allowed)
#   clone -> Internet         ALLOW (MASQUERADE out the uplink)
#   clone -> anything, IPv6   DROP  (FORWARD and INPUT, no exceptions)
#
# All of it lives in five dedicated chains -- DRAKVUF_NAT,
# DRAKVUF_ISOLATION and DRAKVUF_INPUT for IPv4, plus DRAKVUF_ISOLATION6
# and DRAKVUF_INPUT6 for IPv6 -- so the whole posture is readable as a unit
# with `iptables -S DRAKVUF_ISOLATION` and removable in five flushes.
#
# Every one of those chains is TERMINAL for analysis-VLAN traffic as of
# DRAFT-029 (2026-08-12): no packet with xenbr1.<n> as its input or output
# interface reaches FORWARD's or INPUT's default policy, in either address
# family. The posture above therefore holds whatever `-P FORWARD` and
# `-P INPUT` are set to. This script sets neither, deliberately -- see
# section 6.
#
# Idempotent: the chains are flushed and rebuilt on every run, so repeated
# invocations converge instead of appending. run_analysis-ubuntu.sh calls
# this on every launch, and now aborts if it fails. An aborted run leaves
# DRAKVUF_ISOLATION denying rather than empty; that is the on_exit trap
# below, and it will cut the network of any clone already running.
#
# NOT covered, and still open: Android's reaction to an unreachable gateway
# is untested (DRAFT-013 -- it does connectivity probing and may mark the
# network unvalidated, which Ubuntu never checks), and clones retain
# deliberate unrestricted Internet egress (DRAFT-022, roadmap risk #13).
#
# Usage: ./network-setup.sh <number of clone slots>

# --- Section 1: shell safety and arguments ------------------------------

# POSIX only. This file is interpreted by /bin/sh (dash), so `set -E`,
# `set -o pipefail` and `trap ... ERR` are all unavailable: the first two
# are undefined in POSIX sh, and the third is a hard "bad trap" error under
# dash. `pipefail` in particular only reached dash in 0.5.12, while the
# Dom0 host runs Ubuntu 22.04 with an older one -- it would work in the
# development container and fail on the host. `set -eu` plus an EXIT trap
# is the portable equivalent, and shellcheck enforces the distinction for
# this shebang (SC3040/SC3041/SC3047).
#
# `-e` is the "fail loudly" fix itself: before it, every rule below was
# added with no exit-status check anywhere, so a rejected rule left the
# analysis network half-provisioned and said nothing.
set -eu

# Names the phase in progress so the EXIT trap can report where a failure
# happened. Assigned before the trap is installed so `set -u` cannot fire
# inside the handler itself.
step="startup"

# POSIX equivalent of an ERR trap. Without it `set -e` aborts silently and
# a broken analysis network has to be diagnosed from nothing.
#
# Written as a function rather than an inline trap string so `rc=$?` is a
# visible assignment: shellcheck cannot follow assign-then-use inside a
# quoted trap argument and reports SC2154 on it.
on_exit() {
    rc=$?
    if [ "$rc" -eq 0 ]; then
        return 0
    fi
    echo "network-setup.sh: FAILED during: $step (exit $rc)" >&2

    # Fail closed. Section 6 flushes DRAKVUF_ISOLATION and repopulates it;
    # the jump from FORWARD stays installed throughout, and FORWARD's policy
    # on this host is ACCEPT. Exiting with the chain empty would therefore
    # permit everything the chain exists to deny -- strictly worse than the
    # state before the run, because a populated chain has been replaced by
    # an inert one. That is NET-01's shape a second time: a rule present,
    # visible in `iptables -S`, and matching nothing.
    #
    # Denying instead cuts the network of any clone mid-analysis. That is
    # the intended trade: a half-provisioned network that looks like it
    # works is the failure mode this script was rewritten to stop having.
    #
    # `set +e` is required, not tidiness: this handler runs with -e still
    # in effect, so a failing recovery command would abort the handler and
    # leave exactly the state it exists to prevent.
    set +e

    # Both names are assigned below this point, so under `set -u` a bare
    # expansion would itself fail here on any early exit -- an argument
    # error, or a missing bridge. Before section 4 there is no chain to
    # secure and nothing to do.
    chain="${ISOLATION_CHAIN:-}"
    iface="${ANALYSIS_BRIDGE:-}"
    if [ -n "$chain" ] && [ -n "$iface" ] && iptables -S "$chain" >/dev/null 2>&1; then
        iptables -F "$chain"
        iptables -A "$chain" -i "$iface.+" -j DROP
        iptables -A "$chain" -o "$iface.+" -j DROP
        echo "network-setup.sh: $chain left DENYING all analysis-VLAN traffic; re-run to restore" >&2
    fi
}
trap on_exit EXIT

fail() {
    echo "network-setup.sh: $*" >&2
    exit 1
}

step="argument validation"

# `seq 1 $1` with an empty $1 silently produced zero iterations, so a
# missing argument provisioned nothing and still exited 0.
[ $# -eq 1 ] || fail "usage: $0 <number of clone slots>"
case "$1" in
    '' | *[!0-9]*) fail "clone count must be a positive integer, got: '$1'" ;;
esac
[ "$1" -ge 1 ] || fail "clone count must be at least 1, got: $1"

# Upper bound comes from the addressing scheme, not from 802.1Q -- which
# would allow 4094. The slot index is the third octet of 172.16.<slot>.0/24
# (section 5), so 256 is the first value that cannot be expressed at all.
#
# The limit is set at 254 rather than 255: one slot of deliberate margin,
# free because the documented working maximum is 128. To be precise about
# what is NOT the reason -- 172.16.255.1/24 is a perfectly valid host
# address, network 172.16.255.0/24, broadcast 172.16.255.255. Slot 255
# would work. It is excluded by choice, not by arithmetic.
#
# Without any bound the failure is silent until far too late, and does not
# clean up after itself. Evidenced on Dom0 2026-08-12 while testing the
# fail-closed trap: `network-setup.sh 999999` created 255 VLAN
# sub-interfaces and addressed them before `ip addr add 172.16.256.1/24`
# was rejected. The trap secured the firewall chain; the interfaces stayed
# until the next reboot, because nothing removes them.
#
# KNOWN GAP (DRAFT-029 follow-up): interfaces created before ANY mid-loop
# failure are still not cleaned up. This check removes the reachable cause,
# not the consequence.
[ "$1" -le 254 ] || fail \
    "clone count must be at most 254 -- the slot index is the third octet of
  172.16.<slot>.0/24, so 256 and above cannot be addressed. Got: $1"

CLONES="$1"

# --- Section 2: preconditions -------------------------------------------

# Named once here rather than repeated. This is deliberately LOCAL to this
# script and is not the parameterization DRAFT-009 owns: xenbr1 is still
# hard-coded across clone-ubuntu.pl, preconfig-ubuntu.sh, tcpdump.sh,
# drakvuf-ubuntu.sh, cleanup.sh and all four misc/*.cfg, and
# ANALYSIS_BRIDGE in pipeline-ubuntu.env has exactly one consumer.
# Changing the value here renames nothing elsewhere.
UPLINK_BRIDGE=xenbr0
ANALYSIS_BRIDGE=xenbr1

step="checking $ANALYSIS_BRIDGE exists"

# This script does not create the bridge and never has. Without this check
# a missing bridge produces a cascade of downstream `ip` failures instead
# of naming the install step that was skipped.
#
# Checked with `ip link` rather than `ovs-vsctl br-exists`: the stricter
# check would prove the interface is specifically an OVS bridge, but it
# adds a dependency on the OVS CLI and daemon, and answers a question this
# script does not need answered. What matters here is whether VLAN
# sub-interfaces can be attached to it.
ip link show "$ANALYSIS_BRIDGE" >/dev/null 2>&1 || fail \
    "$ANALYSIS_BRIDGE does not exist. It is created once at install time with
  ovs-vsctl add-br $ANALYSIS_BRIDGE
See docs/drakvuf-on-xen-nested-within-proxmox.md."

step="loading the 8021q module"
modprobe 8021q

step="enabling IPv4 forwarding"
echo 1 > /proc/sys/net/ipv4/ip_forward

# --- Section 3: NAT -----------------------------------------------------

# Rules live in dedicated chains rather than directly in POSTROUTING and
# FORWARD. Three practical reasons: the chain can be flushed and rebuilt
# in one step, which makes re-running idempotent by construction rather
# than by check-then-add bookkeeping; `iptables -S DRAKVUF_ISOLATION`
# shows the pipeline's entire containment posture as a unit, which is the
# assertion DRAFT-013 needs; and undoing everything this script did is one
# flush rather than a hunt through chains other tools also write to.
NAT_CHAIN=DRAKVUF_NAT

step="rebuilding $NAT_CHAIN"

# `|| true` is correct here rather than lazy: "chain already exists" is
# success for our purposes, and it is the normal case on every re-run.
iptables -t nat -N "$NAT_CHAIN" 2>/dev/null || true

# The idempotence mechanism. Emptying and rebuilding converges; the
# previous script appended a fresh MASQUERADE to POSTROUTING on every
# launch and never removed one.
iptables -t nat -F "$NAT_CHAIN"

# The jump cannot be flush-and-rebuilt -- it lives in a chain other tools
# also own -- so it is tested for and added only when absent.
iptables -t nat -C POSTROUTING -j "$NAT_CHAIN" 2>/dev/null ||
    iptables -t nat -A POSTROUTING -j "$NAT_CHAIN"

# Gives every analysis clone outbound Internet access. This is the current
# lab's deliberate default, not an oversight -- but there is no offline or
# simulated network mode to switch to yet. The three proposed modes are in
# docs/architecture/networking.md; DRAFT-013 records the observed
# behaviour as a test result before any of them is chosen.
#
# NAT alone reaches the LAN as well as the Internet, because both are
# behind the uplink. Section 6 is what narrows it to the Internet only.
iptables -t nat -A "$NAT_CHAIN" -o "$UPLINK_BRIDGE" -j MASQUERADE

# --- Section 4: isolation chain scaffolding -----------------------------

ISOLATION_CHAIN=DRAKVUF_ISOLATION

step="creating $ISOLATION_CHAIN"

iptables -N "$ISOLATION_CHAIN" 2>/dev/null || true

# The flush deliberately does NOT live here, unlike the other four chains.
# It used to, and the gap between it and the first rule in section 6 spanned
# `ip link set` plus the whole per-clone VLAN loop -- every command of which
# is fatal under `set -eu`, and each one an exit with this chain emptied and
# still jumped to from FORWARD. It is flushed immediately above the rules
# that replace it instead, leaving no window a failure can land in.
#
# Creating the chain and installing the jump are safe here: neither is
# destructive, and both are idempotent.

# Inserted at the HEAD of FORWARD, not appended: a DROP appended below a
# broader ACCEPT never fires.
#
# Position is asserted only when the jump is absent. If another tool later
# inserts above us we leave it alone -- relocating a rule someone else
# placed is a policy decision, not provisioning. This is the one thing
# re-running does NOT converge, and it is deliberate.
iptables -C FORWARD -j "$ISOLATION_CHAIN" 2>/dev/null ||
    iptables -I FORWARD 1 -j "$ISOLATION_CHAIN"

step="bringing $ANALYSIS_BRIDGE up"
ip link set "$ANALYSIS_BRIDGE" up

# --- Section 5: per-clone VLAN sub-interfaces ---------------------------

# A `while` loop rather than `for i in \`seq 1 $1\``: it drops the backtick
# (SC2006's only site in the repository), the unquoted expansion, and the
# dependency on `seq`. `$((i + 1))` is POSIX.
i=1
while [ "$i" -le "$CLONES" ]; do
    vlan_if="$ANALYSIS_BRIDGE.$i"

    # `ip link add link ... type vlan` replaces the deprecated `vconfig
    # add`, which is unmaintained and absent from current distributions.
    #
    # Guarded because these interfaces persist until reboot, so finding one
    # already present is the normal case on a re-run rather than an error.
    step="creating $vlan_if"
    ip link show "$vlan_if" >/dev/null 2>&1 ||
        ip link add link "$ANALYSIS_BRIDGE" name "$vlan_if" type vlan id "$i"

    # Same reasoning, and here the guard is required rather than tidy:
    # `ip addr add` on an existing address exits non-zero, which under
    # `set -e` would now abort the whole script on a normal re-run.
    #
    # The spaces around the pattern and the escaped dots stop
    # 172.16.1.1/24 matching inside 172.16.11.1/24.
    step="addressing $vlan_if"
    ip addr show dev "$vlan_if" | grep -q " 172\.16\.$i\.1/24 " ||
        ip addr add "172.16.$i.1/24" dev "$vlan_if"

    step="bringing $vlan_if up"
    ip link set "$vlan_if" up

    i=$((i + 1))
done

# --- Section 6: what a clone may reach through Dom0 ---------------------

# `xenbr1.+` is an iptables interface wildcard, not a regex: `+` means
# "zero or more characters", so this matches xenbr1.1, xenbr1.2 and so on
# but not the bridge xenbr1 itself -- which is correct, since clones attach
# to the sub-interfaces. Matching the wildcard once keeps this chain a
# fixed nine rules whatever MAX_CLONES is; the per-VLAN form would be nine
# rules per slot, or 1152 at the documented maximum of 128.
#
# The trade-off, recorded because DRAFT-013 may want it back: per-VLAN
# rules would give per-VLAN packet counters, showing WHICH clone attempted
# a blocked connection. The wildcard form gives one counter for all.

step="installing isolation rules"

# Flushed here rather than in section 4, immediately above the rules that
# replace it, so no failure can exit with the chain empty. See the note
# there and the on_exit trap.
iptables -F "$ISOLATION_CHAIN"

# Deny clone-to-clone traffic: anything arriving from an analysis VLAN and
# not leaving via the uplink. This is the rule NET-01 was about -- it was
# written `-o !xenbr0`, the negation form deprecated in iptables 1.4.3
# (2008), which current versions parse as an interface literally named
# "!xenbr0". Combined with the absent exit-status check, a rejected rule
# left NO inter-clone isolation and reported nothing.
iptables -A "$ISOLATION_CHAIN" -i "$ANALYSIS_BRIDGE.+" ! -o "$UPLINK_BRIDGE" -j DROP

# Deny the private address space. NAT alone reaches the LAN as readily as
# the Internet, because both sit behind the uplink -- so without these a
# sample could reach every host on the lab network, the router's admin
# interface included.
#
# This costs no Internet access: a clone's default route points at its own
# gateway on the analysis VLAN, and Dom0 resolves the next hop from its own
# routing table, so the clone never addresses the LAN gateway itself.
#
# 172.16.0.0/12 covers the analysis subnets too, so clone-to-clone is
# blocked by destination as well as by interface -- two independent
# mechanisms rather than one. 169.254.0.0/16 includes 169.254.169.254, the
# cloud metadata address malware routinely probes.
#
# These four must precede the ACCEPT below. A LAN destination leaves via
# the uplink like any other, so an `-o xenbr0 -j ACCEPT` placed above them
# would accept exactly the traffic they exist to block.
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
    iptables -A "$ISOLATION_CHAIN" -i "$ANALYSIS_BRIDGE.+" -d "$net" -j DROP
done

# The four rules below make the chain terminal (DRAFT-029). Until 2026-08-12
# it ended here, and clone egress was permitted by INHERITANCE: the packet
# fell through to FORWARD's policy, which is ACCEPT on this host. Nothing in
# automation/ set that, asserted it, or would have noticed it change --
# anything flipping it to DROP would have killed every clone's network
# silently, and the only symptom would be analyses that observed nothing.
#
# What is DELIBERATE here is stating the posture, not changing it. The
# permit below is the same unrestricted egress the lab has always had; see
# DRAKVUF_NAT above and roadmap risk #13 for why that is a live question.

# The intended egress, stated rather than inherited.
iptables -A "$ISOLATION_CHAIN" -i "$ANALYSIS_BRIDGE.+" -o "$UPLINK_BRIDGE" -j ACCEPT

# The return path. Without it, egress still depends on FORWARD's policy,
# because every rule above matches on the INPUT interface only and a reply
# arrives on the uplink.
iptables -A "$ISOLATION_CHAIN" -o "$ANALYSIS_BRIDGE.+" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Nothing may OPEN a connection to a clone. No DNAT exists that would let
# the Internet reach one today, so this denies a path rather than closing an
# open one -- but it is what stops the previous rule being the only thing
# standing between an inbound packet and the policy.
iptables -A "$ISOLATION_CHAIN" -o "$ANALYSIS_BRIDGE.+" -j DROP

# Catch-all for clone-originated traffic. Redundant today -- the chain's
# first rule drops everything from a VLAN not leaving via the uplink, and
# the ACCEPT above takes what does -- so it fires only if one of those is
# ever narrowed. That is the point: terminality is a property of the chain,
# not a conclusion a reader has to re-derive from the rules above it.
iptables -A "$ISOLATION_CHAIN" -i "$ANALYSIS_BRIDGE.+" -j DROP

# Traffic touching no analysis VLAN matches nothing here and RETURNs to
# FORWARD untouched -- Dom0's other forwarding paths, if any, are not this
# script's to govern. That is the whole reason this is a terminal CHAIN and
# not a `-P FORWARD DROP`, which would apply to all of them.

# --- Section 7: what a clone may reach ON Dom0 --------------------------

# Closes NET-02. FORWARD covers traffic passing THROUGH Dom0; traffic
# addressed TO Dom0 -- including each clone's own gateway at
# 172.16.<vlan>.1 -- traverses INPUT instead, where no policy has ever been
# set anywhere in automation/. A clone could reach every service listening
# on every Dom0 address.
#
# Blocking it costs the pipeline nothing, checked case by case: ARP is L2
# and unfiltered by iptables, addresses are static so no DHCP is needed,
# the resolver is 1.1.1.1 and therefore forwarded rather than local, and
# both sample delivery and tracing are VMI operations with no network path
# at all -- issue #4 removed the last one when it replaced Apache/HTTP
# delivery with `injector -m writefile`.
#
# Scope note: this is DRAFT-029's territory, moved into DRAFT-028
# deliberately at the maintainer's request rather than by accident.
INPUT_CHAIN=DRAKVUF_INPUT

step="rebuilding $INPUT_CHAIN"

iptables -N "$INPUT_CHAIN" 2>/dev/null || true
iptables -F "$INPUT_CHAIN"
iptables -C INPUT -j "$INPUT_CHAIN" 2>/dev/null ||
    iptables -I INPUT 1 -j "$INPUT_CHAIN"

# Replies to traffic Dom0 itself started. Without this, an operator
# pinging or curling a clone from Dom0 gets nothing back -- the reply
# arrives on INPUT and is dropped. Clone-initiated connections remain
# blocked; only what Dom0 opened is allowed back.
iptables -A "$INPUT_CHAIN" -i "$ANALYSIS_BRIDGE.+" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Everything else from a clone to any Dom0 address, all protocols, all
# ports. The gateway is deliberately not pingable from inside the guest.
#
# One behaviour to watch after deployment: a guest that probes its gateway
# to decide whether the network is up may conclude it is down. Android's
# first boot after this lands is the case to check.
iptables -A "$INPUT_CHAIN" -i "$ANALYSIS_BRIDGE.+" -j DROP

# --- Section 8: IPv6 ----------------------------------------------------

# Everything above is iptables, and iptables is IPv4 only. Without this
# section the whole posture is bypassable over IPv6, and not theoretically:
# Dom0's own VLAN gateway interface carries an IPv6 link-local address
# (`ip -br addr show` reports xenbr1.<n> with both 172.16.<n>.1/24 and an
# fe80::/64), so a sample that re-enables IPv6 on its interface -- an
# `ip link set eth0 down; ip link set eth0 up` is enough to regenerate a
# link-local -- can reach Dom0 over v6 with nothing filtering it.
#
# Measured on the analysis clone 2026-08-11: IPv6 was unreachable only
# because preconfig-ubuntu.sh's `ip addr flush dev eth0` had wiped the
# link-local, leaving `::1 dev lo` as the sole route. That is an accident
# of the configuration order, not a control.
#
# Blanket DROP rather than a mirror of the IPv4 rules. The guests have no
# IPv6 uplink to preserve, and the v6 equivalents of the RFC1918 blocks
# (fc00::/7, fe80::/10, 2000::/3) would add up to "everything" anyway. No
# ESTABLISHED,RELATED exception either: unlike IPv4, nothing needs to reach
# a clone from Dom0 over v6, and a rule that accepts nothing cannot be
# reasoned around later.

step="checking IPv6 filtering is available"

if command -v ip6tables >/dev/null 2>&1 && ip6tables -S >/dev/null 2>&1; then
    ISOLATION_CHAIN6="${ISOLATION_CHAIN}6"
    INPUT_CHAIN6="${INPUT_CHAIN}6"

    step="rebuilding $ISOLATION_CHAIN6"
    ip6tables -N "$ISOLATION_CHAIN6" 2>/dev/null || true
    ip6tables -F "$ISOLATION_CHAIN6"
    ip6tables -C FORWARD -j "$ISOLATION_CHAIN6" 2>/dev/null ||
        ip6tables -I FORWARD 1 -j "$ISOLATION_CHAIN6"
    ip6tables -A "$ISOLATION_CHAIN6" -i "$ANALYSIS_BRIDGE.+" -j DROP

    # Both directions, for the same reason the IPv4 chain ends in a pair:
    # matching the input interface alone leaves anything addressed TO a
    # clone falling through to FORWARD's policy, which is ACCEPT here too.
    ip6tables -A "$ISOLATION_CHAIN6" -o "$ANALYSIS_BRIDGE.+" -j DROP

    # FORWARD alone would miss the actual hole -- the link-local path to
    # Dom0 itself traverses INPUT.
    step="rebuilding $INPUT_CHAIN6"
    ip6tables -N "$INPUT_CHAIN6" 2>/dev/null || true
    ip6tables -F "$INPUT_CHAIN6"
    ip6tables -C INPUT -j "$INPUT_CHAIN6" 2>/dev/null ||
        ip6tables -I INPUT 1 -j "$INPUT_CHAIN6"
    ip6tables -A "$INPUT_CHAIN6" -i "$ANALYSIS_BRIDGE.+" -j DROP

elif [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)" = "1" ]; then
    # Nothing to filter. Warn rather than fail: this host was never
    # exposed, so aborting would create an outage without closing a gap.
    echo "network-setup.sh: ip6tables unavailable, but IPv6 is disabled kernel-wide -- no v6 filtering needed" >&2

else
    # Silently having no IPv6 filtering is the exact defect this section
    # exists to fix, so this is fatal rather than a warning. Both remedies
    # are named so the message is actionable.
    fail "ip6tables is unavailable and IPv6 is not disabled kernel-wide.
Clones would have unfiltered IPv6 access to Dom0 over link-local.
Install iptables' IPv6 support, or disable IPv6 with
  sysctl -w net.ipv6.conf.all.disable_ipv6=1"
fi

step=""
echo "network-setup.sh: provisioned $CLONES VLAN sub-interface(s) on $ANALYSIS_BRIDGE"
