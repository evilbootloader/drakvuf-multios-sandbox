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
# Stages one sample into a booted Android (BlissOS) analysis clone and
# configures its network. Called by dirwatch with a fixed 7-argument list,
# identical in order to preconfig-ubuntu.sh's -- that is dirwatch's
# contract (C9), not a per-OS choice.
#
# NOTHING IN THIS FILE HAS RUN AGAINST AN ANDROID GUEST. No injector
# operation ever has: every injector invocation in the Android
# documentation is either labelled a candidate or was derived from
# `injector --help` captured on Dom0 against UBUNTU. The staging-directory
# probe and DRAFT-013's network commands were both run from a guest
# console, not through injector. Treat the two injections below as
# proposed until a runbook says otherwise, and test writefile alone first
# -- see DRAFT-016's TEST section.
#
# The network half is NOT a translation of preconfig-ubuntu.sh's `ip`
# chain. It was measured on a live clone in
# docs/runbooks/verify-android-isolation.md and recorded as
# docs/checklists/android.md §1.6: Bliss-Bass EthernetConfig subsumes the
# whole chain, so address, prefix, gateway and resolver are one framework
# call rather than four `ip` commands and a resolv.conf write.

# $0, not ${BASH_SOURCE[0]} -- see the note in preconfig-ubuntu.sh. The
# licence header above sits before the shebang's line-1 position in the
# sibling scripts, dirwatch spawns these through g_spawn_*, and /bin/sh is
# dash. Keep the rest of this file POSIX.
SCRIPT_DIR="$(
    cd -- "$(dirname -- "$0")" &&
    pwd
)"

# shellcheck disable=SC2034  # read by the sourced env files, not here
REPO_ROOT="$(
    cd -- "$SCRIPT_DIR/.." &&
    pwd
)"

# shellcheck source=automation/platform.env
. "$SCRIPT_DIR/platform.env"

# shellcheck source=automation/pipeline-android.env
. "$SCRIPT_DIR/pipeline-android.env"

ARGC=$#
if [ $ARGC -le 6 ]; then
    exit 0;
fi

REKALL=$1
DOMAIN=$2
PID=$3
VLAN=$4
RUNFOLDER=$5
RUNFILE=$6
OUTPUTFOLDER=$7

# MD5 keys the result directory, as it does for Ubuntu.
MD5=$(md5sum -- "$RUNFOLDER/$RUNFILE" | awk -F" " '{print $1}')

# The guest sees the submitted name (C5). dirwatch admits or rejects the
# name at the watch-folder boundary, so nothing here needs to rewrite it.
# GUEST_STAGING_DIR is /data/local/tmp: it pre-exists in the saved image
# and permits execution, which /storage/self/primary/Download does not.
GUEST_SAMPLE="$GUEST_STAGING_DIR/$RUNFILE"

LOG="$OUTPUTFOLDER/$MD5/preconfig.log"
mkdir -p "$OUTPUTFOLDER/$MD5" 1>/dev/null 2>&1

# 1. Deliver. First, and deliberately: delivery does not depend on guest
#    networking, which is what keeps an `offline` analysis mode reachable.
#    One injection, no guest shell before it (C6). -B is the Dom0 source
#    and -e the guest destination.
injector -r "$REKALL" -d "$DOMAIN" -i "$PID" -m writefile \
    -B "$RUNFOLDER/$RUNFILE" \
    -e "$GUEST_SAMPLE" \
    1>"$LOG" 2>&1
RC=$?

if [ $RC -ne 0 ]; then
    echo "preconfig: writefile failed (rc=$RC); sample not staged" >>"$LOG"
    exit $RC
fi

# No chmod step, matching Ubuntu: writefile leaves the staged file
# executable there, evidenced on Dom0 2026-08-09.
#
# UNVERIFIED ON ANDROID. That evidence is Ubuntu's. If a native sample
# traces empty with a successful WriteFile in this log, check the staged
# file's mode first -- it is the assumption most likely to differ, because
# /data/local/tmp is exec-capable but the writefile implementation's mode
# handling has never been observed on this guest.

# 2. Configure the clone's network.
#
# THE QUOTING HERE IS THE RISKY PART, and it fails silently rather than
# loudly. injector -m execproc is execve-direct with no guest shell, so
# the whole sequence must arrive as ONE argument to /system/bin/sh -c.
# Unlike preconfig-ubuntu.sh, where every $ is meant to expand on Dom0,
# this sequence needs MIXED expansion:
#
#   expands on Dom0   $VLAN, $GUEST_NAMESERVER -- the only two values Dom0
#                     actually knows
#   expands in guest  $a/$n/$v, $APK, and the $(pm path ...) substitution
#
# Written the Ubuntu way, $(pm path ...) would run on DOM0, where pm does
# not exist. It would expand to empty, the guest would receive
# `CLASSPATH= /system/bin/app_process64 ...`, and that command is
# well-formed and wrong. Nothing on the Dom0 side errors.
#
# So: guest-side text stays inside SINGLE quotes and only the two Dom0
# values interpolate. The inner sed uses double quotes so the
# single-quoted segment survives.
#
# ${NETCFG} and not $NETCFG in the concatenations: "$NETCFG172.16..."
# parses as a variable named NETCFG172 and yields the empty string -- the
# same class of silent failure, one line away.
# shellcheck disable=SC2016  # single quotes are the point: see above.
# SC2016 is "expressions don't expand in single quotes" -- correct, and
# exactly what is wanted. These $ must survive Dom0 and expand in the
# guest. Disabled at this site rather than in .shellcheckrc, because
# repository-wide it would hide the real mistake of writing an intended
# Dom0 expansion in single quotes.
NETCFG='while IFS=" " read -r a n v; do [ "$a" = export ] && export "$n=$v"; done < /data/system/environ/classpath; '
# shellcheck disable=SC2016
NETCFG="${NETCFG}"'APK="$(pm path com.example.ethernetconfig | sed "s/^package://")"; '
# shellcheck disable=SC2016
NETCFG="${NETCFG}"'CLASSPATH="$APK" /system/bin/app_process64 / '
NETCFG="${NETCFG}com.example.ethernetconfig.network.EthernetConfigurator STATIC eth0 "
NETCFG="${NETCFG}${SUBNET_PREFIX}.${VLAN}.2 24 ${SUBNET_PREFIX}.${VLAN}.1 ${GUEST_NAMESERVER} none && "

# private_dns_mode off is REQUIRED, not tuning. Left at its default the
# clone resolved over DoT to 1.1.1.1:853 and the pcap recorded an
# encrypted stream instead of the domains the sample looked up -- silently,
# with nothing failing. Pcap-evidenced both ways in
# docs/runbooks/verify-android-isolation.md.
NETCFG="${NETCFG}settings put global private_dns_mode off"

# /system/bin/sh, not /usr/bin/sh: the Ubuntu path does not exist here.
# No sudo and no su -c either -- the guest is already root and ships
# neither. All three measured by DRAFT-013.
injector -r "$REKALL" -d "$DOMAIN" -i "$PID" -m execproc \
    -e "/system/bin/sh" \
    -f "-c" \
    -f "$NETCFG" \
    1>>"$LOG" 2>&1

exit $?;
