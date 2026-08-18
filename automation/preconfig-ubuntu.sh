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
# Stages one sample into a booted analysis clone and configures its
# network. Called by dirwatch with a fixed 8-argument list.
#
# Delivery is host-to-guest injection. It used to be a guest-side fetch
# from a Dom0 web server, removed outright as of issue #4 / DRAFT-027 --
# no fallback branch, no flag, no configuration switch. The mechanism and
# the four reasons it went are recorded once, in
# docs/architecture/analysis-pipeline.md ("Historical: HTTP delivery via
# Apache"), rather than restated here.

# $0, not ${BASH_SOURCE[0]}, and this is not a style choice. The DRAKVUF
# license header above sits BEFORE the shebang, so `#!/bin/bash` is on
# line 104 where the kernel never looks. execv() therefore fails ENOEXEC
# and GLib's g_spawn_* -- how dirwatch invokes this script -- falls back
# to /bin/sh, which is dash on Ubuntu. Under dash `${BASH_SOURCE[0]}` is
# a "Bad substitution" that dash reports and then CONTINUES past, leaving
# the variable empty and SCRIPT_DIR silently equal to $PWD: exactly the
# working-directory dependency issue #4 exists to remove. $0 is correct
# under both shells. Keep the rest of this file POSIX too.
SCRIPT_DIR="$(
    cd -- "$(dirname -- "$0")" &&
    pwd
)"

# shellcheck disable=SC2034  # read by the sourced pipeline-ubuntu.env, not here
REPO_ROOT="$(
    cd -- "$SCRIPT_DIR/.." &&
    pwd
)"

# shellcheck source=automation/pipeline-ubuntu.env
. "$SCRIPT_DIR/pipeline-ubuntu.env"

# 7 was enough while $8 was ignored. The result path now needs it, and an
# unset UTIME would silently produce a directory named "-$VLAN" rather
# than fail, so the arity this script actually requires is 8.
ARGC=$#
if [ $ARGC -le 7 ]; then
    exit 0;
fi

REKALL=$1
DOMAIN=$2
PID=$3
VLAN=$4
RUNFOLDER=$5
RUNFILE=$6
OUTPUTFOLDER=$7
UTIME=$8

# The result directory is <sha256>/<analysis id>, and this script derives
# it rather than being told: dirwatch has no channel to its callbacks
# beyond the argument list, and every value needed is already on it.
#
# SHA-256 groups every analysis of the same bytes; the analysis id
# separates the runs. Keying on content ALONE was F8 in
# docs/runbooks/verify-android-mvp.md -- four samples with identical bytes
# under different submitted names shared one directory and truncated each
# other's logs. That was benign before DRAFT-030 and is not after it: the
# submitted name is now what the guest executes (C5), and extension
# dispatch and argv[0] self-checks are exactly the behaviour that makes
# two such submissions DIFFERENT analyses rather than one repeated.
#
# <utime>-<vlan> is the analysis id. utime is dirwatch's per-run
# time(NULL) (dirwatch.c:531) at second granularity, so it is not unique
# by itself -- two workers cloning in the same second share it. One VLAN
# carries one clone at a time, so the pair is unique, and it stays unique
# across watchers once DRAFT-036 makes VLAN allocation host-global, which
# is the point at which a second watcher may run at all.
#
# NOT the state model's ULID. Deviation recorded in
# docs/architecture/analysis-pipeline.md rather than left to be
# rediscovered: a ULID cannot be derived independently by three scripts,
# so it would have to be generated in dirwatch.c and carried, which is a
# C change and a C9 question this does not need to open.
SHA256=$(sha256sum -- "$RUNFOLDER/$RUNFILE" | awk -F" " '{print $1}')
RESULT="$OUTPUTFOLDER/$SHA256/$UTIME-$VLAN"

# The guest sees the name the sample was SUBMITTED with, not its digest
# (C5; DRAFT-030, 2026-08-15). Malware behaviour is frequently
# name-dependent -- extension-driven handler dispatch, argv[0] self-checks,
# APK filename assumptions -- and a sample renamed to its SHA-256
# exercises none of that. Until this change the guest saw the hash, which
# was the right call while the name still travelled through a guest shell
# and is a deviation from the decided rule now that it does not.
#
# $RUNFILE is used unmodified, and that is the whole normalizer: dirwatch
# ADMITS or REJECTS the name at the watch-folder boundary rather than
# rewriting it, so anything that reaches this script has already been
# checked (no separators, no control characters, <=200 bytes). Names that
# would need rewriting never get here. One consequence worth stating for
# whoever implements the state model: original_filename and guest_filename
# are therefore always EQUAL, and DRAFT-011 should record that rather than
# emit two fields implying they can differ.
#
# Safe despite admitting spaces, quotes and a leading '-', because the
# name is never parsed: injector takes -e as a single argv element, and
# the path it forms starts with GUEST_STAGING_DIR, so a leading '-' is
# never in option position.
GUEST_SAMPLE="$GUEST_STAGING_DIR/$RUNFILE"

LOG="$RESULT/preconfig.log"
mkdir -p "$RESULT" 1>/dev/null 2>&1

# 1. Deliver. Deliberately first: delivery no longer depends on guest
#    networking, and running it before the network exists is what keeps
#    an `offline` analysis mode possible (docs/architecture/networking.md).
#    -B is the Dom0 source, -e the guest destination -- confirmed from the
#    installed build's own help, captured on Dom0 2026-08-08 and recorded
#    at docs/runbooks/verify-user-placeholder.md:155.
injector -r "$REKALL" -d "$DOMAIN" -i "$PID" -m writefile \
    -B "$RUNFOLDER/$RUNFILE" \
    -e "$GUEST_SAMPLE" \
    1>"$LOG" 2>&1
RC=$?

if [ $RC -ne 0 ]; then
    echo "preconfig: writefile failed (rc=$RC); sample not staged" >>"$LOG"
    exit $RC
fi

# No chmod step needed. drakvuf-ubuntu.sh runs the sample with
# `-m execproc`, which is execve with no guest shell (issue #2), and
# execve does require the x bit -- but writefile leaves the staged file
# executable on its own, so nothing has to set it.
#
# The injector help does not say that. It was established on Dom0
# 2026-08-09, by removing a chmod injection that had been there and
# confirming runs still traced
# (docs/runbooks/deploy-repo-relative-paths.md, D5).
#
# If a sample ever traces empty with a successful WriteFile in this log,
# check the staged file's mode first -- that is what this removal assumed.

# 2. Configure the clone's network for the analysis itself. Separate from
#    delivery now, where it used to be one `&&` chain with it. No
#    filename is interpolated here.
#
#    The nameserver is GUEST_NAMESERVER, not the gateway. Nothing has
#    ever listened on port 53 at 172.16.<vlan>.1, so guest name
#    resolution failed on every run before this change -- see the
#    reasoning and the containment caveats in pipeline-ubuntu.env.
NETCFG="sudo ip addr flush dev eth0 && sudo ip addr add 172.16.$VLAN.2/24 dev eth0 && sudo ip route replace default via 172.16.$VLAN.1 dev eth0 && echo 'nameserver $GUEST_NAMESERVER' | sudo tee /etc/resolv.conf"

injector -r "$REKALL" -d "$DOMAIN" -i "$PID" -m execproc \
    -e "/usr/bin/sh" \
    -f "-c" \
    -f "$NETCFG" \
    1>>"$LOG" 2>&1

exit $?;
