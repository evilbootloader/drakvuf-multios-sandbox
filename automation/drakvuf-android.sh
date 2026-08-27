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
# Runs the DRAKVUF trace against a sample already staged in an Android
# (BlissOS) analysis clone by preconfig-android.sh. Called by dirwatch
# with the same fixed 7-argument list, in the same order (C9).
#
# NOTHING IN THIS FILE HAS RUN AGAINST AN ANDROID GUEST -- see the same
# warning in preconfig-android.sh. The injection shapes below are built
# from the installed tools' own --help, captured on Dom0, but they have
# only ever been exercised against Ubuntu.
#
# TWO EXECUTION PATHS, selected from the sample's own bytes:
#
#   APK          pm install, then launch, both through /system/bin/sh -c
#   native ELF   execve of the staged file -- the Ubuntu shape
#   neither      unsupported_type; nothing is executed
#
# An Android pipeline that could not analyse APKs would not deliver the
# thing the Android target exists for, which is why the install path is
# here rather than deferred.
#
# This does not violate C6. C6 constrains DELIVERY -- one writefile, no
# guest shell before it -- and preconfig-android.sh satisfies it. The
# install below happens afterwards, with the trace already running, so
# PackageManager parsing the APK is itself observed.

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

MD5=$(md5sum -- "$RUNFOLDER/$RUNFILE" | awk -F" " '{print $1}')

# Built by the same rule preconfig-android.sh stages to, from the same two
# dirwatch arguments, so staging and execution cannot name different files.
CMD="$GUEST_STAGING_DIR/$RUNFILE"

RESULT="$OUTPUTFOLDER/$MD5"
mkdir -p "$RESULT/dump" "$RESULT/memdump" 1>/dev/null 2>&1

# --- Sample type: a STRUCTURAL test, not the state model's detected_type -
#
# detected_type is deliberately advisory (issue #3), and §2.7 already
# rejected using it to choose a staging directory: doing so would make an
# advisory field load-bearing. Selecting the EXECUTION METHOD from it has
# the same effect, and a worse symptom -- a misidentified APK would take
# the execve path and fail in a way that looks like a sample that did
# nothing at all.
#
# So this script decides for itself, from the file's own bytes on Dom0:
#
#   APK  = ZIP container (PK\x03\x04) that also contains the literal
#          "AndroidManifest.xml". Positive identification of the container
#          format rather than a heuristic on the name.
#   ELF  = \x7fELF.
#
# Same discipline as the guest destination: computed from content, never
# from the submitted filename.
magic=$(dd if="$RUNFOLDER/$RUNFILE" bs=1 count=4 2>/dev/null \
        | od -An -tx1 | tr -d ' \n')

SAMPLE_KIND=unsupported
case "$magic" in
    504b0304)
        # The manifest name appears as a stored entry name in the archive,
        # so a plain byte search finds it without needing unzip on Dom0.
        if grep -qa 'AndroidManifest\.xml' -- "$RUNFOLDER/$RUNFILE"; then
            SAMPLE_KIND=apk
        fi
        ;;
    7f454c46)
        SAMPLE_KIND=elf
        ;;
esac

if [ "$SAMPLE_KIND" = unsupported ]; then
    # Deliberately not executed. Reported the way the state model names it
    # so the string is greppable once DRAFT-011 emits status properly.
    echo "drakvuf-android: unsupported_type (magic=${magic:-none});" \
         "not an APK or a native ELF; nothing executed" \
         >>"$RESULT/drakvuf.log" 2>&1
    exit 0
fi

# Settling time before the trace attaches, inherited from
# drakvuf-ubuntu.sh. The APK path does not need it: preconfig-android.sh
# has just spent APK_INSTALL_WAIT seconds installing, so the clone is long
# since settled, and every second here comes out of the trace budget the
# launch is already short of.
if [ "$SAMPLE_KIND" = elf ]; then
    sleep 5 2>&1
fi

# --- Trace tuning, shared by both invocations ----------------------------
#
# Built into the positional parameters so the options can be passed as
# "$@" without an unquoted expansion. A single variable holding "-F
# --disable-sysret" would need word splitting at the call site, which is
# the SC2086 pattern DRAFT-011 is removing from this repository rather
# than adding to.
#
# Safe here: dirwatch's seven arguments were copied into named variables
# at the top of this file and nothing below reads $1..$7 again.
#
# See FAST_SINGLESTEP / DISABLE_SYSRET in pipeline-android.env for why
# Android needs these and Ubuntu does not -- and for what --disable-sysret
# costs, which is syscall return values.
set --
if [ "$FAST_SINGLESTEP" = 1 ]; then
    set -- "$@" -F
fi
if [ "$DISABLE_SYSRET" = 1 ]; then
    set -- "$@" --disable-sysret
fi

# --- The two invocations ------------------------------------------------
#
# Everything but the injection differs by nothing, so only the injection
# shape is branched. -f is valid here: `drakvuf --help` on the installed
# build records "-f <args for exec>  Additional args for exec() (requires
# -m execproc or -m shellexec)", captured at
# docs/runbooks/01-verify-user-placeholder.md:104.
if [ "$SAMPLE_KIND" = apk ]; then
    # The sample is ALREADY INSTALLED by preconfig-android.sh; this traces
    # the launch only. See that script for why the install moved out of
    # the traced window (F3: 3s untraced, unfinished after 120s traced).
    #
    # THE TRACED WINDOW IS ONE execve AND NOTHING ELSE. Everything that
    # can happen before the sample runs already has: preconfig-android.sh
    # installed the APK, resolved its launcher component, read it back to
    # Dom0 and removed the guest copy. What is traced is `am start -n`.
    #
    # That is measured, not tidiness. On 2026-08-17 this branch read the
    # component in-guest with a shell, and `sh`, `cat` and `rm` cost
    # 1434 + 1546 + 1542 traced syscall events before `am` even began --
    # every one of them at the trace's slowdown, out of the same budget
    # the launch was already failing to fit into. A shell here is three
    # toybox execs and their dynamic linking; none of it is sample
    # behaviour.
    #
    # NO GUEST SHELL, so nothing is re-parsed. $CMP is guest-derived and
    # therefore untrusted -- an APK chooses its own package and activity
    # names -- but it reaches execve as a single argv element and no
    # character in it is special. It is validated for shape below anyway,
    # because a component that is not <package>/<activity> means
    # resolve-activity returned a diagnostic and there is nothing to
    # launch.
    #
    # `am` is /system/bin/sh's two-line wrapper around `cmd activity`, the
    # same native binary `pm` wraps, so this needs no classpath import.
    # `monkey` would: it reaches app_process64, which aborts with exit 134
    # before main() without the import (evidenced 2026-08-17, and already
    # recorded at docs/checklists/android.md:833). monkey is not used even
    # with the import, because ActivityManager.isUserAMonkey() reports it
    # to the sample -- the same anti-evasion reasoning that renamed the
    # injection anchor in issue #7.
    COMPONENT_FILE="$RESULT/launch-component"
    CMP=$(cat "$COMPONENT_FILE" 2>/dev/null)

    # Exactly one '/', and only characters a package or class name can
    # contain -- '$' included, since an inner class is a legitimate
    # launcher activity. Anything else is resolve-activity's diagnostic,
    # or an empty file, or preconfig never got that far.
    #
    # The '$' is QUOTED inside the bracket expression. Unquoted, the shell
    # expands `$-` (the current option flags) while building the pattern,
    # which silently eats both '$' and '-' from the character class and
    # rejects perfectly valid components -- caught in test 2026-08-17,
    # where com.x/.Outer$Inner and a_b-c.d/.E were both refused.
    LAUNCH_OK=no
    case "$CMP" in
        */*/*)                    ;;
        */*) LAUNCH_OK=yes        ;;
    esac
    case "$CMP" in
        *[!A-Za-z0-9._/'$'-]*) LAUNCH_OK=no ;;
    esac

    if [ "$LAUNCH_OK" != yes ]; then
        echo "drakvuf-android: no usable launcher component" \
             "(got '${CMP:-<empty>}'); nothing executed. See preconfig.log." \
             >>"$RESULT/drakvuf.log" 2>&1
        exit 1
    fi

    # -t 150, not the ELF path's 120. dirwatch.c:650 arms a 180s timer over
    # this phase, so 150 plus process startup leaves roughly 20s of
    # headroom where 120 left 55s unused -- and a launch is heavier than an
    # execve: zygote fork, ART init and an activity start, all at the
    # trace's slowdown. Raising it past ~150 means raising dirwatch's timer
    # too, which needs a recompile and slows every Android run.
    drakvuf -r "$REKALL" -d "$DOMAIN" -i "$PID" \
        -m execproc -e "/system/bin/am" -f "start" -f "-n" -f "$CMP" \
        "$@" \
        -o json -t 150 \
        -a syscalls -a filetracer -a fileextractor -a memdump \
        -D "$RESULT/dump" \
        --memdump-dir "$RESULT/memdump" \
        1>"$RESULT/drakvuf.log" 2>&1
else
    # Native ELF: execve of the staged file, exactly Ubuntu's shape. This
    # is the property /data/local/tmp was chosen for -- it is exec-capable,
    # where /storage/self/primary/Download is a noexec mount on which
    # chmod is silently a no-op.
    drakvuf -r "$REKALL" -d "$DOMAIN" -i "$PID" \
        -m execproc -e "$CMD" \
        "$@" \
        -o json -t 120 \
        -a syscalls -a filetracer -a fileextractor -a memdump \
        -D "$RESULT/dump" \
        --memdump-dir "$RESULT/memdump" \
        1>"$RESULT/drakvuf.log" 2>&1
fi

RET=$?

if [ $RET -eq 1 ]; then
   mv -- "$RUNFOLDER/$RUNFILE" "$RESULT" 1>/dev/null 2>&1
fi

# KNOWN GAP (DRAFT-011), inherited from drakvuf-ubuntu.sh rather than
# introduced: the match is unanchored and `.` is a regex wildcard, so
# VLAN 1 also matches xenbr1.10-19 once there are more than nine clones.
# Not fixed here, because fixing it in one of two copies is worse than
# fixing it in neither -- it is the same line in both files.
TCPDUMPPID=$(ps aux | grep "tcpdump -i $ANALYSIS_BRIDGE.$VLAN" | grep -v grep | awk -F" " '{print $2}')
kill -9 $TCPDUMPPID 1>/dev/null 2>&1

exit $RET;
