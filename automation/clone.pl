#!/usr/bin/perl
#
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

######
# Creates a disposable analysis clone of the sandbox template domain:
#   1. an LVM copy-on-write snapshot of the origin's LV, and
#   2. `xl restore` of the origin's previously saved memory image,
# into a rewritten Xen config (own name, own per-VLAN vif, own disk).
#
# SHARED BY ALL THREE OS PIPELINES. This file was clone-ubuntu.pl until
# DRAFT-015 (2026-08-15) and contains no OS-specific value: everything
# that varies between Ubuntu, Android and Windows arrives either on the
# 3-argument contract (origin, vlan, config), is derived from those, or
# comes from the environment. That is not an accident to be worked around
# -- it is the property that lets one file serve three pipelines. If you
# are about to add an `if ($origin eq ...)`, add a variable instead.
#
# Verified against Android before the rename: handed
# `android_sandbox 1 misc/android_sandbox.cfg`, the rewrites below produce
# byte-for-byte what docs/runbooks/06-verify-android-isolation.md steps 2-3
# wrote out by hand on 2026-08-14.
#
# The origin is passed as an argument (e.g. ubuntu_sandbox, not the golden
# ubuntu) and its LVM volume must share that name. The saved memory image
# is produced out-of-band, once per sandbox template -- see
# docs/checklists/ubuntu.md and docs/checklists/android.md.
#
# The memory image used to be a hard-coded /home/user/Documents path while
# the origin was a parameter, so the two had to be kept in agreement by
# hand or a clone got one domain's disk with another's memory. Issue #4
# removed that class of mistake rather than documenting it: the path is
# now derived from the origin argument, as
# "<repo root>/state/<origin>.bak", so disk and memory cannot name
# different domains. dirwatch passes no extra argument for it -- its
# CLONE_CMD is a fixed `<script> <origin> <vlan> <config>`
# (dirwatch.c:122) -- which is why this is derived rather than passed.
#
# NOTICE:
# If an LVM volume exists with the clone's name, it is removed.
#
use strict;
use warnings;

# RealBin, not Bin: DEPLOY keeps the old ~/drakvuf-tools path alive as a
# symlink during the transition, and the state/ directory belongs to the
# real checkout, not to whatever alias invoked this script.
use FindBin;

# For the per-clone lock (DRAFT-033). Fcntl also gives O_* for sysopen.
use Fcntl qw(:flock O_RDWR O_CREAT);

## --- Failure handling (DRAFT-033) --------------------------------------
#
# THE STDOUT CONTRACT IS THE ONLY FAILURE CHANNEL THAT REACHES dirwatch.
#
# dirwatch runs this script with
#   g_spawn_command_line_sync(command, &output, NULL, NULL, NULL)
# (dirwatch.c:178) -- the exit-status argument is NULL. It cannot see a
# non-zero exit at all. It parses stdout for a domain ID and retries when
# it does not get one (prepare(), dirwatch.c:206-232).
#
# So: print the clone ID to stdout on success and NOTHING to stdout on any
# failure. Every diagnostic goes to stderr. The exit codes below exist for
# humans and for a future dirwatch that reads them; they are deliberately
# distinct so a Dom0 operator running this by hand can tell a transient
# failure from a futile one, but nothing consumes them today.
our $EXIT_USAGE     = 2;   # bad arguments -- retry is futile
our $EXIT_PRECHECK  = 3;   # missing binary, LV, config or saved state
our $EXIT_LOCKED    = 4;   # another process holds this clone's lock
our $EXIT_LVM       = 5;   # lvremove/lvcreate failed
our $EXIT_RESTORE   = 6;   # xl restore failed, or produced no domain

# Files to remove if we exit before handing a working clone back. The END
# block below runs on die() as well as on a normal exit, so a partially
# created snapshot does not survive to block the next run for this VLAN --
# which is exactly the stale-/dev/<vg>/<clone> failure DRAFT-033 names.
our @cleanup_files;
our $clone_lv_to_remove;
our $succeeded = 0;

sub fail {
    my ($code, @msg) = @_;
    print STDERR "clone.pl: $_\n" for @msg;
    exit $code;
}

# Empty is treated as unset, matching the ${NAME:-default} idiom every
# pipeline-<os>.env entry uses. Not cosmetic: Perl's `//` is defined-or,
# so an exported-but-empty CLONE_LV_SIZE would interpolate to `-L` with no
# argument and lvcreate would take the device path as its size operand.
sub env_or {
    my ($name, $default) = @_;
    return (defined $ENV{$name} && length $ENV{$name})
        ? $ENV{$name}
        : $default;
}

# Runs a command, captures stdout+stderr, and returns (ok, output).
# Backticks are kept rather than moving to system() with a list, because
# every caller here wants the output for a diagnostic. None of the
# interpolated values is attacker-controlled: the origin, vlan and config
# path all come from dirwatch's own argv, never from a sample filename
# (that separation is DRAFT-030's).
sub run {
    my ($what, @argv) = @_;
    my $cmd = join(' ', @argv);
    my $out = `$cmd 2>&1`;
    my $rc  = $?;

    return (1, $out) if $rc == 0;

    my $how = $rc == -1            ? "failed to execute: $!"
            : ($rc & 127)          ? sprintf("died with signal %d", $rc & 127)
            :                        sprintf("exited %d", $rc >> 8);
    chomp $out;
    return (0, "$what $how\n  command: $cmd\n  output: "
               . (length $out ? $out : "(none)"));
}

## Settings
#
# The LVM volume group
#
# Host-global (C4), so it comes from automation/platform.env by way of the
# environment, not from pipeline-<os>.env. run_analysis-<os>.sh sources
# platform.env and exports this; the default matches the literal it
# replaced, so an unset variable behaves exactly as before.
our $lvm_vg = env_or("VG_NAME", "vg-root");

# Size of the LVM copy-on-write snapshot -- the exception store, i.e. how
# much divergence from the origin a clone may accumulate before the
# snapshot is invalidated. That is a function of how much the guest writes
# during an analysis, so it is a property of the OS image and is per-OS
# (C3): 64G for Ubuntu, 32G for Android, Windows likely more.
#
# Read from the environment rather than passed, because dirwatch's
# CLONE_CMD is a fixed 3-argument contract this may not change (C9).
# run_analysis-<os>.sh sources pipeline-<os>.env and exports this;
# dirwatch spawns every callback with envp = NULL (dirwatch.c:178), which
# inherits the parent environment.
#
# The default reproduces the literal this replaced, so an unset variable
# behaves exactly as before the value was parameterized. Note that this
# makes a lost value INVISIBLE rather than fatal: an Android clone built
# at 64G works, and merely over-allocates. Check `lvs` reports the size
# you expect rather than inferring it from a clone that came up.
#
# Empty is treated as unset, matching the ${NAME:-default} idiom every
# pipeline-<os>.env entry uses. Not cosmetic: `//` alone is defined-or, so
# an exported-but-empty value would interpolate to `-L` with no argument
# and lvcreate would take the device path as its size operand.
our $clone_lv_size = env_or("CLONE_LV_SIZE", "64G");

# Clone network bridge name. Host-global (C4) -- see $lvm_vg above.
our $clone_bridge = env_or("ANALYSIS_BRIDGE", "xenbr1");

# vif options merged into the clone's Xen config. Any bridge=, script= or
# backend= inherited from the origin's config is stripped first (see the
# vif rewrite in clone()), then these options plus bridge=<bridge>.<vlan>
# are appended -- so a clone always lands on its own VLAN sub-interface
# regardless of what the origin config said.
our $vif_script = "script=vif-openvswitch";

############################################################

# `2>/dev/null` is load-bearing, not tidiness. Without it a `which` that
# finds nothing produced two kinds of noise on stderr before any useful
# diagnostic: the shell's own "which: no lvcreate in ..." lines, and --
# because Perl optimizes a single bare command to a direct exec with no
# shell -- a "Can't exec which" warning if `which` itself is absent.
# The redirect forces the shell path and swallows both.
our $lvcreate  = `which lvcreate 2>/dev/null`;
our $lvremove  = `which lvremove 2>/dev/null`;
our $lvdisplay = `which lvdisplay 2>/dev/null`;
our $xl        = `which xl 2>/dev/null`;
our $mkfifo    = `which mkfifo 2>/dev/null`;

# Undef when the command failed to run at all, so the chomp below would
# otherwise warn five times. check_tools() reports the empty string.
for ($lvcreate, $lvremove, $lvdisplay, $xl, $mkfifo) {
    $_ = "" unless defined;
    s/\015?\012?$//;
}

# A missing binary used to produce an empty string here, so `$lvdisplay
# /dev/...` ran as a bare redirect, returned nothing, and the tr/// count
# below operated on undef -- a warning, then a silent fall-through into an
# lvcreate that was also empty. Naming the missing tool is the whole point
# of DRAFT-033: fail where the cause is, not three steps later.
#
# mkfifo is deliberately not checked. It is a leftover from the upstream
# clone.pl this was derived from and is referenced nowhere else in the
# file; requiring it would fail hosts that do not need it.
sub check_tools {
    my @missing;
    push @missing, "lvcreate"  unless length $lvcreate;
    push @missing, "lvremove"  unless length $lvremove;
    push @missing, "lvdisplay" unless length $lvdisplay;
    push @missing, "xl"        unless length $xl;

    return unless @missing;
    fail($EXIT_PRECHECK,
         "required command(s) not found in PATH: " . join(', ', @missing),
         "  This script runs on Xen Dom0 and needs LVM and the Xen CLI.",
         "  PATH=" . (defined $ENV{PATH} ? $ENV{PATH} : "(unset)"));
}

sub clone {
    if (@ARGV != 3) {
        fail($EXIT_USAGE,
             "expected 3 arguments, got " . scalar(@ARGV),
             "Usage: clone.pl <origin domain> <vlan> <path/to/domain.cfg>");
    }

    my $origin = $_[0];
    my $vlan   = $_[1];
    my $config = $_[2];

    # Validated because both go straight into a device path and a domain
    # name. Not an injection defence -- these come from dirwatch's own
    # argv, never from a sample filename -- but a typo'd origin otherwise
    # surfaces as an opaque lvcreate error naming a device nobody meant.
    fail($EXIT_USAGE, "vlan must be a positive integer, got: '$vlan'")
        unless $vlan =~ /\A[0-9]+\z/ && $vlan >= 1;

    # 254 for the reason network-setup.sh caps there: the vlan is the third
    # octet of <prefix>.<vlan>.0/24, so above it there is no gateway.
    fail($EXIT_USAGE, "vlan must be at most 254 (it is the third octet of "
                    . "the gateway address), got: $vlan")
        if $vlan > 254;

    fail($EXIT_USAGE, "origin domain name may contain only "
                    . "[A-Za-z0-9._-], got: '$origin'")
        unless $origin =~ /\A[A-Za-z0-9._-]+\z/;

    my $clone = "$origin-$vlan-clone";

    check_tools();

    # --- Lock, per CLONE NAME rather than per origin ---------------------
    #
    # DRAFT-033's PLAN step 2 asks which scope. Per-origin is wrong here
    # and would be worse than no lock: dirwatch runs MAX_CLONES workers
    # against the SAME origin concurrently, so a per-origin lock would
    # serialize the whole pipeline to one analysis at a time -- a
    # throughput bug dressed as a safety fix.
    #
    # The hazard that actually exists is narrower. Clone names are
    # <origin>-<vlan>-clone and dirwatch claims thread slots with an atomic
    # compare-and-exchange, so two workers in ONE process can never
    # generate the same name. Two dirwatch PROCESSES against the same
    # origin can -- one command away, and likelier once the Android and
    # Windows launchers exist. A lock keyed on the clone name catches
    # exactly that and serializes nothing else.
    #
    # (The per-origin lock in the removed scaffolding came from upstream's
    # clone.pl, which live-snapshots the origin domain. This version never
    # touches the origin domain at all. Git history: 7764b77.)
    #
    # Non-blocking with bounded retry, never a blocking LOCK_EX: dirwatch's
    # 60s preconfig timer does not cover the clone step, so a blocking
    # acquire has no external timeout and would hang a worker forever.
    my $lock_path = "/run/lock/drakvuf-clone-$clone.lock";
    my $lock_fh;
    unless (sysopen($lock_fh, $lock_path, O_RDWR | O_CREAT, 0600)) {
        # A read-only or absent /run/lock must not stop a clone: the lock
        # guards a rare cross-process case, and refusing to work without it
        # would be a worse failure than the one it prevents.
        print STDERR "clone.pl: cannot open $lock_path ($!); "
                   . "proceeding without the cross-process lock\n";
    }
    else {
        my $got = 0;
        for (1 .. 30) {
            if (flock($lock_fh, LOCK_EX | LOCK_NB)) { $got = 1; last }
            sleep 1;
        }
        fail($EXIT_LOCKED,
             "another process is already cloning '$clone' "
           . "(held $lock_path for >30s)",
             "  Two dirwatch instances against origin '$origin' collide on "
           . "clone names. Run one launcher per origin domain.")
            unless $got;
    }

    # Exit status checked as of DRAFT-033. A destroy that fails leaves the
    # LV open, which makes the lvremove below fail too -- previously both
    # passed silently and `xl restore` then landed on the PREVIOUS sample's
    # snapshot. That is cross-sample contamination, not a crash, so nothing
    # reported it.
    my $clone_test = `$xl domid $clone 2>/dev/null`;
    if (length $clone_test) {
        my ($ok, $out) = run("xl destroy of the stale clone '$clone'",
                             $xl, "destroy", $clone);
        fail($EXIT_RESTORE, $out) unless $ok;

        # `xl destroy` returns before the block device is released --
        # measured on Dom0 2026-08-14, where lvremove reported "Logical
        # volume in use" and succeeded on a retry
        # (docs/runbooks/06-verify-android-isolation.md:965, annotated :996).
        # Waiting here is what makes the lvremove below reliable.
        for (1 .. 10) {
            last unless length `$xl domid $clone 2>/dev/null`;
            sleep 1;
        }
    }

    fail($EXIT_PRECHECK, "domain config not found: $config")
        unless -e $config;
    fail($EXIT_PRECHECK, "domain config not readable: $config")
        unless -r $config;

    # Checked before anything is created, so a wrong origin costs nothing
    # and names itself.
    my ($origin_ok) = run("lvdisplay of the origin LV",
                          $lvdisplay, "/dev/$lvm_vg/$origin");
    fail($EXIT_PRECHECK,
         "origin logical volume not found: /dev/$lvm_vg/$origin",
         "  VG_NAME=$lvm_vg. Check `lvs` and the origin domain argument.")
        unless $origin_ok;

    # Checked here rather than just before `xl restore`, for the same
    # reason: everything past this point creates state that would then have
    # to be torn down again.
    my $saved_state = "$FindBin::RealBin/../state/$origin.bak";
    unless (-r $saved_state) {
        fail($EXIT_PRECHECK,
             "saved memory image not found or unreadable: $saved_state",
             "  Expected <repo root>/state/<origin domain>.bak -- see "
           . "docs/runbooks/02-deploy-repo-relative-paths.md");
    }

    my $domconfig = `cat $config`;

    my $clone_config = "/tmp/$clone.config";
    push @cleanup_files, $clone_config;

    open(my $fh, '>', $clone_config)
        or fail($EXIT_PRECHECK, "cannot write $clone_config: $!");

    while ($domconfig =~ /([^\n]+)\n?/g) {
        my $line = $1;

        if ($line =~ /^\s*name\s*=/) {
            print $fh "name = \"$clone\"\n";
            next;
        }

        if ($line =~ /^\s*vif\s*=/) {
            my ($inside) = $line =~ /\[\s*['"](.+?)['"]\s*\]/;

            die "Unable to parse VIF configuration: $line\n"
                unless defined $inside;

            my @values = split /,/, $inside;
            my @new_values;

            foreach my $value (@values) {
                $value =~ s/^\s+//;
                $value =~ s/\s+$//;

                next if $value eq '';
                next if $value =~ /^(?:bridge|script|backend)\s*=/;

                push @new_values, $value;
            }

            if (defined $vif_script && length $vif_script) {
                foreach my $option (split /,/, $vif_script) {
                    $option =~ s/^\s+//;
                    $option =~ s/\s+$//;

                    push @new_values, $option if length $option;
                }
            }

            push @new_values, "bridge=$clone_bridge.$vlan";

            print $fh "vif = [ '" . join(',', @new_values) . "' ]\n";
            next;
        }

        if ($line =~ /^\s*disk\s*=/) {
            print $fh
                "disk = [ 'phy:/dev/$lvm_vg/$clone,hda,w' ]\n";
            next;
        }

        print $fh "$line\n";
    }

    # TODO: evaluate qemu stubdomain usability
    #print $fh "device_model_stubdomain_override = 1\n";

    close $fh;

    # A disabled per-origin flock used to sit here, under the comment
    # "only one clone process may manipulate a particular origin VM at the
    # same time". That requirement came from upstream's clone.pl, which
    # live-snapshots the origin domain -- the same upstream inheritance
    # that left the wrong description in this file's header. This version
    # never touches the origin domain at all: it only reads the origin's
    # LV as a snapshot source, and the sole `xl destroy` above targets the
    # clone. So the requirement as stated does not apply here.
    #
    # What does hold today: clone names are `<origin>-<vlan>-clone`, and
    # dirwatch derives the vlan from a worker slot claimed with an atomic
    # compare-and-exchange (dirwatch.c), so two concurrent workers can
    # never generate the same clone name. Raising the clone count does not
    # change that.
    #
    # Both gaps the block above described are closed as of DRAFT-033: the
    # destroy/lvremove/lvcreate sequence is now checked, and the
    # cross-process collision is covered by the per-clone-name lock taken
    # at the top of this function.

    # A stale snapshot from a previous run for this VLAN. Removing it is
    # normal, not exceptional -- nothing else deletes clone LVs, so one
    # survives every analysis (cleanup.sh destroys the domain only).
    my ($stale_ok) = run("lvdisplay", $lvdisplay, "/dev/$lvm_vg/$clone");
    if ($stale_ok) {
        my ($rm_ok, $rm_out) =
            run("lvremove of the stale clone LV", $lvremove, "-f",
                "/dev/$lvm_vg/$clone");
        fail($EXIT_LVM, $rm_out,
             "  A clone LV still open means a domain has not finished "
           . "dying. Check `xl list` and `lvs`.",
             "  Proceeding would have restored onto the PREVIOUS sample's "
           . "snapshot.")
            unless $rm_ok;
    }

    # From here on a failure leaves a snapshot behind, so register it for
    # the END block before creating it.
    $clone_lv_to_remove = "/dev/$lvm_vg/$clone";

    my ($lv_ok, $lv_out) =
        run("lvcreate of the clone snapshot", $lvcreate, "-s", "-n", $clone,
            "-L$clone_lv_size", "/dev/$lvm_vg/$origin");
    unless ($lv_ok) {
        # Nothing was created, so do not let END try to remove it.
        $clone_lv_to_remove = undef;
        fail($EXIT_LVM, $lv_out,
             "  CLONE_LV_SIZE=$clone_lv_size, VG_NAME=$lvm_vg. "
           . "If the VG is full this is not transient -- check `vgs`.");
    }

    my ($restore_ok, $restore_out) =
        run("xl restore", $xl, "restore", "-p", "-e", $clone_config,
            $saved_state);
    fail($EXIT_RESTORE, $restore_out) unless $restore_ok;

    my $cloneID = `$xl domid $clone 2>/dev/null`;
    chomp($cloneID) if defined $cloneID;

    # STDOUT IS THE ONLY THING dirwatch READS -- see the contract note at
    # the top of this file. `xl restore` can exit 0 and still leave no
    # usable domain, and `xl domid` prints its own errors, so the value is
    # checked rather than trusted. Anything that is not a bare integer is a
    # diagnostic, not an ID, and must not reach stdout: dirwatch would
    # parse it as a domain.
    unless (defined $cloneID && $cloneID =~ /\A[0-9]+\z/) {
        fail($EXIT_RESTORE,
             "xl restore reported success but no domain id came back for "
           . "'$clone'",
             "  xl domid printed: "
           . (defined $cloneID && length $cloneID ? "'$cloneID'" : "(nothing)"));
    }

    # The one and only write to stdout, and the last statement that can
    # fail: past here the clone exists and is dirwatch's to tear down.
    $succeeded = 1;
    print "$cloneID";
}

# Runs on normal exit AND on die(), so a half-built clone does not survive
# to block the next run for this VLAN. Deliberately silent about the
# snapshot on success -- the LV is the clone's disk and must persist.
END {
    my $status = $?;

    unlink $_ for @cleanup_files;

    if (!$succeeded && defined $clone_lv_to_remove) {
        print STDERR "clone.pl: removing partial snapshot "
                   . "$clone_lv_to_remove\n";
        my ($ok, $out) = run("cleanup lvremove", $lvremove, "-f",
                             $clone_lv_to_remove);
        print STDERR "clone.pl: $out\n" unless $ok;
    }

    $? = $status;
}

############################################################

clone($ARGV[0], $ARGV[1], $ARGV[2]);
