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

## Settings
#
# The LVM volume group
our $lvm_vg = "vg-root";

# Clone network bridge name
our $clone_bridge = "xenbr1";

# vif options merged into the clone's Xen config. Any bridge=, script= or
# backend= inherited from the origin's config is stripped first (see the
# vif rewrite in clone()), then these options plus bridge=<bridge>.<vlan>
# are appended -- so a clone always lands on its own VLAN sub-interface
# regardless of what the origin config said.
our $vif_script = "script=vif-openvswitch";

############################################################

our $lvcreate  = `which lvcreate`;
our $lvremove  = `which lvremove`;
our $lvdisplay = `which lvdisplay`;
our $xl        = `which xl`;
our $mkfifo    = `which mkfifo`;

$lvcreate  =~ s/\015?\012?$//;
$lvremove  =~ s/\015?\012?$//;
$lvdisplay =~ s/\015?\012?$//;
$xl        =~ s/\015?\012?$//;
$mkfifo    =~ s/\015?\012?$//;

sub clone {
    if (@ARGV != 3) {
        die "Insufficient number of arguments!\n"
          . "Usage: ./clone.pl <domain name> <vlan> <path/to/domain.cfg>\n";
    }

    my $origin = $_[0];
    my $vlan   = $_[1];
    my $config = $_[2];
    my $clone  = "$origin-$vlan-clone";

    my $clone_test = `$xl domid $clone 2>/dev/null`;
    if (length $clone_test) {
        `$xl destroy $clone`;
    }

    unless (-e $config) {
        die "0";
    }

    my $domconfig = `cat $config`;

    open(my $fh, '>', "/tmp/$clone.config")
        or die "Could not open file!";

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
    # KNOWN GAP (DRAFT-033), narrower than the old comment implied:
    #   - Nothing checks the exit status of the destroy/lvremove/lvcreate
    #     sequence below, so a clone LV still held open by a domain that
    #     has not finished dying fails silently (DRAFT-033 / DRAKVUF-06).
    #   - Clone-name uniqueness depends on there being ONE dirwatch per
    #     origin. dirwatch hard-codes a single origin per invocation, so a
    #     second dirwatch started against the same origin would collide --
    #     one command away, and worth locking against before the Android
    #     and Windows launchers exist.
    # The disabled flock is in git history at 7764b77.

    my $test = `$lvdisplay /dev/$lvm_vg/$clone 2>&1`;
    if (($test =~ tr/\n//) != 1) {
        `$lvremove -f /dev/$lvm_vg/$clone 2>&1`;
    }

    `$lvcreate -s -n $clone -L64G /dev/$lvm_vg/$origin 2>&1`;


    my $saved_state = "$FindBin::RealBin/../state/$origin.bak";

    unless (-r $saved_state) {
        die "Saved memory image not found or unreadable: $saved_state\n"
          . "Expected <repo root>/state/<origin domain>.bak -- see "
          . "docs/runbooks/deploy-repo-relative-paths.md\n";
    }

    my $error=`$xl restore -p -e /tmp/$clone.config $saved_state 2>&1`;
    print STDERR $error;

    my $cloneID = `$xl domid $clone`;

    chomp($cloneID);

    print "$cloneID";
}

############################################################

clone($ARGV[0], $ARGV[1], $ARGV[2]);
