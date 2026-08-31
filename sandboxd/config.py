"""**The source of truth for this Dom0. Edit this file to tune the host.**

Everything below is a value an operator may reasonably need to change for their
own environment. It is plain Python with no framework: read it top to bottom,
change a value, restart `sandboxd`.

## What lives here, and what does not

**Here:** facts about the machine and the lab — the volume group, the bridges,
the CPU partition, filesystem paths, sizing constants. These are committed,
reviewed, and identical for every process on the host.

**Not here: secrets and endpoints.** `WORKER_TOKEN`, `SANDBOXD_API`,
`SANDBOXD_TOTAL_MIB` and the TLS paths come from the process environment, via
`/etc/sandboxd/sandboxd.env`. A token in a git-tracked file is a token in every
clone of the repository, and the memory budget deliberately has **no default**
at all — there is no safe guess for how much memory a Dom0 may hand to malware.
`Settings.from_env` in `daemon.py` reads those and refuses to start without
them.

## This file feeds two things that are not Python

`automation/platform.env` is sourced by `network-setup.sh`, `clone.pl` and the
per-OS scripts, and `misc/*.cfg` are Xen configs. Neither can import Python, so
both are **generated from the values below**:

    scripts/gen-xen-configs.py            # rewrite them
    scripts/gen-xen-configs.py --check    # exit 1 if either has drifted

`sandboxd/tests/test_xen_configs.py` fails until they agree, so editing a
generated file by hand is reverted on the next run. **Change it here.**

The reason for that direction, rather than reading the env file: one source has
to win, and disagreement between the shell pipeline and `sandboxd` about
`ANALYSIS_BRIDGE` is not a loud misconfiguration. It is a clone attached to a
bridge carrying no isolation rules, which looks exactly like a working analysis.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


# ===========================================================================
# Storage
# ===========================================================================

#: LVM volume group holding the golden images, the sandbox templates and every
#: per-clone copy-on-write snapshot. One VG per host.
#:
#: A dash in the name is escaped by device-mapper as a double dash, so
#: `vg-root` appears as `vg--root-*` under `/dev/mapper` and in `grub.cfg`.
#: That has already produced a false-negative grep during the migration; see
#: docs/TROUBLESHOOTING.md. A name with no dash would have avoided it.
VG_NAME = "vg-root"


# ===========================================================================
# Networking
# ===========================================================================

#: The analysis bridge. VLAN sub-interfaces `<bridge>.<vlan>` are created on it,
#: one per clone slot, and every isolation rule matches the `<bridge>.+`
#: wildcard rather than anything guest-specific.
#:
#: Nothing creates the bridge itself -- `ovs-vsctl add-br xenbr1` is a one-time
#: install step, and `network-setup.sh` fails with a message naming that step if
#: it is absent.
ANALYSIS_BRIDGE = "xenbr1"

#: The uplink to the Internet. Clone egress is narrowed to this interface:
#: traffic out of a VLAN sub-interface to anywhere else is dropped, which is
#: what stops clone-to-clone and clone-to-LAN traffic.
UPLINK_BRIDGE = "xenbr0"

#: First two octets of the per-VLAN gateway scheme, `<prefix>.<vlan>.1/24`. The
#: third octet IS the VLAN id, which is why a clone count above 255 is rejected.
#:
#: This is NOT the RFC1918 range used in the isolation drop list. That list
#: covers 172.16.0.0/12 among others and is about what a clone may *reach*, not
#: where its own gateway lives. The two are independent.
SUBNET_PREFIX = "172.16"


# ===========================================================================
# CPU partition
# ===========================================================================
#
# **Xen sees 24 online pCPUs, not 32.** `smt=0` parks all eight P-core
# siblings, leaving 8 P-cores as the EVENS 0,2,4,6,8,10,12,14 and 16 E-cores
# as 16-31.
#
# **That is the trap.** A range resolves against ONLINE pCPUs, so the
# nested-era `cpus="6-11"` silently meant {6,8,10} -- three cores, all three
# of them Dom0's, with clones sharing every core with the DRAKVUF event loop.
# Enumerate P-cores explicitly. Ranges are safe only across 16-31, where no
# sibling is parked. Confirm the online set with `xl cpupool-list -c`.
#
# The split is the hardware boundary, adopted 2026-08-31: Dom0 and DRAKVUF on
# the fast cores, guests on the slow ones. Defensible because
# docs/runbooks/12-baremetal-trial.md F7 measured clone vCPUs paused ~93% of
# wall time, and H2 measured clones on E-cores at -0.5% against the P-core
# baseline -- inside the 0.6% run-to-run spread, so no measurable cost. C3a's
# 1.7x E-core figure is a busy loop and does not transfer to a mostly-paused
# guest.

#: Dom0's own pCPUs. **Recorded, not applied.** Dom0's affinity comes from
#: `dom0_max_vcpus` and `dom0_vcpus_pin` on the Xen boot line, which lives in
#: `/etc/default/grub.d/` on the host and is not in this repository. This value
#: exists so the whole partition is readable in one place and a reviewer can
#: check the boot line against it.
#:
#: `dom0_vcpus_pin` hands Dom0 the first N ONLINE pCPUs, so `dom0_max_vcpus=8`
#: yields exactly the eight evens below. **Verify with `xl vcpu-list 0` after
#: any change**: FINDING C-1 records the sixth pin silently not taking on a
#: sparse online set, leaving one vCPU floating onto another's core.
DOM0_PCPUS = "0,2,4,6,8,10,12,14"

#: Analysis clones, written into `misc/*_sandbox.cfg`. All clones share this
#: set; it is not divided per slot and does not need to be, because memory
#: binds concurrency long before cores do.
CLONE_PCPUS = "16-27"

#: The platform DomU, written into `misc/platform.cfg`. Disjoint from
#: `CLONE_PCPUS` on purpose: it is a long-running service and clones are
#: transient, so overlapping would put analysis load on the domain that records
#: the analysis.
PLATFORM_PCPUS = "28-31"


# ===========================================================================
# Filesystem paths on Dom0
# ===========================================================================

#: Where the repository is checked out on Dom0. Scripts resolve their own
#: location at runtime, so this only matters to paths built from it.
DOM0_REPO_ROOT = Path("/root/drakvuf-multios-sandbox")

#: Samples are staged here before injection, and results collected here after.
#: Both are Dom0-side; nothing under them is ever visible to a guest.
STAGING_DIR = Path("/var/lib/sandboxd/staging")
RESULTS_DIR = Path("/var/lib/sandboxd/results")

#: Per-clone Xen configs are written here. `/tmp` is deliberate -- they are
#: regenerated per run and must not survive a reboot.
CONFIG_DIR = Path("/tmp")


# ===========================================================================
# Sizing and timing
# ===========================================================================

#: Added to a domain's `memory =` to get what it actually costs the host.
#:
#: **The overhead is unresolved and this is a guard, not a measurement.** Two
#: observations from the same lab disagree: 112 MiB measured directly, against
#: ~2063 MiB consumed for a 2048 MiB clone. Neither is wrong on its face -- the
#: methods differ and nobody has reconciled them. Both numbers are recorded
#: here, rather than in a runbook, because the next person to tune this down
#: needs to know the figure is contested.
#:
#: **Set above the measurement, not to it.** The failure modes are asymmetric:
#: over-reserving costs a little idle RAM, under-reserving overcommits the host
#: and the symptom is a clone failing to restore under memory pressure, not a
#: number anyone reads. One measurement of one clone is not a distribution.
#:
#: A second Dom0 needs its own pass -- capacity is a property of the machine
#: even when the overhead is a property of Xen. A Windows clone's overhead has
#: never been observed at all.
DOMAIN_OVERHEAD_MIB = 150

#: How often the daemon renews a job lease. Well inside the platform's
#: `LEASE_SECONDS=120`, so two consecutive failures still leave margin.
HEARTBEAT_INTERVAL = 20.0

#: Live console relay, off unless explicitly enabled. This is a **Dom0-side
#: kill switch** independent of the platform's own `CONSOLE_ENABLED`: an
#: operator can refuse sessions on this host without touching the platform.
#:
#: Off by default, and it really is off -- it read `True` with no override at
#: all until 2026-08-27, so a host opened a relay socket per analysis with no
#: way to stop it short of editing this file. Overridable at runtime with
#: `SANDBOXD_CONSOLE_ENABLED`, because turning it off is an emergency action.
CONSOLE_ENABLED = False
