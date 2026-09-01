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


# ===========================================================================
# Egress -- where a clone's traffic goes (DRAFT-057)
# ===========================================================================
#
# **This host declares what it can offer; the platform offers only that.** A
# mode the host does not declare cannot be selected in the UI, cannot be
# submitted through the API, and would be refused here if it somehow arrived.
# That chain is what keeps `direct` off the web entirely.
#
# `offline` is not listed and never needs to be. It is the absence of a rule,
# so every host can always provide it and nothing can fail to install it -- see
# sandboxd/egress.py.

#: How long an `iptables` call waits for the xtables lock before giving up.
#:
#: **Every egress rule carries this, and the teardown path is why.** Several
#: worker threads apply and revoke rules at once, and `network-setup.sh` fires
#: dozens more when it is re-run; without a wait, the loser of a collision
#: exits 4 ("Another app is currently holding the xtables lock"). On the APPLY
#: path that is survivable -- `check=True`, so the job fails and no clone runs
#: with a half-built mode. On the REVOKE path it was not: those calls are
#: unchecked by necessity, because most of them fail legitimately when there
#: was nothing to remove, so a lock collision was indistinguishable from the
#: normal case and left a live permit behind.
#:
#: Bounded rather than a bare `-w`, which waits forever: teardown would then
#: stall until `timing.CLEANUP_BUDGET` killed it, twelve times over. Five
#: seconds is far longer than any rule edit here takes and still an order of
#: magnitude inside that budget.
#:
#: `-w <seconds>` needs iptables >= 1.6.0 (2016). Dom0 is Ubuntu 24.04
#: (kernel 6.8.0-138, CURRENT-STATE.md §1, confirmed 2026-08-28), which ships
#: 1.8.10.
IPTABLES_WAIT_SECONDS = 5

#: Whether this host will NAT clones out its OWN uplink.
#:
#: **On this deployment the uplink is a residential line**, which is the whole
#: reason DRAFT-057 exists: the binding constraint on detonating real malware
#: is the ISP's acceptable-use terms, enforced with no prosecutor by a party
#: that already knows the subscriber. Roadmap risk #13.
#:
#: So this is off, and turning it on is a deliberate act by someone at the
#: host with `SANDBOXD_ALLOW_DIRECT=1`. It exists for one purpose: reproducing
#: the pre-2026-08-31 behaviour that the evidenced Ubuntu pipeline was measured
#: on, so that a regression run compares like with like. It is not a
#: convenience for getting a sample online.
ALLOW_DIRECT = False

#: Exits this host can route through, as `name -> (mode, interface, country)`.
#:
#: Empty until an exit exists. A `routed` entry must not be added before its
#: kill-switch has been proven by packet capture -- DRAFT-057 makes that a
#: precondition of the mode being usable, and declaring it here is what makes
#: it selectable. The check is the operator's; the code cannot verify a capture.
#:
#: Peers are configuration, NEVER a submitter-supplied endpoint. A submitter
#: naming a tunnel endpoint would be choosing where Dom0 sends traffic, which
#: is a different feature with a different threat model.
#:
#: To offer Tor, install `automation/torrc` as `/etc/tor/torrc`, start tor, and
#: add::
#:
#:     EXITS = {
#:         "tor-default": {
#:             "mode": "tor",
#:             "caveats": ["tcp-only", "smtp-blocked-upstream",
#:                         "smb-blocked-upstream"],
#:         },
#:     }
#:
#: **The caveats are not decoration.** They are what makes the report say "SMTP
#: was blocked upstream" instead of showing nothing and letting a reader
#: conclude the sample was quiet. Tor's default exit policy rejects 25 and 445
#: among others, and it carries TCP only -- so a run that observed no UDP
#: observed nothing about whether the sample uses UDP.
#:
#: `tor` is withheld automatically if nothing is listening on TOR_TRANS_PORT,
#: so a declaration here is a statement of intent rather than a promise the
#: daemon takes on trust.
EXITS: dict[str, dict] = {}

#: Tor's transparent-proxy ports, as `automation/torrc` configures them.
#:
#: **These two numbers appear in three places and all three must agree**:
#: here, in `automation/torrc`, and in `network-setup.sh`'s uplink DROP rules
#: (which are literals, because that script cannot import Python). Changing one
#: alone gives a clone whose TCP is redirected to a port nothing listens on --
#: every connection times out, and the report reads as a sample that tried to
#: talk and got nowhere. `sandboxd/tests/test_egress.py` pins the pair against
#: the torrc so the divergence fails a test instead of an analysis.
#:
#: 9040/9053 rather than Tor's defaults (9050 SOCKS, 9051 control) so that a
#: system tor started by the distribution's own unit cannot be mistaken for
#: this one, and so a SOCKS client on the host cannot accidentally reach the
#: transparent proxy.
TOR_TRANS_PORT = 9040
TOR_DNS_PORT = 9053

#: FakeNet-NG's proxy listeners, as `automation/fakenet.ini` configures them.
#: Both TCP and UDP use 38926, which is FakeNet's own default.
#:
#: This is the CATCH-ALL, and pointing everything at it is what stops our rules
#: carrying a copy of FakeNet's port table. The proxy identifies the protocol
#: from the content and hands off to the right listener, so one redirect rule
#: covers every port a sample might pick -- including the unusual ones malware
#: actually uses. Enumerating 80, 443, 25, 21, 110, 6667 in our chains instead
#: would be a second copy of a list that lives in FakeNet's config, free to
#: drift, with "the sample's traffic was silently unanswered" as the symptom.
#:
#: The mechanism is OUR redirect rule and nothing else. `RedirectAllTraffic`
#: and `DefaultTCPListener` in fakenet.ini describe the same intent, but they
#: are read only by FakeNet's diverter, which `DivertTraffic: No` means we
#: never start. Treating them as the cause would be a trap: they can be right
#: while the behaviour is absent, and they were, before this rule existed.
#: 38926 is FakeNet's own default, kept so its documentation still reads true.
#: Note it sits INSIDE `ip_local_port_range` (32768-60999) and its listener
#: sets no SO_REUSEADDR, so one of Dom0's own outbound connections holding it
#: at startup would fail the bind and exit FakeNet. Not observed, low
#: probability, and the symptom is the same `[Errno 98]` documented for the DNS
#: port -- so look here before assuming a config error.
FAKENET_PROXY_PORT = 38926

#: DNS is redirected to FakeNet's DNS listener DIRECTLY rather than through the
#: proxy above. One extra rule, and it buys certainty about the single most
#: load-bearing protocol in a sandbox: a sample that cannot resolve its C2
#: domain does nothing at all, and the report looks like a dud sample rather
#: than a broken responder.
#:
#: NOT 53, and that is settled rather than provisional. FakeNet's DNS listener
#: binds 0.0.0.0 and its UDP server sets no SO_REUSEADDR, so systemd-resolved's
#: stub on 127.0.0.53 wins the port -- confirmed on Dom0 2026-09-01,
#: `[Errno 98] Address already in use`, and a listener that cannot bind exits
#: the whole of FakeNet.
#:
#: **Only the redirect TARGET moves.** The rule still matches the guest's
#: `--dport 53`; nothing in the guest sees this number, and no preconfig script
#: changes. `egress._argv_apply_simulated` is the only reader.
#:
#: 5300 rather than something near 38926 because `ip_local_port_range` starts
#: at 32768: a port inside it can be held by one of Dom0's own outbound
#: connections at the moment FakeNet starts, which would be the same fatal bind
#: failure arriving intermittently. Anything chosen here should stay below
#: 32768 for that reason.
FAKENET_DNS_PORT = 5300

EXITS = {
    "tor-default": {
        "mode": "tor",
        "caveats": ["tcp-only", "smtp-blocked-upstream",
                    "smb-blocked-upstream"],
    },
    # `tls-untrusted-cert` is not optional on a `simulated` exit. The responder
    # mints its certificate from an ephemeral CA the guest has never trusted,
    # so a sample that validates refuses the handshake and its HTTPS never
    # reaches a listener -- observed on Dom0 2026-09-01. Without the string the
    # report shows a sample that did nothing rather than one whose encryption
    # was refused. `sandboxd/tests/test_egress.py` fails if it is omitted.
    "sim-local": {
        "mode": "simulated",
        "caveats": ["no-real-internet", "tls-untrusted-cert"],
    },
}
