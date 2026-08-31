"""Per-VLAN egress: which way out one clone gets, for the length of one job.

DRAFT-057. `automation/network-setup.sh` creates three empty chains and jumps
to them; this module fills them for one VLAN when a clone launches and empties
them when it is destroyed.

**The default is no egress, and it is an absence rather than a rule.** A VLAN
with nothing installed falls through `DRAKVUF_ISOLATION` to its terminal DROP.
So `offline` cannot be misconfigured -- there is no rule expressing it to get
wrong -- and every other mode is a positive, per-VLAN, per-job statement.

Nothing here runs a command. Every function returns argv for `proc.run`, which
is what lets the whole rule set be asserted in the development container where
`iptables` does not exist and must not be assumed to (CLAUDE.md, "Infrastructure
boundary"). It is the same split `clone.argv_lvcreate` and `guests.argv_trace`
already use.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

from . import config
from .naming import MAX_VLAN, MIN_VLAN

log = logging.getLogger("sandboxd.egress")


class EgressMode(str, Enum):
    """Where a clone's traffic goes. Mirrored by the platform's `egress_mode`.

    The submitter chooses this, which makes it the **second untrusted routing
    input** in the system after `target_os` -- so like that one it is a closed
    set validated at a boundary, never free text, and never widened casually.
    """

    #: No route out. Isolation and gateway intact, nothing installed.
    OFFLINE = "offline"
    #: A responder on the gateway answers instead of the Internet (Phase 3).
    SIMULATED = "simulated"
    #: Transparently through Tor. TCP only -- see CAVEATS (Phase 2).
    TOR = "tor"
    #: Out through a tunnel to a VPS we rent (Phase 4).
    ROUTED = "routed"
    #: NAT out the host's own uplink. **The residential line.**
    DIRECT = "direct"


# Limitations that belong on the REPORT rather than in a comment.
#
# DRAFT-057's acceptance criterion 7: if an exit blocks a port, the report must
# distinguish "no SMTP traffic" from "SMTP was blocked upstream" -- otherwise a
# provider's policy silently becomes a false negative, which is the worst thing
# a sandbox can produce because it looks exactly like a result.
#
# Carried per exit rather than per mode: two VPS exits at different hosts block
# different things, and the whole point of recording them is that they are a
# property of the way out, not of the software.
CAVEAT_TCP_ONLY = "tcp-only"
CAVEAT_NO_UDP_DNS = "dns-via-resolver-only"
CAVEAT_SMTP_BLOCKED = "smtp-blocked-upstream"
CAVEAT_SMB_BLOCKED = "smb-blocked-upstream"
CAVEAT_NO_INTERNET = "no-real-internet"
CAVEAT_HOST_UPLINK = "egresses-via-host-uplink"


@dataclass(frozen=True)
class Exit:
    """One configured way out, declared by the host and never by a submitter.

    DRAFT-057 is explicit that peers are server-side configuration: a submitter
    naming a tunnel endpoint would be choosing where Dom0 sends traffic, which
    is a different feature with a different threat model. `name` is what crosses
    the API, and it is only ever matched against the set the host declared.
    """

    name: str
    mode: EgressMode
    #: The interface traffic leaves by. None for modes that never forward --
    #: `offline` (nothing leaves) and the redirect modes (the packet is
    #: rewritten to a local address and delivered to INPUT instead).
    interface: str | None = None
    country: str | None = None
    caveats: tuple[str, ...] = ()


class EgressUnavailable(RuntimeError):
    """This host cannot provide the requested exit.

    Raised at apply time as a last line: the platform should already have
    refused the job at submission, because it only offers what the host
    declared. Reaching here means the two disagree, and running the sample
    anyway -- with some other way out, or none -- is the failure this whole
    issue exists to prevent.
    """


def _vlan_ok(vlan: int) -> None:
    # Bounded before it reaches a chain name or an address. The same range
    # `naming.py` enforces, for the same reason: the vlan is the third octet of
    # <prefix>.<vlan>.0/24, so a value outside it has no gateway to belong to.
    if not isinstance(vlan, int) or isinstance(vlan, bool):
        raise ValueError(f"vlan must be an int, got {type(vlan).__name__}")
    if not MIN_VLAN <= vlan <= MAX_VLAN:
        raise ValueError(f"vlan out of range [{MIN_VLAN}, {MAX_VLAN}]: {vlan}")


def _waited(rules: list[list[str]]) -> list[list[str]]:
    """Put `-w <seconds>` on every rule, in one place rather than 30.

    Applied here rather than written into each literal so the rule bodies stay
    readable as rules -- what a reviewer checks is the match and the target,
    and a lock flag repeated on every line is noise that hides them.

    It goes immediately after `iptables` and before any `-t <table>`, which
    iptables accepts in any order. See `config.IPTABLES_WAIT_SECONDS` for why
    every one of these needs it; the short version is that an unwaited revoke
    losing a lock race left a clone's egress installed, silently, and looked
    exactly like the ordinary "there was nothing to remove" failure.
    """
    wait = str(config.IPTABLES_WAIT_SECONDS)
    return [[argv[0], "-w", wait, *argv[1:]] for argv in rules]


# Per-VLAN sub-chains, one pair per live clone.
#
# The alternative -- writing rules straight into DRAKVUF_EGRESS and deleting
# them by exact spec at teardown -- requires teardown to know which mode was
# applied. It does not always: a crash between `lvcreate` and the mode being
# recorded, or a partial apply, leaves rules whose shape nobody can reconstruct.
# Deleting a sub-chain needs no such knowledge, so cleanup is total by
# construction rather than by bookkeeping.
#
# It also makes one clone's whole network posture readable in one command:
#
#     iptables -S DRAKVUF_EGRESS_V3
#
# 23 characters at the longest (`DRAKVUF_EGRESS_NAT_V254`), inside iptables'
# 28-character chain-name limit.
def filter_chain(vlan: int) -> str:
    _vlan_ok(vlan)
    return f"DRAKVUF_EGRESS_V{vlan}"


def nat_chain(vlan: int) -> str:
    _vlan_ok(vlan)
    return f"DRAKVUF_EGRESS_NAT_V{vlan}"


def pre_chain(vlan: int) -> str:
    """Where a redirect mode's PREROUTING rules live."""
    _vlan_ok(vlan)
    return f"DRAKVUF_EGRESS_PRE_V{vlan}"


def in_chain(vlan: int) -> str:
    """Where a redirect mode's INPUT exception lives.

    Needed because a REDIRECT rewrites the destination to the clone's own
    gateway, which makes the packet locally destined -- so it is delivered to
    INPUT and never reaches FORWARD. `DRAKVUF_INPUT`'s blanket drop would
    otherwise discard the very traffic the mode exists to carry.
    """
    _vlan_ok(vlan)
    return f"DRAKVUF_EGRESS_IN_V{vlan}"


#: Filled by network-setup.sh, jumped to from DRAKVUF_ISOLATION, POSTROUTING,
#: PREROUTING and DRAKVUF_INPUT respectively.
PARENT_FILTER = "DRAKVUF_EGRESS"
PARENT_NAT = "DRAKVUF_EGRESS_NAT"
PARENT_PRE = "DRAKVUF_EGRESS_PRE"
PARENT_IN = "DRAKVUF_EGRESS_IN"


def vlan_interface(vlan: int, bridge: str = config.ANALYSIS_BRIDGE) -> str:
    _vlan_ok(vlan)
    return f"{bridge}.{vlan}"


def vlan_subnet(vlan: int, subnet: str = config.SUBNET_PREFIX) -> str:
    """The clone's /24. Used to source-match NAT.

    Matching on the source network rather than on the input interface because
    POSTROUTING runs after the routing decision, where `-i` is no longer
    meaningful -- iptables rejects `-i` in POSTROUTING outright.
    """
    _vlan_ok(vlan)
    return f"{subnet}.{vlan}.0/24"


# Modes implemented here, and what each one's rules look like. Absent modes
# raise rather than silently doing nothing -- see `argv_apply`.
#
# Adding an interface-based exit is one entry, not a branch: `routed` differs
# from `direct` only in which interface it names, which is why the builder is
# parameterised on `exit_.interface` rather than switched on the mode.
_FORWARDING_MODES = frozenset({EgressMode.DIRECT, EgressMode.ROUTED})

#: Modes that rewrite the destination to the clone's own gateway instead of
#: forwarding. They share a shape -- rules in PREROUTING and INPUT, none in
#: FORWARD or POSTROUTING -- and a failure mode: a redirect to a port nothing
#: listens on is a black hole that reads as a quiet sample.
_REDIRECT_MODES = frozenset({EgressMode.TOR, EgressMode.SIMULATED})

#: The port whose liveness decides whether a redirect mode may be offered at
#: all, and re-checked before it is applied to a clone.
LISTENER_PORT = {
    EgressMode.TOR: config.TOR_TRANS_PORT,
    EgressMode.SIMULATED: config.FAKENET_PROXY_PORT,
}


#: The one exit every host always has. Not read from configuration, because a
#: host that failed to configure anything must still be able to run a sample
#: with no way out -- that is the safe direction to fail in, and it is the mode
#: DRAFT-057 calls "the cheapest risk reduction available to this project".
OFFLINE_EXIT = Exit(
    name="offline",
    mode=EgressMode.OFFLINE,
    caveats=(CAVEAT_NO_INTERNET,),
)


def listener_ready(port: int, *, host: str = "127.0.0.1",
                   timeout: float = 2.0) -> bool:
    """Is something accepting connections on this port right now?

    **The check that stops a redirect mode becoming a black hole.** Installing
    a PREROUTING REDIRECT to a port nothing listens on gives a clone whose
    every connection is refused instantly -- and the report then shows a sample
    that tried to talk and got nowhere, which is indistinguishable from a
    sample that was blocked, and worse than a sample that had no network at
    all. At least `offline` is honest about it.

    A TCP connect rather than parsing `ss` or `systemctl is-active`: it asks
    the question the rules actually depend on. tor can be running, enabled and
    healthy while bound to the wrong address, and a unit-file check would call
    that fine.

    127.0.0.1 because the listener binds 0.0.0.0, so loopback proves it is up
    without depending on any VLAN interface existing yet -- this runs at
    startup, before a clone has ever been built.
    """
    import socket

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        # Refused, unreachable, or timed out. All mean the same thing for this
        # decision: do not offer the mode.
        return False


def available_exits(
    *,
    allow_direct: bool = config.ALLOW_DIRECT,
    exits: dict | None = None,
    uplink: str = config.UPLINK_BRIDGE,
    probe=listener_ready,
) -> list[Exit]:
    """What this host declares it can offer. The platform offers only this.

    The gate on `direct` lives here rather than in the API because the host is
    the only party that knows what its uplink actually is. A platform-side
    check would be a second place that has to agree, and CLAUDE.md's own
    example of that shape -- two pipelines free to disagree about the bridge --
    is a clone attached to a network with no isolation rules, which looks like
    a working analysis.
    """
    out = [OFFLINE_EXIT]

    for name, spec in (exits if exits is not None else config.EXITS).items():
        mode = EgressMode(spec["mode"])
        if mode is EgressMode.DIRECT and not allow_direct:
            continue

        # A redirect mode is only offerable if its listener is actually up.
        # Withheld rather than offered-and-broken: the platform then never
        # shows it, so a submitter cannot pick a mode that would silently
        # produce an empty report. The daemon logs the withholding, because
        # "tor is not offered" needs to be findable when someone expects it.
        if mode in _REDIRECT_MODES and not probe(LISTENER_PORT[mode]):
            log.warning(
                "exit %r (%s) is configured but nothing is listening on "
                "127.0.0.1:%d -- NOT offering it. Until the responder is "
                "running this mode would redirect clone traffic to a closed "
                "port, and every analysis would report a sample that could "
                "not connect. See automation/%s.",
                name, mode.value, LISTENER_PORT[mode],
                "torrc" if mode is EgressMode.TOR else "fakenet.ini")
            continue

        out.append(Exit(
            name=name,
            mode=mode,
            interface=spec.get("interface"),
            country=spec.get("country"),
            caveats=tuple(spec.get("caveats", ())),
        ))

    if allow_direct and not any(e.mode is EgressMode.DIRECT for e in out):
        # The implicit one. A host that set SANDBOXD_ALLOW_DIRECT=1 means the
        # uplink, and requiring it to also spell out an EXITS entry naming its
        # own bridge would be a second switch that can disagree with the first.
        out.append(Exit(
            name="host-uplink",
            mode=EgressMode.DIRECT,
            interface=uplink,
            caveats=(CAVEAT_HOST_UPLINK,),
        ))

    return out


def argv_apply(
    vlan: int,
    exit_: Exit,
    *,
    bridge: str = config.ANALYSIS_BRIDGE,
    subnet: str = config.SUBNET_PREFIX,
) -> list[list[str]]:
    """The commands that give this VLAN this way out. Run in order, all checked.

    Returns an empty list for `offline`: there is nothing to install, because
    the absence of a rule IS the mode. That is deliberate rather than a
    shortcut -- an `offline` that installed a DROP would be one more thing that
    can fail to be installed, and its failure would open egress rather than
    close it.
    """
    _vlan_ok(vlan)

    if exit_.mode is EgressMode.OFFLINE:
        return []

    if exit_.mode is EgressMode.TOR:
        return _argv_apply_tor(vlan, bridge)

    if exit_.mode is EgressMode.SIMULATED:
        return _argv_apply_simulated(vlan, bridge)

    if exit_.mode not in _FORWARDING_MODES:
        raise EgressUnavailable(
            f"egress mode {exit_.mode.value!r} has no rule builder on this "
            f"host (exit {exit_.name!r}). The host should not have declared "
            f"this exit."
        )

    if not exit_.interface:
        raise EgressUnavailable(
            f"exit {exit_.name!r} is mode {exit_.mode.value!r}, which forwards, "
            f"but declares no interface to forward out of. A rule naming no "
            f"interface would accept egress by ANY route, including the host "
            f"uplink this mode may exist to avoid."
        )

    fchain = filter_chain(vlan)
    nchain = nat_chain(vlan)
    iface = vlan_interface(vlan, bridge)
    source = vlan_subnet(vlan, subnet)
    out = exit_.interface

    return _waited([
        # Created fresh. `-N` fails if it exists, which is the wanted
        # behaviour: a chain left over from a previous clone on this VLAN
        # means the sweep or the teardown did not run, and quietly reusing it
        # would inherit that clone's rules -- DRAFT-033's cross-sample
        # contamination, in the network instead of on disk.
        ["iptables", "-N", fchain],

        # The permit, naming exactly one interface in each direction. Under
        # `routed` this is the kill-switch: nothing here names the uplink, so
        # if the tunnel interface disappears the rule cannot match and the
        # packet falls to DRAKVUF_ISOLATION's terminal DROP. Fail-closed is a
        # property of what the rule says, not of a watchdog noticing in time.
        ["iptables", "-A", fchain, "-i", iface, "-o", out, "-j", "ACCEPT"],

        # The return path. Every rule above matches on the input interface, and
        # a reply arrives on the exit interface, so without this egress would
        # depend on FORWARD's policy again -- which is what DRAFT-029 removed.
        ["iptables", "-A", fchain, "-i", out, "-o", iface,
         "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],

        # Terminal, per VLAN, for the same reason the parent chain is terminal:
        # so that this clone's posture is decided here and does not depend on
        # what any later rule happens to say.
        ["iptables", "-A", fchain, "-j", "DROP"],

        # Source NAT for this VLAN only.
        ["iptables", "-t", "nat", "-N", nchain],
        ["iptables", "-t", "nat", "-A", nchain, "-s", source, "-o", out,
         "-j", "MASQUERADE"],

        # Jumps LAST, both tables. Until these are added the sub-chains are
        # unreachable, so a failure part-way through the rules above leaves a
        # clone with no egress rather than with a partly-built one that permits
        # more than it should. Install the policy, then connect it.
        ["iptables", "-t", "nat", "-A", PARENT_NAT, "-s", source,
         "-j", nchain],
        ["iptables", "-A", PARENT_FILTER, "-i", iface, "-j", fchain],
    ])


def _argv_apply_tor(vlan: int, bridge: str) -> list[list[str]]:
    """Transparent Tor for one VLAN: redirect TCP and DNS, drop the rest.

    **Nothing is forwarded, so there is no FORWARD rule and no MASQUERADE.**
    A REDIRECT rewrites the destination to the incoming interface's own
    address, so the packet stops being transit traffic and becomes traffic
    addressed to Dom0 -- delivered to INPUT, where the sub-chain below admits
    it, and never seen by DRAKVUF_ISOLATION at all.

    Two consequences fall out of that and both are wanted:

    * **The clone needs no configuration.** It keeps its resolver and its real
      destination address; the rewrite happens underneath it. That is what
      keeps the agentless design intact and is the same mechanism
      `networking.md` reasons through for FakeNet.
    * **Everything not matched here dies.** UDP other than 53, ICMP, and any
      IPv6 fall through to DRAKVUF_ISOLATION's terminal DROP with no rule
      needed. That is not a gap: Tor carries TCP only, so a UDP permit would
      lead somewhere that cannot carry it.

    The onion virtual range (10.192.0.0/10, per `automation/torrc`) sits inside
    the 10.0.0.0/8 that DRAKVUF_ISOLATION drops. Harmless, and worth writing
    down rather than rediscovering: nat PREROUTING rewrites the destination
    before FORWARD is consulted, so an onion connection is already addressed to
    the gateway by the time that rule could match.
    """
    pchain = pre_chain(vlan)
    ichain = in_chain(vlan)
    iface = vlan_interface(vlan, bridge)
    trans = str(config.TOR_TRANS_PORT)
    dns = str(config.TOR_DNS_PORT)

    return _waited([
        ["iptables", "-t", "nat", "-N", pchain],

        # Every TCP connection, whatever its destination address or port. Tor
        # decides what it can actually carry; its exit policy rejects 25 and
        # 445 among others, and that refusal is recorded as a caveat on the
        # exit rather than hidden.
        ["iptables", "-t", "nat", "-A", pchain, "-i", iface, "-p", "tcp",
         "-j", "REDIRECT", "--to-ports", trans],

        # DNS, to Tor's own resolver. Matched on the PORT rather than on the
        # configured nameserver's address: a sample that sets its own resolver
        # would otherwise bypass this and emit plaintext queries that go
        # nowhere, and the capture would show the lookups without the answers.
        ["iptables", "-t", "nat", "-A", pchain, "-i", iface, "-p", "udp",
         "--dport", "53", "-j", "REDIRECT", "--to-ports", dns],

        # The INPUT exception, scoped to this VLAN and these two ports. The
        # destination port matched here is the REWRITTEN one, because nat
        # PREROUTING runs before filter INPUT.
        ["iptables", "-N", ichain],
        ["iptables", "-A", ichain, "-i", iface, "-p", "tcp",
         "--dport", trans, "-j", "ACCEPT"],
        ["iptables", "-A", ichain, "-i", iface, "-p", "udp",
         "--dport", dns, "-j", "ACCEPT"],
        # Terminal, so this VLAN's access to Dom0 is decided here rather than
        # by whatever sits below the parent's jump.
        ["iptables", "-A", ichain, "-i", iface, "-j", "DROP"],

        # Jumps last, as in the forwarding case: until these are added the
        # sub-chains are unreachable, so a failure above leaves the clone with
        # no egress rather than with a half-built mode.
        ["iptables", "-t", "nat", "-A", PARENT_PRE, "-i", iface, "-j", pchain],
        ["iptables", "-A", PARENT_IN, "-i", iface, "-j", ichain],
    ])


def _argv_apply_simulated(vlan: int, bridge: str) -> list[list[str]]:
    """A fake Internet on the clone's own gateway, for one VLAN.

    Structurally identical to `tor` -- redirect, never forward -- and different
    only in where the traffic is pointed. See `_argv_apply_tor` for why that
    shape is what keeps the guest unconfigured.

    **Everything goes to FakeNet's proxy listener rather than to per-protocol
    ports.** `DefaultTCPListener: ProxyTCPListener` means the proxy identifies
    the protocol from the content and hands off internally, so one rule covers
    every port a sample might choose. The alternative -- enumerating 80, 443,
    25, 21, 110, 6667 here -- would put a second copy of FakeNet's own port
    table in our chains, free to drift, with "the sample's traffic went
    unanswered" as the only symptom.

    DNS is the exception, sent straight to the DNS listener. One extra rule for
    certainty about the protocol everything else depends on: a sample that
    cannot resolve its C2 domain does nothing, and that reads as a dull sample
    rather than as a broken responder.

    **This mode reaches nothing.** No FORWARD accept, no MASQUERADE, so a
    failure of the responder cannot become egress -- it can only become
    silence, which is the direction this whole issue insists on failing in.
    """
    pchain = pre_chain(vlan)
    ichain = in_chain(vlan)
    iface = vlan_interface(vlan, bridge)
    proxy = str(config.FAKENET_PROXY_PORT)
    dns = str(config.FAKENET_DNS_PORT)

    return _waited([
        ["iptables", "-t", "nat", "-N", pchain],

        # DNS first: a more specific rule must precede the catch-all below, or
        # queries would be swallowed by the proxy port.
        ["iptables", "-t", "nat", "-A", pchain, "-i", iface, "-p", "udp",
         "--dport", "53", "-j", "REDIRECT", "--to-ports", dns],

        ["iptables", "-t", "nat", "-A", pchain, "-i", iface, "-p", "tcp",
         "-j", "REDIRECT", "--to-ports", proxy],
        ["iptables", "-t", "nat", "-A", pchain, "-i", iface, "-p", "udp",
         "-j", "REDIRECT", "--to-ports", proxy],

        ["iptables", "-N", ichain],
        ["iptables", "-A", ichain, "-i", iface, "-p", "tcp",
         "--dport", proxy, "-j", "ACCEPT"],
        ["iptables", "-A", ichain, "-i", iface, "-p", "udp",
         "--dport", proxy, "-j", "ACCEPT"],
        ["iptables", "-A", ichain, "-i", iface, "-p", "udp",
         "--dport", dns, "-j", "ACCEPT"],
        ["iptables", "-A", ichain, "-i", iface, "-j", "DROP"],

        ["iptables", "-t", "nat", "-A", PARENT_PRE, "-i", iface, "-j", pchain],
        ["iptables", "-A", PARENT_IN, "-i", iface, "-j", ichain],
    ])


def argv_revoke(
    vlan: int,
    *,
    bridge: str = config.ANALYSIS_BRIDGE,
    subnet: str = config.SUBNET_PREFIX,
) -> list[list[str]]:
    """The commands that take this VLAN's egress away. Run in order, UNCHECKED.

    **Every one of these may legitimately fail**, and the caller must not treat
    that as an error: the usual reason is that there was nothing to remove --
    an `offline` job, or a clone that died before its rules were installed.
    `iptables -D` on an absent rule and `-X` on an absent chain both exit 1.

    The consequence is that this function cannot report its own success, so a
    caller that needs to know must ask separately -- see `argv_probe_chains`.
    Treating a non-zero exit here as failure would fail every teardown; the
    reverse, which is what happened, silently kept the ones that mattered.

    Order is the reverse of `argv_apply`: disconnect first, then empty, then
    remove. A clone loses its network at the first command rather than at the
    last, so a failure part-way through leaves it isolated instead of leaving a
    live sub-chain nothing points at.
    """
    _vlan_ok(vlan)

    fchain = filter_chain(vlan)
    nchain = nat_chain(vlan)
    pchain = pre_chain(vlan)
    ichain = in_chain(vlan)
    iface = vlan_interface(vlan, bridge)
    source = vlan_subnet(vlan, subnet)

    return _waited([
        # All four disconnections first, whichever mode actually ran. A
        # forwarding job never had a PRE chain and a tor job never had a NAT
        # one; attempting both is how this stays mode-agnostic, and the two
        # that were never there fail harmlessly.
        ["iptables", "-D", PARENT_FILTER, "-i", iface, "-j", fchain],
        ["iptables", "-t", "nat", "-D", PARENT_NAT, "-s", source, "-j", nchain],
        ["iptables", "-t", "nat", "-D", PARENT_PRE, "-i", iface, "-j", pchain],
        ["iptables", "-D", PARENT_IN, "-i", iface, "-j", ichain],

        ["iptables", "-F", fchain],
        ["iptables", "-X", fchain],
        ["iptables", "-t", "nat", "-F", nchain],
        ["iptables", "-t", "nat", "-X", nchain],
        ["iptables", "-t", "nat", "-F", pchain],
        ["iptables", "-t", "nat", "-X", pchain],
        ["iptables", "-F", ichain],
        ["iptables", "-X", ichain],
    ])


def argv_probe_chains(
    vlan: int,
    *,
    bridge: str = config.ANALYSIS_BRIDGE,
) -> list[list[str]]:
    """Ask whether this VLAN's chains are still there. **Exit 0 means PRESENT.**

    The inverted sense is deliberate and is the whole reason this exists.
    `argv_revoke` cannot report its own success: ten of its twelve commands
    fail legitimately on the ordinary path -- `iptables -D` on an absent rule
    and `-X` on an absent chain both exit 1 -- so a genuine failure is
    indistinguishable from "there was nothing to remove". A revoke that lost a
    lock race, timed out, or hit a still-referenced chain looked exactly like
    an `offline` job tearing down cleanly.

    So cleanliness is asserted POSITIVELY instead of inferred from exit codes:
    `iptables -S <chain>` succeeds if and only if the chain exists. Any of
    these succeeding means something survived teardown, and the VLAN must not
    be handed to the next sample -- it would inherit this one's way out, which
    is DRAFT-033's cross-sample contamination in the network.

    Slightly conservative: a chain that was emptied and unreferenced but not
    deleted is harmless, and this still calls it dirty. That is the correct
    direction to be wrong in, and the startup sweep reclaims the VLAN.
    """
    _vlan_ok(vlan)
    return _waited([
        ["iptables", "-S", filter_chain(vlan)],
        ["iptables", "-t", "nat", "-S", nat_chain(vlan)],
        ["iptables", "-t", "nat", "-S", pre_chain(vlan)],
        ["iptables", "-S", in_chain(vlan)],
    ])


def argv_revoke_blanket(
    *,
    bridge: str = config.ANALYSIS_BRIDGE,
    uplink: str = config.UPLINK_BRIDGE,
) -> list[list[str]]:
    """Remove a wildcard permit `network-setup.sh direct` left behind.

    **Not per-VLAN, and that is the whole point.** Everything in `argv_revoke`
    names one VLAN, because everything sandboxd installs names one VLAN. The
    legacy `direct` rules name none -- they match `<bridge>.+`, every clone at
    once -- so no per-VLAN delete can ever match them and nothing removed them.

    The consequence was that `direct` was permanent rather than
    per-invocation. One `ALLOW_DIRECT=1 ./run_analysis-ubuntu.sh` left both
    rules standing for the host's uptime, and every job afterwards egressed
    through them -- including jobs recorded and reported as `offline`, which
    install no rules and so had nothing that could notice.

    Run once per sweep rather than once per VLAN: there is one rule, not one
    per slot. Unchecked like the rest of teardown -- the normal case on a host
    that has never run `direct` is that both deletes fail because there is
    nothing to delete.

    Safe here and nowhere else. The sweep has just destroyed every clone, so
    removing a blanket permit cannot cut a live analysis; doing the same thing
    while clones were running would.
    """
    return _waited([
        ["iptables", "-D", PARENT_FILTER, "-i", f"{bridge}.+", "-o", uplink,
         "-j", "ACCEPT"],
        ["iptables", "-t", "nat", "-D", PARENT_NAT, "-o", uplink,
         "-j", "MASQUERADE"],
    ])
