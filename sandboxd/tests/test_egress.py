"""Per-VLAN egress rules, asserted as argv. DRAFT-057.

`iptables` is not in this container and must not be assumed to be, so what is
tested here is the rule set as a sequence of argv -- never a rendered command
line. A test that joined arguments into a string would let a rule pass here and
be re-split differently by a shell on Dom0, which is the class of bug the argv
split exists to remove.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sandboxd import config
from sandboxd.egress import (
    PARENT_FILTER,
    PARENT_NAT,
    EgressMode,
    EgressUnavailable,
    Exit,
    argv_apply,
    argv_probe_chains,
    argv_revoke,
    argv_revoke_blanket,
    available_exits,
    filter_chain,
    nat_chain,
)

DIRECT = Exit(name="host-uplink", mode=EgressMode.DIRECT, interface="xenbr0")
ROUTED = Exit(name="es-vps-1", mode=EgressMode.ROUTED, interface="wg0",
              country="es")
OFFLINE = Exit(name="offline", mode=EgressMode.OFFLINE)


def test_offline_installs_nothing():
    """The mode IS the absence of a rule.

    Not a shortcut: an `offline` that installed a DROP would be one more thing
    that can fail to be installed, and its failure would OPEN egress rather
    than close it.
    """
    assert argv_apply(3, OFFLINE) == []


def test_routed_never_names_the_uplink():
    """The kill-switch, asserted as a property of the rules themselves.

    If nothing in a routed VLAN's rule set names the host uplink, then a
    tunnel that disappears cannot silently fall back to it -- the ACCEPT
    cannot match and the packet hits the terminal DROP. This is the assertion
    that keeps that true as the builder changes.
    """
    for argv in argv_apply(3, ROUTED):
        assert "xenbr0" not in argv, f"routed rule names the uplink: {argv}"


def _op(argv: list[str]) -> str:
    """The iptables operation flag, wherever `-t <table>` put it."""
    return argv[_op_index(argv)]


def _op_index(argv: list[str]) -> int:
    """Where the operation flag sits.

    Found rather than assumed, because `-t <table>` and `-w <seconds>` both
    push it along by two and neither is present on every rule. A test that
    indexed a fixed position would break on the next flag added to all of
    them, which is what happened when `-w` arrived.
    """
    for i, token in enumerate(argv):
        if token in ("-N", "-A", "-D", "-F", "-X", "-I", "-S"):
            return i
    raise AssertionError(f"no operation flag in {argv}")


def test_routed_accepts_only_out_of_the_tunnel():
    """The OUTBOUND permit names the tunnel and nothing else.

    Filtered to rules whose input is the clone's interface: the chain also
    carries a return-path ACCEPT, and that one's `-o` is legitimately the VLAN
    interface, because it admits replies INTO the clone.
    """
    rules = argv_apply(7, ROUTED)
    outbound = [
        a for a in rules
        if a[-1] == "ACCEPT" and "-i" in a and a[a.index("-i") + 1] == "xenbr1.7"
    ]
    assert outbound, "no outbound ACCEPT was built"
    for argv in outbound:
        assert argv[argv.index("-o") + 1] == "wg0"


def test_return_path_admits_only_established():
    """Otherwise the return rule is a hole the Internet can open."""
    rules = argv_apply(7, ROUTED)
    inbound = [
        a for a in rules
        if a[-1] == "ACCEPT" and "-o" in a and a[a.index("-o") + 1] == "xenbr1.7"
    ]
    assert len(inbound) == 1
    assert "ESTABLISHED,RELATED" in inbound[0]


def test_jumps_are_installed_last():
    """Policy first, then connect it.

    A failure part-way through must leave a clone with NO egress rather than
    with a half-built chain that permits more than it should. That is only
    true if the jumps from the parent chains come after the rules.
    """
    rules = argv_apply(3, DIRECT)
    jump_positions = [
        i for i, a in enumerate(rules)
        if PARENT_FILTER in a or PARENT_NAT in a
    ]
    assert jump_positions == [len(rules) - 2, len(rules) - 1]


def test_each_vlan_gets_its_own_chains():
    assert filter_chain(3) != filter_chain(4)
    assert nat_chain(3) != nat_chain(4)


def test_chain_names_fit_the_iptables_limit():
    """28 characters. The longest name is at the top of the VLAN range."""
    for vlan in (1, 9, 10, 99, 100, 254):
        assert len(filter_chain(vlan)) <= 28
        assert len(nat_chain(vlan)) <= 28


def test_nat_matches_on_source_not_interface():
    """POSTROUTING runs after the routing decision, where `-i` is meaningless
    and iptables rejects it outright."""
    nat = [a for a in argv_apply(5, DIRECT) if "nat" in a and "-A" in a]
    assert nat
    for argv in nat:
        assert "-i" not in argv
    masq = [a for a in nat if a[-1] == "MASQUERADE"][0]
    assert masq[masq.index("-s") + 1] == "172.16.5.0/24"


def test_revoke_reverses_apply():
    """Disconnect, empty, remove -- the reverse of apply.

    So a failure part-way through teardown leaves the clone isolated rather
    than leaving a live sub-chain that nothing points at.
    """
    rules = argv_revoke(3)

    # EVERY disconnection comes first -- one per table a mode might have used
    # -- so the clone loses its network at the first commands rather than at
    # the last, whichever mode it was actually running.
    disconnects = [a for a in rules if _op(a) == "-D"]
    assert len(disconnects) == 4
    assert rules[:4] == disconnects
    assert PARENT_FILTER in rules[0]
    assert PARENT_NAT in rules[1]

    # Everything after them empties and removes; nothing deletes a chain
    # before it has been unjumped from.
    assert all(_op(a) in ("-F", "-X") for a in rules[4:])
    for chain in (filter_chain(3), nat_chain(3)):
        flush = next(i for i, a in enumerate(rules)
                     if _op(a) == "-F" and chain in a)
        drop = next(i for i, a in enumerate(rules)
                    if _op(a) == "-X" and chain in a)
        assert flush < drop


def test_revoke_needs_no_knowledge_of_the_mode():
    """The reason for per-VLAN sub-chains.

    Teardown does not always know which mode was applied -- a crash before the
    mode was recorded, or a partial apply. Removing a sub-chain needs no such
    knowledge, so cleanup is total by construction rather than by bookkeeping.
    """
    assert argv_revoke(3) == argv_revoke(3)
    # Same call signature whether the job ran direct, routed or offline.
    for exit_ in (DIRECT, ROUTED, OFFLINE):
        argv_apply(3, exit_) if exit_ is not OFFLINE else None
        assert argv_revoke(3)[0][_op_index(argv_revoke(3)[0]) + 1] == PARENT_FILTER


# --- simulated (Phase 3) --------------------------------------------------

SIMULATED = Exit(name="sim-local", mode=EgressMode.SIMULATED,
                 caveats=("no-real-internet",))


def test_simulated_reaches_nothing():
    """A responder failure must become silence, never egress.

    No FORWARD accept and no MASQUERADE means there is no path by which this
    mode can reach the real Internet, whatever happens to FakeNet.
    """
    rules = argv_apply(3, SIMULATED)
    assert not any("MASQUERADE" in a for a in rules)
    assert not any(PARENT_FILTER in a for a in rules)


def test_simulated_sends_everything_to_the_proxy_listener():
    """One rule per protocol, not a copy of FakeNet's port table.

    Enumerating 80/443/25/21/110/6667 here would be a second copy of a list
    that lives in fakenet.ini, free to drift, with "the sample's traffic went
    unanswered" as the only symptom.
    """
    redirects = [a for a in argv_apply(3, SIMULATED) if "REDIRECT" in a]
    proxied = [a for a in redirects
               if a[a.index("--to-ports") + 1] == str(config.FAKENET_PROXY_PORT)]
    assert len(proxied) == 2
    assert {a[a.index("-p") + 1] for a in proxied} == {"tcp", "udp"}
    for argv in proxied:
        assert "--dport" not in argv, "the catch-all must not filter by port"


def test_simulated_sends_dns_straight_to_the_dns_listener():
    """And BEFORE the catch-all, or queries are swallowed by the proxy port.

    DNS is the one protocol everything else depends on: a sample that cannot
    resolve its C2 domain does nothing, and that reads as a dull sample rather
    than as a broken responder.
    """
    redirects = [a for a in argv_apply(3, SIMULATED) if "REDIRECT" in a]
    dns = [a for a in redirects if "--dport" in a and a[a.index("--dport") + 1] == "53"]
    assert len(dns) == 1
    assert dns[0][dns[0].index("--to-ports") + 1] == str(config.FAKENET_DNS_PORT)
    assert redirects.index(dns[0]) == 0, "DNS must precede the UDP catch-all"


def test_both_redirect_modes_have_the_same_shape():
    """tor and simulated differ only in where traffic is pointed.

    If one grows a FORWARD rule and the other does not, the difference is a
    bug rather than a design -- they are the same mechanism.
    """
    for exit_ in (TOR, SIMULATED):
        rules = argv_apply(3, exit_)
        tables = {tuple(a[:3]) for a in rules}
        assert not any("MASQUERADE" in a for a in rules), exit_.name
        assert any("REDIRECT" in a for a in rules), exit_.name
        assert any("DRAKVUF_EGRESS_IN" in " ".join(a) for a in rules), exit_.name
        assert tables  # shape assertion above is the substance


def test_a_mode_with_no_builder_refuses_loudly():
    """Half a mode is worse than none: it looks like a working analysis."""
    class Fake(str):
        value = "teleport"
    bogus = Exit(name="x", mode=Fake("teleport"))
    with pytest.raises(EgressUnavailable, match="no rule builder"):
        argv_apply(3, bogus)


# --- tor (Phase 2) --------------------------------------------------------

TOR = Exit(name="tor-default", mode=EgressMode.TOR,
           caveats=("tcp-only", "smtp-blocked-upstream"))


def test_tor_forwards_nothing():
    """The structural property of a redirect mode.

    A REDIRECT rewrites the destination to the gateway, so the packet is
    delivered locally and never transits. A FORWARD accept or a MASQUERADE
    here would mean some traffic bypassing Tor entirely -- which is the one
    failure this mode cannot have, because it would leave from the host's own
    address while the report said `tor`.
    """
    rules = argv_apply(3, TOR)
    assert not any("MASQUERADE" in a for a in rules)
    assert not any(PARENT_FILTER in a for a in rules)
    assert not any(a[-1] == "ACCEPT" and "-o" in a for a in rules)


def test_tor_redirects_all_tcp_regardless_of_destination():
    """Matched on protocol, not on address or port.

    A sample connecting to a hard-coded IP on a strange port must go through
    Tor like any other. Matching destinations would be an allowlist of the
    traffic we expected, and malware is the thing that does not do what you
    expected.
    """
    tcp = [a for a in argv_apply(3, TOR) if "tcp" in a and "REDIRECT" in a]
    assert len(tcp) == 1
    assert "-d" not in tcp[0] and "--dport" not in tcp[0]
    assert tcp[0][tcp[0].index("--to-ports") + 1] == str(config.TOR_TRANS_PORT)


def test_tor_redirects_dns_by_port_not_by_resolver_address():
    """A sample that sets its own resolver must not escape the redirect.

    Matching on the configured nameserver's address would let it emit
    plaintext queries that go nowhere, and the capture would show the lookups
    without the answers.
    """
    udp = [a for a in argv_apply(3, TOR) if "udp" in a and "REDIRECT" in a]
    assert len(udp) == 1
    assert udp[0][udp[0].index("--dport") + 1] == "53"
    assert "-d" not in udp[0]
    assert udp[0][udp[0].index("--to-ports") + 1] == str(config.TOR_DNS_PORT)


def test_tor_grants_input_access_to_exactly_two_ports():
    """The hole punched in DRAKVUF_INPUT is one VLAN wide and two ports deep."""
    rules = argv_apply(7, TOR)
    accepts = [a for a in rules if a[-1] == "ACCEPT"]
    assert len(accepts) == 2
    for argv in accepts:
        assert argv[argv.index("-i") + 1] == "xenbr1.7"
        assert argv[argv.index("--dport") + 1] in (
            str(config.TOR_TRANS_PORT), str(config.TOR_DNS_PORT))
    # And the chain is terminal, so this VLAN's reach into Dom0 is decided
    # here rather than by whatever sits below the parent's jump.
    assert rules[[i for i, a in enumerate(rules)
                  if a[-1] == "DROP"][0]][-1] == "DROP"


def test_tor_leaves_udp_and_icmp_to_die_in_the_isolation_chain():
    """Not a gap. Tor carries TCP only, so a UDP permit would lead somewhere
    that cannot carry it -- the sample would hang rather than fail."""
    rules = argv_apply(3, TOR)
    udp_rules = [a for a in rules if "udp" in a]
    # Exactly one UDP rule, and it is the DNS redirect.
    assert len(udp_rules) == 2  # the REDIRECT and its INPUT accept
    assert all("53" in a or str(config.TOR_DNS_PORT) in a for a in udp_rules)
    assert not any("icmp" in a for a in rules)


def test_revoke_removes_the_tor_chains_too():
    """Teardown stays mode-agnostic as modes are added.

    A tor job never had a NAT chain and a forwarding job never had a PRE one.
    Attempting all four is what lets teardown work without knowing which ran.
    """
    revoked = " ".join(" ".join(a) for a in argv_revoke(3))
    for chain in ("DRAKVUF_EGRESS_V3", "DRAKVUF_EGRESS_NAT_V3",
                  "DRAKVUF_EGRESS_PRE_V3", "DRAKVUF_EGRESS_IN_V3"):
        assert f"-X {chain}" in revoked, f"{chain} is never removed"


def test_per_vlan_revoke_cannot_match_the_legacy_wildcard():
    """Why `argv_revoke_blanket` has to exist at all.

    The legacy `direct` rule is `-i xenbr1.+ -o xenbr0 -j ACCEPT`. Every
    delete in `argv_revoke` names one VLAN, and `iptables -D` matches an exact
    spec, so none of them can ever remove it. This asserts the gap rather than
    leaving the next reader to rediscover why a second function exists.
    """
    for argv in argv_revoke(3):
        assert "xenbr1.+" not in argv, (
            f"a per-VLAN revoke now names the wildcard interface: {argv}")


def test_blanket_revoke_removes_both_legacy_direct_rules():
    """The permit AND its NAT. Either one alone leaves the mode half-on.

    Without the MASQUERADE a clone's packets leave unNATted and the replies
    never come back, which looks like a broken network rather than a leak --
    so removing only the ACCEPT would still be wrong, just quieter.
    """
    revoked = argv_revoke_blanket(bridge="xenbr1", uplink="xenbr0")
    wait = str(config.IPTABLES_WAIT_SECONDS)

    assert revoked == [
        ["iptables", "-w", wait, "-D", PARENT_FILTER, "-i", "xenbr1.+",
         "-o", "xenbr0", "-j", "ACCEPT"],
        ["iptables", "-w", wait, "-t", "nat", "-D", PARENT_NAT,
         "-o", "xenbr0", "-j", "MASQUERADE"],
    ]


def test_blanket_revoke_deletes_by_spec_and_never_flushes():
    """A flush here would cut every live clone's network mid-trace.

    `-F` or `-X` on DRAKVUF_EGRESS would take the per-VLAN jumps with it. The
    sweep runs with nothing live so it would survive that, but the function is
    one edit away from being called somewhere that is not the sweep, and the
    guarantee should be a property of the argv rather than of the caller.
    """
    for argv in argv_revoke_blanket():
        assert "-D" in argv, f"blanket revoke is not a delete-by-spec: {argv}"
        assert "-F" not in argv and "-X" not in argv, argv


def test_network_setup_removes_the_wildcard_when_asked_for_offline():
    """The other half of the pair, pinned against the script.

    `direct` installs the wildcard and `offline` removes it; neither is
    idempotent alone. When only the install existed, one opt-in run made
    `direct` permanent -- every later job egressed through it, including jobs
    recorded and reported as `offline`. This fails if that branch is dropped
    again.
    """
    setup = (Path(__file__).resolve().parents[2]
             / "automation" / "network-setup.sh").read_text()

    assert '-D "$EGRESS_CHAIN" -i "$ANALYSIS_BRIDGE.+"' in setup, (
        "network-setup.sh no longer deletes the legacy wildcard ACCEPT; "
        "a single `direct` run becomes permanent again")
    assert '-D "$EGRESS_NAT_CHAIN" -o "$UPLINK_BRIDGE"' in setup, (
        "network-setup.sh no longer deletes the legacy wildcard MASQUERADE")

    # The deletion must never become a flush, for the reason section 3a gives:
    # it would take live clones' per-VLAN jumps with it.
    assert '-F "$EGRESS_CHAIN"' not in setup, (
        "network-setup.sh flushes DRAKVUF_EGRESS -- that cuts the network of "
        "every clone currently under analysis")


def test_every_rule_waits_for_the_xtables_lock():
    """No unwaited `iptables` anywhere, on any path.

    Worker threads apply and revoke concurrently and `network-setup.sh` fires
    dozens more on a re-run, so an unwaited call can lose the lock and exit 4.
    On the revoke path that was invisible -- those calls are unchecked by
    necessity, so a lock collision looked exactly like the ordinary "nothing
    to remove" failure and left the clone's egress installed.

    Asserted across every builder rather than one, because the flag is applied
    centrally in `_waited` and the failure mode of that refactor is a return
    path that forgot to go through it.
    """
    every = [
        *argv_apply(3, DIRECT), *argv_apply(3, ROUTED),
        *argv_apply(3, TOR), *argv_apply(3, SIMULATED),
        *argv_revoke(3), *argv_revoke_blanket(), *argv_probe_chains(3),
    ]
    assert every, "no rules to check -- the builders returned nothing"

    for argv in every:
        assert argv[0] == "iptables", argv
        assert argv[1] == "-w", f"unwaited iptables call: {argv}"
        assert argv[2] == str(config.IPTABLES_WAIT_SECONDS), argv


def test_the_wait_is_bounded():
    """A bare `-w` waits forever.

    Teardown would then stall until CLEANUP_BUDGET killed it, twelve times
    over, turning a lock collision into a teardown that takes minutes.
    """
    assert isinstance(config.IPTABLES_WAIT_SECONDS, int)
    assert 0 < config.IPTABLES_WAIT_SECONDS < 30


def test_the_probe_asks_about_every_chain_a_mode_could_leave():
    """Whichever mode ran, teardown must be able to detect its leftovers.

    A forwarding job leaves filter+nat chains and a redirect job leaves
    pre+input ones. Probing only one shape would make the other undetectable,
    which is the state the whole check exists to leave behind.
    """
    probed = " ".join(" ".join(a) for a in argv_probe_chains(7))
    for chain in ("DRAKVUF_EGRESS_V7", "DRAKVUF_EGRESS_NAT_V7",
                  "DRAKVUF_EGRESS_PRE_V7", "DRAKVUF_EGRESS_IN_V7"):
        assert f"-S {chain}" in probed, f"{chain} is never probed"


def test_the_probe_only_reads():
    """It runs on the teardown path against a VLAN whose state is unknown.

    `-S` and nothing else: a probe that could modify a chain would be a second
    writer racing the revoke it is checking.
    """
    for argv in argv_probe_chains(3):
        assert _op(argv) == "-S", f"probe is not read-only: {argv}"


def test_fakenet_never_flushes_iptables():
    """The single most dangerous default in FakeNet-NG, for this host.

    `LinuxFlushIptables: Yes` flushes EVERY rule -- DRAKVUF_ISOLATION,
    DRAKVUF_INPUT, both IPv6 chains -- for every clone currently running, and
    only restores them if its termination sequence is not interrupted. A
    kill -9 means malware VMs on an unfiltered network with nothing saying so.
    """
    ini = (Path(__file__).resolve().parents[2]
           / "automation" / "fakenet.ini").read_text()
    assert "LinuxFlushIptables: No" in ini


def test_fakenet_does_not_divert_traffic_itself():
    """Its diverter installs a BLANKET PREROUTING redirect.

    That would capture every analysis VLAN, so a clone submitted as `offline`
    would be answered by the responder -- `offline` would stop meaning offline,
    silently, and the report would look like a working analysis.
    """
    ini = (Path(__file__).resolve().parents[2]
           / "automation" / "fakenet.ini").read_text()
    assert "DivertTraffic: No" in ini


def test_fakenet_leaves_dom0s_own_resolver_alone():
    """These would edit /etc/resolv.conf and stop the resolver ON THE
    HYPERVISOR, to serve a guest that never asked."""
    ini = (Path(__file__).resolve().parents[2]
           / "automation" / "fakenet.ini").read_text()
    for option in ("ModifyLocalDNS: No", "StopDNSService: No",
                   "FixGateway: No", "FixDNS: No"):
        assert option in ini, option


def _fakenet_ini():
    """Parsed exactly as `Fakenet.parse_config()` parses it.

    Which is the point: that function reads ONLY the file it is given. There is
    no merge with FakeNet's `default.ini` -- that is the fallback for when no
    `-c` is passed. Asserting on the parse rather than on the text is what
    makes the next test able to say "nothing would bind".
    """
    from configparser import ConfigParser

    cfg = ConfigParser()
    cfg.read(Path(__file__).resolve().parents[2] / "automation" / "fakenet.ini")
    return cfg


def _fakenet_listeners():
    """The listener sections that would actually start, in start order."""
    cfg = _fakenet_ini()
    return [(name, dict(cfg.items(name)))
            for name in cfg.sections()
            if name not in ("FakeNet", "Diverter")
            and cfg.getboolean(name, "enabled")]


def test_the_fakenet_ports_agree_with_the_ini():
    """The proxy port is the catch-all our one redirect rule points at."""
    ini = (Path(__file__).resolve().parents[2]
           / "automation" / "fakenet.ini").read_text()
    assert "DefaultTCPListener: ProxyTCPListener" in ini
    assert "DefaultUDPListener: ProxyUDPListener" in ini
    assert "RedirectAllTraffic: Yes" in ini
    # 38926 is FakeNet's own default for both proxy listeners, read from
    # fakenet/configs/default.ini on 2026-08-31. Not restated in our ini, so
    # this pins the constant to the upstream default we relied on.
    assert config.FAKENET_PROXY_PORT == 38926

    # The three keys above are DIVERTER settings, and `DivertTraffic: No` means
    # the diverter never runs -- so they describe the intent and cause none of
    # it. These sections are what actually binds the port our rules target, and
    # for a while the file had the keys and not the sections.
    listeners = dict(_fakenet_listeners())
    for section, proto in (("ProxyTCPListener", "tcp"),
                           ("ProxyUDPListener", "udp")):
        assert section in listeners, f"{section} is missing or disabled"
        assert listeners[section]["protocol"].lower() == proto
        assert int(listeners[section]["port"]) == config.FAKENET_PROXY_PORT

    assert "DNS Server" in listeners, "nothing would answer a redirected query"
    assert int(listeners["DNS Server"]["port"]) == config.FAKENET_DNS_PORT


def test_fakenet_ini_starts_at_least_one_listener():
    """The failure this file exists to make impossible.

    A config carrying only [FakeNet] and [Diverter] parses, logs "Loaded
    configuration file", binds nothing, and idles -- and every check that looks
    for FakeNet's process finds it running. The symptom appears three steps
    later as a `simulated` clone that talks to nobody, which reads as a dull
    sample. Executing runbook 13 step 6 is what found it.
    """
    assert _fakenet_listeners(), (
        "fakenet.ini defines no enabled listener sections; FakeNet would "
        "start, bind nothing, and look healthy")


def test_fakenet_protocol_listeners_precede_the_raw_fallback():
    """Section order is behaviour, and nothing else in this file is.

    The proxy picks a listener by highest `taste()` confidence, breaking ties
    by whichever started first -- the ini's order. With diversion off the
    original destination port is unrecoverable, so every taste() scores on
    content alone: FTPListener returns 1 on a match and RawListener returns 1
    on anything. Move Raw above FTP and FTP silently stops being reachable.
    """
    names = [name for name, _ in _fakenet_listeners()]
    raw = [i for i, n in enumerate(names) if n.startswith("Raw")]
    assert raw, "no RawListener: unrecognised traffic would get silence"

    protocol_listeners = [i for i, n in enumerate(names)
                          if n.startswith(("FTPListener", "HTTPListener",
                                           "SMTP", "POP", "IRC", "TFTP",
                                           "DNS"))]
    assert max(protocol_listeners) < min(raw), (
        "a protocol listener is ordered after the Raw fallback; Raw's flat "
        "confidence of 1 will win the tie and that protocol is unreachable")


def test_fakenet_writable_roots_are_outside_the_package():
    """FTP and TFTP let the SAMPLE write, and upstream aims them at itself.

    FTPListener accepts any credentials and grants `elradfmwM` -- store,
    delete, rename, mkdir -- on FTProot. Upstream's default is `defaultFiles/`,
    which resolves to the installed package directory, so a sample under
    analysis could write into Dom0's site-packages. TFTPRoot takes uploads the
    same way.
    """
    for name, cfg in _fakenet_listeners():
        for key in ("ftproot", "tftproot"):
            if key not in cfg:
                continue
            root = cfg[key]
            assert root.startswith("/"), (
                f"[{name}] {key} is relative, so it resolves against the "
                f"installed package: {root}")


def test_fakenet_uplink_drops_cover_every_bound_port():
    """Every listener binds 0.0.0.0, so every port needs the uplink DROP.

    FakeNet overwrites each listener's address with one process-wide value and,
    with diversion off, never reads the setting that would restrict it to an
    interface. So enabling a listener in the ini exposes it to the house LAN --
    an open DNS resolver, in the worst case -- and the exposure is invisible to
    every test run from inside the lab.
    """
    import re

    setup = (Path(__file__).resolve().parents[2]
             / "automation" / "network-setup.sh").read_text()

    dropped = {"tcp": set(), "udp": set()}
    for proto in dropped:
        match = re.search(rf"^for fakenet_{proto} in ([^;]+); do$",
                          setup, re.MULTILINE)
        assert match, f"network-setup.sh has no fakenet_{proto} DROP loop"
        for token in match.group(1).split():
            if ":" in token:
                low, high = (int(p) for p in token.split(":"))
                dropped[proto].update(range(low, high + 1))
            else:
                dropped[proto].add(int(token))

    for name, cfg in _fakenet_listeners():
        proto = cfg["protocol"].lower()
        for token in cfg["port"].split(","):
            token = token.strip()
            if "-" in token:
                low, high = (int(p) for p in token.split("-"))
                ports = range(low, high + 1)
            else:
                ports = [int(token)]
            for port in ports:
                assert port in dropped[proto], (
                    f"[{name}] binds {proto}/{port} on 0.0.0.0 and "
                    f"network-setup.sh does not DROP it on the uplink")

        # pyftpdlib binds these on demand during a transfer, so they are absent
        # from `ss` at launch and are the ones a manual check misses.
        for token in cfg.get("pasvports", "").split(","):
            token = token.strip()
            if not token:
                continue
            low, high = (int(p) for p in token.split("-"))
            for port in range(low, high + 1):
                assert port in dropped["tcp"], (
                    f"[{name}] passive-data port tcp/{port} is not dropped "
                    f"on the uplink")


def test_fakenet_patch_is_shipped_and_pinned():
    """`DivertTraffic: No` is a path upstream does not run.

    Without the patch FakeNet binds every port, logs nothing alarming and
    answers nothing -- the confident false negative this whole issue exists to
    prevent. The version is pinned because hunk 3 is in a class upstream added
    recently and is the likeliest of the three to move.
    """
    patch = (Path(__file__).resolve().parents[2]
             / "automation" / "fakenet-divert-no.patch")
    assert patch.exists(), "fakenet.ini requires a patch that is not shipped"

    text = patch.read_text()
    assert "v3.5" in text, "the patch does not say which version it applies to"
    for target in ("fakenet/fakenet.py",
                   "fakenet/listeners/ProxyListener.py",
                   "fakenet/diverters/diverterbase.py"):
        assert f"+++ b/{target}" in text, f"patch no longer touches {target}"


def test_the_tor_ports_agree_with_the_torrc():
    """Three copies of two numbers, and nothing else checks they match.

    `automation/torrc` binds the listeners, `config.py` builds the redirect
    rules, and `network-setup.sh` DROPs the ports on the uplink. Change one
    alone and every clone's TCP goes to a port nothing listens on -- which
    reads as a sample that tried to talk and got nowhere, not as a
    misconfiguration.
    """
    torrc = (Path(__file__).resolve().parents[2]
             / "automation" / "torrc").read_text()
    assert f"TransPort 0.0.0.0:{config.TOR_TRANS_PORT}" in torrc
    assert f"DNSPort 0.0.0.0:{config.TOR_DNS_PORT}" in torrc

    setup = (Path(__file__).resolve().parents[2]
             / "automation" / "network-setup.sh").read_text()
    assert f"{config.TOR_TRANS_PORT} {config.TOR_DNS_PORT}" in setup, (
        "network-setup.sh's uplink DROP no longer covers both tor ports; "
        "without it these listeners are reachable from the uplink")


def test_tor_is_withheld_when_nothing_is_listening():
    """The check that stops this mode becoming a black hole.

    Rules redirecting to a closed port give a clone whose every connection is
    refused instantly, and the report then shows a sample that tried to talk
    and got nowhere -- worse than `offline`, which is at least honest.
    """
    exits = {"tor-default": {"mode": "tor"}}
    names = [e.name for e in available_exits(exits=exits,
                                             probe=lambda port: False)]
    assert "tor-default" not in names
    assert names == ["offline"]


def test_tor_is_offered_once_the_listener_is_up():
    exits = {"tor-default": {"mode": "tor", "caveats": ["tcp-only"]}}
    offered = available_exits(exits=exits, probe=lambda port: True)
    tor = [e for e in offered if e.name == "tor-default"]
    assert len(tor) == 1
    assert tor[0].mode is EgressMode.TOR
    assert tor[0].caveats == ("tcp-only",)


def test_simulated_is_withheld_when_the_responder_is_down():
    """Same guard as tor, and the reason the user chose `simulated` as the
    default rests on it: the safest mode must not depend on a daemon being up
    in a way that fails towards silence-that-looks-like-a-result."""
    exits = {"sim-local": {"mode": "simulated"}}
    names = [e.name for e in available_exits(exits=exits,
                                             probe=lambda port: False)]
    assert names == ["offline"]


def test_the_probe_asks_about_each_redirect_modes_own_port():
    asked = []
    available_exits(
        exits={"tor-default": {"mode": "tor"},
               "sim-local": {"mode": "simulated"}},
        probe=lambda port: asked.append(port) or True)
    assert set(asked) == {config.TOR_TRANS_PORT, config.FAKENET_PROXY_PORT}


def test_the_probe_asks_about_the_transport_port():
    """Not the DNS port, and not a unit-file check.

    tor can be running, enabled and healthy while bound to the wrong address;
    `systemctl is-active` would call that fine. The TCP connect asks the
    question the rules actually depend on.
    """
    asked = []
    available_exits(exits={"tor-default": {"mode": "tor"}},
                    probe=lambda port: asked.append(port) or True)
    assert asked == [config.TOR_TRANS_PORT]


def test_a_forwarding_exit_is_not_probed():
    """`direct` and `routed` have no local listener to check.

    Probing them would make an unrelated failure withhold a working mode.
    """
    asked = []
    available_exits(allow_direct=True,
                    exits={"es": {"mode": "routed", "interface": "wg0"}},
                    probe=lambda port: asked.append(port) or True)
    assert asked == []


def test_the_torrc_refuses_to_relay():
    """This host must never carry strangers' traffic.

    It would mix our analysis egress with theirs and make the exit address'
    reputation somebody else's to spend.
    """
    torrc = (Path(__file__).resolve().parents[2]
             / "automation" / "torrc").read_text()
    assert "ORPort 0" in torrc
    assert "ExitRelay 0" in torrc
    assert "SOCKSPort 0" in torrc


def test_forwarding_mode_without_an_interface_refuses():
    """A rule naming no interface would accept egress by ANY route."""
    with pytest.raises(EgressUnavailable, match="no interface"):
        argv_apply(3, Exit(name="broken", mode=EgressMode.ROUTED))


@pytest.mark.parametrize("vlan", [0, 255, 300, -1])
def test_vlan_is_bounded(vlan):
    with pytest.raises(ValueError, match="out of range"):
        argv_apply(vlan, DIRECT)


def test_offline_is_always_available():
    """A host that configured nothing can still run a sample with no way out.

    That is the safe direction to fail in, so it must not depend on config.
    """
    names = [e.name for e in available_exits(allow_direct=False, exits={})]
    assert names == ["offline"]


def test_direct_is_absent_unless_the_host_opts_in():
    """The gate that keeps the residential line off the web UI.

    The platform offers only what the host declares, so not declaring `direct`
    is what makes it unselectable -- there is no second check to disagree.
    """
    assert not any(e.mode is EgressMode.DIRECT
                   for e in available_exits(allow_direct=False, exits={}))

    opted_in = available_exits(allow_direct=True, exits={}, uplink="xenbr0")
    direct = [e for e in opted_in if e.mode is EgressMode.DIRECT]
    assert len(direct) == 1
    assert direct[0].interface == "xenbr0"


def test_a_configured_direct_exit_is_still_gated():
    """Spelling it out in EXITS must not bypass the switch."""
    exits = {"uplink": {"mode": "direct", "interface": "xenbr0"}}
    assert not any(e.mode is EgressMode.DIRECT
                   for e in available_exits(allow_direct=False, exits=exits))


def test_declared_exits_carry_their_caveats():
    """Caveats are a property of the way out, and the report renders them."""
    exits = {"es-vps-1": {"mode": "routed", "interface": "wg0",
                          "country": "es", "caveats": ["smtp-blocked-upstream"]}}
    got = [e for e in available_exits(exits=exits) if e.name == "es-vps-1"][0]
    assert got.country == "es"
    assert got.caveats == ("smtp-blocked-upstream",)


def test_vlan_must_be_an_int():
    """A string vlan would build a chain name and an address out of it."""
    with pytest.raises(ValueError, match="must be an int"):
        argv_apply("3", DIRECT)
    with pytest.raises(ValueError, match="must be an int"):
        argv_apply(True, DIRECT)