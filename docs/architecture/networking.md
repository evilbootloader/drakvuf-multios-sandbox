# Network architecture

> Verified-vs-proposed distinction: the current OVS/VLAN setup below is
> confirmed by direct source reading of `automation/network-setup.sh`
> (2026-08-07). The broader containment design goals are carried over from
> the brainstormed workstream list and are not yet implemented.

## Current implementation: `automation/network-setup.sh`

Provisions the isolated per-clone networking that `clone-ubuntu.pl` and
`preconfig-ubuntu.sh` assume already exists:

- `modprobe 8021q` — VLAN kernel module.
- `echo 1 > /proc/sys/net/ipv4/ip_forward` — enables IP forwarding.
- `iptables -t nat -A POSTROUTING -o xenbr0 -j MASQUERADE` — NATs outbound
  traffic via the uplink bridge `xenbr0`.
- `ifconfig xenbr1 up`.
- For each VLAN `1..N` (`N` = clone count argument): `vconfig add xenbr1 $i`,
  gateway `172.16.$i.1/24` on `xenbr1.$i`, and
  `iptables -A FORWARD -i xenbr1.$i -o !xenbr0 -j DROP` (blocks inter-VLAN
  traffic).

This is the source of the `172.16.<VLAN>.1` gateway value used by
`preconfig-ubuntu.sh`, and of the `xenbr1.<vlan>` interface name
`clone-ubuntu.pl` attaches clones to and `tcpdump.sh` captures on.

## Confirmed defect: guest DNS never resolved (fixed 2026-08-09)

`preconfig-ubuntu.sh` wrote `nameserver 172.16.<vlan>.1` into the clone's
`/etc/resolv.conf` — the clone's own gateway, which is a Dom0 address.
**Nothing has ever listened on port 53 there.** `network-setup.sh` sets
`ip_forward` and a `MASQUERADE` rule but starts no resolver and installs
no DNAT, so a query to that address is delivered to Dom0's INPUT chain
and answered with ICMP port-unreachable rather than forwarded.

Guest name resolution therefore failed on every analysis run to date. It
went unnoticed because the only evidenced runs fetched by IP
(`http://172.16.1.1/<sample>`) and never resolved a name. The practical
cost is analysis fidelity, not containment: a sample that resolves a C2
domain died at its first lookup, and the pcap recorded a few unanswered
queries and nothing else.

Since 2026-08-09 the resolver is `GUEST_NAMESERVER` in
`automation/pipeline-<os>.env`, defaulting to `1.1.1.1`. That is
consistent with the posture the lab already had — `network-setup.sh:139`
NATs every clone to the uplink, so clones already had unrestricted
outbound IP access, and refusing only DNS was a broken resolver rather
than a control. It is **not** egress control — clone containment remains
unverified (DRAFT-013) and the inter-clone `FORWARD` `DROP` rule may never
install at all (DRAFT-028).

It costs no visibility. `tcpdump.sh` captures the clone's entire
`xenbr1.<vlan>` sub-interface and DNS is plaintext UDP/53, so every query
and answer is in the per-sample pcap whichever resolver serves it.

Android carries the same dead assumption one layer deeper, baked into the
golden image: `docs/checklists/android.md:466-469` DNATs all in-guest DNS
to `172.16.10.1:53`, where nothing listens either. That redirect must be
removed or repointed before Android analysis can resolve names.

### Why `1.1.1.1` is expected to survive the simulated modes

A public resolver address here is not a placeholder to be swapped back
later. The candidate tool for `simulated` / `controlled-internet` is
[FakeNet-NG](https://github.com/mandiant/flare-fakenet-ng), and it fits
this topology without changing the guest's configuration:

- Its **MultiHost** mode "simulate[s] the Internet by acting as the
  gateway for another machine"
  ([`docs/internals.md`](https://github.com/mandiant/flare-fakenet-ng/blob/master/docs/internals.md)) —
  Dom0-side, with no in-guest agent, which is what keeps DRAKVUF's
  agentless design intact. MultiHost is **Linux-only**, and Dom0 is
  Linux; Windows supports SingleHost only, so the guest OS is irrelevant
  to this choice.
- Redirection is an `iptables` `REDIRECT` rule in the `PREROUTING` chain
  (`LinuxRedirectNonlocal`), so it captures traffic addressed to **any**
  destination IP, not just to the gateway. The README's own worked
  example is traffic "destined to an external host IP address 1.1.1.1".
- A clone's default route already points at `172.16.<vlan>.1`, so its
  packets transit the prospective FakeNet host regardless of the address
  they carry.
- Its `DNSListener` "replies to A records with either a local machine's
  IP address or a configurable address in the `DNSResponse` setting"
  ([README](https://github.com/mandiant/flare-fakenet-ng/blob/master/README.md)).

So when a responder lands on the gateway, queries aimed at `1.1.1.1` are
intercepted with no edit to `GUEST_NAMESERVER`. This needs no follow-on
issue of its own: it is part of implementing the modes above, and until
then the pcap already records what was asked and what came back.

`xenbr0` is the uplink/production bridge; `xenbr1` is the analysis bridge
(see `CLAUDE.md`'s naming tables). Golden VMs use `xenbr0` directly (see
`misc/ubuntu.cfg`, `misc/android.cfg` — both `vif = [ 'type=ioemu,model=e1000,bridge=xenbr0' ]`,
no VLAN, no `vif-openvswitch` script); sandbox VMs use `xenbr1` with the OVS
vif script (see `misc/ubuntu_sandbox.cfg`, `misc/android_sandbox.cfg` —
`bridge=xenbr1`).

## Known gap: Android network isolation is unverified

`docs/checklists/android.md` §1.3 ("Verify sandbox network isolation TODO")
is explicitly incomplete — the 6-row isolation test table (Dom0 analysis
gateway, Dom0 management IP, Proxmox management IP, another LAN host,
Internet IPv4, Internet IPv6) has no "Actual"/"Passed" values recorded. This
means Android sandbox containment is **unverified, not just undone** —
tracked as DRAFT-013, gating any real (non-benign) sample execution with
networking enabled for Android.

## Proposed containment design (not yet implemented)

Carried over from the brainstormed workstream list, for later design work,
not decided:

- Network modes: `offline`, `simulated`, `controlled-internet`.
- Default-deny; block management interfaces, RFC1918/home-LAN ranges,
  cloud metadata addresses, unintended IPv6 paths.
- Clone-to-clone isolation (the current per-VLAN `DROP` rule in
  `network-setup.sh` is the closest existing mechanism).
- DNS strategy, egress logging, connection/rate limits, emergency kill
  switch.
- Verification tests proving isolation *before* any Internet access is
  enabled for a given analysis.

## TLS visibility — confirmed gap, not solved

DRAKVUF's `tlsmon` plugin (source-verified, `src/plugins/tlsmon/tlsmon.cpp`
in `tklengyel/drakvuf`) hooks Windows `ncrypt.dll`/Schannel specifically —
it has no OpenSSL/BoringSSL hook path and does not work on Linux/Android
guests. Any TLS visibility for Ubuntu/Android analysis requires original
engineering (hypervisor memory scanning, or in-guest key logging — which
conflicts with the project's agentless design goal) or must be deferred.
Tracked as a research spike, DRAFT-023.