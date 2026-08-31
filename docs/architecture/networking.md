# Network architecture

> Verified-vs-proposed distinction: the current OVS/VLAN setup below is
> confirmed by direct source reading of `automation/network-setup.sh`
> (2026-08-07). The broader containment design goals are carried over from
> the brainstormed workstream list and are not yet implemented.

## Current implementation: `automation/network-setup.sh`

Provisions the isolated per-clone networking that `clone.pl` and
`preconfig-ubuntu.sh` assume already exists. **Rewritten by DRAFT-028
(2026-08-11)**; the shape below is current.

- `modprobe 8021q` — VLAN kernel module.
- `echo 1 > /proc/sys/net/ipv4/ip_forward` — enables IP forwarding.
- `ip link set xenbr1 up`, after checking the bridge exists at all.
- For each VLAN `1..N` (`N` = clone count argument):
  `ip link add link xenbr1 name xenbr1.$i type vlan id $i` and gateway
  `172.16.$i.1/24`, both guarded so a re-run is not an error.

The filtering lives in **five dedicated chains**, flushed and rebuilt on
every run:

| Chain | Table | Contents |
|---|---|---|
| `DRAKVUF_NAT` | `nat`, from `POSTROUTING` | `-o xenbr0 -j MASQUERADE` |
| `DRAKVUF_ISOLATION` | `filter`, inserted at head of `FORWARD` | clone-to-clone DROP, RFC1918 and link-local destination DROPs, then the terminal pair: uplink ACCEPT + `ESTABLISHED,RELATED` return ACCEPT, closed by DROPs in both directions |
| `DRAKVUF_INPUT` | `filter`, inserted at head of `INPUT` | `ESTABLISHED,RELATED` ACCEPT, then DROP everything from `xenbr1.+` |
| `DRAKVUF_ISOLATION6` | `filter6`, head of `FORWARD` | DROP everything to or from `xenbr1.+` |
| `DRAKVUF_INPUT6` | `filter6`, head of `INPUT` | DROP everything from `xenbr1.+` |

The resulting posture:

```text
clone -> clone            DROP    (two independent rules)
clone -> LAN / RFC1918    DROP    (incl. the router's admin interface)
clone -> link-local       DROP    (incl. 169.254.169.254 metadata)
clone -> Dom0 itself      DROP    (replies to Dom0-initiated traffic allowed)
clone -> Internet         ALLOW   (MASQUERADE out the uplink)
clone -> anything, IPv6   DROP    (FORWARD and INPUT, no exceptions)
Internet -> clone         DROP    (except replies to what the clone opened)
```

### Why the chains are terminal (DRAFT-029, 2026-08-12)

No packet with `xenbr1.<n>` as its input or output interface reaches
`FORWARD`'s or `INPUT`'s default policy, in either address family. The
posture above therefore holds **whatever those policies are set to**, and
`network-setup.sh` sets none of them.

That is a deliberate choice of instrument. Until 2026-08-12 the
`clone -> Internet` permit was inherited rather than stated: the packet
fell through `DRAKVUF_ISOLATION` to `-P FORWARD`, which is `ACCEPT` on this
host. Nothing in `automation/` set that, asserted it, or would have noticed
it change — anything flipping it to `DROP` (a firewall package, Docker,
libvirt, an administrator) would have killed every clone's network
silently, and the only symptom would have been analyses that observed
nothing.

The obvious alternative — `-P FORWARD DROP` plus explicit permits — was
rejected for three reasons:

- It buys nothing on `INPUT`. `DRAKVUF_INPUT` already ends in an
  unconditional drop, so clone traffic to Dom0 is decided inside the chain.
  `-P INPUT DROP` would govern only *non-clone* traffic, which is Dom0 host
  hardening rather than analysis-network containment — and it is the most
  effective way there is to lock an operator out of a headless L1 guest.
- `-P FORWARD DROP` applies to every forwarding path on the host, not just
  the analysis network. That is a policy decision about Dom0, made by a
  script whose job is provisioning one bridge.
- A terminal chain gives the identical guarantee with a blast radius of
  exactly the interfaces it names, and keeps the property the chains were
  built for: the whole posture stays readable with
  `iptables -S DRAKVUF_ISOLATION` and removable in a flush.

Traffic touching no analysis VLAN matches nothing and `RETURN`s to
`FORWARD` untouched.

**Rule order is load-bearing.** The uplink `ACCEPT` sits *below* the four
RFC1918 and link-local `DROP`s. A LAN destination leaves via `xenbr0` like
any other, so an `-o xenbr0 -j ACCEPT` placed above them would accept
exactly the traffic they exist to block.

### An aborted run leaves the chain denying, not empty

`DRAKVUF_ISOLATION` is flushed and rebuilt, and the jump from `FORWARD`
stays installed throughout. Exiting between the two would therefore permit
everything the chain exists to deny — worse than the state before the run,
because a populated chain has been replaced by an inert one. That is
NET-01's shape a second time: a rule present, visible in `iptables -S`, and
matching nothing.

Two changes close it. The flush was moved to sit immediately above the
rules that replace it — it previously sat far enough above them that
`ip link set` and the entire per-clone VLAN loop ran inside the gap, every
command of which is fatal under `set -eu`. And the `EXIT` trap now fails
**closed**: on a non-zero exit it flushes the chain and installs a bare
deny in both directions.

Failing closed cuts the network of any clone mid-analysis. That is the
intended trade — a half-provisioned network that looks like it works is the
failure mode this script was rewritten to stop having.

### Why IPv6 is dropped outright

Everything except the last row is `iptables`, and `iptables` is IPv4 only.
Without the v6 chains the entire posture is bypassable — and not
theoretically. Dom0's own VLAN gateway interface carries an IPv6
link-local address:

```text
xenbr1.1@xenbr1  UP  172.16.1.1/24  fe80::f4f1:81ff:febf:3b4a/64
```

So a sample that re-enables IPv6 on its interface — `ip link set eth0
down; ip link set eth0 up` regenerates a link-local — reaches Dom0 over v6
with nothing filtering it. `DRAKVUF_INPUT` would never see the packet.

Measured on an analysis clone on 2026-08-11: IPv6 was unreachable
(`::1 dev lo` the sole route, `ping6: Network is unreachable`) **only
because `preconfig-ubuntu.sh`'s `ip addr flush dev eth0` had wiped the
link-local**. That is an accident of configuration order, not a control,
and a sample can undo it.

Blanket DROP rather than mirroring the IPv4 rules: the guests have no IPv6
uplink to preserve, and the v6 equivalents of the RFC1918 blocks
(`fc00::/7`, `fe80::/10`, `2000::/3`) add up to everything anyway. No
`ESTABLISHED,RELATED` exception either — unlike IPv4, nothing needs to
reach a clone from Dom0 over v6.

If `ip6tables` is unavailable, `network-setup.sh` **fails** rather than
proceeding, unless IPv6 is disabled kernel-wide — in which case there is
nothing to filter and it warns instead. Silently having no v6 filtering is
the defect the section exists to prevent.

Blocking RFC1918 costs no Internet access: a clone's default route points
at its own gateway on the analysis VLAN, and Dom0 resolves the next hop
from its own routing table, so the clone never addresses the LAN gateway.
`172.16.0.0/12` covers the analysis subnets too, so clone-to-clone is
denied by destination as well as by interface.

Blocking Dom0 costs the pipeline nothing either — ARP is L2 and unfiltered,
addresses are static so no DHCP is needed, the resolver is `1.1.1.1` and
therefore forwarded rather than local, and both sample delivery and tracing
are VMI operations with no network path (issue #4 removed the last one when
it replaced Apache/HTTP delivery with `injector -m writefile`).

Chains rather than loose rules for three reasons: flush-and-rebuild makes
re-running idempotent by construction, `iptables -S DRAKVUF_ISOLATION`
shows the whole containment posture as a unit, and undoing it is three
flushes rather than a hunt through chains other tools also write to.

> **How not to check containment (observed 2026-08-20).**
> `iptables -S FORWARD | grep -c xenbr1` returns 0 on a correctly contained
> host and cannot answer the question at all: the per-VLAN rules live *in*
> `DRAKVUF_ISOLATION`, and `FORWARD` holds only the jump to it. Any
> containment check must name the chain — `iptables -S DRAKVUF_ISOLATION` —
> or it will read a working posture as an absent one. Containment itself was
> re-verified correct on that date: 9 rules, correct order, terminal in both
> directions.

This is the source of the `172.16.<VLAN>.1` gateway value used by
`preconfig-ubuntu.sh`, and of the `xenbr1.<vlan>` interface name
`clone.pl` attaches clones to and `tcpdump.sh` captures on.

**It does not create `xenbr1`, despite being the file named
`network-setup.sh`.** It calls only `modprobe`, `ip` and `iptables`; the
OVS bridge itself comes from a separate one-time install step,
`ovs-vsctl add-br xenbr1`
(`docs/drakvuf-on-xen-nested-within-proxmox.md`). It now checks for the
bridge and fails with a message naming that step, rather than configuring
VLAN sub-interfaces on a bridge that does not exist.

### What DRAFT-028 did not close

- ~~**No terminal policy is set on `FORWARD` or `INPUT` themselves.**~~
  **Closed 2026-08-12 by DRAFT-029** — and by making the chains terminal
  rather than by setting a policy, which is a different answer to the same
  question. See "Why the chains are terminal" above.
- ~~**Containment is still unverified by a live test.**~~ **Largely closed
  2026-08-11 by DRAFT-028's own deployment**, which produced the nine-row
  connectivity matrix with per-rule packet counters
  (`docs/checklists/android.md` §1.3, transcript in
  `docs/runbooks/04-deploy-network-isolation.md`). Measured on Ubuntu clones,
  which transfers — the rules match on interface, not on anything
  guest-specific. What does not transfer is the guest's *reaction*: Android
  probes connectivity and may mark the network unvalidated when it cannot
  reach its gateway, which Ubuntu never checks. That single Android clone
  boot is all DRAFT-013 still is.
- **`DROP` everywhere means a clone sees timeouts**, where a real host on a
  real network would answer with RST or ICMP unreachable. A black-holing
  firewall is itself a sandbox signal; revisit under the anti-evasion work.

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
than a control. It is **not** egress control.

> Both caveats that used to close this paragraph are now discharged. The
> inter-clone `FORWARD` `DROP` rule was fixed and measured in DRAFT-028
> (2026-08-11), made terminal in DRAFT-029 (2026-08-12), and clone
> containment was verified against an Android guest in DRAFT-013
> (2026-08-14, `docs/runbooks/06-verify-android-isolation.md`).

**It costs no visibility — on Ubuntu.** `tcpdump.sh` captures the clone's
entire `xenbr1.<vlan>` sub-interface and DNS is plaintext UDP/53 there, so
every query and answer is in the per-sample pcap whichever resolver serves
it.

### This does not hold on Android 14

**Measured 2026-08-14**, and it is the one place where a shared design
assumption breaks on a per-OS basis.

Android 9 and later default `private_dns_mode` to `opportunistic`: the
resolver probes whether the configured server supports DNS-over-TLS on port
853 and silently upgrades when it does. **`1.1.1.1` supports DoT.** On a
clone left at the default, the capture carried a completed TLS session —
probe, handshake and a 3263-byte certificate chain — rather than queries:

```text
16:35:23.917190 IP 172.16.1.2.32922 > 1.1.1.1.53: 24543+ AAAA? WqVk6n-dnsotls-ds.metric.gstatic.com. (54)
16:35:23.810620 IP 172.16.1.2.41640 > 1.1.1.1.853: Flags [S], seq 2299661284 ...
16:35:23.816160 IP 1.1.1.1.853 > 172.16.1.2.41640: Flags [P.], seq 1:3264 ... length 3263
```

`WqVk6n-dnsotls-ds.metric.gstatic.com` is Android's DoT capability probe.
Only after `settings put global private_dns_mode off` did the capture show
plaintext 53 alone.

**The failure mode is the dangerous kind: silent.** Nothing errors, the guest
resolves names normally, the pcap is written, and the analyst gets TLS to
`1.1.1.1:853` where they expected the domains a sample looked up.

**Mitigation today** is per-clone and belongs to the guest: `preconfig-android.sh`
sets `private_dns_mode off` (DRAFT-016). The parity matrix in
`docs/checklists/android.md` records it as a required step, not an optional
one.

**The alternative is a Dom0-side control** — drop outbound 853 on the
analysis VLANs in `network-setup.sh`, so the opportunistic probe fails and
Android falls back to plaintext without needing any guest cooperation. That
is the more robust answer, because it does not depend on a guest-side command
succeeding, and it would cover a *sample* that configures DoT for itself,
which the guest-side setting does not. It also affects all three OS families
and changes the egress posture, so it needs its own issue and review. **Not
proposed here.**

Ubuntu and Windows are unaffected as written: neither has an equivalent
opportunistic-DoT default, and Ubuntu's resolver was measured on plaintext 53
throughout.

Android carried the same dead assumption one layer deeper, baked into the
golden image: §1.4 of `docs/checklists/android.md` DNATs all in-guest DNS to
`172.16.10.1:53`, where nothing listens either.

**Fixed 2026-08-11 (issue #7).** The Android golden VM was reinstalled and
`android_sandbox` rebuilt from it; `iptables -t nat -L OUTPUT` was empty on
the new image and the DNAT was deliberately not re-applied. The template now
carries **no resolver configuration at all**, which is the intended end
state rather than a gap: per-clone resolver configuration belongs to
`preconfig-android.sh` at analysis time, exactly as `preconfig-ubuntu.sh`
applies `GUEST_NAMESERVER`. Baking a resolver into a saved image would put a
containment-relevant value where no per-OS config could override it.
DRAFT-016 owns writing that step.

The §1.4 command block is annotated in place rather than edited — it is
dated evidence of what was done on 2026-08-06.

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

## Closed: Android tolerates the isolation rules (measured 2026-08-14)

*(Corrected twice. On 2026-08-12 this section was retitled from "Android
network isolation is unverified", because §1.3's table had been filled the
day before by DRAFT-028's deployment. **Closed 2026-08-14** by DRAFT-013 —
`docs/runbooks/06-verify-android-isolation.md`. The narrowed gap described
below is answered, and the answer is at the end of the section.)*

`docs/checklists/android.md` §1.3's isolation table is **complete** — nine
rows with measured results and per-rule packet counters, transcript in
`docs/runbooks/04-deploy-network-isolation.md`. The mechanism is verified, and
it verifies for all three OS families at once: `network-setup.sh` matches on
interface (`-i`/`-o xenbr1.+`), not on anything guest-specific.

What remains is narrower and is the whole of DRAFT-013. The measurements
were taken on **Ubuntu** clones. Android performs connectivity probing and
may mark a network unvalidated when it cannot reach its gateway — which it
now cannot, since `DRAKVUF_INPUT` drops clone traffic to Dom0 and the
gateway is deliberately not pingable. Ubuntu never checks. One Android
clone boot answers it.

### The answer: it probes, it is refused, and it does not care

One Android clone was booted on `xenbr1.1` under the current rules on
2026-08-14. **The posture survives contact with a guest that actively
validates its network**, and the evidence is more useful than a simple pass:

- **Android did probe the gateway.** `DRAKVUF_INPUT` counted **10 packets
  dropped**, and the pcap identifies them as ICMP echo requests to
  `172.16.1.1` at 16:44:13 and 16:44:14. No replies.
- **It validated the network anyway.** Android reported "Internet through
  Ethernet", raised no captive-portal notification, and a browser loaded a
  public page.

That combination — probed, refused, unbothered — is the strongest of the
three possible outcomes. It means the posture is **robust rather than
lucky**: it does not depend on Android happening not to look. **No
ICMP-to-gateway exemption is needed**, so the `DRAKVUF_INPUT` blanket drop
introduced by DRAFT-028 stays closed for all three OS families.

The mechanism the prediction rested on is confirmed too. ARP/NUD is L2 and
unfiltered by `iptables` — Dom0 answered the clone's ARP for `172.16.1.1`,
which is the only way the clone could then route to `1.1.1.1`. This is the
same property DRAFT-028 relied on when it concluded that blocking clone→Dom0
traffic costs the pipeline nothing.

**IPv6 is a second confirmation.** `DRAKVUF_INPUT6` counted 8 dropped router
solicitations to `ff02::2`, retried unanswered from 16:14 to 16:31. Android
obtained no IPv6 address and still validated the network, with no visible
complaint — so the blanket v6 DROP described above costs nothing on the OS
most likely to object to it.

One caveat worth carrying: a restored clone boots holding the **golden VM's**
LAN identity until `preconfig-android.sh` runs, and spends its first seconds
ARPing for a residential gateway on the analysis VLAN. Containment held —
that traffic reached nothing — but it is noise in every Android pcap and a
window in which the clone is not yet configured. Detail and evidence in the
runbook's finding F4; the fix belongs to DRAFT-015/016.

Non-benign sample execution with networking remains gated, but on
DRAFT-022 rather than on this — see roadmap risk #13.

## Proposed containment design (not yet implemented)

> **Where the exit-provider material lives.** Which host carries analysis
> egress, what each one's acceptable-use policy permits, and the correspondence
> that establishes it are **not in this repository** — see `private/README.md`.
> That is a publication decision, not a secrecy one: this document is intended
> to be public and the *mechanism* below belongs in it, while analysis of the
> operator's own liability and commercial intent do not. Do not restate them
> here; point at them.

### Partly built, 2026-08-31 — DRAFT-057 Phase 1

The mode *framework* exists and two modes work. Recorded here rather than in
the list below, which describes what was proposed and is kept for the rest.

| Mode | State |
|---|---|
| `offline` | **Built, and it is the absence of a rule** rather than a rule |
| `direct` | **Built**, host-gated behind `SANDBOXD_ALLOW_DIRECT=1`, never offered in the UI |
| `simulated` | Enum, UI and API only. Needs a responder — Phase 3 |
| `tor` | **Built.** Needs `automation/torrc` installed and tor running; withheld automatically if not |
| `routed` | Enum, UI and API only. Needs a peer and a kill-switch capture — Phase 4 |

What changed in `network-setup.sh`: the unconditional `MASQUERADE` in
`DRAKVUF_NAT` is gone, and `DRAKVUF_ISOLATION`'s wildcard
`-i xenbr1.+ -o xenbr0 -j ACCEPT` is now `-j DRAKVUF_EGRESS` — a chain this
script creates **empty and never flushes**, because flushing it on a re-run
would cut the network of every clone then under analysis. `sandboxd` fills it
per job with a VLAN sub-chain pair and empties it at teardown; the startup
sweep clears any **per-VLAN** rules a dead process left behind.

The qualifier matters, and its absence was a real defect. The legacy
`network-setup.sh <n> direct` path writes a *wildcard* pair — `-i xenbr1.+ -o
xenbr0 -j ACCEPT` plus a matching `MASQUERADE` — that names no VLAN, so no
per-VLAN delete could match it and nothing removed it. One
`ALLOW_DIRECT=1 ./run_analysis-ubuntu.sh` therefore granted egress for the
host's whole uptime, and every later job used it, including jobs recorded and
reported as `offline` — which install no rules at all and so had nothing that
could collide with the leftovers. Two things now remove it: the `offline`
branch of `network-setup.sh` (by exact spec, never a flush, so live clones'
per-VLAN jumps survive) and `egress.argv_revoke_blanket` from the startup
sweep. `direct` is per-invocation again, which is what it always claimed to
be.

The clone-to-clone rule changed shape with it, from `! -o xenbr0` to
`-o xenbr1.+`. The old form meant "leaving by anything other than the uplink",
which is correct only while the uplink is the single way out — with a tunnel
interface in play it would drop exactly the traffic `routed` exists to permit.
Nothing is lost: clone-to-clone is still denied twice (by interface here, by
the `172.16.0.0/12` destination rule below), and egress by an unauthorised
interface is denied by the chain being terminal.

**A mode a host does not declare cannot be chosen.** The host reports its exits
at registration; the platform offers that set and nothing else. There is no
rule about `direct` in the API — it is unreachable purely because an
unconfigured host never declares it, which is what stops the two from falling
out of step.

**Which host carries `routed` traffic is not in this repository** — see
`private/README.md`. The mechanism is public; the provider relationship is not.

#### `tor` redirects; it does not forward

Worth stating separately because it is the part that surprises people reading
the chains. `tor` installs no `FORWARD` accept and no `MASQUERADE`. A
`REDIRECT` in `nat PREROUTING` rewrites the destination to the clone's **own
gateway**, so the packet stops being transit traffic and becomes traffic
addressed to Dom0 — delivered to `INPUT`, where a per-VLAN sub-chain admits it
on 9040 (TCP) and 9053 (DNS) and drops the rest.

Three things follow, and all three are wanted:

- **The guest is not reconfigured.** It keeps `1.1.1.1` and its real
  destination addresses; the rewrite happens underneath it. Same property
  `networking.md` already reasons through for FakeNet, and it is what keeps
  the agentless design intact.
- **UDP other than 53, and ICMP, die in `DRAKVUF_ISOLATION`'s terminal DROP**
  with no rule needed. Not a gap — Tor carries TCP only, so forwarding them to
  it would make a sample hang instead of fail.
- **The onion range overlaps a rule that drops it, harmlessly.** `torrc` maps
  `.onion` names into `10.192.0.0/10`, which sits inside the `10.0.0.0/8` this
  chain drops as RFC1918. `nat PREROUTING` rewrites the destination before
  `FORWARD` is consulted, so the packet never reaches that rule. Written down
  so nobody "fixes" the overlap.

`TransPort` and `DNSPort` bind `0.0.0.0`, because a `REDIRECT` targets the
address of the interface the packet arrived on and that differs per VLAN.
`network-setup.sh` therefore **drops both ports arriving on the uplink**, as
the first rules in `DRAKVUF_INPUT`. Without those two rules this host is an
open proxy for anyone who can reach it.

---

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

**With Windows a current target, that same finding reads the other way
round for the Windows pipeline: `tlsmon` is the one working TLS-visibility
path the project has**, not a plugin it cannot use. The constraint above is
a per-OS limitation of Ubuntu and Android, not a project-wide one — see
`docs/roadmap/project-roadmap.md` risk #4.