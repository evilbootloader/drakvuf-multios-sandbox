# `routed` — egress through a tunnel to a rented exit

**Status: DESIGN. Nothing here has run.** Every command is **Candidate** until
a runbook says otherwise. DRAFT-057 Phase 4.

The mechanism is public and lives here. Which host carries the traffic, what
its AUP says, and who agreed to what is `private/egress-exits.md` — see
`private/README.md` for why that line is drawn where it is.

## Why this is being designed now, with no provider

Outreach to hosting providers returned refusals (2026-09, filed in
`private/outreach/`). That invalidates the *deployment*, not the design, and
the two are separable to an unusual degree here:

**Most of `routed` can be built and proven against a local peer.** The far end
of a WireGuard tunnel does not have to be rented to be a different network
namespace with its own routing table and its own source address. The platform
DomU is on `xenbr0`, is not Dom0, and can terminate a tunnel. Against it, all
of this is testable today:

- the policy routing that sends one VLAN's traffic into the tunnel
- **the kill-switch**, which is the acceptance criterion that gates the mode
- DNS following the tunnel rather than leaking to the uplink resolver
- MTU and MSS behaviour
- teardown, and non-leakage between concurrent jobs

Exactly one criterion needs a rented host: *"`routed` egresses from the chosen
country, proven by observed source address."* Everything else is engineering
that a refusal does not touch.

So the useful order is: build it, prove the kill-switch against a local peer,
and leave the exit undeclared. A host that declares no routed exit cannot
offer one — `available_exits` reads `config.EXITS`, so the mode stays
unreachable until somebody has a provider, with no flag to forget.

## What already exists

**The iptables layer is implemented and tested.** `routed` was not deferred out
of the rule builder; it shares one with `direct`, parameterised on
`exit_.interface` rather than switched on the mode
(`sandboxd/egress.py`, `_FORWARDING_MODES`).

The kill-switch is already structural rather than supervisory:

```
-A DRAKVUF_EGRESS_V<n> -i xenbr1.<n> -o wg0 -j ACCEPT
-A DRAKVUF_EGRESS_V<n> -i wg0 -o xenbr1.<n> -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A DRAKVUF_EGRESS_V<n> -j DROP
```

Nothing in that set names the uplink, and the chain is terminal. If `wg0`
disappears the ACCEPT cannot match and the packet falls to
`DRAKVUF_ISOLATION`'s terminal DROP. **Fail-closed is a property of what the
rule says, not of a watchdog noticing in time** —
`test_routed_never_names_the_uplink` and
`test_routed_accepts_only_out_of_the_tunnel` pin it.

Groundwork elsewhere was laid for this too: `DRAKVUF_ISOLATION`'s
clone-to-clone rule was reshaped from `! -o xenbr0` to `-o xenbr1.+` in
DRAFT-057 Phase 1 precisely because the old form meant "leaving by anything
other than the uplink" and would have dropped tunnel traffic.

`Exit` already carries `interface` and `country`.

## What is missing, in the order it bites

### 1. Policy routing — and today its absence is why nothing works

**This is the real gap.** The iptables rules *permit* forwarding out of `wg0`;
they do not *cause* it. The clone's packets are still routed by the main table,
whose default route points at `xenbr0`. So the kernel picks `xenbr0`, the
`-o wg0` ACCEPT does not match, and the terminal DROP fires.

`routed` therefore fails closed one hundred percent of the time today. That is
the safe direction, and it is also why a casual test would report "routed does
not work" rather than "routed is half built".

The missing half is source-based routing, per VLAN, installed and removed
alongside the rules:

```sh
# Candidate — not yet run on Dom0.
ip rule add from 172.16.<vlan>.0/24 lookup <table>
ip route add default dev wg0 table <table>
```

with `<table>` derived from the VLAN so two clones cannot collide, the same way
their chains and subnets already are.

**Two independent fail-closed mechanisms, and that is deliberate.** If the
`ip rule` is missing, packets fall to the main table, head for `xenbr0`, and
die on the iptables terminal DROP. If the iptables chain is missing, the route
sends them into a tunnel that is down and they die with no route to host.
Either layer alone is sufficient; neither is load-bearing on the other. Say so
in the comments, because the natural reading is that they are redundant.

Open decision: whether these belong in `sandboxd/egress.py` as argv beside the
iptables commands, or in `network-setup.sh`. **Beside the iptables commands**
is the better answer — the routes are per-job and per-VLAN, and
`network-setup.sh` owns host-global chains it rebuilds on every run, which is
the ownership split the parent chains already respect.

### 2. A liveness probe, which `routed` currently does not have

`available_exits` probes only `_REDIRECT_MODES`, and
`test_a_forwarding_exit_is_not_probed` asserts that forwarding exits are not
probed at all: *"probing them would make an unrelated failure withhold a
working mode."*

That reasoning is right for `direct`, whose interface is the host's own uplink
and is up whenever the host is. **It is wrong for `routed`**, whose interface
is a tunnel to somebody else's machine over a link nobody controls.

Unprobed, a `routed` job with a dead tunnel runs to completion, reaches
nothing, and the report says `routed`. That is precisely the failure the
FakeNet work spent five patches eliminating for `simulated`, and DRAFT-057
exists to prevent it.

A tunnel is not a listening port, so the probe is not `listener_ready`. The
honest signal is a recent WireGuard handshake:

```sh
wg show wg0 latest-handshakes    # Candidate
```

A peer with no handshake inside roughly its keepalive window is not carrying
traffic, whatever `ip link` says about the interface being UP.

**"Withhold or downgrade" is a false choice: the existing modes already do
both.** `available_exits` withholds at registration and `_apply_egress`
re-checks at launch, and both are keyed on the same set — `_REDIRECT_MODES` and
`LISTENER_PORT` have identical keys, `{tor, simulated}`. So `routed` does not
pick one; it either joins that treatment or stays unguarded.

Two real decisions sit underneath, and only the second is contentious.

**Mechanical: `LISTENER_PORT` is a mode-to-port map, and a tunnel is not a
port.** Both call sites index it, so adding `routed` means generalising it from
`mode -> int` to `mode -> health predicate`. `listener_ready(port)` becomes one
such predicate; `handshake_recent(iface)` becomes another. That is a small
refactor and it is what unblocks everything else here.

**Policy: at launch, does a dead tunnel downgrade the job or fail it?** See
below.

### DECISION (2026-09-02): a dead tunnel FAILS a routed job

Withhold at registration, as `tor` and `simulated` do. But at launch, raise
`EgressUnavailable` and let the job go to terminal `failed` with the tunnel as
the stated reason — **do not downgrade to `offline`.**

This deliberately differs from the maintainer's 2026-08-31 decision for
`simulated`, and the difference is not an inconsistency:

- **The safety argument does not transfer.** Downgrading is justified there
  because it "only ever moves towards LESS egress". Under `routed` the rules
  already fail closed structurally — nothing names the uplink — so when the
  tunnel is down, nothing escapes whether or not the job is downgraded.
  Downgrading buys no safety here. It only decides whether the run is spent.
- **The submitter's intent inverts.** `simulated` and `offline` are both "no
  real Internet", so a downgrade is a more conservative version of the same
  answer. `routed` means "reach the real Internet, but not from my address";
  `offline` is not a conservative version of that, it is a different
  experiment.
- **Downgrading spends the sample; failing preserves it.** A sample that
  checks in once is burned by an offline run — the report correctly says it did
  nothing, and the one opportunity to observe its C2 is gone. `FAILED` is
  terminal, so failing costs a resubmission, but the sample itself is still
  unexecuted.

The precedent is already in `stages.py`. `_resolve_exit` refuses outright
rather than downgrading when a job names an exit the host does not have,
because "the submitter asked a specific question about where their sample's
traffic goes, and silently answering a different one produces a report whose
network section means something other than what it says." That reasoning fits a
dead tunnel better than it fits a mistyped exit name.

Withholding at registration makes this path rare: the launch check only covers
the window between the exit being offered and the job starting.

**What would overturn this:** evidence that tunnels flap often enough that
failed jobs become noise. Then the answer is a bounded retry at the queue
level, not a downgrade — the two are different fixes for different problems,
and reaching for the downgrade would re-introduce the burned-sample cost to
solve a scheduling one.

### 3. DNS, which needs nothing and should be tested anyway

The guest is configured with `1.1.1.1` and its queries are ordinary UDP to a
public address, so the same policy route carries them into the tunnel. No
redirect is needed — unlike `tor`, which needs one because Tor carries TCP
only.

Test it explicitly regardless. A DNS leak to the uplink resolver is the
quietest possible failure: the sample resolves, the analysis looks complete,
and the queries went out over the line the tunnel exists to protect.

### 4. MTU and MSS

WireGuard's usable MTU is below the clone's 1500. A full-size segment needs
PMTUD, and malware is not obliged to honour it. Standard mitigation, per VLAN:

```
-A DRAKVUF_EGRESS_V<n> -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

**Candidate, and not to be added speculatively.** Add it if a run shows large
transfers stalling while small ones succeed — the signature is a TLS handshake
completing and the first big response hanging. Written down so the symptom is
recognised rather than debugged from scratch.

### 5. Caveats

`country` is already a field; surface it on the report. Beyond that, the one
that matters is upstream port blocking: most providers block outbound 25, and
DRAFT-057's criterion 7 requires that a blocked port reads as blocked rather
than as absent. `smtp-blocked-upstream` already exists and applies unchanged.

`egresses-via-host-uplink` must **not** appear on a routed exit — it is
`direct`'s caveat and it would be actively false here.

### 6. Keys

The tunnel's private key is host configuration, not repository content. Same
split as `tor`: `automation/torrc` is tracked and carries no secret, while the
provider relationship is `private/`. A `wg0.conf` template belongs in
`automation/` with the key and endpoint left as placeholders; the filled
version never leaves Dom0.

## Proving it — runbook 14, against a local peer

The acceptance criterion is *"drop the tunnel mid-run and no packet reaches the
uplink, asserted by capture, not by inspecting rules."*

The trap in that test is that a silent capture is also what you get when
nothing was ever sent. **The capture has to show the traffic working first.**
So the shape is:

1. Bring up a routed job against the local peer. Confirm from inside the guest
   that it reaches the peer, and from Dom0 that the source address seen at the
   far end is the tunnel's, not the lab's.
2. Start `tcpdump -i xenbr0 -n 'net 172.16.0.0/12'` **before** touching
   anything, and leave it running.
3. With the sample still running, `wg-quick down wg0`.
4. Assert: zero packets from the clone's subnet on `xenbr0`, for the whole
   capture including the period *before* the drop — the clone's traffic was in
   the tunnel, so it was never on the uplink to begin with. The drop tests that
   losing the tunnel does not change that.
5. Confirm the guest sees timeouts, not resets — the same distinction step 3 of
   runbook 13 draws for `offline`.

Then the honest part: **that discharges the kill-switch criterion and not the
country criterion.** A local peer proves traffic cannot escape to the uplink.
It proves nothing about a provider's egress policy, and the runbook should say
so rather than let a green result read as more than it is.

## What this does not address

- **Whether a provider will carry it.** Design only; see `private/`.
- **Throttling.** A rented exit shared with anything else needs rate limiting,
  and nothing here does that.
- **IPv6.** Stays dropped, as it is for every other mode. A tunnel that carried
  v6 while the v6 chains dropped it would fail closed, which is the right
  direction but worth a test rather than an assumption.