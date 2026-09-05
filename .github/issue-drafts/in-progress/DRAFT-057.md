# DRAFT-057: Egress routing — offline, direct, or through an exit we choose

**Status:** **[#42](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/42) — published 2026-08-25, OPEN.**
**Area:** platform/security
**OS:** ALL
**Milestone:** M2 — this gates live detonation, not enriches it.
**Priority:** **P0.** The binding constraint on detonating anything real.
**Depends on:** DRAFT-022 (the legal position), `network-setup.sh`.
**Needs Dom0:** **Yes.**

# Objective

Choose per run where a clone's traffic goes: nowhere, straight out, or through
an exit whose country we select — and make `offline` exist at all.

# Context

## The constraint that actually binds

Roadmap risk #13, and it is not a technical one:

> The lab is operated **personally, over a residential Internet line**, and
> analysis clones have deliberate unrestricted NAT egress. The binding
> constraint on live detonation is the ISP's acceptable-use terms, not Spanish
> criminal law — enforced without a prosecutor, court or complainant, by a
> party that already knows who the subscriber is. Realistic failure is an
> abuse report and disconnection of a household line.

It "costs nothing today — only benign fixtures have ever been detonated — and
becomes real on the first non-benign run."

**So this is not an enrichment issue.** Every other draft in this set makes
reports better. This one decides whether real samples can be run at all.

## `offline` was proposed, scoped, and left unowned

`docs/architecture/networking.md` proposes an `offline` mode and the roadmap
records it as undecided M2 work with no owner. It also records how small it
is: `network-setup.sh` already isolates the posture in dedicated chains
(`DRAKVUF_NAT`, `DRAKVUF_ISOLATION`, `DRAKVUF_INPUT`), so `offline` is the
`DRAKVUF_NAT` `MASQUERADE` rule **not being installed**.

That is the cheapest risk reduction available to this project and it has been
sitting unclaimed.

## What routing buys beyond safety

Country selection is a real analysis capability, not only a legal shield. ANY.RUN
advertises "network geography manipulation" because malware behaves
differently by geography: geofenced C2, region-locked payloads, and the
CIS-exclusion behaviour that also motivates DRAFT-058's keyboard work. A
sample that does nothing from a Spanish address may do plenty from elsewhere.

## The provider question, checked

`ideas.md` carries a provider table. Verified 2026-08-25:

- **"Specter VPN — explícitamente permitido, mejor VPN encontrada" does not
  check out.** The only "Specter" with an AUP mentioning security research is
  **Upgrade AI's** accounting/finance agent platform, whose policy *prohibits*
  introducing malware. There is separately a consumer Android VPN app of that
  name with no research tier and no published carve-out. **Treat that row as
  unusable.**
- **Mullvad's row is accurate.** Its ToS prohibits exactly one thing:
  reselling VPN service. No malware, abuse or research clause exists. But two
  operational details the table misses: **ports 25, 137–139, 445 and 53 are
  blocked permanently**, which silently breaks analysis of spam bots and SMB
  worms — the sample runs, the traffic vanishes, and the report shows no
  network activity. They also null-route addresses when hosting providers
  force it after botnet traffic.
- **The table's own preferred row is the right answer, and it is the one
  chosen** (maintainer, 2026-08-25): **a VPS the operator rents, running
  WireGuard.** The AUP relationship is held directly with a host that was
  told what the traffic is, rather than inferred from a consumer VPN's
  silence — and the exit country is whichever region the VPS sits in.

**"Not expressly prohibited" is silence, not permission.** A VPN provider can
terminate exactly as fast as an ISP, and risk #13's point is that enforcement
needs no prosecutor.

## TOR is the wrong tool here

> **OVERRIDDEN by the maintainer, 2026-08-31, and BUILT (Phase 2).** The
> analysis below is unchanged and still correct — every objection in it is a
> real property of Tor. What changed is the conclusion drawn from them, and
> the reasoning is at the end of this section. ANY.RUN offers the same
> capability with the same limitations.

`ideas.md` suggests TOR so a dirty line is not needed. Three reasons against,
and the first is disqualifying:

- **Tor carries TCP streams only.** UDP C2 and direct DNS simply do not
  appear. The report would show no network activity for a sample that was
  talking — a false negative delivered confidently.
- **Exit operators are volunteers who absorb the abuse complaints
  personally.** It moves the problem onto them rather than solving it.
- **Many families fingerprint and avoid Tor**, so you measure evasion rather
  than behaviour.

### Why it was built anyway

**The first objection is about the REPORT, not about Tor.** "A false negative
delivered confidently" is a property of a report that does not say what was
blocked — and that is fixable, by the same mechanism acceptance criterion 7
already requires for upstream port blocking. So `tor` carries
`caveats: [tcp-only, smtp-blocked-upstream, smb-blocked-upstream]`, the report
renders them next to the network section, and "no UDP traffic" and "UDP could
not leave" are different sentences on the page. The objection is answered by
building the disclosure, not by declining the mode.

**A finding that arrived with the Phase 0 research and sharpens this**: Tor's
default exit policy rejects **the same ports Mullvad blocks** — 25, 135–139,
445. So the intuition that Tor is the free way around a commercial VPN's port
blocking is simply wrong, and worth stating because it is the reason someone
would reach for Tor first. It is not a cheaper `routed`; it is a different
thing with its own limits.

**What it actually buys is time.** `routed` needs a provider decision, a
purchase, and a kill-switch capture before it can be enabled. `tor` needs a
package and a config file. It is the mode that makes the lab useful on real
samples *before* an exit has been rented — which, given this issue is the
binding constraint on detonating anything at all, is worth a documented
limitation.

**The volunteer-operator objection stands and is not answered by anything
technical.** It is a judgment the maintainer has made knowingly. The
throttles in Phase 5 bound what a single run can push through an exit, which
is a partial mitigation and not a full one.

# Dependencies

- **DRAFT-022** — owns the legal position; this is its engineering half.
- **`network-setup.sh`** — where the chains already live.
- **DRAFT-052** — mode selected per job.

# Out of scope

- **Simulated internet** (fake DNS, sinkholed responses). A distinct mode
  worth having later; `offline` is the honest first step.
- **Per-request filtering or MITM.**
- **Selecting the hosting provider.** The *mechanism* is decided — one rented
  VPS running WireGuard — but which host, and in which country, is the
  operator's purchase. The one requirement this issue places on it: the host
  must be told what the traffic is, in writing, before it carries any.

# PLAN

1. **`offline` first, and make it the default.** Smallest change, largest risk
   reduction, and it is already scoped in `networking.md`.
2. `direct` is today's behaviour, renamed and made explicit.
3. `routed` last, once a provider decision exists (DRAFT-022).
4. Prove the kill-switch by capture before `routed` is usable.

# CREATE

## Three modes

| Mode | Behaviour | For |
|---|---|---|
| **offline** | No `MASQUERADE`. Isolation and gateway intact, no route out | Anything not yet cleared for live detonation. **Should be the default** |
| **direct** | Today's behaviour — NAT through the host's uplink | Benign fixtures, and only while the uplink is acceptable |
| **routed** | Out through WireGuard to **a VPS we rent** | Real samples, country selection |

**`offline` first, and default.** It is the smallest change, it is what makes
the lab safe to use on real samples immediately, and everything else can
follow.

## The exit: one VPS we rent

**Decided 2026-08-25.** A rented VPS running WireGuard, not a commercial VPN.

The reasoning is about *who answers for the traffic* rather than about
technology. With a VPS the AUP relationship is direct: the host can be told in
writing what the traffic is and can agree or refuse before anything runs.
A consumer VPN's silence in its ToS — which is all Mullvad offers, accurately
— is not agreement, and finding out where the line is by crossing it is the
one experiment worth avoiding.

Practical consequences worth stating:

- **Nothing is blocked that we did not block.** Mullvad permanently blocks
  ports 25, 137–139, 445 and 53. On our own VPS the only filtering is ours,
  so a spam bot's SMTP and an SMB worm's 445 are visible rather than silently
  absent.
- **The exit address is ours and stays ours**, so a burned address is a
  problem we can see and act on rather than one shared with strangers.
- **One country to start.** Country selection is a set of peers; the design
  supports several and the deployment starts with one. Adding a second VPS is
  configuration, not a redesign.

Peers are **server-side configuration, never a submitter-supplied endpoint.**
A submitter naming an arbitrary tunnel endpoint would be choosing where Dom0
sends traffic, which is a different feature with a different threat model.

## The kill-switch property

Under `routed`, if the tunnel drops, egress must **fail closed** — traffic
must not silently fall back to the residential uplink. That is the single most
important behaviour in this issue: a fallback would send exactly the traffic
the tunnel exists to keep off that line, at exactly the moment nobody is
watching.

# TEST

1. **`offline` blocks egress** — a clone cannot reach the internet, proven by
   attempting it; and isolation rules still hold.
2. **`offline` is the default** on a fresh deployment.
3. **`direct` reproduces today's behaviour** exactly.
4. **`routed` egresses from the chosen country**, proven by observed source
   address. **DESCOPED 2026-09-05** — the mechanism is built and the lab
   declares no country to prove. See the status section below.
5. **Kill-switch: drop the tunnel mid-run and no packet reaches the uplink.**
   Asserted by capture on the host's uplink interface, not by inspecting
   rules.
6. **Mode changes do not leak between runs** — chains are rebuilt per run, as
   `network-setup.sh` already does.
7. **Port-blocking is visible.** If an exit blocks 25 or 445, the report must
   distinguish "no SMTP traffic" from "SMTP was blocked upstream" — otherwise
   a provider's policy becomes a false negative.
8. **`offline` and `interactive` (DRAFT-056) compose**, so a human can drive a
   sample with no way out.

# DEPLOY

`network-setup.sh` already rebuilds its chains per run, so a mode is a
different rule set rather than a migration. Deploy `offline` alone first: it
requires no provider, no tunnel and no purchase, and it is what makes the lab
safe for a real sample today.

`routed` deploys with a WireGuard configuration and must not be enabled until
its kill-switch capture exists.

# Acceptance criteria

- [x] Three modes implemented in the existing chains; `offline` default.
      **Five, in the end** — `offline`, `direct`, `tor`, `simulated`, `routed`.
- [x] Per-job selection, recorded on the job and shown on the report.
- [x] Kill-switch proven by packet capture, not by rule inspection.
      Runbook 14, against a local peer. See the note below on what that does
      and does not discharge.
- [x] Exit set is server-side; no submitter-supplied endpoints.
      `config.EXITS`; a name not declared there is refused, not approximated.
- [x] Upstream port blocking surfaced rather than silently reported as absence
      of traffic. `caveats` on each exit, rendered beside the network section.
- [x] The `ideas.md` provider table corrected with the Specter finding.

## Status 2026-09-04 — built, and blocked on a provider rather than on code

Phases 0–4 are done. `tor` and `simulated` are evidenced in
`docs/runbooks/13-verify-egress-modes.md`; `routed` is built and its
kill-switch is proven by capture in runbook 14, executed 2026-09-02 to
2026-09-04.

**Criterion 4 is the one left, and it is not an engineering task.**
*"`routed` egresses from the chosen country, proven by observed source
address"* needs a rented host, and hosting outreach was refused
(`private/outreach/`, 2026-09). The kill-switch was therefore proven against a
**local WireGuard peer on a throwaway DomU**, which establishes that a clone's
traffic cannot reach the house uplink and **establishes nothing about a
provider's egress policy**. Runbook 14 says so in its own header rather than
letting a green run read as more than it is.

Worth carrying forward: the capture passed on the **third** attempt. The first
two produced `0 packets captured` — once with the capture stopped before the
tunnel dropped, once with no clone running. A silent capture is also what an
empty machine produces, so the step now states its preconditions as lettered
asserts.

`config.EXITS` declares only `tor-default` and `sim-local`, so `routed` stays
unreachable until somebody has a provider. That is the mechanism keeping this
honest — a host that declares no routed exit cannot offer one, and there is no
flag to forget.

## Status 2026-09-05 — criterion 4 descoped, Phase 5 built and unevidenced

**Supersedes the section above on criterion 4.** The maintainer's decision
(2026-09-05) is that this lab will not rent an exit, so the country criterion
is closed as *mechanism built, deliberately unused* rather than left open on a
purchase that is not going to happen.

**The mechanism was already complete**, which is why descoping costs nothing.
`country` is plumbed end to end and has been since Phase 4: `Exit.country`
(`sandboxd/egress.py:99`), read from the spec at `:517`, advertised at
`sandboxd/api.py:209`, received and length-checked at
`platform/sandbox_platform/routers/worker.py:91`, stored by
`platform/migrations/0006_egress.sql:107`, attached to the job at
`sandboxd/stages.py:527`, and rendered in both the picker
(`submit.html:58`) and the report (`tabs/_overview.html:33`).
`sandboxd/tests/test_egress.py:1269` already asserts it round-trips. Country
selection is a set of peers, exactly as this issue designed it; the set is
empty.

**What was rejected, and why it matters more than the descope.** Declaring
`country` on the local `router` DomU would have satisfied the criterion's
wording — the field exists, the report would print it — while making the
product worse. Nothing verifies the value, so the report would assert an exit
country that is not true, which is the same class of confident wrong answer as
the "no network activity" false negative this issue's `caveats` mechanism
exists to prevent. A label nobody checked is not an observed source address.

So the honest end state is the current one: no exit declares a country, and
`routed`'s only peer is local. If a remote exit ever appears, the field is
already there and the open question becomes verification — comparing the
declaration against an observed address at apply time — rather than plumbing.

**Phase 5 is now the open item.** The throttles are built in
`argv_apply`'s forwarding path: a per-clone new-connection rate
(`--hashlimit-above 20/sec`, packet mode, `--ctstate NEW`), a per-clone
bandwidth cap (`--hashlimit-above 6mb/s`, byte mode) and a parallel-connection
cap (`--connlimit-above 50`), all three DROPs installed above the single
`-o`-constrained ACCEPT so the kill-switch is unchanged. **No Dom0 evidence
exists**, and the four constants are guesses: nothing has measured what a
benign run actually does. Runbook 15 is the test.

**`tor` and `simulated` are deliberately unthrottled** (maintainer,
2026-09-05). `argv_apply` returns at `sandboxd/egress.py:577` and `:580`
before reaching the throttles, so only `direct` and `routed` carry them. That
contradicts this issue's own Tor override above, which offers the Phase 5
throttles as the partial mitigation for the volunteer-exit-operator objection
— that sentence overstates what is built, and the objection currently stands
unmitigated rather than partly mitigated.

# Evidence required

- A clone failing to reach the internet under `offline`, and isolation intact.
- ~~Observed exit address per configured country.~~ Descoped 2026-09-05; no
  exit declares a country, so there is no address to observe.
- The kill-switch capture.
- The throttle baseline and the four constants it justifies (Phase 5).
- A run through an exit that blocks a port, showing how the report says so.

# Security considerations

- **This is the issue that decides whether real malware can be detonated
  here.** Everything else in the capability set assumes a sample ran; this
  decides whether running it is defensible.
- **A kill-switch failure is worse than no tunnel**, because it produces
  exactly the outcome the tunnel exists to prevent while everyone believes
  they are protected. Fail closed, and prove it with a capture.
- **The exit is now the abuse-report recipient**, and with a rented VPS that
  recipient is the operator. That is the point: the report arrives somewhere
  it can be answered, rather than at a residential ISP that will simply
  disconnect. It does not make abuse costless — a host that receives enough
  of them terminates, taking the capability along.
- **Tell the host in writing, first.** This is the single cheapest risk
  reduction in the issue and it is not a technical control. A host that
  agreed in advance behaves very differently from one discovering it through
  a complaint.
- **Country selection is attributable.** Traffic from a chosen exit is still
  traffic someone paid for, and a rented VPS is more directly attributable
  than a shared VPN address.
- **`offline` is not containment.** It removes egress; it does nothing about a
  guest escape reaching Dom0 or the Proxmox management network. Those are
  separate, still-open items — `ideas.md`'s "DOM0 isolation if malware
  escapes" and the roadmap's Proxmox firewall prerequisite.
- **Recording the mode is a correctness requirement.** A report showing no
  network activity means nothing without knowing whether egress existed.

# Documentation changes

- **New:** the three modes, and the kill-switch requirement.
- **Updated:** `docs/architecture/networking.md` — `offline` moves from
  proposal to built, with an owner.
- **Updated:** `docs/roadmap/project-roadmap.md` risk #13 — the engineering
  half now exists.
- **Updated:** DRAFT-022 — the provider findings, including Specter.
- **Updated:** `ideas.md` — TOR and the provider table, both corrected.

# Recovery / rollback

Set the mode to `direct` and the behaviour is today's. Removing the WireGuard
configuration removes `routed` and leaves the other two.
