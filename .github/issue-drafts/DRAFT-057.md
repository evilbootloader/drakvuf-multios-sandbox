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

`ideas.md` suggests TOR so a dirty line is not needed. Three reasons against,
and the first is disqualifying:

- **Tor carries TCP streams only.** UDP C2 and direct DNS simply do not
  appear. The report would show no network activity for a sample that was
  talking — a false negative delivered confidently.
- **Exit operators are volunteers who absorb the abuse complaints
  personally.** It moves the problem onto them rather than solving it.
- **Many families fingerprint and avoid Tor**, so you measure evasion rather
  than behaviour.

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
   address.
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

- [ ] Three modes implemented in the existing chains; `offline` default.
- [ ] Per-job selection, recorded on the job and shown on the report.
- [ ] Kill-switch proven by packet capture, not by rule inspection.
- [ ] Exit set is server-side; no submitter-supplied endpoints.
- [ ] Upstream port blocking surfaced rather than silently reported as absence
      of traffic.
- [ ] The `ideas.md` provider table corrected with the Specter finding.

# Evidence required

- A clone failing to reach the internet under `offline`, and isolation intact.
- Observed exit address per configured country.
- The kill-switch capture.
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
