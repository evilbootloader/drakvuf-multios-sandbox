# DRAFT-047: Per-user isolation, using the identity Cloudflare Access already establishes

**Status:** Published as [#40](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/40), 2026-08-24.
JWT verification and `owner` landed early, in #36; the read-path
scoping and the quota did not.
**Area:** core/platform, security
**OS:** ALL
**Milestone:** M1 → replaces part of M8
**Priority:** P0 — until this lands, every authenticated browser user can read,
cancel and stream every analysis, including samples and extracted payloads.
**Depends on:** **#36** (the API) and **#39** (the tunnel). Touches every
browser read path, so it lands as one change rather than piecemeal.
**Needs Dom0:** no. The worker channel is deliberately untouched.

# Objective

Give the platform real per-user isolation at M1, by verifying the JWT
Cloudflare Access already issues and using it to populate the `owner` column
reserved since #35 — plus a per-user quota measured in analysis runtime.

# Context

## Why this is possible now rather than at M8

DRAFT-043 put multi-tenancy at M8 on the assumption that it meant building
authentication. It does not. **Cloudflare Access authenticates the user and
hands the origin a signed assertion** — `Cf-Access-Jwt-Assertion`, verifiable
against Cloudflare's JWKS — so the expensive half already exists.

What remains is small: verify the token, write the email into a column that is
already there, and scope the browser reads. `owner` and `visibility` were
reserved in migration 0001 for exactly this, so nothing needs retrofitting
onto populated data — which is the reason to do it now rather than after a few
hundred analyses have accumulated with no owner.

## What is true today, and why it is not acceptable for long

There is **no tenancy at all**. Any caller who reaches the API can read any
job by id — including presigned artifact URLs — list everyone's jobs, cancel
them, and subscribe to their event streams.

The practical consequence is a deployment constraint rather than a bug:
**Cloudflare Access must currently admit only people who may see
everything.** The first time a colleague is added for a good reason, the
isolation silently is not there.

## Two authorization models, one per channel

The part most likely to be got wrong later, so it is stated plainly.

| Channel | Authorized by | Scoped to |
|---|---|---|
| Browser | Verified Access JWT | The caller's own jobs, plus published ones |
| **Worker (Dom0)** | **The lease** | **Jobs it currently holds, whoever owns them** |

**Dom0 is infrastructure, not a tenant.** It must be able to run anyone's job,
so ownership must never scope the worker channel — `lease_owner` already does
that and has since #35. A future change that "unifies" the two models breaks
the pipeline for every job not owned by whoever Dom0's certificate names.

# The decisions

| # | Decision |
|---|---|
| 1 | **Verify the Access JWT** against Cloudflare's JWKS — signature, expiry, `aud`. Never trust the header |
| 2 | **`owner` is the verified email.** Set at submission, never from a request field |
| 3 | **Browser routes bind loopback only**, so `cloudflared` is the sole path and Access cannot be bypassed |
| 4 | **A user reads their own jobs plus published ones**, and nothing else |
| 5 | **Publishing is the owner's, after the fact.** Private by default |
| 6 | **A published job is readable in full** — including the sample and `extracted/` |
| 7 | **Object keys gain a per-user prefix**: `u/<owner>/samples/<job_id>/…` |
| 8 | **Quota is measured in analysis runtime**, not stored bytes |
| 9 | **The worker channel is unchanged.** Lease-scoped, never owner-scoped |

## Why binding loopback matters as much as the JWT check

The two are complementary and cover each other's weakness.

The JWT check answers *who is this*. Binding to loopback answers *can this be
reached without going through Access at all* — and answers it structurally.
With browser routes on the LAN, "Access is the gate" is a property of
application code, and one route added later without the check reopens
everything silently. On loopback there is no path to reach, so a missing check
is not exploitable from the network.

It also means a forged `Cf-Access-Jwt-Assertion` header has nowhere to be
injected from — which makes the verification easier to reason about, without
removing the need to verify the signature properly.

**The cost, stated:** the UI becomes unreachable locally when the tunnel is
down, including from the machine itself.

## Publishing: after the fact, and in full

Jobs are private by default and the owner may publish one. Deciding at
submission would mean choosing before anyone has seen what came out, which is
the wrong moment — people share a result once they know it is worth sharing.

**A published job is readable in full, sample and `extracted/` included.**
Considered and rejected: exposing only metadata and traces. For a malware lab
the payload is frequently the point of sharing, and a "public" analysis whose
artifacts are withheld would mostly generate requests to send them by other
means — which is worse, because those paths have no record.

Two things this leans on, both already decided elsewhere:

- **#39 wraps executables in password-protected archives** before they reach
  the object store, so what a second user downloads over the tunnel is an
  encrypted blob rather than a live PE. That is what keeps this on the
  transmitting side of Cloudflare's *distribution* clause.
- **Publishing is effectively irreversible.** Anything downloadable while a
  job was public, someone has. Unpublishing restores the access check, not
  the secret, and the UI should say so at the moment of publishing rather than
  in documentation nobody reads.

## Quota by analysis runtime, not by bytes

**Runtime bounds the resource that is actually scarce.** Dom0 runs one job per
clone slot and each analysis is capped by the 60 s preconfig and 180 s trace
guards, so a user's consumed runtime is a direct measure of the machine time
they have taken from everyone else. Bytes are downstream of it: bounding runs
bounds artifacts as a side effect.

It also sidesteps a real limitation. MinIO quotas are **per-bucket**, and
decision 7 keeps one bucket, so a storage quota would have meant a bucket per
user with the lifecycle management that implies. A runtime quota needs no
storage restructuring at all.

Enforced at **admission**, before a job is queued, so a user over quota is
told at submission rather than discovering it as a job that never runs.

**Three sub-questions this issue must answer, deliberately left open here
because they are policy rather than mechanism:** the window (rolling 24 h, or
calendar), the allowance, and whether exceeding it rejects or defers. Charging
actual runtime after completion is simpler than reserving the 240 s ceiling up
front and refunding, and self-corrects for jobs that fail early.

**It does not bound storage directly.** A user submitting many small,
fast-failing jobs consumes little runtime and still writes artifacts. With F1
unresolved — the object store shares an oversubscribed thin pool with the Xen
L1 VM — that residual path is worth watching rather than assuming closed.

## Why a key prefix, given it enforces nothing

Isolation is enforced by the API refusing to mint a presigned URL for a job
the caller cannot see. MinIO has no concept of these users either way, so the
prefix adds no security.

Worth having anyway: it makes per-user lifecycle rules and per-user accounting
possible, and it makes the store legible when something has gone wrong.

# Dependencies

- **#36** — every browser route gains a scope check.
- **#39** — the tunnel is what puts Access in front, and decision 3 depends on
  `cloudflared` running inside the platform container.

# Out of scope

- **Roles, groups, and sharing with named users.** Publishing is all-or-none
  to authenticated users at M1.
- **Anything on the worker channel.** Deliberately untouched.
- **Access policy design** — who may authenticate, and with which identity
  provider. Cloudflare configuration, recorded in the runbook.
- **Storage quotas.** Superseded by decision 8; the residual path above is
  recorded, not solved.

# PLAN

1. Verify a real Access JWT against the JWKS, including `aud` and expiry.
2. Add the scope predicate in one place, and route every browser read
   through it.
3. Move the browser routes to their own loopback listener.
4. Add the per-user key prefix, the publish endpoint, and the runtime ledger.
5. Write the negative tests first — they are what proves any of it.

# CREATE

- JWT verification: fetch and cache the JWKS, validate signature, `exp`,
  `iss` and `aud`. A cached key set with a bounded refresh, so an unreachable
  Cloudflare does not lock everyone out at the next key rotation.
- One scope predicate — `owner = %s OR visibility = 'public'` — used by every
  browser read, so the rule exists once and is greppable.
- `POST /api/v1/jobs/{id}/publish`, owner only.
- Runtime accounting: record elapsed analysis time per job at completion, and
  a query that sums it per owner over the window.
- A second uvicorn listener bound to `127.0.0.1` for the browser routes.

# TEST

**The negative cases are the issue.** A tenancy check never exercised against
a second user is a check nobody has tested.

1. **User B cannot read user A's job** by id — 404, not 403, so ids cannot be
   probed.
2. **User B cannot cancel user A's job.**
3. **User B cannot subscribe to user A's event stream.**
4. **User B's listing does not contain user A's jobs.**
5. **User B cannot obtain a presigned URL for user A's artifacts** — the check
   must be before the URL is minted, not on download.
6. **A published job is readable by user B in full**, sample and `extracted/`
   included.
7. **Only the owner may publish**, and unpublishing restores the check.
8. **A forged JWT is refused** — wrong signature, wrong `aud`, expired, as
   three separate cases.
9. **No JWT is refused**, and the browser routes are **not reachable** from a
   non-loopback address.
10. **A user over their runtime quota is refused at admission**, with a
    distinct reason, and is not silently queued.
11. **The worker channel still runs a job it does not own** — the regression
    that would break the pipeline for everyone.

# DEPLOY

Access application and identity provider configured in Cloudflare; the
audience tag recorded in the platform's environment. Recorded in
`docs/runbooks/08-deploy-platform-lxc.md`.

Rollback is reverting to the single-tenant build and narrowing Access to
trusted users only — which must be deliberate, since it silently removes
isolation.

# Acceptance criteria

- [ ] The Access JWT is verified — signature, `exp`, `aud` — never trusted
      from the header alone.
- [ ] `owner` is set from the verified email, never from a request field.
- [ ] Every browser read is scoped by one shared predicate.
- [ ] Browser routes are unreachable from a non-loopback address.
- [ ] Publishing is owner-only, after the fact, and grants full access.
- [ ] Runtime quota is enforced at admission with its own reject reason.
- [ ] **The worker channel is provably unchanged** — a worker runs a job
      owned by someone else.
- [ ] All eleven tests, with the forged-JWT cases as three distinct failures.

# Evidence required

`pytest` output for the eleven cases; a `curl` from a LAN address showing the
browser routes unreachable; a decoded real Access JWT showing the claims being
validated.

# Security considerations

- **Verify, never trust.** A `Cf-Access-Jwt-Assertion` header is attacker
  controlled unless its signature is checked against the JWKS and its `aud`
  matches this application. A JWT verified without the audience check is one
  that any Access application in any account can mint.
- **404, not 403, for another user's job.** A 403 confirms the id exists.
- **The scope check goes before the presigned URL is minted.** Checking on
  download is too late: the URL is a bearer capability that has already left.
- **Publishing hands over the payload.** Decision 6 is deliberate, and it
  means a published job's sample is retrievable by every authenticated user —
  wrapped per #39, but retrievable. The UI must say so at the moment of
  publishing.
- **Dom0 is not a tenant**, and making it one breaks the pipeline.
- **The runtime quota does not bound storage.** Many fast-failing jobs cost
  little runtime and still write artifacts; with F1 unresolved that reaches
  the Xen host's thin pool.

# Documentation changes

- **Updated:** `docs/architecture/platform.md` — the trust boundary table
  gains a browser-to-browser row it does not currently have.
- **Updated:** `.github/issue-drafts/completed/DRAFT-043.md` — annotate that
  multi-tenancy moved out of M8.
- **Updated:** `docs/runbooks/08-deploy-platform-lxc.md` — Access application,
  identity provider, audience tag.

# Recovery / rollback

Reverting the code restores single-tenant behaviour; `owner` values already
written are harmless. The deployment step that must not be forgotten is
narrowing Cloudflare Access again — a wide Access policy plus single-tenant
code is the configuration this issue exists to remove.
