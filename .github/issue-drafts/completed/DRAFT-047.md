# DRAFT-047: Per-user isolation, using the identity Cloudflare Access already establishes

**Status:** Published as [#40](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/40), 2026-08-24. **CLOSED 2026-09-10**, deployed from commit `9ab3a35` — `docs/runbooks/16-deploy-tenancy-and-quota.md`. **Decision 3 is not closed by it** and is carried to DRAFT-061; see the table below.

Landing in three parts rather than the one this draft assumed, because the
first part landed before the draft was written:

| Decision | State |
|---|---|
| 1, 2 — verify the JWT, set `owner` from it | Landed in **#36**, 2026-08-24 |
| 4 — scope every browser read | **Landed 2026-09-05**, in the repository. `auth.visible_to`, `platform/tests/test_tenancy.py`. Not deployed |
| 5, 6 — publishing | **Landed 2026-09-06**, in the repository. Migration 0007, `POST /jobs/{id}/publish` and `/unpublish`, the UI control, nine tests in section 7. Not deployed |
| 3 — loopback-only browser routes | **Deployed 2026-09-06, REVERSED 2026-09-10.** The live console dials that listener from Dom0 and loopback is unreachable across machines. Carried to **DRAFT-061** — see below |
| 7 — per-user key prefix | **Landed 2026-09-07**, in the repository. Migration 0008, `objects.owner_prefix`, section 12 of `test_tenancy.py`. Not deployed |
| 8 — runtime quota | **Landed 2026-09-07**, in the repository. Migration 0008's `tenants`, `routers/account.py`, `worker._charge_for_runtime`, `platform/tests/test_quota.py`. Not deployed. **Shape changed** — see below |

**Decision 3's acceptance criterion was restated on 2026-09-06, and this is
why.** Both systemd units run the same ASGI object
(`sandbox_platform.app:app`), so the mTLS listener on `192.168.1.10:8443`
serves the browser routers too, with `REQUIRE_ACCESS_JWT` deliberately unset —
`visible_to` returns `TRUE` there and every job is readable. That is not an
oversight: Dom0 and `submit.py` hold certificates rather than browser sessions,
and locking them out is the failure mode the per-listener split exists to
avoid.

So binding `:8000` to loopback makes the browser routes unreachable from the
LAN **without a client certificate signed by our CA**, which is what the
criterion now says. The original wording — plainly unreachable — describes an
arrangement where the two listeners serve different applications, and cannot be
met by a bind-address change.

**Splitting the ASGI app is deferred, and is its own change.** It is not a
line in `app.py`: `tests/conftest.py` builds its client from
`sandbox_platform.app:app`, and `test_tenancy.py` drives browser and worker
routes in the same module. Keep one app and the split goes untested; split the
fixture and the suite is restructured. That question is larger than decision 3
and should not be smuggled into it.

The bind change itself is written up as `platform-domu.md` §E4a, **Candidate**.

**Two rules that look independent and are not.** `_visible_or_404` runs once,
when an SSE stream or console socket is opened, so an open connection outlives
a visibility change. That is sound *only because publication requires a
terminal state*: `events.py` ends a stream on the snapshot when the job is
already terminal, and `routers/console.py` refuses a socket outside
`RUNNING_STATES`, so no connection can be open on a job that is publishable.
Terminal states are absorbing, so this cannot be arranged after the fact
either.

**Relaxing publication to non-terminal jobs therefore reopens the subscribe-time
check**, and the symptom would be a user who keeps receiving a job's transitions
after it was unpublished. Either rule may be changed; neither may be changed
alone.

**"It lands as one change rather than piecemeal", below, is no longer true**
and is left as written. It was already false when this draft was published —
#36 had shipped half of it — and the claim is what made the remaining work
hard to see. What is true is narrower: the *read paths* had to land together,
because a partial scope is not a scope, and they did.

**One decision this draft does not contain, taken 2026-09-05 and REVERSED
2026-09-07.** A job with `owner IS NULL` — anything submitted over the mTLS
listener, where a certificate identifies a machine rather than a person — was
made readable by any authenticated user, on the grounds that unowned means an
infrastructure job rather than a private one, and that the literal predicate
below would otherwise have made every CLI submission vanish from the UI on
deploy.

Migration 0008 ends that: `owner` is NOT NULL, because a job nobody owns is a
job nobody can be charged for or asked about, and decision 8 needs both.
`auth.required_identity` refuses the ownerless callers with a 403 rather than a
constraint violation. The `owner IS NULL` arm of `visible_to` is kept but is
now unreachable — the shared pool it described has no way to acquire members,
and the constraint is the only thing keeping it that way.
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
| 7 | **Object keys gain a per-user prefix**: `u/<owner>/<shard>/samples/<job_id>/…`, the shard being three hex characters of the job id (added 2026-09-07) |
| 8 | **Quota is measured in analysis runtime**, not stored bytes. A prepaid balance rather than a window, decided 2026-09-07 |
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

**It does not bound storage directly.** A user submitting many small,
fast-failing jobs consumes little runtime and still writes artifacts. With F1
unresolved — the object store shares an oversubscribed thin pool with the Xen
L1 VM — that residual path is worth watching rather than assuming closed.

### What decision 8 became, 2026-09-07

The three sub-questions above — the window, the allowance, and whether
exceeding rejects or defers — were answered by **replacing the window with a
prepaid balance**. Seconds are bought once and drawn down as jobs finish; an
idle month neither expires nor replenishes anything. Purchasing (Stripe) is a
later draft, so until it exists the opening grant is 3600 s and the operator
tops balances up with an `UPDATE`.

| Question | Answer |
|---|---|
| Where does the clock start | `queries.CLAIM`, when a host takes the job. Queue time is not billable — a submitter cannot control how long they wait behind other people's work |
| What charges | Anything that had a clone: `completed`, `failed`, `cancelled`, and a worker-reported `interrupted` |
| What does not | Reaped and reconciled jobs, and anything that never reached `CLAIM` |
| Exceeding | 402 Payment Required at admission. Balances may go negative; nothing caps a running job |
| Enforcement point | The two worker routes, via one helper — not a trigger |

**Why reaped and reconciled jobs are free**, which is the part worth reading:
`REAP` fires because Dom0 crashed, restarted or lost its link — the platform's
fault in almost every case. It also cannot measure what it lost. `updated_at`
is when the sweep *noticed*, so the elapsed time carries up to `LEASE_SECONDS`
(120) plus a sweep interval (30) of pure detection lag, and for `RECONCILE` the
gap is unbounded — the job died with the previous process and the platform
learns of it whenever sandboxd next starts. Charging would bill a number nobody
could defend.

**Why the routers rather than a database trigger.** A trigger was the plan
while the rule was "charge every terminal transition", because `report_state`
sees only two of the six exits. Once the reaper paths must *not* charge, the
routers seeing only the graceful exits stopped being the gap and became the
point. `auth.leased_job` refuses any job outside `LEASED_STATES` with a 409, so
a reaped job cannot be charged late either.

**`started_at IS NOT NULL` carries the whole "had a clone" rule**, which is why
no list of chargeable states appears anywhere in the code. A state added to the
pipeline later inherits the right behaviour without anyone deciding it should.

**Two consequences of `owner NOT NULL`**, taken for traceability in the same
migration. The mTLS listener can no longer submit — `auth.required_identity`
refuses it with a 403 rather than a constraint violation — which is temporary
in the right way, since the CLI carries an Access service token once it routes
through the tunnel. And `visible_to`'s `owner IS NULL` arm becomes unreachable;
it is kept, with the constraint now the only thing holding that shared pool
empty, and `test_an_ownerless_job_cannot_exist_at_all` fails first if anyone
drops it.

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
- Runtime accounting: `jobs.started_at` set at CLAIM, `jobs.charged_seconds`
  written once at the terminal transition, and a `tenants` row per identity
  holding the remaining balance. No window and no sum -- the balance is the
  running total, decremented in place.
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

## What of the eleven exists, 2026-09-06

`platform/tests/test_tenancy.py`, twenty-nine tests, all passing.

| # | State |
|---|---|
| 1–5, 11 | Done |
| 6 | Done — the predicate in section 6, the route that writes it in section 7 |
| 7 | **Done**, 2026-09-06. Nine tests, including the two cases below |
| 8 | Already in `test_access_jwt.py`, which owns verification |
| 9 | Token half done there too; the non-loopback half needs decision 3 |
| 10 | Blocked: needs the quota |

**Sections 6 and 7 stay separate on purpose.** Section 6 sets `visibility`
directly, so a failure there is the *read* rule; section 7 drives
`POST /publish`, so a failure there is the *write* rule. Merged, either fault
could hide behind the other.

**Two cases test 7 does not name, and both are load-bearing:**

- **The publish gate is `owner = %s`, not `auth.visible_to`.** That predicate
  admits public rows through its third arm, so it is reflexive: the instant A
  publishes, B is inside it and could revoke A's publication. Control of
  publication would pass from the owner to everyone the act of publishing had
  just admitted. `test_b_cannot_unpublish_as_published_job` is the only test
  that fails if the two gates are merged.
- **An ownerless job is publishable by nobody.** `owner = %s` never matches
  NULL. It costs nothing today — the ownerless set is already readable by every
  authenticated user — and it keeps the later narrowing of that arm total,
  rather than leaving permanent grants written onto rows whose read rule is
  expected to change.

**Each negative test was checked against a neutered predicate** — `visible_to`
made to return `TRUE` unconditionally — and eleven of them fail. Two defects
were found that way and fixed: the two SSE tests *hung* rather than failed
(an unscoped stream on a non-terminal job stays open, and a hanging suite gets
retried where a failing one gets read), and the WebSocket test used a bare
`pytest.raises(Exception)`, which passed against the unscoped build because it
caught a refusal for an unrelated reason.

**Section 7 was checked the same way** — `_owned_or_404`'s `AND owner = %s`
removed, leaving it owner-blind. Exactly three fail, and they are the three
that assert the gate. The other six cover the state rule, idempotency and the
listener gate (`_publisher`), each of which fails open in its own way.

# DEPLOY

Access application and identity provider configured in Cloudflare; the
audience tag recorded in the platform's environment. Recorded in
`docs/runbooks/08-deploy-platform-lxc.md`.

Rollback is reverting to the single-tenant build and narrowing Access to
trusted users only — which must be deliberate, since it silently removes
isolation.

# Acceptance criteria

**Nothing here is ticked, and that is deliberate: every box below is a
statement about the deployment, and none of this is deployed.** The repository
column records what is written and tested in the dev container.

| | Criterion | In the repository |
|---|---|---|
| [ ] | The Access JWT is verified — signature, `exp`, `aud` — never trusted from the header alone | Yes, #36 |
| [ ] | `owner` is set from the verified email, never from a request field | Yes, #36 |
| [ ] | Every browser read is scoped by one shared predicate | Yes, 2026-09-05 |
| [ ] | Browser routes are unreachable from a non-loopback address **without a client certificate signed by our CA** — restated 2026-09-06 | **Held 2026-09-06 to 2026-09-10, then reversed.** The bind broke the live console; `REQUIRE_ACCESS_JWT=1` is the gate today. Carried to **DRAFT-061** |
| [ ] | Publishing is owner-only, after the fact, and grants full access | Yes, 2026-09-06 |
| [ ] | Objects are written under a per-owner key prefix, taken from the row rather than the caller | Yes, 2026-09-07, migration 0008 |
| [ ] | Runtime quota is enforced at admission with its own status | Yes, 2026-09-07 — 402, `test_quota.py`. Reject *reason* dropped: a refusal at admission never creates a job to carry one |
| [ ] | A job the platform lost track of is not charged for | Yes, 2026-09-07, `test_a_reaped_job_does_not_charge` |
| [ ] | A redelivered terminal report charges once | Yes, 2026-09-07, `test_the_helper_charges_once_however_often_it_is_called` |
| [ ] | **The worker channel is provably unchanged** — a worker runs a job owned by someone else | Yes, tests 11 |
| [ ] | All eleven tests, with the forged-JWT cases as three distinct failures | 11 of 11 — test 10 landed 2026-09-07 with decision 8 |

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
