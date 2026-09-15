# DRAFT-061: One listener, our own identity — replace Cloudflare Access with credentials we hold and JWTs we issue

**Status:** Draft, 2026-09-10. Successor to decision 3 of
[#40](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/40),
which was deployed 2026-09-06 and reversed 2026-09-10.

**Area:** core/platform, security
**OS:** ALL
**Milestone:** M1
**Priority:** P1 for the whole. **F12 was the P0 inside it and shipped alone on
2026-09-10** — the remainder is P1 and no longer racing an open door.
**Depends on:** #40 (closed). Replaces the identity half of #36 and touches
`auth.py`, both systemd units, the cloudflared ingress, the TLS layer, and
`tests/conftest.py`.
**Needs Dom0:** yes — the worker channel and the console both change.

# Objective

Serve the platform from **one listener with one authentication model**, where
users and analysis hosts both present a JWT this platform issued against
credentials this platform stores.

# Context

## Every defect in this thread came from one app behind two doors

Not from the auth being weak. From there being two of it:

```
:8443  mTLS + worker token   →  sandbox_platform.app:app   (ALL routers)
:8000  Access JWT            →  sandbox_platform.app:app   (ALL routers)
```

The browser routers are reachable on 8443 with a certificate and no Access
session — `visible_to` returns `TRUE` there and every job is readable. The
worker routers are reachable on 8000 with a token and no certificate — and were
reachable **through the tunnel from the internet** until F12 was closed on
2026-09-10. Neither is intended. Both follow
from serving one object twice, and the list of what it has cost is long enough
to be the argument:

| | |
|---|---|
| **F11** | the console dialled 8443, both ends landed in different registries, and the session hung with no error |
| **F12** | `/api/v1/worker/*` routed from the public hostname for fifteen days — closed 2026-09-10, see below |
| **#40 decision 3** | its acceptance criterion had to be *restated* because a bind cannot make one app two |
| **2026-09-10** | the loopback bind was reversed after four days, because `sandboxd` dials the browser listener for the console and loopback is unreachable across machines |

One listener does not fix those bugs. It makes them **unrepresentable**.

## What one listener does to the console

The relay pairs two sockets **in one process**. Today the browser end must
arrive on 8000 — a browser cannot present a client certificate — while the
worker end would naturally belong on 8443, and reconciling that is what F11 and
the decision-3 reversal were both about.

With one listener the question disappears. No cross-process registry, no
Postgres `LISTEN`/`NOTIFY`, no Redis. **This is the largest simplification in
the draft and it is a by-product rather than the goal.**

## What this gives up, stated plainly

**Cloudflare Access currently bounces unauthenticated requests at the edge.**
After this, every request reaches FastAPI — including every credential-stuffing
attempt. On a host whose neighbour runs malware, that is a real change in
exposure and the reason the login route needs rate limiting *in the same change*
rather than afterwards.

DRAFT-047's opening argument was that Access let this project skip building
authentication. That argument was correct then. What changes it is **self-service
signup**: Access requires an operator to add every user to a policy, which is
not a thing a public service can do. The cost was worth paying while the user
list was one person and stops being worth paying at the point of the second
tenant who is not a colleague.

**The Tunnel stays.** It is transport, not identity — no inbound ports, no
public IP. Only the Access *application* goes.

# The decisions

| # | Decision |
|---|---|
| 1 | **One listener**, one ASGI app, one authentication model |
| 2 | **Credentials in our own tables**, argon2id, in a table *beside* `tenants` rather than in it |
| 3 | **We issue the JWTs.** Short-lived access token, refresh token, revocable |
| 4 | **Workers present a JWT *and* their client certificate.** Two factors on the worker routes, not one |
| 5 | **mTLS terminates in Caddy**, because uvicorn cannot hand the app a peer certificate |
| 6 | **F12's ingress rule shipped first, alone**, depending on none of this — done 2026-09-10 |

## Decision 2 — beside `tenants`, not inside it

The idea as raised was to hold hashed credentials in `tenants`. I would keep
them in `tenant_credentials`, keyed on the same `owner`, for three reasons that
are about operations rather than taste:

- **`SELECT balance_seconds` runs on every page load.** `routers/account.py`
  hits `tenants` on `DOMContentLoaded`. That query should not touch a table
  containing password hashes.
- **Erasure and retention pull in opposite directions.** DRAFT-022 will need
  credentials destroyed on request; a balance is a financial record that may
  need keeping. Same row means one policy for both.
- **Auth grows columns and billing does not.** MFA secrets, recovery codes,
  failed-attempt counters, lockout timestamps, password-changed-at. None of
  that belongs next to a seconds counter.

`tenants.owner` stays the identity everything else joins on, so `jobs.owner`,
`key_prefix` and `visible_to` are all untouched.

## Decision 2a — the address is not the join key, and signup is why

Added after a security review of the implementation, 2026-09-13, before any of
it was pushed. 0009 as first written gave `identities` one address column, and
`resolve_tenant` resolved a Cloudflare Access assertion by looking it up:
`WHERE lower(email) = lower(%s)`.

**That made one user-writable column the join key for two independent
issuers.** `/auth/signup` takes an address entirely on trust — a Telegram code
proves control of a Telegram account and says nothing whatever about an
address, and nothing in this platform ever sends to one. So claiming an address
that no identity held yet meant the next Access assertion for it resolved to
the *claimant's* row, with the claimant's password on it: that tenant's jobs,
prepaid balance and object prefix, taken with one request and one `/start`.
`service:<common_name>` — what `access_identity` reports for a service token —
was claimable the same way and needed no victim address to guess at all.

The fix is two disjoint keyspaces rather than a verification loop:

    identities.email           the login address. Written by signup and
                               create_user.py. Read by /auth/login and by the
                               reset lookup. Never resolved against.
    identities.access_subject  what an external provider asserts. Written only
                               by resolve_tenant, and by create_user.py behind
                               an explicit --access-subject. The only column
                               resolution joins on.

**An email server was considered and rejected.** Verifying the address would
need either inbound mail — a public port, against "no public IP, no open ports,
everything through the tunnel" — or an outbound relay, which is a new
dependency, a new secret and a new outbound path from a DomU whose neighbour
runs malware. It would also not have fixed the `service:` variant, which has no
address to confirm. The column split holds without any of it.

**The cost, stated plainly: one person can end up with two identities**, if they
sign up here and also arrive through Access with the same address. This platform
cannot know the two are the same human — believing it could is the hole above —
so it declines to guess. `create_user.py --access-subject` is where an operator
records that knowledge, and it is the only place the two keyspaces may
deliberately be joined.

Pinned by four tests in `tests/test_telegram.py`; the two that matter fail
against the old lookup, which was checked rather than assumed.

## Decision 4/5 — the obstacle, and why the proxy is not optional

**Checked 2026-09-10: uvicorn 0.52.4 does not implement the ASGI TLS
extension.** There is no `scope["extensions"]["tls"]`, so an app served by
uvicorn **cannot see whether a client certificate was presented, or whose it
was**. `--ssl-cert-reqs 1` (CERT_OPTIONAL) therefore does not enable "one
listener, app decides per route" — the app has nothing to decide on.

So mTLS terminates in front, in **Caddy**:

```
Dom0 ──mTLS──> Caddy ──> uvicorn        (one app, one port)
browser ──> cloudflared ──> Caddy ──> uvicorn
```

Caddy rather than nginx for two reasons, the second mattering more: the
client-certificate block is a handful of lines against nginx's verbose form,
and `header_up` **replaces** rather than appends, which makes the one dangerous
property below a shorter argument to get right. Caddy exposes the verified
subject directly as `{http.request.tls.client.subject}`. Automatic HTTPS is
turned off — the certificate comes from the internal CA (§E2), not from ACME.

**That header is a trust boundary and must be set, not forwarded.** Caddy has
to overwrite it unconditionally on every request, or a client sends it and
mints a worker identity. Delete-then-set rather than relying on replace
semantics, and the app must additionally refuse it from any source but the
proxy. This is the single most dangerous line in the whole change and belongs
in its own test.

> **A WAF was considered and deferred, 2026-09-10.** Recorded because the
> reason is specific to this application rather than general: **the platform
> deliberately accepts input a WAF exists to block.**
> `test_hostile_filenames_survive_the_http_layer` submits `'; DROP TABLE jobs;
> --`, `<img src=x onerror=alert(1)>.exe` and `$(whoami).sh` as *passing*
> cases, and `_reject_unsafe_filename` says why: "Refused, never sanitised. The
> submitted name is part of what is being analysed -- DRAFT-030 -- so a
> rewritten name would analyse something the submitter did not send." An OWASP
> CRS in blocking mode on `/api/v1/jobs` would reject exactly the submissions
> this platform exists to analyse.
>
> It is also thinner cover than it looks: sample bytes never traverse the
> platform — the browser POSTs them straight to MinIO with a presigned policy —
> so a WAF would see metadata, not malware. SQL is parameterised throughout and
> XSS is covered by `test_ui_browser.py`.
>
> **If one is ever added:** detection-only first, read the logs, and scope it to
> the auth routes this draft creates. Never in front of submission.

**The property being preserved is worth naming.** `platform.md`'s trust table
says of Platform → CA: *"The signing key is not on this machine — a full host
compromise cannot mint worker certificates."* Issuing worker JWTs from the
platform would end that. Keeping the certificate as a second factor keeps it:
a compromised platform can mint a worker **token** but not a worker
**certificate**, and the worker routes want both.

## Decision 3 — what "we issue" costs

Everything below is security-critical surface this project does not have today
and would be taking on:

- argon2id, with parameters chosen and recorded rather than defaulted
- login rate limiting and account lockout — **the edge no longer does this**
- password reset, which needs mail delivery this deployment has no path for
- MFA, or a deliberate written decision not to have it
- signing-key storage and rotation, and refresh-token revocation
- CSRF, which is currently held by the *absence* of `CORSMiddleware` — a
  cookie-based session would change that reasoning and a `Authorization: Bearer`
  header would not

**The verification half is already built and tested.** `auth.access_identity`
does JWKS fetch, `iss`/`aud` validation, key caching and a bounded refresh, with
`test_access_jwt.py` forging tokens against it. Issuance is the new half.

# Dependencies and ordering

**F12 went first and waited for nothing. DONE 2026-09-10.** The
`sandbox.evilbootloader.com` ingress had no path rule, so `/api/v1/worker/*` —
claim, heartbeat, state, artifact tickets and the console's worker end — routed
from the internet, gated by Access and a static bearer token but not by a
certificate. Confirmed open and then closed the same day:

```
Matched rule #1
    hostname: sandbox.evilbootloader.com
    path: ^/api/v1/worker(/|$)
    service: http_status:404
```

The rule was written in `docs/runbooks/09-verify-sandboxd-and-console.md` F12 on
2026-08-26 and applied fifteen days later.
`docs/runbooks/16-deploy-tenancy-and-quota.md` carries EVIDENCE F12: three
`ingress rule` checks placing the 404 between the bucket rule and the API
catch-all, a `HTTP/2 404` past Access through the live tunnel, and a job that
still claims and completes over the LAN.

**A recommendation with no evidence block is one nobody applied** — worth taking
from this as a process lesson, not only as an exposure.

Two things learned in the applying that the draft did not anticipate, both now
in the runbook:

- **`tunnel ingress rule` reads the config file, not the running daemon.** It
  can pass green against an ingress the process has not loaded.
- **An anonymous `curl` from outside cannot verify an ingress rule**, because
  Access bounces it at the edge before cloudflared is reached — it returned the
  same 302 before the rule existed. `/api/v1/worker/claim` is POST-only, so a
  GET past Access discriminates cleanly: 404 is the rule, 405 is the origin,
  302 is the edge.

The rest of this draft is unblocked and none of it depends on F12.

# TEST

The suite is part of the work. `tests/conftest.py` builds its client from
`sandbox_platform.app:app` and `test_tenancy.py` drives browser and worker
routes in one module — which one listener finally makes *correct* rather than a
compromise.

1. **The proxy header cannot be forged.** A request carrying the verified-subject
   header from outside must be refused. If one test survives review, this one.
2. Login: right password succeeds, wrong fails, both in constant time; lockout
   after N attempts; a locked account stays locked.
3. An expired access token is refused; a refresh issues a new one; a revoked
   refresh token does not.
4. A worker route with a valid JWT and **no** client certificate is refused.
5. Every test in `test_tenancy.py` and `test_quota.py` still passes — the
   identity source changes, the scoping rules do not.
6. A console session pairs, with both ends on the one listener.

# Acceptance criteria

| | Criterion |
|---|---|
| [x] | `/api/v1/worker/*` returns 404 through the tunnel (**F12 — shipped alone, 2026-09-10**) |
| [ ] | One listener serves the whole app; 8443 and the second unit are gone |
| [ ] | The verified-subject header is refused from any source but the proxy, asserted by test |
| [~] | Worker routes require a **per-worker credential** — **2026-09-13**. The certificate half was dropped with Caddy, so this is one factor rather than two; see the note below |
| [x] | A human can sign up, log in, and see their balance without an operator touching a policy — **2026-09-13**, `test_a_session_reaches_the_rest_of_the_api` |
| [x] | Login is rate limited and accounts lock — mechanism built and tested; **the edge is still in front**, so it has not yet run without help |
| [x] | `test_tenancy.py` and `test_quota.py` pass unchanged in intent — the identity source changed, the scoping rules did not |
| [ ] | A full analysis runs end to end, and a console session pairs |

# Out of scope

- **Purchasing** (Stripe) — its own draft, though it lands on the same tables.
- **Moving the analysis hosts off the LAN.** Dom0 keeps reaching the platform
  directly; only the door it knocks on changes.
- **SSO / social login.** If it ever matters, the JWT verification path is where
  it plugs in, which is an argument for keeping issuance and verification
  separable.

# Security considerations

- **The edge stops filtering.** Every unauthenticated request now reaches
  FastAPI. Rate limiting is not a follow-up.
- **A forged proxy header is a full compromise of the worker channel.** See
  decision 5.
- **The platform gains the ability to mint user identities**, which it does not
  have today. Keeping the CA off the machine (decision 4) is what stops that
  extending to worker identities.
- **A self-service signup route can propose any identifier it likes**, so
  nothing an external issuer resolves against may share a column with it. See
  decision 2a: while `resolve_tenant` joined on the address, one signup took
  over any Access identity that had not yet made its first request. The general
  rule this is an instance of — *an identifier a stranger can propose is not an
  identifier a verifier may trust* — applies again the moment SSO plugs into
  the verification path, which "Out of scope" above anticipates.
- **The console cannot be "simplified" onto a certificate-gated path.** Any
  design that puts the browser's socket where `visible_to` returns `TRUE` lets
  any authenticated user open any job's console.
- **Loopback binding becomes coherent again** once there is one listener — but
  only if Dom0 reaches it another way. That is a decision this draft leaves
  open rather than assuming.

# Cut-over — what it takes to stop depending on Cloudflare authentication

Implemented 2026-09-13. **`REQUIRE_ACCESS_JWT=0` on the browser listener is the
switch**, and it is genuinely a switch rather than a migration:
`access_identity` returns None without even reading the header when that flag is
off, so a forged `Cf-Access-Jwt-Assertion` is ignored rather than trusted, and
`caller_identity` falls through to the session cookie. Flipping it back restores
Access. **Keep `cloudflared` either way** — the tunnel is transport, not
authentication, and removing it puts the platform on a public IP.

Four things had to change first, and they were not equally severe:

- **The console never read the session cookie** (`routers/console.py`). It took
  only the Cloudflare header, so with Access gone the identity was None — which
  since DRAFT-061 is refused by `visible_to` rather than read as "see
  everything". It would have failed as a `ValueError` inside a socket handler.
  This was the real blocker.
- **`/ui/login` sat behind the gate it exists to get someone through.** It
  carried `dependencies=[]` and a comment claiming that put it outside the
  router's; FastAPI does not compose them that way. Harmless once
  `REQUIRE_ACCESS_JWT` is off, fatal during the period when both credentials
  are meant to work — which is the period the rollback plan below depends on.
  It is on its own ungated router now.
- **An unset `JWT_AUDIENCE` mints tokens that can never be verified.**
  `jwt.encode` writes `aud: ""` and `jwt.decode` reports the claim as MISSING,
  so the deployment would have signed people in and then treated every
  subsequent request as anonymous, with nothing logging why. Refused at mint
  time now. `JWT_SIGNING_KEY`, `JWT_ISSUER` and `JWT_AUDIENCE` all default to
  empty and all three must be set.
- **The router gates read `access_identity`, which cannot see a session.** Now
  `caller_identity`. Worth correcting but NOT the blocker it first looked like:
  every route on those routers already takes its own identity dependency, so at
  `REQUIRE_ACCESS_JWT=0` the old gate was a no-op rather than a refusal — its
  own comment said so. What the change buys is that the gate enforces again, so
  a route added later without an identity parameter is not public by omission.

Still outstanding, and not in this change:

- **`submit.py` authenticates with `cf-access-token`.** The command-line tools
  ride Access service tokens, so they need a credential of ours before Access
  can be switched off for them. `required_identity` already anticipates this.
- **MFA is opt-in.** Access OTP is a possession factor today; after the
  cut-over an account with no TOTP enrolled is a password alone. If the
  cut-over is to be a net gain rather than a wash, making TOTP mandatory —
  at least for any identity with a balance — is a decision to take BEFORE.
- **`TRUSTED_CLIENT_IP_HEADER=CF-Connecting-IP`** while the tunnel stays, or
  every user shares one rate-limit bucket.

Pinned by `tests/test_cutover.py`, which runs on `no_identity` — no Access
override and no header, which is the post-cut-over deployment. The rest of the
suite overrides `access_identity` and would pass against a platform that could
not authenticate anybody by itself.

# Recovery / rollback

Cutting back to Cloudflare Access means restoring the two units and the Access
drop-in, and re-adding users to the Access policy. **Credentials created in the
meantime do not carry over**, so a rollback after real signups is a data
decision rather than a config one — which argues for keeping Access configured
but unused until this has run for a while.
