# Deploy per-user isolation and the analysis-seconds balance

> **Issue:** DRAFT-047 —
> [#40](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/40).
>
> **Status: EXECUTED on the platform DomU, 2026-09-10.** All thirteen steps ran
> and every `EVIDENCE` block below is filled. Migrations 0007 and 0008 applied
> in one pass; decisions 4, 5/6, 7 and 8 of #40 are live, from commit
> `9ab3a35`.
>
> **What this proves:** a second identity cannot read, publish or unpublish
> another's job; artifacts written under the old flat layout are still
> reachable; and a completed analysis charges its owner — 3600 → 3457 s on a
> real run.
>
> **Two steps needed correcting mid-flight, and both are recorded rather than
> tidied away.** Step 9's `8443` check was written without a client
> certificate, so it reset the connection — the mutual-TLS gate working, not a
> fault. Step 8's seed inserted nothing for reasons never established; the
> deploy was unaffected because the first-contact upsert is the real path. Both
> carry a FINDING at the step.
>
> **Decision 3 was REVERSED during this work**, and not by this runbook. The
> browser listener is back on the LAN address so that the live console can
> reach it from Dom0 — see "Known gaps" at the foot, and
> `platform-domu.md` §E4a.
>
> **What this does not deploy:** splitting the ASGI app, the CLI through the
> tunnel, and purchasing. Each is its own draft.

## What changes on the running platform

| | Before | After |
|---|---|---|
| Reading another user's job | permitted | 404 |
| `jobs.owner` | nullable; mTLS submissions recorded NULL | **NOT NULL** |
| Submitting over `8443` (mTLS) | works | **403** — see the warning below |
| Object keys | `samples/<job_id>/…` | `u/<owner>/<shard>/samples/<job_id>/…` for new jobs; **existing keys do not move** |
| Analysis time | unmetered | 3600 s granted per identity, drawn down at each terminal state |
| Publishing | no route | `POST /jobs/{id}/publish`, owner only |

> **The command-line tools stop being able to submit.** `auth.required_identity`
> refuses a caller with no Access identity, and the mTLS listener has none by
> design. Reads, claims and every worker route are unaffected — this is
> submission only. If anything currently POSTs to `/api/v1/jobs` on 8443, it
> breaks at this deploy and stays broken until the CLI routes through the
> tunnel. **Confirm nothing does before starting.**

## Before you start

> **NEVER run the platform test suite here.** `tests/conftest.py`'s `conn`
> fixture runs `TRUNCATE jobs, tenants, worker_pipelines, workers RESTART
> IDENTITY CASCADE`. `tenants` was added to that list on 2026-09-07, so the
> suite now destroys balances as well as job history. It was attempted on the
> old deployment 2026-08-25 and failed with 312 errors because
> `sandbox_platform_test` does not exist — **the correct response is not to
> create it.** This runbook's `curl` checks and the UI are the verification.
>
> Do not run `playwright install` here either.

Two things must be true before step 1, and both are cheap to check.

---

## Step 1 — Is anything in flight?

Stopping the API stops heartbeats. A job holding a lease will lapse it, and the
next maintenance sweep marks it `interrupted` with `failure_reason =
lease_expired`. That is recoverable but it destroys a run, so drain first
unless the queue is empty.

```bash
# on the platform DomU
sudo -u postgres psql sandbox_platform -c "
  SELECT state, count(*) FROM jobs
   WHERE state IN ('cloning','preparing','executing','collecting','cleaning',
                   'queued','received')
   GROUP BY state ORDER BY state;"
```

Empty output means nothing is running and you can go straight on. Anything in a
running state: wait for it, or accept losing it and say so in the evidence.

> **In-flight jobs are not charged, and that is correct.** Their rows predate
> `started_at`, so they carry NULL, and `_charge_for_runtime` skips them. A job
> that spans this deploy is free — once.

## Step 2 — The blocker: rows with no owner

`0008` runs `ALTER COLUMN owner SET NOT NULL`, which **aborts if any row
violates it**. Migration 0007 already needed a backfill for exactly this reason
on `visibility`, so this is a known shape of failure here, not a hypothetical.

```bash
sudo -u postgres psql sandbox_platform -c \
  "SELECT count(*) AS ownerless FROM jobs WHERE owner IS NULL;"
```

**Zero** — continue.

**Non-zero** — stop and decide. These are jobs submitted over the mTLS listener
before this change, when unowned meant "an infrastructure job". They cannot be
guessed at; nothing in the row says who ran it. Two honest options, and picking
one is a judgement about the history, not a mechanical step:

- Attribute them to a named operator identity, if you know they are all yours:
  ```bash
  # Candidate -- only if every ownerless row is genuinely the operator's
  sudo -u postgres psql sandbox_platform -c \
    "UPDATE jobs SET owner = 'x90sh@proton.me' WHERE owner IS NULL;"
  ```
- Or delete them, if they are test submissions with nothing worth keeping.
  Their objects in MinIO are **not** removed by this and would be orphaned
  until the lifecycle rule expires them.

```
EVIDENCE 1-2                                                      ____-__-__

in-flight jobs before stopping:  0
ownerless rows:                  0
action taken (if any):           none
```

## Step 3 — Back up the database

The migration is not reversible by `run.py` — there is no down-migration, by
design. This dump is the rollback.

```bash
sudo -u postgres pg_dump -Fc sandbox_platform \
  > /var/backups/sandbox_platform-pre-0008-$(date +%F).dump
ls -lh /var/backups/sandbox_platform-pre-0008-*.dump
```

> **Back up only what cannot be rebuilt.** The job rows and the `manifest`
> JSON cannot; MinIO's objects can be re-fetched from nothing, so they are not
> in scope here — but note that a restore therefore gives you rows pointing at
> artifacts that may since have been expired by the lifecycle rule.

## Step 4 — Fetch the code, without starting it

The order matters and is the one thing this runbook exists to get right.
**`JobSummary.visibility` has no default**, so the new code cannot read a
pre-0007 row: it raises rather than rendering a job as private. Pull the code,
then migrate, then start.

```bash
# on the platform DomU
cd /opt/platform/src
sudo -u platform git fetch origin
sudo -u platform git log --oneline -1 origin/platform-domu   # expect 9ab3a35
sudo -u platform git status --short                          # expect empty
sudo -u platform git checkout platform-domu
sudo -u platform git pull --ff-only
git log --oneline -1
```

No dependency changes in this commit — `requirements.txt` is untouched, so no
`pip install` step and no venv rebuild.

## Step 5 — Stop both API listeners

Both, not just the browser one. They run the same ASGI object, so a running
8443 would serve new code against an old schema for the length of the
migration.

```bash
sudo systemctl stop sandbox-api-browser sandbox-api
systemctl is-active sandbox-api-browser sandbox-api    # expect: inactive
```

## Step 6 — Apply migrations 0007 and 0008

```bash
cd /opt/platform/src/platform
sudo -u platform env $(grep -h '^DATABASE_URL=' /etc/sandbox-platform/api.env) \
  .venv/bin/python migrations/run.py --status
```

`--status` first, and read it. Expect `0001`–`0006` applied and `0007`, `0008`
pending. **If it reports a digest mismatch on an already-applied file, stop** —
that means an applied migration was edited, and the fix is a conversation, not
a re-run.

```bash
sudo -u platform env $(grep -h '^DATABASE_URL=' /etc/sandbox-platform/api.env) \
  .venv/bin/python migrations/run.py
```

```
EVIDENCE 6                                                        ____-__-__

--status before:  
 applied  0001_jobs.sql
 applied  0002_triggers.sql
 applied  0003_sample_etag.sql
 applied  0004_results_bytes.sql
 applied  0005_console.sql
 applied  0006_egress.sql
 pending  0007_publish.sql
 pending  0008_tenancy.sql

applied 0007:     yes
applied 0008:     yes

 applied  0001_jobs.sql
 applied  0002_triggers.sql
 applied  0003_sample_etag.sql
 applied  0004_results_bytes.sql
 applied  0005_console.sql
 applied  0006_egress.sql
 applied  0007_publish.sql
 applied  0008_tenancy.sql

```

## Step 7 — Verify the schema landed

```bash
sudo -u postgres psql sandbox_platform -c "\d jobs" | \
  grep -E "owner|visibility|key_prefix|started_at|charged_seconds"
sudo -u postgres psql sandbox_platform -c "\d tenants"
```

Four things to confirm, and the third is the one people skim past:

- `owner` shows **not null**
- `key_prefix`, `started_at`, `charged_seconds` exist
- `jobs_key_prefix_regex` is present in the constraint list
- `tenants` exists with `balance_seconds bigint not null default 3600`

## Step 8 — Seed `tenants` from the owners you already have

**The migration does not do this, deliberately, and it is the one manual step.**
A `tenants` row is created on first contact by the balance endpoint or by
`create_job`, so every active user gets one the next time they load the UI.
What that does not cover is a job **already queued at step 1** that completes
afterwards: `_charge_for_runtime` would run `UPDATE tenants … WHERE owner = %s`
against no row, match nothing, and charge nobody — silently, because a
zero-row UPDATE is not an error.

```bash
sudo -u postgres psql sandbox_platform -c "
  INSERT INTO tenants (owner)
  SELECT DISTINCT owner FROM jobs WHERE owner IS NOT NULL
  ON CONFLICT (owner) DO NOTHING;"
sudo -u postgres psql sandbox_platform -c \
  "SELECT owner, balance_seconds FROM tenants ORDER BY owner;"
```

Everyone with history starts at the same 3600 s as a newcomer. That is a policy
choice — it grants existing users an hour they have not paid for — and it is
the simple one. Adjust individual balances by hand here if you want otherwise;
there is no purchasing pipeline yet and `UPDATE tenants SET balance_seconds =
…` is the intended interface until there is.

```
EVIDENCE 7-8                                                      2026-09-10

owner NOT NULL:            yes
key_prefix constraint:     yes
tenants table:             yes
tenants seeded (count):    0 -- see the FINDING below
```

> ### FINDING — the seed inserted nothing, and the deploy was fine anyway
>
> `tenants` was still empty after step 8. **Why is not established** — the
> jobs table had rows and none were ownerless (step 2), so
> `SELECT DISTINCT owner FROM jobs WHERE owner IS NOT NULL` should have
> returned at least one. The command's own output was not captured, so this is
> recorded as unexplained rather than diagnosed.
>
> **It did not matter, because the first-contact upsert is the real path.**
> Loading `/ui/jobs` created the row (step 11 evidence: the masthead rendered
> a balance), and a job that finished afterwards charged against it correctly
> — 3600 → 3457. The seed exists only for a job **already queued when the API
> stopped**, which would otherwise finish and charge against no row: an
> `UPDATE … WHERE owner = %s` matching nothing is not an error and reports
> nothing. Step 1 showed the queue empty, so that window was closed here.
>
> **What to do if it recurs on a busier deployment:** run the seed again after
> step 9 and read the row count it prints, rather than the table afterwards.
> `INSERT … ON CONFLICT DO NOTHING` is idempotent, so re-running costs nothing.

## Step 9 — Start, and check both listeners

```bash
sudo systemctl start sandbox-api-browser sandbox-api
systemctl is-active sandbox-api-browser sandbox-api

# The browser listener speaks TLS. http:// here returns "Empty reply from
# server" and means nothing is wrong with the service -- see
# [TROUBLESHOOTING](../TROUBLESHOOTING.md#empty-reply-from-server-from-a-listener-that-is-running).
curl -sS --cacert /etc/sandbox-platform/tls/ca.crt https://192.168.1.10:8000/healthz

# 8443 is MUTUAL TLS and demands a client certificate. Without --cert/--key it
# resets the connection, which is the gate working rather than a fault -- see
# [TROUBLESHOOTING](../TROUBLESHOOTING.md#recv-failure-connection-reset-by-peer-from-8443).
# Run this one from DOM0, which is where the client certificate lives.
curl -sS --cacert /etc/sandboxd/tls/ca.crt \
     --cert /etc/sandboxd/tls/dom0-lab.crt \
     --key  /etc/sandboxd/tls/dom0-lab.key \
     https://192.168.1.10:8443/healthz; echo
```

Then the drop-in, because losing it turns the browser listener into an
unauthenticated one and nothing else in this runbook would notice:

```bash
systemctl show sandbox-api-browser -p Environment --no-pager   # REQUIRE_ACCESS_JWT=1
systemctl show sandbox-api         -p Environment --no-pager   # must stay empty
```

## Step 10 — The old artifacts must still resolve

**This is the check that would catch the worst outcome of decision 7.** Every
object already in the bucket sits at the flat `results/<job_id>/…` key, and
`key_prefix = ''` is what reproduces that byte for byte. If the empty prefix
were wrong, every artifact the deployment has ever collected would be
unreachable — and it would look like retention having expired, not like a bug.

Open a **completed job from before this deploy** in the UI and download one
artifact.

```bash
root@platform:~# sudo -u postgres psql sandbox_platform -c "
  SELECT id, submitted_filename, key_prefix FROM jobs
   WHERE state = 'completed' AND key_prefix = ''
   ORDER BY created_at DESC LIMIT 3;"
                  id                  | submitted_filename | key_prefix 
--------------------------------------+--------------------+------------
 17ec0241-f61b-4892-bf77-ec3ab3c3f29e | slow.sh            | 
 a99d967b-95ae-4e8f-ab5c-656a23f9f256 | slow.sh            | 
 b4773ed3-f32c-4cc8-bd5c-5759976955f2 | hello.txt          | 
(3 rows)

```

Then fetch one through the browser, signed in through the tunnel. A 200 with
the right bytes settles it.

## Step 11 — Submit, and watch the balance move

The end-to-end check. Through the tunnel, as a real Access user.

1. Load `/ui/jobs`. **The masthead shows a balance** — that is `balance.js`
   calling `POST /api/v1/account/balance`, which is also what creates the
   tenant row for a first-time user.
2. Submit a benign sample and let it run to completion.
3. The balance drops by roughly the analysis duration.

```bash
sudo -u postgres psql sandbox_platform -c "
  SELECT j.submitted_filename, j.state, j.started_at, j.charged_seconds,
         t.balance_seconds
    FROM jobs j JOIN tenants t ON t.owner = j.owner
   ORDER BY j.created_at DESC LIMIT 1;"
```

`charged_seconds` non-NULL and `balance_seconds` reduced by it is the whole of
decision 8 working. `started_at` non-NULL proves `CLAIM` set the clock.

```
EVIDENCE 9-11                                                     2026-09-10

both listeners active:        Yes
REQUIRE_ACCESS_JWT on 8000:   Yes
8443 Environment empty:       Yes
pre-deploy artifact fetched:  Yes
balance rendered in masthead: Yes
charged_seconds after a run:  Yes
balance after:                3457

root@dom0:/home/user# curl -sS --cacert /etc/sandboxd/tls/ca.crt \
     --cert /etc/sandboxd/tls/dom0-lab.crt \
     --key  /etc/sandboxd/tls/dom0-lab.key \
     https://192.168.1.10:8443/healthz; echo
{"status":"ok"}
```

> ### FINDING — 3600 − 3457 = 143 s, and that is decision 8 working end to end
>
> A real analysis charged 143 seconds against a balance that started at the
> column default. `charged_seconds` non-NULL proves `_charge_for_runtime` ran;
> the balance moving by exactly that proves the `tenants` UPDATE matched a row.
> `started_at` non-NULL proves `queries.CLAIM` set the clock — the bug that
> made both charge sites raise before this commit.

## Step 12 — The worker channel is unchanged

The regression that would break the pipeline for everyone. Dom0 must still be
able to claim and run a job it does not own — `lease_owner` scopes the worker
channel and `owner` must never be allowed to.

Run one analysis submitted by a *different* browser identity than the one at
step 11, and confirm Dom0 claims it normally. If there is only one identity on
this deployment, `test_a_worker_runs_a_job_it_does_not_own` covers the property
in the dev container and this step is a formality — **say which, in the
evidence, rather than leaving it ambiguous.**

## Step 13 — Tenancy, with a second identity

Only meaningful with two Access identities. If there is one, this step cannot
run here and the property rests on `platform/tests/test_tenancy.py` — record
that rather than ticking it.

- B opens A's job id → **404**, not 403.
- B's history does not list A's jobs.
- A publishes; B can then read it **in full**, including `extracted/`.
- A unpublishes; B gets 404 again.
- B cannot publish or unpublish A's job.

```
EVIDENCE 12-13                                                    ____-__-__

worker claimed another user's job:  Yes with jobs submitted from two owners  (or: single identity, see tests)
B reading A's job:                  Can't and gets 404
B after A publishes:                Yes
B unpublishing A's job:             B can't unpublish (404)
B reading A's job after A unpublishes Can't and gets 404
```

---

## Rollback

**The migration has no down path.** Rolling back means restoring the dump from
step 3 and checking out the previous commit.

```bash
sudo systemctl stop sandbox-api-browser sandbox-api
cd /opt/platform/src && sudo -u platform git checkout 97290f1
sudo -u postgres dropdb sandbox_platform
sudo -u postgres createdb -E UTF8 -T template0 sandbox_platform
sudo -u postgres pg_restore -d sandbox_platform \
  /var/backups/sandbox_platform-pre-0008-<date>.dump
sudo systemctl start sandbox-api-browser sandbox-api
```

> **What a rollback loses.** Any job submitted after the deploy, and its
> `tenants` row. Its objects stay in MinIO under `u/<owner>/<shard>/…`, which
> the restored code cannot address — they are orphaned until the lifecycle rule
> expires them. That asymmetry is the reason to do step 11's verification
> promptly rather than a day later.

## Known gaps at deploy time

- **F12 — the whole worker channel is reachable from the internet.** Confirmed
  on this deployment, 2026-09-10:

  ```
  root@platform:~# cloudflared --config /etc/cloudflared/config.yml tunnel ingress rule \
      https://sandbox.evilbootloader.com/api/v1/worker/claim
  Using rules from /etc/cloudflared/config.yml
  Matched rule #1
      hostname: sandbox.evilbootloader.com
      service: https://192.168.1.10:8000
  ```

  The ingress has no path restriction, so `/api/v1/worker/*` — claim,
  heartbeat, state, artifact tickets, and the console's worker end — routes
  from the public hostname. Those routes carry `require_worker_token`, not the
  Access dependency, so **the worker token alone is what stands between the
  internet and the queue**, behind Access at the edge. The mTLS listener on
  8443 additionally demands a client certificate; this path does not, which
  makes it strictly the weaker of the two doors into the same app.

  **What it would let a token holder do:** claim other people's jobs, move them
  through the state machine, upload artifacts against them, and attach to a
  running clone's console. Not read the database or enumerate MinIO — the
  worker channel is scoped by `lease_owner` — but enough to corrupt a run and
  to watch one.

  Pre-existing rather than introduced here: these routes have always been in
  the app served on 8000. What changed is that the console now *depends* on
  that listener (`live-console.md` §4.1c), so it can no longer be dismissed as
  theoretical. `docs/runbooks/09-verify-sandboxd-and-console.md` F12 wrote the
  rule in 2026-08-26 and nobody applied it.

  **Candidate — apply on the platform DomU.** First match wins in cloudflared,
  so a 404 ahead of the catch-all is the whole fix:

  ```yaml
  ingress:
    # The worker channel is LAN-only. sandboxd reaches :8000 directly at
    # 192.168.1.10; nothing on the internet needs these paths.
    - hostname: sandbox.evilbootloader.com
      path: ^/api/v1/worker(/|$)
      service: http_status:404

    - hostname: sandbox.evilbootloader.com
      service: https://192.168.1.10:8000
      originRequest:
        caPool: /etc/cloudflared/ca.crt
    # ... the objects.evilbootloader.com rules unchanged ...
  ```

  ```bash
  cloudflared --config /etc/cloudflared/config.yml tunnel ingress validate
  cloudflared --config /etc/cloudflared/config.yml tunnel ingress rule \
      https://sandbox.evilbootloader.com/api/v1/worker/claim     # -> http_status:404
  cloudflared --config /etc/cloudflared/config.yml tunnel ingress rule \
      https://sandbox.evilbootloader.com/api/v1/jobs/x/console   # -> 192.168.1.10:8000
  systemctl reload cloudflared || systemctl restart cloudflared

  # From outside, and from Dom0 -- both must hold:
  curl -si https://sandbox.evilbootloader.com/api/v1/worker/claim | head -1   # 404
  ```

  **The second `ingress rule` check is not optional.** The BROWSER's console
  socket is `/api/v1/jobs/{id}/console` and must still route; a regex that
  caught it would take the console away from the very users it is for. Then
  confirm a job still runs end to end — `sandboxd` polls `:8000` over the LAN
  and is unaffected, but that is a claim worth testing rather than assuming.

  ```
  EVIDENCE F12                                                    ____-__-__

  ingress rule /api/v1/worker/claim:      ______
  ingress rule /api/v1/jobs/x/console:    ______
  curl from outside:                      ______
  a job still claims and completes:       ______
  ```


- **Decision 3 is no longer in force.** The browser listener was rebound from
  `127.0.0.1:8000` back to the LAN address during this work, because the live
  console dials it from Dom0 and loopback is unreachable from another machine
  (`ConnectionRefusedError` from `vnc.py:368` on every trace). **The gate is now
  `REQUIRE_ACCESS_JWT=1` alone** — the loopback bind was defence in depth behind
  it, and that layer is gone. What it cost: a lost `access.conf` drop-in is now
  a config slip on a LAN socket rather than on a loopback one, and the worker
  console route on `:8000` has no `--ssl-ca-certs`, so attaching to a running
  clone's VNC over the LAN is gated by the bearer token alone. Both were the
  pre-2026-09-06 state.

  **Do not "fix" the console by pointing `SANDBOXD_CONSOLE_API` at 8443.** The
  relay pairs two sockets in an in-process registry and the browser end arrives
  on 8000, so the two would land in different uvicorn processes and hang rather
  than refuse — worse, because a refusal names its cause and a hang reads as
  infrastructure trouble. The durable fix is moving the registry out of process
  (Postgres `LISTEN`/`NOTIFY` needs no new dependency); that is a design change
  and wants its own draft, together with the app split below.
- **The mTLS listener still serves the browser routers.** Both units run
  `sandbox_platform.app:app`, so a client-certificate holder reaches every job
  on 8443 with `visible_to` returning `TRUE`. Decision 3 closed the LAN path,
  not this one. Splitting the app is deferred and is its own change.
- **No purchasing.** Balances are topped up with `UPDATE tenants SET
  balance_seconds = …`. There is no audit of who did that or when.
- **Nothing caps a running job**, so a balance can go arbitrarily negative — a
  job admitted with one second left runs to completion. The bound is Dom0's
  analysis timeout times the concurrent slot count, and that number is not
  recorded anywhere yet.
- **The quota does not bound storage.** Many small fast-failing jobs consume
  little runtime and still write artifacts. DRAFT-041 watches that residual.
- **An email address in an object key cannot be erased by nulling a column.**
  Decision 7 puts the submitter's address in the key path, so a DRAFT-022
  erasure request means copy-and-delete across live malware, plus MinIO's
  access logs and any backups. Worth recording against DRAFT-022 before there
  is a volume of it.
