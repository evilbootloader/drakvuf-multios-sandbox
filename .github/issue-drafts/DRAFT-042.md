# DRAFT-042: Job schema and the claim query, with head-of-line reservation

**Status:** **[#35](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/35) — published 2026-08-22, OPEN.**
**Area:** core/platform
**OS:** ALL
**Milestone:** M1 → gates M7
**Priority:** P0 — first buildable piece of the platform. Everything that
reads or writes job state depends on this shape being right.
**Depends on:** DRAFT-041 (decided). Nothing open.
**Blocks:** DRAFT-043 (API), DRAFT-045 (web UI), and the `sandboxd` and
cancellation issues that follow.
**Needs Dom0:** **No.** Postgres and pytest in the development container.

# Objective

Create the Postgres schema that holds job state and the queue, and the
claim query that implements **head-of-line reservation** — the property that
stops a large Windows job starving behind smaller ones.

One database, one table, three queries. If this is wrong, everything built
on it is wrong, which is why it is a separate issue from the API that calls
it.

# Context

## Why the schema is the risky part

`docs/architecture/platform.md` decided Postgres holds *both* job state and
the queue, and the reason was a single property: **claiming a job and
transitioning its state must be one transaction.** Split them across two
stores and you get the classic double-run, and cancelling a queued job
becomes two writes with no transaction between them.

That property is not a feature you add later. It is a consequence of the
schema and the query shape, so it is what this issue is actually about.

## The measured problem this must solve

Greedy admission starves the largest clone. Measured on Dom0 2026-08-20:
170 consecutive admission holds, zero clones for a 6294 MiB job, seven
2198 MiB jobs completing meanwhile. Every individual decision was correct;
each decision-maker only saw its own.

A Windows clone costs 6294 MiB (`misc/windows.cfg`'s `memory = 6144` plus a
per-host domain overhead) against 2198 for Ubuntu and Android — roughly 3×.
The golden Windows VM now exists, so this stops being hypothetical.

## What the state model already fixes

The states are **not** designed here. `docs/architecture/analysis-pipeline.md`
already specifies them, and this schema carries them unchanged:

```text
received → admitted → queued → cloning → preparing → executing → collecting
                                                                      │
                                                 completed ← cleaning ┘
exits
  admitted           → rejected     admission failed; no clone made
  queued             → cancelled    cancelled before a clone existed
  cloning…executing  → cleaning → cancelled
  cloning…collecting → cleaning → failed        + failure_stage/failure_reason
  any non-terminal   → cleaning → interrupted   owning process died
```

# Dependencies

- **DRAFT-041** — decided; this implements its schema sketch.
- Nothing else. This issue deliberately does not depend on the API existing:
  the queries are tested directly against a database.

# Out of scope

- **The HTTP API** (DRAFT-043). This issue produces SQL and a thin data
  access layer, not endpoints.
- **MinIO, buckets, presigned URLs** (DRAFT-044). `manifest` is a `jsonb`
  column here and nothing writes it yet.
- **`sandboxd`.** Nothing calls the claim query from Dom0 in this issue.
- **Authentication and multi-tenancy.** `owner` and `visibility` are created
  as nullable columns and nothing populates or enforces them. M8 owns that,
  and this issue must not design it — but must not foreclose it either,
  which is why the columns exist now rather than being added by a later
  migration to a populated table.
- **Backfill.** Letting a small job run when it provably cannot delay the
  reserved job needs per-OS runtime estimates the project does not have.
  Deferred deliberately, not overlooked.

# PLAN

1. Settle the migration mechanism (see CREATE — numbered SQL, recommended
   over Alembic, with the reason).
2. Write the schema. Take the state list from `analysis-pipeline.md` rather
   than retyping it, so the two cannot drift.
3. Write the three queries: claim, reserve-report, cancel. Plus the reaper.
4. Write the tests **first for the concurrency properties**, because those
   are the ones that pass by accident under single-threaded testing.
5. Confirm head-of-line against the measured numbers — 6294 ahead of a queue
   of 2198s — rather than against invented ones.

# CREATE

## Migrations: numbered SQL, not Alembic

**Recommend plain numbered SQL files** (`migrations/0001_jobs.sql`, …) plus a
`schema_migrations` table and a ~30-line runner.

Alembic is the obvious alternative and is rejected for this project
specifically: its value is autogenerating diffs from ORM models, and there is
no ORM here — the claim query is hand-written SQL that no ORM would express
well. Adopting Alembic means adopting SQLAlchemy models that exist only to be
diffed. Numbered SQL is auditable by reading it, which matters more here than
convenience.

## Schema

```sql
-- 0001_jobs.sql

-- target_os is a Postgres ENUM deliberately, not a text column with a
-- CHECK. Issue #3's decision is that the OS token is a closed set the
-- submitter chooses from, and that this is the ONLY untrusted routing input
-- in the system. An enum makes "closed" a property the database enforces:
-- an unknown value fails at the type boundary, before any application code
-- decides what to do with it.
CREATE TYPE target_os AS ENUM ('ubuntu', 'android', 'windows');

-- state is text + CHECK, NOT an enum, for the opposite reason: it will gain
-- values as the pipeline grows, and ALTER TYPE ... ADD VALUE cannot run in a
-- transaction with other DDL on older Postgres. The constraint is
-- greppable and a migration can change it in one statement.
CREATE TABLE jobs (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),

    -- Reserved for M8. Created now rather than added later, because adding
    -- a tenancy column to a populated table means deciding what every
    -- existing row's owner is, retroactively.
    owner              text,
    visibility         text,

    target_os          target_os NOT NULL,

    -- DATA, never interpolated. Reaches the guest byte-exact (extension
    -- dispatch and argv[0] self-checks are real evasion surface), reaches
    -- the browser escaped-on-output, and reaches SQL only as a bound
    -- parameter.
    submitted_filename text NOT NULL,

    sha256             text,
    size_bytes         bigint,

    -- Advisory. REPORTS, never routes -- it can reject a mismatch against
    -- target_os and that is its only authority (issue #3).
    detected_type      text,
    type_identifiers   jsonb NOT NULL DEFAULT '{}'::jsonb,

    state              text NOT NULL DEFAULT 'received'
        CHECK (state IN ('received','admitted','queued','cloning','preparing',
                         'executing','collecting','cleaning','completed',
                         'rejected','cancelled','failed','interrupted')),

    -- Host-global FIFO order. bigserial, not created_at: two jobs can share
    -- a timestamp, and the queue must be totally ordered or head-of-line
    -- has no head.
    queue_seq          bigserial NOT NULL,

    -- memory + per-host domain overhead, from the worker's registration.
    -- Snapshotted onto the job at admission so a later retune of
    -- misc/*.cfg cannot silently change what a queued job costs.
    required_mib       integer,

    queue_reason       text,
    failure_stage      text,
    failure_reason     text,
    cleanup_status     text,
    attempt            integer NOT NULL DEFAULT 0,
    cancel_requested   boolean NOT NULL DEFAULT false,

    -- Job RECORD ownership, not a physical resource. A lapsed lease marks
    -- the job interrupted so it stops occupying the queue; it frees nothing
    -- on Dom0, and the platform could not free a VLAN if it wanted to.
    lease_owner        text,
    lease_expires_at   timestamptz,

    -- Diagnostics and reconciliation only. Dom0's live state (xl list,
    -- ip link) is authoritative; a row disagreeing with it is stale.
    clone_domain       text,
    vlan               integer,

    manifest           jsonb
);

-- What each analysis host can afford, declared by the host itself.
--
-- Persisted rather than held in the API's memory for one reason: admission
-- runs at SUBMISSION time and needs to know whether any host could ever run
-- this job (see "A deadlock this schema must refuse"). An API restart with
-- in-memory registration would leave that check unable to answer until the
-- worker's next poll, and the honest failure would be to accept a job that
-- can never run.
--
-- required_mib is per-OS because a Windows clone costs ~3x an Ubuntu one.
-- It is derived ON DOM0 from misc/<os>_sandbox.cfg plus that host's own
-- domain overhead, and sent here -- never duplicated on the platform side,
-- which would recreate the two-files-free-to-disagree failure platform.env
-- exists to prevent.
CREATE TABLE workers (
    worker_id     text PRIMARY KEY,
    registered_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    total_mib     integer NOT NULL,
    total_vlans   integer NOT NULL,
    total_slots   integer NOT NULL
);

CREATE TABLE worker_pipelines (
    worker_id    text NOT NULL REFERENCES workers(worker_id) ON DELETE CASCADE,
    os           target_os NOT NULL,
    required_mib integer NOT NULL,
    PRIMARY KEY (worker_id, os)
);

-- The claim query's index. Partial: the queue is a small hot subset of a
-- table that grows without bound, and a full index on queue_seq would be
-- mostly cold history.
CREATE INDEX jobs_queue ON jobs (queue_seq) WHERE state = 'queued';

CREATE INDEX jobs_sha256 ON jobs (sha256);
CREATE INDEX jobs_created ON jobs (created_at DESC);
CREATE INDEX jobs_lease ON jobs (lease_expires_at)
    WHERE lease_expires_at IS NOT NULL;
```

## The claim query — this is the issue

```sql
-- $1 worker_id   $2 lease TTL   $3 free_mib reported by the worker
UPDATE jobs
   SET state            = 'cloning',
       lease_owner      = $1,
       lease_expires_at = now() + $2::interval,
       attempt          = attempt + 1,
       queue_reason     = NULL,
       updated_at       = now()
 WHERE id = (
         SELECT id
           FROM jobs
          WHERE state = 'queued'
            AND NOT cancel_requested
          ORDER BY queue_seq
          FOR UPDATE SKIP LOCKED
          LIMIT 1
       )
   AND required_mib <= $3
RETURNING id, target_os, sha256, submitted_filename, required_mib;
```

**Read the two halves separately, because the second is the whole point.**

The subquery takes *the head of the queue and only the head*. The
`required_mib <= $3` test then sits on the outer `UPDATE`, so when the head
does not fit the statement matches zero rows and **no other job is
considered**. That is head-of-line reservation: one statement, no
application logic, no distributed protocol. A greedy implementation would
put the fit test inside the subquery, and would then hand out the next job
that fits — which is exactly the 170-holds behaviour.

`FOR UPDATE SKIP LOCKED` is what makes two workers safe. It does *not*
undermine head-of-line: a locked head is a head another worker is claiming
right now, so moving past it is correct. The lock lives for the transaction,
which is microseconds.

Zero rows returned is ambiguous — empty queue, or head does not fit — so the
caller disambiguates:

```sql
-- Reservation report. Read-only; runs only when the claim returned nothing.
SELECT id AS blocking_job_id, required_mib
  FROM jobs
 WHERE state = 'queued' AND NOT cancel_requested
 ORDER BY queue_seq
 LIMIT 1;
```

## Cancellation

```sql
-- Before a clone exists: terminal immediately, nothing to tear down.
-- This single statement is what DRAFT-040 said today's design cannot
-- express at all.
UPDATE jobs
   SET state = 'cancelled', updated_at = now()
 WHERE id = $1
   AND state IN ('received','admitted','queued')
RETURNING id;

-- While running: request it; sandboxd sees it on its next heartbeat and
-- tears down through cleanup.sh, passing through 'cleaning'.
UPDATE jobs
   SET cancel_requested = true, updated_at = now()
 WHERE id = $1
   AND state IN ('cloning','preparing','executing','collecting')
RETURNING id;
```

## The reaper

```sql
UPDATE jobs
   SET state = 'interrupted', updated_at = now()
 WHERE lease_expires_at < now()
   AND state IN ('cloning','preparing','executing','collecting')
RETURNING id;
```

Marks the record, frees nothing on Dom0. Reconciliation on `sandboxd`
startup is what resolves an interrupted job against a domain that may still
be running — and it reads `xl list`, not this table.

## A deadlock this schema must refuse

**A job larger than any worker's total capacity blocks the queue forever.**
Head-of-line means the head waits; if the head can never fit, nothing behind
it ever runs, and the symptom is the silent hold this whole design exists to
remove.

The guard belongs at admission, not at claim time:

```sql
-- Could ANY registered host ever run this? Note total_mib, not free_mib --
-- the question is capability, not current availability. A job that only
-- fails because the host is busy belongs in the queue; one that fails
-- because the host is too small belongs in rejected.
SELECT EXISTS (
    SELECT 1
      FROM worker_pipelines wp
      JOIN workers w USING (worker_id)
     WHERE wp.os = $1
       AND wp.required_mib <= w.total_mib
);
```

False → `state = 'rejected'`, `failure_reason = 'no_capacity'`, before the
job is ever queued. Rejecting at submission is a message the submitter can
act on; blocking at claim time is a hang.

**The empty case is a trap.** With no worker ever registered the `EXISTS` is
false and every submission is rejected — which reads as the platform being
broken. Distinguish it: no registered workers at all is
`failure_reason = 'no_workers'`, a different message, and it is the correct
answer on a fresh install rather than an error to paper over.

## Live status

A trigger on state change issuing `pg_notify('jobs', json)`, consumed by the
API's SSE endpoint. This is why the web UI needs no Redis pub/sub.

# TEST

`pytest` against a real Postgres in the development container — not SQLite,
not a mock. `SKIP LOCKED` and transactional visibility are the things under
test, and neither exists in a substitute.

**Concurrency tests first.** These are the ones that pass by accident when
written after the fact and run single-threaded:

1. **Head-of-line holds.** Enqueue 6294, then twelve 2198s. Claim with
   `free_mib = 5082` (the measured figure: 12082 free minus a 7000 reserve).
   Assert zero rows, assert the reservation report names the 6294 job, and
   **assert no 2198 job moved out of `queued`**. This is the 2026-08-20
   measurement inverted and is the acceptance test for the whole issue.
2. **Head-of-line releases.** Same queue, claim with `free_mib = 6294`.
   Assert the large job is claimed *first*, ahead of twelve older-fitting
   smaller ones.
3. **No double-issue.** N concurrent claims against one queued job; exactly
   one gets it. Run under real threads with a barrier, not sequentially.
4. **Claim is atomic with the transition.** Kill the connection mid-claim;
   assert the job is either `queued` with no lease or `cloning` with one,
   never `queued` holding a lease.
5. **Cancel a queued job.** Assert single statement, one row, state
   `cancelled`, and that no clone-related column was ever set.
6. **Cancel a running job** sets `cancel_requested` and does *not* change
   `state`.
7. **A cancelled job is never claimed** — `cancel_requested` set on the head
   must not block the queue behind it.
8. **Lease expiry** marks `interrupted` and leaves `clone_domain`/`vlan`
   untouched.
9. **Over-capacity rejection.** A job larger than the largest registered
   worker is `rejected`/`no_capacity` at admission and never reaches
   `queued`.

Plus: every migration applies to an empty database and is idempotent under
re-run; `state`'s CHECK list matches `analysis-pipeline.md`'s state machine
exactly, asserted by a test that reads both.

# DEPLOY

Postgres runs in the platform LXC (DRAFT-041). This issue does not stand
that container up — it produces migrations that run against it, and a
`docker compose`/local instance is enough to develop and test against.

Rollback is `DROP DATABASE` while nothing depends on it, which is true for
exactly as long as this issue is the only thing built. Once DRAFT-043 lands,
rollback becomes a down-migration and the ordering matters.

# Acceptance criteria

- [ ] Migrations create the schema on an empty database, and re-running the
      runner is a no-op.
- [ ] `target_os` is a database-enforced enum; an unknown value fails at the
      type boundary.
- [ ] `state`'s CHECK list is identical to the state machine in
      `analysis-pipeline.md`, verified by a test rather than by reading.
- [ ] The claim query returns a job **or** a reservation, never a smaller
      job when the head does not fit — test 1.
- [ ] The large job is claimed ahead of the queue once capacity allows —
      test 2.
- [ ] Claim and state transition are one transaction — tests 3 and 4.
- [ ] Cancelling a queued job is a single statement — test 5.
- [ ] A job that cannot fit any registered worker is rejected at admission
      with `no_capacity`, not queued — test 9.
- [ ] `owner` and `visibility` exist and nothing reads them.
- [ ] `lease_expires_at` expiry marks the record only; no Dom0 resource is
      implied to be freed, and a comment in the migration says so.
- [ ] No `automation/` file changes.

# Evidence required

- `pytest` output with all nine concurrency tests passing, run against a
  real Postgres.
- The `EXPLAIN` plan for the claim query, showing the partial index is used
  — a sequential scan here is a correctness risk as well as a performance
  one, because the lock ordering stops being the queue order.
- Test 1's assertion output showing the *count* of smaller jobs still
  `queued`, so the result is legible as "held the queue" rather than merely
  "returned nothing".

# Security considerations

- **`target_os` is the only untrusted routing input**, and the enum is what
  makes issue #3's decision enforceable rather than merely documented. Any
  later change that widens it to free text reopens a decision that was taken
  deliberately.
- **`submitted_filename` is attacker-controlled and is stored verbatim.**
  That is correct — it must reach the guest byte-exact — and it means every
  consumer is responsible for its own escaping. Bound parameters here;
  escape-on-output in the UI; an `argv` element, never a formatted string,
  on Dom0.
- **`detected_type` must never be used to route.** It exists to reject a
  mismatch. A future query that selects a pipeline by `detected_type` breaks
  issue #3 and should be rejected on that ground.
- **The database is reachable only by the API process** (DRAFT-041's D4
  choice). No Dom0 credentials, no direct connections from the analysis
  host. A schema change that assumes otherwise — a role for `sandboxd`, say
  — contradicts the architecture.
- **`manifest` is `jsonb` written from worker-supplied content.** Validate
  its shape at the API boundary; a compromised Dom0 can write anything here.

# Documentation changes

- **New:** `migrations/` with a `README.md` stating the runner and the
  ordering rule.
- **Updated:** `docs/architecture/platform.md` — replace the schema *sketch*
  with a pointer to the real migration, so the two cannot drift. The sketch
  exists because there was no schema; once there is one, a second copy is a
  liability.
- **Updated:** `docs/architecture/result-schema.md` — `manifest`'s shape is
  its concern, and the MD5-keying `KNOWN GAP` recorded there names `job_id`
  as the fix. This is where `job_id` first exists.

# Recovery / rollback

Nothing deployed depends on this until DRAFT-043. Rollback is dropping the
database and reverting the migration files. The analysis pipeline continues
running on `dirwatch` throughout, unaffected — that is the property that
makes the whole platform buildable without a flag day.