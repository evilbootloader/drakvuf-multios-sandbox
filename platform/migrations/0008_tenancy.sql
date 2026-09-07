-- 0008_tenancy.sql -- where a job's objects live in the store.
--
-- Issue #40 (DRAFT-047) decision 7. NO BEGIN/COMMIT -- run.py owns the
-- transaction, per the note at the head of 0001_jobs.sql.
--
-- The prefix is STORED, not derived at read time, and that is the whole design
-- of this column. Three different callers need the same key -- the submitter at
-- admission, Dom0 on the worker channel with no browser identity at all, and a
-- second user reading a published job -- and only the first of them holds the
-- identity the key was built from. Deriving from the caller gives a different
-- answer to each. The row is the only thing all three share.
--
-- It is also snapshotted for the reason `required_mib` is: a later change to
-- the naming rule must not move objects that were already written under the
-- old one. Same argument, different resource.
--
-- **`''` is the pre-#40 flat layout and is CORRECT for every existing row**,
-- not a missing backfill. `samples/<job_id>/…` and `results/<job_id>/…` are
-- where those objects actually are, and the key builders concatenate this
-- value in front, so an empty prefix reproduces the old key byte for byte.
-- That is what makes this migration safe against a populated bucket.
--
-- The trailing slash is part of the value, deliberately. It means the builders
-- are pure concatenation with no separator logic, so the empty and non-empty
-- cases need no branch and cannot disagree about where the `/` goes -- which
-- they did, in three different places, before the slash moved in here.
--
-- The user segment comes FIRST because S3 lifecycle prefixes are literal
-- rather than globs -- see platform/minio/provision.sh, which records that
-- `results/*/extracted/` cannot be expressed for exactly this reason. With
-- `u/<owner>/` leading, a per-user rule is expressible; under
-- `samples/u/<owner>/` it would not be, and per-user lifecycle and accounting
-- are the only things this column buys. It enforces nothing: isolation is the
-- API refusing to mint a capability for a job the caller cannot see, and MinIO
-- has no concept of these users either way.
--
-- **The three hex characters after the owner are a SHARD**, taken from
-- `job_id.hex[:3]`, and they bound directory fan-out under one owner. MinIO
-- lays each object out as a directory on the backing filesystem, so without
-- them `u/<owner>/samples/` accumulates one child per job and both listing and
-- the lifecycle scanner walk every one. 4096 shards, and `gen_random_uuid()`
-- is v4, so they fill evenly -- a time-ordered id would put a whole week in
-- one and buy nothing.
--
-- It is worth saying plainly that this is UNMEASURED. The bucket held a
-- handful of analyses when it was written. It is here anyway because the cost
-- is asymmetric: adding a shard now is free, and adding one later means
-- copying every object in a bucket of live malware.
--
-- It lives in the STORED VALUE rather than in the key builders, which is the
-- second reason `create_job` generates the job id instead of letting the
-- column default do it. A builder that inserted the shard itself would need
-- `if key_prefix: shard else: don't`, because the legacy flat layout must not
-- get one -- and that branch is exactly what produced double slashes and three
-- prefix bugs before the trailing slash moved into the value. The builders
-- stay pure concatenation; the prefix is the whole answer.
--
-- `owner` becomes NOT NULL here, for traceability: every submission carries an
-- Access identity, so a job nobody owns is a job nobody can be charged for or
-- asked about. `auth.required_identity` is the matching refusal at the API,
-- and it turns what would be a constraint violation into a 403. **Note what
-- this makes unreachable**: `auth.visible_to`'s `owner IS NULL` arm is a
-- shared pool visible to every authenticated user, and this constraint is the
-- only thing keeping it empty.

ALTER TABLE jobs
    ALTER COLUMN owner SET NOT NULL,
    ADD COLUMN key_prefix text NOT NULL DEFAULT '',
    ADD COLUMN started_at timestamptz,
    ADD COLUMN charged_seconds bigint,
    ADD CONSTRAINT jobs_key_prefix_regex
        CHECK (key_prefix = '' OR key_prefix ~ '^u/[^/]+/[0-9a-f]{3}/$');

COMMENT ON COLUMN jobs.key_prefix IS
    'Where this job''s objects live, as a key prefix with its trailing slash. '
    'Empty means the pre-#40 flat layout (samples/<job_id>/, results/<job_id>/) '
    'and is correct for every row created before this migration -- not a '
    'missing backfill. Otherwise u/<lowercased owner>/<3 hex of job_id>/, the '
    'trailing directory being a shard that bounds fan-out under one owner. '
    'Written once at submission by create_job and never re-derived: the caller '
    'reading a job is frequently not the caller who wrote it.';

-- The billing clock (decision 8). Set by queries.CLAIM, which is when a host
-- takes the job -- everything before it is queue time, and a submitter cannot
-- control how long they wait behind other people's work.
COMMENT ON COLUMN jobs.started_at IS
    'When a host claimed this job, or NULL if none ever did. Set by '
    'queries.CLAIM. Doubles as the "a clone existed" test: a submission '
    'rejected at admission never reached CLAIM, so it carries no start and is '
    'charged nothing -- which is why no list of chargeable states exists.';

COMMENT ON COLUMN jobs.charged_seconds IS
    'Seconds drawn from the owner''s balance when this job reached a terminal '
    'state, or NULL if it was never charged. Both a record and the idempotence '
    'marker: routers.worker._charge_for_runtime writes it in the same '
    'conditional UPDATE that reads it, so a redelivered report charges once. '
    'NULL on a reaped or reconciled job is correct and deliberate -- the '
    'platform lost track of those and cannot say when they stopped.';


-- Who may spend analysis time, and how much is left.
--
-- Issue #40 (DRAFT-047) decision 8. A prepaid balance, not a rolling window:
-- seconds are bought once and drawn down as jobs finish, so an idle month
-- neither expires nor replenishes anything.
--
-- **A row appears on first contact, not by an administrator.** There is no
-- signup step and no tenant registry to keep in step with Cloudflare Access
-- -- Access decides who may reach the listener at all, and anyone it lets
-- through is a tenant by definition. The row is created by whichever of the
-- balance endpoint or `create_job` sees the identity first, which is why both
-- must insert idempotently rather than test-then-insert: the UI asks for a
-- balance on page load and a headless client submits without ever asking, so
-- the two race by construction on a first visit.
--
-- `owner` is the primary key and is the same lowercased address `jobs.owner`
-- carries, so the two join without a surrogate id. No foreign key from
-- `jobs`, deliberately: a job row is evidence and must survive its tenant
-- being erased under DRAFT-022, which a reference would prevent.
--
-- 3600 is a grant, not a trial, and it is DEFERRED POLICY rather than a
-- decision -- purchasing is a later draft (Stripe), and until it exists the
-- operator tops balances up with an UPDATE. The number lives HERE and only
-- here: application code must read the row back after inserting rather than
-- assume what the default gave it, or the UI and the database will disagree
-- the first time this changes.
--
-- Negative balances are permitted on purpose. The charge lands when a job
-- reaches a terminal state, so a job admitted with one second left may run to
-- completion and overdraw; refusing mid-analysis would destroy work already
-- paid for in host time. Admission is the gate (402 at or below zero), and
-- the overdraft is bounded by Dom0's analysis timeout, not by anything here.
CREATE TABLE tenants (
    owner text PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    balance_seconds bigint NOT NULL DEFAULT 3600
);

COMMENT ON TABLE tenants IS
    'One row per Access identity that has reached the platform. Created on '
    'first contact by the balance endpoint or create_job, never by an admin.';

COMMENT ON COLUMN tenants.balance_seconds IS
    'Prepaid analysis seconds remaining. Drawn down when a job reaches a '
    'terminal state having had a clone; may go negative, because the charge '
    'lands at the end and nothing caps a running job. 3600 is the opening '
    'grant -- read it back from the row, never hardcode it.';

