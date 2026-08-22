-- 0001_jobs.sql -- job state, the queue, and what each analysis host can afford.
--
-- Issue #35 (DRAFT-042). Design record: docs/architecture/platform.md.
--
-- This schema holds BOTH job state and the queue, in one database, because
-- claiming a job and transitioning its state must be one transaction. Split
-- them across two stores and you get the classic double-run, and cancelling a
-- queued job becomes two writes with nothing tying them together. That
-- property is not a feature added later; it is a consequence of this file and
-- of the claim query in 0003.
--
-- NO BEGIN/COMMIT IN THIS FILE. run.py owns the transaction, because the
-- migration and its schema_migrations row must commit together -- a COMMIT
-- here would close the runner's transaction early and leave the schema
-- applied but unrecorded. run.py refuses a file containing either keyword.

-- target_os is an ENUM deliberately, not text with a CHECK.
--
-- Issue #3 decided that the OS token is a closed set the submitter chooses
-- from, and that it is the ONLY untrusted routing input in the system. An
-- enum makes "closed" a property the database enforces: an unknown value
-- fails at the type boundary, before any application code decides what to do
-- with it. Widening this to free text reopens a decision that was taken
-- deliberately, and would do it silently.
CREATE TYPE target_os AS ENUM ('ubuntu', 'android', 'windows');

CREATE TABLE jobs (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),

    -- Reserved for M8 multi-tenancy. Created now and read by nothing.
    -- Adding a tenancy column to a populated table later means deciding what
    -- every existing row's owner is, retroactively, which is a decision made
    -- under pressure by whoever writes that migration.
    owner              text,
    visibility         text,

    target_os          target_os NOT NULL,

    -- DATA. Never interpolated, anywhere.
    --
    -- It reaches the guest byte-exact -- extension dispatch and argv[0]
    -- self-checks are real evasion surface, which is why DRAFT-030 stopped
    -- naming the staged guest file after its hash. It reaches SQL only as a
    -- bound parameter, and the browser only escaped-on-output. dirwatch's
    -- admission check rejects `/` and control characters and nothing else, so
    -- `"`, `$`, a backtick and `;` are all admissible here.
    submitted_filename text NOT NULL,

    sha256             text,
    size_bytes         bigint,

    -- Advisory. REPORTS, never routes: it may reject a mismatch against
    -- target_os and that is the whole of its authority (issue #3). A query
    -- that selects a pipeline by this column is a bug, not an optimisation.
    detected_type      text,
    type_identifiers   jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- text + CHECK rather than an enum, for the opposite reason to
    -- target_os: this list is expected to grow, and a CHECK is changed by one
    -- statement in a migration. Kept identical to the state machine in
    -- docs/architecture/analysis-pipeline.md; tests/test_schema.py asserts
    -- the two agree rather than trusting that they do.
    state              text NOT NULL DEFAULT 'received'
        CHECK (state IN ('received','admitted','queued','cloning','preparing',
                         'executing','collecting','cleaning','completed',
                         'rejected','cancelled','failed','interrupted')),

    -- Host-global FIFO order.
    --
    -- bigserial and not created_at: two jobs can share a timestamp, and a
    -- queue that is not TOTALLY ordered has no well-defined head -- which
    -- would make head-of-line reservation depend on which row the planner
    -- happened to return first.
    queue_seq          bigserial NOT NULL,

    -- The domain's `memory` plus that host's domain overhead, taken from
    -- worker_pipelines at admission and SNAPSHOTTED here, so retuning
    -- misc/*.cfg cannot change what an already-queued job costs.
    required_mib       integer,

    queue_reason       text,
    failure_stage      text,
    failure_reason     text,
    cleanup_status     text,
    attempt            integer NOT NULL DEFAULT 0,
    cancel_requested   boolean NOT NULL DEFAULT false,

    -- Job RECORD ownership. NOT a physical resource.
    --
    -- Read this before "fixing" it to look like the VLAN lease it resembles.
    -- DRAFT-040 established that VLAN and memory leases must release on
    -- process death and ONLY on death, because a TTL would reassign a
    -- stalled-but-alive watcher's VLAN while its clone still ran on that
    -- segment. That reasoning was about coordinating three processes; there
    -- is one orchestrator now, and VLAN allocation is an in-process table on
    -- Dom0 with no lease file at all.
    --
    -- What expires here is bookkeeping: a lapsed lease marks the job
    -- interrupted so it stops occupying the queue. It frees NOTHING on Dom0,
    -- and the platform could not free a VLAN if it wanted to -- it has no
    -- idea what one is. Dom0's startup reconciliation against `xl list` and
    -- `ip link` is what actually decides.
    lease_owner        text,
    lease_expires_at   timestamptz,

    -- Diagnostics and reconciliation only. Dom0's live state is
    -- authoritative; a row disagreeing with it is stale, not binding.
    clone_domain       text,
    vlan               integer,

    manifest           jsonb
);

-- What each analysis host can afford, declared by the host itself.
--
-- Persisted rather than held in the API's memory because admission runs at
-- SUBMISSION time and must answer "could any host ever run this?" -- see
-- 0003's over-capacity guard. In-memory registration would leave that
-- unanswerable across an API restart, and the honest failure would be to
-- accept a job that can never run.
CREATE TABLE workers (
    worker_id     text PRIMARY KEY,
    registered_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    total_mib     integer NOT NULL CHECK (total_mib > 0),
    total_vlans   integer NOT NULL CHECK (total_vlans > 0),
    total_slots   integer NOT NULL CHECK (total_slots > 0)
);

-- required_mib is per-OS because a Windows clone costs roughly 3x an Ubuntu
-- one: 6144 + overhead against 2048 + overhead. It is derived ON DOM0 from
-- misc/<os>_sandbox.cfg plus that host's own measured overhead and sent here.
-- Never computed platform-side -- that would recreate exactly the
-- two-files-free-to-disagree failure automation/platform.env exists to
-- prevent, with no loud symptom when they drift.
CREATE TABLE worker_pipelines (
    worker_id    text NOT NULL REFERENCES workers(worker_id) ON DELETE CASCADE,
    os           target_os NOT NULL,
    required_mib integer NOT NULL CHECK (required_mib > 0),
    PRIMARY KEY (worker_id, os)
);

-- The claim query's index, and the reason it is partial: the queue is a small
-- hot subset of a table that grows without bound. A full index on queue_seq
-- would be mostly cold history, and the planner choosing a sequential scan
-- here is a CORRECTNESS risk as well as a performance one -- lock acquisition
-- order stops matching queue order.
CREATE INDEX jobs_queue ON jobs (queue_seq) WHERE state = 'queued';

CREATE INDEX jobs_sha256  ON jobs (sha256);
CREATE INDEX jobs_created ON jobs (created_at DESC);
CREATE INDEX jobs_lease   ON jobs (lease_expires_at)
    WHERE lease_expires_at IS NOT NULL;
