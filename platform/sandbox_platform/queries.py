"""The queue's SQL, as named constants.

Issue #35 (DRAFT-042). Design record: docs/architecture/platform.md.

Kept as SQL rather than expressed through an ORM because the claim query's
correctness lives in exactly where one condition sits, and that is not
something an ORM would let anyone read.

Every parameter is bound (%s), never formatted. Submitted filenames are
attacker-controlled -- dirwatch's admission check rejects `/` and control
characters and nothing else, so quotes, `$`, backticks and `;` all reach here.
"""

from __future__ import annotations

# --------------------------------------------------------------------------
# CLAIM -- the reason this issue exists.
#
# Read the two halves separately.
#
# The SUBQUERY picks the head of the queue and only the head: oldest
# queue_seq, not cancelled, one row.
#
# The FIT TEST -- `required_mib <= %(free_mib)s` -- sits on the OUTER UPDATE.
# So when the head does not fit, the statement matches zero rows and NO OTHER
# JOB IS CONSIDERED. That is head-of-line reservation, and it is the whole
# difference between this and the arrangement measured on 2026-08-20: 170
# consecutive admission holds, zero clones for a 6294 MiB Windows job, seven
# 2198 MiB jobs completing meanwhile.
#
# MOVING THE FIT TEST INTO THE SUBQUERY IS THE BUG. It would skip the head and
# hand out the next job that fits, which is greedy admission -- every
# individual decision correct, the aggregate starving the largest clone.
#
# FOR UPDATE SKIP LOCKED makes concurrent workers safe and does NOT undermine
# the above: a locked head is one another worker is claiming right now, so
# passing over it is correct rather than a starvation path. The lock is held
# for the transaction, which is microseconds.
#
# attempt is incremented here rather than by the caller so that a retry is
# counted even if the worker dies before reporting anything.
# --------------------------------------------------------------------------
CLAIM = """
UPDATE jobs
   SET state            = 'cloning',
       lease_owner      = %(worker_id)s,
       lease_expires_at = now() + %(lease)s::interval,
       attempt          = attempt + 1,
       queue_reason     = NULL,
       -- The billing clock (DRAFT-047 decision 8), started HERE because this
       -- is the moment a host takes the job -- everything before it is queue
       -- time, which is the platform being busy rather than work the
       -- submitter asked for.
       --
       -- Not in report_state, where it was first written: this statement sets
       -- 'cloning' itself, so a worker never REPORTS that transition and the
       -- branch waiting for it never ran. started_at stayed NULL and both
       -- charge sites raised on `updated_at - None`.
       --
       -- Needs no `WHERE started_at IS NULL` guard: this matches only a
       -- 'queued' row, and nothing returns a job to 'queued' -- a retry is a
       -- new job with a new id.
       started_at       = now()
 WHERE id = (
         SELECT id
           FROM jobs
          WHERE state = 'queued'
            AND NOT cancel_requested
          ORDER BY queue_seq
          FOR UPDATE SKIP LOCKED
          LIMIT 1
       )
   AND required_mib <= %(free_mib)s
RETURNING id, target_os, sha256, submitted_filename, required_mib,
          lease_expires_at, attempt, egress_mode, egress_exit, key_prefix
"""

# --------------------------------------------------------------------------
# RESERVATION REPORT -- why CLAIM returned nothing.
#
# Zero rows from CLAIM is ambiguous: the queue may be empty, or the head may
# not fit. This distinguishes them, and it is the difference between the API
# answering "idle" and answering "reserved", which the web UI renders as a
# job waiting rather than a job stuck.
#
# Read-only and deliberately NOT part of CLAIM's transaction: another worker
# may claim the head between the two statements. That race is harmless because
# nothing acts on this -- it is a diagnostic, not a decision.
# --------------------------------------------------------------------------
RESERVATION = """
SELECT id AS blocking_job_id, required_mib AS need_mib
  FROM jobs
 WHERE state = 'queued'
   AND NOT cancel_requested
 ORDER BY queue_seq
 LIMIT 1
"""

# --------------------------------------------------------------------------
# CANCEL, before a clone exists.
#
# One statement, terminal, nothing to tear down. This is the operation
# DRAFT-040 recorded as UNEXPRESSIBLE rather than merely unimplemented: under
# dirwatch a queued job is a file in a watch directory plus a worker spinning
# inside an admission loop, with no id to name it by and no field to set.
# --------------------------------------------------------------------------
CANCEL_QUEUED = """
UPDATE jobs
   SET state = 'cancelled'
 WHERE id = %(job_id)s
   AND state IN ('received', 'admitted', 'queued')
RETURNING id
"""

# --------------------------------------------------------------------------
# CANCEL, while running.
#
# Request only. sandboxd sees cancel_requested in its next heartbeat RESPONSE
# and tears down through cleanup.sh, passing through 'cleaning'. The heartbeat
# is the only channel because Dom0 has no inbound listener and never will --
# a push cancel would require one, which is the hardest constraint in
# platform.md.
#
# state is deliberately NOT changed here: the job is still running, and
# claiming otherwise would make the record disagree with the host.
# --------------------------------------------------------------------------
CANCEL_RUNNING = """
UPDATE jobs
   SET cancel_requested = true
 WHERE id = %(job_id)s
   AND state IN ('cloning', 'preparing', 'executing', 'collecting')
   AND NOT cancel_requested
RETURNING id
"""

# --------------------------------------------------------------------------
# REAP -- expire the BOOKKEEPING of jobs whose worker stopped reporting.
#
# This frees NOTHING on Dom0 and must not be made to. VLANs and memory are
# allocated in-process on the analysis host; the platform has no idea what a
# VLAN is. What lapses here is the record's claim to be in flight, so it stops
# occupying the queue.
#
# Marking 'interrupted' rather than requeueing is deliberate: the clone may
# still be running. sandboxd's startup reconciliation against `xl list` and
# `ip link` is what actually decides, and it is the authority.
# --------------------------------------------------------------------------
REAP = """
UPDATE jobs
   SET state          = 'interrupted',
       failure_stage  = state,
       failure_reason = 'lease_expired'
 WHERE lease_expires_at < now()
   AND state IN ('cloning', 'preparing', 'executing', 'collecting')
RETURNING id, lease_owner, failure_stage
"""

# --------------------------------------------------------------------------
# ABANDON -- submissions whose upload never happened.
#
# A job enters 'received' when the row and its presigned policy are created,
# and leaves it when /uploaded is called. If the submitter never uploads --
# closes the tab, is refused by the policy, or never existed -- the row stays
# there forever. Nothing else in this schema expires it.
#
# The clock is the UPLOAD POLICY's lifetime, not an arbitrary age. Once the
# policy has expired the submitter *cannot* complete the upload even by
# returning, so the row is provably dead rather than merely old. The margin
# above it exists so a client uploading at the very edge of its window is
# never swept out from under itself mid-request.
#
# Terminal state is 'rejected' rather than a new 'abandoned': 'rejected' is
# already what a job that did not pass admission becomes, and an upload that
# never completed never reached admission. failure_reason carries the detail.
# A new state would mean amending the CHECK, the state machine in
# docs/architecture/analysis-pipeline.md, and test_schema.py's agreement
# between them -- for a distinction the reason string already makes.
# --------------------------------------------------------------------------
ABANDON = """
UPDATE jobs
   SET state          = 'rejected',
       failure_stage  = 'received',
       failure_reason = 'upload_not_completed'
 WHERE state = 'received'
   AND created_at < now() - %(grace)s::interval
RETURNING id
"""

# --------------------------------------------------------------------------
# RECONCILE -- what sandboxd declares at startup.
#
# Any job this worker holds a lease on that is NOT in the list it sent is a
# job whose clone died with the previous process. Jobs in the list keep their
# lease and carry on.
#
# This is what makes the lease TTL safe. The TTL expires bookkeeping;
# reconciliation against the host's real state is what decides.
# --------------------------------------------------------------------------
RECONCILE = """
UPDATE jobs
   SET state          = 'interrupted',
       failure_stage  = state,
       failure_reason = 'worker_restarted'
 WHERE lease_owner = %(worker_id)s
   AND state IN ('cloning', 'preparing', 'executing', 'collecting')
   AND NOT (id = ANY(%(live_job_ids)s::uuid[]))
RETURNING id, failure_stage
"""

# --------------------------------------------------------------------------
# CAPACITY -- could ANY registered host ever run a job of this size?
#
# total_mib, not free: the question is capability, not current availability.
# A job that only fails because a host is busy belongs in the queue. One that
# fails because every host is too small belongs in 'rejected', answered at
# SUBMISSION where the submitter can act on it.
#
# Without this guard such a job sits at the head forever and, because
# head-of-line blocking is working as designed, holds everything behind it --
# the silent hang this whole architecture exists to remove, reintroduced from
# the other end.
# --------------------------------------------------------------------------
CAPACITY = """
SELECT EXISTS (
    SELECT 1
      FROM worker_pipelines wp
      JOIN workers w USING (worker_id)
     WHERE wp.os = %(target_os)s
       AND wp.required_mib <= w.total_mib
) AS affordable,
(SELECT count(*) FROM workers) AS worker_count
"""

# Registration. Upsert, because a worker re-registers on every restart and its
# capacity may legitimately have changed -- a Dom0 given more RAM, or a
# misc/*.cfg retune. required_mib stays DERIVED ON DOM0 from
# misc/<os>_sandbox.cfg plus that host's own overhead; computing it here would
# recreate the two-files-free-to-disagree failure platform.env exists to
# prevent, with no loud symptom when they drift.
UPSERT_WORKER = """
INSERT INTO workers (worker_id, total_mib, total_vlans, total_slots)
VALUES (%(worker_id)s, %(total_mib)s, %(total_vlans)s, %(total_slots)s)
ON CONFLICT (worker_id) DO UPDATE
   SET total_mib    = EXCLUDED.total_mib,
       total_vlans  = EXCLUDED.total_vlans,
       total_slots  = EXCLUDED.total_slots,
       last_seen_at = now()
"""

UPSERT_PIPELINE = """
INSERT INTO worker_pipelines (worker_id, os, required_mib)
VALUES (%(worker_id)s, %(os)s, %(required_mib)s)
ON CONFLICT (worker_id, os) DO UPDATE
   SET required_mib = EXCLUDED.required_mib
"""

# --------------------------------------------------------------------------
# Egress exits (DRAFT-057)
# --------------------------------------------------------------------------

# DELETE-then-INSERT rather than upsert, and this is the one place in this file
# where that is the right shape.
#
# An exit that a host has STOPPED offering must disappear. Upserting would leave
# it behind, and a stale row here is not a cosmetic problem: it offers the
# submitter a way out the host can no longer provide, so the job is accepted,
# queued, claimed, and then refused on Dom0 after a clone has been built.
#
# The concrete case this prevents: an operator unsets SANDBOXD_ALLOW_DIRECT and
# restarts. `direct` must be gone from the UI on the next registration, not
# linger because nothing deleted it. Registration is the only writer, so the
# host's current view is authoritative by construction.
CLEAR_EGRESS = "DELETE FROM worker_egress WHERE worker_id = %(worker_id)s"

INSERT_EGRESS = """
INSERT INTO worker_egress (worker_id, name, mode, country, caveats)
VALUES (%(worker_id)s, %(name)s, %(mode)s, %(country)s, %(caveats)s)
ON CONFLICT (worker_id, name) DO UPDATE
   SET mode    = EXCLUDED.mode,
       country = EXCLUDED.country,
       caveats = EXCLUDED.caveats
"""

# What the submit form may offer: the UNION across hosts, not one host's set.
#
# Deduplicated by name because two analysis hosts configured alike both offer
# `es-vps-1`, and the submitter is choosing a destination rather than a machine.
# Which host runs the job is the queue's decision, made later.
#
# The caveats of the FIRST host to declare a name win. That is a real
# simplification and worth naming: two hosts declaring the same exit name with
# different upstream port blocks would be a misconfiguration -- the name is
# supposed to identify the way out -- and this makes the disagreement invisible
# rather than loud. Acceptable at one analysis host; revisit at two.
OFFERED_EXITS = """
SELECT DISTINCT ON (name) name, mode, country, caveats
  FROM worker_egress
 ORDER BY name, worker_id
"""

# Does ANY host offer this exit? Asked at submission, like CAPACITY, and for the
# same reason: a job nothing can run belongs in 'rejected' where the submitter
# can act on it, not at the head of a queue holding everything behind it.
EXIT_AVAILABLE = """
SELECT EXISTS (
    SELECT 1 FROM worker_egress WHERE name = %(name)s AND mode = %(mode)s
) AS available
"""