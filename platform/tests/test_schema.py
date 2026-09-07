"""Schema invariants that prose alone cannot hold.

Issue #35 (DRAFT-042).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PIPELINE_DOC = REPO_ROOT / "docs" / "architecture" / "analysis-pipeline.md"

# The state machine, as analysis-pipeline.md specifies it. Duplicated here on
# purpose: the point of this file is to catch the three copies drifting, and
# a test that imports its expectation from one of the copies it checks is
# checking nothing.
CANONICAL_STATES = {
    "received", "admitted", "queued", "cloning", "preparing", "executing",
    "collecting", "cleaning", "completed",
    "rejected", "cancelled", "failed", "interrupted",
}


def test_state_check_matches_the_state_machine(conn):
    """The CHECK constraint and the design document must agree.

    They are separately maintained and there is no mechanism keeping them
    together except this test.
    """
    with conn.cursor() as cur:
        cur.execute("""
            SELECT pg_get_constraintdef(oid)
              FROM pg_constraint
             WHERE conname = 'jobs_state_check'
        """)
        definition = cur.fetchone()[0]

    in_check = set(re.findall(r"'([a-z_]+)'::text", definition))
    assert in_check == CANONICAL_STATES


def test_every_state_appears_in_the_design_document():
    """A state the database accepts but the document never mentions is a
    state nobody designed."""
    doc = PIPELINE_DOC.read_text()
    missing = sorted(s for s in CANONICAL_STATES if s not in doc)
    assert not missing, f"states absent from {PIPELINE_DOC.name}: {missing}"


def test_target_os_enum_is_closed(conn):
    """Issue #3's closed set, enforced by the database rather than documented.

    Widening this to free text reopens a decision taken deliberately, and the
    OS token is the only untrusted routing input in the system.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT unnest(enum_range(NULL::target_os))::text")
        assert {r[0] for r in cur.fetchall()} == {"ubuntu", "android", "windows"}


def test_claim_uses_the_partial_index_not_a_sequential_scan(conn):
    """A sequential scan here is a CORRECTNESS risk, not only a slow one.

    The claim query depends on FOR UPDATE SKIP LOCKED visiting rows in
    queue_seq order, which is what makes "the head of the queue" well
    defined. A sequential scan visits them in heap order, so the job that
    gets locked stops being the oldest -- head-of-line reservation would then
    reserve for an arbitrary job.

    Needs enough rows for the planner to make a realistic choice; on a
    handful it correctly prefers a scan and the test would prove nothing.
    """
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO jobs (target_os, submitted_filename, required_mib, state,
                              owner)
            SELECT 'ubuntu', 'bulk-' || g || '.bin', 2198, 'queued',
                   'fixture-owner@example.test'
              FROM generate_series(1, 5000) AS g
        """)
        cur.execute("ANALYZE jobs")
        cur.execute("""
            EXPLAIN SELECT id FROM jobs
             WHERE state = 'queued' AND NOT cancel_requested
             ORDER BY queue_seq
             LIMIT 1
        """)
        plan = "\n".join(r[0] for r in cur.fetchall())

    assert "jobs_queue" in plan, f"partial index not used:\n{plan}"
    assert "Seq Scan" not in plan, f"sequential scan on the queue:\n{plan}"


def test_migrations_are_recorded_by_filename(conn):
    """schema_migrations keys on filename, with the digest as a tripwire.

    Keying on the digest instead would let an edited migration look brand new
    and be applied twice -- disarming the check it exists for. Asked and
    answered 2026-08-22; asserted here so the answer survives.
    """
    with conn.cursor() as cur:
        cur.execute("""
            SELECT a.attname
              FROM pg_index i
              JOIN pg_attribute a
                ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
             WHERE i.indrelid = 'schema_migrations'::regclass AND i.indisprimary
        """)
        assert [r[0] for r in cur.fetchall()] == ["filename"]