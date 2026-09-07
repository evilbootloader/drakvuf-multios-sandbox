"""The periodic sweep, and the two mechanisms that did not run without it.

Issue #36. Both of these were implemented, documented, and never invoked --
`jobs.reap` had a test and no call site. These assert the sweep actually
reaches them, which is the part that was missing.
"""

from __future__ import annotations

import uuid

import pytest
from conftest import enqueue

from sandbox_platform import jobs, maintenance
from sandbox_platform.config import settings


def _job(conn, *, state: str, age: str = "0 seconds") -> uuid.UUID:
    return conn.execute(
        """
        INSERT INTO jobs (target_os, submitted_filename, state, created_at, owner)
        VALUES ('ubuntu', 'x.bin', %s, now() - %s::interval,
                'fixture-owner@example.test')
        RETURNING id
        """,
        (state, age),
    ).fetchone()[0]


def _state(conn, job_id):
    return conn.execute(
        "SELECT state, failure_reason FROM jobs WHERE id = %s", (job_id,)
    ).fetchone()


# --- abandoned submissions -------------------------------------------------

def test_a_submission_that_never_uploaded_is_abandoned(conn):
    """The gap found on the deployment 2026-08-23.

    A job whose upload never happened stayed in `received` permanently. With
    no authentication on the browser routes, that is a table anyone reachable
    can grow for free.
    """
    grace = settings.upload_ttl + settings.abandon_margin
    stale = _job(conn, state="received", age=f"{grace + 60} seconds")

    assert jobs.abandon(conn, grace_seconds=grace) == [stale]
    assert _state(conn, stale) == ("rejected", "upload_not_completed")


def test_a_recent_submission_is_left_alone(conn):
    """The margin is the point: a client uploading at the edge of its policy
    window must not be swept out from under itself mid-request."""
    grace = settings.upload_ttl + settings.abandon_margin
    fresh = _job(conn, state="received", age=f"{grace - 60} seconds")

    assert jobs.abandon(conn, grace_seconds=grace) == []
    assert _state(conn, fresh)[0] == "received"


@pytest.mark.parametrize("state", ["queued", "executing", "completed", "failed"])
def test_abandon_touches_only_received(conn, state):
    """A job past `received` has an object in the store and belongs to the
    queue or a worker. Sweeping one on age alone would delete live work."""
    job = _job(conn, state=state, age="30 days")

    assert jobs.abandon(conn, grace_seconds=60) == []
    assert _state(conn, job)[0] == state


# --- the sweep itself ------------------------------------------------------

def test_the_sweep_reaps_expired_leases(conn, client, worker_headers):
    """`jobs.reap` existed, was tested, and had no call site.

    A worker that died mid-analysis left its job in `executing` with an
    expired lease forever -- never interrupted, never retried, and still
    counted against capacity in every later claim.
    """
    enqueue(conn, "ubuntu", 2198)
    lease = client.post(
        "/api/v1/worker/claim",
        json={"worker_id": "w1", "free_mib": 99999,
              "free_vlans": 4, "free_slots": 4},
        headers=worker_headers,
    ).json()
    assert lease["status"] == "leased"

    conn.execute(
        "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
        "WHERE id = %s",
        (lease["job_id"],),
    )
    conn.commit()

    reaped, _ = maintenance.sweep()

    assert uuid.UUID(lease["job_id"]) in reaped
    assert _state(conn, lease["job_id"]) == ("interrupted", "lease_expired")


def test_the_sweep_is_idempotent(conn, client):
    """Both statements are UPDATE ... WHERE, so a second pass -- or a second
    instance -- duplicates work rather than corrupting it."""
    grace = settings.upload_ttl + settings.abandon_margin
    stale = _job(conn, state="received", age=f"{grace + 60} seconds")
    conn.commit()

    first_reaped, first_abandoned = maintenance.sweep()
    second_reaped, second_abandoned = maintenance.sweep()

    assert uuid.UUID(str(stale)) in [uuid.UUID(str(i)) for i in first_abandoned]
    assert second_abandoned == []
    assert second_reaped == first_reaped == []