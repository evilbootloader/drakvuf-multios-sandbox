"""The periodic sweep, and the mechanisms that did not run without it.

Issue #36. Each of these was implemented, documented, and never invoked --
`jobs.reap` had a test and no call site, and the two token tables had two
comments naming `maintenance` as their reaper while nothing here touched them.
These assert the sweep actually reaches them, which is the part that was
missing.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from conftest import enqueue, identity_id, owner_id

from sandbox_platform import jobs, maintenance, sessions, telegram
from sandbox_platform.config import settings
from sandbox_platform.credentials import hash_refresh_token


def _job(conn, *, state: str, age: str = "0 seconds") -> uuid.UUID:
    return conn.execute(
        """
        INSERT INTO jobs (target_os, submitted_filename, state, created_at, owner)
        VALUES ('ubuntu', 'x.bin', %s, now() - %s::interval, %s)
        RETURNING id
        """,
        (state, age, owner_id(conn)),
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
        json={"free_mib": 99999,
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

    reaped = maintenance.sweep().reaped

    assert uuid.UUID(lease["job_id"]) in reaped
    assert _state(conn, lease["job_id"]) == ("interrupted", "lease_expired")


def test_the_sweep_is_idempotent(conn, client):
    """Every statement is `UPDATE ... WHERE` or `DELETE ... WHERE`, so a second
    pass -- or a second instance -- duplicates work rather than corrupting it.

    Named attributes rather than positional unpacking, which is the reason
    `SweepResult` exists: this test read `first_reaped, first_abandoned =
    sweep()` until the token sweeps were added, and a two-tuple that grows is a
    call site that has to be found again every time.
    """
    grace = settings.upload_ttl + settings.abandon_margin
    stale = _job(conn, state="received", age=f"{grace + 60} seconds")
    conn.commit()

    first = maintenance.sweep()
    second = maintenance.sweep()

    assert uuid.UUID(str(stale)) in [uuid.UUID(str(i)) for i in first.abandoned]
    assert second.abandoned == []
    assert second.reaped == first.reaped == []


# --- dead token rows -------------------------------------------------------
#
# **Every assertion here is scoped to an owner the test just created.**
# `refresh_tokens`, `verification_tokens` and `identities` are none of them in
# the `conn` fixture's TRUNCATE, so a bare `SELECT count(*)` would be measuring
# whatever ran before it -- the same trap `test_sessions.py` records at its
# `owner` fixture. The returned counts are asserted as `>= 1` for the same
# reason: another test's leftovers legitimately go in the same pass.

#: Comfortably past `_DEAD_TOKEN_GRACE`, so a row backdated by this is dead
#: whichever clock the sweep reads. The grace itself is read from the module
#: rather than copied, so changing it there does not silently make these tests
#: assert nothing.
_WELL_PAST_GRACE = maintenance._DEAD_TOKEN_GRACE + timedelta(hours=1)


def _identity(conn) -> str:
    with conn.cursor() as cur:
        return identity_id(cur, f"maint-{uuid.uuid4().hex[:12]}@example.test")


def _expire_refresh_token(conn, token: str, *, ago: timedelta) -> None:
    conn.execute(
        "UPDATE refresh_tokens SET expires_at = %s WHERE token_hash = %s",
        (datetime.now(UTC) - ago, hash_refresh_token(token)),
    )


def _expire_code(conn, code: str, *, ago: timedelta) -> None:
    conn.execute(
        "UPDATE verification_tokens SET expires_at = %s WHERE token_hash = %s",
        (datetime.now(UTC) - ago, hash_refresh_token(code)),
    )


def _live_refresh_hashes(conn, owner: str) -> set[str]:
    with conn.cursor() as cur:
        cur.execute("SELECT token_hash FROM refresh_tokens WHERE owner = %s",
                    (owner,))
        return {r[0] for r in cur.fetchall()}


def _code_count(conn, owner: str) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM verification_tokens WHERE owner = %s",
                    (owner,))
        return cur.fetchone()[0]


def test_an_expired_refresh_token_is_swept(conn, client):
    """The table grew forever, and on FAILED authentication as well as
    successful.

    `sessions.revoke_all_for_owner` said "`maintenance` is where the expired
    ones are eventually swept" and `maintenance.sweep` touched no token table at
    all. Past `expires_at` the row has nothing left to say -- rotation raises
    `UnknownRefreshToken` for expired, revoked and never-issued alike -- so it
    can go.
    """
    owner = _identity(conn)
    dead = sessions.issue_refresh_token(conn, owner)
    live = sessions.issue_refresh_token(conn, owner)
    _expire_refresh_token(conn, dead, ago=_WELL_PAST_GRACE)

    result = maintenance.sweep()

    assert result.refresh_tokens >= 1
    assert _live_refresh_hashes(conn, owner) == {hash_refresh_token(live)}


def test_a_refresh_token_inside_the_grace_is_left_alone(conn, client):
    """**The grace is the point, not an accident of rounding.**

    `expires_at` is written by one clock and compared by another -- Python in
    `sessions.issue_refresh_token`, SQL in `telegram.mint_code` -- and a row
    survives its own expiry long enough for somebody who hears about a problem
    the next morning to still have it to look at.
    """
    owner = _identity(conn)
    just_lapsed = sessions.issue_refresh_token(conn, owner)
    _expire_refresh_token(conn, just_lapsed, ago=timedelta(minutes=1))

    maintenance.sweep()

    assert _live_refresh_hashes(conn, owner) == {
        hash_refresh_token(just_lapsed)
    }


def test_a_rotated_chain_drains_without_a_foreign_key_violation(conn, client):
    """**One link per pass, and that is deliberate rather than a bug.**

    `replaced` is a self-referencing foreign key, so a successor that is still
    pointed at cannot be deleted. The sweep therefore deletes only rows nothing
    points at, and the chain drains from its root. Without that guard the DELETE
    raises the first time an operator LOWERS `REFRESH_TOKEN_TTL_DAYS` -- and
    because `db.connection` rolls the whole block back on error, that would take
    the lease reap down with it on every pass, forever.
    """
    owner = _identity(conn)
    first = sessions.issue_refresh_token(conn, owner)
    second, _ = sessions.rotate_refresh_token(conn, first)
    for token in (first, second):
        _expire_refresh_token(conn, token, ago=_WELL_PAST_GRACE)

    # The successor is still referenced by its predecessor, so this pass may
    # only take the root.
    maintenance.sweep()
    assert _live_refresh_hashes(conn, owner) == {hash_refresh_token(second)}

    # With the root gone, nothing points at the successor any more.
    maintenance.sweep()
    assert _live_refresh_hashes(conn, owner) == set()


def test_an_expired_verification_token_is_swept(conn, client):
    """The claim migration 0009 makes about its own column.

    `verification_tokens.used_at` says "`maintenance._loop` is where the
    genuinely expired ones go", which was false when it was written. The
    migration is applied and checksum-frozen, so the code is what had to move.
    """
    owner = _identity(conn)
    dead = telegram.mint_code(conn, owner, "password_reset")
    telegram.mint_code(conn, owner, "password_reset")
    _expire_code(conn, dead, ago=_WELL_PAST_GRACE)

    result = maintenance.sweep()

    assert result.verification_tokens >= 1
    assert _code_count(conn, owner) == 1


def test_a_verification_token_inside_the_grace_is_left_alone(conn, client):
    """A 15-minute credential gets the same grace as a multi-day one.

    The grace is sized for somebody noticing and asking, not for the token's own
    lifetime -- see `maintenance._DEAD_TOKEN_GRACE`.
    """
    owner = _identity(conn)
    code = telegram.mint_code(conn, owner, "telegram_linking")
    _expire_code(conn, code, ago=timedelta(minutes=30))

    maintenance.sweep()

    assert _code_count(conn, owner) == 1