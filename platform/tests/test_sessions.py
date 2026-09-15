"""Refresh-token rotation, and what happens when one is replayed.

Against a REAL Postgres, for the reason `conftest` gives about the queue tests:
`SELECT ... FOR UPDATE` and the row-locking that makes concurrent rotation safe
have no substitute. A mock would assert that the code calls what it calls.
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from conftest import DSN, identity_id
from psycopg.rows import dict_row

from sandbox_platform import credentials, sessions


@pytest.fixture
def owner(conn):
    """A tenant id to hang sessions off, UNIQUE to this test.

    `refresh_tokens` is not in the `conn` fixture's TRUNCATE and neither is
    `identities`, so a shared address would accumulate sessions across the whole
    session and any count assertion would be measuring what ran before it. A
    fresh address per test makes each one independent of run order.
    """
    with conn.cursor() as cur:
        return identity_id(cur, f"sessions-{uuid.uuid4().hex[:12]}@example.test")


def _row(conn, token):
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT id, owner, replaced, revoked_at FROM refresh_tokens"
            " WHERE token_hash = %s",
            (credentials.hash_refresh_token(token),),
        )
        return cur.fetchone()


# --- issuing ----------------------------------------------------------------


def test_issuing_stores_only_the_hash(conn, owner):
    """The plaintext exists once, in the caller's hand.

    A database disclosure -- a dump, a backup, a read-only injection -- must not
    hand over live sessions, which is the same reason a password is hashed.
    """
    token = sessions.issue_refresh_token(conn, owner)

    # Scoped to THIS owner: `refresh_tokens` is not truncated between tests, so
    # an unqualified SELECT would read whichever row ran first.
    with conn.cursor() as cur:
        cur.execute("SELECT token_hash FROM refresh_tokens WHERE owner = %s",
                    (owner,))
        stored = cur.fetchone()[0]

    assert stored != token
    assert stored == credentials.hash_refresh_token(token)


def test_a_fresh_token_has_no_successor(conn, owner):
    """`replaced IS NULL` is what "this token is live" means.

    It was briefly declared `serial`, which made every row point at its own id
    and every live token look already rotated.
    """
    token = sessions.issue_refresh_token(conn, owner)
    assert _row(conn, token)["replaced"] is None


# --- rotation ---------------------------------------------------------------


def test_rotating_returns_a_new_token_and_the_owner(conn, owner):
    first = sessions.issue_refresh_token(conn, owner)
    second, got_owner = sessions.rotate_refresh_token(conn, first)

    assert second != first
    assert got_owner == owner


def test_rotating_points_the_old_token_at_the_new_one(conn, owner):
    first = sessions.issue_refresh_token(conn, owner)
    second, _ = sessions.rotate_refresh_token(conn, first)

    assert _row(conn, first)["replaced"] == _row(conn, second)["id"]
    assert _row(conn, second)["replaced"] is None


def test_a_rotated_token_cannot_be_rotated_again(conn, owner):
    """**The replay detection**, and the whole reason rotation exists.

    A refresh token that stayed valid for its lifetime would be
    indistinguishable from a copy of itself -- both work, forever, and nothing
    ever looks wrong. Rotating means the honest client always moves on, so a
    second presentation is two parties holding one secret.
    """
    first = sessions.issue_refresh_token(conn, owner)
    sessions.rotate_refresh_token(conn, first)

    with pytest.raises(sessions.TokenReused):
        sessions.rotate_refresh_token(conn, first)


def test_an_unknown_token_is_refused(conn, owner):
    with pytest.raises(sessions.UnknownRefreshToken):
        sessions.rotate_refresh_token(conn, "never-issued")


def test_a_revoked_token_is_refused_the_same_way_as_an_unknown_one(conn, owner):
    """One exception for both, deliberately.

    Distinguishing them would tell a caller probing with guessed values which of
    them had ever been real.
    """
    token = sessions.issue_refresh_token(conn, owner)
    sessions.revoke_all_for_owner(conn, owner)

    with pytest.raises(sessions.UnknownRefreshToken):
        sessions.rotate_refresh_token(conn, token)


def test_an_expired_token_is_refused(conn, owner):
    token = sessions.issue_refresh_token(conn, owner)
    conn.execute(
        "UPDATE refresh_tokens SET expires_at = %s WHERE token_hash = %s",
        (datetime.now(UTC) - timedelta(seconds=1),
         credentials.hash_refresh_token(token)),
    )
    with pytest.raises(sessions.UnknownRefreshToken):
        sessions.rotate_refresh_token(conn, token)


# --- revocation -------------------------------------------------------------


def test_revoking_a_chain_reaches_every_descendant(conn, owner):
    """**The whole chain, not just the replayed link.**

    A replay means two parties hold one secret, and nothing here can tell which
    is the legitimate one. Revoking only the presented token would, half the
    time, revoke the attacker's copy and leave the victim's session running --
    or the reverse. Ending the session is the only answer correct either way.
    """
    first = sessions.issue_refresh_token(conn, owner)
    second, _ = sessions.rotate_refresh_token(conn, first)
    third, _ = sessions.rotate_refresh_token(conn, second)

    sessions.revoke_chain(conn, _row(conn, first)["id"])

    for token in (first, second, third):
        assert _row(conn, token)["revoked_at"] is not None


def test_revoking_a_chain_leaves_other_sessions_alone(conn, owner):
    """One compromised session must not log the user out of the others.

    The recursive walk follows `replaced`, so it cannot wander into a sibling
    chain -- and this is the test that would fail if it were rewritten as
    "revoke everything for this owner".
    """
    compromised = sessions.issue_refresh_token(conn, owner)
    other = sessions.issue_refresh_token(conn, owner)

    sessions.revoke_chain(conn, _row(conn, compromised)["id"])

    assert _row(conn, compromised)["revoked_at"] is not None
    assert _row(conn, other)["revoked_at"] is None


def test_revoking_everything_for_an_owner_ends_every_session(conn, owner):
    """"Log out everywhere", and what a password change should call.

    A changed password that leaves existing sessions running has not evicted
    whoever prompted the change.
    """
    tokens = [sessions.issue_refresh_token(conn, owner) for _ in range(3)]

    assert sessions.revoke_all_for_owner(conn, owner) == 3
    for token in tokens:
        assert _row(conn, token)["revoked_at"] is not None


def test_revoking_does_not_delete_the_row(conn, owner):
    """Revoked rather than deleted, so a later replay still finds its row.

    A deleted row would make a stolen token indistinguishable from a guessed
    one, and the fact that it was once real -- the thing worth noticing -- would
    be gone.
    """
    token = sessions.issue_refresh_token(conn, owner)
    sessions.revoke_all_for_owner(conn, owner)

    assert _row(conn, token) is not None


# --- concurrency ------------------------------------------------------------


def test_two_simultaneous_rotations_of_one_token_produce_one_winner(conn, owner):
    """**What `FOR UPDATE` is for.**

    Without the row lock both callers read `replaced IS NULL`, both mint a
    successor and both succeed -- one session silently becomes two, and the
    replay detection above can never fire because neither presentation is ever
    second.

    Two real connections, because the lock is what is under test and a single
    connection cannot block against itself.
    """
    token = sessions.issue_refresh_token(conn, owner)
    results: list = []
    barrier = threading.Barrier(2)

    def rotate():
        with psycopg.connect(DSN) as c:
            barrier.wait()
            try:
                results.append(("ok", sessions.rotate_refresh_token(c, token)[0]))
                c.commit()
            except Exception as exc:
                results.append(("raised", type(exc).__name__))

    threads = [threading.Thread(target=rotate) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    outcomes = sorted(kind for kind, _ in results)
    assert outcomes == ["ok", "raised"], results