"""Refresh tokens: issuing, rotating, and noticing when one is replayed.

DRAFT-061 decision 3, and the persistent half of `credentials.py`. Split from it
so that module stays testable without a database -- hashing and signing are pure
functions, and rotation is inherently transactional.

**Rotation on every use is what makes a stolen token detectable.** A refresh
token that stayed valid for its whole life would be indistinguishable from a
copy of itself: both work, forever, and nothing ever looks wrong. Rotating means
the legitimate client always moves on to the successor, so a second presentation
of a spent token is not a retry -- it is two parties holding one secret.

Every function here takes an open `conn` rather than opening its own. The caller
is a route that already has one, and rotation has to be one transaction: the
`SELECT ... FOR UPDATE`, the insert of the successor and the update of the
predecessor cannot be allowed to interleave with a second refresh.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from psycopg.rows import dict_row

from .config import settings
from .credentials import CredentialsError, hash_refresh_token, new_refresh_token


class TokenReused(CredentialsError):
    """A refresh token was presented after it had already been rotated.

    Not a retry. The legitimate client holds the successor, so a second
    presentation of the spent token means the value leaked and someone else has
    it. Which of the two holders is the attacker cannot be known from here,
    which is why the response is to revoke the whole chain rather than to refuse
    this one request.
    """


class UnknownRefreshToken(CredentialsError):
    """No live row for this token: never issued, expired, or already revoked.

    Deliberately one exception for all three. Telling a caller which of them it
    was would say whether a guessed token had ever existed.
    """


def issue_refresh_token(conn, owner: str) -> str:
    """Mint a refresh token for `owner` and return the plaintext.

    The plaintext is returned and never stored; only its hash reaches the
    database. This is the only moment it exists in this process.
    """
    token, token_hash = new_refresh_token()
    expires_at = datetime.now(UTC) + timedelta(days=settings.refresh_token_ttl_days)
    conn.execute(
        """
        INSERT INTO refresh_tokens (token_hash, owner, expires_at)
        VALUES (%s, %s, %s)
        """,
        (token_hash, owner, expires_at),
    )
    return token


def rotate_refresh_token(conn, presented: str) -> tuple[str, str]:
    """Exchange a refresh token for its successor. Returns `(new token, owner)`.

    **`FOR UPDATE` is what makes this safe against itself.** Two requests
    arriving with the same token would otherwise both read `replaced IS NULL`,
    both mint a successor, and both succeed -- turning one session into two and
    making the replay detection below unreachable. The row lock serialises them,
    so the second waits and then sees the `replaced` the first wrote.

    Three outcomes, and the middle one is the point of the whole design:

      live            rotate it, return the successor
      already rotated raise `TokenReused` -- the caller revokes the chain
      anything else   raise `UnknownRefreshToken`

    Expiry and revocation are checked here rather than by the caller so a route
    cannot forget one of them.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, owner, replaced, revoked_at,
                   expires_at <= now() AS expired
              FROM refresh_tokens
             WHERE token_hash = %s
               FOR UPDATE
            """,
            (hash_refresh_token(presented),),
        )
        row = cur.fetchone()

        # No row at all is indistinguishable from a revoked or expired one, on
        # purpose: a caller probing with guessed tokens learns nothing about
        # which of them were ever real.
        if row is None or row["revoked_at"] is not None:
            raise UnknownRefreshToken("no live refresh token for this value")

        # **Checked against the database's clock, not this process's**, which
        # this comment claimed while the code compared against
        # `datetime.now(UTC)` -- the process's. The comparison is now `expires_at
        # <= now()`, evaluated by Postgres inside the same statement that takes
        # the row lock, so the claim is true rather than aspirational.
        #
        # It matters because the two clocks can disagree and a token's lifetime
        # should not depend on which host asked. The row is WRITTEN with a
        # Python-computed `expires_at` (`issue_refresh_token` below), so reading
        # it back through the database's clock is what keeps a single skewed
        # API host from either honouring a token past its expiry or retiring one
        # early. `maintenance._DEAD_TOKEN_GRACE` absorbs the same skew on the
        # deletion side.
        if row["expired"]:
            raise UnknownRefreshToken("refresh token has expired")

        if row["replaced"] is not None:
            # The successor was already issued, so the honest client is using
            # it. This presentation is a replay.
            raise TokenReused(str(row["id"]))

        token, token_hash = new_refresh_token()
        expires_at = datetime.now(UTC) + timedelta(
            days=settings.refresh_token_ttl_days
        )
        cur.execute(
            """
            INSERT INTO refresh_tokens (token_hash, owner, expires_at)
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (token_hash, row["owner"], expires_at),
        )
        successor = cur.fetchone()["id"]

        # Written AFTER the successor exists, so the foreign key always has
        # something to point at and a crash between the two leaves the old token
        # live rather than pointing at nothing.
        cur.execute(
            "UPDATE refresh_tokens SET replaced = %s WHERE id = %s",
            (successor, row["id"]),
        )

    return token, str(row["owner"])


def revoke_chain(conn, token_id: int) -> int:
    """Revoke a token and every token descended from it. Returns how many.

    **The whole chain, not just the replayed token.** A replay means two parties
    hold one secret and there is no way to tell from here which is the
    legitimate one -- so revoking only the presented token would, half the time,
    revoke the attacker's copy and leave the victim's session running, or the
    reverse. Ending the session and making someone log in again is the only
    answer that is correct either way.

    Walks `replaced` forward recursively, so it does not matter which link in
    the chain was replayed.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            WITH RECURSIVE chain AS (
                SELECT id, replaced FROM refresh_tokens WHERE id = %s
                UNION ALL
                SELECT r.id, r.replaced
                  FROM refresh_tokens r
                  JOIN chain c ON r.id = c.replaced
            )
            UPDATE refresh_tokens
               SET revoked_at = now()
             WHERE id IN (SELECT id FROM chain)
               AND revoked_at IS NULL
            """,
            (token_id,),
        )
        return cur.rowcount


def revoke_all_for_owner(conn, owner: str) -> int:
    """Revoke every live refresh token for one identity. Returns how many.

    This is "log out everywhere", and it is also what a password change should
    call -- a changed password that leaves existing sessions running has not
    actually evicted whoever prompted the change.

    **Rows are revoked rather than deleted, and NOT so that a later presentation
    is recognised as revoked** -- `rotate_refresh_token` raises
    `UnknownRefreshToken` for a revoked row and a missing one alike, deliberately,
    so a caller probing with guessed tokens learns nothing from either. Nobody on
    the other side of this can tell. What keeping the row buys is entirely on
    this side: `revoke_chain` can still walk `replaced` through it, and an audit
    can still tell "the session timed out" from "someone logged out, or we
    detected a replay", which is the question `revoked_at` exists to answer.

    `maintenance.sweep` deletes them a grace period after `expires_at` passes --
    true since 2026-09-14, and false for as long as this docstring had claimed
    it. See `maintenance._DEAD_TOKEN_GRACE` for how long the grace is and why.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE refresh_tokens
               SET revoked_at = now()
             WHERE owner = %s AND revoked_at IS NULL
            """,
            (owner,),
        )
        return cur.rowcount