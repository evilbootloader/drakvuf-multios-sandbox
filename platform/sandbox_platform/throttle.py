"""Counting failed attempts, in two scopes.

DRAFT-061 decision 3. Cloudflare Access used to bounce unauthenticated requests
at the edge; once the platform issues its own credentials, every
credential-stuffing attempt reaches FastAPI and argon2 runs on this DomU. These
are the two things standing in front of that.

**Two mechanisms, and neither substitutes for the other:**

`rate_limit`, per bucket per window
    The DoS guard. Runs BEFORE any hashing, counts attempts from a source
    regardless of which account they name, and is the only one of the two that
    can see an attack on addresses that do not exist.

`tenant_credentials.failed_attempts` / `locked_until`, per account
    The credential-stuffing guard. A distributed attack rotates addresses to
    stay under any per-source window, so the only thing that sees it is the
    account being attacked from everywhere at once.

**Bucket keys carry their kind**: `ip:203.0.113.5`, `email:alice@example.test`.
One table and one primary key for both, which is what lets an address that has
no account be counted exactly like one that does -- see `login_buckets`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from psycopg.rows import dict_row

from .config import settings


class Throttled(Exception):
    """Base for both refusals, so the route layer can map them together.

    **They must be indistinguishable in the response.** A caller that can tell
    "you are rate limited" from "that account is locked" has learned the account
    exists, which hands back the enumeration signal `credentials.verify_password`
    pays a full argon2 hash to withhold.
    """

    #: Seconds after which the caller may reasonably retry. Both subclasses
    #: carry one so the handler can emit `Retry-After` without knowing which
    #: it caught.
    retry_after: int = 60


class RateLimited(Throttled):
    """Too many attempts from this bucket in the current window."""


class AccountLocked(Throttled):
    """This account is locked out after repeated failures."""


def login_buckets(src_ip: str | None, email: str) -> list[str]:
    """The buckets one login attempt counts against.

    **Two, and the second is what closes an enumeration hole.** Counting only
    by source address leaves this divergence: guesses at a real account
    eventually lock and return 429, while guesses at an address that does not
    exist have nothing to increment and return 401 forever. An attacker does not
    need to read the error text -- they watch which addresses eventually change
    behaviour.

    Bucketing on the submitted address as well means a nonexistent account
    accumulates a counter exactly like a real one and hits the same limit at the
    same point, so the two paths stay identical over time as well as per
    request.

    `src_ip` may be None where no trusted header is configured and the socket
    peer is not meaningful; the address bucket still applies.
    """
    buckets = [f"email:{email.lower()}"]
    if src_ip:
        buckets.append(f"ip:{src_ip}")
    return buckets


def enforce_limit(conn, bucket_key: str) -> None:
    """Count one attempt against `bucket_key`, refusing past the limit.

    **One UPSERT, not a SELECT then an INSERT.** Two requests arriving together
    would both miss the read, both insert, and one would hit the primary key --
    so the naive form turns a limiter into a 500 under exactly the load it
    exists for.

    Windows are fixed rather than sliding: `_current_window` puts every attempt
    in the same window into one row, which is what gives the upsert a stable
    conflict target. A sliding window would need a row per attempt and a count
    over a range -- more storage and more work for a bound that does not need to
    be that precise.
    """
    window = _current_window()
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO rate_limit (window_start, bucket_key)
            VALUES (%s, %s)
            ON CONFLICT (window_start, bucket_key)
            DO UPDATE SET count = rate_limit.count + 1
            RETURNING count
            """,
            (window, bucket_key),
        )
        count = cur.fetchone()["count"]

    if count > settings.attempts_per_window:
        raise RateLimited(f"too many attempts for {bucket_key}")


def _current_window() -> datetime:
    """The start of the window this moment falls in.

    Truncated to a multiple of the configured length from the epoch, so every
    caller agrees on where a window begins without coordinating.

    **From the epoch, and it used to be from the hour** -- `floored.minute %
    minutes`, which restarts the count at every `:00`. With a length that does
    not divide 60 that makes the last window of every hour short, and a short
    window is a free counter reset on a schedule an attacker can read off a
    clock. Measured at WINDOW_LENGTH_MINUTES=7: `:00 -> 10:00`, `:55 -> 10:49`,
    `:56 -> 10:56`, `:59 -> 10:56` -- so the 10:56 window is four minutes long
    and anyone who has spent their attempts by 10:58 gets a fresh allowance at
    11:00 rather than at 11:03.

    Harmless at the default of 5 ONLY because 5 divides 60, which is also why
    this survived: every value anyone had tried (1, 5, 10, 15, 30) divides an
    hour and agrees with epoch truncation exactly. 7, 8, 45 and 90 do not, and
    nothing in `config.py` refuses them.

    Seconds since the epoch rather than calendar arithmetic because that is the
    only clock with no boundaries in it for the truncation to restart against --
    no hour, no day, no DST. The result is still an aware UTC datetime, which is
    what `rate_limit.window_start` (timestamptz) and the upsert's conflict
    target want.
    """
    length = max(1, settings.window_length_minutes) * 60
    now = int(datetime.now(UTC).timestamp())
    return datetime.fromtimestamp(now - now % length, UTC)


def assert_not_locked(conn, owner: str) -> None:
    """Refuse if this account is inside a lockout.

    Returns quietly when there is no credentials row at all: an identity that
    has never set a password cannot be locked, and raising here would tell a
    caller the difference between "no such account" and "account exists".
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT locked_until FROM tenant_credentials WHERE owner = %s",
            (owner,),
        )
        row = cur.fetchone()

    # No row, or a lockout that has already passed. `locked_until` is a
    # timestamp rather than a flag precisely so that it clears itself and
    # nothing has to run to unlock an account.
    if row is None or row["locked_until"] is None:
        return
    if row["locked_until"] > datetime.now(UTC):
        raise AccountLocked("account is locked")


def record_failure(conn, owner: str | None) -> None:
    """Count a failed attempt against an account, locking it past the threshold.

    `owner` may be None -- the address did not resolve to an identity -- and
    that is a no-op here on purpose. There is no row to count against, and
    creating one would both invent an account and tell a later query that an
    address had been guessed at. The per-address bucket in `login_buckets` is
    what covers that case, and it is why this can afford to do nothing.

    **The counter decays**, which is the difference between a lockout and a
    slowly accumulating denial of service against a legitimate user. Without it
    five typos spread over a year lock the account on the fifth.
    """
    if owner is None:
        return

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE tenant_credentials
               SET failed_attempts =
                       CASE WHEN last_failed_at IS NULL
                             OR last_failed_at < now() - %s
                            THEN 1
                            ELSE failed_attempts + 1
                       END,
                   last_failed_at = now()
             WHERE owner = %s
            """,
            (timedelta(minutes=settings.decay_window_minutes), owner),
        )
        # Separate statement, and `>=` rather than `>`: the threshold is the
        # number of failures that locks the account, so at LOCKOUT_THRESHOLD=5
        # the fifth failure locks rather than the sixth.
        cur.execute(
            """
            UPDATE tenant_credentials
               SET locked_until = now() + %s
             WHERE owner = %s AND failed_attempts >= %s
            """,
            (
                timedelta(minutes=settings.lockout_duration_minutes),
                owner,
                settings.lockout_threshold,
            ),
        )


def record_success(conn, owner: str) -> None:
    """Clear the failure state after a successful login.

    `locked_until` is cleared too. Reaching here means the password was correct,
    so any lockout still on the row has been satisfied by the only thing that
    should lift it -- and leaving it set would lock out the person who just
    proved who they are.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE tenant_credentials
               SET failed_attempts = 0,
                   last_failed_at = NULL,
                   locked_until = NULL
             WHERE owner = %s
            """,
            (owner,),
        )


def sweep_expired_windows(conn) -> int:
    """Delete rate-limit windows that can no longer be reached.

    Called from `maintenance._loop`, which already owns the periodic database
    work. Nothing reads a closed window, so these rows are pure growth -- one
    per bucket per window, and a credential-stuffing run mints one per address
    it tries.

    The horizon is one window back, which keeps the window immediately before
    this one: a request in flight when the clock crossed the boundary still has
    its row, and a limiter that forgets the window it just left is a limiter
    with a hole at every boundary. That arithmetic is only exact now that
    `_current_window` truncates from the epoch -- while it truncated within the
    hour, windows were not uniformly `window_length_minutes` apart and
    subtracting one length landed short of the previous window's start. It erred
    toward keeping rows, so the bug was invisible here.
    """
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM rate_limit WHERE window_start < %s",
            (_current_window() - timedelta(minutes=settings.window_length_minutes),),
        )
        return cur.rowcount