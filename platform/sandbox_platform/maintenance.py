"""Periodic bookkeeping that nothing else triggers.

Issue #36 (DRAFT-043).

Two of this schema's mechanisms only work if something calls them on a
schedule, and until this module existed nothing did:

- **The lease TTL.** `jobs.reap` was written, tested, and never invoked. A
  worker that died mid-analysis left its job in `executing` with an expired
  lease permanently -- never marked `interrupted`, never retried, and still
  counted against capacity in every later claim. The mechanism meant to
  handle a worker dying was the one that did not run.
- **Abandoned submissions.** A job whose upload never happened stays in
  `received` forever. With no authentication on the browser routes that is a
  table anyone reachable can grow for free.
- **Console sessions outliving their job.** `console.Registry.end` was written
  with a docstring saying it is "called from teardown" and had no caller at
  all. Normally a session ends when a socket closes, but a worker whose console
  thread wedges never closes its end -- `ConsoleSession.stop` joins for 5s and
  then drops the thread -- so the platform kept a session, and a socket, for a
  job that had already completed. This loop is the teardown that docstring
  meant: it runs on the event loop, which is where the registry's lock and
  events live.
- **Dead credential rows.** `sessions.revoke_all_for_owner` said "`maintenance`
  is where the expired ones are eventually swept" and `verification_tokens`'
  own column comment said "`maintenance._loop` is where the genuinely expired
  ones go" -- and neither table was touched here at all. Two tables that only
  grow, one of them fed by FAILED authentication as well as successful, with
  two comments asserting a reaper that did not exist. Same shape as the lease
  TTL above: the mechanism was described, believed, and never ran.

**In the application rather than cron** because both need the connection pool
that the lifespan already owns, and because a cron entry is a second place to
look for why the queue is behaving oddly.

The job statements are `UPDATE ... WHERE` and the token statements are
`DELETE ... WHERE`, so every one of them is idempotent and safe to run
concurrently -- a second instance would duplicate work, not corrupt it.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import NamedTuple

from . import console, jobs, throttle
from .config import settings
from .db import connection
from .enums import RUNNING_STATES

log = logging.getLogger(__name__)

_task: asyncio.Task | None = None

#: How long a token row is kept after it stops working.
#
# **Sized for the human loop rather than the credential's**, which is why one
# value covers both tables even though a refresh token lives for days
# (`refresh_token_ttl_days`, 1 by default) and a verification code for fifteen
# minutes (`telegram._CODE_TTL_MINUTES`). The grace buys no extra credential:
# past `expires_at` neither table's reader can tell a deleted row from a dead
# one -- `sessions.rotate_refresh_token` raises `UnknownRefreshToken` for
# "expired", "revoked" and "no row" alike, deliberately, and
# `telegram.redeem_code` returns None for all three. What it buys is that
# somebody who hears about a problem after the fact still has a row to look at,
# and "I was logged out overnight" and "the reset code never arrived" both
# arrive the next morning whatever the token's own lifetime was. A day covers
# a night's sleep; that is the whole of the sizing.
#
# It is also margin over a boundary that TWO clocks write. `expires_at` is
# computed in Python by `sessions.issue_refresh_token` and in SQL by
# `telegram.mint_code` (`now() + make_interval(...)`), so whichever clock this
# sweep reads, one of the two comparisons crosses a clock boundary. They are the
# same host in this deployment, which is a deployment fact and not a guarantee.
# Margin over a boundary rather than the boundary itself, the same reasoning
# `abandon_margin` records: 300s of margin over a 900s upload policy.
_DEAD_TOKEN_GRACE = timedelta(hours=24)


class SweepResult(NamedTuple):
    """What one pass did, per mechanism.

    A named tuple rather than a bare one because this is the third thing the
    sweep has grown and positional unpacking broke at every addition -- `reaped,
    abandoned = sweep()` is a silent behaviour change away from wrong rather
    than a loud one. Still a tuple, so a caller that wants all of it can still
    unpack.

    Jobs come back as id lists because `_loop` names them in its log line and an
    operator needs to know WHICH job was interrupted. Tokens come back as counts:
    the only identifier a token row has is its hash, which is a credential-shaped
    value that has no business in a log file, and a count is all the line says.
    """

    reaped: list
    abandoned: list
    refresh_tokens: int
    verification_tokens: int


def sweep() -> SweepResult:
    """One pass. Separated from the loop so a test can call it directly."""
    with connection() as conn:
        reaped = jobs.reap(conn)
        # The grace period is the upload policy's own lifetime plus a margin,
        # so a client uploading at the very edge of its window is never swept
        # out from under itself mid-request.
        abandoned = jobs.abandon(
            conn, grace_seconds=settings.upload_ttl + settings.abandon_margin
        )
        # Closed rate-limit windows are unreachable but not self-removing, and
        # a credential-stuffing run mints one row per address it tries. Swept
        # here rather than in a second loop because this one already owns the
        # periodic database work and its failure handling.
        throttle.sweep_expired_windows(conn)
        refresh, verification = _sweep_dead_tokens(conn)
    return SweepResult(reaped, abandoned, refresh, verification)


def _sweep_dead_tokens(conn) -> tuple[int, int]:
    """Delete token rows that lapsed more than `_DEAD_TOKEN_GRACE` ago.

    **Deleted rather than left, because past `expires_at` a row has nothing
    further to say.** Both tables keep dead rows on purpose while they still
    mean something -- `refresh_tokens.revoked_at` distinguishes "the session
    timed out" from "someone logged out or we detected a replay", and
    `verification_tokens.used_at` makes a second presentation ALREADY USED
    rather than unknown -- but both of those questions are answered off
    `expires_at` too. Once it passes, the row is indistinguishable from absence
    to every reader either table has.

    **Keyed on `expires_at` alone**, not on `revoked_at`/`used_at`, though a
    revoked or redeemed row is dead the moment it is written. One predicate is
    easier to reason about than two, and the cost of waiting is bounded by the
    column that bounds everything else here: fifteen minutes for a code, and for
    a refresh token no longer than the life it would have had anyway.

    The one caller that reads a row after it dies is `/auth/logout`, which looks
    the owner up by hash and then revokes that owner's other sessions. Past the
    grace it finds nothing and revokes nothing -- which needs a hand-built client
    to reach at all, because `_set_session_cookies` gives the refresh cookie a
    `max_age` equal to the token's own TTL, so a browser has dropped it long
    before this sweep can.
    """
    horizon = datetime.now(UTC) - _DEAD_TOKEN_GRACE
    with conn.cursor() as cur:
        # **`NOT EXISTS` is what keeps this from wedging the whole sweep.**
        # `replaced` is a self-referencing foreign key, so deleting a token that
        # a predecessor still points at raises -- and because `db.connection`
        # rolls the whole block back on error, that failure would take the lease
        # reap and the abandon sweep with it, every pass, forever, logged as one
        # line from `_loop`'s `except`. It cannot happen while every token has
        # the same TTL, since a successor is issued later and therefore expires
        # later; it happens the first time an operator LOWERS
        # `REFRESH_TOKEN_TTL_DAYS`, after which a short-lived successor outlives
        # its long-lived predecessor in this table.
        #
        # So only rows nothing points at are deleted, and a chain drains from
        # its root one link per pass. `NOT EXISTS` rather than `id NOT IN
        # (SELECT replaced ...)`: `replaced` is NULL for every live token, and
        # `NOT IN` over a set containing NULL is never true -- that form would
        # delete nothing at all and look like it worked.
        cur.execute(
            """
            DELETE FROM refresh_tokens r
             WHERE r.expires_at < %s
               AND NOT EXISTS (SELECT 1 FROM refresh_tokens p
                                WHERE p.replaced = r.id)
            """,
            (horizon,),
        )
        refresh = cur.rowcount

        # No such guard here: nothing references `verification_tokens`, and its
        # own `owner` points outward at `identities`.
        cur.execute(
            "DELETE FROM verification_tokens WHERE expires_at < %s",
            (horizon,),
        )
        return refresh, cur.rowcount


def stale_sessions(job_ids: list[str]) -> list[str]:
    """Which of these jobs no longer have any business holding a console.

    Phrased as "no longer has a live clone" rather than "is terminal", so a job
    id the registry holds that has no row at all -- deleted, or never existed
    -- is also reported. A session outside that window is a socket pointed at a
    domain being torn down.

    **Widened from `state = 'executing'` on 2026-09-05**, in step with the two
    console routes. Left as it was, this loop would have reaped a session the
    moment the job moved on to `collecting` -- and refused to let one exist
    during `cloning` or `preparing` at all -- which is precisely the window the
    widening exists to open. A reaper narrower than the thing it reaps is how a
    feature ends up working only in tests.

    Separated from the loop so a test can call it directly, like `sweep`.
    """
    if not job_ids:
        return []
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id::text FROM jobs "
            "WHERE id = ANY(%s::uuid[]) AND state = ANY(%s)",
            (job_ids, [s.value for s in RUNNING_STATES]),
        )
        live = {row[0] for row in cur.fetchall()}
    return [job_id for job_id in job_ids if job_id not in live]


async def _loop() -> None:
    while True:
        await asyncio.sleep(settings.maintenance_interval)
        try:
            # Blocking DB work off the event loop: this runs in the same
            # process as the request handlers, and a slow sweep must not stall
            # a long-polling /worker/claim.
            result = await asyncio.to_thread(sweep)
        except Exception:
            # Never let one bad pass kill the loop -- a maintenance task that
            # dies silently reintroduces exactly the gap it was added to close.
            log.exception("maintenance sweep failed")
            continue
        if result.reaped:
            log.warning("reaped %d job(s) with expired leases: %s",
                        len(result.reaped),
                        ", ".join(str(i) for i in result.reaped))
        if result.abandoned:
            log.info("abandoned %d submission(s) never uploaded",
                     len(result.abandoned))
        # **DEBUG, where the two lines above are WARNING and INFO**, and the
        # difference is what the line tells an operator. A reaped lease means a
        # worker died; an abandoned submission means someone asked for an upload
        # ticket and never used it. A token passing its expiry is neither -- it
        # is the design working, on every pass, for as long as anyone uses the
        # platform. At INFO this would be a line every `maintenance_interval`
        # seconds forever, which is how the two lines that DO mean something
        # stop being read. Returned rather than merely counted so a test can
        # assert on it without reading the log.
        if result.refresh_tokens or result.verification_tokens:
            log.debug("swept %d dead refresh token(s) and %d verification "
                      "token(s)", result.refresh_tokens,
                      result.verification_tokens)

        # Ended here on the event loop, where the registry's lock and its
        # Events belong -- the request handlers that would otherwise notice are
        # sync functions running in a threadpool, and setting an asyncio.Event
        # from another thread is not safe.
        try:
            live = console.registry.live
            for job_id in await asyncio.to_thread(stale_sessions, live):
                log.info("ending the console session for job %s: it is no "
                         "longer executing", job_id)
                await console.registry.end(job_id)
        except Exception:
            log.exception("could not reap stale console sessions")


def start() -> None:
    global _task
    if settings.maintenance_interval <= 0:
        log.warning("maintenance disabled: leases will not be reaped")
        return
    _task = asyncio.create_task(_loop())


async def stop() -> None:
    global _task
    if _task is None:
        return
    _task.cancel()
    try:
        await _task
    except asyncio.CancelledError:
        pass
    _task = None