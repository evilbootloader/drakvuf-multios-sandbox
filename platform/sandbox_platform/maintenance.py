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

**In the application rather than cron** because both need the connection pool
that the lifespan already owns, and because a cron entry is a second place to
look for why the queue is behaving oddly.

Both statements are `UPDATE ... WHERE`, so they are idempotent and safe to run
concurrently -- a second instance would duplicate work, not corrupt it.
"""

from __future__ import annotations

import asyncio
import logging

from . import console, jobs
from .config import settings
from .db import connection
from .enums import RUNNING_STATES

log = logging.getLogger(__name__)

_task: asyncio.Task | None = None


def sweep() -> tuple[list, list]:
    """One pass. Separated from the loop so a test can call it directly."""
    with connection() as conn:
        reaped = jobs.reap(conn)
        # The grace period is the upload policy's own lifetime plus a margin,
        # so a client uploading at the very edge of its window is never swept
        # out from under itself mid-request.
        abandoned = jobs.abandon(
            conn, grace_seconds=settings.upload_ttl + settings.abandon_margin
        )
    return reaped, abandoned


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
            reaped, abandoned = await asyncio.to_thread(sweep)
        except Exception:
            # Never let one bad pass kill the loop -- a maintenance task that
            # dies silently reintroduces exactly the gap it was added to close.
            log.exception("maintenance sweep failed")
            continue
        if reaped:
            log.warning("reaped %d job(s) with expired leases: %s",
                        len(reaped), ", ".join(str(i) for i in reaped))
        if abandoned:
            log.info("abandoned %d submission(s) never uploaded", len(abandoned))

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