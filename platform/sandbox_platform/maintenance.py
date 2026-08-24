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

**In the application rather than cron** because both need the connection pool
that the lifespan already owns, and because a cron entry is a second place to
look for why the queue is behaving oddly.

Both statements are `UPDATE ... WHERE`, so they are idempotent and safe to run
concurrently -- a second instance would duplicate work, not corrupt it.
"""

from __future__ import annotations

import asyncio
import logging

from . import jobs
from .config import settings
from .db import connection

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