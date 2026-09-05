"""Live job status, from Postgres NOTIFY to server-sent events.

Issue #36 (DRAFT-043). No Redis: migration 0002's trigger emits on every state
change, and this fans it out.

**The subscription is scoped, but not here.** Since #40 (DRAFT-047) the
`/jobs/{id}/events` route refuses a job the caller may not see, BEFORE calling
`stream()` -- it has to be before, because once the `StreamingResponse` holds
this generator the status line is already 200 and a refusal from inside would
arrive as an empty event stream, which a client cannot tell from a job that is
simply not changing.

**So `stream()` itself checks nothing, and a second caller must do its own
check.** This module previously argued the scope belonged here as well as in
the HTTP layer rather than instead of it. That argument still holds and is not
yet acted on: there is exactly one caller, and it checks. Adding a second one
without a scope check would reopen the hole with no test failing, since the
tests in `test_tenancy.py` drive the route rather than this function.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncIterator
from uuid import UUID

import psycopg

from .config import settings

log = logging.getLogger(__name__)

# Bounded, deliberately: a browser that stops reading must not be able to grow
# this process's memory. A subscriber that falls behind loses events rather
# than being buffered forever, and the UI's polling fallback covers the gap
# (DRAFT-045).
_QUEUE_DEPTH = 32

# Keyed by job id, so a payload reaches ONLY the queues watching that job.
# Filtering after enqueue would let one busy job's events push another
# subscriber's out of its bounded queue -- cross-subscriber interference
# through nothing but volume.
_subscribers: dict[str, set[asyncio.Queue[dict]]] = {}
_listener: asyncio.Task | None = None


async def _listen() -> None:
    """Hold one connection open on the `jobs` channel and fan out.

    **One listener for the whole process, not one per browser tab.** LISTEN
    occupies a connection for its entire lifetime, so a per-tab listener would
    hold pool slots open indefinitely and a handful of tabs would exhaust it.
    This connection is outside the pool for the same reason.

    One channel, filtered by subscription -- NOT a channel per job. Postgres
    channel names are identifiers, so per-job channels would be unbounded and
    each subscription would need its own LISTEN.
    """
    while True:
        try:
            conn = await psycopg.AsyncConnection.connect(
                settings.database_url, autocommit=True
            )
            async with conn:
                await conn.execute("LISTEN jobs")
                log.info("listening for job events")
                async for note in conn.notifies():
                    try:
                        payload = json.loads(note.payload)
                    except json.JSONDecodeError:
                        continue
                    for q in list(_subscribers.get(payload.get("id", ""), ())):
                        try:
                            q.put_nowait(payload)
                        except asyncio.QueueFull:
                            # Slow reader. Dropping is the right failure: the
                            # alternative is unbounded growth driven by a
                            # client that stopped reading.
                            pass
        except asyncio.CancelledError:
            raise
        except Exception:
            # A dropped connection must not end the stream for everyone
            # permanently. Reconnect; subscribers see a gap, which the UI's
            # polling fallback covers.
            log.exception("job event listener failed; reconnecting")
            await asyncio.sleep(1.0)


def start() -> None:
    global _listener
    if _listener is None or _listener.done():
        _listener = asyncio.create_task(_listen())


async def stop() -> None:
    global _listener
    if _listener is not None:
        _listener.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await _listener
        _listener = None


def _snapshot(job_id: UUID) -> dict | None:
    """The job's current state, shaped like a NOTIFY payload."""
    from .db import connection

    with connection() as conn:
        row = conn.execute(
            "SELECT id, state FROM jobs WHERE id = %s", (job_id,)
        ).fetchone()
    return {"id": str(row[0]), "state": row[1]} if row else None


async def stream(job_id: UUID) -> AsyncIterator[str]:
    """SSE frames for one job: its current state, then every change.

    **The first frame is a snapshot, and without it this stream loses races it
    cannot win.** NOTIFY only reaches subscribers that already exist, so a
    client that connects after the job finished would wait forever for an event
    that already happened. That is not hypothetical -- `submit.py` subscribes
    *after* `/uploaded` returns, and a worker long-polling on /claim can take a
    job from queued to completed inside that gap, because a fake or fast worker
    walks the state machine at HTTP round-trip speed.

    Reproduced 2026-08-24 by inserting 3s between admission and subscription:
    the job reached `completed` and `--watch` then hung for its whole budget.
    On the LAN the gap was sub-millisecond and the race was won by luck; #37's
    tunnel put Cloudflare, an Access check and a TLS handshake in it and the
    luck ran out.

    **Order matters here.** The queue is registered BEFORE the snapshot is
    read, so a change landing between the two is queued rather than dropped.
    The cost is a possible duplicate frame, which is harmless: these are states,
    not increments, and a client applying the same state twice is unchanged.

    The stream then ENDS on a terminal state rather than keeping a connection
    open on a job that can never change again.

    A keepalive comment goes out on idle so proxies -- Cloudflare included --
    do not close what looks like a dead connection. Without it the stream dies
    silently and the page freezes on a stale state, which is indistinguishable
    from a stuck analysis.
    """
    from .enums import TERMINAL_STATES, JobState

    key = str(job_id)
    q: asyncio.Queue[dict] = asyncio.Queue(maxsize=_QUEUE_DEPTH)
    _subscribers.setdefault(key, set()).add(q)
    try:
        # A blocking read on the pooled connection, in a thread, so one small
        # SELECT does not stall the event loop for every other subscriber.
        snapshot = await asyncio.to_thread(_snapshot, job_id)
        if snapshot is not None:
            yield f"data: {json.dumps(snapshot)}\n\n"
            if JobState(snapshot["state"]) in TERMINAL_STATES:
                return

        while True:
            try:
                payload = await asyncio.wait_for(q.get(), timeout=15.0)
            except TimeoutError:
                yield ": keepalive\n\n"
                continue
            yield f"data: {json.dumps(payload)}\n\n"
            if payload.get("state") in {s.value for s in TERMINAL_STATES}:
                return
    finally:
        watchers = _subscribers.get(key)
        if watchers is not None:
            watchers.discard(q)
            if not watchers:
                del _subscribers[key]
