"""Live job status, from Postgres NOTIFY to server-sent events.

Issue #36 (DRAFT-043). No Redis: migration 0002's trigger emits on every state
change, and this fans it out.

**SINGLE-TENANT, and this is a stated limit rather than an oversight.** A
subscriber may watch any job whose id it knows, because there is no owner
check anywhere yet -- `owner` and `visibility` are reserved columns that
nothing populates. Every authenticated caller can see every job, so Cloudflare
Access must only admit people who may see everything. **DRAFT-047 closes
this**; when it does, the scope check belongs here as well as in the HTTP
layer, not instead of it.
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


async def stream(job_id: UUID) -> AsyncIterator[str]:
    """SSE frames for one job, until the client disconnects.

    A keepalive comment goes out on idle so proxies -- Cloudflare included --
    do not close what looks like a dead connection. Without it the stream dies
    silently and the page freezes on a stale state, which is
    indistinguishable from a stuck analysis.
    """
    key = str(job_id)
    q: asyncio.Queue[dict] = asyncio.Queue(maxsize=_QUEUE_DEPTH)
    _subscribers.setdefault(key, set()).add(q)
    try:
        while True:
            try:
                payload = await asyncio.wait_for(q.get(), timeout=15.0)
            except TimeoutError:
                yield ": keepalive\n\n"
                continue
            yield f"data: {json.dumps(payload)}\n\n"
    finally:
        watchers = _subscribers.get(key)
        if watchers is not None:
            watchers.discard(q)
            if not watchers:
                del _subscribers[key]
