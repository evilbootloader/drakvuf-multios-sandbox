"""Live console sessions: pairing a browser with a clone's VNC.

DRAFT-056. Design and threat model: `docs/architecture/live-console.md`.

**The relay moves bytes and nothing else.** No RFB parsing, no framing logic,
no state beyond which job a socket belongs to. That was the property DRAFT-056
wanted from it, and v1 keeps it because view-only -- the only thing that would
have required parsing -- has no consumer until `hidsim` (DRAFT-055) exists.

## Dom0 dials out

The draft's diagram had the platform connecting to Dom0. That would give the
machine running malware an inbound listener and break the deploy runbook's
step 5, which checks the platform *cannot* reach Dom0 and which the draft
itself says must still pass during a session.

So the direction is reversed. Both sides connect **to the platform**:

    browser ──WS──> platform <──WS── sandboxd ──> 127.0.0.1:59xx
                       │                 │
                pairs by job_id    dials OUT, as it already
                                   does for /claim

`sandboxd` learns a session was requested from its **heartbeat response** --
the channel that already carries `cancel_requested`, for exactly this reason.

## What this module is not

It is not a WebSocket endpoint. Those live on the routers, so they inherit the
authentication each side already has: Cloudflare Access for the browser, mutual
TLS plus the worker token for Dom0 over the LAN. This is the pairing table they
both meet in, kept separate so it can be tested without a server.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum

# A session that nobody completes must not sit in the table forever. One
# heartbeat interval plus margin: sandboxd cannot answer faster than its next
# beat, which is the latency floor of dialling out rather than listening.
PAIR_TIMEOUT = 90.0

# Bounded so a stalled reader cannot grow memory without limit. Framebuffer
# updates are large, so this is generous -- what it prevents is unbounded
# growth, not large frames.
QUEUE_DEPTH = 64


# The control channel between the platform and sandboxd, in TEXT frames. All
# console data is BINARY, so the two can never be confused and neither side
# has to parse framing to tell them apart. Mirrored in sandboxd/vnc.py.
PEER_ATTACHED = "peer-attached"
PEER_GONE = "peer-gone"


class Side(Enum):
    BROWSER = "browser"
    WORKER = "worker"


class SessionError(RuntimeError):
    pass


class AlreadyAttached(SessionError):
    """One session, one viewer.

    DRAFT-056 scopes a session to a single viewer, and a second request is
    refused rather than queued: two people driving one mouse is not a feature,
    and silently sharing would mean an analyst's input arriving from someone
    they cannot see.
    """


@dataclass
class Session:
    """One job's console. Holds two sockets and pumps between them."""

    job_id: str
    browser: object | None = field(default=None, repr=False)
    worker: object | None = field(default=None, repr=False)
    interacted: bool = False
    _paired: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    _closed: asyncio.Event = field(default_factory=asyncio.Event, repr=False)

    @property
    def paired(self) -> bool:
        return self.browser is not None and self.worker is not None

    def attach(self, side: Side, socket: object) -> None:
        current = self.browser if side is Side.BROWSER else self.worker
        if current is not None:
            raise AlreadyAttached(
                f"job {self.job_id} already has a {side.value} attached; "
                f"a session is one viewer, and a second is refused rather "
                f"than queued"
            )
        if side is Side.BROWSER:
            self.browser = socket
        else:
            self.worker = socket
        if self.paired:
            self._paired.set()

    def detach(self, side: Side) -> None:
        """Either side leaving ends the session.

        Not just the one that left: a browser with no worker has nothing to
        show, and a worker with no browser is a socket into a malware VM's
        console with nobody watching it. The second is the one that matters.
        """
        if side is Side.BROWSER:
            self.browser = None
        else:
            self.worker = None
        self.close()

    def close(self) -> None:
        self._closed.set()
        self._paired.set()      # release anyone waiting to pair

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    async def wait_paired(self, timeout: float = PAIR_TIMEOUT) -> bool:
        """Wait for the other side. False if it never came.

        Whichever side arrives first waits: the browser may open before
        sandboxd has seen its heartbeat, or sandboxd may dial out just as the
        operator closes the tab.
        """
        try:
            await asyncio.wait_for(self._paired.wait(), timeout)
        except (asyncio.TimeoutError, TimeoutError):
            return False
        return self.paired and not self.closed


class Registry:
    """Every live session on this platform, by job id.

    In-process and deliberately not in Postgres: a session is a pair of open
    sockets on THIS process, and a row describing one held by a process that
    has since restarted would be a lie that outlives the thing it describes.
    """

    def __init__(self):
        self._sessions: dict[str, Session] = {}
        self._lock = asyncio.Lock()

    async def open(self, job_id: str, side: Side, socket: object) -> Session:
        async with self._lock:
            session = self._sessions.get(job_id)
            if session is None or session.closed:
                session = Session(job_id=job_id)
                self._sessions[job_id] = session
            session.attach(side, socket)
            return session

    async def close(self, job_id: str, side: Side) -> None:
        async with self._lock:
            session = self._sessions.get(job_id)
            if session is None:
                return
            session.detach(side)
            if session.browser is None and session.worker is None:
                self._sessions.pop(job_id, None)

    async def end(self, job_id: str) -> None:
        """Terminate a session because the JOB ended.

        Called from teardown: DRAFT-056 scopes a session to a job that is
        executing, and leaving one open past the trace would leave a socket
        pointed at a domain that no longer exists.
        """
        async with self._lock:
            session = self._sessions.pop(job_id, None)
        if session is not None:
            session.close()

    def get(self, job_id: str) -> Session | None:
        return self._sessions.get(job_id)

    @property
    def live(self) -> list[str]:
        return [j for j, s in self._sessions.items() if not s.closed]


# One per process. The endpoints on the routers share it.
registry = Registry()


async def pump(source, sink, session: Session, *, mark_input: bool = False):
    """Move bytes one way until either side stops.

    **This is the whole relay.** It does not know what RFB is. It reads a
    frame, writes a frame, and stops when the session closes -- which is the
    property that keeps the code between the internet and a malware host small
    enough to reason about.

    `mark_input` records that a human sent something, on the browser→clone
    direction only. That flag is a correctness requirement rather than
    bookkeeping: a report from an interactive session is not comparable to an
    automated one, because a person made choices that changed what happened.
    Two reports that look alike must not describe different experiments.
    """
    try:
        while not session.closed:
            data = await source()
            if data is None:
                break
            if mark_input and data:
                session.interacted = True
            await sink(data)
    finally:
        session.close()