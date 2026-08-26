"""The two ends of a live console session.

DRAFT-056. Design and threat model: `docs/architecture/live-console.md`.

Two WebSocket endpoints on two different routers, because the two sides
authenticate differently and conflating them would leave a reader unable to
tell which failure removes which protection:

    browser  ──> /api/v1/jobs/{id}/console          Cloudflare Access
    sandboxd ──> /api/v1/worker/jobs/{id}/console   LAN, mTLS, worker token

Losing Access exposes the console to the internet. Losing the client
certificate exposes it to the LAN. They are not the same incident.

**Both sides connect TO the platform.** DRAFT-056's diagram had the platform
dialling Dom0, which would give the machine that runs malware an inbound
listener and break the deploy runbook's step 5 -- the check the draft itself
says must still pass during a session. Reversed here; `vnclisten` stays on
Dom0's loopback in all five `misc/*.cfg`.
"""

from __future__ import annotations

import logging
from uuid import UUID

from fastapi import (
    APIRouter, HTTPException, WebSocket, WebSocketDisconnect, status,
)

from .. import auth, console
from ..config import settings
from ..db import connection
from ..enums import JobState

log = logging.getLogger(__name__)

# Close codes. 1008 is "policy violation", which is the honest one for every
# refusal here: the request was well-formed and not allowed.
POLICY = status.WS_1008_POLICY_VIOLATION
TRY_LATER = status.WS_1013_TRY_AGAIN_LATER

browser_router = APIRouter(prefix="/api/v1/jobs", tags=["console"])
worker_router = APIRouter(prefix="/api/v1/worker/jobs", tags=["console"])


def _job_row(job_id: UUID):
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT state, console_requested FROM jobs WHERE id = %s",
            (job_id,),
        )
        return cur.fetchone()


def _set_console_requested(job_id: UUID, wanted: bool) -> None:
    with connection() as conn:
        conn.execute(
            "UPDATE jobs SET console_requested = %s WHERE id = %s",
            (wanted, job_id),
        )


def _mark_interacted(job_id: UUID) -> None:
    """Record that a human drove this run.

    A correctness requirement rather than bookkeeping: a report from an
    interactive session is not comparable to an automated one, because a person
    made choices that changed what happened. Two reports that look alike must
    not describe different experiments.
    """
    with connection() as conn:
        conn.execute("UPDATE jobs SET interacted = true WHERE id = %s", (job_id,))


async def _relay(websocket: WebSocket, job_id: UUID, side: console.Side):
    """Attach one side, wait for the other, then move bytes until it ends."""
    try:
        session = await console.registry.open(str(job_id), side, websocket)
    except console.AlreadyAttached:
        await websocket.close(POLICY, "a session is already open for this job")
        return

    # The two sides wait differently, because they arrive for different
    # reasons. sandboxd dials at the START of a trace and holds the socket for
    # its duration, so a short cap here would have it give up before the
    # operator opened the panel -- which is most of the trace. The browser
    # arrives on a human's click and should be told promptly if nobody is
    # there.
    #
    # The worker's wait is bounded by the trace: it closes its own end during
    # teardown, on every path.
    timeout = (settings.console_pair_timeout if side is console.Side.BROWSER
               else None)
    try:
        if not await session.wait_paired(timeout=timeout):
            await websocket.close(
                TRY_LATER,
                "the other end never arrived"
                if side is console.Side.BROWSER
                else "no viewer",
            )
            return

        other = (session.worker if side is console.Side.BROWSER
                 else session.browser)

        async def source():
            try:
                return await websocket.receive_bytes()
            except (WebSocketDisconnect, RuntimeError):
                return None

        async def sink(data: bytes):
            await other.send_bytes(data)

        # `mark_input` on the browser direction only. Watching changes nothing
        # about the experiment, so it must not mark the run as interactive.
        await console.pump(source, sink, session,
                           mark_input=side is console.Side.BROWSER)

        if side is console.Side.BROWSER and session.interacted:
            _mark_interacted(job_id)
    finally:
        await console.registry.close(str(job_id), side)
        if side is console.Side.BROWSER:
            # The request is satisfied or abandoned either way; leaving it set
            # would have sandboxd dial out again on its next beat for a viewer
            # that has gone.
            _set_console_requested(job_id, False)


@browser_router.websocket("/{job_id}/console")
async def browser_console(websocket: WebSocket, job_id: UUID):
    """The operator's end. Authenticated by Cloudflare Access.

    `access_identity` is called directly rather than attached as a dependency,
    because it raises `HTTPException` -- which has no meaning on a WebSocket
    and would surface as a dropped connection with no reason. Calling it here
    reuses the SAME verification (JWKS fetch, audience, issuer) and turns a
    refusal into a close code a client can read. A second implementation of
    Access verification is exactly what must not exist.
    """
    try:
        auth.access_identity(websocket.headers.get("cf-access-jwt-assertion"))
    except HTTPException as exc:
        await websocket.close(POLICY, str(exc.detail))
        return

    if not settings.console_enabled:
        await websocket.close(POLICY, "the live console is disabled")
        return

    row = _job_row(job_id)
    if row is None:
        await websocket.close(POLICY, "no such job")
        return

    state = JobState(row[0])
    if state is not JobState.EXECUTING:
        # DRAFT-056 scopes a session to a job that is EXECUTING: not before the
        # clone exists, not after teardown. Outside that window there is
        # nothing to show and nothing to drive.
        await websocket.close(
            POLICY, f"job is {state.value}; a console needs an executing job")
        return

    # Asking is what tells sandboxd to dial out -- it learns on its next
    # heartbeat. Set before accepting, so the worker can be on its way while
    # the browser waits.
    _set_console_requested(job_id, True)
    await websocket.accept()
    await _relay(websocket, job_id, console.Side.BROWSER)


@worker_router.websocket("/{job_id}/console")
async def worker_console(websocket: WebSocket, job_id: UUID):
    """Dom0's end. Authenticated by the worker token over the LAN.

    Not `Depends(require_worker_token)`: that dependency reads an HTTP
    Authorization header, and a browser's WebSocket API cannot set headers --
    but `sandboxd` is not a browser and does send them, so the token is read
    here directly from the handshake request. Doing it explicitly also keeps
    the two authentications visibly separate, which section 4.4 of the threat
    model argues for.
    """
    if not settings.console_enabled:
        await websocket.close(POLICY, "the live console is disabled")
        return

    token = websocket.headers.get("authorization", "")
    expected = f"Bearer {settings.worker_token}"
    # Constant-time: this is a bearer token on a route that reaches a malware
    # VM's console, and `==` on secrets leaks length and prefix through timing.
    import hmac
    if not hmac.compare_digest(token, expected):
        await websocket.close(POLICY, "bad worker token")
        return

    row = _job_row(job_id)
    if row is None or JobState(row[0]) is not JobState.EXECUTING:
        await websocket.close(POLICY, "job is not executing")
        return
    # **The "nobody asked" refusal is gone, deliberately.** It required
    # `console_requested` to be set before a worker could dial, which made the
    # feature impossible: the panel only appears once the job is `executing`,
    # so the request could never arrive before the trace began (F8).
    #
    # sandboxd now dials for every executing job when the console is enabled on
    # that host. What still bounds this is unchanged and is where the argument
    # now rests: CONSOLE_ENABLED is off by default on both sides, the job must
    # be EXECUTING, the worker token is required, and the socket is a relay to
    # a browser that must still pass Cloudflare Access.

    await websocket.accept()
    await _relay(websocket, job_id, console.Side.WORKER)