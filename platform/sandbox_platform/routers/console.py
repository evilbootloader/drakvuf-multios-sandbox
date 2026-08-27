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
            "SELECT state, console_requested, lease_owner FROM jobs "
            "WHERE id = %s",
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

        if side is console.Side.WORKER:
            # Tell Dom0 a viewer has arrived, so it can open the TCP
            # connection to the console NOW rather than at dial time.
            #
            # RFB has the SERVER speak first, so a connection opened before
            # anyone is watching sends its banner to nobody and waits -- which
            # QEMU gives up on. sandboxd dials at the start of the trace so the
            # relay is ready; this is what tells it the other half is real
            # (F10).
            #
            # A TEXT frame, where all data is BINARY. That split is the entire
            # control channel: nothing has to be parsed to tell them apart, and
            # RFB bytes can never be read as a control message.
            await websocket.send_text(console.PEER_ATTACHED)

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
        # **Both departures are announced, but not in the same way, because the
        # two peers are different kinds of program.**
        #
        # The WORKER leaving first is the normal case -- the trace ends and
        # sandboxd calls `console.stop()`. Until 2026-08-27 only a departing
        # browser was announced, so the viewer stayed blocked in
        # `receive_bytes()` inside `pump` (which never re-tests
        # `session.closed`) until their next mouse movement raised out of
        # `sink`. noVNC reports that as "Session lost" rather than the clean
        # "the analysis finished" message console.js exists to show.
        # `Session.detach` already promised better: "Either side leaving ends
        # the session."
        #
        # Dom0 gets a PEER_GONE text frame because sandboxd is our code and
        # reads the control channel. The browser gets a socket CLOSE, because
        # its end is noVNC: it sets `binaryType = "arraybuffer"` and speaks
        # only RFB, so a text frame is not something it can act on. A close
        # while it is `connected` is what it reads as a clean end
        # (novnc/core/rfb.js `_socketClose`), which is precisely the signal we
        # want to send.
        try:
            if side is console.Side.BROWSER and session.worker is not None:
                await session.worker.send_text(console.PEER_GONE)
            elif side is console.Side.WORKER and session.browser is not None:
                await session.browser.close(
                    status.WS_1000_NORMAL_CLOSURE, "the analysis finished")
        except Exception:  # noqa: BLE001 - the peer socket may already be gone
            log.debug("could not tell the peer that the %s side of job %s left",
                      side.value, job_id)
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

    # **The caller must hold this job's lease, not merely the worker token.**
    #
    # Every other job-scoped worker route resolves through `auth.leased_job`,
    # and worker.py's module docstring says why: "a worker reaches the jobs it
    # currently holds and nothing else". This route checked the token and the
    # state and stopped there, so any token holder -- a second registered
    # analysis host, or a compromised Dom0 whose blast radius is supposed to be
    # the jobs it is running -- could attach as the WORKER side of another
    # host's job and feed arbitrary RFB bytes to the operator's browser, or
    # simply occupy the session slot so the real worker was refused.
    #
    # Not `Depends(auth.leased_job)` for the same reason the token is read by
    # hand here: that dependency raises `HTTPException`, which on a WebSocket
    # surfaces as a dropped connection with no reason. The CHECK is the same
    # one -- lease_owner against X-Worker-Id -- expressed as a close code.
    worker_id = websocket.headers.get("x-worker-id", "")
    if not worker_id or row[2] != worker_id:
        # Deliberately the same message either way: a worker that guesses a job
        # id must not learn whether it exists, which is why `leased_job` returns
        # 404 rather than 403 for someone else's job.
        await websocket.close(POLICY, "no such job for this worker")
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