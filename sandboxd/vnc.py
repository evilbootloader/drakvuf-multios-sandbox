"""Bridging a clone's console to the platform. sandboxd's half of DRAFT-056.

Design and threat model: `docs/architecture/live-console.md`.

**Dom0 dials out.** DRAFT-056's diagram had the platform connecting to Dom0,
which would give the machine that runs malware an inbound listener and break
the deploy runbook's step 5 -- the check the draft itself says must still pass
during a session. So the direction is reversed: `sandboxd` learns a session was
requested from its heartbeat response, opens a WebSocket to the platform, and
bridges it to the clone's console on loopback.

Nothing here listens. `vnclisten` stays `127.0.0.1` in all five `misc/*.cfg`
and the console is reachable only from Dom0 itself.
"""

from __future__ import annotations

import asyncio
import logging
import re
import threading

log = logging.getLogger("sandboxd.vnc")

# QEMU's VNC display numbers map to 5900 + N. A clone's port is assigned by Xen
# at restore time and is not predictable from the domain id, so it has to be
# read rather than computed.
VNC_PORT_BASE = 5900

# Generous: the console is a diagnostic path, and a slow answer is better than
# a session that fails to open because `xl` was busy.
QUERY_TIMEOUT = 30.0

# One read, one write. Large enough not to fragment a framebuffer update into
# hundreds of WebSocket frames, small enough that a stalled peer does not hold
# a megabyte per session.
CHUNK = 64 * 1024

# The control channel, carried in TEXT frames. Data is always BINARY, so RFB
# bytes can never be read as a control message and no framing has to be parsed
# to tell them apart.
PEER_ATTACHED = "peer-attached"
PEER_GONE = "peer-gone"


class ConsoleUnavailable(RuntimeError):
    """No console to bridge. Not a failure of the analysis.

    The trace continues regardless -- DRAFT-056 makes the console an observer
    of the run, never a participant in its lifecycle.
    """


def resolve_vnc_port(runner, domid: int, domain: str) -> int:
    """Find the port QEMU is serving this clone's console on.

    > **UNVERIFIED ON DOM0.** Both readings below are *Candidate* per
    > CLAUDE.md and neither has been run against a real clone. The first Dom0
    > session that opens a console must confirm which works and record it;
    > until then this function is untested against anything real.

    Two sources, tried in order:

    1. `xenstore-read /local/domain/<domid>/console/vnc-port` -- the port
       directly, written by the device model when it binds.
    2. `xl list -l <domain>` -- the JSON dump, which carries a `vfb`/`vnc`
       stanza. Slower and more to parse, so it is the fallback.

    Ordered that way because xenstore holds what QEMU actually bound, where
    the domain config holds what was *asked for* -- and with `vncunused` those
    differ whenever the requested port was taken.
    """
    result = runner.run(
        ["xenstore-read", f"/local/domain/{domid}/console/vnc-port"],
        timeout=QUERY_TIMEOUT, what="xenstore-read vnc-port",
    )
    if result.ok:
        text = result.stdout.strip()
        if text.isdigit():
            return int(text)
        log.warning("xenstore returned %r for the vnc port, not a number", text)

    result = runner.run(["xl", "list", "-l", domain], timeout=QUERY_TIMEOUT,
                        what="xl list -l")
    if result.ok:
        # Deliberately a regex over the dump rather than a JSON parse: the
        # shape of `xl list -l` differs across Xen versions, and this needs one
        # number rather than a model of the whole domain.
        m = re.search(r'"vnclisten"\s*:\s*"[^"]*:(\d+)"', result.stdout)
        if m:
            return int(m.group(1))
        m = re.search(r'"vncdisplay"\s*:\s*(\d+)', result.stdout)
        if m:
            return VNC_PORT_BASE + int(m.group(1))

    raise ConsoleUnavailable(
        f"could not find a VNC port for {domain!r} (domid {domid}). Both "
        f"readings are Candidate and unverified on Dom0 -- see "
        f"docs/architecture/live-console.md §2.2."
    )


async def bridge(ws, host: str, port: int, stop=None) -> None:
    """Move bytes between an open WebSocket and the clone's console.

    Symmetrical with the platform's `console.pump`, and for the same reason:
    it does not know what RFB is. Two directions, no parsing, and either side
    closing ends both.

    **The TCP connection to the console is opened only once a viewer has
    attached**, not when the WebSocket is dialled. `sandboxd` dials at the
    start of the trace so the relay is ready, but the browser may arrive a
    minute later -- and RFB has the SERVER speak first. Connecting early sends
    a ProtocolVersion banner to nobody and then waits, which QEMU eventually
    gives up on: the session died about forty seconds in with no explanation
    (Dom0 2026-08-26, F10).

    It also means no socket is held into a malware VM's console while nobody
    is watching, which is what `live-console.md` §4.1b was uneasy about.

    The platform signals a viewer with a TEXT frame; the byte stream is
    BINARY. That split is the whole control channel -- no framing to parse,
    and RFB data can never be mistaken for a control message because RFB is
    carried in binary frames and nothing else is.
    """
    reader = writer = None
    viewer_left = False

    async def wait_for_viewer():
        """Read frames until the platform says a viewer has attached.

        Anything binary arriving before that is protocol from a peer that
        should not exist yet, and is refused rather than forwarded.
        """
        while True:
            frame = await ws.recv()
            if isinstance(frame, str):
                if frame == PEER_ATTACHED:
                    return
                log.warning("unknown control frame %r; ignoring", frame[:40])
                continue
            raise ConsoleUnavailable(
                "received console data before a viewer attached"
            )

    async def to_console():
        nonlocal viewer_left
        while True:
            frame = await ws.recv()
            if isinstance(frame, str):
                # Control, not data. A viewer leaving ends this VIEWING, not
                # the relay -- recorded so the loop below can tell "the
                # operator closed the tab" from "the platform went away", which
                # look identical from here and mean opposite things.
                if frame == PEER_GONE:
                    viewer_left = True
                    return
                continue
            if not frame:
                return
            writer.write(frame)
            await writer.drain()

    async def to_platform():
        while True:
            data = await reader.read(CHUNK)
            if not data:
                return
            await ws.send(data)

    async def watch_stop():
        while stop is not None and not stop.is_set():
            await asyncio.sleep(0.2)

    async def first_of(named):
        """Run the named coroutines; return the names of those that finished.

        The FIRST to finish ends the group -- a half-open bridge would leave a
        socket pointed at a malware VM's console with nothing reading it.

        **Exceptions are raised, not swallowed.** Both pumps used to sit inside
        `except Exception: pass`, so a bridge that died on its first read logged
        "session ended" and nothing else -- the code destroyed the evidence
        needed to diagnose it, which is how F10 stayed a guess.
        """
        tasks = [asyncio.create_task(coro, name=name) for name, coro in named]
        done, pending = await asyncio.wait(
            tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            if task.exception() is not None:
                raise task.exception()
        return {task.get_name() for task in done}

    def stop_watch():
        """The stop watcher, for whichever wait is about to run.

        A function rather than a value because each `asyncio.wait` needs its
        own coroutine object: the first one is cancelled when a viewer arrives,
        and a cancelled coroutine cannot be awaited again.
        """
        return [("stop", watch_stop())] if stop is not None else []

    try:
        # **One iteration per VIEWER, not one per analysis.**
        #
        # Leaving the job page used to end the relay for good: `to_console`
        # returned on PEER_GONE, this function returned, and `ConsoleSession`
        # dials exactly once -- so re-opening a still-running analysis waited
        # out the platform's pair timeout for a peer that no longer existed.
        # Looping here is what makes coming back work.
        #
        # **A NEW TCP connection each time, which is the point rather than an
        # implementation detail.** RFB state lives in the connection: the
        # handshake happens once and framebuffer updates are meaningless
        # without it. Handing a second viewer the existing socket mid-stream
        # would feed noVNC updates for a session it never negotiated. Closing
        # and reconnecting gives each viewer its own handshake, and costs
        # nothing because the connection is already opened per viewer (F10).
        while True:
            # **The stop flag is watched from the FIRST await, not from after a
            # viewer has attached.** `wait_for_viewer` blocks on `ws.recv()`
            # with no timeout, and sandboxd dials for every trace whether or not
            # anyone opens the panel -- so waiting here unguarded meant
            # `ConsoleSession.stop()` set a flag nothing was reading, timed out
            # its 5s join, and then dropped the only reference to a thread still
            # blocked in this call. One leaked thread and one open WebSocket per
            # unviewed analysis, for the life of the daemon.
            if "viewer" not in await first_of(
                    [("viewer", wait_for_viewer())] + stop_watch()):
                log.info("console for %s:%d stopped before a viewer arrived",
                         host, port)
                return

            viewer_left = False
            reader, writer = await asyncio.open_connection(host, port)
            log.info("console bridged to %s:%d", host, port)
            try:
                await first_of([("to_console", to_console()),
                                ("to_platform", to_platform())] + stop_watch())
            finally:
                # Closed on every exit from this viewing, so the next viewer
                # opens a fresh one and no socket is held into a malware VM's
                # console while nobody is watching -- the property
                # `live-console.md` §4.1b was uneasy about, preserved now that
                # there can be more than one viewing per analysis.
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception as exc:
                        log.debug("console socket close: %s", exc)
                    reader = writer = None

            if not viewer_left:
                # The platform's socket closed, the console socket closed, or
                # the trace is stopping. Nothing left to wait for -- only a
                # departing VIEWER is worth going round again for.
                return
            log.info("viewer left the console for %s:%d; waiting for another",
                     host, port)
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception as exc:
                log.debug("console socket close: %s", exc)
        log.info("console session for %s:%d ended", host, port)


class ConsoleSession:
    """One console session, run alongside a trace.

    Started when a heartbeat says one was requested, and stopped when the
    trace ends -- which is what keeps a session scoped to a job that is
    executing, with no orphaned relay to reap.

    **`websockets`, not `httpx-ws`.** httpx-ws would reuse the existing httpx
    client, so the SSL context with Dom0's client certificate would carry for
    free -- but it does not implement the protocol, it adapts `wsproto` onto
    httpx. That is two libraries where one will do, one of them pre-1.0, on the
    path between the internet and the machine running malware. `websockets`
    takes the same `SSLContext` object directly, so the advantage disappears,
    and it is already what the platform's uvicorn uses to accept the browser's
    end -- one implementation on both sides rather than two.
    """

    def __init__(self, api_base: str, token: str, job_id: str,
                 host: str = "127.0.0.1", ssl_context=None,
                 worker_id: str = ""):
        self._base = api_base.rstrip("/")
        self._token = token
        self._job_id = job_id
        self._host = host
        self._ssl = ssl_context
        self._worker_id = worker_id
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def url(self) -> str:
        scheme = "wss" if self._base.startswith("https") else "ws"
        rest = self._base.split("://", 1)[1]
        return f"{scheme}://{rest}/api/v1/worker/jobs/{self._job_id}/console"

    def headers(self) -> dict:
        # This worker's own credential, which the rest of the channel uses
        # too. The relay does not get a separate one: it is the same door on
        # the same LAN.
        #
        # **No `X-Worker-Id` since DRAFT-061.** The platform resolves the
        # worker id from this token's hash, then checks it against the job's
        # `lease_owner` before pairing the socket -- so what stops one host
        # attaching to another host's executing job is now the credential
        # itself rather than a header anyone could have typed.
        return {"Authorization": f"Bearer {self._token}"}

    # -- running alongside a synchronous trace ------------------------------

    def start(self, port: int) -> None:
        """Dial out and bridge, on a thread of its own.

        A thread with its own event loop because the stage machine is
        synchronous -- `drakvuf` is one blocking call -- and the console has to
        live for the whole of it. Nothing is shared with the analysis but the
        stop flag, so a console that fails cannot affect the trace.
        """
        if self._thread is not None:
            raise RuntimeError("this session has already been started")
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, args=(port,), daemon=True,
            name=f"console-{self._job_id[:8]}")
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """End the session. Called when the trace ends, on every path.

        DRAFT-056 scopes a session to a job that is executing; one left open
        past the trace is a socket pointed at a domain being destroyed.
        """
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def _run(self, port: int) -> None:
        try:
            asyncio.run(self._session(port))
        except Exception:
            # A console failure must never touch the analysis. It is an
            # observer of the run, not a participant in its lifecycle.
            log.exception("console session for job %s ended in an error",
                          self._job_id)

    async def _session(self, port: int) -> None:
        from websockets.asyncio.client import connect

        kwargs = {"additional_headers": self.headers(), "open_timeout": 30}
        if self._ssl is not None:
            # Passed through to create_connection. The SAME context object
            # `client_tls.ssl_context()` builds, carrying Dom0's client
            # certificate -- not a second derivation of it.
            kwargs["ssl"] = self._ssl

        async with connect(self.url, **kwargs) as ws:
            log.info("console dialled out for job %s", self._job_id)
            await bridge(ws, self._host, port, stop=self._stop)
