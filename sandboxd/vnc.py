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

from .proc import CommandError

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


async def bridge(ws, host: str, port: int) -> None:
    """Move bytes between an open WebSocket and the clone's console.

    Symmetrical with the platform's `console.pump`, and for the same reason:
    it does not know what RFB is. Two directions, no parsing, and either side
    closing ends both.
    """
    reader, writer = await asyncio.open_connection(host, port)
    log.info("console bridged to %s:%d", host, port)

    async def to_console():
        try:
            while True:
                data = await ws.recv()
                if data is None:
                    break
                writer.write(data if isinstance(data, bytes) else data.encode())
                await writer.drain()
        except Exception:
            pass

    async def to_platform():
        try:
            while True:
                data = await reader.read(CHUNK)
                if not data:
                    break
                await ws.send(data)
        except Exception:
            pass

    a = asyncio.create_task(to_console())
    b = asyncio.create_task(to_platform())
    try:
        # The FIRST to finish ends the session. A half-open bridge would leave
        # a socket pointed at a malware VM's console with nothing reading it.
        done, pending = await asyncio.wait(
            {a, b}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        log.info("console session for %s:%d ended", host, port)


class ConsoleSession:
    """One console session, run alongside a trace.

    Started when a heartbeat says one was requested, and stopped when the
    trace ends -- which is what keeps a session scoped to a job that is
    executing, with no orphaned relay to reap.
    """

    def __init__(self, api_base: str, token: str, job_id: str,
                 host: str = "127.0.0.1"):
        self._base = api_base.rstrip("/")
        self._token = token
        self._job_id = job_id
        self._host = host
        self._task: asyncio.Task | None = None

    @property
    def url(self) -> str:
        scheme = "wss" if self._base.startswith("https") else "ws"
        rest = self._base.split("://", 1)[1]
        return f"{scheme}://{rest}/api/v1/worker/jobs/{self._job_id}/console"

    def headers(self) -> dict:
        # The same worker token the rest of the channel uses. The relay does
        # not get a credential of its own: it is the same door on the same
        # LAN, already gated by the client certificate at the TLS layer.
        return {"Authorization": f"Bearer {self._token}"}
