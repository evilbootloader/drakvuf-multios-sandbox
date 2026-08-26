"""Live console pairing: DRAFT-056.

The relay itself is four lines of pump; what needs testing is the pairing and
the lifetime rules, because those are what keep a socket pointed at a malware
VM's console from outliving the analysis.

Design and threat model: docs/architecture/live-console.md
"""

from __future__ import annotations

import asyncio

import pytest

from sandbox_platform.console import (
    AlreadyAttached, Registry, Session, Side, pump,
)

# anyio's pytest plugin rather than pytest-asyncio: anyio is already a FastAPI
# dependency, so this adds nothing to a container whose security argument rests
# on staying small.
pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def reg():
    return Registry()


# --- pairing ----------------------------------------------------------------

async def test_either_side_may_arrive_first(reg):
    """The browser may open before sandboxd has seen its heartbeat, or
    sandboxd may dial out just as the operator closes the tab."""
    s1 = await reg.open("job-1", Side.WORKER, object())
    assert not s1.paired

    s2 = await reg.open("job-1", Side.BROWSER, object())
    assert s2 is s1
    assert s1.paired


async def test_a_second_viewer_is_refused_not_queued(reg):
    """One session, one viewer. Two people driving one mouse is not a feature,
    and silently sharing means input arriving from someone you cannot see."""
    await reg.open("job-1", Side.BROWSER, object())

    with pytest.raises(AlreadyAttached, match="one viewer"):
        await reg.open("job-1", Side.BROWSER, object())


async def test_a_second_worker_is_refused(reg):
    await reg.open("job-1", Side.WORKER, object())
    with pytest.raises(AlreadyAttached):
        await reg.open("job-1", Side.WORKER, object())


async def test_sessions_for_different_jobs_are_independent(reg):
    a = await reg.open("job-a", Side.BROWSER, object())
    b = await reg.open("job-b", Side.BROWSER, object())

    assert a is not b
    assert sorted(reg.live) == ["job-a", "job-b"]


async def test_waiting_for_a_partner_times_out(reg):
    """A session nobody completes must not sit in the table forever."""
    session = await reg.open("job-1", Side.BROWSER, object())

    assert await session.wait_paired(timeout=0.05) is False


async def test_waiting_returns_true_once_paired(reg):
    session = await reg.open("job-1", Side.BROWSER, object())

    async def partner():
        await asyncio.sleep(0.01)
        await reg.open("job-1", Side.WORKER, object())

    task = asyncio.create_task(partner())
    assert await session.wait_paired(timeout=2.0) is True
    await task


# --- lifetime ---------------------------------------------------------------

async def test_either_side_leaving_ends_the_session(reg):
    """Not just the one that left. A browser with no worker has nothing to
    show; a worker with no browser is a socket into a malware VM's console
    with nobody watching it -- and the second is the one that matters."""
    session = await reg.open("job-1", Side.BROWSER, object())
    await reg.open("job-1", Side.WORKER, object())

    await reg.close("job-1", Side.BROWSER)

    assert session.closed


async def test_the_job_ending_ends_the_session(reg):
    """DRAFT-056 scopes a session to a job that is EXECUTING. One left open
    past the trace is a socket pointed at a domain that no longer exists."""
    session = await reg.open("job-1", Side.BROWSER, object())
    await reg.open("job-1", Side.WORKER, object())

    await reg.end("job-1")

    assert session.closed
    assert reg.live == []


async def test_ending_a_job_with_no_session_is_not_an_error(reg):
    """Teardown runs on every path, including the ones where nobody ever
    opened a console. Making it fatal turns tidy-up into a new failure."""
    await reg.end("job-nobody-watched")


async def test_a_closed_session_is_replaced_not_reused(reg):
    """A dropped session is reopened, not resumed -- DRAFT-056 puts
    reconnection out of scope."""
    first = await reg.open("job-1", Side.BROWSER, object())
    await reg.close("job-1", Side.BROWSER)

    second = await reg.open("job-1", Side.BROWSER, object())

    assert second is not first
    assert not second.closed


async def test_waiting_wakes_when_the_session_closes(reg):
    """A side waiting to pair must not block for the full timeout after the
    job has already ended."""
    session = await reg.open("job-1", Side.BROWSER, object())

    async def ender():
        await asyncio.sleep(0.01)
        await reg.end("job-1")

    task = asyncio.create_task(ender())
    assert await session.wait_paired(timeout=5.0) is False
    await task


# --- the relay itself -------------------------------------------------------

async def test_the_pump_moves_bytes_without_interpreting_them():
    """The whole security argument for writing this rather than deploying a
    general-purpose gateway: it does not know what RFB is."""
    session = Session(job_id="j")
    frames = [b"RFB 003.008\n", b"\x00\x00\x00\x01", b"\xff" * 4096, None]
    got = []

    async def source():
        return frames.pop(0)

    async def sink(data):
        got.append(data)

    await pump(source, sink, session)

    assert got == [b"RFB 003.008\n", b"\x00\x00\x00\x01", b"\xff" * 4096]


async def test_the_pump_stops_when_the_session_closes():
    session = Session(job_id="j")
    session.close()
    called = []

    async def source():
        called.append(1)
        return b"x"

    await pump(source, lambda d: asyncio.sleep(0), session)

    assert called == []


async def test_input_is_recorded_on_the_browser_direction():
    """A report from an interactive session is NOT comparable to an automated
    one: a human made choices that changed what happened. The flag is a
    correctness requirement, not bookkeeping."""
    session = Session(job_id="j")
    frames = [b"\x04\x01\x00\x00\x00\x00\xff\x41", None]

    async def source():
        return frames.pop(0)

    async def sink(data):
        pass

    await pump(source, sink, session, mark_input=True)

    assert session.interacted is True


async def test_watching_alone_does_not_count_as_interaction():
    """Set when input is FORWARDED, not when the session opens. Watching
    changes nothing about the experiment."""
    session = Session(job_id="j")
    frames = [b"framebuffer data", None]

    async def source():
        return frames.pop(0)

    await pump(source, lambda d: asyncio.sleep(0), session)   # clone -> browser

    assert session.interacted is False


async def test_a_failing_sink_still_closes_the_session():
    """A dropped connection must not leave the other socket open against a
    malware VM."""
    session = Session(job_id="j")

    async def source():
        return b"x"

    async def sink(data):
        raise ConnectionError("browser went away")

    with pytest.raises(ConnectionError):
        await pump(source, sink, session)

    assert session.closed

# --- route shadowing --------------------------------------------------------
#
# F5, from the browser 2026-08-26: the WebSocket at /api/v1/jobs/{id}/console
# was shadowed by a POST route at the SAME path on the jobs router, which is
# included first. The upgrade request matched the HTTP route and got
# `405 Allow: POST`; the socket handler was never reached.

def test_the_websocket_path_is_not_also_an_http_route():
    """Two routers share the /api/v1/jobs prefix, and include order decides
    which claims a path. A collision is silent at import and only shows up as
    a 405 on an upgrade -- which reads like a proxy problem, not a routing
    one."""
    import os
    os.environ.setdefault("DATABASE_URL", "postgresql:///unused")
    os.environ.setdefault("WORKER_TOKEN", "unused")
    from fastapi.routing import APIRoute, APIWebSocketRoute

    from sandbox_platform.app import app

    # FastAPI wraps an included router in `_IncludedRouter`, which exposes the
    # real routes on `.original_router.routes` rather than `.routes`. Walking
    # the wrong attribute silently finds nothing, which would make this test
    # pass while proving the opposite of what it claims.
    def walk(routes):
        for r in routes:
            inner = getattr(r, "original_router", None)
            if inner is not None:
                yield from walk(inner.routes)
            else:
                yield r

    http_paths = {r.path for r in walk(app.routes) if isinstance(r, APIRoute)}
    ws_paths = {r.path for r in walk(app.routes)
                if isinstance(r, APIWebSocketRoute)}

    assert ws_paths, "no WebSocket routes registered at all"
    clash = http_paths & ws_paths
    assert clash == set(), (
        f"{clash} is served by both an HTTP route and a WebSocket route; "
        f"whichever router is included first wins and the other is dead"
    )


def test_the_console_endpoints_are_where_the_client_expects():
    """console.js and sandboxd/vnc.py build these paths independently, so a
    rename on one side has to fail here rather than at runtime."""
    import os
    os.environ.setdefault("DATABASE_URL", "postgresql:///unused")
    os.environ.setdefault("WORKER_TOKEN", "unused")
    from fastapi.routing import APIWebSocketRoute

    from sandbox_platform.app import app

    def walk(routes):
        for r in routes:
            inner = getattr(r, "original_router", None)
            if inner is not None:
                yield from walk(inner.routes)
            else:
                yield r

    ws = {r.path for r in walk(app.routes) if isinstance(r, APIWebSocketRoute)}

    assert "/api/v1/jobs/{job_id}/console" in ws
    assert "/api/v1/worker/jobs/{job_id}/console" in ws


def test_uvicorn_can_actually_serve_websockets():
    """F6, from the deployment 2026-08-26: a 404 on a route that exists.

    uvicorn does not implement the WebSocket protocol itself. With neither
    `websockets` nor `wsproto` installed it does not handle an upgrade at all
    -- the request is treated as a plain HTTP GET, nothing matches the socket
    path, and the client gets `404` from uvicorn while the route is registered
    and correct.

    **The rest of this file cannot catch that.** `TestClient` speaks ASGI
    directly and never goes through uvicorn's protocol layer, so every
    WebSocket test here passes against a server that could not serve one. This
    is the only check that looks at the deployed shape rather than the app
    object, which is why it is an import assertion rather than a connection.
    """
    try:
        import websockets  # noqa: F401
    except ImportError:
        try:
            import wsproto  # noqa: F401
        except ImportError:
            raise AssertionError(
                "neither websockets nor wsproto is installed, so uvicorn will "
                "404 every WebSocket upgrade -- see requirements.txt"
            ) from None


def test_the_websocket_dependency_is_pinned_in_requirements():
    """Installed-but-unpinned is how this comes back: it is here today as a
    transitive dependency of something else, and a future resolution that drops
    it would restore the 404 with nothing in the diff to explain it."""
    from pathlib import Path

    req = (Path(__file__).resolve().parents[1] / "requirements.txt").read_text()
    assert "websockets==" in req or "wsproto==" in req, (
        "uvicorn's WebSocket support is not pinned in requirements.txt"
    )
