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