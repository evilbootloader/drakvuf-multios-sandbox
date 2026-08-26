"""sandboxd's half of the live console: DRAFT-056.

The port resolution is the part with a real decision in it. The bridge is two
loops that do not know what RFB is, which is the property that keeps the code
between the internet and a malware host small enough to reason about.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd import vnc  # noqa: E402
from sandboxd.tests.fake import FakeRunner  # noqa: E402

XL_LIST_L = '''
{
    "config": {
        "c_info": { "type": "hvm", "name": "ubuntu_sandbox-3-clone" },
        "b_info": {
            "device_model_version": "qemu_xen",
            "u": { "hvm": { "vnc": {
                "enable": "True",
                "vnclisten": "127.0.0.1:5903",
                "findunused": "False"
            } } }
        }
    }
}
'''


def test_the_port_comes_from_xenstore_first():
    """xenstore holds what QEMU actually BOUND; the domain config holds what
    was asked for. With `vncunused` those differ whenever the requested port
    was already taken."""
    r = FakeRunner()
    r.script(("xenstore-read",), rc=0, stdout="5903\n")

    assert vnc.resolve_vnc_port(r, 42, "ubuntu_sandbox-3-clone") == 5903
    assert not r.ran(("xl", "list"))


def test_xl_list_is_the_fallback():
    r = FakeRunner()
    r.script(("xenstore-read",), rc=1, stderr="No such file or directory")
    r.script(("xl", "list", "-l"), rc=0, stdout=XL_LIST_L)

    assert vnc.resolve_vnc_port(r, 42, "ubuntu_sandbox-3-clone") == 5903


def test_a_vnc_display_number_is_converted_to_a_port():
    """QEMU display N is port 5900+N, and `xl list -l` may report either."""
    r = FakeRunner()
    r.script(("xenstore-read",), rc=1)
    r.script(("xl", "list", "-l"), rc=0, stdout='{"vncdisplay": 4}')

    assert vnc.resolve_vnc_port(r, 42, "d") == vnc.VNC_PORT_BASE + 4


def test_a_non_numeric_xenstore_value_falls_through():
    """xenstore-read prints its own errors to stdout in some versions.
    Treating one as a port would produce a connection to nothing."""
    r = FakeRunner()
    r.script(("xenstore-read",), rc=0, stdout="couldn't read path\n")
    r.script(("xl", "list", "-l"), rc=0, stdout=XL_LIST_L)

    assert vnc.resolve_vnc_port(r, 42, "d") == 5903


def test_no_port_anywhere_is_not_an_analysis_failure():
    """The console is an observer of the run, never a participant in its
    lifecycle -- so this raises its own type rather than something the stage
    machine would record as a failed analysis."""
    r = FakeRunner()
    r.script(("xenstore-read",), rc=1)
    r.script(("xl", "list", "-l"), rc=1)

    with pytest.raises(vnc.ConsoleUnavailable, match="Candidate and unverified"):
        vnc.resolve_vnc_port(r, 42, "ubuntu_sandbox-3-clone")


# --- the outbound URL -------------------------------------------------------

def test_the_session_dials_the_worker_endpoint():
    """Dom0 connects TO the platform. Nothing connects to Dom0, which is what
    keeps the deploy runbook's step-5 check passing during a session."""
    s = vnc.ConsoleSession("https://192.168.1.10:9000", "tok", "job-1")

    assert s.url == ("wss://192.168.1.10:9000"
                     "/api/v1/worker/jobs/job-1/console")


def test_plain_http_gets_a_plain_websocket():
    s = vnc.ConsoleSession("http://127.0.0.1:8000", "tok", "job-1")
    assert s.url.startswith("ws://")


def test_the_relay_reuses_the_worker_token():
    """Not a credential of its own: the same door on the same LAN, already
    gated by the client certificate at the TLS layer."""
    s = vnc.ConsoleSession("https://p:9000", "sekrit", "job-1")

    assert s.headers() == {"Authorization": "Bearer sekrit"}


def test_the_url_carries_the_job_id_encoded():
    s = vnc.ConsoleSession("https://p:9000", "t",
                           "11111111-1111-1111-1111-111111111111")
    assert "11111111-1111-1111-1111-111111111111" in s.url

# --- the outbound dial ------------------------------------------------------

def test_a_session_is_not_started_twice():
    """One session per job. A second start would leave the first thread
    bridging with nothing to stop it."""
    s = vnc.ConsoleSession("https://p:9000", "t", "job-1")
    s._thread = object()          # pretend it is running

    with pytest.raises(RuntimeError, match="already been started"):
        s.start(5901)


def test_stopping_a_session_that_never_started_is_safe():
    """stop() runs from the trace's `finally`, which executes on every path
    including the ones where no console was ever opened."""
    vnc.ConsoleSession("https://p:9000", "t", "job-1").stop()


def test_the_ssl_context_is_passed_through_not_rebuilt(monkeypatch):
    """The whole argument for `websockets` over `httpx-ws` was that it takes
    the SAME SSLContext object client_tls builds -- so a test that let this
    become a second derivation would remove the reason for the choice."""
    seen = {}

    class FakeWS:
        async def __aenter__(self): raise RuntimeError("stop here")
        async def __aexit__(self, *a): return False

    def fake_connect(url, **kwargs):
        seen.update(kwargs)
        seen["url"] = url
        return FakeWS()

    import sys, types
    mod = types.ModuleType("websockets.asyncio.client")
    mod.connect = fake_connect
    monkeypatch.setitem(sys.modules, "websockets.asyncio.client", mod)

    sentinel = object()
    s = vnc.ConsoleSession("https://p:9000", "tok", "job-1",
                           ssl_context=sentinel)
    import asyncio
    with pytest.raises(RuntimeError, match="stop here"):
        asyncio.run(s._session(5901))

    assert seen["ssl"] is sentinel, "the SSL context was rebuilt, not passed"
    assert seen["additional_headers"]["Authorization"] == "Bearer tok"
    assert seen["url"].startswith("wss://")


# --- F10: the console socket opens when a viewer arrives, not before -------

def _fake_ws(frames):
    """A WebSocket that yields `frames` then blocks."""
    class WS:
        def __init__(self): self.sent = []
        async def recv(self):
            if frames:
                return frames.pop(0)
            await asyncio.sleep(3600)
        async def send(self, data): self.sent.append(data)
    return WS()


import asyncio  # noqa: E402


def test_no_console_socket_is_opened_before_a_viewer_attaches(monkeypatch):
    """The bug: `open_connection` ran at dial time, so the TCP connection to
    QEMU opened a minute before anyone watched. RFB has the SERVER speak
    first, so the banner went to nobody and QEMU gave up -- the session died
    ~40s in with no explanation (Dom0 2026-08-26).

    It is also what §4.1b was uneasy about: a socket into a malware VM's
    console with nobody watching it.
    """
    opened = []

    async def fake_open(host, port):
        opened.append((host, port))
        raise AssertionError("connected before a viewer attached")

    monkeypatch.setattr(vnc.asyncio, "open_connection", fake_open)
    ws = _fake_ws([])          # nothing arrives; no viewer signal

    async def run():
        await asyncio.wait_for(vnc.bridge(ws, "127.0.0.1", 5900), timeout=0.3)

    with pytest.raises((asyncio.TimeoutError, TimeoutError)):
        asyncio.run(run())

    assert opened == [], "the console was connected with nobody watching"


def test_the_socket_opens_once_the_platform_signals_a_viewer(monkeypatch):
    opened = []

    class FakeReader:
        async def read(self, n): await asyncio.sleep(3600)

    class FakeWriter:
        def write(self, d): pass
        async def drain(self): pass
        def close(self): pass
        async def wait_closed(self): pass

    async def fake_open(host, port):
        opened.append((host, port))
        return FakeReader(), FakeWriter()

    monkeypatch.setattr(vnc.asyncio, "open_connection", fake_open)
    ws = _fake_ws([vnc.PEER_ATTACHED])

    async def run():
        await asyncio.wait_for(vnc.bridge(ws, "127.0.0.1", 5901), timeout=0.4)

    with pytest.raises((asyncio.TimeoutError, TimeoutError)):
        asyncio.run(run())

    assert opened == [("127.0.0.1", 5901)]


def test_console_data_before_a_viewer_is_refused(monkeypatch):
    """Binary before the control frame means a peer that should not exist."""
    monkeypatch.setattr(vnc.asyncio, "open_connection", None)
    ws = _fake_ws([b"RFB 003.008\n"])

    with pytest.raises(vnc.ConsoleUnavailable, match="before a viewer"):
        asyncio.run(vnc.bridge(ws, "127.0.0.1", 5900))


def test_a_bridge_failure_is_raised_not_swallowed(monkeypatch):
    """Both pumps sat in `except Exception: pass`, so a bridge that died on
    its first read logged "session ended" and nothing else -- the code
    destroyed the evidence needed to diagnose it."""
    class Boom:
        async def recv(self): raise ConnectionResetError("relay went away")
        async def send(self, d): pass

    with pytest.raises(ConnectionResetError, match="relay went away"):
        asyncio.run(vnc.bridge(Boom(), "127.0.0.1", 5900))
