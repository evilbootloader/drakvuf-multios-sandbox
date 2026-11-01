"""Screenshots of a clone's console: DRAFT-054.

Two halves. The RFB client is driven against a fake VNC server on loopback,
because what matters is the bytes on the wire -- above all that it never sends
anything but a request to look. The capture loop is driven with a fake `grab`,
because what matters there is the bookkeeping: ticks keep their numbers, caps
stop it honestly, and nothing appears in the job directory after `stop()`.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
import threading
import time
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "platform"))
os.environ.setdefault("DATABASE_URL", "postgresql:///unused")

from sandboxd import screenshots as SS  # noqa: E402

JOB = "11111111-1111-1111-1111-111111111111"


# --- a fake VNC server ------------------------------------------------------

def pixel(x: int, y: int) -> bytes:
    """A pattern with no two neighbours alike, so a misplaced row shows."""
    return bytes([(x * 40) % 256, (y * 60) % 256, ((x + y) * 10) % 256, 0])


def raw_rect(x, y, w, h) -> bytes:
    head = struct.pack(">HHHHi", x, y, w, h, SS.ENCODING_RAW)
    return head + b"".join(pixel(px, py)
                           for py in range(y, y + h) for px in range(x, x + w))


def update(*rects: bytes) -> bytes:
    return struct.pack(">BxH", SS.FRAMEBUFFER_UPDATE, len(rects)) + b"".join(rects)


class FakeVnc:
    """Serves one scripted RFB 3.8 session per connection and records every
    byte the client sends.

    `replies` is a list, one entry per FramebufferUpdateRequest: the bytes to
    answer it with. An empty entry answers nothing, which is how a silent
    console is modelled.
    """

    def __init__(self, width=5, height=3, *, banner=SS.PROTOCOL,
                 security=bytes([1, SS.SECURITY_NONE]), replies=None,
                 name=b"QEMU (clone)"):
        self.width, self.height = width, height
        self.banner, self.security, self.name = banner, security, name
        self.replies = replies if replies is not None else [
            update(raw_rect(0, 0, width, 1), raw_rect(0, 1, width, height - 1))]
        self.received = bytearray()
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self):
        self._sock.close()

    def _recv(self, conn, n) -> bytes:
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                raise ConnectionError
            data += chunk
        self.received += data
        return data

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        with conn:
            try:
                self._session(conn)
            except (ConnectionError, OSError):
                pass

    def _session(self, conn):
        conn.sendall(self.banner)
        if self.banner != SS.PROTOCOL:
            return
        self._recv(conn, 12)
        conn.sendall(self.security)
        self._recv(conn, 1)
        conn.sendall(struct.pack(">I", 0))
        self._recv(conn, 1)                      # ClientInit
        conn.sendall(struct.pack(">HH", self.width, self.height) + bytes(16)
                     + struct.pack(">I", len(self.name)) + self.name)
        replies = list(self.replies)
        while True:
            kind = self._recv(conn, 1)[0]
            if kind == SS.SET_PIXEL_FORMAT:
                self._recv(conn, 19)
            elif kind == SS.SET_ENCODINGS:
                self._recv(conn, 1)
                (n,) = struct.unpack(">H", self._recv(conn, 2))
                self._recv(conn, 4 * n)
            elif kind == SS.FRAMEBUFFER_UPDATE_REQUEST:
                self._recv(conn, 9)
                if replies:
                    conn.sendall(replies.pop(0))
            else:
                return


@pytest.fixture
def vnc():
    servers = []

    def make(**kw):
        s = FakeVnc(**kw)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.close()


def decode_png(data: bytes):
    """Just enough of PNG to check what `encode_png` wrote."""
    assert data[:8] == SS.PNG_SIGNATURE
    pos, chunks = 8, {}
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        tag = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        (crc,) = struct.unpack(">I", data[pos + 8 + length:pos + 12 + length])
        assert crc == zlib.crc32(tag + body) & 0xFFFFFFFF, f"bad CRC on {tag}"
        chunks[tag] = body
        pos += 12 + length
    w, h, depth, colour, _, _, _ = struct.unpack(">IIBBBBB", chunks[b"IHDR"])
    assert (depth, colour) == (8, 2), "8-bit RGB"
    raw = zlib.decompress(chunks[b"IDAT"])
    rows = [raw[y * (w * 3 + 1):(y + 1) * (w * 3 + 1)] for y in range(h)]
    assert all(r[0] == 0 for r in rows), "filter byte 0 on every row"
    return w, h, b"".join(r[1:] for r in rows)


def expected_rgb(w, h) -> bytes:
    return b"".join(pixel(x, y)[:3] for y in range(h) for x in range(w))


# --- the client --------------------------------------------------------------

def test_a_frame_is_read_and_encoded_pixel_for_pixel(vnc):
    s = vnc()
    frame = SS.grab("127.0.0.1", s.port, timeout=2)

    assert (frame.width, frame.height) == (5, 3)
    w, h, rgb = decode_png(SS.encode_png(frame.width, frame.height, frame.rgbx))
    assert (w, h) == (5, 3)
    assert rgb == expected_rgb(5, 3)


def parse_client_bytes(data: bytes) -> list[int]:
    """Every message the client sent after the handshake, by type. Raises if
    any byte is unaccounted for -- a read-only claim is only as good as the
    parse that checks it."""
    assert data[:12] == SS.PROTOCOL
    assert data[12] == SS.SECURITY_NONE
    pos, kinds = 14, []
    while pos < len(data):
        kind = data[pos]
        kinds.append(kind)
        if kind == SS.SET_PIXEL_FORMAT:
            pos += 20
        elif kind == SS.SET_ENCODINGS:
            (n,) = struct.unpack(">H", data[pos + 2:pos + 4])
            pos += 4 + 4 * n
        elif kind == SS.FRAMEBUFFER_UPDATE_REQUEST:
            pos += 10
        else:
            raise AssertionError(f"client sent message type {kind}")
    assert pos == len(data)
    return kinds


def test_the_client_only_ever_asks_to_look(vnc):
    """**Read-only is the property, so it is asserted on the wire.**

    Every byte the server received parses as the handshake or as
    SetPixelFormat, SetEncodings and FramebufferUpdateRequest. KeyEvent (4),
    PointerEvent (5) and ClientCutText (6) never appear, because nothing in
    the module can build them.
    """
    s = vnc(replies=[update(raw_rect(0, 0, 5, 1)), update(raw_rect(0, 1, 5, 2))])
    SS.grab("127.0.0.1", s.port, timeout=2)

    kinds = parse_client_bytes(bytes(s.received))
    assert set(kinds) <= SS.READ_ONLY_MESSAGES
    assert kinds.count(SS.FRAMEBUFFER_UPDATE_REQUEST) == 2, \
        "a partial update is followed by another request, not by a guess"


def test_input_messages_are_refused_before_they_reach_the_socket():
    sent = []

    class Sock:
        def settimeout(self, t):
            pass

        def sendall(self, data):
            sent.append(data)

    client = SS._Client(Sock(), time.monotonic() + 5)
    for kind in (4, 5, 6):
        with pytest.raises(SS.ReadOnlyViolation):
            client._message(kind, b"\x00" * 7)
    client._initialised = True
    with pytest.raises(SS.ReadOnlyViolation):
        client._handshake(b"\x01")
    assert sent == []


def test_the_session_is_shared_so_a_console_viewer_is_not_kicked(vnc):
    s = vnc()
    SS.grab("127.0.0.1", s.port, timeout=2)
    assert s.received[13] == 1, "ClientInit must request a shared session"


def test_the_pixel_format_asked_for_is_rgbx(vnc):
    s = vnc()
    SS.grab("127.0.0.1", s.port, timeout=2)
    msg = bytes(s.received[14:34])
    assert msg[0] == SS.SET_PIXEL_FORMAT
    bpp, depth, big, true_colour, rmax, gmax, bmax, rs, gs, bs = struct.unpack(
        ">BBBBHHHBBB", msg[4:17])
    assert (bpp, depth, big, true_colour) == (32, 24, 0, 1)
    assert (rmax, gmax, bmax, rs, gs, bs) == (255, 255, 255, 0, 8, 16)


def test_bell_and_the_guests_clipboard_are_skipped_not_kept(vnc):
    clip = b"wallet 1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    noise = (bytes([SS.BELL])
             + struct.pack(">B3xI", SS.SERVER_CUT_TEXT, len(clip)) + clip)
    s = vnc(replies=[noise + update(raw_rect(0, 0, 5, 3))])

    frame = SS.grab("127.0.0.1", s.port, timeout=2)
    assert clip not in frame.rgbx
    assert decode_png(SS.encode_png(5, 3, frame.rgbx))[2] == expected_rgb(5, 3)


@pytest.mark.parametrize("kw, match", [
    ({"banner": b"RFB 003.003\n"}, "protocol version"),
    ({"security": bytes([1, 2])}, "authentication"),
    ({"width": 4000, "height": 4000}, "4000x4000"),
    ({"replies": [update(raw_rect(3, 0, 5, 1))]}, "outside"),
    ({"replies": [bytes([9])]}, "message type 9"),
    ({"replies": [struct.pack(">BxH", 0, 1)
                  + struct.pack(">HHHHi", 0, 0, 5, 3, 7)]}, "encoding 7"),
])
def test_anything_but_our_clones_shape_is_refused(vnc, kw, match):
    s = vnc(**kw)
    with pytest.raises(SS.FrameError, match=match):
        SS.grab("127.0.0.1", s.port, timeout=2)


def test_a_silent_console_is_bounded_by_the_deadline(vnc):
    s = vnc(replies=[b""])
    started = time.monotonic()
    with pytest.raises(SS.FrameError, match="no frame within"):
        SS.grab("127.0.0.1", s.port, timeout=0.3)
    assert time.monotonic() - started < 2


def test_nothing_listening_is_a_frame_error_not_a_crash():
    s = socket.create_server(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(SS.FrameError, match="connect"):
        SS.grab("127.0.0.1", port, timeout=1)


# --- the capture loop --------------------------------------------------------

FRAME = SS.Frame(2, 2, bytes(16))


class ScriptedGrab:
    """Answers each call from a script: a Frame, or an exception to raise."""

    def __init__(self, *script):
        self.script = list(script)
        self.calls = 0

    def __call__(self, host, port, *, timeout):
        self.calls += 1
        item = self.script.pop(0) if self.script else FRAME
        if isinstance(item, Exception):
            raise item
        return item


def capture(tmp_path, grab, **kw) -> SS.Capture:
    job_dir = tmp_path / "results" / JOB
    job_dir.mkdir(parents=True)
    kw.setdefault("interval", 0.02)
    return SS.Capture(JOB, job_dir, grab=grab, **kw)


def run_for(cap: SS.Capture, seconds: float) -> dict:
    cap.start(5900)
    time.sleep(seconds)
    cap.stop()
    return json.loads((cap._job_dir / SS.SCREENSHOTS_INDEX).read_text())


def wait_for(predicate, timeout=3.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.005)
    return False


def test_frames_are_named_by_tick_and_a_failure_is_a_gap(tmp_path):
    """**Ticks keep their numbers.** A tick that failed is a missing file with
    a recorded reason, never a renumbering -- so `tick * interval` is the
    elapsed time of every frame that exists, and playback is real time."""
    grab = ScriptedGrab(FRAME, SS.FrameError("console closed"), FRAME, FRAME)
    cap = capture(tmp_path, grab, max_frames=4)
    cap.start(5900)
    assert wait_for(lambda: grab.calls >= 4 and not cap._thread.is_alive())
    cap.stop()

    names = sorted(p.name for p in (cap._job_dir / SS.SCREENSHOTS_DIR).iterdir())
    assert names == ["000.png", "002.png", "003.png"]
    index = json.loads((cap._job_dir / SS.SCREENSHOTS_INDEX).read_text())
    assert [f["tick"] for f in index["data"]["frames"]] == [0, 2, 3]
    assert index["data"]["missed"] == [{"tick": 1, "reason": "console closed"}]


def test_the_frame_cap_stops_capture_and_says_so(tmp_path):
    cap = capture(tmp_path, ScriptedGrab(), max_frames=3)
    cap.start(5900)
    assert wait_for(lambda: not cap._thread.is_alive())
    cap.stop()

    index = json.loads((cap._job_dir / SS.SCREENSHOTS_INDEX).read_text())
    assert len(index["data"]["frames"]) == 3
    assert index["status"] == "partial"
    assert "frame cap" in index["status_reason"]


def test_the_byte_cap_stops_capture_and_says_so(tmp_path):
    one = len(SS.encode_png(2, 2, bytes(16)))
    cap = capture(tmp_path, ScriptedGrab(), max_bytes=one * 2 + 1)
    cap.start(5900)
    assert wait_for(lambda: not cap._thread.is_alive())
    cap.stop()

    index = json.loads((cap._job_dir / SS.SCREENSHOTS_INDEX).read_text())
    assert len(index["data"]["frames"]) == 2
    assert index["status"] == "partial"
    assert "byte cap" in index["status_reason"]


def test_no_console_is_a_failed_index_not_an_empty_strip(tmp_path):
    job_dir = tmp_path / "results" / JOB
    job_dir.mkdir(parents=True)
    cap = SS.Capture(JOB, job_dir, grab=ScriptedGrab())
    cap.unavailable("could not find a VNC port")
    cap.mark("trace_start")
    cap.stop()

    index = json.loads((job_dir / SS.SCREENSHOTS_INDEX).read_text())
    assert index["status"] == "failed"
    assert "could not find a VNC port" in index["status_reason"]
    assert not (job_dir / SS.SCREENSHOTS_DIR).exists()


def test_every_tick_failing_is_failed_with_the_first_reason(tmp_path):
    grab = ScriptedGrab(*[SS.FrameError("refused") for _ in range(50)])
    index = run_for(capture(tmp_path, grab), 0.1)
    assert index["status"] == "failed"
    assert "refused" in index["status_reason"]


def test_marks_are_offsets_from_the_first_tick(tmp_path):
    cap = capture(tmp_path, ScriptedGrab())
    cap.start(5900)
    time.sleep(0.05)
    cap.mark("trace_start")
    cap.stop()

    index = json.loads((cap._job_dir / SS.SCREENSHOTS_INDEX).read_text())
    assert 0.04 <= index["data"]["marks"]["trace_start"] < 1.0


def test_nothing_is_written_after_stop_returns(tmp_path, monkeypatch):
    """**The property `_collect` relies on.** It declares every file's size
    before uploading it; a frame landing after that breaks the presigned
    `content-length-range` and fails the whole job. A grab still in flight
    when `stop()` gives up waiting must discard its frame."""
    monkeypatch.setattr(SS, "FRAME_DEADLINE", 0.05)
    monkeypatch.setattr(SS, "STOP_MARGIN", 0.05)
    release = threading.Event()
    entered = threading.Event()

    def stuck(host, port, *, timeout):
        entered.set()
        release.wait(5)
        return FRAME

    cap = capture(tmp_path, stuck)
    cap.start(5900)
    assert entered.wait(2)
    cap.stop()
    before = sorted(p.name for p in cap._job_dir.rglob("*"))

    release.set()
    cap._thread.join(2)
    assert not cap._thread.is_alive(), "the capture thread outlived its job"
    assert sorted(p.name for p in cap._job_dir.rglob("*")) == before
    assert not list((tmp_path / "results").glob(".screens-*")), \
        "a temporary frame was left behind"


def test_frames_are_never_half_written_in_the_job_directory(tmp_path):
    index = run_for(capture(tmp_path, ScriptedGrab()), 0.1)
    assert index["data"]["frames"]
    job_dir = tmp_path / "results" / JOB
    assert not [p for p in job_dir.rglob("*") if p.name.endswith(".part")]
    for f in (job_dir / SS.SCREENSHOTS_DIR).iterdir():
        assert f.read_bytes()[:8] == SS.PNG_SIGNATURE


def test_stop_is_idempotent(tmp_path):
    cap = capture(tmp_path, ScriptedGrab())
    cap.start(5900)
    cap.stop()
    first = (cap._job_dir / SS.SCREENSHOTS_INDEX).read_text()
    cap.stop()
    assert (cap._job_dir / SS.SCREENSHOTS_INDEX).read_text() == first


def test_the_index_is_the_envelope_the_platform_validates(tmp_path):
    """Writer and reader are two packages; this pins them together, the way
    test_api.py pins the worker channel to the server's own models."""
    from sandbox_platform.manifest import Envelope

    grab = ScriptedGrab(FRAME, SS.FrameError("timeout"))
    index = run_for(capture(tmp_path, grab), 0.1)

    env = Envelope.model_validate(index)
    assert env.schema_id == SS.SCHEMA
    assert env.data["interval_s"] == 0.02
    assert env.status in ("complete", "partial")


def test_a_real_frame_through_the_loop(tmp_path, vnc):
    """The two halves together, against the fake server."""
    s = vnc()
    cap = capture(tmp_path, SS.grab, max_frames=1)
    cap.start(s.port)
    assert wait_for(lambda: not cap._thread.is_alive())
    cap.stop()

    png = (cap._job_dir / SS.SCREENSHOTS_DIR / "000.png").read_bytes()
    assert decode_png(png)[2] == expected_rgb(5, 3)
