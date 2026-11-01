"""The guest's screen, every two seconds, read from Dom0. DRAFT-054.

Design: `docs/architecture/screenshots.md`.

**Agentless, and read-only.** Every clone serves its display over VNC on
Dom0's loopback (`vnc = 1`, `vnclisten = "127.0.0.1"` in all three
`misc/*_sandbox.cfg`), so a frame needs nothing in the guest and nothing
installed on Dom0 -- the same argument DRAKVUF makes, applied to the display.
The guest cannot forge or suppress a frame, because it is read from outside.

This module is an RFB client that can only LOOK. Every byte it sends goes
through `_Client._message`, which admits SetPixelFormat, SetEncodings and
FramebufferUpdateRequest and refuses everything else; there is no code here
that could build a KeyEvent, a PointerEvent or a ClientCutText. That is the
property `live-console.md` §1.2 could not give the console, kept here by
construction because nothing here needs input.

**One TCP connection per frame.** Stateless: a guest that changes resolution,
or a QEMU that drops the client, is handled by the next frame's ServerInit
rather than by DesktopSize handling nobody would exercise until it mattered.

**Every frame is kept, at a fixed interval.** Tick k is due at `t0 + k *
interval` on the monotonic clock and its frame is named after k, so a tick
that failed is a gap with a recorded reason, never a renumbering. Elapsed time
is `tick * interval` by construction, which is what makes playback at the
capture interval honest -- the draft's reason for refusing deduplication.

Standard library only. A frame is decoded from Raw rectangles and encoded as
PNG with `zlib`: no Pillow on the machine that runs malware.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import struct
import tempfile
import threading
import time
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .postprocessing.paths import SCREENSHOTS_DIR, SCREENSHOTS_INDEX

log = logging.getLogger("sandboxd.screenshots")

# The index is a capability document (result-schema.md §4.3), validated on
# the platform by `manifest.Envelope`. `version` is this format's, not the
# daemon's: sandboxd has no release version, and what a reader needs to know is
# which shape of `data` it is looking at.
SCHEMA = "sandbox.screenshots/1"
FORMAT_VERSION = "1"

# One frame, connect to last byte. QEMU answers a FramebufferUpdateRequest at
# its next display refresh, not at once, so this is generous; a frame that
# takes longer than the interval costs the ticks it overran, which the index
# records rather than hides.
FRAME_DEADLINE = 5.0

# How much longer than one frame `stop()` waits for the capture thread. Past
# it, a grab still in flight is abandoned and its frame discarded.
STOP_MARGIN = 2.0

# What a hostile ServerInit may ask this process to allocate. The guest
# chooses its resolution, so it chooses the buffer size: 3840x2160 at 4 bytes
# a pixel is 33 MiB per capture thread. stdvga's VRAM caps a real guest well
# below this.
MAX_PIXELS = 3840 * 2160
MAX_NAME = 4096
# ServerCutText is the GUEST's clipboard. Skipped unread, and bounded so a
# guest cannot make skipping it expensive.
MAX_CUT_TEXT = 1 << 20

PNG_LEVEL = 6
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# RFB 3.8 (RFC 6143), only as much of it as a viewer that never types needs.
PROTOCOL = b"RFB 003.008\n"
SECURITY_NONE = 1
CLIENT_INIT_SHARED = b"\x01"
SET_PIXEL_FORMAT = 0
SET_ENCODINGS = 2
FRAMEBUFFER_UPDATE_REQUEST = 3
ENCODING_RAW = 0
FRAMEBUFFER_UPDATE = 0
SET_COLOUR_MAP_ENTRIES = 1
BELL = 2
SERVER_CUT_TEXT = 3

#: The only client->server message types this module may send. KeyEvent (4),
#: PointerEvent (5) and ClientCutText (6) are absent on purpose: a screenshot
#: that could type is an input channel into a malware VM.
READ_ONLY_MESSAGES = frozenset({SET_PIXEL_FORMAT, SET_ENCODINGS,
                                FRAMEBUFFER_UPDATE_REQUEST})


class FrameError(Exception):
    """One frame could not be taken. The next tick tries again."""


class ReadOnlyViolation(RuntimeError):
    """Something tried to send the guest more than a request to look."""


@dataclass(frozen=True)
class Frame:
    width: int
    height: int
    # R, G, B, X per pixel, rows top to bottom -- the pixel format asked for
    # in `_Client.screenshot`.
    rgbx: bytes


class _Client:
    """One connection, one frame. Not reusable."""

    def __init__(self, sock: socket.socket, deadline: float):
        self._sock = sock
        self._deadline = deadline
        self._initialised = False

    # -- the only two ways bytes leave this process --------------------------

    def _handshake(self, data: bytes) -> None:
        """ProtocolVersion, the security choice and ClientInit. Nothing else,
        and nothing once the handshake is over."""
        if self._initialised:
            raise ReadOnlyViolation("handshake bytes after ClientInit")
        self._write(data)

    def _message(self, kind: int, payload: bytes) -> None:
        if kind not in READ_ONLY_MESSAGES:
            raise ReadOnlyViolation(
                f"refusing to send RFB message type {kind}: the screenshotter "
                f"only asks to look")
        self._write(bytes([kind]) + payload)

    def _write(self, data: bytes) -> None:
        self._sock.settimeout(self._remaining())
        try:
            self._sock.sendall(data)
        except OSError as exc:
            raise FrameError(f"send: {exc}") from exc

    # -- reading -------------------------------------------------------------

    def _remaining(self) -> float:
        left = self._deadline - time.monotonic()
        if left <= 0:
            raise FrameError(f"no frame within {FRAME_DEADLINE:g}s")
        return left

    def _recv(self, n: int) -> bytes:
        buf = bytearray(n)
        view = memoryview(buf)
        got = 0
        while got < n:
            self._sock.settimeout(self._remaining())
            try:
                k = self._sock.recv_into(view[got:])
            except TimeoutError as exc:
                raise FrameError(f"no frame within {FRAME_DEADLINE:g}s") from exc
            except OSError as exc:
                raise FrameError(f"recv: {exc}") from exc
            if k == 0:
                raise FrameError("the console closed the connection")
            got += k
        return bytes(buf)

    def _u32(self) -> int:
        return struct.unpack(">I", self._recv(4))[0]

    # -- the exchange --------------------------------------------------------

    def screenshot(self) -> Frame:
        # Only the shape our clones present (live-console.md §1.2): RFB 3.8,
        # security type None. Anything else is refused rather than negotiated
        # -- a client with states nobody tested is not worth one frame.
        version = self._recv(len(PROTOCOL))
        if version != PROTOCOL:
            raise FrameError(f"unexpected protocol version {version!r}")
        self._handshake(PROTOCOL)

        count = self._recv(1)[0]
        if count == 0:
            reason = self._recv(min(self._u32(), MAX_NAME))
            raise FrameError(f"console refused the connection: {reason!r}")
        if SECURITY_NONE not in self._recv(count):
            raise FrameError("console requires authentication; the clones "
                             "set no VNC password, so this is not one of ours")
        self._handshake(bytes([SECURITY_NONE]))
        if self._u32() != 0:
            raise FrameError("console refused security type None")

        # SHARED, so a live-console viewer watching the same clone is not
        # disconnected by a screenshot.
        self._handshake(CLIENT_INIT_SHARED)
        self._initialised = True

        width, height = struct.unpack(">HH", self._recv(4))
        self._recv(16)                      # the server's pixel format, unused
        name_len = self._u32()
        if name_len > MAX_NAME:
            raise FrameError(f"desktop name of {name_len} bytes")
        self._recv(name_len)
        if not (width and height and width * height <= MAX_PIXELS):
            raise FrameError(f"refusing a {width}x{height} framebuffer")

        # 32 bpp, depth 24, little-endian, true colour, 8 bits a channel at
        # shifts 0/8/16: each pixel arrives as the bytes R, G, B, X, so PNG
        # encoding is three slices with no per-pixel arithmetic.
        self._message(SET_PIXEL_FORMAT, struct.pack(
            ">3xBBBBHHHBBB3x", 32, 24, 0, 1, 255, 255, 255, 0, 8, 16))
        # Raw only. Nothing to decompress, and no pseudo-encoding the server
        # could answer with a message this parser does not model.
        self._message(SET_ENCODINGS,
                      struct.pack(">xH", 1) + struct.pack(">i", ENCODING_RAW))

        fb = bytearray(width * height * 4)
        covered = 0
        while covered < width * height:
            self._request(width, height)
            covered += self._read_until_update(fb, width, height)
        return Frame(width, height, bytes(fb))

    def _request(self, width: int, height: int) -> None:
        # Non-incremental: the whole screen, whatever has or has not changed.
        self._message(FRAMEBUFFER_UPDATE_REQUEST,
                      struct.pack(">BHHHH", 0, 0, 0, width, height))

    def _read_until_update(self, fb: bytearray, width: int, height: int) -> int:
        """Skip what is not a picture; return the area one update covered."""
        while True:
            kind = self._recv(1)[0]
            if kind == FRAMEBUFFER_UPDATE:
                return self._read_update(fb, width, height)
            if kind == BELL:
                continue
            if kind == SERVER_CUT_TEXT:
                self._recv(3)
                length = self._u32()
                if length > MAX_CUT_TEXT:
                    raise FrameError(f"server cut text of {length} bytes")
                self._recv(length)          # the guest's clipboard: discarded
                continue
            if kind == SET_COLOUR_MAP_ENTRIES:
                raise FrameError("colour map sent to a true-colour client")
            raise FrameError(f"unexpected server message type {kind}")

    def _read_update(self, fb: bytearray, width: int, height: int) -> int:
        self._recv(1)
        (count,) = struct.unpack(">H", self._recv(2))
        area = 0
        for _ in range(count):
            x, y, w, h, encoding = struct.unpack(">HHHHi", self._recv(12))
            if encoding != ENCODING_RAW:
                raise FrameError(f"rectangle in encoding {encoding}, not Raw")
            if x + w > width or y + h > height:
                raise FrameError(f"rectangle {w}x{h}+{x}+{y} outside a "
                                 f"{width}x{height} framebuffer")
            row = w * 4
            data = self._recv(row * h)
            for r in range(h):
                start = ((y + r) * width + x) * 4
                fb[start:start + row] = data[r * row:(r + 1) * row]
            area += w * h
        return area


def grab(host: str, port: int, *, timeout: float = FRAME_DEADLINE) -> Frame:
    """One frame of the console at host:port, or FrameError."""
    deadline = time.monotonic() + timeout
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise FrameError(f"connect {host}:{port}: {exc}") from exc
    with sock:
        return _Client(sock, deadline).screenshot()


def encode_png(width: int, height: int, rgbx: bytes) -> bytes:
    """8-bit RGB PNG, filter 0 on every row, one IDAT."""
    rgb = bytearray(width * height * 3)
    rgb[0::3] = rgbx[0::4]
    rgb[1::3] = rgbx[1::4]
    rgb[2::3] = rgbx[2::4]
    stride = width * 3
    raw = bytearray((stride + 1) * height)      # each row's filter byte is 0
    for y in range(height):
        out = y * (stride + 1) + 1
        raw[out:out + stride] = rgb[y * stride:(y + 1) * stride]

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    return (PNG_SIGNATURE
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), PNG_LEVEL))
            + chunk(b"IEND", b""))


class Capture:
    """A filmstrip of one clone, taken on a thread beside the analysis.

    The shape of `vnc.ConsoleSession`, and for the same reason: an observer of
    the run, never a participant. A frame that cannot be taken is a gap in the
    strip, and capture that cannot start at all is a `failed` index -- neither
    ever fails the analysis.

    **`stop()` must be called before the job directory is collected**, and once
    it returns nothing more is written into it. `_collect` declares each file's
    size before uploading it, so a frame still growing under it would break the
    presigned `content-length-range` and fail the whole job.
    """

    def __init__(self, job_id: str, job_dir: Path, *, host: str = "127.0.0.1",
                 interval: float = 2.0, max_frames: int = 450,
                 max_bytes: int = 256 << 20, grab=grab, clock=time.monotonic):
        self._job_id = job_id
        self._job_dir = job_dir
        self._host = host
        self._interval = interval
        self._max_frames = max_frames
        self._max_bytes = max_bytes
        self._grab = grab
        self._clock = clock

        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stopped = False
        self._closed = False

        self._t0: float | None = None
        self._started_at: str | None = None
        self._ticks = 0
        self._bytes = 0
        self._frames: list[dict] = []
        self._missed: list[dict] = []
        self._marks: dict[str, float] = {}
        # Set when capture ends early for a reason the strip cannot show on
        # its own: a cap, or no console to read at all.
        self._cut_short: str | None = None
        self._unavailable: str | None = None

    # -- lifecycle -----------------------------------------------------------

    def start(self, port: int) -> None:
        if self._thread is not None:
            raise RuntimeError("this capture has already been started")
        self._t0 = self._clock()
        self._started_at = _now()
        self._thread = threading.Thread(
            target=self._run, args=(port,), daemon=True,
            name=f"screens-{self._job_id[:8]}")
        self._thread.start()

    def unavailable(self, reason: str) -> None:
        """Capture could not begin. `stop()` records why, so the report can
        say "no console" rather than show an empty strip as if nothing ran."""
        self._unavailable = reason

    def mark(self, name: str) -> None:
        """When something happened, in seconds from the first tick."""
        if self._t0 is None:
            return
        with self._lock:
            self._marks[name] = round(self._clock() - self._t0, 3)

    def stop(self) -> None:
        """End capture and write the index. Idempotent; called on every path.

        After this returns no frame can appear in the job directory: a grab
        still in flight past the join finds `_closed` set and discards its
        frame, so a stuck console costs a frame, never the job.
        """
        if self._stopped:
            return
        self._stopped = True
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=FRAME_DEADLINE + STOP_MARGIN)
            if self._thread.is_alive():
                log.warning("screenshots for job %s: capture thread still in a "
                            "grab at stop; its frame will be discarded",
                            self._job_id)
        with self._lock:
            self._closed = True
            index = self._index()
        try:
            _write_atomically(self._job_dir / SCREENSHOTS_INDEX,
                              json.dumps(index, indent=1).encode())
        except OSError as exc:
            log.warning("screenshots for job %s: index not written: %s",
                        self._job_id, exc)

    # -- the thread ----------------------------------------------------------

    def _run(self, port: int) -> None:
        try:
            self._loop(port)
        except Exception:
            # Never into the analysis. Whatever this was, the index says the
            # strip ends here.
            log.exception("screenshots for job %s ended in an error",
                          self._job_id)
            with self._lock:
                self._cut_short = self._cut_short or "capture ended in an error"

    def _loop(self, port: int) -> None:
        tick = 0
        while not self._stop.is_set():
            if tick >= self._max_frames:
                with self._lock:
                    self._cut_short = (
                        f"stopped at the frame cap of {self._max_frames} "
                        f"({self._max_frames * self._interval:g}s)")
                return
            due = self._t0 + tick * self._interval
            wait = due - self._clock()
            if wait > 0 and self._stop.wait(wait):
                return
            with self._lock:
                self._ticks = tick + 1
            started = self._clock()
            if started - due >= self._interval:
                # This tick's slot passed while the previous frame was taken.
                self._miss(tick, "overrun: the previous frame took longer "
                                 "than the interval")
                tick += 1
                continue
            try:
                frame = self._grab(self._host, port, timeout=FRAME_DEADLINE)
                png = encode_png(frame.width, frame.height, frame.rgbx)
            except (FrameError, OSError) as exc:
                self._miss(tick, str(exc)[:200])
                tick += 1
                continue
            ms = round((self._clock() - started) * 1000)
            if not self._store(tick, png, started - self._t0, ms, frame):
                return
            tick += 1

    def _miss(self, tick: int, reason: str) -> None:
        with self._lock:
            self._missed.append({"tick": tick, "reason": reason})

    def _store(self, tick: int, png: bytes, offset: float, ms: int,
               frame: Frame) -> bool:
        """Write one frame into place, or refuse. False ends capture."""
        with self._lock:
            if self._closed:
                return False
            if self._bytes + len(png) > self._max_bytes:
                self._cut_short = (f"stopped at the byte cap of "
                                   f"{self._max_bytes >> 20} MiB")
                return False
        # Written OUTSIDE the job directory and renamed in, so `_collect` can
        # never find a frame half-written. Same filesystem, so the rename is
        # atomic.
        tmp = _temporary(self._job_dir.parent, png)
        with self._lock:
            if self._closed:
                tmp.unlink(missing_ok=True)
                return False
            frames = self._job_dir / SCREENSHOTS_DIR
            frames.mkdir(parents=True, exist_ok=True)
            os.replace(tmp, frames / frame_name(tick))
            self._bytes += len(png)
            self._frames.append({
                "tick": tick, "t": round(offset, 3), "ms": ms,
                "bytes": len(png), "width": frame.width,
                "height": frame.height})
        return True

    # -- the index -----------------------------------------------------------

    def _index(self) -> dict:
        """The capability envelope; called with the lock held."""
        if self._unavailable is not None:
            status, reason = "failed", f"no console to capture: {self._unavailable}"
        elif not self._frames:
            first = self._missed[0]["reason"] if self._missed else "no tick ran"
            status, reason = "failed", f"no frame could be taken: {first}"
        elif self._cut_short is not None:
            status, reason = "partial", self._cut_short
        elif self._missed:
            status, reason = "partial", (
                f"{len(self._missed)} of {self._ticks} ticks have no frame")
        else:
            status, reason = "complete", None
        return {
            "schema": SCHEMA,
            "job_id": self._job_id,
            "produced_at": _now(),
            "producer": {"name": "sandboxd", "version": FORMAT_VERSION},
            "status": status,
            "status_reason": reason,
            "data": {
                "interval_s": self._interval,
                "started_at": self._started_at,
                "ticks": self._ticks,
                "marks": dict(self._marks),
                "frames": list(self._frames),
                "missed": list(self._missed),
            },
        }


def frame_name(tick: int) -> str:
    """`000.png`. Three digits cover the frame cap; readers sort by the number,
    not the string, so a wider name later would not reorder anything."""
    return f"{tick:03d}.png"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _temporary(directory: Path, data: bytes) -> Path:
    fd, name = tempfile.mkstemp(dir=directory, prefix=".screens-",
                                suffix=".part")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise
    return Path(name)


def _write_atomically(path: Path, data: bytes) -> None:
    os.replace(_temporary(path.parent.parent, data), path)
