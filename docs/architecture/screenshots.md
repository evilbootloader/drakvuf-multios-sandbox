# Screenshots — a filmstrip from the Xen framebuffer

> **Status (2026-10-30): capture and viewer implemented and tested in the
> development container; neither has run on Dom0 or the deployment.** The
> issue is DRAFT-054. The code is `sandboxd/screenshots.py` (capture) and
> `platform/sandbox_platform/screenshots.py`, `routers/jobs.py`,
> `ui/templates/tabs/_screenshots.html` and `ui/static/filmstrip.js` (viewer).
> Its verification is the parked runbook `verify-screenshots.md` at the
> repository root. Every claim below about how QEMU or Xen behaves is from the
> code and the protocol, not from a Dom0 run, until that runbook is executed.

Every few seconds of a run, the guest's screen is captured and kept.

A sample that "did nothing" usually did something visible: an error dialog,
a missing runtime, "this app can't run on your PC". A trace showing a process
start and exit cannot say which. Ransom notes and lock screens are the payload
rather than evidence of it, and a screenshot is often the first thing an
analyst looks at.

---

## 1. Capture

### 1.1 Where frames come from

Every clone serves its display over VNC on Dom0's loopback. All three
`misc/*_sandbox.cfg` set:

```text
builder = "hvm"
vnc = 1
vnclisten = "127.0.0.1"
vga = "stdvga"
```

None sets a VNC password, so QEMU presents RFB 3.8 with security type None
(`live-console.md` §1.2).

The port is found exactly as the live console finds it, with
`vnc.resolve_vnc_port`. Its `xenstore-read
/local/domain/<domid>/console/vnc-port` reading is evidenced on Dom0 (runbook
09 §B2).

That makes capture **agentless**:

- nothing runs in the guest;
- nothing is installed on Dom0 — the client and the PNG encoder are standard
  library Python;
- the guest cannot forge or suppress a frame, because the frame is read from
  outside it. That is the same integrity argument as VMI, and an in-guest
  screenshot agent would not have it.

### 1.2 The client can only look

`sandboxd/screenshots.py` is an RFB client that can only request pictures.
Every byte it sends goes through one of two methods:

- `_Client._handshake` sends `ProtocolVersion`, the security choice and
  `ClientInit`, and refuses anything once the handshake is over;
- `_Client._message` admits only `SetPixelFormat` (0), `SetEncodings` (2) and
  `FramebufferUpdateRequest` (3), which is `READ_ONLY_MESSAGES`.

`KeyEvent` (4), `PointerEvent` (5) and `ClientCutText` (6) cannot be sent,
because no code in the module builds them.

`sandboxd/tests/test_screenshots.py` asserts this on the wire: it parses
every byte the fake server received and fails on any other message type.

This is the guarantee `live-console.md` §1.2 could not give the console,
because the console needs input. The screenshotter needs none, so it is
read-only by construction rather than by filtering.

**`ClientInit` asks for a shared session.** The capture client therefore
never disconnects an operator's live console on the same clone.

`ServerCutText` — the guest's clipboard — is skipped unread, and capped at
1 MiB so that skipping it stays cheap.

### 1.3 One connection per frame

Each frame is a fresh TCP connection:

1. handshake;
2. `SetPixelFormat`: 32 bpp, true colour, R/G/B at shifts 0/8/16, so each pixel
   arrives as the bytes R, G, B, X;
3. `SetEncodings`: Raw only;
4. one non-incremental `FramebufferUpdateRequest`;
5. read until the rectangles cover the screen;
6. close.

**Why a connection per frame.** It is stateless, so a guest that changes
resolution mid-run — booting, or a game going fullscreen — is handled by the
next frame's `ServerInit`. There is no DesktopSize handling to get wrong, and
no stream state for QEMU to drop.

**Bounded against a hostile guest:**

- **Resolution.** The guest chooses its resolution, and so the buffer size.
  Anything over 3840×2160, or a desktop name over 4 KiB, is refused.
- **Rectangles.** One outside the framebuffer is refused, as is one in any
  encoding but Raw.
- **Time.** Each frame has a 5 s deadline, from connect to last byte.

**Candidate fallback.** QEMU answers an update request at its next display
refresh, not immediately, so a frame's latency is QEMU's to decide. Each frame
records its own duration (`ms`, §1.5). If the runbook shows frames regularly
taking longer than the interval, there are two options, both Candidate:

- keep one connection open and request on it at each tick;
- use QEMU's QMP `screendump`, through a QMP socket libxl owns.

### 1.4 Every frame kept, at a fixed interval

Ticks are due at `t0 + k × 2 s` on the monotonic clock, and frame `k` is
written as `screenshots/{k:03d}.png`.

When a tick produces no frame — a refused connection, the deadline, or the
slot already passed while the previous frame was taken — that number is
**missing**, and the index records why. Frames are never renumbered.

So `tick × interval` is the true elapsed time of every frame that exists,
and playing the frames at the interval reproduces the run at real speed.

**Deduplicating identical frames was considered and dropped**, for the
draft's reason. It would save a little storage and buy a real problem: the
surviving frames would be unevenly spaced. Playback would then either have to
reconstruct time from timestamps, or silently compress three idle minutes
followed by a ransom note into what looks like one moment. A desktop that does
not change is a perfectly good result, and a strip of it says so at a glance.

### 1.5 The index — `screenshots.json`

The index is a capability document, using the envelope from
`result-schema.md` §4.3, and validated by the platform's `manifest.Envelope`.
`sandboxd/tests/test_screenshots.py` pins the writer to that model.

```json
{"schema": "sandbox.screenshots/1", "job_id": "…", "produced_at": "…",
 "producer": {"name": "sandboxd", "version": "1"},
 "status": "complete | partial | failed", "status_reason": "…",
 "data": {"interval_s": 2.0, "started_at": "…", "ticks": 68,
          "marks": {"trace_start": 14.0, "trace_end": 136.1},
          "frames": [{"tick": 0, "t": 0.04, "ms": 38, "bytes": 81234,
                      "width": 1024, "height": 768}],
          "missed": [{"tick": 7, "reason": "no frame within 5s"}]}}
```

What `status` means:

- **`failed`** — there are no frames at all, and `status_reason` says why: no
  VNC port, or every tick refused.
- **`partial`** — the strip was cut short by a cap, or some ticks have no
  frame.
- **`complete`** — every tick has its frame.

The other fields:

- **`marks`** give the offsets at which DRAKVUF was started and returned, so
  the report can show where the sample ran.
- **`t` and `ms`** are each frame's real offset and capture time. They are
  the measurement of what capture costs, which DRAFT-050 never scoped.

### 1.6 Lifetime, and the property collection depends on

A capture starts the moment the clone exists — `stages.run`, right after the
console — so preconfig is in the strip. A guest that never got as far as
running the sample is the most useful thing a screenshot can show.

It stops **when the trace ends**, before the domain is destroyed and before
`collecting`.

**After `Capture.stop()` returns, nothing more is written into the job
directory.**

- Frames are written to a temporary file outside the job directory and
  renamed into place while holding a lock.
- `stop()` joins the thread for at most the frame deadline plus 2 s. It then
  sets `closed` under that lock, so a grab still in flight discards its frame.

This matters because `_collect` declares each file's size before uploading
it. A frame landing after that would break the presigned
`content-length-range`, and the upload refusal would fail the whole job.

**Capture never fails an analysis.**

- If no console can be found, the capture is marked unavailable, and its
  `stop()` writes a `failed` index naming why. The report then says "no
  console" rather than showing an empty strip that reads as a screen on which
  nothing happened.
- An exception on the capture thread ends the strip with a reason. It never
  reaches the stage machine.

### 1.7 Bounds

| Bound | Value | Why |
|---|---|---|
| Interval | 2 s (`config.SCREENSHOT_INTERVAL`) | the draft's figure |
| Frames | 450 ticks (`SCREENSHOT_MAX_FRAMES`) | 15 minutes; the trace timeout is under 600 s |
| Bytes | 256 MiB (`SCREENSHOT_MAX_BYTES`) | a guest drawing noise must never be what pushes a job past #37's 4 GiB budget, where a 413 fails it |
| Artifacts | uploaded **last** (`stages._collect`) | the artifact cap or `COLLECT_BUDGET` drops frames, never the trace |

A desktop frame is tens to hundreds of KiB, so a typical run is single-digit
megabytes.

`stages.MAX_ARTIFACTS` was lowered from 2048 to the platform's 1024 in the
same change. A run with between 1025 and 2048 files used to get a 422 at
`/complete` and stick in `cleaning`, and 450 frames made that reachable.

### 1.8 Switching it off

Capture is **on by default** (the operator's decision, 2026-10-30).
`SANDBOXD_SCREENSHOTS_ENABLED=0` turns it off on a host; `false`, `no` and
`off` also work.

Unlike the console it opens nothing toward the platform, so the console's
fail-closed parse does not apply: only a recognised "off" value disables it.

---

## 2. The viewer

The **Screenshots** tab sits second, after Overview, on every guest
(`catalogue._ALWAYS`). It is filled, and badged with a count, when the
manifest names frames.

### 2.1 What it shows

The layout is in the manner of Any.run:

- **One large frame** in a fixed 4:3 stage. It is sized by the page, never by
  the frame, so a guest that changes resolution cannot move the page under
  the reader.
- **Controls under the frame:**
  - previous, play/pause and next;
  - an elapsed clock (`0:16 / 0:58`);
  - a marker chip on the frames where the sample was launched and where the
    trace ended (the index's `marks`);
  - a per-frame download link.
- **The whole run below**, as a horizontally scrolling line of thumbnails.
  The current one is outlined, and the marked ones are dashed.

**Playback is real time, because nothing was dropped.**
`ui/static/filmstrip.js` waits `(next tick − this tick) × interval` before
each step. A tick that has no frame therefore holds the previous frame for
the time it really covered; it is never compressed away. There is no
encoding and no video: the frames already on the page are swapped in place.

Arrow keys step through the frames and space plays.

**A strip swapped out by htmx stops its own timer.**
`test_ui_browser.py::test_leaving_the_tab_stops_playback` counts timers to
prove it.

**Without the script**, the large frame and every thumbnail are plain links
to the image. The step and play buttons are drawn only once the script has
marked `<html>` — the `disclose.js` pattern.

**Which frames exist is the manifest's word, and timing is the index's.**
`platform/sandbox_platform/screenshots.py` offers a frame only if the
manifest lists it, and only if its name is `screenshots/<digits>.png`. It
sorts frames by the number, not the string. With no readable index the frames
are labelled by tick (`#7`) and played at 2 s each, and the tab says so.
A `partial` or `failed` index puts its `status_reason` on the tab.

The empty states follow the Artifacts tab's ladder:

- expired;
- no manifest;
- capture failed, with the reason;
- the index could not be read;
- the host takes no screenshots;
- the run ended without uploading;
- not collected yet.

### 2.2 How frames reach the page — the one raw artifact

**Every other artifact leaves this platform wrapped in a ZIP, and an `<img>`
cannot load a ZIP.** So frames are served by
`GET /api/v1/jobs/{id}/screenshot?name=`. It is a narrow, documented
exception to "artifacts leave wrapped, never raw" (operator, 2026-10-30), and
it is shaped so that a PNG is all it can ever hand over:

- **Tenancy, retention and the manifest come first** — `_for_download`, the
  same gate as the download routes.
- **Only a name that is a frame AND is declared** in the manifest is served.
  A key is never built from the query string.
- **The bytes must begin with the PNG signature**, checked before anything is
  sent. Anything else is a 415 and a log line.
- **The response headers:**
  - `image/png`;
  - `X-Content-Type-Options: nosniff`;
  - `Content-Security-Policy: default-src 'none'; sandbox`;
  - `Cross-Origin-Resource-Policy: same-origin`;
  - `Content-Disposition: inline; filename="NNN.png"`, built from the tick and
    never from the name;
  - `Cache-Control: private, max-age=86400, immutable`.
- **Frames over 32 MiB are not shown inline.** sandboxd cannot write one that
  large.

**Downloading a frame is still wrapped.** The tab's "download this frame" is
`artifact.zip`, like every other artifact. Showing a frame is the exception;
handing over the file is not.

**There is no `data:` or `blob:` URL anywhere**, unlike the upstream
`generate_html_report.py` this replaces. A future `img-src 'self'` CSP holds.

## 3. Security

- **Frames are the most casually shareable artifact.** A ransom note may carry
  a victim identifier or a wallet address. A published job (`visibility =
  'public'`) exposes its frames exactly as it exposes every other artifact.
  DRAFT-022's concern applies.
- **The client parses guest-influenced input** — the resolution and the pixel
  stream, by way of QEMU. That is why everything in §1.3 is bounded and
  refused rather than negotiated.
- **Nothing here listens.** The console stays on `127.0.0.1` and capture dials
  it locally. Exposing the console is DRAFT-056's problem and threat model,
  not this one's.
