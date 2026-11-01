"""The Screenshots tab and the image route behind it: DRAFT-054.

Three layers. The index reader is pure and is driven directly. The route is
the one place an artifact leaves this platform unwrapped, so it is driven end
to end against real objects in the bucket, hostile ones included. The tab is
read as HTML; whether anything in it EXECUTES is test_ui_browser.py's
question.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import uuid
import zlib

import pytest
from conftest import owner_id

from sandbox_platform import screenshots as SS

INTERVAL = 2.0


def png(width: int = 2, height: int = 1) -> bytes:
    """A real, tiny RGB PNG."""
    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))
    raw = b"".join(b"\x00" + b"\x10\x20\x30" * width for _ in range(height))
    return (SS.PNG_SIGNATURE
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw))
            + chunk(b"IEND", b""))


def index_doc(job_id, *, status="complete", reason=None, interval=INTERVAL,
              marks=None, frames=(), missed=()) -> dict:
    """The shape sandboxd/screenshots.py writes."""
    return {
        "schema": "sandbox.screenshots/1", "job_id": str(job_id),
        "produced_at": "2026-10-30T10:00:00+00:00",
        "producer": {"name": "sandboxd", "version": "1"},
        "status": status, "status_reason": reason,
        "data": {"interval_s": interval, "started_at": "2026-10-30T09:58:00+00:00",
                 "ticks": max([*frames, *[m for m, _ in missed], -1]) + 1,
                 "marks": marks or {},
                 "frames": [{"tick": t, "t": t * interval, "ms": 40,
                             "bytes": 100, "width": 2, "height": 1}
                            for t in frames],
                 "missed": [{"tick": t, "reason": r} for t, r in missed]},
    }


def job_with(conn, put_object, objects: dict[str, bytes], *,
             state="completed", target_os="ubuntu",
             owner="fixture-owner@example.test", job_id=None) -> uuid.UUID:
    """A job whose manifest declares exactly `objects`, each in the bucket."""
    job_id = job_id or uuid.uuid4()
    artifacts = [{"name": n, "size_bytes": len(b),
                  "sha256": hashlib.sha256(b).hexdigest()}
                 for n, b in objects.items()]
    documents = [n for n in objects if n == SS.INDEX_NAME]
    manifest = {"schema_version": 1, "truncated": False,
                "documents": documents, "artifacts": artifacts}
    conn.execute(
        """
        INSERT INTO jobs (id, target_os, submitted_filename, state, sha256,
                          size_bytes, detected_type, owner, manifest)
        VALUES (%s, %s, 'x.bin', %s, 'af9c4ea0', 19, 'ELF', %s, %s)
        """,
        (job_id, target_os, state, owner_id(conn, owner), json.dumps(manifest)),
    )
    for name, body in objects.items():
        put_object(f"results/{job_id}/{name}", body)
    SS._load.cache_clear()
    return job_id


def filmstrip(conn, put_object, ticks, *, index=True, **index_kw):
    """A completed job with a frame at each tick and, unless told otherwise,
    the index sandboxd would have written beside them."""
    job_id = uuid.uuid4()
    objects = {f"screenshots/{t:03d}.png": png() for t in ticks}
    if index:
        doc = index_doc(job_id, frames=ticks, **index_kw)
        objects[SS.INDEX_NAME] = json.dumps(doc).encode()
    return job_with(conn, put_object, objects, job_id=job_id)


# --- what is a frame --------------------------------------------------------

@pytest.mark.parametrize("name, tick", [
    ("screenshots/000.png", 0),
    ("screenshots/449.png", 449),
    ("screenshots/1000.png", 1000),
    ("screenshots/12.png", None),
    ("screenshots/../000.png", None),
    ("screenshots/000.png.exe", None),
    ("screenshots/sub/000.png", None),
    ("extracted/000.png", None),
    ("screenshots/<img src=x onerror=alert(1)>.png", None),
])
def test_only_screenshots_digits_png_is_a_frame(name, tick):
    assert SS.frame_tick(name) == tick


# --- the index ----------------------------------------------------------------

def test_the_index_sandboxd_writes_is_read():
    doc = index_doc(uuid.uuid4(), status="partial", reason="1 of 3 ticks",
                    marks={"trace_start": 14.0, "trace_end": 30.0,
                           "elsewhere": 1.0},
                    frames=[0, 2], missed=[(1, "timeout")])
    loaded = SS.parse_index(json.dumps(doc).encode())

    assert loaded.error is None
    assert loaded.index.status == "partial"
    assert loaded.index.interval == INTERVAL
    assert loaded.index.missed == 1
    assert loaded.index.marks == {"trace_start": 14.0, "trace_end": 30.0}


@pytest.mark.parametrize("raw, fragment", [
    (b"not json", "not JSON"),
    (json.dumps({"schema": "sandbox.screenshots/1"}).encode(),
     "not a capability document"),
    (json.dumps({**index_doc(uuid.uuid4()), "schema": "sandbox.capa/1"}).encode(),
     "sandbox.capa/1"),
    (json.dumps(index_doc(uuid.uuid4(), interval=0)).encode(), "interval_s"),
])
def test_an_unusable_index_gets_a_sentence(raw, fragment):
    loaded = SS.parse_index(raw)
    assert loaded.index is None
    assert fragment in loaded.error


# --- the route: the one artifact served raw ---------------------------------

def test_a_frame_is_served_as_an_image(client, conn, put_object):
    frame = png()
    job_id = job_with(conn, put_object, {"screenshots/003.png": frame})

    r = client.get(f"/api/v1/jobs/{job_id}/screenshot",
                   params={"name": "screenshots/003.png"})

    assert r.status_code == 200
    assert r.content == frame
    assert r.headers["content-type"] == "image/png"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["content-security-policy"] == "default-src 'none'; sandbox"
    assert r.headers["cross-origin-resource-policy"] == "same-origin"
    assert r.headers["content-disposition"] == 'inline; filename="003.png"'


def test_only_declared_frames_are_served(client, conn, put_object):
    """**The name resolves against the manifest AND must be a frame.** Either
    alone is not enough: a declared executable is not a frame, and a
    frame-shaped name the manifest never declared is not this run's."""
    job_id = job_with(conn, put_object, {
        "screenshots/000.png": png(),
        "extracted/001.png": png(),           # declared, PNG, not a frame
        "trace.stderr": b"text"})
    put_object(f"results/{job_id}/screenshots/001.png", png())   # undeclared

    for name in ("extracted/001.png", "screenshots/001.png", "trace.stderr",
                 "screenshots/../extracted/001.png", "../screenshots/000.png"):
        r = client.get(f"/api/v1/jobs/{job_id}/screenshot",
                       params={"name": name})
        assert r.status_code == 404, name


def test_bytes_that_are_not_a_png_are_refused(client, conn, put_object):
    """A frame-shaped name declared by a broken -- or not our -- worker, over
    bytes a browser could be talked into treating as something else."""
    job_id = job_with(conn, put_object, {
        "screenshots/000.png": b"<html><script>alert(1)</script>"})

    r = client.get(f"/api/v1/jobs/{job_id}/screenshot",
                   params={"name": "screenshots/000.png"})

    assert r.status_code == 415
    assert b"<script>" not in r.content


def test_an_expired_job_refuses_frames(client, conn, put_object):
    job_id = job_with(conn, put_object, {"screenshots/000.png": png()})
    conn.execute("UPDATE jobs SET created_at = now() - interval '45 days'"
                 " WHERE id = %s", (job_id,))

    r = client.get(f"/api/v1/jobs/{job_id}/screenshot",
                   params={"name": "screenshots/000.png"})
    assert r.status_code == 410


def test_another_tenants_frames_are_not_found(client, conn, put_object):
    job_id = job_with(conn, put_object, {"screenshots/000.png": png()},
                      owner="someone-else@example.test")

    r = client.get(f"/api/v1/jobs/{job_id}/screenshot",
                   params={"name": "screenshots/000.png"})
    assert r.status_code == 404


def test_a_frame_still_downloads_wrapped(client, conn, put_object):
    """Displaying is the exception; handing over the file is not."""
    job_id = job_with(conn, put_object, {"screenshots/000.png": png()})

    detail = client.get(f"/api/v1/jobs/{job_id}").json()
    assert detail["artifacts"]["screenshots/000.png"].startswith(
        f"/api/v1/jobs/{job_id}/artifact.zip?name=")


# --- the tab -----------------------------------------------------------------

@pytest.mark.parametrize("target_os", ["ubuntu", "android", "windows"])
def test_every_guest_has_the_tab(client, conn, put_object, target_os):
    """All three guests are desktops, and capture needs no plugin."""
    job_id = job_with(conn, put_object, {}, target_os=target_os)
    assert ">Screenshots<" in client.get(f"/ui/jobs/{job_id}").text


def test_frames_fill_the_tab_and_count_on_it(client, conn, put_object):
    job_id = filmstrip(conn, put_object, [0, 1, 2])

    page = client.get(f"/ui/jobs/{job_id}").text
    tab = page.split('?tab=screenshots"', 1)[1].split("</a>", 1)[0]

    assert "data-empty" not in tab
    assert '<span class="n"> 3</span>' in tab


def test_no_frames_leaves_the_tab_dimmed(client, conn, put_object):
    job_id = job_with(conn, put_object, {"trace.stderr": b""})

    page = client.get(f"/ui/jobs/{job_id}").text
    tab = page.split('?tab=screenshots"', 1)[1].split("</a>", 1)[0]
    assert "data-empty" in tab


def test_the_strip_is_in_tick_order_with_elapsed_time(client, conn, put_object):
    """Numeric, not lexical: `1000.png` sorts before `999.png` as a string."""
    job_id = filmstrip(conn, put_object, [999, 7, 1000],
                       marks={"trace_start": 13.0})

    page = client.get(f"/ui/jobs/{job_id}?tab=screenshots").text

    ticks = [int(t) for t in re.findall(r'data-tick="(\d+)"', page)]
    assert ticks == [7, 999, 1000]
    assert ">0:14<" in page                # tick 7 at 2 s
    assert "33:18" in page                 # tick 999
    # The first frame at or after the trace started is marked.
    assert 'data-tick="7"' in page and "sample started" in page


def test_frames_are_shown_through_the_image_route_and_downloaded_wrapped(
        client, conn, put_object):
    job_id = filmstrip(conn, put_object, [0])

    page = client.get(f"/ui/jobs/{job_id}?tab=screenshots").text

    assert f'src="/api/v1/jobs/{job_id}/screenshot?name=screenshots%2F000.png"' in page
    assert f"/api/v1/jobs/{job_id}/artifact.zip?name=screenshots%2F000.png" in page
    assert "infected" in page


def test_the_player_script_is_loaded_with_a_cache_key(client, conn, put_object):
    job_id = filmstrip(conn, put_object, [0])
    assert "filmstrip.js?v=" in client.get(f"/ui/jobs/{job_id}").text


def test_the_interval_reaches_the_player(client, conn, put_object):
    job_id = filmstrip(conn, put_object, [0, 1], interval=0.5)
    page = client.get(f"/ui/jobs/{job_id}?tab=screenshots").text
    assert 'data-interval-ms="500"' in page


def test_a_partial_strip_says_why(client, conn, put_object):
    job_id = filmstrip(conn, put_object, [0, 2], status="partial",
                       reason="stopped at the frame cap of 450 (900s)")
    page = client.get(f"/ui/jobs/{job_id}?tab=screenshots").text
    assert "Partial strip." in page
    assert "stopped at the frame cap" in page


def test_frames_without_an_index_are_numbered_not_timed(client, conn,
                                                        put_object):
    job_id = filmstrip(conn, put_object, [0, 3], index=False)
    page = client.get(f"/ui/jobs/{job_id}?tab=screenshots").text
    assert ">#3<" in page
    assert "no screenshot index" in page


# --- the tab's empty states ---------------------------------------------------

def test_a_capture_that_took_nothing_says_why(client, conn, put_object):
    """The worker's reason is shown -- and it is text a worker wrote, so it is
    escaped like everything else."""
    job_id = uuid.uuid4()
    doc = index_doc(job_id, status="failed",
                    reason="no console to capture: <script>alert(1)</script>")
    job_with(conn, put_object, {SS.INDEX_NAME: json.dumps(doc).encode()},
             job_id=job_id)

    page = client.get(f"/ui/jobs/{job_id}?tab=screenshots").text

    assert "No screenshots were taken." in page
    assert "no console to capture" in page
    assert "<script>alert(1)" not in page


def test_a_completed_run_with_no_capture_says_so(client, conn, put_object):
    job_id = job_with(conn, put_object, {"trace.stderr": b""})
    page = client.get(f"/ui/jobs/{job_id}?tab=screenshots").text
    assert "This run has no screenshots." in page
    assert "SANDBOXD_SCREENSHOTS_ENABLED" in page


def test_a_running_job_has_nothing_yet(client, conn, put_object):
    job_id = job_with(conn, put_object, {}, state="executing")
    page = client.get(f"/ui/jobs/{job_id}?tab=screenshots").text
    assert "Not collected yet." in page


def test_expired_frames_say_so(client, conn, put_object):
    job_id = filmstrip(conn, put_object, [0])
    conn.execute("UPDATE jobs SET created_at = now() - interval '45 days'"
                 " WHERE id = %s", (job_id,))
    page = client.get(f"/ui/jobs/{job_id}?tab=screenshots").text
    assert "Screenshots have expired." in page
