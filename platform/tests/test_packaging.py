"""The password-protected ZIP wrapper (`packaging.py`).

Every test here decrypts with the STDLIB `zipfile`, deliberately. The module
writes an archive format by hand, and the only claim worth making about it is
that a reader nobody on this project wrote can open it -- an assertion against
our own parser would pass just as happily on a format only we understand.
"""

from __future__ import annotations

import io
import os
import zipfile

import pytest

from sandbox_platform import packaging


def build(files: dict[str, bytes], chunk: int = 8192) -> bytes:
    """Run the writer the way the route does: one chunk at a time."""
    def chunks(blob: bytes):
        if not blob:
            yield b""
            return
        for i in range(0, len(blob), chunk):
            yield blob[i:i + chunk]

    return b"".join(
        packaging.stream([(name, chunks(blob)) for name, blob in files.items()])
    )


def opened(blob: bytes, password: bytes = packaging.PASSWORD) -> zipfile.ZipFile:
    archive = zipfile.ZipFile(io.BytesIO(blob))
    archive.setpassword(password)
    return archive


# --- the format ------------------------------------------------------------

def test_a_written_archive_round_trips_through_the_stdlib():
    """The whole point: a reader we did not write opens it and gets the bytes
    back exactly."""
    files = {
        "trace.log": b"syscall openat\n" * 5000,
        "memdump/0x1000.dmp": os.urandom(70000),
        "extracted/evil.exe": b"MZ" + os.urandom(4096),
        "capture.pcap": os.urandom(3),
    }

    archive = opened(build(files))

    assert archive.testzip() is None
    assert set(archive.namelist()) == set(files)
    for name, expected in files.items():
        assert archive.read(name) == expected


def test_an_empty_artifact_survives():
    """A zero-byte file is a legitimate result -- `trace.log` at 0 bytes is
    exactly what the trace-note path records."""
    archive = opened(build({"trace.log": b""}))

    assert archive.read("trace.log") == b""


def test_the_archive_is_actually_encrypted():
    """Without the password the stdlib refuses, which is the property that
    stops a browser, an OS or a scanner acting on the contents."""
    blob = build({"extracted/evil.exe": b"MZ" + b"\x90" * 1024})

    with pytest.raises(RuntimeError, match="password required"):
        zipfile.ZipFile(io.BytesIO(blob)).read("extracted/evil.exe")

    with pytest.raises(RuntimeError):
        opened(blob, b"wrong").read("extracted/evil.exe")


def test_the_executable_bytes_do_not_appear_in_the_stream():
    """The reason for wrapping at all. If the MZ header survived into the
    download, every scanner between here and the analyst would still see it."""
    payload = b"MZ" + b"This program cannot be run in DOS mode" * 40

    blob = build({"extracted/evil.exe": payload})

    assert payload not in blob
    assert b"This program cannot be run in DOS mode" not in blob


def test_hostile_filenames_are_carried_verbatim():
    """`sample_name_admissible` lets quotes, `$` and `;` through, and the
    manifest validator has already refused anything that escapes the prefix.
    Nothing here re-parses a name, so nothing here can be confused by one."""
    name = 'weird; $(id) `x` "q".txt'

    archive = opened(build({name: b"edge case"}))

    assert archive.read(name) == b"edge case"


def test_names_are_written_as_utf8():
    archive = opened(build({"报告.log": b"ok"}))

    assert archive.read("报告.log") == b"ok"
    assert archive.getinfo("报告.log").flag_bits & 0x800


# --- the guard -------------------------------------------------------------

def test_an_entry_too_large_for_one_pass_is_refused(monkeypatch):
    """Zip64 in a local header needs the compressed size before the bytes are
    written, which a single pass cannot know. `max_artifact_bytes` defaults to
    2 GiB, so this guards a reconfigured deployment rather than a normal run."""
    monkeypatch.setattr(packaging, "_MAX_ENTRY", 16)

    with pytest.raises(packaging.EntryTooLarge, match="single pass"):
        build({"huge.dmp": b"x" * 64}, chunk=8)
