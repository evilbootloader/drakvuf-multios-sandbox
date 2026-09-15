"""The password-protected ZIP wrapper (`packaging.py`).

Every test here decrypts with the STDLIB `zipfile`, deliberately. The module
writes an archive format by hand, and the only claim worth making about it is
that a reader nobody on this project wrote can open it -- an assertion against
our own parser would pass just as happily on a format only we understand.
"""

from __future__ import annotations

import io
import os
import struct
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


# --- the central directory -------------------------------------------------
#
# An archive only reaches a >4 GiB entry offset by actually containing 4 GiB,
# which no test is going to stream. `_central_record` is pure and takes the
# offset as an argument for exactly that reason, so the escape path is reachable
# with a synthetic number. What these cannot cover is a real reader opening a
# real oversized archive; the round-trip tests above do that for the common path.

_CENTRAL_FIXED = 46  # bytes before the name: the record minus its variable tail


def decoded_central(offset: int, name: str = "memdump/0x1000.dmp") -> dict:
    """`_central_record` unpacked back into the fields this file asserts on."""
    raw = packaging._central_record(
        name, 0x0809, 0x4321, 0x5678, 0xDEADBEEF, 1234, 5678, offset)

    (sig, _made_by, needed, _flags, _method, _time, _date, _crc,
     _compressed, _uncompressed, name_len, extra_len, _comment_len, _disk,
     _internal, _external, stored_offset) = struct.unpack(
        "<IHHHHHHIIIHHHHHII", raw[:_CENTRAL_FIXED])

    assert sig == packaging._SIG_CENTRAL
    return {
        "version_needed": needed,
        "declared_extra_len": extra_len,
        "stored_offset": stored_offset,
        "name": raw[_CENTRAL_FIXED:_CENTRAL_FIXED + name_len],
        "extra": raw[_CENTRAL_FIXED + name_len:],
    }


def test_an_ordinary_offset_carries_no_extra_field():
    """The common case, pinned so the Zip64 path cannot regress it: a normal
    archive is byte-for-byte what it was before any of this existed."""
    record = decoded_central(0x1000)

    assert record["stored_offset"] == 0x1000
    assert record["version_needed"] == 20
    assert record["declared_extra_len"] == 0
    assert record["extra"] == b""
    assert record["name"] == b"memdump/0x1000.dmp"


def test_an_offset_past_4_gib_escapes_into_a_zip64_extra_field():
    """The bug this replaces wrote the 0xFFFFFFFF escape with a hard-coded
    extra-field length of 0, so a reader found the marker with nothing to
    resolve it against and the whole central directory was unreadable."""
    offset = 0x1_0000_0000 + 4242  # 4 GiB and change, never actually streamed

    record = decoded_central(offset)

    # The 32-bit field holds the escape, not a truncated offset.
    assert record["stored_offset"] == 0xFFFFFFFF

    # The declared length matches the bytes actually appended. This is the
    # assertion the old code failed.
    assert record["declared_extra_len"] == len(record["extra"])
    assert record["declared_extra_len"] != 0

    header_id, payload_len = struct.unpack("<HH", record["extra"][:4])
    assert header_id == 0x0001
    assert payload_len == len(record["extra"]) - 4

    # Payload is the offset ALONE -- `_MAX_ENTRY` refuses any entry whose sizes
    # would need escaping, so the two size fields that would otherwise precede
    # it in the fixed order are absent.
    assert payload_len == 8
    assert struct.unpack("<Q", record["extra"][4:])[0] == offset

    # A reader that cannot do Zip64 must be told to refuse rather than misparse.
    assert record["version_needed"] == 45


def test_the_escape_value_itself_is_escaped():
    """0xFFFFFFFF is the marker, so an offset of exactly that cannot be written
    literally -- a reader would look for the extra field either way."""
    record = decoded_central(0xFFFFFFFF)

    assert record["stored_offset"] == 0xFFFFFFFF
    assert record["version_needed"] == 45
    assert struct.unpack("<Q", record["extra"][4:])[0] == 0xFFFFFFFF


@pytest.mark.parametrize("count, offset, size", [
    (packaging._U16, 0x1000, 0x1000),          # exactly 65,535 entries
    (2, packaging._U32, 0x1000),               # directory at exactly 4 GiB
    (2, 0x1000, packaging._U32),               # directory exactly 4 GiB long
])
def test_a_value_sitting_on_its_escape_marker_forces_eocd64(count, offset, size):
    """The archive-level twin of `test_the_escape_value_itself_is_escaped`.

    The plain EOCD writes each of these through `min(value, escape)`, so a value
    EQUAL to its marker is written as the marker. `>` would emit no EOCD64
    record behind it and the directory would be unreadable -- the same defect
    the per-entry extra field fixes, one level up.

    `count` is the arm with no backstop: a 4 GiB directory implies some entry
    was past 4 GiB and `forced` covers it, but 65,535 small entries reach the
    count with every offset still inside 32 bits.
    """
    assert packaging._needs_eocd64(count, offset, size, forced=False)


def test_ordinary_totals_need_no_eocd64():
    """One below each marker, so the boundary is pinned from both sides."""
    assert not packaging._needs_eocd64(
        packaging._U16 - 1, packaging._U32 - 1, packaging._U32 - 1,
        forced=False)


def test_an_escaped_entry_forces_eocd64_on_its_own():
    """`forced` is the entry-level decision arriving here, and is not a
    threshold: an entry that escaped its offset needs these records too."""
    assert packaging._needs_eocd64(1, 0, 0, forced=True)


def test_real_archives_still_take_the_ordinary_path():
    """Nothing a normal download produces should be emitting Zip64 per entry."""
    blob = build({"trace.log": b"syscall openat\n" * 1000,
                  "capture.pcap": os.urandom(2048)})

    for info in opened(blob).infolist():
        assert info.header_offset < 0xFFFFFFFF
        assert info.extra == b""
        assert info.extract_version == 20


# --- the guard -------------------------------------------------------------

def test_an_entry_too_large_for_one_pass_is_refused(monkeypatch):
    """Zip64 in a local header needs the compressed size before the bytes are
    written, which a single pass cannot know. `max_artifact_bytes` defaults to
    2 GiB, so this guards a reconfigured deployment rather than a normal run."""
    monkeypatch.setattr(packaging, "_MAX_ENTRY", 16)

    with pytest.raises(packaging.EntryTooLarge, match="single pass"):
        build({"huge.dmp": b"x" * 64}, chunk=8)
