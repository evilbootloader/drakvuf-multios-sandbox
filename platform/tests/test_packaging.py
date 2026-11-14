"""The password-protected ZIP wrapper (`packaging.py`).

Every archive here is read back by a reader this project did not write:
stream-unzip (the writer's author's, but a different code path), and 7-Zip
where it is installed -- the tool an analyst opens these with. The standard
library's `zipfile` reads ZipCrypto and not AES, which these archives are
since 2026-11-14; it is used only to read the directory, which is not
encrypted.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import zipfile

import pytest
from stream_unzip import stream_unzip

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


def opened(blob: bytes, password: str = packaging.PASSWORD) -> dict[str, bytes]:
    """Every member of the archive, decrypted and inflated, by name."""
    return {name.decode(): b"".join(body)
            for name, _size, body in stream_unzip([blob], password=password)}


FILES = {
    "trace.log": b"syscall openat\n" * 5000,
    "memdump/0x1000.dmp": os.urandom(70000),
    "extracted/evil.exe": b"MZ" + os.urandom(4096),
    "capture.pcap": os.urandom(3),
}


def test_a_written_archive_round_trips():
    """The whole point: a reader we did not write opens it and gets the bytes
    back exactly."""
    assert opened(build(FILES)) == FILES


@pytest.mark.skipif(shutil.which("7z") is None, reason="7-Zip is not installed")
def test_7zip_opens_it_with_the_password(tmp_path):
    """What an analyst runs. An AES archive does not open in Windows
    Explorer, macOS Archive Utility or Info-ZIP unzip; 7-Zip is the tool the
    Artifacts tab names."""
    archive = tmp_path / "a.zip"
    archive.write_bytes(build(FILES))
    test = subprocess.run(["7z", "t", f"-p{packaging.PASSWORD}", str(archive)],
                          capture_output=True, text=True, timeout=60)
    assert test.returncode == 0 and "Everything is Ok" in test.stdout, test.stdout + test.stderr
    out = tmp_path / "out"
    subprocess.run(["7z", "x", f"-p{packaging.PASSWORD}", f"-o{out}", str(archive)],
                   capture_output=True, check=True, timeout=60)
    for name, blob in FILES.items():
        assert (out / name).read_bytes() == blob


def test_an_empty_artifact_survives():
    """A zero-byte file is a legitimate result -- `trace.log` at 0 bytes is
    exactly what the trace-note path records."""
    assert opened(build({"trace.log": b""})) == {"trace.log": b""}


def test_the_archive_is_actually_encrypted():
    """AES-256 on every member, and a wrong password reads nothing: the
    property that stops a browser, an OS or a scanner acting on the
    contents."""
    blob = build({"extracted/evil.exe": b"MZ" + b"\x90" * 1024})
    info = zipfile.ZipFile(io.BytesIO(blob)).getinfo("extracted/evil.exe")
    assert info.flag_bits & 0x1 and info.compress_type == 99  # AE-x

    with pytest.raises(Exception):
        opened(blob, "wrong")


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

    assert opened(build({name: b"edge case"})) == {name: b"edge case"}


def test_names_are_written_as_utf8():
    blob = build({"报告.log": b"ok"})

    assert opened(blob) == {"报告.log": b"ok"}
    assert zipfile.ZipFile(io.BytesIO(blob)).getinfo("报告.log").flag_bits & 0x800


def test_nothing_is_read_before_it_is_asked_for():
    """An abandoned download stops pulling from the store: the writer takes
    an artifact's chunks only as the response asks for the archive's."""
    taken = []

    def chunks(name):
        for i in range(4):
            taken.append((name, i))
            yield os.urandom(1 << 16)

    archive = packaging.stream([(n, chunks(n)) for n in ("a", "b")])
    assert taken == []
    next(iter(archive))
    assert ("b", 0) not in taken


def test_an_entry_past_four_gib_is_not_refused_up_front():
    """Every entry is Zip64, so no artifact size is refused (the hand-written
    writer stopped at 4 GiB per entry). Shown on the header: a member's
    local header carries the Zip64 extra field before a byte is read."""
    import struct
    head = b"".join(packaging.stream([("big.dmp", iter([b"x"]))]))
    assert head[:4] == b"PK\x03\x04"
    name_len, extra_len = struct.unpack("<HH", head[26:30])
    extra, ids = head[30 + name_len:30 + name_len + extra_len], []
    while extra:
        field, size = struct.unpack("<HH", extra[:4])
        ids.append(field)
        extra = extra[4 + size:]
    assert 0x0001 in ids  # the Zip64 extended information field
