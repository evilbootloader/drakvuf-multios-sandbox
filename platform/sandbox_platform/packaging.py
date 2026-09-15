"""Password-protected ZIP packaging for artifact downloads.

The artifacts tab has told operators since #38 that "executable artifacts
download as ZIP with the password `infected`". Nothing implemented that until
2026-08-27: the link was a presigned GET for the raw object, so an analyst
clicking a file recovered from `extracted/` received a live, unwrapped
executable while reading a sentence that said it was inert. This module is that
sentence made true.

**What the password is for, stated plainly: it is NOT confidentiality.**
ZipCrypto is weak and trivially broken, and `infected` is a published
convention rather than a secret -- MalwareBazaar, VirusShare and every sample
exchange use it. What wrapping buys is that the bytes on the wire are not the
bytes of an executable: the browser will not run it, the OS will not decorate
it, and the scanner in between will not quarantine the download or the mailbox
it passed through. Anyone who can reach the link can still open the archive.
That is the intended property, not a shortfall in it.

**ZipCrypto rather than AES.** pyzipper would give AES-256 and a C
implementation, but an AES ZIP does not open in Windows Explorer or macOS
Archive Utility -- only in 7-Zip and friends. "The convention every analyst and
tool expects" is the compatible one, and since the password is not protecting
anything, the stronger cipher buys nothing to trade compatibility for.

**Streamed, never written to disk and never held whole in memory**, for the
reason `objects.inspect` gives about samples: this is the one machine whose
security argument rests on not handling malware, and it holds the database and
object-store credentials. Shelling out to `zip(1)` would have been faster and
would have required materialising every artifact in a temp directory first,
which is exactly the thing that argument forbids.

The cost is that the cipher is a per-byte loop in Python. Deflate runs FIRST
for that reason as much as for size: it is C, and every byte it removes is a
byte the Python loop never sees. Trace logs, memory dumps and pcaps all
compress heavily, so the cipher usually sees a small fraction of the artifact.

Format notes, so the next reader does not have to re-derive them:

  - Data descriptors (general-purpose bit 3) carry the CRC and sizes AFTER the
    data, which is what makes single-pass streaming possible at all. With that
    bit set, the encryption header's check byte comes from the high byte of the
    DOS mod time rather than of the CRC -- the CRC is not known yet.
  - Zip64 appears wherever the format forces it and nowhere else, which is two
    places. The end-of-central-directory records get it when the archive as a
    whole outgrows the 32-bit counts. A single central-directory record gets a
    Zip64 extended-information extra field when THAT entry's local header sits
    past 4 GiB: the 32-bit offset field can then only hold the escape value
    0xFFFFFFFF, and the escape is meaningless unless the extra field carrying
    the real offset is written beside it.
  - A single entry over 4 GiB is refused instead of escaped
    (`EntryTooLarge`), because the sizes live in the LOCAL header, which is
    written before the bytes are read. `max_artifact_bytes` defaults to 2 GiB,
    so that is a guard against a reconfigured deployment rather than a routine
    path. The archive TOTAL is a different question and not guarded at all:
    `max_job_result_bytes` defaults to exactly 4 GiB, so one full-run download
    can reach the offsets that need escaping without anything being
    misconfigured.
"""

from __future__ import annotations

import os
import struct
import zlib
from collections.abc import Iterable, Iterator
from datetime import datetime

# The convention. Not a secret -- see the module docstring.
PASSWORD = b"infected"

# General-purpose bit flags.
_ENCRYPTED = 0x0001
_DATA_DESCRIPTOR = 0x0008
_UTF8_NAMES = 0x0800

_DEFLATED = 8

# Deflate level 1. The point here is throughput, not ratio: the bytes this
# removes are bytes the Python cipher loop below never has to touch, and level 9
# would spend far more time to save a little more of what is already a fraction.
_COMPRESSION_LEVEL = 1

_SIG_LOCAL = 0x04034B50
_SIG_DESCRIPTOR = 0x08074B50
_SIG_CENTRAL = 0x02014B50
_SIG_EOCD = 0x06054B50
_SIG_EOCD64 = 0x06064B50
_SIG_EOCD64_LOCATOR = 0x07064B50

# Header id of the Zip64 extended-information extra field.
_ZIP64_EXTRA_ID = 0x0001

# "Version needed to extract" values: 2.0 for a deflated entry, 4.5 for one
# that cannot be read without understanding Zip64.
_VERSION_DEFLATE = 20
_VERSION_ZIP64 = 45

# 4 GiB - 16, the largest value the 32-bit size fields can carry with room to
# spare. An entry above this would need zip64 in the local header, which cannot
# be written in one pass without knowing the compressed size in advance.
_MAX_ENTRY = 0xFFFFFFF0

_U32 = 0xFFFFFFFF
_U16 = 0xFFFF


class EntryTooLarge(ValueError):
    """One artifact is too large to wrap in a single-pass archive."""


def _crc_table() -> list[int]:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
        table.append(c)
    return table


_TABLE = _crc_table()


class _ZipCrypto:
    """PKWARE's traditional stream cipher, as ZIP defines it.

    Three 32-bit keys seeded from the password, then advanced by every
    PLAINTEXT byte -- which is what makes this inherently sequential and why it
    cannot be vectorised away.
    """

    def __init__(self, password: bytes):
        self._k0 = 0x12345678
        self._k1 = 0x23456789
        self._k2 = 0x34567890
        for byte in password:
            self._update(byte)

    def _update(self, byte: int) -> None:
        self._k0 = (self._k0 >> 8) ^ _TABLE[(self._k0 ^ byte) & 0xFF]
        self._k1 = ((self._k1 + (self._k0 & 0xFF)) * 134775813 + 1) & _U32
        self._k2 = (self._k2 >> 8) ^ _TABLE[(self._k2 ^ (self._k1 >> 24)) & 0xFF]

    def encrypt(self, data: bytes) -> bytes:
        # Keys and the table are bound to locals: this loop runs once per byte
        # of every artifact anyone downloads, and attribute lookups dominate it.
        k0, k1, k2 = self._k0, self._k1, self._k2
        table = _TABLE
        out = bytearray(len(data))
        for i, plain in enumerate(data):
            temp = (k2 | 2) & _U16
            out[i] = plain ^ (((temp * (temp ^ 1)) >> 8) & 0xFF)
            k0 = (k0 >> 8) ^ table[(k0 ^ plain) & 0xFF]
            k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & _U32
            k2 = (k2 >> 8) ^ table[(k2 ^ (k1 >> 24)) & 0xFF]
        self._k0, self._k1, self._k2 = k0, k1, k2
        return bytes(out)


def _dos_timestamp(when: datetime) -> tuple[int, int]:
    """(time, date) in DOS format. Years before 1980 are not representable."""
    year = max(when.year, 1980)
    dos_time = (when.hour << 11) | (when.minute << 5) | (when.second // 2)
    dos_date = ((year - 1980) << 9) | (when.month << 5) | when.day
    return dos_time, dos_date


def _offset_needs_zip64(offset: int) -> bool:
    """Whether a local-header offset has to be escaped into a Zip64 field.

    `>=`, not `>`: 0xFFFFFFFF IS the escape marker, so an offset of exactly
    that value cannot be written literally either -- a reader would go looking
    for the extra field regardless of which of the two we meant.
    """
    return offset >= _U32


def _needs_eocd64(entry_count: int, directory_offset: int,
                  directory_size: int, forced: bool) -> bool:
    """Whether the archive needs the Zip64 end-of-directory records.

    **`>=` on all three thresholds, which is the same off-by-one
    `_offset_needs_zip64` records one level down.** The plain EOCD writes each
    of these through `min(value, escape)`, so a value sitting EXACTLY on its
    escape marker -- 0xFFFF entries, a 0xFFFFFFFF directory offset or size --
    is written AS the marker whether or not it was meant as one. With `>` no
    EOCD64 record is emitted behind it, so a reader resolves the escape against
    nothing and the directory is unreadable: byte for byte the failure that
    made an unescaped entry offset unreadable.

    `forced` is the entry-level decision arriving here, and it is the only one
    of the four that is not a threshold: an entry that escaped its own offset
    needs these records too.

    **`entry_count` is the arm with no backstop**, which is why this is worth a
    predicate rather than an inline condition. A directory past 4 GiB implies
    some entry was past 4 GiB, so `forced` usually rescues the two offset arms
    in practice -- but 65,535 small entries reach the count with every offset
    still comfortably inside 32 bits, and nothing else would notice.
    """
    return (forced
            or entry_count >= _U16
            or directory_offset >= _U32
            or directory_size >= _U32)


def _central_record(name: str, flags: int, dos_time: int, dos_date: int,
                    crc: int, compressed: int, uncompressed: int,
                    offset: int) -> bytes:
    """One central-directory record, escaping the offset to Zip64 if it must.

    An offset past 4 GiB does not fit the 32-bit field, so that field carries
    the escape value 0xFFFFFFFF and the real number moves into a Zip64
    extended-information extra field (header id 0x0001). The escape is only
    meaningful WITH that field: a reader that finds 0xFFFFFFFF and no extra
    field has nothing to resolve it against, and the directory is unreadable.

    The extra field's payload holds only the values that were escaped, in the
    order the format fixes -- uncompressed size, compressed size, local-header
    offset, disk start -- with no room to say which of them are present. Here
    that payload is the offset alone, eight bytes with nothing before it,
    because `_MAX_ENTRY` refuses any entry whose sizes would need escaping and
    the disk number is always zero. That is the whole reason it is this short.

    Pure and offset-only, so the 4 GiB case is testable without writing 4 GiB.
    """
    raw_name = name.encode("utf-8")
    if _offset_needs_zip64(offset):
        extra = struct.pack("<HHQ", _ZIP64_EXTRA_ID, 8, offset)
        version_needed = _VERSION_ZIP64
        stored_offset = _U32
    else:
        extra = b""
        version_needed = _VERSION_DEFLATE
        stored_offset = offset

    return struct.pack(
        "<IHHHHHHIIIHHHHHII", _SIG_CENTRAL, _VERSION_DEFLATE, version_needed,
        flags, _DEFLATED, dos_time, dos_date, crc, compressed, uncompressed,
        len(raw_name), len(extra), 0, 0, 0, 0, stored_offset,
    ) + raw_name + extra


def stream(entries: Iterable[tuple[str, Iterable[bytes]]],
           password: bytes = PASSWORD,
           when: datetime | None = None) -> Iterator[bytes]:
    """Yield a password-protected ZIP of `entries`, one chunk at a time.

    Each entry is `(name, chunks)`, where `chunks` is any iterable of bytes --
    typically `objects._chunks` over one stored artifact. Nothing is read until
    the consumer asks for the next chunk, so an abandoned download stops
    fetching from the object store rather than finishing on its own.

    Raises `EntryTooLarge` mid-stream if an artifact exceeds what a single pass
    can describe. That is a partial response by then, which is unavoidable and
    is why the caller checks sizes from the manifest first where it can.
    """
    dos_time, dos_date = _dos_timestamp(when or datetime.now())
    flags = _ENCRYPTED | _DATA_DESCRIPTOR | _UTF8_NAMES

    central: list[bytes] = []
    offset = 0
    needs_zip64 = False

    for name, chunks in entries:
        raw_name = name.encode("utf-8")
        header = struct.pack(
            "<IHHHHHIIIHH", _SIG_LOCAL, 20, flags, _DEFLATED,
            dos_time, dos_date,
            0, 0, 0,                      # crc and sizes: in the descriptor
            len(raw_name), 0,
        ) + raw_name
        yield header
        entry_offset = offset
        offset += len(header)

        cipher = _ZipCrypto(password)
        # 11 random bytes and a check byte the reader verifies before spending
        # anything on the body. With a data descriptor the CRC is not known
        # yet, so the check byte is the high byte of the mod time instead.
        preamble = bytearray(os.urandom(11))
        preamble.append((dos_time >> 8) & 0xFF)
        encrypted = cipher.encrypt(bytes(preamble))
        yield encrypted

        compressed = len(encrypted)
        deflate = zlib.compressobj(_COMPRESSION_LEVEL, zlib.DEFLATED, -15)
        crc = 0
        uncompressed = 0

        for chunk in chunks:
            crc = zlib.crc32(chunk, crc)
            uncompressed += len(chunk)
            if uncompressed > _MAX_ENTRY:
                raise EntryTooLarge(
                    f"{name} exceeds {_MAX_ENTRY} bytes; it cannot be wrapped "
                    f"in a single pass and must be fetched on its own"
                )
            block = deflate.compress(chunk)
            if block:
                block = cipher.encrypt(block)
                compressed += len(block)
                yield block

        tail = deflate.flush()
        if tail:
            tail = cipher.encrypt(tail)
            compressed += len(tail)
            yield tail

        descriptor = struct.pack("<IIII", _SIG_DESCRIPTOR, crc,
                                 compressed, uncompressed)
        yield descriptor
        offset += compressed + len(descriptor)

        if _offset_needs_zip64(entry_offset):
            # The entry itself fits in 32 bits; where it SITS does not, which
            # only the central directory has to express -- `_central_record`
            # escapes the offset into a Zip64 extra field, and the archive as a
            # whole then needs the Zip64 end-of-directory records too.
            needs_zip64 = True

        central.append(_central_record(name, flags, dos_time, dos_date, crc,
                                       compressed, uncompressed, entry_offset))

    directory_offset = offset
    directory = b"".join(central)
    yield directory

    if _needs_eocd64(len(central), directory_offset, len(directory),
                     needs_zip64):
        # 44 is the record's own size field: everything after it.
        yield struct.pack("<IQHHIIQQQQ", _SIG_EOCD64, 44, 45, 45, 0, 0,
                          len(central), len(central),
                          len(directory), directory_offset)
        yield struct.pack("<IIQI", _SIG_EOCD64_LOCATOR, 0,
                          directory_offset + len(directory), 1)

    yield struct.pack("<IHHHHIIH", _SIG_EOCD, 0, 0,
                      min(len(central), _U16), min(len(central), _U16),
                      min(len(directory), _U32),
                      min(directory_offset, _U32), 0)
