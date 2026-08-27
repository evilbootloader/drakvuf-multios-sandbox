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
  - Zip64 appears only in the end-of-central-directory records, and only when
    the archive actually needs it. A single entry over 4 GiB is refused instead
    (`EntryTooLarge`); `max_artifact_bytes` defaults to 2 GiB, so that is a
    guard against a reconfigured deployment rather than a routine path.
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

        if entry_offset > _U32:
            # The entry itself fits in 32 bits; where it SITS does not, which
            # only the central directory has to express.
            needs_zip64 = True

        central.append(struct.pack(
            "<IHHHHHHIIIHHHHHII", _SIG_CENTRAL, 20, 20, flags, _DEFLATED,
            dos_time, dos_date, crc, compressed, uncompressed,
            len(raw_name), 0, 0, 0, 0, 0,
            min(entry_offset, _U32),
        ) + raw_name)

    directory_offset = offset
    directory = b"".join(central)
    yield directory

    if (needs_zip64 or len(central) > _U16
            or directory_offset > _U32 or len(directory) > _U32):
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
