"""Password-protected ZIP packaging for artifact downloads.

The artifacts tab has told operators since #38 that executable artifacts
download as a ZIP with the password `infected`. Nothing implemented that until
2026-08-27: the link was a presigned GET for the raw object, so an analyst
clicking a file recovered from `extracted/` received a live, unwrapped
executable while reading a sentence that said it was inert. This module is that
sentence made true.

**What the password is for, stated plainly: it is NOT confidentiality.**
`infected` is a published convention rather than a secret -- MalwareBazaar,
VirusShare and every sample exchange use it. What wrapping buys is that the
bytes on the wire are not the bytes of an executable: the browser will not run
it, the OS will not decorate it, and the scanner in between will not quarantine
the download or the mailbox it passed through. Anyone who can reach the link
can still open the archive. That is the intended property, not a shortfall in
it.

**Written by stream-zip, as AES-256 (WinZip AE-2), since 2026-11-14
(operator).** Until then this module wrote the format by hand -- local
headers, data descriptors, the central directory, Zip64 escapes, ZipCrypto --
in some 340 lines, three of whose Zip64 off-by-ones its own docstring had to
record. The library writes all of it, and the cipher runs in C through
pycryptodome where ZipCrypto was a per-byte loop in Python.

The cost, which the Artifacts tab states: Windows Explorer, macOS Archive
Utility and Info-ZIP `unzip` open ZipCrypto and not AES. 7-Zip, WinRAR, The
Unarchiver and `7z` open both. Since the password protects nothing, the
cipher was chosen for neither strength nor secrecy; ZipCrypto's one advantage
was those three tools, traded for a maintained writer.

**Streamed, never written to disk and never held whole in memory**, for the
reason `objects.inspect` gives about samples: this is the one machine whose
security argument rests on not handling malware, and it holds the database and
object-store credentials. stream-zip takes an iterable of chunks per member
and yields the archive as it goes, so nothing is materialised, and an
abandoned download stops pulling from the store.

pycryptodome 4.x warns (DeprecationWarning) on stream-zip's key derivation:
PBKDF2-HMAC-SHA1 at 1000 rounds is what AE-2 specifies, not a choice made
here. requirements.in says why its pin must move deliberately.

**Every entry is ZIP_64**: deflated, with Zip64 sizes in its local header and
data descriptor, so an artifact of any size wraps in one pass -- the size is
not known before the bytes are read, which is what capped one entry at 4 GiB
under the hand-written writer (`EntryTooLarge`, gone). Deflate at level 1:
throughput over ratio, as before.
"""

from __future__ import annotations

import stat
import zlib
from collections.abc import Iterable, Iterator
from datetime import datetime

from stream_zip import ZIP_64, stream_zip

# The convention. Not a secret -- see the module docstring.
PASSWORD = "infected"

# A regular file, read-only for its owner, as it unpacks
_MODE = stat.S_IFREG | 0o600

# Deflate level 1: what it removes is removed cheaply, and level 9 would spend
# far more time to save a little more of what is already a fraction (trace
# logs, memory dumps and pcaps all compress heavily).
_COMPRESSION_LEVEL = 1


def _compressobj():
    return zlib.compressobj(wbits=-zlib.MAX_WBITS, level=_COMPRESSION_LEVEL)


def stream(entries: Iterable[tuple[str, Iterable[bytes]]],
           password: str = PASSWORD,
           when: datetime | None = None) -> Iterator[bytes]:
    """Yield a password-protected ZIP of `entries`, one chunk at a time.

    Each entry is `(name, chunks)`, where `chunks` is any iterable of bytes --
    typically `objects.chunks` over one stored artifact. Nothing is read until
    the consumer asks for the next chunk, so an abandoned download stops
    fetching from the object store rather than finishing on its own.
    """
    when = when or datetime.now()
    return stream_zip(((name, when, _MODE, ZIP_64, chunks) for name, chunks in entries),
                      get_compressobj=_compressobj, password=password)
