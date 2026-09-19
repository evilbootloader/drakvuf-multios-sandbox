"""Per-process log viewing: the slices of a plugin log one process produced.

`sandboxd/postprocessing/indexer.py` writes `log_index` after the split: for
every process (by `seqid`) and every `<plugin>.log`, the byte ranges of that
process's lines and the `Method` each range carries. This module reads that
index back and serves a process's lines out of the stored log with HTTP range
reads -- so a viewer over a 1.2 GB syscall.log costs the bytes of the lines
shown, not the log.

What drakvuf-sandbox does in `web/api.py::process_logs` and its LazyLog
viewer, without the JavaScript: a page of lines, a method filter, and a
"more" that asks for the next page. Paging is by offset into the VIRTUAL
stream of the selected blocks laid end to end, as upstream's `Range` is, so
a filter change starts over and a page boundary never depends on what the
other processes wrote in between.

Trust: `log_index` and the logs are artifacts sandboxd uploaded, and the
lines are the sample's. The index is validated for shape before any offset
in it is used; every read is bounded (bytes per page, range requests per
page, span size); and the lines reach the page as text through autoescape.
An index that lies about offsets gets the bytes that are there, cut where
the object ends, and nothing else.
"""

from __future__ import annotations

import io
import logging
from dataclasses import dataclass, field
from functools import lru_cache
from uuid import UUID

import msgpack

from . import manifest as manifest_schema
from . import objects

log = logging.getLogger("sandbox_platform.logview")

INDEX_NAME = "log_index"

# 2.5 MB for the 146-process, nine-plugin Windows run of 2026-09-19.
MAX_INDEX_BYTES = 32 * 1024 * 1024

# One page of lines. 48 KiB is roughly 200 syscall lines.
PAGE_BYTES = 48 * 1024
# A process's lines are interleaved with everyone else's, so its blocks are
# many and small. Adjacent blocks closer than this are fetched as one span
# and cut locally: one range request instead of dozens.
SPAN_GAP = 64 * 1024
MAX_SPAN_BYTES = 1024 * 1024
# And a page stops early rather than issue more requests than this, so the
# cost of one click is bounded whatever the index says.
MAX_REQUESTS_PER_PAGE = 32
# Blocks per entry the index may name. 5000 is many hundred pages.
MAX_BLOCKS = 200_000
MAX_METHODS = 2000


class IndexError_(Exception):
    """The index is not the shape indexer.py writes."""


@dataclass(frozen=True)
class Entry:
    """One process's slice of one plugin log."""
    blocks: tuple[tuple[int, int], ...]     # [start, end) into the log
    values: tuple[str, ...]                  # the distinct Method values
    mapping: tuple[int, ...]                 # per block, an index into values

    @property
    def total_bytes(self) -> int:
        return sum(end - start for start, end in self.blocks)

    def select(self, method: str | None) -> list[tuple[int, int]]:
        if not method:
            return list(self.blocks)
        if method not in self.values:
            return []
        wanted = self.values.index(method)
        return [b for b, m in zip(self.blocks, self.mapping) if m == wanted]


@dataclass(frozen=True)
class Index:
    toc: tuple[dict[str, int], ...]     # per seqid, plugin -> offset into blob
    blob: bytes                          # the concatenated entries

    def plugins_for(self, seqid: int) -> list[str]:
        if seqid < 0 or seqid >= len(self.toc):
            return []
        return sorted(self.toc[seqid])

    def entry(self, seqid: int, plugin: str) -> Entry | None:
        if seqid < 0 or seqid >= len(self.toc):
            return None
        offset = self.toc[seqid].get(plugin)
        if offset is None or offset < 0 or offset >= len(self.blob):
            return None
        try:
            raw = msgpack.Unpacker(io.BytesIO(self.blob[offset:]),
                                   raw=False, max_buffer_size=len(self.blob)).unpack()
            return _entry(raw)
        except (msgpack.UnpackException, ValueError, TypeError, IndexError_) as exc:
            log.warning("log_index entry for seqid %d/%s unusable: %s", seqid, plugin, exc)
            return None


def _entry(raw: object) -> Entry:
    if not isinstance(raw, dict):
        raise IndexError_("entry is not a map")
    blocks = raw.get("blocks", [])
    values = raw.get("values", [])
    mapping = raw.get("mapping", [])
    if not (isinstance(blocks, list) and isinstance(values, list)
            and isinstance(mapping, list)):
        raise IndexError_("entry fields have the wrong types")
    if len(blocks) > MAX_BLOCKS or len(values) > MAX_METHODS:
        raise IndexError_("entry is larger than this reader accepts")
    out_blocks = []
    for block in blocks:
        if (not isinstance(block, list) or len(block) != 2
                or not all(isinstance(v, int) and v >= 0 for v in block)
                or block[1] <= block[0]):
            raise IndexError_("a block is not a [start, end) pair")
        out_blocks.append((block[0], block[1]))
    if not all(isinstance(v, str) for v in values):
        raise IndexError_("a method value is not a string")
    if len(mapping) != len(out_blocks) and mapping:
        raise IndexError_("mapping and blocks disagree in length")
    if not all(isinstance(m, int) and 0 <= m < len(values) for m in mapping):
        raise IndexError_("a mapping entry points outside values")
    return Entry(tuple(out_blocks), tuple(v[:256] for v in values), tuple(mapping))


def parse_index(raw: bytes) -> Index:
    """Bytes of `log_index` to an Index, or IndexError_."""
    unpacker = msgpack.Unpacker(io.BytesIO(raw), raw=False, max_buffer_size=len(raw) or 1)
    try:
        toc = unpacker.unpack()
    except (msgpack.UnpackException, ValueError) as exc:
        raise IndexError_(f"table of contents: {exc}") from exc
    if not isinstance(toc, list):
        raise IndexError_("table of contents is not a list")
    out = []
    for row in toc:
        if not isinstance(row, dict) or not all(
                isinstance(k, str) and isinstance(v, int) and v >= 0
                for k, v in row.items()):
            raise IndexError_("a table-of-contents row is not plugin -> offset")
        out.append({k[:64]: v for k, v in row.items()})
    return Index(tuple(out), raw[unpacker.tell():])


@lru_cache(maxsize=32)
def _load(key: str, sha256: str) -> Index | None:
    out = bytearray()
    try:
        for chunk in objects.chunks(key):
            out += chunk
            if len(out) > MAX_INDEX_BYTES:
                log.warning("log_index %s is over %d bytes; not read", key, MAX_INDEX_BYTES)
                return None
        return parse_index(bytes(out))
    except IndexError_ as exc:
        log.warning("log_index %s unusable: %s", key, exc)
        return None
    except Exception as exc:  # noqa: BLE001 - a page must render without it
        log.warning("log_index %s could not be read: %s", key, exc)
        return None


@dataclass(frozen=True)
class Available:
    """What the viewer can offer for one job: the index, and which plugin
    logs the manifest actually lists (a gzipped syscall.log is listed as
    `syscall.log.gz`, which the index's offsets cannot address)."""
    index: Index | None = None
    logs: frozenset[str] = frozenset()        # plugin names with a `.log` present
    compressed: frozenset[str] = frozenset()  # plugin names present only as `.log.gz`
    key_prefix: str = ""
    job_id: UUID | None = None

    def plugins_for(self, seqid: int) -> list[str]:
        if self.index is None:
            return []
        return [p for p in self.index.plugins_for(seqid) if p in self.logs]

    def compressed_for(self, seqid: int) -> list[str]:
        """Plugin logs stored gzipped, offered as downloads. From the manifest
        alone: gzip_syscalls runs before index_logs on Dom0, so a compressed
        log has no index entry for any process."""
        return sorted(self.compressed) if self.index is not None else []


def for_job(job_id: UUID, manifest: object, key_prefix: str,
            expired: bool = False) -> Available:
    if expired:
        return Available()
    parsed = manifest_schema.parse(manifest)
    names = {a.name: a for a in parsed.artifacts}
    entry = names.get(INDEX_NAME)
    if entry is None or not entry.sha256:
        return Available()
    logs = frozenset(n[:-4] for n in names if n.endswith(".log") and "/" not in n)
    gz = frozenset(n[:-7] for n in names if n.endswith(".log.gz") and "/" not in n)
    key = objects.result_prefix(job_id, key_prefix) + INDEX_NAME
    return Available(_load(key, entry.sha256), logs, gz - logs, key_prefix, job_id)


# --- a page of lines -----------------------------------------------------------

@dataclass
class Page:
    lines: list[str] = field(default_factory=list)
    skip: int = 0                  # virtual offset this page started at
    next_skip: int | None = None   # where the next page starts, if any
    total_bytes: int = 0           # size of the selection, for "x of y"
    truncated_by_requests: bool = False


def page(available: Available, seqid: int, plugin: str, method: str | None,
         skip: int) -> Page | None:
    """One page of a process's lines from `<plugin>.log`, or None when the
    index has no such entry."""
    if available.index is None or plugin not in available.logs:
        return None
    entry = available.index.entry(seqid, plugin)
    if entry is None:
        return None
    blocks = entry.select(method)
    key = objects.result_prefix(available.job_id, available.key_prefix) + f"{plugin}.log"

    total = sum(end - start for start, end in blocks)
    out = Page(skip=skip, total_bytes=total)
    if skip >= total:
        return out

    # Walk the blocks from the virtual offset, grouping the ones to read into
    # spans, until a page's worth of bytes is in hand.
    virtual = 0
    got = bytearray()
    requests = 0
    span_start = span_end = None
    pending: list[tuple[int, int]] = []   # blocks inside the current span

    def flush() -> bool:
        """Fetch the current span, keep its blocks' bytes. False when the
        request budget is spent."""
        nonlocal requests, span_start, span_end, pending
        if span_start is None:
            return True
        if requests >= MAX_REQUESTS_PER_PAGE:
            return False
        requests += 1
        data = objects.range_bytes(key, span_start, span_end)
        for start, end in pending:
            got.extend(data[start - span_start:end - span_start])
        span_start = span_end = None
        pending = []
        return True

    stopped = False
    for start, end in blocks:
        size = end - start
        if virtual + size <= skip:
            virtual += size
            continue
        if virtual < skip:
            # The page starts inside this block.
            start += skip - virtual
            virtual = skip
        if span_start is not None and (start - span_end > SPAN_GAP
                                       or end - span_start > MAX_SPAN_BYTES):
            if not flush():
                stopped = True
                break
        # Only as much of this block as the page has room for; the cut to a
        # line boundary below trims the partial line, and the next page
        # starts where this one stopped.
        have = len(got) + sum(e - s for s, e in pending)
        end = min(end, start + (PAGE_BYTES - have))
        if span_start is None:
            span_start = start
        span_end = end
        pending.append((start, end))
        virtual += end - start
        if have + (end - start) >= PAGE_BYTES:
            break
    if not stopped and not flush():
        stopped = True

    raw = bytes(got)
    # Cut at a line boundary so no line is shown half; the remainder is the
    # next page's first line. On the bytes, before decoding: a replaced
    # invalid sequence would otherwise change the count.
    if raw and skip + len(raw) < total and not raw.endswith(b"\n"):
        keep = raw.rfind(b"\n") + 1
        if keep > 0:
            raw = raw[:keep]
    consumed = len(raw)
    out.lines = raw.decode("utf-8", errors="replace").splitlines()
    if skip + consumed < total:
        out.next_skip = skip + consumed
    out.truncated_by_requests = stopped
    return out