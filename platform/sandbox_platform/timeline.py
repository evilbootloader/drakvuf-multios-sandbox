"""The sample's timeline, a window at a time: the Timeline tab.

`sandboxd/postprocessing/plugins/cape_plugin/timeline.py` writes it beside
the calls log: every plugin's records of the sample's processes -- each call,
and what no call holds (inject, fileextractor, memdump, procdump, tlsmon,
rootkitmon, Falco's alerts) -- across processes, in time order.

- `timeline.jsonl.gz`: gzip members of `chunk` rows each, end to end. A row
  is one compact JSON line; its position in the file is its index, the `#N`
  a reader jumps to.
- `timeline_index.json`: the row count, rows per plugin and per process, and
  per member `[offset, length, first_row, first_ts, {seqid: rows} | null]`.

Three operations, each bounded:

- `window`: WINDOW rows from an index, optionally one process's -- the
  20-row windows the tab scrolls through (operator, 2026-11-14);
- `before`: the WINDOW rows above an index, for scrolling up;
- `find`: the next (or previous) row holding a text, case-insensitively. It
  moves through the list rather than filtering it. One request reads one run
  of consecutive members -- one ranged GET, at most SEARCH_BYTES -- and says
  where to resume when the match is further on; the page re-issues it until
  it finds one or reaches the end.

A run from before the timeline was written gets the same three operations
over its CAPE events (`from_events`), which the report already holds.

Everything here is the sample's text, and reaches the page through
autoescape; nothing is marked safe.
"""

from __future__ import annotations

import bisect
import json
import logging
import zlib
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Callable, Iterable
from uuid import UUID

from . import manifest as manifest_schema
from . import objects

log = logging.getLogger("sandbox_platform.timeline")

INDEX_NAME = "timeline_index.json"
LOG_NAME = "timeline.jsonl.gz"

WINDOW = 20
MAX_INDEX_BYTES = 32 * 1024 * 1024
# A member is 500 rows: ~30 KiB gzipped, ~100 KiB inflated.
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_INFLATED = 32 * 1024 * 1024
# Members a window may read past ones holding nothing of its process
MAX_MEMBERS_PER_WINDOW = 32
# One search request: one ranged read of at most this many bytes of
# consecutive members. ~250 members, ~125,000 rows, well under a second.
SEARCH_BYTES = 8 * 1024 * 1024
MAX_SEARCH_MEMBERS = 256
MAX_QUERY = 200
MAX_CHUNKS = 1_000_000


class IndexError_(Exception):
    """The index is not the shape sandboxd writes."""


@dataclass(frozen=True)
class Chunk:
    offset: int
    length: int
    first: int
    seqids: frozenset[int] | None


@dataclass(frozen=True)
class Index:
    count: int
    plugins: dict[str, int]
    processes: dict[int, int]
    chunks: tuple[Chunk, ...]
    firsts: tuple[int, ...]

    def chunk_of(self, row: int) -> int:
        return max(0, bisect.bisect_right(self.firsts, row) - 1)


def _counts(raw: Any, keyed=str) -> dict:
    if not isinstance(raw, dict):
        raise IndexError_("counts are not a map")
    out = {}
    for k, v in list(raw.items())[:100_000]:
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            raise IndexError_("a count is not a number")
        try:
            out[keyed(k)] = v
        except ValueError as exc:
            raise IndexError_("a process key is not a seqid") from exc
    return out


def parse_index(raw: bytes) -> Index:
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise IndexError_(f"not JSON: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise IndexError_("not a version 1 timeline index")
    count = doc.get("count")
    chunks = doc.get("chunks")
    if (not isinstance(count, int) or isinstance(count, bool) or count < 0
            or not isinstance(chunks, list) or len(chunks) > MAX_CHUNKS):
        raise IndexError_("count or chunks missing")
    parsed, end = [], 0
    for c in chunks:
        if (not isinstance(c, list) or len(c) != 5
                or not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in c[:3])
                or c[1] == 0):
            raise IndexError_("a chunk is not [offset, length, first, ts, seqids]")
        # Members end to end: what lets a search read a run of them in one
        # range. Rows numbered from 0 and rising: what lets a window find
        # the member holding a row by bisecting the firsts.
        if c[0] != end or (parsed and c[2] <= parsed[-1].first) or (not parsed and c[2] != 0):
            raise IndexError_("chunks are not consecutive")
        parsed.append(Chunk(c[0], c[1], c[2], None if c[4] is None else frozenset(_counts(c[4], int))))
        end = c[0] + c[1]
    if (parsed and parsed[-1].first >= count) or (not parsed and count):
        raise IndexError_("row numbers do not match the count")
    return Index(count, _counts(doc.get("plugins", {})), _counts(doc.get("processes", {}), int),
                 tuple(parsed), tuple(c.first for c in parsed))


# --- a row --------------------------------------------------------------------------

@dataclass(frozen=True)
class Row:
    index: int
    ts: Any
    seqid: int | None
    pid: int | None
    plugin: str
    name: str
    category: str
    status: bool | None
    text: str
    cid: int | None = None
    data: dict = field(default_factory=dict)  # a CAPE event's, for a run without a timeline

    @property
    def failed(self) -> bool:
        return self.status is False

    def matches(self, needle: str) -> bool:
        """`needle` lower-cased already."""
        return any(needle in v.lower() for v in (self.name, self.text, self.plugin, self.category) if v)


def _s(value: Any, limit: int) -> str:
    if value is None:
        return ""
    value = value if isinstance(value, str) else str(value)
    return value[:limit]


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _row(raw: Any, index: int) -> Row | None:
    if not isinstance(raw, dict):
        return None
    status = raw.get("status")
    return Row(index=index, ts=_s(raw.get("ts"), 32), seqid=_int(raw.get("seqid")), pid=_int(raw.get("pid")),
               plugin=_s(raw.get("plugin"), 32), name=_s(raw.get("name"), 256),
               category=_s(raw.get("category"), 64),
               status=status if isinstance(status, bool) else None,
               text=_s(raw.get("text"), 1024), cid=_int(raw.get("cid")))


# --- the result of an operation -------------------------------------------------------

@dataclass
class Window:
    rows: list[Row]
    next: int | None        # where the window after this one starts; None at the end
    start: int              # the first index this window covered (an "earlier" starts above it)


@dataclass
class Found:
    index: int | None       # the matching row
    resume: int | None      # not found yet: where the next request starts
    scanned: int            # how far this request got, for the progress line


# --- the store --------------------------------------------------------------------------

def _probe(needle: str) -> bytes | None:
    """What a member's raw bytes must contain to hold a row matching
    `needle` (lower-cased): the needle as the writer's JSON spells it, a
    backslash doubled and a quote escaped. A whole member is lower-cased and
    tested in one C-level search, and most are skipped without a row parsed
    -- a search that matched nothing in a 7.8 M-row run took 37 s parsing
    every row. Key names match too ("text" is in every line), which costs a
    parse, never a miss: each candidate is confirmed on the parsed row.
    None for a needle that is not ASCII, which `bytes.lower` would not fold."""
    if not needle.isascii():
        return None
    return json.dumps(needle)[1:-1].encode()


class Store:
    """A run's timeline in the object store."""

    def __init__(self, index: Index, log_key: str, reader: Callable | None = None):
        self.index = index
        self.log_key = log_key
        self.read = reader or objects.range_bytes
        self.count = index.count
        self.plugins = index.plugins
        self.processes = index.processes

    def _members(self, first: int, last: int, probe: bytes | None = None) -> Iterable[tuple[int, list[Any]]]:
        """Members first..last inclusive, read in one range: (chunk, rows).
        With a `probe`, a member whose bytes cannot hold it is skipped
        unparsed (see `_probe`)."""
        chunks = self.index.chunks
        start, end = chunks[first].offset, chunks[last].offset + chunks[last].length
        try:
            data = self.read(self.log_key, start, end)
        except Exception as exc:  # noqa: BLE001 - one bad read is an empty window
            log.warning("timeline bytes %d-%d unreadable: %s", start, end, exc)
            return
        for ci in range(first, last + 1):
            c = chunks[ci]
            if c.length > MAX_MEMBER_BYTES:
                continue
            piece = data[c.offset - start:c.offset - start + c.length]
            try:
                text = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(piece, MAX_INFLATED)
            except zlib.error as exc:
                log.warning("timeline member at %d unreadable: %s", c.offset, exc)
                continue
            if probe is not None and probe not in text.lower():
                continue
            rows = []
            for line in text.splitlines():
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    rows.append(None)
            yield ci, rows

    def _wanted(self, ci: int, seqid: int | None) -> bool:
        seqids = self.index.chunks[ci].seqids
        return seqid is None or seqids is None or seqid in seqids

    def window(self, start: int, seqid: int | None = None, size: int = WINDOW) -> Window:
        out = Window([], None, start)
        if start >= self.count:
            return out
        ci, read = self.index.chunk_of(start), 0
        while ci < len(self.index.chunks):
            if not self._wanted(ci, seqid):
                ci += 1
                continue
            if read >= MAX_MEMBERS_PER_WINDOW:
                out.next = self.index.chunks[ci].first
                return out
            read += 1
            for _, rows in self._members(ci, ci):
                first = self.index.chunks[ci].first
                for li, raw in enumerate(rows):
                    index = first + li
                    if index < start:
                        continue
                    row = _row(raw, index)
                    if row is None or (seqid is not None and row.seqid != seqid):
                        continue
                    if len(out.rows) == size:
                        out.next = index
                        return out
                    out.rows.append(row)
            ci += 1
        return out

    def before(self, end: int, seqid: int | None = None, size: int = WINDOW) -> Window:
        """The `size` rows above `end` (theirs, under a process filter);
        `start` is the first index read, 0 when the top was reached."""
        found: list[Row] = []
        if end <= 0:
            return Window([], end, 0)
        ci, read = self.index.chunk_of(min(end, self.count) - 1), 0
        while ci >= 0 and len(found) < size:
            if not self._wanted(ci, seqid):
                ci -= 1
                continue
            if read >= MAX_MEMBERS_PER_WINDOW:
                break
            read += 1
            first = self.index.chunks[ci].first
            for _, rows in self._members(ci, ci):
                mine = [r for r in (_row(raw, first + li) for li, raw in enumerate(rows))
                        if r is not None and r.index < end and (seqid is None or r.seqid == seqid)]
                found = mine + found
            ci -= 1
        rows = found[-size:]
        top = rows[0].index if rows else end
        reached_top = ci < 0 and len(found) <= size
        return Window(rows, end, 0 if reached_top else top)

    def find(self, needle: str, start: int, seqid: int | None = None, backwards: bool = False) -> Found:
        needle = needle.lower()[:MAX_QUERY]
        chunks = self.index.chunks
        if not needle or not chunks:
            return Found(None, None, start)
        if backwards:
            if start <= 0:
                return Found(None, None, 0)
            last = self.index.chunk_of(min(start, self.count) - 1)
            first, size = last, chunks[last].length
            while first > 0 and last - first < MAX_SEARCH_MEMBERS and size + chunks[first - 1].length <= SEARCH_BYTES:
                first -= 1
                size += chunks[first].length
            members = list(self._members(first, last, _probe(needle)))
            for ci, rows in reversed(members):
                if not self._wanted(ci, seqid):
                    continue
                base = chunks[ci].first
                for li in range(len(rows) - 1, -1, -1):
                    row = _row(rows[li], base + li)
                    if row is None or row.index >= start or (seqid is not None and row.seqid != seqid):
                        continue
                    if row.matches(needle):
                        return Found(row.index, None, row.index)
            top = chunks[first].first
            return Found(None, top if top > 0 else None, top)
        if start >= self.count:
            return Found(None, None, self.count)
        first = self.index.chunk_of(start)
        last, size = first, chunks[first].length
        while last + 1 < len(chunks) and last - first < MAX_SEARCH_MEMBERS and size + chunks[last + 1].length <= SEARCH_BYTES:
            last += 1
            size += chunks[last].length
        for ci, rows in self._members(first, last, _probe(needle)):
            if not self._wanted(ci, seqid):
                continue
            base = chunks[ci].first
            for li, raw in enumerate(rows):
                row = _row(raw, base + li)
                if row is None or row.index < start or (seqid is not None and row.seqid != seqid):
                    continue
                if row.matches(needle):
                    return Found(row.index, None, row.index)
        end = chunks[last + 1].first if last + 1 < len(chunks) else self.count
        return Found(None, end if end < self.count else None, end)


    def matches(self, needle: str, start: int = 0, seqid: int | None = None, limit: int = WINDOW) -> Window:
        """Up to `limit` rows from `start` holding `needle`, the others left
        out: one Network row's own timeline -- the rows naming its address
        or name. One request reads at most SEARCH_BYTES; `next` is where the
        next request starts, which may hold nothing yet (a reader scrolling
        on keeps the list scanning)."""
        needle = needle.lower()[:MAX_QUERY]
        out = Window([], None, start)
        chunks = self.index.chunks
        if not needle or not chunks or start >= self.count:
            return out
        first = self.index.chunk_of(start)
        last, size = first, chunks[first].length
        while last + 1 < len(chunks) and last - first < MAX_SEARCH_MEMBERS and size + chunks[last + 1].length <= SEARCH_BYTES:
            last += 1
            size += chunks[last].length
        for ci, rows in self._members(first, last, _probe(needle)):
            if not self._wanted(ci, seqid):
                continue
            base = chunks[ci].first
            for li, raw in enumerate(rows):
                row = _row(raw, base + li)
                if (row is None or row.index < start or (seqid is not None and row.seqid != seqid)
                        or not row.matches(needle)):
                    continue
                if len(out.rows) == limit:
                    out.next = row.index
                    return out
                out.rows.append(row)
        end = chunks[last + 1].first if last + 1 < len(chunks) else self.count
        out.next = end if end < self.count else None
        return out


class Rows:
    """The same operations over rows already in memory: a run from before
    the timeline file, over its CAPE events."""

    def __init__(self, rows: list[Row]):
        self.rows = rows
        self.count = len(rows)
        self.plugins: dict[str, int] = {}
        self.processes: dict[int, int] = {}
        for r in rows:
            self.plugins[r.plugin] = self.plugins.get(r.plugin, 0) + 1
            if r.seqid is not None:
                self.processes[r.seqid] = self.processes.get(r.seqid, 0) + 1

    def _mine(self, seqid):
        return self.rows if seqid is None else [r for r in self.rows if r.seqid == seqid]

    def window(self, start: int, seqid: int | None = None, size: int = WINDOW) -> Window:
        rows = [r for r in self._mine(seqid) if r.index >= start]
        return Window(rows[:size], rows[size].index if len(rows) > size else None, start)

    def before(self, end: int, seqid: int | None = None, size: int = WINDOW) -> Window:
        rows = [r for r in self._mine(seqid) if r.index < end]
        shown = rows[-size:]
        return Window(shown, end, 0 if len(rows) <= size else shown[0].index)

    def find(self, needle: str, start: int, seqid: int | None = None, backwards: bool = False) -> Found:
        needle = needle.lower()[:MAX_QUERY]
        if not needle:
            return Found(None, None, start)
        rows = self._mine(seqid)
        candidates = (reversed([r for r in rows if r.index < start]) if backwards
                      else (r for r in rows if r.index >= start))
        for r in candidates:
            if r.matches(needle):
                return Found(r.index, None, r.index)
        return Found(None, None, 0 if backwards else self.count)


    def matches(self, needle: str, start: int = 0, seqid: int | None = None, limit: int = WINDOW) -> Window:
        needle = needle.lower()[:MAX_QUERY]
        rows = [r for r in self._mine(seqid) if r.index >= start and needle and r.matches(needle)]
        return Window(rows[:limit], rows[limit].index if len(rows) > limit else None, start)


def from_events(events: list) -> Rows:
    """A report's CAPE events (cape.Event) as timeline rows: the fallback
    for a run whose postprocessing predates the timeline file."""
    return Rows([Row(index=i, ts=e.timestamp, seqid=e.seqid, pid=e.pid, plugin=e.object,
                     name=e.event, category=e.object, status=None, text=e.target, data=e.data)
                 for i, e in enumerate(events)])


# --- loading ----------------------------------------------------------------------------

@lru_cache(maxsize=16)
def _load(key: str, sha256: str) -> Index | None:
    out = bytearray()
    try:
        for chunk in objects.chunks(key):
            out += chunk
            if len(out) > MAX_INDEX_BYTES:
                log.warning("timeline index %s is over %d bytes; not read", key, MAX_INDEX_BYTES)
                return None
        return parse_index(bytes(out))
    except IndexError_ as exc:
        log.warning("timeline index %s unusable: %s", key, exc)
        return None
    except Exception as exc:  # noqa: BLE001 - a page must render without it
        log.warning("timeline index %s could not be read: %s", key, exc)
        return None


def for_job(job_id: UUID, manifest: object, key_prefix: str, expired: bool = False) -> Store | None:
    """The run's timeline file, or None for a run without one (or past
    retention, or with an index this module will not use)."""
    if expired:
        return None
    names = {a.name: a for a in manifest_schema.parse(manifest).artifacts}
    entry = names.get(INDEX_NAME)
    if entry is None or not entry.sha256 or LOG_NAME not in names:
        return None
    prefix = objects.result_prefix(job_id, key_prefix)
    index = _load(prefix + INDEX_NAME, entry.sha256)
    return Store(index, prefix + LOG_NAME) if index is not None else None
