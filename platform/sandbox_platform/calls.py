"""A process's calls, parsed, a page at a time: the process panel's table.

`sandboxd/postprocessing/plugins/cape_analysis.py` writes them beside the
report, for the sample's processes only:

- `calls.jsonl.gz`: one gzip member per chunk of calls of one process (200
  by default), laid end to end. Each line is one call as CAPE parsed it --
  time, thread, API, category, status, return, arguments -- its values
  already bounded on Dom0.
- `calls_index.json`: per seqid, the process's pid, call count, threads,
  calls per category and per API, and per chunk `[offset, length,
  first_cid, {category: n}]`.

A call's position in its process is CAPE's `cid` -- what a signature's
`mark_call` names -- so the chunk holding a call is `cid // chunk`.

A page costs one ranged read of one member and its inflation; a filtered
page reads members until it has a page or has read MAX_MEMBERS_PER_PAGE,
skipping members whose category counts say they hold none of the category
asked for. Every read is bounded (member bytes, inflated bytes, lines,
arguments), the index is validated before an offset in it is used, and the
calls reach the page as text through autoescape.
"""

from __future__ import annotations

import json
import logging
import zlib
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any
from uuid import UUID

from . import manifest as manifest_schema
from . import objects

log = logging.getLogger("sandbox_platform.calls")

INDEX_NAME = "calls_index.json"
LOG_NAME = "calls.jsonl.gz"

MAX_INDEX_BYTES = 16 * 1024 * 1024
# A member is 200 calls: ~15 KiB gzipped, ~100 KiB inflated for ordinary
# calls, ~3 MiB for 200 calls each carrying a 16 K-character buffer.
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_INFLATED = 32 * 1024 * 1024
MAX_MEMBERS_PER_PAGE = 16
PAGE_CALLS = 100
MAX_ARGUMENTS = 64
MAX_VALUE = 16 * 1024
MAX_CHUNKS = 200_000


class IndexError_(Exception):
    """The index is not the shape cape_analysis writes."""


@dataclass(frozen=True)
class Chunk:
    offset: int
    length: int
    first: int
    categories: dict[str, int]


@dataclass(frozen=True)
class ProcessCalls:
    pid: int | None
    count: int
    threads: tuple[str, ...]
    categories: dict[str, int]
    apis: dict[str, int]
    chunks: tuple[Chunk, ...]

    def matching(self, category: str) -> int:
        return self.categories.get(category, 0) if category else self.count


@dataclass(frozen=True)
class Index:
    chunk: int
    processes: dict[int, ProcessCalls]


def _counts(raw: Any) -> dict[str, int]:
    if not isinstance(raw, dict):
        raise IndexError_("counts are not a map")
    out = {}
    for k, v in list(raw.items())[:2000]:
        if not isinstance(k, str) or not isinstance(v, int) or v < 0:
            raise IndexError_("a count is not name -> number")
        out[k[:256]] = v
    return out


def parse_index(raw: bytes) -> Index:
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise IndexError_(f"not JSON: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise IndexError_("not a version 1 calls index")
    chunk = doc.get("chunk")
    if not isinstance(chunk, int) or not 0 < chunk <= 100_000:
        raise IndexError_("chunk size missing")
    processes = doc.get("processes")
    if not isinstance(processes, dict):
        raise IndexError_("processes is not a map")
    out = {}
    for key, entry in processes.items():
        try:
            seqid = int(key)
        except ValueError as exc:
            raise IndexError_("a process key is not a seqid") from exc
        if not isinstance(entry, dict):
            raise IndexError_("a process entry is not a map")
        chunks = entry.get("chunks", [])
        if not isinstance(chunks, list) or len(chunks) > MAX_CHUNKS:
            raise IndexError_("chunks is not a list")
        parsed = []
        for c in chunks:
            if (not isinstance(c, list) or len(c) != 4
                    or not all(isinstance(v, int) and v >= 0 for v in c[:3]) or c[1] == 0):
                raise IndexError_("a chunk is not [offset, length, first, counts]")
            parsed.append(Chunk(c[0], c[1], c[2], _counts(c[3])))
        threads = entry.get("threads", [])
        pid = entry.get("pid")
        count = entry.get("count", 0)
        if not isinstance(threads, list) or not isinstance(count, int) \
                or not (pid is None or isinstance(pid, int)):
            raise IndexError_("a process entry has the wrong types")
        out[seqid] = ProcessCalls(pid, count, tuple(str(t)[:32] for t in threads[:1000]),
                                  _counts(entry.get("categories", {})),
                                  _counts(entry.get("apis", {})), tuple(parsed))
    return Index(chunk, out)


# --- one call ------------------------------------------------------------------------

@dataclass(frozen=True)
class Argument:
    name: str
    value: str
    pretty: str = ""

    @property
    def long(self) -> bool:
        return len(self.value) > 96 or "\n" in self.value


@dataclass(frozen=True)
class Call:
    cid: int
    ts: str
    tid: str
    api: str
    kernel: bool
    category: str
    status: bool | None
    ret: str
    caller: str
    repeated: int
    plugin: str
    sources: tuple[str, ...]
    arguments: tuple[Argument, ...]

    @property
    def failed(self) -> bool:
        return self.status is False

    @property
    def has_long(self) -> bool:
        return any(a.long for a in self.arguments)


def _s(value: Any, limit: int = MAX_VALUE) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = json.dumps(value) if isinstance(value, (list, dict)) else str(value)
    return value if len(value) <= limit else value[:limit] + "…[truncated]"


def _call(row: Any, cid: int) -> Call | None:
    if not isinstance(row, dict):
        return None
    args = []
    raw_args = row.get("arguments")
    for a in (raw_args if isinstance(raw_args, list) else [])[:MAX_ARGUMENTS]:
        if isinstance(a, dict):
            args.append(Argument(_s(a.get("name"), 128), _s(a.get("value")), _s(a.get("pretty"), 2048)))
    status = row.get("status")
    sources = row.get("sources")
    repeated = row.get("repeated")
    return Call(
        cid=cid, ts=_s(row.get("ts"), 32), tid=_s(row.get("tid"), 32), api=_s(row.get("api"), 256),
        kernel=bool(row.get("kernel")), category=_s(row.get("category"), 64),
        status=status if isinstance(status, bool) else None, ret=_s(row.get("return"), 256),
        caller=_s(row.get("caller"), 32),
        repeated=repeated if isinstance(repeated, int) and repeated > 0 else 0,
        plugin=_s(row.get("plugin"), 32),
        sources=tuple(_s(s, 32) for s in sources[:8]) if isinstance(sources, list) else (),
        arguments=tuple(args))


# --- the store -------------------------------------------------------------------------

@dataclass(frozen=True)
class Available:
    index: Index | None = None
    log_key: str = ""

    def process(self, seqid: int) -> ProcessCalls | None:
        return self.index.processes.get(seqid) if self.index else None


@lru_cache(maxsize=16)
def _load(key: str, sha256: str) -> Index | None:
    out = bytearray()
    try:
        for chunk in objects.chunks(key):
            out += chunk
            if len(out) > MAX_INDEX_BYTES:
                log.warning("calls index %s is over %d bytes; not read", key, MAX_INDEX_BYTES)
                return None
        return parse_index(bytes(out))
    except IndexError_ as exc:
        log.warning("calls index %s unusable: %s", key, exc)
        return None
    except Exception as exc:  # noqa: BLE001 - a page must render without it
        log.warning("calls index %s could not be read: %s", key, exc)
        return None


def for_job(job_id: UUID, manifest: object, key_prefix: str, expired: bool = False) -> Available:
    if expired:
        return Available()
    names = {a.name: a for a in manifest_schema.parse(manifest).artifacts}
    entry = names.get(INDEX_NAME)
    if entry is None or not entry.sha256 or LOG_NAME not in names:
        return Available()
    prefix = objects.result_prefix(job_id, key_prefix)
    return Available(_load(prefix + INDEX_NAME, entry.sha256), prefix + LOG_NAME)


def _read_member(available: Available, chunk: Chunk, reader=None) -> list[Any]:
    """One chunk's calls, as parsed JSON lines; [] for a member that is not
    one, too large, or unreadable."""
    if chunk.length > MAX_MEMBER_BYTES:
        return []
    read = reader or objects.range_bytes
    try:
        data = read(available.log_key, chunk.offset, chunk.offset + chunk.length)
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        text = inflater.decompress(data, MAX_INFLATED)
    except Exception as exc:  # noqa: BLE001 - one bad member is one empty page
        log.warning("calls member at %d unreadable: %s", chunk.offset, exc)
        return []
    rows = []
    for line in text.splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            rows.append(None)
    return rows


@dataclass
class Page:
    calls: list[Call] = field(default_factory=list)
    next: str | None = None         # cursor of the next page, if any
    matching: int = 0               # calls the filter can match, for "x of y"
    stopped: bool = False           # stopped at the member budget, not the end


def _cursor(text: str) -> tuple[int, int]:
    try:
        chunk, line = text.split(".", 1)
        return max(0, int(chunk)), max(0, int(line))
    except ValueError:
        return 0, 0


def page(available: Available, seqid: int, cursor: str = "", category: str = "",
         api: str = "", tid: str = "", failed: bool = False, reader=None) -> Page | None:
    """A page of one process's calls from `cursor` ("chunk.line"), filtered;
    None when the index has no such process."""
    proc = available.process(seqid)
    if proc is None:
        return None
    out = Page(matching=proc.matching(category))
    start_chunk, start_line = _cursor(cursor)
    members = 0
    for ci in range(start_chunk, len(proc.chunks)):
        chunk = proc.chunks[ci]
        if category and not chunk.categories.get(category):
            continue
        if members >= MAX_MEMBERS_PER_PAGE:
            out.next, out.stopped = f"{ci}.0", True
            return out
        members += 1
        rows = _read_member(available, chunk, reader)
        first_line = start_line if ci == start_chunk else 0
        for li in range(first_line, len(rows)):
            call = _call(rows[li], chunk.first + li)
            if call is None:
                continue
            if ((category and call.category != category) or (api and call.api != api)
                    or (tid and call.tid != tid) or (failed and not call.failed)):
                continue
            if len(out.calls) == PAGE_CALLS:
                out.next = f"{ci}.{li}"
                return out
            out.calls.append(call)
    return out


def call(available: Available, seqid: int, cid: int, reader=None) -> Call | None:
    """One call by its cid, for a signature's mark."""
    proc = available.process(seqid)
    if proc is None or cid < 0 or available.index is None:
        return None
    ci = cid // available.index.chunk
    if ci >= len(proc.chunks):
        return None
    chunk = proc.chunks[ci]
    rows = _read_member(available, chunk, reader)
    line = cid - chunk.first
    if not 0 <= line < len(rows):
        return None
    return _call(rows[line], cid)
