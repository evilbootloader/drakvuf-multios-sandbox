"""The sample's timeline: every plugin's records of the sample's processes,
across processes, in time order, for the platform's Timeline tab.

Written beside the calls log (cape_analysis._CallsLog), from it and from
what the calls do not hold:

- **every call**, of every plugin that makes one -- syscall, apimon, procmon,
  filetracer, regmon, socketmon, unixsocketmon, libmon, cpuidmon and the
  detection plugins (ptracemon, debugmon, ebpfmon) -- read back out of
  `calls.jsonl.gz` a member at a time, so one process's calls are never all
  in memory;
- **the records no call shape holds** (trace_split.AUX_PLUGINS): inject,
  fileextractor, memdump, procdump(2), tlsmon, rootkitmon, from the
  `aux/<plugin>.log` trace_split set aside;
- **Falco's alerts**, at the time each rule first fired for a process.

A row is compact -- time, process, plugin, call or record name, category,
status and a line of text -- and a call's row names its `cid`, through which
the platform opens the whole call from the calls log. The text keeps what a
reader searches a timeline for (paths, names, addresses, keys) and leaves out
the arguments that are only a number or a pointer; it is what the platform's
search reads, so it must hold the endpoint a Network row searches for.

Layout, as the calls log's: TIMELINE_PER_CHUNK rows per gzip member, the
members end to end in time order, and an index of
`[offset, length, first_row, first_ts, {seqid: rows} | None]` per member. A
row's position in the file is its index -- the `#N` the platform jumps to --
and the members being consecutive is what lets a search read a run of them
in one ranged request.

Inputs are read whole and bounded by projection, never by cutting: every
call becomes a row (memory: the operator's rule that postprocessing parses
every line). A 7.8 M-call run (al-khaser, job 4ecd7232) is 7.8 M rows.
"""
from __future__ import annotations

import gzip
import heapq
import logging
import zlib
from collections import Counter
from pathlib import Path
from typing import Iterable, Iterator, Optional

import orjson

from .modules import aux_records

log = logging.getLogger(__name__)

TIMELINE_LOG = "timeline.jsonl.gz"
TIMELINE_INDEX = "timeline_index.json"
TIMELINE_PER_CHUNK = 500
# A member's process counts are kept only while it holds this many processes
# or fewer: past it the platform reads the member rather than skipping it.
MAX_SEQIDS_PER_CHUNK = 64
MAX_VALUE_CHARS = 120
MAX_TEXT_CHARS = 320

# The plugins whose records are not calls, as trace_split sets them aside.
# socketmon and unixsocketmon are calls too and come in that way.
AUX_TIMELINE = ("inject", "fileextractor", "memdump", "procdump", "procdump2", "tlsmon", "rootkitmon")


def _noise(value: str) -> bool:
    """A value only a pointer, a handle, a size or a flag word: no reader
    searches a timeline for 0x7ffa544cfe94."""
    v = value.strip()
    if not v:
        return True
    if v.startswith(("0x", "-0x")):
        try:
            int(v.lstrip("-"), 16)
            return True
        except ValueError:
            return False
    return v.lstrip("-").isdigit()


def call_text(arguments: Iterable[dict]) -> str:
    """A call's arguments as one line of `name=value`, the numbers left out."""
    parts, size = [], 0
    for arg in arguments or ():
        if not isinstance(arg, dict):
            continue
        value = arg.get("value")
        if value is None or isinstance(value, (int, float, bool)):
            continue
        value = str(value)
        name = str(arg.get("name") or "?")
        if "port" in name.lower():
            # A port is the one number a reader searches by: kept, decimal
            try:
                port = int(value, 0)
            except ValueError:
                port = None
            if port:
                parts.append(f"{name}={port}")
                size += len(parts[-1]) + 1
            continue
        if _noise(value):
            continue
        part = f"{name}={value[:MAX_VALUE_CHARS]}"
        parts.append(part)
        size += len(part) + 1
        if size >= MAX_TEXT_CHARS:
            break
    return " ".join(parts)[:MAX_TEXT_CHARS]


def _ts(value) -> Optional[float]:
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return None
    return ts if ts > 0 else None


class _Owner:
    """A record's process: the sample's process with that PID alive at the
    record's time; the first with it where none was (a PID reused)."""

    def __init__(self, processes: list[dict], sample: set):
        self.by_pid: dict[int, list[dict]] = {}
        for p in processes:
            if p.get("seqid") in sample and isinstance(p.get("process_id"), int):
                self.by_pid.setdefault(p["process_id"], []).append(p)

    def __call__(self, pid, ts: Optional[float]) -> Optional[dict]:
        found = self.by_pid.get(pid) if isinstance(pid, int) else None
        if not found:
            return None
        if ts is not None:
            for p in found:
                start, end = _ts(p.get("started_ts")), _ts(p.get("exited_ts"))
                if (start is None or start <= ts) and (end is None or ts <= end):
                    return p
        return found[0]


def _join(*values) -> str:
    return " ".join(str(v) for v in values if v not in (None, ""))[:MAX_TEXT_CHARS]


def _aux_row(plugin: str, rec: dict, owner: _Owner) -> Optional[tuple]:
    """(ts, row) for one record of a non-call plugin, or None when it is not
    the sample's. Who a record is about decides: memdump and procdump name a
    target as well as the process that did it, and either being the sample's
    makes the record the sample's."""
    ts = _ts(rec.get("TimeStamp"))
    if ts is None:
        return None
    pid = rec.get("PID")
    name, text, category = plugin, "", "misc"
    if plugin == "inject":
        pid = rec.get("InjectedPid")
        name, category = "inject", "process"
        text = _join(rec.get("Method"), rec.get("Status"), rec.get("ProcessName"), rec.get("Arguments"))
    elif plugin == "fileextractor":
        name, category = "extracted", "filesystem"
        text = _join(rec.get("FileName"), f"{rec.get('Size')} bytes" if rec.get("Size") is not None else "",
                     rec.get("Method"))
    elif plugin == "memdump":
        if owner(pid, ts) is None:
            pid = rec.get("DumpPID")
        name, category = rec.get("DumpReason") or "memdump", "memory"
        text = _join(rec.get("Method"), rec.get("DumpAddr"), rec.get("DumpSize"),
                     f"→ {rec['DumpFilename']}" if rec.get("DumpFilename") else "")
    elif plugin in ("procdump", "procdump2"):
        if owner(pid, ts) is None:
            pid = rec.get("TargetPID")
        name, category = rec.get("DumpReason") or "procdump", "memory"
        text = _join(rec.get("Method"), rec.get("TargetName"), rec.get("DumpSize"))
    elif plugin == "tlsmon":
        name, category = rec.get("Method") or "tlsmon", "crypto"
        text = _join("client_random", rec.get("client_random"))
    elif plugin == "rootkitmon":
        # The kernel's, not a process's: kept whole, like the anomalies
        name, category = rec.get("Type") or rec.get("Method") or "rootkitmon", "kernel"
        text = _join(*(f"{k}={v}" for k, v in rec.items()
                       if k not in ("Plugin", "TimeStamp", "PID", "PPID", "TID", "UserId", "EventUID")
                       and isinstance(v, (str, int)) and v != ""))
        return ts, {"ts": rec.get("TimeStamp"), "seqid": None, "pid": None, "plugin": plugin,
                    "name": str(name), "category": category, "status": None, "text": text}
    proc = owner(pid, ts)
    if proc is None:
        return None
    return ts, {"ts": rec.get("TimeStamp"), "seqid": proc["seqid"], "pid": proc["process_id"],
                "plugin": plugin, "name": str(name)[:128], "category": category,
                "status": None, "text": text}


def _falco_rows(results: dict, owner: _Owner) -> Iterator[tuple]:
    for alert in (results.get("falco") or {}).get("alerts") or ():
        ts = _ts(alert.get("first_seen", alert.get("time")))
        proc = owner(alert.get("pid"), ts)
        if ts is None or proc is None:
            continue
        count = alert.get("count") or 1
        yield ts, {"ts": str(ts), "seqid": proc["seqid"], "pid": proc["process_id"], "plugin": "falco",
                   "name": str(alert.get("rule") or "falco")[:128], "category": "detection",
                   "status": None,
                   "text": _join(alert.get("priority"), alert.get("output"),
                                 f"(×{count})" if count > 1 else "")}


def _calls(seqid: int, entry: dict, handle) -> Iterator[tuple]:
    """One process's calls as (ts, seqid, cid, row), a member at a time.
    A call with no time takes its predecessor's, so it stays in place."""
    last = 0.0
    pid = entry.get("pid")
    for offset, length, first, _counts in entry.get("chunks", ()):
        handle.seek(offset)
        text = zlib.decompress(handle.read(length), 16 + zlib.MAX_WBITS)
        for line_no, line in enumerate(text.splitlines()):
            try:
                call = orjson.loads(line)
            except orjson.JSONDecodeError:
                continue
            ts = _ts(call.get("ts"))
            last = ts if ts is not None else last
            cid = first + line_no
            yield last, seqid, cid, {
                "ts": call.get("ts"), "seqid": seqid, "pid": pid, "cid": cid,
                "plugin": call.get("plugin") or "", "name": call.get("api") or "",
                "category": call.get("category") or "", "status": call.get("status"),
                "text": call_text(call.get("arguments")),
            }


def write_timeline(directory: Path, results: dict, sample: set, aux_dir: Optional[Path],
                   calls_log: str, calls_index: str) -> int:
    """TIMELINE_LOG and TIMELINE_INDEX beside the calls log; the rows
    written."""
    index_path = directory / calls_index
    processes = orjson.loads(index_path.read_bytes()).get("processes", {}) if index_path.exists() else {}
    owner = _Owner((results.get("behavior") or {}).get("processes") or [], sample)

    others = []
    for plugin in AUX_TIMELINE:
        for rec in aux_records(aux_dir, plugin):
            row = _aux_row(plugin, rec, owner)
            if row is not None:
                others.append((row[0], -1, len(others), row[1]))
    others.extend((ts, -1, len(others) + i, row) for i, (ts, row) in enumerate(_falco_rows(results, owner)))
    others.sort(key=lambda r: (r[0], r[2]))

    out = (directory / TIMELINE_LOG).open("wb")
    chunks, plugins, by_seqid = [], Counter(), Counter()
    batch, batch_seqids, first_ts, offset, count = [], Counter(), None, 0, 0

    def flush():
        nonlocal batch, batch_seqids, first_ts, offset
        if not batch:
            return
        member = gzip.compress(b"\n".join(batch) + b"\n", compresslevel=3)
        out.write(member)
        seqids = ({str(k): v for k, v in batch_seqids.items()}
                  if len(batch_seqids) <= MAX_SEQIDS_PER_CHUNK else None)
        chunks.append([offset, len(member), count - len(batch), first_ts, seqids])
        offset += len(member)
        batch, batch_seqids, first_ts = [], Counter(), None

    handle = (directory / calls_log).open("rb") if processes else None
    try:
        # One shared handle: each process's stream seeks before it reads
        streams = [_calls(int(s), e, handle) for s, e in processes.items()]
        for ts, _s, _c, row in heapq.merge(*streams, iter(others), key=lambda r: (r[0], r[1], r[2])):
            if first_ts is None:
                first_ts = ts
            batch.append(orjson.dumps(row))
            batch_seqids[row["seqid"] if row["seqid"] is not None else -1] += 1
            plugins[row["plugin"]] += 1
            if row["seqid"] is not None:
                by_seqid[row["seqid"]] += 1
            count += 1
            if len(batch) == TIMELINE_PER_CHUNK:
                flush()
        flush()
    finally:
        out.close()
        if handle is not None:
            handle.close()
    (directory / TIMELINE_INDEX).write_bytes(orjson.dumps({
        "version": 1, "chunk": TIMELINE_PER_CHUNK, "log": TIMELINE_LOG, "count": count,
        "plugins": dict(plugins.most_common()),
        "processes": {str(k): v for k, v in by_seqid.items()},
        "chunks": chunks,
    }))
    return count
