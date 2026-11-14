"""CAPE's processing over the job's trace.log: `results`, as CAPE builds it.

`cape_plugin/trace_split.py` cuts trace.log into CAPE's `logs/` layout, one
file per process; `RunProcessing` then runs CAPE's processing modules over
it (BehaviorAnalysis, and the capa pass at its end) exactly as CAPE does.

The per-process logs live in a temporary directory inside the job, and **for
as long as anything reads `calls`**: each process's calls are a lazy iterator
that re-reads its file (CAPE's ParseProcessLog), so the signatures, when they
run, must run inside the same `with`. The directory's leading dot and its
deletion keep it out of the log index and the upload.
"""
from __future__ import annotations

import gzip
import json
import re
from collections import Counter
from datetime import datetime, timezone
import logging
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Optional

import orjson

from ...guests import PATHS, TargetOs
from .. import clrjit
from ..paths import CAPE_RESULTS, DUMPS_DIR, EXTRACTED_DIR
from .cape_plugin import (
    CapeOptions, RunProcessing, RunSignatures, load_signatures, split_by_process,
)
from .cape_plugin.filetype import package
from .cape_plugin.modules import FileInfo
from .cape_plugin.static import elf_info, file_static, pe_info
from .cape_plugin.timeline import TIMELINE_INDEX, TIMELINE_LOG, write_timeline
from .plugin_base import CapeConfigSection, PostprocessContext

log = logging.getLogger(__name__)


# The guest's type, in `file`'s words: what DRAKVUF traced is a 64-bit
# Windows or Linux userland, whatever the sample itself was. capa's CAPE
# extractor reads format, OS and arch out of it (`info.guest_type`,
# capa_integration.capa_inputs) -- so a 32-bit sample or a script gets its
# dynamic pass all the same. It is `target.file.type` only for a job whose
# sample file the daemon did not pass: the sample's own type otherwise
# (FileInfo.describe: libmagic's, else filetype.sniff's).
TARGET_FILE_TYPE = {
    TargetOs.WINDOWS: "PE32+ executable (GUI) x86-64, for MS Windows",
    TargetOs.UBUNTU: "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), for GNU/Linux",
    # BlissOS is Android-x86: an x86-64 Linux kernel, which is all capa asks.
    TargetOs.ANDROID: "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), for GNU/Linux",
}

# `info.package` of a job whose sample file is not at hand, as before
# 2026-11-12; with the file it is filetype.package's answer.
DEFAULT_PACKAGE = {TargetOs.WINDOWS: "exe", TargetOs.UBUNTU: "generic", TargetOs.ANDROID: "generic"}


def cape_yara_rules(cfg: CapeConfigSection) -> Path:
    """CAPE's family YARA rules, where the community checkout keeps them."""
    return Path(cfg.community) / "data" / "yara" / "CAPE"


def _target(os_: TargetOs, sample: Optional[Path], yara_rules, cape_rules=None) -> dict:
    """CAPE's `target`: the sample's own hashes, type, YARA hits, PE or
    ELF fields and format-free static facts when the daemon passed it; otherwise the guest's type and no
    hashes, which is all a trace alone can say. The guest's type is no
    stand-in for a sample whose type is unknown: that one is `data`."""
    # `name` and `path` always: signatures index them without asking
    # (mimics_extension raised KeyError on every job without a sample file)
    file = {"name": "", "path": "", "type": TARGET_FILE_TYPE[os_], "md5": "", "sha1": "", "sha256": "",
            "yara": [], "cape_yara": []}
    if sample is not None and sample.is_file():
        file = FileInfo(yara_rules, cape_rules).describe(sample)
        file["name"] = sample.name
        file["type"] = file["type"] or "data"
        pe = pe_info(sample)
        if pe:
            file["pe"] = pe
        # An ELF's headers (CAPE's parse_elf names), and for any format its
        # entropy, strings, archive members and text: static.py has why
        # these are keys no signature reads.
        elf = elf_info(sample)
        if elf:
            file["elf"] = elf
        facts = file_static(sample)
        if facts:
            file["static"] = facts
        # The sample's own functions as located before the run, and which
        # of them were hooked (sandboxd/samplehooks.py, through stages).
        located = sample.parent / "located.json"
        if located.is_file():
            try:
                file["located"] = json.loads(located.read_text())
            except ValueError:
                pass
        # And of what it dropped during the run (sandboxd/stagehooks.py)
        stages = []
        for found in sorted(sample.parent.glob("located.stage*.json")):
            try:
                stages.append(json.loads(found.read_text()))
            except ValueError:
                pass
        if stages:
            file.setdefault("located", {})["stages"] = stages
    return {"category": "file", "file": file}


def _trace_times(analysis_dir: Path) -> tuple:
    """(first, last) TimeStamp of trace.log, from its head and its tail."""
    stamp = re.compile(rb'"TimeStamp":\s*"?([0-9.]+)')
    first = last = 0.0
    with (analysis_dir / "trace.log").open("rb") as f:
        m = stamp.search(f.read(1 << 16))
        if m:
            first = float(m.group(1))
        f.seek(max(0, f.seek(0, 2) - (1 << 16)))
        found = stamp.findall(f.read())
        if found:
            last = float(found[-1])
    return first, last


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _json_default(obj):
    if isinstance(obj, (set, frozenset)):
        return sorted(obj, key=str)
    return str(obj)


# The sample's calls, parsed, for the platform's call viewer: one gzip member
# per CALLS_PER_CHUNK calls of one process, laid end to end, and an index of
# where each member is. A page of the viewer is then one ranged read and one
# member to inflate, out of a file the platform never reads whole.
CALLS_LOG = "calls.jsonl.gz"
CALLS_INDEX = "calls_index.json"
CALLS_PER_CHUNK = 200
# A value past this is cut (and says so): a 4 KiB buffer DRAKVUF printed
# with \xHH escapes is about 16 K characters; nothing a reader pages through
# needs more.
MAX_ARGUMENT_CHARS = 8192
# The APIs a process's index lists by count, for the viewer's API filter
TOP_APIS = 300


def _call_row(call: dict) -> dict:
    """One parsed call as the viewer reads it: CAPE's call, its arguments'
    values bounded, `raw_value` dropped where it repeats `value`."""
    arguments = []
    for arg in call.get("arguments") or ():
        value = arg.get("value")
        if isinstance(value, str) and len(value) > MAX_ARGUMENT_CHARS:
            value = value[:MAX_ARGUMENT_CHARS] + "…[cut]"
        row = {"name": arg.get("name"), "value": value}
        if arg.get("pretty_value") not in (None, value):
            row["pretty"] = arg["pretty_value"]
        arguments.append(row)
    return {
        "ts": call.get("timestamp"), "tid": call.get("thread_id"),
        "api": call.get("api") or call.get("syscall") or "",
        "kernel": "api" not in call, "category": call.get("category") or "",
        "status": call.get("status"), "return": call.get("return"),
        "caller": call.get("caller"), "repeated": call.get("repeated") or 0,
        "plugin": call.get("plugin"), "sources": call.get("sources"),
        "arguments": arguments,
    }


class _CallsLog:
    """CALLS_LOG and CALLS_INDEX, a process at a time."""

    def __init__(self, directory: Path):
        self.file = (directory / CALLS_LOG).open("wb")
        self.directory = directory
        self.offset = 0
        self.processes: dict = {}
        # clrjit.Timeline, when the caller wants the sample's compiled methods
        self.jit = None

    def add(self, proc: dict, calls) -> int:
        """Write a process's calls; their count. A call's position is CAPE's
        `cid` (a signature's mark_call), so chunk = cid // CALLS_PER_CHUNK."""
        chunks, categories, apis, threads = [], Counter(), Counter(), set()
        count, batch, batch_categories = 0, [], Counter()

        def flush():
            nonlocal batch, batch_categories
            if not batch:
                return
            member = gzip.compress(b"\n".join(batch) + b"\n", compresslevel=6)
            self.file.write(member)
            chunks.append([self.offset, len(member), count - len(batch), dict(batch_categories)])
            self.offset += len(member)
            batch, batch_categories = [], Counter()

        for call in calls:
            row = _call_row(call)
            if self.jit is not None:
                self.jit.add(proc.get("process_id"), row)
            batch.append(orjson.dumps(row, default=_json_default))
            batch_categories[row["category"]] += 1
            categories[row["category"]] += 1
            apis[row["api"]] += 1
            if row["tid"] not in (None, ""):
                threads.add(str(row["tid"]))
            count += 1
            if len(batch) == CALLS_PER_CHUNK:
                flush()
        flush()
        self.processes[str(proc["seqid"])] = {
            "pid": proc.get("process_id"), "count": count,
            "threads": sorted(threads, key=lambda t: (len(t), t)),
            "categories": dict(categories.most_common()),
            "apis": dict(apis.most_common(TOP_APIS)),
            "chunks": chunks,
        }
        return count

    def close(self) -> None:
        self.file.close()
        (self.directory / CALLS_INDEX).write_bytes(orjson.dumps(
            {"version": 1, "chunk": CALLS_PER_CHUNK, "log": CALLS_LOG,
             "processes": self.processes}))


def write_results(path: Path, results: dict, sample: Optional[set] = None, jit=None) -> None:
    """`results` as JSON, each process's `calls` replaced by `call_count`;
    the calls of the processes in `sample` (seqids) beside it, in CALLS_LOG.
    Only the sample's: the guest's other processes are not the report's
    (operator, 2026-11-11), and with `scope="all"` they would be most of it."""
    behavior = results.get("behavior") or {}
    processes = []
    calls_log = _CallsLog(path.parent) if sample is not None else None
    if calls_log is not None:
        calls_log.jit = jit
    try:
        for proc in behavior.get("processes", []):
            calls = proc.get("calls")
            if calls is None:
                count = 0
            elif calls_log is not None and proc.get("seqid") in sample:
                count = calls_log.add(proc, calls)
            else:
                count = sum(1 for _ in calls)
            processes.append({**{k: v for k, v in proc.items() if k != "calls"}, "call_count": count})
    finally:
        if calls_log is not None:
            calls_log.close()
    doc = {**results, "behavior": {**behavior, "processes": processes}}
    # The sample's managed methods in the order the runtime compiled them
    compiled = jit.result() if jit is not None else None
    if compiled:
        doc["dotnet_jit"] = compiled
    path.write_bytes(orjson.dumps(doc, default=_json_default,
                                  option=orjson.OPT_NON_STR_KEYS | orjson.OPT_INDENT_2))


def _timeline(analysis_dir: Path, results: dict, split) -> None:
    """Every plugin's records of the sample, in time order, beside the calls
    log (cape_plugin/timeline.py): the platform's Timeline tab. A failure
    here costs the timeline, never the report it is built from; the partial
    files go, so the platform falls back rather than reading half of one."""
    try:
        rows = write_timeline(analysis_dir, results, split.sample, split.aux_dir, CALLS_LOG, CALLS_INDEX)
        log.info("timeline: %d rows", rows)
    except Exception:  # noqa: BLE001 - the report is already written and must ship
        log.exception("timeline not written")
        for name in (TIMELINE_LOG, TIMELINE_INDEX):
            (analysis_dir / name).unlink(missing_ok=True)


def network_filter(cfg: CapeConfigSection) -> dict:
    """NetworkMap's NetworkFilter arguments from the config section: a list
    left unset keeps network_map.py's default."""
    out = {"include_domains": cfg.network_include_domains,
           "include_networks": cfg.network_include_networks}
    if cfg.network_exclude_domains is not None:
        out["exclude_domains"] = cfg.network_exclude_domains
    if cfg.network_exclude_networks is not None:
        out["exclude_networks"] = cfg.network_exclude_networks
    return out


def run_cape(context: PostprocessContext, cfg: CapeConfigSection,
             sample: Optional[Path] = None) -> dict:
    """Split, process, write `cape_results.json`; return `results`. The
    trace is compressed meanwhile (TraceCompression), and stays as it was if
    any of it raises."""
    compression: list = []

    def compress() -> None:
        if cfg.compress_trace:
            compression.append(TraceCompression(context.analysis_dir))

    try:
        results = _run_cape(context, cfg, sample, compress)
    except BaseException:
        for running in compression:
            running.cancel()
        raise
    for running in compression:
        running.finish()
    return results


def _run_cape(context: PostprocessContext, cfg: CapeConfigSection,
              sample: Optional[Path], compress) -> dict:
    """`compress` starts the trace's compression: called once the split's
    first pass, which forks, is over (trace_split.split_by_process)."""
    analysis_dir = context.analysis_dir
    sample = sample or getattr(context, "sample", None)
    started, ended = _trace_times(analysis_dir)
    windows = context.target_os == TargetOs.WINDOWS
    target = _target(context.target_os, sample, str(context.config.yara.rules_directory),
                     str(cape_yara_rules(cfg)))
    results = {
        # CAPE's analysisinfo, as far as a sandboxd job has the facts. Twenty
        # one signature files read `info.package` unconditionally.
        "info": {
            "id": analysis_dir.name, "version": "2.5-CAPE", "category": "file",
            # CAPE's package for the sample's type and name (filetype.package)
            "package": (package(target["file"]["type"], sample.name)
                        if sample is not None and sample.is_file() else DEFAULT_PACKAGE[context.target_os]),
            "machine": {"name": context.target_os.value, "platform": "windows" if windows else "linux"},
            "started": _iso(started), "ended": _iso(ended),
            "duration": int(max(0.0, ended - started)),
            # The trace's first TimeStamp as DRAKVUF wrote it: what the
            # platform shows every time relative to (t+seconds)
            "started_ts": started,
            # What capa reads format, OS and arch from: the guest's, not the
            # sample's own type (a script, a 32-bit PE), see TARGET_FILE_TYPE.
            # Unchanged by what `target.file.type` says of the sample.
            "guest_type": TARGET_FILE_TYPE[context.target_os],
        },
        "target": target,
        "statistics": {"processing": [], "signatures": [], "reporting": []},
    }
    with tempfile.TemporaryDirectory(dir=analysis_dir, prefix=".cape-") as tmp:
        logs = Path(tmp) / "logs"
        paths = PATHS[context.target_os]
        split = split_by_process(analysis_dir, logs, context.target_os,
                                 scope=cfg.scope, kernel_syscalls=cfg.kernel_syscalls,
                                 launch=(paths.shell, paths.delay, sample.name if sample is not None else None)
                                 if cfg.skip_launcher else None,
                                 after_prelude=compress)
        s = split.stats
        log.info("trace split: %d processes (%d in the sample), %d lines, records %s, "
                 "%d syscalls paired / %d unpaired / %d kernel-mode dropped, "
                 "%d processes procmon never saw, %d lines not UTF-8, %d not JSON",
                 s.processes, len(split.sample), s.lines, dict(s.records), s.syscalls_paired,
                 s.syscalls_unpaired, s.kernel_syscalls_dropped, s.nodes_added, s.bad_utf8,
                 s.bad_json)
        results["trace_split"] = {
            "processes": s.processes, "sample_processes": len(split.sample),
            "records": dict(s.records), "merged": dict(s.merged),
            "syscalls_paired": s.syscalls_paired,
            "syscalls_unpaired": s.syscalls_unpaired,
            "kernel_syscalls_dropped": s.kernel_syscalls_dropped,
            "nodes_added": s.nodes_added, "bad_utf8": s.bad_utf8, "bad_json": s.bad_json,
            # Records a raw newline in a value had cut over several lines
            "joined": s.joined,
            # Processes made the sample's by a sample process making them
            # run code (trace_split.follow_transfers), and how
            "followed": split.followed,
            # Of sandboxd's launch (behaviour.mark_launcher), the processes
            # among those: the sample's since it took them over, by seqid
            "launcher_followed": sorted(split.launcher_followed),
            # Threads the sample started through a process handle the trace
            # never saw opened: targets nobody could follow
            "transfers_unresolved": [{"pid": pid, "time": ts, "call": call}
                                     for pid, ts, call in split.unresolved],
            # The sample, by seqid: the injected processes the tree knew, and
            # everything the report shows (theirs, their descendants', the
            # ones they took over). The platform renders nothing else.
            "roots": sorted(split.roots),
            "sample": sorted(split.sample),
        }

        options = CapeOptions(
            analysis_call_limit=cfg.call_limit,
            capa=cfg.capa,
            capa_rules=str(cfg.capa_rules),
            capa_pids=split.sample_pids,
            scope=cfg.scope,
            sample_pids=split.sample_pids,
            launcher=split.launcher,
            yara_rules=str(context.config.yara.rules_directory),
            cape_yara_rules=str(cape_yara_rules(cfg)),
            falco=context.config.falco,
            vlan=context.vlan,
            trace_plugins=set(s.plugins),
            network_filter=network_filter(cfg),
        )
        RunProcessing(context=context, results=results, options=options, logs_path=logs,
                      aux_path=split.aux_dir).run()

        # Inside the `with`: evented signatures iterate the same lazy calls.
        if cfg.signatures:
            loaded = load_signatures(cfg.community)
            if loaded["signatures"]:
                RunSignatures(context=context, results=results).run()

        write_results(analysis_dir / CAPE_RESULTS, results, sample=split.sample,
                      jit=clrjit.Timeline(sample, (analysis_dir / EXTRACTED_DIR, analysis_dir / DUMPS_DIR)))
        # Inside the `with` too: the non-call plugins' records are read from
        # trace_split's aux logs, which go with the temporary directory.
        _timeline(analysis_dir, results, split)
    return results


class TraceCompression:
    """trace.log -> trace.log.gz beside the analysis, not after it.

    Compressing 3 GB took 40 s of a 246 s pass (a 20-minute Windows trace,
    2026-11-14) with the processor idle but for it. zlib works outside the
    interpreter's lock, so a thread does it while the trace is read for the
    analysis: no second process, and no memory but its megabyte of buffer.
    The raw file is removed by `finish`, once the analysis has read the last
    of it and the copy is complete (written under a temporary name, as
    gzip_syscalls did). `cancel` leaves the trace as it was: an analysis that
    raised is uploaded with the raw trace, as before."""

    def __init__(self, analysis_dir: Path):
        self.src = analysis_dir / "trace.log"
        self.tmp = analysis_dir / "trace.log.gz.tmp"
        self.dst = analysis_dir / "trace.log.gz"
        self._stop = threading.Event()
        self._error: Optional[BaseException] = None
        self._thread = threading.Thread(target=self._run, name="compress-trace", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            with self.src.open("rb") as fin, gzip.open(self.tmp, "wb", compresslevel=6) as fout:
                while not self._stop.is_set():
                    block = fin.read(1 << 20)
                    if not block:
                        break
                    fout.write(block)
        except BaseException as exc:  # noqa: BLE001 - reported by finish, in the caller's thread
            self._error = exc

    def finish(self) -> None:
        self._thread.join()
        if self._error is not None:
            self.tmp.unlink(missing_ok=True)
            raise self._error
        self.tmp.replace(self.dst)
        self.src.unlink()

    def cancel(self) -> None:
        self._stop.set()
        self._thread.join()
        self.tmp.unlink(missing_ok=True)


def compress_trace(analysis_dir: Path) -> None:
    """trace.log -> trace.log.gz, the raw file removed only once the copy is
    complete."""
    TraceCompression(analysis_dir).finish()


def cape_analysis(context: PostprocessContext) -> None:
    cfg = context.config.cape
    if not cfg.enabled:
        log.info("cape_analysis is disabled (SANDBOXD_POSTPROCESS_CAPE)")
        return
    run_cape(context, cfg)