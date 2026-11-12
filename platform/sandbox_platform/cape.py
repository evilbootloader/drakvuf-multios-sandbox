"""The CAPE report of one run: `cape_results.json`, read back for the job page.

`sandboxd/postprocessing/plugins/cape_analysis.py` writes it on Dom0: CAPE's
processing modules and signatures over the run's trace. This module is its
only reader. Everything in it is what the sample did -- process names,
command lines, paths, registry keys, URLs, buffers -- so it is untrusted
input, read with the discipline `report.py` had for its predecessor:

- **Bounded before it is parsed.** A read stops at MAX_RESULTS_BYTES; every
  string is cut at MAX_STRING and every list at MAX_ITEMS before pydantic sees
  them, so the cost of a page is a function of these constants.
- **Lenient about shape, strict about type -- per section.** A key this module
  does not know is ignored. A section whose types are wrong is dropped and
  named in `Report.section_errors`; the rest of the report still renders,
  because one signature's odd data must not blank a page of facts.
- **Never raises into a page.** `for_job` returns a `Loaded` whose `error`
  names what went wrong; the templates render that sentence.

**The sample's processes only.** The page is the malware's, not the guest's
(operator, 2026-11-11): every section is cut to the processes in
`trace_split.sample` -- the injected ones, their descendants, the ones they
took over -- right after loading. sandboxd already writes the sample's alone
under its default scope; this makes a `scope="all"` run read the same, and
keeps the browser's page the size of what the sample did.

Rendering is Jinja with autoescape on, and nothing under `templates/tabs/`
marks report text `| safe`; `tests/test_ui.py` counts the marks.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from functools import cached_property, lru_cache
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import manifest as manifest_schema
from . import objects

log = logging.getLogger("sandbox_platform.cape")

RESULTS_NAME = "cape_results.json"

# 78 KB for a one-process Windows run (samples/trace-windows.log through the
# CAPE pass, 2026-11-11); the calls are not in it (calls.py). 64 MiB leaves
# room for a sample that touches thousands of files and keys, and is still
# one read.
MAX_RESULTS_BYTES = 64 * 1024 * 1024

# Per string and per list, applied before validation. An encrypted buffer
# is the longest string the report carries: 4 KiB printed with \xHH escapes.
MAX_STRING = 16 * 1024
MAX_ITEMS = 20_000
MAX_DEPTH = 16
TRUNCATED = "…[truncated]"


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="ignore")


Number = int | float


# --- the sections ------------------------------------------------------------

class Process(_Lenient):
    """One process of `behavior.processes`, with trace_split's identity of it
    (`seqid`, `parent_seqid`, times and exit, added for this page)."""
    process_id: int
    process_name: str = ""
    parent_id: int | None = None
    module_path: str = ""
    threads: list[str | int] = Field(default_factory=list)
    environ: dict[str, Any] = Field(default_factory=dict)
    file_activities: dict[str, list[str]] = Field(default_factory=dict)
    seqid: int | None = None
    parent_seqid: int | None = None
    started_ts: Number | None = None
    exited_ts: Number | None = None
    exit_code: int | None = None
    exit_code_str: str | None = None
    killed_by: int | None = None
    call_count: int = 0

    @property
    def basename(self) -> str:
        name = self.process_name or self.module_path
        return name.replace("\\", "/").rsplit("/", 1)[-1] or name

    @property
    def command_line(self) -> str:
        value = self.environ.get("CommandLine")
        return value if isinstance(value, str) else ""

    @property
    def exited_with_error(self) -> bool:
        # NTSTATUS severity bits, where procmon named the code (Windows)
        return bool(self.exit_code_str) and self.exit_code is not None \
            and bool(self.exit_code & 0xC0000000)

    @property
    def ended(self) -> bool:
        return self.exited_ts is not None or self.exit_code is not None


class Signature(_Lenient):
    name: str
    description: str = ""
    categories: list[str] = Field(default_factory=list)
    severity: int = 1
    confidence: Number = 0
    weight: Number = 0
    references: list[str] = Field(default_factory=list)
    families: list[str] = Field(default_factory=list)
    data: list[Any] = Field(default_factory=list)
    alert: bool = False
    # From results["ttps"], joined by signature name in Report.signatures
    ttps: list[str] = Field(default_factory=list)
    mbcs: list[str] = Field(default_factory=list)

    @property
    def level(self) -> str:
        """CAPE's severity as a word: 1 low, 2 medium, 3 and over high."""
        return "high" if self.severity >= 3 else "medium" if self.severity == 2 else "low"


class TtpGroup(_Lenient):
    signature: str = ""
    ttps: list[str] = Field(default_factory=list)
    mbcs: list[str] = Field(default_factory=list)


class Capa(_Lenient):
    """CAPE's `capa_summary`: `ATTCK` and `MBC` as {tactic: ["Name:: id"]},
    `CAPABILITY` as {namespace: ["rule (N matches)"]}."""
    ATTCK: dict[str, list[str]] = Field(default_factory=dict)
    MBC: dict[str, list[str]] = Field(default_factory=dict)
    CAPABILITY: dict[str, list[str]] = Field(default_factory=dict)


class Event(_Lenient):
    """One `behavior.enhanced` event, with the process that made it."""
    event: str
    object: str
    timestamp: str | Number | None = None
    eid: int = 0
    data: dict[str, Any] = Field(default_factory=dict)
    pid: int | None = None
    seqid: int | None = None

    @property
    def target(self) -> str:
        """What the event is about, in one line."""
        d = self.data
        if self.event in ("move", "copy"):
            return f"{d.get('from') or ''} → {d.get('to') or ''}"
        for key in ("file", "regkey", "service", "windowname", "classname"):
            if d.get(key):
                return str(d[key])
        return ""


class Anomaly(_Lenient):
    name: str = ""
    pid: int | None = None
    category: str | None = None
    funcname: str | None = None
    message: str | None = None


class EncryptedBuffer(_Lenient):
    process_name: str = ""
    pid: int | None = None
    api_call: str = ""
    direction: str = "encrypt"
    buffer: str = ""
    buffer_size: int | None = None
    crypt_key: str | int | None = None
    algorithm: str | None = None
    key: str | None = None


class PInfo(_Lenient):
    process_id: int | None = None
    process_name: str = ""
    events: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)


class Endpoint(_Lenient):
    ip_port: str = ""
    ip: str = ""
    port: int | None = None
    pinfo: list[PInfo] = Field(default_factory=list)


class UnixSocket(_Lenient):
    path: str = ""
    pinfo: list[PInfo] = Field(default_factory=list)


class HostProcesses(_Lenient):
    host: str = ""
    pinfo: list[PInfo] = Field(default_factory=list)


class AgentProcesses(_Lenient):
    user_agent: str = ""
    pinfo: list[PInfo] = Field(default_factory=list)


class DnsIntent(_Lenient):
    process: PInfo = Field(default_factory=PInfo)
    api: str = ""
    sources: list[str] = Field(default_factory=list)
    answers: list[str] = Field(default_factory=list)


class DnsIntents(_Lenient):
    domain: str
    intents: list[DnsIntent] = Field(default_factory=list)


class DnsAnswers(_Lenient):
    domain: str
    answers: list[str] = Field(default_factory=list)


class HttpRequest(_Lenient):
    url: str | None = None
    host: str | None = None
    method: str | None = None
    user_agent: str | None = None
    process_id: int | None = None
    process_name: str | None = None
    time: str | Number | None = None
    api: str = ""
    source: str = ""


class NetworkMap(_Lenient):
    endpoint_map: list[Endpoint] = Field(default_factory=list)
    listeners: list[Endpoint] = Field(default_factory=list)
    unix_sockets: list[UnixSocket] = Field(default_factory=list)
    http_host_map: list[HostProcesses] = Field(default_factory=list)
    dns_intents: list[DnsIntents] = Field(default_factory=list)
    dns_answers: list[DnsAnswers] = Field(default_factory=list)
    http_requests: list[HttpRequest] = Field(default_factory=list)
    user_agents: list[AgentProcesses] = Field(default_factory=list)
    filtered: dict[str, int] = Field(default_factory=dict)


class Flow(_Lenient):
    src: str = ""
    sport: int | None = None
    dst: str = ""
    dport: int | None = None
    time: Number | None = None
    process_id: int | None = None
    process_name: str | None = None
    source: str = ""


class Host(_Lenient):
    ip: str = ""
    hostname: str = ""
    ports: list[int] = Field(default_factory=list)


class DnsAnswer(_Lenient):
    type: str = ""
    data: str = ""


class DnsRecord(_Lenient):
    request: str = ""
    type: str = ""
    answers: list[DnsAnswer] = Field(default_factory=list)
    process_id: int | None = None
    process_name: str | None = None
    source: str = ""


class PcapHttp(_Lenient):
    uri: str | None = None
    host: str = ""
    method: str = ""
    user_agent: str = Field("", alias="user-agent")
    process_id: int | None = None
    process_name: str | None = None
    source: str = ""
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class Network(_Lenient):
    """CAPE's `network`: what the behaviour attributed to a process
    (`source: behavior`) and what only the capture shows."""
    hosts: list[Host] = Field(default_factory=list)
    tcp: list[Flow] = Field(default_factory=list)
    udp: list[Flow] = Field(default_factory=list)
    dns: list[DnsRecord] = Field(default_factory=list)
    http: list[PcapHttp] = Field(default_factory=list)


class YaraHit(_Lenient):
    name: str = ""
    namespace: str = ""
    meta: dict[str, Any] = Field(default_factory=dict)
    strings: list[str] = Field(default_factory=list)


class FileFacts(_Lenient):
    """A file CAPE described (FileInfo.describe): the target, a dropped file,
    a process dump. `path` is a Dom0 path and never shown."""
    name: str | list[str] = ""
    path: str = ""
    size: int | None = None
    type: str = ""
    crc32: str = ""
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    sha512: str = ""
    yara: list[YaraHit] = Field(default_factory=list)
    cape_yara: list[YaraHit] = Field(default_factory=list)

    @property
    def display_name(self) -> str:
        if isinstance(self.name, list):
            return self.name[0] if self.name else ""
        return self.name

    @property
    def stored_name(self) -> str:
        """The file's name in the job's artifacts (its Dom0 path's last part)."""
        return self.path.replace("\\", "/").rsplit("/", 1)[-1]

    @property
    def hits(self) -> list[YaraHit]:
        return [*self.yara, *self.cape_yara]


class Dropped(FileFacts):
    guest_paths: list[str] | str = Field(default_factory=list)
    pid: int | None = None
    process_name: str = ""
    process_path: str = ""
    reason: str = ""

    @property
    def guest_path(self) -> str:
        if isinstance(self.guest_paths, list):
            return self.guest_paths[0] if self.guest_paths else ""
        return self.guest_paths


class ProcDump(FileFacts):
    pid: int | None = None
    process_name: str = ""
    target_pid: int | None = None
    target_process: str = ""
    dump_size: str | int | None = None
    compression: str | None = None
    status: str | None = None


class Region(_Lenient):
    start: str = ""
    end: str = ""
    size: str = ""
    path: str = ""
    sha256: str = ""
    type: str = ""
    method: str | None = None
    reason: str | None = None
    target_pid: int | None = None

    @property
    def stored_name(self) -> str:
        return self.path.replace("\\", "/").rsplit("/", 1)[-1]


class ProcMemory(_Lenient):
    pid: int | None = None
    name: str = ""
    proc_path: str = ""
    yara: list[YaraHit] = Field(default_factory=list)
    address_space: list[Region] = Field(default_factory=list)


class Section(_Lenient):
    name: str = ""
    virtual_address: str = ""
    virtual_size: str = ""
    size_of_data: str = ""
    characteristics: str = ""
    entropy: str = ""


class ImportedSymbol(_Lenient):
    address: str = ""
    name: str = ""


class ImportedDll(_Lenient):
    dll: str = ""
    imports: list[ImportedSymbol] = Field(default_factory=list)


class Export(_Lenient):
    address: str = ""
    name: str = ""
    ordinal: int | None = None


class NameValue(_Lenient):
    name: str = ""
    value: str = ""


class Pe(_Lenient):
    imagebase: str = ""
    entrypoint: str = ""
    machine_type: str = ""
    timestamp: str = ""
    imphash: str = ""
    sections: list[Section] = Field(default_factory=list)
    imports: dict[str, ImportedDll] = Field(default_factory=dict)
    exports: list[Export] = Field(default_factory=list)
    versioninfo: list[NameValue] = Field(default_factory=list)
    overlay: dict[str, Any] | None = None
    pdbpath: str | None = None


class TargetFile(FileFacts):
    pe: Pe | None = None


class Target(_Lenient):
    category: str = "file"
    file: TargetFile = Field(default_factory=TargetFile)


class Info(_Lenient):
    started: str = ""
    ended: str = ""
    duration: Number = 0
    started_ts: Number | None = None
    machine: dict[str, Any] = Field(default_factory=dict)


class Transfer(_Lenient):
    """A control transfer trace_split followed (follow_transfers)."""
    pid: int
    target_pid: int
    time: Number | None = None
    how: str = ""


class TraceSplit(_Lenient):
    processes: int = 0
    sample_processes: int = 0
    records: dict[str, int] = Field(default_factory=dict)
    merged: dict[str, int] = Field(default_factory=dict)
    syscalls_paired: int = 0
    syscalls_unpaired: int = 0
    kernel_syscalls_dropped: int = 0
    nodes_added: int = 0
    bad_utf8: int = 0
    bad_json: int = 0
    followed: list[Transfer] = Field(default_factory=list)
    roots: list[int] | None = None
    sample: list[int] | None = None


class FalcoAlert(_Lenient):
    rule: str = ""
    priority: str = ""
    output: str = ""
    tags: list[str] = Field(default_factory=list)
    pid: int | None = None
    count: int = 1
    time: str | Number | None = None


class Falco(_Lenient):
    alerts: list[FalcoAlert] = Field(default_factory=list)
    coverage: dict[str, Any] = Field(default_factory=dict)


SUMMARY_KEYS = ("files", "read_files", "write_files", "delete_files", "keys", "read_keys",
                "write_keys", "delete_keys", "executed_commands", "resolved_apis", "mutexes",
                "created_services", "started_services")


# --- derived shapes -------------------------------------------------------------

@dataclass
class Node:
    process: Process
    children: list[Node] = field(default_factory=list)

    def walk(self):
        """Pre-order, iteratively: a report is untrusted, and a chain
        thousands deep would exhaust Python's recursion limit."""
        stack = [self]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(node.children))

    @property
    def descendants(self) -> int:
        return sum(1 for _ in self.walk()) - 1


@dataclass(frozen=True)
class Mark:
    """One row of a signature's matched data, classified for display:
    `call` (a call by pid and cid, which opens in place), `process`, `ioc`
    (a typed value from add_match), `field` (anything else, as text)."""
    kind: str
    label: str = ""
    value: str = ""
    pid: int | None = None
    cid: int | None = None


@dataclass(frozen=True)
class Technique:
    """One ATT&CK technique, from capa and/or signatures."""
    id: str
    name: str
    tactic: str
    capa: bool
    signatures: tuple[str, ...]


_TECHNIQUE_ID = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
_BEHAVIOR_ID = re.compile(r"\[?\b([BCEF]\d{4}(?:\.\d{3})?)\b\]?")


def _text(value: Any) -> str:
    """A signature datum as one line of text."""
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    try:
        return json.dumps(value, ensure_ascii=False, separators=(", ", ": "))[:MAX_STRING]
    except (TypeError, ValueError):
        return str(value)[:MAX_STRING]


def _datum_pid(item: Any) -> int | None:
    """The process a signature datum names, if it names one."""
    if not isinstance(item, dict):
        return None
    pid = item.get("pid", item.get("process_id"))
    if isinstance(pid, int) and not isinstance(pid, bool):
        return pid
    proc = item.get("process")
    if isinstance(proc, dict):
        pid = proc.get("process_id", proc.get("pid"))
        if isinstance(pid, int) and not isinstance(pid, bool):
            return pid
    return None


def marks(signature: Signature) -> list[Mark]:
    out: list[Mark] = []
    for item in signature.data:
        if isinstance(item, dict) and item.get("type") == "call" \
                and isinstance(item.get("cid"), int) and isinstance(item.get("pid"), int):
            out.append(Mark("call", pid=item["pid"], cid=item["cid"]))
            continue
        if isinstance(item, dict) and isinstance(item.get("signs"), list):
            proc = item.get("process")
            if isinstance(proc, dict):
                out.append(Mark("process", "process", _text(proc.get("process_name")),
                                pid=_datum_pid(item)))
            for sign in item["signs"]:
                if isinstance(sign, dict):
                    out.append(Mark("ioc", _text(sign.get("type")), _text(sign.get("value"))))
            continue
        if isinstance(item, dict):
            for key, value in item.items():
                out.append(Mark("field", str(key), _text(value), pid=_datum_pid(item)))
            continue
        out.append(Mark("field", "", _text(item)))
    return out


# --- the report -------------------------------------------------------------------

class Report:
    """The sections the page renders, each validated on its own and cut to
    the sample's processes."""

    def __init__(self, document: dict):
        self.section_errors: dict[str, str] = {}
        behavior = document.get("behavior") if isinstance(document.get("behavior"), dict) else {}

        self.info = self._one(Info, document.get("info"), "info")
        self.target = self._one(Target, document.get("target"), "target")
        self.trace_split = self._one(TraceSplit, document.get("trace_split"), "trace_split")
        processes = self._many(Process, behavior.get("processes"), "processes")

        # The sample, by seqid; all of them for a report from before
        # trace_split wrote it (sandboxd's own scope was the sample then).
        if self.trace_split.sample is not None:
            sample = set(self.trace_split.sample)
            processes = [p for p in processes if p.seqid in sample]
        self.processes = processes
        self.sample_seqids = {p.seqid for p in processes if p.seqid is not None}
        self.sample_pids = {p.process_id for p in processes}
        self.roots = set(self.trace_split.roots or ())

        mine = self._mine
        self._raw_signatures = self._many(Signature, document.get("signatures"), "signatures")
        ttp_groups = self._many(TtpGroup, document.get("ttps"), "ttps")
        self.capa = self._one(Capa, document.get("capa_summary") or {}, "capa_summary")
        self.falco = self._one(Falco, document.get("falco") or {}, "falco")
        self.falco.alerts = [a for a in self.falco.alerts if a.pid is None or mine(a.pid)]

        summary = dict(behavior.get("summary") or {}) if isinstance(behavior.get("summary"), dict) else {}
        by_process = summary.pop("by_process", None)
        self.summary = {k: list(v) for k, v in self._dict_of_lists(summary, "summary").items()
                        if k in SUMMARY_KEYS}
        # Each process's own lists (sandboxd's Summary.by_process), the
        # sample's only; None for a report from before they were written.
        self.summary_by_process: dict[int, dict[str, list[str]]] | None = None
        if isinstance(by_process, dict):
            self.summary_by_process = {}
            for key, lists in by_process.items():
                try:
                    seqid = int(key)
                except ValueError:
                    continue
                if seqid in self.sample_seqids:
                    self.summary_by_process[seqid] = _autostart_first({
                        k: v for k, v in self._dict_of_lists(lists, "summary.by_process").items()
                        if k in SUMMARY_KEYS and v})
        self.events = [e for e in self._many(Event, behavior.get("enhanced"), "enhanced")
                       if self._event_mine(e)]
        self.anomalies = [a for a in self._many(Anomaly, behavior.get("anomaly"), "anomaly")
                          if a.name == "kernel" or mine(a.pid)]
        self.encrypted = [b for b in self._many(EncryptedBuffer, behavior.get("encryptedbuffers"),
                                                "encryptedbuffers") if mine(b.pid)]
        self.network_map = self._cut_network_map(
            self._one(NetworkMap, behavior.get("network_map") or {}, "network_map"))
        self.network = self._cut_network(
            self._one(Network, document.get("network") or {}, "network"))
        self.dropped = [d for d in self._many(Dropped, document.get("dropped"), "dropped")
                        if mine(d.pid)]
        self.procdump = [d for d in self._many(ProcDump, document.get("procdump"), "procdump")
                         if mine(d.pid)]
        self.procmemory = [m for m in self._many(ProcMemory, document.get("procmemory"), "procmemory")
                           if mine(m.pid)]

        # Signatures: TTPs joined by name; data rows naming another process
        # dropped, and a signature with nothing of the sample's left dropped too
        by_name: dict[str, TtpGroup] = {g.signature: g for g in ttp_groups}
        self.signatures: list[Signature] = []
        for sig in self._raw_signatures:
            data = [d for d in sig.data if _datum_pid(d) is None or mine(_datum_pid(d))]
            if sig.data and not data:
                continue
            group = by_name.get(sig.name)
            self.signatures.append(sig.model_copy(update={
                "data": data,
                "ttps": sig.ttps or (group.ttps if group else []),
                "mbcs": sig.mbcs or (group.mbcs if group else [])}))
        self.signatures.sort(key=lambda s: (-s.severity, s.name))

        # Under scope "all" the summary lists are every process's: rebuilt
        # from what the sample's own processes did.
        if self.trace_split.sample is not None and self.trace_split.processes > len(self.sample_seqids):
            self.summary = self._summary_from_sample()
        self.summary = _autostart_first(self.summary)

    # -- validation, a section at a time -----------------------------------------

    def _note(self, name: str, exc: ValidationError) -> None:
        problems = "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"
                             for e in exc.errors()[:3])
        self.section_errors[name] = problems

    def _one(self, model, value, name):
        try:
            return model.model_validate(value if isinstance(value, dict) else {})
        except ValidationError as exc:
            self._note(name, exc)
            return model()

    def _many(self, model, value, name) -> list:
        """Each item on its own: a bad one is skipped and counted, the rest kept."""
        if not isinstance(value, list):
            return []
        out, bad, first = [], 0, None
        for item in value:
            try:
                out.append(model.model_validate(item))
            except ValidationError as exc:
                bad += 1
                first = first or exc
        if bad:
            self._note(name, first)
            self.section_errors[name] = f"{bad} entr{'y' if bad == 1 else 'ies'} unreadable ({self.section_errors[name]})"
        return out

    def _dict_of_lists(self, value, name) -> dict[str, list[str]]:
        if not isinstance(value, dict):
            return {}
        out = {}
        for key, items in value.items():
            if isinstance(items, list):
                out[str(key)] = [i for i in items if isinstance(i, str)]
            else:
                self.section_errors[name] = f"{key}: not a list"
        return out

    # -- the sample -----------------------------------------------------------------

    def _mine(self, pid: int | None) -> bool:
        return pid is not None and pid in self.sample_pids

    def _event_mine(self, event: Event) -> bool:
        if event.seqid is not None:
            return event.seqid in self.sample_seqids
        return self._mine(event.pid)

    def _pinfo_cut(self, items: list) -> list:
        out = []
        for item in items:
            kept = [p for p in item.pinfo if self._mine(p.process_id)]
            if kept:
                out.append(item.model_copy(update={"pinfo": kept}))
        return out

    def _cut_network_map(self, nm: NetworkMap) -> NetworkMap:
        intents = []
        for d in nm.dns_intents:
            kept = [i for i in d.intents if self._mine(i.process.process_id)]
            if kept:
                intents.append(d.model_copy(update={"intents": kept}))
        domains = {d.domain for d in intents}
        return nm.model_copy(update={
            "endpoint_map": self._pinfo_cut(nm.endpoint_map),
            "listeners": self._pinfo_cut(nm.listeners),
            "unix_sockets": self._pinfo_cut(nm.unix_sockets),
            "http_host_map": self._pinfo_cut(nm.http_host_map),
            "user_agents": self._pinfo_cut(nm.user_agents),
            "dns_intents": intents,
            "dns_answers": [a for a in nm.dns_answers if a.domain in domains],
            "http_requests": [r for r in nm.http_requests if self._mine(r.process_id)],
        })

    def _cut_network(self, net: Network) -> Network:
        """The capture's view, kept where it meets the sample: a flow or a
        record a process is credited with, the sample's; one the capture
        alone saw, kept when its far end is an address or name the sample
        used. The whole capture is a download on the same tab."""
        ips = {e.ip for e in self.network_map.endpoint_map}
        names = {d.domain for d in self.network_map.dns_intents}
        for a in self.network_map.dns_answers:
            ips.update(a.answers)

        def keep(pid, *ends) -> bool:
            if pid is not None:
                return self._mine(pid)
            return any(e and (e in ips or e in names) for e in ends)

        return net.model_copy(update={
            "tcp": [f for f in net.tcp if keep(f.process_id, f.dst)],
            "udp": [f for f in net.udp if keep(f.process_id, f.dst)],
            "dns": [d for d in net.dns if keep(d.process_id, d.request)],
            "http": [h for h in net.http if keep(h.process_id, h.host)],
            "hosts": [h for h in net.hosts if h.ip in ips or h.hostname in names],
        })

    def _summary_from_sample(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {k: [] for k in SUMMARY_KEYS}

        def add(key, value):
            if value and value not in out[key]:
                out[key].append(value)
        if self.summary_by_process is not None:
            # The sample's own lists, merged: exact
            for lists in self.summary_by_process.values():
                for key, items in lists.items():
                    for item in items:
                        add(key, item)
            return out
        # A report from before them: what the processes' file activities
        # and the timeline say
        for p in self.processes:
            for kind in ("read_files", "write_files", "delete_files"):
                for f in p.file_activities.get(kind, []):
                    add(kind, f)
                    add("files", f)
        for e in self.events:
            target = e.target
            if e.object == "registry":
                add("keys", target)
                add({"write": "write_keys", "read": "read_keys", "delete": "delete_keys"}
                    .get(e.event, "keys"), target)
            elif e.event == "execute":
                add("executed_commands", target)
            elif e.object == "service":
                add("started_services" if e.event == "start" else "created_services", target)
        return out

    # -- for the templates ----------------------------------------------------------

    def summary_groups(self) -> list[tuple[Process, dict[str, list[str]], list[EncryptedBuffer]]] | None:
        """Summary, one group per process of the sample, in the tree's order:
        each process, its own lists and its encrypted buffers -- the ones with
        nothing too, which the tab names in one line. None for a report from
        before sandboxd kept the lists per process."""
        if self.summary_by_process is None:
            return None
        out = []
        for root in self.tree:
            for node in root.walk():
                p = node.process
                out.append((p, self.summary_by_process.get(p.seqid, {}),
                            [b for b in self.encrypted if b.pid == p.process_id]))
        return out

    @cached_property
    def by_seqid(self) -> dict[int, Process]:
        return {p.seqid: p for p in self.processes if p.seqid is not None}

    @cached_property
    def by_pid(self) -> dict[int, list[Process]]:
        out: dict[int, list[Process]] = {}
        for p in self.processes:
            out.setdefault(p.process_id, []).append(p)
        return out

    def process_for(self, pid: int | None) -> Process | None:
        """The sample's process with that PID; the first, where one reused it."""
        found = self.by_pid.get(pid) if pid is not None else None
        return found[0] if found else None

    def t(self, ts: Any) -> float | None:
        """A TimeStamp as seconds into the trace; None when unknown (apimon's
        DLL events carry none)."""
        try:
            value = float(ts)
        except (TypeError, ValueError):
            return None
        if value <= 0 or self.info.started_ts is None:
            return None
        return max(0.0, value - float(self.info.started_ts))

    @cached_property
    def tree(self) -> list[Node]:
        """The sample's processes as a forest, by trace_split's parent seqid.
        A parent outside the sample makes a root; a loop is cut at its
        lowest seqid (the process procmon saw first)."""
        seqids = set(self.by_seqid)
        parent_of = {s: p.parent_seqid if p.parent_seqid in seqids and p.parent_seqid != s else None
                     for s, p in self.by_seqid.items()}
        ON_PATH, DONE = 1, 2
        state: dict[int, int] = {}
        for start in parent_of:
            path: list[int] = []
            s = start
            while s is not None and s not in state:
                state[s] = ON_PATH
                path.append(s)
                s = parent_of[s]
            if s is not None and state[s] == ON_PATH:
                parent_of[min(path[path.index(s):])] = None
            for s in path:
                state[s] = DONE
        nodes = {s: Node(p) for s, p in sorted(self.by_seqid.items())}
        roots: list[Node] = []
        for s, node in nodes.items():
            parent = parent_of[s]
            (roots if parent is None else nodes[parent].children).append(node)
        # Processes without a seqid (a report from before it was written)
        roots.extend(Node(p) for p in self.processes if p.seqid is None)
        return roots

    @cached_property
    def followed_seqids(self) -> set[int]:
        """The processes the sample took over (control transfers), each the
        instance alive at the transfer -- marked in the tree."""
        out = set()
        for t in self.trace_split.followed:
            for p in self.by_pid.get(t.target_pid, ()):
                if p.started_ts is None or t.time is None or p.started_ts <= t.time:
                    out.add(p.seqid)
        return out

    def diagram(self) -> Diagram:
        return layout(self.tree, self.roots, len(self.processes))

    @cached_property
    def root_process(self) -> Process | None:
        for s in sorted(self.roots):
            if s in self.by_seqid:
                return self.by_seqid[s]
        return self.tree[0].process if self.tree else None

    @property
    def dump_count(self) -> int:
        return len(self.procdump) + sum(len(m.address_space) for m in self.procmemory)


    @property
    def autostart_writes(self) -> list[str]:
        return [k for k in self.summary.get("write_keys", []) if is_autostart(k)]

    def tab_counts(self) -> dict[str, int]:
        """The number beside a tab's label, where one number means something."""
        return {k: v for k, v in {
            "signatures": len(self.signatures),
            "behaviour": len(self.processes),
            "timeline": len(self.events),
            "network": len(self.network_map.endpoint_map) + len(self.network_map.dns_intents),
            "dropped": len(self.dropped),
            "memory": self.dump_count,
        }.items() if v}

    def filled_tabs(self) -> set[str]:
        filled = {"overview"}
        if self.signatures or self.capa.CAPABILITY or self.falco.alerts or self.yara_hits:
            filled.add("signatures")
        if self.processes:
            filled.add("behaviour")
        if self.events or self.anomalies:
            filled.add("timeline")
        if any(self.summary.values()) or self.encrypted:
            filled.add("summary")
        nm = self.network_map
        if (nm.endpoint_map or nm.listeners or nm.unix_sockets or nm.dns_intents
                or nm.http_requests or self.network.tcp or self.network.udp):
            filled.add("network")
        if self.dropped:
            filled.add("dropped")
        if self.dump_count:
            filled.add("memory")
        if self.target.file.pe or self.target.file.sha256:
            filled.add("static")
        return filled

    # -- per process ----------------------------------------------------------------

    def activity(self, process: Process) -> dict[str, list]:
        """One process's share of the report: the panel's "its own activity"."""
        pid = process.process_id

        def has(pinfo):
            return any(p.process_id == pid for p in pinfo)
        nm = self.network_map
        return {
            "events": [e for e in self.events if e.seqid == process.seqid
                       or (e.seqid is None and e.pid == pid)],
            "endpoints": [e for e in nm.endpoint_map if has(e.pinfo)],
            "listeners": [e for e in nm.listeners if has(e.pinfo)],
            "dns": [d.domain for d in nm.dns_intents
                    if any(i.process.process_id == pid for i in d.intents)],
            "http": [r for r in nm.http_requests if r.process_id == pid],
            "signatures": [s for s in self.signatures
                           if any(_datum_pid(d) == pid for d in s.data)],
            "encrypted": [b for b in self.encrypted if b.pid == pid],
        }

    # -- detections -----------------------------------------------------------------

    @cached_property
    def techniques(self) -> list[Technique]:
        """ATT&CK from capa (named, under a tactic) and from signatures (by
        id, naming the signatures), merged by technique id."""
        found: dict[str, dict] = {}
        for tactic, items in self.capa.ATTCK.items():
            for item in items:
                m = _TECHNIQUE_ID.search(item)
                if not m:
                    continue
                name = item.split("::")[0].strip()
                entry = found.setdefault(m.group(1), {"name": name, "tactic": tactic.title(),
                                                       "capa": True, "sigs": []})
                entry["capa"] = True
        for sig in self.signatures:
            for ttp in sig.ttps:
                m = _TECHNIQUE_ID.search(ttp)
                if not m:
                    continue
                entry = found.setdefault(m.group(1), {"name": "", "tactic": "", "capa": False, "sigs": []})
                if sig.name not in entry["sigs"]:
                    entry["sigs"].append(sig.name)
        return sorted((Technique(tid, e["name"], e["tactic"], e["capa"], tuple(e["sigs"]))
                       for tid, e in found.items()),
                      key=lambda t: (t.tactic or "~", t.id))

    @cached_property
    def behaviors(self) -> list[tuple[str, str, str]]:
        """MBC from capa: (objective, behaviour, id)."""
        out = []
        for objective, items in self.capa.MBC.items():
            for item in items:
                m = _BEHAVIOR_ID.search(item)
                out.append((objective.title(), item.split("::")[0].strip(), m.group(1) if m else ""))
        return out

    @cached_property
    def yara_hits(self) -> list[tuple[str, str, YaraHit]]:
        """Every YARA hit: (where, what file, hit)."""
        out = [("sample", self.target.file.display_name or "the sample", h)
               for h in self.target.file.hits]
        out += [("dropped", d.display_name, h) for d in self.dropped for h in d.hits]
        out += [("process dump", d.display_name, h) for d in self.procdump for h in d.hits]
        out += [("memory", f"{m.name} ({m.pid})", h) for m in self.procmemory for h in m.yara]
        return out

    def signature_marks(self, signature: Signature) -> list[Mark]:
        return marks(signature)


# Autostart locations, by the key path as CAPE names it (HKEY_...). A hint
# for the eye -- these are where a persistence write goes -- not a verdict.
_AUTOSTART = re.compile(
    r"\\(?:Run|RunOnce|RunOnceEx|RunServices|RunServicesOnce|Winlogon|Shell Folders"
    r"|User Shell Folders|Image File Execution Options|AppInit_DLLs|Services\\[^\\]+\\ImagePath"
    r"|Explorer\\Run|Policies\\Explorer\\Run|Windows\\Load|Active Setup\\Installed Components)(?:\\|\Z)",
    re.I)


def is_autostart(key: str) -> bool:
    return bool(_AUTOSTART.search(key or ""))


def _autostart_first(lists: dict[str, list[str]]) -> dict[str, list[str]]:
    """The registry lists with their autostart keys first, in their own
    order otherwise: what a reader scans them for, and an order every page of
    a long list agrees on."""
    out = dict(lists)
    for kind in ("write_keys", "read_keys", "delete_keys"):
        if kind in out:
            out[kind] = sorted(out[kind], key=lambda k: not is_autostart(k))
    return out


# --- the diagram --------------------------------------------------------------------
#
# The sample's process forest as inline SVG, laid out here and drawn by the
# template: left to right, one row per leaf, a parent centred on its children.

NODE_W = 180
NODE_H = 22
COL_GAP = 40
ROW_GAP = 8
PAD = 8
LABEL_CHARS = 18


@dataclass(frozen=True)
class Box:
    process: Process
    x: int
    y: int
    depth: int
    root: bool

    @property
    def label(self) -> str:
        name = self.process.basename
        return name if len(name) <= LABEL_CHARS else name[:LABEL_CHARS - 1] + "…"

    @property
    def cy(self) -> int:
        return self.y + NODE_H // 2


@dataclass(frozen=True)
class Edge:
    x1: int
    y1: int
    x2: int
    y2: int

    @property
    def path(self) -> str:
        mid = (self.x1 + self.x2) // 2
        return f"M{self.x1} {self.y1} H{mid} V{self.y2} H{self.x2}"


@dataclass(frozen=True)
class Diagram:
    width: int
    height: int
    boxes: tuple[Box, ...]
    edges: tuple[Edge, ...]
    shown: int
    total: int
    node_w: int = NODE_W
    node_h: int = NODE_H


def layout(roots: list[Node], root_seqids: set[int], total: int) -> Diagram:
    """Iterative post-order placement: a deep chain cannot overflow the stack."""
    boxes: list[Box] = []
    edges: list[Edge] = []
    placed: dict[int, Box] = {}
    row = 0
    for root in roots:
        stack: list[tuple[Node, int, bool]] = [(root, 0, False)]
        while stack:
            node, depth, visited = stack.pop()
            if not visited:
                stack.append((node, depth, True))
                stack.extend((c, depth + 1, False) for c in reversed(node.children))
                continue
            x = PAD + depth * (NODE_W + COL_GAP)
            kids = [placed[id(c)] for c in node.children]
            if kids:
                y = (kids[0].y + kids[-1].y) // 2
            else:
                y = PAD + row * (NODE_H + ROW_GAP)
                row += 1
            box = Box(node.process, x, y, depth, node.process.seqid in root_seqids)
            placed[id(node)] = box
            boxes.append(box)
            edges.extend(Edge(x + NODE_W, box.cy, k.x, k.cy) for k in kids)
    depth = max((b.depth for b in boxes), default=0)
    width = PAD * 2 + (depth + 1) * NODE_W + depth * COL_GAP
    height = PAD * 2 + max(row, 1) * (NODE_H + ROW_GAP) - ROW_GAP
    return Diagram(width, height, tuple(boxes), tuple(edges), len(boxes), total)


# --- reading ----------------------------------------------------------------------

@dataclass(frozen=True)
class Loaded:
    """A report, or the sentence for its absence. `absent` is the ordinary
    case for a run from before the CAPE chain; `error` is set only when the
    run did produce a report this module could not use."""
    report: Report | None = None
    error: str | None = None

    @property
    def absent(self) -> bool:
        return self.report is None and self.error is None


def _bound(value: object, depth: int = 0) -> object:
    """Cut every string and list to the limits, recursively, before parsing."""
    if depth > MAX_DEPTH:
        return None
    if isinstance(value, str):
        return value if len(value) <= MAX_STRING else value[:MAX_STRING] + TRUNCATED
    if isinstance(value, list):
        return [_bound(v, depth + 1) for v in value[:MAX_ITEMS]]
    if isinstance(value, dict):
        return {str(k)[:256]: _bound(v, depth + 1) for k, v in list(value.items())[:MAX_ITEMS]}
    return value


def parse(raw: bytes) -> Loaded:
    """Bytes of cape_results.json to a Report, or the reason there is none.
    Pure: `tests/test_cape.py` drives it with real shapes and hostile ones."""
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        return Loaded(error=f"cape_results.json is not JSON: {exc}")
    if not isinstance(document, dict):
        return Loaded(error="cape_results.json is not a JSON object")
    bounded = _bound(document)
    try:
        return Loaded(report=Report(bounded))
    except Exception as exc:  # noqa: BLE001 - a page renders the sentence, never a 500
        log.warning("cape_results.json unusable: %s", exc)
        return Loaded(error=f"cape_results.json could not be read: {type(exc).__name__}")


def _read(key: str) -> bytes | None:
    """At most MAX_RESULTS_BYTES of one object, or None past the cap."""
    out = bytearray()
    for chunk in objects.chunks(key):
        out += chunk
        if len(out) > MAX_RESULTS_BYTES:
            return None
    return bytes(out)


@lru_cache(maxsize=8)
def _load(key: str, sha256: str) -> Loaded:
    """One parsed report per (object, digest): a retried run's new report at
    the same key is a new entry, and an entry never goes stale."""
    try:
        raw = _read(key)
    except Exception as exc:  # noqa: BLE001 - the page must render regardless
        log.warning("report %s could not be read: %s", key, exc)
        return Loaded(error="cape_results.json could not be read from the store")
    if raw is None:
        return Loaded(error=f"cape_results.json is over {MAX_RESULTS_BYTES} bytes and was not read")
    return parse(raw)


def for_job(job_id: UUID, manifest: object, key_prefix: str, expired: bool = False) -> Loaded:
    """The report of one run, from what its manifest says it uploaded:
    absent without a `cape_results.json` with a digest, or past retention."""
    if expired:
        return Loaded()
    parsed = manifest_schema.parse(manifest)
    entry = next((a for a in parsed.artifacts if a.name == RESULTS_NAME), None)
    if entry is None or not entry.sha256:
        return Loaded()
    return _load(objects.result_prefix(job_id, key_prefix) + RESULTS_NAME, entry.sha256)


def artifact_link(artifacts: dict[str, str], *names: str) -> str | None:
    """The download link of the first of `names` the job has."""
    for name in names:
        if name in artifacts:
            return artifacts[name]
    return None

