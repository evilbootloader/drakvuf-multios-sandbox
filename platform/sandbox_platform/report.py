"""The behavioural report of one run: `report.json`, read back for the UI.

`sandboxd/postprocessing/plugins/generate_report.py` writes it on Dom0 after
the trace, from the per-plugin logs; this module is its only reader. What it
holds is what the sample DID -- process names and command lines, file paths,
DNS names, URLs, HTTP headers -- so every string in it is sample-influenced
and this module treats the file as untrusted input on the same footing as a
submitted filename:

- **Bounded before it is parsed.** A read stops at MAX_REPORT_BYTES; a string
  is cut at MAX_STRING and a list at MAX_ITEMS before pydantic sees them. The
  page cost is then a function of these constants, not of the sample.
- **Lenient about shape, strict about type.** A key this module does not know
  is ignored, so a newer sandboxd adding one does not blank the page; a key it
  does know that carries the wrong type fails the whole report, and the tab
  says the report could not be read rather than rendering half of it.
- **Never raises into a page.** `for_job` returns a `Loaded` whose `error`
  names what went wrong; the templates render that sentence.

Rendering is Jinja with autoescape on -- see `ui/__init__.py`'s module
docstring for why that is structural here -- and nothing in the templates
under `tabs/` marks report text `| safe`. `tests/test_ui.py` greps for it.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from functools import lru_cache
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import manifest as manifest_schema
from . import objects

log = logging.getLogger("sandbox_platform.report")

REPORT_NAME = "report.json"

# 74 KB for a 146-process Windows run with 41 modified and 67 deleted files
# (trace-windows.log, 2026-09-19). 16 MiB is two orders of magnitude of
# headroom for a sample that touches everything, and is still one read.
MAX_REPORT_BYTES = 16 * 1024 * 1024

# Per string and per list, applied before validation. A Windows path or a
# command line is rarely over a few hundred characters; a URL crafted to be
# long is the case this is for. Truncation is marked, not silent.
MAX_STRING = 2048
MAX_ITEMS = 5000
TRUNCATED = "…[truncated]"

# The schema this reader was written for. Newer minor additions are fine
# (unknown keys ignored); a different major is refused with a sentence.
SCHEMA_VERSION = 1


# --- the models --------------------------------------------------------------
#
# Field by field what generate_report.py writes. Every list defaults to empty:
# a run without socketmon has no `connections` key at all, and that is an
# empty Network tab, not a broken one.

class _Lenient(BaseModel):
    model_config = ConfigDict(extra="ignore")


class Process(_Lenient):
    seqid: int
    pid: int
    parent_seqid: int | None = None
    name: str = ""
    args: list[str] = Field(default_factory=list)
    started_at: float | None = None
    exited_at: float | None = None
    exit_code: int | None = None
    exit_code_str: str | None = None
    killed_by: int | None = None

    @property
    def basename(self) -> str:
        """`Notepad.exe` for a `\\Device\\HarddiskVolume2\\...\\Notepad.exe`.

        Both separators: the tree is Windows-only today, but the report format
        is not, and a Linux `procname` would otherwise render whole."""
        return self.name.replace("\\", "/").rsplit("/", 1)[-1] or self.name

    @property
    def command_line(self) -> str:
        return " ".join(self.args)

    @property
    def exited_with_error(self) -> bool:
        # NTSTATUS severity bits: 0xC... is an error, 0x8... a warning.
        return self.exit_code is not None and bool(self.exit_code & 0xC0000000)


class Startup(_Lenient):
    status: str | None = None
    process_name: str | None = None
    arguments: str | None = None
    pid: int | None = None
    process: int | None = None
    error_code: int | str | None = None
    error: str | None = None


class Ttp(_Lenient):
    name: str
    attck: list[str] = Field(default_factory=list, alias="att&ck")
    mbc: list[str] = Field(default_factory=list)
    process_seqids: list[int] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class HttpRequest(_Lenient):
    verb: str | None = None
    path: str | None = None
    version: str | None = None
    referer: str | None = None
    flags: int | str | None = None
    extra_headers: list[str] = Field(default_factory=list)
    server_name: str | None = None
    server_port: int | None = None
    username: str | None = None
    password: str | None = None
    service: int | str | None = None
    user_agent: str | None = None
    proxy: str | None = None
    proxy_bypass: str | None = None
    process_seqid: int | None = None


class CrackedUrl(_Lenient):
    url: str
    process_seqids: list[int] = Field(default_factory=list)


class FileRef(_Lenient):
    filename: str
    process_seqids: list[int] = Field(default_factory=list)


# A label beside a remote port, as upstream's UI shows one. A hint for the
# eye, not a classification: 443 says nothing about what went over it.
PORT_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 123: "ntp", 135: "rpc", 137: "netbios", 139: "smb",
    143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
    3306: "mysql", 3389: "rdp", 5900: "vnc", 8080: "http-alt", 8443: "https-alt",
}


class Connection(_Lenient):
    protocol: str = ""
    local_ip: str = ""
    local_port: int | None = None
    remote_ip: str = ""
    remote_port: int | None = None
    process_seqids: list[int] = Field(default_factory=list)

    @property
    def service(self) -> str:
        return PORT_NAMES.get(self.remote_port, "") if self.remote_port else ""


class DnsQuery(_Lenient):
    domain: str
    process_seqids: list[int] = Field(default_factory=list)


class Memdump(_Lenient):
    index: int | None = None
    dump_reason: str = ""
    method: str = ""
    pid: int | None = None
    address: str = ""
    size: int | None = None
    filename: str = ""
    target_pid: int | None = None
    target_process: int | None = None
    target_addr: str | None = None


class MemdumpGroup(_Lenient):
    process_seqid: int | None = None
    dumps: list[Memdump] = Field(default_factory=list)


class RegistryValue(_Lenient):
    """A value set (or deleted): key path, value name, and for a set, the
    data as regmon rendered it -- a string, or a hex dump for binary."""
    key: str
    value_name: str | None = None
    value: str | None = None
    autostart: bool = False
    process_seqids: list[int | None] = Field(default_factory=list)


class RegistryKey(_Lenient):
    key: str
    autostart: bool = False
    process_seqids: list[int | None] = Field(default_factory=list)


class Report(_Lenient):
    schema_version: int = 1
    startup: Startup = Field(default_factory=Startup)
    processes: list[Process] = Field(default_factory=list)
    ttps: list[Ttp] = Field(default_factory=list)
    http_requests: list[HttpRequest] = Field(default_factory=list)
    cracked_urls: list[CrackedUrl] = Field(default_factory=list)
    modified_files: list[FileRef] = Field(default_factory=list)
    deleted_files: list[FileRef] = Field(default_factory=list)
    connections: list[Connection] = Field(default_factory=list)
    dns_queries: list[DnsQuery] = Field(default_factory=list)
    memdumps: list[MemdumpGroup] = Field(default_factory=list)
    registry_set_values: list[RegistryValue] = Field(default_factory=list)
    registry_created_keys: list[RegistryKey] = Field(default_factory=list)
    registry_deleted_keys: list[RegistryKey] = Field(default_factory=list)
    registry_deleted_values: list[RegistryValue] = Field(default_factory=list)

    # -- derived, for the templates ------------------------------------------

    @property
    def registry_autostart(self) -> list[RegistryValue | RegistryKey]:
        """Writes under the well-known autostart locations, first on the tab
        because they are what a reader scans a registry section for."""
        return [r for r in (*self.registry_set_values, *self.registry_created_keys)
                if r.autostart]

    @property
    def registry_count(self) -> int:
        return (len(self.registry_set_values) + len(self.registry_created_keys)
                + len(self.registry_deleted_keys) + len(self.registry_deleted_values))

    @property
    def by_seqid(self) -> dict[int, Process]:
        return {p.seqid: p for p in self.processes}

    @property
    def tree(self) -> list[Node]:
        """The processes as a forest, built from `parent_seqid`.

        A child whose parent is not in the list becomes a root rather than
        vanishing: the report is evidence, and a dangling reference is a fact
        about procmon's view, not a reason to hide the process."""
        nodes = {p.seqid: Node(p) for p in self.processes}
        roots: list[Node] = []
        for node in nodes.values():
            parent = nodes.get(node.process.parent_seqid) \
                if node.process.parent_seqid is not None else None
            if parent is None or parent is node:
                roots.append(node)
            else:
                parent.children.append(node)
        return roots

    @property
    def startup_process(self) -> Process | None:
        if self.startup.process is None:
            return None
        return self.by_seqid.get(self.startup.process)

    def killer_of(self, process: Process) -> Process | None:
        if process.killed_by is None:
            return None
        return self.by_seqid.get(process.killed_by)

    @property
    def dump_count(self) -> int:
        return sum(len(g.dumps) for g in self.memdumps)

    def lineage(self) -> list[Node]:
        """The sample's ancestors and its whole subtree; nothing else.

        The forest with every sibling pruned off the path from a root to the
        sample -- the picture that answers "what did it spawn, and what spawned
        it" without the OS's hundred idle services around it. Empty when the
        report does not say which process the sample was."""
        target = self.startup.process
        if target is None:
            return []
        parent_of = {p.seqid: p.parent_seqid for p in self.processes}
        if target not in parent_of:
            return []
        path: list[int] = []
        seqid: int | None = target
        seen: set[int] = set()
        while seqid is not None and seqid not in seen:
            seen.add(seqid)
            path.append(seqid)
            seqid = parent_of.get(seqid)
        path.reverse()  # root first

        by_seqid = self.by_seqid
        full = {n.process.seqid: n for root in self.tree for n in root.walk()}
        sample = full[target]
        chain: Node | None = None
        for ancestor in reversed(path[:-1]):
            chain = Node(by_seqid[ancestor], [chain or sample])
        return [chain or sample]

    def diagram(self, everything: bool = False) -> Diagram:
        roots = self.tree if everything else (self.lineage() or self.tree)
        return layout(roots, self.startup.process, len(self.processes))

    def filled_tabs(self) -> set[str]:
        """Which of the report-driven tabs have something to show."""
        filled: set[str] = set()
        if self.processes or self.modified_files or self.deleted_files:
            filled.add("behaviour")
        if (self.connections or self.dns_queries or self.http_requests
                or self.cracked_urls):
            filled.add("network")
        if self.memdumps:
            filled.add("memory")
        if self.registry_count:
            filled.add("registry")
        return filled


@dataclass
class Node:
    process: Process
    children: list[Node] = field(default_factory=list)

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()


# --- the diagram --------------------------------------------------------------
#
# A picture of the process forest, laid out here and drawn by the template as
# inline SVG. Server-side and script-free for the same reason the rest of the
# UI is: the names in it are the sample's, and inline SVG is HTML as far as
# autoescape is concerned, so the escaping rule stays structural.
#
# Left to right, one row per leaf, a parent centred on its children -- the
# layout a reader expects of a process tree, and one whose height is the leaf
# count rather than the node count, which is what keeps 146 processes on one
# scrollable panel.

NODE_W = 180       # px, one box: an 18-character label and a 5-digit PID
NODE_H = 22
COL_GAP = 40       # between a parent's right edge and a child's left edge
ROW_GAP = 8
PAD = 8
LABEL_CHARS = 18   # basename characters that fit beside the PID at 11px mono


@dataclass(frozen=True)
class Box:
    process: Process
    x: int
    y: int
    depth: int
    in_sample_tree: bool

    @property
    def label(self) -> str:
        name = self.process.basename
        return name if len(name) <= LABEL_CHARS else name[:LABEL_CHARS - 1] + "…"

    @property
    def cx(self) -> int:
        return self.x + NODE_W // 2

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
        """An elbow: out of the parent, across, into the child."""
        mid = (self.x1 + self.x2) // 2
        return f"M{self.x1} {self.y1} H{mid} V{self.y2} H{self.x2}"


@dataclass(frozen=True)
class Diagram:
    width: int
    height: int
    boxes: tuple[Box, ...]
    edges: tuple[Edge, ...]
    # How many of the report's processes this picture shows. Less than all
    # when it is the lineage view.
    shown: int
    total: int

    # For the template, which draws every box the same size.
    node_w: int = NODE_W
    node_h: int = NODE_H


def layout(roots: list[Node], sample_seqid: int | None, total: int) -> Diagram:
    boxes: list[Box] = []
    edges: list[Edge] = []
    row = 0
    in_sample = False

    def place(node: Node, depth: int) -> Box:
        nonlocal row, in_sample
        entering = node.process.seqid == sample_seqid
        if entering:
            in_sample = True
        x = PAD + depth * (NODE_W + COL_GAP)
        if node.children:
            child_boxes = [place(child, depth + 1) for child in node.children]
            y = (child_boxes[0].y + child_boxes[-1].y) // 2
        else:
            y = PAD + row * (NODE_H + ROW_GAP)
            row += 1
            child_boxes = []
        box = Box(node.process, x, y, depth, in_sample)
        boxes.append(box)
        for child in child_boxes:
            edges.append(Edge(x + NODE_W, box.cy, child.x, child.cy))
        if entering:
            in_sample = False
        return box

    for root in roots:
        place(root, 0)

    depth = max((b.depth for b in boxes), default=0)
    width = PAD * 2 + (depth + 1) * NODE_W + depth * COL_GAP
    height = PAD * 2 + max(row, 1) * (NODE_H + ROW_GAP) - ROW_GAP
    return Diagram(width, height, tuple(boxes), tuple(edges),
                   shown=len(boxes), total=total)


@dataclass(frozen=True)
class Loaded:
    """What `for_job` hands the page: a report, or the sentence for its absence.

    `absent` is the ordinary case for every run before postprocessing shipped
    and for every non-Windows run today, and is not an error: the tabs fall
    back to their pending state. `error` is set only when the run DID produce
    a report and this module could not use it."""
    report: Report | None = None
    error: str | None = None

    @property
    def absent(self) -> bool:
        return self.report is None and self.error is None


# --- reading ----------------------------------------------------------------

def _bound(value: object, depth: int = 0) -> object:
    """Cut every string and list to the limits, recursively, before parsing.

    Depth is capped too: the report is three levels deep, and a document that
    nests further is not one generate_report wrote."""
    if depth > 8:
        return None
    if isinstance(value, str):
        return value if len(value) <= MAX_STRING \
            else value[:MAX_STRING] + TRUNCATED
    if isinstance(value, list):
        return [_bound(v, depth + 1) for v in value[:MAX_ITEMS]]
    if isinstance(value, dict):
        return {str(k)[:64]: _bound(v, depth + 1)
                for k, v in list(value.items())[:MAX_ITEMS]}
    return value


def parse(raw: bytes) -> Loaded:
    """Bytes of report.json to a Report, or the reason there is none.

    Pure: no store, no database. `tests/test_report.py` drives it directly
    with the shapes generate_report.py writes and with hostile ones."""
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        return Loaded(error=f"report.json is not JSON: {exc}")
    if not isinstance(document, dict):
        return Loaded(error="report.json is not a JSON object")
    version = document.get("schema_version", 1)
    if version != SCHEMA_VERSION:
        return Loaded(error=f"report.json is schema version {version!r}; "
                            f"this platform reads version {SCHEMA_VERSION}")
    try:
        report = Report.model_validate(_bound(document))
    except ValidationError as exc:
        # One line per problem, not pydantic's multi-paragraph rendering:
        # this ends up in a <div> on the report page.
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"
            for e in exc.errors()[:5])
        return Loaded(error=f"report.json did not validate: {problems}")
    return Loaded(report=report)


def _read(key: str) -> bytes | None:
    """At most MAX_REPORT_BYTES of one object, or None past the cap.

    Stops reading rather than reading and then refusing: the cap is a bound
    on this process's memory, and it only bounds anything if the read obeys
    it."""
    out = bytearray()
    for chunk in objects.chunks(key):
        out += chunk
        if len(out) > MAX_REPORT_BYTES:
            return None
    return bytes(out)


@lru_cache(maxsize=32)
def _load(key: str, sha256: str) -> Loaded:
    """One parsed report per (object, digest). The digest is the manifest's,
    so a re-run that writes a different report.json at the same key -- a
    retried attempt -- is a different cache entry, and an entry never goes
    stale. Bounded by maxsize times MAX_REPORT_BYTES."""
    try:
        raw = _read(key)
    except Exception as exc:  # noqa: BLE001 - the page must render regardless
        log.warning("report %s could not be read: %s", key, exc)
        return Loaded(error="report.json could not be read from the store")
    if raw is None:
        return Loaded(error=f"report.json is over {MAX_REPORT_BYTES} bytes "
                            "and was not read")
    return parse(raw)


def for_job(job_id: UUID, manifest: object, key_prefix: str,
            expired: bool = False) -> Loaded:
    """The report of one run, from what its manifest says it uploaded.

    Absent unless the manifest names `report.json` with a digest: `parse`
    yields no artifacts for a manifest it could not validate, and a report
    from an unvalidated manifest is not one to fetch. Absent past retention
    too -- the object is gone, and a read would only say so slowly."""
    if expired:
        return Loaded()
    parsed = manifest_schema.parse(manifest)
    entry = next((a for a in parsed.artifacts if a.name == REPORT_NAME), None)
    if entry is None or not entry.sha256:
        return Loaded()
    key = objects.result_prefix(job_id, key_prefix) + REPORT_NAME
    return _load(key, entry.sha256)
