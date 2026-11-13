"""DRAKVUF's `trace.log` cut into CAPE's `logs/` layout: one file per process.

CAPE's `behavior.py` (`Processes`, `ParseProcessLog`) reads `logs/<pid>.bson`,
one file per monitored process whose first message (`__process__`) says which
process it is, and hands each process's calls out lazily -- re-reading the
file every time a consumer iterates them. DRAKVUF writes one interleaved
stream for every process on the guest instead. This module rewrites that
stream into the layout CAPE expects, `<out>/<seqid>.log`:

* line 1, a synthetic `{"Plugin": "__process__", ...}` built from the process
  tree, standing in for CAPE's `__process__` message;
* then that process's records, in EventUID order, with each `syscall` already
  merged with its `sysret` (`Ret`, `Info`).

Keyed by **seqid, not PID**: PIDs are reused within a trace, and the tree's
seqid is the one name for a process instance every other reader here uses.

Two passes over the file, both streamed. Pass 1 reads only the procmon and
inject lines (a substring test per line, no JSON) to build the tree and find
the sample; pass 2 parses, reorders, attributes, pairs and writes. What is
held at any moment is the reorder window, the syscalls still waiting for
their return, and the open file handles -- never the trace.
"""
from __future__ import annotations

import heapq
import json
import logging
import posixpath
import re
import shlex
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple

import mslex
import orjson

from ....guests import TargetOs
from ...drakvuf_records import DRAKVUF_STRING_ARG, unescape_drakvuf
from ...process_tree import Process, ProcessTree, split_commandline, tree_from_log
from .api_kernel import OBJECT_NAME_KEYS, VALUE_SERVICES, kernel_services
from .api_tables import canonical
from .launch import launch_seqids

log = logging.getLogger(__name__)

TRACE_LOG = "trace.log"

# The plugins `behaviour.JsonParser` turns into calls, with the order of two
# records under one EventUID -- falco's (`falco/events.py::_KIND_RANK`): a
# filetracer reading of a path precedes the syscall it belongs to, procmon's
# clone precedes the child's own records. Everything else in the trace
# (memdump, fileextractor, tlsmon, rootkitmon, inject) has no CAPE call shape
# and is skipped here; inject is read by pass 1, rootkitmon -- the kernel's,
# no process's -- from the aux log by the Anomaly module.
SOURCES: Dict[str, int] = {
    "procmon": 0, "filetracer": 1, "syscall": 2, "sysret": 3, "apimon": 4,
    "libmon": 5, "regmon": 6, "socketmon": 7, "unixsocketmon": 8, "cpuidmon": 9,
    # A process's own detections: the Anomaly module's (behaviour._parse_event)
    "ptracemon": 10, "debugmon": 11, "ebpfmon": 12,
}

# Records the calls do not include but CAPE's other modules read
# (cape_plugin/modules.py): set aside, whole and unfiltered, in
# `<out>/../aux/<plugin>.log` during the same pass. socketmon and
# unixsocketmon are both calls and, for the network module, records.
AUX_PLUGINS = frozenset(("fileextractor", "memdump", "tlsmon", "procdump2", "procdump",
                         "inject", "socketmon", "unixsocketmon", "rootkitmon"))

# 2026-11-03, job 88b44209: the worst EventUID out of place in a per-plugin
# log was 110; `falco/events.py::TraceConfig.reorder_window` has the numbers.
# A record further out is written late, never dropped.
REORDER_WINDOW = 4096

# Syscalls waiting for their sysret, per thread. Windows nests kernel-mode
# syscalls (a driver's Zw* call) inside a user one, so this is a stack; 32 is
# far past any nesting seen, and what overflows is written unpaired.
MAX_PENDING_PER_THREAD = 32

# Upper bound on per-process files open at once: `scope="all"` on an Android
# trace is hundreds of processes. The least recently written one is closed
# and reopened for append when its process logs again.
MAX_OPEN_FILES = 256

# The Plugin name of a raw line, without decoding it. DRAKVUF writes most
# lines compact but some spaced (`{ "Plugin": "apimon", ...`).
_PLUGIN = re.compile(rb'"Plugin":\s*"([A-Za-z0-9_]+)"')
# How every record begins. A line that does not is the rest of a record cut
# by a raw newline inside one of its strings: regmon prints a REG_SZ as it
# is, and a JSON document stored in the registry is a value of twenty lines
# (6 records over 105 more lines in one Windows job, 2026-11-12).
_RECORD_START = re.compile(rb'\{\s*"Plugin"')
# Lines of one record at most; a cut record longer than this is bad_json
MAX_CONTINUATION_LINES = 64
_CONTROL = re.compile(r"[\x00-\x1f]")


@dataclass
class SplitStats:
    lines: int = 0
    records: Counter = field(default_factory=Counter)   # kept, per plugin
    plugins: Counter = field(default_factory=Counter)   # every line, per plugin
    bad_json: int = 0          # dropped: not a JSON object
    joined: int = 0            # kept: a record cut over several lines, put together
    bad_utf8: int = 0          # kept: decoded with U+FFFD for the bad bytes
    bad_control: int = 0       # kept: a raw control character escaped first
    no_pid: int = 0            # dropped: a record that names no process
    nodes_added: int = 0       # processes procmon never reported
    out_of_scope: int = 0
    merged: Counter = field(default_factory=Counter)    # folded into a syscall, per plugin
    api_with_kernel: int = 0   # API records given their kernel-side records
    syscalls_paired: int = 0
    syscalls_unpaired: int = 0
    kernel_syscalls_dropped: int = 0
    processes: int = 0


# -- helpers copied rather than imported: falco/ and split_drakvuf_log are -----
# -- part of the chain this replaces ------------------------------------------

def _event_uid(rec: dict) -> int:
    raw = rec.get("EventUID")
    if isinstance(raw, str):
        try:
            return int(raw, 16)
        except ValueError:
            return -1
    return raw if isinstance(raw, int) else -1


def _windowed(stream: Iterable[tuple], window: int) -> Iterator[tuple]:
    """`stream` in key order, for a stream out of order by at most `window`
    positions; a record further out is yielded late, never dropped. The key
    is `item[:2]`; `seq` keeps equal keys in file order."""
    heap: list = []
    seq = 0
    for item in stream:
        heapq.heappush(heap, (item[0], item[1], seq, item))
        seq += 1
        if len(heap) > window:
            yield heapq.heappop(heap)[3]
    while heap:
        yield heapq.heappop(heap)[3]


def _compact(obj) -> bytes:
    try:
        return orjson.dumps(obj)
    except (TypeError, orjson.JSONEncodeError):
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8", "surrogatepass")


def _decode(line: bytes, stats: SplitStats) -> Optional[dict]:
    try:
        rec = orjson.loads(line)
    except orjson.JSONDecodeError:
        # A raw byte DRAKVUF copied out of guest memory into a string: the
        # line is JSON, just not UTF-8. split_drakvuf_log dropped these
        # (parse_errors.log); a process's call is worth more than the byte.
        text = line.decode("utf-8", "replace")
        try:
            rec = orjson.loads(text)
            stats.bad_utf8 += 1
        except orjson.JSONDecodeError:
            # A raw control character inside a string. The output formatter
            # quotes a value it is handed unescaped (`fmt::Rstr`, jsonfmt.h:
            # std::quoted, which escapes `"` and `\` and nothing else), and
            # apimon appends the names it resolves -- FileName, Key,
            # CommandLine -- that way: a file called `\x01` made ten such
            # lines in one Windows trace (2026-11-11). Escaped, the line is
            # the JSON it was meant to be.
            try:
                rec = orjson.loads(_CONTROL.sub(
                    lambda m: f"\\u{ord(m.group(0)):04x}", text.rstrip("\r\n")))
                stats.bad_control += 1
            except orjson.JSONDecodeError:
                stats.bad_json += 1
                return None
    if not isinstance(rec, dict):
        stats.bad_json += 1
        return None
    return rec


# -- pass 1: the tree and the sample -----------------------------------------

@dataclass
class TracePrelude:
    tree: ProcessTree
    injected: List[Tuple[int, float]]   # (pid, inject TimeStamp)
    has_sysret: bool
    # (source PID, TimeStamp, target PID, how): one process making another
    # run code (_control_transfer, _WindowsEvidence)
    transfers: List[Tuple[int, float, int, str]] = field(default_factory=list)
    # (requester PID, when it asked, TimeStamp, new PID, how): a process a
    # broker started from a command the requester named (_WindowsEvidence)
    started_for: List[Tuple[int, float, float, int, str]] = field(default_factory=list)
    # (PID, TimeStamp, call): a thread started through a process handle the
    # trace never saw opened -- a transfer nobody can follow
    unresolved: List[Tuple[int, float, str]] = field(default_factory=list)


# How one process makes another run its code: from then on the other runs
# the sample's, and is the sample's (follow_transfers). A write into another
# process is not one -- process_vm_writev, /proc/<pid>/mem, PTRACE_POKEDATA,
# WriteProcessMemory place bytes that run only once control is handed to
# them, and these are the ways it is.
# ptracemon (Linux): the target's registers set, its instruction pointer
# among them, for it to continue there
_PTRACE_TRANSFER = frozenset(("PTRACE_SETREGS", "PTRACE_SETREGSET", "PTRACE_POKEUSER"))
# memdump (Windows): a remote thread, or a thread whose context was set,
# starting in the target's executable memory. The record names the target
# only where memdump prints one: `DumpPID` is the process the calling thread
# is attached to, which is the caller's own for a user-mode call -- all 309
# such records of three Windows jobs (2026-11-12) are the System process's,
# with DumpPID 4 -- so on those traces this rule finds nothing, and the
# calls themselves are what is read (_WindowsEvidence).
_MEMDUMP_TRANSFER = frozenset(("CreateRemoteThread heuristic", "SetThreadContext heuristic"))
# A line worth parsing for one: cheaper than parsing every line
_TRANSFER_HINTS = (b'"ptracemon"', b'heuristic"')


def _control_transfer(rec: dict) -> Optional[Tuple[int, int, str]]:
    """(source PID, target PID, how) when `rec` is one process making
    another run code; None for anything else, a process's own included."""
    pid = rec.get("PID")
    if not isinstance(pid, int):
        return None
    plugin = rec.get("Plugin")
    target, how = None, ""
    if plugin == "ptracemon" and rec.get("Type") in _PTRACE_TRANSFER:
        target, how = rec.get("TargetPID"), f"ptrace {rec['Type']}"
    elif plugin == "memdump" and rec.get("DumpReason") in _MEMDUMP_TRANSFER:
        target = rec.get("TargetPID") if isinstance(rec.get("TargetPID"), int) else rec.get("DumpPID")
        how = f"memdump {rec['DumpReason']}"
    if not isinstance(target, int) or target <= 0 or target == pid:
        return None
    return pid, target, how


def _hex(value) -> Optional[int]:
    try:
        return int(value, 16) if isinstance(value, str) else None
    except ValueError:
        return None


def _nt_success(value) -> bool:
    status = _hex(value)
    return status is not None and status < 0x80000000


def _words(command: str) -> Tuple[str, ...]:
    """A Windows command line as its words, lower case: what two spellings
    of one command -- quoted or not, any case -- share."""
    try:
        return tuple(w.lower() for w in mslex.split(command, check=False, like_cmd=False))
    except Exception:  # noqa: BLE001 - not a command line mslex can read: no match
        return ()


def _basename(path) -> str:
    return PureWindowsPath(str(path or "")).name.lower()


class _WindowsEvidence:
    """Windows control transfers, read from the calls of pass 1.

    **A thread of another process made to run** (`transfers`), each rule
    with the records it rests on (three Windows jobs, 2026-11-12):

    * a thread created in another process -- NtCreateThreadEx /
      NtCreateThread whose ProcessHandle is not the caller's own
      (CreateRemoteThread and RtlCreateUserThread end in it);
    * an APC queued to a thread of another process -- NtQueueApcThread[Ex,
      Ex2];
    * the context of a thread of another process set -- NtSetContextThread,
      or NtSetInformationThread(ThreadWow64Context) for a 32-bit thread.
      The set alone: where the thread then runs is decided, whichever of
      NtResumeThread, NtAlertResumeThread or NtResumeProcess lets it.

    The syscall plugin's record is the call (a direct syscall included); it
    carries a handle, not a PID. What a handle is open on comes from
    procmon, which prints the handle a process was given beside the PID it
    is of: NtOpenProcess (`ProcessHandle`, `ClientID`), NtOpenThread
    (`ThreadHandle`, `ClientID`, `UniqueThread`) and NtCreateUserProcess
    (`NewProcessHandle`/`NewPid`, `NewThreadHandle`/`NewTid`), until the
    process closes it (NtClose). apimon resolves a thread handle itself
    (`ProcessId=`, `ThreadId=` on NtQueueApcThread, NtResumeThread...), so
    its record of the same call names the target where no procmon record
    did -- and NtQueueApcThreadEx2's syscall record has no arguments at
    all. A call counts once it returned success (sysret), or as made in a
    trace without sysret.

    Not transfers, and why: NtWriteVirtualMemory and NtResumeThread on
    another process are every process creation (the launch's cmd.exe wrote
    twice into each child and resumed it once; csrss wrote four times) and
    an executable section mapped into another process is csrss's and
    svchost's daily work (32..47 and 6 a job) -- neither runs anything by
    itself. Where one came before a transfer to the same target, `how` says
    so. A handle the trace never saw opened (duplicated, inherited,
    NtGetNextProcess) resolves to nothing: `unresolved`.

    **A process a broker started for another** (`started_for`): the
    requester's own records name a command, and a broker then creates a
    process from exactly that command line -- compared as words, lower
    case. Linked, because each is an equality and no guess:

    * a service: CreateService[A|W] / ChangeServiceConfig[A|W]'s
      `lpBinaryPathName`, then services.exe;
    * a scheduled task: the `/TR` of a `schtasks.exe /Create` the requester
      started, then the Schedule service's svchost.exe (taskeng.exe and
      taskhostw.exe before it);
    * WMI: the command of a `wmic.exe process call create` the requester
      started, then WmiPrvSE.exe.

    A process started with elevation (AppInfo's svchost) needs no link: its
    records name the requester as its parent and tree_from_log moves it
    there. Not linked, for want of a record naming the command: a task
    registered through ITaskService, Win32_Process.Create through
    IWbemServices::ExecMethod (PowerShell, a script's GetObject), and a
    ShellExecute handed to explorer or DllHost through COM."""

    # (the argument holding the target's handle, whether it is a thread's)
    TRIGGERS = {
        "NtCreateThreadEx": ("ProcessHandle", False, "remote thread"),
        "NtCreateThread": ("ProcessHandle", False, "remote thread"),
        "NtQueueApcThread": ("ThreadHandle", True, "APC queued to a thread"),
        "NtQueueApcThreadEx": ("ThreadHandle", True, "APC queued to a thread"),
        "NtQueueApcThreadEx2": ("ThreadHandle", True, "APC queued to a thread"),
        "NtSetContextThread": ("ThreadHandle", True, "thread context set"),
        "NtSetInformationThread": ("ThreadHandle", True, "thread context set"),
    }
    THREAD_WOW64_CONTEXT = 0x1d
    # The caller's own process (-1) and thread (-2), as 64 and 32 bit values
    OWN = frozenset((0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFE))
    # PAGE_EXECUTE, _READ, _READWRITE, _WRITECOPY
    EXECUTABLE = 0xF0
    # (a broker's image name, what it was asked through)
    BROKERS = {
        "service": (frozenset(("services.exe",)), "the service binary it registered ({api})"),
        "task": (frozenset(("svchost.exe", "taskeng.exe", "taskhostw.exe")),
                 "the /TR command of the schtasks.exe it ran"),
        "wmi": (frozenset(("wmiprvse.exe",)), "the command of the `wmic process call create` it ran"),
    }
    SERVICE_APIS = frozenset(("CreateServiceA", "CreateServiceW", "ChangeServiceConfigA",
                              "ChangeServiceConfigW"))
    HINTS = (b"NtCreateThread", b"NtQueueApcThread", b"NtSetContextThread", b"NtSetInformationThread",
             b"NtMapViewOfSection", b"NtWriteVirtualMemory called", b'"NtClose"',
             b"CreateService", b"ChangeServiceConfig")
    # What every line with one of HINTS (or _TRANSFER_HINTS) has: most
    # lines fail these five tests and are spared the eleven
    COARSE = (b"Thread", b"Nt", b"Service", b"ptracemon", b"heuristic")
    PROCMON = (b'"NtOpenProcess"', b'"NtOpenThread"', b'"NtCreateUserProcess"')
    _CLOSE = re.compile(rb'"PID":\s*(\d+),.*"Method":\s*"NtClose".*"Handle":\s*"(0x[0-9a-fA-F]+)"')

    def __init__(self):
        self.transfers: List[Tuple[int, float, int, str]] = []
        self.started_for: List[Tuple[int, float, float, int, str]] = []
        self.unresolved: List[Tuple[int, float, str]] = []
        self.has_sysret = False
        # (PID, handle) -> the PID the handle is open on
        self.handles: Dict[Tuple[int, int], int] = {}
        # thread -> [call, TimeStamp, target PID or None, counted]: entered;
        # kept once counted, so apimon's record of it is not a second call
        self.pending: Dict[Tuple[int, int], list] = {}
        # (source PID, target PID) -> what the source did to the target before
        self.prepared: Dict[Tuple[int, int], Set[str]] = {}
        # (requester PID, TimeStamp, kind, words, how)
        self.asked: List[Tuple[int, float, str, Tuple[str, ...], str]] = []

    def wants(self, plugin: bytes, line: bytes) -> bool:
        if plugin == b"procmon":
            return any(h in line for h in self.PROCMON)
        if b"NtSetInformationThread" in line and b"0x1d" not in line:
            return plugin == b"sysret" and bool(self.pending)
        return plugin in (b"syscall", b"sysret", b"apimon", b"memdump")

    def feed(self, plugin: bytes, line: bytes) -> None:
        if b'"NtClose"' in line:
            closed = self._CLOSE.search(line) if plugin == b"syscall" and self.handles else None
            if closed:
                self.handles.pop((int(closed.group(1)), int(closed.group(2), 16)), None)
            return
        try:
            rec = orjson.loads(line)
        except orjson.JSONDecodeError:
            return
        pid = rec.get("PID") if isinstance(rec, dict) else None
        if not isinstance(pid, int):
            return
        getattr(self, "_" + plugin.decode("ascii"))(rec, pid, float(rec.get("TimeStamp") or 0))

    # -- what the records say ---------------------------------------------------

    def _procmon(self, rec: dict, pid: int, ts: float) -> None:
        method = rec.get("Method")
        if method == "NtCreateUserProcess":
            if not _nt_success(rec.get("Status")) or not isinstance(rec.get("NewPid"), int):
                return
            for name in ("NewProcessHandle", "NewThreadHandle"):
                self._opened(pid, rec.get(name), rec["NewPid"])
            self._created(rec, pid, ts)
        elif method in ("NtOpenProcess", "NtOpenThread") and isinstance(rec.get("ClientID"), int):
            self._opened(pid, rec.get("ProcessHandle" if method == "NtOpenProcess" else "ThreadHandle"),
                         rec["ClientID"])

    def _opened(self, pid: int, handle, target: int) -> None:
        handle = _hex(handle)
        if handle:
            self.handles[(pid, handle)] = target

    def _target(self, pid: int, handle) -> Optional[int]:
        """The PID `handle` is open on in `pid`: its own for the pseudo
        handles, None for a handle nothing here saw opened."""
        handle = _hex(handle)
        if handle is None:
            return None
        return pid if handle in self.OWN else self.handles.get((pid, handle))

    def _memdump(self, rec: dict, pid: int, ts: float) -> None:
        target = rec.get("TargetPID")
        if rec.get("DumpReason") == "NtWriteVirtualMemory called" and isinstance(target, int) and target != pid:
            self.prepared.setdefault((pid, target), set()).add("NtWriteVirtualMemory")

    def _syscall(self, rec: dict, pid: int, ts: float) -> None:
        method = rec.get("Method")
        if rec.get("PreviousMode") == "Kernel":
            return      # a driver's, in whatever process was current
        if method in ("NtMapViewOfSection", "NtMapViewOfSectionEx"):
            target = self._target(pid, rec.get("ProcessHandle"))
            if target not in (None, pid) and (_hex(rec.get("Win32Protect")) or 0) & self.EXECUTABLE:
                self.prepared.setdefault((pid, target), set()).add(f"an executable section mapped ({method})")
            return
        trigger = self.TRIGGERS.get(method)
        if trigger is None or (method == "NtSetInformationThread"
                               and _hex(rec.get("ThreadInformationClass")) != self.THREAD_WOW64_CONTEXT):
            return
        thread = (pid, rec.get("TID"))
        entered = self.pending.pop(thread, None)
        if entered is not None and not self.has_sysret:
            self._made(pid, entered)      # no sysret in this trace: as made
        # NtQueueApcThreadEx2 is printed without arguments: apimon names it
        self.pending[thread] = [method, ts, self._target(pid, rec.get(trigger[0])) if trigger[0] in rec
                                else None, False]

    def _sysret(self, rec: dict, pid: int, ts: float) -> None:
        self.has_sysret = True
        thread = (pid, rec.get("TID"))
        entered = self.pending.get(thread)
        if entered is None or entered[0] != rec.get("Method"):
            return
        if not _nt_success(rec.get("Ret")):
            del self.pending[thread]
        elif entered[2] is not None or not self.TRIGGERS[entered[0]][1]:
            self._made(pid, entered)
        # else: returned, on a thread handle only apimon's record can resolve

    def _apimon(self, rec: dict, pid: int, ts: float) -> None:
        method = rec.get("Method")
        if rec.get("Event") != "api_called" or not isinstance(method, str):
            return
        arguments = dict(a.split("=", 1) for a in rec.get("Arguments") or () if isinstance(a, str) and "=" in a)
        if method in self.SERVICE_APIS:
            found = DRAKVUF_STRING_ARG.match(arguments.get("lpBinaryPathName", ""))
            words = _words(unescape_drakvuf(found.group(1))) if found else ()
            # A NULL handle is a service not created; ChangeServiceConfig returns a BOOL
            if words and _hex(rec.get("ReturnValue")):
                self.asked.append((pid, ts, "service", words,
                                   self.BROKERS["service"][1].format(api=method)))
            return
        if method.startswith("Zw"):
            method = "Nt" + method[2:]
        trigger = self.TRIGGERS.get(method)
        if trigger is None or (method == "NtSetInformationThread" and _hex(
                arguments.get("ThreadInformationClass")) != self.THREAD_WOW64_CONTEXT):
            return
        thread = (pid, rec.get("TID"))
        entered = self.pending.get(thread)
        if entered is not None and entered[0] == method:
            del self.pending[thread]
        else:
            entered = [method, ts, None, False]     # no syscall record of it: apimon's alone
        if entered[3] or not _nt_success(rec.get("ReturnValue")):
            return
        if entered[2] is None and arguments.get("ProcessId", "").isdigit():
            entered[2] = int(arguments["ProcessId"])    # of the thread handle, resolved by apimon
        if entered[2] is None:
            entered[2] = self._target(pid, arguments.get(trigger[0]))
        self._made(pid, entered)

    def _made(self, pid: int, entered: list) -> None:
        """Count a call that was made, once."""
        method, ts, target, counted = entered
        if counted:
            return
        entered[3] = True
        if target is None:
            if not self.TRIGGERS[method][1]:
                self.unresolved.append((pid, ts, method))
            return      # (a thread handle nothing resolved is the caller's own CreateThread's, mostly)
        if target <= 0 or target == pid:
            return
        how = f"{self.TRIGGERS[method][2]} ({method})"
        before = self.prepared.get((pid, target))
        if before:
            how += " after " + " and ".join(sorted(before))
        self.transfers.append((pid, ts, target, how))

    def _created(self, rec: dict, pid: int, ts: float) -> None:
        """A creation: something a requester asks a broker through
        (schtasks.exe, wmic.exe), or a broker's answer to an earlier one."""
        try:
            args = [a.lower() for a in split_commandline(rec.get("CommandLine") or "")]
        except Exception:  # noqa: BLE001 - a command line nobody can split names nothing
            return
        image = _basename(rec.get("ImagePathName"))
        if image == "schtasks.exe" and "/create" in args and "/tr" in args[:-1]:
            words = _words(args[args.index("/tr") + 1])
            if words:
                self.asked.append((pid, ts, "task", words, self.BROKERS["task"][1]))
        elif image == "wmic.exe" and args[1:4] == ["process", "call", "create"] and len(args) > 4:
            words = _words(args[4])
            if words:
                self.asked.append((pid, ts, "wmi", words, self.BROKERS["wmi"][1]))
        broker = _basename(rec.get("ProcessName"))
        words = tuple(args)
        for requester, asked_ts, kind, wanted, what in self.asked:
            if broker in self.BROKERS[kind][0] and wanted == words and requester != pid:
                self.started_for.append((requester, asked_ts, ts, rec["NewPid"],
                                         f"{broker} started {what}"))
                break

    def finish(self) -> None:
        if not self.has_sysret:
            for (pid, _), entered in self.pending.items():
                self._made(pid, entered)
        self.pending.clear()


# The reader of control transfers in the calls themselves, per guest: Linux
# has ptracemon's records (_control_transfer) and nothing to add.
_EVIDENCE = {TargetOs.WINDOWS: _WindowsEvidence}


def read_prelude(trace: Path, os_: TargetOs) -> TracePrelude:
    """The process tree from the trace's procmon lines, the injected PIDs,
    whether DRAKVUF ran with sysret, and every process making another run
    code. procmon lines go to `tree_from_log` in file order, exactly as
    `build_process_tree` fed it procmon.log."""
    injected: List[Tuple[int, float]] = []
    transfers: List[Tuple[int, float, int, str]] = []
    has_sysret = False
    evidence = _EVIDENCE[os_]() if os_ in _EVIDENCE else None
    hints = _TRANSFER_HINTS + (evidence.HINTS if evidence is not None else ())
    coarse = evidence.COARSE if evidence is not None else _TRANSFER_HINTS

    def procmon_lines() -> Iterator[str]:
        nonlocal has_sysret
        with trace.open("rb") as f:
            for line in f:
                hint = any(h in line for h in coarse) and any(h in line for h in hints)
                if b"procmon" not in line and b"inject" not in line and not hint and (
                        has_sysret or b"sysret" not in line):
                    continue
                m = _PLUGIN.search(line)
                plugin = m.group(1) if m else b""
                if evidence is not None and (hint or plugin == b"procmon") and evidence.wants(plugin, line):
                    evidence.feed(plugin, line)
                if plugin == b"sysret":
                    has_sysret = True
                elif plugin == b"procmon":
                    yield line.decode("utf-8", "replace")
                elif plugin == b"inject":
                    try:
                        rec = orjson.loads(line)
                    except orjson.JSONDecodeError:
                        continue
                    pid = rec.get("InjectedPid")
                    if rec.get("Status") == "Success" and isinstance(pid, int) and pid > 0:
                        injected.append((pid, float(rec.get("TimeStamp") or 0)))
                elif hint and plugin in (b"ptracemon", b"memdump"):
                    try:
                        rec = orjson.loads(line)
                    except orjson.JSONDecodeError:
                        continue
                    found = _control_transfer(rec) if isinstance(rec, dict) else None
                    if found:
                        transfers.append((found[0], float(rec.get("TimeStamp") or 0), found[1], found[2]))

    tree = tree_from_log(procmon_lines(), os_)
    prelude = TracePrelude(tree, injected, has_sysret, transfers)
    if evidence is not None:
        evidence.finish()
        prelude.transfers += evidence.transfers
        prelude.started_for, prelude.unresolved = evidence.started_for, evidence.unresolved
    return prelude


def _instances(tree: ProcessTree) -> Dict[int, List[Process]]:
    by_pid: Dict[int, List[Process]] = {}
    for p in tree.processes:
        by_pid.setdefault(p.pid, []).append(p)
    for nodes in by_pid.values():
        nodes.sort(key=lambda p: p.evtid_from or 0)
    return by_pid


def sample_roots(prelude: TracePrelude) -> Tuple[Set[int], Set[int]]:
    """(seqids of the injected processes the tree knows, injected PIDs it
    does not). For each injection, the instance of that PID that was not
    already dead when it happened -- the one DRAKVUF started or exec'd into."""
    by_pid = _instances(prelude.tree)
    found: Set[int] = set()
    missing: Set[int] = set()
    for pid, ts in prelude.injected:
        alive = [p for p in by_pid.get(pid, ()) if p.ts_to is None or p.ts_to >= ts]
        if alive:
            found.add(alive[0].seqid)
        else:
            missing.add(pid)
    return found, missing


def follow_transfers(prelude: TracePrelude, sample: Set[int], pending_roots: Set[int],
                     launcher: Optional[Set[int]] = None,
                     unresolved: Optional[List[Tuple[int, float, str]]] = None) -> List[dict]:
    """Grow `sample` (seqids) by every process a sample process made run code
    (TracePrelude.transfers) or had a broker start (`started_for`), and what
    that one started from then on -- until no transfer adds one: the target
    may make another in turn.

    A process is the sample's from a point in time: the injected ones and
    their descendants always, a target from its transfer. Only a transfer
    after its source became the sample's counts -- explorer resuming a
    thread before the sample took it over is explorer's own. The target is
    the instance of its PID alive at the transfer; one the tree does not know
    yet joins `pending_roots`, the sample's at its first record (_Attributor),
    as an injected PID the tree does not know is (no procmon).

    `launcher` (seqids, launch.launch_seqids) are sandboxd's own launch:
    in the sample's tree and not the sample, so no source of a transfer --
    what the launch's shell does to another process is sandboxd's doing --
    until a sample process makes one of them run its code. That one is taken
    out of `launcher` and is a source from then on, as any target is. The
    shell creating the sample is no transfer at all (_WindowsEvidence).

    Returns what was followed, for the report: one entry per (source,
    target, how), the first. `unresolved` is given the sample's share of
    TracePrelude.unresolved."""
    by_pid = _instances(prelude.tree)
    pending_sample = set(pending_roots)     # injected, not in the tree: the sample's throughout
    launcher = launcher if launcher is not None else set()
    since: Dict[int, float] = {seqid: float("-inf") for seqid in sample if seqid not in launcher}

    def alive_at(pid: int, ts: float) -> Optional[Process]:
        alive = [p for p in by_pid.get(pid, ())
                 if (p.ts_from or 0) <= ts and (p.ts_to is None or p.ts_to >= ts)]
        return alive[-1] if alive else None

    def is_sample(pid: int, ts: float) -> bool:
        src = alive_at(pid, ts)
        if src is None:
            return pid in pending_sample
        return src.seqid in since and since[src.seqid] <= ts

    # (source PID, when the source acted, TimeStamp, target PID, how)
    transfers = sorted([(src, ts, ts, target, how) for src, ts, target, how in prelude.transfers]
                       + list(prelude.started_for), key=lambda t: t[2])
    followed: List[dict] = []
    listed: Set[Tuple[int, int, str]] = set()
    done: Set[Tuple[int, float, int]] = set()
    changed = True
    while changed:
        changed = False
        for src_pid, acted, ts, target_pid, how in transfers:
            if (src_pid, ts, target_pid) in done or not is_sample(src_pid, acted):
                continue        # not the sample's then (a later round may find it was)
            done.add((src_pid, ts, target_pid))
            if (src_pid, target_pid, how) not in listed:
                listed.add((src_pid, target_pid, how))
                followed.append({"pid": src_pid, "target_pid": target_pid, "time": ts, "how": how})
            target = alive_at(target_pid, ts)
            if target is None:
                pending_roots.add(target_pid)
                pending_sample.add(target_pid)
                changed = True
                continue
            for seqid, joined in _started_from(target, ts).items():
                if joined < since.get(seqid, float("inf")):
                    since[seqid] = joined
                    sample.add(seqid)
                    launcher.discard(seqid)
                    changed = True
    if unresolved is not None:
        unresolved += [u for u in prelude.unresolved if is_sample(u[0], u[1])]
    return followed


def _started_from(root: Process, ts: float) -> Dict[int, float]:
    """`root`, the sample's from `ts`, and what it started at or after `ts`
    and everything under those, each from its start: a child started before
    the transfer never ran the sample's code."""
    out = {root.seqid: ts}
    todo = [c for c in root.children if (c.ts_from or 0) >= ts]
    while todo:
        p = todo.pop()
        if p.seqid in out:
            continue
        out[p.seqid] = max(ts, p.ts_from or 0)
        todo.extend(p.children)
    return out


def descendants(roots: Iterable[Process]) -> Set[int]:
    """Seqids of `roots` and everything under them, by the tree's own edges:
    a reused PID is a different node and does not drag its namesake in."""
    out: Set[int] = set()
    todo = list(roots)
    while todo:
        p = todo.pop()
        if p.seqid in out:
            continue
        out.add(p.seqid)
        todo.extend(p.children)
    return out


# -- pass 2 -------------------------------------------------------------------

def _records(trace: Path, stats: SplitStats,
             aux_dir: Optional[Path] = None) -> Iterator[Tuple[int, int, dict]]:
    """(uid, rank, record) for every record of `SOURCES`, in file order.

    A record without a usable EventUID takes the previous record's key --
    its UID and its rank, or a lower-ranked plugin would sort ahead of the
    record it followed -- so it stays where DRAKVUF wrote it: apimon's
    `dll_loaded`/`dll_discovered` have none, and cpuidmon's is always `0x0`."""
    last_uid, last_rank = 0, 0
    aux: Dict[str, object] = {}
    try:
        yield from _records_of(trace, stats, aux_dir, aux, last_uid, last_rank)
    finally:
        for handle in aux.values():
            handle.close()


def _whole_lines(f, stats: SplitStats) -> Iterator[bytes]:
    """The lines of `f`, with a record cut over several lines (_RECORD_START)
    put together again -- the raw newlines stay in it, and _decode escapes
    them as it does any raw control character. Put together only when the
    first line is not a record by itself and the lines up to one ending in
    `}` are: anything else goes out line by line, as it came."""
    held: List[bytes] = []
    for line in f:
        stats.lines += 1
        if not held and line.endswith(b"}\n"):
            yield line          # nearly every line: a whole record
            continue
        if held:
            if _RECORD_START.match(line) or len(held) >= MAX_CONTINUATION_LINES:
                yield from held         # never completed: each line as it was
                held = []
            else:
                held.append(line)
                if line.rstrip().endswith(b"}"):
                    whole = b"".join(held)
                    counted = (stats.bad_json, stats.bad_utf8, stats.bad_control)
                    complete = _decode(whole, stats) is not None
                    stats.bad_json, stats.bad_utf8, stats.bad_control = counted
                    if complete:
                        stats.joined += 1
                        held = []
                        yield whole
                continue
        if _RECORD_START.match(line) and not line.rstrip().endswith(b"}"):
            held = [line]       # cut short: wait for the rest
            continue
        yield line
    yield from held


def _records_of(trace, stats, aux_dir, aux, last_uid, last_rank):
    with trace.open("rb") as f:
        for line in _whole_lines(f, stats):
            m = _PLUGIN.search(line)
            if m is None:
                continue
            plugin = m.group(1).decode("ascii")
            stats.plugins[plugin] += 1
            if aux_dir is not None and plugin in AUX_PLUGINS:
                handle = aux.get(plugin)
                if handle is None:
                    aux_dir.mkdir(parents=True, exist_ok=True)
                    handle = aux[plugin] = (aux_dir / f"{plugin}.log").open("wb")
                handle.write(line if line.endswith(b"\n") else line + b"\n")
            rank = SOURCES.get(plugin)
            if rank is None:
                continue
            rec = _decode(line, stats)
            if rec is None:
                continue
            if "RunningProcess" in rec:
                continue   # the header says it; pass 1 built the node
            uid = _event_uid(rec)
            if uid <= 0 or plugin == "cpuidmon":
                uid, rank = last_uid, last_rank
            else:
                last_uid, last_rank = uid, rank
            stats.records[plugin] += 1
            yield uid, rank, rec


class _Attributor:
    """(PID, EventUID) -> the process instance it belongs to.

    The latest instance of that PID created at or before the EventUID; failing
    that, the earliest (a vfork child's exec is logged a UID before its
    clone). Where `ProcessTree.get_process_for_evtid` finds a process this
    agrees with it; where it finds none -- a record after the exit procmon
    saw, or a PID procmon never saw -- this still answers, and for an unseen
    PID adds the node, under the PPID the record names."""

    def __init__(self, tree: ProcessTree, sample: Set[int],
                 pending_roots: Set[int], stats: SplitStats):
        self.tree = tree
        self.by_pid = _instances(tree)
        self.sample = sample
        self.pending_roots = pending_roots
        self.stats = stats
        self.cache: Dict[int, Tuple[Process, Optional[int]]] = {}
        # Injected PIDs the tree did not know, and the seqids of the injected
        # processes: the report's sample itself (SplitResult.roots)
        self.injected: Set[int] = set()
        self.roots: Set[int] = set()

    def __call__(self, rec: dict, uid: int) -> Optional[Process]:
        pid = rec.get("PID")
        if not isinstance(pid, int):
            self.stats.no_pid += 1
            return None
        cached = self.cache.get(pid)
        if cached is not None:
            proc, valid_until = cached
            if (valid_until is None or uid < valid_until) and uid >= (proc.evtid_from or 0):
                return proc
        nodes = self.by_pid.get(pid)
        if not nodes:
            return self._add(rec, pid, uid)
        proc = nodes[0]
        valid_until = nodes[1].evtid_from if len(nodes) > 1 else None
        for i, p in enumerate(nodes):
            if (p.evtid_from or 0) <= uid:
                proc = p
                valid_until = nodes[i + 1].evtid_from if i + 1 < len(nodes) else None
        self.cache[pid] = (proc, valid_until)
        return proc

    def _add(self, rec: dict, pid: int, uid: int) -> Process:
        ppid = rec.get("PPID") if isinstance(rec.get("PPID"), int) else 0
        parents = self.by_pid.get(ppid)
        parent = parents[-1] if parents else None
        proc = self.tree.add_process(
            pid=pid, ppid=ppid, evtid_from=uid,
            ts_from=float(rec.get("TimeStamp") or 0),
            procname=str(rec.get("ProcessName") or rec.get("RunningProcess") or ""),
            parent=parent)
        self.by_pid[pid] = [proc]
        self.cache[pid] = (proc, None)
        self.stats.nodes_added += 1
        # The sample, for a trace whose procmon never saw it (or that has no
        # procmon): the injected PID's first record makes it a root, and a
        # process that appears under a sample process is one too.
        if pid in self.pending_roots or (parent is not None and parent.seqid in self.sample):
            if pid in self.injected:
                self.roots.add(proc.seqid)
            self.pending_roots.discard(pid)
            self.sample.add(proc.seqid)
        return proc


# What a sysret record carries that is not an output argument.
_SYSRET_KEYS = frozenset((
    "Plugin", "TimeStamp", "PID", "PPID", "TID", "UserId", "UserName", "ProcessName",
    "Method", "EventUID", "ThreadName", "Module", "vCPU", "CR3", "Syscall", "Ret", "Info",
    "Type",
))


class _SyscallPairer:
    """Merges each syscall with its sysret, and writes it at the return.

    CAPE's monitor logs a call when it returns, with its return value; this
    is that order. They pair by (PID, TID) and the `Syscall` number -- they
    share no EventUID. A thread's new user-mode syscall means everything it
    still has pending will never return (NtTerminateProcess on itself,
    NtContinue, an exit), so that is written unpaired then; Linux has no
    nesting at all. Without sysret in the trace each syscall goes out as it
    comes. Kernel-mode syscalls (Windows `PreviousMode: Kernel`: a driver's
    call, in whatever process happened to be current) are paired -- they
    must not take their parent's return -- and dropped unless asked for."""

    def __init__(self, has_sysret: bool, nested: bool, keep_kernel: bool, stats: SplitStats):
        self.has_sysret = has_sysret
        self.nested = nested
        self.keep_kernel = keep_kernel
        self.stats = stats
        self.pending: Dict[Tuple[int, int], List[Tuple[Process, dict]]] = {}

    def _out(self, proc: Process, rec: dict, paired: bool) -> Iterator[Tuple[Process, dict]]:
        if paired:
            self.stats.syscalls_paired += 1
        else:
            self.stats.syscalls_unpaired += 1
        if rec.get("PreviousMode") == "Kernel" and not self.keep_kernel:
            self.stats.kernel_syscalls_dropped += 1
            return
        yield proc, rec

    def feed(self, proc: Process, rec: dict) -> Iterator[Tuple[Process, dict]]:
        plugin = rec.get("Plugin")
        if plugin == "syscall":
            if not self.has_sysret:
                yield from self._out(proc, rec, False)
                return
            key = (rec.get("PID"), rec.get("TID"))
            stack = self.pending.setdefault(key, [])
            if stack and (not self.nested or rec.get("PreviousMode") != "Kernel"):
                for p, r in stack:
                    yield from self._out(p, r, False)
                stack.clear()
            stack.append((proc, rec))
            if len(stack) > MAX_PENDING_PER_THREAD:
                p, r = stack.pop(0)
                yield from self._out(p, r, False)
        elif plugin == "sysret":
            stack = self.pending.get((rec.get("PID"), rec.get("TID")))
            nr = rec.get("Syscall")
            if not stack:
                return
            for i in range(len(stack) - 1, -1, -1):
                p, r = stack[i]
                if r.get("Syscall") == nr:
                    del stack[i]
                    r["Ret"] = rec.get("Ret")
                    r["Info"] = rec.get("Info")
                    # A DRAKVUF that prints output arguments at return puts
                    # them on the sysret record, under the argument's name:
                    # they replace the entry-time pointers, and `Outputs`
                    # tells the parser which values are real.
                    outputs = [k for k in rec if k not in _SYSRET_KEYS]
                    if outputs:
                        for k in outputs:
                            r[k] = rec[k]
                        r["Outputs"] = outputs
                    yield from self._out(p, r, True)
                    return
        else:
            yield proc, rec

    def flush(self) -> Iterator[Tuple[Process, dict]]:
        for stack in self.pending.values():
            for p, r in stack:
                yield from self._out(p, r, False)
        self.pending.clear()


# What an attached copy of a kernel-side record leaves out: who and when,
# which the API record it is attached to already says. `Syscall` goes only
# as a number (the service's index); Linux filetracer's is its name.
_EVENT_KEYS = frozenset((
    "TimeStamp", "PID", "PPID", "TID", "UserId", "UserName", "ProcessName", "EventUID",
    "ThreadName", "vCPU", "CR3", "Module", "NArgs", "FromModule", "FromParentModule",
    "PreviousMode", "Resolved",
    # Where a Windows syscall was made from (syscall_origin)
    "Caller", "ParentCaller", "Bitness", "FromModuleCopy", "FromParentModuleCopy", "StubSyscall",
    "ParentCallTarget", "ParentCallTargetModule",
))


def _trimmed(rec: dict) -> dict:
    return {k: v for k, v in rec.items()
            if k not in _EVENT_KEYS and not k.startswith("_")
            and not (k == "Syscall" and not isinstance(v, str))
            and not (k == "Type" and isinstance(v, str) and not v.startswith("0x"))}

# The argument an API passes a registry value's name in (hooks.txt names
# them as Microsoft's prototypes do; `ValueName` is the Nt* services').
_VALUE_NAME_ARGUMENTS = ("lpValueName=", "ValueName=", "lpValue=", "pszValue=")


def _service_name(rec: dict):
    """The system service a kernel-side record is about. Linux filetracer
    hooks the syscall entry, so its Method is always `do_syscall_64` and the
    service is in `Syscall`, by name."""
    service = rec.get("Syscall")
    if rec.get("Plugin") == "filetracer" and isinstance(service, str):
        return service
    name = rec.get("Method")
    if isinstance(name, str) and name.startswith("Zw") and name[2:3].isupper():
        return "Nt" + name[2:]
    return name


def _kernel_view(rec: dict) -> List[dict]:
    """What an API record keeps of a kernel-side record of the same call:
    the plugin records that resolved something (regmon's key and data,
    filetracer's path, procmon's process), and of the syscall itself only a
    name it resolved or an output it returned. The syscall's arguments are
    the API's own, or a native layer's the API never named."""
    if rec.get("Plugin") != "syscall":
        return [_trimmed(rec)]
    out = [_trimmed(child) for child in rec.get("Resolved") or ()]
    own = {"Plugin": "syscall", "Method": rec.get("Method")}
    for name in OBJECT_NAME_KEYS:
        if isinstance(rec.get(name), str):
            own[name] = rec[name]
    outputs = rec.get("Outputs")
    if outputs:
        own["Outputs"] = outputs
        own.update((name, rec.get(name)) for name in outputs)
    if len(own) > 2:
        out.append(own)
    return out


def _value_name(rec: dict):
    """The registry value a kernel-side record names, lowercased; None when
    it names none."""
    for source in (rec, *(rec.get("Resolved") or ())):
        name = source.get("ValueName")
        if isinstance(name, str):
            return name.lower()
    return None


def _api_value_name(rec: dict):
    """The registry value an API record names, lowercased; None when its
    arguments name none."""
    for arg in rec.get("Arguments") or ():
        if isinstance(arg, str) and arg.startswith(_VALUE_NAME_ARGUMENTS):
            m = DRAKVUF_STRING_ARG.match(arg.partition("=")[2])
            return unescape_drakvuf(m.group(1)).lower() if m else None
    return None


class _CallMerger:
    """Gives each API record the kernel's side of the same call.

    One call reaches the trace several times. The syscall plugin reports the
    system service, with every argument as passed. regmon, filetracer and
    procmon report the same service from inside the kernel, with what a
    handle or an OBJECT_ATTRIBUTES resolves to: the key and the data, the
    file, the process. apimon (libmon on Linux) reports the API in user
    mode -- the ntdll stub of that service, and any Win32 function that was
    called to get there.

    Two kinds of call come out of this (behaviour.py). The **syscall** is
    the service: a regmon/filetracer/procmon record that arrives while the
    same service is pending on its thread is attached to it (`Resolved`) and
    not written on its own. The **API** call is what CAPE's signatures read,
    and what they read from it -- the full name of a registry value, the
    data it was set to, the command line of a process -- is on the kernel's
    side. So each API record is given the kernel-side records of its own
    call (`Kernel`), trimmed to what they resolved; nothing is dropped, and
    the syscall stays a call of its own.

    **Which records are an API's own.** An API record is written when the
    API returns, so its services are already behind it on the same thread:

    * a stub (`NtSetValueKey`) directly follows its service: the latest
      kernel-side record on the thread is it, or the stub has none. A WOW64
      process returns through two stubs, 64-bit ntdll's and then its own
      32-bit one; both are given the record.
    * a wrapper (`RegSetValueExW`, `CreateProcessInternalW`) returns some
      way after, past the stub and whatever else it called. Its services
      are listed in `api_kernel.KERNEL_SERVICES`; the nearest such record
      on the thread that no earlier call of the same API took is its own.
      A record naming a registry value is taken only by an API naming the
      same one.

    Linux: filetracer hooks the syscall entry and shares its EventUID; it is
    held until the syscall of that EventUID and attached to it, and libmon's
    record takes the syscall by `api_kernel.LIBC_SERVICES`."""

    # Kernel-side records remembered per thread, for a wrapper to look back
    # through. CreateProcessInternalW issues its NtCreateUserProcess some
    # eighty services before it returns.
    RECENT = 128

    def __init__(self, pairer: "_SyscallPairer", linux: bool, stats: SplitStats):
        self.pairer = pairer
        self.linux = linux
        self.stats = stats
        self.recent: Dict[tuple, deque] = {}                    # thread -> kernel-side records
        self.entry: Dict[tuple, Tuple[Process, dict]] = {}      # Linux filetracer

    def _remember(self, rec: dict) -> None:
        key = (rec.get("PID"), rec.get("TID"))
        recent = self.recent.get(key)
        if recent is None:
            recent = self.recent[key] = deque(maxlen=self.RECENT)
        recent.append(rec)

    def _attach(self, rec: dict) -> None:
        """Give API record `rec` its kernel-side records, as `Kernel`."""
        api = rec.get("Method")
        wanted, stub = kernel_services(api, self.linux)
        recent = self.recent.get((rec.get("PID"), rec.get("TID"))) if wanted else None
        if not recent:
            return
        # One record, one call of a given API: what a second RegSetValueExW
        # finds already taken was the first one's. The mark goes on the
        # remembered dict, which was serialised when it was written.
        claim = None if stub else canonical(api)
        value_name = None
        if claim is not None and not VALUE_SERVICES.isdisjoint(wanted):
            value_name = _api_value_name(rec)
        found: List[dict] = []
        for i in range(len(recent) - 1, -1, -1):
            kernel = recent[i]
            mine = _service_name(kernel) in wanted and (
                claim is None or claim not in kernel.get("_claims", ()))
            if mine and value_name is not None:
                named = _value_name(kernel)
                mine = named is None or named == value_name
            if mine:
                found.append(kernel)
                if kernel.get("Plugin") == "syscall":
                    break       # the service itself, and everything folded into it
            elif stub or found:
                break
        if not found:
            return
        view: List[dict] = []
        for kernel in found:
            if claim is not None:
                kernel.setdefault("_claims", set()).add(claim)
            view.extend(_kernel_view(kernel))
        if view:
            rec["Kernel"] = view
            self.stats.api_with_kernel += 1

    def feed(self, proc: Process, rec: dict) -> Iterator[Tuple[Process, dict]]:
        plugin = rec.get("Plugin")
        key = (rec.get("PID"), rec.get("TID"))

        if plugin in ("apimon", "libmon"):
            if rec.get("Event") == "api_called":
                self._attach(rec)
            yield proc, rec
            return

        if self.linux:
            if plugin == "filetracer":
                previous = self.entry.pop(key, None)
                if previous is not None:
                    self._remember(previous[1])
                    yield previous
                self.entry[key] = (proc, rec)
                return
            if plugin == "syscall":
                previous = self.entry.pop(key, None)
                if previous is not None:
                    if previous[1].get("EventUID") == rec.get("EventUID"):
                        rec.setdefault("Resolved", []).append(previous[1])
                        self.stats.merged["filetracer"] += 1
                    else:
                        self._remember(previous[1])
                        yield previous
        elif plugin in ("filetracer", "regmon", "procmon"):
            stack = self.pairer.pending.get(key)
            # Not into a kernel-mode syscall that will be dropped: the
            # record would go with it (conhost's creation, 2026-11-10).
            if (stack and stack[-1][1].get("Method") == rec.get("Method")
                    and (self.pairer.keep_kernel or stack[-1][1].get("PreviousMode") != "Kernel")):
                stack[-1][1].setdefault("Resolved", []).append(rec)
                self.stats.merged[plugin] += 1
                return
            # No syscall to join (a trace without the syscall plugin, a
            # service entered from the kernel): a kernel-side record in its
            # own right.
            self._remember(rec)

        for p, r in self.pairer.feed(proc, rec):
            if r.get("Plugin") == "syscall":
                self._remember(r)
            yield p, r

    def flush(self) -> Iterator[Tuple[Process, dict]]:
        yield from self.entry.values()
        self.entry.clear()
        yield from self.pairer.flush()


def _header(proc: Process, os_: TargetOs) -> dict:
    windows = os_ == TargetOs.WINDOWS
    name = PureWindowsPath(proc.procname).name if windows else posixpath.basename(proc.procname)
    try:
        cmdline = (mslex.join(proc.args) if windows else shlex.join(proc.args)) if proc.args else ""
    except Exception:  # noqa: BLE001 - a name mslex will not quote is still a name
        cmdline = " ".join(proc.args)
    return {
        "Plugin": "__process__",
        "Seqid": proc.seqid,
        # The tree's own parent, which a reused PID cannot confuse: what the
        # report's process tree links by (behaviour.ProcessTree)
        "ParentSeqid": proc.parent.seqid if proc.parent is not None else None,
        "PID": proc.pid,
        "PPID": proc.ppid,
        "ProcessName": name or proc.procname,
        "ModulePath": proc.procname,
        "CommandLine": cmdline,
        "TimeStamp": proc.ts_from or 0.0,
        # How it ended, as procmon saw it: the report's process facts
        "ExitTimeStamp": proc.ts_to,
        # Only of a process that ended: an NtTerminateProcess that ended
        # nothing leaves a status too (a NULL handle ends the caller's other
        # threads; procmon repeats the record while procdump2 holds the call)
        "ExitCode": proc.exit_code if proc.ts_to is not None else None,
        "ExitCodeStr": proc.exit_code_str if proc.ts_to is not None else None,
        "KilledBy": proc.killed_by if proc.ts_to is not None else None,
    }


class _Writers:
    """`<out>/<seqid>.log`, header first, with at most MAX_OPEN_FILES open."""

    def __init__(self, out_dir: Path, os_: TargetOs):
        self.out_dir = out_dir
        self.os_ = os_
        self.open: "OrderedDict[int, object]" = OrderedDict()
        self.started: Set[int] = set()

    def write(self, proc: Process, rec: dict) -> None:
        f = self.open.get(proc.seqid)
        if f is None:
            f = (self.out_dir / f"{proc.seqid}.log").open("ab")
            if proc.seqid not in self.started:
                self.started.add(proc.seqid)
                f.write(_compact(_header(proc, self.os_)) + b"\n")
            self.open[proc.seqid] = f
            if len(self.open) > MAX_OPEN_FILES:
                self.open.popitem(last=False)[1].close()
        else:
            self.open.move_to_end(proc.seqid)
        f.write(_compact(rec) + b"\n")

    def close(self) -> None:
        for f in self.open.values():
            f.close()
        self.open.clear()


@dataclass
class SplitResult:
    tree: ProcessTree
    sample: Set[int]                # seqids of the injected processes and descendants
    files: Dict[int, Path]          # seqid -> its log
    stats: SplitStats
    aux_dir: Optional[Path] = None  # <plugin>.log of AUX_PLUGINS
    # The control transfers that made a process the sample's (follow_transfers)
    followed: List[dict] = field(default_factory=list)
    # seqids of the injected processes the tree knew (sample_roots): what
    # the report calls the sample itself, its descendants aside
    roots: Set[int] = field(default_factory=set)
    # seqids of sandboxd's own launch (launch.launch_seqids), which are in
    # `sample` and not the sample; and those of them a sample process made
    # run its code (follow_transfers), which are the sample's after all
    launcher: Set[int] = field(default_factory=set)
    launcher_followed: Set[int] = field(default_factory=set)
    # Threads the sample started through a process handle the trace never
    # saw opened: (PID, TimeStamp, call), transfers nobody could follow
    unresolved: List[Tuple[int, float, str]] = field(default_factory=list)

    @property
    def sample_pids(self) -> Set[int]:
        return {self.tree.processes[s].pid for s in self.sample}


def split_by_process(analysis_dir: Path, out_dir: Path, os_: TargetOs,
                     scope: str = "sample", kernel_syscalls: bool = False,
                     launch: Optional[Tuple[Optional[str], Optional[str], Optional[str]]] = None,
                     ) -> SplitResult:
    """Write `<out_dir>/<seqid>.log` for every process in `scope` ("sample":
    the injected processes and their descendants, and the processes they
    made run code (follow_transfers); "all": every process). The sample is
    worked out either way; capa looks at nothing else.

    `launch` is (shell, delay, sample name) of sandboxd's own launch
    (launch.launch_seqids), when its processes are not to count as the
    sample: they then make no control transfer of the sample's."""
    if scope not in ("sample", "all"):
        raise ValueError(f"scope must be 'sample' or 'all', not {scope!r}")
    trace = analysis_dir / TRACE_LOG
    out_dir.mkdir(parents=True, exist_ok=True)
    prelude = read_prelude(trace, os_)
    stats = SplitStats()

    found, pending_roots = sample_roots(prelude)
    injected_unseen = set(pending_roots)
    sample = descendants(prelude.tree.processes[s] for s in found)
    if not prelude.injected:
        log.warning("%s has no successful inject record: no sample processes", trace)
    launcher = launch_seqids(
        ({"seqid": p.seqid, "parent_seqid": p.parent.seqid if p.parent is not None else None,
          "module_path": h["ModulePath"], "process_name": h["ProcessName"],
          "command_line": h["CommandLine"]}
         for p, h in ((p, _header(p, os_)) for p in (prelude.tree.processes[s] for s in sorted(sample)))),
        *launch) if launch else set()
    launch_processes = set(launcher)
    unresolved: List[Tuple[int, float, str]] = []
    # A process the sample made run code runs the sample's: the sample's too
    followed = follow_transfers(prelude, sample, pending_roots, launcher, unresolved)

    attribute = _Attributor(prelude.tree, sample, pending_roots, stats)
    # An injected PID the tree did not know is a root from its first record
    attribute.injected, attribute.roots = injected_unseen, set(found)
    pairer = _SyscallPairer(prelude.has_sysret, nested=os_ == TargetOs.WINDOWS,
                            keep_kernel=kernel_syscalls, stats=stats)
    merger = _CallMerger(pairer, linux=os_ != TargetOs.WINDOWS, stats=stats)
    writers = _Writers(out_dir, os_)

    def in_scope(proc: Process) -> bool:
        return scope == "all" or proc.seqid in sample

    try:
        aux_dir = out_dir.parent / "aux"
        for uid, _, rec in _windowed(_records(trace, stats, aux_dir), REORDER_WINDOW):
            proc = attribute(rec, uid)
            if proc is None:
                continue
            if not in_scope(proc):
                stats.out_of_scope += 1
                continue
            for p, r in merger.feed(proc, rec):
                writers.write(p, r)
        for p, r in merger.flush():
            writers.write(p, r)
    finally:
        writers.close()

    files = {s: out_dir / f"{s}.log" for s in sorted(writers.started)}
    stats.processes = len(files)
    return SplitResult(prelude.tree, sample, files, stats, aux_dir, followed, attribute.roots,
                       launcher, launch_processes - launcher, unresolved)