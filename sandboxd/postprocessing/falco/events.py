"""Falco-shaped events from DRAKVUF's per-plugin logs.

Falco's rules look at exit events: the syscall, its arguments and result, and
the state of the process and file descriptor at that moment. DRAKVUF writes
those pieces to different logs, so this reads them, sorts them by `EventUID`
(one counter across every plugin) and replays them through a small state
machine:

- `procmon.log` gives the processes: the ones running at start, clones, execs
  (from a return hook on `begin_new_exec`, so every exec record is a
  successful exec) and exits. Every process is tracked, not only the sample's,
  because a rule asks about ancestors.
- `syscall.log` gives each call's arguments at entry, and `sysret.log` its
  result, paired by thread and syscall number.
- `filetracer.log` writes a second reading of the same path under the same
  `EventUID`; it wins, because the syscall plugin's reading is sometimes wrong.
- `libmon.log` gives library calls, which are events of their own source, and
  -- only when sysret is off -- the result of the syscall a libc wrapper made.

What the trace does not say is `UNKNOWN`, not a guess: a result without
sysret, a file descriptor opened before the trace, a working directory never
seen. `condition` turns those into undetermined matches rather than alerts.
"""
from __future__ import annotations

import logging
import pathlib
import posixpath
import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, Iterator, List, Optional, Set, Tuple

import orjson

from ..drakvuf_records import DRAKVUF_STRING_ARG, unescape_drakvuf
from . import linux
from .condition import UNKNOWN

logger = logging.getLogger(__name__)

MAX_FDS_PER_PROCESS = 4096


class FdInfo:
    __slots__ = ("name", "nameraw", "typechar", "type", "flags", "cloexec",
                 "l4proto", "sip", "sport", "cip", "cport", "lip", "lport",
                 "rip", "rport", "connected", "family", "name_changed")

    def __init__(self, name=UNKNOWN, nameraw=UNKNOWN, typechar="f", type_="file",
                 flags=0, cloexec=False) -> None:
        self.name = name
        self.nameraw = nameraw
        self.typechar = typechar
        self.type = type_
        self.flags = flags
        self.cloexec = cloexec
        # Socket endpoints, filled when a plugin reported them (unixsocketmon)
        self.l4proto = None
        self.sip = self.sport = self.cip = self.cport = None
        self.lip = self.lport = self.rip = self.rport = None
        self.connected = None
        self.family = None
        # Falco's fd.name_changed: set for a socket whose destination came with
        # the message (an unconnected sendto); otherwise name against nameraw
        self.name_changed = None

    def copy(self, cloexec: Optional[bool] = None) -> "FdInfo":
        new = FdInfo.__new__(FdInfo)
        for slot in FdInfo.__slots__:
            setattr(new, slot, getattr(self, slot))
        if cloexec is not None:
            new.cloexec = cloexec
        return new


class FdTable:
    """A process's open files. `complete` is False when it may hold
    descriptors the trace never saw opened -- anything inherited from before
    the trace -- so a lookup that misses is UNKNOWN, not "not open"."""
    __slots__ = ("fds", "complete")

    def __init__(self, complete: bool) -> None:
        self.fds: Dict[int, FdInfo] = {}
        self.complete = complete

    def get(self, fd):
        if not isinstance(fd, int):
            return UNKNOWN
        info = self.fds.get(fd)
        if info is None:
            return None if self.complete else UNKNOWN
        return info

    def set(self, fd: int, info: FdInfo) -> None:
        if fd in self.fds or len(self.fds) < MAX_FDS_PER_PROCESS:
            self.fds[fd] = info
        else:
            self.complete = False

    def pop(self, fd) -> None:
        if isinstance(fd, int):
            self.fds.pop(fd, None)

    def copy(self) -> "FdTable":
        new = FdTable(self.complete)
        new.fds = dict(self.fds)
        return new


class Proc:
    __slots__ = ("pid", "ppid", "comm", "exepath", "exe", "args", "env",
                 "cwd", "cwd_seen", "uid", "pgid", "start", "memfd", "fds", "exec_seen")

    def __init__(self, pid: int, ppid, comm=UNKNOWN, exepath=UNKNOWN, uid=UNKNOWN) -> None:
        self.pid = pid
        self.ppid = ppid
        self.comm = comm
        self.exepath = exepath
        self.exe = UNKNOWN            # argv[0]
        self.args = UNKNOWN           # argv[1:], space-joined, as Falco's proc.args
        self.env = UNKNOWN            # dict of the variables procmon printed
        self.cwd = UNKNOWN
        # True once a chdir or fchdir in the trace set `cwd`. Until then it
        # is the PWD of the last exec, which the next exec's PWD replaces.
        self.cwd_seen = False
        self.uid = uid
        self.pgid = UNKNOWN
        self.start = UNKNOWN
        self.memfd = UNKNOWN
        self.fds = FdTable(complete=False)
        self.exec_seen = False

    def fork(self, pid: int, ts: float, share_files: bool) -> "Proc":
        child = Proc.__new__(Proc)
        for slot in Proc.__slots__:
            setattr(child, slot, getattr(self, slot))
        child.pid, child.ppid, child.start = pid, self.pid, ts
        child.fds = self.fds if share_files else self.fds.copy()
        child.exec_seen = False
        return child


class Event:
    __slots__ = ("source", "type", "num", "time", "tid", "pid", "proc", "procs",
                 "comm", "uid", "rawres", "args", "fd", "fdnum", "api", "buffer")

    def __init__(self, source: str, type_: str, num: int, time: float, tid, pid: int,
                 proc: Proc, procs: Dict[int, Proc]) -> None:
        self.source = source
        self.type = type_
        self.num = num
        self.time = time
        self.tid = tid
        self.pid = pid
        self.proc = proc
        self.procs = procs
        self.comm = proc.comm
        self.uid = proc.uid
        self.rawres = UNKNOWN
        self.args: Dict[str, object] = {}
        self.fd = None
        self.fdnum = None
        self.api = None
        self.buffer = None


@dataclass
class TraceConfig:
    # Environment variables procmon prints: its default filter
    # (`src/plugins/procmon/linux.cpp`, `configure_filter`) unless DRAKVUF was
    # given `--procmon-filter-file`. A variable outside it is unknown.
    env_filter: FrozenSet[str] = frozenset({"LD_PRELOAD", "PWD", "OLDPWD"})
    users: Dict[int, str] = field(default_factory=lambda: {0: "root"})


@dataclass
class TraceStats:
    records: Dict[str, int] = field(default_factory=dict)
    events: Dict[str, int] = field(default_factory=dict)
    sysret: bool = False
    procmon: bool = False
    libmon: bool = False
    unpaired: int = 0          # syscall entries whose result never came
    results_from_libmon: int = 0


# `K=V,K=V` as procmon's map_to_str writes it; a value may itself contain a
# comma, so split only where a new NAME= starts.
_ENV_SPLIT = re.compile(r",(?=[A-Za-z_][A-Za-z0-9_]*=)")


def parse_environment(text: str) -> Dict[str, str]:
    out = {}
    for item in _ENV_SPLIT.split(text or ""):
        k, sep, v = item.partition("=")
        if sep:
            out[k] = v
    return out


def parse_libmon_arguments(args: Iterable[str]) -> Tuple[Dict[str, object], List[object]]:
    """`["Path=0x7f:\\"/tmp/x\\"", "Flags=0x0"]` -> by name and by position."""
    by_name, by_pos = {}, []
    for arg in args or ():
        if not isinstance(arg, str):
            continue
        name, sep, value = arg.partition("=")
        if not sep:
            by_pos.append(arg)
            continue
        m = DRAKVUF_STRING_ARG.match(value)
        parsed = unescape_drakvuf(m.group(1)) if m else linux.parse_int(value, 64)
        if parsed is None:
            parsed = value
        by_name[name] = parsed
        by_pos.append(parsed)
    return by_name, by_pos


def _normalise(path: str) -> str:
    out = posixpath.normpath(path)
    return "/" + out.lstrip("/") if out.startswith("//") else out


def _basename(path: object) -> object:
    if not isinstance(path, str) or not path:
        return UNKNOWN
    return path.rstrip("/").rsplit("/", 1)[-1] or path


def socket_info(rec: dict) -> FdInfo:
    """A socket's fd entry from the endpoints unixsocketmon reported.

    `Type` AF_INET/AF_INET6/AF_LOCAL, `Protocol` TCP/UDP,
    `LocalIp`/`LocalPort`/`RemoteIp`/`RemotePort` or `LocalPath`/`RemotePath`,
    `Connected`. Outbound: the guest is the client, so Falco's cip/sip are the
    local and remote ends.
    """
    proto = str(rec.get("Protocol") or "")
    family = rec.get("Type")
    info = FdInfo(name="", nameraw="")
    if family == "AF_LOCAL":
        info.typechar, info.type = "u", "unix"
        info.name = info.nameraw = rec.get("RemotePath") or rec.get("LocalPath") or ""
    else:
        v6 = family == "AF_INET6"
        info.typechar, info.type = ("6", "ipv6") if v6 else ("4", "ipv4")
        low = proto.lower()
        info.l4proto = "tcp" if low.startswith("tcp") else "udp" if low.startswith("udp") else None
        info.lip, info.lport = rec.get("LocalIp"), rec.get("LocalPort")
        info.rip, info.rport = rec.get("RemoteIp"), rec.get("RemotePort")
        info.cip, info.cport, info.sip, info.sport = info.lip, info.lport, info.rip, info.rport
        if info.rip:
            local = f"{info.lip}:{info.lport}" if info.lip and info.lport else "0.0.0.0:0"
            info.name = info.nameraw = f"{local}->{info.rip}:{info.rport}"
    if "Connected" in rec:
        info.connected = bool(rec["Connected"])
        info.name_changed = not info.connected and bool(rec.get("RemoteIp") or rec.get("RemotePath"))
    return info


def _uid(raw) -> int:
    return raw if isinstance(raw, int) else UNKNOWN


@dataclass
class _Pending:
    type: str
    nr: object
    uid: int
    time: float
    tid: object
    pid: int
    proc: Proc
    comm: object
    user: object
    args: Dict[str, object]
    # A unixsocketmon record of this call: its socket's endpoints
    endpoints: Optional[dict] = None


def _read_jsonl(path: pathlib.Path, keep) -> Iterator[dict]:
    with path.open("rb") as f:
        for line in f:
            try:
                rec = orjson.loads(line)
            except orjson.JSONDecodeError:
                continue
            if isinstance(rec, dict) and keep(rec):
                yield rec


def _event_uid(rec: dict) -> int:
    raw = rec.get("EventUID")
    if isinstance(raw, str):
        try:
            return int(raw, 16)
        except ValueError:
            return -1
    return raw if isinstance(raw, int) else -1


def injected_pids(analysis_dir: pathlib.Path) -> List[int]:
    """The processes DRAKVUF started: the sample, by `-i/-e` injection.

    Every successful injection with a process, not exactly one as capa's
    `get_malware_processes` insists: a benchmark that writes its workload with
    `--write-file` adds a WriteFile entry, which names no process.
    """
    path = analysis_dir / "inject.log"
    if not path.exists():
        return []
    out = []
    for rec in _read_jsonl(path, lambda r: True):
        pid = rec.get("InjectedPid")
        if rec.get("Status") == "Success" and isinstance(pid, int) and pid > 0:
            out.append(pid)
    return out


def sample_scope(analysis_dir: pathlib.Path) -> Set[int]:
    """The injected processes and every descendant, by PID.

    Built from procmon's clones when procmon ran, otherwise from the PPID
    every syscall record carries -- so a job without procmon still has a scope,
    just without exec rules to evaluate in it.
    """
    roots = injected_pids(analysis_dir)
    if not roots:
        return set()
    children: Dict[int, Set[int]] = {}
    procmon = analysis_dir / "procmon.log"
    if procmon.exists():
        for rec in _read_jsonl(procmon, lambda r: r.get("Method") == "kernel_clone"):
            if "CLONE_THREAD" in str(rec.get("Flags", "")):
                continue
            parent, child = rec.get("PID"), rec.get("NewPid")
            if isinstance(parent, int) and isinstance(child, int):
                children.setdefault(parent, set()).add(child)
    syscalls = analysis_dir / "syscall.log"
    if not children and syscalls.exists():
        pairs = re.compile(rb'"PID":\s*(\d+),\s*"PPID":\s*(\d+)')
        with syscalls.open("rb") as f:
            for line in f:
                m = pairs.search(line)
                if m:
                    children.setdefault(int(m.group(2)), set()).add(int(m.group(1)))
    scope, todo = set(), list(roots)
    while todo:
        pid = todo.pop()
        if pid in scope:
            continue
        scope.add(pid)
        todo.extend(children.get(pid, ()))
    return scope


class Trace:
    """Replays a job directory's logs as Falco events, in EventUID order."""

    def __init__(self, analysis_dir: pathlib.Path, config: TraceConfig,
                 syscall_types: Optional[Set[str]], libmon_types: Optional[Set[str]],
                 scope: Optional[Set[int]]) -> None:
        self.dir = analysis_dir
        self.config = config
        # Types a rule asks about (None: every type), and the ones read anyway
        # because they change the state the fields read.
        self.syscall_emit = syscall_types
        self.libmon_emit = libmon_types
        self.scope = scope
        self.procs: Dict[int, Proc] = {}
        self.pending: Dict[object, _Pending] = {}
        self.exec_type: Dict[object, str] = {}
        self.stats = TraceStats()
        self.sysret = (analysis_dir / "sysret.log").exists()
        self.stats.sysret = self.sysret
        self.stats.procmon = (analysis_dir / "procmon.log").exists()
        self.stats.libmon = (analysis_dir / "libmon.log").exists()
        self.socket_endpoints = (analysis_dir / "unixsocketmon.log").exists()

    # -- reading --------------------------------------------------------------

    def _in_scope(self, rec: dict) -> bool:
        return self.scope is None or rec.get("PID") in self.scope

    def _wanted_syscall(self, t: object) -> bool:
        return (t in linux.STATE_EVENTS or self.syscall_emit is None
                or t in self.syscall_emit)

    def _collect(self) -> List[Tuple[int, int, str, dict]]:
        items: List[Tuple[int, int, str, dict]] = []
        seq = 0
        counts = self.stats.records

        def add(kind: str, rec: dict, uid: Optional[int] = None) -> None:
            nonlocal seq
            items.append((_event_uid(rec) if uid is None else uid, seq, kind, rec))
            seq += 1
            counts[kind] = counts.get(kind, 0) + 1

        procmon = self.dir / "procmon.log"
        if procmon.exists():
            for rec in _read_jsonl(procmon, lambda r: True):
                add("procmon", rec)
        for rec in _read_jsonl(self.dir / "inject.log", lambda r: True) if (self.dir / "inject.log").exists() else ():
            add("inject", rec, uid=-1)

        syscall = self.dir / "syscall.log"
        if syscall.exists():
            for rec in _read_jsonl(syscall, lambda r: self._in_scope(r)
                                   and self._wanted_syscall(r.get("Method"))):
                add("syscall", rec)
        if self.sysret:
            for rec in _read_jsonl(self.dir / "sysret.log", lambda r: self._in_scope(r)
                                   and self._wanted_syscall(r.get("Method"))):
                add("sysret", rec)

        libmon = self.dir / "libmon.log"
        if libmon.exists():
            backfill = set()
            if not self.sysret:
                for names in linux.LIBC_EQUIVALENTS.values():
                    backfill.update(names)

            def keep_libmon(r: dict) -> bool:
                if r.get("Event") != "api_called" or not self._in_scope(r):
                    return False
                m = r.get("Method")
                return (self.libmon_emit is None or m in self.libmon_emit or m in backfill)
            for rec in _read_jsonl(libmon, keep_libmon):
                add("libmon", rec)

        if self.socket_endpoints:
            for rec in _read_jsonl(self.dir / "unixsocketmon.log", self._in_scope):
                add("unixsocketmon", rec)

        self.filetracer: Dict[int, dict] = {}
        ft = self.dir / "filetracer.log"
        if ft.exists():
            for rec in _read_jsonl(ft, lambda r: self._in_scope(r)
                                   and r.get("Syscall") in linux.FILETRACER_PATH_ARG):
                self.filetracer[_event_uid(rec)] = rec

        items.sort(key=lambda x: (x[0], x[1]))
        return items

    def __iter__(self) -> Iterator[Event]:
        for _, _, kind, rec in self._collect():
            if kind == "procmon":
                yield from self._procmon(rec)
            elif kind == "inject":
                self._inject(rec)
            elif kind == "syscall":
                yield from self._syscall(rec)
            elif kind == "sysret":
                yield from self._sysret(rec)
            elif kind == "libmon":
                yield from self._libmon(rec)
            elif kind == "unixsocketmon":
                p = self.pending.get(rec.get("TID"))
                if p is not None and p.type in _SOCKET_CALLS:
                    p.endpoints = rec
        for p in list(self.pending.values()):
            yield from self._finish(p, UNKNOWN)
        self.pending.clear()

    # -- processes ------------------------------------------------------------

    def _proc_for(self, rec: dict) -> Proc:
        pid = rec.get("PID")
        ppid = rec.get("PPID", UNKNOWN)
        proc = self.procs.get(pid)
        if proc is None:
            name = rec.get("ProcessName")
            proc = Proc(pid, ppid,
                        comm=rec.get("ThreadName") or _basename(name),
                        exepath=name if isinstance(name, str) and name.startswith("/") else UNKNOWN,
                        uid=_uid(rec.get("UserId")))
            self.procs[pid] = proc
        elif isinstance(ppid, int) and ppid != proc.ppid:
            proc.ppid = ppid      # reparented, or first seen without one
        return proc

    def _inject(self, rec: dict) -> None:
        pid = rec.get("InjectedPid")
        if rec.get("Status") != "Success" or not isinstance(pid, int) or pid <= 0:
            return
        proc = self.procs.get(pid) or Proc(pid, UNKNOWN)
        self.procs[pid] = proc
        name = rec.get("ProcessName")
        if isinstance(name, str) and name:
            proc.exe = name
            proc.exepath = name
            proc.comm = _basename(name)[:15]
            proc.args = rec.get("Arguments") or ""

    def _procmon(self, rec: dict) -> Iterator[Event]:
        method = rec.get("Method")
        if "RunningProcess" in rec:
            pid, name = rec.get("PID"), rec.get("RunningProcess")
            if isinstance(pid, int) and pid not in self.procs:
                self.procs[pid] = Proc(
                    pid, rec.get("PPID", UNKNOWN),
                    comm=_basename(name)[:15] if isinstance(name, str) and name.startswith("/") else name,
                    exepath=name if isinstance(name, str) and name.startswith("/") else UNKNOWN)
            return
        if method == "kernel_clone":
            self._clone(rec)
        elif method == "do_execveat_common":
            yield from self._exec(rec)

    def _clone(self, rec: dict) -> None:
        flags = str(rec.get("Flags", ""))
        child_pid = rec.get("NewPid")
        if "CLONE_THREAD" in flags or not isinstance(child_pid, int):
            return
        parent = self._proc_for(rec)
        ts = float(rec.get("TimeStamp") or 0)
        child = self.procs.get(child_pid)
        if child is None:
            self.procs[child_pid] = parent.fork(child_pid, ts, "CLONE_FILES" in flags)
            return
        # The child's own records came first: the clone record is printed when
        # the clone returns in the parent, which a vfork child outruns. Keep
        # what the child's records said and inherit only what they could not.
        child.ppid = parent.pid
        if child.start is UNKNOWN:
            child.start = ts
        if child.cwd is UNKNOWN:
            child.cwd = parent.cwd
        if not child.exec_seen:
            for slot in ("exe", "args", "env", "pgid", "memfd"):
                if getattr(child, slot) is UNKNOWN:
                    setattr(child, slot, getattr(parent, slot))
        if not child.fds.fds and parent.fds.complete:
            child.fds = parent.fds.copy()

    def _exec(self, rec: dict) -> Iterator[Event]:
        proc = self._proc_for(rec)
        tid = rec.get("TID")
        cmd = rec.get("CommandLine")
        if isinstance(cmd, str):
            argv0, _, rest = cmd.partition(" ")
            proc.exe, proc.args = argv0, rest
        else:
            proc.exe = proc.args = UNKNOWN
        filename = rec.get("FileName") or rec.get("ImagePathName")
        # The kernel names the task after the file passed to execve
        # (kbasename(bprm->filename)), truncated to TASK_COMM_LEN - 1.
        proc.comm = _basename(filename)[:15] if isinstance(filename, str) else UNKNOWN
        image = rec.get("ImagePathName")
        proc.exepath = image if isinstance(image, str) and image else UNKNOWN
        env = rec.get("Environment")
        proc.env = parse_environment(env) if isinstance(env, str) else {}
        if not proc.cwd_seen and "PWD" in proc.env:
            proc.cwd = proc.env["PWD"]
        euid = rec.get("euid", rec.get("UserId"))
        proc.uid = _uid(euid)
        proc.pgid = rec.get("PGID", UNKNOWN)
        proc.start = float(rec.get("TimeStamp") or 0)
        fdpath = str(rec.get("fdpath") or "")
        proc.memfd = "memfd:" in fdpath or (isinstance(image, str) and image.startswith("/memfd:"))
        proc.exec_seen = True
        for fd in [fd for fd, info in proc.fds.fds.items() if info.cloexec]:
            del proc.fds.fds[fd]
        exec_type = self.exec_type.pop(tid, "execve")
        # procmon is read for every process, for the ancestry; only the
        # sample's execs are events.
        if not self._in_scope(rec):
            return
        ev = Event("syscall", exec_type, _event_uid(rec),
                   float(rec.get("TimeStamp") or 0), tid, proc.pid, proc, self.procs)
        ev.rawres = 0
        self._count(ev)
        yield ev

    # -- syscalls -------------------------------------------------------------

    def _syscall(self, rec: dict) -> Iterator[Event]:
        tid = rec.get("TID")
        prev = self.pending.pop(tid, None)
        if prev is not None:
            yield from self._finish(prev, UNKNOWN)
        t = rec.get("Method")
        if t in ("execve", "execveat"):
            self.exec_type[tid] = t
            return
        proc = self._proc_for(rec)
        uid = _event_uid(rec)
        args = {k: v for k, v in rec.items() if k not in _COMMON_KEYS}
        ft = self.filetracer.get(uid)
        if ft is not None and ft.get("Syscall") == t:
            target = linux.FILETRACER_PATH_ARG.get(t)
            if target and isinstance(ft.get("FileName"), str):
                args[target] = ft["FileName"]
            if isinstance(ft.get("newpath"), str) and "newpath" in args:
                args["newpath"] = ft["newpath"]
        p = _Pending(t, rec.get("Syscall"), uid, float(rec.get("TimeStamp") or 0), tid,
                     proc.pid, proc, rec.get("ThreadName") or proc.comm,
                     _uid(rec.get("UserId")), args)
        if (self.sysret or (self.stats.libmon and t in linux.LIBC_EQUIVALENTS)
                or (self.socket_endpoints and t in _SOCKET_CALLS)):
            self.pending[tid] = p
        else:
            yield from self._finish(p, UNKNOWN)

    def _sysret(self, rec: dict) -> Iterator[Event]:
        tid = rec.get("TID")
        p = self.pending.get(tid)
        if p is None or p.nr != rec.get("Syscall"):
            return
        del self.pending[tid]
        ret = linux.parse_int(rec.get("Ret"), 64)
        yield from self._finish(p, ret if ret is not None else UNKNOWN)

    def _libmon(self, rec: dict) -> Iterator[Event]:
        tid = rec.get("TID")
        name = rec.get("Method")
        by_name, by_pos = parse_libmon_arguments(rec.get("Arguments"))
        ret = linux.parse_int(rec.get("ReturnValue"), 64) if "ReturnValue" in rec else UNKNOWN
        p = self.pending.get(tid)
        if p is not None and not self.sysret:
            del self.pending[tid]
            if name in linux.LIBC_EQUIVALENTS.get(p.type, ()) and self._same_path(p, by_name):
                self.stats.results_from_libmon += 1
                # libc reports failure as -1 and errno, which libmon does not
                # print: the call failed, with an errno nobody saw.
                yield from self._finish(p, -1 if isinstance(ret, int) and ret < 0 else ret)
            else:
                yield from self._finish(p, UNKNOWN)
        if self.libmon_emit is not None and name not in self.libmon_emit:
            return
        proc = self._proc_for(rec)
        ev = Event("libmon", name, _event_uid(rec), float(rec.get("TimeStamp") or 0),
                   tid, proc.pid, proc, self.procs)
        ev.uid = _uid(rec.get("UserId", proc.uid))
        ev.rawres = ret if ret is not None else UNKNOWN
        ev.api = {
            "name": name,
            "lib": rec.get("Library"),
            "from_module": rec.get("FromModule"),
            "called_from": rec.get("CalledFrom"),
            "args": by_name,
            "argv": by_pos,
        }
        self._count(ev)
        yield ev

    @staticmethod
    def _same_path(p: _Pending, libmon_args: Dict[str, object]) -> bool:
        ours = p.args.get("pathname", p.args.get("oldpath"))
        theirs = libmon_args.get("Path", libmon_args.get("From"))
        if not isinstance(ours, str) or not isinstance(theirs, str):
            return True
        return ours == theirs

    # -- results and state ----------------------------------------------------

    def _render(self, t: str, raw: Dict[str, object]) -> Tuple[Dict[str, object], Dict[str, int]]:
        rendered: Dict[str, object] = {}
        ints: Dict[str, int] = {}
        for falco_name, drak_name, kind in linux.EVENT_ARGS.get(t, ()):
            value = raw.get(drak_name)
            if value is None:
                rendered[falco_name] = UNKNOWN
                continue
            if kind == "path":
                rendered[falco_name] = value if isinstance(value, str) else str(value)
                continue
            n = linux.parse_int(value, 32 if kind in ("fd", "oflags", "mode", "af", "socktype", "uid", "nsflags") else 64)
            if n is None:
                rendered[falco_name] = UNKNOWN
                continue
            ints[falco_name] = n
            if kind == "oflags":
                rendered[falco_name] = linux.render_open_flags(n)
            elif kind == "mode":
                rendered[falco_name] = linux.render_mode(n)
            elif kind == "ptrace":
                rendered[falco_name] = linux.PTRACE_REQUESTS.get(n, str(n))
            elif kind == "af":
                rendered[falco_name] = linux.ADDRESS_FAMILIES.get(n, str(n))
            elif kind == "socktype":
                rendered[falco_name] = linux.render_socket_type(n)
            elif kind == "uid":
                rendered[falco_name] = self.config.users.get(n, UNKNOWN)
            elif kind == "bpfcmd":
                rendered[falco_name] = linux.BPF_COMMANDS.get(n, str(n))
            elif kind == "nsflags":
                rendered[falco_name] = linux.render_ns_flags(n)
            else:
                rendered[falco_name] = n
        return rendered, ints

    def _resolve(self, proc: Proc, dirfd, path) -> object:
        if not isinstance(path, str):
            return UNKNOWN
        if path.startswith("/"):
            return _normalise(path)
        if dirfd is None or dirfd == linux.AT_FDCWD:
            base = proc.cwd
        else:
            info = proc.fds.get(dirfd)
            base = info.name if isinstance(info, FdInfo) else UNKNOWN
        if not isinstance(base, str):
            return UNKNOWN
        return _normalise(posixpath.join(base, path)) if path else base

    def _finish(self, p: _Pending, res) -> Iterator[Event]:
        if res is UNKNOWN:
            self.stats.unpaired += 1 if self.sysret else 0
        t, proc = p.type, p.proc
        args, ints = self._render(t, p.args)
        fds = proc.fds
        ok = res is UNKNOWN or (isinstance(res, int) and res >= 0)
        fd_info, fd_num = None, None

        if t in ("open", "openat", "creat"):
            flags = ints.get("flags", 0o1101 if t == "creat" else 0)
            dirfd = ints.get("dirfd") if t == "openat" else None
            raw_path = p.args.get("pathname")
            directory = bool(flags & linux.O_DIRECTORY)
            fd_info = FdInfo(name=self._resolve(proc, dirfd, raw_path),
                             nameraw=raw_path if isinstance(raw_path, str) else UNKNOWN,
                             typechar="d" if directory else "f",
                             type_="directory" if directory else "file",
                             flags=flags, cloexec=bool(flags & linux.O_CLOEXEC))
            if isinstance(res, int):
                fd_num = res if res >= 0 else -1
                if res >= 0:
                    fds.set(res, fd_info)
            else:
                fd_num = UNKNOWN
        elif t == "memfd_create":
            fd_info = FdInfo(name="memfd:" + str(args.get("name", "")), typechar="m", type_="memfd")
            if isinstance(res, int) and res >= 0:
                fds.set(res, fd_info)
            fd_num = res
        elif t == "socket":
            domain = ints.get("domain")
            typechar, type_ = {linux.AF_INET: ("4", "ipv4"), linux.AF_INET6: ("6", "ipv6"),
                               linux.AF_UNIX: ("u", "unix"), linux.AF_NETLINK: ("n", "netlink"),
                               }.get(domain, ("s", "socket"))
            fd_info = FdInfo(name="", typechar=typechar, type_=type_,
                             cloexec=bool(ints.get("type", 0) & linux.SOCK_CLOEXEC))
            fd_info.family = domain
            stype = ints.get("type", 0) & 0xF
            fd_info.l4proto = {1: "tcp", 2: "udp"}.get(stype) if domain in (linux.AF_INET, linux.AF_INET6) else None
            if isinstance(res, int) and res >= 0:
                fds.set(res, fd_info)
            fd_num = res
        elif t in ("accept", "accept4"):
            listening = fds.get(ints.get("fd"))
            if isinstance(listening, FdInfo):
                fd_info = listening.copy(cloexec=bool(ints.get("flags", 0) & linux.SOCK_CLOEXEC))
                fd_info.name = UNKNOWN
            else:
                fd_info = UNKNOWN
            if isinstance(res, int) and res >= 0 and isinstance(fd_info, FdInfo):
                fds.set(res, fd_info)
            fd_num = res
        elif t in ("dup", "dup2", "dup3"):
            old = ints.get("oldfd")
            fd_info, fd_num = fds.get(old), old
            new = res if isinstance(res, int) and res >= 0 else (
                ints.get("newfd") if res is UNKNOWN and t != "dup" else None)
            if isinstance(new, int) and isinstance(fd_info, FdInfo):
                fds.set(new, fd_info.copy(cloexec=bool(ints.get("flags", 0) & linux.O_CLOEXEC)))
        elif t == "fcntl":
            if ints.get("cmd") in (linux.F_DUPFD, linux.F_DUPFD_CLOEXEC) and isinstance(res, int) and res >= 0:
                src = fds.get(ints.get("fd"))
                if isinstance(src, FdInfo):
                    fds.set(res, src.copy(cloexec=ints.get("cmd") == linux.F_DUPFD_CLOEXEC))
        elif t == "close":
            fd_info, fd_num = fds.get(ints.get("fd")), ints.get("fd")
            if ok:
                fds.pop(ints.get("fd"))
        elif t == "chdir":
            if ok:
                proc.cwd = self._resolve(proc, None, p.args.get("path"))
                proc.cwd_seen = True
        elif t == "fchdir":
            info = fds.get(ints.get("fd"))
            if ok:
                proc.cwd = info.name if isinstance(info, FdInfo) else UNKNOWN
                proc.cwd_seen = True
        else:
            which = linux.EVENT_FD.get(t)
            if which:
                n = ints.get(which)
                fd_info, fd_num = fds.get(n), n
            if p.endpoints is not None and isinstance(fd_num, int):
                # unixsocketmon saw this socket during the call: its endpoints
                # complete the fd entry, for this event and the ones after it
                seen = socket_info(p.endpoints)
                if isinstance(fd_info, FdInfo):
                    seen.cloexec = fd_info.cloexec
                if t == "connect" and (res is UNKNOWN or res == 0 or res == -115):   # EINPROGRESS
                    seen.connected = True
                fds.set(fd_num, seen)
                fd_info = seen

        if self.syscall_emit is not None and t not in self.syscall_emit:
            return
        ev = Event("syscall", t, p.uid, p.time, p.tid, p.pid, proc, self.procs)
        ev.comm = p.comm
        ev.uid = p.user if p.user is not UNKNOWN else proc.uid
        ev.rawres = res
        ev.args = args
        ev.fd = fd_info
        ev.fdnum = fd_num
        self._count(ev)
        yield ev

    def _count(self, ev: Event) -> None:
        key = f"{ev.source}:{ev.type}"
        self.stats.events[key] = self.stats.events.get(key, 0) + 1


# The calls unixsocketmon reports endpoints for, by thread, while they run
_SOCKET_CALLS = frozenset({"connect", "sendto", "sendmsg"})

# Keys every syscall record carries that are not the call's arguments
_COMMON_KEYS = frozenset({
    "Plugin", "TimeStamp", "PID", "PPID", "TID", "UserId", "ProcessName",
    "Method", "EventUID", "ThreadName", "Module", "vCPU", "CR3", "Syscall",
    "NArgs", "Type", "FromModule", "FromParentModule",
})