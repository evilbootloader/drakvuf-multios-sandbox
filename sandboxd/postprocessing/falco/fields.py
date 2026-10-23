"""Falco's fields, extracted from `events.Event`.

Each field returns a value, None (the field exists but has no value here, as
a container field on a VM: every comparison is false, as in Falco) or UNKNOWN
(this trace cannot say). A field that is not in these tables makes the rule
that uses it unsupported, so a rule is never evaluated against a field this
module only pretends to have.

What each field reads, and which are always unknown, is tabulated in
docs/architecture/falco-rules.md; keep the two in step.
"""
from __future__ import annotations

import ipaddress
import posixpath
from typing import Callable, Dict, List, Optional, Tuple

from . import linux
from .condition import UNKNOWN, Environment, Extractor, Multi, UnsupportedField
from .events import Event, FdInfo, Proc

MAX_ANCESTRY = 64


# --- processes ----------------------------------------------------------------

def _ancestors(ev: Event) -> Tuple[List[Proc], bool]:
    """The parent, grandparent, ...; and whether the chain reached the root."""
    out: List[Proc] = []
    seen = {ev.proc.pid}
    p = ev.proc
    for _ in range(MAX_ANCESTRY):
        ppid = p.ppid
        if not isinstance(ppid, int):
            return out, False
        if ppid == 0:
            return out, True
        parent = ev.procs.get(ppid)
        if parent is None or parent.pid in seen:
            return out, parent is not None
        seen.add(parent.pid)
        out.append(parent)
        p = parent
    return out, False


def _parent(ev: Event):
    ppid = ev.proc.ppid
    if not isinstance(ppid, int):
        return UNKNOWN
    if ppid == 0:
        return None
    return ev.procs.get(ppid, UNKNOWN)


def _cmdline(p: Proc, comm=None):
    name = comm if comm is not None else p.comm
    if name is UNKNOWN or p.args is UNKNOWN:
        return UNKNOWN
    return f"{name} {p.args}" if p.args else str(name)


PROC_ATTRS: Dict[str, Callable[[Proc], object]] = {
    "name": lambda p: p.comm,
    "exe": lambda p: p.exe,
    "exepath": lambda p: p.exepath,
    "args": lambda p: p.args,
    "cmdline": _cmdline,
    "pid": lambda p: p.pid,
}


def _of_parent(attr: Callable[[Proc], object]) -> Extractor:
    def get(ev: Event):
        parent = _parent(ev)
        if parent is UNKNOWN or parent is None:
            return parent
        return attr(parent)
    return get


def _of_ancestor(attr: Callable[[Proc], object], index: Optional[str]) -> Extractor:
    if index is None:
        def any_ancestor(ev: Event):
            chain, complete = _ancestors(ev)
            values = [attr(p) for p in chain]
            known = [v for v in values if v is not UNKNOWN and v is not None]
            return Multi(known, complete and len(known) == len(values))
        return any_ancestor
    try:
        n = int(index)
    except ValueError:
        raise UnsupportedField(f"ancestor index {index!r}")
    if n == 0:
        return lambda ev: attr(ev.proc)

    def nth(ev: Event):
        chain, complete = _ancestors(ev)
        if len(chain) >= n:
            return attr(chain[n - 1])
        return None if complete else UNKNOWN
    return nth


def _env(ev: Event, name: Optional[str], env_filter) -> object:
    env = ev.proc.env
    if name is None:
        if not isinstance(env, dict):
            return UNKNOWN
        return Environment([f"{k}={v}" for k, v in env.items()], env_filter)
    if isinstance(env, dict):
        if name in env:
            return env[name]
        if name in env_filter:
            return None
    return UNKNOWN


def _duration(ev: Event):
    start = ev.proc.start
    if not isinstance(start, (int, float)):
        return UNKNOWN
    return int(max(0.0, ev.time - start) * 1e9)


def _cwd(ev: Event):
    cwd = ev.proc.cwd
    if not isinstance(cwd, str):
        return UNKNOWN
    return cwd if cwd.endswith("/") else cwd + "/"


# --- files and sockets --------------------------------------------------------

def _fd(attr: Callable[[FdInfo], object]) -> Extractor:
    def get(ev: Event):
        info = ev.fd
        if info is None or info is UNKNOWN:
            return info
        return attr(info)
    return get


def _directory(info: FdInfo):
    if not isinstance(info.name, str):
        return info.name
    if info.typechar == "d":
        return info.name
    if info.typechar != "f":
        return None
    return posixpath.dirname(info.name) or "/"


def _filename(info: FdInfo):
    if not isinstance(info.name, str):
        return info.name
    if info.typechar not in ("f", "d"):
        return None
    return posixpath.basename(info.name.rstrip("/")) or info.name


def _name_changed(info: FdInfo):
    if info.name_changed is not None:
        return info.name_changed
    if not isinstance(info.name, str) or not isinstance(info.nameraw, str):
        return UNKNOWN
    return info.name != info.nameraw


def _is_socket(info: FdInfo) -> bool:
    return info.typechar in ("4", "6", "u")


def _endpoint(attr: str) -> Callable[[FdInfo], object]:
    """A socket endpoint: None on a non-socket, UNKNOWN until reported."""
    def get(info: FdInfo):
        if not _is_socket(info) or (attr in _IP_ATTRS and info.typechar == "u"):
            return None
        v = getattr(info, attr)
        if v is None:
            return UNKNOWN
        if attr in _IP_ATTRS:
            try:
                return ipaddress.ip_address(v)
            except ValueError:
                return UNKNOWN
        return v
    return get


_IP_ATTRS = frozenset({"sip", "cip", "lip", "rip"})


def _either(a: str, b: str) -> Callable[[FdInfo], object]:
    """`fd.ip`, `fd.port`, `fd.net`: true when either end matches. An end
    the trace does not know -- the local end of a connect, before the kernel
    binds it -- leaves the other to decide a match, and only a mismatch
    unknown."""
    first, second = _endpoint(a), _endpoint(b)

    def get(info: FdInfo):
        x, y = first(info), second(info)
        if x is None and y is None:
            return None
        known = [v for v in (x, y) if v is not None and v is not UNKNOWN]
        if not known:
            return UNKNOWN
        return Multi(known, complete=UNKNOWN not in (x, y))
    return get


# --- events -------------------------------------------------------------------

def _res(ev: Event):
    r = ev.rawres
    if not isinstance(r, int):
        return UNKNOWN
    return linux.errno_name(r)


def _failed(ev: Event):
    r = ev.rawres
    return r < 0 if isinstance(r, int) else UNKNOWN


def _open_flags(test: Callable[[int], bool]) -> Extractor:
    def get(ev: Event):
        if ev.type not in ("open", "openat", "openat2", "creat"):
            return None
        info = ev.fd
        if not isinstance(info, FdInfo):
            return UNKNOWN
        return test(info.flags)
    return get


def _evt_arg(name: str) -> Extractor:
    def get(ev: Event):
        if name in ("res", "fd") and linux.EVENT_FD.get(ev.type) == "res":
            return ev.rawres
        if name == "res" and ev.type in ("execve", "execveat"):
            return ev.rawres
        return ev.args.get(name)
    return get


def _evt_arg_index(index: str) -> Extractor:
    try:
        n = int(index)
    except ValueError:
        return _evt_arg(index)

    def get(ev: Event):
        values = list(ev.args.values())
        return values[n] if 0 <= n < len(values) else None
    return get


def _evt_args(ev: Event) -> str:
    return " ".join(f"{k}={'<NA>' if v is UNKNOWN else v}" for k, v in ev.args.items())


def _user_name(users: Dict[int, str]) -> Extractor:
    def get(ev: Event):
        uid = ev.uid
        if not isinstance(uid, int):
            return UNKNOWN
        return users.get(uid, UNKNOWN)
    return get


def _api_arg(index: str) -> Extractor:
    try:
        n = int(index)
    except ValueError:
        n = None

    def get(ev: Event):
        if ev.api is None:
            return None
        if n is not None:
            argv = ev.api["argv"]
            return argv[n] if 0 <= n < len(argv) else None
        return ev.api["args"].get(index)
    return get


class FieldTable:
    """The resolver `condition.Compiler` takes, for one rule source."""

    def __init__(self, source: str, users: Dict[int, str], env_filter) -> None:
        self.source = source
        self.users = users
        self.env_filter = frozenset(env_filter)
        self.plain: Dict[str, Extractor] = self._plain()

    def __call__(self, name: str, arg: Optional[str]) -> Extractor:
        if arg is None and name in self.plain:
            return self.plain[name]
        if name.startswith("evt.arg.") and arg is None and self.source == "syscall":
            return _evt_arg(name[len("evt.arg."):])
        if name == "evt.arg" and arg is not None and self.source == "syscall":
            return _evt_arg_index(arg)
        if name == "proc.env":
            filt = self.env_filter
            return lambda ev: _env(ev, arg, filt)
        if name.startswith("proc.a") and name[len("proc.a"):] in PROC_ATTRS:
            return _of_ancestor(PROC_ATTRS[name[len("proc.a"):]], arg)
        if name == "api.arg" and self.source == "libmon":
            if arg is None:
                raise UnsupportedField("api.arg needs [name] or [index]")
            return _api_arg(arg)
        if name.startswith(("k8s.", "container.", "k8smeta.")):
            return self._container(name)
        raise UnsupportedField(f"field {name}{'[' + arg + ']' if arg is not None else ''} is not supported")

    @staticmethod
    def _container(name: str) -> Extractor:
        # A VM guest is Falco's "host": no container, no pod.
        if name in ("container.id", "container.name"):
            return lambda ev: "host"
        return lambda ev: None

    def _plain(self) -> Dict[str, Extractor]:
        unknown = lambda ev: UNKNOWN  # noqa: E731
        t: Dict[str, Extractor] = {
            "evt.type": lambda ev: ev.type,
            "evt.num": lambda ev: ev.num,
            "evt.rawtime": lambda ev: int(ev.time * 1e9),
            "evt.time": lambda ev: f"{ev.time:.6f}",
            "evt.dir": lambda ev: "<",
            "evt.source": lambda ev: self.source,
            "evt.rawres": lambda ev: ev.rawres,
            "evt.res": _res,
            "evt.failed": _failed,
            "evt.hostname": lambda ev: None,

            "proc.name": lambda ev: ev.comm,
            "proc.exe": lambda ev: ev.proc.exe,
            "proc.exepath": lambda ev: ev.proc.exepath,
            "proc.args": lambda ev: ev.proc.args,
            "proc.cmdline": lambda ev: _cmdline(ev.proc),
            "proc.pid": lambda ev: ev.pid,
            "proc.vpid": lambda ev: ev.pid,
            "proc.tid": lambda ev: ev.tid,
            "thread.tid": lambda ev: ev.tid,
            "thread.vtid": lambda ev: ev.tid,
            "proc.ppid": lambda ev: ev.proc.ppid,
            "proc.pvpid": lambda ev: ev.proc.ppid,
            "proc.pname": _of_parent(PROC_ATTRS["name"]),
            "proc.pexe": _of_parent(PROC_ATTRS["exe"]),
            "proc.pexepath": _of_parent(PROC_ATTRS["exepath"]),
            "proc.pcmdline": _of_parent(_cmdline),
            "proc.pargs": _of_parent(PROC_ATTRS["args"]),
            "proc.cwd": _cwd,
            "proc.duration": _duration,
            "proc.vpgid": lambda ev: ev.proc.pgid,
            "proc.is_vpgid_leader": lambda ev: (ev.proc.pgid == ev.pid
                                                if isinstance(ev.proc.pgid, int) else UNKNOWN),
            "proc.is_exe_from_memfd": lambda ev: ev.proc.memfd,
            # Falco's overlayfs check, for container images: a guest's root
            # filesystem is not an overlay.
            "proc.is_exe_upper_layer": lambda ev: False,
            "proc.is_container_healthcheck": lambda ev: False,
            "proc.is_container_liveness_probe": lambda ev: False,
            "proc.is_container_readiness_probe": lambda ev: False,
            "proc.tty": unknown,
            "proc.sname": unknown,
            "proc.sid": unknown,
            "proc.is_exe_writable": unknown,
            "proc.exe_ino": unknown,
            "proc.exe_ino.ctime": unknown,
            "proc.exe_ino.mtime": unknown,
            "proc.loginshellid": unknown,
            "thread.cap_effective": unknown,
            "thread.cap_permitted": unknown,
            "thread.cap_inheritable": unknown,

            "user.uid": lambda ev: ev.uid,
            "user.name": _user_name(self.users),
            "user.loginuid": unknown,
            "user.loginname": unknown,
            "user.homedir": unknown,
            "user.shell": unknown,
            "group.gid": unknown,
            "group.name": unknown,
        }
        if self.source == "syscall":
            t.update({
                "evt.args": _evt_args,
                "evt.is_open_read": _open_flags(lambda f: (f & linux.O_ACCMODE) in (0, 2)),
                "evt.is_open_write": _open_flags(lambda f: (f & linux.O_ACCMODE) in (1, 2)),
                "evt.is_open_create": _open_flags(lambda f: bool(f & linux.O_CREAT)),
                "evt.is_open_exec": lambda ev: (None if ev.type not in ("open", "openat", "openat2", "creat")
                                                else UNKNOWN),
                "evt.buffer": lambda ev: ev.buffer,
                "fd.num": lambda ev: ev.fdnum,
                "fd.name": _fd(lambda i: i.name),
                "fd.nameraw": _fd(lambda i: i.nameraw),
                "fd.directory": _fd(_directory),
                "fd.filename": _fd(_filename),
                "fd.typechar": _fd(lambda i: i.typechar),
                "fd.type": _fd(lambda i: i.type),
                "fd.name_changed": _fd(_name_changed),
                "fd.sockfamily": _fd(lambda i: ("ip" if i.typechar in ("4", "6")
                                                else "unix" if i.typechar == "u" else None)),
                "fd.l4proto": _fd(lambda i: (i.l4proto if i.typechar in ("4", "6") and i.l4proto
                                             else None if i.typechar not in ("4", "6") else UNKNOWN)),
                "fd.connected": _fd(_endpoint("connected")),
                "fd.sip": _fd(_endpoint("sip")), "fd.cip": _fd(_endpoint("cip")),
                "fd.lip": _fd(_endpoint("lip")), "fd.rip": _fd(_endpoint("rip")),
                "fd.sport": _fd(_endpoint("sport")), "fd.cport": _fd(_endpoint("cport")),
                "fd.lport": _fd(_endpoint("lport")), "fd.rport": _fd(_endpoint("rport")),
                "fd.ip": _fd(_either("sip", "cip")), "fd.port": _fd(_either("sport", "cport")),
                "fd.net": _fd(_either("sip", "cip")), "fd.snet": _fd(_endpoint("sip")),
                "fd.cnet": _fd(_endpoint("cip")), "fd.lnet": _fd(_endpoint("lip")),
                "fd.rnet": _fd(_endpoint("rip")),
                # Reverse DNS of an endpoint: Falco resolves it, the trace does not.
                "fd.sip.name": _fd(lambda i: UNKNOWN if _is_socket(i) else None),
                "fd.cip.name": _fd(lambda i: UNKNOWN if _is_socket(i) else None),
                "fd.lip.name": _fd(lambda i: UNKNOWN if _is_socket(i) else None),
                "fd.rip.name": _fd(lambda i: UNKNOWN if _is_socket(i) else None),
            })
        else:
            t.update({
                "api.name": lambda ev: ev.api["name"],
                "api.lib": lambda ev: ev.api["lib"],
                "api.ret": lambda ev: ev.rawres,
                "api.from_module": lambda ev: ev.api["from_module"],
                "api.called_from": lambda ev: ev.api["called_from"],
            })
        return t


def render_output(template: str, ev: Event, table: FieldTable) -> Tuple[str, Dict[str, str]]:
    """Falco's `%field` substitution; a field that has no value is <NA>."""
    import re
    fields: Dict[str, str] = {}

    def value_of(m: "re.Match[str]") -> str:
        name, arg = m.group(1), m.group(3)
        key = name + (f"[{arg}]" if arg is not None else "")
        try:
            v = table(name, arg)(ev)
        except UnsupportedField:
            v = None
        if v is UNKNOWN or v is None:
            s = "<NA>"
        elif isinstance(v, Multi):
            s = ",".join(str(x) for x in v.values) or "<NA>"
        else:
            s = str(v)
        fields[key] = s
        return s
    text = re.sub(r"%([A-Za-z_][A-Za-z0-9_.]*[A-Za-z0-9_])(\[([^\]]*)\])?", value_of, template)
    return text, fields