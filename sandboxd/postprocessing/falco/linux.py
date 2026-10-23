"""x86-64 Linux constants, and how DRAKVUF's syscall arguments map to Falco's.

Falco renders flag arguments symbolically (`O_WRONLY|O_CREAT|O_TRUNC`,
`S_IRUSR|S_ISUID`, `PTRACE_ATTACH`) and its rules test them with `contains`,
so the numbers DRAKVUF prints are rendered the same way here. The argument
names on the left are Falco's exit-event parameters; on the right, the names
DRAKVUF's syscalls plugin prints (`src/plugins/syscalls/linux.h`).
"""
from __future__ import annotations

import errno
from typing import Dict, List, Optional, Tuple

AT_FDCWD = -100

O_ACCMODE = 0o3
OPEN_ACCESS = {0: "O_RDONLY", 1: "O_WRONLY", 2: "O_RDWR"}
OPEN_FLAGS = (
    (0o100, "O_CREAT"), (0o200, "O_EXCL"), (0o400, "O_NOCTTY"),
    (0o1000, "O_TRUNC"), (0o2000, "O_APPEND"), (0o4000, "O_NONBLOCK"),
    (0o4010000, "O_SYNC"), (0o10000, "O_DSYNC"), (0o20000, "O_ASYNC"),
    (0o40000, "O_DIRECT"), (0o100000, "O_LARGEFILE"),
    (0o20200000, "O_TMPFILE"), (0o200000, "O_DIRECTORY"),
    (0o400000, "O_NOFOLLOW"), (0o1000000, "O_NOATIME"),
    (0o2000000, "O_CLOEXEC"), (0o10000000, "O_PATH"),
)
O_CREAT = 0o100
O_DIRECTORY = 0o200000
O_CLOEXEC = 0o2000000

MODE_BITS = (
    (0o4000, "S_ISUID"), (0o2000, "S_ISGID"), (0o1000, "S_ISVTX"),
    (0o400, "S_IRUSR"), (0o200, "S_IWUSR"), (0o100, "S_IXUSR"),
    (0o40, "S_IRGRP"), (0o20, "S_IWGRP"), (0o10, "S_IXGRP"),
    (0o4, "S_IROTH"), (0o2, "S_IWOTH"), (0o1, "S_IXOTH"),
)

PTRACE_REQUESTS = {
    0: "PTRACE_TRACEME", 1: "PTRACE_PEEKTEXT", 2: "PTRACE_PEEKDATA",
    3: "PTRACE_PEEKUSR", 4: "PTRACE_POKETEXT", 5: "PTRACE_POKEDATA",
    6: "PTRACE_POKEUSR", 7: "PTRACE_CONT", 8: "PTRACE_KILL",
    9: "PTRACE_SINGLESTEP", 12: "PTRACE_GETREGS", 13: "PTRACE_SETREGS",
    14: "PTRACE_GETFPREGS", 15: "PTRACE_SETFPREGS", 16: "PTRACE_ATTACH",
    17: "PTRACE_DETACH", 18: "PTRACE_GETFPXREGS", 19: "PTRACE_SETFPXREGS",
    24: "PTRACE_SYSCALL", 0x4200: "PTRACE_SETOPTIONS",
    0x4201: "PTRACE_GETEVENTMSG", 0x4202: "PTRACE_GETSIGINFO",
    0x4203: "PTRACE_SETSIGINFO", 0x4204: "PTRACE_GETREGSET",
    0x4205: "PTRACE_SETREGSET", 0x4206: "PTRACE_SEIZE",
    0x4207: "PTRACE_INTERRUPT", 0x4208: "PTRACE_LISTEN",
    0x4209: "PTRACE_PEEKSIGINFO",
}

ADDRESS_FAMILIES = {
    0: "AF_UNSPEC", 1: "AF_UNIX", 2: "AF_INET", 3: "AF_AX25", 4: "AF_IPX",
    5: "AF_APPLETALK", 9: "AF_X25", 10: "AF_INET6", 15: "AF_KEY",
    16: "AF_NETLINK", 17: "AF_PACKET", 38: "AF_ALG", 40: "AF_VSOCK",
    44: "AF_XDP",
}
AF_UNIX, AF_INET, AF_INET6, AF_NETLINK, AF_PACKET = 1, 2, 10, 16, 17

SOCK_TYPES = {1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW", 4: "SOCK_RDM",
              5: "SOCK_SEQPACKET", 10: "SOCK_PACKET"}
SOCK_NONBLOCK = 0o4000
SOCK_CLOEXEC = 0o2000000

BPF_COMMANDS = {
    0: "BPF_MAP_CREATE", 1: "BPF_MAP_LOOKUP_ELEM", 2: "BPF_MAP_UPDATE_ELEM",
    3: "BPF_MAP_DELETE_ELEM", 4: "BPF_MAP_GET_NEXT_KEY", 5: "BPF_PROG_LOAD",
    6: "BPF_OBJ_PIN", 7: "BPF_OBJ_GET", 8: "BPF_PROG_ATTACH",
    9: "BPF_PROG_DETACH", 10: "BPF_PROG_TEST_RUN",
}

NAMESPACE_FLAGS = (
    (0x00000080, "CLONE_NEWTIME"), (0x00020000, "CLONE_NEWNS"),
    (0x02000000, "CLONE_NEWCGROUP"), (0x04000000, "CLONE_NEWUTS"),
    (0x08000000, "CLONE_NEWIPC"), (0x10000000, "CLONE_NEWUSER"),
    (0x20000000, "CLONE_NEWPID"), (0x40000000, "CLONE_NEWNET"),
)

F_DUPFD, F_DUPFD_CLOEXEC = 0, 1030


def signed(value: int, bits: int) -> int:
    top = 1 << (bits - 1)
    return value - (1 << bits) if value & top else value


def parse_int(raw: object, bits: int = 64) -> Optional[int]:
    """DRAKVUF prints integers as hex strings; filetracer, as decimal ones."""
    if isinstance(raw, bool):
        return int(raw)
    if isinstance(raw, int):
        return raw
    if not isinstance(raw, str) or not raw:
        return None
    try:
        v = int(raw, 0) if raw.startswith(("0x", "0X")) else int(raw, 10)
    except ValueError:
        return None
    if v < 0:
        return v
    return signed(v & ((1 << bits) - 1), bits)


def render_open_flags(flags: int) -> str:
    parts = [OPEN_ACCESS.get(flags & O_ACCMODE, "O_RDONLY")]
    rest = flags & ~O_ACCMODE
    for bit, name in OPEN_FLAGS:
        if (rest & bit) == bit:
            parts.append(name)
            rest &= ~bit
    return "|".join(parts)


def render_mode(mode: int) -> str:
    return "|".join(name for bit, name in MODE_BITS if mode & bit) or "0"


def render_ns_flags(flags: int) -> str:
    return "|".join(name for bit, name in NAMESPACE_FLAGS if flags & bit) or str(flags)


def render_socket_type(t: int) -> str:
    parts = [SOCK_TYPES.get(t & 0xF, str(t & 0xF))]
    if t & SOCK_NONBLOCK:
        parts.append("SOCK_NONBLOCK")
    if t & SOCK_CLOEXEC:
        parts.append("SOCK_CLOEXEC")
    return "|".join(parts)


def errno_name(rawres: int) -> str:
    if rawres >= 0:
        return "SUCCESS"
    return errno.errorcode.get(-rawres, f"E{-rawres}")


# (Falco parameter, DRAKVUF argument, kind). Kinds: path, fd, int, oflags,
# mode, ptrace, af, socktype, uid, bpfcmd, nsflags.
ArgSpec = Tuple[str, str, str]
EVENT_ARGS: Dict[str, List[ArgSpec]] = {
    "open": [("name", "pathname", "path"), ("flags", "flags", "oflags"), ("mode", "mode", "mode")],
    "openat": [("dirfd", "dirfd", "fd"), ("name", "pathname", "path"),
               ("flags", "flags", "oflags"), ("mode", "mode", "mode")],
    "creat": [("name", "pathname", "path"), ("mode", "mode", "mode")],
    "close": [("fd", "fd", "fd")],
    "chmod": [("filename", "pathname", "path"), ("mode", "mode", "mode")],
    "fchmod": [("fd", "fd", "fd"), ("mode", "mode", "mode")],
    "fchmodat": [("dirfd", "dirfd", "fd"), ("filename", "pathname", "path"), ("mode", "mode", "mode")],
    "rename": [("oldpath", "oldpath", "path"), ("newpath", "newpath", "path")],
    "renameat": [("olddirfd", "olddirfd", "fd"), ("oldpath", "oldpath", "path"),
                 ("newdirfd", "newdirfd", "fd"), ("newpath", "newpath", "path")],
    "renameat2": [("olddirfd", "olddirfd", "fd"), ("oldpath", "oldpath", "path"),
                  ("newdirfd", "newdirfd", "fd"), ("newpath", "newpath", "path"),
                  ("flags", "flags", "int")],
    "unlink": [("path", "pathname", "path")],
    "unlinkat": [("dirfd", "dirfd", "fd"), ("name", "pathname", "path"), ("flags", "flags", "int")],
    "rmdir": [("path", "pathname", "path")],
    "mkdir": [("path", "pathname", "path"), ("mode", "mode", "mode")],
    "mkdirat": [("dirfd", "dirfd", "fd"), ("path", "pathname", "path"), ("mode", "mode", "mode")],
    "symlink": [("target", "target", "path"), ("linkpath", "linkpath", "path")],
    "symlinkat": [("target", "target", "path"), ("linkdirfd", "newdirfd", "fd"),
                  ("linkpath", "linkpath", "path")],
    "link": [("oldpath", "oldpath", "path"), ("newpath", "newpath", "path")],
    "linkat": [("olddir", "olddirfd", "fd"), ("oldpath", "oldpath", "path"),
               ("newdir", "newdirfd", "fd"), ("newpath", "newpath", "path"), ("flags", "flags", "int")],
    "chdir": [("path", "path", "path")],
    "fchdir": [("fd", "fd", "fd")],
    "fcntl": [("fd", "fd", "fd"), ("cmd", "cmd", "int")],
    "dup": [("oldfd", "oldfd", "fd")],
    "dup2": [("oldfd", "oldfd", "fd"), ("newfd", "newfd", "fd")],
    "dup3": [("oldfd", "oldfd", "fd"), ("newfd", "newfd", "fd"), ("flags", "flags", "int")],
    "ptrace": [("request", "request", "ptrace"), ("pid", "pid", "int")],
    "setuid": [("uid", "uid", "uid")],
    "setns": [("fd", "fd", "fd"), ("nstype", "nstype", "nsflags")],
    "unshare": [("flags", "flags", "nsflags")],
    "bpf": [("cmd", "cmd", "bpfcmd")],
    "init_module": [("len", "len", "int")],
    "finit_module": [("fd", "fd", "fd"), ("flags", "flags", "int")],
    "userfaultfd": [("flags", "flags", "int")],
    "memfd_create": [("name", "name", "path"), ("flags", "flags", "int")],
    "socket": [("domain", "domain", "af"), ("type", "type", "socktype"), ("proto", "protocol", "int")],
    "connect": [("fd", "sockfd", "fd")],
    "bind": [("fd", "sockfd", "fd")],
    "listen": [("fd", "sockfd", "fd"), ("backlog", "backlog", "int")],
    "accept": [("fd", "sockfd", "fd")],
    "accept4": [("fd", "sockfd", "fd"), ("flags", "flags", "int")],
    "sendto": [("fd", "sockfd", "fd"), ("size", "len", "int")],
    "sendmsg": [("fd", "sockfd", "fd")],
    "recvfrom": [("fd", "sockfd", "fd"), ("size", "len", "int")],
    "recvmsg": [("fd", "sockfd", "fd")],
}

# Which file descriptor an event's `fd.*` fields describe: the one it
# returned ("res"), or the one named by an argument.
EVENT_FD = {
    "open": "res", "openat": "res", "creat": "res", "memfd_create": "res",
    "socket": "res", "accept": "res", "accept4": "res",
    "connect": "fd", "bind": "fd", "listen": "fd", "sendto": "fd",
    "sendmsg": "fd", "recvfrom": "fd", "recvmsg": "fd", "close": "fd",
    "fchmod": "fd", "setns": "fd", "finit_module": "fd", "fchdir": "fd",
    "dup": "oldfd", "dup2": "oldfd", "dup3": "oldfd",
}

# The path filetracer printed for the same EventUID, which wins over the
# syscall plugin's: the two read the string differently, and the syscall
# plugin's reading is sometimes garbage (renameat2's `newpath` came out "H=" in
# the 2026-10-23 benchmark trace where filetracer had `.//dpkg.status.0`).
FILETRACER_PATH_ARG = {
    "open": "pathname", "openat": "pathname", "creat": "pathname",
    "chmod": "pathname", "fchmodat": "pathname", "unlink": "pathname",
    "unlinkat": "pathname", "rmdir": "pathname", "mkdir": "pathname",
    "mkdirat": "pathname", "rename": "oldpath", "renameat": "oldpath",
    "renameat2": "oldpath", "link": "oldpath", "linkat": "oldpath",
}

# Events that change the state the fields read (the fd table, the working
# directory) and are read even when no rule asks for them.
STATE_EVENTS = frozenset({
    "open", "openat", "creat", "close", "dup", "dup2", "dup3", "fcntl",
    "chdir", "fchdir", "socket", "accept", "accept4", "memfd_create",
    "execve", "execveat",
})

# The libc function libmon reports for a syscall, by syscall: without sysret,
# a libmon record of the same thread and path is where the result comes from.
# glibc's open() and creat() are openat underneath; the rest share the name.
LIBC_EQUIVALENTS = {
    "openat": ("open", "openat", "open64", "creat"),
    "open": ("open", "open64"),
    "creat": ("creat",),
    "unlink": ("unlink", "remove"), "unlinkat": ("unlinkat", "unlink", "remove"),
    "rename": ("rename",), "renameat": ("rename",), "renameat2": ("rename",),
    "chmod": ("chmod",), "fchmodat": ("fchmodat", "chmod"), "fchmod": ("fchmod",),
    "mkdir": ("mkdir",), "rmdir": ("rmdir", "remove"),
    "chdir": ("chdir",), "fchdir": ("fchdir",),
    "socket": ("socket",), "connect": ("connect",), "bind": ("bind",),
    "listen": ("listen",), "accept": ("accept",), "accept4": ("accept",),
    "dup2": ("dup2",), "ptrace": ("ptrace",), "memfd_create": ("memfd_create",),
}

# uid -> name for a Debian or Ubuntu guest: base-passwd allocates 0-99 and
# 65534 statically, so they are the same on every such install. Everything
# from 100 up is allocated at package install and differs per image.
DEBIAN_BASE_USERS = {
    0: "root", 1: "daemon", 2: "bin", 3: "sys", 4: "sync", 5: "games",
    6: "man", 7: "lp", 8: "mail", 9: "news", 10: "uucp", 13: "proxy",
    33: "www-data", 34: "backup", 38: "list", 39: "irc", 41: "gnats",
    65534: "nobody",
}