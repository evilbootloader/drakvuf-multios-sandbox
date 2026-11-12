"""The kernel's side of an API call, for the API call to borrow from.

Since 2026-11-11 a call is one of two things (behaviour.py): an **api** call,
from apimon or libmon's user-mode hook, which is what CAPE's signatures
read; or a **syscall** call, from the syscall plugin, regmon, filetracer and
procmon, kept apart for signatures of their own. The two describe the same
events from either side of the kernel boundary, and each knows what the
other does not: apimon has the API's name and arguments as passed, the
kernel side has what a handle is open on, the data a registry value was set
to, the process that was created.

`trace_split._CallMerger` attaches to each API record the kernel-side
records of the same call (`Kernel`), and `behaviour.ParseProcessLog` folds
them in. This module is what both need to know:

* `KERNEL_SERVICES` / `LIBC_SERVICES` -- which system services an API is
  made of, so the merger knows which kernel records to look for. An `Nt*` /
  `Zw*` stub is its own service and needs no entry. **Written by hand**;
  add a line when an API should take values from a service.
* the registry helpers, which turn the kernel's key paths and value bytes
  into what capemon logs for the same call (`FullName`, `Buffer`).

Stdlib only, no relative imports beyond `api_tables`: trace_split loads it
for every record of a trace.
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

from .api_tables import canonical

# Win32 API, by `api_tables.canonical` name (no trailing A/W) -> the system
# services it issues that DRAKVUF's kernel-side plugins report something
# useful about: regmon (key, value name, data), filetracer (the file a
# handle is open on), procmon (the process created, opened or ended).
KERNEL_SERVICES = {
    # -- registry: regmon -----------------------------------------------------
    "RegOpenKey": ("NtOpenKey", "NtOpenKeyEx"),
    "RegOpenKeyEx": ("NtOpenKey", "NtOpenKeyEx"),
    "RegOpenKeyTransacted": ("NtOpenKeyTransacted", "NtOpenKeyTransactedEx"),
    "RegCreateKey": ("NtCreateKey",),
    "RegCreateKeyEx": ("NtCreateKey",),
    "RegCreateKeyTransacted": ("NtCreateKeyTransacted",),
    "RegSetValue": ("NtSetValueKey",),
    "RegSetValueEx": ("NtSetValueKey",),
    "RegSetKeyValue": ("NtSetValueKey",),
    "SHSetValue": ("NtSetValueKey",),
    "RegQueryValue": ("NtQueryValueKey",),
    "RegQueryValueEx": ("NtQueryValueKey",),
    "RegGetValue": ("NtQueryValueKey",),
    "SHGetValue": ("NtQueryValueKey",),
    "SHRegGetValue": ("NtQueryValueKey",),
    "RegQueryMultipleValues": ("NtQueryMultipleValueKey", "NtQueryValueKey"),
    "RegDeleteValue": ("NtDeleteValueKey",),
    "RegDeleteKeyValue": ("NtDeleteValueKey",),
    "SHDeleteValue": ("NtDeleteValueKey",),
    "RegDeleteKey": ("NtDeleteKey",),
    "RegDeleteKeyEx": ("NtDeleteKey",),
    "RegDeleteTree": ("NtDeleteKey",),
    "SHDeleteKey": ("NtDeleteKey",),
    "RegEnumValue": ("NtEnumerateValueKey",),
    "RegEnumKey": ("NtEnumerateKey",),
    "RegEnumKeyEx": ("NtEnumerateKey",),
    "RegQueryInfoKey": ("NtQueryKey",),
    # -- files: filetracer ----------------------------------------------------
    "CreateFile": ("NtCreateFile", "NtOpenFile"),
    "CreateFile2": ("NtCreateFile", "NtOpenFile"),
    "CreateFileTransacted": ("NtCreateFile", "NtOpenFile"),
    "CreateDirectory": ("NtCreateFile",),
    "CreateDirectoryEx": ("NtCreateFile",),
    "ReadFile": ("NtReadFile",),
    "ReadFileEx": ("NtReadFile",),
    "WriteFile": ("NtWriteFile",),
    "WriteFileEx": ("NtWriteFile",),
    "DeleteFile": ("NtSetInformationFile", "NtDeleteFile"),
    "RemoveDirectory": ("NtSetInformationFile",),
    "SetFileAttributes": ("NtSetInformationFile",),
    "SetFileTime": ("NtSetInformationFile",),
    "SetFileInformationByHandle": ("NtSetInformationFile",),
    "SetEndOfFile": ("NtSetInformationFile",),
    # -- processes: procmon ---------------------------------------------------
    "CreateProcessInternal": ("NtCreateUserProcess",),
    "CreateProcess": ("NtCreateUserProcess",),
    "CreateProcessAsUser": ("NtCreateUserProcess",),
    "CreateProcessWithLogon": ("NtCreateUserProcess",),
    "CreateProcessWithToken": ("NtCreateUserProcess",),
    "RtlCreateUserProcess": ("NtCreateUserProcess",),
    "WinExec": ("NtCreateUserProcess",),
    "ShellExecuteEx": ("NtCreateUserProcess",),
    "OpenProcess": ("NtOpenProcess",),
    "TerminateProcess": ("NtTerminateProcess",),
    "OpenThread": ("NtOpenThread",),
}

# glibc function -> the Linux syscalls it issues that filetracer resolves a
# path for (it shares the syscall's EventUID, and the merger has already
# folded it into the syscall record).
LIBC_SERVICES = {
    "open": ("openat", "open"), "open64": ("openat", "open"),
    "openat": ("openat",), "openat64": ("openat",), "creat": ("creat", "openat"),
    "fopen": ("openat", "open"), "fopen64": ("openat", "open"), "freopen": ("openat", "open"),
    "read": ("read",), "pread": ("pread64",), "pread64": ("pread64",),
    "write": ("write",), "pwrite": ("pwrite64",), "pwrite64": ("pwrite64",),
    "unlink": ("unlink", "unlinkat"), "unlinkat": ("unlinkat",),
    "remove": ("unlink", "unlinkat", "rmdir"), "rmdir": ("rmdir", "unlinkat"),
    "rename": ("rename", "renameat", "renameat2"),
    "mkdir": ("mkdir", "mkdirat"), "chmod": ("chmod", "fchmodat"),
    "fchmodat": ("fchmodat",), "chown": ("chown", "fchownat"), "fchownat": ("fchownat",),
    "ftruncate": ("ftruncate",), "readlink": ("readlink", "readlinkat"),
}

# The keys DRAKVUF puts what an OBJECT_ATTRIBUTES names under, in apimon's
# appended arguments and the syscall plugin's records alike: capemon's name
# for it, by service (drakvuf src/plugins/helpers/object_attributes.h). `Key`
# is a key's full NT path, as regmon's; `ObjectName` is any other object's
# name as the caller gave it, which capemon logs in place of ObjectAttributes.
OBJECT_NAME_KEYS = ("FileName", "Key", "MutexName", "EventName", "PipeName", "MailslotName",
                    "ObjectName", "TargetKeyName", "SourceFileName", "NewFileName",
                    "OldFileName")

# The key services whose ObjectAttributes name the key they create or open,
# which capemon logs in place of the argument.
KEY_OPEN_SERVICES = frozenset(("NtCreateKey", "NtCreateKeyTransacted", "NtOpenKey",
                               "NtOpenKeyEx", "NtOpenKeyTransacted", "NtOpenKeyTransactedEx"))

# Services whose kernel record names a registry VALUE: an API call is only
# given one whose value name is its own.
VALUE_SERVICES = frozenset(("NtSetValueKey", "NtQueryValueKey", "NtDeleteValueKey",
                            "NtQueryMultipleValueKey"))


def kernel_services(api: str, linux: bool) -> Tuple[tuple, bool]:
    """(the services whose records belong to a call of `api`, whether `api`
    is the service's own stub). A stub's record directly follows its
    syscall on the thread; a wrapper's follows it at some distance."""
    if not api:
        return (), False
    if linux:
        return LIBC_SERVICES.get(api, (api,)), False
    name = canonical(api)
    if name.startswith("Nt") and len(name) > 2 and name[2].isupper():
        return (name,), True
    return KERNEL_SERVICES.get(name, ()), False


# -- registry -------------------------------------------------------------------

# The predefined keys an application passes instead of a handle (winreg.h).
# They are not handles, so nothing kernel-side resolves them; capemon names
# them as below (misc.c, get_full_key_pathW).
PREDEFINED_KEYS = {
    0x80000000: "HKEY_CLASSES_ROOT",
    0x80000001: "HKEY_CURRENT_USER",
    0x80000002: "HKEY_LOCAL_MACHINE",
    0x80000003: "HKEY_USERS",
    0x80000004: "HKEY_PERFORMANCE_DATA",
    0x80000005: "HKEY_CURRENT_CONFIG",
    0x80000006: "HKEY_DYN_DATA",
    0x80000050: "HKEY_PERFORMANCE_TEXT",
    0x80000060: "HKEY_PERFORMANCE_NLSTEXT",
}

# `\REGISTRY\USER\<the interactive user's SID>[_Classes]`. capemon compares
# with the SID of the process it is in; a trace has no such thing to ask, and
# an analysis guest has one interactive account, so any account SID (S-1-5-21)
# is read as that user. Service accounts (S-1-5-18/19/20, .DEFAULT) stay
# under HKEY_USERS, as they do in capemon.
_USER_HIVE = re.compile(r"\\REGISTRY\\USER\\S-1-5-21-[0-9-]+(_Classes)?(?=\\|\Z)", re.I)


def predefined_key(handle) -> Optional[str]:
    """`HKEY_LOCAL_MACHINE` for `0x80000002` (also sign-extended to 64 bits)."""
    try:
        value = int(str(handle), 16) & 0xFFFFFFFF
    except ValueError:
        return None
    return PREDEFINED_KEYS.get(value)


def cape_key_path(path: Optional[str]) -> str:
    """An NT registry path as capemon reports it (misc.c, `normal:` in
    get_key_path): `\\REGISTRY\\MACHINE` is `HKEY_LOCAL_MACHINE`, the user's
    hive `HKEY_CURRENT_USER`, its classes hive
    `HKEY_CURRENT_USER\\Software\\Classes`, the rest of `\\REGISTRY\\USER`
    `HKEY_USERS`. Anything else -- already translated, or relative -- is
    returned as it is."""
    if not path:
        return ""
    m = _USER_HIVE.match(path)
    if m:
        root = "HKEY_CURRENT_USER\\Software\\Classes" if m.group(1) else "HKEY_CURRENT_USER"
        return root + path[m.end():]
    upper = path[:17].upper()
    if upper == "\\REGISTRY\\MACHINE" and path[17:18] in ("", "\\"):
        return "HKEY_LOCAL_MACHINE" + path[17:]
    if upper[:14] == "\\REGISTRY\\USER" and path[14:15] in ("", "\\"):
        return "HKEY_USERS" + path[14:]
    return path


def _join(base: str, name: Optional[str]) -> str:
    if not name:
        return base
    name = name.lstrip("\\")
    if not base:
        return name
    return base.rstrip("\\") + "\\" + name


def registry_full_name(key: Optional[str] = None, handle_key: Optional[str] = None,
                       root=None, subkey: Optional[str] = None,
                       value_name: Optional[str] = None, is_value: bool = False) -> str:
    """capemon's `FullName` for a registry call: the key's path, and for a
    call on a value its name after it (`(Default)` for the unnamed one).

    From the best of what the call has, in this order:

    * `key`, the path the KERNEL resolved for this very call (regmon). It is
      the key operated on, sub-key included, so nothing is appended to it;
    * `handle_key`, the path apimon resolved the API's handle to, plus the
      sub-key the API names;
    * `root`, a predefined key (HKEY_LOCAL_MACHINE...) plus the sub-key;
    * the sub-key alone -- a true part of the full name, where no handle
      could be resolved. capemon logs an empty name there; a partial one
      still matches what an unanchored pattern looks for.
    """
    if key:
        base = key
    elif handle_key:
        base = _join(handle_key, subkey)
    else:
        base = _join(predefined_key(root) or "", subkey)
    base = cape_key_path(base)
    if is_value:
        return _join(base, value_name or "(Default)")
    return base


REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_QWORD = 4, 5, 11
_HEX_BYTES = re.compile(r"\A[0-9a-fA-F]{2}(?: [0-9a-fA-F]{2})*\Z")


def registry_data(value, reg_type) -> str:
    """regmon's rendering of a value's data, as capemon logs `Buffer`.

    regmon prints strings as they are and everything else as hex bytes
    (`0d 00 00 00`, regmon.cpp::get_data_as_string), without the type; the
    API call has the type. capemon logs a DWORD or QWORD as the number --
    signatures compare it as text, `buf == "1"` -- so those are decoded
    here, in decimal as capemon prints them. Everything else is regmon's
    text."""
    if value is None:
        return ""
    text = str(value)
    try:
        kind = int(str(reg_type), 16)
    except ValueError:
        return text
    if kind in (REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_QWORD) and _HEX_BYTES.match(text):
        raw = bytes.fromhex(text.replace(" ", ""))
        if len(raw) in (4, 8):
            return str(int.from_bytes(raw, "big" if kind == REG_DWORD_BIG_ENDIAN else "little"))
    return text