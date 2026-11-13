"""Where a syscall was made from (cape_plugin/syscall_origin.py), the call
behaviour.py logs beside one made where the system makes none, and the
community signatures that read it (modules/signatures/all/evasive_syscalls.py).

The records are shaped as DRAKVUF's syscalls plugin prints them
(src/plugins/syscalls/win.cpp and linux.cpp, print_syscall); nothing here has
been checked against a trace from Dom0 yet.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd.guests import TargetOs  # noqa: E402
from sandboxd.postprocessing.plugins.cape_plugin import cape_compat  # noqa: E402
from sandboxd.postprocessing.plugins.cape_plugin.syscall_origin import classify  # noqa: E402
from sandboxd.postprocessing.plugins.plugin_base import (  # noqa: E402
    CapeConfigSection, PostprocessContext, PostprocessingConfig,
)
from sandboxd.tests.test_cape_split import BASE, cape_analysis, inject, processes, rec, write_trace  # noqa: E402

NTDLL = "\\Windows\\System32\\ntdll.dll"
WIN32U = "\\Windows\\System32\\win32u.dll"
KERNELBASE = "\\Windows\\System32\\KernelBase.dll"
WOW64 = "\\Windows\\System32\\wow64.dll"
WOW64CPU = "\\Windows\\System32\\wow64cpu.dll"
NTDLL32 = "\\Windows\\SysWOW64\\ntdll.dll"
KERNELBASE32 = "\\Windows\\SysWOW64\\KernelBase.dll"
SAMPLE = "\\Users\\user\\Desktop\\sample.exe"

STUB = "0x7ffd1a0c1014"          # after `syscall` in ntdll's stub
STUB32 = "0x77d42b3c"            # after `call edx` in the 32-bit ntdll's stub
IN_SAMPLE = "0x7ff612341234"
IN_SAMPLE32 = "0x401234"
IN_KERNELBASE = "0x7ffd18a01234"


def syscall(**fields) -> dict:
    """A user-mode syscall record; `fields` its frames."""
    return {"Plugin": "syscall", "Method": "NtAllocateVirtualMemory", "Module": "nt",
            "Syscall": 24, "PreviousMode": "User", **fields}


ORDINARY = dict(Caller=STUB, FromModule=NTDLL, ParentCaller=IN_KERNELBASE, FromParentModule=KERNELBASE)


@pytest.mark.parametrize("fields", [
    pytest.param(ORDINARY, id="kernelbase calls ntdll's stub"),
    pytest.param(dict(Caller=STUB, FromModule=WIN32U, ParentCaller=IN_KERNELBASE,
                      FromParentModule="\\Windows\\System32\\user32.dll"), id="win32u's stub"),
    pytest.param(dict(Caller=STUB, FromModule="\\WINDOWS\\SYSTEM32\\NTDLL.DLL"), id="any case"),
    # Programs call ntdll's exports themselves, from their image or JIT code
    pytest.param(dict(ORDINARY, ParentCaller=IN_SAMPLE, FromParentModule=SAMPLE), id="the image calls the stub"),
    pytest.param(dict(ORDINARY, ParentCaller=IN_SAMPLE, FromParentModule=""), id="JIT code calls the stub"),
    pytest.param(dict(ORDINARY, PreviousMode="Kernel", FromModule="\\SystemRoot\\x.sys"), id="from a driver"),
    pytest.param(dict(Caller=IN_SAMPLE, ParentCaller=IN_SAMPLE), id="frame 0 not looked up"),
    # WoW64: the 32-bit call WoW64 made it for
    pytest.param(dict(Bitness=32, Caller=STUB32, FromModule=NTDLL32, ParentCaller=IN_SAMPLE32,
                      FromParentModule=KERNELBASE32), id="WoW64, 32-bit kernelbase calls ntdll"),
    # WoW64's own 64-bit code, with no 32-bit call to show
    pytest.param(dict(Bitness=64, Caller=STUB, FromModule=NTDLL, ParentCaller=IN_KERNELBASE,
                      FromParentModule=WOW64), id="WoW64's own 64-bit code"),
    pytest.param(dict(Bitness=64, Caller="0x77c51234", FromModule=WOW64CPU, ParentCaller=IN_SAMPLE32,
                      FromParentModule=SAMPLE), id="a wow64cpu turbo thunk"),
    # From the benign SteamSetup job (2026-11-12): a thread's first win32k call, whose stub
    # DRAKVUF compared with a stale KTHREAD.SystemCallNumber
    pytest.param(dict(Caller="0x7ffa51f870f4", FromModule=WIN32U, ParentCaller="0x7ffa51abd97c",
                      FromParentModule="\\Windows\\System32\\gdi32full.dll", Module="win32k", Syscall=738,
                      StubSyscall="0x12e2"), id="the stub of the service dispatched, win32k"),
    pytest.param(dict(ORDINARY, StubSyscall="0x18"), id="the stub of the service dispatched, nt"),
    # and the 32-bit kernel32's and KernelBase's own thunks, for the CSR calls of a process creation
    pytest.param(dict(Bitness=32, Caller="0x7563dd6c", FromModule="\\Windows\\SysWOW64\\kernel32.dll",
                      ParentCaller="0x75641eec", FromParentModule="\\Windows\\SysWOW64\\kernel32.dll"),
                 id="WoW64, kernel32's NtWow64Csr thunk"),
    pytest.param(dict(Bitness=32, Caller="0x76af1d9c", FromModule=KERNELBASE32, ParentCaller="0x76ae9ad7",
                      FromParentModule=KERNELBASE32), id="WoW64, KernelBase's NtWow64Csr thunk"),
])
def test_windows_own_syscalls_are_not_reported(fields):
    assert classify(syscall(**fields)) is None


@pytest.mark.parametrize("fields, technique, caller", [
    pytest.param(dict(Caller=IN_SAMPLE, FromModule=SAMPLE, ParentCaller="0x7ff612340100",
                      FromParentModule=SAMPLE), "direct", IN_SAMPLE, id="Hell's Gate, in the image"),
    pytest.param(dict(Caller="0x1f0010", FromModule="", ParentCaller="0x1f0400", FromParentModule=""),
                 "direct", "0x1f0010", id="Hell's Gate, in shellcode"),
    pytest.param(dict(ORDINARY, FromModuleCopy="0x1e0000"), "direct", STUB, id="a copy of ntdll"),
    pytest.param(dict(ORDINARY, FromModule="\\Windows\\System32\\Tasks\\ntdll.dll"), "direct", STUB,
                 id="a System32 subdirectory"),
    pytest.param(dict(ORDINARY, ParentCaller=IN_SAMPLE, FromParentModule=SAMPLE,
                      ParentCallTarget="0x7ff612342000", ParentCallTargetModule=SAMPLE),
                 "indirect", IN_SAMPLE, id="HellsHall, a stub of its own"),
    pytest.param(dict(ORDINARY, ParentCaller=IN_SAMPLE, FromParentModule=SAMPLE, StubSyscall="0x50"),
                 "indirect", IN_SAMPLE, id="another service's stub"),
    pytest.param(dict(ORDINARY, ParentCaller=IN_SAMPLE, FromParentModule=SAMPLE, Syscall=738,
                      StubSyscall="0x12e2"), "indirect", IN_SAMPLE, id="a win32k stub for an nt service"),
    pytest.param(dict(Caller="0x16954934a8c", FromModule="(null)", ParentCaller="0x16954934000",
                      FromParentModule="(null)"), "direct", "0x16954934a8c", id="unbacked, as 9722578 printed it"),
    pytest.param(dict(Bitness=32, Caller=IN_SAMPLE32, FromModule=SAMPLE, ParentCaller="0x401300",
                      FromParentModule=SAMPLE), "wow64_direct", IN_SAMPLE32, id="call fs:[0C0h]"),
    pytest.param(dict(Bitness=32, Caller=STUB32, FromModule=NTDLL32, ParentCaller=IN_SAMPLE32,
                      FromParentModule=SAMPLE, ParentCallTarget="0x77d42b35",
                      ParentCallTargetModule=NTDLL32), "wow64_indirect", IN_SAMPLE32, id="into the 32-bit stub"),
    pytest.param(dict(Bitness=64, Caller=IN_SAMPLE32, FromModule=SAMPLE, ParentCaller="0x401300",
                      FromParentModule=SAMPLE), "heavens_gate", IN_SAMPLE32, id="64-bit syscall"),
    pytest.param(dict(Bitness=64, Caller=STUB, FromModule=NTDLL, ParentCaller=IN_SAMPLE32,
                      FromParentModule=""), "heavens_gate", IN_SAMPLE32, id="64-bit ntdll from shellcode"),
    pytest.param(dict(Bitness=64, Caller=STUB, FromModule=NTDLL, ParentCaller=IN_KERNELBASE,
                      FromParentModule=WOW64, FromParentModuleCopy="0x60000000"), "heavens_gate",
                 IN_KERNELBASE, id="a copy of wow64.dll"),
])
def test_syscalls_made_elsewhere_are_reported_with_the_samples_code(fields, technique, caller):
    origin = classify(syscall(**fields))
    assert (origin.technique, origin.caller) == (technique, caller)
    assert origin.address == fields["Caller"] and origin.evidence


# --- the call behaviour.py logs beside one -----------------------------------------------

DIRECT = dict(Caller=IN_SAMPLE, FromModule=SAMPLE, ParentCaller="0x7ff612340100", FromParentModule=SAMPLE)


def direct_trace():
    return (*BASE,
            rec("syscall", 0x10, 100, method="NtAllocateVirtualMemory", Module="nt", Syscall=24,
                PreviousMode="User", **DIRECT),
            rec("syscall", 0x11, 100, method="NtClose", Module="nt", Syscall=15, PreviousMode="User",
                **ORDINARY))


def test_a_syscall_made_elsewhere_is_followed_by_capemons_call_for_it(tmp_path):
    [p] = processes(tmp_path, *direct_trace())
    first, second = list(p["calls"]), list(p["calls"])
    assert [(c.get("syscall"), c.get("api")) for c in first] == [
        ("NtAllocateVirtualMemory", None), (None, "syscall"), ("NtClose", None)]
    # The same twice: iterating again starts with nothing queued
    assert [c.get("api") for c in second] == [c.get("api") for c in first]
    # The syscall's own frames, and no frame among its arguments
    assert first[0]["caller"] == IN_SAMPLE and first[0]["module"] == SAMPLE
    assert not {"Caller", "ParentCaller", "FromModule"} & {a["name"] for a in first[0]["arguments"]}
    origin = first[1]
    assert (origin["caller"], origin["parentcaller"]) == (IN_SAMPLE, "0x7ff612340100")
    arguments = {a["name"]: a["value"] for a in origin["arguments"]}
    assert arguments["Return Address"] == IN_SAMPLE and arguments["Module"] == SAMPLE
    assert (arguments["Technique"], arguments["Service"]) == ("direct", "NtAllocateVirtualMemory")


# --- Linux --------------------------------------------------------------------------------

LIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"


def linux_syscall(**fields) -> dict:
    return {"Plugin": "syscall", "Method": "mprotect", "Module": "linux", "Syscall": 10, "Type": "x64",
            **fields}


@pytest.mark.parametrize("fields", [
    pytest.param(dict(Caller="0x7f12345678", FromModule=LIBC), id="libc"),
    pytest.param(dict(Caller="0x7ffd12340abc", FromModule="[vdso]"), id="the vDSO"),
    # Static and Go programs make their syscalls themselves
    pytest.param(dict(Caller="0x401234", FromModule="/tmp/sample"), id="a static program"),
    pytest.param(dict(Caller="0x401234"), id="not looked up"),
    pytest.param(dict(Type="x32", Bitness=32, Caller="0xf7f1f549", FromModule="[vdso]"),
                 id="a 32-bit process"),
    pytest.param(dict(Type="x32", Caller="0x401234", FromModule="/tmp/sample"), id="bitness unknown"),
    # The Windows fields mean nothing here
    pytest.param(dict(Caller="0x401234", FromModule="/tmp/sample", ParentCallTarget="0x402000"),
                 id="no frame 1 on Linux"),
])
def test_linux_syscalls_the_system_makes_are_not_reported(fields):
    assert classify(linux_syscall(**fields), linux=True) is None


@pytest.mark.parametrize("fields, technique", [
    pytest.param(dict(Caller="0x7f0000001010", FromModule=""), "unbacked", id="shellcode"),
    pytest.param(dict(Type="x32", Bitness=64, Caller="0x401236", FromModule="/tmp/sample"),
                 "compat_from_64bit", id="int 0x80 in a 64-bit process"),
    pytest.param(dict(Type="x32", Bitness=64, Caller="0x7f0000001010", FromModule=""),
                 "compat_from_64bit", id="int 0x80 from shellcode"),
])
def test_linux_syscalls_made_elsewhere_are_reported(fields, technique):
    origin = classify(linux_syscall(**fields), linux=True)
    assert (origin.technique, origin.address, origin.caller) == (technique, fields["Caller"], fields["Caller"])


def linux_trace(*records):
    return (inject(100),
            rec("procmon", 0x0f, 100, ppid=1, method="do_execveat_common", FileName="/tmp/s",
                ImagePathName="/tmp/s", CommandLine="/tmp/s"),
            *records)


def test_a_linux_syscall_from_memory_no_file_backs_is_followed_by_a_call_for_it(tmp_path):
    [p] = processes(
        tmp_path, *linux_trace(
            rec("syscall", 0x10, 100, ppid=1, method="openat", Type="x64", Caller="0x7f12345678",
                FromModule=LIBC),
            rec("syscall", 0x11, 100, ppid=1, method="mprotect", Type="x64", Caller="0x7f0000001010",
                FromModule="")),
        os_=TargetOs.UBUNTU)
    calls = list(p["calls"])
    assert [(c.get("syscall"), c.get("api")) for c in calls] == [
        ("do_execveat_common", None), ("openat", None), ("mprotect", None), (None, "syscall")]
    # Where it was made from is no argument of the call
    assert not {"Caller", "FromModule"} & {a["name"] for a in calls[1]["arguments"]}
    arguments = {a["name"]: a["value"] for a in calls[3]["arguments"]}
    assert (arguments["Technique"], arguments["Service"]) == ("unbacked", "mprotect")
    assert calls[3]["caller"] == "0x7f0000001010"


def run_signatures(tmp_path, os_, *records):
    """evasive_syscalls.py from the community checkout, alone in a copy of
    its layout, over `records`."""
    from sandboxd.postprocessing.plugins.cape_plugin import signatures as loader

    source = cape_compat.DEFAULT_COMMUNITY / "modules" / "signatures" / "all" / "evasive_syscalls.py"
    group = tmp_path / "community" / "modules" / "signatures" / "all"
    group.mkdir(parents=True)
    shutil.copy(source, group)
    job = tmp_path / "job"
    job.mkdir()
    write_trace(job, *records)
    try:
        return cape_analysis.run_cape(
            PostprocessContext(job, PostprocessingConfig(), os_),
            CapeConfigSection(capa=False, community=tmp_path / "community", compress_trace=False))
    finally:
        # The registry and the import shims are process-wide.
        loader._loaded_from = None
        loader.list_plugins("signatures").clear()
        for name in [n for n in sys.modules if n.startswith("modules.signatures")]:
            del sys.modules[name]


def test_the_community_signatures_read_it(tmp_path):
    results = run_signatures(tmp_path, TargetOs.WINDOWS, *direct_trace())
    [matched] = results["signatures"]
    assert matched["name"] == "direct_syscall"
    assert matched["data"][0] == {"type": "call", "pid": 100, "cid": 1}
    assert "NtAllocateVirtualMemory" in matched["data"][1]["syscalls"][0]


def test_the_community_signatures_read_linux_ones(tmp_path):
    results = run_signatures(
        tmp_path, TargetOs.UBUNTU, *linux_trace(
            rec("syscall", 0x10, 100, ppid=1, method="mprotect", Type="x64", Caller="0x7f0000001010",
                FromModule=""),
            rec("syscall", 0x11, 100, ppid=1, method="execve", Type="x32", Bitness=64,
                Caller="0x401236", FromModule="/tmp/s")))
    assert sorted(s["name"] for s in results["signatures"]) == [
        "compat_syscall_from_64bit", "syscall_from_unbacked_memory"]
