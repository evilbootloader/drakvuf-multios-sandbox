"""Where a Windows syscall was made from, and whether Windows makes syscalls there.

Hell's Gate and the techniques after it make system calls without going
through ntdll's stubs, so that a hook placed in ntdll never sees them. DRAKVUF
hooks the kernel's dispatcher and sees every call however it was made: what
gives these away is where they came from. For a call from user mode the
syscall plugin reports (drakvuf src/plugins/syscalls/win.cpp, `get_origin`):

* `Caller`, frame 0: the instruction after `syscall`, in ntdll's or win32u's
  stub unless the call was made somewhere else;
* `ParentCaller`, frame 1: what that stub returns to, the code that called it;
* `FromModule` / `FromParentModule`: the file each address lies in, as
  Windows names it (volume relative, `\\Windows\\System32\\ntdll.dll`); `""`
  for memory no file backs; left out when it could not be looked up, which
  decides nothing here. `FromModuleCopy` / `FromParentModuleCopy`: the base
  of the mapping, when it is a second mapping of a system DLL -- a copy of
  ntdll the sample mapped, or a file of that path on another volume;
* `StubSyscall`: when frame 0 is in a stub, the service that stub is for,
  when the thread called another. DRAKVUF up to 9722578 took the service
  called from KTHREAD.SystemCallNumber, which is stale on a thread's first
  win32k call: converting it to a GUI thread makes callbacks and Zw calls
  that overwrite the number before the service is dispatched. So it is
  compared here with `Syscall`, the service the kernel dispatched, in
  `Module`'s table, and counts only when it is another;
* `ParentCallTarget` / `ParentCallTargetModule`: what the call instruction
  before frame 1 called, when that was not the stub `syscall` ran in but
  that stub past its start, or code that looks like a syscall stub of its own
  (`mov r10, rcx` and a jmp);
* `Bitness`, for a WoW64 process only: 32 when the frames are the 32-bit call
  WoW64 made the syscall for -- the 64-bit ones are ntdll's stub and
  wow64.dll every time, and are not reported -- and 64 when they are 64-bit
  code's: the process's own, or WoW64's with no 32-bit call to show.

The techniques, by what gives each away:

`direct`
    frame 0 is no stub of Windows': `syscall` ran in the sample's image, its
    memory or its copy of ntdll (Hell's, Halo's and Tartarus' Gate,
    SysWhispers 1 and 2, FreshyCalls).
`indirect`
    frame 0 is ntdll's stub, but frame 1 called a stub of the sample's own
    that jumped there, or into it past its start (HellsHall, SysWhispers3's
    jumper, RecycledGate) -- or another service's stub ran the syscall
    (SysWhispers3's randomized jumper).
`heavens_gate`
    a WoW64 process's 64-bit code made the syscall: anything above, or
    ntdll's stub called from outside WoW64's 64-bit layer.
`wow64_direct`
    a WoW64 process entered Wow64Transition from outside the 32-bit stubs
    (`call dword ptr fs:[0C0h]` in its own code).
`wow64_indirect`
    a 32-bit stub's call to Wow64Transition, entered past the stub's start.

On Linux (src/plugins/syscalls/linux.cpp, `get_origin`) a record has
`Caller`, pt_regs->ip, and `FromModule`, the file mapped there -- `""` for
memory no file backs, `[vdso]` for the vDSO -- and, for a 32-bit syscall
(`Type` x32), `Bitness`, the process's. Two techniques:

`unbacked`
    the syscall was made from memory no file backs: shellcode, injected
    code, or a packer's unpacked program (UPX unpacks a static program into
    anonymous memory). Made from a program's own file is not one: static and
    Go programs make their syscalls themselves.
`compat_from_64bit`
    a 64-bit process made a 32-bit syscall (`int 0x80`): past tools that
    trace only the 64-bit syscall table and seccomp filters written for it.

KNOWN GAPS:

* Linux: no frame 1 (`ParentCaller`), so no indirect syscalls -- a libc
  wrapper that is a cancellation point keeps a frame of its own, and nothing
  here unwinds with .eh_frame. No file on a kernel of 6.1 or later, whose VMAs
  are in a maple tree DRAKVUF does not walk: no `unbacked` there.
* A call DRAKVUF cannot decode -- through a register, or through memory a
  register points to, CFG's dispatch among them -- says nothing of what it
  called: an indirect syscall made through one is reported only when another
  service's stub ran it.
* A stub of the sample's own is told by its bytes, not decoded; a stub that
  does not end in `mov r10, rcx` and a jmp is not seen, and code that holds
  those bytes otherwise is taken for one.
* 32-bit code is not matched as a stub of its own (it has no `mov r10, rcx`),
  and a 32-bit stub's service is not compared with the one called: WoW64 makes
  syscalls of its own for a 32-bit call. A 32-bit indirect syscall is
  reported only when it entered the stub past its start.
* A system DLL Windows itself had to relocate in one process -- something
  else held its base -- is a copy there.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# The API name capemon gives a syscall it saw made outside ntdll, and CAPE's
# signatures look for (`direct_syscall_evasion`, `unbacked_syscall_execution`)
ORIGIN_API = "syscall"

TECHNIQUES = ("direct", "indirect", "heavens_gate", "wow64_direct", "wow64_indirect",
              "unbacked", "compat_from_64bit")

_SYSTEM32 = "\\windows\\system32\\"
_SYSWOW64 = "\\windows\\syswow64\\"

# Where Windows' own code runs `syscall`: ntdll's and win32u's stubs. win32k's
# were user32's, gdi32's and imm32's on Windows 7, and wow64win's in a WoW64
# process; wow64cpu's turbo thunks make some of a WoW64 process's syscalls.
SYSCALL_SITES = frozenset(_SYSTEM32 + name for name in (
    "ntdll.dll", "win32u.dll", "user32.dll", "gdi32.dll", "imm32.dll", "wow64win.dll",
    "wow64cpu.dll"))
# A stub something calls, so that frame 1 is its caller. A turbo thunk is
# jumped to: the qword at the stack pointer is not a return address there.
_CALLED_STUBS = SYSCALL_SITES - {_SYSTEM32 + "wow64cpu.dll"}
# What calls ntdll's stubs in a WoW64 process on behalf of its 32-bit code:
# DRAKVUF's `through_wow64` (win.cpp), which this must stay the same as.
WOW64_LAYER = frozenset(_SYSTEM32 + name for name in (
    "ntdll.dll", "wow64.dll", "wow64win.dll", "wow64cpu.dll", "wow64base.dll", "wow64con.dll"))
# Where a 32-bit process's stubs call Wow64Transition: ntdll's and win32u's;
# user32's, gdi32's and imm32's on Windows 7. kernel32's and KernelBase's are
# the NtWow64Csr* thunks, which wow64.dll answers with a call to csrss
# (NtAlpcSendWaitReceivePort): every 32-bit process creation makes them.
WOW64_STUBS = frozenset(_SYSWOW64 + name for name in (
    "ntdll.dll", "win32u.dll", "user32.dll", "gdi32.dll", "imm32.dll",
    "kernel32.dll", "kernelbase.dll"))
# The service number in a stub's `mov eax`: bit 12 is win32k's table (DRAKVUF's
# SERVICE_MASK, origin.h)
_WIN32K_TABLE = 0x1000
_SERVICE_MASK = 0x1fff


@dataclass(frozen=True)
class Origin:
    """A syscall made where Windows makes none. `address` and `module` are
    frame 0 (capemon's `Return Address` and `Module`), `caller` the sample's
    code that made the call and `parentcaller` its caller where known --
    capemon's `caller` and `parentcaller` -- and `evidence` what gave it away."""
    technique: str
    address: str
    module: str
    caller: str
    evidence: str
    parentcaller: Optional[str] = None


@dataclass(frozen=True)
class _Frame:
    address: Optional[str]
    module: Optional[str]       # as reported; None when not looked up
    copy: Optional[str]

    @property
    def path(self) -> Optional[str]:
        return self.module.lower() if self.module is not None else None

    def describe(self) -> str:
        if self.address is None:
            return "an address not read"
        if self.module is None:
            where = "memory that could not be looked up"
        elif self.module == "":
            where = "memory no file backs"
        elif self.copy:
            where = f"a copy of {self.module} mapped at {self.copy}"
        else:
            where = self.module
        return f"{self.address} in {where}"


def _frame(rec: dict, address: str, module: str, copy: str) -> _Frame:
    value = rec.get(address)
    if not isinstance(value, str):
        return _Frame(None, None, None)
    name = rec.get(module)
    copied = rec.get(copy)
    # DRAKVUF up to 9722578 printed the empty string as "(null)"
    if name == "(null)":
        name = ""
    return _Frame(value, name if isinstance(name, str) else None,
                  copied if isinstance(copied, str) else None)


def _is(frame: _Frame, places) -> bool:
    """`frame` lies in one of `places` -- named files, so never one in a
    directory below System32 that any user can write to -- in Windows' own
    mapping of it."""
    return frame.path in places and not frame.copy


def _another_services_stub(rec: dict, stub_service) -> bool:
    """`StubSyscall` is a stub of another service than the one the kernel
    dispatched. A record without a service number says nothing against it."""
    if not isinstance(stub_service, str):
        return False
    number = rec.get("Syscall")
    if isinstance(number, bool) or not isinstance(number, int):
        return True
    try:
        stub = int(stub_service, 16)
    except ValueError:
        return True
    called = number | (_WIN32K_TABLE if rec.get("Module") == "win32k" else 0)
    return (stub ^ called) & _SERVICE_MASK != 0


def _classify_linux(rec: dict) -> Optional[Origin]:
    caller = _frame(rec, "Caller", "FromModule", "")
    if rec.get("Type") == "x32" and rec.get("Bitness") == 64:
        return Origin("compat_from_64bit", caller.address, caller.module or "", caller.address,
                      f"a 64-bit process made a 32-bit syscall, at {caller.describe()}")
    if caller.address and caller.module == "":
        return Origin("unbacked", caller.address, "", caller.address,
                      f"the syscall was made at {caller.describe()}")
    return None


def classify(rec: dict, linux: bool = False) -> Optional[Origin]:
    """The technique a syscall record was made with, or None for one the
    system's own code made -- or one whose frames could not be looked up."""
    if linux:
        return _classify_linux(rec)
    if rec.get("PreviousMode") != "User":
        return None
    caller = _frame(rec, "Caller", "FromModule", "FromModuleCopy")
    parent = _frame(rec, "ParentCaller", "FromParentModule", "FromParentModuleCopy")
    target = _frame(rec, "ParentCallTarget", "ParentCallTargetModule", "")
    stub_service = rec.get("StubSyscall")
    bitness = rec.get("Bitness")

    def origin(technique, at: _Frame, evidence, parentcaller=None):
        return Origin(technique, caller.address, caller.module or "", at.address, evidence,
                      parentcaller)

    if bitness == 32:
        if caller.module is not None and not _is(caller, WOW64_STUBS):
            return origin("wow64_direct", caller,
                          f"entered Wow64Transition from {caller.describe()}", parent.address)
        if target.address:
            return origin("wow64_indirect", parent,
                          f"{parent.address} called {target.describe()}, past the start of "
                          f"the stub at {caller.address}")
        return None

    own = "heavens_gate" if bitness == 64 else None
    if caller.module is not None and not _is(caller, SYSCALL_SITES):
        return origin(own or "direct", caller, f"`syscall` ran at {caller.describe()}",
                      parent.address)
    if target.address:
        return origin(own or "indirect", parent,
                      f"{parent.address} called {target.describe()}, not the stub of "
                      f"{caller.module} that ran the syscall")
    if _another_services_stub(rec, stub_service):
        return origin(own or "indirect", parent,
                      f"the syscall ran in the stub of service {stub_service} at "
                      f"{caller.address}, not of the one called")
    # A WoW64 process's own 64-bit code called ntdll's stub
    if own and _is(caller, _CALLED_STUBS) and parent.module is not None and not _is(parent, WOW64_LAYER):
        return origin(own, parent, f"ntdll's stub was called from {parent.describe()}")
    return None
