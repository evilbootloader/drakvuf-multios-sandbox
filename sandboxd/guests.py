"""Per-guest analysis packages: how a sample is staged and how it is run.

Issue #41 (DRAFT-060).

This is the per-OS boundary that `preconfig-<os>.sh` and `drakvuf-<os>.sh`
occupied, expressed as argv builders. Everything here is a **pure function**
returning a list, so the parity criterion -- "the same sample produces the same
artifact set" -- was checkable at the desk against the literal commands those
scripts ran, before any Dom0 time was spent. They were deleted 2026-09-15; the
literals they contributed are recorded at each builder below.

## What is carried across, and why each one

A port that loses these re-earns them the hard way, so each arrives with its
reason attached:

  * **No `chmod` after `writefile`.** `writefile` leaves the staged file
    executable. Established on Dom0 2026-08-09 by REMOVING a chmod injection
    that had been there and confirming runs still traced. The injector help
    does not say this. If a sample ever traces empty with a successful
    WriteFile, check the staged file's mode first -- that is the assumption.
  * **Android traces with `-F --disable-sysret`; Ubuntu does not** (it did
    from 2026-08-29 to 2026-10-23, `default_trace_options` says why it
    stopped). On Android it is a property of the guest, not a preference: every binder IPC is an `ioctl()` and every
    system service runs a Looper on `epoll_pwait`, so an idle BlissOS clone
    emits thousands of events before anything is analysed. Without these an
    APK installed and launched correctly and still could not finish drawing
    inside the window.
  * **`am`, never `monkey`.** `monkey` reaches `app_process64`, which aborts
    with exit 134 without the `/data/system/environ/classpath` import; and
    `ActivityManager.isUserAMonkey()` reports it to the sample. `am` is a
    two-line wrapper around the native `cmd`, so it needs no import.
  * **The install is not traced.** `pm install` takes 3s untraced and does not
    finish in 120s under the trace. Nothing is lost -- an Android application
    cannot run its own code during installation.
  * **The guest sees the SUBMITTED filename, not a digest** (C5, DRAFT-030).
    Extension dispatch and `argv[0]` self-checks are real evasion surface that
    a hash-named file exercises none of.

## What is NOT carried across, because it was wrong

**The sample is no longer launched directly** (2026-10-02). The scripts did
`-e <sample>`, which starts it before DRAKVUF has armed a single plugin --
`main.cpp` injects, then calls `start_plugins()`, then `loop()` -- so the
sample's first seconds were never recorded by any of them, on any guest, and
the trace completed normally without saying so. `LAUNCH_DELAY` below is the
wait that closes that, and the two `_*_launch` builders are how each guest
spends it. Parity with the scripts is the acceptance criterion everywhere else
in this module; here it is the defect.

## What is deliberately NOT carried

`1>"$OUT/drakvuf.log" 2>&1`. Every trace in the scripts merges DRAKVUF's
diagnostics into what `-o json` makes a pure JSONL event stream, which is what
blocks capa (DRAFT-019). `proc.spawn` takes separate paths and offers no merge.
"""

from __future__ import annotations

import logging
import re
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from . import config

from .postprocessing.paths import DUMPS_DIR, EXTRACTED_DIR, IPT_DIR, PROCDUMPS_DIR

log = logging.getLogger("sandboxd.guests")

# The one plugin whose selection changes the argv beyond `-a`: it needs a
# directory (`--ipt-dir`) and a ring to trace. The name is DRAKVUF's, as the
# platform's catalogue spells it (`catalogue.PLUGINS`).
IPT_PLUGIN = "ipt"
UNIXSOCKETMON_PLUGIN = "unixsocketmon"
PROCMON_PLUGIN = "procmon"
PROCDUMP2_PLUGIN = "procdump2"
MEMDUMP_PLUGIN = "memdump"
FILEEXTRACTOR_PLUGIN = "fileextractor"
APIMON_PLUGIN = "apimon"
RPCMON_PLUGIN = "rpcmon"
# The Linux counterpart of apimon, from the DRAKVUF fork (`drakvuf/` submodule,
# `src/plugins/libmon`). Like apimon it needs a hook list to do anything at
# all -- "without it the plugin does nothing", its README says -- but the
# option and the file format are its own: `--so-hooks-list`, keyed by shared
# object rather than by DLL.
LIBMON_PLUGIN = "libmon"
# `--procmon-envs-list`, read by `argv_trace` and by falco_analysis's config,
# which must agree on which variables procmon printed.
PROCMON_ENVS_LIST = Path(__file__).parent.absolute() / "data" / "procmon-envs.txt"


class TargetOs(str, Enum):
    UBUNTU = "ubuntu"
    ANDROID = "android"
    WINDOWS = "windows"


class SampleKind(str, Enum):
    """Chosen from the sample's own BYTES, never from `detected_type`.

    `detected_type` is advisory and submitter-influenced; this decides whether
    a file is installed or executed. The Android trace script drew the same
    distinction and it is kept: a structural test, repeated where it is needed
    rather than carried between stages, because a marker file is state a sample
    could read.
    """

    ELF = "elf"
    APK = "apk"
    PE = "pe"
    UNSUPPORTED = "unsupported_type"


class Interaction(str, Enum):
    """Who drives the guest while the trace runs.

    **Not yet supplied by anything.** The submit form renders no such control
    and `submit.js` posts only `target_os`, `filename` and `size_bytes`. The
    field exists so the stage machine has one place to read it from when
    DRAFT-055 (`hidsim`) and DRAFT-056 (VNC) land, and `NONE` reproduces
    exactly what the scripts do today.
    """

    NONE = "none"           # today: the sample runs unattended
    AUTOMATIC = "automatic"  # DRAFT-055: hidsim synthesises mouse/keyboard
    MANUAL = "manual"        # DRAFT-056: an operator drives it over VNC


@dataclass(frozen=True)
class TraceOptions:
    """The trace budget and plugin set for one job.

    **Nothing supplies these per-job yet**, and the UI says so in red:
    `_plugins.html` reads "Nothing here takes effect yet ... The selection is
    not sent, not stored and not honoured." DRAFT-052 is what wires the picker
    to the job row.

    So `for_os()` below returns exactly what the shell scripts hard-code. That
    is the point: until a job carries its own, the port must produce the same
    argv the scripts do, which is #41's acceptance criterion rather than an
    aspiration.
    """

    plugins: tuple[str, ...]
    timeout: int
    fast_singlestep: bool = False    # -F
    disable_sysret: bool = False
    interaction: Interaction = Interaction.NONE

    def drakvuf_flags(self) -> list[str]:
        flags: list[str] = []
        if self.fast_singlestep:
            flags.append("-F")
        if self.disable_sysret:
            flags.append("--disable-sysret")
        return flags


# Per guest, rather than shared, because the plugin matrix is per-guest
# (`drakvuf_plugin_os_support` in plugins.h) and a shared tuple would invite a
# Windows-only plugin into a Linux list. They began as the literals the per-OS
# trace scripts passed.
#
# **Still load-bearing after DRAFT-052.** A job now carries its own selection
# (`Lease.plugins`), but these remain what a job that selected nothing gets --
# a row queued before migration 0010, or a submitter who ticked no boxes. See
# `stages._trace_options`, which overlays the selection onto these rather than
# replacing them.
#
# **Every plugin the platform offers but `ipt` and `hidsim`, on every guest**
# (operator, 2026-10-23) -- the submit form pre-ticks the same set
# (`catalogue.Plugin.default`). `ipt` records every instruction and is
# selected per job; `hidsim` moves the desktop's mouse, and under it most of
# the trace is the desktop handling that input rather than the sample.
# procmon is what the process tree and every Falco exec rule rest on, and
# unixsocketmon what fills the Linux Network tab; neither costs measurable
# throughput (CURRENT-STATE, 2026-10-23).
_LINUX_PLUGINS = ("syscalls", "filetracer", "fileextractor", "memdump",
                  "procmon", "procdump2", "cpuidmon", "debugmon",
                  "ptracemon", "ebpfmon", "unixsocketmon")

# Ubuntu's set is the shared Linux one plus `libmon`, added 2026-09-26.
#
# **Android is excluded on evidence, not on suspicion** (operator, 2026-09-26),
# and stays so under "every plugin" (2026-10-23): libmon is for glibc Linux.
# The guest is BlissOS, so the linker is bionic. `readelf --dyn-syms` on its
# bootstrap linker (`system/bin/bootstrap/linker64`, inside `system_a.img`)
# returns 27 entries and **`_r_debug` is not one of them**:
#
#   - Not a layout problem. bionic implements the same SVR4 `r_debug` /
#     `link_map` shape `dl_rendezvous_abi.hpp` hardcodes.
#   - It is one symbol lookup. `dl_rendezvous.cpp:268` resolves `_r_debug` at
#     the LINKER's base, justifying it with a glibc version tag. bionic does
#     not export it, so `try_arm` cannot succeed: libmon retries
#     ARM_MAX_ATTEMPTS times and then emits `not_tracked` for every process.
#     Cost with no output, which is why it is not in the default set.
#   - **A newer BlissOS does not help.** bionic's export map
#     (`linker/linker.generic.map`) is an allowlist -- 25 `global:` names,
#     then `local: *;` -- and `_r_debug` is not on it in AOSP main either. No
#     Android version ships glibc, so there is no ROM to switch to.
#
# **The same output shows the way through.** `rtld_db_dlactivity` IS exported
# -- bionic's analogue of `_dl_debug_state`, which glibc hides and libmon's
# README records as unresolvable there. The two libcs export opposite halves
# of the rendezvous protocol, so a bionic port breakpoints that symbol rather
# than reaching `r_brk` through `_r_debug`. Walking `link_map` still wants the
# `DT_DEBUG` route `dl_rendezvous_abi.hpp` already names as v2.
#
# Revisit this row when libmon grows either path, not before.
#
# The sets are separate names rather than one shared tuple for the reason the
# `_WINDOWS_PLUGINS` comment below gives: sharing invites an edit to one set
# to become a silent edit to the other.
_UBUNTU_PLUGINS = _LINUX_PLUGINS + (LIBMON_PLUGIN,)

_ANDROID_PLUGINS = _LINUX_PLUGINS

# `apimon` added 2026-09-27, and it is what makes `hooks.txt` mean anything to
# capa. Without it the hook list is passed (memdump takes the same
# `--dll-hooks-list`) but only drives where memdump dumps: no `apimon.log` is
# written, so capa's dynamic pass reads `syscall.log` alone, and the 175
# file-scope rules get nothing because `Import` features come from apimon's
# `dll_loaded` event (`apimon.cpp:290`).
#
# **It is `heavy` in `catalogue.py` and this is the change that makes ~1,330
# hooks start firing for real.** Cost on a Windows trace is unmeasured; see the
# CURRENT-STATE row.
#
# The rest from 2026-10-23, as on Linux: every plugin offered but `ipt` and
# `hidsim`.
_WINDOWS_PLUGINS = ("syscalls", "filetracer", "fileextractor", "memdump",
                    "apimon", "procmon", "procdump2", "cpuidmon", "debugmon",
                    "regmon", "socketmon", "tlsmon", "rootkitmon")


# A plugin name as `-a` will accept it. Restrictive on purpose: this value
# arrives from the environment and goes straight into argv, and while the
# runner never uses a shell, a name with a space in it would silently become
# two arguments and `-a` would take the wrong one.
_PLUGIN_NAME = re.compile(r"\A[a-z][a-z0-9_]*\Z")


class PluginOverrideError(ValueError):
    """`SANDBOXD_PLUGINS` was set to something that cannot be a plugin set.

    Raised at startup rather than at trace time. An unknown name makes DRAKVUF
    exit, so without this every job would claim the host and fail identically
    — a misconfiguration reported once per sample instead of once.
    """


def parse_plugins_override(raw: str | None) -> tuple[str, ...] | None:
    """`SANDBOXD_PLUGINS=syscalls,memdump` -> `("syscalls", "memdump")`.

    **A measurement tool, not a configuration knob.** DRAKVUF issue #108 says
    the only way to size a plugin's cost is to run the same workload with and
    without it and compare; issue #517's advice for a slow guest is "disable
    the plugins you don't need". Both need the set changed without editing
    code, which is what this is for. DRAFT-052 is what records a real
    per-job selection, and it will supersede this.

    Unset or empty means "use the measured defaults", so the variable being
    absent is exactly today's behaviour.

    **Whatever this is set to applies to every job on the host, and nothing
    records that per job.** A trace missing `filetracer` output then looks
    identical to one where `filetracer` found nothing — the same silent
    absence of evidence that let the missing `memdump` directory go unnoticed
    (§F, 2026-08-27). The daemon logs the override loudly at startup for that
    reason, and it should be unset again once a measurement is finished.
    """
    if raw is None or not raw.strip():
        return None

    names = tuple(n.strip() for n in raw.split(",") if n.strip())
    if not names:
        raise PluginOverrideError(
            "SANDBOXD_PLUGINS is set but names no plugins. Unset it to use the "
            "defaults; an empty set would run DRAKVUF with no plugin at all."
        )
    for name in names:
        if not _PLUGIN_NAME.match(name):
            raise PluginOverrideError(
                f"SANDBOXD_PLUGINS contains {name!r}, which is not a plugin "
                f"name. Expected a comma-separated list such as "
                f"'syscalls,memdump'."
            )
    if "syscalls" not in names:
        # Not a hard error -- there are real reasons to trace without it -- but
        # it is far more often a typo, and the resulting trace is nearly empty
        # while still reporting success.
        log.warning(
            "SANDBOXD_PLUGINS does not include 'syscalls': traces will record "
            "almost nothing and will still complete normally"
        )
    return names


def default_trace_options(os_: TargetOs, kind: SampleKind) -> TraceOptions:
    """What the per-OS trace scripts did, per guest.

    `kind` matters only on Android, where the APK path gets `-t 150` rather
    than 120: the C watcher armed a 180s timer over the trace, so 150 leaves
    roughly 20s of headroom where 120 left 55s unused -- and a launch is
    heavier than an execve (zygote fork, ART init, an activity start, all at
    the trace's slowdown).
    """
    if os_ is TargetOs.UBUNTU:
        # `-F` added 2026-08-27 at the operator's request, after pinning Dom0
        # and the clones to disjoint pCPUs left the guest still crawling. The
        # measurement that decided it (runbook §F6e/§F7): with two traces
        # running, Dom0 sat at 196% of 600% -- four idle cores -- while each
        # clone got ~7% of its single vCPU. Nothing was CPU-starved; the guest
        # was paused ~93% of wall time waiting for Dom0 to service traps. That
        # is per-event cost, and no amount of scheduling fixes it.
        #
        # **`-F` costs no information at all.** It swaps the full singlestep
        # round trip after each hooked event for a second altp2m view: the same
        # events, carrying the same data, delivered more cheaply. Requires Xen
        # 4.14+; Dom0 runs 4.20.1, and Android has run it evidenced since
        # 2026-08-17.
        #
        # **Return values are kept again, from 2026-10-23.** `--disable-sysret`
        # stops hooking syscall returns: the trace still shows that a sample
        # called openat/connect/execve and with what arguments, but not
        # whether any of it succeeded, nor the fd that came back. It was
        # adopted 2026-08-29 for 2.06x (415 -> 856 syscalls/s,
        # baremetal-trial.md Part H) on one stated condition: that nothing
        # consumed return values.
        #
        # Two things changed. The Falco rules (`postprocessing/falco`) consume
        # them -- `fd.num >= 0`, `evt.res`, the fd table behind every
        # `fd.name` -- and without them most file rules can only report
        # "undetermined". And the price fell: on the parallel-events build,
        # this plugin set ran 557k-603k syscalls and 49-55 workload loops a
        # minute with returns, against 720k-776k and 67-73 without (3 runs
        # each, 2026-10-23), about a quarter rather than half.
        #
        # The returns were also all 0x0 until drakvuf 44b6a19 -- the Linux
        # dispatchers return void and the result is in pt_regs->ax -- so a
        # trace from an older pin has sysret records with no information in
        # them, whichever way this flag was set.
        #
        # DRAFT-052's syscall filter is still the better lever: it removes
        # syscall ENTRIES too while keeping returns for the calls analysed.
        return TraceOptions(plugins=_UBUNTU_PLUGINS, timeout=120,
                            fast_singlestep=True, disable_sysret=False)

    if os_ is TargetOs.ANDROID:
        return TraceOptions(
            plugins=_ANDROID_PLUGINS,
            timeout=150 if kind is SampleKind.APK else 120,
            fast_singlestep=True,
            disable_sysret=True,
        )

    # **CANDIDATE. Every value below is a starting hypothesis, not a
    # measurement.** Until 2026-09-01 this branch did not exist and Windows
    # raised instead, on the grounds that defaulting to the Linux set would be
    # inventing evidence. What changed is that a guest now exists to try them
    # on -- not that anything has been measured on it.
    #
    # So the refusal moved rather than disappeared: `catalogue.py` still
    # declines to claim a Windows analysis works, and the checklist entry stays
    # Candidate until a run fills it in. Read these as the values to test
    # first, and treat a Windows trace that produces nothing as a question
    # about this tuple before anything else.
    #
    # Three of them are load-bearing guesses, in decreasing order of how likely
    # they are to be wrong:
    #
    #   `syscalls`        needs the kernel symbol table from `profiles/
    #                     windows.json`. On Linux the same plugin resolves
    #                     against a kernel built from source; here it depends
    #                     on whatever the symbol JSON actually covers, and a
    #                     partial table degrades to silence, not to an error.
    #
    #   `disable_sysret`  adopted on Ubuntu for a measured 2.06x, on the
    #                     condition that nothing in this repository parses
    #                     return values. That condition still holds, but the
    #                     COST was measured on Linux syscall shapes. Windows
    #                     may pay differently.
    #
    #   `timeout=120`     copied from Ubuntu with no Windows run behind it.
    #                     A Windows guest boots and settles slower than the
    #                     Ubuntu clone, so this is the value most likely to
    #                     cut a trace short.
    #
    # `_WINDOWS_PLUGINS` is deliberately its own name: sharing a tuple with
    # the Linux set would make an edit to one silently an edit to the other,
    # and their Windows-only and Linux-only plugins would cross.
    # `test_guests.py` pins that this branch reads its own name.
    if os_ is TargetOs.WINDOWS:
        return TraceOptions(
            plugins=_WINDOWS_PLUGINS, timeout=120,
            fast_singlestep=True,
            disable_sysret=True,
        )

    # Not dead code: it is what a fourth `TargetOs` member gets on the day one
    # is added, instead of silently inheriting whichever branch fell through.
    raise NotImplementedError(
        f"no analysis package for {os_}: there is no measured plugin set or "
        f"timeout to default to, and guessing one would be inventing evidence."
    )


# **Seconds the sample waits, inside the guest, before its own first
# instruction** -- the one wait that is not in `timing.py`, because the guest
# spends it rather than sandboxd (the inventory there points here).
#
# It covers DRAKVUF's plugin arming, which happens AFTER the injection.
# `drakvuf/src/main.cpp` runs `inject_cmd()`, then `start_plugins()`, then
# `loop()`, and `inject_cmd` returns once the injected `execve` has returned in
# the child (`libinjector/linux/methods/linux_execve.c`, STEP4) -- so the sample
# is already running, unhooked, while the plugins are still going in. Nothing in
# that window is recorded and nothing anywhere says so: the trace completes
# normally and its events simply begin partway through the sample's life.
#
# That window is the most informative part of a trace -- unpacking,
# anti-analysis probes and the first connect() all happen in a sample's first
# moments. `libmon`'s README states the same ordering as the reason it has to
# adopt already-running processes at startup, and its limitations put the cost
# plainly: "a process that does its work and exits inside that window is
# missed".
#
# **UNMEASURED on this host (2026-10-02).** 10s is chosen for the asymmetry, not
# from a measurement: too short silently reinstates the gap this exists to
# close, too long costs a few seconds of late-trace runtime. Arming cost is a
# property of Dom0 and of the plugin set rather than of the guest, so it is one
# number and not a per-OS row -- only the command that spends it is per-OS.
#
# **Lower it from a trace, not from an argument.** The sample's own `execve` is
# now an event in `trace.log` (`do_execveat_common`, `FileName` = the staged
# path), which it could not be before: the exec used to happen before the
# syscalls plugin existed. The span from the first event of the run to that one
# IS the arming cost, measured on the real plugin set.
#
# `drakvuf -t` is deliberately NOT raised to compensate. The trace window still
# opens when `loop()` does, so a sample is observed from its first instruction
# for `timeout` minus however much of the delay outlasted arming. That trades a
# few seconds at the end of the window for the whole beginning of it, which is
# the trade this exists to make; raising `-t` instead would also move the phase
# budget and the Android APK path's 150s, neither of which this change has
# evidence to touch.
LAUNCH_DELAY = 5


@dataclass(frozen=True)
class GuestPaths:
    """Where a sample lands inside the guest, per OS.

    Carried from the per-OS env files. `/data/local/tmp` is not arbitrary: it pre-exists
    in the saved Android image and permits execution, where
    `/storage/self/primary/Download` is a noexec mount on which `chmod` is
    silently a no-op.

    `delay` is a guest command that waits `LAUNCH_DELAY` seconds and prints
    nothing, rendered here rather than templated so the row shows exactly what
    the guest runs. `None` means this guest launches its sample immediately.
    """

    staging_dir: str
    shell: str
    nameserver: str = "1.1.1.1"
    delay: str | None = None


PATHS = {
    TargetOs.UBUNTU: GuestPaths(staging_dir=f"/home/{config.ANALYSIS_USERNAME}/Desktop",
                                shell="/usr/bin/sh",
                                delay=f"/usr/bin/sleep {LAUNCH_DELAY}"),
    # /system/bin/sh, not /usr/bin/sh: the Ubuntu path does not exist here. No
    # sudo and no `su -c` either -- the guest is already root and ships
    # neither. All three measured by DRAFT-013.
    #
    # `sleep` is toybox, in the same directory as the shell.
    TargetOs.ANDROID: GuestPaths(staging_dir="/data/local/tmp",
                                 shell="/system/bin/sh",
                                 delay=f"/system/bin/sleep {LAUNCH_DELAY}"),

    # **`ping`, because `timeout` cannot be used here.** `timeout /t` reads the
    # console to watch for a keypress and aborts with "ERROR: Input redirection
    # is not supported" whenever it does not own one -- which is the normal case
    # for a command cmd.exe runs under `/c` from an injected `ShellExecuteEx`.
    # `ping` to loopback is the idiom that works without a console, and it is
    # the operator's call (2026-10-02).
    #
    # **`-n` is a COUNT, not a duration**, which is why this row is spelled out
    # rather than templated from `LAUNCH_DELAY`: the first echo goes out
    # immediately and the gap between consecutive ones is a second, so five
    # pings wait about four. Windows therefore gets a second less than the
    # Linux guests, deliberately (operator, 2026-10-02) -- five pings is the
    # idiom, and a `+1` to make the two exactly equal would be arithmetic
    # nobody reading `ping -n 6` would expect. If arming turns out to need the
    # whole `LAUNCH_DELAY`, raise the constant rather than patching this row.
    #
    # Absolute path for the same reason as the Linux rows: the injected process
    # inherits the ANCHOR's environment, and a `ping` found on PATH is a `ping`
    # that can be "not found" in a guest whose anchor has a thin one.
    TargetOs.WINDOWS: GuestPaths(
        staging_dir=f"C:\\Users\\{config.ANALYSIS_USERNAME}\\Desktop",
        shell="C:\\Windows\\System32\\cmd.exe",
        delay=f"C:\\Windows\\System32\\PING.EXE -n {LAUNCH_DELAY} 127.0.0.1 >nul"),
}


# **What makes a staged filename stop being one argument to `cmd.exe /c`.**
#
# The Linux launch hands the untrusted name to the guest as a separate `execve`
# element (`sh -c '<script>' sh "$1"`), which is what CLAUDE.md requires and
# what `sample_name_admissible()` leans on when it admits `"`, `$`, a backtick
# and `;`. **cmd.exe has no equivalent**: `/c` takes one string it re-parses,
# and `%1` in a batch file is substituted before parsing rather than after. So
# the Windows delay is the one place in this module where a sample-chosen name
# does reach a guest shell as text, and it is admitted only after this check.
#
# A name that fails it keeps the direct `ShellExecuteEx` the trace used before
# this change -- so it loses its launch delay, not its analysis, and never its
# byte-exact name (C5, DRAFT-030).
#
# Inside a double-quoted argument cmd stops processing `& < > | ^`, and `!`
# needs delayed expansion, which is off by default -- so `"` and `%` are the
# two that actually escape the quoting. The rest are rejected anyway: reviewing
# this should not require knowing that.
_CMD_UNSAFE = frozenset('"%&<>|^!')


# The symbol profiles DRAKVUF takes beside the kernel one (`-r`): option ->
# file in the directory `Job.profile` is in, so the paths are absolute like
# every other one in the argv and the checkout can live anywhere. Every name
# is in `long_opts` of both upstream main.cpp and the deployed fork
# (lfreijo/drakvuf@memdump), checked 2026-09-19; the files themselves are
# untracked, `windows_symbols.md` evidences two of them, and
# `scripts/windows-symbol-profiles.py` produces the set from the golden image.
#
# Passed unconditionally: DRAKVUF stores a path and the plugin that wants it
# opens it, so an unselected plugin's profile costs nothing. `--json-wow` is
# the exception -- it is the core's, loaded in drakvuf_init, and a file that
# fails to load there is a NULL and a debug line, not an error.
#
# `--json-ole32` and `--json-ndis` are absent on purpose: neither DLL's
# symbols could be produced (2026-09-19).
#
# Linux plugins take only the kernel profile.
SYMBOL_PROFILES: dict[TargetOs, tuple[tuple[str, str], ...]] = {
    TargetOs.UBUNTU: (),
    TargetOs.ANDROID: (),
    TargetOs.WINDOWS: (
        ("--json-wow", "wow.json"),
        ("--json-tcpip", "tcpip.json"),
        ("--json-win32k", "win32k.json"),
        ("--json-sspicli", "sspicli.json"),
        ("--json-kernel32", "kernel32.json"),
        ("--json-kernelbase", "kernelbase.json"),
        ("--json-wow-kernel32", "kernel32wow.json"),
        ("--json-ntdll", "ntdll.json"),
        ("--json-iphlpapi", "iphlpapi.json"),
        ("--json-ole32", "ole32.json"),
        ("--json-clr", "clr.json"),
        ("--json-mscorwks", "mscorwks.json"),
        ("--json-hal", "hal.json"),
        ("--json-fwpkclnt", "fwpkclnt.json"),
        ("--json-fltmgr", "fltmgr.json"),
        ("--json-ci", "ci.json"),
        ("--json-netio", "netio.json"),
        ("--json-ndis", "ndis.json"),
        ("--json-services", "services.json"),
    ),
}


# --- what a sample is, from its bytes ---------------------------------------

def classify(path: Path) -> SampleKind:
    """A structural test on the file itself.

    Deliberately not `detected_type`, which is advisory and derived from a
    submitter-supplied name at admission. This decides whether a file is
    installed or executed, and that decision should rest on the bytes.
    """
    with open(path, "rb") as fh:
        magic = fh.read(4)

    if magic[:4] == b"\x7fELF":
        return SampleKind.ELF
    if magic[:2] == b"MZ":
        return SampleKind.PE
    if magic[:2] == b"PK":
        # A ZIP containing AndroidManifest.xml is an APK. Reading the central
        # directory is not decompressing: it is cheap, bounded, and does not
        # enter the code path where bombs live.
        try:
            with zipfile.ZipFile(path) as z:
                if "AndroidManifest.xml" in z.namelist():
                    return SampleKind.APK
        except (zipfile.BadZipFile, OSError):
            return SampleKind.UNSUPPORTED
    return SampleKind.UNSUPPORTED


@dataclass(frozen=True)
class Job:
    """Everything the stage machine needs about one analysis.

    The first six come from the lease and are all the platform sends today
    (`LeaseResponse` in routers/worker.py). `options` is filled from
    `default_trace_options` until DRAFT-052 records a real selection on the
    job row.
    """

    job_id: str
    target_os: TargetOs
    submitted_filename: str
    attempt: int
    domid: int
    vlan: int
    clone_domain: str
    sample_path: Path          # on Dom0, for `injector -B`
    profile: Path              # -r, the LibVMI kernel profile
    injection_pid: int
    result_dir: Path
    options: TraceOptions
    kind: SampleKind

    @property
    def guest_sample(self) -> str:
        """`<staging>/<submitted filename>`, built by ONE rule.

        Both the stage that delivers and the stage that executes derive it the
        same way, from the same two values. That drift is not hypothetical: it
        is exactly what issue #2 found, where the trace held a literal
        `/home/<USER>/Desktop/test` while preconfig staged to
        `/home/carlos/Desktop/test`.
        """
        return  f"{PATHS[self.target_os].staging_dir}\\{self.submitted_filename}" if self.target_os == TargetOs.WINDOWS else f"{PATHS[self.target_os].staging_dir}/{self.submitted_filename}"


# --- staging -----------------------------------------------------------------

def argv_deliver(job: Job) -> list[str]:
    """Push the sample into the guest. One injection, no guest shell (C6).

    Deliberately first, and before any network exists: delivery does not depend
    on guest networking, which is what keeps an offline analysis mode reachable.
    `-B` is the Dom0 source, `-e` the guest destination -- confirmed from the
    installed build's own help on Dom0 2026-08-08.
    """
    return [
        "injector", "-r", str(job.profile), "-d", str(job.domid),
        "-i", str(job.injection_pid), "-m", "writefile",
        "-B", str(job.sample_path),
        "-e", job.guest_sample,
    ]


def _ubuntu_netcfg(job: Job, subnet: str) -> str:
    paths = PATHS[TargetOs.UBUNTU]
    return (
        f"sudo ip addr flush dev eth0 && "
        f"sudo ip addr add {subnet}.{job.vlan}.2/24 dev eth0 && "
        f"sudo ip route replace default via {subnet}.{job.vlan}.1 dev eth0 && "
        f"echo 'nameserver {paths.nameserver}' | sudo tee /etc/resolv.conf"
    )


def _android_netcfg(job: Job, subnet: str) -> str:
    """Bliss-Bass `EthernetConfigurator`, measured by DRAFT-013 -- not Ubuntu's
    `ip` chain, which BlissOS does not honour.

    `private_dns_mode off` is REQUIRED, not tuning: left at its default the
    clone resolved over DoT to 1.1.1.1:853 and the pcap recorded an encrypted
    stream instead of the domains the sample looked up. Silently, with nothing
    failing. Pcap-evidenced both ways in 06-verify-android-isolation.md.

    **The ANDROID_* exports build `app_process64` a runtime environment rather
    than assuming it inherits one. KEEP THEM.**

    Without them `app_process64` cannot locate its dalvik-cache or its APEX
    roots, so it **exits 0 having printed nothing and done nothing** -- and
    since `execproc` returns at process start, Dom0 sees a successful
    injection either way. Every clone ran with no address while reporting
    success. Measured 2026-08-29 on a live clone: with the exports the same
    command prints `SUCCESS` and `ip addr show eth0` reports 172.16.1.2/24;
    without them, silence and no address. The `classpath` import above does not
    substitute: it adds BOOTCLASSPATH and its three siblings, and was written
    to top up a SHELL's environment rather than to build one from nothing.

    **The reason they were added no longer holds, and whether they are still
    REQUIRED is unverified (2026-09-04).** They were added on 2026-08-29 because
    the anchor was then PID 1, and a child of `init` inherits init's
    environment -- four variables on this build: `PATH`, `_`, and init's own
    `SELINUX_STARTED_AT` and `FIRST_STAGE_STARTED_AT`. On 2026-08-31 the anchor
    reverted to a backgrounded `ping` started from a booted session, whose
    environment is not that sparse, so they may now be redundant.

    That question needs a clone, not an argument, and the measurement above was
    taken under the other anchor. **Do not delete them on the reasoning alone:**
    the failure they prevent is silent and reports success, so a regression here
    is invisible until someone reads a pcap. See `sandboxd/stages.py`
    `injection_pids` for the anchor history.

    `pm` is unaffected and that is why the install path kept working -- it is a
    two-line wrapper around `cmd`, which is native. Only the runtime needs this.
    """
    ns = PATHS[TargetOs.ANDROID].nameserver
    return (
        'while IFS=" " read -r a n v; do [ "$a" = export ] && export "$n=$v"; '
        'done < /data/system/environ/classpath; '
        'export ANDROID_DATA=/data ANDROID_ROOT=/system '
        'ANDROID_ART_ROOT=/apex/com.android.art '
        'ANDROID_I18N_ROOT=/apex/com.android.i18n '
        'ANDROID_TZDATA_ROOT=/apex/com.android.tzdata; '
        'APK="$(pm path com.example.ethernetconfig | sed "s/^package://")"; '
        'CLASSPATH="$APK" /system/bin/app_process64 / '
        'com.example.ethernetconfig.network.EthernetConfigurator STATIC eth0 '
        f'{subnet}.{job.vlan}.2 24 {subnet}.{job.vlan}.1 {ns} none && '
        'settings put global private_dns_mode off'
    )

def _windows_netcfg(job: Job, subnet: str) -> str:
    paths = PATHS[TargetOs.WINDOWS]
    return (
        f"netsh interface ip set address name=Ethernet static {subnet}.{job.vlan}.2 255.255.255.0 {subnet}.{job.vlan}.1 && netsh interface ip set dns name=Ethernet static {paths.nameserver} validate=no"
        )


def argv_configure_network(job: Job, subnet: str = "172.16") -> list[str]:
    """Give the clone its address. A separate injection from delivery.

    The guest-side text is ONE argument to `sh -c`. It reaches the guest as a
    single `execve` element and no Dom0 shell ever sees it, which is what makes
    the mixed-expansion Android form safe -- Dom0 interpolates only the vlan
    and the nameserver; everything else expands in the guest.
    """
    # Each branch names its own `PATHS` key. A single `PATHS[job.target_os]`
    # above the chain read fine, but it ran BEFORE any branch was chosen, so an
    # unhandled `TargetOs` died on a `KeyError` here instead of reaching the
    # refusal at the bottom -- which is the one that can name the guest and say
    # what it is missing.
    if job.target_os == TargetOs.ANDROID:
        script = (_android_netcfg(job, subnet))
        return [
            "injector", "-r", str(job.profile), "-d", str(job.domid),
            "-i", str(job.injection_pid), "-m", "execproc",
            "-e", PATHS[TargetOs.ANDROID].shell, "-f", "-c", "-f", script,
        ]
    elif job.target_os == TargetOs.UBUNTU:
        script = (_ubuntu_netcfg(job, subnet))
        return [
            "injector", "-r", str(job.profile), "-d", str(job.domid),
            "-i", str(job.injection_pid), "-m", "execproc",
            "-e", PATHS[TargetOs.UBUNTU].shell, "-f", "-c", "-f", script,
        ]
    elif job.target_os == TargetOs.WINDOWS:
        script = f"/c {(_windows_netcfg(job, subnet))}"
        return [
            "injector", "-r", str(job.profile), "-d", str(job.domid),
            "-i", str(job.injection_pid), "-m", "shellexec",
            "-e", PATHS[TargetOs.WINDOWS].shell, "-f", script,
        ]

    # Not dead code, and the same guard `default_trace_options` ends with: it
    # is what a fourth `TargetOs` member gets on the day one is added.
    #
    # Falling off the chain used to return `None`, which `proc._validate`
    # rejected as "argv is empty" -- a complaint about the runner, several
    # steps from the cause, on a path whose visible symptom is a clone with no
    # address. Refusing here names the guest and the two things a new one needs
    # before its clone can be addressed at all.
    raise NotImplementedError(
        f"no network configuration for {job.target_os}: it needs a netcfg "
        f"builder here and a `PATHS` entry giving its staging directory and "
        f"shell. Guessing either produces a clone that boots, takes an address "
        f"nothing routes, and reads as a sample that chose not to talk."
    )


def argv_install_apk(job: Job, handoff: str) -> list[str]:
    """Install, and resolve the launcher component, untraced.

    **The untrusted filename never becomes shell text.** `sh -c '<script>' sh
    "$GUEST_SAMPLE"` puts the path in `$1`, which nothing re-parses --
    `sample_name_admissible()` admits `"`, `$`, a backtick and `;`, and all
    four are live inside a double-quoted guest shell word. Sample-derived text
    may be held in guest shell VARIABLES and used quoted; what it may not do is
    arrive as text Dom0 pasted into a command.
    """
    # **`pm install`'s output goes to the handoff, not to /dev/null.**
    #
    # The handoff is written FIRST with pm's own diagnostic and only overwritten
    # by the component on success, so a failed install explains itself instead
    # of vanishing. It used to be `>/dev/null 2>&1`, which made every install
    # failure indistinguishable from an APK with no launcher activity: `PKG`
    # came back empty, the `[ -n "$PKG" ]` guard exited 0 before the redirect
    # ran, the handoff never existed, and the readfile failed with ENOENT.
    #
    # Observed 2026-08-29 against F-Droid.apk, which installs and resolves to
    # org.fdroid.fdroid/.views.main.MainActivity in one second when injected by
    # hand. Whatever differs in the pipeline, the guest was the only thing that
    # knew and it had been told to say nothing.
    #
    # This adds no artifact a sample could find: same single file, same `rm` in
    # stages.py, and it is gone before the sample runs.
    script = (
        'B=$(pm list packages 2>/dev/null); '
        f'pm install -r -t -g "$1" > {handoff} 2>&1; '
        'PKG=$(pm list packages 2>/dev/null | while read -r p; do '
        'case "$B" in *"$p"*) ;; *) echo "$p";; esac; done | head -1 '
        '| sed "s/^package://"); '
        '[ -n "$PKG" ] || exit 0; '
        'cmd package resolve-activity --brief '
        f'-c android.intent.category.LAUNCHER "$PKG" 2>/dev/null | tail -1 > {handoff}'
    )
    return [
        "injector", "-r", str(job.profile), "-d", str(job.domid),
        "-i", str(job.injection_pid), "-m", "execproc",
        "-e", PATHS[TargetOs.ANDROID].shell,
        "-f", "-c", "-f", script, "-f", "sh", "-f", job.guest_sample,
    ]


def argv_read_component(job: Job, handoff: str, dest: Path) -> list[str]:
    """Bring the resolved component to Dom0 so the trace needs no guest shell."""
    return [
        "injector", "-r", str(job.profile), "-d", str(job.domid),
        "-i", str(job.injection_pid), "-m", "readfile",
        "-B", str(dest), "-e", handoff,
    ]


def argv_remove_handoff(job: Job, handoff: str) -> list[str]:
    """Delete the component file before the sample runs.

    Not tidiness: from the launch onward the sample is running, and a file in
    its own staging directory naming its own component is exactly what an
    evasive application looks for. Nothing of the sample's has run yet -- an
    Android application cannot execute during installation -- so removing it
    here closes the window rather than narrowing it.
    """
    return [
        "injector", "-r", str(job.profile), "-d", str(job.domid),
        "-i", str(job.injection_pid), "-m", "execproc",
        "-e", "/system/bin/rm", "-f", "-f", "-f", handoff,
    ]


# --- tracing -----------------------------------------------------------------

def _linux_launch(paths: GuestPaths, target: str) -> list[str]:
    """Wait `LAUNCH_DELAY`, then become the sample.

    **The untrusted filename never becomes shell text.** `sh -c '<script>' sh
    "$GUEST_SAMPLE"` puts the path in `$1`, which nothing re-parses --
    `sample_name_admissible()` admits `"`, `$`, a backtick and `;`, and all four
    are live inside a double-quoted guest shell word. Same idiom and same
    reason as `argv_install_apk`.

    **`exec`, never `<delay>; <sample>`.** The shell replaces itself, so the
    sample keeps the pid the injection reported, its `argv[0]` is the staged
    path byte for byte (C5, DRAFT-030), and its parent is the anchor -- exactly
    what a direct `-e <sample>` produced. A child process instead would make
    `inject.log`'s `InjectedPid`, and therefore `report.json`'s
    `startup.process`, describe the shell rather than the sample, and would
    point `--procdump-on-finish` at it if `procdump` is ever selected
    (`main.cpp` sets `options.procdump_on_finish = injected_pid`).

    The shell's own startup is NOT in the traced window -- it is what the
    injection returns from, so it runs while the plugins are still going in,
    which is the whole point. What lands inside the window is one `execve`.
    """
    if not paths.delay:
        return ["-e", target]
    return ["-e", paths.shell, "-f", "-c",
            "-f", f'{paths.delay}; exec "$1"',
            "-f", "sh", "-f", target]


def _windows_launch(paths: GuestPaths, target: str) -> list[str]:
    """The same wait, through the one shell that cannot take it as an argument.

    `shellexec` reaches `ShellExecuteEx` with `-e` as `lpFile` and **only the
    first `-f` as `lpParameters`** (`win_injector.c` uses `args[0]` and ignores
    the rest), so the whole command is one string cmd.exe re-parses. `_CMD_UNSAFE`
    is what keeps the staged name out of that string when the name would not
    survive it; a rejected name is launched directly, as before this change.

    **`&`, not `&&`.** `ping` to loopback should always succeed, but a guest
    whose loopback is broken would skip the sample entirely under `&&` -- a
    trace that completes, uploads, and analysed nothing. `&` runs the sample
    whatever the wait did.

    Two consequences worth knowing, both from Windows having no `exec`:
    cmd.exe is the injected process, so `inject.log` reports its pid and name
    and `report.json`'s `startup.process` resolves to it, with the sample as
    its child -- a child the plugins now SEE being created, which they could
    not before. And the sample runs with a console attached. Normal for
    Windows, and a closer parent than the anchor process was.
    """

    execute_string = target

    if target.lower().endswith(".ps1"):
        ps_args = (
            f'-NoProfile -ExecutionPolicy Bypass -File "{target}"'
        )

        if not paths.delay or _CMD_UNSAFE & set(ps_args):
            return ["-e", "powershell.exe", "-f", ps_args]

        return [
            "-e",
            paths.shell,
            "-f",
            f"/c {paths.delay} & powershell.exe {ps_args}",
        ]

    if not paths.delay or _CMD_UNSAFE & set(execute_string):
        return ["-e", execute_string]

    return [
        "-e",
        paths.shell,
        "-f",
        f'/c {paths.delay} & "{execute_string}"',
    ]

# `--wait-stop-plugins`, in seconds: "Wait for plugins to stop before
# termination loop" (`drakvuf --help`). Without it DRAKVUF asks each plugin to
# stop ONCE at `-t` and exits even when one answers that it cannot yet, removing
# that plugin's traps with a call it injected still running in the guest.
# fileextractor extracts a Windows file through a chain of kernel calls injected
# into the writing thread; a call whose return trap is gone returns into a frame
# nothing restores, and the guest bugchecks 0x1e (execute at address 0) after
# the trace. Measured on Dom0 2026-10-21, 60s traces of the Windows default set
# plus a file-writing workload, drakvuf with that day's fileextractor fix:
# 16 of 16 crashed at the end without the wait, 0 of 16 with 30s.
#
# A ceiling, not a delay: DRAKVUF stops waiting as soon as every plugin has
# stopped, and does not wait at all when they all stop on the first request --
# the case for every plugin of the Ubuntu and Android defaults, so their traces
# end as before. Passed on every OS anyway: the option belongs to the engine,
# and whichever plugin has a call in flight, the guest is the one that pays.
# `timing.budgets` adds it to the trace phase guard, which would otherwise kill
# DRAKVUF mid-wait.
#
# **The trace goes on during the wait.** syscalls' stop() leaves the hooks of its
# per-OS plugin in place until DRAKVUF exits (upstream too), so a Windows job can
# carry up to this many seconds of records past `-t` -- of the sample still
# running, which is real behaviour rather than noise.
PLUGIN_STOP_WAIT = 30

# `--fileextractor-timeout`: "Timeout (in seconds) to finish file extractions".
# Once fileextractor has been stopping this long it ends a Windows extraction at
# the return of its current injected call instead of injecting the next one, so
# it must run out before `PLUGIN_STOP_WAIT` does. Without it a large file still
# being copied outlasts any wait: Edge's msedge.dll did in 5 of 6 traces with
# every plugin, and DRAKVUF exited with the call in the guest (Dom0 2026-10-21).
# The file is then reported as a `Timeout` failure. Linux fileextractor injects
# nothing and does not read the option.
FILEEXTRACTOR_STOP_TIMEOUT = 20


def argv_trace(job: Job, component: str | None = None) -> list[str]:
    """The DRAKVUF invocation.

    Two execution paths, selected from the sample's bytes: an APK is LAUNCHED,
    already installed, via `am start -n`; anything else is executed through a
    guest shell that waits first.

    **The sample does not begin when the injection returns. It begins
    `LAUNCH_DELAY` seconds later**, because DRAKVUF arms its plugins after
    injecting and nothing records what the sample did in between -- see that
    constant, and the two `_*_launch` helpers for how each guest spends the
    wait. The APK path is the exception and says why inline.
    """
    mode = "shellexec" if job.target_os == TargetOs.WINDOWS else "execproc"
    paths = PATHS[job.target_os]

    # `-s`: "Hide Hypervisor bits and signature in CPUID" (`drakvuf --help`,
    # operator-confirmed 2026-09-19). The cheapest evasion a sample tries is
    # a CPUID for the hypervisor-present bit; `cpuidmon` records the check,
    # this makes the answer the one bare metal gives. Every OS, every trace.
    argv = [
        "drakvuf", "-r", str(job.profile), "-s", "-d", str(job.domid),
        "-i", str(job.injection_pid), "-m", mode, "--parallel-events",
        "--sysret-mode", "kernel", 
    ]

    if job.kind is SampleKind.APK:
        if not component:
            raise ValueError(
                "an APK trace needs a launcher component; preconfig resolves "
                "it and a missing one means resolve-activity returned a "
                "diagnostic -- nothing should be executed"
            )
        # **No launch delay here, and that is a decision rather than an
        # omission.** The sample is not this process: `am` asks the activity
        # manager to start the activity and the app is forked from zygote
        # afterwards, so the sample's first instruction is already an `am`
        # startup plus an ART startup past the injection -- past arming without
        # help. Adding the shell would also undo a measured finding: a shell in
        # this window cost 1434 + 1546 + 1542 traced syscall events (2026-08-17)
        # out of a budget the launch was already failing to fit into, which is
        # what `test_the_traced_window_is_one_execve` pins.
        argv += ["-e", "/system/bin/am", "-f", "start", "-f", "-n",
                 "-f", component]

    elif job.target_os == TargetOs.WINDOWS:
        argv += _windows_launch(paths, job.guest_sample)
    else:
        argv += _linux_launch(paths, job.guest_sample)

    argv += job.options.drakvuf_flags()
    argv += ["-o", "json", "-t", str(job.options.timeout)]
    argv += ["--wait-stop-plugins", str(PLUGIN_STOP_WAIT)]
    for plugin in job.options.plugins:
        argv += ["-a", plugin]
    # The names are the postprocessing package's, not literals: process_dumps
    # reads DUMPS_DIR, and when these were spelled here by hand (2026-09-18)
    # `--memdump-dir` said `memdumps/` while the plugin read `dumps/`.
    argv += ["-D", str(job.result_dir / EXTRACTED_DIR),
             "--memdump-dir", str(job.result_dir / DUMPS_DIR)]
    if IPT_PLUGIN in job.options.plugins:
        # From `drakvuf --help` (operator-confirmed 2026-09-19):
        #   --ipt-dir <directory>   Where to store data recorded with Intel
        #                           Processor Trace
        #   --ipt-trace-os          Enable IPT tracing in ring 0
        #   --ipt-trace-user        Enable IPT tracing in ring > 0
        # Ring > 0 only: the sample's own code is what the trace is for, and
        # ring 0 would record the whole kernel under it. Only when the plugin
        # was selected -- an `--ipt-dir` with no `-a ipt` is a directory
        # nothing writes and compress_ipt would pack empty.
        argv += ["--ipt-dir", str(job.result_dir / IPT_DIR), "--ipt-trace-user"]
    # How many bytes of each message's payload unixsocketmon prints ("Max
    # message size (in bytes) to print", `drakvuf --help`). It does not limit
    # what the guest sends: `Size` is still the whole request, every buffer of
    # it, and only the printed `Value` is cut. DRAKVUF's default is 0, which
    # prints no payload at all. 2048 holds a request line and its headers, and
    # on the Ubuntu desktop's 2,300-4,900 messages a minute keeps the log
    # under ~20 MB a minute even if every one were full. Before drakvuf
    # bfab6ba the plugin hooked nothing on Ubuntu 22.04's kernel, and Size
    # was only the first buffer's length.
    if UNIXSOCKETMON_PLUGIN in job.options.plugins:
        argv += ["--unixsocketmon-max-size-print", "2048"]
    if FILEEXTRACTOR_PLUGIN in job.options.plugins:
        argv += ["--fileextractor-timeout", str(FILEEXTRACTOR_STOP_TIMEOUT), "--fileextractor-exclude-list",  (Path(__file__).parent.absolute() / "data" / "fileextractor-exclusions.txt").as_posix()]
    if MEMDUMP_PLUGIN in job.options.plugins or APIMON_PLUGIN in job.options.plugins or RPCMON_PLUGIN in job.options.plugins:
        argv += ["--dll-hooks-list", (Path(__file__).parent.absolute() / "data" / "hooks.txt").as_posix()]
    # libmon's own option and its own file. **Not `--dll-hooks-list`**: the
    # grammar is the same but the first field is a shared object rather than
    # a DLL, and pointing libmon at `hooks.txt` would match nothing on a
    # Linux guest while looking like it was configured. Without the list the
    # plugin loads and does nothing at all (its README says so), so the two
    # always travel together.
    if LIBMON_PLUGIN in job.options.plugins:
        argv += ["--so-hooks-list",
                 (Path(__file__).parent.absolute() / "data"
                  / "so-hooks-linux.txt").as_posix()]
    # The environment variables procmon prints at each exec. Without a list
    # it prints LD_PRELOAD, PWD and OLDPWD only (`configure_filter` in
    # procmon/linux.cpp), and a list REPLACES those, so the file names them
    # too. The rest are what Falco's rules test (`proc.env icontains
    # GLIBC_TUNABLES`, `... HTTP_PROXY`): a variable outside the list is
    # unknown to `falco_analysis`, not unset. One name per line and nothing
    # else -- DRAKVUF reads every line, a comment included, as a name. Only
    # Linux procmon reads it; Windows procmon ignores the option.
    if PROCMON_PLUGIN in job.options.plugins:
        argv += ["--procmon-envs-list", PROCMON_ENVS_LIST.as_posix()]
    # procdump2 dumps the injected process's whole memory when the trace ends
    # (`main.cpp`: procdump_on_finish = injected_pid), and needs somewhere to
    # put it: without --procdump-dir it has no output at all. Compressed,
    # because a GUI process's memory runs to hundreds of MB against the job's
    # 4 GiB result budget. `stages._trace` creates the directory.
    #
    #if PROCDUMP2_PLUGIN in job.options.plugins:
    #    argv += ["--procdump-dir", str(job.result_dir / PROCDUMPS_DIR), "--compress-procdumps"]
    for option, name in SYMBOL_PROFILES[job.target_os]:
        argv += [option, str(job.profile.parent / name)]
    return argv


def argv_tcpdump(job: Job, bridge: str, dest: Path) -> list[str]:
    """Capture on the clone's own VLAN sub-interface.

    `-U` so packets are written as they arrive: without it a trace that ends
    abruptly loses whatever is still in the buffer, which is the traffic
    closest to whatever ended it.
    """
    return ["tcpdump", "-i", f"{bridge}.{job.vlan}", "-n", "-U",
            "-w", str(dest)]


# --- component validation ----------------------------------------------------

def component_is_launchable(component: str) -> bool:
    """`<package>/<activity>`, and nothing else.

    Guest-derived and therefore untrusted -- an APK chooses its own package and
    activity names. It reaches `execve` as a single argv element so nothing
    re-parses it, but a value that is not a component means `resolve-activity`
    returned a diagnostic and there is nothing to launch.

    `$` is admitted because an inner class is a legitimate launcher activity.
    """
    # The empty string is rejected by the slash count -- it has none -- so
    # there is no separate `if not component` test. There was one, after this
    # line and therefore unreachable; a reader who adds one back should put it
    # first or not at all.
    if component.count("/") != 1:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyz"
                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                  "0123456789._/$-")
    return all(c in allowed for c in component)
