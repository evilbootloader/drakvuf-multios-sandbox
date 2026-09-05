"""Per-guest analysis packages: how a sample is staged and how it is run.

Issue #41 (DRAFT-060).

This is the per-OS boundary that `preconfig-<os>.sh` and `drakvuf-<os>.sh`
occupy today, expressed as argv builders. Everything here is a **pure
function** returning a list, so the parity criterion -- "the same sample
produces the same artifact set" -- is checkable at the desk against the
literal commands the scripts run, before any Dom0 time is spent.

## What is carried across, and why each one

A port that loses these re-earns them the hard way, so each arrives with its
reason attached:

  * **No `chmod` after `writefile`.** `writefile` leaves the staged file
    executable. Established on Dom0 2026-08-09 by REMOVING a chmod injection
    that had been there and confirming runs still traced. The injector help
    does not say this. If a sample ever traces empty with a successful
    WriteFile, check the staged file's mode first -- that is the assumption.
  * **Android traces with `-F --disable-sysret`; Ubuntu does not.** A property
    of the guest, not a preference: every binder IPC is an `ioctl()` and every
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

log = logging.getLogger("sandboxd.guests")


class TargetOs(str, Enum):
    UBUNTU = "ubuntu"
    ANDROID = "android"
    WINDOWS = "windows"


class SampleKind(str, Enum):
    """Chosen from the sample's own BYTES, never from `detected_type`.

    `detected_type` is advisory and submitter-influenced; this decides whether
    a file is installed or executed. `drakvuf-android.sh` already draws the
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


# The literals from drakvuf-ubuntu.sh:181 and drakvuf-android.sh:324. Identical
# today; kept per-OS rather than shared because the plugin matrix is per-guest
# (`drakvuf_plugin_os_support` in plugins.h) and a shared tuple would invite a
# Windows-only plugin into a Linux list.
_LINUX_PLUGINS = ("syscalls", "filetracer", "fileextractor", "memdump")

_WINDOWS_PLUGINS = ("syscalls", "filetracer", "fileextractor", "memdump")


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
    """What the scripts do today, per guest.

    `kind` matters only on Android, where the APK path gets `-t 150` rather
    than 120: `dirwatch.c:653` arms a 180s timer over the trace, so 150 leaves
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
        # **`--disable-sysret` DOES cost information, and was adopted anyway on
        # 2026-08-29.** It stops hooking syscall returns, so the trace still
        # shows that a sample called openat/connect/execve and with what
        # arguments, but not whether any of it succeeded and not the fd or
        # handle that came back. Attempted behaviour stays visible; outcomes do
        # not.
        #
        # What bought it: 2.06x on this host -- 415 -> 856 syscalls/s -- and
        # Dom0 coming off saturation entirely, against four levers that do NOT
        # remove events (CPU placement, -F, compiler hardening) which moved
        # nothing beyond 0.6%. Full series in baremetal-trial.md Part H.
        #
        # §F7a declined this trade on the grounds that it costs return values.
        # What overturned it is that nothing consumes them: `disable_sysret`
        # appears in the platform only as a UI default and a template, the
        # trace JSONL is collected and uploaded as an artifact, and no code in
        # this repository parses it. **That is the condition of the trade, not
        # a footnote** -- a return-value consumer added later (CAPA is on
        # ideas.md) makes this silent data loss, and whoever adds one owns
        # revisiting this line.
        #
        # DRAFT-052's syscall filter is strictly better and would replace it:
        # it removes syscall ENTRIES too while keeping returns for the calls
        # actually analysed. Blocked on a curated list of what detection needs.
        return TraceOptions(plugins=_LINUX_PLUGINS, timeout=120,
                            fast_singlestep=True, disable_sysret=True)

    if os_ is TargetOs.ANDROID:
        return TraceOptions(
            plugins=_LINUX_PLUGINS,
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
    # `_WINDOWS_PLUGINS` is deliberately its own name even though it currently
    # equals `_LINUX_PLUGINS`. The equality is a starting point that should be
    # free to change; sharing the tuple would make an edit to the Linux set
    # silently become an edit to this one. `test_guests.py` pins that this
    # branch reads its own name.
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


@dataclass(frozen=True)
class GuestPaths:
    """Where a sample lands inside the guest, per OS.

    From `pipeline-<os>.env`. `/data/local/tmp` is not arbitrary: it pre-exists
    in the saved Android image and permits execution, where
    `/storage/self/primary/Download` is a noexec mount on which `chmod` is
    silently a no-op.
    """

    staging_dir: str
    shell: str
    nameserver: str = "1.1.1.1"


PATHS = {
    TargetOs.UBUNTU: GuestPaths(staging_dir="/home/carlos/Desktop",
                                shell="/usr/bin/sh"),
    # /system/bin/sh, not /usr/bin/sh: the Ubuntu path does not exist here. No
    # sudo and no `su -c` either -- the guest is already root and ships
    # neither. All three measured by DRAFT-013.
    TargetOs.ANDROID: GuestPaths(staging_dir="/data/local/tmp",
                                 shell="/system/bin/sh"),

    TargetOs.WINDOWS: GuestPaths(staging_dir="C:\\Users\\carlos\\Desktop",
                                 shell="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
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
        f"\"netsh interface ip set address name=\\\"Local Area Connection\\\" static {subnet}.{job.vlan}.2 255.255.255.0 {subnet}.{job.vlan}.1 && netsh interface ip set dns name=\\\"Local Area Connection\\\" static ${ns} validate=no\""
        )


def argv_configure_network(job: Job, subnet: str = "172.16") -> list[str]:
    """Give the clone its address. A separate injection from delivery.

    The guest-side text is ONE argument to `sh -c`. It reaches the guest as a
    single `execve` element and no Dom0 shell ever sees it, which is what makes
    the mixed-expansion Android form safe -- Dom0 interpolates only the vlan
    and the nameserver; everything else expands in the guest.
    """
    shell = PATHS[job.target_os].shell

    if job.target_os == TargetOs.ANDROID:
        script = (_android_netcfg(job, subnet))
    elif job.target_os == TargetOs.UBUNTU:
        script = (_ubuntu_netcfg(job, subnet))
    elif job.target_os == TargetOs.WINDOWS:
        script = (_windows_netcfg(job, subnet))

    mode = "shellexec" if job.target_os == TargetOs.WINDOWS else "execproc"
    launch_command = "-Command -NoProfile -ExecutionPolicy Bypass" if job.target_os == TargetOs.WINDOWS else "-c"

    return [
        "injector", "-r", str(job.profile), "-d", str(job.domid),
        "-i", str(job.injection_pid), "-m", mode,
        "-e", shell, "-f", launch_command, "-f", script,
    ]


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

def argv_trace(job: Job, component: str | None = None) -> list[str]:
    """The DRAKVUF invocation.

    Two execution paths, selected from the sample's bytes: an APK is LAUNCHED,
    already installed, via `am start -n`; anything else is `execve`d directly.
    """
    mode = "shellexec" if job.target_os == TargetOs.WINDOWS else "execproc"

    argv = [
        "drakvuf", "-r", str(job.profile), "-d", str(job.domid),
        "-i", str(job.injection_pid), "-m", mode,
    ]

    if job.kind is SampleKind.APK:
        if not component:
            raise ValueError(
                "an APK trace needs a launcher component; preconfig resolves "
                "it and a missing one means resolve-activity returned a "
                "diagnostic -- nothing should be executed"
            )
        argv += ["-e", "/system/bin/am", "-f", "start", "-f", "-n",
                 "-f", component]
    else:
        argv += ["-e", job.guest_sample]

    argv += job.options.drakvuf_flags()
    argv += ["-o", "json", "-t", str(job.options.timeout)]
    for plugin in job.options.plugins:
        argv += ["-a", plugin]
    argv += ["-D", str(job.result_dir / "dump"),
             "--memdump-dir", str(job.result_dir / "memdump")]
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
    if component.count("/") != 1:
        return False
    if not component:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyz"
                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                  "0123456789._/$-")
    return all(c in allowed for c in component)