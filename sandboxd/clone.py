"""Building one disposable clone. The port of `automation/clone.pl`.

Issue #41 (DRAFT-060).

#41 originally scoped `clone.pl` OUT -- "it is Perl on a fixed 3-argument
contract, holds no OS-specific value, and works. Leave it." That was reversed
on 2026-08-26, and the argument for reversing it is the issue's own thesis:

    sub run {
        my ($what, @argv) = @_;
        my $cmd = join(' ', @argv);      # <- argv joined into a string
        my $out = `$cmd 2>&1`;           # <- executed by a shell
    }

`clone.pl` is the last shell-string builder in the pipeline. So are its
`which lvcreate`, `xl domid $clone` and `cat $config` backticks. Leaving it in
place while #41 removes every other shell from Dom0 would leave the one
component that runs `lvremove -f` on a device path built by interpolation.

Three things come free with the port, all of them defects in how dirwatch used
the script rather than in the script itself:

  * **The exit status is read.** `dirwatch.c:369` passes NULL for `exit_rc`, so
    clone.pl's carefully separated codes -- EXIT_PRECHECK, EXIT_LOCKED,
    EXIT_LVM=5, EXIT_RESTORE=6 -- are computed and thrown away, and every
    failure looks identical: no domain id on stdout. Here they become distinct
    reasons on the job row.
  * **stdout stops being a protocol.** clone.pl must print the domain id and
    nothing else, ever, because dirwatch parses whatever it prints as a domain
    id -- which is why every diagnostic in it is carefully routed to stderr.
  * **The lock stops being advisory-by-accident.** clone.pl proceeds without
    the cross-process lock if `/run/lock` is unwritable, because refusing to
    work would be worse. One daemon owning every clone makes the in-process
    case structural, and the file lock stays only as the guard against a
    concurrently-running dirwatch during migration.

Everything the script LEARNED is carried across with its reason. In particular
the wait after `xl destroy`, which is not defensive coding: it was measured.
"""

from __future__ import annotations

import fcntl
import os
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .naming import clone_name
from .proc import CommandError

# `xl destroy` returns before the block device is released -- measured on Dom0
# 2026-08-14, where lvremove reported "Logical volume in use" and succeeded on
# a retry (docs/runbooks/verify-android-isolation.md:965, annotated :996).
# Waiting is what makes the lvremove that follows reliable.
DESTROY_SETTLE_SECONDS = 10

# clone.pl retries the flock 30 times at 1s. Non-blocking with a bounded
# retry, never a blocking LOCK_EX: nothing upstream imposes a timeout on the
# clone step, so a blocking acquire would hang a worker with no way out.
LOCK_RETRY_SECONDS = 30

# Individual Dom0 commands. Generous, because the failure mode of a short
# timeout here is a torn-down clone that would have worked; lvcreate on a busy
# VG and xl restore of a 2 GiB memory image are both legitimately slow.
CMD_TIMEOUT = 120.0

REQUIRED_TOOLS = ("lvcreate", "lvremove", "lvdisplay", "xl")


class CloneError(RuntimeError):
    """Carries the stage that failed, so the job row can say which.

    `stage` replaces clone.pl's exit codes, which dirwatch discarded.
    """

    def __init__(self, stage: str, message: str, *hints: str):
        self.stage = stage
        super().__init__("\n".join([message, *(f"  {h}" for h in hints)]))


@dataclass(frozen=True)
class CloneSpec:
    origin: str          # the sandbox TEMPLATE domain, e.g. ubuntu_sandbox
    vlan: int
    config: Path         # misc/<origin>.cfg
    saved_state: Path    # state/<origin>.bak
    vg: str = "vg-root"
    bridge: str = "xenbr1"
    lv_size: str = "64G"
    vif_script: str = "script=vif-openvswitch"

    @property
    def name(self) -> str:
        return clone_name(self.origin, self.vlan)


# --- the config rewrite, as a pure function --------------------------------
#
# Separated from everything that touches Dom0 so it can be tested against the
# real misc/*.cfg files here. misc/android_sandbox.cfg records that this
# rewrite "reproduces byte-for-byte what verify-android-isolation.md step 2
# wrote out by hand", verified 2026-08-15 -- so it has a known-correct output
# and the port is checkable against it rather than merely plausible.

_NAME = re.compile(r"^\s*name\s*=")
_VIF = re.compile(r"^\s*vif\s*=")
_DISK = re.compile(r"^\s*disk\s*=")
_VIF_INNER = re.compile(r"\[\s*['\"](.+?)['\"]\s*\]")
_DROP_VIF_OPTS = re.compile(r"^(?:bridge|script|backend)\s*=")


def rewrite_config(text: str, spec: CloneSpec) -> str:
    """Turn the template's Xen config into the clone's.

    Three lines change and everything else passes through untouched, comments
    included -- which is deliberate: the templates carry load-bearing comments
    about `altp2m`, `hap` and `viridian`, and a rewrite that dropped them would
    hand the next reader a config with no explanation of why introspection
    settings must not be changed.
    """
    out = []
    for line in text.splitlines():
        if _NAME.match(line):
            out.append(f'name = "{spec.name}"')
            continue

        if _VIF.match(line):
            inner = _VIF_INNER.search(line)
            if not inner:
                raise CloneError("config", f"unable to parse VIF configuration: {line}")
            values = []
            for value in inner.group(1).split(","):
                value = value.strip()
                if not value:
                    continue
                # Whatever the template said about the bridge is discarded, not
                # merged: a clone must land on its OWN vlan sub-interface
                # regardless, and inheriting `bridge=xenbr1` would put it on
                # the trunk with no isolation rules.
                if _DROP_VIF_OPTS.match(value):
                    continue
                values.append(value)
            for option in spec.vif_script.split(","):
                option = option.strip()
                if option:
                    values.append(option)
            values.append(f"bridge={spec.bridge}.{spec.vlan}")
            out.append("vif = [ '" + ",".join(values) + "' ]")
            continue

        if _DISK.match(line):
            out.append(f"disk = [ 'phy:/dev/{spec.vg}/{spec.name},hda,w' ]")
            continue

        out.append(line)

    return "\n".join(out) + "\n"


# --- argv builders, also pure ----------------------------------------------
#
# Every Dom0 command in one place, as lists. Tested against the literal
# commands clone.pl runs today, which is #41's parity criterion proved at the
# desk rather than on the machine.

def argv_lvdisplay(spec: CloneSpec, target: str) -> list[str]:
    return ["lvdisplay", f"/dev/{spec.vg}/{target}"]


def argv_lvremove(spec: CloneSpec, target: str) -> list[str]:
    return ["lvremove", "-f", f"/dev/{spec.vg}/{target}"]


def argv_lvcreate(spec: CloneSpec) -> list[str]:
    # -L<size> with no space, exactly as clone.pl emits it. An empty size would
    # make lvcreate read the device path as its size operand, which is why
    # clone.pl treats an exported-but-empty CLONE_LV_SIZE as unset.
    if not spec.lv_size:
        raise CloneError("lvm", "lv_size is empty; lvcreate would take the "
                                "device path as its size operand")
    return ["lvcreate", "-s", "-n", spec.name, f"-L{spec.lv_size}",
            f"/dev/{spec.vg}/{spec.origin}"]


def argv_xl_domid(name: str) -> list[str]:
    return ["xl", "domid", name]


def argv_xl_destroy(name: str) -> list[str]:
    return ["xl", "destroy", name]


def argv_xl_restore(clone_config: Path, saved_state: Path) -> list[str]:
    # -p leaves the domain PAUSED: injector and drakvuf attach to a stopped
    # domain and unpause it themselves. -e detaches so xl does not stay in the
    # foreground for the life of the domain.
    return ["xl", "restore", "-p", "-e", str(clone_config), str(saved_state)]


# --- the build -------------------------------------------------------------

@contextmanager
def _as_clone_error(stage: str):
    """Give a failed command the stage it failed at.

    Every failure leaving this module is a `CloneError` carrying a stage, so a
    caller can put a real reason on the job row. `CommandError` alone would be
    a regression dressed as a port: dirwatch.c:369 passes NULL for `exit_rc`,
    which is exactly why every clone failure today is indistinguishable from
    every other one.
    """
    try:
        yield
    except CommandError as exc:
        raise CloneError(stage, str(exc)) from exc


@dataclass
class Clone:
    name: str
    domid: int
    vlan: int
    config_path: Path


class CloneBuilder:
    def __init__(self, runner, *, lock_dir: Path = Path("/run/lock"),
                 config_dir: Path = Path("/tmp")):
        self._run = runner
        self._lock_dir = lock_dir
        self._config_dir = config_dir

    def build(self, spec: CloneSpec) -> Clone:
        """Precheck, snapshot, restore. Raises CloneError naming the stage.

        Order is clone.pl's and is not arbitrary: everything that can be
        checked without creating state is checked first, so a wrong origin or
        an unreadable saved image costs nothing and names itself instead of
        surfacing three steps later as an opaque lvcreate error about a device
        nobody meant.
        """
        name = spec.name  # validates origin charset and vlan range
        self._check_tools()

        with self._clone_lock(name):
            self._destroy_stale(name)
            self._precheck(spec)
            config_path = self._write_config(spec)
            created_lv = False
            try:
                self._remove_stale_lv(spec)
                with _as_clone_error("lvm"):
                    self._run.run(argv_lvcreate(spec), timeout=CMD_TIMEOUT,
                                  what="lvcreate of the clone snapshot",
                                  check=True)
                created_lv = True
                with _as_clone_error("restore"):
                    self._run.run(argv_xl_restore(config_path, spec.saved_state),
                                  timeout=CMD_TIMEOUT, what="xl restore",
                                  check=True)
                domid = self._domid(name)
                if domid is None:
                    raise CloneError(
                        "restore",
                        f"xl restore reported success but no domain id came "
                        f"back for {name!r}",
                    )
            except Exception:
                # A half-built clone must not survive to block the next run for
                # this vlan: clone.pl's END block, made explicit.
                if created_lv:
                    self._run.run(argv_lvremove(spec, name), timeout=CMD_TIMEOUT,
                                  what="cleanup lvremove")
                config_path.unlink(missing_ok=True)
                raise

        return Clone(name=name, domid=domid, vlan=spec.vlan,
                     config_path=config_path)

    # -- steps --------------------------------------------------------------

    def _check_tools(self) -> None:
        """Name the missing binary, rather than failing three steps later.

        Resolved through the runner, not `shutil` directly: looking a tool up
        on the real PATH is as much a Dom0 dependency as running it, and doing
        it outside the seam made this whole class untestable in a container
        that correctly has no `xl`.

        No subshell either. clone.pl needs `2>/dev/null` on its `which` to
        suppress two kinds of noise -- the shell's own "no lvcreate in ..." and
        a "Can't exec which" warning when `which` itself is absent -- neither
        of which can arise without a shell.
        """
        missing = [t for t in REQUIRED_TOOLS if self._run.which(t) is None]
        if missing:
            raise CloneError(
                "precheck",
                f"required command(s) not found in PATH: {', '.join(missing)}",
                "This runs on Xen Dom0 and needs LVM and the Xen CLI.",
                f"PATH={os.environ.get('PATH', '(unset)')}",
            )

    def _clone_lock(self, name: str):
        """Per CLONE NAME, never per origin.

        Per-origin would be worse than no lock: every worker clones the same
        origin concurrently, so it would serialise the whole pipeline to one
        analysis at a time -- a throughput bug dressed as a safety fix.

        The in-process case is now structural -- one daemon allocates every
        vlan from one table, so two clones cannot share a name. This file lock
        remains for the case that survives migration: a `dirwatch` started
        against the same origin while sandboxd is running. The launcher guard
        is supposed to prevent that; this is the layer that does not depend on
        a pgrep being right.
        """
        from contextlib import contextmanager

        @contextmanager
        def _lock():
            path = self._lock_dir / f"drakvuf-clone-{name}.lock"
            try:
                fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
            except OSError as exc:
                # clone.pl's judgement, kept: a read-only or absent /run/lock
                # must not stop a clone. The lock guards a rare cross-process
                # case and refusing to work without it is the worse failure.
                print(f"sandboxd: cannot open {path} ({exc}); "
                      f"proceeding without the cross-process lock")
                yield None
                return
            try:
                deadline = time.monotonic() + LOCK_RETRY_SECONDS
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise CloneError(
                                "locked",
                                f"another process is already cloning {name!r} "
                                f"(held {path} for >{LOCK_RETRY_SECONDS}s)",
                                "Two orchestrators against the same origin "
                                "collide on clone names. Run one.",
                            )
                        time.sleep(1)
                yield fd
            finally:
                os.close(fd)

        return _lock()

    def _domid(self, name: str) -> int | None:
        """The domain id, or None. Never a diagnostic mistaken for one.

        clone.pl has to be careful here because dirwatch parses its stdout;
        the check survives for a different reason. `xl restore` can exit 0 and
        still leave no usable domain, so a successful exit is not evidence that
        there is something to trace.
        """
        result = self._run.run(argv_xl_domid(name), timeout=CMD_TIMEOUT,
                               what="xl domid")
        text = result.stdout.strip()
        return int(text) if re.fullmatch(r"[0-9]+", text) else None

    def _destroy_stale(self, name: str) -> None:
        """A clone from a previous run under this name.

        Exit status checked, unlike before DRAFT-033: a destroy that fails
        leaves the LV open, which makes the lvremove fail too -- and both used
        to pass silently, after which `xl restore` landed on the PREVIOUS
        sample's snapshot. That is cross-sample contamination, not a crash, so
        nothing reported it.
        """
        if self._domid(name) is None:
            return

        self._run.run(argv_xl_destroy(name), timeout=CMD_TIMEOUT,
                      what=f"xl destroy of the stale clone {name!r}", check=True)

        deadline = time.monotonic() + DESTROY_SETTLE_SECONDS
        while time.monotonic() < deadline:
            if self._domid(name) is None:
                return
            time.sleep(1)

    def _precheck(self, spec: CloneSpec) -> None:
        if not spec.config.is_file():
            raise CloneError("precheck", f"domain config not found: {spec.config}")
        if not os.access(spec.config, os.R_OK):
            raise CloneError("precheck", f"domain config not readable: {spec.config}")
        if not os.access(spec.saved_state, os.R_OK):
            raise CloneError(
                "precheck",
                f"saved memory image not found or unreadable: {spec.saved_state}",
                "Expected <repo root>/state/<origin domain>.bak",
            )
        origin = self._run.run(argv_lvdisplay(spec, spec.origin),
                               timeout=CMD_TIMEOUT, what="lvdisplay of the origin LV")
        if not origin.ok:
            raise CloneError(
                "precheck",
                f"origin logical volume not found: /dev/{spec.vg}/{spec.origin}",
                f"VG_NAME={spec.vg}. Check `lvs` and the origin domain argument.",
            )

    def _remove_stale_lv(self, spec: CloneSpec) -> None:
        """Normal, not exceptional: nothing else deletes clone LVs, so one
        survives every analysis -- cleanup destroys the domain only."""
        present = self._run.run(argv_lvdisplay(spec, spec.name),
                                timeout=CMD_TIMEOUT, what="lvdisplay")
        if not present.ok:
            return
        removed = self._run.run(argv_lvremove(spec, spec.name), timeout=CMD_TIMEOUT,
                                what="lvremove of the stale clone LV")
        if not removed.ok:
            raise CloneError(
                "lvm",
                removed.stderr.strip() or "lvremove of the stale clone LV failed",
                "A clone LV still open means a domain has not finished dying. "
                "Check `xl list` and `lvs`.",
                "Proceeding would have restored onto the PREVIOUS sample's "
                "snapshot.",
            )

    def _write_config(self, spec: CloneSpec) -> Path:
        text = spec.config.read_text()
        path = self._config_dir / f"{spec.name}.config"
        path.write_text(rewrite_config(text, spec))
        return path
