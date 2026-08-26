"""Running external commands. The only module that may import subprocess.

Issue #41 (DRAFT-060).

**argv, never a string, and `shell` is not a parameter of anything here.** That
is the whole containment argument of #41 and it is one keyword deep, so it is
enforced by a test (`test_proc.py`) rather than by convention: nothing outside
this module imports `subprocess`, and there is exactly ONE `Popen` call in the
codebase -- below, with `shell=False` written out.

Written out, not left to the default. The default is `False` and the behaviour
would be identical; the point is that a reader auditing the security property
greps for `shell=False` and finds code rather than a comment claiming it.

The reason is not hygiene. The pipeline this replaces has been bitten three
times by text becoming code -- DRAFT-030 (a sample named `a b.exe` split into
two arguments), DRAFT-031 (a shebang below the licence header, so GLib fell
back to /bin/sh for five root-run scripts), and the `sh -c '...' sh "$1"` idiom
CLAUDE.md dedicates a section to. `clone.pl` still does it today: its `run()`
joins argv with spaces and executes the result in backticks. DRAFT-052 and
DRAFT-059 then want to add an operator-supplied entry point and run command,
which is untrusted text entering an execution path one layer deeper than the
bug DRAFT-030 fixed.

An operator command is trusted to be GUEST-scoped, not benign: whoever can
submit can already detonate malware of their choosing, so a hostile command in
the guest costs one clone. What must never happen is that text reaching a shell
on Dom0, which holds the worker token, the volume group and reachability to
every clone. Passing a list is what makes that structural.

## Process groups, not processes

Every child starts in its own session (`start_new_session=True`), and
everything that kills one kills the whole group.

`drakvuf` and `injector` fork; killing the direct child can leave descendants
running against a domain that is about to be destroyed. The pipeline this
replaces could not do better -- `cleanup.sh` is a SIBLING process spawned with
only `(domid, vlan)`, so `ps aux | grep injector` was its only way to find
grandchildren it had no handle on. That grep also carries a live defect
(DRAFT-011): `grep "tcpdump -i xenbr1.$VLAN"` treats `.` as a wildcard, so
vlan 1 matches `xenbr1.10` through `xenbr1.19` once there are more than nine
clones.

sandboxd spawns `injector`, `drakvuf` and `tcpdump` itself, so it holds the
handles and the grep disappears rather than being fixed.
"""

from __future__ import annotations

import os
import signal
import subprocess  # noqa: S404 -- the one permitted import; see module docstring
import time
from dataclasses import dataclass, field
from pathlib import Path

# cleanup.sh sends SIGINT, sleeps 5, then sends SIGKILL. Reproduced because the
# interval is doing real work: DRAKVUF flushes and detaches its introspection
# state on SIGINT, and killing it outright can leave the domain with stealth
# breakpoints still written into guest memory.
DEFAULT_GRACE = 5.0


class CommandError(RuntimeError):
    """A command failed, with enough context to act on.

    Carries the argv rather than a rendered command line: there is no shell in
    this path, so a copy-pasteable string would be a fiction, and printing one
    is how a reader comes to believe there was one.
    """

    def __init__(self, what: str, result: Completed):
        self.what = what
        self.result = result
        detail = result.stderr.strip() or result.stdout.strip() or "(no output)"
        how = (f"timed out after {result.duration:.1f}s" if result.timed_out
               else f"exited {result.returncode}")
        super().__init__(f"{what} {how}\n  argv: {result.argv}\n  output: {detail}")


@dataclass(frozen=True)
class Completed:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def _validate(argv: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    """Refuse an argv that is not a list of clean strings.

    A bare string is the mistake this module exists to prevent, and
    `subprocess` accepts one silently: with `shell=False` it treats the whole
    string as a program name, so `run("xl destroy foo")` looks for a binary
    literally called `xl destroy foo` and fails with a confusing ENOENT rather
    than with the real problem.

    NUL is refused because execve truncates at it -- everything after is
    silently dropped, so the argument that arrives is not the one written.
    """
    if isinstance(argv, (str, bytes)):
        raise TypeError(
            "argv must be a list of strings, not a string -- this module never "
            "builds a command line; see the module docstring"
        )
    if not argv:
        raise ValueError("argv is empty")
    out = []
    for i, a in enumerate(argv):
        if not isinstance(a, str):
            raise TypeError(f"argv[{i}] is {type(a).__name__}, not str: {a!r}")
        if "\0" in a:
            raise ValueError(f"argv[{i}] contains NUL, which execve truncates at")
        out.append(a)
    return tuple(out)


def _sink(path, capture):
    if path is not None:
        return open(path, "wb")
    return subprocess.PIPE if capture else subprocess.DEVNULL


@dataclass
class Child:
    """A running command. The only thing that owns a process here.

    `run()` is this plus an immediate `wait()`. There is one spawn primitive
    rather than two because exactly one caller -- `tcpdump`, which runs
    alongside the trace -- needs a handle that outlives the call, and a second
    `Popen` site would be a second place for `shell=False` to be right.
    """

    argv: tuple[str, ...]
    _proc: subprocess.Popen = field(repr=False)
    _started: float = field(repr=False, default_factory=time.monotonic)

    @property
    def pid(self) -> int:
        return self._proc.pid

    @property
    def pgid(self) -> int:
        """Recorded with the lease so a RESTARTED sandboxd can still reach it.

        The normal path never needs it -- the handle is right here -- but a
        sandboxd that died left its children orphaned and reparented, and the
        replacement has no `Popen` for them. See `sweep.py`.
        """
        return os.getpgid(self._proc.pid)

    def running(self) -> bool:
        return self._proc.poll() is None

    def wait(self, *, timeout: float | None = None,
             grace: float = DEFAULT_GRACE) -> Completed:
        """Wait for completion; on timeout kill the GROUP and still return.

        A timeout is a result, not an exception: the caller has a clone to tear
        down and a job row to update either way, and the 60s/180s guards this
        replaces both end in cleanup rather than in a stack trace.
        """
        timed_out = False
        try:
            out_b, err_b = self._proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill(grace=grace)
            # The group is gone, so this returns at once. Without it the pipes
            # stay open and the child stays a zombie.
            out_b, err_b = self._proc.communicate()
        return Completed(
            argv=self.argv,
            returncode=self._proc.returncode,
            stdout=_text(out_b),
            stderr=_text(err_b),
            duration=time.monotonic() - self._started,
            timed_out=timed_out,
        )

    def stop(self, *, grace: float = DEFAULT_GRACE) -> Completed:
        """Signal the group and collect. Used for `tcpdump` at end of trace."""
        if self.running():
            self._kill(grace=grace)
        return self.wait()

    def _kill(self, *, grace: float) -> None:
        """SIGINT the group, wait for OUR child, then SIGKILL the group.

        `self._proc.wait()` and not a `killpg(pgid, 0)` poll, and the
        difference is not academic. Signal 0 is the null signal -- it runs the
        kernel's existence-and-permission check and delivers nothing -- but a
        child that has exited and not yet been reaped is a ZOMBIE, and a zombie
        still has a process-table entry. Polling it with signal 0 keeps
        succeeding, so the loop would burn the whole grace period on every
        timeout and then SIGKILL a corpse.

        `wait()` is exact and reaps. The null-signal poll is right only for
        pids we did not fork, which is `kill_pid_group()` below.
        """
        try:
            pgid = os.getpgid(self._proc.pid)
        except ProcessLookupError:
            return
        try:
            os.killpg(pgid, signal.SIGINT)
        except ProcessLookupError:
            return
        try:
            self._proc.wait(timeout=grace)
            # The leader is gone. Descendants in the group may not be -- this
            # is the case the whole process-group approach exists for.
            _killpg_quiet(pgid, signal.SIGKILL)
            return
        except subprocess.TimeoutExpired:
            _killpg_quiet(pgid, signal.SIGKILL)


def spawn(
    argv: list[str],
    *,
    stdout_path: str | Path | None = None,
    stderr_path: str | Path | None = None,
    capture: bool = False,
    env: dict[str, str] | None = None,
) -> Child:
    """Start a command in its own process group.

    `capture=False` by default, and that default matters for a long-lived
    child: piping a stream nobody reads fills the pipe buffer and blocks the
    writer. `tcpdump` left on a PIPE would stall mid-capture. `run()` passes
    `capture=True` because `communicate()` drains both concurrently.

    **`stdout_path` and `stderr_path` are separate and there is deliberately no
    way to merge them.** Every trace in the pipeline this replaces runs
    `1>"$OUT/drakvuf.log" 2>&1`, merging DRAKVUF's diagnostics into what `-o
    json` makes a pure JSONL event stream. That is what blocks capa
    (DRAFT-019), whose extractor consumes JSONL and chokes on interleaved text.
    Writing a new file is the cheapest moment to stop, so merging is not on
    offer.
    """
    argv_t = _validate(argv)
    out_f = _sink(stdout_path, capture)
    err_f = _sink(stderr_path, capture)
    try:
        proc = subprocess.Popen(  # noqa: S603 -- argv list, shell=False below
            argv_t,
            shell=False,
            stdout=out_f,
            stderr=err_f,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            env=env,
        )
    finally:
        # Only the file objects we opened; PIPE/DEVNULL are ints.
        for f in (out_f, err_f):
            if hasattr(f, "close"):
                f.close()
    return Child(argv=argv_t, _proc=proc)


def run(
    argv: list[str],
    *,
    timeout: float,
    what: str | None = None,
    check: bool = False,
    stdout_path: str | Path | None = None,
    stderr_path: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> Completed:
    """Run a command to completion. `spawn()` plus `wait()`, nothing more."""
    child = spawn(argv, stdout_path=stdout_path, stderr_path=stderr_path,
                  capture=True, env=env)
    result = child.wait(timeout=timeout)
    if check and not result.ok:
        raise CommandError(what or result.argv[0], result)
    return result


def _text(raw: bytes | None) -> str:
    """Decode output for a diagnostic, never for parsing.

    `errors="replace"`: this is guest-adjacent output and may contain anything.
    A UnicodeDecodeError while building an error message would replace the real
    failure with a decoding one.
    """
    return raw.decode("utf-8", errors="replace") if raw else ""


def _killpg_quiet(pgid: int, sig: int) -> None:
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        pass


# --- processes a PREVIOUS sandboxd left behind -----------------------------

def iter_processes() -> list[tuple[int, tuple[str, ...]]]:
    """Every visible pid with its argv, read from /proc.

    **Exact argv elements, not a regex over `ps aux` output.** This is the fix
    for DRAFT-011's live defect rather than a restatement of it:
    `/proc/<pid>/cmdline` is NUL-separated, so `xenbr1.1` and `xenbr1.10`
    compare as the different strings they are, where `grep "xenbr1.1"` matches
    both -- `.` is a wildcard and the pattern is unanchored.

    Used only by the startup sweep. A running daemon holds handles.
    """
    found: list[tuple[int, tuple[str, ...]]] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue  # exited between listdir and read, or another user's
        if not raw:
            continue  # kernel thread
        argv = tuple(p.decode("utf-8", "replace") for p in raw.split(b"\0") if p)
        if argv:
            found.append((int(entry.name), argv))
    return found


def _group_alive(pgid: int) -> bool:
    """Does the group still contain a process that is not a corpse?

    **State, not signal 0**, and the distinction cost a test failure to find.
    An exited-but-unreaped process is a ZOMBIE: it holds a process-table entry,
    so `killpg(pgid, 0)` keeps succeeding and a poll built on it never
    terminates early.

    The first version of this function reasoned that the sweep only ever meets
    ORPHANS -- a dead sandboxd's children, reparented and promptly reaped by
    init -- so zombies could not arise. That is wrong twice over: under a
    subreaper or a systemd service manager the reaper is not init, and nothing
    structurally prevents the sweep from meeting a process this daemon started.
    Reading the state answers the question directly instead of inferring it
    from who the parent is.

    See `parse_stat` for the parsing, which is separate so it can be tested
    without needing a process that has the awkward property under test.
    """
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
        except OSError:
            continue
        parsed = parse_stat(stat)
        if parsed is None:
            continue
        state, pgrp = parsed
        if pgrp == pgid and state != "Z":
            return True
    return False


def parse_stat(stat: str) -> tuple[str, int] | None:
    """(state, pgrp) from one `/proc/<pid>/stat` line, or None.

    **Parsed from the LAST ')', never by splitting the whole line.** The second
    field is the executable name, in parentheses, and the kernel does not
    escape it: a process named `we ird) name` yields
    `123 (we ird) name) S 1 456 ...`, so `stat.split()[2]` reads `name)` as the
    state and `1` as the ppid. A process can choose that name.
    """
    try:
        after = stat[stat.rindex(")") + 1:].split()
        return after[0], int(after[2])
    except (ValueError, IndexError):
        return None


def kill_pid_group(pid: int, *, grace: float = DEFAULT_GRACE) -> bool:
    """Escalate against a group we did NOT fork. True if it is gone.

    The sweep's tool: a previous sandboxd's `injector`, `drakvuf` or `tcpdump`,
    for which this process has no `Popen` and cannot `wait()`.
    """
    try:
        pgid = os.getpgid(pid)
    except ProcessLookupError:
        return True

    _killpg_quiet(pgid, signal.SIGINT)
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if not _group_alive(pgid):
            return True
        time.sleep(0.1)

    _killpg_quiet(pgid, signal.SIGKILL)
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if not _group_alive(pgid):
            return True
        time.sleep(0.1)
    return False
