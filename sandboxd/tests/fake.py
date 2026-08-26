"""A recording stand-in for Dom0.

Issue #41 (DRAFT-060).

`xl`, `lvcreate`, `lvremove`, `lvdisplay`, `injector`, `drakvuf` and `tcpdump`
are not present in the development container and must not be assumed to be
(CLAUDE.md, "Infrastructure boundary"). This records what would have been run
and answers with whatever the test scripted.

**It records argv, never a rendered command line.** A fake that joined
arguments into a string for convenience would let a test pass while the real
code built something a shell would have re-split -- which is precisely the
class of bug #41 exists to remove, hidden by the tool meant to catch it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sandboxd.proc import Completed


@dataclass
class Call:
    argv: tuple[str, ...]
    timeout: float | None = None
    what: str | None = None
    check: bool = False
    stdout_path: str | None = None
    stderr_path: str | None = None
    kind: str = "run"


@dataclass
class FakeRunner:
    """Answers by first-match on argv prefix; records everything.

    Scripted responses are keyed on a tuple prefix rather than on a substring,
    so a rule for `("xl", "domid")` cannot accidentally also answer
    `("xl", "destroy")`.
    """

    responses: list = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    default: Completed | None = None
    # Present by default: this container has none of them, and a test about
    # lvcreate ordering should not have to declare that lvcreate exists. Set to
    # a set of names to make specific tools missing.
    tools_present: bool | set = True

    def which(self, name: str) -> str | None:
        if self.tools_present is True:
            return f"/usr/sbin/{name}"
        return f"/usr/sbin/{name}" if name in self.tools_present else None

    def script(self, prefix: tuple[str, ...], *, rc: int = 0, stdout: str = "",
               stderr: str = "", timed_out: bool = False, times: int | None = None):
        self.responses.append({"prefix": prefix, "rc": rc, "stdout": stdout,
                               "stderr": stderr, "timed_out": timed_out,
                               "times": times})
        return self

    # -- the Runner interface ------------------------------------------------

    def run(self, argv, *, timeout=None, what=None, check=False,
            stdout_path=None, stderr_path=None, env=None) -> Completed:
        argv_t = self._record(argv, timeout, what, check, stdout_path,
                              stderr_path, "run")
        result = self._answer(argv_t, timeout)
        # A real command given an output path writes to it. Without this the
        # collect stage finds an empty result directory and every manifest
        # test passes vacuously -- the fake would be hiding the stage it exists
        # to exercise.
        self._write_outputs(stdout_path, result.stdout, stderr_path,
                            result.stderr)
        if check and not result.ok:
            from sandboxd.proc import CommandError
            raise CommandError(what or argv_t[0], result)
        return result

    def spawn(self, argv, *, stdout_path=None, stderr_path=None, capture=False,
              env=None):
        self._record(argv, None, None, False, stdout_path, stderr_path, "spawn")
        return FakeChild(tuple(argv))

    @staticmethod
    def _write_outputs(stdout_path, stdout, stderr_path, stderr) -> None:
        for path, text in ((stdout_path, stdout), (stderr_path, stderr)):
            if path is None:
                continue
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text or "")

    # -- internals -----------------------------------------------------------

    def _record(self, argv, timeout, what, check, stdout_path, stderr_path, kind):
        if isinstance(argv, (str, bytes)):
            raise TypeError(
                "argv must be a list of strings -- the fake refuses a string "
                "for the same reason proc.run does, so a test cannot pass "
                "against a command line the real runner would reject"
            )
        argv_t = tuple(argv)
        for i, a in enumerate(argv_t):
            if not isinstance(a, str):
                raise TypeError(f"argv[{i}] is {type(a).__name__}, not str: {a!r}")
        self.calls.append(Call(
            argv=argv_t, timeout=timeout, what=what, check=check,
            stdout_path=str(stdout_path) if stdout_path else None,
            stderr_path=str(stderr_path) if stderr_path else None,
            kind=kind,
        ))
        return argv_t

    def _answer(self, argv_t, timeout) -> Completed:
        for rule in self.responses:
            n = len(rule["prefix"])
            if argv_t[:n] != rule["prefix"]:
                continue
            if rule["times"] is not None:
                if rule["times"] <= 0:
                    continue
                rule["times"] -= 1
            return Completed(argv=argv_t, returncode=rule["rc"],
                             stdout=rule["stdout"], stderr=rule["stderr"],
                             duration=0.0, timed_out=rule["timed_out"])
        if self.default is not None:
            return self.default
        return Completed(argv=argv_t, returncode=0, stdout="", stderr="",
                         duration=0.0)

    # -- assertions ----------------------------------------------------------

    def argvs(self, kind: str | None = None) -> list[tuple[str, ...]]:
        return [c.argv for c in self.calls if kind is None or c.kind == kind]

    def find(self, prefix: tuple[str, ...]) -> list[tuple[str, ...]]:
        n = len(prefix)
        return [a for a in self.argvs() if a[:n] == prefix]

    def ran(self, prefix: tuple[str, ...]) -> bool:
        return bool(self.find(prefix))

    def order_of(self, prefix: tuple[str, ...]) -> int | None:
        n = len(prefix)
        for i, a in enumerate(self.argvs()):
            if a[:n] == prefix:
                return i
        return None


@dataclass
class FakeChild:
    argv: tuple[str, ...]
    stopped: bool = False
    pid: int = 4242

    @property
    def pgid(self) -> int:
        return self.pid

    def running(self) -> bool:
        return not self.stopped

    def stop(self, *, grace: float = 5.0):
        self.stopped = True
        return Completed(argv=self.argv, returncode=0, stdout="", stderr="",
                         duration=0.0)
