"""The seam between sandboxd and Dom0.

Issue #41 (DRAFT-060).

Every stage takes a `Runner` instead of calling `proc` directly, for one
reason: `xl`, `lvcreate`, `lvremove`, `lvdisplay`, `injector`, `drakvuf` and
`tcpdump` do not exist in the development container and must not be assumed to
(CLAUDE.md, "Infrastructure boundary"). A recording fake in their place makes
every stage testable at the desk.

**This is where mocking belongs, and where it stops.** `proc` itself is tested
against real processes: process groups, zombie reaping, signal escalation and
pipe buffers are the things that go subtly wrong, and a mocked `killpg` returns
whatever the test author already believed. Two real bugs in this module's first
draft -- both of them a null-signal poll that could not see a zombie -- were
found by `/bin/sleep` and would have passed against a mock.

So: real processes below this line, fakes above it.
"""

from __future__ import annotations

from pathlib import Path

from . import proc


class Runner:
    """Calls the real thing. One instance per daemon.

    The seam is "everything that touches the host", not just "everything that
    spawns a process" -- which is why `which` is here. Resolving a tool against
    the real PATH is as much a Dom0 dependency as running it, and leaving it on
    `shutil` made the clone builder untestable in a container that correctly
    has no `xl`.
    """

    def which(self, name: str) -> str | None:
        import shutil
        return shutil.which(name)

    def run(
        self,
        argv: list[str],
        *,
        timeout: float,
        what: str | None = None,
        check: bool = False,
        stdout_path: str | Path | None = None,
        stderr_path: str | Path | None = None,
        env: dict[str, str] | None = None,
    ) -> proc.Completed:
        return proc.run(argv, timeout=timeout, what=what, check=check,
                        stdout_path=stdout_path, stderr_path=stderr_path,
                        env=env)

    def spawn(
        self,
        argv: list[str],
        *,
        stdout_path: str | Path | None = None,
        stderr_path: str | Path | None = None,
        capture: bool = False,
        env: dict[str, str] | None = None,
    ) -> proc.Child:
        return proc.spawn(argv, stdout_path=stdout_path,
                          stderr_path=stderr_path, capture=capture, env=env)
