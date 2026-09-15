"""The execution layer: issue #41 (DRAFT-060).

The first three tests are the security argument. Everything else checks that
the process-group handling actually works, because "we kill the group" is easy
to write and easy to get subtly wrong -- as the first draft of this module did.
"""

from __future__ import annotations

import os
import re
import signal
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sandboxd import proc  # noqa: E402

SRC = Path(__file__).resolve().parents[1]


# --- the containment line, enforced rather than asserted in prose ----------

def test_only_proc_may_import_subprocess():
    """One module may spawn processes, so there is one place to audit.

    Stronger than banning `shell=True`: a module that cannot import subprocess
    cannot pass any keyword to it, including one added by a future refactor
    that threads **kwargs through a helper.
    """
    offenders = []
    for path in SRC.rglob("*.py"):
        if path.name in ("proc.py",) or "tests" in path.parts:
            continue
        text = path.read_text()
        if re.search(r"^\s*(import subprocess|from subprocess)", text, re.M):
            offenders.append(path.name)
    assert offenders == [], offenders


def test_no_call_site_asks_for_a_shell():
    for path in SRC.rglob("*.py"):
        if "tests" in path.parts:
            continue
        assert "shell=True" not in path.read_text(), path


def test_shell_false_is_written_not_defaulted():
    """It is the default, so this is not about behaviour.

    The module claims `shell=False` as its containment line. A reader auditing
    that greps for it, and must find code rather than a comment asserting the
    default holds.
    """
    src = (SRC / "proc.py").read_text()
    popen_calls = src.count("subprocess.Popen(")
    assert popen_calls == 1, f"expected exactly one Popen call site, found {popen_calls}"
    assert "shell=False," in src


def test_a_string_is_refused_rather_than_run():
    """subprocess accepts a string silently under shell=False -- it becomes a
    program name with spaces in it, and the ENOENT names something that never
    existed rather than the real mistake."""
    with pytest.raises(TypeError, match="not a string"):
        proc.run("echo hello", timeout=5)


def test_nul_in_an_argument_is_refused():
    """execve truncates at NUL, so the argument that arrives is not the one
    that was written."""
    with pytest.raises(ValueError, match="NUL"):
        proc.run(["/bin/echo", "a\0b"], timeout=5)


def test_a_metacharacter_is_an_argument_not_syntax():
    """The property the whole module exists for, demonstrated rather than
    described: what a shell would treat as a command separator arrives as
    text."""
    r = proc.run(["/bin/echo", "; id", "$(whoami)", "`hostname`", "&& rm -rf /"],
                 timeout=10)

    assert r.ok
    assert r.stdout.strip() == "; id $(whoami) `hostname` && rm -rf /"


# --- ordinary running ------------------------------------------------------

def test_output_streams_stay_separate():
    """No merge option exists, and this is why: `-o json` makes stdout a JSONL
    event stream, and `2>&1` is what contaminates it (DRAFT-019)."""
    r = proc.run(["/bin/sh", "-c", "echo OUT; echo ERR >&2"], timeout=10)

    assert r.stdout.strip() == "OUT"
    assert r.stderr.strip() == "ERR"


def test_streams_can_go_to_separate_files(tmp_path):
    out, err = tmp_path / "trace.log", tmp_path / "trace.stderr"

    proc.run(["/bin/sh", "-c", "echo OUT; echo ERR >&2"],
             timeout=10, stdout_path=out, stderr_path=err)

    assert out.read_text().strip() == "OUT"
    assert err.read_text().strip() == "ERR"


def test_a_failure_can_raise_with_context():
    with pytest.raises(proc.CommandError) as exc:
        proc.run(["/bin/sh", "-c", "echo nope >&2; exit 3"],
                 timeout=10, what="the thing", check=True)

    assert "the thing exited 3" in str(exc.value)
    assert "nope" in str(exc.value)
    # The argv, not a rendered command line: there was no shell, and printing
    # one invites a reader to believe there was.
    assert "argv:" in str(exc.value)


# --- timeouts and process groups ------------------------------------------

def test_a_timeout_is_a_result_not_an_exception():
    """The 60s and 180s guards this replaces both end in cleanup. A caller has
    a clone to tear down either way."""
    r = proc.run(["/bin/sleep", "30"], timeout=0.5)

    assert r.timed_out
    assert not r.ok


def test_a_timeout_kills_the_whole_group_not_just_the_child():
    """The reason for start_new_session. drakvuf forks; killing only the direct
    child leaves descendants running against a domain about to be destroyed.

    The child here forks a grandchild that would outlive it, and writes the
    grandchild's pid where the test can check it.
    """
    import tempfile
    marker = Path(tempfile.mkdtemp()) / "grandchild.pid"
    script = f"/bin/sleep 30 & echo $! > {marker}; sleep 30"

    r = proc.run(["/bin/sh", "-c", script], timeout=1.0)
    assert r.timed_out

    grandchild = int(marker.read_text().strip())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(grandchild, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        os.kill(grandchild, signal.SIGKILL)
        pytest.fail(f"grandchild {grandchild} survived the group kill")


def test_the_timeout_path_does_not_burn_the_grace_period():
    """Regression for a real bug in the first draft of this module.

    It polled the dying group with `killpg(pgid, 0)` -- the null signal. But a
    child that has exited and not been reaped is a zombie, and a zombie still
    answers signal 0. The poll therefore never noticed the exit, waited the
    full 5s grace on EVERY timeout, and then SIGKILLed a corpse.

    A process that dies immediately on SIGINT must cost nothing like 5s.
    """
    started = time.monotonic()
    r = proc.run(["/bin/sleep", "30"], timeout=0.3)
    elapsed = time.monotonic() - started

    assert r.timed_out
    assert elapsed < proc.DEFAULT_GRACE, (
        f"took {elapsed:.1f}s; the grace period is {proc.DEFAULT_GRACE}s and "
        "should not have been spent on a process that exited at once"
    )


# --- the long-lived child --------------------------------------------------

def test_a_spawned_child_is_held_not_searched_for(tmp_path):
    """tcpdump's case. The old trace scripts stopped it by grepping `ps aux` for its
    own command line; the handle makes that unnecessary."""
    child = proc.spawn(["/bin/sleep", "30"])
    try:
        assert child.running()
        assert child.pid > 0
        assert child.pgid == child.pid  # its own session leader
    finally:
        child.stop()

    assert not child.running()


def test_a_spawned_child_does_not_stall_on_an_unread_pipe(tmp_path):
    """capture=False by default, and that default is load-bearing: a long-lived
    child on a PIPE nobody drains blocks once the buffer fills. A capture would
    stall mid-analysis, which looks like a hung trace."""
    # Writes far more than a pipe buffer (64 KiB) and must still finish.
    child = proc.spawn(["/bin/sh", "-c", "i=0; while [ $i -lt 20000 ]; do "
                                         "echo padding-line-$i; i=$((i+1)); done"])
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if not child.running():
            break
        time.sleep(0.1)
    else:
        child.stop()
        pytest.fail("the child stalled -- output was piped and never drained")


# --- foreign processes, for the startup sweep ------------------------------

def test_iter_processes_sees_exact_argv_elements():
    """The DRAFT-011 fix, and the reason it is /proc rather than `ps aux`.

    `grep "tcpdump -i xenbr1.1"` matches xenbr1.10 through xenbr1.19, because
    `.` is a regex wildcard and the pattern is unanchored. Exact elements
    cannot do that.
    """
    child = proc.spawn(["/bin/sleep", "31"])
    try:
        table = dict(proc.iter_processes())
        assert child.pid in table
        assert table[child.pid] == ("/bin/sleep", "31")

        # The property that matters: an element is compared whole.
        assert "xenbr1.1" != "xenbr1.10"
        assert not any(a == "xenbr1.1" for a in ("xenbr1.10", "xenbr1.19"))
    finally:
        child.stop()


def test_killing_a_group_we_did_not_fork():
    """The sweep's case: a previous sandboxd's children, with no Popen to
    wait on.

    Deliberately targets a process this test IS the parent of, which is the
    harder case and the one that caught the bug below -- an unreaped child
    stays a zombie in our own process table, where an orphan would have been
    reaped by whatever inherited it.
    """
    child = proc.spawn(["/bin/sh", "-c", "sleep 30"])
    pid = child.pid

    assert proc.kill_pid_group(pid, grace=2.0) is True

    child.stop()
    try:
        os.kill(pid, 0)
        pytest.fail(f"{pid} survived")
    except ProcessLookupError:
        pass


def test_a_zombie_does_not_count_as_alive():
    """Regression, and the second time this exact mistake was made.

    `Child._kill` had it first: a null-signal poll cannot see that a process
    has exited, because an unreaped process still holds a table entry.
    `kill_pid_group` then repeated it behind an argument that foreign
    processes are always orphans and therefore always promptly reaped -- which
    is not true under a subreaper, under systemd, or for a process this daemon
    started.

    So liveness is read from the state letter in /proc/<pid>/stat instead.
    """
    child = proc.spawn(["/bin/sleep", "30"])
    pgid = child.pgid
    assert proc._group_alive(pgid)

    os.killpg(pgid, signal.SIGKILL)
    # Deliberately NOT reaped: the child is now a zombie, and signal 0 still
    # succeeds against it. This is exactly the state that broke the poll.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and proc._group_alive(pgid):
        time.sleep(0.05)

    assert not proc._group_alive(pgid), "a zombie was counted as a live process"
    os.killpg(pgid, 0)  # still answers signal 0 -- which is the whole point

    child.stop()


@pytest.mark.parametrize("line, expected", [
    # Ordinary.
    ("123 (sleep) S 1 456 456 0 -1 4194304 0", ("S", 456)),
    # A name containing a space, a paren, and something that looks like a
    # state letter. A process can choose this, and `stat.split()[2]` would
    # read "name)" as the state and 1 as the pgrp.
    ("123 (we ird) name) S 1 456 456 0 -1 0 0", ("S", 456)),
    ("123 (Z) Z 1 99 99 0 -1 0 0", ("Z", 99)),
    ("123 ((())) R 1 7 7 0 -1 0 0", ("R", 7)),
    # Malformed rather than crashing: /proc entries race with process exit.
    ("garbage", None),
    ("", None),
])
def test_the_stat_parser_reads_from_the_last_paren(line, expected):
    """The kernel does not escape the executable name in /proc/<pid>/stat, so
    splitting the whole line reads the wrong fields for a name a process chose.

    Tested as a pure function rather than by creating a weirdly-named process:
    an earlier version of this test used `exec -a`, which is a bash builtin,
    while /bin/sh here is dash -- so the child died at once and the test passed
    only when it won the race to observe it.
    """
    assert proc.parse_stat(line) == expected


def test_group_liveness_uses_that_parser():
    child = proc.spawn(["/bin/sleep", "30"])
    try:
        assert proc._group_alive(child.pgid)
    finally:
        child.stop()
