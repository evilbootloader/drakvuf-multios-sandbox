"""The analysis clock: `timeout` seconds from the sample's start, not from
DRAKVUF's (guests.LAUNCH_SLACK, stages.Analysis._await_trace), and the dump
of what is still running when the trace ends.

On 2026-11-12 three Windows samples started 37, 45 and 63 s into a 120 s
trace, and the one that mattered most (an installer past its UAC prompt) had
8.5 s of it.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd import guests as G, timing  # noqa: E402
from sandboxd.guests import SampleKind, TargetOs  # noqa: E402
from sandboxd.proc import Completed  # noqa: E402
from sandboxd.stages import Analysis  # noqa: E402
from sandboxd.tests.test_guests import job  # noqa: E402


def windows(tmp_path, **kw):
    return job(tmp_path, TargetOs.WINDOWS, SampleKind.PE, filename="SteamSetup.exe", **kw)


# --- what DRAKVUF is asked for -------------------------------------------------------------

def test_windows_traces_for_the_timeout_and_the_slack(tmp_path):
    j = windows(tmp_path)
    argv = G.argv_trace(j)
    assert j.options.launch_slack == G.LAUNCH_SLACK
    assert argv[argv.index("-t") + 1] == str(j.options.timeout + G.LAUNCH_SLACK)
    # and the phase guard moves with it, so it cannot fire inside the trace
    plain = timing.budgets(TargetOs.WINDOWS, SampleKind.PE, j.options.timeout)
    slack = timing.budgets(TargetOs.WINDOWS, SampleKind.PE, j.options.timeout, launch_slack=G.LAUNCH_SLACK)
    assert slack.trace == plain.trace + G.LAUNCH_SLACK


def test_the_evidenced_guests_keep_drakvufs_own_clock(tmp_path):
    for os_, kind in ((TargetOs.UBUNTU, SampleKind.ELF), (TargetOs.ANDROID, SampleKind.ELF)):
        j = job(tmp_path, os_, kind)
        argv = G.argv_trace(j)
        assert j.options.launch_slack == 0
        assert argv[argv.index("-t") + 1] == str(j.options.timeout)
        assert G.sample_start_marker(j) is None


def test_the_sample_starting_is_procmons_record_naming_its_file(tmp_path):
    marker = G.sample_start_marker(windows(tmp_path))
    exe = (b'{"Plugin":"procmon","PID":7216,"Method":"NtCreateUserProcess","Status":"0x0",'
           b'"ImagePathName":"C:\\\\Users\\\\carlos\\\\Desktop\\\\SteamSetup.exe"}')
    wait = (b'{"Plugin":"procmon","PID":7216,"Method":"NtCreateUserProcess",'
            b'"ImagePathName":"C:\\\\Windows\\\\System32\\\\PING.EXE"}')
    opened = b'{"Plugin":"filetracer","Method":"NtCreateFile","FileName":"\\\\Users\\\\carlos\\\\Desktop\\\\SteamSetup.exe"}'
    assert all(part in exe for part in marker)
    assert not all(part in wait for part in marker)
    assert not all(part in opened for part in marker)
    # A script is an argument of its host's command line
    script = G.sample_start_marker(windows(tmp_path, submitted_filename="x.js"))
    host = (b'{"Plugin":"procmon","Method":"NtCreateUserProcess","ImagePathName":"C:\\\\Windows\\\\System32\\\\WScript.exe",'
            b'"CommandLine":"\\"C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\WScript.exe\\" \\"C:\\\\\\\\Users\\\\\\\\carlos\\\\\\\\Desktop\\\\\\\\x.js\\""}')
    assert all(part in host for part in script)


def test_what_is_still_running_at_the_end_is_dumped(tmp_path):
    for os_, kind in ((TargetOs.WINDOWS, SampleKind.PE), (TargetOs.UBUNTU, SampleKind.ELF)):
        argv = G.argv_trace(job(tmp_path, os_, kind))
        assert "--procdump-new-processes-on-finish" in argv
        assert argv.index("--procdump-dir") < argv.index("--procdump-new-processes-on-finish")


# --- the wait -------------------------------------------------------------------------------

class Drakvuf:
    """A child that runs until interrupted or until its own `-t`."""

    def __init__(self, runs_for=30.0):
        self.done = threading.Event()
        self.interrupted = False
        self._timer = threading.Timer(runs_for, self.done.set)
        self._timer.start()

    def running(self):
        return not self.done.is_set()

    def interrupt(self):
        self.interrupted = True
        self.done.set()

    def stop(self):
        self.done.set()

    def wait(self, *, timeout=None):
        self.done.wait(timeout)
        self._timer.cancel()
        return Completed(argv=("drakvuf",), returncode=0, stdout="", stderr="", duration=0.0,
                         timed_out=not self.done.is_set())


BEAT = SimpleNamespace(cancelled=threading.Event())
MARKER = (b'"Plugin":"procmon"', b'"Method":"NtCreateUserProcess"', b"sample.exe")
START = b'{"Plugin":"procmon","Method":"NtCreateUserProcess","ImagePathName":"C:\\\\x\\\\sample.exe"}\n'


def test_the_trace_ends_the_timeout_after_the_sample_started(tmp_path):
    log = tmp_path / "trace.log"
    log.write_bytes(b'{"Plugin":"syscall"}\n')
    child = Drakvuf()
    threading.Timer(0.3, lambda: log.open("ab").write(START)).start()
    result, started = Analysis._await_trace(child, log, MARKER, 1, 20.0, BEAT, poll=0.05)
    assert child.interrupted and not result.timed_out
    assert 0.25 <= started <= 1.0


def test_a_record_cut_by_the_write_is_read_when_it_is_whole(tmp_path):
    log = tmp_path / "trace.log"
    log.write_bytes(START[:40])                    # DRAKVUF's buffer ended mid-line
    child = Drakvuf()
    threading.Timer(0.3, lambda: log.open("ab").write(START[40:])).start()
    _, started = Analysis._await_trace(child, log, MARKER, 1, 20.0, BEAT, poll=0.05)
    assert child.interrupted and started >= 0.25


def test_a_sample_never_seen_runs_to_drakvufs_own_timeout(tmp_path):
    log = tmp_path / "trace.log"
    log.write_bytes(b'{"Plugin":"syscall"}\n')
    child = Drakvuf(runs_for=0.4)
    result, started = Analysis._await_trace(child, log, MARKER, 1, 20.0, BEAT, poll=0.05)
    assert started is None and not child.interrupted and not result.timed_out
