"""procmon.log to the process tree: the rebind of a process whose PPID changed.

That is the branch of `tree_from_log` for lines whose Method has no parser of
its own, and the one place the tree's edges move -- so the one place it can
stop being a tree. Job 4d8c1c25 (2026-11-03) uploaded a report in which it
had, and the Behaviour tab raised KeyError on it.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sandboxd.guests import TargetOs  # noqa: E402
from sandboxd.postprocessing.process_tree import tree_from_log  # noqa: E402


def procmon(*entries: dict) -> io.StringIO:
    return io.StringIO("".join(json.dumps({"Plugin": "procmon", **e}) + "\n"
                               for e in entries))


def running(pid: int, ppid: int, name: str) -> dict:
    return {"TimeStamp": "1793710665.207391", "PID": pid, "PPID": ppid,
            "RunningProcess": name, "Bitness": 0}


def reachable(tree) -> list:
    out, stack = [], [p for p in tree.processes if p.parent is None]
    while stack:
        p = stack.pop()
        out.append(p)
        stack.extend(p.children)
    return out


# Verbatim from job 4d8c1c25's procmon.log: a timer interrupt on CPU 1 sending
# anacron its SIGALRM, logged in the context of that CPU's idle task.
SIGNAL_FROM_SWAPPER_1 = {
    "TimeStamp": "1793710958.661693", "PID": 0, "PPID": 1, "TID": 0, "UserId": 0,
    "ProcessName": "swapper/1", "Method": "send_signal", "EventUID": "0x6ec2af",
    "ThreadName": "swapper/1", "TargetPID": 1857, "TargetTID": 1857, "TargetPPID": 1,
    "TargetProcessName": "/usr/sbin/anacron", "TargetThreadName": "anacron",
    "Signal": 14, "SignalStr": "SIGALRM"}


def test_a_signal_from_an_idle_cpu_leaves_swapper_0_the_root():
    """swapper/1 is PID 0 like swapper/0 but has PPID 1, so its line read as
    swapper/0 moving under systemd -- its own child -- and made a loop."""
    tree = tree_from_log(procmon(
        running(0, 0, "swapper/0"),
        running(1, 0, "/usr/lib/systemd/systemd"),
        running(1857, 1, "/usr/sbin/anacron"),
        SIGNAL_FROM_SWAPPER_1,
    ), TargetOs.UBUNTU)
    swapper, systemd, anacron = tree.processes
    assert swapper.parent is None and swapper.ppid == 0
    assert systemd.parent is swapper and anacron.parent is systemd
    assert len(reachable(tree)) == len(tree.processes)
    [root] = tree.as_dict()  # process_tree.json
    assert root["procname"] == "swapper/0"


def test_an_orphan_on_linux_stays_under_the_process_that_forked_it():
    """A daemon's fork-and-exit (job of 2026-11-11, a Mirai-family bot): the
    child's later lines name init as its parent, which is the kernel adopting
    an orphan, not a rebind -- moved under systemd it left the sample."""
    elf = "/home/carlos/Desktop/ee57ea3a.elf"
    tree = tree_from_log(procmon(
        running(1, 0, "/usr/lib/systemd/systemd"),
        running(2028, 1, "/usr/bin/dash"),
        {"TimeStamp": "1794344327.034124", "PID": 2028, "PPID": 1, "TID": 2028, "ProcessName": "/usr/bin/dash",
         "Method": "do_execveat_common", "EventUID": "0x207e", "CommandLine": elf, "ImagePathName": elf, "FileName": elf},
        {"TimeStamp": "1794344327.044238", "PID": 2028, "PPID": 1, "TID": 2028, "ProcessName": elf,
         "Method": "kernel_clone", "EventUID": "0x2147", "Flags": "(null)", "NewPid": 2033},
        {"TimeStamp": "1794344327.045404", "PID": 2028, "PPID": 1, "TID": 2028, "ProcessName": elf,
         "Method": "do_exit", "EventUID": "0x2154", "ExitStatus": 0, "ExitStatusStr": "EXIT_SUCCESS"},
        {"TimeStamp": "1794344340.027166", "PID": 2033, "PPID": 1, "TID": 2033, "ProcessName": elf,
         "Method": "send_signal", "EventUID": "0xdbed", "TargetPID": 1468, "Signal": 14},
    ), TargetOs.UBUNTU)
    systemd, sample, daemon = tree.processes
    assert daemon.pid == 2033 and daemon.parent is sample and daemon.ppid == 2028
    assert sample.children == [daemon] and systemd.children == [sample]


def test_a_rebind_takes_the_new_parents_pid_and_happens_once():
    """The rebind itself still happens. Its PPID is the new parent's PID, not
    the new parent's own PPID, with which the next line for the same process
    would differ again and move it to the end of its siblings."""
    tree = tree_from_log(procmon(
        running(4, 0, "System"),
        running(10, 4, "a.exe"),
        running(20, 4, "b.exe"),
        running(30, 10, "c.exe"),
        {"TimeStamp": "2.0", "PID": 30, "PPID": 20, "Method": "NtOpenProcess"},
        running(40, 20, "d.exe"),
        {"TimeStamp": "3.0", "PID": 30, "PPID": 20, "Method": "NtOpenProcess"},
    ), TargetOs.WINDOWS)
    system, a, b, c, d = tree.processes
    assert c.parent is b and c.ppid == 20
    assert a.children == [] and b.children == [c, d]
    assert len(reachable(tree)) == len(tree.processes)
