"""Which processes are sandboxd's own launch of the sample, not the sample.

Where the guest has no exec, the sample is started by an injected shell that
first waits for the plugins to arm (guests._windows_launch: `cmd.exe /c
PING.EXE -n 5 127.0.0.1 >nul & "sample"`), so the trace's root is that
shell, with its console host and the wait beside the sample.

One definition, read twice: `trace_split.follow_transfers` (a launcher is no
source of a control transfer until the sample takes it over) and
`behaviour.mark_launcher` (a launcher's calls are no behaviour of the
sample's). Each hands in its own view of the processes.
"""
from __future__ import annotations

from typing import Iterable, Mapping, Optional, Set

# What the shell runs in itself rather than starts: for these the shell of the
# launch is the sample.
SHELL_SCRIPTS = (".bat", ".cmd")


def command_words(command) -> list:
    """A command line as its words, lower case, without redirections --
    `PING.EXE -n 5 127.0.0.1 >nul` is started as `PING.EXE  -n 5 127.0.0.1`."""
    return [w for w in str(command or "").lower().split() if not w.startswith((">", "<", "2>"))]


def _name(path) -> str:
    return str(path or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def launch_seqids(processes: Iterable[Mapping], shell: Optional[str], delay: Optional[str],
                  sample_name: Optional[str]) -> Set[int]:
    """Seqids of the launch's processes among `processes` (mappings with
    `seqid`, `parent_seqid`, `module_path`, `process_name`, `command_line`).

    A root -- a process whose parent is not among them -- is a launcher when
    it is the launch's shell AND started the wait; then so are the wait and
    the shell's console host. A script the shell runs in itself (.bat, .cmd)
    is the sample in that same process, which then is not one."""
    words = command_words(delay)
    if not shell or not words:
        return set()
    processes = [p for p in processes if p.get("seqid") is not None]
    seqids = {p["seqid"] for p in processes}
    found: Set[int] = set()
    for root in processes:
        if root.get("parent_seqid") in seqids or _name(root.get("module_path")) != _name(shell):
            continue
        children = [p for p in processes if p.get("parent_seqid") == root["seqid"]]
        waits = [p for p in children
                 if command_words(p.get("command_line"))[1:] == words[1:]
                 and _name(p.get("module_path")) == _name(words[0])]
        if not waits:
            continue
        found.update(p["seqid"] for p in waits)
        found.update(p["seqid"] for p in children
                     if str(p.get("process_name") or "").lower() == "conhost.exe")
        if not str(sample_name or "").lower().endswith(SHELL_SCRIPTS):
            found.add(root["seqid"])
    return found
