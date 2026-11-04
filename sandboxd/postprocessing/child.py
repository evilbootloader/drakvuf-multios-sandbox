"""Postprocessing in a child process, with a memory limit.

**Why a child** (Dom0, 2026-11-02 19:55). The heavy passes -- capa and falco
each build the whole in-scope trace in memory -- ran inside the daemon, and
after a 20-minute trace the daemon itself reached 6.7 GiB of anonymous memory
on a Dom0 with 7.9 GiB and was killed by the kernel's OOM killer, taking every
clone's bookkeeping with it. Half an hour before that the job's lease had
lapsed: a process that is swapping does not get to send heartbeats. The
numbers are at `config.POSTPROCESS_MAX_MIB`; the symptom is in
docs/TROUBLESHOOTING.md.

So `stages.Analysis` runs `python -m sandboxd.postprocessing` through the
`Runner` seam. The child sets `RLIMIT_DATA` before it imports a plugin
(`__main__.py`), so an overrun is a `MemoryError` inside ONE plugin -- caught
by `postprocess.run_postprocessing`, logged, the next plugin runs -- and the
daemon is never the process that dies. Going through the `Runner` also gives
the pass what every other stage command has: its own process group, a
wall-clock budget (`timing.POSTPROCESS_BUDGET`) and SIGINT-then-SIGKILL when
that runs out -- and it makes the call visible to the recording fake, so the
stage tests can see what was asked for without running capa.

**This module imports nothing heavy, on purpose.** `stages.py` imports it,
and the point is that the daemon no longer loads capa and vivisect at all.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

log = logging.getLogger("sandboxd.postprocessing")

#: The child's exit status when at least one plugin raised. The trace is
#: still the result; what is missing is derived data, and the child names
#: the plugins on its last stdout line (FAILED_PREFIX) so the manifest can.
EXIT_PLUGIN_FAILED = 3

#: Last line of the child's stdout when plugins failed, followed by their
#: names separated by spaces. Parsed by `_failed_plugins`.
FAILED_PREFIX = "postprocessing-failed:"

#: A stdout line the child prints at the end: its peak resident size in KiB
#: (`ru_maxrss`), so a Dom0 log carries the one number that sizes
#: `SANDBOXD_POSTPROCESS_MAX_MIB` against a real trace. Parsed by `_peak_mib`.
PEAK_PREFIX = "postprocessing-peak-rss-kib:"

MODULE = "sandboxd.postprocessing"


def argv_postprocess(analysis_dir: Path, os_name: str, vlan: int | None,
                     max_mib: int, python: str | None = None) -> list[str]:
    """The child's command line.

    `python` defaults to the daemon's own interpreter, so the child runs in the
    same venv with the same packages -- and in the tests it is whatever runs
    pytest, which the fake records and never executes.
    """
    argv = [python or sys.executable, "-m", MODULE, str(analysis_dir),
            "--os", os_name, "--max-mib", str(max_mib)]
    if vlan is not None:
        argv += ["--vlan", str(vlan)]
    return argv


def postprocess_in_child(runner, analysis_dir: Path, os_name: str,
                         vlan: int | None, *, max_mib: int,
                         timeout: float) -> str | None:
    """Run the plugins over a finished trace. Returns a note, or None.

    Never raises for a postprocessing failure: the trace is the result and
    this is derived from it. The note is for the manifest (`stages._collect`),
    because a job whose `ttps.json` is missing must say why in the record a
    reader sees, not only in a log line on Dom0.
    """
    result = runner.run(argv_postprocess(analysis_dir, os_name, vlan, max_mib),
                        timeout=timeout, what="postprocess")
    tail = _tail(result.stderr)
    peak = _peak_mib(result.stdout)
    if peak is not None:
        log.info("postprocessing of %s: peak RSS %d MiB of the %d MiB limit",
                 analysis_dir.name, peak, max_mib)
    if result.ok:
        if tail:
            log.info("postprocessing of %s:\n%s", analysis_dir.name, tail)
        return None
    if result.timed_out:
        log.warning("postprocessing of %s exceeded its %.0fs budget and was "
                    "stopped; the trace is kept, derived data may be "
                    "incomplete\n%s", analysis_dir.name, timeout, tail)
        return (f"postprocessing stopped at its {timeout:.0f}s budget; "
                f"derived data may be incomplete")
    if result.returncode == EXIT_PLUGIN_FAILED:
        names = ", ".join(_failed_plugins(result.stdout)) or "a plugin"
        log.warning("postprocessing of %s: %s failed; the trace is kept\n%s",
                    analysis_dir.name, names, tail)
        return f"postprocessing: {names} failed; see sandboxd's log on Dom0"
    log.error("postprocessing of %s exited %s\n%s", analysis_dir.name,
              result.returncode, tail)
    return (f"postprocessing exited {result.returncode}; derived data may be "
            f"incomplete")


def _failed_plugins(stdout: str) -> list[str]:
    for line in reversed((stdout or "").splitlines()):
        if line.startswith(FAILED_PREFIX):
            return line[len(FAILED_PREFIX):].split()
    return []


def _peak_mib(stdout: str) -> int | None:
    for line in reversed((stdout or "").splitlines()):
        if line.startswith(PEAK_PREFIX):
            try:
                return int(line[len(PEAK_PREFIX):].strip()) // 1024
            except ValueError:
                return None
    return None


def _tail(text: str, limit: int = 4000) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else "…" + text[-limit:]