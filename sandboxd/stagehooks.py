"""Hooks for what the sample drops and then runs, added while the trace runs.

`samplehooks` reads the submitted file before the trace. A dropper's work is
done by the file it writes or downloads, which did not exist then. DRAKVUF's
fileextractor copies every file the guest writes into the job's `extracted/`
directory as it is written; this watches that directory during the trace,
runs the same locator on each program that appears, and adds its lines to the
end of the job's hook list. libmon and apimon read what a list has gained
(`hook_list_tail` in the fork) and place it, in a process that starts later
and in one that is already running.

What this does not reach, and the job is not told otherwise by it: a payload
that never touches the disk (memfd, a reflective load), code a packer unpacks
in place, and the calls a second stage makes before its lines are read --
the locator takes about a second, and a file may be run the moment it is
closed.

How a finished file and its guest path are known is the extractor's, per OS:

- Linux logs a record with `FileName` and `DumpFile` when it is done with a
  file, and writes no sidecar. The trace is read as it grows for those.
- Windows writes `file.NNNNNN.metadata` beside `file.NNNNNN.mm`, with
  `FileName`, and adds `FileHash` when the file is complete.
"""
from __future__ import annotations

import json
import logging
import sys
import threading
from pathlib import Path
from typing import Callable, Iterator, Optional

from . import timing

log = logging.getLogger(__name__)

#: Programs looked at per job. A sample that writes a thousand executables is
#: not followed into each: the locator is a second of a Dom0 core apiece.
MAX_STAGES = 16
#: Larger than this is not read (the submitted sample has its own limit)
MAX_BYTES = 64 << 20
POLL = 1.0
_MAGIC = (b"\x7fELF", b"MZ")


def linux_candidates(trace_log: Path, extracted: Path, state: dict) -> Iterator[tuple]:
    """(file in `extracted`, guest path) for each file fileextractor has
    logged since the last call. `state` carries the place in the log."""
    try:
        with open(trace_log, "rb") as fh:
            fh.seek(state.get("offset", 0))
            data = fh.read()
    except OSError:
        return
    state["offset"] = state.get("offset", 0) + len(data)
    *lines, state["tail"] = (state.get("tail", b"") + data).split(b"\n")
    for line in lines:
        if b'"DumpFile"' not in line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        name, dump = record.get("FileName"), record.get("DumpFile")
        if record.get("Plugin") != "fileextractor" or not isinstance(name, str) or not isinstance(dump, str):
            continue
        # The name only: the record is the guest's to shape, the directory ours
        yield extracted / Path(dump).name, name


def windows_candidates(extracted: Path, state: dict) -> Iterator[tuple]:
    """(file in `extracted`, guest path) for each file whose sidecar says it
    is complete and that was not given before."""
    seen = state.setdefault("seen", set())
    for sidecar in sorted(extracted.glob("file.*.metadata")):
        if sidecar.name in seen:
            continue
        try:
            record = json.loads(sidecar.read_text(errors="replace").splitlines()[0])
        except (OSError, ValueError, IndexError):
            continue
        if "FileHash" not in record:
            continue        # still being read out of the guest
        seen.add(sidecar.name)
        if isinstance(record.get("FileName"), str):
            yield sidecar.with_suffix(".mm"), record["FileName"]


def candidates(how: str, trace_log: Path, extracted: Path) -> Callable[[], Iterator[tuple]]:
    """The source of finished files for a guest whose extractor announces
    them `how` (guests.EXTRACTED_ANNOUNCED): "log" or "sidecar"."""
    state: dict = {}
    if how == "sidecar":
        return lambda: windows_candidates(extracted, state)
    if how == "log":
        return lambda: linux_candidates(trace_log, extracted, state)
    raise ValueError(f"no source of extracted files called {how!r}")


def is_program(path: Path) -> bool:
    try:
        if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= MAX_BYTES:
            return False
        with path.open("rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    return head.startswith(_MAGIC)


class StageWatcher:
    """Runs beside one trace. `candidates` is one of the functions above,
    bound to the job's paths; `run` is the Runner's."""

    def __init__(self, run: Callable, candidates: Callable[[], Iterator[tuple]],
                 hooks_list: Path, static_list: Path, report_dir: Path) -> None:
        self._run = run
        self._candidates = candidates
        self._hooks_list = hooks_list
        self._static_list = static_list
        self._report_dir = report_dir
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._done: dict = {}       # file name -> size it was read at
        self.stages = 0

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, daemon=True, name="stagehooks")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            # A locator in flight is let finish: its budget bounds the wait
            self._thread.join(timeout=timing.SAMPLEHOOKS_BUDGET + 5)

    def _loop(self) -> None:
        while not self._stop.wait(POLL):
            try:
                self.poll()
            except Exception:  # noqa: BLE001 - never the trace's problem
                log.exception("stagehooks: a poll failed")

    def poll(self) -> None:
        for path, guest_path in self._candidates():
            if self._stop.is_set() or self.stages >= MAX_STAGES:
                return
            if not is_program(path):
                continue
            size = path.stat().st_size
            # Written again and larger: a download that was logged part-way
            if self._done.get(path.name) == size:
                continue
            self._done[path.name] = size
            self.stages += 1
            result = self._run(
                [sys.executable, "-m", "sandboxd.samplehooks", str(path),
                 "--guest-path", guest_path, "--static", str(self._static_list),
                 "--append-to", str(self._hooks_list),
                 "--json", str(self._report_dir / f"located.stage{self.stages:02d}.json")],
                timeout=timing.SAMPLEHOOKS_BUDGET, what="samplehooks")
            if not result.ok:
                log.warning("stagehooks: %s was not read (%s)", path.name,
                            "timed out" if result.timed_out else f"exit {result.returncode}")
