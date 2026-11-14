"""The lines of a trace that contain one of a few byte strings, found by
several processes and handed over in file order.

trace_split's first pass reads a multi-gigabyte trace.log for the few lines
in a hundred it has a use for (procmon's, the injection's, the calls that
make another process run code). Telling them from the rest is a dozen
substring tests a line, ten million times: 35 s of one processor on a
20-minute Windows trace, with the others idle. Here each worker tests one
stretch of the file and returns the lines that pass; what is done with them
stays in the caller, in order, as before.

**Memory.** A worker holds one stretch (`CHUNK` bytes) and its kept lines;
the caller holds at most `2 * workers` results not yet consumed. The workers
are forks of the caller: they share its pages and write to almost none of
them, so each costs its stretch and little else.

**The caller must have no other thread while this runs.** A fork copies the
one thread that forks, and a lock another thread held stays held in the
child for ever. cape_analysis starts compressing the trace, on a thread,
only once this pass is over (`split_by_process`'s `after_prelude`). A fork
server or spawned workers would not care, and would instead import the
caller's `__main__` again, whatever that is.
"""
from __future__ import annotations

import multiprocessing
import os
import re
from collections import deque
from pathlib import Path
from typing import Iterator, Optional, Sequence, Tuple

#: Bytes of the trace a worker reads at a time.
CHUNK = 8 << 20
#: A trace smaller than this is read by the caller itself: starting workers
#: costs more than they save.
MIN_PARALLEL_BYTES = 64 << 20
#: Workers when `SANDBOXD_POSTPROCESS_WORKERS` does not say. Dom0 has six
#: processors and two analyses may be in this pass at once.
DEFAULT_WORKERS = 3


def workers_wanted() -> int:
    """How many processes may scan, from SANDBOXD_POSTPROCESS_WORKERS (1 for
    none), never more than the processors there are."""
    try:
        asked = int(os.environ.get("SANDBOXD_POSTPROCESS_WORKERS", DEFAULT_WORKERS))
    except ValueError:
        asked = DEFAULT_WORKERS
    return max(1, min(asked, os.cpu_count() or 1))


def scan(path: str, start: int, end: int, needles: Sequence[bytes],
         flag: Optional[bytes]) -> Tuple[bytes, bool]:
    """The lines of `path`[start:end] with one of `needles` in them, joined,
    and whether the stretch matches the regular expression `flag` anywhere."""
    with open(path, "rb") as f:
        f.seek(start)
        data = f.read(end - start)
    kept = []
    # At "\n" alone, as a file is read line by line: a record may hold a raw
    # "\r", which splitlines() would cut it at
    for line in data.split(b"\n"):
        for needle in needles:
            if needle in line:
                kept.append(line)
                break
    return b"\n".join(kept), bool(flag and re.search(flag, data))


def lines(kept: bytes) -> list:
    """The lines `scan` joined, each with its newline, as a file gives them."""
    return [line + b"\n" for line in kept.split(b"\n")] if kept else []


def stretches(path: Path, size: int = CHUNK) -> Iterator[Tuple[int, int]]:
    """(start, end) of consecutive stretches of about `size` bytes, each
    ending at the end of a line."""
    total = path.stat().st_size
    start = 0
    with path.open("rb") as f:
        while start < total:
            end = min(total, start + size)
            if end < total:
                f.seek(end)
                f.readline()
                end = f.tell()
            yield start, end
            start = end


def matching(path: Path, needles: Sequence[bytes], flag: Optional[bytes] = None,
             workers: Optional[int] = None, chunk: Optional[int] = None,
             ) -> Iterator[Tuple[bytes, bool]]:
    """(lines, flagged) of every stretch of `path`, in file order: `scan`'s
    answers. Alone for a small file or one worker, else on `workers`
    processes of a fork server."""
    workers = workers_wanted() if workers is None else workers
    chunk = CHUNK if chunk is None else chunk
    needles = tuple(needles)
    if workers <= 1 or path.stat().st_size < MIN_PARALLEL_BYTES:
        for start, end in stretches(path, chunk):
            yield scan(str(path), start, end, needles, flag)
        return
    context = multiprocessing.get_context("fork")
    with context.Pool(workers) as pool:
        pending: deque = deque()
        for start, end in stretches(path, chunk):
            pending.append(pool.apply_async(scan, (str(path), start, end, needles, flag)))
            if len(pending) >= 2 * workers:
                yield pending.popleft().get()
        while pending:
            yield pending.popleft().get()
