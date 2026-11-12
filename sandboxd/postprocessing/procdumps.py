"""Which of procdump2's dumps are the sample's, by the CAPE report.

procdump2 dumps every process that exits while the trace runs -- the guest's
services as much as the sample -- into `procdumps/`, one data file and a
`.metadata` sidecar naming the process (`PID`, `DataFileName`) each. Only the
sample's are uploaded (operator, 2026-11-12): the report and the page are the
malware's, and a whole-process dump of an idle service is tens of megabytes
of the result budget that says nothing about the sample.

The sample is what `cape_results.json` says it is: the processes in
`trace_split.sample` (the injected ones, their descendants, the processes they
took over), by their PIDs in `behavior.processes`. Imported by the daemon, so
the standard library only -- no CAPE module, no capa (see child.py).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional, Set

from .paths import CAPE_RESULTS, PROCDUMPS_DIR

log = logging.getLogger(__name__)

# The report is read whole to find the sample; a report this large is not one
# cape_analysis wrote for any trace seen so far (78 KB for a one-process
# Windows run, 2026-11-11), and reading it is not worth the daemon's memory.
MAX_REPORT_BYTES = 256 * 1024 * 1024


def sample_pids(job_dir: Path) -> Optional[Set[int]]:
    """The PIDs of the sample's processes, from `cape_results.json`; None when
    there is no report, or none that can be read."""
    path = job_dir / CAPE_RESULTS
    try:
        if path.stat().st_size > MAX_REPORT_BYTES:
            log.warning("%s is over %d bytes; not read for the sample's PIDs", path, MAX_REPORT_BYTES)
            return None
        report = json.loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        log.info("no readable %s for the sample's PIDs: %s", path.name, exc)
        return None
    if not isinstance(report, dict):
        return None
    behavior = report.get("behavior") if isinstance(report.get("behavior"), dict) else {}
    processes = [p for p in behavior.get("processes") or () if isinstance(p, dict)]
    split = report.get("trace_split") if isinstance(report.get("trace_split"), dict) else {}
    sample = split.get("sample")
    if isinstance(sample, list):
        seqids = set(sample)
        processes = [p for p in processes if p.get("seqid") in seqids]
    # A report from before trace_split named the sample: its processes were
    # the sample's already (sandboxd's default scope)
    return {p["process_id"] for p in processes if isinstance(p.get("process_id"), int)}


def outside_sample(job_dir: Path) -> Optional[Set[str]]:
    """The files under `procdumps/` that are not the sample's, as paths
    relative to `job_dir`: a dump whose sidecar names another process, and a
    file no sidecar of the sample's names (a dump that cannot be attributed
    is not known to be the sample's). None when there is no report to say
    what the sample is -- everything is kept then, as before."""
    directory = job_dir / PROCDUMPS_DIR
    if not directory.is_dir():
        return set()
    pids = sample_pids(job_dir)
    if pids is None:
        return None
    keep: Set[Path] = set()
    for sidecar in directory.glob("*.metadata"):
        try:
            meta = json.loads(sidecar.read_text(errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(meta, dict) or meta.get("PID") not in pids:
            continue
        keep.add(sidecar)
        keep.add(directory / Path(str(meta.get("DataFileName") or sidecar.stem)).name)
    return {str(p.relative_to(job_dir)) for p in directory.rglob("*")
            if p.is_file() and p not in keep}
