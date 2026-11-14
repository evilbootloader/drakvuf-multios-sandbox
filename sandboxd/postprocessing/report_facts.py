"""What the daemon reads out of a run's `cape_results.json` before reporting
the run: which processes are the sample's (procdumps.py, for which dumps
upload) and the run's score (stages, sent with the manifest at `/complete`
for the platform's jobs row, 0014).

Read once per run and handed to both, rather than once by each: the report
is read whole, and a large run's is tens of megabytes. Imported by the
daemon, so the standard library only -- no CAPE module, no capa (child.py).
"""

from __future__ import annotations

import json
import logging
import math
from pathlib import Path
from typing import Optional

from .paths import CAPE_RESULTS

log = logging.getLogger(__name__)

# The report is read whole; a report this large is not one cape_analysis
# wrote for any trace seen so far (78 KB for a one-process Windows run,
# 2026-11-11), and reading it is not worth the daemon's memory.
MAX_REPORT_BYTES = 256 * 1024 * 1024

# What CAPE's calc_scoring (cape_plugin/scoring.py) can call a run: the
# platform's enums.MalStatus and 0014's CHECK, which refuse anything else.
MALSTATUS = frozenset(("Malicious", "Suspicious", "Clean", "Undetected", "Failed"))


def read(job_dir: Path) -> Optional[dict]:
    """The run's report, or None when there is none, or none that can be
    read -- what each reader then does without it is its own rule."""
    path = job_dir / CAPE_RESULTS
    try:
        if path.stat().st_size > MAX_REPORT_BYTES:
            log.warning("%s is over %d bytes; not read", path, MAX_REPORT_BYTES)
            return None
        report = json.loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        log.info("no readable %s: %s", path.name, exc)
        return None
    return report if isinstance(report, dict) else None


def score(report: Optional[dict]) -> Optional[dict]:
    """`{"malscore": x, "malstatus": word}` for `/complete`, or None for a
    run with no score -- no report, or one without a number calc_scoring
    could have written. A word outside the set is sent as None, the number
    kept: the platform refuses the whole request otherwise."""
    if report is None:
        return None
    value = report.get("malscore")
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or not 0 <= value <= 10):
        return None
    status = report.get("malstatus")
    return {"malscore": float(value), "malstatus": status if status in MALSTATUS else None}
