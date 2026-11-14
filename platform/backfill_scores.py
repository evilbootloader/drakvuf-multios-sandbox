#!/usr/bin/env python3
"""Fill `jobs.malscore` and `jobs.malstatus` (0014) for runs that finished
before the worker reported them.

    cd platform && .venv/bin/python backfill_scores.py [--dry-run] [--limit N]

From each completed job's own `cape_results.json`, read the way the job page
reads it (`cape.for_job`: bounded, never raising), so the history list shows
the number the report does. Skipped, and counted: a job past the retention
window (the store has expired its report), and one with no report or no
score in it (a run from before the CAPE chain, or whose postprocessing
failed) -- those stay NULL, which the list shows as a dash.

Safe to run against the deployment, and to run again: it writes only rows
whose score is still NULL, one UPDATE per job, and reads one report at a
time. A job sandboxd completes while this runs gets its score from
`/complete` and is left alone.
"""

from __future__ import annotations

import argparse
import os
from collections import Counter
from datetime import UTC, datetime, timedelta

import psycopg

from sandbox_platform import cape
from sandbox_platform.config import settings
from sandbox_platform.enums import JobState


def _expired(created_at: datetime) -> bool:
    """The rule `routers/jobs._detail` applies: past it, the objects are gone."""
    return bool(settings.retention_days
                and created_at < datetime.now(UTC) - timedelta(days=settings.retention_days))


def backfill(conn, dry_run: bool = False, limit: int | None = None) -> Counter:
    """Score every completed job that has none and whose report says one;
    what happened to each, counted."""
    rows = conn.execute(
        "SELECT id, manifest, key_prefix, created_at FROM jobs"
        " WHERE state = %s AND malscore IS NULL ORDER BY created_at DESC LIMIT %s",
        (JobState.COMPLETED.value, limit)).fetchall()
    outcome: Counter = Counter()
    for job_id, manifest, key_prefix, created_at in rows:
        if _expired(created_at):
            outcome["expired"] += 1
            continue
        report = cape.for_job(job_id, manifest, key_prefix).report
        if report is None or report.malscore is None:
            outcome["no score in a report"] += 1
            continue
        if not dry_run:
            conn.execute("UPDATE jobs SET malscore = %s, malstatus = %s"
                         " WHERE id = %s AND malscore IS NULL",
                         (report.malscore, report.malstatus, job_id))
            conn.commit()
        outcome["scored"] += 1
    return outcome


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="read and count, write nothing")
    parser.add_argument("--limit", type=int, default=None, help="at most this many jobs, newest first")
    args = parser.parse_args()

    dsn = os.environ.get("DATABASE_URL", settings.database_url)
    print(f"database: {dsn}")
    with psycopg.connect(dsn) as conn:
        outcome = backfill(conn, dry_run=args.dry_run, limit=args.limit)
    for what, n in sorted(outcome.items()):
        print(f"{n:6d}  {what}{' (dry run: not written)' if args.dry_run and what == 'scored' else ''}")
    if not outcome:
        print("nothing to do: every completed job has a score or none to give")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
