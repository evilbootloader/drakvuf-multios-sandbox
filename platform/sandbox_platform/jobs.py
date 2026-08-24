"""Data access for the job queue.

Issue #35 (DRAFT-042). Thin by design: it binds parameters and shapes rows.
The correctness lives in queries.py, where it can be read as SQL.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

from . import queries


# --- claim results ---------------------------------------------------------
#
# Three shapes, not job-or-None. Collapsing the last two makes "a large job is
# holding its place in the queue" indistinguishable from "there is nothing to
# do" -- and being unable to tell those apart from outside the process is
# exactly what made the 2026-08-20 starvation present as a silent hang.

@dataclass(frozen=True)
class Lease:
    """Work, and the right to run it until lease_expires_at."""
    job_id: UUID
    target_os: str
    sha256: str | None
    submitted_filename: str
    required_mib: int
    lease_expires_at: datetime
    attempt: int


@dataclass(frozen=True)
class Reserved:
    """Nothing handed out: the head of the queue does not fit.

    NOT an error. The system is working -- a job too large for the caller's
    current free memory is holding its place rather than being starved by
    smaller ones behind it.
    """
    blocking_job_id: UUID
    need_mib: int


@dataclass(frozen=True)
class Idle:
    """Nothing queued at all."""


ClaimResult = Lease | Reserved | Idle


def claim(
    conn: psycopg.Connection,
    *,
    worker_id: str,
    free_mib: int,
    lease_seconds: int = 120,
) -> ClaimResult:
    """Take the head of the queue if it fits, otherwise reserve for it.

    free_mib is what the CALLER currently has, not what it owns. Capacity is a
    property of the analysis host and is reported per poll; the platform never
    infers it.
    """
    lease = timedelta(seconds=lease_seconds)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            queries.CLAIM,
            {"worker_id": worker_id, "lease": lease, "free_mib": free_mib},
        )
        if row := cur.fetchone():
            return Lease(
                job_id=row["id"],
                target_os=row["target_os"],
                sha256=row["sha256"],
                submitted_filename=row["submitted_filename"],
                required_mib=row["required_mib"],
                lease_expires_at=row["lease_expires_at"],
                attempt=row["attempt"],
            )

        # Zero rows is ambiguous -- empty queue, or head does not fit -- so
        # ask which. Advisory only; see queries.RESERVATION.
        cur.execute(queries.RESERVATION)
        if row := cur.fetchone():
            return Reserved(blocking_job_id=row["blocking_job_id"],
                            need_mib=row["need_mib"])
        return Idle()


CancelOutcome = Literal["cancelled", "cancel_requested", "not_cancellable"]


def cancel(conn: psycopg.Connection, job_id: UUID) -> CancelOutcome:
    """Cancel a job, by whichever route its current state allows.

    Before a clone exists this is terminal and immediate. While running it is
    a request the worker collects on its next heartbeat -- the only channel,
    because Dom0 has no inbound listener.

    Returns not_cancellable for a job already in a terminal state, which is
    not an error: cancelling something that already finished is a race the
    caller lost, not a fault.
    """
    with conn.cursor() as cur:
        cur.execute(queries.CANCEL_QUEUED, {"job_id": job_id})
        if cur.fetchone():
            return "cancelled"
        cur.execute(queries.CANCEL_RUNNING, {"job_id": job_id})
        if cur.fetchone():
            return "cancel_requested"
        return "not_cancellable"


def reap(conn: psycopg.Connection) -> list[UUID]:
    """Mark jobs whose lease lapsed as interrupted.

    Bookkeeping only. Frees nothing on the analysis host -- see queries.REAP.
    """
    with conn.cursor() as cur:
        cur.execute(queries.REAP)
        return [r[0] for r in cur.fetchall()]


def abandon(conn: psycopg.Connection, *, grace_seconds: int) -> list[UUID]:
    """Reject submissions whose upload never completed. See queries.ABANDON."""
    with conn.cursor() as cur:
        cur.execute(queries.ABANDON, {"grace": f"{grace_seconds} seconds"})
        return [r[0] for r in cur.fetchall()]


def reconcile(
    conn: psycopg.Connection, *, worker_id: str, live_job_ids: list[UUID]
) -> list[UUID]:
    """Adopt a restarted worker's view of what is actually running.

    Called before the worker's first claim. Anything it holds a lease on but
    did not list died with the previous process.
    """
    with conn.cursor() as cur:
        cur.execute(
            queries.RECONCILE,
            {"worker_id": worker_id, "live_job_ids": [str(i) for i in live_job_ids]},
        )
        return [r[0] for r in cur.fetchall()]


@dataclass(frozen=True)
class Capacity:
    affordable: bool
    worker_count: int

    @property
    def reject_reason(self) -> str | None:
        """Why a job of this size cannot be accepted, or None if it can.

        no_workers and no_capacity are distinct on purpose. On a fresh install
        no worker has registered and refusing every submission is the CORRECT
        answer -- but "no analysis host has registered yet" is actionable
        where "no host is large enough" would be misleading.
        """
        if self.worker_count == 0:
            return "no_workers"
        if not self.affordable:
            return "no_capacity"
        return None


def capacity_for(conn: psycopg.Connection, target_os: str) -> Capacity:
    """Could any registered host ever run a job for this OS?

    Asked at submission, against total capacity rather than free. A job no
    host can afford would otherwise sit at the head of the queue forever and,
    because head-of-line blocking is working as designed, hold everything
    behind it.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(queries.CAPACITY, {"target_os": target_os})
        row = cur.fetchone()
        return Capacity(affordable=row["affordable"],
                        worker_count=row["worker_count"])


def register_worker(
    conn: psycopg.Connection,
    *,
    worker_id: str,
    total_mib: int,
    total_vlans: int,
    total_slots: int,
    pipelines: dict[str, int],
) -> None:
    """Record what an analysis host can afford, as the host reports it.

    pipelines maps target_os -> required_mib, each derived ON DOM0 from
    misc/<os>_sandbox.cfg plus that host's own measured domain overhead.
    """
    with conn.cursor() as cur:
        cur.execute(queries.UPSERT_WORKER, {
            "worker_id": worker_id, "total_mib": total_mib,
            "total_vlans": total_vlans, "total_slots": total_slots,
        })
        for os_name, required_mib in pipelines.items():
            cur.execute(queries.UPSERT_PIPELINE, {
                "worker_id": worker_id, "os": os_name,
                "required_mib": required_mib,
            })