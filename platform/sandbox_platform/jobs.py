"""Data access for the job queue.

Issue #35 (DRAFT-042). Thin by design: it binds parameters and shapes rows.
The correctness lives in queries.py, where it can be read as SQL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

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
    key_prefix: str
    # Where this job's traffic may go (DRAFT-057). Snapshotted onto the row at
    # submission, so a host that stops offering an exit after a job was queued
    # cannot silently change where that job's sample ends up talking -- Dom0
    # refuses instead, which is the loud outcome.
    egress_mode: str = "offline"
    egress_exit: str | None = None
    # The plugin selection made at submission (DRAFT-052). Snapshotted onto the
    # row for the same reason as egress: the catalogue may change while a job
    # sits in the queue, and the job should run what it was admitted with.
    #
    # **Empty means "the measured defaults", never "no plugins".** A row queued
    # before migration 0010 has NULL here, which `claim` renders as `[]`;
    # `stages._trace_options` reads either as "fall back to
    # `guests.default_trace_options`". Running with no plugin at all produces a
    # trace containing nothing and still reports success.
    plugins: list[str] = field(default_factory=list)
    timeout: int = 180
    disable_sysret: bool = True


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
                egress_mode=row["egress_mode"],
                egress_exit=row["egress_exit"],
                key_prefix=row["key_prefix"],
                # `or []`, so a pre-0010 row's NULL and a submitter who ticked
                # nothing arrive as the same thing. Both mean "the defaults".
                plugins=row["plugins"] or [],
                timeout=row["timeout"],
                disable_sysret=row["disable_sysret"]
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
    exits: list[dict] | None = None,
) -> None:
    """Record what an analysis host can afford, as the host reports it.

    pipelines maps target_os -> required_mib, each derived ON DOM0 from
    misc/<os>_sandbox.cfg plus that host's own measured domain overhead.

    `exits` is the set of ways out this host can provide (DRAFT-057), declared
    for the same reason: only Dom0 knows what its own interfaces are. It is
    REPLACED rather than merged -- see queries.CLEAR_EGRESS.
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

        # Cleared first, unconditionally, INCLUDING when `exits` is empty. A
        # host that now offers nothing must end up offering nothing, and
        # skipping the delete on an empty list would leave its previous set
        # standing -- which is exactly the case that matters, because the empty
        # list is what an operator revoking `direct` produces.
        cur.execute(queries.CLEAR_EGRESS, {"worker_id": worker_id})
        for exit_ in exits or []:
            cur.execute(queries.INSERT_EGRESS, {
                "worker_id": worker_id,
                "name": exit_["name"],
                "mode": exit_["mode"],
                "country": exit_.get("country"),
                "caveats": Jsonb(exit_.get("caveats") or []),
            })


def offered_exits(conn: psycopg.Connection) -> list[dict]:
    """Every exit any registered host can provide, deduplicated by name.

    This is the whole of what a submitter may choose from. A mode absent here is
    unselectable in the UI and refused at admission, which is how `direct` stays
    off the web without a second switch that could disagree with the first.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(queries.OFFERED_EXITS)
        return cur.fetchall()


def exit_available(conn: psycopg.Connection, *, name: str, mode: str) -> bool:
    """Can any host route a job to this exit, in this mode?

    Both are checked together on purpose. Matching the name alone would let a
    submitter pair a real exit name with a different mode and have it accepted
    -- the name would resolve on Dom0 and the mode recorded on the report would
    be a lie about what happened.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(queries.EXIT_AVAILABLE, {"name": name, "mode": mode})
        return bool(cur.fetchone()["available"])