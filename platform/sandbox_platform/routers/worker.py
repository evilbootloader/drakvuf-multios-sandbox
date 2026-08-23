"""The worker channel: everything Dom0 is allowed to ask for.

Issue #36 (DRAFT-043).

**Dom0 opens every connection here and the platform never calls back.** That
is the hardest constraint in platform.md, and it shapes the whole router:
cancellation is delivered in a heartbeat *response* rather than pushed,
because pushing would require an inbound listener on the machine that runs
malware.

Authentication is attached to the router, not to routes, so a route added
later cannot be public by omission. Job-scoped routes additionally resolve
through `leased_job`, so a worker reaches the jobs it currently holds and
nothing else.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from .. import jobs as dal
from ..auth import LeasedJob, require_worker_token
from ..config import settings
from ..db import connection
from ..enums import JobState, TargetOs

router = APIRouter(
    prefix="/api/v1/worker",
    tags=["worker"],
    dependencies=[Depends(require_worker_token)],
)


# --- what a worker may report ---------------------------------------------
#
# Validated server-side because the alternative is trusting the analysis host
# to describe itself accurately, and it is the one machine in this design
# that runs malware. Two failures this prevents:
#
#   - a worker that has lost track of itself reporting `executing` on a job
#     it last reported `cloning`, which would make the state column fiction
#     rather than a record;
#   - a compromised Dom0 marking a job `completed` without doing anything,
#     which is how a sample gets recorded as analysed-and-clean.
#
# Terminal states are reachable only from `cleaning`, mirroring the state
# machine in analysis-pipeline.md: every path that created a clone tears it
# down before it ends.
WORKER_TRANSITIONS: dict[JobState, frozenset[JobState]] = {
    JobState.CLONING:    frozenset({JobState.PREPARING, JobState.CLEANING}),
    JobState.PREPARING:  frozenset({JobState.EXECUTING, JobState.CLEANING}),
    JobState.EXECUTING:  frozenset({JobState.COLLECTING, JobState.CLEANING}),
    JobState.COLLECTING: frozenset({JobState.CLEANING}),
    JobState.CLEANING:   frozenset({
        JobState.COMPLETED, JobState.FAILED,
        JobState.CANCELLED, JobState.INTERRUPTED,
    }),
}


# --- request / response models --------------------------------------------

class PipelineCapacity(BaseModel):
    os: TargetOs
    required_mib: int = Field(gt=0)


class RegisterRequest(BaseModel):
    worker_id: str = Field(min_length=1, max_length=64)
    total_mib: int = Field(gt=0)
    total_vlans: int = Field(gt=0)
    total_slots: int = Field(gt=0)
    pipelines: list[PipelineCapacity]


class ReconcileRequest(BaseModel):
    worker_id: str = Field(min_length=1, max_length=64)
    live_job_ids: list[UUID]


class ClaimRequest(BaseModel):
    worker_id: str = Field(min_length=1, max_length=64)
    free_mib: int = Field(ge=0)
    free_vlans: int = Field(ge=0)
    free_slots: int = Field(ge=0)


class LeaseResponse(BaseModel):
    status: Literal["leased"] = "leased"
    job_id: UUID
    target_os: TargetOs
    sha256: str | None
    submitted_filename: str
    required_mib: int
    lease_expires_at: datetime
    attempt: int


class ReservedResponse(BaseModel):
    """Not an error. A job too large for the caller's current free memory is
    holding its place rather than being starved by smaller ones behind it.

    blocking_job_id and need_mib stay on THIS channel. Dom0 needs the number
    to reason about its own capacity; the browser's view of a held job says
    only that something is reserved ahead of it, because naming another
    submitter's job discloses their details once owner/visibility mean
    anything (M8).
    """

    status: Literal["reserved"] = "reserved"
    blocking_job_id: UUID
    need_mib: int


class IdleResponse(BaseModel):
    status: Literal["idle"] = "idle"


class StateRequest(BaseModel):
    state: JobState
    queue_reason: str | None = None
    failure_stage: str | None = None
    failure_reason: str | None = None
    cleanup_status: str | None = None
    clone_domain: str | None = None
    vlan: int | None = None


class HeartbeatResponse(BaseModel):
    """The only channel by which a running job learns it was cancelled.

    Dom0 has no inbound listener, so there is nowhere to push to. A worker
    that stops heartbeating stops learning, which is correct -- its lease
    then lapses and the record is marked interrupted.
    """

    lease_expires_at: datetime
    cancel_requested: bool


class CompleteRequest(BaseModel):
    manifest: dict


# --- registration and recovery --------------------------------------------

@router.post("/register", status_code=status.HTTP_204_NO_CONTENT)
def register(req: RegisterRequest) -> None:
    """Record what this analysis host can afford.

    Upsert: a worker re-registers on every restart, and its capacity may have
    legitimately changed -- more RAM, or a misc/*.cfg retune. The numbers stay
    DERIVED ON DOM0 from misc/<os>_sandbox.cfg plus that host's own measured
    overhead; computing them here would recreate the two-files-free-to-disagree
    failure platform.env exists to prevent.
    """
    with connection() as conn:
        dal.register_worker(
            conn,
            worker_id=req.worker_id,
            total_mib=req.total_mib,
            total_vlans=req.total_vlans,
            total_slots=req.total_slots,
            pipelines={p.os.value: p.required_mib for p in req.pipelines},
        )


@router.post("/reconcile")
def reconcile(req: ReconcileRequest) -> dict[str, list[UUID]]:
    """Adopt a restarted worker's view of what is actually running.

    Sent before the first claim. Anything this worker holds a lease on but did
    not list died with the previous process.

    This is what makes the lease TTL safe. The TTL expires *bookkeeping*;
    reading Dom0's real state -- `xl list`, `ip link` -- is what decides, and
    that reading happens on Dom0 and arrives here as `live_job_ids`.
    """
    with connection() as conn:
        interrupted = dal.reconcile(
            conn, worker_id=req.worker_id, live_job_ids=req.live_job_ids
        )
    return {"interrupted": interrupted}


# --- taking work ----------------------------------------------------------

@router.post("/claim", response_model=LeaseResponse | ReservedResponse | IdleResponse)
def claim(req: ClaimRequest):
    """Take the head of the queue if it fits, otherwise reserve for it.

    Long-polling with a server-side budget rather than returning immediately.
    The arrangement this replaces logged one "Holding: need ..." line per
    second forever with no backoff -- 170 of them in the 2026-08-20
    measurement -- and a client polling a fast-returning endpoint reproduces
    exactly that from the other side.

    Deliberately a sync `def`, so FastAPI runs it in a threadpool worker: the
    database pool is synchronous, and sleeping inside an `async def` would
    block the event loop for every other request. It occupies one worker for
    up to `claim_poll_seconds`, which is affordable at one analysis host and
    is the cost of not busy-looping.

    `free_mib` is what the CALLER currently has, not what it owns. Capacity
    is a property of the analysis host, reported per poll; the platform never
    infers it.
    """
    deadline = time.monotonic() + settings.claim_poll_seconds
    last: dal.ClaimResult = dal.Idle()

    while True:
        with connection() as conn:
            last = dal.claim(
                conn,
                worker_id=req.worker_id,
                free_mib=req.free_mib,
                lease_seconds=settings.lease_seconds,
            )

        if isinstance(last, dal.Lease):
            return LeaseResponse(
                job_id=last.job_id,
                target_os=TargetOs(last.target_os),
                sha256=last.sha256,
                submitted_filename=last.submitted_filename,
                required_mib=last.required_mib,
                lease_expires_at=last.lease_expires_at,
                attempt=last.attempt,
            )

        if time.monotonic() >= deadline:
            break
        time.sleep(settings.claim_poll_interval)

    if isinstance(last, dal.Reserved):
        return ReservedResponse(
            blocking_job_id=last.blocking_job_id, need_mib=last.need_mib
        )
    return IdleResponse()


# --- reporting on work ----------------------------------------------------

@router.post("/jobs/{job_id}/state", status_code=status.HTTP_204_NO_CONTENT)
def report_state(job: LeasedJob, req: StateRequest) -> None:
    """Record a state transition, if the state machine permits it."""
    current = JobState(job["state"])
    allowed = WORKER_TRANSITIONS.get(current, frozenset())
    if req.state not in allowed:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"illegal transition {current} -> {req.state};"
            f" allowed: {sorted(allowed) or 'none'}",
        )

    # COALESCE so a report carrying only a state does not erase diagnostics an
    # earlier report set. A worker sends what it learned, not the whole row.
    with connection() as conn:
        conn.execute(
            """
            UPDATE jobs
               SET state          = %s,
                   queue_reason   = COALESCE(%s, queue_reason),
                   failure_stage  = COALESCE(%s, failure_stage),
                   failure_reason = COALESCE(%s, failure_reason),
                   cleanup_status = COALESCE(%s, cleanup_status),
                   clone_domain   = COALESCE(%s, clone_domain),
                   vlan           = COALESCE(%s, vlan)
             WHERE id = %s
            """,
            (
                req.state.value, req.queue_reason, req.failure_stage,
                req.failure_reason, req.cleanup_status, req.clone_domain,
                req.vlan, job["id"],
            ),
        )


@router.post("/jobs/{job_id}/heartbeat", response_model=HeartbeatResponse)
def heartbeat(job: LeasedJob) -> HeartbeatResponse:
    """Extend the lease, and deliver a pending cancellation.

    The response is the *only* way a running job learns it was cancelled --
    see HeartbeatResponse.
    """
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE jobs
               SET lease_expires_at = now() + %s::interval
             WHERE id = %s
            RETURNING lease_expires_at, cancel_requested
            """,
            (f"{settings.lease_seconds} seconds", job["id"]),
        )
        expires_at, cancel_requested = cur.fetchone()

    return HeartbeatResponse(
        lease_expires_at=expires_at, cancel_requested=cancel_requested
    )


@router.post("/jobs/{job_id}/complete", status_code=status.HTTP_204_NO_CONTENT)
def complete(job: LeasedJob, req: CompleteRequest) -> None:
    """Terminal: record the manifest and mark the job completed.

    **This one call is what makes publication atomic.** The artifacts are
    already in the object store, but a reader sees nothing until this row
    commits -- so a half-uploaded result set is never served as finished.
    That closes the gap DRAFT-018 carries as a KNOWN GAP.

    Reachable only from `cleaning`, per the transition table: a job that has
    not torn its clone down has not finished.
    """
    if JobState(job["state"]) is not JobState.CLEANING:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"job is {job['state']}; complete is reachable only from cleaning",
        )

    with connection() as conn:
        conn.execute(
            """
            UPDATE jobs
               SET state = %s, manifest = %s, lease_expires_at = NULL
             WHERE id = %s
            """,
            (JobState.COMPLETED.value, json.dumps(req.manifest), job["id"]),
        )