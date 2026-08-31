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
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field, field_validator

from .. import jobs as dal
from .. import manifest as manifest_schema
from .. import objects
from ..auth import LeasedJob, require_worker_token
from ..config import settings
from ..db import connection
from ..enums import EgressMode, JobState, TargetOs

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


class EgressExit(BaseModel):
    """One way out, as the analysis host declares it (DRAFT-057).

    No `interface` field, and its absence is deliberate: a Dom0 device name is
    internal topology, the platform has no use for it, and it would end up
    rendered on a form in a browser.
    """

    name: str = Field(min_length=1, max_length=64)
    mode: EgressMode
    # ISO 3166-1 alpha-2 where it means anything. Free text rather than an enum
    # because it is a label shown to a person, never a routing input -- `name`
    # is what selects the exit.
    country: str | None = Field(default=None, max_length=8)
    caveats: list[str] = Field(default_factory=list, max_length=16)


class RegisterRequest(BaseModel):
    worker_id: str = Field(min_length=1, max_length=64)
    total_mib: int = Field(gt=0)
    total_vlans: int = Field(gt=0)
    total_slots: int = Field(gt=0)
    pipelines: list[PipelineCapacity]
    # Defaulted, so a worker deployed before this field existed still
    # registers -- it simply offers nothing, and every job on it runs offline.
    # That is the correct reading of an old worker's silence.
    exits: list[EgressExit] = Field(default_factory=list, max_length=32)


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
    # Presigned GET for the sample, signed for the LAN endpoint (#39). Dom0
    # holds no object-store credential; this is the whole of its access, and
    # it is scoped to one key with a short expiry.
    sample_url: str

    # Where this job's traffic may go (DRAFT-057). The NAME of an exit the host
    # itself declared, never an endpoint a submitter supplied -- so this is the
    # platform handing back a token the worker gave it, not an instruction the
    # worker must trust.
    #
    # `egress_exit` is None for `offline`, which has no exit to name. sandboxd
    # reads a missing or null exit as offline, so the two agree by default
    # rather than by agreement.
    egress_mode: EgressMode
    egress_exit: str | None = None


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

    # What the host ACTUALLY installed (DRAFT-057), reported at `preparing`
    # alongside clone_domain and vlan because it is learned at the same moment.
    #
    # Not validated field by field, deliberately. This is a diagnostic record
    # whose shape varies by mode and is still being decided by Phases 2-5, and
    # a strict model here would reject a worker that learned something new
    # before the platform did -- turning extra information into a failed run.
    # It is written to jsonb and rendered escaped; it never routes anything.
    egress: dict | None = None


class HeartbeatResponse(BaseModel):
    """The only channel by which a running job learns anything.

    Dom0 has no inbound listener, so there is nowhere to push to. A worker
    that stops heartbeating stops learning, which is correct -- its lease
    then lapses and the record is marked interrupted.

    `console_requested` rides the same channel as `cancel_requested`, for the
    same reason (DRAFT-056). The operator asks for a console on the job row;
    the worker finds out on its next beat and dials OUT. Nothing connects to
    Dom0, so the deploy runbook's step-5 check still fails to reach it -- even
    during a live session, which is what the draft asked for and what its own
    diagram would have prevented.
    """

    lease_expires_at: datetime
    cancel_requested: bool
    console_requested: bool = False


class CompleteRequest(BaseModel):
    # Was `dict`, and was the one worker-supplied payload with no shape at all
    # while every other one -- names, sizes, filenames -- was carefully bounded.
    # See sandbox_platform/manifest.py for what that cost.
    manifest: manifest_schema.Manifest


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
            exits=[{"name": e.name, "mode": e.mode.value,
                    "country": e.country, "caveats": e.caveats}
                   for e in req.exits],
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
            key = objects.sample_key(last.job_id, last.submitted_filename)

            # The sample must be the one admission looked at.
            #
            # The browser's presigned POST outlives admission, so an object
            # can be replaced after it was hashed and queued. Running the
            # replacement would mean the trace, the verdict and the recorded
            # SHA-256 all describe a file that was never executed -- so a
            # mismatch fails the job loudly instead.
            with connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT sample_etag FROM jobs WHERE id = %s", (last.job_id,)
                )
                expected = cur.fetchone()[0]

            status_ = objects.sample_status(key, expected)
            if status_ != "ok":
                # "missing" and "changed" are kept apart because they have
                # different causes: retention expiring a long-queued sample
                # (#37) versus the upload URL being reused after admission.
                reason = ("sample_expired_or_removed" if status_ == "missing"
                          else "sample_changed_after_admission")
                # `failure_stage` is the state the job was actually IN, which
                # `claim` has already moved to `cloning` (queries.CLAIM). It
                # recorded `queued` until 2026-08-27 -- a stage the job had
                # left before this check could run, and precisely the
                # misattribution `failure_stage` exists to prevent. REAP and
                # RECONCILE both use `failure_stage = state` for the same
                # reason.
                with connection() as conn:
                    conn.execute(
                        "UPDATE jobs SET state = %s, failure_stage = %s,"
                        "       failure_reason = %s, lease_owner = NULL,"
                        "       lease_expires_at = NULL WHERE id = %s",
                        (JobState.FAILED.value, JobState.CLONING.value,
                         reason, last.job_id),
                    )
                continue   # take the next job rather than hand back nothing

            return LeaseResponse(
                job_id=last.job_id,
                target_os=TargetOs(last.target_os),
                sha256=last.sha256,
                submitted_filename=last.submitted_filename,
                required_mib=last.required_mib,
                lease_expires_at=last.lease_expires_at,
                attempt=last.attempt,
                sample_url=objects.presigned_get(key, objects.Audience.WORKER,
                                                 ttl=settings.lease_seconds),
                egress_mode=EgressMode(last.egress_mode),
                egress_exit=last.egress_exit,
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
                   vlan           = COALESCE(%s, vlan),
                   egress_applied = COALESCE(%s, egress_applied)
             WHERE id = %s
            """,
            (
                req.state.value, req.queue_reason, req.failure_stage,
                req.failure_reason, req.cleanup_status, req.clone_domain,
                req.vlan, Jsonb(req.egress) if req.egress is not None else None,
                job["id"],
            ),
        )


@router.post("/jobs/{job_id}/heartbeat", response_model=HeartbeatResponse)
def heartbeat(job: LeasedJob) -> HeartbeatResponse:
    """Extend the lease, and deliver anything pending for the worker.

    The response is the *only* way a running job learns it was cancelled, or
    that a console session is wanted -- see HeartbeatResponse.
    """
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE jobs
               SET lease_expires_at = now() + %s::interval
             WHERE id = %s
            RETURNING lease_expires_at, cancel_requested, console_requested
            """,
            (f"{settings.lease_seconds} seconds", job["id"]),
        )
        expires_at, cancel_requested, console_requested = cur.fetchone()

    return HeartbeatResponse(
        lease_expires_at=expires_at,
        cancel_requested=cancel_requested,
        # Reported only while the feature is enabled, so turning the flag off
        # stops sessions being requested without a redeploy -- DRAFT-056 wants
        # the first exception to "Dom0 never listens" switchable off while
        # confidence is built. (It is not an exception any more, since Dom0
        # dials out, but the flag is still worth having.)
        console_requested=console_requested and settings.console_enabled,
    )


class ArtifactTicket(BaseModel):
    """A presigned POST: the URL, plus the form fields carrying the policy."""

    url: str
    fields: dict[str, str]
    expires_in: int


class ArtifactRequest(BaseModel):
    # Relative names under results/<job_id>/, each mapped to the size the
    # worker is about to upload.
    #
    # max_length bounds names PER CALL, not per job -- a worker may call this
    # endpoint again. See config.max_artifact_bytes for what actually bounds a
    # job's total, which is the bucket quota and not anything here.
    artifacts: dict[str, Annotated[int, Field(ge=0)]] = Field(
        min_length=1, max_length=64
    )

    @field_validator("artifacts")
    @classmethod
    def _names_stay_in_the_prefix(cls, v: dict[str, int]) -> dict[str, int]:
        # The same validator the manifest uses. Shared rather than duplicated
        # because these names arrive through two doors -- here when the ticket
        # is minted, and again at /complete -- and for a while only this one
        # was guarded.
        for name in v:
            manifest_schema.reject_unsafe_name(name)
        return v


@router.post("/jobs/{job_id}/artifacts")
def artifact_urls(job: LeasedJob,
                  req: ArtifactRequest) -> dict[str, ArtifactTicket]:
    """Size-capped presigned POSTs for this job's results, one per name.

    One ticket per key, never a prefix: a prefix-scoped write capability would
    let a compromised worker rewrite the whole result set, including other
    jobs' if the prefix were ever widened by accident.
    """
    # Charge the whole request against the job's budget FIRST, in one
    # statement, so two concurrent requests cannot both read the old total and
    # both pass. A job is leased by one worker, so this is belt-and-braces
    # rather than a live race -- but the alternative is a read-then-write that
    # is wrong by construction.
    #
    # Charged when the ticket is minted, not when bytes land, because the API
    # is not in the upload path -- the worker POSTs straight to MinIO. The
    # point is to refuse the CAPABILITY, which is the only moment refusing
    # still prevents anything.
    #
    # So a ticket the worker never uses is still charged, and asking twice for
    # the same name charges twice. Both over-count rather than under-count,
    # which is the safe direction. Never reset: a job_id is analysed once and a
    # retry is a new job.
    total = sum(req.artifacts.values())
    with connection() as conn:
        charged = conn.execute(
            """
            UPDATE jobs
               SET results_bytes = results_bytes + %(delta)s
             WHERE id = %(id)s
               AND results_bytes + %(delta)s <= %(cap)s
            RETURNING results_bytes
            """,
            {"delta": total, "id": job["id"],
             "cap": settings.max_job_result_bytes},
        ).fetchone()

    if charged is None:
        raise HTTPException(
            status.HTTP_413_CONTENT_TOO_LARGE,
            f"job would exceed its {settings.max_job_result_bytes} byte result "
            f"budget; requested {total} more",
        )

    tickets: dict[str, ArtifactTicket] = {}
    for name, size in req.artifacts.items():
        # Names were validated by ArtifactRequest, which refuses anything that
        # could leave this prefix -- see manifest.reject_unsafe_name.
        if size > settings.max_artifact_bytes:
            raise HTTPException(
                status.HTTP_413_CONTENT_TOO_LARGE,
                f"artifact {name!r} exceeds the "
                f"{settings.max_artifact_bytes} byte limit",
            )
        ticket = objects.presigned_artifact_upload(
            f"{objects.result_prefix(job['id'])}{name}",
            min(size, settings.max_artifact_bytes),
        )
        tickets[name] = ArtifactTicket(url=ticket.url, fields=ticket.fields,
                                       expires_in=ticket.expires_in)
    return tickets


@router.post("/jobs/{job_id}/complete", status_code=status.HTTP_204_NO_CONTENT)
def complete(job: LeasedJob, req: CompleteRequest) -> None:
    """Terminal: record the manifest and mark the job completed.

    **This one call is what makes publication atomic.** The artifacts are
    already in the object store, but a reader sees nothing until this row
    commits -- so a half-uploaded result set is never served as finished.
    That closed the atomic-publication gap DRAFT-018 used to carry; it is
    struck in `result-schema.md` §3 rather than still listed as pending.

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
            (JobState.COMPLETED.value, req.manifest.model_dump_json(), job["id"]),
        )