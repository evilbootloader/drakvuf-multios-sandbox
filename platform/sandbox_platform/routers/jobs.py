"""The browser channel: submitting samples and reading results.

Issue #36 (DRAFT-043).

**Sample bytes never pass through this process.** The browser uploads
directly to the object store with a presigned POST, and admission reads the
object back as a stream to hash it. A sample written to this machine's
filesystem would be a sample on the one host whose entire security argument
is that it never handles one -- and this process holds the database and
object-store credentials.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

import magic
from fastapi import APIRouter, HTTPException, Path, Query, status
from psycopg.rows import dict_row
from pydantic import BaseModel, Field

from .. import jobs as dal
from .. import objects
from ..config import settings
from ..db import connection
from ..enums import JobState, RejectReason, TargetOs

router = APIRouter(prefix="/api/v1/jobs", tags=["jobs"])


# --- models ---------------------------------------------------------------

class CreateJobRequest(BaseModel):
    # target_os is parsed into the enum HERE, and this is the only place it is
    # validated. Issue #3: the submitter chooses the OS, it is checked against
    # a closed set at exactly one boundary, and file magic never selects it.
    # An unknown value is a 422 before any handler code runs.
    target_os: TargetOs
    filename: str = Field(min_length=1, max_length=1024)
    size_bytes: int = Field(gt=0)


class CreateJobResponse(BaseModel):
    job_id: UUID
    upload_url: str
    upload_fields: dict[str, str]
    expires_in: int


class JobSummary(BaseModel):
    id: UUID
    created_at: datetime
    target_os: TargetOs
    submitted_filename: str
    state: JobState
    sha256: str | None
    size_bytes: int | None


class JobDetail(JobSummary):
    updated_at: datetime
    detected_type: str | None
    queue_reason: str | None
    failure_stage: str | None
    failure_reason: str | None
    attempt: int
    cancel_requested: bool
    manifest: dict | None
    artifacts: dict[str, str] = {}

    # Deliberately absent: blocking_job_id and need_mib.
    #
    # A held job reports THAT something is reserved ahead of it, never which
    # job or how large. Those are another submitter's details the moment
    # `owner` and `visibility` mean anything (M8), and they live on the worker
    # channel where Dom0 needs them for capacity accounting. Do not add them
    # here for symmetry with /worker/claim.
    reserved_ahead: bool = False


class CancelResponse(BaseModel):
    outcome: Literal["cancelled", "cancel_requested", "not_cancellable"]


# --- submission -----------------------------------------------------------

@router.post("", status_code=status.HTTP_201_CREATED)
def create_job(req: CreateJobRequest) -> CreateJobResponse:
    """Create a job record and hand back an upload capability.

    `size_bytes` is checked before the URL is issued, so an oversized sample
    is refused without the transfer ever happening. It is a claim by the
    client, not a fact -- `mark_uploaded` re-checks it against the stored
    object. The early check saves bandwidth; the later one establishes truth.
    """
    if req.size_bytes > settings.max_sample_bytes:
        raise HTTPException(
            status.HTTP_413_CONTENT_TOO_LARGE,
            f"sample exceeds the {settings.max_sample_bytes} byte limit",
        )

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO jobs (target_os, submitted_filename, size_bytes, state)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (req.target_os.value, req.filename, req.size_bytes,
             JobState.RECEIVED.value),
        )
        job_id = cur.fetchone()[0]

    # min(declared, cap): the claim can only tighten the policy, never loosen
    # it -- a declaration above the cap was already refused above. Signing
    # with the cap alone would make `size_bytes` decorative, which it was
    # until 2026-08-23.
    ticket = objects.presigned_upload(
        job_id, req.filename, min(req.size_bytes, settings.max_sample_bytes)
    )
    return CreateJobResponse(
        job_id=job_id,
        upload_url=ticket.url,
        upload_fields=ticket.fields,
        expires_in=ticket.expires_in,
    )


def _reject(conn, job_id: UUID, reason: RejectReason) -> None:
    conn.execute(
        "UPDATE jobs SET state = %s, failure_stage = %s, failure_reason = %s"
        " WHERE id = %s",
        (JobState.REJECTED.value, JobState.ADMITTED.value, reason.value, job_id),
    )


@router.post("/{job_id}/uploaded")
def mark_uploaded(job_id: Annotated[UUID, Path()]) -> JobDetail:
    """Run admission: received -> admitted -> queued, or rejected with a reason.

    Every check happens before a clone exists, so a rejection costs no VM.
    """
    with connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT id, state, target_os, submitted_filename FROM jobs"
                " WHERE id = %s",
                (job_id,),
            )
            job = cur.fetchone()

        if job is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such job")
        if job["state"] != JobState.RECEIVED.value:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"job is {job['state']}; admission runs once, from received",
            )

        key = objects.sample_key(job_id, job["submitted_filename"])

        # Missing or empty. Checked first because everything below reads bytes.
        stored = objects.head(key)
        if stored is None or stored[0] == 0:
            _reject(conn, job_id, RejectReason.UNREADABLE)
            return _detail(conn, job_id)

        # The REAL size, not the declared one. The signed policy bounds what
        # could be written; this establishes what actually was.
        if stored[0] > settings.max_sample_bytes:
            _reject(conn, job_id, RejectReason.REJECTED_SIZE)
            return _detail(conn, job_id)

        # Streamed: hashed without being stored, header kept for libmagic.
        facts = objects.inspect(key)
        detected = magic.from_buffer(facts.head_bytes)

        conn.execute(
            "UPDATE jobs SET sha256 = %s, size_bytes = %s, detected_type = %s,"
            "       sample_etag = %s, state = %s WHERE id = %s",
            (facts.sha256, facts.size_bytes, detected, facts.etag,
             JobState.ADMITTED.value, job_id),
        )

        # Magic REPORTS; it never routes. It may reject a contradiction with
        # the OS the submitter chose, and that is the whole of its authority
        # (issue #3). It must never be used to pick a pipeline.
        if _contradicts(detected, TargetOs(job["target_os"])):
            _reject(conn, job_id, RejectReason.UNSUPPORTED_TYPE)
            return _detail(conn, job_id)

        # Could any registered host ever run this? Asked against TOTAL
        # capacity, not free: a job that only fails because a host is busy
        # belongs in the queue, while one no host can afford would sit at the
        # head of it forever, holding everything behind it.
        capacity = dal.capacity_for(conn, job["target_os"])
        if reason := capacity.reject_reason:
            _reject(conn, job_id, RejectReason(reason))
            return _detail(conn, job_id)

        conn.execute(
            "UPDATE jobs SET state = %s, required_mib = ("
            "    SELECT min(required_mib) FROM worker_pipelines WHERE os = %s"
            ") WHERE id = %s",
            (JobState.QUEUED.value, job["target_os"], job_id),
        )
        return _detail(conn, job_id)


# Contradictions worth acting on, and no more. libmagic's output is a free
# text description, so this matches on substrings that are reliable rather
# than trying to classify exhaustively -- an over-eager rule here rejects
# valid work, which is worse than admitting a sample the guest then fails to
# run. Ambiguity is resolved in the SUBMITTER's favour, per issue #3: if
# detection cannot tell, the run proceeds on their choice.
_CONTRADICTS: dict[TargetOs, tuple[str, ...]] = {
    TargetOs.WINDOWS: ("ELF ",),
    TargetOs.UBUNTU: ("PE32", "MS-DOS executable"),
    TargetOs.ANDROID: (),   # APK is a ZIP and an Android ELF is an ELF
}


def _contradicts(detected: str, target: TargetOs) -> bool:
    return any(marker in detected for marker in _CONTRADICTS[target])


# --- reading --------------------------------------------------------------

def _detail(conn, job_id: UUID) -> JobDetail:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM jobs WHERE id = %s", (job_id,))
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such job")

    artifacts: dict[str, str] = {}
    if row["manifest"]:
        manifest = row["manifest"]
        if isinstance(manifest, str):
            manifest = json.loads(manifest)
        # One presigned GET per artifact, minted per request and short-lived.
        # Never a prefix -- that would be a bucket enumeration primitive over
        # a store holding live malware.
        for name in manifest.get("artifacts", []):
            artifacts[name] = objects.presigned_get(
                f"{objects.result_prefix(job_id)}{name}",
                objects.Audience.BROWSER,
            )

    reserved_ahead = False
    if row["state"] == JobState.QUEUED.value:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT EXISTS (SELECT 1 FROM jobs WHERE state = %s"
                "   AND NOT cancel_requested AND queue_seq < %s)",
                (JobState.QUEUED.value, row["queue_seq"]),
            )
            reserved_ahead = cur.fetchone()[0]

    return JobDetail(
        **{k: row[k] for k in (
            "id", "created_at", "updated_at", "target_os", "submitted_filename",
            "state", "sha256", "size_bytes", "detected_type", "queue_reason",
            "failure_stage", "failure_reason", "attempt", "cancel_requested",
        )},
        manifest=row["manifest"] if isinstance(row["manifest"], dict) else None,
        artifacts=artifacts,
        reserved_ahead=reserved_ahead,
    )


@router.get("")
def list_jobs(
    state: JobState | None = None,
    target_os: TargetOs | None = None,
    sha256: str | None = None,
    before: datetime | None = Query(
        None, description="keyset cursor: return jobs created strictly before this"
    ),
    limit: int = Query(50, ge=1, le=200),
) -> list[JobSummary]:
    """Job history.

    Keyset pagination on created_at rather than OFFSET: this table grows
    without bound, and OFFSET degrades quietly -- page 1 is fast and page 400
    scans everything before it.
    """
    clauses, params = ["TRUE"], []
    if state:
        clauses.append("state = %s")
        params.append(state.value)
    if target_os:
        clauses.append("target_os = %s")
        params.append(target_os.value)
    if sha256:
        clauses.append("sha256 = %s")
        params.append(sha256)
    if before:
        clauses.append("created_at < %s")
        params.append(before)
    params.append(limit)

    # The WHERE clause is assembled from a fixed set of literal fragments; no
    # caller-supplied text ever enters the statement. Every VALUE is bound.
    sql = (
        "SELECT id, created_at, target_os, submitted_filename, state, sha256,"
        "       size_bytes FROM jobs"
        f" WHERE {' AND '.join(clauses)}"
        " ORDER BY created_at DESC LIMIT %s"
    )
    with connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, params)
        return [JobSummary(**row) for row in cur.fetchall()]


@router.get("/{job_id}")
def get_job(job_id: Annotated[UUID, Path()]) -> JobDetail:
    with connection() as conn:
        return _detail(conn, job_id)


@router.post("/{job_id}/cancel")
def cancel_job(job_id: Annotated[UUID, Path()]) -> CancelResponse:
    """Cancel, by whichever route the job's state allows.

    Before a clone exists this is one UPDATE and terminal -- the operation
    DRAFT-040 recorded as unexpressible under dirwatch, where a queued job was
    a file in a directory with no id to name it by. While running it is a
    request the worker collects on its next heartbeat.
    """
    with connection() as conn:
        return CancelResponse(outcome=dal.cancel(conn, job_id))