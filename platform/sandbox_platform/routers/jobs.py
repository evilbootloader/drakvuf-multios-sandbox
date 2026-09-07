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
import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from urllib.parse import quote
from uuid import UUID, uuid4

import magic
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from fastapi.responses import StreamingResponse
from psycopg.rows import dict_row
from pydantic import BaseModel, Field, model_validator

from .. import auth
from .. import events
from .. import jobs as dal
from .. import manifest as manifest_schema
from .. import objects
from .. import packaging
from ..config import settings
from ..db import connection
from ..enums import (
    TERMINAL_STATES,
    EgressMode,
    JobState,
    RejectReason,
    TargetOs,
    Visibility,
)

import logging
log = logging.getLogger(__name__)

# The identity dependency is attached to the ROUTER, not to routes, so a
# route added later cannot forget it. It is a no-op unless
# REQUIRE_ACCESS_JWT is set for this listener -- see auth.access_identity.
router = APIRouter(prefix="/api/v1/jobs", tags=["jobs"],
                   dependencies=[Depends(auth.access_identity)])


# --- models ---------------------------------------------------------------

# An S3 key caps at 1024 BYTES. `samples/<uuid>/` spends 45 and the owner
# prefix `u/<owner>/<shard>/` up to 261 more (`objects.MAX_OWNER`), leaving
# 718. 512 is well inside that and far above any real sample name.
#
# The sample path is NOT the binding one -- `manifest.MAX_ARTIFACT_NAME` is
# 718 against this 512, so it is the constant that actually exhausts the
# budget and the one `test_the_longest_admissible_key_still_fits_s3` measures.
# An earlier version of that test checked only this path, which is how
# MAX_ARTIFACT_NAME came to be 900 while the prefix it budgeted for grew from
# 45 bytes to 306.
#
# Bytes, not characters: pydantic's max_length counts characters, so the
# previous `max_length=1024` admitted a multi-byte name that minted a key S3
# cannot store -- the submitter got a 201 and a URL that could only ever fail.
# `dirwatch.c`'s MAX_SAMPLE_NAME is 200; it is a buffer limit there, not this
# constraint, so the numbers differ on purpose.
_MAX_SAMPLE_NAME = 512


# Characters NTFS refuses outright, and `:` is the dangerous one rather than
# the noisy one: `sample.exe:payload` is not a file called that, it is an
# ALTERNATE DATA STREAM on `sample.exe`. `injector -m writefile` would create
# the stream, and what `drakvuf-windows.sh` then executes is ambiguous -- a
# sample could be staged under one name and run from another. Extension
# dispatch and argv[0] self-checks are already live evasion surface (DRAFT-030);
# an ADS is a place to hide the payload entirely.
_WINDOWS_FORBIDDEN = set('<>:"/\\|?*')

# DOS device names, still special on every modern Windows. Writing to `CON`
# writes to the console rather than to a file, so the sample never lands and
# the failure looks like a broken injector. Reserved WITH an extension too:
# `CON.txt` is CON.
_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{d}" for d in range(1, 10)}
    | {f"LPT{d}" for d in range(1, 10)}
)


def _reject_for_windows_guest(name: str) -> None:
    """NTFS rules, applied only when the sample is bound for a Windows guest.

    Per-target rather than a lowest common denominator, because `target_os`
    arrives in the same request and the submitted name is part of what is being
    analysed. `payload:1.bin` is a legal Linux filename; refusing it for an
    Ubuntu sample would discard evidence to satisfy a constraint that does not
    apply to it.
    """
    bad = sorted(_WINDOWS_FORBIDDEN & set(name))
    if bad:
        raise ValueError(
            f"filename contains {''.join(bad)!r}, which NTFS refuses: {name!r}"
        )
    if name.split(".")[0].upper() in _WINDOWS_RESERVED:
        raise ValueError(f"filename is a reserved Windows device name: {name!r}")
    if name[-1] in ". ":
        # Windows strips these silently, so the staged file would not have the
        # name that was submitted and the SHA-256 would describe a file at a
        # path nothing wrote.
        raise ValueError(f"filename ends with a dot or space: {name!r}")


def _reject_unsafe_filename(name: str, target: TargetOs | None = None) -> str:
    """Refuse a submitted filename that cannot be a safe path component.

    Two layers. The universal rules below hold for every target; the
    Windows-only rules are in `_reject_for_windows_guest`, because the guest's
    filesystem is what the name ultimately has to survive:

    | Guest | Staging path | Forbidden |
    |---|---|---|
    | Ubuntu | `/home/<user>/Desktop` (ext4) | `/`, NUL |
    | Android | `/data/local/tmp` (ext4/f2fs) | `/`, NUL |
    | Windows | NTFS | `<>:"/\\|?*`, device names, trailing dot/space |

    macOS is not a target of this project (CLAUDE.md names three), so no APFS
    branch exists. If one is ever added, `:` is the character to look at --
    legal in POSIX APIs but the historic HFS separator, which Finder still
    renders as `/`.

    This mirrors `sample_name_admissible()` in `automation/dirwatch.c:250`,
    deliberately: the API is now the submission boundary that `dirwatch`'s
    inotify watch used to be, and the two must not disagree about what a
    sample may be called.

    Three distinct things depend on it, and only the first is about this
    process:

    - **The object key.** `samples/<job_id>/<name>` must stay inside its
      prefix. MinIO happens to refuse `..` components itself
      (`XMinioInvalidObjectName`, checked 2026-08-24), so this is not a live
      escape today -- but that is MinIO's behaviour, not S3's. On real S3 a key
      is fully opaque and `samples/<job>/../../x` is a legal, distinct key, so
      the object would land outside the prefix the whole model assumes.
      DRAFT-044 calls moving to real S3 "a configuration change, not a
      redesign", which is exactly why this cannot rest on the store.
    - **The guest staging path.** `preconfig-*.sh` writes to
      `$GUEST_STAGING_DIR/<submitted filename>` and `drakvuf-*.sh` executes it.
      A `/` in the name moves that path.
    - **Every log line and parser downstream.** A newline in a name forges log
      entries, which is `dirwatch`'s stated reason for the same rule.

    Refused, never sanitised. The submitted name is part of what is being
    analysed -- DRAFT-030 -- so a rewritten name would analyse something the
    submitter did not send.
    """
    if len(name.encode()) > _MAX_SAMPLE_NAME:
        raise ValueError(f"filename exceeds {_MAX_SAMPLE_NAME} bytes")
    if "/" in name:
        raise ValueError(f"filename contains a path separator: {name!r}")
    if name in (".", ".."):
        raise ValueError(f"filename is a directory entry, not a sample: {name!r}")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
        raise ValueError(f"filename contains a control character: {name!r}")
    if target is TargetOs.WINDOWS:
        _reject_for_windows_guest(name)
    return name


class CreateJobRequest(BaseModel):
    # target_os is parsed into the enum HERE, and this is the only place it is
    # validated. Issue #3: the submitter chooses the OS, it is checked against
    # a closed set at exactly one boundary, and file magic never selects it.
    # An unknown value is a 422 before any handler code runs.
    target_os: TargetOs
    filename: str = Field(min_length=1, max_length=_MAX_SAMPLE_NAME)
    size_bytes: int = Field(gt=0)

    # The second untrusted routing input (DRAFT-057), validated at this same
    # boundary and for the same reasons. Two fields rather than one because
    # they answer different questions: the mode is what KIND of way out, the
    # exit is WHICH one -- and one deployment will have several `routed` exits
    # in different countries.
    #
    # BOTH OPTIONAL, and the server resolves what is missing -- see
    # `_resolve_egress`. Requiring them would break every existing client, and
    # more importantly it would make the API unusable during the phases where a
    # mode exists in this enum but no host implements it yet: a hard default of
    # `simulated` refuses every submission on a deployment with no responder,
    # which is a fleet-wide outage caused by a default.
    #
    # `None` means "whatever is safest here", never "whatever is convenient".
    # The resolver only ever picks a mode that does not reach the Internet.
    egress_mode: EgressMode | None = None
    #: The NAME of an exit an analysis host declared. **Never an endpoint.**
    #: A submitter naming a tunnel endpoint would be choosing where Dom0 sends
    #: traffic, which is a different feature with a different threat model.
    #: Length-bounded to match `worker_egress.name`; content is checked against
    #: the declared set at admission, not here.
    egress_exit: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def _exit_suits_the_mode(self) -> CreateJobRequest:
        """Reject only what is incoherent no matter what any host offers.

        That is exactly one combination: `offline` with an exit named. There is
        nowhere for the traffic to go, so the name cannot mean anything, and
        accepting it would record a job whose row says two contradictory things.

        The opposite case -- a mode with no exit named -- is NOT an error. It
        means "any exit that does this", which `_resolve_egress` answers
        against what the hosts actually declare. Deciding it here would mean
        deciding it without that knowledge.
        """
        if self.egress_mode is EgressMode.OFFLINE and self.egress_exit:
            raise ValueError(
                "offline names no exit -- there is nowhere for the traffic to "
                f"go, so {self.egress_exit!r} cannot mean anything"
            )
        return self

    # A model validator rather than a field one, because the rules depend on
    # `target_os` and a field validator cannot see a sibling field.
    @model_validator(mode="after")
    def _filename_suits_the_target(self) -> CreateJobRequest:
        _reject_unsafe_filename(self.filename, self.target_os)
        return self


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

    # The authenticated submitter, from the Access JWT's email claim. NULL on
    # anything submitted over the mTLS listener: a client certificate
    # identifies a machine, and this column is for a person.
    #
    # Since #40 a reader only ever sees rows this value permits: their own,
    # the ownerless ones, and published ones. So `owner` on a returned row is
    # either the caller, NULL, or the publisher of something public -- never
    # an arbitrary third party's address harvested from a listing.
    owner: str | None = None

    # Decisions 5/6 of #40: private by default, published by the owner after the
    # fact. Read by `auth.visible_to`'s third arm; written only by the two
    # routes at the foot of this module.
    #
    # **No default, for the same reason `egress_mode` above has none.** This
    # model is built from an explicit key list in `_detail`, so a default would
    # answer for a column dropped from that list -- and `private` is exactly the
    # reassuring lie nobody would notice on a report.
    visibility: Visibility


class JobDetail(JobSummary):
    updated_at: datetime

    # What was ASKED FOR, and what the host actually DID (DRAFT-057).
    #
    # Both, always, because they can differ and the difference is the point: a
    # run that requested `simulated` on a host whose responder was down ran
    # `offline`, and an empty network section means something completely
    # different in those two cases. DRAFT-057 calls recording the mode a
    # correctness requirement for exactly this reason -- "a report showing no
    # network activity means nothing without knowing whether egress existed".
    #
    # `egress_applied` is null until the worker reaches `preparing`. That is
    # not missing data: before then, nothing had been installed.
    #
    # **`egress_mode` has NO DEFAULT, deliberately.** It carried
    # `= EgressMode.OFFLINE` for about an hour, and in that hour every report
    # said `offline` regardless of what the job actually did -- because
    # `_detail` builds this model from an explicit key list and the column had
    # not been added to it, so the default answered instead. A required field
    # makes that a loud construction error rather than a plausible-looking lie
    # on a report, and "the sample had no network" is exactly the lie that
    # costs an analyst the most.
    egress_mode: EgressMode
    egress_exit: str | None = None
    egress_applied: dict | None = None
    detected_type: str | None
    queue_reason: str | None
    failure_stage: str | None
    failure_reason: str | None
    attempt: int
    cancel_requested: bool
    manifest: dict | None
    artifacts: dict[str, str] = {}

    # Set when the manifest could not be read. The job still renders -- state,
    # timings and sample identity are all on the row and all still true -- and
    # `artifacts` is empty, because a list that could not be validated is not a
    # list to mint capabilities from. `manifest` itself is still returned raw,
    # which is what makes a malformed one diagnosable at all.
    manifest_error: str | None = None

    # Set when a human drove this run through the live console (DRAFT-056).
    # Permanent, and rendered on the report: an interactive run is not
    # comparable to an automated one, so two reports that look alike must not
    # describe different experiments.
    interacted: bool = False

    # True for a manifest in the pre-DRAFT-018 shape: a list of bare names,
    # with no size or digest. Reported rather than hidden so "we do not know
    # this file's size" is distinguishable from "this file is 0 bytes".
    manifest_legacy: bool = False

    # True once the job is older than the store's retention window, at which
    # point `artifacts` is empty because MinIO has expired the objects behind
    # it (issue #37). The manifest still lists what the run produced, so a
    # reader can tell "this analysis collected a pcap, and it is gone" from
    # "this analysis collected nothing" -- which one empty dict alone cannot.
    artifacts_expired: bool = False

    # Deliberately absent: blocking_job_id and need_mib.
    #
    # A held job reports THAT something is reserved ahead of it, never which
    # job or how large. Those are another submitter's details -- literally so
    # since #40, because the job ahead is frequently one this caller may not
    # read -- and they live on the worker channel where Dom0 needs them for
    # capacity accounting. Do not add them here for symmetry with
    # /worker/claim.
    reserved_ahead: bool = False


class CancelResponse(BaseModel):
    outcome: Literal["cancelled", "cancel_requested", "not_cancellable"]


class VisibilityResponse(BaseModel):
    """The row's visibility after the write, so a caller re-renders from fact
    rather than from what it assumed the request would do."""

    visibility: Visibility

# --- submission -----------------------------------------------------------

#: Tried in order when a submitter expresses no preference. **Every entry must
#: be a mode that cannot reach the Internet.** Extending this list with a live
#: mode would make "I didn't say" mean "detonate it on the network", which is
#: the one thing DRAFT-057 exists to stop happening by accident.
#:
#: `simulated` first because it is the more faithful of the two -- a black-holed
#: network is itself a sandbox signal -- and `offline` behind it because it
#: needs no responder and therefore always works. On a deployment where Phase 3
#: has not shipped, no host offers `simulated` and this resolves to `offline`
#: silently and correctly, rather than refusing every submission.
_SAFE_DEFAULT_MODES = (EgressMode.SIMULATED, EgressMode.OFFLINE)


def _resolve_egress(conn, req: CreateJobRequest) -> tuple[str, str | None]:
    """Fill in whatever the submitter left unsaid, from what hosts declare.

    Three cases, and the middle one is the reason this exists:

    * **Nothing said** -- take the first mode in `_SAFE_DEFAULT_MODES` that
      some host offers. Never a live mode, whatever the hosts have.
    * **A mode, no exit** -- "any exit that does this". Resolved to the
      lowest-named one, deterministically, so two identical submissions get the
      same answer and a report can be compared with another report.
    * **Both said** -- taken as given. Whether it is actually available is
      admission's question, asked later against the same table, because a host
      can deregister between these two moments.

    Resolved at CREATE rather than at admission so the row records a concrete
    decision from the first instant it exists. A row that said "decide later"
    would leave a window where the job's own record could not answer what would
    happen to the sample -- and that record is the thing the report rests on.
    """
    offers = dal.offered_exits(conn)

    if req.egress_mode is None:
        for mode in _SAFE_DEFAULT_MODES:
            if mode is EgressMode.OFFLINE:
                # Always available: on Dom0 it is the absence of a rule, so it
                # needs no declaration and cannot be unavailable.
                return EgressMode.OFFLINE.value, None
            named = sorted(o["name"] for o in offers if o["mode"] == mode.value)
            if named:
                return mode.value, named[0]

    if req.egress_mode is EgressMode.OFFLINE:
        return EgressMode.OFFLINE.value, None

    if req.egress_exit:
        return req.egress_mode.value, req.egress_exit

    named = sorted(o["name"] for o in offers
                   if o["mode"] == req.egress_mode.value)
    # An empty list is left as-is rather than downgraded. The submitter asked
    # for a specific kind of way out; admission refuses with `no_egress`, which
    # tells them their request could not be met. Quietly running it offline
    # would produce a report whose empty network section they would read as a
    # finding about the sample.
    return req.egress_mode.value, (named[0] if named else None)


@router.post("", status_code=status.HTTP_201_CREATED)
def create_job(req: CreateJobRequest,
               owner: auth.RequiredIdentity) -> CreateJobResponse:
    """Create a job record and hand back an upload capability.

    `size_bytes` is checked before the URL is issued, so an oversized sample
    is refused without the transfer ever happening. It is a claim by the
    client, not a fact -- `mark_uploaded` re-checks it against the stored
    object. The early check saves bandwidth; the later one establishes truth.

    **RequiredIdentity, not Identity**: this writes `jobs.owner`, which is NOT
    NULL since migration 0008, so a caller without an identity is refused with
    a 403 rather than a constraint violation. See `auth.required_identity`.
    """
    # The same upsert `routers.account.get_balance` uses, and it has to be the
    # same shape: the UI asks for a balance on page load while a headless
    # client submits without ever asking, so on a first visit these two race
    # by construction. Test-then-insert loses that race.
    #
    # **Its own transaction, separate from the job INSERT below, on purpose.**
    # A 402 raised here still leaves the tenant row committed, which is what
    # should happen: the row is a fact about who has reached the platform, not
    # part of the submission, and creating it again on the next attempt would
    # be the same INSERT with the same result. Rolling it back would mean a
    # refused submitter has no balance to be shown why they were refused.
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO tenants (owner) VALUES (%s)
            ON CONFLICT (owner) DO UPDATE SET owner = EXCLUDED.owner
            RETURNING balance_seconds
            """,
            (owner,),
        )
        balance_seconds = cur.fetchone()[0]

    # At or below zero, not below: a balance of exactly nothing buys nothing.
    #
    # This is the ONLY gate. Nothing stops a job already running from taking a
    # balance negative -- the charge lands when it finishes and no per-job cap
    # exists -- which is deliberate, because refusing mid-analysis would
    # destroy host time already spent. See the tenants comment in 0008.
    if balance_seconds <= 0:
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            f"account has {balance_seconds} analysis seconds remaining",
        )

    if req.size_bytes > settings.max_sample_bytes:
        raise HTTPException(
            status.HTTP_413_CONTENT_TOO_LARGE,
            f"sample exceeds the {settings.max_sample_bytes} byte limit",
        )

    # Generated here rather than by the column default, because `key_prefix`
    # contains a shard derived from the id and has to be a value in the same
    # INSERT -- see migration 0008.
    job_id = uuid4()
    try:
        key_prefix = objects.owner_prefix(job_id, owner)
    except ValueError as exc:
        # Nothing the submitter can fix -- the value is the Access token's
        # `email` claim -- so the operator is told at error level and the
        # caller gets the reason rather than a bare failure.
        #
        # 400 rather than 500: this is a deliberate refusal with a specific
        # cause, not the platform breaking, and it must not be retried.
        # Rather than 401 because the token verified fine; the identity in it
        # is simply not one this layout can hold.
        log.error("identity unusable as a key prefix: %s", exc)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    with connection() as conn, conn.cursor() as cur:
        egress_mode, egress_exit = _resolve_egress(conn, req)
        cur.execute(
            """
            INSERT INTO jobs (id, target_os, submitted_filename, size_bytes,
                              state, owner, egress_mode, egress_exit, key_prefix)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (job_id, req.target_os.value, req.filename, req.size_bytes,
             JobState.RECEIVED.value, owner, egress_mode, egress_exit,
             key_prefix),
        )
        job_id = cur.fetchone()[0]

    # min(declared, cap): the claim can only tighten the policy, never loosen
    # it -- a declaration above the cap was already refused above. Signing
    # with the cap alone would make `size_bytes` decorative, which it was
    # until 2026-08-23.
    ticket = objects.presigned_upload(
        job_id, req.filename, min(req.size_bytes, settings.max_sample_bytes), key_prefix
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
def mark_uploaded(job_id: Annotated[UUID, Path()],
                  identity: auth.Identity = None) -> JobDetail:
    """Run admission: received -> admitted -> queued, or rejected with a reason.

    Every check happens before a clone exists, so a rejection costs no VM.

    Scoped like every other read, although the caller here is by construction
    the job's own submitter -- it holds an id issued to it seconds earlier by
    `create_job`. The check buys nothing on the honest path and is here anyway,
    because a `_detail` that is scoped on some paths and not others is what
    gets copied into the next route.
    """
    scope, scope_params = auth.visible_to(identity)
    with connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT id, state, target_os, submitted_filename,"
                "       egress_mode, egress_exit, key_prefix FROM jobs"
                f" WHERE id = %s AND {scope}",
                (job_id, *scope_params),
            )
            job = cur.fetchone()

        if job is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such job")
        if job["state"] != JobState.RECEIVED.value:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"job is {job['state']}; admission runs once, from received",
            )

        key = objects.sample_key(job_id, job["submitted_filename"], job["key_prefix"])

        # Missing or empty. Checked first because everything below reads bytes.
        stored = objects.head(key)
        if stored is None or stored[0] == 0:
            _reject(conn, job_id, RejectReason.UNREADABLE)
            return _detail(conn, job_id, identity)

        # The REAL size, not the declared one. The signed policy bounds what
        # could be written; this establishes what actually was.
        if stored[0] > settings.max_sample_bytes:
            _reject(conn, job_id, RejectReason.REJECTED_SIZE)
            return _detail(conn, job_id, identity)

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
            return _detail(conn, job_id, identity)

        # Could any registered host ever run this? Asked against TOTAL
        # capacity, not free: a job that only fails because a host is busy
        # belongs in the queue, while one no host can afford would sit at the
        # head of it forever, holding everything behind it.
        capacity = dal.capacity_for(conn, job["target_os"])
        if reason := capacity.reject_reason:
            _reject(conn, job_id, RejectReason(reason))
            return _detail(conn, job_id, identity)

        # Can any host route this sample where the submitter asked?
        #
        # Asked here, with the capacity questions, because the answer is the
        # same KIND of answer: a job no host can serve belongs in 'rejected'
        # where the submitter can act on it, not at the head of a queue holding
        # everything behind it.
        #
        # `offline` is skipped rather than checked. It is the absence of a rule
        # on Dom0, so every host can always provide it and there is nothing to
        # look up -- checking would create a way for the safest mode to be
        # refused, which is the wrong direction to fail in.
        #
        # **This is the gate on `direct`.** A host that has not opted in never
        # declared it, so `worker_egress` has no row and the submission is
        # refused here -- with no separate rule about `direct` anywhere in this
        # file that could fall out of step with the host's actual posture.
        if job["egress_mode"] != EgressMode.OFFLINE.value:
            if not dal.exit_available(conn, name=job["egress_exit"],
                                      mode=job["egress_mode"]):
                _reject(conn, job_id, RejectReason.NO_EGRESS)
                return _detail(conn, job_id, identity)

        conn.execute(
            "UPDATE jobs SET state = %s, required_mib = ("
            "    SELECT min(required_mib) FROM worker_pipelines WHERE os = %s"
            ") WHERE id = %s",
            (JobState.QUEUED.value, job["target_os"], job_id),
        )
        return _detail(conn, job_id, identity)


# Contradictions worth acting on, and no more. libmagic's output is a free
# text description, so this matches on substrings that are reliable rather
# than trying to classify exhaustively -- an over-eager rule here rejects
# valid work, which is worse than admitting a sample the guest then fails to
# run. Ambiguity is resolved in the SUBMITTER's favour, per issue #3: if
# detection cannot tell, the run proceeds on their choice.
_CONTRADICTS: dict[TargetOs, tuple[str, ...]] = {
    TargetOs.WINDOWS: ("ELF ", "Android package"),
    TargetOs.UBUNTU: ("PE32", "MS-DOS executable", "Android package"),
    TargetOs.ANDROID: (),   # APK is a ZIP and an Android ELF is an ELF
}

# "Android package" is admitted as a contradiction on the two non-Android
# guests because the mismatch is not merely unrunnable, it routes wrongly.
# `sandboxd/stages.py` enters the APK install path on `job.kind` ALONE, and
# `guests.argv_install_apk` hardcodes Android's shell -- so an APK submitted
# against Ubuntu on 2026-08-29 produced `injector -r .../linux.json -e
# /system/bin/sh` with an Ubuntu staging path, failing at execve with ENOENT
# several minutes and one clone later.
#
# It stays conservative in the way the note above asks for: it matches
# libmagic's confident "Android package (APK)" and NOT "Zip archive data",
# which an APK also is and which a legitimate Windows sample container could
# be. A submitter whose file libmagic cannot place still gets their choice.


def _contradicts(detected: str, target: TargetOs) -> bool:
    return any(marker in detected for marker in _CONTRADICTS[target])


# --- reading --------------------------------------------------------------
#
# **Every read below is scoped by `auth.visible_to`** (issue #40, DRAFT-047
# decision 4), and the scope goes into the WHERE clause rather than into an
# `if` after the fetch. That is deliberate: a post-fetch check leaves a window
# where another user's row exists as a Python object, and the next person to
# add a code path through here has to remember it. In the WHERE clause there is
# nothing to remember.
#
# **A job the caller may not see is 404, never 403**, and with the same detail
# string a genuinely missing id gets. A 403 confirms the id exists, which turns
# this API into an oracle for enumerating other people's job ids.
#
# `scope` is interpolated with an f-string, and that is not a SQL injection:
# it is a literal fragment this process wrote, and every VALUE it refers to is
# passed separately as a bound parameter. Same construction as `_filters`
# below, for the same reason.


def _visible_or_404(conn, job_id: UUID, identity: str | None) -> None:
    """Refuse unless this caller may see this job.

    For the routes that act rather than read -- cancel, console request, event
    subscription -- where there is no row to return and only the permission
    question matters.
    """
    scope, params = auth.visible_to(identity)
    row = conn.execute(
        f"SELECT 1 FROM jobs WHERE id = %s AND {scope}", (job_id, *params)
    ).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such job")


def _detail(conn, job_id: UUID, identity: str | None) -> JobDetail:
    scope, scope_params = auth.visible_to(identity)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT * FROM jobs WHERE id = %s AND {scope}",
                    (job_id, *scope_params))
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such job")

    # Past the retention window MinIO has expired the objects, so minting URLs
    # would produce download links that 404. Computed from age rather than a
    # HEAD per artifact: a detail view would otherwise cost one round trip per
    # file to learn something the policy already determines.
    expired = bool(
        settings.retention_days
        and row["created_at"] < datetime.now(UTC)
        - timedelta(days=settings.retention_days)
    )

    # Total by construction: parse() never raises, so a manifest written under
    # an older contract -- or by a broken writer -- renders the job rather than
    # 500ing the only view of it. See sandbox_platform/manifest.py.
    parsed = manifest_schema.parse(row["manifest"])

    artifacts: dict[str, str] = {}
    if not expired:
        # **Links to this API's wrapping routes, NOT presigned GETs to MinIO.**
        # A presigned GET hands over the stored object exactly as it is, so an
        # analyst clicking something recovered from `extracted/` received a
        # live executable while the tab told them it arrived as a
        # password-protected ZIP. The wrapping can only happen here -- MinIO
        # serves what it stores -- so the link has to come back through the
        # API. See the download routes below.
        #
        # `parsed.artifacts` is empty when `parsed.error` is set, so a name
        # this module could not validate never reaches here: degraded means
        # fewer capabilities, never looser ones.
        for artifact in parsed.artifacts:
            artifacts[artifact.name] = (
                f"/api/v1/jobs/{job_id}/artifact.zip"
                f"?name={quote(artifact.name, safe='')}"
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

    job_detail =JobDetail(
        **{k: row[k] for k in (
            "id", "created_at", "updated_at", "target_os", "submitted_filename",
            "state", "sha256", "size_bytes", "detected_type", "queue_reason",
            "failure_stage", "failure_reason", "attempt", "cancel_requested",
            "owner", "interacted",
            "egress_mode", "egress_exit", "egress_applied", "visibility",
        )},
        manifest=row["manifest"] if isinstance(row["manifest"], dict) else None,
        artifacts=artifacts,
        manifest_error=parsed.error,
        manifest_legacy=parsed.legacy,
        reserved_ahead=reserved_ahead,
        artifacts_expired=expired,
    )

    if job_detail.visibility == "public" and job_detail.owner != identity:
        job_detail.owner = "REDACTED"
    return job_detail


@router.get("")
def list_jobs(
    state: JobState | None = None,
    target_os: TargetOs | None = None,
    sha256: str | None = None,
    before: datetime | None = Query(
        None, description="keyset cursor: return jobs created strictly before this"
    ),
    limit: int = Query(50, ge=1, le=200),
    identity: auth.Identity = None,
) -> list[JobSummary]:
    """Job history, scoped to what the caller may see.

    Keyset pagination on created_at rather than OFFSET: this table grows
    without bound, and OFFSET degrades quietly -- page 1 is fast and page 400
    scans everything before it.
    """
    return query_jobs(identity=identity, state=state, target_os=target_os,
                      sha256=sha256, before=before, limit=limit)


def _filters(state, target_os, sha256, sha256_prefix, before, identity):
    """WHERE fragments and their bound values.

    One builder, used by both the page query and the count. Two copies of this
    logic is the classic way a paginated list ends up claiming "412 results"
    while showing a different set -- the count and the page must be able to
    disagree only about LIMIT.

    **The tenancy scope is built in here rather than added by each caller**, so
    the count and the page cannot disagree about it either. A total that
    included other people's jobs while the page did not would leak how many
    they have, and page through to empty results.

    Every fragment is a literal; no caller-supplied text enters the statement.
    """
    scope, scope_params = auth.visible_to(identity)
    clauses, params = ["TRUE", scope], list(scope_params)

    if state:
        clauses.append("state = %s")
        params.append(state.value)
    if target_os:
        clauses.append("target_os = %s")
        params.append(target_os.value)
    if sha256:
        clauses.append("sha256 = %s")
        params.append(sha256)
    if sha256_prefix:
        # Anchored at the START, and both reasons matter.
        #
        # Nobody holds the middle of a digest. You have the whole thing,
        # because a tool emitted it, or its opening characters, because a UI
        # truncated it -- this history shows twelve. A substring search would
        # serve a way of working that does not exist.
        #
        # And it would be unindexable forever. `LIKE '%abc%'` cannot use a
        # btree at all; `LIKE 'abc%'` can, once this table is large enough to
        # warrant `CREATE INDEX ... (sha256 text_pattern_ops)` -- needed
        # because the database collates C.UTF-8 rather than C, so a plain
        # btree will not answer a pattern match. That index is NOT created
        # yet: the table holds thousands of kilobyte rows and a sequential
        # scan over it is free. Anchoring now keeps adding it later a pure
        # addition rather than a search that silently narrows.
        clauses.append("sha256 LIKE %s")
        params.append(f"{sha256_prefix}%")
    if before:
        clauses.append("created_at < %s")
        params.append(before)
    return clauses, params


def query_jobs(*, identity, state=None, target_os=None, sha256=None,
               sha256_prefix=None, before=None, offset=0, limit=50):
    """The route body as a plain function, so other callers can reuse it.

    **`identity` has no default, on purpose.** Every other argument here is a
    filter, where "not specified" sensibly means "no restriction"; tenancy is
    not, and a default would make forgetting it return every user's jobs
    silently. Required, so forgetting is a TypeError at import-time reach
    rather than a leak nobody sees. Pass None explicitly for the unscoped
    mTLS path -- see `auth.visible_to`.

    The UI (#38) renders the same history, and calling the route directly
    would pass FastAPI's `Query(...)` sentinels through as if they were
    values -- which psycopg then tries to bind, failing with "cannot adapt
    type 'Query'". One query, two callers, no second copy of this SQL.

    `sha256` is exact; `sha256_prefix` matches from the start. The JSON API
    exposes only the first, deliberately: it is a stable contract others may
    script against, and turning an equality filter into a fuzzy one later
    would break callers silently. The UI's search box uses the second.

    **Two pagination schemes, and they are not redundant.** `before` is a
    keyset cursor and stays the API's: it is O(1) at any depth and cannot skip
    or repeat a row when the table is written to mid-scan. `offset` exists for
    the UI's numbered pages, which keyset cannot express -- you cannot jump to
    page 7 without knowing where page 6 ended. OFFSET re-scans what it skips,
    which is free at this table's size and would stay so to roughly a million
    rows; past that the UI moves to next/previous links rather than this
    function changing.
    """
    clauses, params = _filters(state, target_os, sha256, sha256_prefix, before,
                               identity)
    params.extend([limit, offset])
    sql = (
        "SELECT id, created_at, target_os, submitted_filename, state, sha256,"
        "       size_bytes, owner, visibility FROM jobs"
        f" WHERE {' AND '.join(clauses)}"
        " ORDER BY created_at DESC LIMIT %s OFFSET %s"
    )
    with connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, params)
        job_summary_list = [ JobSummary(**row) for row in cur.fetchall() ]
        for job_summary in job_summary_list:
            if job_summary.visibility == "public" and job_summary.owner  != identity:
                job_summary.owner = "REDACTED"
        return job_summary_list


def count_jobs(*, identity, state=None, target_os=None, sha256=None,
               sha256_prefix=None, before=None) -> int:
    """How many rows the same filters match, for the page links.

    A second query rather than `count(*) OVER ()` alongside the page: that
    window returns no row at all on a page past the end, which is exactly when
    the UI most needs the total -- to send someone back to a page that exists.

    `identity` is required here for the same reason as in `query_jobs`, and
    must be the SAME value: the count and the page are one answer split across
    two statements.
    """
    clauses, params = _filters(state, target_os, sha256, sha256_prefix, before,
                               identity)
    sql = f"SELECT count(*) FROM jobs WHERE {' AND '.join(clauses)}"
    with connection() as conn:
        return conn.execute(sql, params).fetchone()[0]


@router.get("/{job_id}")
def get_job(job_id: Annotated[UUID, Path()],
            identity: auth.Identity = None) -> JobDetail:
    with connection() as conn:
        return _detail(conn, job_id, identity)


# --- downloading ----------------------------------------------------------
#
# **Artifacts leave this platform wrapped, never raw**, which is what the
# artifacts tab has claimed since #38 and what nothing implemented until
# 2026-08-27. See `packaging.py` for what the password does and does not buy;
# the short version is that it stops a browser, an OS or a scanner acting on
# the bytes in transit, and protects nothing from whoever holds the link.
#
# These two routes are the ONLY way artifacts are offered now. The presigned
# GET that `_detail` used to mint per artifact went straight to MinIO and
# handed over an unwrapped executable, so it is gone -- `JobDetail.artifacts`
# now carries these URLs instead.
#
# The API is in the data path here, which `objects.py` otherwise avoids on
# purpose. That is the trade: wrapping cannot happen anywhere else, because
# MinIO serves what it stores. Nothing is buffered -- `packaging.stream` and
# `objects.chunks` are both generators, so an abandoned download stops pulling
# from the store rather than running to completion.

def _for_download(job_id: UUID, identity: str | None):
    """The artifacts a download route may serve, or the reason it may not.

    410 rather than 404 for an expired job: the objects existed and the
    manifest still records what they were, which is a different thing to say
    than "no such job".

    **This is where the tenancy check has to happen for artifacts, and it has
    to happen here rather than at the point of streaming.** DRAFT-047 states
    the requirement as "the scope check goes before the presigned URL is
    minted", because a presigned URL is a bearer capability that has already
    left. These routes wrap rather than presign (see the block above), so the
    equivalent moment is before `objects.chunks` opens a read against the
    store -- which is what refusing here achieves.
    """
    scope, scope_params = auth.visible_to(identity)
    with connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT created_at, manifest, key_prefix FROM jobs WHERE id = %s AND {scope}",
            (job_id, *scope_params))
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such job")

    if (settings.retention_days
            and row["created_at"] < datetime.now(UTC)
            - timedelta(days=settings.retention_days)):
        raise HTTPException(status.HTTP_410_GONE,
                            "artifacts have expired from the object store")

    # `parse` never raises and yields no artifacts when it could not validate
    # the manifest, so a name this platform could not check never reaches a
    # download: degraded means fewer capabilities, never looser ones.
    artifacts = manifest_schema.parse(row["manifest"]).artifacts
    key_prefix = row["key_prefix"]
    if not artifacts:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "this run has no artifacts to download")
    return artifacts, key_prefix 


def _attachment(stem: str) -> dict[str, str]:
    """A Content-Disposition built from OUR text, never the artifact's name.

    `manifest.reject_unsafe_name` admits quotes, spaces and unicode on purpose
    -- a dropped file really can be called `50%off.exe` and byte-exactness of
    that name is the point of collecting it. None of that belongs unescaped in
    a response header, so the download name is derived here and the real names
    survive inside the archive, which is where they matter.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", stem).strip("._-")[:60]
    return {"Content-Disposition":
            f'attachment; filename="{safe or "artifacts"}.zip"'}


@router.get("/{job_id}/artifacts.zip")
def download_all_artifacts(job_id: Annotated[UUID, Path()],
                           identity: auth.Identity = None) -> StreamingResponse:
    """Every artifact of one run, in a single password-protected ZIP."""
    artifacts, key_prefix = _for_download(job_id, identity)
    
    key = objects.result_prefix(job_id, key_prefix)

    return StreamingResponse(
        packaging.stream(
            (a.name, objects.chunks(f"{key}{a.name}")) for a in artifacts
        ),
        media_type="application/zip",
        headers=_attachment(f"job-{job_id}-artifacts"),
    )


@router.get("/{job_id}/artifact.zip")
def download_one_artifact(
    job_id: Annotated[UUID, Path()],
    name: Annotated[str, Query(description="artifact name from the manifest")],
    identity: auth.Identity = None,
) -> StreamingResponse:
    """One artifact, wrapped the same way.

    **The name is matched against the manifest rather than used to build a
    key.** It arrives from the query string, so treating it as a path fragment
    would make this an arbitrary-read primitive over a bucket holding live
    malware; resolving it to a manifest entry first means the only reachable
    objects are the ones this job actually declared.
    """
    artifacts, key_prefix =  _for_download(job_id, identity) 
    match  = next((a for a in artifacts if a.name == name),
                 None)
    if match is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "no such artifact for this job")

    key = objects.result_prefix(job_id, key_prefix)
    return StreamingResponse(
        packaging.stream([(match.name, objects.chunks(f"{key}{match.name}"))]),
        media_type="application/zip",
        headers=_attachment(match.name.rsplit("/", 1)[-1]),
    )


@router.post("/{job_id}/cancel")
def cancel_job(job_id: Annotated[UUID, Path()],
               identity: auth.Identity = None) -> CancelResponse:
    """Cancel, by whichever route the job's state allows.

    Before a clone exists this is one UPDATE and terminal -- the operation
    DRAFT-040 recorded as unexpressible under dirwatch, where a queued job was
    a file in a directory with no id to name it by. While running it is a
    request the worker collects on its next heartbeat.

    **The scope is checked here rather than pushed into `dal.cancel`.** That
    keeps the data-access layer free of any notion of `owner`, which is what
    stops a later change from owner-scoping the queries the worker channel also
    reaches. Both statements run on one connection, and `owner` never changes,
    so there is nothing for the gap between them to race with.
    """
    with connection() as conn:
        _visible_or_404(conn, job_id, identity)
        return CancelResponse(outcome=dal.cancel(conn, job_id))

@router.post("/{job_id}/console/request",
             status_code=status.HTTP_204_NO_CONTENT)
def request_console(job_id: Annotated[UUID, Path()],
                    identity: auth.Identity = None) -> None:
    """Ask for a live console on this job (DRAFT-056).

    **`/console/request`, not `/console`** -- the WebSocket lives at
    `/console`, and both routers carry the `/api/v1/jobs` prefix. This router
    is included first, so a POST route at the same path SHADOWED the socket:
    the upgrade request matched here and got `405 Allow: POST`, and the
    WebSocket handler was never reached. Observed from the browser
    2026-08-26, F5.

    **Requested when the job page opens, not when execution starts**, and that
    is the point. Dom0 has no inbound listener, so `sandboxd` only learns of a
    request on its next heartbeat -- setting the flag early means it already
    knows by the time the job is executing, instead of the operator waiting a
    beat after the screen could first have been shown.

    Refused once the job is terminal: there is nothing left to watch, and a
    flag set on a finished job would have the next worker to touch that row
    dial out for a session nobody asked for.

    A no-op unless CONSOLE_ENABLED. The flag is what lets the capability be
    switched off without a redeploy while confidence is built.
    """
    if not settings.console_enabled:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "the live console is disabled"
        )

    scope, scope_params = auth.visible_to(identity)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT state FROM jobs WHERE id = %s AND {scope}",
                    (job_id, *scope_params))
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such job")
        if JobState(row[0]) in TERMINAL_STATES:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"job is {row[0]}; there is nothing left to watch",
            )
        conn.execute(
            "UPDATE jobs SET console_requested = true WHERE id = %s", (job_id,)
        )


@router.get("/{job_id}/events")
async def job_events(job_id: Annotated[UUID, Path()],
                     identity: auth.Identity = None) -> StreamingResponse:
    """Server-sent events for one job, backed by Postgres LISTEN/NOTIFY.

    No Redis, and no polling loop on the server: migration 0002's trigger
    emits on every state change and events.py fans it out from one connection
    shared by the whole process.

    **Checked before the stream is opened**, not inside it. Once
    `StreamingResponse` has the generator the status line is already 200, so a
    refusal from within would arrive as an empty or truncated event stream --
    indistinguishable to a client from the job simply not changing.

    `X-Accel-Buffering: no` because a buffering proxy turns a live stream into
    a stream that arrives all at once when the job finishes -- which looks
    exactly like the stream not working.
    """
    with connection() as conn:
        _visible_or_404(conn, job_id, identity)

    return StreamingResponse(
        events.stream(job_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

def _publisher(identity: str | None) -> str:
    """The person publishing, or a refusal. Publication needs a person.

    `access_identity` returns None only on the certificate-gated listener,
    where the caller is Dom0 or a command-line tool -- a machine. Publishing is
    a judgement about a result, `owner` is a column for a person, and nothing in
    `submit.py` publishes; refusing here also keeps Dom0's one credential from
    carrying an authority it has no use for.

    403 rather than the 404 the rest of this section returns, because it is a
    fact about the LISTENER and not about a job. Answered before any id is
    looked up, so it reveals nothing about which ids exist.
    """
    if identity is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "publication requires an authenticated browser session",
        )
    return identity

def _owned_or_404(conn, job_id: UUID, owner: str) -> str:
    """The state of a job this caller OWNS, or 404. Never a 403.

    The same refusal a missing id gets, with the same detail string, for the
    reason `_visible_or_404` gives: a 403 confirms the id exists, which turns
    this into an oracle for enumerating other people's jobs.
    """
    row = conn.execute(
        "SELECT state FROM jobs WHERE id = %s AND owner = %s", (job_id, owner)
    ).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such job")
    return row[0]

@router.post("/{job_id}/publish")
def publish_analysis(job_id: Annotated[UUID, Path()],
                     identity: auth.Identity = None) -> VisibilityResponse:
    """Make a finished analysis readable by every authenticated user.

    **Terminal states, not `completed` alone.** A run that failed, was cancelled
    or was interrupted is frequently the thing worth sharing -- a sample that
    detected the sandbox and bailed is a finding. What is refused is publishing
    something still queued or running, which is exactly the "before anyone has
    seen what came out" case decision 5 exists to prevent.

    Idempotent: publishing an already-public job is not an error. There is no
    state to conflict over, and a 409 would turn the UI's retry into a failure.

    Two statements on one connection rather than one guarded UPDATE, matching
    `cancel_job` above and for the same reason: `owner` never changes, so there
    is nothing for the gap between them to race with.
    """
    owner = _publisher(identity)
    with connection() as conn:
        state = _owned_or_404(conn, job_id, owner)
        if JobState(state) not in TERMINAL_STATES:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"job is {state}; an analysis is published once it has finished",
            )
        conn.execute("UPDATE jobs SET visibility = %s WHERE id = %s",
                     (Visibility.PUBLIC.value, job_id))
    return VisibilityResponse(visibility=Visibility.PUBLIC)

@router.post("/{job_id}/unpublish")
def unpublish_analysis(job_id: Annotated[UUID, Path()],
                           identity: auth.Identity = None) -> VisibilityResponse:
    """Restore the access check on a published analysis.

    **No state check**, unlike publishing. Withdrawing access is the remedy, and
    a remedy refusable on account of the job's state is not one.

    **This restores the check, not the secret.** Anything downloadable while the
    job was public, somebody has -- so this closes the door and recovers
    nothing. Which is why the warning belongs at the moment of PUBLISHING: by
    the time anyone reaches for this route, the decision it would have informed
    was already taken.
    """
    owner = _publisher(identity)
    with connection() as conn:
        _owned_or_404(conn, job_id, owner)
        conn.execute("UPDATE jobs SET visibility = %s WHERE id = %s",
                     (Visibility.PRIVATE.value, job_id))
    return VisibilityResponse(visibility=Visibility.PRIVATE)

