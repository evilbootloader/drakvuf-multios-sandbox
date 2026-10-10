"""Object store access: presigned URLs, and reading a sample without keeping it.

Issue #36 (DRAFT-043), with the two-endpoint split from #39.

**Neither Dom0 nor the browser ever holds a credential for this store.** Every
access is a presigned URL scoped to one key with a short expiry, issued here
for a job the caller is entitled to. A sample that escapes into Dom0 cannot
enumerate the bucket, read another job's artifacts, or reach the history.

That last clause is held up by `manifest.reject_unsafe_name`, which every key
component passes through before a URL is minted for it -- at the ticket
endpoint and again at `/complete`. Until DRAFT-018 only the first door checked,
and the guarantee rested on the store refusing `..` itself -- MinIO did,
`XMinioInvalidResourceName`, verified 2026-08-25. It was never exploitable,
but a claim made in this docstring should hold because of code in this
repository, not because of a dependency's input validation.

**And that backstop is now gone, which is why it was never the argument.**
Garage accepts `..` in a key and stores it literally (`a/../b.bin`,
`../escape.bin`, measured 2026-10-04), so `reject_unsafe_name` is the only
thing refusing traversal on this store. The three live copies of that rule --
`routers/jobs.py::_reject_unsafe_filename`, `manifest.reject_unsafe_name`,
`sandboxd/naming.py::sample_name_admissible` -- must not disagree, and
`test_manifest.py` and `test_jobs_api.py` are what pin them.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from uuid import UUID

import boto3
from botocore.config import Config

from .config import settings


class Audience(Enum):
    """Who the URL is for, which decides the hostname it is signed against.

    Not cosmetic. SigV4 covers the Host header, so a URL signed for the LAN
    address is rejected when presented to the tunnel hostname and vice versa.
    Choosing the wrong one here produces a signature error from the store
    that talks about signatures and never mentions the host -- a 403 from
    MinIO, a 400 from Garage.
    """

    WORKER = "worker"     # Dom0, over the LAN
    BROWSER = "browser"   # through the Cloudflare tunnel


@lru_cache(maxsize=2)
def _client(audience: Audience):
    """One boto3 client per audience, over the same bucket and credentials.

    path addressing because virtual-host style would need a DNS name per
    bucket, which neither a LAN address nor a tunnel hostname provides.

    The BROWSER client never makes a network call: signing is local
    arithmetic, so it needs no route to the tunnel and its TLS settings are
    irrelevant. Only the WORKER client talks to the store.
    """
    endpoint = (
        settings.s3_internal_endpoint
        if audience is Audience.WORKER
        else settings.s3_public_endpoint
    )
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=settings.s3_access_key,
        aws_secret_access_key=settings.s3_secret_key,
        region_name=settings.s3_region,
        verify=settings.s3_ca_bundle or True,
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
        ),
    )


# --- keys -----------------------------------------------------------------
#
# Keyed by job_id, NOT by SHA-256. DRAFT-030 established that identical bytes
# submitted under different names are separate runs, because the submitted
# name is part of what is being analysed -- extension dispatch and argv[0]
# self-checks are real evasion surface. sha256 is an indexed column for
# search; it is not a path component.

def sample_key(job_id: UUID, filename: str, key_prefix: str) -> str:
    return f"{key_prefix}samples/{job_id}/{filename}"


def result_prefix(job_id: UUID, key_prefix: str) -> str:
    return f"{key_prefix}results/{job_id}/"


# --- issuing capabilities -------------------------------------------------

@dataclass(frozen=True)
class UploadTicket:
    """A presigned POST: the URL, plus the form fields that carry the policy."""

    url: str
    fields: dict[str, str]
    expires_in: int


def presigned_upload(job_id: UUID, filename: str, max_bytes: int, key_prefix: str) -> UploadTicket:
    """A browser-usable upload capability, with the size cap enforced by the store.

    **POST rather than PUT, and this is the whole reason.** A presigned PUT
    cannot constrain the upload's size: the signature covers the key and the
    expiry, so a URL issued for a 10 KB file will happily accept 10 GB. A
    presigned POST carries a policy document, and `content-length-range` in it
    is enforced at upload time by the server.

    **`max_bytes` is min(declared, configured cap), and the tightening is the
    point.** An earlier version signed the policy with the configured cap
    alone, which made the client's declared size decorative -- a request
    declaring 100 bytes could upload 500 KiB, demonstrated 2026-08-23.
    Binding the policy to the claim means a client is held to what it said.
    The claim can only ever make the bound *stricter*: a larger declaration is
    refused before a URL exists, so this cannot be used to raise the ceiling.

    The stored object's real size is still re-checked at admission. Two
    independent controls: this one bounds what can be written, that one
    establishes what actually was.

    The policy is signed, so none of it can be edited client-side -- raising
    the range, dropping the signature or redirecting the key all fail with
    SignatureDoesNotMatch or AccessDenied (verified 2026-08-23).
    """
    conditions = [
        ["content-length-range", 1, max_bytes],
        {"key": sample_key(job_id, filename, key_prefix)},
    ]
    signed = _client(Audience.BROWSER).generate_presigned_post(
        Bucket=settings.s3_bucket,
        Key=sample_key(job_id, filename, key_prefix),
        Conditions=conditions,
        ExpiresIn=settings.upload_ttl,
    )
    return UploadTicket(
        url=signed["url"], fields=signed["fields"], expires_in=settings.upload_ttl
    )


def presigned_get(key: str, audience: Audience, ttl: int | None = None) -> str:
    """Read one object, for a bounded time.

    One key per URL, never a prefix: a prefix-scoped capability is a bucket
    enumeration primitive, and this bucket holds live malware.
    """
    return _client(audience).generate_presigned_url(
        "get_object",
        Params={"Bucket": settings.s3_bucket, "Key": key},
        ExpiresIn=ttl or settings.artifact_get_ttl,
    )


def presigned_artifact_upload(key: str, max_bytes: int,
                              ttl: int | None = None) -> UploadTicket:
    """Write one artifact, size-capped. Worker audience only.

    **POST rather than PUT, and this reverses DRAFT-044's original call.** That
    draft kept artifacts on a presigned PUT because "the size is not knowable in
    advance". It is: `POST /worker/jobs/{id}/artifacts` is called *after* the
    trace finishes, when the files are already on Dom0's disk, so the worker
    knows every size exactly. An unbounded write capability was being handed out
    for no gain.

    So the browser's arrangement applies unchanged -- `min(declared, cap)`,
    with a declaration above the cap refused before a URL exists, so a claim can
    only ever tighten the bound.

    **The range starts at 0, where a sample's starts at 1.** An empty artifact
    is a real result: `capture.pcap` with no bytes means the clone generated no
    traffic. An empty sample is only ever a failed upload.
    """
    signed = _client(Audience.WORKER).generate_presigned_post(
        Bucket=settings.s3_bucket,
        Key=key,
        Conditions=[["content-length-range", 0, max_bytes], {"key": key}],
        ExpiresIn=ttl or settings.upload_ttl,
    )
    return UploadTicket(url=signed["url"], fields=signed["fields"],
                        expires_in=ttl or settings.upload_ttl)


# --- reading, without keeping ---------------------------------------------

@dataclass(frozen=True)
class ObjectFacts:
    """What admission needs to know about an uploaded sample."""

    size_bytes: int
    sha256: str
    head_bytes: bytes
    etag: str


def head(key: str) -> tuple[int, str] | None:
    """The object's real size and ETag, or None if it is not there.

    The ETag is the store's own identity for the bytes. Recorded at admission
    and re-checked when a worker claims the job, because the browser's upload
    capability outlives admission -- see `sample_status`.
    """
    client = _client(Audience.WORKER)
    try:
        r = client.head_object(Bucket=settings.s3_bucket, Key=key)
        return r["ContentLength"], r["ETag"].strip('"')
    except client.exceptions.ClientError:
        return None


def sample_status(key: str, expected: str | None) -> str:
    """Is this object still the one admission looked at? One HEAD.

    Returns `"ok"`, `"missing"` or `"changed"` -- three outcomes rather than a
    boolean, because they have different causes and a worker's `failure_reason`
    is diagnostic. Collapsing them was harmless until retention landed
    (issue #37): a job queued past the expiry window loses its sample to
    the store's lifecycle rule, and reporting that as "changed after admission"
    sends whoever reads it hunting for a tamper that never happened.

    **Why `changed` matters.** The presigned POST issued at submission stays
    valid for its whole TTL, so an object can be overwritten AFTER admission
    hashed it and queued the job. Demonstrated 2026-08-23: a benign ELF was
    admitted, the same upload URL then accepted different bytes, and the stored
    object no longer matched the recorded digest.

    What that costs is not a corrupt file. It is Dom0 executing bytes that were
    never admitted while the trace, the verdict and the SHA-256 all describe
    the file that was replaced -- a sandbox that can be made to analyse one
    thing and report another.

    `expected is None` is `"changed"`, not `"ok"`: admission always records an
    ETag, so a queued job without one should not exist, and the safe reading of
    an impossible state is to refuse it.

    **What this does NOT establish.** For a single-part upload -- which is what
    `generate_presigned_post` produces -- the ETag is the object's MD5 on both
    MinIO and Garage (`etag_from_md5`, measured 2026-10-03). So a match here
    says the two objects have the same MD5, not that they are the same bytes,
    and MD5 collisions are constructible to order. This is a cheap
    early check that makes the ordinary swap loud; it is not the integrity
    guarantee.

    The guarantee is `sandboxd`'s: it verifies the SHA-256 that this same
    admission recorded against the bytes it actually downloads, before the
    sample reaches a guest (`sandboxd/api.py::fetch_sample`). That is the check
    a collision cannot pass, and it covers the window between this HEAD and
    Dom0's GET, which nothing here can close.
    """
    current = head(key)
    if current is None:
        return "missing"
    if expected is None or current[1] != expected:
        return "changed"
    return "ok"


def chunks(key: str, chunk_size: int = 1 << 20) -> Iterator[bytes]:
    """Stream one stored object, for a caller that will not keep it.

    The public face of `_chunks`. Used by the artifact download routes, which
    wrap what they read into an encrypted ZIP and forward it -- so the bytes
    pass through this process without ever reaching its disk, exactly as
    `inspect` requires of a sample.
    """
    return _chunks(key, chunk_size)


def _get(key: str) -> dict:
    """One GET. The response carries the bytes AND their ETag, together.

    Split out from `_chunks` so `inspect` can read the ETag off the SAME
    response it streams. A GET is served from one object version, so the
    header and the body cannot disagree -- which a following HEAD can, and
    did. See `inspect`.
    """
    return _client(Audience.WORKER).get_object(
        Bucket=settings.s3_bucket, Key=key
    )


def _body_chunks(response: dict, chunk_size: int = 1 << 20) -> Iterator[bytes]:
    body = response["Body"]
    try:
        while chunk := body.read(chunk_size):
            yield chunk
    finally:
        body.close()


def _chunks(key: str, chunk_size: int = 1 << 20) -> Iterator[bytes]:
    yield from _body_chunks(_get(key), chunk_size)


def range_bytes(key: str, start: int, end: int) -> bytes:
    """Bytes [start, end) of one object, or b"" when start is past its end.

    For the per-process log viewer, which reads the slices `log_index` names
    out of a per-plugin log that can be over a gigabyte -- so it never reads
    the object whole. An HTTP range is inclusive at both ends; the caller's
    is half-open, like every offset the indexer wrote. S3 answers a start
    past the object with 416, which is "nothing there" rather than a fault.
    """
    if end <= start:
        return b""
    from botocore.exceptions import ClientError
    try:
        response = _client(Audience.WORKER).get_object(
            Bucket=settings.s3_bucket, Key=key,
            Range=f"bytes={start}-{end - 1}",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidRange":
            return b""
        raise
    return b"".join(_body_chunks(response))


def inspect(key: str, head_limit: int | None = None) -> ObjectFacts:
    """Hash a sample and capture its header, without storing it anywhere.

    **Streamed, never written to disk and never held whole in memory.** A
    sample on the platform's filesystem is a sample on the one machine whose
    entire security argument is that it never handles one -- and this process
    holds the database and object-store credentials.

    Only `head_limit` bytes are retained, for libmagic. It needs a header, not
    a file, and bounding it bounds what an attacker-controlled parse costs in
    this process.
    """
    limit = head_limit if head_limit is not None else settings.magic_bytes
    digest = hashlib.sha256()
    size = 0
    head_bytes = b""

    # **ONE request, and the ETag comes out of it rather than out of a second.**
    #
    # This read the body and then issued a separate HEAD, with a comment
    # claiming the ETag therefore "belongs to the bytes just hashed". It did
    # not. The submitter's upload capability outlives admission (see
    # `sample_status`), and they choose when `/uploaded` runs -- so an
    # overwrite landing between the end of the GET and the HEAD produced
    # `sha256` of the old bytes beside the `etag` of the new ones. The
    # claim-time check then compared the new ETag against itself, said "ok",
    # and Dom0 detonated bytes the record did not describe. No hash collision
    # was needed: the guard was simply reading two different objects.
    #
    # A GET is served from a single object version, so the ETag on this
    # response and the bytes on this response are the same object by
    # construction. That is a property of the request, not of the timing.
    response = _get(key)
    etag = response["ETag"].strip('"')

    for chunk in _body_chunks(response):
        digest.update(chunk)
        size += len(chunk)
        if len(head_bytes) < limit:
            head_bytes += chunk[: limit - len(head_bytes)]

    return ObjectFacts(size_bytes=size, sha256=digest.hexdigest(),
                       head_bytes=head_bytes, etag=etag)



# The owner segment is bounded so the composed key cannot exceed S3's 1024
# bytes. 254 is RFC 5321's maximum address, so anything longer is not an
# address at all -- a refusal that explains itself. The bound the arithmetic
# alone would give is 72, which is explicable to nobody.
#
# It is not always an email: auth.access_identity returns
# `service:<common_name>` for an Access service token, and X.520 caps a CN at
# 64, so that form tops out at 72 bytes and never approaches this.
#
# Shares one budget with manifest.MAX_ARTIFACT_NAME: 261 + 45 + 718 = 1024
# exactly. Raising either without lowering the other mints a key the store
# refuses, and test_the_longest_admissible_key_still_fits_s3 is what couples
# them.
MAX_OWNER = 254


def owner_prefix(job_id: UUID, owner: str | None) -> str:
    """Where this owner's objects live, or '' for the pre-#40 flat layout.

    ValueError rather than HTTPException: this module has no FastAPI import
    and should not acquire one. `create_job` is the only caller and is what
    turns this into a response.
    """
    if owner is None:
        return ""
    if len(owner.encode()) > MAX_OWNER:
        raise ValueError(
            f"identity is {len(owner.encode())} bytes, over the "
            f"{MAX_OWNER}-byte limit"
        )
    if "/" in owner:
        # Would add a path segment, so the stored prefix and the key built
        # from it stop agreeing. The 0008 CHECK catches this too, but at
        # INSERT and as a 500.
        raise ValueError(f"identity contains a path separator: {owner!r}")
    return f"u/{owner.lower()}/{job_id.hex[:3]}/"