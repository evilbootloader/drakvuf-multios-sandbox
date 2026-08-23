"""Object store access: presigned URLs, and reading a sample without keeping it.

Issue #36 (DRAFT-043), with the two-endpoint split from #39.

**Neither Dom0 nor the browser ever holds a credential for this store.** Every
access is a presigned URL scoped to one key with a short expiry, issued here
for a job the caller is entitled to. A sample that escapes into Dom0 cannot
enumerate the bucket, read another job's artifacts, or reach the history.
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
    Choosing the wrong one here produces a 403 from MinIO that talks about
    signatures and never mentions the host.
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
    irrelevant. Only the WORKER client talks to MinIO.
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

def sample_key(job_id: UUID, filename: str) -> str:
    return f"samples/{job_id}/{filename}"


def result_prefix(job_id: UUID) -> str:
    return f"results/{job_id}/"


# --- issuing capabilities -------------------------------------------------

@dataclass(frozen=True)
class UploadTicket:
    """A presigned POST: the URL, plus the form fields that carry the policy."""

    url: str
    fields: dict[str, str]
    expires_in: int


def presigned_upload(job_id: UUID, filename: str, max_bytes: int) -> UploadTicket:
    """A browser-usable upload capability, with the size cap enforced by MinIO.

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
        {"key": sample_key(job_id, filename)},
    ]
    signed = _client(Audience.BROWSER).generate_presigned_post(
        Bucket=settings.s3_bucket,
        Key=sample_key(job_id, filename),
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


def presigned_put(key: str, ttl: int | None = None) -> str:
    """Write one artifact. Worker audience only.

    A PUT is acceptable here where it was not for uploads: the size is not
    knowable in advance, and the uploader is already authenticated by lease
    rather than by holding the URL alone.
    """
    return _client(Audience.WORKER).generate_presigned_url(
        "put_object",
        Params={"Bucket": settings.s3_bucket, "Key": key},
        ExpiresIn=ttl or settings.upload_ttl,
    )


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
    capability outlives admission -- see `etag_unchanged`.
    """
    client = _client(Audience.WORKER)
    try:
        r = client.head_object(Bucket=settings.s3_bucket, Key=key)
        return r["ContentLength"], r["ETag"].strip('"')
    except client.exceptions.ClientError:
        return None


def etag_unchanged(key: str, expected: str | None) -> bool:
    """Has this object been replaced since admission looked at it?

    The presigned POST issued at submission stays valid for its whole TTL, so
    an object can be overwritten AFTER admission hashed it and queued the job.
    Demonstrated 2026-08-23: a benign ELF was admitted, the same upload URL
    then accepted different bytes, and the stored object no longer matched the
    recorded digest.

    What that costs is not a corrupt file. It is Dom0 executing bytes that
    were never admitted while the trace, the verdict and the SHA-256 all
    describe the file that was replaced -- a sandbox that can be made to
    analyse one thing and report another.

    One HEAD, checked before the sample URL is handed to a worker.
    """
    if expected is None:
        return False
    current = head(key)
    return current is not None and current[1] == expected


def _chunks(key: str, chunk_size: int = 1 << 20) -> Iterator[bytes]:
    body = _client(Audience.WORKER).get_object(
        Bucket=settings.s3_bucket, Key=key
    )["Body"]
    try:
        while chunk := body.read(chunk_size):
            yield chunk
    finally:
        body.close()


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

    for chunk in _chunks(key):
        digest.update(chunk)
        size += len(chunk)
        if len(head_bytes) < limit:
            head_bytes += chunk[: limit - len(head_bytes)]

    # Read AFTER the body, so the ETag belongs to the bytes just hashed rather
    # than to whatever was there when the request started.
    current = head(key)
    etag = current[1] if current else ""

    return ObjectFacts(size_bytes=size, sha256=digest.hexdigest(),
                       head_bytes=head_bytes, etag=etag)
