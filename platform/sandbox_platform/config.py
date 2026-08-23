"""Runtime configuration, from the environment.

Issue #36 (DRAFT-043).

Every value is read once at import. There is no config file: the service runs
from a systemd unit in the platform LXC, and an environment block is one
place to look rather than two.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


@dataclass(frozen=True)
class Settings:
    # --- database ---------------------------------------------------------
    # Empty host selects the Unix socket. The API and Postgres share the
    # container, so there is no network hop and therefore no password to
    # store -- peer authentication as the `platform` OS user.
    database_url: str = os.environ.get(
        "DATABASE_URL", "postgresql:///sandbox_platform"
    )
    pool_min: int = _int("DB_POOL_MIN", 2)
    pool_max: int = _int("DB_POOL_MAX", 10)

    # --- object store -----------------------------------------------------
    #
    # TWO endpoints, and they are not interchangeable.
    #
    # SigV4 signs the Host header, so a presigned URL is valid only against
    # the host it was signed for -- there is no rewriting it afterwards. Dom0
    # reaches MinIO over the LAN; browsers reach it through the Cloudflare
    # tunnel (issue #39). Each audience therefore needs a URL signed for its
    # own hostname, which means two clients over the same bucket.
    #
    # INTERNAL is also the only one that makes real network calls -- HEAD and
    # GET during admission. PUBLIC only ever signs, and signing is a local
    # computation, so the API never has to reach the tunnel.
    s3_internal_endpoint: str = os.environ.get(
        "S3_INTERNAL_ENDPOINT", "http://127.0.0.1:9000"
    )
    s3_public_endpoint: str = os.environ.get(
        "S3_PUBLIC_ENDPOINT",
        os.environ.get("S3_INTERNAL_ENDPOINT", "http://127.0.0.1:9000"),
    )
    s3_bucket: str = os.environ.get("S3_BUCKET", "analysis")
    s3_access_key: str = os.environ.get("S3_ACCESS_KEY", "")
    s3_secret_key: str = os.environ.get("S3_SECRET_KEY", "")

    # MUST match MinIO's own configured region (MINIO_SITE_REGION). The region
    # is part of the SigV4 signing scope, so a mismatch fails every presigned
    # URL with a 403 that mentions the signature and never the region -- which
    # is a long afternoon if you do not know to look.
    #
    # For a self-hosted store this is a LABEL, not a routing directive: the
    # data lives wherever the container does. It says Europe because that is
    # where it is, which is what DRAFT-022's GDPR position should rest on
    # rather than on a default nobody chose.
    s3_region: str = os.environ.get("S3_REGION", "eu-central-1")

    # CA bundle for verifying MinIO's certificate on the internal link. Empty
    # means system trust, which is right in development and wrong in
    # deployment -- the LAN certificate is signed by the internal CA (#39).
    s3_ca_bundle: str = os.environ.get("S3_CA_BUNDLE", "")

    # Presigned URL lifetimes, seconds. Short by intent: a presigned URL is a
    # bearer capability, so its TTL is how long a leak stays useful.
    upload_ttl: int = _int("S3_UPLOAD_TTL", 900)        # 15 min
    artifact_get_ttl: int = _int("S3_ARTIFACT_GET_TTL", 300)   # 5 min

    # --- admission --------------------------------------------------------
    #
    # Refused before a URL is issued, then re-checked against the object's
    # real size -- a client's declared size is a claim, not a fact.
    #
    # At 512 MiB the binding constraint on the browser path is NOT this value:
    # Cloudflare caps request bodies (100 MB on current free plans), and the
    # upload goes through the tunnel. A sample between that cap and this one
    # fails at Cloudflare with their error page rather than here with
    # `rejected_size`, so the message the submitter sees will not mention this
    # setting. Dom0-side submission and LAN uploads are unaffected.
    #
    # Kept at 512 MiB deliberately: lowering it to match the tunnel would also
    # reject samples the lab can already analyse -- CLAUDE.md records
    # `injector` round-tripping 12 MB byte-exact, and APKs go well beyond
    # that.
    max_sample_bytes: int = _int("MAX_SAMPLE_BYTES", 512 * 1024 * 1024)

    # How much of a sample libmagic sees. It needs a header, not a file, and
    # this bounds what an attacker-controlled parse costs in the process that
    # holds every credential on the platform.
    magic_bytes: int = _int("MAGIC_BYTES", 8192)

    # --- worker channel ---------------------------------------------------
    # The only credential Dom0 ever holds. Scoped to /api/v1/worker/* and, on
    # job routes, to jobs that worker currently leases.
    worker_token: str = os.environ.get("WORKER_TOKEN", "")

    # A lease is bookkeeping, not a resource reservation. It expires so a
    # dead worker's jobs stop occupying the queue; it frees nothing on Dom0.
    lease_seconds: int = _int("LEASE_SECONDS", 120)

    # Server-side long-poll budget for /worker/claim. Long-polling rather
    # than a tight loop, because the arrangement this replaces logged one
    # "Holding: need ..." line per second forever with no backoff.
    claim_poll_seconds: float = float(os.environ.get("CLAIM_POLL_SECONDS", 20))
    claim_poll_interval: float = float(os.environ.get("CLAIM_POLL_INTERVAL", 1.0))


settings = Settings()
