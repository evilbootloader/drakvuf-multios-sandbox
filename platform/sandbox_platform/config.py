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
    s3_endpoint: str = os.environ.get("S3_ENDPOINT", "http://127.0.0.1:9000")
    s3_bucket: str = os.environ.get("S3_BUCKET", "analysis")
    s3_access_key: str = os.environ.get("S3_ACCESS_KEY", "")
    s3_secret_key: str = os.environ.get("S3_SECRET_KEY", "")

    # Presigned URL lifetimes, seconds. Short by intent: a presigned URL is a
    # bearer capability, so its TTL is how long a leak stays useful.
    upload_ttl: int = _int("S3_UPLOAD_TTL", 900)        # 15 min
    artifact_get_ttl: int = _int("S3_ARTIFACT_GET_TTL", 300)   # 5 min

    # --- admission --------------------------------------------------------
    # Refused before a URL is issued, then re-checked against the object's
    # real size -- a client's declared size is a claim, not a fact.
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
