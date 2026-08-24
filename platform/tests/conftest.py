"""Fixtures for the queue tests.

Issue #35 (DRAFT-042).

Against a REAL Postgres, deliberately. FOR UPDATE SKIP LOCKED, transactional
visibility and LISTEN/NOTIFY are the things under test and none of them exists
in a substitute.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import psycopg
import pytest

PLATFORM_DIR = Path(__file__).resolve().parent.parent
DSN = os.environ.get("TEST_DATABASE_URL", "postgresql:///sandbox_platform_test")

# Set BEFORE any sandbox_platform module is imported: config.Settings reads the
# environment once, at import, and conftest is imported before test modules.
#
# claim_poll_seconds = 0 turns the long poll into a single attempt. In
# production it is 20s so a worker does not busy-loop; in tests it would just
# be 20 seconds of sleeping per idle claim.
os.environ.setdefault("DATABASE_URL", DSN)
os.environ.setdefault("WORKER_TOKEN", "test-worker-token")
os.environ.setdefault("CLAIM_POLL_SECONDS", "0")
os.environ.setdefault("CLAIM_POLL_INTERVAL", "0")

# Two endpoints, deliberately DIFFERENT hosts, because that is the property
# under test: SigV4 covers the Host header, so a URL signed for one is invalid
# against the other. The public one is never contacted -- signing is local
# arithmetic -- so it does not need to resolve.
#
# `127.0.0.1` and `localhost` are DIFFERENT hosts as far as SigV4 is
# concerned -- the signature covers the Host header -- while both reach the
# same local MinIO. So the two-endpoint split stays genuinely under test and
# uploads still work, which an unresolvable public hostname would not allow.
# The sweep is driven directly in test_maintenance.py rather than waited on.
# A background task expiring leases mid-test would make the queue tests
# nondeterministic in a way that looks like a bug in the claim query.
os.environ.setdefault("MAINTENANCE_INTERVAL", "0")

os.environ.setdefault("S3_INTERNAL_ENDPOINT", "http://127.0.0.1:9000")
os.environ.setdefault("S3_PUBLIC_ENDPOINT", "http://localhost:9000")
os.environ.setdefault("S3_ACCESS_KEY", "devroot")
os.environ.setdefault("S3_SECRET_KEY", "devrootpass")
os.environ.setdefault("S3_BUCKET", "analysis")
os.environ.setdefault("S3_REGION", "eu-central-1")

WORKER_TOKEN = os.environ["WORKER_TOKEN"]
S3_BUCKET = os.environ["S3_BUCKET"]


@pytest.fixture(scope="session", autouse=True)
def migrated() -> None:
    """Bring the test database up to the current schema, once per run.

    Invokes the real runner rather than loading the .sql files directly, so
    the tests exercise the same path a deployment uses -- a migration that
    only applies when a test applies it is not a migration anyone can trust.
    """
    subprocess.run(
        [sys.executable, str(PLATFORM_DIR / "migrations" / "run.py")],
        env={**os.environ, "DATABASE_URL": DSN},
        check=True,
        capture_output=True,
    )


@pytest.fixture
def conn():
    """A clean database and an autocommit connection.

    autocommit because several tests open ADDITIONAL connections, in threads,
    and must see each other's committed rows. Wrapping a test in one
    transaction would hide precisely the concurrency this suite exists to
    check.

    RESTART IDENTITY resets queue_seq, so "the head of the queue" is
    deterministic per test rather than depending on execution order.
    """
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("TRUNCATE jobs, worker_pipelines, workers RESTART IDENTITY CASCADE")
        yield c


# --- helpers ---------------------------------------------------------------
#
# Jobs are inserted straight to 'queued' here. Admission is the API's (#36);
# this suite tests the queue, and going through an admission path that does
# not exist yet would test nothing but the fixture.

def _s3():
    import boto3
    from botocore.config import Config

    return boto3.client(
        "s3",
        endpoint_url=os.environ["S3_INTERNAL_ENDPOINT"],
        aws_access_key_id=os.environ["S3_ACCESS_KEY"],
        aws_secret_access_key=os.environ["S3_SECRET_KEY"],
        region_name=os.environ["S3_REGION"],
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def enqueue(conn, target_os: str, required_mib: int, filename: str | None = None,
            body: bytes | None = None):
    """Put one job on the queue, with a real object behind it, and return its id.

    The object and its ETag are not decoration. A worker claim verifies that
    the sample has not been replaced since admission recorded its ETag, and a
    job with no recorded ETag **fails closed** -- which is correct, because
    admission always sets one, so a queued job without it should not exist.

    Fabricating a row straight into `queued` with nothing in the bucket would
    therefore test a state production never reaches, and every claim in this
    suite would fail for the wrong reason.
    """
    name = filename or f"{target_os}-{required_mib}.bin"
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO jobs (target_os, submitted_filename, required_mib, state)
            VALUES (%s, %s, %s, 'queued')
            RETURNING id
            """,
            (target_os, name, required_mib),
        )
        job_id = cur.fetchone()[0]

    put = _s3().put_object(
        Bucket=S3_BUCKET,
        Key=f"samples/{job_id}/{name}",
        Body=body if body is not None else b"\x7fELF" + b"\x00" * 60,
    )
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE jobs SET sample_etag = %s WHERE id = %s",
            (put["ETag"].strip('"'), job_id),
        )
    return job_id


def state_of(conn, job_id) -> str:
    with conn.cursor() as cur:
        cur.execute("SELECT state FROM jobs WHERE id = %s", (job_id,))
        return cur.fetchone()[0]


def count_in_state(conn, state: str) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM jobs WHERE state = %s", (state,))
        return cur.fetchone()[0]


# --- API fixtures ---------------------------------------------------------

@pytest.fixture
def client(conn):
    """A test client against a clean database.

    Depends on `conn` so the TRUNCATE runs first: the API opens its own pooled
    connections, and a test that truncated afterwards would be deleting rows
    the request under test had just written.
    """
    from fastapi.testclient import TestClient

    from sandbox_platform.app import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def put_object():
    """Write bytes straight into the bucket, as a browser upload would.

    Bypasses the presigned POST deliberately: what is under test in most of
    these is admission, and going through the signed form as well would make
    a failure ambiguous between the two.
    """
    import boto3
    from botocore.config import Config

    s3 = boto3.client(
        "s3",
        endpoint_url=os.environ["S3_INTERNAL_ENDPOINT"],
        aws_access_key_id=os.environ["S3_ACCESS_KEY"],
        aws_secret_access_key=os.environ["S3_SECRET_KEY"],
        region_name=os.environ["S3_REGION"],
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )

    def _put(key: str, body: bytes) -> None:
        s3.put_object(Bucket=S3_BUCKET, Key=key, Body=body)

    return _put


@pytest.fixture
def read_object():
    """Read a key back with credentials, or None if it is not there.

    The counterpart to `put_object`, and the only way to check what a presigned
    POST actually stored: a POST ticket is a write capability, so it cannot be
    used to verify its own effect.
    """
    from botocore.exceptions import ClientError

    s3 = _s3()

    def _read(key: str) -> bytes | None:
        try:
            return s3.get_object(Bucket=S3_BUCKET, Key=key)["Body"].read()
        except ClientError:
            return None

    return _read


@pytest.fixture
def remove_object():
    """Delete a key, standing in for MinIO's lifecycle rule.

    Retention expiry cannot be waited for in a test -- the shortest lifecycle
    period S3 expresses is one day, and MinIO scans on its own schedule. What
    is under test is how the platform behaves once an object is gone, not
    MinIO's scanner, so the object is removed directly.
    """
    s3 = _s3()

    def _remove(key: str) -> None:
        s3.delete_object(Bucket=S3_BUCKET, Key=key)

    return _remove


@pytest.fixture
def worker_headers():
    """Credentials for the worker channel: the token, plus the worker id that
    job-scoped routes check the lease against."""
    return {
        "Authorization": f"Bearer {WORKER_TOKEN}",
        "X-Worker-Id": "test-worker",
    }