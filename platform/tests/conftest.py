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
    result = subprocess.run(
        [sys.executable, str(PLATFORM_DIR / "migrations" / "run.py")],
        env={**os.environ, "DATABASE_URL": DSN},
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # NOT check=True. That raises a CalledProcessError whose message names
        # the command and swallows its stderr, so every test in the suite
        # errors at setup with no reason given -- observed on the deployment
        # 2026-08-25, where the cause was simply that the test database did
        # not exist and finding that out took a second run with head -40.
        pytest.fail(
            f"migrations failed against {DSN}\n"
            f"  Create it with:  createdb sandbox_platform_test\n"
            f"  or point TEST_DATABASE_URL at an existing database.\n\n"
            f"{result.stderr or result.stdout}",
            pytrace=False,
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
        # `tenants` belongs here for the same reason `jobs` does: a balance
        # surviving into the next test makes a first-submission grant look
        # like a top-up, and a test asserting on a drawn-down balance passes
        # or fails on what ran before it.
        c.execute("TRUNCATE jobs, tenants, worker_pipelines, workers"
                  " RESTART IDENTITY CASCADE")
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


# Who a fixture-built job belongs to when the test does not care.
#
# It has to be SOMEONE: `jobs.owner` is NOT NULL since migration 0008, and the
# deployment has no ownerless rows, so a fixture that made one would build a
# state production cannot reach -- which is how the old ownerless fixtures were
# testing the queue against jobs no submission could produce.
DEFAULT_OWNER = "fixture-owner@example.test"


def enqueue(conn, target_os: str, required_mib: int, filename: str | None = None,
            body: bytes | None = None, owner: str = DEFAULT_OWNER):
    """Put one job on the queue, with a real object behind it, and return its id.

    The object and its ETag are not decoration. A worker claim verifies that
    the sample has not been replaced since admission recorded its ETag, and a
    job with no recorded ETag **fails closed** -- which is correct, because
    admission always sets one, so a queued job without it should not exist.

    Fabricating a row straight into `queued` with nothing in the bucket would
    therefore test a state production never reaches, and every claim in this
    suite would fail for the wrong reason.

    The tenant row is created for the same reason. A terminal transition draws
    the job's runtime down from `tenants` (DRAFT-047 decision 8), and an absent
    tenant makes that UPDATE match zero rows -- silently, since it is not an
    error. Tests asserting on a balance would then pass against a charge that
    never landed.
    """
    name = filename or f"{target_os}-{required_mib}.bin"
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO tenants (owner) VALUES (%s) ON CONFLICT DO NOTHING",
            (owner,),
        )
        cur.execute(
            """
            INSERT INTO jobs (target_os, submitted_filename, required_mib, state,
                              owner)
            VALUES (%s, %s, %s, 'queued', %s)
            RETURNING id
            """,
            (target_os, name, required_mib, owner),
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
def client(conn, request):
    """A test client against a clean database, authenticated as someone.

    Depends on `conn` so the TRUNCATE runs first: the API opens its own pooled
    connections, and a test that truncated afterwards would be deleting rows
    the request under test had just written.

    **The identity override is what makes this the browser listener.**
    `REQUIRE_ACCESS_JWT` is unset by default, so `access_identity` returns None
    -- which since migration 0008 means `create_job` refuses with a 403, because
    `jobs.owner` is NOT NULL and there is nobody to record. That is correct for
    the mTLS listener and wrong for the ninety-odd tests here that are about
    admission, file magic, size policy or UI rendering and merely need a
    submitter to exist.

    A test that is genuinely ABOUT identity asks for `access_token` -- or for
    `issuer`, which `test_access_jwt.py` keeps for itself because it needs the
    private key to forge signatures -- and gets the real dependency with real
    verification. Keyed on `request.fixturenames` rather than on fixture
    ordering, which is not something to depend on: that set is resolved before
    any of them run.
    """
    from fastapi.testclient import TestClient

    from sandbox_platform import auth
    from sandbox_platform.app import app

    if not {"access_token", "issuer", "no_identity"} & set(request.fixturenames):
        app.dependency_overrides[auth.access_identity] = lambda: DEFAULT_OWNER
    try:
        with TestClient(app) as c:
            yield c
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def no_identity():
    """Opt out of `client`'s identity override and get a genuinely anonymous one.

    A marker rather than a value: requesting it is the whole signal, which is
    why it returns nothing.

    Needed because the other two opt-outs do not reach this case. `issuer` and
    `access_token` both switch `REQUIRE_ACCESS_JWT` on, so a request without a
    token gets a 401 from `access_identity` and never reaches the route. The
    state under test here is the OTHER listener: Access off, a client
    certificate at the TLS layer, and therefore an identity of None -- which is
    what `auth.required_identity` refuses with a 403.
    """
    return None


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
def access_token(monkeypatch):
    """Mint verifiable Cloudflare Access headers for arbitrary users.

    A real RSA key and a real signature, checked by the real verification path
    -- only `auth._signing_key` is patched, to serve the public half rather
    than fetching it from Cloudflare. That matters for the tenancy tests: a
    404 they observe came from the scope predicate, not from a token the
    verifier happened to reject for an unrelated reason.

    `test_access_jwt.py` keeps its own issuer rather than using this one. It
    needs control of the PRIVATE key to forge signatures with the wrong one,
    which this factory deliberately does not expose -- these two want opposite
    things from the same machinery.
    """
    import dataclasses
    import time as _time

    import jwt as _jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from sandbox_platform import auth
    from sandbox_platform.config import settings as _settings

    team = "https://testteam.cloudflareaccess.com"
    aud = "0123456789abcdef"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    # Settings is frozen, so replace the object auth.py resolved. This is also
    # closer to deployment, where the two listeners each hold one immutable
    # snapshot with a different REQUIRE_ACCESS_JWT.
    monkeypatch.setattr(auth, "settings", dataclasses.replace(
        _settings, require_access_jwt=True,
        access_team_domain=team, access_aud=aud))
    monkeypatch.setattr(auth, "_signing_key", lambda _t: key.public_key())

    def _headers(email: str) -> dict[str, str]:
        token = _jwt.encode(
            {"aud": aud, "iss": team, "email": email,
             "exp": int(_time.time()) + 600, "iat": int(_time.time())},
            pem, algorithm="RS256", headers={"kid": "test-key-1"},
        )
        return {"Cf-Access-Jwt-Assertion": token}

    return _headers


@pytest.fixture
def worker_headers():
    """Credentials for the worker channel: the token, plus the worker id that
    job-scoped routes check the lease against."""
    return {
        "Authorization": f"Bearer {WORKER_TOKEN}",
        "X-Worker-Id": "test-worker",
    }