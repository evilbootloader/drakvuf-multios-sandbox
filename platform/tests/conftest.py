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
        # `rate_limit` belongs here for the same reason `tenants` does, and the
        # leak is sharper: every request from TestClient reports a peer of
        # `testclient`, so ALL tests share one `ip:testclient` bucket and its
        # count climbs across the whole session. A throttling test then passes
        # or fails on how many tests ran before it.
        c.execute("TRUNCATE jobs, tenants, rate_limit, worker_pipelines, workers"
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


def identity_id(cur, email: str) -> str:
    """The tenant id for an address, creating the identity if it is new.

    **The same statement `auth.resolve_tenant` uses, deliberately duplicated**
    rather than called. `resolve_tenant` takes its own pooled connection, and
    these fixtures write on the `conn` fixture's connection inside a
    transaction the API has not seen -- so calling it would either deadlock on
    the uncommitted row or resolve against a different snapshot. Running the
    upsert on the caller's cursor keeps one transaction.

    Needed at all because `jobs.owner` and `tenants.owner` are `uuid` since
    0009, so a fixture inserting an address gets `invalid input syntax for type
    uuid` -- 252 of them, which is how this was found.

    **Writes `access_subject` and NOT `email`, matching `resolve_tenant` after
    DRAFT-061 split the two.** The address a test hands the `access_identity`
    override is a provider assertion, so it belongs in the column that
    resolution joins on; `email` is the login address, which only signup and
    `create_user.py` write. Mirroring the wrong column made every job invisible
    to the caller who submitted it -- the API resolved the override's address to
    a NEW identity and `visible_to` scoped against that, so 106 tests saw an
    empty history rather than their own row. That is the failure this split is
    meant to produce when the two are confused, so it is worth keeping legible
    here rather than papering over by writing both.
    """
    cur.execute(
        """
        INSERT INTO identities (access_subject) VALUES (lower(%s))
        ON CONFLICT (lower(access_subject))
            DO UPDATE SET access_subject = identities.access_subject
        RETURNING id
        """,
        (email,),
    )
    return str(cur.fetchone()[0])


def credentialed_identity_id(cur, email: str) -> str:
    """`identity_id` for an account that signs in with a PASSWORD.

    **The other half of the DRAFT-061 split, and the reason there are two of
    these.** `identity_id` writes `access_subject`, which is what an external
    provider asserts and what `resolve_tenant` resolves on. This writes `email`,
    which is the login address -- what `/auth/login` looks up and the only one of
    the two a stranger can ever propose. A fixture that writes the wrong column
    produces a plausible-looking account that cannot be logged into at all: 41
    tests failed exactly that way, with `invalid email or password` against a
    password that was correct.

    Mirrors what `/auth/signup` and `create_user.py` write. Neither of them
    touches `access_subject`, and neither does this.
    """
    cur.execute(
        """
        INSERT INTO identities (email) VALUES (lower(%s))
        ON CONFLICT (lower(email)) DO UPDATE SET email = identities.email
        RETURNING id
        """,
        (email,),
    )
    return str(cur.fetchone()[0])


def owner_id(conn, email: str = DEFAULT_OWNER) -> str:
    """`identity_id` for the many tests that insert with `conn.execute`.

    Tests name their submitters by address, because that is what reads as a
    person and what the `access_identity` override hands the API. Since 0009 the
    COLUMN wants the tenant id that address resolves to, and this is the one
    line that bridges the two -- so a raw fixture insert stays as readable as it
    was while writing what `visible_to` and `_owned_or_404` will match on.

    Creates the identity if this is the first mention of the address, which is
    what makes it safe for the one-off submitters in `test_quota.py` that no
    earlier request has introduced.
    """
    with conn.cursor() as cur:
        return identity_id(cur, email)


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
        # `owner` arrives as an address, because that is what reads naturally in
        # a test and what the `access_identity` override hands the API. Both
        # columns below want the tenant id it resolves to.
        owner_id = identity_id(cur, owner)
        cur.execute(
            "INSERT INTO tenants (owner) VALUES (%s) ON CONFLICT DO NOTHING",
            (owner_id,),
        )
        cur.execute(
            """
            INSERT INTO jobs (target_os, submitted_filename, required_mib, state,
                              owner, timeout, disable_sysret)
            VALUES (%s, %s, %s, 'queued', %s, 180, True)
            RETURNING id
            """,
            (target_os, name, required_mib, owner_id),
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

    if not {"access_token", "issuer", "no_identity",
            "infrastructure"} & set(request.fixturenames):
        app.dependency_overrides[auth.access_identity] = lambda: DEFAULT_OWNER
    try:
        # **The CSRF header by default, on every request this client makes.**
        #
        # `sandbox_platform/csrf.py` is attached to the auth, jobs and account
        # routers and refuses any unsafe method without it. Setting it here
        # rather than at ~68 call sites keeps those tests about what they are
        # about -- admission, tenancy, quota, rendering -- instead of turning a
        # security rule into 68 opportunities to forget it and one enormous
        # diff.
        #
        # The rule is still tested, and tested better, by the handful of tests
        # that ask for it EXPLICITLY by sending no header. A negative test that
        # has to construct the failure is a real assertion; sixty-eight positive
        # ones that would all break together are a tripwire, not a test.
        with TestClient(app, headers={"X-Sandbox-Request": "1"}) as c:
            yield c
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def no_identity():
    """Opt out of `client`'s identity override: a genuinely anonymous caller.

    A marker rather than a value: requesting it is the whole signal, which is
    why it returns nothing.

    Needed because the other two opt-outs do not reach this case. `issuer` and
    `access_token` both switch `REQUIRE_ACCESS_JWT` on, so a request without a
    token gets a 401 from `access_identity` and never reaches the route.

    **Since DRAFT-061 this is a 401 rather than an identity of None.** Nobody
    is the same as nobody now: `caller_identity` refuses when no credential
    produced an identity, instead of handing `visible_to` a None it read as
    "see everything". `infrastructure` below is the fixture for the case that
    used to share this one.
    """
    return None


@pytest.fixture
def infrastructure(monkeypatch):
    """A listener where an unauthenticated caller IS infrastructure.

    The mTLS listener: reachable only over the LAN, behind a client certificate,
    carrying Dom0 and the command-line tools. That used to be inferred from
    Access being off, which made it the accidental meaning of every failure to
    produce an identity. `INFRASTRUCTURE_LISTENER` says it out loud, and this
    fixture is how a test asks for it.
    """
    import dataclasses

    from sandbox_platform import auth
    from sandbox_platform.config import settings

    monkeypatch.setattr(
        auth, "settings",
        dataclasses.replace(settings, infrastructure_listener=True),
    )
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


#: The worker every fixture here authenticates as. Named rather than passed
#: around because `enqueue` hands jobs to it and the lease checks compare
#: against it.
TEST_WORKER_ID = "test-worker"


@pytest.fixture
def worker_headers(conn):
    """Credentials for the worker channel.

    **A provisioned row, not a shared secret.** Since DRAFT-061 the platform
    resolves the worker id from the token's own hash, so there is no
    `X-Worker-Id` to send and no `WORKER_TOKEN` that every worker shares --
    a fixture that sent one would be testing a door that no longer exists.

    Depends on `conn` so the row is created after the TRUNCATE, not before it.
    """
    from sandbox_platform.credentials import hash_refresh_token

    conn.execute(
        """
        INSERT INTO workers (worker_id, total_mib, total_vlans, total_slots,
                             token_hash)
        VALUES (%s, 1, 1, 1, %s)
        ON CONFLICT (worker_id) DO UPDATE SET token_hash = EXCLUDED.token_hash
        """,
        (TEST_WORKER_ID, hash_refresh_token(WORKER_TOKEN)),
    )
    return {"Authorization": f"Bearer {WORKER_TOKEN}"}


@pytest.fixture
def other_worker_headers(conn):
    """A SECOND provisioned worker, for the tests about one not reaching
    another's job.

    Before DRAFT-061 those tests changed an `X-Worker-Id` header and kept the
    shared token -- which is exactly the thing that no longer exists, and
    exactly why it was a gap. Impersonation is now expressed the only way it
    can be: by holding a different credential.
    """
    from sandbox_platform.credentials import hash_refresh_token

    token = "second-worker-token"
    conn.execute(
        """
        INSERT INTO workers (worker_id, total_mib, total_vlans, total_slots,
                             token_hash)
        VALUES ('other-worker', 1, 1, 1, %s)
        ON CONFLICT (worker_id) DO UPDATE SET token_hash = EXCLUDED.token_hash
        """,
        (hash_refresh_token(token),),
    )
    return {"Authorization": f"Bearer {token}"}