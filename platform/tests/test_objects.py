"""The object store's own posture, against a real store.

Issue #37 (DRAFT-044).

These test the STORE, not the API: what a presigned URL can reach, what an
unauthenticated caller can learn, and what the service account is refused.

**Both stores, by assertion rather than by name.** `scripts/dev-services.sh`
brings up MinIO or Garage (`OBJECT_STORE=`), and CI runs the suite against
each, so the assertions here test properties -- refused, expired, absent --
rather than one vendor's error strings. Where the two genuinely differ the
comment says so and names the measurement. The three `mc`-gated tests at the
bottom are the exception: a service-account policy is MinIO admin-plane and
has no Garage equivalent, which is what `tests/test_object_front.py` is for. Most
of it was configured during #36 and asserted nowhere, which is the gap this
file closes -- a policy nobody exercises is a policy nobody knows the shape of.

Nothing here needs Dom0.
"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import time
import uuid

import boto3
import httpx
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from conftest import PLATFORM_DIR, S3_BUCKET

from sandbox_platform import objects
from sandbox_platform.config import settings

INTERNAL = os.environ["S3_INTERNAL_ENDPOINT"]


def _client(region: str = None, **creds):
    return boto3.client(
        "s3", endpoint_url=INTERNAL,
        aws_access_key_id=creds.get("key", settings.s3_access_key),
        aws_secret_access_key=creds.get("secret", settings.s3_secret_key),
        region_name=region or settings.s3_region,
        config=Config(signature_version="s3v4",
                      s3={"addressing_style": "path"}),
    )


# --- the sample's identity is read atomically with its bytes ----------------

def test_inspect_reads_the_etag_from_the_get_not_a_second_request(
        put_object, monkeypatch):
    """The digest and the ETag must describe the same object version.

    `inspect` used to stream the body and then issue a separate HEAD, with a
    comment asserting the ETag therefore "belonged to the bytes just hashed".
    It did not. The submitter's upload capability outlives admission and they
    choose when `/uploaded` runs, so an overwrite landing between the GET and
    the HEAD recorded `sha256` of the old bytes beside the `etag` of the new
    ones -- and the claim-time check then compared the new ETag against itself
    and said "ok".

    Pinned by making a follow-up HEAD fail the test outright: a GET is served
    from one object version, so the ETag on that response and the bytes on it
    cannot disagree, and nothing else is needed.
    """
    key = objects.sample_key(uuid.uuid4(), "s.bin", "")
    put_object(key, b"\x7fELF" + b"\x00" * 64)

    def forbidden(*_a, **_kw):
        raise AssertionError(
            "inspect() issued a second request for the ETag; it must come "
            "from the same GET that supplied the bytes")

    monkeypatch.setattr(objects, "head", forbidden)
    facts = objects.inspect(key)

    assert facts.etag
    assert len(facts.sha256) == 64
    assert facts.size_bytes == 68


def test_inspect_reports_the_etag_of_the_bytes_it_hashed(put_object):
    """End to end against the real store: the pair is self-consistent.

    A single-part upload's ETag is the object's MD5, which is exactly why it
    is not the integrity guarantee -- but it must at least describe the object
    that was hashed, because `sample_status` compares it later.
    """
    import hashlib

    body = b"MZ" + b"\x00" * 100
    key = objects.sample_key(uuid.uuid4(), "s.bin", "")
    put_object(key, body)

    facts = objects.inspect(key)

    assert facts.sha256 == hashlib.sha256(body).hexdigest()
    assert facts.etag == hashlib.md5(body).hexdigest()
    assert objects.sample_status(key, facts.etag) == "ok"


# --- what an unauthenticated caller can learn ------------------------------

def test_anonymous_access_reveals_nothing_about_a_key(put_object):
    """Not merely "403" -- 403 for BOTH cases, indistinguishably.

    If a missing key answered 404 while a present one answered 403, anonymous
    requests would be an existence oracle over a store of live malware: probe
    `samples/<job_id>/<guess>` and learn which names were submitted, without
    ever reading a byte.

    S3 gives this for free only while `ListBucket` is absent from the policy --
    grant it and the miss case turns into a 404. That coupling is why this
    test sits next to the policy test below rather than being assumed.
    """
    present = f"samples/{uuid.uuid4()}/present.bin"
    put_object(present, b"\x7fELF" + b"\x00" * 60)
    absent = f"samples/{uuid.uuid4()}/absent.bin"

    hit = httpx.get(f"{INTERNAL}/{S3_BUCKET}/{present}")
    miss = httpx.get(f"{INTERNAL}/{S3_BUCKET}/{absent}")

    assert hit.status_code == miss.status_code == 403
    assert "<Code>AccessDenied</Code>" in hit.text
    assert "<Code>AccessDenied</Code>" in miss.text
    # HEAD carries no body, so status alone must not differ either.
    assert (httpx.head(f"{INTERNAL}/{S3_BUCKET}/{present}").status_code
            == httpx.head(f"{INTERNAL}/{S3_BUCKET}/{absent}").status_code)


def test_anonymous_cannot_list_the_bucket(put_object):
    """The other half: enumeration is refused even without naming a key."""
    r = httpx.get(f"{INTERNAL}/{S3_BUCKET}?list-type=2")
    assert r.status_code == 403


# --- presigned URLs are narrow capabilities --------------------------------

def test_a_presigned_url_expires(put_object):
    """A presigned URL is a bearer capability, so its TTL is the whole of its
    containment. Tested rather than assumed."""
    key = f"samples/{uuid.uuid4()}/x.bin"
    put_object(key, b"data")

    url = objects.presigned_get(key, objects.Audience.WORKER, ttl=1)
    assert httpx.get(url).status_code == 200

    time.sleep(2)
    expired = httpx.get(url)
    # **The property is "refused", and the two stores say it differently.**
    # MinIO answers 403 with `Expired`; Garage answers
    # `400 InvalidRequest, "Date is too old"` (measured 2026-10-03). Asserting
    # MinIO's exact shape would make a store swap look like a broken
    # capability, and `sandboxd` cannot tell them apart either -- it treats
    # every 4xx as a permanent refusal (`api.py`).
    assert expired.status_code in (400, 403), expired.text
    assert any(m in expired.text for m in ("Expired", "expired", "too old"))
    # What actually matters: the bytes are gone with the capability.
    assert b"data" not in expired.content


def test_a_url_for_one_job_cannot_reach_another(put_object):
    """One key per URL, never a prefix.

    The signature covers the path, so swapping the key in a URL minted for
    job A invalidates it -- which is what stops a presigned GET from being a
    bucket-walking primitive one job id at a time.
    """
    a, b = uuid.uuid4(), uuid.uuid4()
    put_object(f"samples/{a}/mine.bin", b"mine")
    put_object(f"samples/{b}/theirs.bin", b"theirs")

    mine = objects.presigned_get(f"samples/{a}/mine.bin",
                                 objects.Audience.WORKER)
    stolen = mine.replace(f"samples/{a}/mine.bin", f"samples/{b}/theirs.bin")

    assert httpx.get(mine).status_code == 200
    assert httpx.get(stolen).status_code == 403


def test_the_ttls_are_the_ones_that_were_decided():
    """DRAFT-044 fixed four lifetimes. They are cheap to change by accident
    and the change would be invisible, so they are pinned here."""
    key = "samples/x/y.bin"

    assert settings.upload_ttl == 900            # browser upload, 15 min
    assert settings.artifact_get_ttl == 300      # browser artifact GET, 5 min

    # A worker's sample URL is useless once its lease lapses, so it is signed
    # for exactly that long rather than for a fixed window.
    worker_url = objects.presigned_get(key, objects.Audience.WORKER,
                                       ttl=settings.lease_seconds)
    assert f"X-Amz-Expires={settings.lease_seconds}" in worker_url
    assert (f"X-Amz-Expires={settings.artifact_get_ttl}"
            in objects.presigned_get(key, objects.Audience.BROWSER))


# --- keys survive hostile names --------------------------------------------

@pytest.mark.parametrize("name", [
    '"; rm -rf ~ #', "$(whoami).sh", "`id`.bin", "a b c.exe",
    "50%off.exe", "<script>alert(1)", "dropped‮gnp.exe", "é" * 40,
])
def test_a_hostile_filename_round_trips_through_a_real_presigned_post(
        name, read_object):
    """Through the SIGNED policy and back out byte-exact.

    The existing submission test uses put_object, which proves the API keeps
    the name but not that the key survives policy signing and multipart form
    encoding -- where the name appears in a signed condition, a form field and
    the stored key, and any one of them could normalise it.
    """
    job_id = uuid.uuid4()
    body = b"\x7fELF" + b"\x00" * 60

    # The empty prefix is the pre-#40 flat layout, and it is what this asserts
    # below. Passed explicitly rather than defaulted: every job written before
    # migration 0008 carries it, so this is the shape with real objects behind
    # it in the deployment, and it must keep resolving byte-identically.
    ticket = objects.presigned_upload(job_id, name, len(body), "")
    r = httpx.post(ticket.url, data=ticket.fields,
                   files={"file": (name, body)})

    assert r.status_code in (200, 201, 204), r.text[:300]
    assert ticket.fields["key"] == f"samples/{job_id}/{name}"
    assert read_object(f"samples/{job_id}/{name}") == body


# --- the store's own configuration -----------------------------------------

def test_the_region_is_enforced():
    """A signature scoped to the wrong region is refused.

    This is the behavioural check for MINIO_SITE_REGION. The obvious probe --
    `mc admin config get <alias> region` -- reports EMPTY for an env-provided
    value and is not a probe at all; it is what made the region look unset
    through two separate investigations before 2026-08-24.
    """
    key = f"samples/{uuid.uuid4()}/x.bin"
    _client().put_object(Bucket=S3_BUCKET, Key=key, Body=b"x")

    wrong = _client(region="us-west-1").generate_presigned_url(
        "get_object", Params={"Bucket": S3_BUCKET, "Key": key}, ExpiresIn=60)
    r = httpx.get(wrong)

    assert r.status_code == 400
    assert "AuthorizationHeaderMalformed" in r.text


def test_versioning_is_off():
    """Off deliberately: versioning a store of large write-once artifacts
    multiplies storage for a rollback nobody performs."""
    status = _client().get_bucket_versioning(Bucket=S3_BUCKET).get("Status")
    assert status in (None, "Suspended"), status


def test_object_lock_is_off():
    """Object lock would make retention UNDECIDABLE -- you cannot delete what
    is locked, and the store's lifecycle rule must be able to.

    It can only be set at bucket creation, so this can only be an assertion.
    `NotImplemented` is Garage's answer and is the strongest form of this
    passing: the feature does not exist there at all, so it cannot be enabled
    by accident later.
    """
    with pytest.raises(ClientError) as exc:
        _client().get_object_lock_configuration(Bucket=S3_BUCKET)
    assert exc.value.response["Error"]["Code"] in (
        "ObjectLockConfigurationNotFoundError", "InvalidRequest",
        "NotImplemented",
    )


# --- the service account's absent capabilities -----------------------------
#
# The acceptance criterion is that these are asserted by test rather than read
# off the policy file, which needs a service account carrying that policy --
# and creating one is MinIO admin-plane, which the S3 API does not reach.

def _mc_binary() -> str | None:
    return os.environ.get("MC_BIN") or shutil.which("mc")


@pytest.fixture(scope="module")
def restricted_client(tmp_path_factory):
    """A boto3 client holding exactly the policy the API is deployed with."""
    binary = _mc_binary()
    if binary is None:
        pytest.skip("mc not found. The policy's ABSENT capabilities cannot be "
                    "asserted without it -- put mc on PATH or set MC_BIN. "
                    "Skipping means no_list/no_delete are UNVERIFIED.")

    policy = PLATFORM_DIR / "minio" / "api-policy.json"
    root_user = os.environ.get("MINIO_ROOT_USER", settings.s3_access_key)
    root_pass = os.environ.get("MINIO_ROOT_PASSWORD", settings.s3_secret_key)
    # MinIO requires 3..20 for an access key and 8..40 for a secret, and says
    # so only after the call fails. 14 and 40 -- the secret matches what
    # provision.sh mints, so the deployed shape is what gets exercised.
    access = f"probe-{uuid.uuid4().hex[:8]}"
    secret = secrets.token_urlsafe(30)

    # Its own config dir, so a developer's ~/.mc aliases are untouched.
    env = {**os.environ, "MC_CONFIG_DIR": str(tmp_path_factory.mktemp("mc"))}

    def mc(*args):
        return subprocess.run([binary, *args], env=env, check=True,
                              capture_output=True, text=True)

    mc("alias", "set", "probe", INTERNAL, root_user, root_pass)
    mc("admin", "user", "svcacct", "add", "probe", root_user,
       "--access-key", access, "--secret-key", secret,
       "--policy", str(policy))
    try:
        yield _client(key=access, secret=secret)
    finally:
        mc("admin", "user", "svcacct", "rm", "probe", access)


def test_the_service_account_can_read_and_write(restricted_client, put_object):
    """The capabilities it does need. PutObject is here even though the API
    never uploads: it SIGNS presigned POSTs, and a presigned URL carries the
    signer's permissions, so without it every upload fails at use time."""
    key = f"samples/{uuid.uuid4()}/x.bin"

    restricted_client.put_object(Bucket=S3_BUCKET, Key=key, Body=b"data")
    assert restricted_client.get_object(
        Bucket=S3_BUCKET, Key=key)["Body"].read() == b"data"
    assert restricted_client.head_object(
        Bucket=S3_BUCKET, Key=key)["ContentLength"] == 4


def test_the_service_account_cannot_enumerate(restricted_client):
    """No ListBucket, so a compromised API cannot walk a store of live malware
    -- and, per the anonymous test above, cannot turn misses into 404s."""
    with pytest.raises(ClientError) as exc:
        restricted_client.list_objects_v2(Bucket=S3_BUCKET)
    assert exc.value.response["Error"]["Code"] == "AccessDenied"

    with pytest.raises(ClientError):
        restricted_client.list_buckets()


def test_the_service_account_cannot_delete(restricted_client, put_object):
    """No DeleteObject. Retention is done by the store's own lifecycle rule, so
    the capability buys nothing and would make a compromised API destructive.

    This is what lets `platform.md` say the API is not a deletion primitive
    without qualifying it.
    """
    key = f"samples/{uuid.uuid4()}/keepme.bin"
    put_object(key, b"evidence")

    with pytest.raises(ClientError) as exc:
        restricted_client.delete_object(Bucket=S3_BUCKET, Key=key)
    assert exc.value.response["Error"]["Code"] == "AccessDenied"


# --- the namespace the tunnel now shares -----------------------------------

def test_no_api_route_claims_the_bucket_prefix():
    """Since #37 the object store is path-routed at `/analysis/*` on the API's
    own hostname, which is what makes the browser upload same-origin and puts
    the store behind Access.

    The cost is a shared namespace: cloudflared matches `^/analysis(/|$)`
    before the API rule, so an API or UI route beginning `/analysis` would be
    routed to the store and simply stop existing. It would fail in deployment
    only, with the store complaining about a signature.
    """
    from sandbox_platform.app import app

    offenders = [r.path for r in app.routes
                 if getattr(r, "path", "").startswith("/analysis")]
    assert offenders == [], offenders