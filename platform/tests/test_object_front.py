"""The capability front's refusals -- `platform/garage/objects.conf`.

**Why this is a separate module.** `test_objects.py` tests the STORE: what a
presigned URL reaches, what the credential may do. Three of its assertions --
no `ListBucket`, no `DeleteObject`, and the service account's shape -- were
properties of MinIO's `api-policy.json`, and **Garage has no policy language**
to express them: `read` implies ListObjects and `write` implies DeleteObject,
DeleteObjects and CopyObject. Runbook 18 DECISION A2 moves those absences into
the nginx front, so they stop being properties of a credential and become
properties of a request path.

That is a worse place to keep a security property in one specific way: nothing
in this repository runs the front, so nothing notices if it stops filtering.
This module is what notices, and `platform/garage/conformance.py` is its
operator-facing twin -- the same assertions, runnable against the deployment
with one credential and no pytest. **The duplication is deliberate and small**,
like the three copies of the sample-name rule: this one gates a merge, that one
gates a deployment, and neither can run where the other does.

It skips unless `S3_FRONT_ENDPOINT` names a front, because
`scripts/dev-services.sh` brings up a bare store with nothing in front of it --
the deployment's shape needs a certificate and a privileged port. A skipped
run leaves the absences **unverified**, which is what the skip message says.

    S3_FRONT_ENDPOINT=https://192.168.1.10:9000 \\
    S3_FRONT_CA=/etc/sandbox-platform/tls/ca.crt \\
      .venv/bin/python -m pytest -q tests/test_object_front.py
"""

from __future__ import annotations

import os
import ssl
import uuid

import boto3
import httpx
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from conftest import S3_BUCKET

FRONT = os.environ.get("S3_FRONT_ENDPOINT")
_CA = os.environ.get("S3_FRONT_CA")

# httpx deprecated `verify=<path>`; botocore still takes one. An SSLContext
# serves both and is built once, because loading a CA file per request is a
# surprising amount of work for a test that makes forty of them.
FRONT_CA = ssl.create_default_context(cafile=_CA) if _CA else True
BOTO_CA = _CA or True

pytestmark = pytest.mark.skipif(
    not FRONT,
    reason="S3_FRONT_ENDPOINT is unset, so the capability front is NOT under "
           "test and `no ListBucket` / `no DeleteObject` are UNVERIFIED. "
           "Point it at a front (runbook 18 Part E) to assert them.",
)


@pytest.fixture(scope="module")
def front():
    return boto3.client(
        "s3", endpoint_url=FRONT,
        aws_access_key_id=os.environ["S3_ACCESS_KEY"],
        aws_secret_access_key=os.environ["S3_SECRET_KEY"],
        region_name=os.environ["S3_REGION"],
        verify=BOTO_CA,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"},
                      retries={"max_attempts": 1}),
    )


@pytest.fixture(scope="module")
def probe(front):
    """One object, written the only way the front allows: a presigned POST.

    Not `put_object` -- a PUT is refused, which is one of the assertions below.
    So the fixture doubles as proof that the allowed path works, and the
    teardown is deliberately absent: the front refuses DELETE, and the bucket's
    lifecycle rule collects `probe/` objects.
    """
    key = f"probe/front-{uuid.uuid4()}.bin"
    post = front.generate_presigned_post(
        Bucket=S3_BUCKET, Key=key,
        Conditions=[["content-length-range", 0, 2048], {"key": key}],
        ExpiresIn=300)
    r = httpx.post(post["url"], data=post["fields"],
                   files={"file": ("probe.bin", b"B" * 64)}, verify=FRONT_CA)
    assert r.status_code in (200, 204), r.text
    return key


def _refused(call, *args, **kwargs) -> str:
    """The status and code of a refusal, or `allowed` -- which is a failure.

    nginx answers with an HTML page, so a refusal from the front carries no S3
    error code and botocore reports the status twice (`403 403`). An
    S3-*coded* 403 means the STORE refused it and the front did not: a weaker
    posture that happens to look the same, so the tests below distinguish them.
    """
    try:
        call(*args, **kwargs)
        return "allowed"
    except ClientError as exc:
        return (f'{exc.response["ResponseMetadata"]["HTTPStatusCode"]} '
                f'{exc.response["Error"]["Code"]}')


# --- what the platform needs, which must keep working ----------------------

def test_the_allowed_path_still_works(front, probe):
    """A front that refuses everything would pass every test below."""
    assert front.get_object(Bucket=S3_BUCKET, Key=probe)["ContentLength"] == 64
    assert front.head_object(Bucket=S3_BUCKET, Key=probe)["ContentLength"] == 64
    ranged = front.get_object(Bucket=S3_BUCKET, Key=probe, Range="bytes=0-9")
    assert ranged["ContentLength"] == 10


# --- what api-policy.json withheld, and the front now withholds -------------

def test_no_list_bucket(front, probe):
    """A compromised API must not be able to enumerate a store of live
    malware. Under MinIO this was the absence of `s3:ListBucket` from the
    service account; here it is the front refusing a bucket-level GET."""
    assert _refused(front.list_objects_v2, Bucket=S3_BUCKET) == "403 403"


def test_no_list_buckets(front):
    assert _refused(front.list_buckets) == "403 403"


def test_no_delete_object(front, probe):
    """Nothing in the design deletes an artifact -- the store's own lifecycle
    rule does the expiring -- so the capability should not exist."""
    assert _refused(front.delete_object, Bucket=S3_BUCKET, Key=probe) == "403 403"


def test_no_multi_object_delete(front, probe):
    """`POST /analysis?delete`, which the method filter alone would miss."""
    assert _refused(front.delete_objects, Bucket=S3_BUCKET,
                    Delete={"Objects": [{"Key": probe}]}) == "403 403"


def test_no_server_side_copy(front, probe):
    """CopyObject turns one object's read into another object's write, and it
    is what CVE-2026-97731 reached through MinIO's unsigned-header gap."""
    assert _refused(front.copy_object, Bucket=S3_BUCKET, Key=probe + ".copy",
                    CopySource={"Bucket": S3_BUCKET, "Key": probe}) == "403 403"


def test_no_bucket_configuration(front):
    """CORS and the lifecycle rule are the provisioning script's, not the
    API's. Garage also refuses this one at the credential, since it needs
    `owner` -- so this asserts the front answers FIRST."""
    assert _refused(front.put_bucket_cors, Bucket=S3_BUCKET, CORSConfiguration={
        "CORSRules": [{"AllowedOrigins": ["*"], "AllowedMethods": ["GET"]}]}
    ) == "403 403"


# --- shapes that need no credential at all ---------------------------------
#
# These fail closed before any signature is examined, which is the property
# that makes the front worth having rather than a second copy of the policy.

@pytest.mark.parametrize("method,path,headers", [
    ("PUT", "/probe-copy", {"x-amz-copy-source": "/analysis/x"}),  # the CVE's shape
    ("PUT", "/probe-put", {}),
    ("POST", "/probe-mpu?uploads", {}),                            # multipart init
    ("DELETE", "/probe-del", {}),
])
def test_unsigned_write_shapes_are_refused(method, path, headers):
    r = httpx.request(method, f"{FRONT}/{S3_BUCKET}{path}",
                      headers=headers, verify=FRONT_CA)
    assert r.status_code == 403, r.text[:200]


@pytest.mark.parametrize("path", [
    "/",                      # ListBuckets
    f"/{S3_BUCKET}",          # ListObjects
    f"/{S3_BUCKET}/",         # ...with a trailing slash
    f"/{S3_BUCKET}?list-type=2",
    "/minio/health/live",     # gone with MinIO
    "/admin/v1/status",       # Garage's admin API, were it ever exposed
])
def test_unsigned_read_shapes_are_refused(path):
    r = httpx.get(f"{FRONT}{path}", verify=FRONT_CA)
    assert r.status_code == 403, r.text[:200]


def test_an_unsigned_object_get_reaches_the_store_and_is_refused_there(probe):
    """The one case that is deliberately NOT a front refusal.

    An unsigned GET of a real key is allowed through, and the store says no.
    Keeping these two refusals distinguishable is what makes a 403 diagnosable
    at all: if this one starts coming from nginx, every anonymous-access
    assertion in `conformance.py` silently stops testing the store.
    """
    r = httpx.get(f"{FRONT}/{S3_BUCKET}/{probe}", verify=FRONT_CA)
    assert r.status_code == 403
    assert "<Code>" in r.text, "a 403 with no S3 body came from the front"
