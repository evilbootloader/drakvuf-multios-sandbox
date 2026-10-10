#!/usr/bin/env python3
"""Assert the analysis object store's posture. Runbook 18, Part D2.

**Why this exists.** `platform/minio/provision.sh` both applied settings and
*asserted* four properties that it never changed -- anonymous access off,
versioning off, object lock off, and the region actually in effect -- because
"set it anyway so the posture is declared rather than inherited". Garage
implements three of those differently, and a fifth group has no equivalent at
all: the capabilities `api-policy.json` deliberately **withheld**.

Garage has no policy language. Permissions are per key, per bucket, and `read`
implies ListObjects while `write` implies DeleteObject, DeleteObjects and
CopyObject (`src/api/s3/router.rs`). So "GetObject and PutObject, and nothing
else" is not expressible as a credential here, and it is enforced by the TLS
front instead -- runbook 18 DECISION A2. That makes it a property of a config
file on one host rather than of the credential, which is exactly the kind of
claim that rots quietly. This is the thing that notices.

**It needs one credential: the API's own.** Measured 2026-10-03, `read` is
enough for `GetBucketVersioning` and `GetBucketLifecycleConfiguration`, object
lock answers `501 NotImplemented` to anybody, and only `GetBucketCors` wants
`owner` -- which is why CORS is asserted *behaviourally* here, through real
preflights, rather than by reading the configuration back. `provision.sh`
prints that read-back at the moment it applies it.

Credentials come from the ENVIRONMENT, never argv: this repository reads
`/proc/<pid>/cmdline` to find processes (`sandboxd/proc.py`), so a secret on a
command line is a secret in every process listing on the host.

    S3_ACCESS_KEY=GK... S3_SECRET_KEY=... \\
      platform/garage/conformance.py \\
        --front https://192.168.1.10:9000 \\
        --direct http://127.0.0.1:3900 \\
        --origin https://sandbox.evilbootloader.com

`--front` is the only required endpoint and is what the platform talks to.
`--direct` is Garage itself, which binds loopback, so it is available only on
the platform DomU -- it unlocks the three store-posture checks that are
bucket-level GETs (the front refuses those on purpose) and the demonstration
of what the front is actually holding back. Everything skips loudly rather
than silently when an endpoint is absent.

Exit status is 0 only when nothing was unexpected. Skips do not fail the run,
and the summary says how many there were, because a run that skipped the
withheld-capability checks has not verified them.
"""

from __future__ import annotations

import argparse
import os
import ssl
import sys
import uuid

try:
    import boto3
    import httpx
    from botocore.config import Config
    from botocore.exceptions import ClientError
except ImportError as exc:        # pragma: no cover - an invocation mistake
    # The shebang finds the system interpreter, which has neither. Say which
    # python to use rather than leaving a bare ModuleNotFoundError: on the
    # platform DomU the only one that can run this is the service's own venv.
    sys.exit(f"conformance: {exc}.\n"
             "Run this with the platform venv's interpreter, which has boto3:\n"
             "  /opt/platform/src/platform/.venv/bin/python "
             "/opt/platform/src/platform/garage/conformance.py ...")

FOREIGN_ORIGIN = "https://attacker.example"

# A probe object has to be written to assert anything about reading one. It
# goes under its own prefix -- never `samples/`, `results/` or `u/`, which are
# the layouts `objects.py` mints and the UI reads -- so it cannot be mistaken
# for a job's data, and the bucket's own lifecycle rule collects it even if
# this script cannot (see --keep-probe).
PROBE_PREFIX = "probe/"


class Walk:
    """One line per control, and a status that means something."""

    def __init__(self) -> None:
        self.ok = self.bad = self.skipped = 0

    def section(self, title: str, note: str = "") -> None:
        print(f"\n== {title}")
        if note:
            print(f"   {note}")

    def check(self, control: str, expected, got) -> bool:
        good = expected == got
        self.ok, self.bad = self.ok + good, self.bad + (not good)
        print(f"  {'ok  ' if good else 'FAIL'}  {control:<52} {got}")
        if not good:
            print(f"        expected: {expected!r}")
        return good

    def skip(self, control: str, why: str) -> None:
        self.skipped += 1
        print(f"  skip  {control:<52} {why}")

    def summary(self) -> int:
        print(f"\n{self.ok} ok, {self.bad} unexpected, {self.skipped} skipped")
        if self.skipped:
            print("A skipped control is an UNVERIFIED control, not a passing one.")
        return 1 if self.bad else 0


def httpx_verify(ca: str | None):
    """What httpx wants, which is no longer a path.

    `verify=<str>` is deprecated there while botocore still takes one, so the
    two get different objects built from the same `--ca`.
    """
    return ssl.create_default_context(cafile=ca) if ca else True


def client(endpoint: str, key: str, secret: str, region: str, ca: str | None):
    return boto3.client(
        "s3", endpoint_url=endpoint, aws_access_key_id=key,
        aws_secret_access_key=secret, region_name=region,
        verify=(ca or True) if endpoint.startswith("https") else True,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"},
                      # One attempt, so a refusal is reported rather than
                      # retried into a timeout. botocore still re-signs on a
                      # region hint -- see the region check.
                      retries={"max_attempts": 1}),
    )


def outcome(fn, *args, **kwargs) -> str:
    """`allowed`, or `<status> <code>` for a refusal.

    nginx answers with an HTML page, so a refusal from the FRONT carries no S3
    error code and botocore reports the status twice -- `403 403`. That is the
    signature of the front having answered rather than the store, and it is
    worth being able to tell apart at a glance.
    """
    try:
        fn(*args, **kwargs)
        return "allowed"
    except ClientError as exc:
        return (f'{exc.response["ResponseMetadata"]["HTTPStatusCode"]} '
                f'{exc.response["Error"]["Code"]}')


def store_posture(w: Walk, direct, bucket: str, retention_days: int) -> None:
    """provision.sh's assertion half. Bucket-level GETs, so --direct only."""
    w.section("the store's posture (provision.sh's assertions)")

    if direct is None:
        for control in ("versioning is off", "object lock is not enabled",
                        "retention rule is installed"):
            w.skip(control, "needs --direct: the front refuses bucket-level GETs")
        return

    # MinIO's provision.sh refused to CHANGE either of these -- turning
    # versioning off would discard existing versions, and object lock can only
    # be set at bucket creation -- so both could only ever be assertions.
    # Garage implements neither, which makes the assertions structural.
    w.check("versioning is off", "off",
            direct.get_bucket_versioning(Bucket=bucket).get("Status", "off"))
    w.check("object lock is not enabled", "501 NotImplemented",
            outcome(direct.get_object_lock_configuration, Bucket=bucket))

    # Retention is the one the API also has to know about: a job row is
    # permanent and its objects are not, so RETENTION_DAYS in api.env must
    # match the rule or the job detail view offers links to objects the store
    # has already removed.
    try:
        rules = direct.get_bucket_lifecycle_configuration(Bucket=bucket)["Rules"]
    except ClientError as exc:
        w.check("retention rule is installed", "one Enabled rule",
                outcome(lambda: (_ for _ in ()).throw(exc)))
        return
    w.check("retention: one rule, Enabled, over the whole bucket",
            (1, "Enabled", ""),
            (len(rules), rules[0]["Status"], rules[0].get("Filter", {}).get("Prefix", "")))
    w.check(f"retention: expires after {retention_days} days", retention_days,
            rules[0].get("Expiration", {}).get("Days"))


def anonymous(w: Walk, base: str, bucket: str, key: str, ca: str | None) -> None:
    w.section("anonymous access")
    # `mc anonymous set none` has no Garage equivalent and needs none: public
    # buckets are not implemented. Assert it rather than inherit it, which is
    # provision.sh's own reason for setting it.
    #
    # This is deliberately NOT a front refusal: a GET of a real object key is
    # allowed through, and the store is what says no. Reading the body is how
    # the two layers are told apart when debugging.
    r = httpx.get(f"{base}/{bucket}/{key}", verify=httpx_verify(ca))
    code = r.text.split("<Code>")[1].split("</Code>")[0] if "<Code>" in r.text else "-"
    w.check("an unsigned GET of a real key is refused", "403 AccessDenied",
            f"{r.status_code} {code}")
    w.check("  ...by the STORE, not by the front", True,
            "does not support anonymous access" in r.text)


def cors(w: Walk, base: str, bucket: str, origin: str, get_url: str,
         ca: str | None) -> None:
    w.section("CORS", "asserted behaviourally: GetBucketCors needs `owner`, "
                      "and behaviour is the better evidence anyway")

    def preflight(from_origin: str):
        return httpx.options(f"{base}/{bucket}", verify=httpx_verify(ca), headers={
            "Origin": from_origin, "Access-Control-Request-Method": "POST"})

    good = preflight(origin)
    w.check("the configured origin's preflight is answered", (200, origin),
            (good.status_code, good.headers.get("access-control-allow-origin")))

    # A 403 preflight is the refusal. Garage's own error page carries
    # `Allow-Origin: *`, which is inert -- the browser abandons the request on
    # the status alone -- so the status is what this asserts.
    w.check("any other origin's preflight is refused", 403,
            preflight(FOREIGN_ORIGIN).status_code)

    # The control that matters: a page at attacker.example holding a LEAKED
    # presigned URL must not be able to read the response. MinIO's default
    # reflected any origin WITH Allow-Credentials: true, which is the posture
    # this replaces.
    real = httpx.get(get_url, verify=httpx_verify(ca), headers={"Origin": FOREIGN_ORIGIN})
    w.check("a real response is not readable cross-origin", (200, None, None),
            (real.status_code,
             real.headers.get("access-control-allow-origin"),
             real.headers.get("access-control-allow-credentials")))


def region(w: Walk, endpoint: str, bucket: str, key: str, access: str,
           secret: str, ca: str | None) -> None:
    w.section("region", "the SigV4 scope, and api.env's S3_REGION must match it")
    # A wrong region is refused with 400 AuthorizationHeaderMalformed, which
    # is MinIO's status and code too.
    #
    # **Only the presigned form is a stable check.** Given a response body,
    # botocore reads Garage's <Region> hint and silently re-signs, so an
    # ordinary call succeeds and proves nothing; a presigned URL has nobody to
    # retry it. That is also the real-world failure mode -- a region mismatch
    # breaks every presigned URL the platform issues.
    wrong = client(endpoint, access, secret, "us-east-1", ca)
    url = wrong.generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=120)
    r = httpx.get(url, verify=httpx_verify(ca))
    w.check("a wrong-region presigned URL is refused", (400, True),
            (r.status_code, "AuthorizationHeaderMalformed" in r.text))


def grants(w: Walk, front, bucket: str, key: str, ca: str | None) -> bool:
    """What api-policy.json GRANTED: GetObject and PutObject, and no more."""
    w.section("what the API key may do through the front "
              "(api-policy.json's grants)")

    # PutObject arrives as a presigned POST, never a PUT: a presigned PUT
    # cannot constrain the upload's size, where a POST policy's
    # content-length-range is enforced by the server as the stream arrives.
    # This is also what creates the probe everything below reads.
    post = front.generate_presigned_post(
        Bucket=bucket, Key=key,
        Conditions=[["content-length-range", 0, 2048], {"key": key}],
        ExpiresIn=300)
    body = b"B" * 1024
    up = httpx.post(post["url"], data=post["fields"],
                    files={"file": ("probe.bin", body)}, verify=httpx_verify(ca))
    if not w.check("PutObject, via a presigned POST", 204, up.status_code):
        print("        the probe could not be written, so the reads below "
              "would all fail for the same reason. Stopping.")
        print(f"        body: {up.text[:300]}")
        return False

    # The size cap is the store's control, not the API's, and it is the one
    # the whole POST-rather-than-PUT decision exists for.
    over = httpx.post(post["url"], data=post["fields"],
                      files={"file": ("probe.bin", b"C" * 4096)}, verify=httpx_verify(ca))
    w.check("  ...and content-length-range is enforced", 400, over.status_code)

    w.check("GetObject", "allowed", outcome(front.get_object, Bucket=bucket, Key=key))
    w.check("HeadObject", "allowed", outcome(front.head_object, Bucket=bucket, Key=key))

    # The per-process log viewer reads slices out of logs that can exceed a
    # gigabyte, so ranges are load-bearing rather than incidental.
    rng = front.get_object(Bucket=bucket, Key=key, Range="bytes=0-9")
    w.check("a range GET", (10, f"bytes 0-9/{len(body)}"),
            (rng["ContentLength"], rng["ContentRange"]))
    # `objects.range_bytes` catches exactly this code and returns b"".
    w.check("a range past the end", "416 InvalidRange",
            outcome(front.get_object, Bucket=bucket, Key=key,
                    Range="bytes=99999-100000"))
    return True


def withheld(w: Walk, front, bucket: str, key: str, base: str,
             ca: str | None) -> None:
    """What api-policy.json WITHHELD. The front's job now."""
    w.section("what api-policy.json withheld -- refused by the front",
              "`403 403`: nginx answers with an HTML page, so there is no S3 "
              "error code. An S3-CODED 403 here means the store refused it "
              "and the front did not, which is a weaker posture -- so it is "
              "reported rather than accepted.")

    # Copy before the two deletes: against an endpoint with no filter the
    # deletes succeed and remove the probe, and a following CopyObject then
    # reports `404 NoSuchKey` instead of the `allowed` that actually names the
    # problem. Order costs nothing and keeps the broken case legible.
    w.check("CopyObject", "403 403",
            outcome(front.copy_object, Bucket=bucket, Key=key + ".copy",
                    CopySource={"Bucket": bucket, "Key": key}))
    w.check("ListObjectsV2", "403 403", outcome(front.list_objects_v2, Bucket=bucket))
    w.check("ListBuckets", "403 403", outcome(front.list_buckets))
    w.check("DeleteObject", "403 403",
            outcome(front.delete_object, Bucket=bucket, Key=key))
    w.check("DeleteObjects", "403 403",
            outcome(front.delete_objects, Bucket=bucket,
                    Delete={"Objects": [{"Key": key}]}))
    w.check("PutBucketCors", "403 403",
            outcome(front.put_bucket_cors, Bucket=bucket, CORSConfiguration={
                "CORSRules": [{"AllowedOrigins": ["*"], "AllowedMethods": ["GET"]}]}))

    # Three shapes the method filters alone would miss, and no credential is
    # needed to try them -- which is the point: these fail closed before any
    # signature is examined.
    def raw(method: str, path: str, headers=None):
        return httpx.request(method, f"{base}{path}", verify=httpx_verify(ca),
                             headers=headers or {}).status_code

    w.check("a PUT carrying x-amz-copy-source (CVE-2026-97731's shape)", 403,
            raw("PUT", f"/{bucket}/probe-copy",
                {"x-amz-copy-source": f"/{bucket}/{key}"}))
    w.check("POST ?delete (multi-object delete)", 403, raw("POST", f"/{bucket}?delete"))
    w.check("POST ?uploads (multipart init)", 403,
            raw("POST", f"/{bucket}/probe-mpu?uploads"))
    w.check("GET / (ListBuckets, unsigned)", 403, raw("GET", "/"))
    w.check("GET /minio/health/live (gone with MinIO)", 403,
            raw("GET", "/minio/health/live"))


def bypass(w: Walk, direct, bucket: str, key: str) -> None:
    """The residual risk, measured rather than asserted. Runbook 18 FINDING D-2."""
    w.section("the same key straight at Garage -- what the front is holding back")

    if direct is None:
        w.skip("the loopback bypass", "needs --direct, which only the DomU has")
        return

    w.check("ListObjectsV2 direct", "allowed",
            outcome(direct.list_objects_v2, Bucket=bucket, MaxKeys=1))
    w.check("CopyObject direct", "allowed",
            outcome(direct.copy_object, Bucket=bucket, Key=key + ".copy",
                    CopySource={"Bucket": bucket, "Key": key}))
    w.check("DeleteObject direct", "allowed",
            outcome(direct.delete_object, Bucket=bucket, Key=key + ".copy"))
    # The one thing `read`+`write` does not reach, and the only part of
    # api-policy.json's shape Garage can still express itself.
    w.check("PutBucketCors direct (needs owner)", "403 AccessDenied",
            outcome(direct.put_bucket_cors, Bucket=bucket, CORSConfiguration={
                "CORSRules": [{"AllowedOrigins": ["*"], "AllowedMethods": ["GET"]}]}))

    print("""
   These four are EXPECTED, and they are the residual risk of DECISION A2
   written down: api-policy.json withheld list, copy and delete from the
   CREDENTIAL, where the front withholds them from the PATH. Equivalent for
   anything arriving over TLS; not equivalent for code already running on the
   platform DomU, which can reach Garage's loopback listener and then list,
   copy and delete the whole bucket with the API's own key.

   On this store, a platform compromise is a bucket compromise. Under MinIO it
   was a bucket READ compromise at worst. That is why Garage binds loopback
   only and why provision.sh's owner key is ephemeral.""")


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--front", required=True,
                   help="the TLS front, e.g. https://192.168.1.10:9000 -- what "
                        "the platform talks to")
    p.add_argument("--direct", default=None,
                   help="Garage's own S3 listener, e.g. http://127.0.0.1:3900. "
                        "DomU only; unlocks the store-posture and bypass checks")
    p.add_argument("--origin", required=True,
                   help="the browser origin provision.sh configured")
    p.add_argument("--bucket", default=os.environ.get("S3_BUCKET", "analysis"))
    p.add_argument("--region", default=os.environ.get("S3_REGION", "eu-central-1"))
    p.add_argument("--retention-days", type=int,
                   default=int(os.environ.get("RETENTION_DAYS", "30")))
    p.add_argument("--ca", default=None,
                   help="CA bundle for the front's certificate "
                        "(default: /etc/sandbox-platform/tls/ca.crt if it exists)")
    p.add_argument("--keep-probe", action="store_true",
                   help="leave the probe object behind instead of deleting it")
    args = p.parse_args()

    access = os.environ.get("S3_ACCESS_KEY")
    secret = os.environ.get("S3_SECRET_KEY")
    if not access or not secret:
        p.error("S3_ACCESS_KEY and S3_SECRET_KEY must be in the environment, "
                "not on the command line -- see this module's docstring")

    ca = args.ca
    if ca is None and args.front.startswith("https"):
        default_ca = "/etc/sandbox-platform/tls/ca.crt"
        ca = default_ca if os.path.exists(default_ca) else None

    front = client(args.front, access, secret, args.region, ca)
    direct = (client(args.direct, access, secret, args.region, None)
              if args.direct else None)

    key = f"{PROBE_PREFIX}conformance-{uuid.uuid4()}.bin"
    w = Walk()
    print(f"front:  {args.front}\ndirect: {args.direct or '(not given)'}\n"
          f"bucket: {args.bucket}   region: {args.region}")

    try:
        if not grants(w, front, args.bucket, key, ca):
            return w.summary() or 1
        # Everything below reads the probe the grants section just wrote.
        store_posture(w, direct, args.bucket, args.retention_days)
        anonymous(w, args.front, args.bucket, key, ca)
        cors(w, args.front, args.bucket, args.origin,
             front.generate_presigned_url(
                 "get_object", Params={"Bucket": args.bucket, "Key": key},
                 ExpiresIn=120), ca)
        region(w, args.front, args.bucket, key, access, secret, ca)
        withheld(w, front, args.bucket, key, args.front, ca)
        bypass(w, direct, args.bucket, key)
    finally:
        # The front refuses DELETE -- that is one of the things being asserted
        # -- so the probe can only be removed through --direct. Saying so is
        # better than leaving the operator to wonder.
        if args.keep_probe:
            print(f"\nprobe left in place: {key}")
        elif direct is not None:
            direct.delete_object(Bucket=args.bucket, Key=key)
            print(f"\nprobe removed: {key}")
        else:
            print(f"\nprobe left in place, because deleting it through the front "
                  f"is refused by design:\n  {key}\n"
                  f"  The bucket's lifecycle rule collects it in "
                  f"{args.retention_days} days, or pass --direct on the DomU.")

    return w.summary()


if __name__ == "__main__":
    sys.exit(main())
