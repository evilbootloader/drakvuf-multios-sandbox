# The object store

Garage, since the migration off MinIO — runbook 18. MinIO's community edition
was archived upstream on 2026-04-25 and
[CVE-2026-97731](https://app.opencve.io/cve/CVE-2026-97731) (CVSS 7.1,
CWE-347) is unfixed in it: MinIO does not verify that every `x-amz-*` header
on a request also appears in the client-supplied `SignedHeaders`, so a holder
of a presigned PUT can add an unsigned `x-amz-copy-source` and have the server
copy any object the *signing key* may read.

Three files, and the third is the one to read first if you are changing
anything:

| | |
|---|---|
| [`provision.sh`](provision.sh) | creates the bucket, the quota, the API's key, CORS and the retention rule. Idempotent |
| [`conformance.py`](conformance.py) | asserts the posture. 31 controls, and it fails if the front is missing |
| [`objects.conf`](objects.conf) | the nginx front: TLS, **and the capabilities Garage cannot withhold** |

This file holds the reasoning that none of those three can: why there is a
reverse proxy at all, what moved when the policy language went away, and what
that costs.

## Why nginx, and why it is not optional

**Garage has no TLS listener.** Not "we chose not to use it" — the feature
does not exist. `src/api/common/generic_server.rs` binds a plain
`TcpListener` and serves `http1::Builder`, with no rustls or native-tls
anywhere in the API path, and upstream's own reverse-proxy cookbook opens
with *"The main reason to add a reverse proxy in front of Garage is to provide
TLS to your users"*. There is no `--certs-dir` equivalent to the one MinIO
was given in runbook 08 §19a.

Everything on this lab's network reaches the store over TLS and cannot stop:
Dom0 fetches every sample from `S3_INTERNAL_ENDPOINT`, `cloudflared` verifies
the origin with `caPool`, and **SigV4 signs the Host header** — so the
address, the port and the certificate all have to stay exactly where MinIO
had them, or every presigned URL in flight is refused with a 403 that talks
about signatures and never about hosts.

So a TLS terminator was required either way. Given one was required, it is
also where the second job goes.

## What moved when the policy language went away

`../minio/api-policy.json` granted `s3:GetObject` and `s3:PutObject` on
`arn:aws:s3:::analysis/*` and **nothing else**, and
[`../minio/README.md`](../minio/README.md) is explicit about what each absence
bought: no `ListBucket`, so a compromised API could not enumerate a store of
live malware; no `DeleteObject`, so it could not be made destructive and
retention stayed the store's own job.

**Garage has no policy language.** Permissions are per key, per bucket, and
there are three — from `authorization_type()` in `src/api/s3/router.rs`:

| Permission | Includes |
|---|---|
| `read` | `GetObject`, `HeadObject`, **`ListObjects`**, `ListObjectsV2` |
| `write` | `PutObject`, **`DeleteObject`**, **`DeleteObjects`**, **`CopyObject`**, `UploadPartCopy` |
| `owner` | `DeleteBucket`, `PutBucketCors`, `GetBucketCors`, `PutBucketLifecycleConfiguration` |

A key that can read an object can list the bucket; a key that can write one
can delete and server-side-copy every one of them. **Both absences are
unexpressible as a credential here.**

### DECISION A2 — they move to the front

`objects.conf` refuses, before any signature is examined:

| Refused | Restores |
|---|---|
| `GET`/`HEAD` on the bucket root, and `?list-type=2` | no `ListBucket` |
| any `DELETE`, and `POST …?delete` | no `DeleteObject` |
| any `PUT` on an object path, and `POST …?uploads` | no `CopyObject`, `UploadPartCopy`, no multipart |
| any request carrying `x-amz-copy-source` | CVE-2026-97731's shape, independently of the server |
| everything outside `/analysis` | the admin API and `ListBuckets` stop existing from the LAN's point of view |

What the platform needs is exactly what is left: a presigned `POST` to the
bucket root, and `GET`/`HEAD` with ranges on object paths. `../sandbox_platform/objects.py`
makes no other call.

**Weaker than an IAM policy in one way, stronger in another.** Not enforced by
the store, so it binds the path rather than the credential — see below. But it
also binds any *future* credential, it is one file you can read in full, and
it is assertable with no credential at all, which `api-policy.json`'s absences
never were: `../tests/test_objects.py` could only check those with `mc` and
therefore skipped them more often than it ran them.

### FINDING D-2 — the residual risk, written down

Measured, not reasoned about. With the API's own key, straight at Garage's
loopback listener rather than through the front:

    ListObjectsV2 direct      allowed
    CopyObject direct         allowed
    DeleteObject direct       allowed
    PutBucketCors direct      403 AccessDenied   (needs owner)

So the front is equivalent to the old policy for anything arriving over TLS,
and **not** equivalent for code already running on the platform DomU. On this
store, a platform compromise is a bucket compromise; under MinIO it was a
bucket *read* compromise at worst, because the service account could neither
list nor delete.

That is why Garage binds loopback only, why `provision.sh`'s owner key is
ephemeral, and why this is written here rather than left to be discovered.
Closing it properly needs an S3 proxy that verifies SigV4 itself, or Garage
growing a policy language.

## Running them

`provision.sh`, on the platform DomU as root — the `garage` CLI reaches the
running server over RPC with the `rpc_secret` from `/etc/garage.toml`:

```sh
BROWSER_ORIGIN=https://sandbox.evilbootloader.com \
BUCKET_QUOTA=200GiB \
RETENTION_DAYS=30 \
  /opt/platform/src/platform/garage/provision.sh
```

`BROWSER_ORIGIN` and `BUCKET_QUOTA` have no defaults on purpose, and `*` is
refused outright: defaulting either reproduces the exact failure issue #37
exists to fix. Seven preconditions are checked before anything is created,
because a run that stops after the bucket and before the lifecycle rule leaves
a store that looks provisioned and has no retention.

Then `conformance.py`, which takes the API's key and **no owner credential**:

```sh
S3_ACCESS_KEY=GK… S3_SECRET_KEY=… \
  /opt/platform/src/platform/.venv/bin/python \
    /opt/platform/src/platform/garage/conformance.py \
      --front  https://192.168.1.10:9000 \
      --direct http://127.0.0.1:3900 \
      --origin https://sandbox.evilbootloader.com
```

Credentials come from the environment, never argv: this repository reads
`/proc/<pid>/cmdline` to find processes, so a secret on a command line is a
secret in every process listing on the host. `--direct` is Garage's loopback
listener and so is DomU-only; without it the three bucket-level read-backs and
the bypass measurement **skip loudly** rather than passing. A skipped control
is an unverified control.

Run it after any change to `objects.conf`. Pointed at a store with no front in
front of it, six checks go red and the exit status is 1 — which is how we know
they are checking something.

`objects.conf` is installed by copying it to `/etc/nginx/conf.d/objects.conf`.
Three lines are host-specific and are marked in the file: the `listen`
address, the two `ssl_certificate*` paths, and the `upstream` port. Because
the deployed copy can drift from this one:

```sh
diff /etc/nginx/conf.d/objects.conf \
     /opt/platform/src/platform/garage/objects.conf
```

## Traps worth knowing before you debug

All measured against Garage v2.4.1 on 2026-10-03.

**`garage key create` does not converge — it mints a second key with the same
name.** Run it twice and there are two live keys called `objects-api` and
nothing says which one `api.env` holds. `provision.sh` counts by name and
refuses at two or more rather than guessing. Related: `bucket info` and
`key info` both exit 1 for *absent* **and** for *"2 matching keys"*, so
neither is usable as an existence test.

**`nginx -t` binds.** It is not a syntax-only check: with MinIO still holding
`192.168.1.10:9000` it fails with `Address already in use`, which says nothing
about the configuration. Read the line above it — `syntax is ok` means the
file parsed, and a bind error is the only error you should accept there.

**A `403` from the front carries no S3 error code.** nginx answers with an
HTML page, so botocore reports the status twice (`403 403`). An S3-*coded*
`403` for one of the withheld capabilities means the store refused it and the
front did not, which is a weaker posture — so `conformance.py` reports it
rather than accepting it.

**An expired or malformed presigned URL is a `400` here, not MinIO's `403`.**
`InvalidRequest`, with `Date is too old` for an expired one. The capability
still expires; only the shape differs, and `sandboxd` treats every 4xx as a
permanent refusal either way. Likewise an over-range upload is
`400 InvalidRequest, "File size does not match policy"` where MinIO said
`EntityTooLarge`, and object lock answers `501 NotImplemented` to anybody.

**The region *is* enforced, and boto3 hides it from you.** A wrong-region
signature is refused with `400 AuthorizationHeaderMalformed` — MinIO's own
status and code. But given a response body, botocore reads Garage's `<Region>`
hint and silently re-signs, so an ordinary call succeeds and proves nothing. A
HEAD (no body) or a presigned URL (nobody to retry it) is what shows the
refusal, and the presigned case is the one that matters: a mismatch between
`s3_region` in `/etc/garage.toml` and `S3_REGION` in `api.env` breaks every
URL the platform issues. `provision.sh` compares them up front.

**Garage ignores unknown configuration keys.** A misspelled setting in
`/etc/garage.toml` is accepted in silence and simply does not apply. There is
no `nginx -t` for it.

**Anonymous access is structural, not configured.** `mc anonymous set none`
has no equivalent and needs none: public buckets are not implemented, and an
unsigned request gets `403 AccessDenied, "Garage does not support anonymous
access yet"` — from the store, which is how you tell it apart from the front's
own 403 while debugging.

## CORS

Per bucket here, where MinIO had only a server-wide `cors_allow_origin` — so
the trap where an env-set value won silently over the config store, invisibly
to `mc admin config get`, is gone with it.

Still defence in depth rather than the primary control: since #37 the browser
reaches the store at `/analysis/*` on the API's own hostname, so the upload is
same-origin and needs no CORS at all. It matters because a store that
reflected any origin would let a page at `attacker.example` holding a *leaked
presigned URL* read the response. Garage is stricter than MinIO's default
here: a preflight from any other origin is refused outright with `403`, and a
real response carries no `Allow-Origin` at all — where MinIO's default
reflected the origin *with* `Allow-Credentials: true`. Neither stops `curl`
with the same URL; nothing does, until the TTL expires.

**The development store needs a different rule, and that is not an
oversight.** `../tests/test_ui_browser.py` has two upload tests that are
cross-origin in a container, and they passed under MinIO only because MinIO's
own default was `*`. Against a deployment-shaped rule they fail with *"It is
on a different origin to this page, so the browser blocked the upload"*. The
dev store wants `AllowedOrigins: ["*"]`, applied by `scripts/dev-services.sh`;
`provision.sh` refuses `*` so a deployment cannot acquire it by accident.

## Retention

`RETENTION_DAYS` installs a lifecycle rule expiring every object after that
many days. **Lifecycle expiry, not object-lock retention** — the two are
opposites sharing a word, and `conformance.py` asserts object lock *absent*
because it would make deletion undecidable later.

Garage runs the expiry itself, daily at midnight
(`src/model/s3/lifecycle_worker.rs`), comparing the age of each version's own
timestamp. The API therefore needs no destructive capability for it, which is
what keeps `DeleteObject` out of what the front allows.

One rule over the whole bucket rather than a shorter period for `samples/` and
a longer one for `results/`. That split is tempting and does not work:
`results/<job_id>/extracted/` is malware too, S3 lifecycle prefixes are
literal rather than globs, so `results/*/extracted/` cannot be expressed, and
a longer results period would keep dropped executables longer than the sample
they came from.

It must match `RETENTION_DAYS` in `api.env`. The API does no deleting — it
uses the value to know when *not* to offer a download link, because a job row
is permanent and its objects are not.

**Two consequences of expiry being keyed to the version's own timestamp**, and
both are capacity-and-GDPR facts rather than bugs: objects copied in during a
migration get their clock reset, so they live up to `RETENTION_DAYS` longer
than their original schedule; and the front's access log records object keys,
which are built from submitted filenames, so it outlives the objects it
describes by however long logrotate keeps it. `objects.conf` logs the path
without its query string for a related reason — a presigned URL carries
`X-Amz-Signature`, and that must not be written to a file that outlives the
URL's TTL.
