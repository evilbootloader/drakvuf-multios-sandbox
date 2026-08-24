# The object store

Issue [#37](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/37)
(DRAFT-044). Two files: the service-account policy, and the script that applies
it along with everything else the store needs.

`api-policy.json` is JSON and cannot carry comments, so its reasoning lives
here.

## Running it

On the platform LXC, once, with root credentials that go no further:

```sh
set -a; . /etc/minio/minio.env; set +a
BROWSER_ORIGIN=https://sandbox.evilbootloader.com \
BUCKET_QUOTA=200GiB \
RETENTION_DAYS=30 \
  /root/drakvuf-multios-sandbox/platform/minio/provision.sh
```

Idempotent — re-running is the recovery path after a partial failure, not a
hazard. It prints the service-account credentials **once**, on first run; they
are not recoverable afterwards and go into `/etc/sandbox-platform/api.env`.

`BROWSER_ORIGIN` and `BUCKET_QUOTA` have no defaults on purpose. Defaulting
either reproduces the exact failure this issue exists to fix: MinIO's own CORS
default is `*`, and a store with no quota fills silently at the end of an
analysis that has already been paid for.

## The policy

`s3:GetObject` and `s3:PutObject` on `arn:aws:s3:::analysis/*`. Nothing else.

**Why `PutObject`, when the API never uploads.** The API itself makes only
`head_object` and `get_object` calls, during admission. But it *signs*
presigned POSTs for the browser and the worker, and **a presigned URL carries
the signer's permissions** — so without `PutObject` here, every upload fails at
use time rather than at signing time, which is a confusing place to find out.

**What is deliberately absent, and what each absence buys:**

| Absent | Consequence if it were present |
|---|---|
| `s3:ListBucket` | A compromised API could enumerate a store holding live malware. Verified refused, 2026-08-24 |
| `s3:DeleteObject` | Nothing in the design deletes an artifact. Retention is done by MinIO's own lifecycle rule, so the capability buys nothing and would make a compromised API destructive |
| Bucket-level actions | The API never creates, configures or removes buckets. That is this script's job, with root credentials, once |

The absences are asserted by `../tests/test_objects.py` rather than read off
the file — a policy nobody exercises is a policy nobody knows the shape of.

Those three assertions need `mc`, because creating a service account carrying
this policy is MinIO **admin**-plane and the S3 API does not reach it. Without
it they skip, loudly:

```sh
MC_BIN=/path/to/mc MINIO_ROOT_USER=… MINIO_ROOT_PASSWORD=… \
  .venv/bin/python -m pytest -q tests/test_objects.py
```

A run that skips them is a run in which `no ListBucket` and `no DeleteObject`
are **unverified**. The skip message says so rather than passing quietly.

Two undocumented MinIO limits, both of which report only after the call fails:
an access key must be **3–20** characters and a secret **8–40**.

Both are used to the maximum, for different reasons. The secret is
`openssl rand -base64 30` — exactly 40 characters carrying 240 bits, where 40
characters of *hex* would carry only 160, since the limit is on characters and
hex packs 4 bits into each. That is also the length and alphabet of a real AWS
secret access key.

The access key is a fixed descriptive string at exactly 20, **not** random: it
is an identity rather than a secret, entropy buys nothing, and `provision.sh`
finds an existing account by that name to decide whether to create or update.
Randomising it would mint a new credential on every run. It has no room to be
renamed longer.

## Two traps worth knowing before you debug

**`mc admin config get <alias> region` reports empty for an env-provided
value.** It is not a probe. `MINIO_SITE_REGION` set in `minio.env` is in
effect but appears only as a commented line under `mc admin config get <alias>
site`, and the `region` subsystem reads empty because nothing was written to
the config store. This cost two separate investigations before it was pinned
down on 2026-08-24. The behavioural check is that a wrong-region signature is
refused with `400 AuthorizationHeaderMalformed`.

**CORS is set in the config store, not in `minio.env`.** Per-bucket CORS does
not exist on this build — both `mc cors set` and boto3's `put_bucket_cors`
return `NotImplemented` — so the only mechanism is the server-wide
`cors_allow_origin`. It applies immediately with no restart. An env-set
`MINIO_API_CORS_ALLOW_ORIGIN` would win silently over the config-store value
while being invisible to `mc admin config get`, which is the same trap as the
region. **Set it in one place, and let that place be this script.**

CORS is defence in depth rather than the primary control: since #37 the browser
reaches the store at `/analysis/*` on the API's own hostname, so the upload is
same-origin and needs no CORS at all. It still matters because MinIO's default
reflects any origin with `Allow-Credentials: true`, which would let a page at
`attacker.example` holding a *leaked presigned URL* read the response. It does
not stop `curl` with the same URL — nothing does, until the TTL expires.

## Retention

`RETENTION_DAYS` installs a lifecycle rule expiring every object after that
many days. **Lifecycle expiry, not object-lock retention** — the two are
opposites sharing a word, and object lock is asserted *off* because it would
make deletion undecidable later.

One rule over the whole bucket rather than a shorter period for `samples/` and
a longer one for `results/`. That split is tempting and does not work:
`results/<job_id>/extracted/` is malware too, S3 lifecycle prefixes are literal
rather than globs, so `results/*/extracted/` cannot be expressed, and a longer
results period would keep dropped executables longer than the sample they came
from.

It must match `RETENTION_DAYS` in `api.env`. The API does no deleting — it uses
the value to know when *not* to offer a download link, because a job row is
permanent and its objects are not.