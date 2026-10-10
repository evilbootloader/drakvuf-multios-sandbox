# Runbook — replace MinIO with Garage as the analysis object store

> **Status: written 2026-10-02, NOT YET EXECUTED ON THE DEPLOYMENT.** Every
> `EVIDENCE` block for Parts B–I is empty until an operator pastes real output
> into it, and **every command in them is Candidate** against this host.
>
> **But the whole procedure was rehearsed end to end in the development
> container on 2026-10-02/03**, against Garage v2.4.1 and a real MinIO, and
> **Part K carries that output.** Four things in the first draft were wrong and
> are corrected in place rather than annotated: Part F's verification recipe,
> Part D's missing assertion half, and two redaction hazards. The rehearsal
> cannot speak for Dom0, the tunnel, the LAN certificate or the real data — see
> the closing table for exactly which rows it did and did not settle.
>
> **Parked at the repository root**, and it belongs at
> `docs/runbooks/18-migrate-object-store-to-garage.md`.
> `scripts/gen-current-state.py` counts `docs.rglob("*.md")` off the filesystem,
> so a new `.md` under `docs/` fails `sandboxd/tests/test_current_state.py`
> while it is still untracked. Move and rename at commit time, then regenerate.
>
> **Redact before pasting into an `EVIDENCE` block.** This procedure prints an
> RPC secret, an admin token and two S3 secret keys. `garage bucket info` and
> `garage key info` *without* `--show-secret` are safe; `/etc/garage.toml`,
> `rclone.conf`, `--show-secret` — and **`garage key create`, which prints the
> secret in full on the line after the key id** — are not.
> `scripts/check-secrets.sh` does not yet know these shapes — see Part J.

## Why this exists

**MinIO community is archived upstream.** Reported timeline: the README was
changed to "THIS REPOSITORY IS NO LONGER MAINTAINED" on 2026-02-12 and the
repository was archived read-only on 2026-04-25, with development moved to the
commercial AIStor product. There is no upstream that will ship a security fix
for the build this lab runs.

**And one is already outstanding.**
[CVE-2026-97731](https://app.opencve.io/cve/CVE-2026-97731), CVSS 7.1, CWE-347
(improper verification of a cryptographic signature): MinIO does not verify that
every `x-amz-*` header present on a request also appears in the client-supplied
`X-Amz-SignedHeaders` list. A holder of a presigned **PUT** can therefore add an
unsigned `x-amz-copy-source` and have the server copy any object the *signing
key* may read — which, here, is every object in `analysis/`, across every owner
prefix.

> ### FINDING W-1 — what this lab's exposure actually is, stated precisely
>
> **The deployed upload path does not hand out presigned PUTs.**
> `platform/sandbox_platform/objects.py` issues presigned **POST** for both the
> browser (`presigned_upload`) and the worker (`presigned_artifact_upload`) —
> DRAFT-044's original presigned PUT for artifacts was reversed — and presigned
> **GET** for reads. A POST carries a policy document rather than a
> `SignedHeaders` list, and a GET cannot copy. So the published capability is
> not directly the one the CVE turns.
>
> That is a reason not to panic, **not** a reason to stay:
>
> - the service account signs with `s3:PutObject` on `arn:aws:s3:::analysis/*`,
>   so any future change back to a presigned PUT — or any other code path that
>   signs a PUT — converts a single-object write capability into a read of the
>   whole bucket, silently;
> - the store holds live malware and every tenant's samples under one bucket,
>   so bucket-wide read is the exact boundary `owner_prefix` exists to draw;
> - nothing will be fixed upstream, and this is the first CVE of this class
>   against the archived tree, not the last.
>
> **Garage closes this class at the server.** `verify_signed_headers` in
> `src/api/common/signature/payload.rs` rejects any request carrying an
> `x-amz-*` header that is absent from `SignedHeaders`
> (`Header '{}' should be signed`), and separately requires `Host` to be
> signed. Part E refuses `x-amz-copy-source` at the TLS front as well, so the
> shape is dead twice over and stays dead if the store is ever swapped again.

Garage is a reasonable target beyond being maintained: single static binary, no
cluster required, S3 path-style addressing, SigV4, and — verified below — the
three behaviours this platform actually depends on.

---

# Part A — the decisions, made

## A1. What Garage does and does not do, against what this platform uses

Verified 2026-10-02 against Garage **v2.4.1** (released 2026-09-08) —
documentation and source on the `main-v2` branch. Nothing in this table was
tested on the deployment; the ✅ rows were then **exercised against a running
Garage v2.4.1 in the development container** (Part K), and Parts F–H are what
turn them into evidence *here*.

| What the platform depends on | Garage | Source |
|---|---|---|
| **Presigned POST with a signed policy** | ✅ implemented | `s3-compatibility`: *PostObject — Implemented* |
| **`content-length-range` enforced server-side** | ✅ `StreamLimiter` fails the stream with `File size does not match policy` | `src/api/s3/post_object.rs` |
| **`key` condition, `Equal` and `StartsWith`** | ✅ `Key '{}' has value not allowed in policy` | same |
| **Policy expiry, and the policy signature** | ✅ `Expiration date is in the past`; `verify_v4(…, policy.as_bytes())` | same |
| **ETag = hex MD5 for a single-part write** | ✅ `encryption.etag_from_md5(&checksums.md5)` | `src/api/s3/put.rs` |
| **416 + code `InvalidRange` for a range past EOF** | ✅ `InvalidRange` → `RANGE_NOT_SATISFIABLE` | `src/api/s3/error.rs` |
| **Range GET, `HEAD`, `GET`, path-style, SigV4** | ✅ | `s3-compatibility` |
| **Per-bucket CORS** | ✅ `PutBucketCors`/`GetBucketCors` — *better than today*, see A3 | `s3-compatibility` |
| **Lifecycle expiry after N days** | ✅ `Expiration` and `AbortIncompleteMultipartUpload` only — which is all `provision.sh` installs. A worker runs **daily at midnight** and expires by days since the version's timestamp | `src/model/s3/lifecycle_worker.rs` |
| **Bucket quota** | ✅ but **not via S3** — `garage bucket set-quotas --max-size/--max-objects` | Garage CLI |
| **Versioning off** | ✅ not implemented at all, so the assertion becomes vacuous rather than checked | `s3-compatibility` |
| **Object lock off** | ✅ not implemented | same |
| **A policy granting `GetObject`+`PutObject` and nothing else** | ❌ **cannot be expressed.** See A2 | `src/api/s3/router.rs` |
| **TLS on `192.168.1.10:9000`** | ❌ **no TLS listener exists.** `generic_server.rs` binds a plain `TcpListener` and serves `http1::Builder`, with no rustls or native-tls in the API path; upstream's reverse-proxy cookbook opens with *"The main reason to add a reverse proxy in front of Garage is to provide TLS to your users"*. There is no `--certs-dir` equivalent. See A3 | `src/api/common/generic_server.rs`, cookbook |
| **`/minio/health/live`** | ❌ → admin API `GET /health`, unauthenticated, on the `[admin]` port | `admin-api` reference |
| **`mc admin …` (service accounts, quota, ilm, config)** | ❌ no MinIO admin plane. The `garage` CLI replaces it, over RPC | — |

## A2. The one real regression, and how it is answered

`platform/minio/api-policy.json` grants `s3:GetObject` and `s3:PutObject` on
`arn:aws:s3:::analysis/*` and **nothing else**. `platform/minio/README.md` is
explicit about what each absence buys: no `ListBucket`, so a compromised API
cannot enumerate a store of live malware; no `DeleteObject`, so it cannot be
made destructive and retention stays MinIO's own job.

**Garage has no policy language.** Permissions are per key, per bucket, and
there are three: `read`, `write`, `owner`. From `authorization_type()` in
`src/api/s3/router.rs`:

| Permission | Includes |
|---|---|
| `read` | `GetObject`, `HeadObject`, **`ListObjects`**, `ListObjectsV2` |
| `write` | `PutObject`, **`DeleteObject`**, **`DeleteObjects`**, **`CopyObject`**, `UploadPartCopy` |
| `owner` | `DeleteBucket`, `PutBucketCors`, `GetBucketCors`, `PutBucketLifecycleConfiguration` |

So a key that can read an object can list the bucket, and a key that can write
one can delete any of them and server-side-copy any of them. **Both absences
that `api-policy.json` exists to guarantee are lost at the credential layer.**

> ### DECISION A2 — the absences move to the TLS front, which is needed anyway
>
> Garage serves plain HTTP, so *something* must terminate TLS on
> `192.168.1.10:9000` (A3). That something sees every request, before any
> credential is examined, and it is the natural place to put a capability
> filter that the store's own model cannot express. Part E's nginx config
> therefore:
>
> | Refused at the front | Restores |
> |---|---|
> | `GET`/`HEAD` on the bucket root (`/analysis`, `/analysis/`, `?list-type=2`) | no `ListBucket` |
> | any `DELETE`, and `POST …?delete` (multi-object delete) | no `DeleteObject` |
> | any `PUT` on an object path | no `CopyObject`/`UploadPartCopy` |
> | any request carrying `x-amz-copy-source` | CVE-2026-97731's shape, server-independently |
> | anything outside `/analysis` | the admin plane and `ListBuckets` stop existing from the LAN's point of view |
>
> **This is weaker than an IAM policy in one way and stronger in another.** It
> is not enforced by the store, so a request that reaches `127.0.0.1:3900`
> directly is unfiltered — which is precisely why Garage binds loopback only
> and why the provisioning key (Part D) is deleted when the migration is done.
> It is stronger in that it also binds the *provisioning* credential and any
> future one, and that it is one file an operator can read in full.
>
> It is also testable **without a credential**: the Part G checks are plain
> `curl`, and they fail closed. `api-policy.json`'s absences needed `mc` and
> root credentials to assert, which is why `platform/tests/test_objects.py`
> skips them more often than it runs them.

## A3. Keep the external contract byte-for-byte

Everything that talks to the store names `https://192.168.1.10:9000` or
`https://sandbox.evilbootloader.com/analysis/…`:

- `S3_INTERNAL_ENDPOINT=https://192.168.1.10:9000` and
  `S3_PUBLIC_ENDPOINT=https://sandbox.evilbootloader.com` in
  `/etc/sandbox-platform/api.env`;
- the `cloudflared` ingress rule `path: ^/analysis(/|$)` →
  `https://192.168.1.10:9000`, which is rule **#0** and must stay ahead of the
  API catch-all;
- Dom0, which fetches every sample from `S3_INTERNAL_ENDPOINT` and verifies our
  CA (`sandboxd/api.py`);
- every presigned URL already in flight, because **SigV4 signs the Host
  header** — change the host or the port and every signature is refused with a
  403 that talks about signatures and never about hosts.

> **DECISION A3.** nginx terminates TLS on `192.168.1.10:9000` with the
> certificate MinIO is already serving. **Not a preference: Garage cannot do
> it.** There is no `--certs-dir` equivalent to the one runbook 08 §19a gave
> MinIO — the API listener is a plain `TcpListener` with no TLS library in its
> path, and upstream documents a reverse proxy as the way to get TLS at all, and proxies to Garage on
> `127.0.0.1:3900`. **`api.env`, `cloudflared/config.yml`, the certificates, the
> CA, `sandboxd.env` and `misc/platform.cfg` are all unchanged** — the only
> edit anywhere is `S3_ACCESS_KEY`/`S3_SECRET_KEY`, because the credential is
> new. Keeping the port also keeps the rollback to one `systemctl` swap.
>
> The alternative — pointing `api.env` and `cloudflared` at a new plain-HTTP
> endpoint — was rejected twice over: it puts sample bytes and presigned URLs
> on the LAN in clear, and it changes the signed host, so every in-flight
> upload ticket breaks at the cutover instant.

Also unchanged by decision: bucket **`analysis`** (the name is load-bearing —
`cloudflared` routes `^/analysis(/|$)` and path-style addressing puts the bucket
first in the URL), region **`eu-central-1`** (part of the SigV4 scope, and
DRAFT-022's GDPR position rests on it), quota **200 GiB**, retention **30 days**.

## A4. Storage, and why the mount point keeps a wrong name

`vg-root/platform_data` is attached as `xvdb` and mounted at `/srv/minio`
(`misc/platform.cfg`), 256 G, inside the `vg-root/thinpool` that the golden
images and every clone snapshot also share.

> **DECISION A4.** Garage's metadata and data go to
> **`/srv/minio/garage/{meta,data}`**, and the mount point keeps its name
> through the migration.
>
> Renaming it means editing the guest's `fstab` and the `misc/platform.cfg`
> comment, and — the part that actually decides it — **both stores must be
> readable at the same time during Part F**, which a single LV mounted at a
> single path cannot do if the path is being changed underneath it. The rename
> is offered as optional Part I-b, after MinIO's data is gone and nothing
> depends on the old path.
>
> **If the two stores do not fit together**, Part B's `df` says so before
> anything is installed, and Part B-alt creates a second thin LV instead. That
> step runs on **Dom0**, not here.

Garage wants its metadata on fast storage. There is only one pool on this host,
so this is a note rather than a choice: `db_engine = "lmdb"`, and the thin pool
is the same shared failure domain it already was — watch `data_percent`.

## A5. Keep MinIO installed, stopped, until Part H passes

MinIO is `disable --now`, not purged, and `/srv/minio/data` is untouched until
Part I. Rollback is then: stop nginx, start MinIO, restore two lines of
`api.env`, restart the API. **Objects written to Garage after the cutover are
lost on rollback** — which is why Part B drains the queue and Part H is run
immediately rather than "next week".

---

# Part B — preflight, on the platform DomU

Nothing here changes state. All of it belongs in `EVIDENCE B`, because Part H
has nothing to compare against otherwise.

```bash
# on the platform DomU, as root
cat /etc/os-release | head -2
/usr/local/bin/minio --version
systemctl is-active minio sandbox-api-browser sandbox-api cloudflared
ss -lntp | grep -E ':(9000|9001|8000|3900|3901|3903)\b'
df -h /srv/minio /
grep -E '^S3_(INTERNAL|PUBLIC)_ENDPOINT|^S3_BUCKET|^S3_REGION|^S3_CA_BUNDLE|^RETENTION_DAYS' \
    /etc/sandbox-platform/api.env            # NOT the key lines
grep -c . /etc/sandbox-platform/api.env
cloudflared --config /etc/cloudflared/config.yml tunnel ingress rule \
    https://sandbox.evilbootloader.com/analysis/probe      # expect -> 192.168.1.10:9000
```

The store's own state, with root credentials, while the admin plane still
exists:

```bash
set -a; . /etc/minio/minio.env; set +a
mc alias set pre https://127.0.0.1:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"
mc ls --recursive --summarize pre/analysis | tail -3      # object count and total size
mc quota info pre/analysis
mc ilm rule ls pre/analysis
mc admin config get pre api | tr ' ' '\n' | sed -n 's/^cors_allow_origin=//p'
mc admin config get pre site | sed -n 's/^# *//p' | grep REGION
mc admin user svcacct info pre sandbox-platform-api
```

**`du`, not only `mc ls`**, because A4's decision depends on the two stores
fitting side by side and the quota is 200 GiB against a 256 G volume:

```bash
du -sh /srv/minio/data
```

> **The space test, stated as a number.** Part F copies every object, so
> `avail(/srv/minio)` must exceed `du(/srv/minio/data)` with room to run. If it
> does not, stop and do Part B-alt.

Drain the queue. The cutover is brief, but a job that is admitted against one
store and claimed against the other is the one failure mode here that is
*silent* rather than loud:

```bash
su - platform -s /bin/bash -c "psql -d sandbox_platform -c \
  \"SELECT state, count(*) FROM jobs WHERE state IN ('received','admitted',\
'queued','cloning','preparing','executing','collecting','cleaning') \
GROUP BY state ORDER BY state\""
```

**Expect zero rows.** Wait for in-flight work rather than cutting across it,
and tell whoever submits that uploads are closed for the window.

> ### FINDING B-1 — why `sample_etag` makes the queue state matter
>
> `jobs.sample_etag` is recorded at admission and re-checked when a worker
> claims the job (`objects.sample_status`): `missing`, `changed` or `ok`, and a
> mismatch means *Dom0 is about to detonate bytes the record does not
> describe*. Part F preserves ETag equality on purpose (DECISION F1), but
> "preserves it if nothing goes wrong" is not the standard to hold a safety
> check to. An empty queue means no row's `sample_etag` is load-bearing while
> the store is being swapped.

```
EVIDENCE B                                                      <date>

(paste: versions, listeners, df, du, api.env non-secret lines, ingress rule,
 mc summarize / quota / ilm / cors / region / svcacct, the queue query)
```

## Part B-alt — only if the two stores do not fit

`lvcreate` cannot run in the development container or in the DomU — it is
**Dom0**. Present these to the operator and wait for output:

```bash
# DOM0 — only if Part B's df/du say the stores will not fit together
lvs vg-root/thinpool -o lv_name,lv_size,data_percent
lvcreate --thin -V 256G -n garage_data vg-root/thinpool
xl block-attach platform phy:/dev/vg-root/garage_data xvdc w
```

Then in the guest: `mkfs.ext4 -L platform-objects /dev/xvdc`, an `fstab` line
mounting it at `/srv/garage`, and `metadata_dir`/`data_dir`/`ReadWritePaths` in
Part C pointed there instead. The `disk = [...]` list in `misc/platform.cfg`
must gain the same device or the attach is lost at the next `xl create` —
those lines are hand-maintained, not generated (`scripts/gen-xen-configs.py`
rewrites only `cpus =`).

---

# Part C — install Garage

```bash
# on the platform DomU, as root
V=v2.4.1
curl -fsSLo /usr/local/bin/garage.new \
  "https://garagehq.deuxfleurs.fr/_releases/$V/x86_64-unknown-linux-musl/garage"
sha256sum /usr/local/bin/garage.new
install -m 755 -o root -g root /usr/local/bin/garage.new /usr/local/bin/garage
rm /usr/local/bin/garage.new
garage --version
```

**Expect this digest**, measured from the same URL on 2026-10-02 (Part K):

    ae49f8de4aaee6b5ca305f7cbdccc8cd8a29b2804aac074649f18bfb83d0a2b6  garage

and `garage v2.4.1 [features: bundled-libs, consul-discovery, fjall, journald,
k2v, kubernetes-discovery, lmdb, metrics, sqlite, syslog, telemetry-otlp]`.
A different digest for `v2.4.1` means the bytes changed under a fixed version
number; stop and find out why before installing it.

> ### FINDING C-1 — upstream publishes no checksum beside the binary
>
> Probed 2026-10-02: `garage.sha256sum`, `garage.sha256`, `sha256sums` and
> `SHA256SUMS` at `_releases/v2.4.1/x86_64-unknown-linux-musl/` all return 404.
> The `garage` object itself returns 200, `content-length: 71272496`,
> `last-modified: Tue, 08 Sep 2026 08:55:24 GMT`.
>
> So integrity here rests on TLS to `garagehq.deuxfleurs.fr`. **Record the
> `sha256sum` you got in `EVIDENCE C`** — that is what makes a later
> re-download comparable, and what a second host can be checked against. If the
> Forgejo release page for `v2.4.1` carries a digest or a signature, prefer it
> and record which you used; that page is behind an anti-bot interstitial and
> could not be read from the development container.

A dedicated system user, and the directories. **Not systemd's `DynamicUser`**,
which upstream's sample unit uses: the data lives on a mounted volume whose
ownership must be stable across restarts.

```bash
adduser --system --group --no-create-home --home /nonexistent garage
install -d -o garage -g garage -m 750 /srv/minio/garage \
    /srv/minio/garage/meta /srv/minio/garage/data
df -h /srv/minio          # MUST be xvdb, not the rootfs
```

The configuration. **Loopback everywhere** — nginx is the only way in:

```bash
RPC_SECRET=$(openssl rand -hex 32)
ADMIN_TOKEN=$(openssl rand -base64 32)

cat > /etc/garage.toml <<EOF
# The analysis object store. Replaces MinIO, which is archived upstream and
# carries CVE-2026-97731 unfixed -- see runbook 18.
#
# Nothing here listens on the LAN. nginx terminates TLS on 192.168.1.10:9000
# and is also the capability filter: Garage's permission model cannot express
# "GetObject and PutObject only", so the absences api-policy.json guaranteed
# live in /etc/nginx/conf.d/objects.conf instead. Runbook 18 DECISION A2.
metadata_dir = "/srv/minio/garage/meta"
data_dir     = "/srv/minio/garage/data"
db_engine    = "lmdb"

# One node. The lab has one.
replication_factor = 1

rpc_bind_addr   = "127.0.0.1:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret      = "$RPC_SECRET"

compression_level = 1

[s3_api]
# MUST equal S3_REGION in /etc/sandbox-platform/api.env. The region is part of
# the SigV4 signing scope, so a mismatch fails every presigned URL with a 403
# that discusses signatures and never mentions regions.
s3_region     = "eu-central-1"
api_bind_addr = "127.0.0.1:3900"
# root_domain is deliberately UNSET. Every client here uses path-style
# addressing (objects.py pins addressing_style="path"), and with no root_domain
# a Host header can never be read as a bucket name.

[admin]
api_bind_addr = "127.0.0.1:3903"
admin_token   = "$ADMIN_TOKEN"
EOF
chown root:garage /etc/garage.toml && chmod 640 /etc/garage.toml
```

**0640, not 0644.** Garage refuses to start on a world-readable secret file
unless `allow_world_readable_secrets` is set; group-readable is what lets the
service read it while the `garage` CLI reads it as root.

```bash
cat > /etc/systemd/system/garage.service <<'EOF'
[Unit]
Description=Garage object store (analysis bucket)
After=network-online.target
Wants=network-online.target

[Service]
Environment=RUST_LOG=garage=info
ExecStart=/usr/local/bin/garage server
User=garage
Group=garage
Restart=always
RestartSec=5
LimitNOFILE=65536
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
# ProtectSystem=strict makes /srv read-only too; this is the one exception.
ReadWritePaths=/srv/minio/garage

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload && systemctl enable --now garage
systemctl is-active garage
ss -lntp | grep -E ':(3900|3901|3903)\b'    # all three on 127.0.0.1, none on the LAN
curl -s -o /dev/null -w 'admin /health: %{http_code}\n' http://127.0.0.1:3903/health
```

> **A `503` here is correct, and is the next step's precondition.** `/health`
> returns 200 only once enough nodes are up to serve requests, and a node with
> no layout is not one of them — measured in Part K: `503` before
> `layout apply`, `200` immediately after. So this is a real readiness probe
> rather than a liveness ping, which is what makes it the right replacement for
> `/minio/health/live`.

A fresh node has no layout, and refuses writes until it does:

```bash
G="garage -c /etc/garage.toml"
$G status                                    # the short node id, and no role
NODE=$($G node id -q | cut -d@ -f1)          # the full id, which assign wants
$G layout assign -z lab -c 200G "$NODE"
$G layout apply --version 1
$G layout show
$G status
curl -s -o /dev/null -w 'admin /health: %{http_code}\n' http://127.0.0.1:3903/health
```

`node id -q` rather than copying from `status`, because `status` prints the
**short** id and the full one is what identifies the node unambiguously.

**`-c 200G` is 200×10⁹ bytes, which `layout show` reports as `186.3 GiB`** —
Garage parses decimal units here. That is harmless for a single node, where
capacity is only ever compared between nodes, but write `200GiB` if you mean
the binary figure.

`-c /etc/garage.toml` is the default, and is written out because the CLI needs
the **`rpc_secret` from that file** to talk to the running server — in v2 the
CLI still speaks RPC, not the admin API, so it must be run as root.

`-z lab` is the zone name and `-c 200G` the node's advertised capacity. With
one node and `replication_factor = 1` neither is a placement decision; capacity
is only compared between nodes. v2.3 added `garage server --single-node`, which
configures the layout for you — the explicit form is used here so the layout
appears in the evidence.

```
EVIDENCE C                                                      <date>

(paste: garage --version, the sha256sum, df, ss, admin /health, layout show,
 garage status. NOT /etc/garage.toml.)
```

---

# Part D — provision the bucket, the keys, CORS and retention

**One command**, and it is `platform/garage/provision.sh` — the successor to
`platform/minio/provision.sh`, which it replaces step for step. The reasoning
for each control lives next to the control, in that file, for the same reason
the MinIO one existed: a policy expressed as a heredoc inside a document has no
copy a test can exercise and no way to be re-applied after a rebuild.

```bash
# on the platform DomU, as root -- the garage CLI needs the rpc_secret
BROWSER_ORIGIN=https://sandbox.evilbootloader.com \
BUCKET_QUOTA=200GiB \
RETENTION_DAYS=30 \
  /opt/platform/src/platform/garage/provision.sh
```

It creates the bucket, sets the quota, mints the API's key, grants it
`read`+`write`, and applies CORS and the lifecycle rule — then prints the two
lines that go into `api.env` and the `conformance.py` invocation for D2.

`BROWSER_ORIGIN` and `BUCKET_QUOTA` still have **no defaults**, and `*` is
still refused outright: defaulting either reproduces the exact failure issue
#37 exists to fix. Seven preconditions are checked before anything is created,
because a run that stops after the bucket and before the lifecycle rule leaves
a store that looks provisioned and has no retention. The one that is new here:
**`s3_region` in `/etc/garage.toml` must equal `S3_REGION`**, which the script
reads and compares rather than leaving to be discovered as a 400 about an
authorization header.

**Idempotent, and three measured behaviours are why that took work:**

| Measured | What the script does |
|---|---|
| `bucket create` exits 1 on an existing bucket | asks `bucket info` first |
| **`key create` mints a SECOND key with the same name** — demonstrated, two live `objects-api` keys and no way to tell which one `api.env` holds | counts by name: 0 creates, 1 reuses, **2 or more refuses** and says how to resolve it by hand |
| `bucket info`/`key info` exit 1 both for "absent" and for "2 matching keys" | never uses `key info` as an existence test |

**`--owner` is not granted to `objects-api`.** That is the one part of
`api-policy.json`'s shape Garage *can* still express: the API cannot change the
bucket's CORS rule, its lifecycle rule, or delete the bucket.

> **The owner key is ephemeral, and there is no second standing credential.**
> `PutBucketCors` and `PutBucketLifecycleConfiguration` need `owner`, so the
> script mints a key named `objects-provision-ephemeral`, uses it for exactly
> those two calls over loopback, and deletes it before printing the final
> state — with a trap as the safety net, and a leftover from an aborted run
> cleaned up on the next one. A standing owner key would be a live secret
> nobody recorded, which is the hazard MinIO's service-account step was
> written around.
>
> Nothing else needs it. Part F's copy uses the API's own key straight at
> Garage, where `read` already implies list and `write` implies put.
>
> Unlike MinIO's service account, **the API key's secret is recoverable** with
> `garage key info objects-api --show-secret` — so that command is secret
> material too, and `garage key create`'s own output prints a secret in full.

**The two bucket-level controls go through the S3 API**, because the `garage`
CLI has no command for either — so `provision.sh` carries a short `boto3` block
for them, and runs it **against `127.0.0.1:3900`, bypassing nginx**: the front
refuses `PUT` on purpose, and `PutBucketCors` and
`PutBucketLifecycleConfiguration` are PUTs. That is also why this script has to
run on the DomU itself rather than from a workstation.

**Read the `cors:` and `ilm:` lines it prints rather than trusting the absence
of a traceback.** The script reads both settings back deliberately: a rule that
was rejected and a rule that was never installed look identical from the
outside, and the difference is whether this store has a retention policy at
all. The `ilm:` line is also the only confirmation that Garage accepted an
empty `Filter.Prefix`.

## D2 — assert the controls, which is the other half of `provision.sh`

**The first draft of this runbook applied provision.sh's settings and omitted
its assertions, and that was a real hole.** Four of that script's steps change
nothing and exist only to *check* something: anonymous access is off,
versioning is off, object lock is off, and the region in effect is the one
`api.env` signs with. Its own comment says why — *"set it anyway so the posture
is declared rather than inherited"* — and three of them are exactly the
properties Garage implements differently.

A fifth group has no equivalent at all: the capabilities `api-policy.json`
**withholds**. Those are now the front's (DECISION A2), so they must be
asserted against the front with a real signed credential, which is something
`platform/tests/test_objects.py` could only ever do with `mc` and therefore
mostly skipped.

**That walk is `platform/garage/conformance.py`.** Run it after Part E, and
again whenever the front's config changes:

```bash
# on the platform DomU, after Part E -- the venv's python, which has boto3
S3_ACCESS_KEY=<objects-api key id> S3_SECRET_KEY=<its secret> \
  /opt/platform/src/platform/.venv/bin/python \
    /opt/platform/src/platform/garage/conformance.py \
      --front  https://192.168.1.10:9000 \
      --direct http://127.0.0.1:3900 \
      --origin https://sandbox.evilbootloader.com
```

**Credentials come from the environment, never argv** — this repository reads
`/proc/<pid>/cmdline` to find processes, so a secret on a command line is a
secret in every process listing on the host.

It needs **no owner key**: measured 2026-10-03, `read` is enough for the
versioning and retention read-backs, object lock answers `501` to anybody, and
only `GetBucketCors` wants `owner` — so CORS is asserted through real
preflights instead, which is better evidence than reading the configuration
back. `--direct` is Garage's loopback listener and is therefore DomU-only; it
unlocks the three bucket-level read-backs and the bypass demonstration, and
**without it those four skip loudly** rather than passing. Exit status is 0
only when nothing was unexpected.

It asserts, against a store provisioned by Parts C–E:

| Control | Garage's answer, measured 2026-10-03 |
|---|---|
| anonymous `GET` of a real key | `403 AccessDenied`, *"Garage does not support anonymous access yet"* — the refusal is **the store's**, so this is structural rather than configured. `mc anonymous set none` has no equivalent and needs none |
| versioning | off; not implemented at all |
| object lock | `501 NotImplemented` |
| retention | one rule, `sandbox-platform-retention`, `Enabled`, whole-bucket prefix, 30 days |
| CORS, the configured origin | preflight `200`, `Allow-Origin: <that origin>`, no `Allow-Credentials` |
| CORS, any other origin | **preflight `403`** — and a real response carries no `Allow-Origin` at all, so a foreign page cannot read it |
| a wrong-region signature | `400 AuthorizationHeaderMalformed` — MinIO's own status and code |
| `GetObject`, `HeadObject`, range `GET`, range past EOF, presigned `POST`, the POST size cap | all as the platform expects: `200`, `206 bytes 0-9/1024`, `416 InvalidRange`, `204`, and `400` for an over-range upload |
| `ListObjectsV2`, `ListBuckets`, `DeleteObject`, `DeleteObjects`, `CopyObject`, `PutBucketCors` **through the front** | `403` — the six capabilities `api-policy.json` withheld |
| the same six **straight at Garage** | list, copy and delete **allowed**; only `PutBucketCors` refused, because that one needs `owner` |

> ### FINDING D-2 — the last row is the residual risk, written down
>
> `api-policy.json` withheld those capabilities *from the credential*. The
> front withholds them *from the path*. Equivalent for anything that comes in
> over TLS on `192.168.1.10:9000`, and **not** equivalent for code already
> running inside the platform DomU, which can reach `127.0.0.1:3900` directly
> and then list, copy and delete the whole bucket with the API's own key.
>
> That is why Garage binds loopback only, why `provision.sh`'s owner key is
> ephemeral, and why it is worth saying plainly rather than discovering later: on
> this store, **a platform compromise is a bucket compromise.** Under MinIO it
> was a bucket *read* compromise at worst, by the same reasoning, since the
> service account could not list or delete. The gap is narrower than it looks
> and it is not zero.
>
> Closing it properly needs an S3 proxy that checks SigV4 itself, or Garage
> growing a policy language. Neither is in scope here; **DRAFT this** rather
> than leaving it in a runbook only.

> **The CORS rule the browser tests need is not this one.** In the deployment
> the upload is same-origin, so the single concrete origin above is right. In
> the development container the page and the store are on different origins —
> which is why `tests/test_ui_browser.py` has two upload tests that MinIO
> passed only because **MinIO's default `cors_allow_origin` is `*`**. Against
> Garage with the deployment's rule they fail with *"It is on a different
> origin to this page, so the browser blocked the upload"*, and pass again with
> `AllowedOrigins: ["*"]`. Measured both ways in Part K. **The dev store needs
> the permissive rule; the deployment must never have it** — Part J.

```
EVIDENCE D                                                      <date>

(paste: bucket create/set-quotas/allow output, bucket info, key info WITHOUT
 --show-secret, the cors: / ilm: lines, and the full conformance walk)
```

---

# Part E — the TLS front

Garage has no TLS listener; this terminates TLS on the port MinIO holds, and
carries DECISION A2's capability filter.

```bash
apt-get install -y nginx
nginx -v

# Debian's package ships a default site that binds 0.0.0.0:80. This domain
# serves nothing on 80 and must not start doing so.
rm -f /etc/nginx/sites-enabled/default
```

The certificate is **the one MinIO is already serving** — same SANs, signed by
the same CA, so Dom0's trust and `cloudflared`'s `caPool` are untouched. Check
before copying, because the whole of A3 rests on it:

```bash
openssl x509 -noout -ext subjectAltName -in /etc/minio/certs/public.crt
# expect IP Address:192.168.1.10 and IP Address:127.0.0.1, DNS:platform.lan
openssl x509 -noout -enddate -in /etc/minio/certs/public.crt

install -d -m 700 -o root -g root /etc/nginx/tls
install -m 600 -o root -g root /etc/minio/certs/public.crt  /etc/nginx/tls/objects.crt
install -m 600 -o root -g root /etc/minio/certs/private.key /etc/nginx/tls/objects.key
```

nginx's master process reads these as root before dropping to `www-data`, so
0600 root-owned is correct and the copy survives `minio-user` being deleted in
Part I.

```bash
install -m 644 -o root -g root \
    /opt/platform/src/platform/garage/objects.conf \
    /etc/nginx/conf.d/objects.conf

# Three lines are host-specific, and the file marks each one: the `listen`
# address, the two `ssl_certificate*` paths, and the `upstream` port. Confirm
# they match this host before testing anything.
grep -n -A2 'HOST-SPECIFIC' /etc/nginx/conf.d/objects.conf

nginx -t
```

> ### FINDING E-1 — `nginx -t` binds, so it fails here and that is not a fault
>
> The first draft of this part said `nginx -t` *"parses and validates WITHOUT
> binding, so this is safe now"*. **That is wrong**, found by running it:
> `nginx -t` attempts to bind every `listen` directive. With MinIO still
> holding the port, expect
>
>     nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
>     nginx: [emerg] bind() to 192.168.1.10:9000 failed (98: Address already in use)
>     nginx: configuration file /etc/nginx/nginx.conf test failed
>
> **Read the first line.** `syntax is ok` means the file parsed — including the
> `map`, `log_format` and `upstream` blocks, which only work because Debian
> includes `conf.d/` inside `http {}`. A bind error is the only error to accept
> here; anything else is real. `nginx -t` must come back fully clean after
> MinIO stops, in Part G step 3, before nginx is started.

**Do not start nginx yet.** MinIO still holds `192.168.1.10:9000`; nginx would
fail to bind and the only thing that changes is that the unit is in a failed
state. The cutover in Part G is where it starts.

```
EVIDENCE E                                                      <date>

(paste: nginx -v, the SAN and enddate output, nginx -t)
```

---

# Part F — copy the objects

Both endpoints are on loopback, and the Garage side bypasses nginx (which
refuses `PUT`, and multipart, by design).

> ### DECISION F1 — force single-part writes, or the ETag check breaks
>
> Garage's ETag for a single-part write is the hex MD5 of the content
> (`etag_from_md5`), exactly as MinIO's is. A **multipart** write's ETag is not:
> it is a digest of digests with a part-count suffix.
>
> `jobs.sample_etag` was recorded by MinIO and is re-checked by
> `objects.sample_status` when a worker claims the job (FINDING B-1). So a
> sample copied in parts gets a new ETag, and a job queued across the cutover
> would be refused as `changed` — the state that means *tampering*. Ugly in the
> best case and a wrong incident in the worst.
>
> `upload_cutoff` and `chunk_size` at `5G` force single-part for everything:
> `MAX_SAMPLE_BYTES` is 1 GiB and `MAX_ARTIFACT_BYTES` 2 GiB, both well under
> S3's 5 GiB single-PUT ceiling. Part B's empty queue is the other half of this
> belt.
>
> **Rehearsed on 3,300 real objects, and it holds for every sample — with one
> class of exception that this decision cannot fix and does not need to.**
> Three of those 3,300 were already stored *multipart in MinIO* (25, 50 and
> 72 MB), so their ETags carried the `-4`, `-6`, `-9` part-count suffix. A
> single-part copy necessarily rewrites those as a plain content MD5: the
> suffix form is a digest of the original part digests, and MinIO's part
> boundaries are not recoverable. The bytes were verified identical by SHA-256
> on both sides, and Garage's new ETag equals the true content MD5.
>
> **All three were `results/` artifacts, and none of the samples was
> multipart** — which is structural, not luck: a sample arrives by presigned
> POST, and a POST is always one part. Artifact ETags are recorded nowhere and
> compared by nothing; `jobs.sample_etag` is the only stored ETag in the
> schema. So the rule for the check below is: **a changed ETag is acceptable
> only where the MinIO side had a `-N` suffix and the sizes match.** Anything
> else is a bad copy.

`rclone` rather than `mc`: it is a maintained Debian package, and `mc` is the
client of the server being removed.

```bash
apt-get install -y rclone jq
install -d -m 700 /root/objstore-migration

install -d -m 700 /root/.config/rclone
cat > /root/.config/rclone/rclone.conf <<EOF
[minio]
type = s3
provider = Minio
endpoint = https://127.0.0.1:9000
region = eu-central-1
force_path_style = true
access_key_id = $MINIO_ROOT_USER
secret_access_key = $MINIO_ROOT_PASSWORD

[garage]
type = s3
provider = Other
endpoint = http://127.0.0.1:3900
region = eu-central-1
force_path_style = true
access_key_id = <objects-api key id>
secret_access_key = <its secret>
# DECISION F1: never multipart, so the ETag stays the content's MD5.
upload_cutoff = 5G
chunk_size = 5G
EOF
chmod 600 /root/.config/rclone/rclone.conf
```

`MINIO_ROOT_USER`/`MINIO_ROOT_PASSWORD` come from the `set -a; . /etc/minio/minio.env`
in Part B; if this is a fresh shell, source it again. The MinIO endpoint is
loopback and its certificate covers `127.0.0.1`, so `--ca-cert` is all that is
needed to verify it:

The manifest is taken with `boto3`, **not** `rclone lsjson --hash`:

> ### FINDING F-1 — `rclone lsjson --hash` reports no hash at all here
>
> The first draft verified the copy by diffing `rclone lsjson -R --hash`
> manifests. Measured in Part K against rclone **1.60.1** (Debian/Ubuntu's
> package): `Hashes.MD5` is `null` for **every object, on both remotes** —
> MinIO's and Garage's alike — while a direct `ListObjectsV2` returns correct
> MD5 ETags for the same objects.
>
> So that check compared `null` to `null` and would have passed against a
> store full of truncated objects. It is replaced, not annotated. Read the
> ETag from the store, which is also where `jobs.sample_etag` came from.

`manifest.py` — put it in `/root/objstore-migration/`:

```python
"""Key, size and ETag for one bucket, sorted. Run twice, diff the two."""
import sys
import boto3
from botocore.config import Config

endpoint, access, secret, bucket = sys.argv[1:5]
s3 = boto3.client(
    "s3", endpoint_url=endpoint, aws_access_key_id=access,
    aws_secret_access_key=secret, region_name="eu-central-1",
    config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
)
rows = []
for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
    for o in page.get("Contents", ()):
        rows.append(f'{o["ETag"].strip(chr(34))}  {o["Size"]:>12}  {o["Key"]}')
rows.sort()
print("\n".join(rows))
print(f"# {len(rows)} objects", file=sys.stderr)
```

It lists the bucket, so it runs **against `127.0.0.1:3900`, not the front** —
listing is exactly what the front refuses. The **API's own key** is enough:
straight at Garage, `read` implies ListObjects and `write` implies PutObject
(FINDING D-2). No owner key is needed anywhere in this part.

```bash
CA=/etc/sandbox-platform/tls/ca.crt
M=/root/objstore-migration
P=/opt/platform/src/platform/.venv/bin/python

$P $M/manifest.py https://127.0.0.1:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" \
    analysis > $M/before.txt
$P $M/manifest.py http://127.0.0.1:3900 <api-key> <its secret> analysis > $M/after.txt

rclone --ca-cert $CA copy minio:analysis garage:analysis \
    --transfers 4 --checksum --stats 30s --stats-one-line

$P $M/manifest.py http://127.0.0.1:3900 <api-key> <its secret> analysis > $M/after.txt
wc -l $M/before.txt $M/after.txt

diff $M/before.txt $M/after.txt && echo 'IDENTICAL: every key, size and ETag matches'
```

**If the `diff` is not empty, it must contain only `-N` pairs.** Every
difference has to be one object appearing twice — once with a suffixed ETag on
the MinIO side, once with a plain MD5 on Garage's — with **identical sizes and
identical keys**. That is DECISION F1's known exception. Anything else is a
failed copy, and the copy is re-runnable:

```bash
# Every differing object, paired by key, so the -N cases are obvious.
diff $M/before.txt $M/after.txt | awk '/^[<>]/' | sort -k3 | head -40
```

Spot-check one of them end to end rather than trusting the pattern — stream
both copies and compare SHA-256, as Part K did for all three of its cases.

> ### FINDING F-2 — retention clocks restart at the copy
>
> Garage's lifecycle worker expires an object by the age of **its own version
> timestamp**, which is when this copy wrote it. Every migrated object
> therefore gets up to 30 more days than its original schedule.
>
> That is a GDPR and a capacity fact, not a bug to fix here: the alternative is
> to delete older objects before copying, which this runbook deliberately does
> not do while the queue is being drained and rollback is still live. If the
> retention window must be honoured exactly, expire first on MinIO
> (`RETENTION_DAYS` is already 30, so one `mc ilm` scan has run daily) and
> record in `EVIDENCE F` what the oldest remaining object's date was.

```
EVIDENCE F                                                      <date>

(paste: both jq length values, rclone's final stats line, the diff result)
```

---

# Part G — cut over

The whole window is between the first and last command here. Read all of them
before starting, and have the rollback block open in a second shell.

```bash
# 1. Stop serving. sandbox-api was disabled by runbook 17 step 11; confirm
#    rather than assume, because a second uvicorn would keep old credentials.
systemctl is-enabled sandbox-api sandbox-api-browser
systemctl stop sandbox-api-browser

# 2. Free the port. disable --now, NOT purge: MinIO's data is the rollback.
systemctl disable --now minio
ss -lntp | grep -E ':(9000|9001)\b' || echo 'port 9000 free'

# 3. The front takes it. `nginx -t` must be FULLY clean now -- the bind
#    errors from Part E were MinIO holding the port, and it no longer is.
nginx -t
systemctl enable --now nginx
systemctl is-active nginx garage
ss -lntp | grep -E ':(9000|3900|3903)\b'

# 4. The one edit to api.env in this whole migration. Keep a copy first.
install -m 600 -o platform -g platform /etc/sandbox-platform/api.env \
        /etc/sandbox-platform/api.env.minio-$(date +%Y%m%d)
sed -i "s|^S3_ACCESS_KEY=.*|S3_ACCESS_KEY=<objects-api key id>|; \
        s|^S3_SECRET_KEY=.*|S3_SECRET_KEY=<objects-api secret>|" \
        /etc/sandbox-platform/api.env
grep -c '^S3_ACCESS_KEY=\|^S3_SECRET_KEY=' /etc/sandbox-platform/api.env   # expect 2

# 5. Serve again.
systemctl start sandbox-api-browser
systemctl is-active sandbox-api-browser
```

Garage key ids are `GK` followed by hex and secrets are hex, so neither
contains `$` — which matters because `api.env` is read as a systemd
`EnvironmentFile` and `$` is expanded in one.

Now the filter checks. **None of these carries a credential**, so nginx answers
every one of them before Garage is reached — which is the point: these are
DECISION A2's absences, asserted directly.

```bash
CA=/etc/sandbox-platform/tls/ca.crt
B=https://192.168.1.10:9000
c() { curl -s -o /dev/null -w "%-34s %{http_code}\n" --cacert $CA "$@"; }

c "$B/analysis"                                  # ListObjects          -> 403
c "$B/analysis?list-type=2"                      # ListObjectsV2        -> 403
c "$B/analysis/"                                 # list, trailing slash -> 403
c -I "$B/analysis/"                              # HEAD the same        -> 403
c -X DELETE "$B/analysis/u/x/000/samples/x/y"    # DeleteObject         -> 403
c -X POST "$B/analysis?delete"                   # DeleteObjects        -> 403
c -X PUT -H 'x-amz-copy-source: /analysis/a' "$B/analysis/b"   # the CVE -> 403
c -X PUT "$B/analysis/b"                         # PutObject/copy       -> 403
c -X POST "$B/analysis/b?uploads"                # multipart init       -> 403
c "$B/"                                          # ListBuckets          -> 403
c "$B/minio/health/live"                         # gone                 -> 403
c "$B/healthz"                                   # the replacement      -> 200
# and the positive direction, which matters just as much
c -X OPTIONS -H 'Origin: https://sandbox.evilbootloader.com' \
  -H 'Access-Control-Request-Method: POST' "$B/analysis"   # preflight   -> 200
```

**All thirteen returned exactly these codes in Part K.** A `200` or a `404`
anywhere above except the last two lines means the filter is not doing its job
— a 404 says the request reached Garage. Stop and fix the location blocks
before going near Part H.

An unsigned `GET` of a *real object key* is the one case that is deliberately
**not** a front refusal: it is allowed through and Garage answers
`403 AccessDenied, "Garage does not support anonymous access yet"`. Reading the
body is how you tell the two layers apart when debugging.

```
EVIDENCE G                                                      <date>

(paste: the systemctl/ss output from steps 1-5, and all ten curl lines)
```

## Rollback

| If it fails at | Undo |
|---|---|
| Part C–F | nothing is serving yet: `systemctl disable --now garage`, and MinIO is still running |
| Part G step 3 (nginx will not bind or serve) | `systemctl disable --now nginx; systemctl enable --now minio` |
| Part G step 4–5, or any Part H check | `systemctl stop sandbox-api-browser; systemctl disable --now nginx; systemctl enable --now minio; cp /etc/sandbox-platform/api.env.minio-<date> /etc/sandbox-platform/api.env; systemctl start sandbox-api-browser` |

**Objects written to Garage after the cutover do not exist in MinIO**, so a
rollback loses any job submitted in the window. Part B's empty queue keeps that
set small; do not let the window run overnight with the UI open.

---

# Part H — verify, end to end

Nothing above proves the platform works — only that the pieces are in place.
Each of these exercises a path that reaches the store differently.

| # | What it proves | How |
|---|---|---|
| H1 | the API can read the store at all | `GET /api/v1/jobs` for an existing job with artifacts, and a download link that returns bytes |
| H2 | browser upload: presigned POST through the tunnel, same-origin | submit a small benign sample in the UI; it must reach `admitted` |
| H3 | **the POST policy's size cap is still enforced by the store** | submit a file larger than declared — the upload must be refused by the store, not by the UI |
| H4 | admission's HEAD/GET, and the ETag path | the job's `sha256` and size are recorded, and `sample_status` reads `ok` at claim |
| H5 | Dom0 fetches a sample over the LAN endpoint | run a job to completion on `ubuntu` |
| H6 | worker artifact upload: presigned POST from Dom0 | artifacts appear on the job detail page |
| H7 | range reads | open the per-process log viewer on a job with a large log |
| H8 | the ZIP wrapper streams from the store | download an artifact bundle |
| H9 | retention and quota survived provisioning | Part D's `ilm:` line, and `garage bucket info analysis` |

H3 is worth doing by hand even though `platform/tests/test_objects.py` covers
the mechanism: it is the one control that is *the store's* and not the API's,
and `StreamLimiter` is the Garage code path this migration is trusting with it.
A refusal looks like the upload failing with a 4xx and the UI saying so.

H5 and H6 are **Dom0**, not the platform DomU. `sandboxd` needs no change —
`SANDBOXD_API`, `SANDBOXD_CACERT` and the internal endpoint are all unchanged —
but that is a claim this step tests rather than assumes:

```bash
# DOM0
cd /root/drakvuf-multios-sandbox
set -a; . /etc/sandboxd/sandboxd.env; set +a
.venv-sandboxd/bin/python -m sandboxd.daemon 2>&1 | tee -a /var/log/sandboxd/$(date +%Y%m%d-%H%M).log
```

Watch for the sample `GET` against `https://192.168.1.10:9000/analysis/…` — the
log line in runbook 17's EVIDENCE is the shape — and for the artifact `POST`
afterwards. A TLS error there means the certificate copy in Part E is wrong; a
403 mentioning a signature means the region or the host moved.

```
EVIDENCE H                                                      <date>

(paste: H1-H9 one line each, and the sandboxd GET/POST log lines)
```

---

# Part I — remove MinIO

**Only after Part H passes**, and after at least one full day of normal use —
the lifecycle worker runs at midnight, and H9 does not prove it ran.

```bash
# on the platform DomU
# provision.sh's owner key is ephemeral, so there should be nothing to
# delete. Confirm rather than assume -- an aborted run can leave one, and the
# next provision.sh run is what would otherwise clean it up.
garage -c /etc/garage.toml key list                  # expect objects-api only
garage -c /etc/garage.toml bucket info analysis      # and RW, never RWO

rm -f /etc/systemd/system/minio.service && systemctl daemon-reload
rm -f /usr/local/bin/minio
rm -rf /etc/minio /root/.mc
rm -rf /srv/minio/data
rm -f /etc/sandbox-platform/api.env.minio-*
rm -rf /root/objstore-migration /root/.config/rclone
deluser --system minio-user
df -h /srv/minio
```

`mc` goes with it: it is the archived server's client, and `garage` plus the
`boto3` snippets replace every use. Keep it only if something outside this
repository needs it.

> **Part I-b, optional and separate.** The mount is still `/srv/minio` and now
> holds Garage (DECISION A4). Renaming it to `/srv/objects` touches the guest's
> `fstab`, `metadata_dir`/`data_dir`/`ReadWritePaths`, and the `misc/platform.cfg`
> comment, and buys only accuracy — do it as its own change, with Garage
> stopped, or leave the name and let this runbook explain it.

---

# Part J — the code changes, and the ones deliberately left

**Done 2026-10-04, and the split is the point.** Everything that is true *today*
has landed; everything that would assert the deployment has already migrated
has not. `docs/CURRENT-STATE.md` describes the running lab, and a repository
that claims Garage while the DomU serves MinIO is the exact failure that file
exists to prevent.

## Landed

| File | Change |
|---|---|
| `platform/garage/provision.sh`, `conformance.py`, `objects.conf`, `README.md` | The four new files, all exercised against a real Garage — K7 |
| **`scripts/dev-services.sh`** | `OBJECT_STORE=minio\|garage`, **default `minio` because that is what the deployment runs**. The Garage path writes a config, starts the server, assigns a layout, creates the bucket, `key import`s the credentials `conftest.py` defaults to, and sets the dev-only `AllowedOrigins: ["*"]`. The summary line names the store that is up |
| **`.github/workflows/static-checks.yml`** | The `platform` job is now a **matrix over both stores**, `fail-fast: false`. The Garage leg pins `v2.4.1` *and its sha256*, since nothing publishes a checksum beside the binary; it also installs `platform/garage/objects.conf` behind a throwaway certificate and runs the front's tests against it. Flip to `[garage]` alone when the deployment cuts over |
| **`platform/tests/test_object_front.py`** | New: 18 assertions against the capability front, skipping **loudly** unless `S3_FRONT_ENDPOINT` names one. The regression test `objects.conf` did not have |
| `platform/tests/conftest.py` | The dev credential is `devrootkey`/`devrootpassphrase`. Not taste: **Garage refuses a key id under 8 characters and a secret under 16**, and the old `devroot`/`devrootpass` was 7 and 11, so it cannot be imported. MinIO's minimums are 3 and 8, so one pair now serves either store with no environment at all |
| `platform/tests/test_objects.py` + 3 others | Four assertions widened from one vendor's error strings to the property they are about — refused, expired, absent. Each names the measurement; K4 lists them |
| `scripts/check-secrets.sh` | Two new patterns, `rpc_secret`/`admin_token`/`metrics_token` and `GK[0-9a-f]{24}`, both verified to fire. The allowlist follows the renamed dev credential — **and this gate caught a real bug while I was making the change**: CI's MinIO container still had the old password, so the `minio` leg would have failed against the renamed defaults |
| `config.py`, `objects.py`, `manifest.py`, `routers/jobs.py`, `routers/worker.py`, `_artifacts.html`, `fake_worker.py`, `sandboxd/api.py`, `tls/issue-cert.sh` | Comments. "MinIO" becomes "the object store" where the sentence is about any S3 store; where it is dated evidence it stays, labelled as MinIO's, with Garage's measured behaviour beside it |
| `docs/TROUBLESHOOTING.md` | Ten symptom-first entries under a new **"The object store — Garage"** heading, each one something the rehearsal actually hit, and the heading says plainly that none of it describes the deployment yet |
| `docs/INDEX.md`, `docs/CURRENT-STATE.md` §3 | Regenerated — a new test file changes the derived counts |

> ### FINDING J-1 — the `..` backstop is gone, and the comments that relied on it were right to worry
>
> **Garage accepts `..` in a key and stores it literally** (`a/../b.bin`,
> `../escape.bin`, measured 2026-10-04). MinIO refused it with
> `XMinioInvalidResourceName`.
>
> Three docstrings described that refusal as a second line of defence —
> `objects.py`, `manifest.py`, `routers/jobs.py` — and `manifest.py`'s said why
> it was not the argument: *"a guarantee that rests entirely on a dependency's
> input validation is one upgrade away from resting on nothing."* **That upgrade
> is this migration.**
>
> No code changed, because all three copies of the rule already reject `.` and
> `..` and `test_manifest.py` / `test_jobs_api.py` already pin them. What
> changed is that the sentence is now the mechanism rather than a precaution,
> and the comments say so.

## Deliberately NOT done until the cutover

| File | Why it waits |
|---|---|
| `docs/CURRENT-STATE.md` §1.3 and §2a/§2b | These state what the lab IS. The `Services` and `Listeners` rows, the `/srv/minio` disk row and the thin-pool retention note are **correct today**, and the superseded-facts rows cannot be written until the facts are superseded. This belongs in the same change as Part G's evidence |
| `platform/minio/` | The deployment still runs MinIO, so deleting its provisioning script would remove the only copy of how the live store was built. `test_objects.py` also loads `minio/api-policy.json`. Delete both in the change that files this runbook |
| `docs/architecture/platform.md`, `docs/checklists/platform.md` | The architecture record describes the deployed design; the checklist tracks progress against it. Both move when the design does |
| `misc/platform.cfg` | Its comments name MinIO and `/srv/minio` and both are still true — and DECISION A4 keeps the mount name through the migration anyway |
| `scripts/dev-services.sh`, CI | The `minio` default and the `minio` matrix leg go in the same change. Until then they are the deployment's half of the pair, and dropping them early would mean no test ever meets the store that is actually running |

> **The ordering rule, once, since four rows above restate it:** anything that
> describes the deployment waits for the deployment. Anything that is a
> capability of the code — a script, a test, a comment about S3 — lands now, so
> the cutover is a `systemctl` swap and two lines of `api.env` rather than a
> code change performed under time pressure.

## What the suite proves now

    OBJECT_STORE=minio   915 passed,  3 skipped      (the 3 are mc-gated)
    OBJECT_STORE=garage  915 passed,  3 skipped
    ...with a front       933 passed,  3 skipped      (+18 front assertions)

The same assertions, against both stores, from one `pytest -q`. That is what
makes the four widened assertions trustworthy rather than merely green: each
one now passes against two different implementations of the behaviour it
describes.

Also for the record, and **not** this runbook's to decide: a maintained MinIO
fork exists (`pgsty/silo`, which patched this CVE), and it would be a smaller
change than Garage. It was not chosen; the choice was Garage, and DECISION A2
is the price.

---

# Part K — rehearsal in the development container, 2026-10-02/03

**This is not deployment evidence and does not fill any `EVIDENCE` block
above.** It is a dress rehearsal of Parts C–G on the development container, run
because the container has no real data and nothing to lose: Garage v2.4.1 from
the URL in Part C, a real MinIO seeded by this repository's own test suite, and
`nginx/1.28.3` carrying Part E's config.

**What it is worth.** It exercised the platform's actual code — 915 tests from
`platform/tests` — against a real Garage, and it corrected four things this
runbook had wrong. **What it is not worth:** it says nothing about Dom0, the
tunnel, the LAN certificate, the real thin pool, or the real data.

Differences from the deployment, all of them deliberate:

| | Deployment | Rehearsal |
|---|---|---|
| Garage S3 API | `127.0.0.1:3900` behind nginx on `192.168.1.10:9000` | `127.0.0.1:9000` behind nginx on `127.0.0.1:9443` |
| TLS | the CA that signs everything in this lab | a throwaway CA, 7 days |
| Storage | `/srv/minio/garage` on `xvdb` | the container's overlay |
| systemd | `garage.service`, `User=garage` | foreground, same binary and config shape |

## K1 — install, layout, provision

`garage v2.4.1`, digest as recorded in Part C. All three listeners came up on
loopback. `/health` **503 before `layout apply`, 200 after** — Part C's note.
`layout assign -z lab -c 200G` showed `186.3 GiB`. `bucket set-quotas
--max-size 200GiB` → `maximum size: 214.7 GB (200.0 GiB)`. `bucket allow`
rendered `RW` for `objects-api`, `RWO` for `objects-provision`. CORS and the
30-day lifecycle rule both applied through `boto3` and **echoed back**,
including `Filter.Prefix: ""`, which was an open question in the first draft.

## K2 — the capability front

Part E's config, `nginx -t` clean, all thirteen Part G checks exactly as
written there — ten `403`, `/healthz` `200`, preflight `200` with
`access-control-allow-origin: https://sandbox.evilbootloader.com`.

## K3 — `provision.sh` conformance, 29 controls

D2's table is this run. `29 ok, 0 unexpected`, after three of my own
expectations turned out to be wrong rather than Garage's behaviour:

- the front's 403 is an **HTML** page, so `botocore` reports no S3 error code;
- a foreign origin's preflight is **refused** (`403`) — the `Allow-Origin: *`
  I first flagged is on Garage's *error* page and is inert;
- a wrong-region signature **is** refused, `400 AuthorizationHeaderMalformed`,
  MinIO's own status and code. It looked unenforced because `botocore` reads
  Garage's `<Region>` hint out of the error body and silently re-signs — so
  only a HEAD (no body) or a presigned URL (no retry) shows the refusal. The
  presigned case is the one that matters in production and it fails closed.

## K4 — the platform's own suite against Garage

`platform/.venv/bin/python -m pytest -q`, with the store on `127.0.0.1:9000`
so the suite's hardcoded ports hold:

    909 passed, 6 failed, 3 skipped in 111.80s

Against MinIO, `tests/test_objects.py` alone was `19 passed, 3 skipped`. The
3 skips are the same `mc`-gated ones in both runs. **All six failures are
assertions about error *shapes*, and in each case the control itself holds** —
verified one at a time rather than assumed:

| Failure | Garage | Is the control intact? |
|---|---|---|
| `test_objects::test_a_presigned_url_expires` | `400 InvalidRequest`, *"Date is too old"* | **yes** — expired is refused; MinIO said `403`. `sandboxd` treats all 4xx as a permanent refusal either way (`api.py:485`) |
| `test_objects::test_object_lock_is_off` | `501 NotImplemented` | **yes, more strongly** — not implemented at all |
| `test_worker_api::test_the_declared_size_binds_the_artifact_policy` | `400 InvalidRequest`, *"File size does not match policy"* | **yes** — over-range upload refused; MinIO said `EntityTooLarge` |
| `test_jobs_api::test_the_signed_policy_cannot_be_edited_client_side` | raised-range tamper → `403 AccessDenied`; **signature or policy field removed** → `400 InvalidRequest` | **yes** — all four tampers refused, and a direct check confirmed only the honest 50 bytes reached the store, never the 100 kB |
| two `test_ui_browser` upload tests | *"the browser blocked the upload"* | **not a Garage difference** — cross-origin dev setup against the deployment's single-origin CORS rule. Both pass with `AllowedOrigins: ["*"]`; see D2's note |

## K5 — the copy, on 3,300 real objects

`before.txt`/`after.txt` manifests over MinIO's bucket as the test suite left
it — 3,300 objects including the hostile filenames `test_jobs_api` submits
(`"; rm -rf ~ #`, `$(whoami).sh`, `<script>alert(1)</script>.exe`, embedded
tabs and spaces) and an owner-prefixed `u/operator@example.test/…` tree.

    3300 objects -> rclone copy --transfers 8 --checksum -> 3300 objects
    3297 identical in key, size and ETag
       3 differing, all `results/` artifacts of 25, 50 and 72 MB

The three are DECISION F1's known exception: multipart in MinIO
(`…-4`, `…-6`, `…-9`), plain MD5 in Garage. Streamed both copies and compared:
**bytes identical by SHA-256, and Garage's ETag equals the true content MD5.**
`samples/` objects with a multipart ETag: **0 of 3,300.**

This run is also what produced FINDING F-1 — `rclone lsjson --hash` returning
`null` for every object on *both* remotes — which invalidated the first draft's
verification and is why the manifest is taken with `boto3`.

## K6 — the cutover, and one lesson that is not about Garage

MinIO stopped, Garage rebound to the port, nginx reloaded onto the new
upstream, `/healthz` 200 through the front: the Part G sequence, in order,
without incident.

## K7 — the two scripts, written and exercised

`platform/garage/provision.sh` and `platform/garage/conformance.py` were
written against this running store on 2026-10-03, not against the
documentation. What that bought:

- **`provision.sh` is idempotent for real.** Run twice against a provisioned
  store: `bucket analysis: exists`, `api key objects-api: exists; reusing it`,
  CORS and the lifecycle rule re-applied, ephemeral owner key minted and
  deleted, final state showing `RW objects-api` and nothing else.
- **`key create` mints duplicates** — found by running it, not by reading
  about it. Two live keys named `objects-api` and no way to tell which one
  `api.env` holds. The script counts by name and refuses at 2 or more; the
  duplicate this probe created was deleted by hand.
- **`bucket info` and `key info` exit 1 for both "absent" and "ambiguous"**,
  so neither is usable as an existence test. `key list` parsing is.
- **All seven preconditions fail closed**, checked one at a time: `*` as the
  origin, a missing quota, a region that disagrees with `garage.toml`, no
  python, an unreadable config, a non-numeric `RETENTION_DAYS`.
- **`conformance.py`: 31 controls, 0 unexpected, exit 0** against the front;
  `23 ok, 4 skipped` front-only, with the skips naming the flag that unlocks
  them.
- **And it fails when it should.** Pointed at bare Garage with no front in the
  path, six withheld-capability checks go red and the exit status is 1. A
  conformance check that cannot fail is decoration; this one was shown to
  detect precisely the regression it exists for.
- `shellcheck` 0.11.0 clean, `dash -n` and `bash -n` clean. The shebang's
  `python3` has no boto3, so a bad invocation now names the venv instead of
  raising `ModuleNotFoundError`.

**`objects.conf` was verified as the shipped file**, installed verbatim at
`/etc/nginx/conf.d/objects.conf` under `nginx/1.28.3`:

- it **parses as a `conf.d` fragment** — `syntax is ok` — which is what proves
  the `map`, `log_format` and `upstream` blocks are legal there;
- **`nginx -t` binds**, which is FINDING E-1 and was the first draft's error;
- with only the three `HOST-SPECIFIC` lines changed, `conformance.py` scores
  **31 ok, 0 unexpected** through it — so what is in the repository is what was
  tested, not a paraphrase of it;
- the access log did what it was shaped to do: six presigned GETs logged as
  method and path, and **zero occurrences of `X-Amz-Signature` or
  `X-Amz-Credential`** in the file.

> **`pkill -f "bin/garage .*server"` killed the shell that ran it**, because
> `pkill -f` matches the rendered command line and the shell's own `-c`
> argument contained the pattern. `CLAUDE.md` already forbids this idiom for
> exactly this reason, and `sandboxd/proc.py::iter_processes` exists because of
> it. **Part G and Part I stop services by unit name, never by pattern** — and
> if a stray process ever has to be found by hand, read `/proc/<pid>/cmdline`
> and compare argv elements, as that module does.

---

# What must be tested on the deployment, and what cannot be tested here

| Claim | Status |
|---|---|
| Every Part A1 row | **rehearsed 2026-10-03 in the development container** (Part K), from Garage docs and `main-v2` source. Parts F–H are what make them evidence *on this host* |
| Garage accepts an empty `Filter.Prefix` on a lifecycle rule | **verified, K1** — and echoed back by `get_bucket_lifecycle_configuration` |
| `garage bucket set-quotas --max-size 200GiB` parses that unit | **verified, K1** — `214.7 GB (200.0 GiB)` |
| nginx's `limit_except` and `if` blocks refuse exactly the Part G requests and nothing the platform needs | **verified both directions, K2–K4** — thirteen checks, plus 909 platform tests passing *through* a front with the same config |
| `rclone` with `upload_cutoff = 5G` preserves every ETag | **refined, K5.** True for every single-part object (3,297 of 3,300) and **impossible** for one already stored multipart — bytes still identical. No sample was multipart |
| `rclone lsjson --hash` can verify the copy | **refuted, FINDING F-1** — `null` on both remotes. Replaced with a `boto3` manifest |
| The six platform-test failures are error-shape assertions, not broken controls | **verified one at a time, K4** |
| `provision.sh` converges on a re-run, and refuses rather than guessing when a duplicate key already exists | **verified, K7** — including all seven precondition refusals |
| `conformance.py` detects a missing capability front | **verified, K7** — six checks red and exit 1 against bare Garage |
| `provision.sh` against a node with **no layout**, and against an **empty** store — the deployment's actual path | **verified, K7** — on a second, fresh Garage node: refused with the layout message before the layout, then created bucket, quota, key, CORS and retention from nothing |
| `provision.sh` run as a **non-root** user, where `/etc/garage.toml` is unreadable | **verified only as the precondition message.** The rehearsal config was readable by the running user; the check fires correctly when pointed at a root-owned path |
| Garage's throughput against MinIO's, for a trace that writes many small artifacts | **unmeasured**, by the rehearsal or this runbook |
| Everything that is Dom0, the tunnel, `cloudflared`, the real certificate, the real thin pool, the 256 G volume, and the real data | **cannot be tested in a container.** Parts B, G, H and I are the only things that settle these, and H5/H6 need an operator on Dom0 |
| Whether anything outside this repository uses `mc` or `/minio/health/live` on this host | **unknown** — Part B's `ss`/`systemctl` output is the only place it would show |
