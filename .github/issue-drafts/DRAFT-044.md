# DRAFT-044: MinIO — bucket layout, policy, and presigned access

**Status:** **[#37](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/37) — published 2026-08-22, OPEN.**
**Area:** core/platform
**OS:** ALL
**Milestone:** M1 → gates M7
**Priority:** P0
**Depends on:** DRAFT-041 (decided). Pairs with **DRAFT-043** — the API is
what mints every URL described here, and neither is finished without the
other.
**Blocks:** artifact upload, DRAFT-045's result views.
**Needs Dom0:** **No.** A local MinIO is enough to build and test against.

# Objective

Stand up the object store that holds samples and results, and define exactly
how the browser and the analysis host reach it — which is **never with
credentials**, only with short-lived URLs scoped to one object.

# Context

## Why self-hosted, and not a cloud bucket

Decided in `docs/architecture/platform.md`. Two reasons, and the first is
not a preference:

- **Most providers' acceptable-use terms prohibit storing malware.** Account
  termination mid-project is a realistic outcome, and it would take the
  evidence with it.
- **DRAFT-022's position gets materially harder** once samples, pcaps and
  memdumps leave the operator's own infrastructure. Third-party traffic is
  captured in those pcaps.

MinIO keeps the S3 API, so `boto3`, presigned URLs and the whole idiom work
unchanged — and moving to a real S3 later is a configuration change, not a
redesign.

## The property this issue exists to hold

**Dom0 never holds object-store credentials.** It gets a presigned URL,
scoped to a single key, with a short expiry, issued by the API for a job it
currently holds a lease on. A sample that escapes into Dom0 therefore cannot
enumerate the bucket, read another job's artifacts, or reach the history.

That is the concrete payoff of DRAFT-041's choice to put an API between Dom0
and the platform's data. This issue is where it is either enforced or
quietly lost.

# Dependencies

- **DRAFT-043** — mints the URLs; this issue defines what they may point at
  and for how long.
- **DRAFT-042** — `job_id` is the key. Results are keyed by job, not by
  content digest, which is the whole reason `job_id` had to exist.

# Out of scope

- **Retention and deletion policy.** Named as an open question in
  `platform.md` and interacting with DRAFT-022. This issue creates the
  store; it does not decide how long anything lives in it. It must not
  foreclose the decision — hence versioning and object-lock notes below.
- **The manifest** and the publication boundary. A later issue.
- **Multi-tenancy.** No per-owner prefixes or policies; M8.
- **Backups.** Real, and separate.

# PLAN

1. Decide the deployment shape (single-node, single-drive — see CREATE).
2. Create the bucket, the service account, and the policy.
3. Settle the presigned-URL question that actually has teeth: PUT versus
   POST, and what enforces the size cap.
4. Configure CORS, without which browser-direct upload silently fails.
5. Size and mount the storage volume deliberately.

# CREATE

## Deployment: single node, single drive, in the platform LXC

MinIO's distributed erasure-coded mode needs four drives minimum and buys
availability this lab does not need. Single-node single-drive is the honest
configuration: it is a lab store whose contents are reproducible by
re-running an analysis, and pretending otherwise adds operational surface
for a durability guarantee nothing depends on.

**Storage gets its own mount point, not the container rootfs.** An LXC
rootfs defaults to 8–16 GB; a single memdump can be gigabytes. Sizing the
rootfs and hoping is how this fills up silently in the middle of an
analysis, and a full object store surfaces as an artifact upload failing at
the end of a run that otherwise worked — the most expensive place to fail.

## Bucket layout

One bucket, `analysis`:

```text
samples/<job_id>/<submitted filename>
results/<job_id>/trace.log
results/<job_id>/capture.pcap
results/<job_id>/memdump/…
results/<job_id>/extracted/…
results/<job_id>/manifest.json
```

**Keyed by `job_id`, not SHA-256.** DRAFT-030 established that identical
bytes submitted under different names are separate runs — the submitted name
is part of what is being analysed, because extension dispatch and `argv[0]`
self-checks are real evasion surface. `sha256` is an indexed column in the
jobs table for search and dedup reporting; it is not a path component. This
is also what closes the MD5-collision gap recorded in
`docs/architecture/result-schema.md` as F8.

**The submitted filename appears in the key.** It is attacker-controlled, so
the key is constructed by S3-escaping it — not by sanitising it, which would
break byte-exactness. A name containing `/` is already refused by the
admission check upstream.

## Access: one service account, no anonymous access

| Principal | Holds | Can |
|---|---|---|
| MinIO root | Deploy-time only, not in any application config | Everything |
| API service account | The API process, in the platform LXC | `GetObject`, `PutObject` on `analysis/*`; **no** `ListBucket` at top level, **no** `DeleteObject` |
| Browser | Nothing | Only what a presigned URL grants |
| Dom0 / `sandboxd` | **Nothing** | Only what a presigned URL grants |

The bucket policy denies anonymous access outright. Withholding
`DeleteObject` from the API is deliberate: nothing in the current design
deletes an artifact, so the capability is absent until retention is designed
and grants it explicitly.

## Presigned PUT versus POST — the size-cap question

This is the one place the obvious choice is wrong, so it is worth stating.

**A presigned PUT cannot constrain the upload's size.** The signature covers
the key and the expiry; a client that receives a URL for a 10 KB file can
send 10 GB to it. `POST /api/v1/jobs`'s `size_bytes` is a *claim by the
client* and constrains nothing on its own.

Two mitigations, and the recommendation is both:

- **Presigned POST with a policy**, which supports
  `content-length-range` and is enforced by MinIO at upload time. This is
  the real fix, and it is what the browser upload should use.
- **Re-check the object's real size** in `POST /jobs/{id}/uploaded` before
  admission, and reject `rejected_size`. This catches anything the policy
  missed and is required regardless, because it is also what verifies the
  object exists at all.

Worker-side artifact uploads stay presigned PUT: the size is not knowable in
advance and the uploader is authenticated by lease.

## TTLs

| URL | TTL | Why |
|---|---|---|
| Browser upload | 15 min | Long enough for a large sample on a slow link; short enough that a leaked URL is not a standing capability |
| Worker sample GET | Lease duration | It is useless once the lease lapses |
| Worker artifact PUT | 15 min, minted per artifact | A single long-lived prefix URL would be a write primitive over the whole result set |
| Browser artifact GET | 5 min, minted per request | Never stored, never embedded in a page that could be shared |

## CORS

Browser-direct upload fails without it, and it fails in a way that looks
like a network error rather than a configuration one. The bucket allows
`PUT`/`POST` from the platform's own origin only — not `*`, which would let
any page a browser visits use a leaked presigned URL.

## Versioning and object lock: off, deliberately

Both are off, and the reason is recorded so it is a decision rather than a
default. Versioning on a store of large write-once artifacts multiplies
storage for a rollback nobody performs. Object lock would make retention
*undecidable* later — you cannot delete what is locked, and retention is
explicitly still open. Turning either on before that decision would foreclose
it.

# TEST

Against a local MinIO. No Dom0.

1. **Anonymous access is refused** for a known key — the baseline that makes
   every other control meaningful.
2. **Presigned upload works**, and **the same URL past its TTL is refused**.
3. **The size policy holds.** A presigned POST issued for 1 MB rejects a
   2 MB body at MinIO, without the API being involved.
4. **The size re-check holds independently.** Upload under the policy, then
   assert `/uploaded` still verifies real size — the two controls must not
   be one control tested twice.
5. **A presigned URL for job A cannot read job B**, even one key over.
6. **The API's service account cannot `ListBucket` at top level and cannot
   delete.** Both asserted, because both are what stop a compromised API
   from being a total loss. 
7. **Hostile filenames survive the round trip.** `"`, `$`, backtick, `;`,
   newline, spaces, unicode, and a name at the length limit: uploaded under
   the escaped key, listed, downloaded, and compared byte-exact against the
   original name and bytes.
8. **CORS** allows the platform origin and refuses another.
9. **A full volume fails loudly** — fill the mount, attempt an artifact
   upload, assert a clear error rather than a truncated object.

# DEPLOY

MinIO in the platform LXC, behind TLS, with a dedicated storage volume sized
against expected memdump volume rather than defaults.

Deploy-time secrets: root credentials, used once to create the bucket, the
service account and the policy, then **not** placed in any application
config. The API gets the service account only.

Rollback is redeploying the previous configuration; the data volume is not
touched by a configuration rollback, which is the reason storage is a
separate volume rather than part of the container.

# Acceptance criteria

- [ ] Bucket `analysis` exists with the two prefixes, and anonymous access
      is denied.
- [ ] The API's service account can read and write and **cannot** list at
      top level or delete — asserted by test, not by reading the policy.
- [ ] Neither Dom0 nor the browser ever receives a credential. Every access
      is a presigned URL for one key.
- [ ] Browser uploads use presigned POST with `content-length-range`, and
      the cap is enforced by MinIO — test 3.
- [ ] Real size is re-checked at admission, independently — test 4.
- [ ] TTLs match the table above, and expiry is tested rather than assumed.
- [ ] A URL for one job cannot reach another — test 5.
- [ ] Hostile filenames round-trip byte-exact — test 7.
- [ ] CORS is origin-scoped, not `*` — test 8.
- [ ] Storage is a dedicated volume, not the container rootfs, and the
      sizing rationale is written down.
- [ ] Versioning and object lock are off, with the reason recorded.
- [ ] No `automation/` file changes.

# Evidence required

- `mc admin policy info` and the bucket policy, showing the absent
  capabilities as well as the present ones.
- Test output for all nine groups.
- A transcript of one sample uploaded by presigned POST, fetched by a
  worker-scoped presigned GET, with artifacts written back — the path a real
  job takes.
- `df -h` of the storage mount, showing it is not the rootfs.

# Security considerations

- **Presigned URLs are bearer capabilities.** Anyone holding one has what it
  grants until it expires. That is why they are per-key and short-lived, and
  why a prefix-scoped URL is never issued — it would be a bucket enumeration
  or bulk-write primitive.
- **This store holds live malware.** It is not a general-purpose bucket, and
  nothing else should be given access to it for convenience. Anything that
  fetches from it fetches a sample.
- **The API is the only credentialed principal**, which concentrates risk
  there. That is the deliberate trade from DRAFT-041 — narrow Dom0 blast
  radius, in exchange for a single high-value component.
- **A leaked browser upload URL is a write into the sample space.** Bounded
  by TTL, by the size policy, and by the fact that an object with no
  corresponding job row is never admitted or executed — a write is not an
  analysis.
- **Bucket contents are subject to DRAFT-022.** Pcaps carry third-party
  traffic and memdumps carry whatever was in guest memory. Retention is
  open, and the longer it stays open the more there is to decide about.

# Documentation changes

- **New:** deployment notes for the MinIO instance — bucket creation, policy,
  service account, CORS, volume — as a runbook that becomes evidence once
  executed.
- **Updated:** `docs/architecture/platform.md` — the bucket layout section
  points at the real policy rather than describing an intended one.
- **Updated:** `docs/architecture/result-schema.md` — object keys are where
  results now live; its F8 `KNOWN GAP` is closed by `job_id` keying and
  should say so once this lands.

# Recovery / rollback

Configuration rollback does not touch the data volume. Losing the volume
loses collected artifacts, which are reproducible by re-running an analysis
but not by any other means — so backups are real work and are deliberately
not claimed by this issue.
---

# Annotation — 2026-08-24, during implementation

Appended rather than rewritten, per the annotate-never-rewrite rule. The
reasoning above is the record of what was decided in advance; this is what
measurement changed.

## Four claims above that measurement contradicted

**1. "Presigned PUT versus POST — the size-cap question."** The section is
right about browser uploads and wrong about artifacts. It keeps them on a
presigned PUT because "the size is not knowable in advance" — but
`POST /worker/jobs/{id}/artifacts` is called *after* the trace finishes, when
the files are already on Dom0's disk, so the worker knows every size exactly.
An unbounded write capability was being issued for nothing. Artifacts now use
a size-capped POST, with the range starting at **0** rather than 1: an empty
`capture.pcap` is a real result meaning the clone generated no traffic.

**2. "CORS ... The bucket allows `PUT`/`POST` from the platform's own origin
only."** Two problems. Per-bucket CORS **does not exist** on this build —
`mc cors set` and boto3's `put_bucket_cors` both return `NotImplemented`
against `RELEASE.2025-09-07` — so the only mechanism is the server-wide
`cors_allow_origin`, which applies immediately with no restart.

More importantly the whole problem was removable. MinIO uses path-style
addressing, so every object URL begins `/analysis/`; routing that path on the
API's own hostname makes the browser upload **same-origin** and retires
`objects.evilbootloader.com` entirely. The store then inherits the existing
Access application rather than sitting on a hostname outside it. CORS is still
set, as defence in depth against a *leaked presigned URL* being read by a page
at another origin — MinIO's default reflects any origin with
`Allow-Credentials: true`.

**3. "A full volume fails loudly" (TEST 9) — via the bucket quota.** The quota
does not fail promptly. Measured: **3 MiB written into a 1 MiB quota, every
write accepted**; the same bucket refused ~45s later with
`XMinioAdminBucketQuotaExceeded`. MinIO enforces quotas against usage
statistics its background scanner refreshes, not at write time. So the quota
stops accumulation over days and permits an overshoot bounded by write rate
times scanner interval — not a documented contract, and not testable
deterministically.

`MAX_JOB_RESULT_BYTES` (`jobs.results_bytes`, migration 0004) is the prompt
guard, charged when a ticket is minted because the API is not in the upload
path. Note this also corrects a premise in "Bucket layout": `max_artifact_bytes`
caps one object, but `memdump` dumps the memory regions a process writes, so a
run produces many small files and a per-object cap bounds a job at nothing.

**4. "This is also what closes the MD5-collision gap ... as F8."** It does not.
`results/<job_id>/` is implemented and tested, but nothing analysing samples
uses it — `dirwatch` still writes `$OUTPUTFOLDER/$MD5/` on Dom0, so both
collisions remain live. Only `sandboxd` closes F8. Recorded in
`docs/architecture/result-schema.md`.

## Scope taken beyond this draft

- **Retention decided, provisionally: 30 days, lifecycle expiry over the whole
  bucket.** "Out of scope" above still holds in spirit — the *policy* question
  is DRAFT-022's — but leaving the store with no expiry at all was the worse
  default. Not split by prefix: `results/<job_id>/extracted/` is malware too and
  S3 lifecycle prefixes are literal rather than globs.
- **Input validation on both upload paths.** The draft says nothing about it.
  `filename` had only length bounds, and its `max_length=1024` counted
  *characters* against an S3 key limit measured in *bytes*. Sample names now
  mirror `dirwatch.c`'s `sample_name_admissible()` (no separators at all);
  artifact names allow subpaths but refuse traversal, because `extracted/` names
  come from what the sample dropped.
- **Sample names are validated against the GUEST's filesystem, per
  `target_os`.** The name does not only become an object key — it becomes
  `$GUEST_STAGING_DIR/<name>`, written by `injector -m writefile`. Ubuntu and
  Android are ext4/f2fs and forbid only `/` and NUL; **Windows is NTFS** and
  forbids `<>:"/\|?*`, the DOS device names (`CON`, `NUL`, `COM1`–`COM9`,
  `LPT1`–`LPT9`, extension or not), and a trailing dot or space.

  `:` is the one that matters. `sample.exe:payload` on NTFS is not a file with
  that name — it is an **alternate data stream** on `sample.exe`, so the
  sample would be staged under one name and executed from another. Extension
  dispatch and `argv[0]` self-checks are already live evasion surface
  (DRAFT-030); an ADS is somewhere to put the payload outright.

  Per-target rather than a lowest common denominator: every one of those names
  is ordinary on ext4, and refusing them for an Ubuntu sample would discard
  evidence to satisfy a constraint that does not apply to it. `target_os`
  arrives in the same request, so the check costs nothing. macOS is not a
  target of this project and has no branch; if one is added, `:` is again the
  character to look at.

  No Windows pipeline exists yet, which is *why* this landed now — the API has
  accepted `target_os=windows` since #36, and fixing the contract before
  `preconfig-windows.sh` is written is cheaper than after.
- **A per-job result budget**, per finding 3.

## Decisions confirmed unchanged

Anonymous access denied; no `ListBucket`; no `DeleteObject`; `job_id` keying;
versioning and object lock off; the four TTLs; one bucket. All now asserted by
`platform/tests/test_objects.py` rather than read off the policy.

## The probe that was wrong twice

`mc admin config get <alias> region` reports **empty for an env-provided
value** and is not a probe. `MINIO_SITE_REGION` set in `minio.env` is in effect
but appears only as a commented line under `... config get <alias> site`. This
was reported twice during #36 as "the region is not being enforced"; it always
was. The behavioural check is that a wrong-region signature is refused with
`400 AuthorizationHeaderMalformed`.
