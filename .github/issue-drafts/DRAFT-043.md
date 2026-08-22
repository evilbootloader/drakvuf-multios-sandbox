# DRAFT-043: The platform API — submission, admission, and the worker channel

**Status:** Drafted, not published.
**Area:** core/platform
**OS:** ALL
**Milestone:** M1 → gates M7
**Priority:** P0
**Depends on:** **DRAFT-042** (schema and claim query) — hard. **DRAFT-044**
(MinIO) for presigned URLs; the two can be built in parallel against a local
MinIO but neither is finished without the other.
**Blocks:** DRAFT-045 (web UI), `sandboxd`.
**Needs Dom0:** **No.** The worker endpoints are tested with a fake worker.

# Objective

Build the HTTP API that is the *only* thing that touches the database. Two
audiences on one service, separated by authentication and by router:
a browser that submits and watches, and one analysis host that asks for work
and reports on it.

# Context

## Why an API rather than letting Dom0 reach Postgres

`docs/architecture/platform.md` chose this deliberately over a direct
database connection, and the reason is the blast radius of the machine at
the other end. **Dom0 runs malware.** With a database connection, a sample
that escapes into Dom0 holds credentials to the job history. With a scoped
API token it holds the ability to update the jobs it is currently leasing
and nothing else — it cannot read another job, enumerate the bucket, or see
the schema.

The cost is one more component. That is the trade, stated plainly, and it is
why this issue exists as its own piece of work rather than as a thin layer.

## The two hard rules this API must not break

1. **Dom0 gains no inbound listener.** Every connection is opened by Dom0.
   Any future feature that needs the platform to *call* Dom0 — a push
   cancel, a health probe — must be redesigned as something Dom0 asks for.
2. **`target_os` comes from the submitter and is validated against a closed
   enum at exactly one boundary** (issue #3). That boundary is
   `POST /api/v1/jobs`. File magic reports and never routes.

# Dependencies

- **DRAFT-042** — the schema and the three queries. This issue calls them; it
  does not reimplement them.
- **DRAFT-044** — bucket layout and presigned URL issuance.

# Out of scope

- **The web UI** (DRAFT-045). This issue serves JSON and an SSE stream.
- **`sandboxd`.** Tested here against a fake worker that speaks the protocol.
- **Authentication beyond a single operator session and the worker token.**
  Multi-tenancy is M8. `owner` and `visibility` stay unread.
- **Artifact upload mechanics** — DRAFT-044 owns the URLs; the manifest
  boundary is its own later issue.

# PLAN

1. Pin the framework (see CREATE — FastAPI, with the reason).
2. Build the browser router against DRAFT-042's queries, with admission.
3. Build the worker router, with the token scope and mTLS.
4. Write the fake worker, and drive a job end to end without Dom0.
5. Confirm the two hard rules above are structurally enforced, not just
   observed — no route calls out to Dom0, `target_os` is parsed in one place.

# CREATE

## Framework: FastAPI

Recommended over Flask, which is what `drakvuf-sandbox` uses. The deciding
property is request-model validation: every endpoint here takes
attacker-influenced JSON, and having the shape enforced declaratively at the
boundary — with `target_os` typed as the enum — is worth more than matching
prior art. It also gives an OpenAPI document the `sandboxd` client can be
checked against.

## Browser router — session auth

### `POST /api/v1/jobs`

```jsonc
// request
{ "target_os": "windows", "filename": "invoice.exe", "size_bytes": 148992 }

// 201
{ "job_id": "0193f2c1-...",
  "upload_url": "https://minio.../samples/0193f2c1-.../invoice.exe?X-Amz-...",
  "expires_in": 900 }
```

Creates the row at `received` and returns a presigned PUT. `target_os` is
parsed into the enum here — **the one place it is validated** — and an
unknown value is a 422 before any handler logic runs.

`size_bytes` is checked against the cap *before* issuing the URL, so an
oversized sample is refused without ever being uploaded. It is a claim by
the client, so it is re-checked in step 3 against the object's real size;
the early check saves the transfer, it does not establish the fact.

### `POST /api/v1/jobs/{id}/uploaded`

Runs admission. The job moves `received` → `admitted` → `queued`, or
`rejected` with a reason from the state model's list:

| Check | Reject reason |
|---|---|
| Object missing, or size 0 | `unreadable` |
| Real size over the cap | `rejected_size` |
| `detected_type` contradicts `target_os` | `unsupported_type` |
| No registered worker could ever afford it | `no_capacity` |
| No worker has ever registered | `no_workers` |

**How the bytes are read matters.** The API streams the object from MinIO to
compute SHA-256 and to feed `libmagic` — it does not download it to disk and
it does not hold it in memory. Two reasons, one of them security: a sample
written to the platform's filesystem is a sample on a machine whose whole
justification is that it never handles one, and `libmagic` needs only the
first few KiB.

`required_mib` is snapshotted onto the job here from `worker_pipelines`, so
a later retune of `misc/*.cfg` cannot change what an already-queued job
costs.

### The rest

| Endpoint | Notes |
|---|---|
| `GET /api/v1/jobs` | Filter by `state`, `target_os`, `sha256`; keyset pagination on `created_at`, not `OFFSET` |
| `GET /api/v1/jobs/{id}` | Row plus manifest plus presigned GETs for artifacts, minted per request |
| `GET /api/v1/jobs/{id}/events` | SSE, backed by `LISTEN jobs`. One Postgres listener per process, fanned out in-process — not one connection per browser tab |
| `POST /api/v1/jobs/{id}/cancel` | Calls DRAFT-042's two cancel statements; returns which applied |

## Worker router — `/api/v1/worker/*`

**mTLS plus a bearer token**, and they answer different questions: the
client certificate says *which host*, the token says *what it may do*. Either
alone is weaker — a stolen token replays from anywhere, and a certificate
alone makes revocation a PKI operation.

The token's scope is the whole point: valid **only** for `/api/v1/worker/*`,
and every job-scoped route additionally requires that the job's
`lease_owner` matches the caller. A compromised Dom0 cannot read a job it
does not hold.

### `POST /worker/register`

```jsonc
{ "worker_id": "dom0-lab",
  "total_mib": 12082, "total_vlans": 8, "total_slots": 2,
  "pipelines": [ { "os": "ubuntu",  "required_mib": 2198 },
                 { "os": "android", "required_mib": 2198 },
                 { "os": "windows", "required_mib": 6294 } ] }
```

Upsert. The numbers stay derived on Dom0 from `misc/<os>_sandbox.cfg` plus
that host's own overhead — never duplicated platform-side.

### `POST /worker/reconcile`

```jsonc
{ "worker_id": "dom0-lab", "live_job_ids": ["0193f2c1-..."] }
```

Sent at startup, before any claim. The API marks as `interrupted` any job
this worker holds a lease on that is *not* in the list — those are jobs
whose clone died with the previous process. Jobs in the list keep their
lease.

This is what makes the lease TTL safe. The TTL expires *bookkeeping*;
reconciliation against Dom0's real state (`xl list`, `ip link`) is what
actually decides. See `platform.md`, "Why there are no VLAN or memory lease
files".

### `POST /worker/claim`

```jsonc
// request
{ "worker_id": "dom0-lab", "free_mib": 5082, "free_vlans": 6, "free_slots": 2 }

// 200 — work
{ "status": "leased", "job_id": "...", "target_os": "windows",
  "sha256": "...", "submitted_filename": "invoice.exe",
  "sample_url": "https://minio.../samples/...?X-Amz-...",
  "lease_expires_at": "2026-08-22T10:31:00Z" }

// 200 — nothing, and why
{ "status": "reserved", "blocking_job_id": "...", "need_mib": 6294 }
{ "status": "idle" }
```

Long-polling with a server-side timeout, not a tight loop — the alternative
is the once-a-second-forever logging the old admission loop produced, 170
identical lines with no backoff.

`reserved` is not an error and must not be logged as one. It is the system
working: a large job is holding its place.

**`blocking_job_id` and `need_mib` are worker-channel fields and stay
there.** Dom0 needs the number to reason about its own capacity and to log
usefully. The browser's view of a held job says only *that* something is
reserved ahead of it — naming the job or its footprint discloses another
submitter's details once `owner` and `visibility` mean anything (M8), and
`GET /api/v1/jobs/{id}` must not grow those fields for symmetry with this
one.

### The rest

| Endpoint | Notes |
|---|---|
| `POST /worker/jobs/{id}/state` | Transition, with `queue_reason`/`failure_stage`/`failure_reason`. Server-side validation against the state machine — an illegal transition is 409, not an update |
| `POST /worker/jobs/{id}/heartbeat` | Extends the lease. **Response carries `cancel_requested`** — this is the only cancellation channel, because Dom0 has no listener |
| `POST /worker/jobs/{id}/artifacts` | Presigned PUTs under `results/{id}/` (DRAFT-044) |
| `POST /worker/jobs/{id}/complete` | Manifest; terminal. Validated for shape before it is stored |

# TEST

`pytest` plus `httpx`, against a real Postgres and a local MinIO. No Dom0.

**A fake worker is a deliverable of this issue**, not test scaffolding: it
speaks register → reconcile → claim → state → heartbeat → complete, and it
is what proves the protocol closes before `sandboxd` exists. It stays useful
afterwards as the thing that isolates an API bug from a Dom0 bug.

1. **Full lifecycle, no Dom0.** Submit, upload to MinIO, admit, fake-claim,
   transition through every state, complete. Assert the row is `completed`
   with a manifest.
2. **`target_os` is closed.** `"ubuntu"`, `"windows"`, `"android"`, an
   integer, and null all 422 at the boundary. Assert the handler was never
   reached.
3. **Magic never routes.** Submit an ELF to `windows` — must be
   `unsupported_type`, and must *not* be rerouted to `ubuntu`.
4. **Head-of-line over HTTP.** DRAFT-042's test 1 through the API: claim with
   `free_mib` below the head's need returns `reserved`, and no smaller job
   left `queued`.
5. **Token scope.** A worker token on a browser route is 403. A worker token
   on another worker's leased job is 403. An expired lease is 409.
6. **Cancel a queued job** — 200, immediate, no clone-related field set.
7. **Cancel a running job** — the next heartbeat response carries
   `cancel_requested: true`.
8. **Reconcile.** Register, claim two jobs, reconcile listing only one;
   assert the other is `interrupted` and the listed one keeps its lease.
9. **Filename hostility.** Submit names containing `"`, `$`, a backtick,
   `;`, a newline, `../`, and a 4096-character name. Each must round-trip
   byte-exact to the claim response, and none may reach SQL as anything but
   a bound parameter.
10. **SSE.** A state change reaches a subscribed client; N clients share one
    Postgres listener.

# DEPLOY

Runs in the platform LXC behind a TLS terminator. Two secrets at deploy
time: the database URL and the MinIO credentials — **both of which live only
here**, which is the property the whole architecture is arranged around.

The worker token and client certificate are issued to Dom0 out of band and
are the only credentials that machine ever holds.

Rollback: stop the service. Nothing else depends on it until DRAFT-045, and
the `dirwatch` pipeline continues running throughout regardless.

# Acceptance criteria

- [ ] Every endpoint above exists, with request models validated at the
      boundary.
- [ ] `target_os` is parsed into the enum in exactly one place — asserted by
      a test, and greppable.
- [ ] Admission produces each of the five reject reasons, and `no_workers`
      is distinguishable from `no_capacity`.
- [ ] Sample bytes are never written to the platform's filesystem — the
      hash and magic are computed from a stream.
- [ ] `claim` returns `leased`, `reserved` or `idle`, and `reserved` is not
      an error path.
- [ ] Head-of-line reservation holds through the HTTP layer — test 4.
- [ ] The worker token cannot reach a browser route or another worker's
      job — test 5.
- [ ] Cancellation of a running job is delivered **only** via the heartbeat
      response; no route opens a connection toward Dom0.
- [ ] Hostile filenames round-trip byte-exact — test 9.
- [ ] The fake worker drives a job end to end with no Dom0.
- [ ] An OpenAPI document is generated and committed.
- [ ] No `automation/` file changes.

# Evidence required

- `pytest` output, all ten groups.
- The generated OpenAPI document.
- A transcript of the fake worker completing one job, end to end — this is
  the artifact that shows the protocol closes.
- `grep` output showing exactly one site parsing `target_os`.

# Security considerations

- **This service is the only thing holding database and object-store
  credentials.** That concentration is deliberate and is what buys the
  narrow Dom0 blast radius. It also makes this the highest-value target on
  the platform, and it argues against adding capability here casually.
- **Every worker route is job-scoped by lease.** Without that check a
  compromised Dom0 could read or mutate any job by id. `lease_owner` matching
  is not a nicety; it is the containment.
- **Cancellation must stay pull-only.** A push channel means an inbound
  listener on Dom0, which is the one constraint `platform.md` calls hardest.
- **Presigned URLs are capabilities.** Short TTL, one key each, issued only
  for a job the caller holds. A URL scoped to a prefix is a bucket
  enumeration primitive.
- **`libmagic` parses attacker-controlled bytes**, in the process that holds
  every credential. Cap the bytes fed to it, and note that this is one of
  the two surfaces that argue for moving the platform from an LXC to a VM at
  M8.
- **SSE and history render the submitted filename.** Escape on output; never
  sanitise on input, because the name must reach the guest byte-exact
  (DRAFT-030's reason for abandoning hash-named guest files).
- **Rate-limit the worker routes.** A compromised Dom0 in a claim loop is a
  denial of service against the queue.

# Documentation changes

- **New:** an OpenAPI document, committed, plus a short `README.md` for
  running the service locally.
- **Updated:** `docs/architecture/platform.md` — its API surface table is a
  *design sketch*; replace it with a pointer to the generated document once
  one exists, for the same reason DRAFT-042 replaces the schema sketch.
- **Updated:** `docs/architecture/networking.md` — the platform↔Dom0 link,
  the Proxmox firewall rule that constrains it, and the mTLS trust anchor.

# Recovery / rollback

Stateless service; rollback is redeploying the previous version. The
database is DRAFT-042's and is untouched by a rollback here, which is why
migrations and the API are separate issues.