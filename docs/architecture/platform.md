# Analysis platform architecture — web tier, job store, and Dom0

**Status: design record, 2026-08-21. Nothing in this document has been
built or executed.** It is the third architecture concern alongside
`analysis-pipeline.md` and `networking.md`, not a section of either, and it
discharges DRAFT-040 PLAN step 5.

Every command, endpoint, schema and bucket key below is **Candidate** in the
sense `docs/checklists/` uses the word. Treat none of it as proven.

**Decided by the maintainer on 2026-08-21**, in the session that produced
this document:

| Question | Decision | Was |
|---|---|---|
| Object storage | **MinIO on the platform server** | DRAFT-040 D5, no recommendation |
| Job state and queue | **Postgres for both**, Redis deferred | DRAFT-040 D1, "move off the filesystem" |
| Transport | **Dom0 polls an HTTPS API** | DRAFT-040 D4, "Dom0 dials out" |
| Orchestrator language | **Python** | DRAFT-010, open |

The Redis decision is a *starting point*, not a permanent exclusion — see
"Why not Redis, and what would change the answer".

---

## Why this document exists

Three needs converged on one mechanism, which is the observation DRAFT-040
was written to record: anti-starvation needs a host-global order over jobs,
cancellation needs a queued job to have an id, and the web platform needs
both. DRAFT-040 stopped short of choosing the mechanism. This document
chooses it.

It also supersedes the framing of the process-model question that was being
drafted as DRAFT-041 earlier the same day. That draft assumed the queue would
be an in-process ordered list, and set out to design a config-file
replacement for `dirwatch`'s `argc != 15` contract. With the queue in
Postgres, **the process-model question answers itself**: there is one
orchestrator process on Dom0 because there is one host-global queue and it
does not live on Dom0 at all. The measurement that prompted the question is
still the reason this design has the shape it does — see "Admission".

---

## The two servers

```text
  Browser
     │  HTTPS (session auth)
     ▼
┌──────────────────────────────────┐          ┌───────────────────────────┐
│ Server A — platform (LXC on L0)  │          │ Server B — Xen Dom0 (L1)  │
│                                  │◄─────────│                           │
│   API      (Flask/FastAPI)       │  HTTPS   │   sandboxd  (Python)      │
│   Postgres (jobs, state, queue)  │ outbound │   DRAKVUF, xl, LVM, OVS   │
│   MinIO    (samples + results)   │   only   │                           │
└──────────────────────────────────┘          └─────────────┬─────────────┘
     ▲                                                      │
     └──────── presigned PUT / GET, object-scoped ──────────┘
                                                            ▼
                                        L2 analysis clones (Ubuntu/Android/Windows)
```

**Dom0 opens every connection.** It has no inbound listener, which preserves
DRAFT-040's D4 and the `DRAKVUF_INPUT` posture `networking.md` describes. The
platform server cannot reach Dom0 at all; it answers requests and does not
make them.

Both are Proxmox guests on L0, siblings rather than nested. Their resources
come out of L0's budget, **not** Dom0's — `dom0_mem` stays pinned at 8192M
and the clone pool above it is untouched.

### The platform is an unprivileged LXC container, not a VM

Decided 2026-08-21. It is proportionate because **the platform never
executes a sample**: that is the asymmetry the whole design rests on, and it
is why Dom0 dials out and never listens. Putting the safe side in a
container buys cheap provisioning, live resize, and snapshots cheap enough
to take before every upgrade.

Three things that follow, and must not be lost:

- **Unprivileged, always.** An LXC shares L0's kernel, so an escape is a
  Proxmox *host* compromise rather than a guest one. A privileged container
  makes that trivial.
- **MinIO needs its own mount point.** An LXC rootfs defaults to 8–16 GB and
  memdumps are large. Sizing the rootfs and hoping is how this fills up
  silently mid-analysis; give the bucket store a dedicated, deliberately
  sized volume.

  **And a dedicated volume is not sufficient — the storage *pool* is the real
  constraint.** Observed on L0 2026-08-22
  (`docs/runbooks/deploy-platform-lxc.md` F1): the LVM thin pool carries
  6.35 TiB of provisioned volumes against 1.82 TiB of real storage, with no
  `thin_pool_autoextend_threshold` set. A full pool affects **every** thin
  volume on it, including the Xen L1 VM's disks. So filling the artifact
  store with memdumps can stop the analysis lab — which means the platform
  and Dom0 share a storage failure domain that the trust boundaries below do
  not describe. Isolation of *access* was designed; isolation of *capacity*
  was not, and is unresolved.
- **Revisit at M8, when the web tier becomes internet-facing.** Two surfaces
  argue for a VM eventually and neither is urgent now: the API computes
  SHA-256 and runs `libmagic` over attacker-controlled bytes, and an
  internet-facing service on a shared kernel is a weaker posture than the
  same service behind a hypervisor. This is a scheduled re-examination, not
  a known defect — recorded so the choice does not calcify by default.

---

## Submission

Sample bytes never touch the platform server's filesystem.

1. **`POST /api/v1/jobs`** — `{target_os, filename, size}`. The API validates
   `target_os` against the closed enum (`ubuntu`, `android`, `windows`),
   inserts a row at state `received`, and returns `job_id` plus a short-lived
   presigned **PUT** URL for `samples/<job_id>/<filename>`.
2. **The browser uploads directly to MinIO.** The API never proxies sample
   bytes, so a large sample does not occupy an application worker and the web
   process never holds malware in memory or on disk.
3. **`POST /api/v1/jobs/<id>/uploaded`** — the API `HEAD`s the object,
   streams it to compute SHA-256, and runs the type detection. Then it
   applies the admission checks `analysis-pipeline.md` already specifies, all
   before any clone exists:
   - size cap → `rejected` / `rejected_size`
   - empty or unreadable → `rejected` / `unreadable`
   - detected type contradicts `target_os` → `rejected` / `unsupported_type`

   Passing moves the job `admitted` → `queued`.

### Issue #3 is preserved, not reversed

`target_os` still comes from the submitter and is validated against the enum
at the submission boundary. File magic still **reports and never routes** —
it can reject a mismatch, and that is its only authority. What changes is the
carrier: a form field instead of a choice of incoming directory. That
substitution is the one `analysis-pipeline.md` already anticipated:

> The submitting user chooses the OS by choosing where to submit. For the M7
> web platform that is a form field mapping to a directory, validated against
> the enum at the submission boundary, where it is the only untrusted routing
> input in the system.

There is still exactly one untrusted routing input, and it is still validated
against a closed enum at one place.

---

## Queue and admission

### The orchestrator polls with its capacity, not for "the next job"

```text
POST /api/v1/worker/claim
  { worker_id, free_mib, free_vlans, free_slots }
```

The API owns the host-global order and answers one of two ways:

- **A lease** — `job_id`, `target_os`, `sha256`, the submitted filename, a
  presigned **GET** for the sample, and the result upload prefix.
- **A reservation** — `{status: "reserved", blocking_job_id, need_mib}`.
  Nothing is handed out.

### Why that second branch is the whole point

Greedy admission starves the largest clone. When each decision-maker sees only
its own decision, a big job waits for a window that smaller jobs keep
consuming as it frees — and every individual decision is correct while the
aggregate is not.

This was measured on 2026-08-20 against a three-watcher arrangement: 170
consecutive one-per-second admission holds, zero clones, while seven
later-arriving smaller jobs ran to completion. The starved job needed
6294 MiB, which is not a synthetic number — it is `misc/windows.cfg`'s
`memory = 6144` plus a per-host domain overhead. A Windows watcher sharing
this Dom0 with Ubuntu would never analyse anything.

Here there is one place that sees every job, so head-of-line reservation is a
property of a single SQL query rather than a distributed protocol:

```sql
-- Sketch, not tested. The head job either fits or blocks; nothing behind it
-- is handed out while it waits. FOR UPDATE SKIP LOCKED makes the claim and
-- the state transition one transaction, so a job cannot be popped without
-- its state moving.
SELECT id, target_os, required_mib
  FROM jobs
 WHERE state = 'queued'
   AND NOT cancel_requested
 ORDER BY queue_seq
   FOR UPDATE SKIP LOCKED
 LIMIT 1;
```

**Policy: strict head-of-line blocking.** A job at the head that does not fit
blocks the queue until it does. The obvious objection is convoying — one
Windows job stalling a queue of Ubuntu jobs — and the answer is that the wait
is *bounded*: `dirwatch`'s successor keeps the 60 s preconfig and 180 s trace
guards, so running clones release memory on a known ceiling rather than
never. Backfill (letting a small job run when it provably cannot delay the
reserved job) needs per-OS runtime estimates the project does not have, and
is deliberately deferred rather than approximated.

### Where `required_mib` comes from

The API cannot read Dom0's `.cfg` files, and duplicating the number on the
platform server would recreate exactly the failure `platform.env` exists to
prevent — two files free to disagree, with no loud symptom.

So the orchestrator **registers** it:

```text
POST /api/v1/worker/register
  { worker_id, total_vlans, total_slots,
    pipelines: [ {os: "ubuntu",  required_mib: 2198},
                 {os: "android", required_mib: 2198},
                 {os: "windows", required_mib: 6294} ] }
```

Each number is derived on Dom0 as `misc/<os>_sandbox.cfg`'s `memory` plus a
per-host domain overhead — `2048 + 150` for Ubuntu and Android, `6144 + 150`
for Windows. Windows is the outlier by roughly 3×, which is the entire reason
head-of-line reservation is not optional.

**The overhead figure is unresolved and must be measured on each host before
it is trusted.** Two observations from the same lab disagree: 112 MiB measured
directly, against ~2063 MiB consumed for a 2048 MiB clone. Neither is wrong on
its face — the measurement methods differ and nobody has reconciled them. Per
the project's standing preference, set the guard above the measured value and
keep both numbers in the comment. A second Dom0 needs its own pass; capacity
is a property of the machine even when the overhead is a property of Xen.

---

## Execution

`sandboxd` downloads the sample from its presigned GET and drives the
**unchanged** callback chain:

```text
clone.pl → preconfig-<os>.sh → drakvuf-<os>.sh → cleanup.sh
                                 (tcpdump.sh on a side thread)
```

C9's arity and order are preserved exactly — `clone.pl` takes 3 arguments and
prints a clone domain ID on success only; `preconfig-<os>.sh` and
`drakvuf-<os>.sh` are passed 8 and read the first 7; diagnostics go to stderr.
**No worker script changes**, and `platform.env` and `pipeline-<os>.env` stay
as they are, still sourced on Dom0 and still `${NAME:-default}` so the
environment wins.

This is the constraint that makes the change survivable. Replacing the
process model *and* the callback contract in one step leaves no working state
to fall back to.

State transitions post as they happen, reusing the machine already specified
in `analysis-pipeline.md`:

```text
received → admitted → queued → cloning → preparing → executing → collecting
                                                                      │
                                                 completed ← cleaning ┘
exits
  admitted           → rejected     admission failed; no clone made
  queued             → cancelled    cancelled before a clone existed
  cloning…executing  → cleaning → cancelled
  cloning…collecting → cleaning → failed        + failure_stage/failure_reason
  any non-terminal   → cleaning → interrupted   owning process died
```

---

## Artifacts and publication

Bucket layout:

```text
samples/<job_id>/<submitted filename>
results/<job_id>/trace.log
results/<job_id>/capture.pcap
results/<job_id>/memdump/…
results/<job_id>/extracted/…
results/<job_id>/manifest.json
```

**Keyed by `job_id`, not by SHA-256.** DRAFT-030 established that identical
bytes submitted under different names are separate runs with separate result
directories, because the submitted name is part of what is being analysed.
`sha256` is an indexed column for search and dedup reporting; it is not the
storage key.

Artifacts upload **directly to MinIO** via presigned PUTs requested from the
API — never through the API itself. Then one terminal call:

```text
POST /api/v1/worker/jobs/<id>/complete   { manifest }
```

The job is not `completed` until that row lands. A half-uploaded result set
is therefore never served as finished, which closes the atomic-publication
`KNOWN GAP` that DRAFT-018 currently carries: publication becomes a single
committed row rather than a directory that readers might catch mid-write.

---

## Status, history and cancellation

The browser reads `GET /api/v1/jobs/<id>` for polling, or subscribes to
`GET /api/v1/jobs/<id>/events` for server-sent events backed by Postgres
`LISTEN`/`NOTIFY`. History and search are ordinary queries against the jobs
table — which is the property a queue-only store would not have given.

Cancellation splits on whether a clone exists:

- **`received` / `admitted` / `queued`** — a single `UPDATE` to `cancelled`.
  No clone was ever made, so there is nothing to tear down.
- **`cloning` … `executing`** — set `cancel_requested`. The orchestrator sees
  it in its next heartbeat response and tears down through `cleanup.sh`,
  passing through `cleaning`.

The first case is the acceptance test DRAFT-040 named, and it is worth being
precise about why it was hard before: today a queued job is *a file in a watch
directory plus a worker spinning inside an admission loop*. It has no id and
no field to set, so cancelling it is unexpressible rather than merely
unimplemented. Here it is one row.

---

## Security posture

### What Dom0 holds

**One scoped API token**, valid only for `/api/v1/worker/*`.

**No MinIO credentials, ever.** Every object access is a presigned URL scoped
to a single key with a short TTL, issued by the API for a job Dom0 currently
holds a lease on. A sample that escapes into Dom0 therefore cannot enumerate
the bucket, read another job's artifacts, or reach the job history.

This is the concrete benefit of choosing the HTTPS API over letting Dom0
speak to Postgres directly. The database is reachable only by the API
process, so the blast radius of a compromised Dom0 is the set of jobs it is
currently leasing.

### Why there are no VLAN or memory lease files

DRAFT-040 recorded that VLAN leases and memory reservations should sit on
`flock`, because their requirement is **release on process death, and only on
death** — a TTL plus heartbeats would reassign a stalled-but-alive watcher's
VLAN while its clone was still running on that segment.

**That reasoning was about coordinating three watcher processes, and this
design has one.** With a single `sandboxd` owning every clone on the host,
VLAN and slot allocation is an in-process table behind a mutex. There is no
second process to coordinate with, so there is nothing for a lease file to
mediate. Building one anyway would be machinery with no contention to manage.

The underlying principle is kept, and is better served than `flock` served it:

- **A single-instance guard on the daemon**, not per-resource leases. Two
  `sandboxd` processes on one Dom0 is the only way the old collision returns,
  and one lock prevents it.
- **Startup reconciliation, not timeouts.** On start, `sandboxd` enumerates
  live domains and interfaces from `xl list` and `ip link`, rebuilds its
  allocation table from what actually exists, and declares the live job ids to
  the platform via `POST /api/v1/worker/reconcile` before accepting work.
  Reading the real state is strictly stronger than inferring it from whether a
  lock was released.

### The database lease is a different object

`lease_owner`/`lease_expires_at` in the jobs table govern **job record
ownership**, not a physical resource. A lapsed heartbeat marks a job
`interrupted` so it stops occupying the queue; it does not free a VLAN, and
nothing on the platform server can free one — the platform has no idea what a
VLAN is.

This distinction is worth stating plainly, because "the reservation must
survive a stall, so never use a TTL" and "the job lease expires on a TTL" look
contradictory and are not. The resource is reclaimed by reading Dom0's actual
state; only the *bookkeeping* expires.

### Untrusted input

`dirwatch`'s admission check rejects only `/` and control characters in a
submitted filename, so `"`, `$`, a backtick and `;` are all admissible — and
all are live inside a double-quoted guest shell word. Two consequences:

- **Everything `CLAUDE.md` says about never splicing an untrusted filename
  into a guest shell string still applies**, and applies *earlier* than
  before: the name now round-trips through a database and a JSON payload
  before reaching the guest, instead of living only in a worker struct. In
  Postgres it is data in a parameterised query. In the orchestrator it is a
  Python string passed as an `argv` element, never formatted into a command.
- **The name is also rendered in a browser.** That is new attack surface this
  design introduces and the current system does not have. Escape on output;
  do not sanitise on input, because the submitted name must reach the guest
  byte-exact — extension dispatch and `argv[0]` self-checks are real evasion
  surface, which is why DRAFT-030 stopped naming the guest file after its
  hash.

### Trust boundaries, stated

| Boundary | Holds | If it falls |
|---|---|---|
| L2 clone → Dom0 | Xen guest isolation | Attacker gets Dom0: one scoped API token, current leases only |
| Dom0 → L0 | Proxmox VM isolation, plus firewall rules denying Dom0 the internal network | Attacker gets the Proxmox host and everything on it, platform container included |
| Dom0 → platform | Scoped API token over mTLS | Attacker can update job state and upload artifacts; cannot read the DB or enumerate MinIO |
| Platform container → L0 | Unprivileged LXC, **shared kernel** | Attacker gets the Proxmox host. Weaker than a VM boundary by construction — the reason M8 revisits it |
| Browser → API | Session auth | Ordinary web auth surface; M8 owns multi-tenancy |
| Platform → internet | Out of scope here | M8 |

The first two rows are why the items the maintainer parked on 2026-08-21 —
verifying a sample cannot escape the Xen L2 guest, and Proxmox firewall rules
blocking Dom0 from the internal network — are prerequisites for this design
being worth its security claims, not independent hardening. **Neither is
designed here.** They are named so the dependency is visible.

The firewall work matters more with the platform in a container than it
would with a VM: Dom0 and the platform are both guests of the same L0, so
"Dom0 reaches only the API" has to be *enforced* at L0 rather than inferred
from the fact that nothing routes between them today.

---

## API surface

Candidate. Names and shapes are the design's, not an implementation's.

**Browser, session auth:**

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/jobs` | Create; returns `job_id` + presigned PUT |
| `POST /api/v1/jobs/{id}/uploaded` | Admission checks; `queued` or `rejected` |
| `GET /api/v1/jobs` | History, filter and search |
| `GET /api/v1/jobs/{id}` | Status, manifest, presigned GETs for artifacts |
| `GET /api/v1/jobs/{id}/events` | SSE, backed by `LISTEN`/`NOTIFY` |
| `POST /api/v1/jobs/{id}/cancel` | Cancel |

**Worker, scoped token, Dom0 only:**

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/worker/register` | Announce pipelines, `required_mib`, VLAN/slot totals |
| `POST /api/v1/worker/reconcile` | Startup sweep against `xl list` |
| `POST /api/v1/worker/claim` | Capacity in; lease or reservation out |
| `POST /api/v1/worker/jobs/{id}/state` | Transition, with `queue_reason`/`failure_*` |
| `POST /api/v1/worker/jobs/{id}/heartbeat` | Keepalive; response carries `cancel_requested` |
| `POST /api/v1/worker/jobs/{id}/artifacts` | Request presigned PUT URLs |
| `POST /api/v1/worker/jobs/{id}/complete` | Manifest; terminal state |

---

## Schema sketch

Candidate. One table carries the state model; the fields are the ones
`analysis-pipeline.md` already names.

```text
jobs
  id                 uuid primary key
  created_at         timestamptz
  updated_at         timestamptz
  owner              text        -- reserved, M8
  visibility         text        -- reserved, M8
  target_os          enum(ubuntu, android, windows)
  submitted_filename text        -- data only; never interpolated anywhere
  sha256             text  indexed
  size_bytes         bigint
  detected_type      text        -- advisory; reports, never routes
  type_identifiers   jsonb
  state              enum(...)   -- the state machine above
  queue_seq          bigserial indexed   -- host-global order
  required_mib       integer
  queue_reason       text
  failure_stage      text
  failure_reason     text
  cleanup_status     text
  attempt            integer
  cancel_requested   boolean
  lease_owner        text        -- worker_id
  lease_expires_at   timestamptz
  clone_domain       text        -- nullable; reconciliation key
  vlan               integer     -- nullable; recorded, not authoritative
  manifest           jsonb       -- nullable until complete
```

`vlan` and `clone_domain` are **recorded for diagnostics and reconciliation,
not authoritative**. The authority is Dom0's live state — `xl list`,
`ip link` — and a row disagreeing with it is stale, not binding.

---

## Why not Redis, and what would change the answer

Redis was considered and deferred rather than rejected. The pros are real:
`rq-dashboard` for operational visibility, ready-made retry semantics, and a
natural home for sessions, rate limiting and caching. It is also what
`drakvuf-sandbox` uses — though *how* they use it has still not been read
from source, so that remains a weak signal (DRAFT-040 PLAN step 2 is owed).

It was deferred for one reason that outweighs those: with the queue in Redis
and the status in Postgres, **claiming a job and transitioning its state stop
being one transaction**. That is the classic double-run and lost-job bug, and
worse here, cancelling a queued job becomes two writes across two stores with
no transaction — the single operation this whole design is measured against.

One argument that is often made for Redis and does **not** apply: absorbing
high-frequency status writes. At one Dom0, at most eight concurrent clones,
and a state change every few seconds, Postgres will not notice.

**What would change the answer:** web-side background work that is not
analysis — report rendering, retention sweeps, enrichment lookups,
notifications. When that appears, Redis becomes additive rather than a
redesign, precisely because the HTTPS API already isolates Dom0 from the
store. Adding it then costs a new component; adding it now costs the
correctness property above.

---

## What this changes in `automation/`

Nothing yet — this document builds nothing. What it *implies*, for the
implementation issues that follow:

- **`dirwatch.c` is replaced by `sandboxd`, in Python.** This settles
  DRAFT-010's open C-vs-Python question. The work is now HTTP, database and
  S3 calls, retry and backoff, a state machine and cancellation — libraries in
  Python, hand-written in C. `dirwatch`'s thread pool and `inotify` watcher
  are most of what is lost, and `inotify` stops being how jobs arrive.
- **The five worker scripts are untouched.** C9 holds.
- **`platform.env` and `pipeline-<os>.env` are untouched**, still sourced on
  Dom0.
- **`MAX_CLONES` and `WATCH_MODE`** need re-homing: under one orchestrator
  there is one pool and one loop, so a per-OS value for either has no
  referent. This is a C3→C4 migration and belongs to the implementation
  issue.
- **The `argc != 15` CLI contract dies**, and with it the three
  `run_analysis-<os>.sh` launchers collapse into one. Note that
  `docs/drakvuf-on-xen-nested-within-proxmox.md:531` builds `dirwatch.c` by
  name; that file is an **imported source guide and is never edited in
  place** — the discrepancy is recorded here instead.
- **The `vlan-lease` prototype is not inherited.** That branch added C-side
  memory admission and `flock` VLAN leases to `dirwatch.c` to make three
  watcher processes safe to run concurrently. This design has one orchestrator
  and puts the ordering on the platform server, so both are replaced rather
  than ported. DRAFT-036's three items are superseded, not completed: memory
  admission becomes the queue's head-of-line reservation, the host-global VLAN
  allocator becomes an in-process table, and anti-starvation is the SQL query
  above. The branch's value was the measurement, which is kept.

---

## Open questions

Not blocking the design, but each has to be answered before the matching
implementation issue:

1. **Network path between the two VMs, and API authentication.** Assumed for
   now: Dom0 (a VM) and the platform (an LXC) are guests of the same L0, on
   a private bridge that is neither the analysis bridge nor the clone
   uplink, with **mTLS** between `sandboxd` and the API so both ends are
   pinned. Because they share a host, the Proxmox firewall is what makes
   "Dom0 reaches the API and nothing else" true; it is not true by topology.
   If they ever end up on separate hosts, this needs WireGuard rather than
   bare TLS, and the assumption should be corrected here rather than in the
   implementation.
2. **Does `/malware_incoming/<os>` survive as an operator submission route?**
   Recommended: keep it, but as a thin local adapter that calls the same API
   over localhost, so there is exactly one queue and one order — not a second
   path into the orchestrator that bypasses admission.
3. **Artifact retention.** Memdumps are large and pcaps carry third-party
   traffic; DRAFT-022's GDPR position gets harder the longer both are kept.
   No policy is set here.
4. **Multi-tenancy.** `owner` and `visibility` are reserved columns and
   nothing populates them. M8 owns this; the design must not foreclose it.
5. **Backfill.** Deferred, and needs per-OS runtime estimates before it can be
   attempted.

---

## Prerequisites this design assumes but does not provide

Recorded on 2026-08-21 at the maintainer's direction, as work for the coming
days:

- **A sample must not escape the Xen L2 guest.** Untested. The first trust
  boundary in the table above rests on it.
- **Dom0 must not reach the Proxmox internal network.** To be enforced with
  Proxmox firewall rules. Until it is, "a compromised Dom0 reaches only the
  API" is a design intent rather than an enforced property.

Neither is designed here, and neither should be assumed discharged by the
existence of this document.