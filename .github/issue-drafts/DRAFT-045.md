# DRAFT-045: The web UI — submission, history, and live job status

**Status:** **[#38](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/38) — published 2026-08-22, OPEN.**
**Area:** core/platform
**OS:** ALL
**Milestone:** M1 → gates M7
**Priority:** P1 — the first piece an operator actually touches, and the
last of the four desk-only pieces.
**Depends on:** **DRAFT-043** (API) — hard. **DRAFT-044** for the upload
path.
**Needs Dom0:** **No.** Driven end to end against the fake worker DRAFT-043
delivers.

# Objective

The operator-facing surface: submit a sample against a chosen OS, watch a
run progress, and read what came out. Nothing more — this is the first
milestone's UI, not the eventual product.

# Context

## Why this is the smallest of the four, and should stay that way

The three issues before it carry the properties that are hard to get right:
head-of-line reservation, credential scoping, atomic publication. This one
renders their results. The risk here is scope, not difficulty — a UI is
where "while we're at it" lands, and every feature added now is one built
before anyone has used the thing once.

## The one genuinely new attack surface

**The submitted filename is rendered in a browser.** The current system has
no such surface: a name goes from a watch directory into an `argv` vector
and never gets displayed anywhere. Now it round-trips through a database, a
JSON payload and a page.

The rule, and it runs the opposite way to the instinct:

> **Escape on output. Never sanitise on input.**

The name must reach the guest **byte-exact** — extension dispatch and
`argv[0]` self-checks are real evasion surface, which is exactly why
DRAFT-030 stopped naming the staged guest file after its hash. A UI that
strips quotes to make rendering safe silently changes what gets analysed.

# Dependencies

- **DRAFT-043** — every endpoint this consumes.
- **DRAFT-044** — presigned POST for upload, presigned GET for artifacts.

# Out of scope

- **Authentication beyond a single operator session.** No user accounts, no
  registration, no roles. M8, and `owner`/`visibility` stay unread.
- **Cancellation UI.** The API supports it; wiring a button is trivial and
  belongs with the cancellation issue that proves the whole path, not here.
- **Result *interpretation*** — no trace viewer, no behavioural summary, no
  capa integration (DRAFT-019). Artifacts are downloadable, not analysed in
  the browser.
- **Search beyond the API's filters.** Whatever `GET /api/v1/jobs` supports.
- **Multi-host views.** One analysis host.

# PLAN

1. Pin the rendering approach (see CREATE — server-rendered, with the
   reason).
2. Build the three views against the API.
3. Wire SSE for live status, with a polling fallback.
4. Prove the escaping rule with hostile names before building anything else
   on top.

# CREATE

## Server-rendered templates plus a little JavaScript

**Recommend server-rendered HTML** — Jinja templates from the same FastAPI
service — with JavaScript only where the page genuinely needs it: the direct
upload to MinIO, and the SSE subscription.

A single-page application is the reflex and is rejected here. It adds a
build toolchain, a second deployment artifact and a second place where
escaping can go wrong, in exchange for interactivity three read-mostly views
do not need. Server-rendered templates also make the escaping rule
*structural*: Jinja autoescapes by default, so the dangerous thing becomes
the explicit `| safe` that a reviewer can grep for, rather than the absent
call nobody notices.

If the UI later grows into a product surface, that is a deliberate rewrite
with a reason — not a decision made now by picking a framework.

## The three views

### Submit

A form: OS radio (`ubuntu` / `android` / `windows`) and a file picker. On
submit the page calls `POST /api/v1/jobs`, uploads directly to MinIO with
the presigned POST, then calls `POST /jobs/{id}/uploaded` and redirects to
the job view.

The OS control is a fixed set of three radios rendered from the enum —
**not** a free-text field, and not a list fetched from anywhere mutable.
Issue #3's decision is that this is the only untrusted routing input in the
system, and it is validated server-side regardless; the UI matching that
shape is what stops someone later "improving" it into an autocomplete.

Two states worth designing rather than leaving to chance, because both are
normal:

- **Upload progress**, since a Windows sample on a slow link is not instant
  and a silent form reads as broken.
- **`no_workers` and `no_capacity` rejections**, which are the honest answer
  on a fresh install and after a retune respectively. Both should say what
  they mean — "no analysis host has registered" and "no registered host is
  large enough to run a Windows job" — not "submission failed".

### Job

The state, the timeline, and the artifacts. Live via SSE.

The design point: **`queued` is not a failure and must not look like one.**
When a job holds because a larger job is at the head of the queue, the page
should say so — *"waiting: a job is reserved ahead of this one"* —
using `queue_reason` and the reservation the API already reports. The
measured failure mode this whole architecture exists to remove was a silent
hold with correct-looking logs; reproducing that in a UI would be a poor
joke.

`rejected` and `failed` render `failure_stage` and `failure_reason`
verbatim, because a reason the operator cannot see is a reason that costs a
Dom0 session to rediscover.

### History

A table: submitted name, OS, state, created, duration. Filters passed
straight through to the API. Keyset pagination, matching the API — an
`OFFSET`-based UI over a table that grows without bound degrades quietly.

Rows link to the job view. Identical bytes under two names are **two rows**,
which is correct and is worth showing plainly — it is the visible
consequence of keying on `job_id` rather than content digest.

## Live status

`EventSource` against `GET /api/v1/jobs/{id}/events`, backed by Postgres
`LISTEN`/`NOTIFY`. No Redis, no polling loop.

**A polling fallback is required, not optional.** SSE dies on proxies,
sleeping laptops and lost connections, and the failure mode is a page frozen
on a stale state — which is indistinguishable from a stuck analysis. Fall
back to `GET /api/v1/jobs/{id}` on an interval when the stream drops, and
show that it happened.

# TEST

`pytest` plus a headless browser, against the API and the fake worker
DRAFT-043 delivers. No Dom0.

1. **Submit to completion.** Choose an OS, upload, watch the job reach
   `completed` driven by the fake worker, download an artifact.
2. **XSS, thoroughly.** Submit names containing `<script>alert(1)</script>`,
   `"><img src=x onerror=alert(1)>`, `'; DROP TABLE jobs; --`, a
   javascript: URL, and unicode direction-override characters. Each must
   render as text in **all three** views, and — the half that is usually
   missed — must still be **byte-identical** in the API response and in the
   object key. Escaping the display must not have changed the value.
3. **`queued` with a reservation** renders as waiting-with-a-reason, not as
   an error or a spinner.
4. **Every reject reason renders a distinct, actionable message** — the five
   from DRAFT-043 plus `no_workers`.
5. **SSE fallback.** Kill the stream mid-run; assert polling takes over and
   the page says so.
6. **Two jobs, identical bytes, different names** appear as two rows with
   two artifact sets and one shared `sha256`.
7. **Oversized upload** is refused by the MinIO policy, and the page
   explains it rather than failing silently.
8. **No `| safe`** on any user-supplied value — a grep, run in CI, because
   this is the rule that will be broken later by someone making a table
   render nicely.

# DEPLOY

Served by the same FastAPI process as the API, in the platform LXC. No
separate deployment artifact, no build step — which is most of the argument
for server-rendered templates.

Rollback is redeploying the previous version. Nothing else depends on the
UI; the pipeline runs headless.

# Acceptance criteria

- [ ] Submit, job and history views exist and work against a real API.
- [ ] A sample can be submitted and driven to `completed` by the fake
      worker, with artifacts downloadable — test 1.
- [ ] Hostile filenames render as text in all three views **and** remain
      byte-exact end to end — test 2. Both halves, or the criterion is not
      met.
- [ ] The OS control is three fixed radios rendered from the enum.
- [ ] `queued` states show `queue_reason` and say that a job is reserved
      ahead — **without** naming that job's id or its memory footprint.
      Those are another submitter's details under M8, and a message format
      is not a thing anyone revisits when auth lands — test 3.
- [ ] All six reject reasons have distinct messages — test 4.
- [ ] SSE degrades to polling visibly — test 5.
- [ ] No `| safe` on user-supplied values, enforced by a CI grep — test 8.
- [ ] No result interpretation, no cancellation button, no auth beyond the
      operator session. Scope held.
- [ ] No `automation/` file changes.

# Evidence required

- Test output, all eight groups.
- Screenshots of the three views, including a `queued`-with-reservation job
  and a rejected one — these are the two states most likely to be designed
  badly and never noticed.
- For test 2, a side-by-side of the rendered HTML and the API's raw JSON for
  the same job, showing the escaping is in the rendering and not in the
  value.

# Security considerations

- **Escape on output, never sanitise on input.** The single rule this issue
  turns on. A sanitising UI silently changes what gets analysed, and would
  do it in a way that only shows up as a sample behaving differently in the
  sandbox than in the wild — the worst possible failure for this project.
- **Artifacts are malware.** A downloaded pcap or extracted file is hostile
  content. Serve with `Content-Disposition: attachment` and a
  non-executable content type; never render an artifact inline; never
  preview an extracted file in the browser.
- **A strict CSP**, with no inline script, so an escaping miss is not
  immediately an execution. Defence in depth, not a substitute for test 2.
- **The operator session is the only auth**, and this UI is not
  internet-facing at M1. It becomes so at M8, which is also when the
  platform's LXC-versus-VM choice is re-examined — the two are the same
  exposure change and should be looked at together.
- **`sha256` is displayed and is safe to display.** The submitted filename
  is neither of those things by default.

# Documentation changes

- **Updated:** `docs/architecture/platform.md` — the submission path
  currently describes an intended flow; point it at the implementation.
- **New:** a short operator note — how to submit, what the states mean, and
  specifically that a held `queued` job is the system working rather than a
  stall. That last point is the one that will otherwise generate a support
  question from the operator to themselves in six months.

# Recovery / rollback

Stateless; rollback is redeploying the previous version. No migration, no
data change. The pipeline is unaffected by the UI being down.
