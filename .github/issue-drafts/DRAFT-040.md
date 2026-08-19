# DRAFT-040: Decide the job-queue and web↔Dom0 communication architecture

**Status:** Drafted, not published. **Decision issue** — it settles an
architecture question and produces no automation of its own.
**Area:** core/platform
**OS:** ALL
**Milestone:** M1 → gates M7
**Priority:** P1
**Depends on:** DRAFT-036 items 1 and 2 produced it — implemented in PR #15
and awaiting a Dom0 build, so "landed" is not yet the right word.
Couples tightly to **DRAFT-010** (C vs Python) and **DRAFT-035**
(cancellation). Informs **DRAFT-018** (result schema).
**Origin:** DRAFT-036's item 3 could not be designed without it; raised by
the maintainer on 2026-08-19 while reviewing the VLAN lease.

# Objective

Decide **where job state lives, how jobs are ordered, and how the future
web platform and Dom0 talk to each other** — as one decision, because
three separate needs have converged on the same mechanism and answering
them independently produces three mechanisms.

This issue decides and records. It does not build the web platform.

# Context

## The premise that expired

`docs/roadmap/project-roadmap.md` decision #6 reads: *"Job-queue technology
for the eventual orchestrator — low urgency, revisit near M7."* That was
correct when written. It is not now, for a reason that has nothing to do
with the web platform arriving sooner:

**Three things that looked separate all need the same thing.**

1. **Anti-starvation** (DRAFT-036 item 3). Memory admission landed greedy,
   and greedy admission starves the largest clone — a 6 GiB Windows clone
   waits for a window that smaller Ubuntu and Android jobs keep consuming,
   while every individual decision is correct. The fix is head-of-line
   reservation, which needs a **host-global order** over jobs.
2. **Cancellation** (DRAFT-035). The state model says cancelling in
   `received`/`admitted`/`queued` is immediate because no clone exists
   (`analysis-pipeline.md`). Today a queued job has **no record anywhere**
   — it is a file in a watch directory plus a worker spinning inside
   `admission_try_reserve()`. There is no id to name it by and no field to
   set. Cancellation of a queued job is not merely unimplemented; it is
   unexpressible.
3. **Web↔Dom0** (M7). The web tier must submit jobs, read state, and
   cancel. All three are the same channel.

Deferring means building a filesystem-shaped queue now and discarding it
at M7. That is the cost the deferral was meant to avoid.

## What is already recorded, and is correct

`docs/roadmap/project-roadmap.md`'s reuse table:

> | Task/job queue (Flask + RQ + Redis) | Reuse/Adapt | Simple,
> well-understood; adaptable to drive Xen/LVM/OVS clones instead of
> snapshot restores. |

**Verified against upstream 2026-08-19**, from
`CERT-Polska/drakvuf-sandbox`'s `requirements.txt` at `master`:

```text
rq==2.9.0
rq-dashboard==0.8.7
Flask==3.0.3
flask-openapi3[swagger]==4.1.0
boto3==1.35.81
msgpack==1.0.8
karton-core>=5.9.0,<6.0.0
```

So the note is accurate and current: **RQ over Redis**, Flask for the API,
`boto3` for artifact storage, with Karton an optional integration rather
than the backbone.

> **Scope of that verification, stated so it is not over-read.** This is
> the dependency manifest only. Nobody here has read how `drakvuf-sandbox`
> *uses* RQ — its queue names, its retry/visibility semantics, or how the
> worker reaches the Xen host. Do not treat "they use RQ" as evidence that
> a particular usage pattern works. PLAN step 2 reads the source.

## What must NOT move

**VLAN leases and memory reservations stay on `flock`.** This is not
inertia; it is a property the alternatives do not have.

Their defining requirement is *release on process death, and only on
death*. `flock` gets that from the kernel. A broker-held lease needs a TTL
plus heartbeats, and a watcher that **stalls rather than dies** past its
TTL would have its VLAN reassigned while its clone is still running on
that segment — which is precisely the defect DRAFT-036 just removed,
reintroduced with extra machinery.

The split is therefore by responsibility, not by preference:

| Concern | Mechanism | Why |
|---|---|---|
| VLAN lease, memory reservation | `flock` on `$DRAKVUF_LEASE_DIR` | Host-local; kernel-released on death; never on delay |
| Job identity, queue order, state, cancellation | To be decided here | Cross-host; needs ordering and addressability by id |
| Artifacts (pcap, memdump, extracted files) | To be decided here | Blobs; a broker is the wrong shape |

# The decisions

## D1 — Does job state move off the filesystem?

**Recommend: yes.** A FIFO with head-of-line reservation, addressable by
id, readable by another host, is a sorted set and a hash. Building that on
lock files reimplements a broker badly, and the result is still
single-host.

Counter-argument to weigh: it adds a daemon and a dependency to a lab that
currently has neither, and the filesystem approach is running today.

## D2 — RQ, or Redis as a plain broker?

This is the consequential one, because **it largely decides DRAFT-010**.

- **RQ.** Python library. Its job payloads and worker protocol are
  Python-side, so an *RQ worker* cannot be written in C. Adopting it means
  `dirwatch`'s replacement is Python. Gains: `rq-dashboard`, retry and
  failure semantics already written, and alignment with the closest prior
  art.
- **Redis as a plain broker**, via `hiredis` from C. `dirwatch` stays C and
  the investment in it is kept. Cost: the queue semantics — reliable pop,
  visibility timeout, requeue-on-crash, ordering — are written by hand,
  which is exactly the class of thing that is subtly wrong for months.

> **Correction to an earlier framing, recorded so it is not repeated.**
> This was initially put as "you cannot speak Redis from C". That is
> wrong — `hiredis` is a mature C client and the C path is entirely
> viable. The real constraint is narrower and only about RQ: its job
> serialization and worker loop are Python. Stating it the broad way would
> have foreclosed a legitimate option.

**No recommendation is made here.** It belongs to DRAFT-010, which owns
the C-vs-Python question, and this issue should hand it the constraint
rather than pre-empt the decision.

## D3 — Where do Redis and the web tier run?

**Recommend: a separate L1 VM under Proxmox, sibling to Xen Dom0.**

Not on Dom0. Dom0 runs malware, and putting an inbound-listening web
service on it inverts the containment posture DRAFT-028/029 built. It also
discards the property that makes the pull model attractive — that Dom0
needs no listener at all.

Sizing is not a constraint: job records are kilobytes and there are
thousands, not millions. 2 GiB and 2 vCPUs is generous. It comes out of
L0's budget, **not** Dom0's — `dom0_mem` is pinned at 8192M and the clone
pool sits above it, both untouched.

Secondary benefit: independent lifecycles. Dom0 can be rebooted — which is
how the lab recovers from a bad clone — without losing queue state.

## D4 — Which side dials?

**Recommend: Dom0 dials out. No inbound listener on Dom0, ever.**

RQ's model is that workers pull. Dom0 connects outward to Redis; the web
tier connects outward to Redis; neither can reach the other. This is
consistent with the existing `DRAKVUF_INPUT` posture and it survives the
web tier eventually being internet-facing at M8.

The trade, stated plainly: **Redis becomes a trust boundary.** If a sample
escapes into Dom0 it holds Redis credentials. The worker therefore needs a
scoped Redis ACL user — its own queues, no admin commands, no `CONFIG`, no
`FLUSHALL` — rather than the default full-access user. This must be
decided before anything is built, not retrofitted.

## D5 — How do artifacts reach the web tier?

**A broker is not for blobs.** Results live on Dom0 at
`/malware_finished/<sha256>/<analysis_id>/` — pcaps, memdumps, extracted
files, and `dump/` — and can be large.

Options, none recommended yet:

- **Object storage** (MinIO/S3, `boto3`), which is what upstream does.
  Dom0 pushes on completion. Clean separation; adds another service.
- **Authenticated pull from Dom0.** Fewer moving parts, but it means an
  inbound listener on Dom0, which D4 exists to avoid.
- **Read-only export from Dom0** to the web VM. Simplest, but the web VM
  then mounts a filesystem full of malware artifacts.

This interacts with **DRAFT-018**, which owns the result schema and the
atomic-publication boundary that is still an open `KNOWN GAP`.

# Dependencies

- **DRAFT-010** — receives D2 as a constraint. This issue must not decide
  C-vs-Python; it must make the consequences of each explicit.
- **DRAFT-035** — cancellation is the acceptance test for whatever is
  chosen. A design that cannot cancel a *queued* job has failed.
- **DRAFT-036 item 3** — head-of-line reservation is built on the outcome.
- **DRAFT-018** — D5 overlaps its storage-layout and publication work.
- **DRAFT-022** — a web tier that accepts third-party submissions changes
  the GDPR position materially; that is DRAFT-022's, but this issue must
  not design something that forecloses it.

# Out of scope

- Building the web platform (M7).
- Implementing head-of-line reservation (DRAFT-036 item 3).
- Implementing cancellation (DRAFT-035).
- Rewriting `dirwatch` (DRAFT-010).
- Moving VLAN leases or memory reservations off `flock` — decided above,
  and deliberately closed rather than left open.
- Authentication and multi-tenancy (M8). `owner`/`visibility` are already
  reserved in the state model; this issue must not design the auth system
  that eventually populates them.

# PLAN

1. **Write down the three converging needs** and confirm with the
   maintainer that one mechanism is intended to serve all three. If the
   answer is no, this issue collapses to "add a retry-ordering hack" and
   should be closed.
2. **Read `drakvuf-sandbox`'s actual RQ usage** — queue names, worker
   entry points, how the worker reaches the Xen host, what it puts in a
   job payload, and how it reports progress. The dependency manifest is
   evidence of *what* they use, not *how*. Record file:line, per this
   project's evidence discipline.
3. **Prototype nothing on Dom0.** A Redis instance and a toy producer and
   consumer on the development container is enough to answer the questions
   that matter: does a crashed worker requeue, and how is a queued job
   cancelled.
4. **Decide D1, D3, D4, D5.** Hand D2 to DRAFT-010 with both consequences
   written out.
5. **Record the decision** in `docs/architecture/` as a new document —
   this is a third architecture concern alongside the analysis pipeline
   and networking, not a section of either.
6. **Correct roadmap decision #6** to point at that document rather than
   at "revisit near M7".

# Acceptance criteria

- [ ] D1, D3, D4 and D5 are decided and recorded with reasoning, in
      `docs/architecture/`.
- [ ] D2 is handed to DRAFT-010 as a stated constraint, with the RQ and
      plain-Redis consequences written out and **no recommendation made
      here**.
- [ ] `drakvuf-sandbox`'s RQ usage is read from source and cited with
      file:line, not inferred from `requirements.txt`.
- [ ] The chosen design can express **cancelling a job that has no clone
      yet**. This is the acceptance test, because it is what today's
      arrangement cannot do at all.
- [ ] The chosen design can express **head-of-line reservation** across
      more than one watcher.
- [ ] VLAN leases and memory reservations are explicitly recorded as
      staying on `flock`, with the stall-vs-death reasoning, so it is not
      revisited as an oversight.
- [ ] Roadmap decision #6 is updated; its "low urgency" premise is
      annotated as expired rather than deleted.
- [ ] No `automation/` file changes. This issue decides; it does not
      build.

# Security considerations

- **Dom0 must not gain an inbound listener.** This is the single hardest
  constraint in the issue and D4 exists to hold it. Any design requiring
  the web tier to connect *into* Dom0 should be rejected on this ground
  alone.
- **Redis is a trust boundary once Dom0 holds credentials for it.** Scoped
  ACL user, no admin commands. A compromised Dom0 must not be able to read
  other tenants' jobs or flush the queue.
- **Job payloads carry attacker-influenced data** — submitted filenames,
  at minimum. Everything `CLAUDE.md` says about not splicing untrusted
  filenames into shell strings applies to whatever deserializes a job.
  Note specifically: **RQ's default job serialization is Python `pickle`**,
  which is unsafe against a queue an attacker can write to. If RQ is
  chosen, the serializer and the queue's write access both need a decision.
- **A web tier accepting third-party samples changes the legal position**
  (DRAFT-022): GDPR exposure through pcaps and memdumps stops being about
  one operator's own samples.

# Recovery / rollback

Entirely a documentation change. Nothing in `automation/` is touched and
no deployed behaviour changes, so rollback is reverting a document. The
decision it records is reversible until DRAFT-036 item 3 or DRAFT-035
builds on it, which is the argument for taking it now rather than after.
