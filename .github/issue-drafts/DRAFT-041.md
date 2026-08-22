# DRAFT-041: Decide the analysis platform architecture — web tier, job store, and Dom0

**Status:** **[#34](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/34) — published 2026-08-22, OPEN.** **Decision issue** — it settles an
architecture question and produces documentation, not automation.
**Area:** core/platform
**OS:** ALL
**Milestone:** M1 → gates M7
**Priority:** P0 — it re-answers DRAFT-040's D1/D3/D4/D5, settles DRAFT-010's
open C-vs-Python question, and supersedes DRAFT-036. Every remaining Track C
item is downstream of it.
**Depends on:** nothing open. DRAFT-040 raised the questions this answers.
**Decides for:** DRAFT-010 (Python), DRAFT-035 (cancellation becomes an
`UPDATE`), DRAFT-036 (superseded outright), DRAFT-018 (atomic publication
becomes a committed row).
**Origin:** the maintainer, 2026-08-21 — the analysis pipeline should be
driven by a web tier with its own database and object storage, on a separate
server from Dom0, with a safe channel between them.

# Objective

Decide and record where job state lives, how jobs are ordered, how samples and
results move, and how the web tier and Dom0 talk to each other — as one
decision, because they are one mechanism.

This issue decides and records. It builds nothing, and changes no file under
`automation/`.

# Context

## Why the earlier framing was abandoned

Two things were in flight on 2026-08-20 and both are closed by this decision
rather than continued.

**PR #15 / the `vlan-lease` branch is abandoned.** It added C-side memory
admission and `flock` VLAN leases to `dirwatch.c` so that three concurrent
watcher processes would stop colliding. That was the right fix for the process
model it targeted, and this design does not have that process model: one
orchestrator, with the ordering on a different server. The branch is not
merged, not ported, and not a dependency of anything below.

**A narrower DRAFT-041 was started and discarded the same day.** It asked "one
multi-OS orchestrator, or three?" and assumed the queue would be an in-process
ordered list, which meant designing a config-file replacement for `dirwatch`'s
`argc != 15` contract. With the queue in Postgres on another server the
question answers itself — there is one orchestrator on Dom0 because there is
one host-global queue and it does not live on Dom0 at all. Recorded here so
the reasoning is not re-derived.

## What survives from that work: the measurement

Greedy admission starves the largest clone. Measured on 2026-08-20 against a
three-watcher arrangement:

```
grep -c 'Holding: need 6294' starve-android.log   -> 170
grep -c 'Making clone'       starve-android.log   -> 0
grep -c 'Finished processing' starve-ubuntu.log   -> 7
```

170 consecutive one-per-second admission holds, zero clones, the large sample
never executed — while seven later-arriving smaller jobs ran to completion.
Every individual admission decision was correct; the aggregate was not,
because each watcher saw only its own.

**6294 MiB is the Windows number**, not a synthetic one: `misc/windows.cfg`
sets `memory = 6144`, and a per-host domain overhead is added on top. Ubuntu
and Android are both `memory = 2048`. So Windows is the outlier by roughly 3×,
and the measurement says a Windows watcher sharing this Dom0 with Ubuntu would
never analyse anything.

This finding is a property of greedy admission in general, not of the
prototype it was observed on, which is why it outlives the branch.

**One honesty note:** the watcher was SIGKILLed ~170 s in by something still
unidentified — not the `pgrep` guard (removed for the test), not `cleanup.sh`
(its greps match a *clone* name), and not the kernel OOM killer (`dmesg` is
empty). The honest claim is "held for the 170 s it was alive", not "held
across all twelve samples".

## Windows makes it urgent

As of **2026-08-21** the coupling `issue-index.md` predicted in the abstract
is concrete: the golden Windows domain is installed with Defender disabled,
and the `windows_sandbox` LV has been cloned from it (`misc/windows_sandbox.cfg`
and the LibVMI profile still outstanding). The guest that triggers the
starvation case now exists.

The failure mode if this is not fixed first is worth naming, because it is not
an error: **one admission-hold line per second, forever, no clone, nothing in
the logs to explain it.**

# The decisions

Recorded in full, with reasoning, in **`docs/architecture/platform.md`** — the
third architecture concern alongside `analysis-pipeline.md` and
`networking.md`, which discharges DRAFT-040 PLAN step 5.

| # | Decision | Supersedes |
|---|---|---|
| 1 | **MinIO on the platform server** for samples and results | DRAFT-040 D5, which made no recommendation |
| 2 | **Postgres holds both job state and the queue**; Redis deferred | DRAFT-040 D1 |
| 3 | **Dom0 polls an HTTPS API**; no inbound listener on Dom0, ever | DRAFT-040 D4, confirmed and made concrete |
| 4 | **The platform runs in an unprivileged LXC on L0**, sibling to Dom0 | DRAFT-040 D3, which assumed a VM |
| 5 | **`sandboxd` is written in Python** | DRAFT-010's open question |

Three properties are what the design is measured on:

- **Head-of-line reservation is a SQL query.** The orchestrator polls with its
  *capacity* (`free_mib`, `free_vlans`, `free_slots`) and the API answers with
  either a lease or a reservation. A 6294 MiB job at the head blocks the
  2198 MiB jobs behind it instead of being starved by them.
- **Cancelling a queued job is one `UPDATE`.** DRAFT-040's stated acceptance
  test — today unexpressible rather than merely unimplemented, because a
  queued job is a file in a directory plus a spinning worker, with no id and
  no field to set.
- **Publication becomes a committed row.** Artifacts upload to MinIO, then one
  terminal call carries the manifest; a job is not `completed` until that row
  lands. This closes DRAFT-018's atomic-publication `KNOWN GAP`.

## Why there are no lease files

DRAFT-040 recorded that VLAN leases and memory reservations belong on `flock`,
because they must release **on process death and only on death**. That
reasoning was about coordinating three watcher processes, and this design has
one. VLAN and slot allocation becomes an in-process table; there is no second
process for a lease file to mediate.

The principle is kept and better served: a single-instance guard on the
daemon, plus startup reconciliation that rebuilds the allocation table from
`xl list` and `ip link`. Reading the real state is stronger than inferring it
from whether a lock was released.

The database's `lease_owner`/`lease_expires_at` are a different object — they
govern job *record* ownership, and a lapsed heartbeat marks a job
`interrupted` without freeing anything on Dom0.

## What does not change

- **Issue #3.** `target_os` still comes from the submitter, validated against
  a closed enum at one boundary; file magic still reports and never routes.
  The carrier becomes a form field instead of a directory choice — the
  substitution `analysis-pipeline.md` already anticipated for M7.
- **C9, the callback contract.** `clone.pl`, `preconfig-<os>.sh`,
  `drakvuf-<os>.sh`, `cleanup.sh` and `tcpdump.sh` keep their arity and order.
  **No worker script changes.** This is the constraint that makes the change
  survivable: rewriting the process model *and* the callback contract at once
  leaves no working state to fall back to.
- **`platform.env` and `pipeline-<os>.env`.** Still sourced on Dom0, still
  `${NAME:-default}` so the environment wins and CI overrides without patching
  files.

# Dependencies

- **DRAFT-040** — D1/D3/D4/D5 answered here; D2 (RQ vs plain Redis) becomes
  moot under decision 2.
- **DRAFT-010** — receives Python as its answer. No longer a documentation
  chore.
- **DRAFT-036 / issue #33** — superseded, not completed. Memory admission
  becomes the queue's head-of-line reservation; the host-global VLAN allocator
  becomes an in-process table; anti-starvation is the SQL query. The issue
  should be closed with that reasoning rather than left open against work that
  is no longer planned.
- **DRAFT-035, DRAFT-018** — become downstream implementation work.
- **Track D (Windows)** — supplies the guest that makes the starvation case
  real. Coupling, not a blocker in either direction.

# Out of scope

- **Building any of it.** The implementation issues are proposed below, not
  drafted here.
- **The two security prerequisites** the maintainer parked on 2026-08-21:
  verifying a sample cannot escape the Xen L2 guest, and Proxmox firewall
  rules blocking Dom0 from the internal network. Both are named in
  `platform.md` as assumptions this design rests on; neither is designed here
  and neither should be assumed discharged.
- **Authentication and multi-tenancy (M8).** `owner` and `visibility` are
  reserved columns; this issue must not design what populates them.
- **Artifact retention policy.** Named as an open question; interacts with
  DRAFT-022.

# PLAN

1. Record the decisions and their reasoning in
   `docs/architecture/platform.md`. **Done.**
2. Annotate DRAFT-040's D1/D3/D4/D5 as answered — in place, dated, with a
   reference here. Do not rewrite the recommendations.
3. Update `issue-index.md`: the Track C row, the dependency graph, the D→C
   coupling note, and the open-issue list (#33's disposition).
4. Amend `docs/architecture/analysis-pipeline.md`: the "one `dirwatch`
   instance per OS" routing sentence, and the C1/C3/C4 consequences
   (`MAX_CLONES`/`WATCH_MODE` re-homing, the launcher collapse). State
   explicitly that issue #3 is not reversed.
5. Record the concurrency constraint in `docs/checklists/windows.md`, with the
   failure mode named as a silent hold.
6. Record the install-guide discrepancy in the living docs. **Do not edit
   `docs/drakvuf-on-xen-nested-within-proxmox.md`.**
7. Answer the two open questions in `platform.md` — network path plus API
   authentication, and whether the directory-drop route survives.

# CREATE

Documentation only. No file under `automation/` is touched and no deployed
behaviour changes.

# TEST

Nothing to execute. Verification is review: that the decisions are recorded
with their costs, that C9 is preserved verbatim, and that the reason there are
no lease files is stated rather than left implicit.

**Two behavioural tests are handed to the implementation**, because both are
properties of the design rather than of any one commit:

1. **Cancel a job that has no clone yet.** A design that cannot name the job
   has failed regardless of what it can cancel later.
2. **A 6294 MiB job admitted ahead of a queue of 2198 MiB jobs** — the
   measurement above, inverted. Same setup, and the large job must clone. Run
   the worker under `setsid … < /dev/null` so the result covers all twelve
   samples rather than the first 170 s.

# DEPLOY

Nothing to deploy. Deployment arrives with the implementation issues, and
involves a second L1 VM under Proxmox that does not exist yet.

# Acceptance criteria

- [ ] `docs/architecture/platform.md` exists and records decisions 1–5 with
      reasoning and with the cost of each stated.
- [ ] Head-of-line reservation, queued-job cancellation, and atomic
      publication are each shown to follow from the design, not asserted.
- [ ] C9 is explicitly preserved and the consequence — no worker script
      changes — is stated.
- [ ] The absence of VLAN and memory lease files is explained against
      DRAFT-040's `flock` reasoning, so it does not read as an oversight.
- [ ] Issue #3 is explicitly recorded as **not** reversed.
- [ ] DRAFT-040's D1/D3/D4/D5 are annotated **in place** as answered, with a
      date and a reference. D2 is recorded as moot rather than deleted.
- [ ] DRAFT-036 / issue #33 is recorded as superseded with reasoning, and
      recommended for closure — not closed silently, and not left open against
      abandoned work.
- [ ] `issue-index.md`'s Track C row **and** its dependency graph both reflect
      the new order. Updating one and not the other is the defect this
      criterion exists to prevent.
- [ ] The Windows concurrency constraint is in `docs/checklists/windows.md`.
- [ ] The two security prerequisites are recorded as assumptions, not as
      discharged.
- [ ] No `automation/` file changes.

# Evidence required

Already held: the 2026-08-20 starvation measurement above — the two admission
banners establishing 6294 MiB and 2198 MiB, and the three `grep -c` results.
It is retained as a finding about greedy admission, not as a claim about any
branch that will merge.

Nothing further is owed for this decision. The re-run under `setsid` is more
cheaply done as TEST item 2 against the built system than as a repeat of an
abandoned baseline.

# Security considerations

- **Dom0 holds one scoped API token and no database or MinIO credentials.**
  Every object access is a presigned URL scoped to a single key, issued for a
  job Dom0 currently leases. This is the concrete reason the HTTPS API was
  chosen over letting Dom0 speak to Postgres directly: the blast radius of a
  compromised Dom0 is the jobs it is currently leasing, not the job history.
- **Dom0 gains no inbound listener.** The hardest constraint in DRAFT-040 and
  it survives unchanged. Any later proposal to give the queue an introspection
  endpoint on Dom0 should be rejected on this ground alone.
- **The OS-selection surface is unchanged**, and this is the load-bearing
  security claim. Any implementation deriving `target_os` from a sidecar file,
  a queue payload written by something other than the submission endpoint, or
  file magic, breaks issue #3 and must be rejected.
- **Untrusted filenames gain two new carriers.** They now round-trip through a
  database and a JSON payload before reaching the guest — parameterised
  queries and `argv` elements, never formatted strings. And they are
  **rendered in a browser**, which is attack surface the current system does
  not have: escape on output, never sanitise on input, because the name must
  reach the guest byte-exact (DRAFT-030's reason for abandoning hash-named
  guest files).
- **This design rests on two unverified properties** — no L2 escape, and Dom0
  unable to reach the Proxmox internal network. Until both hold, the trust
  boundaries in `platform.md` are design intent rather than enforced. The
  second matters more with the platform in a container: Dom0 and the platform
  are guests of the same L0, so "Dom0 reaches only the API" has to be
  enforced by firewall rules rather than inferred from topology.
- **The platform container shares L0's kernel.** Unprivileged LXC only, and
  the choice is scheduled for re-examination at M8 when the web tier becomes
  internet-facing — recorded as a dated revisit rather than a known defect,
  because the platform never executes a sample and that is what makes the
  weaker boundary proportionate today.

# Documentation changes

- **New:** `docs/architecture/platform.md`; this file.
- **Annotated in place:** `.github/issue-drafts/DRAFT-040.md` (D1/D3/D4/D5
  answered, D2 moot); `.github/issue-drafts/DRAFT-036.md` (superseded).
- **Updated:** `.github/issue-drafts/issue-index.md`;
  `docs/architecture/analysis-pipeline.md`; `docs/checklists/windows.md`;
  `docs/roadmap/project-roadmap.md` decision #6, whose "revisit near M7"
  premise is now expired rather than low-urgency.
- **Never edited:** `docs/drakvuf-on-xen-nested-within-proxmox.md`. Its
  `dirwatch.c` build step at line 531 becomes stale; the discrepancy is
  recorded in `platform.md`.

# Proposed implementation issues

Not drafted here. Listed so the decision's scope is visible and so no single
issue tries to build a subsystem:

| # | Scope |
|---|---|
| A | Postgres schema + the queue query, with head-of-line reservation, tested against fixtures — no Dom0 |
| B | The platform API: submission, admission checks, presigned URL issuance |
| C | MinIO deployment and bucket policy; presigned URL TTLs |
| D | `sandboxd` skeleton: register, reconcile, claim, heartbeat — driving the existing five callbacks unchanged |
| E | Artifact upload and the manifest/publication boundary (absorbs DRAFT-018's gap) |
| F | Cancellation, end to end (DRAFT-035) |
| G | The web UI: submission form, job history, live status |
| H | Retire `dirwatch.c` and the three launchers; re-home `MAX_CLONES`/`WATCH_MODE` |

A and B need no Dom0 at all, which makes them the cheapest place to start and
keeps Track D's use of the machine uncontended.

# Loose ends

- **`run_analysis-ubuntu.sh:121` cites `automation/dirwatch.c:453`** for
  `argc != 15`; it is at `:739`. Stale, and owned by whoever next edits that
  launcher — under this design, the change that deletes it (issue H).
- **The unexplained SIGKILL** of the watcher during the 2026-08-20 run.
  `journalctl --since … | grep -i -E 'oom|killed'` never ran. Low value now
  that the binary is abandoned, but it was never explained.
- **`dirwatch_old.c`** still sits in `automation/` under a name that has meant
  two different things. DRAFT-010 owned deciding its fate; issue H inherits
  that.

# Recovery / rollback

Entirely a documentation change; rollback is reverting two files. The decision
is reversible until implementation issue A begins, which is the argument for
taking it now rather than after — the same argument DRAFT-040 made for itself.