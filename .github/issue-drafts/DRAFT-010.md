# DRAFT-010: Document `dirwatch.c`'s interface and resolve the two-source ambiguity

**Status:** Drafted, not published
**Area:** core (shared orchestrator — Ubuntu, Android and Windows)
**Milestone:** M0
**Priority:** P1 — raised from the title-index entry's implicit low
priority, see "Why now"
**Depends on:** None open. The build/test half needs Xen Dom0.
**Origin:** `docs/roadmap/project-roadmap.md` risk #9;
`project-assessment.md` → CI-04; extended 2026-08-09 by the repository
comment audit → CONF-01, CONF-05, CONF-11, DEAD-01, CMT-09

# Objective

Produce the reference document for `automation/dirwatch.c`: its CLI
contract, its callback contract with the worker scripts, and its
concurrency and lifecycle behaviour. Along the way, settle which of the
two orchestrator sources in `automation/` is authoritative, and close out
the long-standing question of whether upstream DRAKVUF issue #140's
retry bug applies here.

# Context

`dirwatch.c` is the shared half of the pipeline. Every OS target runs
through it, and nothing else in the repository documents it.

## The two sources are not the same program

`automation/` contains `dirwatch.c` (661 lines) and `dirwatch_old.c`
(670 lines). `project-assessment.md`'s CI-04 describes them as differing
"almost entirely [in] formatting and function ordering", making
`dirwatch_old.c` "a reformatted sibling rather than an older design".

**That is right about most of the 128 differing lines and wrong about the
ones that matter.** Three differences are behavioural, and neither file is
a superset of the other:

| | `dirwatch.c` | `dirwatch_old.c` |
|---|---|---|
| Worker cleanup on the retry path | No `worker_finished:` label. `run_drakvuf()` calls `prepare(start, -1)` and `goto restart` unconditionally; the return-value check is commented out. | `worker_finished:` releases the thread slot and frees `start` on **every** exit path, and the `prepare()` return value is checked. |
| Partial-clone cleanup on shutdown | `prepare()` checks `shutting_down` after `make_clone()` and destroys a clone created during shutdown. | Absent — a clone created as shutdown begins is leaked. |
| Clone-count guard | `threads <= 0` on a `uint32_t` (always false below zero; `-Wtype-limits`). | `threads == 0`. |

The first is a defect in the file that is actually built. If a phase times
out and `prepare()` then returns `NULL` because a shutdown arrived
mid-retry, `dirwatch.c`'s `end:` block is skipped by its own
`if (!shutting_down)` guard and `run_drakvuf()` falls off the end of the
function — **leaking the worker slot and the `start_drakvuf` struct**.
`dirwatch_old.c`'s `worker_finished:` label exists precisely to handle
that path. The commented-out `if (prepared)` block in `dirwatch.c` is the
fingerprint of the deletion.

## The filenames assert the opposite of the truth

`git log` is unambiguous:

- `dirwatch.c` has not been modified since the initial commit `7764b77`
  (apart from a comment correction in `b914123`).
- `dirwatch_old.c` was **replaced** in `885ad3c` with the Dom0 host's
  newer variant; the genuinely old 520-line copy is in history at
  `2514168`. `CLAUDE.md` records this correctly. To check if it's drakvuf
  upstream dirwatch.

**On that last point — the evidence says yes, or very close to it.** The
519-line version at `2514168` carries **none** of this project's
modifications: no `valid_threadid`, no `release_thread`, no `slots_busy`,
no `allocated_here`, and none of the added diagnostics ("Refusing to
create clone…", "leaving it in the input directory", "discarding prepared
clone"). It allocates worker slots the way upstream does, with a mutex
array:

```c
static GMutex locks[128];
...
if (g_mutex_trylock(&locks[i]))
```

That is the line both current files carried commented out as
`//static GMutex locks[128];` until `b914123` removed it — the vestige of
the approach the atomic `slots_busy` table replaced.

**So the filename was originally correct and was invalidated by a sync.**
`dirwatch_old.c` began as the pre-modification baseline kept for
reference, which is exactly what `_old` should mean. Commit `885ad3c`
overwrote that reference copy with a *newer* working variant from the host
while keeping the filename, and the name has been false since. That is a
better account than "the name is simply wrong", and it changes the
disposition: the question is not only which file wins, but whether the
project still wants a pristine upstream baseline tracked at all — and if
so, under a name that says so.

Confirming it *is* byte-identical to a specific upstream revision needs a
pinned checkout to compare against, which is DRAFT-024's output. Until
then this is strong circumstantial evidence, not a verified match.

Either way the current state is misleading: the file named `_old` carries
the newer and, on the retry path, safer code — while `dirwatch.c` is what
the install guide compiles
(`docs/drakvuf-on-xen-nested-within-proxmox.md:531`,
`cp ~/drakvuf-tools/dirwatch.c ~/drakvuf/src/dirwatch/`).

## Upstream issue #140 looks already addressed

`docs/architecture/upstream-drakvuf.md` and
`docs/architecture/analysis-pipeline.md` both still record the
retry-loses-its-sample bug as "not yet checked" against this copy. Source
reading says it does not apply:

- `main()` calls `prepare()` **before** the `mv`, and the failure path
  logs "leaving it in the input directory" without moving anything.
- On the retry path the sample is already in `run_folder`, and
  `start->input` plus `run_folder` still resolve, so the worker scripts
  find it.
- `dirwatch.c` carries a deliberate comment saying exactly this: *"Keep
  the sample in in_folder while waiting so it cannot be stranded in
  run_folder."*

This is not a full discharge — it is source reading, not execution — but
the documents should stop describing it as unexamined when the source
carries a comment about it.

## Other constraints worth recording

- **It only compiles inside a DRAKVUF source tree.** `#include <config.h>`
  and `#include "../xen_helper/xen_helper.h"` mean it cannot be built
  standalone, which is why `docs/workflow-ci.md`'s Level 1 tier
  deliberately does not compile it.
- **One origin domain per invocation.** The origin is `argv[2]`, fixed for
  the process lifetime. Three concurrent OS pipelines therefore means
  three `dirwatch` processes unless the contract changes — which is the
  constraint DRAFT-014's routing work will run into.
- **Filenames reach `g_spawn_command_line_sync()` unquoted** in five
  command templates. Not classic command injection (no shell is spawned),
  but `g_shell_parse_argv()` word-splitting means a sample name with a
  space moves the wrong file. Owned by DRAFT-030; this document should
  describe the contract, not fix it.

## Why now

Two things raised this from a documentation chore:

1. **CONF-11 — DRAKVUF engine work is near-term**, not deferred to M9.
   `dirwatch.c` stops being a file the project merely maintains and
   becomes one it develops. It is also already the file
   `docs/workflow-ci.md`'s Level 2 tier rebuilds from on every PR.
2. **The leak above is real** and sits in the built file.

# Dependencies

None open. DRAFT-030 overlaps on filename handling — this issue documents
the contract, that one changes it; sequence them either way but do not
duplicate the fix here.

# Out of scope

- Rewriting `dirwatch.c` in Python. Explicitly deferred by
  `docs/architecture/analysis-pipeline.md`'s open architecture decision,
  which requires this document first.
- Changing the 14-argument CLI contract. Documenting it is the point;
  changing it would invalidate all five worker scripts at once.
- Fixing the filename handling (DRAFT-030) or the `ps | grep` process
  discovery (DRAFT-011).

# PLAN

1. Read both sources in full and produce a complete behavioural diff,
   separating formatting from semantics. The three differences above are
   the starting point, not the finding — confirm nothing else was missed.
2. Decide which source is authoritative. The recommendation is
   `dirwatch.c` (it is what builds and what Dom0 runs) **with
   `dirwatch_old.c`'s `worker_finished:` cleanup path restored**, since
   that is the one place the other file is better.
3. Settle the upstream-baseline question, which is separable from step 2
   and is really two questions:
   - **Is the 519-line version at `2514168` upstream's `dirwatch.c`?**
     Diff it against a pinned `tklengyel/drakvuf` checkout. Needs
     DRAFT-024's pinned revision; if that has not landed, a one-off
     clone is enough for this comparison.
   - **Does the project still want an upstream baseline tracked in
     `automation/`?** It is the only way to see this project's
     divergence at a glance, and that becomes more valuable, not less,
     once engine work starts (CONF-11). If yes, restore it under a name
     that says what it is — `dirwatch.upstream.c` or similar — rather
     than reusing `_old`, which has now meant two different things.
4. Decide the fate of the current `dirwatch_old.c`: delete it, or rename
   it to state what it actually is (a host-side variant with a better
   retry path). `_old` is wrong for it either way.
5. Confirm the leak by reading, then by test (see TEST).
6. Write the reference document, including the callback contract each
   worker script depends on.

# CREATE

1. Add `docs/architecture/dirwatch.md`: CLI contract, callback contract,
   thread-pool and timer behaviour, shutdown semantics, and the
   divergence-from-upstream notes.
2. Move the changelog narrative currently inline at `dirwatch.c`'s worker
   reservation — *"the previous code only did this once before scanning
   the directory…"* — into that document. It was reduced to its invariant
   in `b914123` on the grounds that this document is where it belongs;
   this is that document. *(Audit finding CMT-09.)*
3. Apply the step-2 decision: restore the `worker_finished:` path if that
   is the outcome, and rename or remove the non-authoritative source.
4. Correct the "not yet checked" language in
   `docs/architecture/upstream-drakvuf.md` and
   `docs/architecture/analysis-pipeline.md` to reflect the source
   evidence, keeping the verified/unverified distinction honest.
5. Fix `threads <= 0` to `threads == 0` if `dirwatch.c` is authoritative.

# TEST

Local, no Xen:

```bash
diff -u -w -B automation/dirwatch_old.c automation/dirwatch.c
```

Requires Xen Dom0 — this is a build and a behaviour test, and must be
presented for manual execution per `CLAUDE.md`'s infrastructure boundary:

1. Build the chosen source inside the DRAKVUF tree
   (`cp … ~/drakvuf/src/dirwatch/`, then `./autogen.sh && ./configure &&
   make`). It cannot be compiled anywhere else.
2. Reproduce the leak against the **pre-fix** binary, on a disposable
   clone and a benign fixture only: start `dirwatch`, let a preconfig or
   trace phase hit its timeout, and send `SIGTERM` while the retry is in
   flight. Expect the worker slot never to be released — visible as the
   pool refusing to accept a subsequent sample.
3. Repeat against the fixed binary and confirm the slot is released and
   the process exits cleanly.
4. Confirm no orphaned domains remain (`xl list`) and no clone LVs are
   left behind (`lvs`) after either run.

# DEPLOY

`dirwatch` is rebuilt and reinstalled from the DRAKVUF tree, so this is a
build-and-replace on Dom0, not a file copy. Keep the previous binary until
the fixed one has processed at least one benign sample end to end.
Rollback is reinstalling the previous build.

# Acceptance criteria

- [ ] `docs/architecture/dirwatch.md` exists and documents the 14-argument
      CLI contract, the callback contract, the 60s/180s timers, the
      thread-pool sizing, and shutdown behaviour.
- [ ] The behavioural differences between the two sources are enumerated,
      and one is named authoritative with a reason.
- [ ] The non-authoritative source is deleted or renamed. No file called
      `dirwatch_old.c` remains, since the name has now meant two
      different things and is false for the current contents.
- [ ] The 519-line version at `2514168` is either confirmed as upstream
      `tklengyel/drakvuf:src/dirwatch/dirwatch.c` at a named revision, or
      recorded as not-upstream with what it actually is.
- [ ] A decision is recorded on whether an upstream baseline stays
      tracked in `automation/`, and under what name. If yes, this
      project's divergence from it is summarised in the new document —
      that summary is the thing engine work (CONF-11) will need.
- [ ] The worker-slot and `start_drakvuf` leak is either fixed or recorded
      as a known defect with an issue reference — not left undecided.
- [ ] `project-assessment.md`'s CI-04 is annotated to record that the two
      files differ behaviourally, correcting "almost entirely formatting".
- [ ] Upstream issue #140's status is stated with its evidence category
      (source-read, not execution) in both architecture documents.
- [ ] CMT-09's narrative is in the new document, not inline in the source.

# Evidence required

The behavioural diff; the build log from Dom0; the before/after leak
observation from TEST steps 2–3; `xl list` and `lvs` output after each
run.

# Security considerations

The leak is a resource-exhaustion path, not a containment break: a
shutdown racing a timeout retires a worker slot permanently, and enough of
them stall the pipeline. Worth stating plainly because it is *not* a
sample-escape risk and should not be prioritised as one.

The genuine containment-adjacent item in this file is the unquoted
filename reaching `g_spawn_command_line_sync()`, which belongs to
DRAFT-030. Do not fix it here; do document it, since the reference
document is where the next reader will look for the input contract.

Any Dom0 test uses a disposable clone and a benign fixture. Never a real
sample, and never the golden or template domains.

# Documentation changes

New: `docs/architecture/dirwatch.md`.
Updated: `docs/architecture/upstream-drakvuf.md` and
`docs/architecture/analysis-pipeline.md` (issue #140 status),
`docs/roadmap/project-roadmap.md` risk #9,
`.github/issue-drafts/issue-index.md` (this entry now has a draft file).

# Recovery / rollback

Documentation changes: `git revert`. Source changes: reinstall the
previous `dirwatch` build on Dom0. The deleted or renamed source stays in
git history either way.