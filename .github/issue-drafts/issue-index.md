# Issue index

Full draft-title index, first batch (DRAFT-001 through DRAFT-008 — the
scope approved for this session). See `docs/roadmap/project-roadmap.md` for
the complete brainstormed workstream list this was derived from, and for
the DRAFT-009 onward range. Most of that range is still title-index only;
the exceptions, each with its own `DRAFT-NNN.md`, are DRAFT-009, DRAFT-010,
DRAFT-025 through DRAFT-034, and DRAFT-036.

| Draft ID | Title | Area | Milestone | Priority | Depends on | Status |
|---|---|---|---|---|---|---|
| DRAFT-001 | Initialize git repository and commit current baseline | governance | M0 | P0 | — | **Closed** — done 2026-08-07 |
| DRAFT-002 | Add root README.md | governance | M0 | P1 | DRAFT-001 | **Closed** — done 2026-08-07 |
| DRAFT-003 | Reorganize docs/ into roadmap/architecture/checklists, preserving Android checklist evidence verbatim | governance | M0 | P0 | DRAFT-001 | **Closed** — done 2026-08-07 |
| DRAFT-004 | Fix checklist doc-reference and provenance-list defects | governance | M0 | P2 | DRAFT-003 | **Closed** — done 2026-08-07 |
| DRAFT-005 | Add CONTRIBUTING.md capturing PLAN→CREATE→TEST→DEPLOY lifecycle + issue template | governance | M0 | P1 | DRAFT-003 | **Closed** — done 2026-08-07 |
| DRAFT-006 | Reconcile `misc/` Xen guest config naming and cross-references | governance | M0 | P2 | DRAFT-001 | **Closed** — [#1](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/1), done 2026-08-08 |
| DRAFT-007 | Verify `drakvuf-ubuntu.sh`'s `<USER>` placeholder bug against real behavior | ubuntu | M1 | P0 | DRAFT-001 | **Closed** — [#2](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/2), done 2026-08-08; premise refuted (see note below) |
| DRAFT-008 | Define OS-independent analysis job/result state model | core | M0 | P0 | DRAFT-001 | **Closed** — [#3](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/3), done 2026-08-09; model in `docs/architecture/analysis-pipeline.md` |
| DRAFT-025 | Standardize Xen analysis pipeline paths | platform | M0 | P1 | DRAFT-001; informed by DRAFT-006, DRAFT-007 | Published — [#4](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/4), retitled 2026-08-09 to "…paths **and replace HTTP sample delivery**" when DRAFT-027 was folded in; **Closed 2026-08-10** — CREATE and DEPLOY both complete (`docs/runbooks/deploy-repo-relative-paths.md`), PR #5 merged. One acceptance criterion carried forward to DRAFT-009/#6 and DRAFT-015/016/034. Scope expanded — see note below |
| DRAFT-026 | Implement GitHub Actions and self-hosted Xen integration runner | ci | M1 | P1 | DRAFT-001; soft dep. on DRAFT-025; supersedes DRAFT-012; informed by DRAFT-006, DRAFT-007 | Drafted, not published — see `.github/issue-drafts/DRAFT-026.md` |

## Second batch — DRAFT-027 through DRAFT-034

Added 2026-08-08 from the backlog review in `project-assessment.md`. Each
entry names the assessment finding that produced it; none duplicates an
open issue or an existing draft (see that document's "Existing Issue and
Draft Review" for the coverage check). All are **drafted, not published**.

The `OS` column reflects the project's three current targets — Ubuntu,
Android and Windows. `ALL` means one fix serves all three, because the
code it touches is in the shared half of `automation/` (`dirwatch.c`,
`network-setup.sh`, `cleanup.sh`, `tcpdump.sh`) or is a decision the
per-OS scripts inherit.

| Draft ID | Title | Area | OS | Milestone | Priority | Depends on | Origin finding |
|---|---|---|---|---|---|---|---|
| DRAFT-027 | Replace HTTP/Apache sample delivery with direct guest injection | core/platform | ALL | M1 → M2/M3 | P0 | Issue #4; blocks DRAFT-016, DRAFT-026b | DRAKVUF-01 — **implemented for Ubuntu 2026-08-09 inside issue #4**, never published separately |
| DRAFT-028 | Make `network-setup.sh` fail loudly, install correct rules, and be idempotent | platform/networking | ALL | M2 | P0 | — (blocks DRAFT-013) | NET-01, NET-04, NET-05 |
| DRAFT-029 | ~~Restrict analysis-clone access to Dom0 host services~~ — retitled 2026-08-12 to "Make the DRAKVUF chains terminal, so containment does not depend on Dom0's default policies" | platform/security | ALL | M2 | P0 | DRAFT-028 (landed); ~~DRAFT-013~~, ~~DRAFT-027~~ both dropped — see `DRAFT-029.md` | NET-02, plus the fail-open window found 2026-08-12 |
| DRAFT-030 | Stop passing untrusted sample filenames through shell-parsed command lines | core | ALL | M1 | P1 | — (should precede DRAFT-014) | DRAKVUF-03, DRAKVUF-02 |
| DRAFT-031 | Establish a `shellcheck` baseline that `automation/` actually passes | testing | ALL | M1 | P1 | — (blocks DRAFT-026a) | CI-01 |
| DRAFT-032 | Reconcile documentation with current project direction and closed issues #1/#2 | governance/docs | ALL | M0 | P1 | — | DOC-01…DOC-09, NET-04, GOV-02; extended 2026-08-09 by the comment audit (CONF-02/03/04/06/07/08/11/12, DOC-N4/N5/N6, TODO-03) |
| DRAFT-033 | Make `clone-ubuntu.pl` fail safely and lock, before it is copied twice | core/ubuntu | ALL (template) | M1 | P1 | Issue #4 | DRAKVUF-05, DRAKVUF-06 |
| DRAFT-034 | Establish the Windows analysis-guest track (baseline, profile, anchor, configs) | windows | W | M5 → current | P1 | Issue #3, Issue #4, DRAFT-009, DRAFT-027; supersedes DRAFT-020's design half | Focus change; GOV-02, DOC-09 |

### Recommendations affecting existing entries

Where the recommendations from `project-assessment.md` now live:

| Entry | Recommendation recorded in |
|---|---|
| DRAFT-008 / issue #3 | `DRAFT-008.md` — assessment notes added inline to Objective, Dependencies, PLAN step 2, and Acceptance criteria |
| DRAFT-025 / issue #4 | `DRAFT-025.md` — added to the layout diagram, PLAN steps 2/3/5, Acceptance criteria, Security considerations, Documentation changes |
| DRAFT-026 | `DRAFT-026.md` — new "Recommended split" section, plus fixes in Dependencies, CREATE and Acceptance criteria |
| DRAFT-009 … DRAFT-024 | The "Assessment notes" table at the end of this file — these have no draft files yet, so the corrections wait there |

**Applied to the draft files; not applied to GitHub.** The published bodies
of issues #3 and #4 have therefore diverged from their drafts, deliberately
— the drafts now carry the recommended changes and the issues do not.
Reconciling them is a `gh issue edit` operation, which `CONTRIBUTING.md`
gates behind explicit approval. Nothing has been published, closed,
committed or pushed.

Two carried forward unchanged, for visibility:

- **DRAFT-026 → SPLIT** into `026a` (static tier; no Dom0/Proxmox/fixture
  dependencies, blocked only on DRAFT-031) and `026b` (self-hosted tier).
  The split itself is a structural decision left for review; the four
  design defects behind it (CI-01 … CI-05) have been fixed in the draft.
- **DRAFT-012 → FULLY OBSOLETE**, superseded by DRAFT-026a, but still
  cited as live by `docs/checklists/ubuntu.md:201` and roadmap M1 —
  DRAFT-032 corrects those references.

## Third batch — DRAFT-035, DRAFT-036

Added 2026-08-09, produced by issue #3's design work rather than by a
backlog review. Both are implementation consequences of the decided state
model; neither is covered anywhere in DRAFT-009…034.

**DRAFT-036 is now drafted in full** — see `.github/issue-drafts/DRAFT-036.md`.
It carries a publication gate: its Objective, Context and Evidence are
source-verified and settled, but PLAN/CREATE wait on DRAFT-010's
C-vs-Python decision, which determines whether the fix is a cross-process
lease added to `dirwatch.c` or an allocator designed into its replacement.
Do not publish it as a GitHub issue before then. **DRAFT-035 remains an
index entry only.**

| Draft ID | Title | Area | OS | Milestone | Priority | Depends on | Origin |
|---|---|---|---|---|---|---|---|
| DRAFT-035 | Implement the job control channel: cancellation, retry guard, per-OS watch-directory admission | core | ALL | M1 | P1 | Issue #3; soft dep. on DRAFT-010 | Issue #3 decisions 1 and 3 |
| DRAFT-036 | Replace fixed clone slots with a host-global admission controller — VLAN leases, memory reservation, starvation-free queue | core/platform | ALL | M1 | **P0** | Issue #3; blocks concurrent per-OS watchers | Issue #3 decision 4 |

## Fourth batch — DRAFT-037

Added 2026-08-11. Not from a backlog review: the golden Android VM was
reinstalled that day to fix a reproducible `surfaceflinger` crash, which
invalidated everything Phase 1 of `docs/checklists/android.md` had
evidenced.

| Draft ID | Title | Area | OS | Milestone | Priority | Depends on | Origin |
|---|---|---|---|---|---|---|---|
| DRAFT-037 | Rebuild the Android sandbox template from the reinstalled golden VM | android/platform | A | M2 → M3 | **P0** | None open; **blocks DRAFT-015/016/017** | AND-001; roadmap risk #12 |

**Published and closed 2026-08-11 — [#7](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/7)** (label `bug`). Drafted,
published and executed the same day. Transcript:
`docs/runbooks/rebuild-android-sandbox.md`; resolution in
`.github/issue-drafts/DRAFT-037.md`.

New saved state `1844fc0a…`, anchor PID 3163, golden LV unmodified, AND-001
regression-checked after restore. Two outcomes beyond the draft's scope: the
dead DNS DNAT was retired rather than reproduced (closing the Android half
of `CLAUDE.md`'s known issue), and the anchor is now a backgrounded `nano`
for anti-evasion — which makes **"anchor auto-discovery must not key on a
process-name grep"** a constraint on DRAFT-015/016.

**All seven issues are now closed.** Nothing is open. *(Superseded
2026-08-12: #9 published and closed the same day; #11 and #12 published and
open. Current state is at the end of this file — do not read this line as
live.)*

`android_sandbox` is a clone of the golden VM, so the reinstall made its LV,
its saved state (`457fe0d7…`) and its anchor PID (`5715`) all describe an
image that no longer exists. §1.5 still recorded them as validated. Every
Android script draft is written against that template, which is why this
takes P0 ahead of them rather than queueing behind them.

The systemic half is registered separately as **roadmap risk #12** and is
deliberately not in DRAFT-037's scope: nothing links a saved state to the
golden image it came from, `.bak` files carry no provenance, and no check
would have caught this. It applies to Ubuntu and Windows identically and is
currently unowned.

**DRAFT-035** — a user must be able to stop a running analysis. The
model's `cancelled` terminal status needs a mechanism: a cancellation
request channel, a check at each transition, and reuse of the existing
clone-destroy primitive (`timer_thread` → `cleanup()`,
`dirwatch.c:240-241`). Carries one non-obvious requirement: the cancel flag
must also be checked at `dirwatch.c:425`, alongside `shutting_down`, or the
retry branch re-clones the sample and the "stop" becomes an unbounded loop.
Also owns creating the per-OS watch directories and the one-`dirwatch`-per-OS
launch arrangement. The only prior mention of cancellation anywhere in the
repository is `DRAFT-026.md:243`, which is about cancelling a *CI* job.

**DRAFT-036** — P0 because it contains a **blocking defect**, not just an
efficiency gain. `slots_busy[]` is process-local (`dirwatch.c:161`) and the
slot index doubles as the VLAN (`:297`), so the moment a second `dirwatch`
instance runs, both allocate VLAN 1 and both clones land on `xenbr1.1` /
`172.16.1.0/24` — defeating the per-VLAN isolation `network-setup.sh`
exists to provide. Per-OS watchers cannot run concurrently until VLAN
allocation is host-global, which makes this a prerequisite of issue #3's
OS-selection mechanism rather than a follow-up to it.

The efficiency half is the other reason: independent per-OS `<max clones>`
caps cannot lend capacity to each other, so any static split ("5 Windows,
3 Ubuntu, 3 Android") is either wasteful when one OS is busy or
overcommitted when all three are. Clones are not interchangeable either —
`misc/*_sandbox.cfg` pins `memory = maxmem = 2048` with no ballooning, and
Windows will want more — so the admissible quantity is **memory, not clone
count**. Candidate rule and its caveats are in
`docs/architecture/analysis-pipeline.md`, "Clone concurrency"; the
`xl restore` peak-vs-steady-state question must be measured on Dom0 before
the rule is trusted.

It grew a third half in drafting, and all three are one change. A memory
check is check-then-act, so several watchers deciding at once all see the
same free memory and all proceed — and a clone's memory is not accounted by
`xl info` until its domain is built, so a lock released at `xl restore`
does not close the window. Memory admission is also greedy, which starves
the largest clone: a Windows job waits for a window that never opens
because a smaller Ubuntu or Android job is always already eligible. And
three watchers means three independent `inotify` queues with no relative
ordering, so the ordering cannot come from the watchers either. VLAN
leasing, memory reservation and queue order therefore need one host-global,
crash-safe authority, which is why the draft refuses to split them.

One interaction worth carrying forward: bounded backfill (letting a small
job run ahead of a reservation it cannot delay) needs a worst-case runtime
per job, and there isn't one. The retry loop at `dirwatch.c:424-429` has no
cap and its `if (prepared)` guard is commented out, so a reliably-timing-out
sample retries forever. That is the same branch DRAFT-035 must add a cancel
check to and the same cleanup path DRAFT-010 found the worker-slot leak in
— three issues meeting at one `goto`.

## Note on DRAFT-007

**Resolution (2026-08-08):** the premise was **wrong**, in the same way
DRAFT-006's was. `<USER>` was never a production bug — the deployed Dom0
copy of `drakvuf-ubuntu.sh` had always been correctly substituted with
`CMD="/home/carlos/Desktop/test"`, and Ubuntu analysis runs have been
executing their samples all along (`ExecProc Status:Success`, ~359k trace
records, clean `exit_group` — see run
`cd22b2c623c0cf35ec4fea588fe61bf6`). It was *this repository's* copy that
carried the unsubstituted placeholder.

What the verification actually uncovered is more useful than what it set out
to check: `automation/` had silently diverged from the deployed Dom0 copies,
undetected. `drakvuf-ubuntu.sh` differed on two lines, not one — the repo
also had `--memdump_dir` (underscore), which the installed build rejects.
Resolved the same day by syncing `automation/` wholesale from the tested
production host; five of the eight files were already byte-identical.
DRAFT-006's outstanding host-side rename (`linux_sandbox.cfg` →
`ubuntu_sandbox.cfg`) was completed at the same time, so issue #1 is now
closed end-to-end as well.

Also settled, and worth carrying into any future work on these scripts:
`drakvuf -e` is **execve-direct**, with no shell in the guest, so a `$USER`
in that argument can never dereference guest-side.

Full transcript: `docs/runbooks/verify-user-placeholder.md`. Recurrence
prevention (a repo↔host checksum check) is folded into DRAFT-026.

## Note on DRAFT-026

Added in this session at the user's request to plan CI implementation.
Not part of the original DRAFT-001–024 batch or DRAFT-025's later
addition — numbered next-available (026) for the same reason DRAFT-025
was. Supersedes DRAFT-012's title-only "Add static CI" scope (see the
remaining title-index below) rather than leaving it as a separate,
never-drafted entry, since Level 1 of this issue's design **is**
DRAFT-012's scope, just designed alongside the heavier self-hosted tier
rather than in isolation. Full design lives in `docs/workflow-ci.md`.

## Note on DRAFT-025

Not part of the original DRAFT-001–024 brainstormed batch — added in a
later session at the user's direct request to standardize repository-owned
asset paths (`automation/`, `misc/`, LibVMI profiles, Xen saved state)
around a canonical `/root/sandbox_project` Dom0 checkout, while explicitly
leaving `/malware_*` runtime data paths untouched. Numbered 025 (next
available) rather than inserted into the 009–024 range so the original
roadmap-derived title index stays intact. See `.github/issue-drafts/DRAFT-025.md`.

**Scope note added 2026-08-09, on closing issue #3.** That carve-out is
now load-bearing rather than incidental: issue #3 changed the `/malware_*`
layout, so #4 must keep its hands off it deliberately, not merely by
omission. Specifically, `/malware_incoming` gains a per-OS subdirectory
level (`ubuntu/`, `android/`, `windows/`), and result directories move from
`/malware_finished/<MD5>` to `/malware_finished/<analysis_id>` with an
`index/by-sha256/` mapping. Two consequences for #4, neither of which
changes what it implements:

- The runtime data layout is owned by issue #3's state model and
  DRAFT-018, not by #4. #4 should not standardize `/malware_*` paths even
  where they sit next to the repo-owned ones it does move.
- Any documentation #4 touches must not restate the current flat
  MD5-keyed layout as settled. `docs/architecture/result-schema.md` §1
  still describes it, correctly, as *current source-verified behaviour* —
  that framing is what keeps it accurate, and #4 should preserve it rather
  than promoting it to a convention.

Nothing was edited on GitHub; `CONTRIBUTING.md` gates `gh issue edit`
behind explicit approval, and #4's published body is unchanged.

> **Superseded in part, 2026-08-09 (same day), at the maintainer's
> request.** The first bullet no longer holds: **#4 did implement the
> per-OS `/malware_*` subdirectory level**, for Ubuntu. The three
> `dirwatch` folder arguments now point at
> `/malware_{incoming,processing,finished}/ubuntu`.
>
> Two reasons it moved into #4 rather than waiting for DRAFT-018:
>
> 1. The per-OS level is *launcher configuration* — which directory a
>    `dirwatch` instance watches — not result schema. It is the same class
>    of value as the `.cfg` and profile paths #4 was already relocating.
> 2. It could not be deferred safely once #4 touched `/malware_processing`:
>    Apache's `DocumentRoot` was that directory, so a per-OS level would
>    have 404'd the guest's `wget`, silently. DRAFT-027 was implemented in
>    the same change to remove the coupling entirely.
>
> **The second bullet stands unchanged and was honoured.** Result
> directories are still MD5-keyed; nothing #4 touched promotes that to a
> convention, and `result-schema.md` §1's framing is intact. The
> `analysis_id` rename and the `index/by-sha256/` mapping remain
> DRAFT-018's.
>
> See `DRAFT-025.md`, "CREATE completed 2026-08-09".

## Revision note on DRAFT-006

Originally titled "Commit missing Xen guest `.cfg` files" — that premise
was **wrong**. All four configs (`misc/linux.cfg`, `misc/linux_sandbox.cfg`,
`misc/android.cfg`, `misc/android_sandbox.cfg`) were already tracked in the
repository; the earlier research pass simply missed the `misc/` directory.
DRAFT-006 is revised to the smaller, real gap: the `linux*.cfg` filenames
are misleading (they define `ubuntu`/`ubuntu_sandbox`, not a generic
"linux" domain), and `automation/run_analysis-ubuntu.sh` hard-codes a
deployment path (`/home/user/drakvuf-tools/linux_sandbox.cfg`) that doesn't
match this repo's `misc/` location.

**Resolution (2026-08-08):** Both fixed in commit `ced4e77`, which closed
issue #1 — `misc/linux.cfg`/`misc/linux_sandbox.cfg` renamed to
`misc/ubuntu.cfg`/`misc/ubuntu_sandbox.cfg` and every in-repo reference
updated. The host-side rename was completed the **same day**, so issue #1 is
closed end to end — recorded at `:111-113` of this file and evidenced with
the exact `mv` and a re-tested run in `docs/checklists/ubuntu.md`. DRAFT-025
and DRAFT-026 already treat this as settled ("which #1 already settled") and
need no further changes. *(Corrected 2026-08-11, CONF-03: this paragraph
ended "The real Dom0 host's copies still need a separate manual rename; see
the issue #1 thread", which this same file already contradicted.)*

## Remaining title-index (DRAFT-009 through DRAFT-024)

Not yet drafted in full — titles only, from `docs/roadmap/project-roadmap.md`:

| Draft ID | Title | Area | Milestone | Priority | Depends on |
|---|---|---|---|---|---|
| ~~DRAFT-009~~ | **Drafted in full and published 2026-08-10 — [#6](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/6).** See `.github/issue-drafts/DRAFT-009.md`. Retitled "Define the shared-vs-OS-specific script boundary **and the per-OS configuration contract**"; priority raised P1 → **P0** | core/platform | M0 | **P0** | DRAFT-008 (closed), issue #4 (closed) |
| ~~DRAFT-010~~ | **Now drafted in full — see `.github/issue-drafts/DRAFT-010.md`.** Retitled "Document `dirwatch.c`'s interface and resolve the two-source ambiguity"; priority raised to P1 | core | M0 | P1 | — |
| DRAFT-011 | Retrofit Ubuntu pipeline with structured status output (no behavior change) | ubuntu | M1 | P1 | ~~DRAFT-007~~ (closed 2026-08-08), DRAFT-008 |
| DRAFT-012 | ~~Add static CI (`bash -n`, `shellcheck`, `perl -c`) for `automation/*`~~ — superseded by DRAFT-026 | testing | M1 | P1 | DRAFT-001 |
| ~~DRAFT-013~~ | **Drafted in full and published 2026-08-12 — [#13](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/13).** Retitled "Confirm an Android clone tolerates the isolation rules, **and establish connectivity parity with Ubuntu**" — the parity half was added on drafting and is the larger one | android/security | M2 | P0 | DRAFT-028, DRAFT-029, DRAFT-037 — all landed |
| DRAFT-014 | Decide sample OS auto-detection contract (magic/MIME/PE/ELF/APK) | core | M2 | P1 | DRAFT-008 |
| DRAFT-015 | Implement `clone-android.pl` per checklist §2.5 | android | M3 | P1 | DRAFT-009, DRAFT-013 |
| DRAFT-016 | Implement `preconfig-android.sh` / `drakvuf-android.sh` per checklist §2.7–2.8 | android | M3 | P1 | DRAFT-015 |
| DRAFT-017 | Implement Android sample classification (checklist §2.6) | android | M3 | P1 | DRAFT-014 |
| DRAFT-018 | Define artifact/result schema | core | M4 | P1 | DRAFT-008 |
| DRAFT-019 | Integrate capa against DRAKVUF logs (native v7.2.0 extractor) | enrichment | M4 | P2 | DRAFT-018 |
| DRAFT-020 | Windows baseline selection + clone-per-run confirmation | windows | M5 | P2 | DRAFT-008 |
| DRAFT-021 | Licensing review write-up | governance | M0 | P1 | — |
| ~~DRAFT-022~~ | **Drafted in full 2026-08-11 — see `.github/issue-drafts/DRAFT-022.md`.** Retitled "Establish the legal and compliance position for networked malware analysis (Spain/EU)"; priority raised P2 → **P1**, because DRAFT-028 confirmed the lab has working deliberate Internet egress today | compliance | M2 → M8 | **P1** | — |
| DRAFT-023 | TLS-visibility research spike for Linux/Android (tlsmon confirmed N/A) | networking | M2 | P3 | DRAFT-013 |
| DRAFT-024 | Pin and mirror **both** DRAKVUF upstreams — `tklengyel/drakvuf` and the `lfreijo` fork — as the baseline engine changes are diffed from | governance | M0 | **P1** *(raised from P2, 2026-08-11)* | DRAFT-001 |

Note: DRAFT-021's content (the licensing review) and DRAFT-020's premise
(the VM-lifecycle question) were substantially resolved during the same
session that drafted this index — see `docs/architecture/licensing.md` and
`docs/checklists/windows.md` respectively. They remain listed for
completeness and because DRAFT-021 in particular should still go through a
real legal review, not just this desk research.

### Assessment notes on DRAFT-009 … DRAFT-024 (2026-08-08)

From the backlog review in `project-assessment.md`. These entries have no
draft files yet, so the corrections live here — apply them **when each
entry is drafted in full**, rather than drafting from the title and
dependency columns above, which have drifted.

The `OS` column reflects the project's three current targets. Where an
entry was scoped to one OS but the code it governs is shared, that is
called out — the whole point of recording it now is that the correction is
cheap before the draft exists and expensive after.

| ID | OS | Assessment | Apply when drafted |
|---|---|---|---|
| **009** | ALL | **DRAFTED IN FULL 2026-08-10** — see `DRAFT-009.md`; this row is superseded. | ~~Start from the source-verified split…~~ Applied, and the scope shrank in the process: issue #4 shipped `pipeline-ubuntu.env`, so the file-level split and the per-OS-config decision are already settled and written down (`pipeline-ubuntu.env:15-18`). What the draft actually owns is the parameterization contract — the `carlos`/`vg-root`/`xenbr1` question, still genuinely three-shaped — plus three things the assessment did not anticipate: host-global values sitting in per-OS files (`ANALYSIS_BRIDGE` has one consumer while `xenbr1` is hard-coded in six places), `clone-*.pl` being outside the config mechanism entirely, and the rule that a template defect is fixed before the template is copied. DRAKVUF-01 is no longer at risk of triplication — DRAFT-027 landed inside issue #4. |
| **010** | ALL | **DRAFTED IN FULL 2026-08-09** — see `DRAFT-010.md`; this row is superseded. | ~~Add CI-04…~~ Done, and CI-04's premise was corrected in the process: the two sources differ **behaviourally**, not "almost entirely [in] formatting". `dirwatch_old.c` has a `worker_finished:` cleanup path that `dirwatch.c` lacks, so the built file leaks a worker slot and its `start_drakvuf` struct when a timeout retry coincides with shutdown. Separately, the 519-line version at `2514168` carries none of this project's modifications and allocates slots with upstream's `GMutex locks[128]`, so it is very likely pristine upstream — the `_old` name was correct for *that* file and was invalidated when `885ad3c` overwrote it with a newer host variant. |
| **011** | U → ALL | **PARTIALLY OBSOLETE — shrink, then widen.** | **Remove** the "reconcile with the deployed Dom0 copy" element: issue #2 completed it on 2026-08-08. **Add** DRAKVUF-04 (`ps aux \| grep` PID safety) — 3 of its 4 sites are in shared `cleanup.sh`, so that part is not Ubuntu-only; the `"tcpdump -i xenbr1.$VLAN"` match is unanchored with `.` as a regex wildcard, so VLAN 1 also matches `xenbr1.10`–`19` above 9 clones. Dependency on DRAFT-007 is closed. **Added 2026-08-10 (issue #6):** this draft owns **emitting** `guest_filename` and `original_filename` as separate fields in `status.json`, so a reader can see when the two differ and why. It does not own the normalizer or the staging change — those went to DRAFT-030 in the same pass, because they are one input travelling one hop and splitting them would mean two normalizers. Gains a soft dependency on DRAFT-030: the field is meaningless before a normalized name exists. |
| **012** | ALL | **FULLY OBSOLETE.** Superseded by DRAFT-026a. | Do not draft. Still cited as live by `docs/checklists/ubuntu.md:201` and roadmap M1 — DRAFT-032 fixes those references. |
| **013** | A | **DRAFTED IN FULL 2026-08-12** — see `DRAFT-013.md`; this row is superseded. | ~~NEEDS UPDATE — retitle away from Android-only.~~ **Backwards, as it turned out.** DRAFT-028's deployment measured the shared mechanism directly and the result transfers to any OS, because the rules match on interface rather than on anything guest-specific. What does not transfer is the guest's *reaction*, which is Android-specific — so the entry narrowed to Android-only instead of widening. NET-02 was closed inside DRAFT-028 and NET-03 belongs to DRAFT-022, so neither survives as an "expected finding". The draft carries a falsifiable prediction (Android passes, because ARP/NUD is unfiltered and validation probes go to the Internet) so the test can fail rather than confirm. |
| **014** | ALL | **NEEDS UPDATE.** The title parenthetical already anticipates PE, but with Windows current this becomes a genuine three-way routing decision rather than an ELF/APK split. **Superseded 2026-08-09 (issue #3): there is no routing decision left.** | ~~Note it is the entry that makes `dirwatch`'s one-domain-per-invocation contract actually limiting (see 010).~~ The opposite held: issue #3 adopted that contract as the OS-selection mechanism (one watch directory per OS, chosen by the submitter), so detection no longer decides where a sample runs. **Retitle** from "Decide sample OS auto-detection contract" to a typing and identification contract. Remaining scope: `detected_type` as an advisory admission check (mismatch → `rejected`/`unsupported_type`), and the `type_identifiers` set — `imphash`/`telfhash`/APK signing identity — including whether Dom0 takes a `pefile`/LIEF dependency to compute them. Still should follow DRAFT-030. The `target_os_source` revisit condition survives unchanged. |
| **015** | A | READY. | Must follow issue #4's path convention and **DRAFT-033's** error-handling/locking pattern rather than copying today's `clone-ubuntu.pl` verbatim — `CLAUDE.md` directs new scripts to be written from the Ubuntu implementation, which currently has its `flock` commented out (`:236-241`) and checks no exit status. |
| **016** | A | READY. | **DRAFT-027 must land first** so Android is never built against the HTTP delivery path. `docs/checklists/android.md:1003` already prefers `injector -m writefile`; `:1877`'s "keep HTTP as an optional compatibility path" is superseded — no fallback is to be implemented. |
| **017** | A | READY. | Consumes DRAFT-014. ~~No change.~~ **Rescoped 2026-08-09 (issue #3):** follows DRAFT-014's rescope — Android "classification" is now identification (package name, `version_code`, signing-certificate SHA-256, ABI), not a routing input. An unsupported ABI or a non-APK is an admission rejection, not a dispatch decision. |
| **018** | ALL | READY. | ~~Defer the MD5-vs-SHA-256 keying decision to issue #3, which now owns it; `docs/architecture/result-schema.md` §3 currently poses the same question independently.~~ **Done 2026-08-09:** issue #3 decided it — result directories are named by `analysis_id`, SHA-256 is the sample key and index, MD5/SHA-1 are identifiers only — and `result-schema.md` §3 now defers. What remains for 018: the storage layout inside a result directory, the atomic-publication boundary in practice, and the `pefile`/LIEF/`telfhash` dependency decision that gates which `type_identifiers` are computed. |
| **019** | ALL | READY. | No change. |
| **020** | W | **PARTIALLY OBSOLETE, and now under-scoped.** | Drop the lifecycle-decision half — resolved by roadmap decision #3 (snapshot-restore is non-viable in this nested setup), though `docs/checklists/windows.md:41` still lists it as open (DOC-05). The remaining half is absorbed by **DRAFT-034**, which is the real Windows track head. Either close this entry into DRAFT-034 or keep it as the baseline-selection sub-task. |
| **021** | — | **PARTIALLY OBSOLETE.** | The desk research is written (`docs/architecture/licensing.md`). Retitle to reflect that what remains is a real legal review, not a write-up. |
| **022** | — | **DRAFTED IN FULL 2026-08-11** — see `DRAFT-022.md`; this row is superseded. | ~~READY. No change.~~ The desk research landed with it, and one finding inverts the usual assumption: **holding and executing samples is comparatively safe**. Art. 264 ter CP requires *both* lack of authorisation *and* intent to facilitate an offence, and the Fiscalía's circular `FIS-C-2017-00003` explicitly protects dual-use tooling used for security auditing. What is *not* settled is civil negligence exposure for live-Internet detonation, and GDPR — which applies to the pcaps and memdumps already on disk, regardless of egress, and is the most likely live compliance gap in the project today. |
| **023** | U/A → +W | **NEEDS UPDATE — the premise has flipped.** | Currently premised on "tlsmon confirmed N/A". `tlsmon` hooks Windows `ncrypt.dll`/Schannel only (`docs/architecture/networking.md:61-64`) — so with Windows current it is **applicable**, and becomes the project's only working TLS-visibility path. Rescope to "adopt `tlsmon` for Windows; research options for Ubuntu/Android". Roadmap risk #4 and the reuse table (`:90`) need the same correction (DRAFT-032). |
| **024** | ALL | **READY, priority should rise from P2 — now for three independent reasons.** | (1) DRAFT-026b rebuilds DRAKVUF/LibVMI from source in every job with nothing pinned to build against. (2) Scope spans **two** upstreams with different bus-factor profiles: `tklengyel/drakvuf` (Windows-oriented plugin set, healthy) and the single-maintainer `lfreijo` fork (Linux/Android plugin support, risk #8). The Windows track leans mainly on the former — the pinned fork commit `8dc77880…` is titled "Add **Linux** support for memdump, filetracer, fileextractor, and syscalls plugins". (3) **Added 2026-08-09 (CONF-11):** with DRAKVUF engine work near-term rather than deferred to M9, a pinned revision stops being bus-factor insurance and becomes the baseline engine changes are diffed from — a prerequisite, not a precaution. DRAFT-010 also needs a pinned checkout to confirm whether `dirwatch_old.c`'s original 519-line form is pristine upstream. Retitle away from `lfreijo`-only. |

Dependency corrections to the table above, once these are drafted:

- **DRAFT-013** gains a dependency on DRAFT-028 (fix before measuring).
- **DRAFT-014** gains a soft dependency on DRAFT-030 (harden filename
  handling before routing widens the input surface).
- **DRAFT-015** gains a dependency on DRAFT-033 (fix the clone template
  before copying it).
- **DRAFT-020** is superseded in substance by DRAFT-034.
- **DRAFT-023** gains a dependency on DRAFT-034 for its Windows half.

Added 2026-08-09 from issue #3:

- **DRAFT-014 and DRAFT-017** lose their routing premise and are rescoped
  to identification; see the assessment table above.
- **DRAFT-011** gains the shared model as its target output — it is the
  first pipeline to emit `status.json`, and therefore the first real test
  of whether the model survives contact with a running pipeline.

Added 2026-08-10, on drafting DRAFT-009:

- **Issue #4 has one acceptance criterion still open**, deliberately: new
  per-OS scripts inherit its path convention and the corrected
  `injector -m writefile` syntax. It cannot be closed by #4 — the scripts do
  not exist — and its original wording predates Windows as a current target.
  Widened to **DRAFT-015/016 and DRAFT-034**, and discharged through
  DRAFT-009's conformance checklist. Annotated in `DRAFT-025.md`.
- **DRAFT-009 handed ordering constraints to three drafts.** Applied
  2026-08-10 as issue #6 executed; they now live in "Load-bearing
  constraints, in one place" at the end of this file.
- **DRAFT-009 must not pre-empt DRAFT-036.** It may decide *where* a
  host-global value lives; DRAFT-036 decides *who allocates it*. Nor may it
  change `dirwatch`'s callback contract, which is DRAFT-010's. *(Honoured —
  issue #6 changed no contract and designed no allocator.)*

Scope moved by issue #6, same date:

- **DRAFT-030 gains** the guest-filename normalizer (one implementation for
  all three pipelines), the Ubuntu staging retrofit — which **changes Ubuntu
  runtime behaviour** and needs its own end-to-end run — and re-establishing
  the single-argv invariant per OS, since Android installs rather than
  `execve`s and issue #2's finding does not carry over.
- **DRAFT-011 gains** emitting `guest_filename` and `original_filename` as
  separate fields, plus a soft dependency on DRAFT-030.
- **Proposed, needs confirming:** `automation/platform.env` is a code change
  issue #6 cannot make. Each file's existing owner wires its own — DRAFT-028
  creates it and wires `network-setup.sh`, DRAFT-033 wires `clone-*.pl`,
  DRAFT-011 wires `cleanup.sh` and `tcpdump.sh`.
- **DRAFT-016 and DRAFT-017 lose the in-guest collection steps.** `logcat`,
  `logd`, `dumpsys` and `dmesg` are withdrawn; `docs/checklists/android.md`
  §4.2–4.4 are annotated as historical candidates. Android's semantic
  visibility is reduced as a result, knowingly — see
  `docs/architecture/analysis-pipeline.md`, decision 4.

## Fifth batch — DRAFT-038, DRAFT-039

Added 2026-08-12, produced by DRAFT-029's deployment rather than a backlog
review. Both are findings recorded in
`docs/runbooks/deploy-terminal-chains.md`; neither is a defect in what
DRAFT-029 changed.

| Draft ID | Title | Area | OS | Milestone | Priority | Depends on | Origin |
|---|---|---|---|---|---|---|---|
| DRAFT-038 | Verify the installed firewall posture, and settle which netfilter backend this project owns | platform/security | ALL | M2 | P1 | DRAFT-028, DRAFT-029 (both landed) | Findings F1, F2′ |
| DRAFT-039 | Clean up the VLAN interfaces a failed `network-setup.sh` run leaves behind | platform | ALL | M2 | P2 | DRAFT-029 (landed); must not pre-empt DRAFT-036 | Finding F4 |

**Both published 2026-08-12** —
[#11](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/11)
(`enhancement`) and
[#12](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/12)
(`bug`).

**DRAFT-038** is the third step in a sequence: DRAFT-028 made provisioning
fail loudly on a *rejected* rule, DRAFT-029 made the chains terminal, and
neither checks that what reached the kernel is what was intended. Two
findings show the gap is not theoretical. **F1** — this host runs two
iptables backends, so every containment assertion is a statement about one
of two independently-evaluated rulesets, and `iptables-save` silently omits
the other, which means *the rollback captures in every runbook here are
partial*. **F2′** — `iptables -S` reports a nonexistent chain and an
unreadable one with the same message, so the total absence of containment
presents as a confusing error. That is not hypothetical either: the
DRAFT-029 runbook was written up asserting filtering was still live at a
moment when there were no rules, no chains and no VLAN interfaces, and it
took the maintainer to catch it.

**F2 was withdrawn** the same day it was recorded. It claimed an
unexplained readback failure that "cleared on reboot"; a one-command test
showed there had never been a failure. The withdrawal is annotated in the
runbook rather than edited out, because the reasoning error is the most
instructive thing in that file.

**DRAFT-039** is P2 and explicitly closes no security gap — stray
interfaces are covered by the same `xenbr1.+` rules as live ones. It is
listed because the naive fix is wrong: the provisioning loop is idempotent
by *reuse*, so a trap deleting every `xenbr1.*` would remove interfaces
belonging to a running clone. Cleanup must distinguish what this run
created from what it found, which is why it is an issue rather than a patch.

## Current order (consolidated 2026-08-11)

The single current sequence. Two earlier order blocks and their scattered
dated addenda were removed on 2026-08-11 — three stacked revisions patching
each other by reference had stopped reading as one sequence, which is the
whole point of having one.

**#1, #2, #3, #4, #6, #7 and #9 are all closed** — #9 (DRAFT-029) was
published, merged as `aed37af` and deployed on 2026-08-12. **Three issues
are open:**

| # | Draft | Priority | State |
|---|---|---|---|
| [#13](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/13) | DRAFT-013 | P0 | Runbook written (`docs/runbooks/verify-android-isolation.md`), awaiting execution on Dom0 |
| [#11](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/11) | DRAFT-038 | P1 | Spawned by DRAFT-029's deployment (F1, F2′) |
| [#12](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/12) | DRAFT-039 | P2 | Spawned by DRAFT-029's deployment (F4) |
DRAFT-037/#7 was drafted, published and executed on 2026-08-11 and has been
struck from the sequence below. The remaining drafted P0s — DRAFT-028,
DRAFT-030, DRAFT-031, DRAFT-033, DRAFT-036 — are all still unpublished, and
DRAFT-031 is now first.

### Next six

| # | Draft | Why here |
|---|---|---|
| 1 | **DRAFT-013** — **re-scope before working it** | **Shrank to Android-only.** DRAFT-028's deployment already produced the nine-row connectivity matrix with per-rule packet counters, and because `network-setup.sh` matches on interface (`-i xenbr1.+`) rather than anything guest-specific, that result transfers to any OS. What does *not* transfer is the guest's reaction: Android does connectivity probing and may mark a network unvalidated when it cannot reach its gateway, which Ubuntu never checks. Remaining scope is one Android clone boot. |
| 2 | ~~**DRAFT-029**~~ — **DONE 2026-08-12.** [#9](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/9) closed, [PR #10](https://github.com/evilbootloader/drakvuf-multios-sandbox/pull/10) merged as `aed37af`, deployed and tested on Dom0 (`docs/runbooks/deploy-terminal-chains.md`, steps 0–8). Spawned DRAFT-038 and DRAFT-039 | Its Dom0-service half (NET-02, the `INPUT`-chain gap) landed inside DRAFT-028 at the maintainer's request. `DRAFT-029.md` is now rewritten to match, and the remaining scope **inverted** in the process: `DRAKVUF_INPUT` is already terminal, so setting `-P INPUT`/`-P FORWARD` buys nothing for containment and risks locking the operator out — the fix is to make `DRAKVUF_ISOLATION` terminal instead, and set no policies at all. Retitled accordingly. Also absorbs a fail-open window found while sweeping: the chain is flushed at `network-setup.sh:272` and not repopulated until `:342`, with the whole VLAN loop in between, so any `ip` failure exits leaving it empty behind `-P FORWARD ACCEPT`. |
| 3 | **DRAFT-030** | Restores `SC2086` coverage, which `.shellcheckrc` currently disables repository-wide — so it should precede the six Android and Windows scripts, not follow them. Also owns the guest-filename normalizer. |
| 4 | **DRAFT-010** | Moved ahead of DRAFT-036 because it gates it. DRAFT-036's PLAN/CREATE wait on DRAFT-010's C-vs-Python decision, which determines whether the fix is a cross-process lease in `dirwatch.c` or an allocator designed into its replacement. CONF-11 raises its value independently: with engine work near-term, this becomes input to that work. |
| 5 | **DRAFT-036** | P0 **correctness** defect, not tuning: `slots_busy[]` is process-local and the slot index *is* the VLAN, so a second watcher allocates VLAN 1 too and both clones land on `xenbr1.1`. Per-OS watchers cannot run concurrently until this lands — it is a prerequisite of issue #3's OS-selection mechanism, not a follow-up to it. |
| 6 | **DRAFT-033** | `clone-ubuntu.pl` is the template `clone-android.pl` is written from and it checks no exit status. Copying first puts the defect in three files. Precedes DRAFT-015. |

**Three items came off this list on 2026-08-11**, all executed the same day:

- **DRAFT-037 / #7** — Android template rebuilt. This is what promotes
  DRAFT-013: with a working template in hand, unverified containment is the
  nearest thing to a real risk rather than a distant one.
- **DRAFT-031** — `shellcheck automation/*.sh` exits 0 against the
  `.shellcheckrc` baseline. Repo side done; the Dom0 pull and one benign
  analysis run are still outstanding, and CI cannot supply them.
- **DRAFT-026a** — the static CI tier exists and is green. **026b, the
  self-hosted Xen integration tier, is untouched** and still drafted.

DRAFT-031 also left a standing constraint: `.shellcheckrc` disables SC2086,
SC2009 and SC2006 repository-wide, so those checks are **not** protecting
new Android or Windows scripts. Each names its owning issue, and landing
**DRAFT-030** is what restores SC2086 coverage before six more scripts are
written against it.

### Considered and deliberately not taken (2026-08-11)

**In-guest command observability.** `preconfig-ubuntu.sh` configures the
clone's network with a single `&&` chain injected through
`injector -m execproc`. `injector` reports `STATUS:SUCCESS` when it
successfully *starts* the shell, and the script's `exit $?` propagates that
rather than the chain's status — so a failure inside the guest is invisible
to `dirwatch`, to `preconfig.log` and to the operator.

Established the same day, and worth keeping: **the chain is correct.**
Verified in-guest — `ip route replace` returns 0, `getent hosts google.com`
resolves, `dig @1.1.1.1` answers. Issue #4's `GUEST_NAMESERVER` fix does
work, and `docs/checklists/ubuntu.md`'s `[x] Guest DNS resolves` is now
evidenced rather than inferred, which it was not before.

A draft was prepared to close the observability gap — sentinel file plus
`injector -m readfile`, the documented inverse already used for issue #4's
integrity check — and **the maintainer declined it for now: not a change
wanted in this architecture at this stage.** Recorded here so it is not
re-proposed as a new finding, and so the reasoning survives if it is
revisited:

- The gap is real but currently costs nothing, because the chain works.
- It would matter most for a *false negative* — a clone with no resolver
  produces an analysis that looks complete and observed nothing.
- One latent fragility sits behind it: `/etc/resolv.conf` in the golden
  image is a symlink into `/run/systemd/resolve/`, and `systemd-resolved`
  is active. The write currently sticks, but that file is owned by a
  running service.
- If revisited, it should precede **DRAFT-016** — `preconfig-android.sh` is
  written from this file, and `CLAUDE.md`'s rule is that a template defect
  is fixed before the copy is made.

**DRAFT-032** was first in this list and is now executed — see the note at
the end of this section.

### Then

```
DRAFT-013 → DRAFT-029 → DRAFT-030 → DRAFT-026a → DRAFT-015 → DRAFT-016
         → DRAFT-024 → DRAFT-034 → DRAFT-014 → DRAFT-017 → DRAFT-011
         → DRAFT-035 → DRAFT-018 → DRAFT-019 → DRAFT-026b
```

`DRAFT-030` before `DRAFT-016`: DRAFT-030 owns the guest-filename normalizer
and the Ubuntu staging retrofit, so writing `preconfig-android.sh` first
means writing it against SHA-256 staging and rewriting it immediately.
`DRAFT-024` rises to P1 (see its row above). `DRAFT-012` is obsolete — do not
draft it.

### Load-bearing constraints, in one place

These are defect-multiplication rules, not preferences. Violating one costs
more than the item it reorders:

- **DRAFT-031, DRAFT-033 and DRAFT-030 all precede DRAFT-015/016.** Each is
  a defect in the template that gets copied into two more files otherwise.
- **Anchor auto-discovery must not key on a process-name grep** (added
  2026-08-11 by issue #7). The Android anchor is a backgrounded `nano`,
  chosen so the string `drakvuf` appears nowhere in the guest. A generic
  name makes `grep` ambiguous and `injector` does not warn, so §7.2's
  "Resolve the injection anchor PID/TGID automatically / Reject zero or
  multiple matching anchors" must key on something else. `INJECTION_PID` is
  a number and always was; only human verification used the name.
- ~~**DRAFT-028 before DRAFT-013.** Fix before measuring.~~ **Satisfied** —
  DRAFT-028 deployed 2026-08-11, DRAFT-029 2026-08-12. DRAFT-013 is drafted
  against the fixed implementation and is unblocked.
- **An Android clone must attach to `xenbr1.<vlan>`, never to `xenbr1`**
  (added 2026-08-12 by DRAFT-013's drafting). The isolation rules match the
  `xenbr1.+` wildcard, which does not match the bare bridge, so a guest on
  `xenbr1` is covered by no rule at all. `clone-ubuntu.pl:229` rewrites the
  vif correctly and `clone-android.pl` will inherit that, but the **manual**
  procedure in `rebuild-android-sandbox.md` step 7 does not — it inherits
  `bridge=xenbr1` from `misc/android_sandbox.cfg`. Any hand-built test
  domain must override it.
- **DRAFT-010 before DRAFT-036.** Publication gate, stated in DRAFT-036.
- **DRAFT-036 before any concurrent per-OS watcher**, and therefore before
  DRAFT-035's launch arrangement and before DRAFT-015/016 run alongside
  Ubuntu.

> **DRAFT-032 status, 2026-08-11.** Applied to the repository without being
> published as a GitHub issue, as a documentation-only pass. Tables A–E are
> corrected or annotated; three items (DOC-04, CONF-02, CONF-04) were found
> already resolved by later work and needed no change. Nothing in
> `automation/` or `misc/` was touched and no issue body was edited, so
> `CONTRIBUTING.md`'s Stage 2 gate was not triggered.