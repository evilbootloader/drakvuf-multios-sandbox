# Issue index

Full draft-title index, first batch (DRAFT-001 through DRAFT-008 — the
scope approved for this session). See `docs/roadmap/project-roadmap.md` for
the complete brainstormed workstream list this was derived from, and for
the DRAFT-009 onward range. Most of that range is still title-index only;
the exceptions, each with its own `DRAFT-NNN.md`, are DRAFT-009, DRAFT-010,
DRAFT-013, DRAFT-015, DRAFT-016, DRAFT-022, DRAFT-025 through DRAFT-034, and
DRAFT-036 through DRAFT-039. *(Corrected 2026-08-14: this sentence had not
been updated since DRAFT-013, DRAFT-022 and the DRAFT-037–039 batch were
written, and listed only DRAFT-009/010, 025–034 and 036. DRAFT-015 added
2026-08-15.)*

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
| DRAFT-025 | Standardize Xen analysis pipeline paths | platform | M0 | P1 | DRAFT-001; informed by DRAFT-006, DRAFT-007 | Published — [#4](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/4), retitled 2026-08-09 to "…paths **and replace HTTP sample delivery**" when DRAFT-027 was folded in; **Closed 2026-08-10** — CREATE and DEPLOY both complete (`docs/runbooks/02-deploy-repo-relative-paths.md`), PR #5 merged. One acceptance criterion carried forward to DRAFT-009/#6 and DRAFT-015/016/034. Scope expanded — see note below |
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
| ~~**DRAFT-028b**~~ | **Done 2026-08-15.** Create `automation/platform.env` and wire `network-setup.sh` to it. `ANALYSIS_BRIDGE`, `UPLINK_BRIDGE`, `SUBNET_PREFIX`, `VG_NAME`; `network-setup.sh` and `run_analysis-ubuntu.sh` source it; `ANALYSIS_BRIDGE` removed from `pipeline-ubuntu.env`. **Not deployed or tested on Dom0** | platform/networking | ALL | M2 | P1 | DRAFT-028 (landed 2026-08-11) | issue #6 decision 2; assigned 2026-08-15 — unblocked DRAFT-015's C4 |
| DRAFT-029 | ~~Restrict analysis-clone access to Dom0 host services~~ — retitled 2026-08-12 to "Make the DRAKVUF chains terminal, so containment does not depend on Dom0's default policies" | platform/security | ALL | M2 | P0 | DRAFT-028 (landed); ~~DRAFT-013~~, ~~DRAFT-027~~ both dropped — see `DRAFT-029.md` | NET-02, plus the fail-open window found 2026-08-12 |
| ~~DRAFT-030~~ | **Dom0 half done 2026-08-15.** Stop passing untrusted sample filenames through shell-parsed command lines. All five `g_spawn_command_line_sync` sites converted to argv vectors via `g_spawn_sync`; the `mv` subprocess replaced by `g_rename`; filename admission added at the watch-folder boundary, with rejected samples moved to `<out>/rejected/` so they cannot spin the scan loop. Callback arity and order unchanged (C9). A leading `-` is deliberately **admitted** — every consumer path-prefixes the name, so it is never in option position. **Guest-side half done the same day**: `preconfig-ubuntu.sh` stages to and `drakvuf-ubuntu.sh` executes `$GUEST_STAGING_DIR/$RUNFILE`, and every SC2086 site carrying the sample filename is quoted (`tcpdump.sh`'s bare `md5sum` returned an EMPTY digest for a spaced name, sending every such pcap to one shared path). **There is no normalizer, deliberately** — admission at the boundary means no name needs rewriting, so `original_filename` == `guest_filename` always. `dirwatch.c` cannot be compiled outside a DRAKVUF tree; admission rules and argv construction were verified by standalone harness, and the guest-path invariant by an end-to-end stub run | core | ALL | M1 | P1 | — (should precede DRAFT-014) | DRAKVUF-03, DRAKVUF-02 |
| DRAFT-031 | Establish a `shellcheck` baseline that `automation/` actually passes | testing | ALL | M1 | P1 | — (blocks DRAFT-026a) | CI-01 |
| DRAFT-032 | Reconcile documentation with current project direction and closed issues #1/#2 | governance/docs | ALL | M0 | P1 | — | DOC-01…DOC-09, NET-04, GOV-02; extended 2026-08-09 by the comment audit (CONF-02/03/04/06/07/08/11/12, DOC-N4/N5/N6, TODO-03) |
| ~~DRAFT-033~~ | **Done 2026-08-15.** Make `clone.pl` fail safely and lock. Exit status checked on `xl destroy`/`lvremove`/`lvcreate`/`xl restore`; preflight on tools, config, origin LV and saved state; argument validation; `END`-block removal of a partial snapshot and of the temporary config (the item no issue owned); stdout carries the clone ID **only** on success, guarded to a bare integer. Lock is **per clone name, not per origin** — a per-origin lock would serialize all `MAX_CLONES` workers of one origin and throttle the pipeline to one analysis at a time. Wired to `platform.env` (`VG_NAME`, `ANALYSIS_BRIDGE`). Title's "before it is copied twice" premise is void — DRAFT-015 shared the file instead. **Not deployed or tested on Dom0** | core/shared | ALL (shared) | M1 | P1 | Issue #4; DRAFT-028b | DRAKVUF-05, DRAKVUF-06 |
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
`docs/runbooks/03-rebuild-android-sandbox.md`; resolution in
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

Full transcript: `docs/runbooks/01-verify-user-placeholder.md`. Recurrence
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
| ~~DRAFT-015~~ | **Drafted and implemented 2026-08-15 — see `.github/issue-drafts/DRAFT-015.md`.** Retitled "Complete the Android pipeline — `pipeline-android.env`, `run_analysis-android.sh`, and a shared `clone.pl`". Scope widened from one file to three deliverables: DRAFT-016 assigns `pipeline-android.env` and `run_analysis-android.sh` here and no issue owned the latter. **Decision taken on drafting: there is no `clone-android.pl`** — `clone-ubuntu.pl` holds exactly one Ubuntu-specific value (`-L64G`), so once that comes from `$ENV{CLONE_LV_SIZE}` the file has no per-OS content and is renamed `automation/clone.pl`, shared by all three pipelines. **This amends C1 and C2** in `analysis-pipeline.md`. Android's `CLONE_LV_SIZE` is `32G`, measured from the 32,00g origin LV. Also found: `INJECTION_PID` is **3164**, not §1.5's 3163 — the template was re-saved before DRAFT-013 ran . **Built:** `pipeline-android.env` (C3 complete, C4 clean by grep), `run_analysis-android.sh`, and the `clone.pl` rename. `preconfig-android.sh`/`drakvuf-android.sh` remain DRAFT-016's, and the launcher refuses to start without them. Both launchers gained a DRAFT-036 concurrency guard — a one-sided guard would have protected nothing. **Nothing Android has run on Dom0** | android/core | M3 | P1 | DRAFT-033, DRAFT-028b (both hard); DRAFT-013/#13 and DRAFT-037/#7 landed; blocks DRAFT-016 |
| ~~DRAFT-016~~ | **Drafted 2026-08-14, implemented 2026-08-15 — see `.github/issue-drafts/DRAFT-016.md`.** Retitled "Implement `preconfig-android.sh` **and** `drakvuf-android.sh`" — §2.7–2.8 is no longer the specification for either half (§1.6 supersedes the network half; issue #6 withdrew the in-guest collection §2.8's stage list assumes). Two decisions taken on drafting: the **APK path (`pm install` + launch) is in scope**, selected by a structural test rather than the advisory `detected_type`; and **`70-collect` is dropped with C7 unamended**. Dependencies widened from DRAFT-015 alone . **Built:** `preconfig-android.sh` (writefile + the single EthernetConfig call, mixed Dom0/guest quoting) and `drakvuf-android.sh` (APK via `pm install`+`monkey` through `/system/bin/sh -c`; native ELF via direct `execve`; anything else `unsupported_type`). `drakvuf -f` is evidenced from the installed build's own help, not assumed. **Nothing has run against an Android guest** — the APK launch step in particular is unverified | android | M3 | P1 | DRAFT-015, DRAFT-030, DRAFT-033 (all hard); DRAFT-011 (soft); DRAFT-013/#13 landed, supplies the spec |
| DRAFT-017 | Implement Android sample classification (checklist §2.6) | android | M3 | P1 | DRAFT-014 |
| ~~DRAFT-018~~ | **Drafted and implemented 2026-08-26 — see `.github/issue-drafts/DRAFT-018.md`.** Two thirds of the row's remaining scope had closed while it sat unwritten: result keying (issue #3, then #37's `result_prefix`) and the atomic-publication boundary (#36's single committed `complete`), both now struck rather than solved; the `type_identifiers` dependency decision moved to DRAFT-048, which owns PE/ELF/APK parsing. What was actually left was unrecorded: `manifest: dict`, the one worker payload with no shape, over a reader that minted a presigned URL per element. Measured 2026-08-25 — a string minted nine URLs, one per character; `null`/`int`/nested list 500'd the only view of a finished job, permanently; 50,000 names cost 11.74s and 17.92 MB per request. **Built:** `sandbox_platform/manifest.py` — validated manifest with per-artifact size and digest, `reject_unsafe_name` shared with the ticket endpoint (the same names arrived through two doors and only one was guarded), a tolerant `parse()` that degrades rather than raises and still validates legacy rows, and the capability envelope every `*.json` shares. Traversal was probed and is **not** exploitable — MinIO refuses `..` itself — so it is recorded as defence-in-depth, not a live hole | core/platform | M4 | P1 | DRAFT-008; #36, #37 (both closed) |
| DRAFT-019 | Integrate capa against DRAKVUF logs (native v7.2.0 extractor) | enrichment | M4 | P2 | DRAFT-018 |
| DRAFT-020 | ~~Windows baseline selection + clone-per-run confirmation~~ → **What is installed in the guests — coverage, and not looking like a sandbox** *(retitled 2026-08-25; the old title described DRAFT-034's work)* | core | M5 | **P1** | DRAFT-034 |
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
- ~~**Proposed, needs confirming:**~~ **Confirmed 2026-08-15.**
  `automation/platform.env` is a code change issue #6 cannot make. Each
  file's existing owner wires its own — DRAFT-028 creates it and wires
  `network-setup.sh`, DRAFT-033 wires `clone-*.pl`, DRAFT-011 wires
  `cleanup.sh` and `tcpdump.sh`.
  > **Carried to DRAFT-028b, because DRAFT-028 itself has landed.** The
  > proposal's stated reason was that DRAFT-028 *"is already rewriting that
  > file"* — true when it was written, not now: DRAFT-028 deployed
  > 2026-08-11 (see the ordering note at the end of this file). Scope added
  > to landed work does not land, so `platform.env` and the
  > `network-setup.sh` wiring go to a follow-on, numbered on the DRAFT-026a/b
  > precedent. DRAFT-033's and DRAFT-011's halves are unaffected — both are
  > still open. Raised while drafting DRAFT-015, which cannot satisfy C4
  > until `platform.env` exists.
- **DRAFT-016 and DRAFT-017 lose the in-guest collection steps.** `logcat`,
  `logd`, `dumpsys` and `dmesg` are withdrawn; `docs/checklists/android.md`
  §4.2–4.4 are annotated as historical candidates. Android's semantic
  visibility is reduced as a result, knowingly — see
  `docs/architecture/analysis-pipeline.md`, decision 4.

## Fifth batch — DRAFT-038, DRAFT-039

Added 2026-08-12, produced by DRAFT-029's deployment rather than a backlog
review. Both are findings recorded in
`docs/runbooks/05-deploy-terminal-chains.md`; neither is a defect in what
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

## Sixth batch — DRAFT-040

Added 2026-08-19, produced by DRAFT-036's implementation rather than a
backlog review. It is a **decision issue**: it settles an architecture
question and produces no automation.

| Draft ID | Title | Area | OS | Milestone | Priority | Depends on | Origin |
|---|---|---|---|---|---|---|---|
| DRAFT-040 | Decide the job-queue and web↔Dom0 communication architecture | core/platform | ALL | M1 → gates M7 | P1 | Couples to DRAFT-010 and DRAFT-035; informs DRAFT-018 | DRAFT-036 item 3 could not be designed without it |

**Drafted in full** — see `.github/issue-drafts/DRAFT-040.md`.

It exists because **roadmap decision #6's premise expired**. That decision
reads "job-queue technology — low urgency, revisit near M7", which was
correct when written. Three things that looked separate have since
converged on one mechanism: anti-starvation needs a host-global order over
jobs (DRAFT-036 item 3); cancellation needs a queued job to *have a
record*, which today it does not — it is a file in a watch directory plus a
spinning worker, with no id and no field to set, so cancelling a queued job
is unexpressible rather than merely unimplemented (DRAFT-035); and the web
platform needs all of it (M7). Deferring now means building a
filesystem-shaped queue and discarding it, which is the cost the deferral
was meant to avoid.

Two things it settles that are worth reading even if the rest waits:

- **VLAN leases and memory reservations stay on `flock`, deliberately.**
  Their requirement is release on process *death* and never on delay. A
  broker TTL plus heartbeats would reassign a stalled watcher's VLAN while
  its clone was still on that segment — the defect DRAFT-036 just removed,
  rebuilt with more machinery.
- **`drakvuf-sandbox` uses RQ over Redis**, verified 2026-08-19 from its
  `requirements.txt` at `master` (`rq==2.9.0`, `Flask==3.0.3`,
  `boto3`, `karton-core` as an optional integration). The roadmap's reuse
  table was already right. What has *not* been read is how they use it —
  the manifest is evidence of what, not how, and PLAN step 2 owns that.

It deliberately makes **no recommendation on RQ vs plain Redis**, because
that largely decides DRAFT-010: RQ's job payloads and worker loop are
Python, so an RQ *worker* cannot be C — though `hiredis` makes plain Redis
from C entirely viable. The constraint is handed to DRAFT-010 rather than
pre-empted.

> **Answered 2026-08-21 by DRAFT-041.** Neither, for now: Postgres holds the
> queue as well as the state, so D2 is moot rather than decided, and
> DRAFT-010's C-vs-Python question falls out as Python. See the annotation in
> the draft itself for how each of D1–D5 resolved.

## Seventh batch — DRAFT-041 through DRAFT-045

Added 2026-08-21. The direction change and the first buildable slice under
it. **DRAFT-041 is a decision issue; 042–045 are build issues that need no
Dom0 at all** — which is why they are the four chosen to start, and why they
do not compete with Track D for the machine.

| Draft ID | Title | Area | OS | Milestone | Priority | Depends on | Origin |
|---|---|---|---|---|---|---|---|
| DRAFT-041 | Decide the analysis platform architecture — web tier, job store, and Dom0 | core/platform | ALL | M1 → gates M7 | P0 | Nothing open | Maintainer, 2026-08-21 |
| DRAFT-042 | Job schema and the claim query, with head-of-line reservation | core/platform | ALL | M1 | P0 | DRAFT-041 | DRAFT-041 |
| DRAFT-043 | The platform API — submission, admission, and the worker channel | core/platform | ALL | M1 | P0 | DRAFT-042; pairs with 044 | DRAFT-041 |
| DRAFT-044 | MinIO — bucket layout, policy, and presigned access | core/platform | ALL | M1 | P0 | DRAFT-041; pairs with 043 | DRAFT-041 |
| DRAFT-045 | The web UI — submission, history, and live job status | core/platform | ALL | M1 | P1 | DRAFT-043, DRAFT-044 | DRAFT-041 |

**All five drafted in full and published 2026-08-22:**

| Draft | Issue | Draft | Issue |
|---|---|---|---|
| DRAFT-041 | [#34](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/34) **open** | DRAFT-044 | [#37](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/37) **open** |
| DRAFT-042 | [#35](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/35) **open** | DRAFT-045 | [#38](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/38) **open** |
| DRAFT-043 | [#36](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/36) **CLOSED 2026-08-24** | | |

Published together rather than one at a time, against the rule that a draft
is published when work on it starts: #35 is where work starts, and the other
four are its context. Reading #35 without #34 gives you a schema with no
argument behind it.

What DRAFT-041 settled, in one place: Postgres holds job state **and** the
queue; MinIO on the platform host holds samples and results; Dom0 polls an
HTTPS API and never listens; `sandboxd` in Python replaces `dirwatch.c`; and
the platform runs in an **unprivileged LXC on L0** rather than a VM,
proportionate because it never executes a sample and scheduled for
re-examination at M8.

Three properties are what the slice is measured on, and each is a test in a
specific draft rather than an aspiration:

- **Head-of-line reservation is one SQL statement** (DRAFT-042). The fit
  test sits on the outer `UPDATE`, not inside the subquery, so a head that
  does not fit blocks the queue instead of being skipped. This is the
  2026-08-20 starvation measurement inverted.
- **Cancelling a queued job is a single `UPDATE`** (DRAFT-042) — the
  operation DRAFT-040 recorded as unexpressible rather than unimplemented.
- **Dom0 holds one scoped token and no credentials** (DRAFT-043, DRAFT-044).
  Every object access is a presigned URL for one key, issued for a job it
  currently leases.

Deferred to the pass after this one, in order: `sandboxd`; artifact upload
and the manifest/publication boundary; cancellation end to end; retiring
`dirwatch.c` and the three launchers; and the Windows pipeline.

## Eighth batch — DRAFT-046

Added 2026-08-23, while building #36. Transport security spans #36 and #37
and is owned by neither, which is the reason it is separate: folding it into
either would leave the CA — the most security-relevant component on the
platform — belonging to nobody.

| Draft ID | Title | Area | OS | Milestone | Priority | Depends on | Origin |
|---|---|---|---|---|---|---|---|
| DRAFT-046 | Transport security — Cloudflare Tunnel outward, an internal CA inward | core/platform, security | ALL | M1 → gates M7/M8 | P0 | DRAFT-041 | Maintainer, 2026-08-23 |

## Ninth batch — DRAFT-047

| Draft ID | Title | Area | OS | Milestone | Priority | Depends on | Origin |
|---|---|---|---|---|---|---|---|
| DRAFT-047 | Per-user isolation, using the identity Cloudflare Access already establishes | core/platform, security | ALL | M1 → replaces part of M8 | P0 | DRAFT-043, DRAFT-046 | Maintainer, 2026-08-23 |

| Draft | Issue |
|---|---|
| DRAFT-047 | [#40](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/40) **open** |

**Published 2026-08-24, at the point its absence became a defect.** The
runbook, the code comments and #36's closing comment had all been citing
`#47` — the draft number — as though it were an issue. It was not: numbering
had only reached 39, so every one of those references pointed at nothing.
Publishing it made the number real, and it is **#40**, not #47.

Half of it landed early. Verifying the Access JWT and populating `owner`
were done inside #36, because closing that issue honestly meant the browser
routes could not stay anonymous. What remains is the half that matters: no
read path filters on `owner` or `visibility`, so every authenticated user
still sees every job.

**The topology has two trust domains, not one**, and that is the finding
that shaped it. Browsers reach the platform through a **Cloudflare Tunnel**,
so public TLS is Cloudflare's — no inbound port, no public DNS, no ACME, and
no browser-facing certificate for this project to issue. Dom0 stays on the
**LAN** with mTLS against an internal CA, because routing the worker channel
through a third party would make local analysis depend on someone else's
uptime and put the worker token through their edge.

Three things it settles that are worth reading even if the rest waits:

- **The CA root key never touches the platform container.** A CA mints
  identities, so one held there would let a platform compromise issue itself
  a Dom0 client certificate and enter the worker channel — turning credential
  theft into identity forgery. Held offline, an attacker gets the
  certificates already on that host and cannot produce more.
- **Executable artifacts are served as password-protected archives, wrapped
  on Dom0.** Cloudflare terminates TLS, and their terms prohibit using the
  service to *distribute* malicious code — a clause that bites on the
  download path, since `fileextractor` output is files the malware wrote. The
  wrapping happens on Dom0 rather than in the API because archiving there
  would stream sample bytes through the process holding every credential,
  giving up the property that made direct-to-MinIO upload worth its routing
  complexity.
- **There is no `dhparam.pem`, deliberately.** Raised in review. Forward
  secrecy is a property of the protocol — TLS 1.3 removed static RSA key
  exchange and 1.2 negotiates ECDHE by default — while `openssl dhparam`
  supplies parameters for finite-field DHE that nothing here enables. What
  the question did surface is a real gap, now decision 8: pin a TLS 1.2 floor
  explicitly, so a package upgrade cannot re-enable 1.0 or 1.1 unnoticed.

## Current order (consolidated 2026-08-19, revised 2026-08-21) — five tracks

Replaces the 2026-08-11 sequence, which had gone stale in the way this
project treats as a defect rather than drift: it listed #13 as open (closed
2026-08-14), called DRAFT-028/030/031/033 "still unpublished P0s" when all
four had landed, and led its "Next six" with four completed items. Removed
rather than annotated, for the reason the 2026-08-11 block itself gave when
it removed *its* predecessors — stacked revisions patching each other by
reference stop reading as one sequence, which is the whole point of having
one.

### The tracker now matches reality (2026-08-19)

Until this date, **two GitHub issues were open against roughly seventeen
open drafts**. The gap was not neglect: most work here was implemented
straight from its draft without ever being opened as an issue —
DRAFT-015, 016, 028b, 030 and 033 all shipped in PR #14 that way. Anyone
reading GitHub saw a nearly-idle project.

**Sixteen issues were published on 2026-08-19 to close that gap**
(#18–#33). Fifteen were created and immediately closed, because the work
was already done; #33 (DRAFT-036) is open, because it is not.

| Draft | Issue | Draft | Issue |
|---|---|---|---|
| DRAFT-001 | [#18](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/18) | DRAFT-032 | [#27](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/27) |
| DRAFT-002 | [#19](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/19) | DRAFT-015 | [#28](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/28) |
| DRAFT-003 | [#20](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/20) | DRAFT-016 | [#29](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/29) |
| DRAFT-004 | [#21](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/21) | DRAFT-028b | [#30](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/30) |
| DRAFT-005 | [#22](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/22) | DRAFT-030 | [#31](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/31) |
| DRAFT-027 | [#23](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/23) | DRAFT-033 | [#32](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/32) |
| DRAFT-028 | [#24](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/24) | DRAFT-036 | [#33](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/33) **open** |
| DRAFT-031 | [#25](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/25) | DRAFT-026a | [#26](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/26) |

Two were published against their own recorded decision not to be, and each
issue says so rather than quietly overwriting it: **DRAFT-027** was folded
into issue #4, and **DRAFT-032** was applied as a documentation-only pass
that deliberately did not trigger the Stage-2 gate. Their draft files keep
the original reasoning; only the "never published" clause is superseded.

**The rule this establishes:** a draft is published as an issue when work on
it starts, not after. The three open issues are now the real open list.

**Open issues (2026-08-22):**
[#11](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/11)
(DRAFT-038, firewall posture) and
[#12](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/12)
(DRAFT-039, stray VLAN interfaces) — Track B containment, untouched by the
redesign. Plus the platform slice published 2026-08-22:
[#34](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/34)
(DRAFT-041, the decision),
[#35](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/35)
(DRAFT-042, schema — **in progress**),
[#36](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/36)
(DRAFT-043, API),
[#37](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/37)
(DRAFT-044, MinIO),
[#38](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/38)
(DRAFT-045, web UI).

[#33](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/33)
(DRAFT-036, admission controller) was **closed as not planned on
2026-08-21** — superseded by DRAFT-041, not completed. All three of its
items assumed three concurrent watcher processes; there will be one
orchestrator.

**Open pull requests: none.** #17 (docs, Dom0 checkout path) merged
2026-08-21. #16 merged 2026-08-19. **#15 was closed unmerged on 2026-08-21**
and its `vlan-lease` branch deleted — it implemented a C-side orchestrator
that will not be built. One commit was salvaged onto master first
(`7af5042`, the Android MVP runbook, 1522 lines of dated Dom0 evidence that
`CLAUDE.md` already cited). The `<sha256>/<utime>-<vlan>` result-directory
commit was deliberately declined; see `docs/architecture/result-schema.md`
for the gap that leaves open.

### The six tracks

| Track | Contents | Consumes | Blocked by | Unblocks |
|---|---|---|---|---|
| **A — ~~Close out what is built~~** | **Closed 2026-08-21.** #15 closed unmerged, #33 closed as superseded, the Android runbook salvaged to master. Nothing remains: the `dirwatch.c` build and two-watcher test were verifying code that is no longer going anywhere | — | — | — |
| **B — Containment** | #11 firewall posture; #12 stray VLAN interfaces | **Dom0** | nothing | confidence in every containment claim. **Now unblocked** — A is closed, and the concurrency change that made "measure first" risky is no longer in flight |
| **C — Platform architecture** | **DRAFT-041 decided** → DRAFT-042 schema + queue → DRAFT-043 API → DRAFT-044 MinIO → DRAFT-045 web UI → then `sandboxd`, artifacts, cancellation, dirwatch retirement | **Desk** | nothing | F, D's concurrency ceiling, and M7 |
| **D — Windows** | DRAFT-034 Phase 0 — golden VM **installed 2026-08-21** (operator-reported); outstanding: `misc/windows_sandbox.cfg`, kernel PDB → `profiles/windows.json` via `pdbconv.py`, injection anchor, licensing | **Dom0 + long external waits** | nothing to *build*; a Windows *analysis* on a shared Dom0 needs C's head-of-line reservation | DRAFT-023 (`tlsmon`), M5 |
| **E — Legal & governance** | DRAKVUF licence email; DRAFT-022 rescope for a paid service; the entity and ISP questions; DRAFT-024 pin both upstreams | **Desk / external** | nothing | M7/M8 gates |
| **F — Output quality** | DRAFT-011 `status.json`; DRAFT-018 schema + atomic publication; DRAFT-014 → DRAFT-017 typing; DRAFT-019 capa; DRAFT-026b self-hosted CI | **Mixed** | A | M4 |

### What actually parallelizes, and why

**Parallelism here is bounded by access to one Dom0 and one operator — not
by dependencies.** Most remaining items have few hard blockers. What
serializes them is that Dom0 testing is manual, physical and one-at-a-time.
Ordering this backlog by dependency alone gives a misleading picture: it
suggests a long chain where there are really a few short ones contending
for a single machine.

Four practical rules follow. *(Revised 2026-08-21: A is closed, which
retires the A-before-B rule and frees the machine.)*

- **C and E need no Dom0 at all.** They run against B and D continuously,
  and C is now more of the work than it was — DRAFT-042 through 045 are
  schema, API, object storage and web UI, all buildable and testable on a
  development container with nothing from the lab.
- **B and D contend for one machine.** Sequence them *within* a Dom0
  session rather than treating them as independent workstreams. With A
  closed there are only two claimants.
- ~~**A should precede B.**~~ **Discharged.** The rule existed because A
  changed `dirwatch` and raised concurrency, so measuring containment first
  meant measuring a system about to move. `dirwatch` is now frozen until
  `sandboxd` replaces it wholesale, so B measures a stable system and can
  start immediately.
- **D has the longest lead time and no software dependency.** The install is
  done; the PDB fetch and profile generation are mostly *waiting*. Starting
  it early raises throughput even though it ranks below C by priority.

### Couplings a dependency list would miss

- **D → C, now measured.** Windows at `memory = 6144` costs **6294 MiB**
  admitted, against 2198 for Ubuntu and Android, and admission is greedy.
  Measured on Dom0 2026-08-20: 170 consecutive holds, zero clones, seven
  smaller jobs completing meanwhile. Every individual decision was correct.
  Windows can be *built* without C — the golden VM already exists — but the
  first Windows *analysis* on a shared Dom0 hangs with correct-looking logs
  until C's head-of-line reservation lands. Recorded in
  `docs/checklists/windows.md`; until then, run Windows alone.
- **E → C.** A paid hosted service makes multi-tenancy concrete, which
  changes what the queue must carry. `owner` and `visibility` are already
  reserved columns in the schema; E's entity and ISP answers are direct
  inputs to what the platform must enforce.
- **D → DRAFT-023.** Windows is what makes `tlsmon` applicable — the
  project's only working TLS-visibility path, and useless without a Windows
  guest.
- **C → F.** Reversed on 2026-08-21. This used to read A → F. DRAFT-011's
  `status.json` and DRAFT-018's atomic publication are both largely absorbed
  by the platform: job state becomes a database row rather than a file, and
  publication becomes a committed manifest. F should not start until C's
  schema (DRAFT-042) is settled, or it will emit a file format nothing
  reads.

### Hard edges only

Everything not drawn is independent. The graph is deliberately shown to be
shallow — the constraint is the machine, not the ordering.

```
C: DRAFT-041 ──► DRAFT-042 ──► DRAFT-043 ──► DRAFT-045
   (decided)     schema +       platform      web UI
                 queue          API
                    │              │
                    │              └──► DRAFT-044  MinIO + bucket policy
                    │
                    └──► F         schema first, or status.json emits
                                   a format nothing reads

                    ▲
D (Windows) ────────┘  coupling, not a build blocker: the golden VM is
   └──► DRAFT-023      installed, but the first Windows ANALYSIS on a
        (tlsmon)       shared Dom0 needs head-of-line reservation

A   closed 2026-08-21
B   independent — and no longer waits on A
E   independent
```

Deferred to the pass after DRAFT-042–045, in this order: `sandboxd`
(register/reconcile/claim/heartbeat, driving the five callbacks unchanged),
artifact upload and the manifest boundary, cancellation, then retiring
`dirwatch.c` and the three launchers.

A standing constraint DRAFT-031 left behind, still live: `.shellcheckrc`
disables `SC2009` and `SC2006` repository-wide, so those checks are **not**
protecting the Windows scripts still to be written. `SC2086` coverage was
restored by DRAFT-030/#31.

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

### Load-bearing constraints, in one place

These are defect-multiplication rules, not preferences. Violating one costs
more than the item it reorders. Discharged entries are struck rather than
deleted, so the reasoning survives the constraint.

**Still live:**

- ~~**DRAFT-040 before DRAFT-036 item 3 and before DRAFT-035.**~~
  **Discharged 2026-08-21 — the queue mechanism is chosen** (DRAFT-041:
  Postgres, on a platform host separate from Dom0). The constraint was right
  and is now satisfied rather than pending. What it protected against still
  holds as a rule for what follows: **DRAFT-042's schema before anything
  that reads or writes job state.** Anti-starvation needs a host-global
  *order* over jobs and cancellation needs a queued job to *have a record* —
  today it is a file in a watch directory plus a spinning worker, with no id
  and no field to set, so cancelling it is unexpressible rather than merely
  unimplemented. Both become properties of the schema, so the schema is the
  thing that must not be guessed at twice.
- **`master` means verified-on-Dom0 for code changes.** Branch, PR, Dom0
  tests *the branch*, then merge — the pattern the runbooks already used
  for DRAFT-028 (`git branch --show-current # expect:
  draft-028-network-isolation`). Docs-only changes merge on review; there
  is nothing for Dom0 to verify. This keeps master always deployable,
  which matters because master is what the Dom0 checkout pulls.
- **Admission constants are per-host.** `DOMAIN_OVERHEAD_MIB = 150` was set
  against a 112 MiB measurement on the home-lab Dom0. A second host — the
  production server — needs its own measurement pass; the constant is a
  property of Xen and the domain config, but the capacity that follows from
  it is a property of the machine.
- **Anchor auto-discovery must not key on a process-name grep** (added
  2026-08-11 by issue #7). The Android anchor is deliberately unremarkable
  so the string `drakvuf` appears nowhere in the guest. A generic name makes
  `grep` ambiguous and `injector` does not warn, so §7.2's "resolve the
  anchor PID/TGID automatically" must key on something else. `INJECTION_PID`
  is a number and always was; only human verification used the name.
- **An Android clone must attach to `xenbr1.<vlan>`, never to `xenbr1`**
  (added 2026-08-12 by DRAFT-013's drafting). The isolation rules match the
  `xenbr1.+` wildcard, which does **not** match the bare bridge, so a guest
  on `xenbr1` is covered by no rule at all. `clone.pl` rewrites the vif
  correctly, but the **manual** procedure in `03-rebuild-android-sandbox.md`
  step 7 does not — it inherits `bridge=xenbr1` from
  `misc/android_sandbox.cfg`. Any hand-built test domain must override it.

**Discharged:**

- ~~**DRAFT-031, DRAFT-033 and DRAFT-030 all precede DRAFT-015/016.**~~
  **Satisfied** — all five landed, in that order, by 2026-08-15. Each was a
  defect in a template that would otherwise have been copied into two more
  files.
- ~~**DRAFT-028 before DRAFT-013.** Fix before measuring.~~ **Satisfied** —
  DRAFT-028 deployed 2026-08-11, DRAFT-029 2026-08-12, #13 closed
  2026-08-14.
- ~~**DRAFT-010 before DRAFT-036.**~~ **Dissolved 2026-08-19, not
  satisfied** — and the distinction matters. The gate existed because the
  fix shape depended on the C-vs-Python decision. Making the allocator
  *out of process* — `flock`'d lease files that `dirwatch` is merely a
  client of — removed that dependency, because a Python replacement speaks
  the same protocol without sharing a line of code. **It returns for item
  3**, where a host-global queue is exactly where the language question
  bites.
- ~~**DRAFT-036 before any concurrent per-OS watcher.**~~ **Satisfied by
  PR #15**, pending the Dom0 build. Both `pgrep` guards are removed; the
  VLAN comes from a host-global lease.

`DRAFT-012` is obsolete — superseded by DRAFT-026a/#26. Do not draft it.

> **DRAFT-032 status, 2026-08-11.** Applied to the repository without being
> published as a GitHub issue, as a documentation-only pass. Tables A–E are
> corrected or annotated; three items (DOC-04, CONF-02, CONF-04) were found
> already resolved by later work and needed no change. Nothing in
> `automation/` or `misc/` was touched and no issue body was edited, so
> `CONTRIBUTING.md`'s Stage 2 gate was not triggered.

## Tenth batch — DRAFT-019, DRAFT-048 through DRAFT-060

Drafted 2026-08-25 while planning the web UI (#38).

**Two published 2026-08-25** — the pair that block everything else and were
owned by nobody:

| Draft | Issue |
|---|---|
| DRAFT-060 | [#41](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/41) **CLOSED 2026-09-04** — `sandboxd` delivered and evidenced |
| DRAFT-057 | [#42](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/42) **open** — built through Phase 4; blocked on a provider, not on code. See DRAFT-057.md |

> **Issue sweep, 2026-09-04.** Five issues were closed together after checking
> each against the repository rather than against its own text, which is the
> rule this file already states: **#34** (architecture — decided by DRAFT-041),
> **#35** (job schema), **#38** (web UI), **#39** (transport security) and
> **#41** (`sandboxd`). All five were marked `[x] Completed and evidenced` in
> `docs/checklists/platform.md` and had simply never been closed on GitHub —
> the repository record was being kept and the issue list was not.
>
> **Four remain open**, and all four were verified as still live rather than
> assumed: **#40** per-user isolation (not started), **#42** egress (above),
> **#11** firewall posture (nothing pins a netfilter backend) and **#12** VLAN
> cleanup (the `KNOWN GAP (DRAFT-029 follow-up)` is still in
> `network-setup.sh:325`).
>
> M7 is now fully closed on GitHub except the `[preset.x]` item, so **M8 is the
> only open platform milestone.**

The remaining twelve stay unpublished deliberately: ten *older* index rows
still have no file, and adding twelve more issues on top would widen that gap
rather than close it. See below.

| Draft ID | Title | Area | OS | Milestone | Priority | Depends on | Origin |
|---|---|---|---|---|---|---|---|
| DRAFT-019 | Integrate capa against DRAKVUF logs | enrichment | ALL | M4 | P1 | DRAFT-018 | Indexed from the start, **never written until now** |
| DRAFT-048 | Static analysis of the submitted sample (FLOSS, YARA, per-format) | enrichment | ALL | M4 | P1 | #37 | Capability comparison, 2026-08-25 |
| DRAFT-049 | Network processing — read the pcap we already capture | enrichment | ALL | M4 | P1 | #37, DRAFT-050 | Capability comparison |
| DRAFT-050 | Audit all 45 DRAKVUF plugins and evidence the ones that earn it | core | ALL | M4 | P0 | Nothing | `plugins.h`, 2026-08-24 |
| DRAFT-051 | Memory and payload extraction — YARA over dumps, family configs | enrichment | ALL | M5 | P2 | DRAFT-022 (licence), DRAFT-048 | Capability comparison |
| DRAFT-052 | Per-job plugin selection and trace budget | core/platform | ALL | M5 | P2 | **DRAFT-060** | Maintainer, 2026-08-24 |
| DRAFT-053 | Public report links, and the `infected` packaging that makes them safe | core/platform | ALL | M5 | P2 | #37, #39, borrows #40's `visibility` | Maintainer, 2026-08-24 |
| DRAFT-054 | Screenshots — a filmstrip from the Xen framebuffer | enrichment | ALL | M5 | P2 | DRAFT-060 | Maintainer, 2026-08-24 |
| DRAFT-055 | `hidsim` — synthetic mouse and keyboard, no inbound channel | core | ALL | M5 | P2 | DRAFT-050, DRAFT-052 | `plugins.h` + maintainer |
| DRAFT-056 | Live interactive analysis — noVNC over a relay we own | core/platform | ALL | M6 | P3 | DRAFT-060, #39, #40 | Maintainer, 2026-08-25 |
| DRAFT-057 | Egress routing — offline, direct, or through an exit we choose | platform/security | ALL | M2 | **P0** | DRAFT-022 | `ideas.md` + roadmap risk #13 |
| DRAFT-058 | Guest locale and keyboard layout as an analysis control | core | ALL | M5 | P2 | DRAFT-052, golden images | `ideas.md` |
| DRAFT-059 | Archive submission — password-protected archives and multi-file samples | core/platform | ALL | M4 | P1 | #36, #37, DRAFT-060 | Maintainer, 2026-08-25 |
| DRAFT-060 | `sandboxd` — the analysis orchestrator, and argv instead of shell | core/platform | ALL | M2 → gates M7 | **P0** | #35, #36, #37 | DRAFT-041, **never drafted until now** |

### What this batch is, and why it is shaped this way

#38 was rescoped rather than enlarged. It builds the **shell** — layout,
theme, submit, history, live status, a tab framework — and each capability
became its own issue filling one tab with its own evidence. Forced by the
plugin matrix as much as chosen: a Registry tab cannot exist on Ubuntu, so the
tab list is computed per guest rather than fixed.

### Two P0s that were nobody's

- **DRAFT-060 (`sandboxd`)** — named in `platform.md` since 2026-08-21,
  carried in this index as "deferred", **never given a draft**, while three
  capability tracks queued behind it. It is now the critical path.
- **DRAFT-057 (egress routing)** — `offline` was proposed in
  `networking.md`, recorded in the roadmap as undecided M2 work, and left
  unowned. It is the only issue here that gates whether real malware can be
  detonated at all; everything else assumes a sample already ran.

### Most of this batch is testable without Dom0

Noted by the maintainer, 2026-08-25, and it changes the order things can be
built in. The platform-side drafts — **019, 048, 049, 051, 053, 059** — are
post-processing over objects that already exist, so they can be exercised with
scripts against the live API at `sandbox.evilbootloader.com`, the way
`platform/submit.py` already is. No analysis host, no clone, no Dom0 session.

That is most of the capability set. Only **050, 052, 054, 055, 056, 057, 058
and 060** need Dom0 at all, and 060 gates several of those.

### The ten fileless index rows, triaged 2026-08-25

Maintainer went through them. Most were not gaps at all — they were rows
describing work that has since been decided elsewhere, and the index simply
never caught up.

**Superseded — strike from the index, do not write:**

| Draft | Why it is gone |
|---|---|
| DRAFT-011 | Structured status output. **Superseded by the web UI.** `status.json` existed so an operator could see state, queue reason and failure stage; #38 renders all three from the job row, live over SSE |
| DRAFT-012 | Static CI. Already superseded by DRAFT-026, recorded years-of-index ago and never struck |
| DRAFT-014 | Sample OS auto-detection contract. **Already decided, and shipped.** Issue #3 settled it: the *operator* selects the target, and libmagic only judges whether the sample is appropriate for it. That is `_contradicts()` in `routers/jobs.py` — detection rejects a mismatch and never routes |
| DRAFT-017 | Android sample classification. Same decision, and `drakvuf-android.sh` already selects APK-vs-ELF structurally from the sample's own bytes |
| DRAFT-035 | Job control channel. **Superseded in three pieces** — see below |

**DRAFT-035, piece by piece**, because it is the one worth being precise about:

- **Cancellation** — done. #36 delivers it in the heartbeat *response*
  (`cancel_requested`), which is what keeps Dom0 from needing an inbound
  listener.
- **Retry guard** — **decided, and it is a divergence from `dirwatch`.**
  `dirwatch.c` retries internally on timeout, spawning a fresh clone for the
  same sample. The platform has **no requeue path**: `reap` marks an expired
  lease `interrupted` and nothing returns a job to `queued`. That is
  deliberate. A retry is a **new job with a new id**, submitted by an
  operator who decided to — not a loop the daemon runs on its own.
  **#41 must preserve this rather than port `dirwatch`'s behaviour across.**
- **Per-OS watch-directory admission** — largely moot. `dirwatch`'s one
  directory per OS *was* the routing mechanism; the API's `POST /jobs` with a
  validated `target_os` replaced it. Whether anything remains here is the one
  open question in the row.

**Deferred — real, but not before a basic sandbox runs end to end:**

DRAFT-021 (licensing write-up), DRAFT-023 (TLS-visibility spike for
Linux/Android), DRAFT-024 (pin and mirror both DRAKVUF upstreams).

DRAFT-024 is the one to revisit first when the time comes: the 2026-08-24
`plugins.h` read narrowed what actually needs mirroring from "Linux/Android
plugin support" to **two plugins**, so the job is smaller and better specified
than when it was written.

**Still needed:**

- **DRAFT-018** — the result schema. The only fileless row that is a live
  dependency of written work: DRAFT-019 declares it, and every capability
  draft writes a `*.json` into a schema nobody has specified. Not urgent
  because each draft defines its own output, and that is precisely how the
  outputs drift apart.
- **DRAFT-020** — **now written**, and its row title was wrong. "Windows
  baseline selection + clone-per-run confirmation" describes DRAFT-034's work
  (which says so, and supersedes that half) plus a question already closed
  (clone-per-run, by elimination). What was actually unwritten is **what
  software is installed in the guests** — Office, a browser, a PDF reader, the
  .NET and VC++ runtimes, and an unpacker that DRAFT-059 hard-depends on;
  plus the realism settings that stop the guest announcing itself. Windows
  first, measured with Pafish before and after, then the same method
  elsewhere. Maintainer, 2026-08-25.

