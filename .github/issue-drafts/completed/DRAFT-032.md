# DRAFT-032: Reconcile documentation with current project direction and closed issues #1/#2

> **Retitled 2026-08-09.** Was "Reconcile documentation with issues #1/#2
> and the three-OS project focus". The scope now covers **two** direction
> changes, not one — Windows becoming current (DOC-09) and DRAKVUF engine
> work becoming near-term (CONF-11, section E) — so the old title
> understated it.

**Status:** **[#27](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/27) — published and closed 2026-08-19.** **Applied 2026-08-11**, without being published as a GitHub
issue — a documentation-only pass, so `CONTRIBUTING.md`'s Stage 2 gate was
not triggered and no issue body was edited. Tables A–E below are the record
of what was found; the resolution note at the end of this file records what
each item became.
**Area:** governance / documentation (all OS targets)
**Milestone:** M0
**Priority:** P1
**Depends on:** None open. Independent of every other draft — deliberately,
so it can land immediately.
**Origin:** `project-assessment.md` → Findings → DOC-01 … DOC-09, NET-04,
GOV-02. Extended 2026-08-09 by the repository comment audit → CONF-02,
CONF-03, CONF-04, CONF-06, CONF-07, CONF-08, CONF-11, CONF-12, DOC-N4,
DOC-N5, DOC-N6, TODO-03.

# Objective

Remove completed work that is still presented as outstanding, correct
statements that issues #1 and #2 invalidated, and update the documents that
describe Windows — and DRAKVUF engine work — as deferred when both are
current.

# Context

`CONTRIBUTING.md`'s "Issue dependency and cleanup" section states the rule
this issue enforces: *"The repository state is the source of truth for what
an issue still needs to do, not the original issue text… If work it
requests has already been implemented by an earlier issue: remove the
already-completed task."* Several documents have drifted from that.

This is a bounded, enumerated cleanup — not an open-ended "improve the
docs" issue. The complete list is below; anything not on it is out of
scope.

## A. Already-completed work still listed as open

| ID | Location | Problem |
|---|---|---|
| DOC-02 | `docs/checklists/ubuntu.md:192-195` | Lists `[ ] Reconcile automation/drakvuf-ubuntu.sh with the deployed Dom0 copy … No draft/issue yet` as open M1 work. Issue #2 did exactly this on 2026-08-08, and the same file's Known-issues section (`:108-130`) records it as resolved. The file contradicts itself. |
| DOC-03 | `docs/checklists/ubuntu.md:201-203` | Marks static-check CI as "blocked on Bash being non-functional in this dev container as of 2026-08-07". The blocker is lifted — `bash` 5.3.9, `shellcheck` 0.11.0 and `perl` were re-confirmed working in-container on 2026-08-08 and again on 2026-08-09. Also cites DRAFT-012, which `issue-index.md` records as superseded by DRAFT-026. *(This row previously cited `CONTRIBUTING.md:52-54` as the evidence; that passage was collapsed to a standing instruction on 2026-08-09 — see CONF-12 — so the citation was updated rather than the finding.)* |
| DOC-05 | `docs/checklists/windows.md:41` | Phase 0 carries `[ ] Decide golden-VM lifecycle model (clone-per-run vs. snapshot-restore)` while the same file's status table records the decision as made (clone-per-run, by elimination), matching roadmap decision #3. |
| CONF-06 | `docs/roadmap/project-roadmap.md:27-38` | "Environment & tooling constraints (as of 2026-08-07)" lists three blockers, all since resolved: Bash non-functional in the dev container (lifted — see DOC-03), no git repository (closed as DRAFT-001, baseline `7764b77`, and recorded as such by risk #1 in the same file), and `gh` availability unverifiable (four issues have since been published with it). The section contradicts the roadmap's own risk register two screens further down. **Note:** `CONTRIBUTING.md`'s copy of the Bash narrative was already collapsed on 2026-08-09, so only the roadmap's remains. |
| CONF-07 | `docs/roadmap/project-roadmap.md:222-223` | The "Requires Xen Dom0 / L1" test-classification list includes "re-deriving and validating the missing `.cfg` files against the real host". Risk #6 in the same file records that no config file is missing — all four are tracked under `misc/` — and closes the item. Delete the line. |

## B. Statements invalidated by issues #1 and #2

| ID | Location | Problem |
|---|---|---|
| DOC-01 | `docs/architecture/networking.md:20` | Still documents `ifconfig xenbr1 up`. Issue #2's sync replaced it with `ip link set xenbr1 up` (`network-setup.sh:121`). `docs/checklists/ubuntu.md:66-69` was updated; this file was missed. |
| DOC-06 | `docs/roadmap/project-roadmap.md:69-71` | Current-state section still names `misc/linux_sandbox.cfg` / `misc/linux.cfg`, renamed by issue #1 on both repo and host sides. The file is also stamped "Last updated: 2026-08-07" while containing 2026-08-08 content. |
| DOC-04 | `docs/checklists/ubuntu.md:182-185` | States the hard-coded `/home/user/drakvuf-tools/...` known issue without referencing issue #4, which now owns it. |
| DOC-08 | `docs/architecture/analysis-pipeline.md:44-46` | Says the thread-pool bound is "validated 1–128 in upstream; this project's copy has not been independently re-verified". It has been — `dirwatch.c` enforces exactly that range in `main()`. |
| — | `docs/checklists/ubuntu.md` (issue #2 evidence), `CLAUDE.md` | Record `-e` as execve-direct with no guest shell, without the `[LINUX]` qualifier the source evidence carries (`[LINUX] (execproc -> execve(...); 64bit only)`). Correct for Linux/Android; must not be inherited by Windows injection design unverified. |
| CONF-02 | `.github/issue-drafts/README.md:15` | Lists "DRAFT-007 (issue #2, **open**)". Issue #2 closed 2026-08-08 — commit `885ad3c` is literally titled "Close issue #2", and `issue-index.md:16` records it as Closed. One-word fix. |
| CONF-03 | `.github/issue-drafts/issue-index.md:158-159` | The DRAFT-006 revision note ends "The real Dom0 host's copies still need a separate manual rename; see the issue #1 thread." That rename was completed 2026-08-08 — stated at `:111-113` of the **same file**, and evidenced in `docs/checklists/ubuntu.md:132-145` with the exact `mv` and a re-tested run. Delete the stale sentence. |
| CONF-04 | `docs/workflow-ci.md:55-58` | A CI goal reads: prevent drift because "'Ubuntu automation works' is currently an assertion … that has never been re-verified by execution evidence in this repository." It has been, on 2026-08-08 — and lines 41-43 and 599-605 of the **same file** say so. Rewrite the goal as drift-prevention, which is what it is actually for now. |
| DOC-N4 | `docs/checklists/android.md:2478` (provenance footer) | Still names `misc/linux.cfg` (golden `ubuntu`) and `misc/linux_sandbox.cfg` (`ubuntu_sandbox`) and comments on "the misleading 'linux' filenames" — renamed by issue #1 the following day. **This line is editable despite the file-wide annotate-only rule:** it is itself an editorial annotation added during the 2026-08-07 reorg and explicitly marked "not part of the original checklist content above", so correcting it preserves the evidence boundary rather than crossing it. See the carve-out in Acceptance criteria. |

## C. Descriptions that do not match the implementation

| ID | Location | Problem |
|---|---|---|
| NET-04 | `CLAUDE.md`, `docs/checklists/ubuntu.md:65-67` | Both describe `network-setup.sh` as provisioning "the OVS bridge". It does not — it calls only `modprobe`/`ip`/`vconfig`/`iptables`. `xenbr1` is created by a separate documented install step, `ovs-vsctl add-br xenbr1` (`docs/drakvuf-on-xen-nested-within-proxmox.md:421`). |
| DOC-07 | `README.md:1`, `CLAUDE.md:1` | Titled "DRAKVUF **Android** Automation Project" for a repository named `drakvuf-multios-sandbox` covering three OS targets. `README.md`'s layout section also omits `docs/runbooks/` and `docs/workflow-ci.md`, both of which now exist. |
| DOC-N5 | `docs/checklists/android.md:24,26` (status table) | Stamped `Last update \| 2026-08-06`; the file was edited 2026-08-07 (docs reorg), 2026-08-08 (commit `885ad3c`) and 2026-08-09 (Phase 2 annotations). `Current blocker` is **blank** while §1.3's network-isolation verification is recorded as open and blocking by the roadmap (risk #5), `docs/architecture/networking.md`, and §1.3 itself. `docs/checklists/ubuntu.md` keeps both fields current — apply the same treatment. |
| DOC-N6 | `CLAUDE.md` → "Source documentation" list | `docs/Project-definition.txt` is listed **first**, so it is the first document a reader or agent opens. Its five lines say the project supports "ubuntu malware (without network connection)" and point at `automated_drakvuf_on_xen_nested_within.md`, a filename that does not exist (the file is `drakvuf-on-xen-nested-within-proxmox.md`). Both are wrong now: Android Phase 1 is evidenced, Windows is current, and clones have unrestricted NAT egress by default (NET-03). **Do not edit the file** — it is an imported source document. Demote it in `CLAUDE.md`'s list to a historical-provenance entry, so its framing is not read as current. |
| TODO-03 | `docs/checklists/android.md:1930,1948` (§6.1) | The acceptance gate demands "No remaining `<USER>` or placeholder paths" and greps `'<USER>\|TODO\|FIXME'`. Two problems: the grep is written as a bare command whose exit status inverts the intended meaning (same defect as CI-02 in `docs/workflow-ci.md`), and the TODO/FIXME clause would now **fail on two legitimate markers** — `clone-ubuntu.pl`'s stubdomain TODO and §1.3's own heading. Narrow the gate to `<USER>` and placeholder paths; drop the TODO/FIXME clause. A zero-TODO policy is not the policy this repository wants. |
| CONF-12 | `docs/checklists/ubuntu.md:272` | Reads "consistent with `CONTRIBUTING.md`'s re-verification note (they were not on 2026-08-07)". That note was collapsed to a standing instruction on 2026-08-09 (audit finding MISS-03), so the citation now dangles. The statement was true when written and sits inside a dated evidence block, so **annotate rather than edit** — record that the cited passage was later collapsed and where the fact now lives. *(Self-inflicted: the MISS-03 change should have swept its citations in the same pass. Recorded here as the worked example behind the proposed comment-policy rule that a change updates the comments and checklists it touches.)* |

## D. Windows described as deferred

**DOC-09.** Windows is now a current target alongside Ubuntu and Android.
Five locations still describe it as planned or not-started:

| Location | Current wording |
|---|---|
| `CLAUDE.md:11,16` | "(planned) Windows analysis guest"; "Windows is a planned future target" |
| `README.md:10,16` | "L2 Windows analysis VM (planned)"; "Windows is a planned future target" |
| `docs/roadmap/project-roadmap.md:11,18,78` | "Windows(planned)"; "no work started at all"; "**Windows** — no work started" |
| `docs/roadmap/project-roadmap.md:161` | M5 = "Windows planning spike … Design only" |
| `docs/checklists/windows.md:3-11` | "skeleton only… No Windows automation work has started" |
| `docs/workflow-ci.md:617` | "Windows CI once the M5 planning spike (`docs/checklists/windows.md`) produces a baseline" — a **sixth** location, not in the original five. Point it at DRAFT-034 instead. *(Added 2026-08-09; CONF-08. Confirmed by the project owner the same day: a Windows analysis VM is wanted and DRAFT-034 is its track head.)* |

Two consequences beyond wording, both of which change *technical*
statements:

- **`tlsmon` stops being "Not applicable".**
  `docs/roadmap/project-roadmap.md:90` (reuse table) and risk #4 (`:180`)
  both record tlsmon as not applicable because it hooks Windows
  `ncrypt.dll`/Schannel only — source-verified in
  `docs/architecture/networking.md:61-64`. With a Windows guest in scope,
  tlsmon becomes the only TLS-visibility path the project actually has.
  Risk #4 should be rescoped to "no TLS visibility *on Ubuntu/Android*".
- **The `lfreijo` fork matters less for Windows.**
  `docs/architecture/upstream-drakvuf.md:31` records ~30 Windows-oriented
  plugins present upstream, and the pinned fork commit is titled "Add
  **Linux** support for memdump, filetracer, fileextractor, and syscalls
  plugins". The Windows track leans on upstream `tklengyel/drakvuf`, which
  narrows risk #8's scope — worth stating, since it changes what DRAFT-024
  has to pin.

## E. DRAKVUF engine work described as deferred to M9

**CONF-11.** Added 2026-08-09. Modifying DRAKVUF source — adding
functionality to the engine, not just orchestrating it — is **near-term
intended work**. Three documents forbid it until the last milestone:

| Location | Current wording |
|---|---|
| `docs/architecture/upstream-drakvuf.md:71-72` | "Do not begin modifying DRAKVUF engine code itself until a stable per-OS pipeline exists (Milestone M9, deliberately last)." |
| `docs/roadmap/project-roadmap.md` M9 row | "Upstream DRAKVUF contribution — Only after a stable OS pipeline + resolved repo strategy. Deliberately last." |
| `docs/roadmap/project-roadmap.md` dependency graph | "upstream DRAKVUF engine work (deliberately last; depends on ≥1 stable OS pipeline + repo-strategy decision)" |
| `.github/issue-drafts/issue-index.md:183` | DRAFT-024 scoped to "mirror/backup + pin documentation" — insurance against the fork disappearing, not a baseline to develop against. |

This is the same class of item as DOC-09, and it is why this issue was
retitled. It differs from every other finding in this document in one
respect worth stating plainly: **nothing in the repository contradicts it.**
Ordinary drift leaves a seam — one document disagreeing with another, or
with the code. Here all four locations agree, and only the project's actual
direction disagrees with all of them. A reader has no signal that the
constraint is stale, so an agent asked to work on the engine would defer or
refuse, citing M9 correctly.

Two consequences that change technical statements, not just sequencing:

- **DRAFT-024's purpose changes.** Pinning both upstreams is currently
  justified as bus-factor insurance (risk #8) at P2. If engine code is
  about to be modified, a pinned revision becomes the baseline those
  changes are diffed from — a prerequisite, not a precaution.
  `issue-index.md:221` already argues for raising it from P2 for a
  different reason (DRAFT-026b builds from source with nothing pinned);
  this is a second, independent one.
- **DRAFT-010's purpose changes.** Documenting `dirwatch.c`'s interface
  becomes input to engine work rather than documentation for its own sake
  — and `dirwatch.c` is already the file `docs/workflow-ci.md`'s Level 2
  tier rebuilds from on every PR. Its unresolved `dirwatch.c` /
  `dirwatch_old.c` authority question stops being a tidy-up.

Do **not** renumber milestones here. Record the direction change and the
two consequences; let the affected drafts propose their own resequencing,
the same way this issue defers Windows renumbering to DRAFT-034.

# Dependencies

None. This issue is deliberately self-contained so it does not queue
behind the implementation work it describes.

# Out of scope

- **Rewriting historical evidence.** `docs/checklists/android.md`'s dated
  evidence blocks, `docs/runbooks/01-verify-user-placeholder.md`,
  `.github/issue-drafts/DRAFT-001…007`, and the roadmap's dated correction
  narratives are records of what was true when written. Where they are now
  outdated, **annotate**, never edit in place — the precedent is issue
  #1's revision note.
- Populating `docs/checklists/windows.md` with actual Windows phases. This
  issue changes its *status framing*; building the track is DRAFT-034.
- Any change to `automation/` or `misc/`. Documentation only.
- The `carlos` / `vg-root` / `xenbr1` parameterization discussion —
  DRAFT-009/DRAFT-011.
- Re-deciding anything. Every item above is a correction to match a
  decision already made and evidenced elsewhere.

# PLAN

1. Confirm each item in tables A–E still applies at implementation time —
   several reference line numbers that other in-flight issues may shift.
   **This is not theoretical: as of 2026-08-09 the line references into
   `docs/checklists/android.md` inherited from `project-assessment.md` are
   already off by roughly two** (its `:1003` is now `:1001`, `:1877` is now
   `:1922`, `:2250` is now `:2249`), from commit `885ad3c` plus the Phase 2
   annotations. Match on text, not line number.
2. For each, classify as *correct in place* (current-state documentation)
   or *annotate only* (historical evidence). Get this wrong and the issue
   destroys evidence, which is the one failure mode that matters here.
   Two items are deliberately classified against the file-wide default:
   **DOC-N4** is editable inside an otherwise annotate-only file (it is an
   annotation itself), and **CONF-12** is annotate-only inside an
   otherwise-editable one (it sits in a dated evidence block).
3. Confirm the Windows framing with the project owner before editing
   `CLAUDE.md`/`README.md` headline text — a title change is visible and
   should be deliberate.
4. Decide whether `docs/roadmap/project-roadmap.md`'s milestone table needs
   restructuring, or only M5's wording. Windows moving from M5-design-only
   to a current track arguably reorders M2–M5; recommendation is to note
   the change here and let DRAFT-034 propose any renumbering, so this issue
   stays a documentation correction rather than a replan.

# CREATE

1. Table A: delete the completed items, leaving the resolved records that
   already exist elsewhere in the same files.
2. Table B: correct each statement; add the `[LINUX]` qualifier to the
   `-e` semantics note wherever it appears as current-state guidance.
3. Table C: describe `network-setup.sh` as what it does, and state that
   the OVS bridge is created by a separate install step; retitle
   `README.md`/`CLAUDE.md` and complete the repository-layout list.
4. Table D: update all **six** locations; rescope roadmap risk #4 and reuse
   table row for `tlsmon`; note the two-upstream distinction for risk #8.
5. Table E: correct the three M9 statements and `issue-index.md`'s
   DRAFT-024 scoping; record the two consequences (DRAFT-024's purpose,
   DRAFT-010's purpose) without renumbering milestones.
6. Update `docs/roadmap/project-roadmap.md`'s "Last updated" stamp, and
   its Current-state section to name the three current targets.
7. Update `docs/checklists/android.md`'s status table (DOC-N5) — the
   `Last update` stamp and the empty `Current blocker` field.

# TEST

Documentation only — verification is grep-based and runs locally:

```bash
# No stale references remain (excluding preserved historical evidence):
grep -rns "ifconfig" docs/ CLAUDE.md README.md
grep -rns "linux_sandbox.cfg\|misc/linux.cfg" docs/ CLAUDE.md README.md
grep -rns "planned future target\|Windows(planned)\|no work started" docs/ CLAUDE.md README.md
grep -rns "provisions the OVS bridge" docs/ CLAUDE.md

# Added 2026-08-09:
grep -rns "deliberately last\|until a stable per-OS pipeline" docs/ .github/   # CONF-11
grep -rns "M5 planning spike" docs/                                            # CONF-08
grep -rns "issue #2, open\|still need a separate manual rename" .github/       # CONF-02, CONF-03
grep -rns "never been re-verified by execution evidence" docs/                 # CONF-04
grep -rns "re-verification note" docs/                                         # CONF-12
grep -rns "missing \`.cfg\` files" docs/                                       # CONF-07

# Historical evidence is untouched, with one deliberate exception:
git diff docs/checklists/android.md
# expect: annotation-only additions with zero deletions, EXCEPT the
# provenance footer at the end of the file (DOC-N4) and the status table
# (DOC-N5), both of which are editorial rather than recorded evidence.
git diff --stat docs/runbooks/ .github/issue-drafts/DRAFT-00*.md
# expect: no changes at all
```

Read-through review of each changed passage against the source it cites.
No Xen access required; no execution evidence applies.

# DEPLOY

Not applicable — documentation only, no infrastructure impact.

# Acceptance criteria

- [ ] Every item in tables A, B, C, D and E is corrected or annotated.
- [ ] No completed work remains listed as an open task in
      `docs/checklists/ubuntu.md` or `docs/checklists/windows.md`.
- [ ] `docs/architecture/networking.md` matches the synced
      `network-setup.sh`, including the OVS-provisioning correction.
- [ ] The `-e` execve-direct finding carries its `[LINUX]` qualifier
      everywhere it appears as current-state guidance.
- [ ] All five Windows-status locations describe it as a current target.
- [ ] Roadmap risk #4 is rescoped to Ubuntu/Android; the reuse table's
      `tlsmon` row no longer reads "Not applicable" unqualified.
- [ ] Roadmap risk #8 notes that the Windows track depends on upstream
      `tklengyel`, not the single-maintainer fork.
- [ ] `git diff` shows **zero deletions** in `docs/runbooks/` and
      `.github/issue-drafts/DRAFT-001…007.md`, and zero deletions in
      `docs/checklists/android.md` **except** its provenance footer
      (DOC-N4) and status table (DOC-N5). *(Carve-out added 2026-08-09.
      The original criterion forbade touching either, but both are
      editorial metadata rather than recorded evidence — the footer says
      so about itself. Forbidding their correction was the rule
      overshooting its purpose.)*
- [ ] Every grep in TEST returns only intentionally-preserved historical
      matches, each explainable.
- [ ] All four M9 "engine work is deferred" statements are corrected, and
      the two consequences (DRAFT-024's purpose, DRAFT-010's purpose) are
      recorded in those entries — without renumbering milestones here.
- [ ] `.github/issue-drafts/README.md` and `issue-index.md` no longer
      contradict themselves about the status of issues #1 and #2.
- [ ] `docs/checklists/android.md`'s `Current blocker` field names the
      §1.3 network-isolation gap, and its `Last update` stamp is current.
- [ ] `docs/Project-definition.txt` is unchanged, and `CLAUDE.md` no
      longer presents it as current-state reading.

# Evidence required

The diff, plus the TEST grep output with any remaining matches explained
one by one.

# Security considerations

None directly — no code, permissions, or containment behaviour changes.

One indirect point worth stating: correcting NET-04 removes a false
assurance. A reader currently believes `network-setup.sh` provisions the
OVS bridge and, by extension, that running it is sufficient to establish
the analysis network. It is not, and that gap is part of why DRAFT-028
exists.

# Documentation changes

This issue *is* the documentation change: `README.md`, `CLAUDE.md`,
`docs/roadmap/project-roadmap.md`, `docs/architecture/networking.md`,
`docs/architecture/analysis-pipeline.md`, `docs/checklists/ubuntu.md`,
`docs/checklists/windows.md`, and annotation-only additions to
`docs/checklists/android.md`.

Added 2026-08-09: `docs/architecture/upstream-drakvuf.md` (CONF-11),
`docs/workflow-ci.md` (CONF-04, CONF-08),
`.github/issue-drafts/README.md` (CONF-02) and
`.github/issue-drafts/issue-index.md` (CONF-03, CONF-11's DRAFT-024
scoping). The last two make this issue touch the issue-drafts directory,
which is a GitHub-facing artifact — but only the local draft files, not
published issue bodies, so `CONTRIBUTING.md`'s Stage 2 gate is not
triggered. Do not `gh issue edit` anything as part of this work.

Not in scope: `docs/Project-definition.txt` itself (DOC-N6 changes only how
`CLAUDE.md` presents it) and `CONTRIBUTING.md` (its half of CONF-06 was
already collapsed on 2026-08-09).

# Recovery / rollback

`git revert`. Nothing depends on the exact wording, and the
evidence-preservation rule means no information is destroyed even if the
change is wrong.

---

# Resolution — 2026-08-11

Applied as a documentation-only pass. Per PLAN step 1, every item was
re-confirmed against current file contents by text match rather than line
number; the line references above had drifted and are left as written.

**Three items needed no change** — later work had already resolved them:

| ID | Why |
|---|---|
| DOC-04 | `docs/checklists/ubuntu.md` already records the hard-coded `/home/user/drakvuf-tools/...` paths as "fixed 2026-08-09 (issue #4)". |
| CONF-02 | `.github/issue-drafts/README.md:15` already reads "DRAFT-007 (issue #2, closed)". |
| CONF-04 | The offending sentence had been reworded already; the goal was still framed as an assertion-check rather than drift-prevention, so it was rewritten anyway. |

**Everything else was corrected or annotated**, and the classification in
PLAN step 2 held: the two deliberate exceptions (DOC-N4 editable inside an
annotate-only file, CONF-12 annotate-only inside an editable one) were both
honoured.

Corrections beyond the enumerated list, all in the same class and each
noted in place:

- `docs/architecture/networking.md` gained the `xenbr1`-is-not-created-here
  paragraph (the NET-04 fix needed a home in the architecture doc, not only
  in `CLAUDE.md`/`ubuntu.md`) and the Windows half of the `tlsmon` rescope.
- `docs/roadmap/project-roadmap.md`'s layout diagram was retitled from
  "Proposed" to actual and gained `docs/runbooks/`, `docs/workflow-ci.md`,
  `profiles/` and `state/` — the same omission DOC-07 raised against
  `README.md`.
- `README.md`'s Testing section gained `dash -n`, which `CLAUDE.md` requires
  and `README.md` omitted, plus the current `shellcheck` state.
- `docs/checklists/android.md` §6.1 gained `dash -n` alongside the TODO-03
  fix.
- `.github/issue-drafts/issue-index.md`'s two superseded ordering blocks
  were **deleted** rather than marked superseded, and replaced with a single
  "Current order (consolidated 2026-08-11)" section. The load-bearing
  constraints scattered across three dated addenda were merged into one
  list there; the duplicated bullets were removed at source.

**Verification.** All ten TEST greps run; every remaining match is either a
preserved historical record, a dated evidence block, or this pass's own
quotation of the text it corrected. `git diff --stat docs/runbooks/
.github/issue-drafts/DRAFT-00*.md` is empty as required. Deletions in
`docs/checklists/android.md` are confined to the status table (DOC-N5), the
provenance footer (DOC-N4), §6.1's unticked Candidate command block
(TODO-03), and one stray `roo` typo.

**Not done, and deliberately out of scope:** the title change was confirmed
with the project owner first, per PLAN step 3 — both headings are now
"DRAKVUF Multi-OS Sandbox". Milestones were not renumbered, in either the
Windows (D) or engine-work (E) case, exactly as the draft directed.