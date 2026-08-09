# Contributing

This project uses a `PLAN → CREATE → TEST → DEPLOY` lifecycle with mandatory
human-review gates. It exists because this repo automates infrastructure
that's expensive to get wrong (Xen/LVM/OVS state, a golden malware-analysis
VM, real malware samples) — every stage below stops for review before the
next one starts.

## PLAN

1. Explore the current code and documentation.
2. Understand existing interfaces before proposing replacements.
3. Identify dependencies and ordering.
4. Research upstream projects/documentation when necessary.
5. Produce an implementation plan.
6. Think hard to break large work into small, independently verifiable tasks.
7. Identify risks, unknowns, and decisions requiring experimentation.
8. Do not modify production/lab infrastructure.
9. Do not commit.
10. Do not push.
11. Do not create GitHub issues yet.

The plan is reviewed before CREATE begins.

## CREATE

1. Make only the changes belonging to the approved task.
2. Keep changes small and reviewable.
3. Add tests alongside functionality where practical.
4. Update the comments, checklists and cross-references this change
   touches, in the same change. A comment left describing the pre-change
   behaviour is a defect in the change, and a citation left pointing at
   text the change removed is the same defect one file over. See
   "Comments and historical context".
5. Do not commit.
6. Do not push.
7. Do not deploy changes to Xen/Proxmox automatically.
8. Show the resulting diff.

## TEST

Every task must define how it is verified. Tests can include: unit tests,
static analysis, `shellcheck`, `bash -n`, `perl -c`, Python tests/type
checking, fixture-based tests, mocked-infrastructure tests, benign
integration fixtures, or disposable Xen clone tests where explicitly
approved.

Distinguish between:

- tests that can run inside the development container;
- tests that must run on L1 Xen Dom0;
- tests that execute inside L2 analysis guests.

Static checks (`bash -n`, `shellcheck`, `perl -c`) run in the development
container. If it ever loses the ability to spawn processes, defer them to
the real host or CI rather than skipping them.

Do not claim a task is complete without evidence.

## Human review / commit gate

After CREATE and TEST:

1. Show all modified files.
2. Show the relevant diff.
3. Show test commands and results.
4. List unresolved warnings/limitations.
5. Stop.

Commits are made by the project owner, not automatically. Never run
`git commit` or `git push` unless this policy is explicitly changed.

## DEPLOY

Deployment is separate from implementation. For changes affecting Xen, LVM,
Open vSwitch, firewall rules, routing, VM snapshots, golden analysis VMs,
saved VM state, the DRAKVUF installation, or real malware, prepare
deployment and rollback instructions first. Do not perform destructive or
infrastructure-changing operations unless explicitly approved.

## GitHub issue workflow

Work is broken into small GitHub issues, but issue creation is a side
effect requiring human review — it happens in two stages.

### Stage 1 — draft only

Local issue drafts live under `.github/issue-drafts/`, one Markdown file
per proposed issue, plus `.github/issue-drafts/README.md` and
`.github/issue-drafts/issue-index.md`. The index shows: draft ID, title,
area, milestone, priority, dependencies, blocking issues, and approximate
implementation order. Each issue represents one small, independently
verifiable change rather than an entire subsystem. If an issue is too large
to have precise acceptance criteria, split it further. Prefer dependency
relationships over relying only on issue numbering.

Each issue draft uses this template:

```markdown
# Objective

# Context

# Dependencies

# Out of scope

# PLAN

# CREATE

# TEST

# DEPLOY

# Acceptance criteria

# Evidence required

# Security considerations

# Documentation changes

# Recovery / rollback
```

### Stage 2 — publication gate

Before creating any GitHub issue with `gh`:

1. Show the complete issue index.
2. Show all proposed issue titles.
3. Summarize dependencies.
4. Show the exact `gh issue create` commands that would be executed.
5. Stop and ask for approval.

Do not run those commands until approved. Before publishing anything,
inspect `gh --version`, `gh auth status`, and `gh repo view`. Do not create
repositories, issues, labels, milestones, or projects during a PLAN pass.

### Issue dependency and cleanup

The repository state is the source of truth for what an issue still needs
to do, not the original issue text. Issue text drifts stale as work lands;
the code, docs, and checklists don't.

**Before starting or updating any issue** (draft or published): compare
what it asks for against the current repository state. If work it requests
has already been implemented by an earlier issue:

- remove the already-completed task from the issue;
- update or simplify the affected acceptance criteria;
- remove implementation steps that are now obsolete;
- keep only the work that is still actually required;
- update the `Dependencies` field / issue-index dependency column if the
  relationship has changed;
- do not reimplement functionality just because it still appears in an
  older issue's description.

**When an issue is completed**, also review later/open issues that depend
on it or overlap with its scope. For each affected later issue:

1. Identify which of its tasks the just-completed issue already covered.
2. Remove those tasks.
3. Update paths, commands, and assumptions the implementation changed.
4. Remove acceptance criteria that are already satisfied.
5. Keep relevant historical/context information, but clearly separate it
   from what remains outstanding (see the `issue-index.md` "Note on
   DRAFT-NNN" sections for the existing pattern).
6. Reference the completed issue so the scope change is traceable.

Do not close a later issue merely because part of its scope landed
elsewhere. If *all* of its requirements turn out to already be satisfied,
report that and recommend closing it — do not close it silently.

This cleanup pass is itself a change to a GitHub-facing artifact, so it
follows the same gate as issue creation: before running `gh issue edit` (or
editing a merged/published draft file) to apply any of the above, show the
proposed diff and get explicit approval, unless automatic issue maintenance
has been explicitly authorized for the session.

## Comments and historical context

> The repository explains **the current system** and the reasoning needed
> to maintain it. **Git history** explains how it got there.

History stays in a current file only when knowing it prevents repeating a
mistake or violating an architectural or security constraint — and then it
carries a date. Everything else belongs in the commit message or in
`docs/`.

These rules exist because each one has already been broken here. The
2026-08-09 comment audit is the worked example; where a rule cites a
specific defect, that defect was real and is in the history.

1. **Comments answer *why*, not *what*.** If the sentence is the next line
   of code translated into English, delete it. The block comments in
   `dirwatch.c`'s `prepare()` — allocation ownership, partial-clone
   cleanup, retry backoff — are the house standard. `network-setup.sh`'s
   former "Enable IP forwarding" above `echo 1 > .../ip_forward` was the
   anti-pattern.

2. **A comment stating a guarantee must be true, or dated.** Comments
   about security, isolation, concurrency, destructive operations or VM
   lifecycle either describe what the code enforces *today*, or say
   explicitly that they do not — `KNOWN GAP (DRAFT-NNN)`, never a bare
   assertion. When an implementation is removed or disabled, its rationale
   comment is rewritten in the same change. An orphaned rationale is worse
   than no comment: `clone-ubuntu.pl` still asserts that only one clone
   process may touch an origin VM at a time while its `flock` sits
   commented out and `dirwatch` runs a thread pool.

3. **Delete commented-out code; git has it.** One exception: a one- or
   two-line optional configuration **that carries a note saying what it is
   for and what still blocks it**. Without that note it is
   indistinguishable from dead code and will eventually be deleted by
   someone tidying up — which nearly happened to `misc/*.cfg`'s
   `#soundhw` line, the only record that audio passthrough is planned. A
   commented-out block that marks a live divergence between two files is
   not an exception; it is a bug to resolve.

4. **No inline changelogs.** "The previous code did X" belongs in the
   commit message or the relevant `docs/` write-up. Inline, state the
   invariant that now holds.

5. **Record direction changes as first-class edits, and sweep what they
   invalidate.** Annotate superseded content in place with a dated line
   and a reference; do not silently rewrite evidence. Then find the
   statements the change falsified and fix them in the same pass.
   Two of the largest errors this project has carried — Windows treated as
   deferred, and DRAKVUF engine work deferred to M9 — were invisible from
   inside the repository, because every document agreed with every other
   one. **Consistency is not evidence of currency.** Nothing but a
   deliberate record catches this class of drift.

6. **Sweep checklists when work lands.** The "Issue dependency and
   cleanup" rule above applies to `- [ ]` boxes too. An unchecked box
   reads as live work with no expiry, and that is where this repository's
   staleness actually accumulates — not in `TODO` markers, of which there
   is currently one in all of `automation/`.

7. **Tag the OS scope of any comment about shared code.** A comment in
   `dirwatch.c`, `network-setup.sh`, `cleanup.sh` or `tcpdump.sh`
   describes behaviour for three pipelines. One in a `*-ubuntu.*` file is
   a template about to be copied twice. Say which.

Two things this policy deliberately does **not** ask for.

It does not ask for *fewer* comments. The 2026-08-09 audit removed 14
lines and added considerably more, because the repository's real problem
was thin explanation, not excess. Four of the six scripts in
`automation/` — `cleanup.sh`, `drakvuf-ubuntu.sh`, `preconfig-ubuntu.sh`
and `tcpdump.sh` — still carry no explanatory comment at all beyond the
DRAKVUF licence header. That is an open gap, not a style to copy when
writing the Android and Windows equivalents.

And it does not ask for a zero-`TODO` repository. A `TODO` naming real,
unscheduled work is worth more than its absence; `automation/` currently
contains exactly one, and it should stay until the question it asks is
answered.

### What not to touch

Dated evidence blocks in `docs/checklists/`, `docs/runbooks/`, and the
resolution sections of closed issue drafts are records of what was true
when written. Annotate them; never edit them in place.

"Never edit in place" scopes *what*, not *how*. Ordinary files — code,
`CLAUDE.md`, the roadmap, the architecture docs — are edited and the diff
is committed; that is what version control is for. The exception is
evidence, which is append-only: its value is that the file itself still
says "on 2026-08-08 we ran X and observed Y." Rewriting that sentence
destroys the record even though git retains the bytes, because nobody
diffs history to find a change they do not suspect.

The imported source guides — `docs/Project-definition.txt`,
`docs/drakvuf-on-xen-nested-within-proxmox.md`, `docs/android_setup.md` —
are provenance for how the lab was originally built and are not kept in
sync with later renames or fixes. Where their staleness is genuinely
confusing, record the discrepancy in the living docs instead.

## Repository organization

See `docs/roadmap/project-roadmap.md` for the current milestone plan and
`docs/checklists/` for per-OS execution evidence, kept separate from the
roadmap so the per-OS checklists stay focused on what's actually been done
rather than absorbing the whole product roadmap.