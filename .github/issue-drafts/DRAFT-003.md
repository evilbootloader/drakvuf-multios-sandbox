# DRAFT-003: Reorganize docs/ into roadmap/architecture/checklists, preserving Android checklist evidence verbatim

**Status:** **[#20](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/20) — published and closed 2026-08-19.** Closed — done 2026-08-07
**Area:** governance
**Milestone:** M0
**Priority:** P0
**Depends on:** DRAFT-001 (for commit ordering)

# Objective

Split `docs/android-drakvuf-automation-checklist.md` from absorbing the
entire product roadmap by introducing `docs/roadmap/`, `docs/architecture/`,
and `docs/checklists/`, while preserving every checkbox, evidence block,
issue-log entry, and change-log entry in the Android checklist exactly as
written.

# Context

The original checklist was both an Android-specific execution log *and*,
implicitly, the only place broader product-planning content could have
gone. The user explicitly wanted the Android checklist to stay
Android-specific once a real roadmap existed, and explicitly required no
loss of evidence during the move — the checklist contains real, dated
evidence (checksums, PID records, config paths) mixed with unfilled
evidence templates that must not be mistaken for "safe to delete."

# Dependencies

DRAFT-001 (git, for commit ordering / diff review).

# Out of scope

- Rewriting or summarizing any checklist content — this was a structural
  move only, with exactly two content fixes (see DRAFT-004).
- Deciding the final home for `docs/checklists/platform.md` vs. a separate
  `web-platform.md` — resolved during CREATE by merging them, since keeping
  both would have created the near-duplicate files explicitly flagged as a
  risk during planning.

# PLAN

1. Read `docs/android-drakvuf-automation-checklist.md` in full (2,476
   lines, two chunks given the tool's read-window limit).
2. Write it verbatim to `docs/checklists/android.md`.
3. Verify line-for-line alignment against the original by comparing tail
   offsets before making any further edits.
4. Apply the two DRAFT-004 fixes as separate, auditable edits — not baked
   into the initial copy.
5. Create `docs/roadmap/project-roadmap.md`, `docs/architecture/*.md` (5
   files), and `docs/checklists/{ubuntu,windows,platform}.md` as new
   content, clearly distinguishing source-verified facts from proposed/
   pending design work in each.

# CREATE

Files created: `docs/checklists/android.md`, `docs/checklists/ubuntu.md`,
`docs/checklists/windows.md`, `docs/checklists/platform.md`,
`docs/roadmap/project-roadmap.md`, `docs/architecture/analysis-pipeline.md`,
`docs/architecture/networking.md`, `docs/architecture/result-schema.md`,
`docs/architecture/upstream-drakvuf.md`, `docs/architecture/licensing.md`.

The original `docs/android-drakvuf-automation-checklist.md` was **not**
deleted — no delete capability was available in the environment this was
drafted in (Bash was non-functional). It should be removed via `git rm`
once DRAFT-001's repository exists, so the removal is a reviewable diff
rather than an unrecoverable manual deletion.

# TEST

- Verified by reading back `docs/checklists/android.md` and confirming line
  numbers for the tail section (change log, issue log, source-files list)
  matched the original file's line numbers exactly, with only line 2468
  (the doc-reference fix) differing and one appended provenance note.
- No automated test applies to a documentation move; the verification was
  manual line-alignment comparison, done in the same session.

# DEPLOY

Not applicable — documentation only, no infrastructure impact.

# Acceptance criteria

- [x] `docs/checklists/android.md` is a verbatim copy of the original,
  modulo the two DRAFT-004 fixes.
- [x] `docs/roadmap/`, `docs/architecture/`, `docs/checklists/` all exist
  with the planned content.
- [x] No checklist evidence, checkbox state, or log entry was altered.
- [x] Original `docs/android-drakvuf-automation-checklist.md` removed.
  Satisfied by a different mechanism than originally planned: per
  DRAFT-001's evidence log, the file was deleted before the initial commit
  rather than tracked-then-`git rm`'d, so it never entered history at all.
  Confirmed absent from the current working tree.

# Evidence required

The line-alignment comparison performed during CREATE (see TEST above);
the new files themselves.

# Security considerations

None.

# Documentation changes

This issue is itself the documentation reorganization.

# Recovery / rollback

Once committed, `git revert` restores the pre-reorg single-file layout. The
original file was left in place during this pass specifically so nothing
was lost even before git existed.