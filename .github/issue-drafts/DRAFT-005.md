# DRAFT-005: Add CONTRIBUTING.md capturing PLAN→CREATE→TEST→DEPLOY lifecycle + issue template

**Status:** Closed — done 2026-08-07
**Area:** governance
**Milestone:** M0
**Priority:** P1
**Depends on:** DRAFT-003

# Objective

Capture the `PLAN → CREATE → TEST → DEPLOY` lifecycle, review gates, and
issue-draft template in a durable file, so future sessions (and future
Claude Code instances reading `CLAUDE.md`) inherit the process instead of
re-deriving it from conversation history each time.

# Context

The lifecycle, gates, and issue template existed only as instructions given
in one conversation. Nothing in the repository captured them.

# Dependencies

DRAFT-003 (so `CONTRIBUTING.md` can reference the new `docs/` layout).

# Out of scope

Rewriting or reinterpreting the lifecycle — this is a faithful capture of
what was specified, not a redesign.

# PLAN

Transcribe the PLAN/CREATE/TEST/DEPLOY sections, the human-review gate, the
two-stage GitHub issue workflow, and the issue template, adding only the
minimum project-specific context needed to make it self-contained (e.g.,
the Bash-non-functional caveat found this session, and a pointer to
`docs/roadmap/` and `docs/checklists/`).

# CREATE

Wrote `/CONTRIBUTING.md` with all of the above. `CLAUDE.md`'s "Workflow"
section should get a one-line pointer to it (tracked as part of DRAFT-003's
follow-on CLAUDE.md update, not duplicated here).

# TEST

Read-through only — confirm nothing in the lifecycle was altered or
dropped compared to what was specified.

# DEPLOY

Not applicable.

# Acceptance criteria

- [x] `CONTRIBUTING.md` exists with the full lifecycle, gates, and issue
  template.
- [x] References the actual `docs/` layout and `.github/issue-drafts/`
  directory that exist in this repo.

# Evidence required

The file itself.

# Security considerations

None.

# Documentation changes

This issue is the documentation addition.

# Recovery / rollback

Trivial — revert the file; nothing else depends on its exact wording,
though other docs (`README.md`, `docs/roadmap/project-roadmap.md`) link to
it by filename.