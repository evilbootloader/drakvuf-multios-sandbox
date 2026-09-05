# DRAFT-002: Add root README.md

**Status:** **[#19](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/19) — published and closed 2026-08-19.** Closed — done 2026-08-07
**Area:** governance
**Milestone:** M0
**Priority:** P1
**Depends on:** DRAFT-001 (nominally — in practice this was done before
git existed, since it's just a file write; sequencing only matters once
commits are involved)

# Objective

Give the repository a human-facing entry point — as of 2026-08-07 there was
no `README.md` at all, only the agent-facing `CLAUDE.md`.

# Context

`CLAUDE.md` documents rules and conventions for Claude Code sessions. It
doesn't orient a human contributor: what this project is, how the repo is
laid out, where to find the roadmap vs. the per-OS checklists, how to run
the static checks. That gap is `README.md`.

# Dependencies

None functionally; listed as depending on DRAFT-001 only for commit
ordering once git exists.

# Out of scope

- A full contributor onboarding guide (that's `CONTRIBUTING.md`, DRAFT-005).
- Screenshots, badges, or marketing copy — this project has no CI/build
  status to badge yet, and inventing content not backed by the repo would
  violate the "don't invent" rule in `CLAUDE.md`.

# PLAN

Derive content only from already-verified facts: `CLAUDE.md`'s existing
architecture description, the actual repository layout as it exists after
the `docs/` reorg (DRAFT-003), and the testing commands already documented
in `CLAUDE.md`.

# CREATE

Write `/README.md` — see the file itself for final content. Sections:
project purpose/architecture diagram, repository layout (with `misc/`
correctly described per the 2026-08-07 correction — files exist, `linux*`
naming is historical), pointer to `CONTRIBUTING.md` for the dev lifecycle,
testing commands, infrastructure boundary summary, and a pointer to
Claude Code best practices.

# TEST

Read-through only — confirm every claim in the README matches a
source-verified fact elsewhere in the repo (no invented paths, no claims
about test coverage or CI that don't exist yet).

# DEPLOY

Not applicable — documentation only.

# Acceptance criteria

- [x] `README.md` exists at repo root.
- [x] Repository layout section matches the actual post-reorg structure.
- [x] No invented/unverified claims.

# Evidence required

The file itself, `README.md`, committed in DRAFT-001's baseline commit (or
a follow-up commit if DRAFT-001 already landed first).

# Security considerations

None — no secrets, no infrastructure details beyond what's already public
in `CLAUDE.md`.

# Documentation changes

This issue *is* a documentation change.

# Recovery / rollback

Trivial — delete or revert the file; nothing else depends on its exact
content.