# Issue drafts

Locally-drafted GitHub issues, reviewed here before anything is published
with `gh`. See `CONTRIBUTING.md`'s "GitHub issue workflow" section for the
full two-stage process this directory implements.

- `issue-index.md` — the full draft-title index: ID, title, area,
  milestone, priority, dependencies, and status.
- `DRAFT-NNN.md` — one file per issue, using the template in
  `CONTRIBUTING.md` (`Objective/Context/Dependencies/Out of scope/PLAN/
  CREATE/TEST/DEPLOY/Acceptance criteria/Evidence required/Security
  considerations/Documentation changes/Recovery-rollback`).

As of 2026-08-10, five drafts have been published with `gh issue create`:
DRAFT-006 (issue #1, closed), DRAFT-007 (issue #2, closed), DRAFT-008
(issue #3, closed), DRAFT-025 (issue #4, closed) and DRAFT-009 (issue #6,
open) — see `issue-index.md`'s Status column for current state. Issue #5 is
the pull request that closed #4, not an issue. Publishing any further draft
still requires the
Stage 2 gate in `CONTRIBUTING.md`: show the index, show every title,
summarize dependencies, show the exact commands, and get explicit approval
first.

Four of the first eight drafts (DRAFT-002, DRAFT-003, DRAFT-004, DRAFT-005)
were completed directly during the same session that drafted them, since
they were pure documentation/scaffolding work already covered by that
session's approved CREATE scope — see each file's `Status` field and
`Evidence required` section for what was actually produced. They're kept
as drafts here (not deleted) for the historical record and in case they're
still useful to publish as closed-with-evidence GitHub issues later.