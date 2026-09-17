# Issue drafts

Locally-drafted GitHub issues, reviewed here before anything is published
with `gh`. See `CONTRIBUTING.md`'s "GitHub issue workflow" section for the
full two-stage process this directory implements.

- `issue-index.md` — the full draft-title index: ID, title, area,
  milestone, priority, dependencies, and status.
- `<state>/DRAFT-NNN.md` — one file per issue, using the template in
  `CONTRIBUTING.md` (`Objective/Context/Dependencies/Out of scope/PLAN/
  CREATE/TEST/DEPLOY/Acceptance criteria/Evidence required/Security
  considerations/Documentation changes/Recovery-rollback`).

## The three subdirectories, and how a file earns its place

Added 2026-09-04, when 52 drafts in one flat directory had made "what is
actually left to do here?" a question you answered by opening files.

| Directory | Rule | Count |
|---|---|---|
| `completed/` | its GitHub issue is **closed**, the work landed without ever being published, **or its subject no longer exists** | 38 |
| `in-progress/` | its issue is **open**, or the repository shows work started against it | 3 |
| `todo/` | not published, and not started | 12 |

**The issue's state is the signal, not the draft's prose.** A draft's own
`Status:` line is written once and rots; `gh issue list` does not. Where the
two disagree, GitHub wins and the file moves.

**The third `completed/` clause was added 2026-09-17, for `DRAFT-010`**, whose
subject — `automation/dirwatch.c` — was deleted on 2026-09-15. It is neither
closed nor landed nor doable, and leaving it in `todo/` would have made "what
is actually left to do here?" wrong by one file forever, which is the question
this split exists to answer. Such a draft is marked **STALE** in its own
`Status:` block, which says what outlived the deletion and what merely lapsed;
it is kept rather than deleted because a draft can describe a thing that still
runs somewhere even after its source is gone.

**One deliberate exception, and the reason it is worth naming.** `DRAFT-020`
is unpublished and sits in `in-progress/`, because the Windows guest build it
specifies is largely done (recorded in the draft itself, 2026-09-04). Placing
it in `todo/` would have been true of its GitHub state and false about the
repository — which is the failure mode this directory structure exists to
prevent, so the rule bends rather than the file.

**Moving a file is part of closing an issue.** A draft left in `todo/` after
its issue is closed is the same defect as a stale `Status:` line, one
directory over. `issue-index.md` stays at this level because it indexes all
three.

## Publication history

Drafts published with `gh issue create` are listed with their issue numbers
and current state in `issue-index.md`'s Status column, which is maintained;
this README deliberately no longer duplicates that list, because it had gone
stale — it claimed five published drafts and named issue #6 as open long after
it closed.

Publishing any further draft still requires the Stage 2 gate in
`CONTRIBUTING.md`: show the index, show every title, summarize dependencies,
show the exact commands, and get explicit approval first.

Four of the first eight drafts (DRAFT-002, DRAFT-003, DRAFT-004, DRAFT-005)
were completed directly during the same session that drafted them, since
they were pure documentation/scaffolding work already covered by that
session's approved CREATE scope — see each file's `Status` field and
`Evidence required` section for what was actually produced. They're kept
as drafts here (not deleted) for the historical record and in case they're
still useful to publish as closed-with-evidence GitHub issues later.
