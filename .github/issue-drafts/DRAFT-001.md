# DRAFT-001: Initialize git repository and commit current baseline

**Status:** Closed — done 2026-08-07
**Area:** governance
**Milestone:** M0
**Priority:** P0
**Depends on:** —

# Objective

Turn this working directory into a git repository and commit the current
state as a baseline, so every subsequent change can be reviewed as a diff
and rolled back if needed.

# Context

As of 2026-08-07 this directory had no `.git` — confirmed both by the
session environment metadata and by direct file probing. All "evidence"
(the Android checklist, automation scripts, Xen configs under `misc/`)
existed only as uncommitted files with no history. This is the literal
prerequisite for the `PLAN → CREATE → TEST → DEPLOY` review-gate discipline
in `CONTRIBUTING.md` — there is no diff/rollback without it.

# Dependencies

None. This is the first issue.

# Out of scope

- Choosing a remote / pushing anywhere.
- Setting up branch protection, CI, or any GitHub-side configuration.
- Deciding the DRAKVUF upstream repository strategy (that's
  `docs/architecture/upstream-drakvuf.md`'s recommendation, tracked
  separately — this issue is only about *this* automation repo).

# PLAN

1. Confirm no `.git` already exists (avoid double-initializing).
2. Decide `.gitignore` is in place first (already done — see
   `.gitignore` in this repo, covers malware samples, pcaps, memdumps,
   secrets, `.bak` snapshot files).
3. Decide the baseline commit's scope: everything currently on disk,
   including `automation/`, `misc/`, `docs/`, `CLAUDE.md`, `README.md`,
   `CONTRIBUTING.md`, and this `.github/issue-drafts/` directory itself.

# CREATE

```bash
git init
git add -A
git status   # review before committing — confirm nothing in .gitignore's
             # patterns slipped through, confirm no malware samples present
git commit -m "Initial commit: baseline automation, docs, and roadmap"
```

# TEST

- `git log --oneline` shows exactly one commit.
- `git status` is clean.
- `git show --stat HEAD` includes `automation/`, `misc/`, `docs/`,
  `CLAUDE.md`, `README.md`, `CONTRIBUTING.md` — spot-check nothing
  unexpected (no `.env`, no sample files) was included.

All of the above run locally, no Xen needed.

# DEPLOY

Not applicable — this is a local repository operation with no
infrastructure impact.

# Acceptance criteria

- [x] `.git` exists and `git log` shows a baseline commit.
- [x] `git status` is clean immediately after.
- [x] No files matching `.gitignore` patterns are tracked.

# Evidence required

`git log --oneline`, `git status`, and `git show --stat HEAD` output,
pasted into this issue or the commit message body.

# Evidence (2026-08-07)

Two deviations from the original PLAN, both confirmed with the user before
committing: `docs/android-drakvuf-automation-checklist.md` (a stale
duplicate of `docs/checklists/android.md` left over from the docs reorg,
despite `CLAUDE.md` claiming it no longer existed) was deleted rather than
committed; `.claude/` and `.devcontainer/` were left untracked rather than
included, since the PLAN's file list didn't name them.

```
$ git log --oneline
bb8ad14 Initial commit: baseline automation, docs, and roadmap

$ git status
On branch master
Untracked files:
  (use "git add <file>..." to include in what will be committed)
	.claude/
	.devcontainer/

nothing added to commit but untracked files present (use "git add" to track)

$ git show --stat HEAD
commit bb8ad14a34ce9a31860334832716dfdd6bb3f55c
Author: lluisbessasanz <lluisbessasanz@proton.me>
Date:   Fri Aug 7 19:04:33 2026 +0000

    Initial commit: baseline automation, docs, and roadmap

 52 files changed, 5332538 insertions(+)
 (full per-file stat omitted here for length; automation/, misc/, docs/,
 CLAUDE.md, README.md, CONTRIBUTING.md, and .github/issue-drafts/ are all
 present as expected — see repo `git show --stat HEAD` for the complete list)
```

`git ls-files` was also grepped for `.gitignore` patterns
(`.pcap`/`.dmp`/`.memdump`/`drakvuf.json`/`.bak`/`.env`/`secrets/`/`.key`/`.pem`)
— no matches.

# Security considerations

Review `git status`/`git show --stat` output before committing to ensure
no credentials, `.env` contents, or malware samples are included — the
`.gitignore` patterns are a safety net, not a substitute for looking.

# Documentation changes

None beyond this issue itself. `docs/roadmap/project-roadmap.md`'s risk
register item #1 should be marked resolved once this lands.

# Recovery / rollback

Trivial — this is the first commit; "rollback" would just mean removing
`.git` entirely, which loses nothing since it's the starting point.