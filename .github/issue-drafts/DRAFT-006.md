# DRAFT-006: Reconcile `misc/` Xen guest config naming and cross-references

**Status:** Closed — [issue #1](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/1), done 2026-08-08 (revised 2026-08-07 — see below)
**Area:** governance
**Milestone:** M0
**Priority:** P2
**Depends on:** DRAFT-001

# Objective

Resolve the misleading `linux*.cfg` filenames under `misc/` (they define
Ubuntu domains, not a generic "linux" one) and fix the deployment-path
mismatch between `automation/run_analysis-ubuntu.sh`'s hard-coded config
path and this repo's actual `misc/` location.

# Context

This issue was originally titled "Commit missing Xen guest `.cfg` files
(`android_sandbox.cfg`, `linux_sandbox.cfg`, etc.) from the real Dom0
host," based on research that checked `automation/`, `docs/`, and repo
root and found no `.cfg` files anywhere. That premise was **wrong** — the
user corrected it directly: all four configs
(`misc/linux.cfg` → golden `ubuntu`, `misc/linux_sandbox.cfg` →
`ubuntu_sandbox`, `misc/android.cfg` → golden `android`,
`misc/android_sandbox.cfg` → `android_sandbox`) were already tracked under
a `misc/` directory the research pass had simply never checked. This is a
good example of why the "verify, don't just trust an earlier research
pass" discipline in `CLAUDE.md` matters — see
`docs/roadmap/project-roadmap.md`'s corrected risk register entry #6.

What's left, once the false premise is removed:

1. `misc/linux.cfg` and `misc/linux_sandbox.cfg` are confusingly named —
   both define Ubuntu domains (`name = "ubuntu"` /
   `name = "ubuntu_sandbox"`), not anything Linux-generic. A reader
   expecting `linux.cfg` to be reusable across Linux guest types would be
   wrong.
2. `automation/run_analysis-ubuntu.sh` hard-codes
   `/home/user/drakvuf-tools/linux_sandbox.cfg` as the domain config path
   passed to `dirwatch` — a path that doesn't match this repo's `misc/`
   location. This only matters if the script is ever run directly from
   this checkout rather than a host laid out to match the hard-coded path;
   still worth fixing as part of the broader hard-coded-value cleanup
   `docs/checklists/ubuntu.md` already tracks for Milestone M1.

# Dependencies

DRAFT-001 (for commit ordering / diff review).

# Out of scope

- Renaming the files outright — `misc/linux.cfg` / `misc/linux_sandbox.cfg`
  are referenced by name in checklist evidence and possibly by the real
  Dom0 host's own scripts; renaming needs coordination with whatever's
  deployed there, not just a repo-side change. This issue should decide
  *whether* to rename, not do it unilaterally.
- The general hard-coded-value parameterization work in
  `automation/run_analysis-ubuntu.sh` beyond this one path — that's
  DRAFT-011 (Ubuntu modernization, M1).

# PLAN

1. Confirm with whoever operates the real Dom0 host whether `misc/linux.cfg`
   /`misc/linux_sandbox.cfg` match what's actually deployed there, or
   whether the deployed copies have already been renamed.
2. Decide: rename in this repo to `ubuntu.cfg`/`ubuntu_sandbox.cfg` (with a
   redirect/deprecation note for anyone with the old names memorized), or
   leave as-is and just document the naming clearly (already done in
   `README.md`, `docs/checklists/ubuntu.md`, and
   `docs/architecture/networking.md` as of this session).
3. If renaming: update every reference (`docs/checklists/android.md`'s
   evidence blocks reference `android_sandbox.cfg` and `android.cfg` by
   name, which are unaffected; the Ubuntu-side references in
   `docs/checklists/ubuntu.md` and `automation/run_analysis-ubuntu.sh`
   would need updating).

# CREATE

Done — commit `ced4e77` ("Rename misc/linux*.cfg to ubuntu*.cfg and fix
cross-references (#1)"). Decision made: renamed rather than left as-is.
`misc/linux.cfg` → `misc/ubuntu.cfg`, `misc/linux_sandbox.cfg` →
`misc/ubuntu_sandbox.cfg` (content unchanged), and every in-repo reference
updated: `automation/run_analysis-ubuntu.sh`'s hard-coded config path,
`docs/checklists/ubuntu.md`, `docs/architecture/networking.md`,
`docs/architecture/analysis-pipeline.md`,
`docs/drakvuf-on-xen-nested-within-proxmox.md`, `README.md`, and
`CLAUDE.md`. The commit message notes the real Dom0 host's copies still
need a separate manual rename to match — that coordination is tracked in
the issue thread, not in this repo.

# TEST

If renamed: `bash -n automation/run_analysis-ubuntu.sh` after updating the
hard-coded path (once Bash is available); grep the repo for the old
filenames to confirm no dangling references remain.

# DEPLOY

If the real Dom0 host's files are renamed to match: requires manual
coordination on that host — present the exact `mv`/config-update commands
for manual execution, per `CLAUDE.md`'s infrastructure boundary rule. Do
not assume this repo's rename should drive a change on the real host
without confirming first.

# Acceptance criteria

- [x] Decision made and recorded: rename `misc/linux*.cfg` or keep as-is
  with documentation only. (Renamed — see `CREATE`.)
- [x] `automation/run_analysis-ubuntu.sh`'s hard-coded config path matches
  wherever the config actually lives (this repo's `misc/`, or the real
  Dom0 deployment path — decide which is authoritative). (Updated to
  `misc/ubuntu_sandbox.cfg` in commit `ced4e77`.)
- [x] No dangling references to a renamed-away filename anywhere in
  `docs/` or `automation/`. (All cross-references updated in the same
  commit; historical checklist evidence in `docs/checklists/android.md`
  was unaffected since it never referenced the `linux*` names.)

# Evidence required

Commit `ced4e77`'s diff (10 files changed) and the current `misc/`
directory listing (`ubuntu.cfg`, `ubuntu_sandbox.cfg`, `android.cfg`,
`android_sandbox.cfg` — no `linux*.cfg` remaining).

# Security considerations

None — this is a naming/path-consistency issue, not a permissions or
containment change.

# Documentation changes

Update `README.md`, `docs/checklists/ubuntu.md`, and
`docs/architecture/networking.md` if the rename happens; otherwise no
further changes needed beyond what this session already wrote.

# Recovery / rollback

If renamed and it turns out the real Dom0 host still expects the old
names, revert the rename commit — no data loss either way, this is a
repo-side file-naming change only.