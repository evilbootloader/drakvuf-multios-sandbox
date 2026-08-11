# DRAFT-031: Establish a `shellcheck` baseline that `automation/` actually passes

**Status:** **Implemented 2026-08-11.** Repo change and static verification
complete; the Dom0 pull and one benign analysis run remain outstanding (see
DEPLOY). Verified in CI rather than by a Dom0 runbook, at the maintainer's
direction — `.github/workflows/static-checks.yml` was implemented alongside
this issue, which also discharges **DRAFT-026a**.
**Area:** testing (shared — sets the house style for Ubuntu, Android and
Windows scripts)
**Milestone:** M1
**Priority:** P1
**Depends on:** None open. **Blocks DRAFT-026a** (static CI tier), which
specifies `shellcheck automation/*.sh` as a gate.
**Origin:** `project-assessment.md` → Findings → CI-01

# Objective

Make `shellcheck automation/*.sh` exit zero — by deciding how the DRAKVUF
license header and the shebang coexist, and by clearing or explicitly
suppressing the remaining findings — so that a static CI tier can gate on
it instead of being red from the first run.

# Context

`CLAUDE.md` and `README.md` both name `shellcheck SCRIPT` as a required
check. It does not currently pass. Re-run in the development container on
2026-08-08 (`shellcheck` 0.11.0):

```
$ shellcheck automation/*.sh >/dev/null; echo $?
1
$ shellcheck -f gcc -S error automation/*.sh | cut -d: -f1 | sort -u
automation/cleanup.sh
automation/drakvuf-ubuntu.sh
automation/network-setup.sh
automation/preconfig-ubuntu.sh
automation/tcpdump.sh
```

The failures are **error**-severity, not stylistic: SC1128, "The shebang
must be on the first line." Five of the six scripts carry the 103-line
DRAKVUF license header *before* `#!/bin/bash`, so the shebang sits at line
104. Only `run_analysis-ubuntu.sh` has it at line 1 — and that file is
also the only one not inherited from upstream DRAKVUF's `tools/`
directory (`docs/architecture/upstream-drakvuf.md:11-15`).

`bash -n` and `perl -c` both pass cleanly on everything.

**This is not a live bug.** These are the tested production copies synced
from Dom0 in issue #2, and they execute correctly: both GLib's `g_spawn`
(which `dirwatch` uses) and `bash` fall back to `/bin/sh` when `execve`
returns `ENOEXEC`, so a script whose first line is not a valid shebang
still runs. The scripts are also invoked via absolute paths by `dirwatch`,
never sourced.

**It is a blocker for CI.** `docs/workflow-ci.md:139` specifies
`shellcheck automation/*.sh` verbatim as a Level 1 step. As written, the
static tier fails on every pull request, against unmodified working code,
with no baseline and no documented suppression. A gate that is red by
default gets ignored, which defeats the purpose of adding it.

Beyond SC1128 there is a long tail of SC2086 (unquoted expansions) and
SC2009 (`ps aux | grep`) findings — roughly 45 across the six files. Those
overlap other issues (DRAFT-011 owns the `ps|grep` sites, DRAFT-030 the
filename expansions), so this issue's job is to decide **which findings
the gate enforces now** and record why, not to fix all of them.

**Why this is multi-OS work.** Whatever convention is chosen becomes the
house style that `preconfig-android.sh`, `drakvuf-android.sh`,
`clone-android.pl` (DRAFT-015/016) and their Windows counterparts are
written to. Six more scripts are coming. `docs/checklists/android.md:1927`
already lists "`shellcheck` passes or every suppression is documented" as
an Android acceptance gate — this issue is what makes that gate
achievable.

# Dependencies

- None open.
- **Blocks DRAFT-026a.** The static workflow should not be written until
  the command it runs can pass.
- Interacts with DRAFT-011 (`ps|grep` sites) and DRAFT-030 (filename
  expansions) — this issue must not silently fix what those own; it
  decides whether the gate tolerates them in the interim.
- Touches the licence-header question, so `docs/architecture/licensing.md`
  is the reference for what may and may not be altered.

# Out of scope

- Fixing every SC2086 in `automation/`. Many are inside the DRAKVUF-derived
  worker scripts and interact with DRAFT-011/DRAFT-030; blanket-quoting
  them is a behaviour change to production code that `CLAUDE.md` requires
  be flagged and confirmed first.
- Replacing `ps aux | grep` process discovery (SC2009) — DRAFT-011.
- Writing the CI workflow itself — DRAFT-026a.
- `perl -c` / `perlcritic` for `clone-ubuntu.pl` — `perl -c` already
  passes; any deeper Perl linting is a separate decision.
- Removing or shortening the DRAKVUF licence header. It is a licence
  obligation, not boilerplate (see Security considerations).

# PLAN

1. **Confirm the licence constraint before touching the header.** DRAKVUF's
   licence text requires that redistributed covered works "obey and carry
   forward all of the terms of this license" and that the terms "must be
   included as well" (header text, `automation/cleanup.sh:52-62`).
   Establish whether moving the shebang *above* the header — leaving the
   header intact, just one line lower — satisfies that, which it plainly
   should, since nothing is removed.
2. Choose between the options:
   - **(a) Move the shebang to line 1**, header immediately after. One line
     per file, SC1128 disappears, and the scripts become directly
     executable rather than relying on the `ENOEXEC` fallback.
     **Recommended — but as `#!/bin/sh`, not `#!/bin/bash`.**

     > **Correction, 2026-08-11.** This step originally read "(a) Move
     > `#!/bin/bash` to line 1 … zero behaviour change". **That was wrong,
     > and it mattered.** Those five scripts run under `dash` today: the
     > line-104 shebang is invisible to the kernel, `dirwatch` spawns them
     > via `g_spawn_command_line_sync()`, GLib's `g_execute()` gets
     > `ENOEXEC` and falls back to `/bin/sh` — which is `dash`. Putting
     > `#!/bin/bash` on line 1 makes the kernel honour it and switches five
     > scripts that run malware analysis as root to a different
     > interpreter, under cover of a lint fix. `#!/bin/sh` preserves the
     > current interpreter exactly and keeps `CLAUDE.md`'s "write POSIX for
     > these files" rule true.
     >
     > Measured before choosing: shellcheck reports the **identical** 43
     > findings under either shebang, so no bashisms surface under `sh`,
     > and `dash -n` passes on all five rewritten files.
   - **(b) Keep the layout, add `# shellcheck disable=SC1128`.** Cheap,
     but shellcheck's directive must itself precede the shebang to apply,
     which reproduces the same ordering awkwardness.
   - **(c) Set a severity floor** (`shellcheck -S warning` or `-S error`
     with an exclusion list). Does not fix anything; hides the finding.
3. **Verify option (a) against Dom0 before adopting it.** These files are
   byte-synced with production (issue #2). A one-line reordering is still
   a change to files that run malware analysis as root, and the repo↔host
   sync must be preserved — the host copies need the same change, in the
   same window, or the drift issue #2 just closed reopens.
4. Decide the enforced finding set for the gate: which codes are errors,
   which are accepted-with-a-recorded-reason, and where that record lives
   (a `.shellcheckrc` in the repo root is the conventional home and is
   itself reviewable).
5. Decide whether `run_analysis-ubuntu.sh` — which has no licence header —
   should gain one for consistency, or whether its absence is correct
   because the file is this project's own work, not DRAKVUF-derived.

# CREATE

1. Apply the chosen option from PLAN step 2 to the five affected scripts.
2. Add `.shellcheckrc` recording the enforced set and, for each accepted
   exception, a one-line reason and the issue that owns fixing it
   (DRAFT-011, DRAFT-030). An exception with no owner is not an exception,
   it is an untracked defect.
3. Add the same layout convention to `CONTRIBUTING.md`'s TEST section so
   the Android and Windows scripts are written to it rather than
   inheriting the current shape by copy-paste.
4. Record in `docs/checklists/ubuntu.md` that `shellcheck` now passes, and
   what it is passing *against* — a green check with an undocumented
   baseline is worse than a red one.

# TEST

Runs entirely in the development container — no Xen needed:

```bash
# The gate itself:
shellcheck automation/*.sh; echo "exit=$?"     # expect: exit=0

# Nothing regressed:
for f in automation/*.sh; do bash -n "$f" || echo "FAIL $f"; done
perl -c automation/clone-ubuntu.pl

# The shebang is where the gate expects it:
for f in automation/*.sh; do head -1 "$f"; done   # expect: #!/bin/bash x6

# The licence text is intact and unaltered — compare against the pre-change
# copies rather than eyeballing:
git diff --stat automation/          # expect: 1 insertion + 1 deletion per file
git diff automation/ | grep -c '^-#'  # expect: 0 removed comment lines
```

**The same checks run in CI**, which is where this change was verified —
`.github/workflows/static-checks.yml`, DRAFT-026a's Level 1 tier,
implemented alongside this issue rather than after it. That workflow is the
durable form of the checks above: it installs the toolchain explicitly,
records the `shellcheck` version, and gates every push and pull request.

> **Verification approach changed 2026-08-11**, at the maintainer's
> direction: implement CI and test there, rather than writing a Dom0
> runbook for a behaviourally inert change. This is sound for what CI can
> see, and the limit needs stating — **CI proves the scripts parse, not
> that they execute.** No GitHub-hosted tier can spawn `dirwatch`.

Requires Xen Dom0 — present for manual execution, still outstanding:

```bash
# Deployment is a pull, not a copy (issue #4). Never while an analysis is
# in flight -- dirwatch re-reads the worker scripts per sample.
git -C /root/sandbox_project pull
git -C /root/sandbox_project status --porcelain    # expect empty
head -1 /root/sandbox_project/automation/cleanup.sh   # expect #!/bin/sh
ls -l /bin/sh    # confirms the premise: /bin/sh is dash on Dom0

# Then one benign end-to-end analysis run.
```

> **Stale-path correction, 2026-08-11.** This section previously compared
> `sha256sum /home/user/drakvuf-tools/*.sh` against `sha256sum
> automation/*.sh`. That path is retired: issue #4 replaced hand-copying
> with a git checkout at `/root/sandbox_project`, and the old directory is
> now `…​.retired-issue4`. Parity is a `git status`, not a checksum
> comparison.

# DEPLOY

Requires manual Dom0 coordination — present, do not execute:

1. Push, then `git -C /root/sandbox_project pull`. **Do not edit the
   deployed scripts in place** — that is how the drift issue #2 diagnosed
   happened.
2. Confirm `git status --porcelain` is empty and line 1 of each worker
   script is `#!/bin/sh`.
3. Run one benign analysis and confirm normal completion. **This is the
   only step that produces execution evidence**, and it is what CI cannot
   replace: the kernel now honours the shebang rather than failing
   `ENOEXEC` into `/bin/sh`, so the path by which the interpreter is
   selected has changed even though the interpreter has not.
4. Rollback: revert the commit, push, pull again. Behaviourally inert
   either way — `dash` before and after.

# Acceptance criteria

- [ ] `shellcheck automation/*.sh` exits 0 in the development container.
- [ ] No line of DRAKVUF licence text is removed, reworded or reordered —
      proven by the diff, which should contain no removed comment lines.
- [ ] `bash -n` and `perl -c` still pass on every file.
- [ ] `.shellcheckrc` (or the chosen equivalent) records every accepted
      exception with a reason and an owning issue.
- [ ] `CONTRIBUTING.md` states the script-layout convention so future
      Android/Windows scripts inherit it.
- [ ] The five deployed Dom0 copies receive the identical change, with
      matching `sha256sum` output on both sides recorded as evidence.
- [ ] One benign end-to-end Ubuntu analysis completes normally after the
      change.
- [ ] `docs/checklists/ubuntu.md` records what the passing gate covers.

# Evidence required

- `shellcheck` exit status before and after.
- `git diff automation/` in full — it should be trivially reviewable.
- The `sha256sum` pairs from repo and Dom0.
- The post-change benign analysis log excerpt.

# Security considerations

- **The DRAKVUF licence header is a licence obligation, not boilerplate.**
  `docs/architecture/licensing.md` documents that DRAKVUF's terms treat
  subprocess-orchestration-and-parse as derivative work. Do not delete,
  truncate or relocate the header to another file. Moving the shebang
  above it changes no licence text and is the only reason option (a) is
  acceptable.
- These are the scripts that run malware analysis as root on Dom0. A
  "cosmetic" reordering is still a production change and goes through the
  normal gate, including a real analysis run.
- Do not use this issue as cover for quoting fixes. Silently changing
  expansion behaviour in `preconfig-ubuntu.sh` or `drakvuf-ubuntu.sh`
  while claiming a lint cleanup is exactly the kind of unreviewed
  behaviour change `CLAUDE.md` prohibits.
- Every suppression must name the issue that will remove it. Suppressions
  without owners become permanent.

# Documentation changes

`CONTRIBUTING.md` (script layout convention + what the `shellcheck` gate
enforces), `docs/checklists/ubuntu.md` (the gate now passes, and against
what), `docs/checklists/android.md` §6.1 (annotate that its "shellcheck
passes or every suppression is documented" gate is now defined by this
issue's baseline), `docs/workflow-ci.md:139` (reference the baseline
rather than a bare command).

# Recovery / rollback

A one-line reordering per file, revertible from git, with the host copies
restorable from recorded checksums. No infrastructure, network or guest
state is involved.