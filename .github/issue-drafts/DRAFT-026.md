# DRAFT-026: Implement GitHub Actions and self-hosted Xen integration runner

**Status:** **[#26](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/26) — 026a published and closed 2026-08-19.** **026a (static tier) implemented 2026-08-11** —
`.github/workflows/static-checks.yml`, green on run
[`31505320234`](https://github.com/evilbootloader/drakvuf-multios-sandbox/actions/runs/31505320234).
Built alongside DRAFT-031, which unblocked it by making `shellcheck` exit 0.
**026b (self-hosted Xen integration tier) remains drafted, not published.**
**Area:** ci
**Milestone:** M1 (static tier can start now); heavy tier is effectively a new M1½ — it needs a working Ubuntu pipeline to validate against, but doesn't need to wait for M6 ("CI expansion, after ≥2 OS pipelines exist") since it's designed around Ubuntu today and Android as it lands
**Priority:** P1
**Depends on:** DRAFT-001 (repo baseline); soft dependency on DRAFT-025 /
issue #4 (path standardization — the integration tier's `dirwatch`
invocation needs `$GITHUB_WORKSPACE`-relative paths either from DRAFT-025
landing or from a workflow-side stopgap); informed by issue #2
(DRAFT-007, resolved 2026-08-08) and issue #1 (DRAFT-006, `misc/` naming)

# Objective

Add a two-tier GitHub Actions CI: a fast GitHub-hosted static-check tier
for every pull request, and a self-hosted tier that rebuilds DRAKVUF and
LibVMI from the PR's own code and runs a real benign analysis against a
pre-installed golden VM, proving the pipeline scripts actually work
rather than just parse. Full design in `docs/workflow-ci.md`.

# Context

No `.github/workflows/` exists in this repository today. The roadmap
(`docs/roadmap/project-roadmap.md`, Milestone M1) already lists "add
`bash -n`/`shellcheck`/`perl -c` CI" as a goal, and the issue index
(`.github/issue-drafts/issue-index.md`) has a title-only placeholder for
this scope, DRAFT-012. This issue supersedes DRAFT-012 — its static-check
scope is fully incorporated here as Level 1, rather than drafted
separately, because the two tiers need to be designed together (Level 1
exists specifically to gate Level 2 cheaply).

The heavier motivation: "Ubuntu automation works" was, until
2026-08-08, an unverified assertion in
`docs/Project-definition.txt`/`CLAUDE.md`. Issue #2 has since settled it
by hand — the pipeline is execution-evidenced and `automation/` now
matches the tested Dom0 host. What that episode showed is that the repo
had silently diverged from the host for months with nothing to detect it.
A CI tier that clones a sandbox and runs the real pipeline against a
benign fixture keeps that verification standing continuously rather than
depending on someone repeating the manual runbook.

This was designed interactively and went through several revisions
before landing on the current shape (see `docs/workflow-ci.md`'s full
reasoning) — notably: the self-hosted runner's base snapshot contains a
fully-installed Ubuntu 22.04 + Xen **and both golden guest VMs
(`ubuntu`, `android`) already installed**, not just a bare OS; DRAKVUF
and LibVMI are rebuilt from scratch inside every job, since those are
the parts a PR can actually break; the runner resets to that base
snapshot before every job via the Proxmox VE API over Tailscale (not
direct Proxmox host access) rather than staying persistent; and the
heavy tier runs on `pull_request` (restricted to same-repository PRs
triggered by the repo owner) rather than only on manual dispatch, since
the goal is pre-merge validation, not just an on-demand check.

# Recommended split (assessment, 2026-08-08)

`project-assessment.md` → "Existing Issue and Draft Review" → DRAFT-026
recommends **splitting this issue in two before publication**. Recorded
here for decision; not yet applied.

- **DRAFT-026a — static tier.** `ci-static.yml` only. Its sole dependency
  is DRAFT-031 (the `shellcheck` baseline). No Dom0, no Proxmox API, no
  Tailscale, no base snapshot, no fixtures. Landable in days.
- **DRAFT-026b — self-hosted integration tier.** Everything else, with the
  dependency list below.

The reason: as one issue, the half that needs a YAML file waits on the
half that needs a Proxmox API token, Tailscale ACLs, an L0 supervisor
loop, a rebuilt base snapshot with three golden VMs, and a benign fixture
set that `docs/checklists/android.md` §6.4 still records as unpopulated.
Level 1 exists specifically to gate Level 2 cheaply, and it cannot do that
while it ships with it.

# Dependencies

- DRAFT-001 (commit ordering / diff review).
- DRAFT-025 / issue #4 (path standardization) — soft dependency for the
  integration tier specifically; Level 1 (static) has no such dependency.
- Supersedes DRAFT-012's static-check scope (title-only in the roadmap,
  never drafted as its own file).
- Informed by issue #2 (DRAFT-007, resolved 2026-08-08 out-of-band via
  `docs/runbooks/verify-user-placeholder.md`) and issue #1 (DRAFT-006,
  `misc/` naming, now closed on both repo and host sides).

*Added 2026-08-08 from `project-assessment.md`:*

- **DRAFT-031 (`shellcheck` baseline) — hard dependency of the static
  tier.** `shellcheck automation/*.sh` exits 1 today at **error** severity
  on five of six scripts (SC1128: the 103-line DRAKVUF licence header
  precedes the shebang). As specified, Level 1 is red on its first run
  against unmodified, working production code. See CI-01.
- **DRAFT-024 (pin/mirror upstream revisions) — hard dependency of the
  integration tier.** Level 2 rebuilds DRAKVUF and LibVMI from source in
  every job and currently has nothing pinned to build against. Note this
  now spans **two** upstreams with different bus-factor profiles:
  `tklengyel/drakvuf` (Windows-oriented plugin set, healthy) and the
  single-maintainer `lfreijo` fork (Linux/Android plugin support, risk
  #8).
- **DRAFT-027 (replace HTTP sample delivery) — should precede the base
  snapshot build.** The documented "Recreating CI" procedure installs and
  configures `apache2` (`docs/workflow-ci.md:403`). If DRAFT-027 lands
  afterwards, the snapshot, that checklist and the `ubuntu-pipeline`
  stage all have to be redone. See CI-05.
- **DRAFT-034 (Windows track) — informs the base snapshot.** Windows is
  now a current target, so the snapshot needs a third golden VM and the
  workflow a `windows-pipeline` stage.

# Out of scope

- Actually building the Ubuntu/Android unattended-install automation —
  the design deliberately keeps golden-VM creation manual/interactive,
  baked into the base snapshot once, not automated per job. See
  `docs/workflow-ci.md`'s "Future CI work".
- `android-pipeline` execution — `clone-android.pl`/`preconfig-android.sh`/
  `drakvuf-android.sh` don't exist yet (DRAFT-015/016). This issue defines
  the CI path for it and leaves it wired up but non-functional until those
  scripts land.
- Windows CI — no Windows work has started (M5 not begun).
- The Proxmox VE API / Tailscale snapshot-restore supervisor loop's exact
  implementation (API token scoping, Tailscale ACLs, the actual
  restore-and-relaunch script) — this issue's CREATE section builds it,
  but the detailed credential/network design should get its own review
  given it's the mechanism protecting the lab host from a bad PR.
- Building the benign fixture set — tracked as a dependency of the
  integration tier, not built by this issue itself (see TEST/DEPLOY).
- Rewriting `run_analysis-ubuntu.sh`'s hard-coded
  `/home/user/drakvuf-tools/...` paths — that's DRAFT-025's territory;
  this issue's workflow only works around it with `$GITHUB_WORKSPACE`
  paths as a stopgap.

# PLAN

- [ ] Confirm the Proxmox host has VT-x/EPT and nested virtualization
  enabled, and that a Tailscale-reachable Proxmox VE API token with
  minimal scope (VM snapshot rollback/start/stop only, not full admin)
  can be issued for the runner-reset mechanism.
- [ ] Decide the exact snapshot-reset trigger mechanism: an L0-side
  supervisor loop watching for ephemeral-runner-agent exit, driven over
  the Proxmox API via Tailscale, per `docs/workflow-ci.md`'s "Runner
  lifecycle" section.
- [ ] Inventory the full DRAKVUF build dependency list and confirm it
  against `docs/drakvuf-on-xen-nested-within-proxmox.md`'s "Automated
  analysis setup" section (already done for this draft — recheck at
  implementation time in case the doc has changed).
- [ ] Decide the OS-family path-filter rule (which changed files trigger
  `ubuntu`/`android`/both pipelines) before writing the workflow YAML.
- [ ] Classify every candidate CI command as static (Level 1,
  GitHub-hosted) vs. integration (Level 2, self-hosted) — done in
  `docs/workflow-ci.md`, re-confirm nothing was missed at implementation
  time.
- [ ] Define the security model precisely: `pull_request` gated to
  same-repository branches and owner-triggered runs only; no
  `pull_request_target`; minimal `GITHUB_TOKEN` permissions; no secrets
  reachable from fork-triggered workflows.
- [ ] Define triggers precisely: `pull_request` (same-repo, owner-
  triggered) + `push` to `master` + `workflow_dispatch` for Level 2;
  `pull_request` (all, incl. forks) + `push` for Level 1.

# CREATE

- [ ] Add `docs/workflow-ci.md` (done as a draft in this session — mark
  final once this issue's PLAN items are confirmed).
- [ ] Build the golden-VM base snapshot: Xen installed, `ubuntu` and
  `android` golden VMs installed and their `dwarf2json` profiles
  generated and registered in `/etc/libvmi.conf`, installer ISOs staged
  on disk, GitHub Actions runner agent installed in `--ephemeral` mode.
  **Now three golden VMs, not two** — Windows is a current target, and its
  profile is *not* produced by `dwarf2json` (that toolchain is
  Linux/Android-only; DRAFT-034 PLAN step 2 establishes the Windows
  mechanism). **Do not install `apache2` into the snapshot** if DRAFT-027
  has landed — see the Dependencies section.
- [ ] Build the L0 supervisor loop that reverts the L1 VM to the base
  snapshot via the Proxmox VE API (over Tailscale) after each ephemeral
  runner job completes, and relaunches the runner agent for the next job.
- [ ] Add `.github/workflows/ci-static.yml` — `bash -n`/`shellcheck`/
  `perl -c` plus the `<USER>`/`ps|grep` anti-pattern greps, GitHub-hosted,
  triggered on `pull_request` (incl. forks) and `push` to `master`.
  **Two corrections to `docs/workflow-ci.md`'s specified commands must be
  made before this is written** (assessment CI-02, CI-03):

  ```bash
  # docs/workflow-ci.md:147 as written — WRONG. grep exits 1 when it finds
  # nothing, && short-circuits, and the compound exits 1. GitHub Actions
  # runs `run:` steps as `bash -e {0}`, so this fails the step precisely
  # when the repository is CLEAN. Verified: the grep exits 1 today.
  grep -Rns '<USER>' automation/ && exit 1

  # Correct form:
  if grep -Rns '<USER>' automation/; then exit 1; fi

  # docs/workflow-ci.md:148 — enforces nothing. It matches four live sites
  # today (drakvuf-ubuntu.sh:130, cleanup.sh:118,124,134) and exits 0
  # because grep found matches, inverting the intent. Decide whether this
  # gate is advisory or blocking, and write it accordingly. If blocking, it
  # cannot be enabled until DRAFT-011 removes those sites.
  grep -Rns 'ps aux.*grep\|ps .*|.*grep' automation/
  ```

  Also make the file glob OS-agnostic (`automation/*.sh`,
  `automation/*.pl`) so the Android and Windows scripts are covered on
  arrival without a workflow edit.
- [ ] Add `.github/workflows/ci-build-and-test.yml` — self-hosted,
  ephemeral, gated to same-repository owner-triggered `pull_request` +
  `push` to `master` + `workflow_dispatch`; implements the DRAKVUF/LibVMI
  build, sandbox-VM clone, network provisioning, plugin matrix, and
  `ubuntu-pipeline`/`android-pipeline` sub-stages from `docs/workflow-ci.md`.
  Add a `windows-pipeline` stage, defined-but-inactive, the same way
  `android-pipeline` already is.
- [ ] State which `dirwatch` source the build step uses.
  `automation/dirwatch.c` (665 lines) and `automation/dirwatch_old.c`
  (674 lines) differ on 132 lines — almost entirely formatting and
  function ordering, so `dirwatch_old.c` is a reformatted sibling rather
  than an older design. The install guide copies only `dirwatch.c`
  (`docs/drakvuf-on-xen-nested-within-proxmox.md:531`). Resolve via
  DRAFT-010 or state it here; do not leave a build step ambiguous about
  which of two near-identical sources it compiles. *(Assessment CI-04.)*
- [ ] Add failure-artifact collection (build logs, `drakvuf.log`, DRAKVUF
  JSON output, plugin dump folders, `xl dmesg`/`xl list -l`, network
  diagnostics, `cleanup.log`) with explicit exclusions for anything from
  the real `/malware_incoming`/`/malware_processing`/`/malware_finished`
  paths or `.bak` saved-state files.
- [ ] Add `if: always()` cleanup steps as defense-in-depth alongside the
  snapshot-revert as primary cleanup.

# TEST

- [ ] `docs/workflow-ci.md`'s "Recreating CI" checklist run once, in
  order, on real hardware — record where it diverges from the document
  and fix the document, not just the workflow.
- [ ] Build at least one benign, deterministic Ubuntu-side fixture (per
  `docs/checklists/android.md` §6.4's still-unpopulated fixture table)
  with a recorded SHA-256, before `ubuntu-pipeline` is trusted to run.
- [ ] Run `ci-static.yml` against a PR with a deliberately broken script
  to confirm it fails correctly, and against a clean PR to confirm it
  passes.
- [ ] Run `ci-build-and-test.yml` manually via `workflow_dispatch` first
  (not on `pull_request`) and record the full result — DRAKVUF/LibVMI
  build success, sandbox clone success, plugin-matrix results per
  `docs/workflow-ci.md`'s plugin list, and whether `ubuntu-pipeline`
  reproduces the known-good result issue #2 established by hand.
- [ ] Only after a clean manual run, enable `ci-build-and-test.yml` on
  `pull_request` for real.
- [ ] Deliberately fail a job mid-run (e.g. cancel it) and confirm the
  next job still gets a clean base via the snapshot revert, with no
  manual Dom0 cleanup needed.
- [ ] Confirm a job cannot write to any golden LV (`ubuntu`, `android`,
  and `windows` once DRAFT-034 lands) — only to its own cloned `_sandbox`
  LV.

# DEPLOY

- [ ] Register the self-hosted runner against this repository with
  labels `self-hosted, linux, x64, xen-dom0`.
- [ ] Enable branch protection on `master` requiring at least the static
  workflow (`ci-static.yml`) before merge; decide separately whether to
  also require `ci-build-and-test.yml` given its cost/latency.
- [ ] Document the final, validated Proxmox API token scope and Tailscale
  ACL configuration (no raw credentials committed) in
  `docs/workflow-ci.md`'s "Runner registration"/"Runner lifecycle"
  sections, replacing the conceptual description with the real one.
- [ ] Rollback: disable the `pull_request` trigger on
  `ci-build-and-test.yml` (fall back to `workflow_dispatch`-only) if the
  snapshot-reset mechanism proves unreliable in practice; `ci-static.yml`
  has no meaningful rollback risk.

# Acceptance criteria

- [ ] `docs/workflow-ci.md` documents how to recreate the CI and the
  self-hosted runner from scratch.
- [ ] A pull request touching only `automation/*.sh`/`*.pl` syntax
  triggers `ci-static.yml` and nothing else, and fails on a deliberate
  syntax error.
- [ ] A same-repository, owner-triggered pull request touching Ubuntu
  pipeline code triggers `ci-build-and-test.yml`, which rebuilds
  DRAKVUF/LibVMI from that PR's `automation/dirwatch.c`, clones a sandbox
  from the pre-installed golden `ubuntu` VM, and runs a benign fixture
  through the real pipeline scripts.
- [ ] A fork-originated pull request never reaches the self-hosted
  runner automatically — only `ci-static.yml` runs for it.
- [ ] `ci-build-and-test.yml` never touches
  `/malware_incoming`/`/malware_processing`/`/malware_finished`; it only
  ever uses a CI-scoped fixture directory.
- [ ] The self-hosted runner resets to the clean base snapshot (Ubuntu
  22.04 + Xen + all golden VMs, no DRAKVUF/LibVMI, no `_sandbox` state)
  before every job, via the Proxmox VE API over Tailscale.
- [ ] A failed job does not require manual Dom0 cleanup before the next
  job runs cleanly.
- [ ] Failure artifacts (build logs, `drakvuf.log`, plugin dump folders,
  `xl`/network diagnostics, `cleanup.log`) are collected and uploaded;
  real malware/sample data and `.bak` state are never uploaded.
- [ ] `android-pipeline` is defined in the workflow (even if
  non-functional pending DRAFT-015/016) rather than silently omitted.
- [ ] `GITHUB_TOKEN` permissions are minimal and explicit in both
  workflow files; no secrets are reachable from fork-triggered runs.
- [ ] At least one successful `ubuntu-pipeline` run reproduces the
  known-good Ubuntu result issue #2 established by hand on 2026-08-08.
- [ ] A repo-vs-Dom0 checksum check for `automation/*` runs in the
  integration tier — the drift issue #2 uncovered went undetected for
  months and nothing currently guards against it recurring.

*Added 2026-08-08 from `project-assessment.md` (CI-01 … CI-05):*

- [ ] **`ci-static.yml` passes on unmodified `master` before it is enabled
      as a merge gate.** Today `shellcheck automation/*.sh` exits 1 at
      error severity on five of six scripts (SC1128). DRAFT-031 fixes
      this; do not paper over it with a severity floor chosen inside the
      workflow.
- [ ] The `<USER>` regression guard **passes on a clean repository** and
      fails only when a placeholder is present — i.e. it is not written as
      `grep … && exit 1`, which fails a clean repo under `bash -e`.
- [ ] The `ps|grep` anti-pattern check has a stated verdict — advisory or
      blocking — and its exit-code behaviour matches that verdict.
- [ ] The workflow's file globs cover `automation/*.sh` **and**
      `automation/*.pl`, so Android and Windows scripts are gated on
      arrival without a workflow edit.
- [ ] The build step names which `dirwatch` source it compiles, and
      `dirwatch_old.c` is either removed, documented, or explicitly
      excluded from the build.
- [ ] The base snapshot contains **three** golden VMs (`ubuntu`,
      `android`, `windows`), and `windows-pipeline` is defined in the
      workflow even if non-functional pending DRAFT-034.
- [ ] The base snapshot does **not** install `apache2`, assuming DRAFT-027
      has landed; if it has not, this issue records why the dependency is
      still present and what removes it.
- [ ] DRAKVUF and LibVMI are built from **pinned** revisions per
      DRAFT-024, not from branch tips — a job that rebuilds from a moving
      tip cannot distinguish a PR regression from an upstream change.

# Evidence required

- Diff of `docs/workflow-ci.md` (finalized) and both new workflow files.
- A recorded run of the "Recreating CI" checklist against real hardware,
  noting any step that had to be corrected.
- `ci-static.yml` pass/fail evidence against both a clean and a
  deliberately broken PR.
- `ci-build-and-test.yml`'s first successful manual (`workflow_dispatch`)
  run, including the plugin-matrix results and the `ubuntu-pipeline`
  execution evidence for issue #2.
- Confirmation (screenshot or log excerpt) that a fork PR only triggered
  `ci-static.yml`.

# Security considerations

- The self-hosted runner executes PR-controlled code with root/sudo
  access on infrastructure that also hosts real malware-analysis work.
  The design's primary control is restricting the heavy tier's
  `pull_request` trigger to same-repository, owner-triggered runs, plus
  an ephemeral/snapshot-reset lifecycle so nothing a job does persists
  past the next reset — but this does not eliminate in-the-moment risk
  during a running job (see `docs/workflow-ci.md`'s "Security model").
- No `pull_request_target` anywhere in this design.
- The Proxmox VE API token used for snapshot restore must be scoped as
  narrowly as the Proxmox permission model allows (VM
  start/stop/rollback on the specific L1 VM only) and reachable only over
  Tailscale, not the public internet — this token is effectively the key
  to the lab's reset mechanism and must not leak into workflow logs.
- `GITHUB_TOKEN` permissions minimal and explicit in both workflows; no
  secrets reachable from fork-triggered workflows.
- Never upload real `/malware_incoming`/`/malware_processing`/
  `/malware_finished` content or `.bak` saved-state files as CI
  artifacts, even on success.
- A job must never be able to write to the golden `ubuntu`/`android` LVs
  directly — only clone from them.

# Documentation changes

`docs/workflow-ci.md` (already drafted, to be finalized alongside
implementation), `docs/roadmap/project-roadmap.md` (mark DRAFT-012's
scope as superseded by this issue), `.github/issue-drafts/issue-index.md`
(add this entry), `CONTRIBUTING.md`/`README.md` if CI becomes a required
step in the contribution flow (e.g. branch protection referencing
`ci-static.yml`).

# Recovery / rollback

Entirely additive — no existing script or documented procedure is
modified by this issue, only new workflow files and the new base
snapshot/supervisor infrastructure. If the self-hosted tier proves
unreliable, disable its `pull_request` trigger and fall back to
`workflow_dispatch`-only without affecting `ci-static.yml`. If the
snapshot-reset mechanism itself fails, the runner can be manually reset
(boot the base snapshot by hand via the Proxmox web UI) with no CI
downtime beyond the self-hosted tier being temporarily unavailable —
`ci-static.yml` keeps running regardless, since it has no dependency on
the self-hosted runner at all.