# DRAFT-025: Standardize Xen analysis pipeline paths

**Status:** Published — [issue #4](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/4)
**Area:** platform
**Milestone:** M0
**Priority:** P1
**Depends on:** DRAFT-001 (repo baseline); informed by DRAFT-006 (issue #1,
`misc/` naming — closed on both repo and host sides 2026-08-08) and
DRAFT-007 (issue #2, closed 2026-08-08; `automation/` now matches the
deployed Dom0 copies this issue will relocate)

# Objective

Standardize all Xen Dom0-side path assumptions in this repository's
automation, Xen guest configs, LibVMI profiles, and documentation around a
single canonical repository root, `/root/sandbox_project`, instead of the
current mix of `/home/user/drakvuf-tools`, `/home/user/Documents`,
`~/drakvuf-tools`, and bare `/root/*.json`. Runtime malware directories
(`/malware_incoming`, `/malware_processing`, `/malware_finished`) are
explicitly confirmed correct as-is and stay out of this redesign — this is
about repository-owned assets (code, configs, profiles, saved VM state)
only.

# Context

The automation scripts, Xen `.cfg` files, and documentation in this repo
were written against a Dom0 layout that does not match where this
repository itself lives when cloned. Concretely, as found by inspecting
`automation/`, `misc/`, and `docs/` in this session:

- `automation/run_analysis-ubuntu.sh` invokes `dirwatch` with six
  hard-coded `/home/user/drakvuf-tools/...` arguments (config, clone
  script, preconfig script, drakvuf-trace script, cleanup script, tcpdump
  script) and a bare `/root/linux.json` profile path — none of which
  match this repo's actual `automation/`/`misc/` layout.

  ```
  automation/run_analysis-ubuntu.sh:5    /home/user/drakvuf-tools/network-setup.sh 2
  automation/run_analysis-ubuntu.sh:13   /home/user/drakvuf-tools/ubuntu_sandbox.cfg
  automation/run_analysis-ubuntu.sh:14   /root/linux.json
  automation/run_analysis-ubuntu.sh:20-24 /home/user/drakvuf-tools/{clone-ubuntu.pl,preconfig-ubuntu.sh,drakvuf-ubuntu.sh,cleanup.sh,tcpdump.sh}
  ```

- `automation/clone-ubuntu.pl:253` hard-codes the saved-state restore path:
  `/home/user/Documents/ubuntu_sandbox.bak`.
- `automation/drakvuf-ubuntu.sh:119` and
  `automation/preconfig-ubuntu.sh:122` both hard-code the **in-guest**
  staged-sample path `/home/carlos/Desktop/test`. These are guest-side
  paths, out of scope here, and noted only as context. *(Updated
  2026-08-08: `drakvuf-ubuntu.sh` previously held an unsubstituted
  `<USER>` placeholder here — resolved in issue #2, which also synced
  `automation/` to the deployed Dom0 copies. The two scripts now agree.)*
- None of the scripts resolve their own location (no
  `SCRIPT_DIR`/`FindBin` pattern anywhere); every reference to a sibling
  script or asset is a hard-coded absolute.
- `misc/android.json` and `misc/linux.json` (LibVMI/DRAKVUF profiles) are
  already committed to this repository under `misc/`, but every script and
  doc that consumes a profile references it at the fixed runtime location
  `/root/android.json` / `/root/linux.json`, disconnected from the
  repo-tracked copy. There is no documented mechanism that gets the
  repo-tracked profile onto that runtime path.
- `docs/drakvuf-on-xen-nested-within-proxmox.md`, `docs/android_setup.md`,
  and `docs/checklists/android.md` are heavily seeded with the same
  `~/drakvuf-tools` / `~/Documents` / bare `$HOME` patterns — presumably
  where the automation scripts' hard-coded values originated:

  ```
  docs/drakvuf-on-xen-nested-within-proxmox.md:324,422,442,459,531,653,656
      ~/drakvuf-tools/ubuntu.cfg, ~/drakvuf-tools/ubuntu_sandbox.cfg,
      ~/Documents/ubuntu_sandbox.bak, ~/drakvuf-tools/network-setup.sh, ...
  docs/drakvuf-on-xen-nested-within-proxmox.md:392-396
      /root/linux.json (dwarf2json output + libvmi.conf)
  docs/android_setup.md:585,703,715,719
      /home/user/drakvuf-tools/Bliss-...iso, /root/android.json (x3)
  docs/checklists/android.md:715-717
      ANDROID_XL_CONFIG=/home/user/drakvuf-tools/android_sandbox.cfg,
      ANDROID_PROFILE=/root/android.json,
      ANDROID_SAVE_FILE=/home/user/Documents/android_sandbox.bak
  docs/checklists/android.md:786-813 (and many more through §2.x evidence)
      test -r /root/android.json; ~/drakvuf-tools/*.pl|*.sh throughout
  docs/architecture/analysis-pipeline.md:25-26
      dirwatch 1 ubuntu_sandbox /home/user/drakvuf-tools/ubuntu_sandbox.cfg /root/linux.json ...
  misc/android.cfg:25   file:/home/user/drakvuf-tools/Bliss-v17.8.3-...iso,hdc:cdrom,r
  misc/ubuntu.cfg:24    file:/home/user/Documents/ubuntu-20.04.6-desktop-amd64.iso,hdc:cdrom,r
  ```

- `.gitignore` currently ignores `*.bak` (saved VM state) but does **not**
  ignore the LibVMI profile JSON files, which is why `misc/android.json`
  and `misc/linux.json` ended up committed — worth an explicit decision
  either way (see Out of scope / PLAN).

## Proposed canonical path layout

```
/root/sandbox_project/            <- this repository, cloned on Xen Dom0
├── automation/                   <- existing, unchanged location
├── misc/                         <- existing, unchanged location (Xen .cfg files stay here)
├── profiles/                     <- new: LibVMI/DRAKVUF JSON profiles
│   ├── linux.json                <- moved from misc/linux.json
│   ├── android.json              <- moved from misc/android.json
│   └── windows.json              <- future (DRAFT-034); slot reserved here
├── state/                        <- new: Xen `xl save` saved-state blobs (gitignored, .bak)
│   ├── ubuntu_sandbox.bak
│   ├── android_sandbox.bak
│   └── windows_sandbox.bak       <- future (DRAFT-034); slot reserved here
└── docs/                         <- existing, unchanged location
```

`/malware_incoming`, `/malware_processing`, `/malware_finished` are
unaffected and stay exactly where they are.

> **Assessment update (2026-08-08, `project-assessment.md` → Issue #4):**
> Windows is now a **current** target, so the convention this issue
> establishes must have room for a third OS from the start — including
> `misc/windows.cfg` / `misc/windows_sandbox.cfg`. The Windows artifacts
> themselves are built by DRAFT-034; this issue only guarantees they
> inherit the layout rather than needing a fourth standardization pass.

## Repository-owned files vs runtime data

| Category | Canonical root | Examples | Git-tracked? |
|---|---|---|---|
| Source code, automation, config, profiles, VM state | `/root/sandbox_project` | `automation/*.sh`, `automation/*.pl`, `misc/*.cfg`, `profiles/*.json`, `state/*.bak` | Code/config: yes. Profiles: yes (already the case, decision to revisit — see PLAN). State `.bak`: no, gitignored (already the case). |
| Mutable runtime analysis data | `/malware_*` (unchanged, top-level) | `/malware_incoming`, `/malware_processing`, `/malware_finished` | No — already gitignored, and correctly so. May be owned by `www-data` (Apache serves `/malware_processing` per `docs/drakvuf-on-xen-nested-within-proxmox.md:612,628,644`); do not change ownership/location as part of this work. |
| Xen/LVM guest storage | `/dev/vg-root/...` | golden/sandbox LVs for `ubuntu`, `android` | N/A — block devices, not files |

## Path resolution rules

1. No script may depend on `$PWD`, `~`, `$HOME`, or a hard-coded
   `/home/<user>/...` path to locate repository-owned assets.
2. Shell scripts must resolve their own location and the repo root at the
   top of the file:

   ```bash
   SCRIPT_DIR="$(
       cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
       pwd
   )"

   REPO_ROOT="$(
       cd -- "$SCRIPT_DIR/.." &&
       pwd
   )"
   ```

   All references to sibling scripts, `misc/*.cfg`, `profiles/*.json`, and
   `state/*.bak` must be built from `$REPO_ROOT`, not hard-coded absolutes.
3. Perl scripts (`clone-ubuntu.pl`, future `clone-android.pl`) must use
   `FindBin` (`$FindBin::Bin`, `$FindBin::Bin/..`) for the same purpose.
4. `dirwatch`'s existing 15-argument CLI contract already takes
   `domain_config`, `json_kernel_path`, and the five script paths as
   explicit arguments (`automation/dirwatch.c:474-486`) — this rule does
   not change that contract, only the *values* the launcher passes for
   them, so they resolve under `$REPO_ROOT` instead of
   `/home/user/drakvuf-tools`.
5. In-guest paths (staged-sample destination, `drakvuf-ubuntu.sh`'s `CMD`)
   are a separate concern from Dom0 repo-relative paths and are explicitly
   out of scope here. Note `-e` is execve-direct with no guest shell
   (established in issue #2), so these can only ever be resolved Dom0-side.
6. `/malware_incoming`, `/malware_processing`, `/malware_finished` remain
   absolute, fixed, top-level paths — not made repo-relative or
   configurable by this issue.

# Dependencies

- DRAFT-001 (repo baseline, for commit ordering).
- Informed by DRAFT-006 / issue #1 (`misc/` naming reconciliation — this
  issue fixes how `misc/*.cfg` files are *referenced*, not their names,
  which #1 already settled).
- Informed by DRAFT-007 / issue #2 (**closed 2026-08-08**; the in-guest
  paths this issue excludes, and the repo↔Dom0 sync it performed, which
  means `automation/` now matches the host this issue will relocate).
- Should land before DRAFT-015/016 (Android `clone-android.pl` /
  `preconfig-android.sh` / `drakvuf-android.sh` / `run_analysis-android.sh`
  implementation) so the Android scripts are written against this
  convention from the start rather than needing a follow-up pass.

# Out of scope

- Relocating `/malware_incoming`, `/malware_processing`,
  `/malware_finished` — confirmed correct where they are.
- The in-guest staging path `/home/carlos/Desktop/test` in
  `drakvuf-ubuntu.sh` / `preconfig-ubuntu.sh`, including parameterizing
  the hard-coded guest username — open M1 work, not this issue's.
- Implementing `clone-android.pl` / `preconfig-android.sh` /
  `drakvuf-android.sh` / `run_analysis-android.sh` themselves (DRAFT-015/
  016) — this issue only defines the path convention those
  implementations must follow.
- Renaming `misc/linux.cfg` / `misc/linux_sandbox.cfg` further — already
  handled by issue #1; this issue only fixes how those files are
  *referenced*.
- Changing the `dirwatch` CLI argument contract/order — only the values
  passed for existing path arguments.
- `docs/android_setup.md`'s `$HOME/BlissOS` build-tree paths — those are
  Android *build*-machine paths, not Xen Dom0 analysis-pipeline paths.
- Any change to `/dev/vg-root/...` LVM device naming.
- Actually deploying/moving anything on the real Dom0 host — covered by
  this issue's own DEPLOY section as a separate, manually-executed stage.

# PLAN

1. Confirm with the Dom0 operator that `/root/sandbox_project` is an
   acceptable, available clone location, and whether the real host's
   current `~/drakvuf-tools` checkout should be replaced or kept as a
   symlink alias during transition.
2. Decide the profile-delivery mechanism: point `libvmi.conf` directly at
   `$REPO_ROOT/profiles/*.json`, or have the launcher copy/symlink them to
   `/root/*.json` at start-of-run? (Needs checking LibVMI's config format
   and restart tolerance against upstream docs before deciding.) LibVMI setup
   shoudln't be needed as the drakvuf program is run with the profile path during
   automated analysis.

   > **Assessment evidence supporting the above (2026-08-08,
   > `project-assessment.md` → PATH-04).** Confirmed by source reading, and
   > the case is stronger than "shouldn't be needed" — it *cannot* be
   > needed:
   >
   > - `drakvuf-ubuntu.sh:122` and `preconfig-ubuntu.sh:125` both pass
   >   `-r "$REKALL"` explicitly, supplied by `dirwatch` from its
   >   `json_kernel_path` argument (`dirwatch.c:477`), which
   >   `run_analysis-ubuntu.sh:14` controls.
   > - Clones are named `<origin>-<vlan>-clone` (`clone-ubuntu.pl:157`),
   >   e.g. `ubuntu_sandbox-1-clone`. The documented `/etc/libvmi.conf`
   >   stanzas cover only `ubuntu` and `ubuntu_sandbox`
   >   (`docs/drakvuf-on-xen-nested-within-proxmox.md:395-396`). **No clone
   >   domain has a stanza at all**, so the automated path has never
   >   resolved a profile through `libvmi.conf`.
   >
   > So this PLAN step narrows to two smaller questions, neither of which
   > involves LibVMI's config format:
   >
   > a. Does the launcher pass `$REPO_ROOT/profiles/<os>.json` directly to
   >    `-r`, or copy it to a runtime path first? (Direct is simpler and
   >    removes a sync step.)
   > b. Are `/etc/libvmi.conf` stanzas still wanted for the *manual*
   >    diagnostic tooling — `vmi-process-list <domain>`, used throughout
   >    `docs/checklists/android.md:250,475` — given that even that
   >    accepts a profile path via `-j`
   >    (`docs/checklists/android.md:567`)? This matters for
   >    `docs/workflow-ci.md:268,278`, which registers stanzas in the CI
   >    base snapshot.
3. Decide whether `profiles/*.json` stays git-tracked (current state) or
   moves to `.gitignore` as host-generated/regeneratable — currently
   inconsistent with `.bak` files being ignored while `.json` profiles are
   committed. *(Context for the decision: the two tracked profiles are
   65 MB and 48 MB — `misc/android.json`, `misc/linux.json` — and are by
   far the largest objects in the repository.)*
4. Confirm no other hard-coded path was missed via the validation grep in
   TEST, beyond what's listed in Context.
5. Decide whether `misc/*.cfg`'s hard-coded installer-ISO paths are in or
   out of scope, and say which — they are currently described in Context
   but covered by no acceptance criterion. *(Added from
   `project-assessment.md` → PATH-03. The two paths are
   `misc/ubuntu.cfg:24` → `/home/user/Documents/ubuntu-20.04.6-…iso` and
   `misc/android.cfg:25` → `/home/user/drakvuf-tools/Bliss-…iso`; a
   Windows config will add a third. Note `docs/workflow-ci.md` stages ISOs
   at `/root/isos/`, so a decision here should not contradict it.)*
6. Produce the smallest-diff patch set per script/doc.

# CREATE

1. Add `SCRIPT_DIR`/`REPO_ROOT` resolution to each `automation/*.sh` file.
2. Add `FindBin`-based resolution to `automation/clone-ubuntu.pl`.
3. Replace hard-coded `/home/user/drakvuf-tools/...` arguments in
   `automation/run_analysis-ubuntu.sh`'s `dirwatch` invocation with
   `$REPO_ROOT`-relative paths.
4. Replace `/home/user/Documents/ubuntu_sandbox.bak` in
   `automation/clone-ubuntu.pl:253` with a `$REPO_ROOT/state/`-relative
   path (parameterized, not re-hard-coded).
5. Create `profiles/` and `state/` under the repo; `git mv
   misc/linux.json profiles/linux.json` and `git mv misc/android.json
   profiles/android.json`, preserving history.
6. Update `.gitignore` per the PLAN step 3 decision, and confirm/adjust
   the `.bak` pattern still matches `state/*.bak`.
7. Update `README.md`, `docs/architecture/analysis-pipeline.md`, and the
   Ubuntu/Android checklists to reference the new layout.
8. Leave `/malware_incoming`, `/malware_processing`,
   `/malware_finished` untouched in every file.

# TEST

Static checks (run inside this dev container per `CONTRIBUTING.md` — last
re-verified working 2026-08-08):

```bash
bash -n automation/run_analysis-ubuntu.sh
bash -n automation/cleanup.sh
bash -n automation/tcpdump.sh
bash -n automation/network-setup.sh
bash -n automation/preconfig-ubuntu.sh
bash -n automation/drakvuf-ubuntu.sh
shellcheck automation/*.sh
perl -c automation/clone-ubuntu.pl
```

Validation that no stale hard-coded paths remain (excluding intentionally
preserved historical checklist evidence and out-of-scope in-guest paths):

```bash
grep -RnsE '/home/|/root/[a-z]+\.json|~/|drakvuf-tools|Documents' automation misc docs
```

Location-independence proof — requires Xen Dom0, present for manual
execution, do not run against real infrastructure from this container:

```bash
cd /tmp
/root/sandbox_project/automation/run_analysis-ubuntu.sh
```

This must succeed identically to running it from inside
`/root/sandbox_project/automation/`, proving no `$PWD` dependency remains.

# DEPLOY

Requires manual Dom0 coordination — present, do not execute automatically:

1. Clone (or confirm existing clone of) this repository to
   `/root/sandbox_project` on the real Xen Dom0 host.
2. Move/copy the real `.bak` saved-state files from
   `/home/user/Documents/` to `/root/sandbox_project/state/`.
3. Confirm the real `/root/linux.json` / `/root/android.json` either match
   `profiles/linux.json` / `profiles/android.json` in this repo, or decide
   which is authoritative and reconcile.
4. Update `libvmi.conf` on Dom0 if the PLAN step 2 decision changes where
   LibVMI reads the profile from.
5. Update or retire any `~/drakvuf-tools` checkout so it doesn't silently
   diverge from `/root/sandbox_project` going forward.
6. Rollback: keep the old `~/drakvuf-tools` checkout in place, untouched,
   until the new paths are verified working end-to-end on Dom0 — revert by
   pointing `dirwatch`'s invocation back at the old paths if problems
   surface.

# Acceptance criteria

- [ ] No `automation/*.sh` file depends on `$PWD`, `~`, or `$HOME` to
      locate repository-owned assets.
- [ ] `automation/clone-ubuntu.pl` resolves its own location via `FindBin`
      instead of hard-coding `/home/user/Documents/ubuntu_sandbox.bak`.
- [ ] `automation/run_analysis-ubuntu.sh`'s `dirwatch` invocation passes
      `$REPO_ROOT`-relative paths for the config, profile, and five script
      arguments — no `/home/user/drakvuf-tools` references remain.
- [ ] `profiles/linux.json` and `profiles/android.json` exist at their
      decided canonical location (moved from `misc/` with history
      preserved), and the profile-delivery mechanism to the runtime path
      is documented.
- [ ] `state/` is the documented canonical location for `.bak` saved
      state, and `.gitignore` correctly excludes it.
- [ ] `/malware_incoming`, `/malware_processing`, `/malware_finished`
      remain unchanged in every file touched by this issue.
- [ ] `README.md`, `docs/architecture/analysis-pipeline.md`, and the
      Ubuntu/Android checklists reflect the new convention.
- [ ] All static checks in TEST pass.
- [ ] The validation grep in TEST returns no unexplained matches (any
      remaining `/home/`/`~/` hits are either historical checklist
      evidence explicitly preserved verbatim, or in-guest guest-side
      paths, which are out of scope).
- [ ] The out-of-repo location-independence test is presented for manual
      execution on Xen Dom0, with results recorded once run.
- [ ] Android automation scripts, when implemented (DRAFT-015/016), are
      written against this same convention from the start.

*Added 2026-08-08 from `project-assessment.md` → Issue #4:*

- [ ] The `misc/*.cfg` installer-ISO paths (`misc/ubuntu.cfg:24`,
      `misc/android.cfg:25`) are either standardized under this
      convention or explicitly recorded as out of scope with a reason —
      PLAN step 5's decision, either way, is written down. *(PATH-03: they
      appear in this issue's Context but were covered by no criterion.)*
- [ ] The layout reserves slots for the Windows track —
      `profiles/windows.json`, `state/windows_sandbox.bak`,
      `misc/windows*.cfg` — so DRAFT-034 inherits the convention rather
      than triggering a fourth standardization pass. *(Windows is now a
      current target.)*
- [ ] `docs/workflow-ci.md` is updated alongside the other documentation.
      It did not exist when this issue was written and is now a major
      consumer of these paths — it stages ISOs at `/root/isos/`
      (`:180`), registers profiles in `/etc/libvmi.conf` (`:268,278`), and
      DRAFT-026b's integration tier needs `$GITHUB_WORKSPACE`-relative
      paths that this convention determines.
- [ ] PLAN step 2 is answered as the two narrowed questions (a) and (b),
      not as the original "point `libvmi.conf` at the repo or copy to
      `/root`" framing — the automated path never consults `libvmi.conf`
      (PATH-04).

# Evidence required

- Diff of every file changed under CREATE.
- Output of all TEST-section static checks.
- Output of the validation grep, with any remaining matches explained.
- Manual confirmation from the Dom0 operator that the out-of-repo
  invocation test passed on the real host (cannot be verified inside the
  development container per `CLAUDE.md`'s infrastructure boundary).

# Security considerations

- `/malware_processing` is served by Apache as `www-data`
  (`docs/drakvuf-on-xen-nested-within-proxmox.md:612,628,644`) — this
  issue must not change its ownership, permissions, or location.
  *(2026-08-08: DRAFT-027 removes the pipeline's dependency on that Apache
  instance entirely. It does not change the directory's location or
  ownership either, so this constraint stands unchanged — but if DRAFT-027
  lands first, the `www-data` ownership may no longer be load-bearing.
  Check before assuming it still is.)*
- `state/*.bak` files (saved VM memory images) can be large and may
  contain sensitive in-guest data from prior analysis runs; the existing
  `.bak` gitignore coverage must be preserved, not accidentally dropped,
  when the pattern is updated for the new `state/` subdirectory.
- `profiles/*.json` (LibVMI/DRAKVUF kernel profiles) are not secret, but
  if PLAN step 3 decides to keep them git-tracked, confirm they don't
  embed anything host-identifying that shouldn't be public if this repo is
  ever made public.

# Documentation changes

`README.md`, `docs/architecture/analysis-pipeline.md`,
`docs/drakvuf-on-xen-nested-within-proxmox.md`, `docs/android_setup.md`,
`docs/checklists/ubuntu.md`, `docs/checklists/android.md` — all need their
path examples updated to the new convention. Historical checklist evidence
blocks (verbatim command transcripts) should be annotated rather than
rewritten, consistent with how issue #1's revision note handled a similar
situation.

*Added 2026-08-08 (`project-assessment.md` → Issue #4):*
`docs/workflow-ci.md` — omitted above because it did not exist when this
issue was written, and it is now one of the heaviest consumers of these
paths (ISO staging at `/root/isos/`, `libvmi.conf` registration, and the
`$GITHUB_WORKSPACE`-relative invocation DRAFT-026b depends on).
`docs/checklists/windows.md` — so the Windows track starts on this
convention rather than being retrofitted.

# Recovery / rollback

Entirely repo-side and additive until the DEPLOY step. If the Dom0-side
migration causes problems, the old `~/drakvuf-tools` checkout is left in
place untouched (DEPLOY step 6) and `dirwatch`'s invocation can be pointed
back at it with a one-line revert of `run_analysis-ubuntu.sh`. No data
loss risk — `.bak` files are moved, not deleted, and profiles are copied
before any old copy is removed.

# CREATE completed 2026-08-09 — with three deliberate scope changes

Repo-side work is done and statically verified. Nothing is deployed;
DEPLOY is `docs/runbooks/deploy-repo-relative-paths.md`, not yet executed.

**Issue #4 was updated on GitHub the same day, with approval.** Its body
was rewritten to match what was built (per `CONTRIBUTING.md`'s "Issue
dependency and cleanup" rule) and it was retitled to "[Platform]
Standardize Xen analysis pipeline paths **and replace HTTP sample
delivery**" to reflect DRAFT-027 being folded in. The pre-rewrite body
remains in GitHub's edit history. This draft stays the draft of record;
the sections below are the fuller account the issue body summarizes.

Three things went beyond what this draft scoped, each at the maintainer's
explicit request in session:

## 1. `/malware_*` is no longer carved out

This draft, and `issue-index.md`'s "Note on DRAFT-025", both stated that
#4 must not touch the runtime data paths because issue #3 and DRAFT-018
own them. **That carve-out was lifted on request.** The three folder
arguments now point at `/malware_{incoming,processing,finished}/ubuntu`,
implementing the per-OS layout issue #3 decided but never built.

The carve-out's *reasoning* still holds and is unchanged: the result
directory is still MD5-keyed, not `analysis_id`-keyed, and
`result-schema.md` §1 still describes that as current source-verified
behaviour rather than a settled convention. What #4 implemented is the
directory level above it — the OS-selection mechanism — which is
`dirwatch` launcher configuration, not result schema.

## 2. DRAFT-027 was folded in rather than sequenced after

Per-OS `/malware_processing/ubuntu` breaks the HTTP delivery path:
Apache's `DocumentRoot` is `/malware_processing`, so the guest's
`wget http://<gw>/<filename>` would 404 — silently, mid-`&&`-chain, with
no sample staged and a trace of nothing. Rather than work around that,
DRAFT-027 was implemented in the same change and the coupling removed.

**DRAFT-027's PLAN steps 1–2 did not need the Dom0 capture they ask
for.** That capture already existed, taken during issue #2 and recorded
at `docs/runbooks/verify-user-placeholder.md:154-157`. It also refuted
the Android checklist's candidate command, which had `-e`/`-f` where the
real interface is `-B` (Dom0 source) and `-e` (guest destination) — see
DRAFT-027's own resolution note.

## 3. Two defects found while editing the affected lines

Neither was in scope; both were in code this issue had to touch anyway,
and both are recorded where they were found rather than deferred:

- **Guest DNS never resolved.** `preconfig-ubuntu.sh` pointed
  `/etc/resolv.conf` at the clone's gateway, where nothing has ever
  listened on port 53. Now `GUEST_NAMESERVER`, defaulting to `1.1.1.1`.
  No follow-on issue: `tcpdump.sh` already captures the queries (plaintext
  UDP/53 on the clone's VLAN interface), and FakeNet-NG's `PREROUTING`
  redirect will intercept them unchanged when a simulated mode lands, so
  the value does not need revisiting. Full reasoning in
  `docs/architecture/networking.md`.
- **`automation/*.sh` run under `dash`, not `bash`.** Five of six carry
  the DRAKVUF license header above the shebang, so `#!/bin/bash` never
  reaches the kernel and GLib falls back to `/bin/sh`. This nearly
  defeated the issue: a first pass used `${BASH_SOURCE[0]}`, which dash
  evaluates to empty *without stopping*, silently making `SCRIPT_DIR`
  equal to `$PWD`. Resolution uses `$0`. The shebang placement itself is
  still DRAFT-031's to fix.

## DEPLOY completed 2026-08-09 — all acceptance criteria met

The runbook was executed on Dom0 the same day, against commit `57713fc`.
D1–D6 passed; evidence is in
`docs/runbooks/deploy-repo-relative-paths.md`, summarized in
`docs/checklists/ubuntu.md`.

- Location independence: launched from `/tmp`, behaved identically.
- Delivery: `WriteFile STATUS:SUCCESS` with `apache2` stopped, 88,812-line
  trace.
- Integrity: `readfile` pull hashed identically to the Dom0 source.
- `writefile` **does** leave the file executable — the `chmod` injection
  was removed, so delivery is two injections rather than three.

Dom0 now runs a checkout of this repository at `/root/sandbox_project`
over a read-only deploy key, which makes `git log -1` / `git status
--porcelain` the permanent answer to the repo↔host question that issue #2
needed a runbook to settle once.

## Three findings the deployment surfaced, none caused by this issue

Recorded because this is where they were seen; all are pre-existing.

- **`network-setup.sh` is not idempotent** — `RTNETLINK answers: File
  exists`, `Error: ipv4: Address already assigned` on the second launch.
  First execution evidence for **DRAFT-028**, which had been reasoned from
  source only.
- **A clone showed `maxmem` unlimited in `xl top`**, though all four
  `misc/*.cfg` set `maxmem` equal to `memory`. Undiagnosed. Recorded
  against **DRAFT-036** as a precondition — memory-based admission cannot
  work if a clone's ceiling is unbounded at runtime.
- **Two trace-phase timeouts on the first runs after a Dom0 reboot**, then
  none; runs before the reboot were fine. Probably the 2.1 GB saved image
  read cold from disk, but unmeasured — `drop_caches` would falsify it
  cheaply. The retry path worked correctly. `dirwatch`'s 180s guard leaves
  ~55s over `drakvuf-ubuntu.sh`'s `sleep 5` + `-t 120`, and neither number
  is configurable today.

Follow-up not blocking this issue: retiring `/home/user/drakvuf-tools`
broke `misc/android.cfg`'s install-cdrom path, which pointed at an ISO in
that directory. Annotated in the config; no analysis is affected.