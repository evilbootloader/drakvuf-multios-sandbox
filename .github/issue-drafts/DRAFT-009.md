# DRAFT-009: Define the shared-vs-OS-specific script boundary and the per-OS configuration contract

**Status:** **Published 2026-08-10 —
[#6](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/6)**
**Area:** core / platform
**OS:** ALL
**Milestone:** M0
**Priority:** P0 — raised from the title-index's P1; see "Why the priority
moved" below
**Depends on:** DRAFT-008 / issue #3 (**closed** 2026-08-09) — the job/result
model the per-OS scripts must eventually emit against. Issue #4 / DRAFT-025
(CREATE + DEPLOY **complete** 2026-08-09) — built `pipeline-ubuntu.env`,
which is the mechanism this issue formalizes rather than invents.
**Blocks:** DRAFT-015, DRAFT-016 (Android scripts), DRAFT-034 (Windows
track). Discharges issue #4's one remaining open acceptance criterion.
**Origin:** `docs/roadmap/project-roadmap.md` title-index; rescoped by
`project-assessment.md` → "Title-only entries" row 009 and
`.github/issue-drafts/issue-index.md:321`

# Objective

Decide, once and in writing, two things:

1. **Which files in `automation/` are shared across all three OS targets and
   which are copied per OS** — including the files that are *neither* today,
   because they are shared code carrying per-OS hard-coded values.
2. **What a new per-OS pipeline must provide, in which file, under which
   names** — so `clone-android.pl`, `preconfig-android.sh`,
   `drakvuf-android.sh`, `run_analysis-android.sh` and their Windows
   equivalents are written against a stated contract instead of by copying
   the `*-ubuntu.*` set and editing until it runs.

**No Ubuntu behaviour change.** The deliverable is a documented contract, a
conformance checklist, and comment-level annotation of
`pipeline-ubuntu.env`. Any rename that lands must keep every existing
default byte-identical.

# Context

## What is already decided, and is no longer this issue's question

The file-level split is source-verified and stable. Every shared file takes
its OS-varying inputs as arguments:

| Shared — no OS in the name | Signature evidence |
|---|---|
| `dirwatch.c` | domain, config and profile are arguments (`dirwatch.c:453` validates count only) |
| `network-setup.sh` | one argument: clone-slot count (`:128` usage comment) |
| `cleanup.sh` | `DOMAIN=$1`, `VLAN=$2` (`:113-114`) — nothing else |
| `tcpdump.sh` | `VLAN`, `RUNFOLDER`, `RUNFILE`, `OUTPUTFOLDER` (`:111-114`) |

| Per-OS — one copy per target | Ubuntu instance |
|---|---|
| `clone-*.pl` | `clone-ubuntu.pl` |
| `preconfig-*.sh` | `preconfig-ubuntu.sh` |
| `drakvuf-*.sh` | `drakvuf-ubuntu.sh` |
| `run_analysis-*.sh` | `run_analysis-ubuntu.sh` |
| `pipeline-*.env` | `pipeline-ubuntu.env` |

And the routing arrangement is decided: one `dirwatch` instance and one
incoming directory per OS (`docs/architecture/analysis-pipeline.md`,
"Target OS selection"; `dirwatch.c:472` hard-codes one origin per process).
`pipeline-ubuntu.env:15-18` already records the consequence — *"Android and
Windows get their own copy of this file rather than a shared one with per-OS
branches"*.

**Issue #4 changed what this issue is.** It was drafted when the
parameterization mechanism did not exist; it now does, for the shell half.
Re-deriving the split is bookkeeping. The four questions below are what is
genuinely undecided, and each will otherwise be answered independently — and
differently — in the Android and Windows scripts.

## Q1 — the guest-staging vocabulary does not generalize

`pipeline-ubuntu.env:77-78`:

```sh
GUEST_USER="${GUEST_USER:-carlos}"
GUEST_STAGING_DIR="${GUEST_STAGING_DIR:-/home/$GUEST_USER/Desktop}"
```

Both consumers derive the guest path from `GUEST_STAGING_DIR`, not from
`GUEST_USER` (`preconfig-ubuntu.sh:162`, `drakvuf-ubuntu.sh:150`). Android
has no `/home/<user>` concept at all; Windows takes a third form, with a
different separator. `GUEST_USER` is therefore an Ubuntu-shaped intermediate
variable sitting in the position of a contract term.

The decision is small and the cost of deferring it is three vocabularies:
**`GUEST_STAGING_DIR` is the primitive every pipeline must define;
`GUEST_USER` is an Ubuntu-local convenience other pipelines are not required
to have.**

This does **not** close the open M1 item — `GUEST_USER` stays configured
rather than discovered from the guest (`pipeline-ubuntu.env:75-76`,
`CLAUDE.md` known issues). It only stops that item from being inherited by
two more pipelines as a required field.

## Q2 — host-global values are currently held in per-OS files

`ANALYSIS_BRIDGE` (`:141`) and `MAX_CLONES` (`:139`) live in the per-OS
config, but there is one analysis bridge and one VLAN space on the host.
Three copies of that file means three places that must agree, with nothing
checking that they do.

Worse, the variable does not actually parameterize the thing it names.
`ANALYSIS_BRIDGE` has exactly **one** consumer in the whole tree —
`run_analysis-ubuntu.sh:49` — while the bridge name is hard-coded at every
point that matters:

- `network-setup.sh:144-148` — `ip link set xenbr1 up`, `vconfig add
  xenbr1 $i`, `172.16.$i.1/24`;
- `cleanup.sh:118` and `drakvuf-ubuntu.sh:161` — `tcpdump -i xenbr1.$VLAN`;
- `clone-ubuntu.pl:145` — `$clone_bridge = "xenbr1"`;
- all four `misc/*.cfg`.

`network-setup.sh`'s own header already states this plainly: *"xenbr0
(uplink) and xenbr1 (analysis bridge) are project-wide fixed names… Renaming
them here alone is not enough."* The same is true of the
`172.16.<vlan>.0/24` scheme, which `network-setup.sh:148` owns and
`preconfig-ubuntu.sh:205` independently restates guest-side.

**Decide:** do host-global values move to a platform-level config
(`automation/platform.env`, or similar) that both the shared scripts and
each `pipeline-<os>.env` read, or do the shared scripts stay
argument-only — and `ANALYSIS_BRIDGE` gets deleted rather than left as a
variable implying a parameterization that does not exist? Either answer is
defensible; three files silently disagreeing is not.

## Q3 — `clone-*.pl` sits outside the configuration mechanism entirely

It reads no config. `dirwatch` invokes it with a fixed 3-argument contract
(`dirwatch.c:175`), and it hard-codes:

| Line | Value | Problem for the copies |
|---|---|---|
| `:142` | `$lvm_vg = "vg-root"` | host-global, duplicated per copy |
| `:145` | `$clone_bridge = "xenbr1"` | same, and see Q2 |
| `:280` | `lvcreate -s … -L64G` | a Windows golden LV is unlikely to want 64G |

It *can* reach a config — it already resolves `$FindBin::RealBin` to derive
the saved-state path (`:283`), which is exactly how issue #4 made the disk
snapshot and the memory image incapable of naming different domains.

**Decide, before `clone-android.pl` is written from this file:** does the
Perl source a config, take more arguments, or stay hard-coded with per-OS
copies?

> **Boundary with DRAFT-010.** This issue decides **what values a per-OS
> script needs**; DRAFT-010 decides **how they arrive**, because that is a
> question about `dirwatch`'s callback contract. Q3 must therefore be
> answered without changing the 3-argument contract. If the answer turns out
> to require a contract change, that is a finding handed to DRAFT-010, not a
> change made here.

## Q4 — what "per-OS copy" is permitted to mean

`CLAUDE.md` directs that new scripts be written from the corresponding
Ubuntu implementation. Applied literally today, that copies known defects:

- `clone-ubuntu.pl` checks no exit status on `lvremove`/`lvcreate`/`xl
  restore` (DRAKVUF-06 → **DRAFT-033**);
- `preconfig-*`/`drakvuf-*` inherit the untrusted-filename handling
  DRAFT-030 exists to fix;
- all five carry the licence header above the shebang (**DRAFT-031**).

So the rule this issue must state: **a defect known in the template is fixed
in the template before the copy is made.** That converts three soft
"informs" relationships into hard ordering constraints, one of which
`issue-index.md:327` already records for DRAFT-015.

## Issue #4's carried-forward criterion belongs here

Issue #4 has one acceptance criterion it cannot satisfy itself:

> *Android automation scripts, when implemented (DRAFT-015/016), are written
> against this same convention from the start* — `DRAFT-025.md:360-361`

It is deliberately carried forward, it needs a Windows counterpart
(DRAFT-034) that the original wording does not cover, and it now also covers
the corrected `injector -m writefile` syntax — `-B` is the Dom0 source and
`-e` the guest destination, which refuted the Android checklist's candidate
command (`docs/runbooks/01-verify-user-placeholder.md:154-157`, DRAFT-027's
resolution note). The conformance checklist this issue produces is what
discharges it, for both remaining targets.

## Why the priority moved

P1 in the title-index, written when only Ubuntu existed and Android was
next. With Android *and* Windows script sets both imminent, this is the gate
that decides whether the shared defects are fixed once or three times —
`project-assessment.md:730-734` calls it "the single largest ordering change
this assessment recommends". It is also, right now, the only P0 that is
actually unblocked: DRAFT-036 outranks it but carries a publication gate on
DRAFT-010's C-vs-Python decision (`issue-index.md:100-106`).

# Dependencies

- **DRAFT-008 / issue #3** — closed 2026-08-09. The state model is what the
  per-OS `stage` vocabularies hang off; the conformance checklist references
  it rather than restating it.
- **Issue #4 / DRAFT-025** — CREATE and DEPLOY complete. This issue
  formalizes the mechanism #4 built and inherits its open criterion.
- **Informs DRAFT-015, DRAFT-016, DRAFT-034** — all three are blocked on the
  conformance checklist existing.
- **Hands ordering constraints to DRAFT-033, DRAFT-030, DRAFT-031** — each
  becomes a prerequisite of the copy that would otherwise inherit its
  defect.
- **Must not conflict with DRAFT-036** — Q2's answer names *where a value
  lives*; DRAFT-036 decides *who allocates it*. PLAN step 4 checks the two
  against each other.

# Out of scope

- Implementing any Android or Windows script — DRAFT-015/016/034.
- The `dirwatch` callback contract, the `dirwatch_old.c` disposition, and
  C-vs-Python — DRAFT-010.
- Host-global VLAN leasing and memory-based clone admission — DRAFT-036.
  This issue may say where `MAX_CLONES` belongs; it must not design the
  allocator that replaces it.
- Fixing the template defects themselves — DRAFT-030, DRAFT-031, DRAFT-033.
  This issue orders them relative to the copies; it does not do them.
- Discovering `GUEST_USER` from the guest instead of configuring it — open
  M1 work, unchanged by this issue.
- The `/malware_*` runtime layout — issue #3 and DRAFT-018 own it.
- Any change to Ubuntu runtime behaviour.

# PLAN

1. **Re-derive the shared/per-OS table from the current files**, not from
   `project-assessment.md`. For each shared file record its *argument
   signature* as the evidence that it is shared, and record every
   OS-specific value it nonetheless hard-codes — that second column is the
   real finding.
2. **Enumerate every value a per-OS pipeline needs.** Sources:
   `pipeline-ubuntu.env`, the hard-coded values in `clone-ubuntu.pl`, and
   the guest-side assumptions in `preconfig-ubuntu.sh` (`eth0`,
   `172.16.$VLAN.2/24`, `sudo`, `/etc/resolv.conf` — none of which hold on
   Android). Classify each as **per-OS**, **host-global**, or **per-run**
   (already a `dirwatch` argument).
3. **Answer Q1 against real Android evidence.** Read
   `docs/checklists/android.md` for where a sample can be staged in BlissOS
   and whether the Android track already assumes a path. Do not invent one;
   if the checklist has no answer, record the question as open and scope the
   contract term so Android can fill it without renaming anything.
4. **Answer Q2**, and check the answer against DRAFT-036's requirements
   before adopting it, so the two do not have to be reconciled later.
5. **Answer Q3** without changing `dirwatch`'s 3-argument contract.
6. **Write the conformance checklist** — what a new per-OS pipeline must
   provide, in which file, under which names, including the `writefile`
   syntax and the "no component of the guest path derived from the submitted
   filename" rule from the state model.
7. **State the ordering rules** that fall out of Q4, and record them in
   `issue-index.md` as dependency corrections rather than prose.

# CREATE

- **`docs/architecture/analysis-pipeline.md`** — a new "Shared and per-OS
  code boundary" section: the two tables, the four decisions, and the
  conformance checklist. It belongs in this document because the per-OS
  routing decision it builds on is already here.
- **`automation/pipeline-ubuntu.env`** — annotate each variable with its
  classification from PLAN step 2 (per-OS / host-global / inherited).
  Comment-only; no value changes. If Q2's answer moves a variable, that
  is a separate, reviewable hunk with the default preserved.
- **`CLAUDE.md`** — point "Current implementation" at the new section, and
  amend the "write new scripts from the Ubuntu implementation" instruction
  to "…from the corrected Ubuntu implementation, per the conformance
  checklist".
- **`docs/checklists/android.md` §2.5, §2.7–2.8** and
  **`docs/checklists/windows.md`** — annotate that new scripts must satisfy
  the checklist. Annotate; do not rewrite. These carry dated evidence.
- **`.github/issue-drafts/issue-index.md`** — the dependency corrections
  from PLAN step 7.

# TEST

This is a documentation and comment change, so the tests are about proving
*absence* of behaviour change:

```sh
bash -n automation/*.sh
dash -n automation/*.sh
shellcheck automation/*.sh
perl -c automation/clone-ubuntu.pl
shellcheck -s sh automation/pipeline-ubuntu.env   # sourced, never executed
```

Plus one specific check, because it is the whole no-behaviour-change claim
in one line — capture the `dirwatch` command `run_analysis-ubuntu.sh` would
launch, before and after, and diff:

```sh
# with the launcher's exec line temporarily echoed rather than run
diff <(before) <(after)   # expect: identical
```

And a completeness check: every name in the conformance checklist actually
exists in `pipeline-ubuntu.env`, and every variable in
`pipeline-ubuntu.env` appears in the checklist with a classification.

# DEPLOY

Nothing to deploy if the change stays documentation and comments. If a
variable rename or move lands, it deploys the same way everything does since
issue #4 — `git -C /root/sandbox_project pull`, **never while an analysis is
in flight**, since `dirwatch` re-reads the worker scripts per sample. Verify
with `git log -1` and `git status --porcelain` (expect empty).

One benign end-to-end Ubuntu run afterwards, to confirm the no-change claim
against a real analysis rather than only against a diff.

# Acceptance criteria

- [ ] `docs/architecture/analysis-pipeline.md` carries a shared/per-OS
      boundary section stating, per file, which side it is on and the
      argument or config evidence for that placement.
- [ ] Every OS-specific value hard-coded inside a *shared* file is
      enumerated, with its owning issue named — none is left implicit.
- [ ] Q1 is answered: `GUEST_STAGING_DIR` (or the agreed replacement) is the
      contract term, and `GUEST_USER`'s status as Ubuntu-local is written
      down.
- [ ] Q2 is answered, and the answer is checked against DRAFT-036 in
      writing. `ANALYSIS_BRIDGE` either gains real consumers or is recorded
      as not parameterizing what its name suggests.
- [ ] Q3 is answered without any change to `dirwatch`'s 3-argument clone
      contract; anything requiring one is handed to DRAFT-010 explicitly.
- [ ] A conformance checklist exists that `clone-android.pl` and a Windows
      equivalent can be written *against*, including the corrected
      `injector -m writefile` syntax (`-B` Dom0 source, `-e` guest
      destination) and the no-untrusted-bytes-in-the-guest-path rule.
- [ ] The ordering rules from Q4 are recorded in `issue-index.md`:
      DRAFT-033 before DRAFT-015; DRAFT-030 before the second `preconfig-*`;
      DRAFT-031 before either copy inherits the shebang placement.
- [ ] Issue #4's carried-forward criterion is restated here in a form that
      covers **Windows (DRAFT-034) as well as Android**, and #4's own copy
      is annotated to point at it.
- [ ] Ubuntu behaviour is unchanged: identical `dirwatch` invocation,
      identical defaults, all static checks pass, one benign end-to-end run
      completes normally.
- [ ] `CLAUDE.md` and both affected checklists reference the new section.

# Evidence required

- The `bash -n` / `dash -n` / `shellcheck` / `perl -c` output.
- The before/after `dirwatch` command-line diff, empty.
- The completeness-check output (checklist ↔ `pipeline-ubuntu.env`).
- The post-change benign analysis log excerpt, if any file under
  `automation/` was touched.

# Security considerations

- **The boundary is itself a security fact.** A defect in a shared file is a
  defect in three analysis networks at once — `network-setup.sh` holds the
  only inter-clone isolation rule in the project, and `cleanup.sh` is what
  guarantees a clone is destroyed. Recording which files those are is what
  makes DRAFT-013/028/029 reviewable as three-OS work instead of Ubuntu work
  that Android and Windows happen to share.
- **Q1 decides where untrusted content lands in each guest.** The state
  model's rule — no component of the guest path derived from the submitted
  filename, the name being the sample's Dom0-computed SHA-256 — must be
  restated as a per-OS obligation in the conformance checklist. Left as an
  Ubuntu implementation detail, it is exactly the kind of property a copy
  loses silently.
- **Per-OS copies must not become per-OS security postures.**
  `GUEST_NAMESERVER`'s reasoning (`pipeline-ubuntu.env:80-119`) is an
  analysis-network policy decision, not an Ubuntu one. Three copies free to
  diverge is an unreviewable containment posture; the checklist should mark
  which terms are policy (identical across pipelines by default) and which
  are genuinely per-OS.
- This issue changes no privilege, no network rule and no destructive
  command. Its risk is entirely in what it *permits later* — which is why
  Q4's ordering rules are acceptance criteria rather than advice.

# Documentation changes

`docs/architecture/analysis-pipeline.md` (new boundary section — primary
deliverable), `CLAUDE.md` (cross-reference and the amended
write-from-Ubuntu instruction), `automation/pipeline-ubuntu.env` (per-variable
classification comments), `docs/checklists/android.md` §2.5/§2.7–2.8 and
`docs/checklists/windows.md` (annotations pointing at the checklist),
`.github/issue-drafts/issue-index.md` (dependency corrections),
`.github/issue-drafts/DRAFT-025.md` (annotate the carried-forward criterion
to name this issue as where it is discharged).

# CREATE completed 2026-08-10

All seven PLAN steps executed. Documentation and comments only — no
executable line changed anywhere, which is the acceptance property this
issue committed to.

**The evidence pass reshaped the issue.** Re-deriving the table from current
sources (PLAN 1) produced a finding the assessment had not: *the shared
files hard-code no OS-specific value at all* — every literal in
`dirwatch.c`, `network-setup.sh`, `cleanup.sh` and `tcpdump.sh` is
host-global. The split was already correct as a split; what was missing was
a host-global config. That is a different problem from the one this issue
was written to solve, and it is why decision 2 exists.

**Four decisions**, in `docs/architecture/analysis-pipeline.md`:

1. Guest path is `<staging dir>/<guest_filename>`, staging flat in a
   pre-existing directory — `writefile` cannot create parents, so a
   per-sample directory costs a second injection through a guest shell.
2. Host-global values move to `automation/platform.env`. `CLONE_LV_SIZE` is
   **not** among them — it sizes a CoW exception store, so it tracks guest
   write volume, which is per-OS. Corrected by the maintainer.
3. `clone-*.pl` reads host values from the environment; `dirwatch` spawns
   with `envp = NULL`, so no contract change and no Perl config parser.
   Source-reasoned; needs one Dom0 run.
4. No in-guest collection on any target — `logcat`, `logd`, `dumpsys`,
   `dmesg` withdrawn. Maintainer's call, and the sharpened reason is that a
   collector inside the guest is visible to the sample, writes a file the
   sample can poison, and needs in-guest state to stop.

**Android's staging directory is execution-evidenced**, not Candidate:
`/data/local/tmp`, after a probe on the live guest refuted one hypothesis
(namespace resolution — the anchor sees `/storage/self/primary` fine) and
confirmed two (`noexec` on the FUSE mount, `chmod` silently a no-op).
`/storage/self/primary/Download` is writable and visible and still cannot
execute anything. Recorded in `docs/checklists/android.md`.

**Conformance checklist C1–C10** written so each item is verifiable from the
files rather than from an assertion, keeping it convertible into a
DRAFT-026a check later. C10 exists because of the Android finding above.

**Scope handed on, confirmed by the maintainer:** the normalizer, the Ubuntu
staging retrofit and the per-OS argv re-establishment to DRAFT-030; emitting
`guest_filename`/`original_filename` to DRAFT-011.

## Still open

- **Who creates `platform.env`.** Proposed: DRAFT-028 creates it and wires
  `network-setup.sh`, DRAFT-033 wires `clone-*.pl`, DRAFT-011 wires
  `cleanup.sh`/`tcpdump.sh` — each file's existing owner. Not confirmed.
- **Decision 3 is unverified on Dom0.** An empty `$ENV{VG_NAME}` falls back
  to `vg-root` and looks like success, so it needs a deliberate check.

## TEST results, 2026-08-10

```text
bash -n automation/*.sh                 clean
dash -n automation/*.sh                 clean
perl -c automation/clone-ubuntu.pl      syntax OK
sh -n automation/pipeline-ubuntu.env    parses as POSIX sh
shellcheck -f gcc automation/*.sh       48 findings — identical to the
                                        baseline recorded in PR #5
```

No-behaviour-change, proven rather than asserted — every non-comment line of
`pipeline-ubuntu.env` is byte-identical to `HEAD`:

```sh
diff <(git show HEAD:automation/pipeline-ubuntu.env | grep -vE '^\s*#|^\s*$') \
     <(grep -vE '^\s*#|^\s*$' automation/pipeline-ubuntu.env)   # empty
```

No Dom0 execution was required by this issue and none was performed.

# Recovery / rollback

Documentation and comments; a single-commit revert restores the previous
state exactly. If a variable move lands in `pipeline-ubuntu.env`, rollback is
the same revert plus a Dom0 `git pull` — and because every default is
preserved by construction, a partially-rolled-back Dom0 behaves identically
either way. No persistent infrastructure change is made by this issue.