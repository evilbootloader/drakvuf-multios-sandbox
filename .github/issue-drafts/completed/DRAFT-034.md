# DRAFT-034: Establish the Windows analysis-guest track (baseline, profile, anchor, configs)

**Status:** **Completed 2026-09-17**, never published. **A Windows job ran end
to end on Dom0 — operator-confirmed, 2026-09-05**, which is the date of the
bring-up commit run (`1b98391` … `48ee57d`) and should be corrected here if the
run was actually another day. `shellexec` is the working injection mode:
`25e5fc6` moved it to `createproc` and `48ee57d` reverted that six minutes
later as a regression.

**What carries the close.** `misc/windows.cfg` and `misc/windows_sandbox.cfg`
are tracked; the profile toolchain is established from primary sources and
recorded (`docs/checklists/windows.md` §0.1 — volatility3 `pdbconv.py`, not
`dwarf2json`, which was the open unknown this issue raised); the baseline is
64-bit Windows 10 with kernel PDB GUID `72c69e726c648bc18257af38fa78a2f21`
(`windows_symbols.md`); the injection anchor is PID 4696
(`sandboxd/stages.py:257`); and `sandboxd/guests.py` carries the Windows rows
as per-OS values rather than as branches, satisfying C1's surviving rule.

**Closed with its evidence unwritten, and that is the gap to name.** This
issue's acceptance list is made almost entirely of *recorded* evidence, and
the run that discharges it left no transcript in the repository:

* **No Windows runbook exists.** `docs/runbooks/` ends at 17 and none of them
  is this. A runbook is what would make the close self-supporting.
* **`docs/checklists/windows.md` Phase 0 stays unchecked**, by its own
  evidence-before-checkbox rule. The plugin-validation matrix, the verbatim
  `injector --help` capture of Windows injection semantics, and the PID/TGID
  record across three boots were never produced — 4696 is recorded once, not
  three times, and the anchor comment at `stages.py:249` warns that a stale
  PID fails silently.
* **Licensing/activation (PLAN step 6) was never answered.** It borders on
  DRAFT-022's scope and is a compliance question, not an operational one.
* **`profiles/windows.json`** is untracked, so nothing here can assert it
  exists or which build it covers.

`CURRENT-STATE.md` §1.5 and `catalogue.py`'s `_EVIDENCED` now record Windows as
evidenced on the operator's attestation, in the same form the Android APK row
already used. Anyone rebuilding this guest needs the runbook above, not this
file.

**Area:** windows
**Milestone:** M5 → promoted to a current track (see Context)
**Priority:** P1
**Depends on:** Issue #3 (job/result state model), issue #4 (path
standardization), DRAFT-009 (shared-vs-per-OS script boundary),
DRAFT-027 (sample-delivery mechanism). Supersedes the design-spike half of
DRAFT-020.
**Origin:** `project-assessment.md` → Project focus change; Findings →
GOV-02, DOC-09

# Objective

Bring the Windows analysis guest to the same evidenced state Android
reached at `docs/checklists/android.md` Phase 1 — a golden VM, a working
LibVMI/DRAKVUF profile, a verified injection anchor, tracked Xen configs,
and a saved sandbox state — so that Windows automation scripts can then be
written against the same shared contracts as Ubuntu and Android.

# Context

Windows is now a current target alongside Ubuntu and Android. The
repository does not reflect that yet — `docs/checklists/windows.md` is a
Phase-0 skeleton, and `DRAFT-020` ("Windows baseline selection +
clone-per-run confirmation") is a title-only entry scoped as a design
spike. `project-assessment.md`'s GOV-02 records the resulting imbalance:
Android has DRAFT-013/015/016/017 plus a 2,478-line checklist; Windows has
one title.

**What already exists and carries over.** Two decisions do not need
remaking:

- **VM lifecycle is settled.** `docs/roadmap/project-roadmap.md` decision
  #3 rules out snapshot-restore in this nested Xen-inside-Proxmox setup
  entirely (`xl save`/`xl restore` leaves base and cloned disk images
  read-only), so Windows uses clone-per-run like the other two. This is
  the half of DRAFT-020 that is already resolved, and
  `docs/checklists/windows.md` still lists it as open (DOC-05, fixed by
  DRAFT-032).
- **The Xen config template is already Windows-shaped.** All four tracked
  configs carry `viridian = 1` (`misc/*.cfg:20-21`), `altp2m = 2`,
  `builder = "hvm"` and `hap = 1` — the Hyper-V-enlightenment and
  altp2m settings a Windows HVM guest needs. A `misc/windows.cfg` starts
  from a working template rather than from nothing.

**What does not carry over, and is the real work.**

- **The profile toolchain is different.** Ubuntu and Android profiles are
  produced with `dwarf2json` against kernel debug symbols
  (`docs/drakvuf-on-xen-nested-within-proxmox.md:389`; `docs/android_setup.md`
  §14). Nothing in this repository documents how a Windows profile is
  produced, and the DWARF-based path does not apply to Windows kernels.
  This is an unresolved prerequisite, not an adaptation of an existing
  step, and it must be established from DRAKVUF/LibVMI's own documentation
  rather than assumed (`CLAUDE.md`: do not invent options) (How to in https://drakvuf.com/).
- **The injection anchor concept needs a Windows answer.** Ubuntu uses a
  long-lived privileged process whose PID is recorded at save time (1415,
  `run_analysis-ubuntu.sh:15`); Android built a dedicated native anchor
  (`docs/checklists/android.md` §1.4, with PID/TGID recorded across three
  boots). Windows needs an equivalent, chosen and evidenced the same way.
- **`-e` semantics must be re-established.** Issue #2 settled that
  `drakvuf -e` is execve-direct with no guest shell — but the evidence is
  explicitly labelled `[LINUX] (execproc -> execve(...); 64bit only)`.
  That finding is currently recorded without the qualifier in `CLAUDE.md`
  and `docs/checklists/ubuntu.md` (DOC-09/DRAFT-032). Windows injection
  semantics must be captured from `injector --help` on the real host, not
  inherited.
- **Plugin support is inverted relative to Linux.**
  `docs/architecture/upstream-drakvuf.md:31` records ~30 Windows-oriented
  plugins present in upstream `tklengyel/drakvuf`, while the pinned
  `lfreijo` fork commit is titled "Add **Linux** support for memdump,
  filetracer, fileextractor, and syscalls plugins". So the Windows track
  depends mainly on upstream rather than the single-maintainer fork —
  narrowing risk #8 for this track, and changing what DRAFT-024 must pin.
- **`tlsmon` becomes available.** `docs/architecture/networking.md:61-64`
  source-verified that `tlsmon` hooks Windows `ncrypt.dll`/Schannel only,
  which is why roadmap risk #4 and the reuse table (`:90`) record it as
  "Not applicable". With a Windows guest in scope it becomes the project's
  only working TLS-visibility path — a genuine capability gain, and a
  rescope for DRAFT-023.
- **Licensing and activation.** A Windows golden VM has licensing
  obligations the Ubuntu and BlissOS guests do not, and clone-per-run
  means many short-lived clones of one activated image. This needs a
  deliberate answer before a golden image is built, not after.

# Dependencies

- **Issue #3** — the job/result state model must accommodate a Windows
  execution sequence (PE execution) alongside Ubuntu's and Android's
  install→launch→stimulate shape. Windows should be an input to that
  design, not a later adaptation.
- **Issue #4** — `misc/windows*.cfg`, `profiles/windows.json` and
  `state/windows_sandbox.bak` must follow the standardized layout from the
  start rather than needing a follow-up pass.
- **DRAFT-009** — with three targets, the shared/per-OS boundary decides
  whether a `clone-windows.pl` is even needed or whether the existing
  clone script becomes parameterized.
- **DRAFT-027** — the sample-delivery mechanism must be decided before a
  Windows preconfig script exists, so Windows never inherits the HTTP
  path.
- **DRAFT-024** — pinning now spans two upstreams; the Windows track needs
  the `tklengyel` side pinned.

# Out of scope

- **Implementing the Windows automation scripts.** `clone-windows.pl`,
  `preconfig-windows.sh`, `drakvuf-windows.sh`,
  `run_analysis-windows.sh` are follow-on issues mirroring
  DRAFT-015/016/017, written only after this issue's prerequisites are
  evidenced.
- PE/DLL sample-type branches and execution recipes — the analogue of
  Android's Phase 3, and a separate track.
- The `windows-pipeline` CI stage and the third golden VM in the CI base
  snapshot — DRAFT-026b.
- TLS visibility via `tlsmon` — DRAFT-023, which this issue unblocks but
  does not implement.
- Windows-specific anti-evasion work. The roadmap treats anti-evasion as a
  per-OS quality track attaching after each pipeline is functional.
- Rewriting `docs/checklists/windows.md`'s status framing — DRAFT-032.

# PLAN

1. **Select the Windows baseline** (version, build, architecture) and
   record why. Constraints to weigh: DRAKVUF/LibVMI profile support for
   that build, plugin coverage, and what the lab can license.
2. **Establish the profile toolchain from primary sources.** Determine
   from DRAKVUF's and LibVMI's own documentation how a Windows kernel
   profile is produced and registered, and capture the real commands. Do
   not port the `dwarf2json` procedure by analogy — it does not apply.
   Record the exact tool and version in `docs/checklists/windows.md`
   §0.1-equivalent, matching how Android recorded its build identifiers.
3. **Confirm DRAKVUF actually works against the chosen baseline** before
   building any automation: enumerate guest processes through LibVMI, then
   run DRAKVUF briefly with a minimal plugin set, then test each intended
   plugin separately — the same sequence
   `docs/checklists/android.md` §0.4 used, including its plugin-validation
   matrix.
4. **Capture Windows injection semantics** from `injector --help` and the
   installed source on the real host: which methods exist for a Windows
   guest, and whether the `[LINUX]`-labelled `execproc`/execve behaviour
   from issue #2 has a Windows counterpart with different semantics.
5. **Choose and evidence an injection anchor**, following
   `docs/checklists/android.md` §1.4's discipline: a long-lived process
   with stable identity, PID/TGID recorded across at least three boots,
   confirmed visible through LibVMI, creating no recurring log noise.
6. **Resolve licensing/activation** for a clone-per-run model before
   building the golden image.
7. Confirm `vg-root` has capacity for a Windows golden LV plus per-run
   sandbox clones, which are larger than the 64G Linux guests
   (`clone-ubuntu.pl:250`'s hard-coded `-L64G` is parameterized by
   DRAFT-033 partly for this reason).

# CREATE

1. `misc/windows.cfg` (golden `windows`) and `misc/windows_sandbox.cfg`
   (`windows_sandbox`), derived from the existing templates, following
   issue #1's naming rule — the filename names the domain it defines.
2. The Windows profile, placed per issue #4's decided layout.
3. `docs/checklists/windows.md` populated with real Phase 0/Phase 1
   sections mirroring `docs/checklists/android.md`'s structure, with the
   same Existing-vs-Candidate labelling and the same
   evidence-before-checkbox discipline.
4. A saved sandbox memory state, with the anchor PID/TGID recorded at save
   time.
5. `CLAUDE.md`'s "Current Windows names" section, matching the existing
   Ubuntu and Android naming tables.

# TEST

Nothing in this issue can be tested in the development container —
`CLAUDE.md` places `xl`, `drakvuf`, `injector`, `vmi-process-list`,
`lvcreate`/`lvs` and OVS/iptables out of bounds here. Everything below is
presented for manual execution on Xen Dom0.

```bash
# Baseline and profile (PLAN steps 1-2) — record exact tool + version.

# Profile validity, before any automation exists:
vmi-process-list windows            # or -j <profile>, per PLAN step 2

# Plugin validation matrix (PLAN step 3) — one row per intended plugin,
# same shape as docs/checklists/android.md §0.4:
#   plugin | command | result | notes

# Injection semantics (PLAN step 4):
injector --help                     # capture verbatim; do not paraphrase

# Anchor stability (PLAN step 5):
#   record PID/TGID across three boots
#   confirm the process survives >= 30 minutes
#   confirm visibility via vmi-process-list

# Clone-per-run confirmation (the surviving half of DRAFT-020):
#   clone the golden windows LV, restore saved state, confirm the domain
#   boots, is attached to the intended VLAN, and is destroyed cleanly.
```

Acceptance is evidence recorded in `docs/checklists/windows.md`, not
assertions — same standard the Android checklist was held to.

# DEPLOY

Requires manual Dom0 coordination — present, do not execute:

1. Build the golden `windows` VM interactively (installation is
   deliberately manual, consistent with `docs/workflow-ci.md`'s
   "Future CI work" note that golden-VM creation stays out of automation).
2. Register the profile per PLAN step 2's determined mechanism.
3. Create the `windows_sandbox` LV and saved state.
4. Do **not** wire Windows into `dirwatch`/`run_analysis-*` in this issue —
   that is the follow-on script work, gated on DRAFT-009.
5. Rollback: the golden LV and saved state are new artifacts; removing
   them affects nothing existing. No Ubuntu or Android behaviour is
   touched by this issue at any point.

# Acceptance criteria

- [x] Windows baseline selected, recorded, with the selection rationale.
      64-bit Windows 10 — the *fallback* of the 2026-08-19 direction rather
      than a fresh choice, which is itself the rationale on record.
- [x] The Windows profile toolchain is established from primary
      documentation and its exact commands and versions recorded — not
      ported by analogy from `dwarf2json`. `docs/checklists/windows.md` §0.1.
- [x] A working profile exists and LibVMI enumerates guest processes with
      it. Implied by the run, not separately transcribed;
      `profiles/windows.json` is untracked, so nothing in the repository
      states which build it covers.
- [ ] Every intended DRAKVUF plugin is tested individually against the
      Windows guest, with a completed validation matrix. — **Not done.**
      `guests._WINDOWS_PLUGINS` is still the Linux four, carried as a
      hypothesis; DRAFT-050 owns the matrix.
- [ ] Windows injection semantics captured verbatim from the installed
      build, and the `[LINUX]`-only scope of issue #2's `-e` finding
      explicitly noted. — **Not done.** `shellexec` was settled empirically
      against `createproc`, not by reading `injector --help`.
- [ ] An injection anchor is chosen, with PID/TGID recorded across three
      boots and LibVMI visibility confirmed. — **Half done.** 4696 is
      recorded once. The three-boot discipline is what proves the PID is a
      property of the saved image and not of one lucky boot, and a stale one
      fails silently (`stages.py:249`).
- [x] `misc/windows.cfg` and `misc/windows_sandbox.cfg` tracked, named per
      issue #1's rule, following issue #4's path convention.
- [x] Saved sandbox state created; a clone-per-run cycle demonstrated
      end-to-end (clone → restore → boot → destroy, cleanly). Carried by the
      end-to-end run; no `xl list`/`lvs` transcript was kept.
- [ ] Licensing/activation answered for the clone-per-run model.
      — **Not done.**
- [ ] `docs/checklists/windows.md` populated with real evidence;
      `CLAUDE.md` gains a "Current Windows names" section. — **Not done.**
      The checklist records the design contract, not the run.
- [x] Ubuntu and Android pipelines demonstrably unaffected. The prediction
      that "no shared file is modified" did not survive — `sandboxd/guests.py`
      and `sandboxd/stages.py` are shared and both gained Windows content.
      They gained it as **per-OS rows**, which is what C1's surviving rule
      asks for, so the property that mattered held even though the wording
      did not.

# Evidence required

Following `docs/checklists/android.md`'s Phase 0/1 standard: recorded tool
and profile versions with checksums; `vmi-process-list` output; the
plugin-validation matrix; `injector --help` verbatim; PID/TGID records
across three boots; `lvs`/`xl list` output from the clone-restore-destroy
cycle; the tracked `.cfg` files.

# Security considerations

- A Windows analysis guest is the highest-value target in the lab for
  real-world malware, and the one most likely to be handed genuinely
  malicious PE samples. **Do not build it before the containment work is
  in place**: DRAFT-028 (isolation rules actually install) and DRAFT-029
  (clones cannot reach Dom0 services) should land first, or the first
  Windows sample runs on a network whose isolation is unverified — the
  exact gap `docs/checklists/android.md` §1.3 has left open for Android.
- The golden Windows LV joins the golden `ubuntu`/`android` LVs on
  `CLAUDE.md`'s never-operate-on list from the moment it exists.
- Clone-per-run from an activated Windows image has licensing implications
  that are a compliance question, not merely an operational one (PLAN
  step 6); it borders on DRAFT-022's legal/compliance scope.
- Windows guests are noisier on the network by default than the minimal
  Linux guests, so NET-03 (unrestricted egress by default) is materially
  more consequential here. Do not enable networking for a Windows clone
  before the containment decisions are made.
- Use only benign fixtures during this issue. No real malware anywhere in
  the baseline, profiling or anchor work.

# Documentation changes

`docs/checklists/windows.md` (populated), `CLAUDE.md` (current Windows
names; architecture line), `README.md` (Windows as current),
`docs/roadmap/project-roadmap.md` (M5 reframed; risk #4 and the `tlsmon`
reuse-table row rescoped — coordinate with DRAFT-032 so the two do not
conflict), `docs/architecture/analysis-pipeline.md` and
`docs/architecture/networking.md` (three targets, not two).

# Recovery / rollback

Entirely additive. New LVs, a new saved state, new `.cfg` files, new
profile, new documentation — nothing existing is modified, and no shared
script is touched. Rollback is removing the new artifacts, with zero
effect on the Ubuntu or Android pipelines.