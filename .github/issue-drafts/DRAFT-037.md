# DRAFT-037: Rebuild the Android sandbox template from the reinstalled golden VM

**Status:** **Published 2026-08-11 — [#7](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/7)**, label `bug`. Open.
**Area:** android / platform
**Milestone:** M2 → M3 (gates the Android MVP)
**Priority:** P0
**Depends on:** None open. The golden VM fix has already landed.
**Blocks:** DRAFT-015, DRAFT-016, DRAFT-017 — every Android script is
written against a sandbox template that does not currently exist in a
usable form.
**Origin:** AND-001 in `docs/checklists/android.md`; roadmap risk #12.

# Objective

Rebuild `android_sandbox` — LV, injection anchor and saved memory state —
from the golden `android` VM reinstalled on 2026-08-11, and remove the stale
artifacts left by the previous one.

Phase 1 of `docs/checklists/android.md` is recorded as complete. It is not:
everything it evidences was derived from a golden image that no longer
exists.

# Context

The golden `android` VM rendered through Mesa llvmpipe with no GPU
passthrough. Its `surfaceflinger` SIGSEGVed reproducibly inside
JIT-generated shader code on the first window opened in desktop mode, taking
`system_server` into a permanent 60-second watchdog loop. BlissOS upstream
confirmed on 2026-08-11 that *"llvmpipe currently is still unstable on
Android"* and gave `HWACCEL=0` as the fix. **The golden VM was reinstalled
with it the same day and is now sound** — that work is done and is not part
of this issue.

What is not done is everything downstream of it. `android_sandbox` is a
clone of the golden VM, so §1.1–§1.5 of the checklist all describe the old
image:

| Artifact | Recorded in | Why it is stale |
|---|---|---|
| `android_sandbox` LV | §1.1 | Snapshot of the pre-reinstall golden |
| `state/android_sandbox.bak`, sha256 `457fe0d7…` | §1.5 | `xl save` of a guest whose renderer was broken |
| Anchor PID/TGID `5715` | §1.4, §1.5 | A property of that `.bak` file, not of the domain |

The anchor PID is the sharpest edge. `automation/pipeline-ubuntu.env` states
the rule for the Ubuntu equivalent — *"It is a property of the `.bak` file,
not of this config — re-saving the template almost certainly changes it"* —
and Android has no `pipeline-android.env` yet to carry the value at all. A
stale `INJECTION_PID` does not fail loudly: `injector` attaches to whichever
process now holds that PID, or to none.

**Nothing detected any of this.** No check anywhere compares a saved state
against the golden image it came from, and `.bak` files carry no provenance.
That is registered as roadmap risk #12 and applies equally to Ubuntu and
Windows; the general fix is deliberately **not** in this issue's scope.

# Dependencies

None open.

Note the direction of one relationship that looks like a dependency and is
not: **§1.3 network isolation (DRAFT-013) does not gate this issue.** §1.5's
own checklist carries `[ ] Confirm network isolation is active` as a
precondition of saving, and it has never been ticked. Saving a template
whose containment is unverified is exactly as true today as it was on
2026-08-06 — this issue does not make it worse and does not fix it. The
constraint that matters is unchanged and belongs to DRAFT-013: **close §1.3
before any non-benign sample runs with networking enabled.**

# Out of scope

- **The golden VM.** Reinstalled and working; do not touch it. This issue
  reads from it and never writes to it.
- **The generic provenance fix for risk #12** — recording golden-image
  identity alongside saved state and checking it at restore. It applies to
  all three OS targets and needs its own design; unowned.
- **DRAFT-013's isolation verification.** See Dependencies.
- **Any Android automation script.** `clone-android.pl`,
  `preconfig-android.sh`, `drakvuf-android.sh` and
  `run_analysis-android.sh` remain DRAFT-015/016 and are written *against*
  the template this issue produces.
- **`pipeline-android.env`.** It does not exist and this issue does not
  create it — the per-OS config contract is issue #6's and the file is
  DRAFT-015's to add. This issue records the new anchor PID in the
  checklist so DRAFT-015 has a value to put in it.
- **AND-002 (the thermal HAL).** Log noise and CPU cost, no functional
  failure, and fixing it means another image rebuild. Deliberately deferred
  so this issue does not grow a BlissOS build dependency.
- **`misc/android.cfg`'s broken cdrom path.** Recorded as broken in the file
  itself since 2026-08-09. It only blocks reinstalling the golden VM from
  ISO, which has already happened by other means.

# PLAN

1. **Inventory before destroying anything.** On Dom0, establish what
   actually exists — the previous artifacts may or may not have been
   removed already, and the answer decides steps 2 and 8.

   ```bash
   sudo xl list
   sudo lvs -a -o lv_name,origin,lv_size,data_percent vg-root
   ls -lh state/
   sha256sum state/android_sandbox.bak 2>/dev/null
   ```

   Record the output verbatim in §1.5 before proceeding. If a `.bak` is
   present, confirm whether it hashes to `457fe0d7…` — if it does, it is the
   stale one; if it does not, **stop and reconcile**, because an unrecorded
   third state exists.

2. **Confirm the golden VM's fix took, and that it is not running.** The
   `HWACCEL=0` option is silent when it fails to apply, which is the whole
   reason this issue exists.

   ```bash
   sudo xl list                     # `android` must not be running
   grep -i hwaccel /boot/grub/android.cfg   # inside the guest, or via kpartx mount
   ```

   **`adb` is not enabled on this build**, so the usual confirmation —
   `adb shell dumpsys SurfaceFlinger | grep -i 'GLES:'` — is unavailable.
   The evidence is behavioural instead: open an application in desktop mode
   over VNC and confirm the renderer survives (TEST, row 1). That is a
   weaker signal than reading the renderer name, so record the GRUB config
   grep alongside it rather than relying on either alone.

3. **The LibVMI profile has already been confirmed still valid** — the
   reinstall did not change the kernel, so `profiles/android.json` does not
   need regenerating. Recorded here because the failure mode is misleading:
   `dwarf2json` output is valid for one exact kernel build, and a mismatched
   profile makes every introspection step downstream fail in a way that
   looks like a DRAKVUF problem. Kernel identity is pinned in
   `misc/Artifacts/kernel-identifiers.txt`.

4. Re-run checklist §1.1 → §1.5 in order, against the reinstalled golden.
   Do not copy forward any recorded value from the previous pass.

5. Decide where the new anchor PID is written down. Today §1.5 is the only
   place; note it there and flag it for DRAFT-015's `pipeline-android.env`.

# CREATE

No code. This issue produces infrastructure state and checklist evidence.

Order matters — creation before destruction, so a failed rebuild leaves the
previous state in place (see Recovery / rollback):

1. **Create the new `android_sandbox` LV** from the reinstalled golden
   (§1.1). Alongside the old one rather than reusing the name, if space
   allows.
2. Confirm `misc/android_sandbox.cfg` still matches (§1.2). It is tracked
   and should need no change — confirm rather than assume.
3. Create the injection anchor (§1.4) and record its PID/TGID.
4. Clean, save, and manually validate the restore onto a **disposable** LV
   (§1.5).
5. **Only now remove the stale artifacts** identified in PLAN step 1, and
   record their removal.
6. Update `docs/checklists/android.md`:
   - fill §1.1–§1.5 evidence blocks with the new run;
   - record the new saved-state SHA-256 and anchor PID/TGID;
   - annotate, do not edit, the 2026-08-06 blocks already there — the
     2026-08-11 annotations establish the pattern;
   - move `Current phase` on from Phase 1 once §1.5 validates.
7. Update roadmap risk #12 to record that the Android instance is closed
   while the generic gap stays open.

# TEST

**Requires Xen Dom0 / L1** in full. Nothing here runs in the development
container, per `CLAUDE.md`'s infrastructure boundary.

| Check | Command | Pass condition |
|---|---|---|
| Renderer survives use | Open an application in desktop mode, wait 60 s | No `surfaceflinger` tombstone; no `system_server_watchdog` entries in `/data/system/dropbox/` |
| Saved state restores | `xl restore -p -e <test cfg> state/android_sandbox.bak` onto a **disposable** clone LV | Domain builds and unpauses |
| Anchor present after restore | `vmi-process-list -n android_test -j profiles/android.json` | The recorded anchor PID/TGID is present and is the anchor |
| Golden untouched | `sha256sum` / `lvs` on the golden LV before and after | Identical |

The restore validation **must** target a disposable LV, never the golden or
the template — §1.5's existing note says the same and it is the one step
here that can destroy hours of work.

# DEPLOY

Deployment is the work: it changes LVM state and a saved VM image on Dom0.
Per `CONTRIBUTING.md`'s DEPLOY stage, present every command for manual
execution and do not run them automatically. No analysis may be in flight.

# Acceptance criteria

- [ ] PLAN step 1's inventory is recorded verbatim in §1.5 before anything
      is created or destroyed.
- [ ] The golden VM is confirmed unmodified by this work (hash or `lvs`
      before/after).
- [ ] `HWACCEL=0` is evidenced two ways, since `adb` is unavailable on this
      build: present in `/boot/grub/android.cfg`, **and** the renderer
      survives an application opened in desktop mode over VNC.
- [ ] The kernel is confirmed unchanged by the reinstall, so
      `profiles/android.json` remains valid — recorded, not re-derived.
- [ ] A new `state/android_sandbox.bak` exists, its SHA-256 is recorded, and
      it is **not** `457fe0d7320085fab1b722ce087d2056d5470562196dcccd0a1183399a32389c`.
- [ ] The new anchor PID/TGID is recorded, and it is flagged for
      `pipeline-android.env` (DRAFT-015).
- [ ] Manual restore validation passes on a disposable LV.
- [ ] Stale artifacts from the previous golden are removed, and their
      removal is recorded.
- [ ] §1.5's 2026-08-11 annotation is updated to point at the new evidence
      rather than deleted.
- [ ] The 2026-08-06 evidence blocks are annotated, never edited.
- [ ] `docs/checklists/android.md`'s `Current phase` and `Current blocker`
      reflect the outcome.

# Evidence required

The verbatim output of every command in TEST, in the §1.1–§1.5 evidence
blocks. Specifically: `lvs` before and after, both saved-state checksums
(old and new, so the replacement is provable), the anchor PID/TGID, the
`/boot/grub/android.cfg` grep, and the restore validation transcript.

The renderer check has no command output — `adb` is not enabled on this
build — so record it as an observation: what was opened, over VNC, and that
no tombstone or `system_server_watchdog` entry followed within 60 s.

The AND-001 diagnostic capture is not kept in this repository; the Issue
log's reproduced excerpts are the record. Nothing in this issue depends on
it.

# Security considerations

- **§1.3 network isolation is still unverified**, and this issue saves a
  template without closing it. That is unchanged from the state the previous
  template was saved in, and is stated here so it is a known carry-forward
  rather than an oversight. DRAFT-013 owns it. **No non-benign sample may
  run against clones of this template with networking enabled until it is
  closed.**
- The golden Android LV and the current saved state are both on
  `CLAUDE.md`'s never-operate-on list. This issue is the explicit
  instruction that lifts that for `state/android_sandbox.bak` and the
  `android_sandbox` LV **only** — the golden LV stays read-only throughout.
- A stale `INJECTION_PID` is a correctness *and* safety issue: `injector`
  attaching to an unintended process executes a sample somewhere nobody is
  monitoring.

# Documentation changes

`docs/checklists/android.md` (§1.1–§1.5 evidence, status table, Change log),
`docs/roadmap/project-roadmap.md` (risk #12), and `profiles/README.md` if
the profile is regenerated.

# Recovery / rollback

**Ordering is the rollback.** Build and validate the new template *before*
destroying the old artifacts, so a failed rebuild leaves the previous state
in place. Concretely:

1. Keep the existing `state/android_sandbox.bak` under a dated name until
   the new one passes restore validation.
2. Create the new LV alongside the old rather than reusing the name, if
   space allows.
3. Only then remove the stale LV and `.bak`.

If the rebuild fails outright, nothing is lost that was usable — the old
artifacts were already invalid — but the *record* of them is worth keeping,
which is why the inventory in PLAN step 1 is written down first.

The golden VM is the true recovery path: `android_sandbox` is rebuildable
from it at any time, which is precisely why `misc/android_sandbox.cfg` sets
`on_crash = "destroy"` while `misc/android.cfg` sets `preserve`.