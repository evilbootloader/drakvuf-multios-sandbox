# DRAFT-008: Define OS-independent analysis job/result state model

**Status:** Published — [issue #3](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/3)
**Area:** core
**Milestone:** M0
**Priority:** P0
**Depends on:** DRAFT-001

# Objective

Design (not yet implement) a single job/result state model that works
across the Ubuntu, Android and Windows pipelines, replacing the per-OS ad
hoc status vocabularies currently scattered across the checklists and
scripts.

> **Assessment update (2026-08-08, `project-assessment.md`):** Windows is
> now a **current** target, not "planned" — so it is a first-class input to
> this design rather than something the model is adapted for later. The
> published issue #3 body still says "the planned Windows pipeline"; that
> wording should be updated when the issue is next touched.

# Context

Right now there is no shared model: `automation/drakvuf-ubuntu.sh` uses an
MD5-keyed result directory and an implicit two-state outcome (DRAKVUF
return code 1 means "move the sample," anything else is undifferentiated);
`docs/checklists/android.md` §7.3 proposes a much richer SHA-256-keyed
`status.json` with an explicit state list
(`received → classified → queued → cloning → restoring → preparing →
monitoring → executing → stimulating → collecting → cleaning →
completed/failed`) and a status-value vocabulary (`success`,
`install_failed`, `unsupported_type`, etc.) — but none of it is
implemented, only proposed. Windows has no model at all yet. Every
downstream piece of work that needs to know "what state is this analysis
in" (Ubuntu modernization, Android Phase 2+, Windows planning, the eventual
artifact schema, and any future web platform) depends on this being decided
once, not reinvented three times.

# Dependencies

DRAFT-001 (for commit ordering / diff review). Conceptually independent of
any Xen work — this is pure design.

Blocks DRAFT-009, DRAFT-011, DRAFT-018 and DRAFT-034 (the Windows track
head). Nothing blocks this issue, which is why `project-assessment.md`
places it **first** in the recommended order.

# Out of scope

- Implementing the model in any script — this issue is design only.
- The full artifact/result *schema* (file layout, what's stored where) —
  that's DRAFT-018, which builds on this issue's state model but adds the
  storage-layer contract.
- Deciding shared-vs-OS-specific script boundaries — that's DRAFT-009,
  which consumes this issue's output but is a separate decision.

# PLAN

1. Reconcile the two existing partial models: `drakvuf-ubuntu.sh`'s
   implicit MD5-keyed, two-outcome model, and the Android checklist's
   proposed SHA-256-keyed, richer state model. Decide which wins where
   they conflict (recommendation: SHA-256 keying and the richer state list,
   since Ubuntu's simpler model was never a deliberate design choice, just
   what existed first).
2. Define the field list precisely (candidate fields already sketched in
   `docs/architecture/analysis-pipeline.md`: `analysis_id`,
   `sample_sha256`, `original_filename`, `detected_type`, `target_os`,
   `target_os_source` (target_os_source likely not needed we only need to know
    target OS of analysis vm), `execution_recipe`, `requested_timeout`, 
    `network_mode`, `sandbox_version`, `profile_version`, `domain`, `clone_id`, 
    `vlan`, `started_at`, `finished_at`, `status`, `failure_stage`).

   > **Assessment note on dropping `target_os_source`
   > (`project-assessment.md` → Issue #3):** the reasoning holds under the
   > current architecture — `dirwatch` hard-codes a single origin domain
   > per invocation (`automation/dirwatch.c:475`), so the target OS is a
   > property of the launcher, not something discovered per sample. Do not
   > reinstate the field as part of this issue. **Revisit only if**
   > DRAFT-014's auto-detection contract has to disambiguate cases where
   > the detected type alone is insufficient — Android ELF vs. Linux ELF
   > (roadmap "Architecture decisions needing experiments" #2), or PE32
   > vs. PE32+ once the Windows track lands — and then only with evidence
   > that a provenance field is what resolves it.

3. Define the state machine precisely, reconciling it with the Android
   checklist's `status.json` state list so the two documents don't diverge.
4. Define how per-OS status vocabularies (Android's `success`/
   `install_failed`/etc.) map onto the shared model — generalize, don't
   discard.
5. Consider recovery-after-interruption from the start, per the original
   workstream brainstorm — a job's state must be reconstructable from disk
   after a host reboot, not just held in a running process's memory.
6. **Validate the state machine against all three OS execution sequences,
   not two** (assessment: Issue #3, "Problems with current scope"). They
   are genuinely different shapes: Ubuntu stages one file and executes it;
   Android's `docs/checklists/android.md` Phase 3 is
   install → launch → stimulate exported components, with branches per
   package format; Windows executes a PE with no install step. A model
   validated only against Ubuntu and Android will need reworking for the
   third.
7. **Settle the MD5-vs-SHA-256 keying question here, once.**
   `docs/architecture/result-schema.md` §3 currently poses the same
   question independently, so the two documents will answer it separately
   unless one defers. This issue owns the decision; `result-schema.md`
   should reference it rather than re-decide (assessment: Issue #3).

# CREATE

Not started. Output of this issue is a design document
(`docs/architecture/analysis-pipeline.md`'s "Proposed" section already has
a placeholder — this issue replaces "proposed, not decided" with an actual
decision), not code.

# TEST

Design-review only — no code to test yet. Acceptance is a written model
that DRAFT-009, DRAFT-011, DRAFT-018, and Android/Windows planning can all
build on without contradiction.

# DEPLOY

Not applicable.

# Acceptance criteria

- [ ] Field list finalized and written into
  `docs/architecture/analysis-pipeline.md`.
- [ ] State machine finalized, reconciled with
  `docs/checklists/android.md` §7.3's proposal (update one or both so they
  agree).
- [ ] Recovery-after-interruption addressed explicitly, not deferred
  silently.
- [ ] Ubuntu's simpler existing model reconciled (documented as
  intentionally superseded, not silently ignored).
- [ ] The state machine is walked through against **all three** OS
  execution sequences — Ubuntu (stage + execute), Android (install →
  launch → stimulate), Windows (PE execution) — and any state that only
  fits one of them is identified as such. *(Added from
  `project-assessment.md`; Windows is a current target.)*
- [ ] Result keying (MD5 vs. SHA-256) is decided here, and
  `docs/architecture/result-schema.md` §3 is updated to reference this
  decision instead of restating the open question. *(Added from
  `project-assessment.md`.)*
- [ ] `target_os_source` is absent from the finalized field list, with a
  one-line note recording the condition under which DRAFT-014 would
  revisit it. *(Reflects the draft's PLAN step 2 annotation.)*

# Evidence required

The finalized design document itself; no execution evidence applies since
nothing is implemented yet.

# Security considerations

None directly — this is a data-model design. Downstream implementations
should ensure `original_filename` and similar untrusted fields are never
used unsanitized in paths/commands (already flagged in
`docs/checklists/android.md` §2.6/§2.7).

# Documentation changes

Updates `docs/architecture/analysis-pipeline.md` and
`docs/architecture/result-schema.md`; may require a small update to
`docs/checklists/android.md` §7.3 if the reconciled model differs from what
was originally proposed there (do this as an explicit, reviewed edit, not
a silent rewrite, per the "preserve evidence" rule).

# Recovery / rollback

Not applicable — design document only.