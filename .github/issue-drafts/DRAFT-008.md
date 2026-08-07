# DRAFT-008: Define OS-independent analysis job/result state model

**Status:** Open
**Area:** core
**Milestone:** M0
**Priority:** P0
**Depends on:** DRAFT-001

# Objective

Design (not yet implement) a single job/result state model that works
across Ubuntu, Android, and the planned Windows pipeline, replacing the
per-OS ad hoc status vocabularies currently scattered across the checklists
and scripts.

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
   `target_os_source`, `execution_recipe`, `requested_timeout`,
   `network_mode`, `sandbox_version`, `profile_version`, `domain`,
   `clone_id`, `vlan`, `started_at`, `finished_at`, `status`,
   `failure_stage`).
3. Define the state machine precisely, reconciling it with the Android
   checklist's `status.json` state list so the two documents don't diverge.
4. Define how per-OS status vocabularies (Android's `success`/
   `install_failed`/etc.) map onto the shared model — generalize, don't
   discard.
5. Consider recovery-after-interruption from the start, per the original
   workstream brainstorm — a job's state must be reconstructable from disk
   after a host reboot, not just held in a running process's memory.

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