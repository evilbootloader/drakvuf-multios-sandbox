# Windows DRAKVUF Automated Analysis — Implementation Checklist and Command Log

> **Status: skeleton only.** No Windows automation work has started as of
> 2026-08-07. This file intentionally contains no invented commands,
> configs, or evidence — populate it only from real work, following the
> same discipline as `android.md` (Existing vs. Candidate, evidence before
> checking a box). See `docs/roadmap/project-roadmap.md` Milestone M5
> ("Windows planning spike") for what precedes any implementation here:
> baseline selection, profile/symbol requirements, and the clone-vs-snapshot
> VM-lifecycle architecture decision (DRAFT-020).

---

## Project status

| Field | Value |
|---|---|
| Golden domain | TBD |
| Sandbox domain | TBD |
| LibVMI profile | TBD |
| Volume group | TBD |
| Analysis bridge | TBD |
| Saved state | TBD |
| Windows baseline (version/build) | Not yet selected |
| VM lifecycle model | clone-per-run (current Ubuntu/Android model) — decided by elimination: snapshot-restore (DRAKVUF Sandbox's model) does not work in this nested Xen-inside-Proxmox setup, since `xl save`/`xl restore` leaves the base and cloned disk images read-only; see roadmap "Architecture decisions needing experiments" |
| Current phase | Not started |
| Current blocker | M5 planning spike not yet begun |

### Status legend

- [ ] Not started
- [x] Completed and evidenced
- `BLOCKED:` Waiting on a dependency or unresolved fault
- `SKIPPED:` Deliberately excluded, with reason recorded

---

# Phase 0 — Planning spike (M5)

- [ ] Select a specific supported Windows baseline (version/build).
- [ ] Decide golden-VM lifecycle model (clone-per-run vs. snapshot-restore).
- [ ] Determine profile/symbol requirements for the selected baseline.
- [ ] Determine injector target and plugin compatibility for Windows guests.
- [ ] Scope the first Windows sample type (PE executable, per the roadmap's
  "do not support every sample type in the first milestone" guidance).

No further phases are defined yet — later phases should mirror `android.md`'s
structure (sandbox VM build, automation scripts, sample-type branches,
artifact collection, network containment, testing, reliability) once Phase 0
decisions are made, not before.