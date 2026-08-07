# Web Sandbox Platform — Implementation Checklist and Command Log

> **Status: skeleton only.** No web-platform work has started as of
> 2026-08-07. This tracks both the job-submission API/queue/UI (roadmap
> Milestone M7) and public-facing security hardening (M8) — kept as one
> file rather than two, since splitting them prematurely risked drifting
> into near-duplicate documents before either has real content.
>
> Per `docs/roadmap/project-roadmap.md`: this milestone only begins after
> M0–M6 are done **and** the licensing question in
> `docs/architecture/licensing.md` is resolved — DRAKVUF's license text
> treats subprocess-orchestration-and-parse as a derivative work, which
> directly affects what business model this platform can use. Do not start
> implementation here before that's settled.

---

## Project status

| Field | Value |
|---|---|
| Current phase | Not started — blocked on M0–M6 and the licensing decision |
| Job queue technology | Not yet decided (see roadmap: RQ+Redis, matching DRAKVUF Sandbox, vs. something simpler — low urgency, revisit near M7) |
| Web framework | Not yet decided |
| Licensing gate | Open — see `docs/architecture/licensing.md` |

### Status legend

- [ ] Not started
- [x] Completed and evidenced
- `BLOCKED:` Waiting on a dependency or unresolved fault
- `SKIPPED:` Deliberately excluded, with reason recorded

---

# M7 — Web platform MVP (not started)

- [ ] Resolve the licensing gate before any implementation.
- [ ] Choose job queue technology.
- [ ] Define job submission API surface (multi-OS target selection, per-OS
  parameters).
- [ ] Minimal UI: upload, status, results.
- [ ] Reuse `[preset.x]`-style per-OS configuration presets (see roadmap
  reuse-vs-build table).

# M8 — Public hardening + legal gate (not started)

- [ ] AuthN/AuthZ.
- [ ] Rate limiting, abuse controls.
- [ ] Tenant isolation.
- [ ] Formal legal review (not just the desk-research licensing flag) before
  any external or paying users.
- [ ] The public web application must never directly expose privileged Xen
  operations to clients (existing project rule, carried over from the
  brainstormed workstream list).

No further detail is defined yet — populate this file only once M7/M8 work
actually begins.