# DRAKVUF Multi-OS Sandbox — Project Roadmap

> Last updated: 2026-08-07. This roadmap is a living document — update it as
> milestones close, decisions get made, and new gaps are found. It does not
> replace the per-OS checklists under `docs/checklists/`; those track
> execution evidence, this tracks direction and sequencing.

## Context

The project automates a DRAKVUF malware-analysis sandbox on
`Proxmox/KVM → Xen Dom0 + DRAKVUF/LibVMI → {Ubuntu, Android/BlissOS, Windows(planned)}`.
Ubuntu automation (`automation/*-ubuntu.sh`, `clone-ubuntu.pl`, orchestrated by
a modified `dirwatch.c`) mostly works. Android automation has real evidenced
progress through `docs/checklists/android.md` Phase 1 (golden→sandbox clone,
injection anchor, saved memory state), but Phase 2 onward — the actual
Android scripts, sample-type handling, artifact collection, containment,
testing, reliability hardening — is 100% unstarted "Candidate" content.
Windows support is planned but has no work started at all.

This roadmap exists because writing more automation directly on top of the
brainstormed workstream list would have meant redoing work once the shared
job model, script boundaries, and containment gaps were sorted out. It
restructures that list into a dependency-ordered set of milestones and
issues, using a formal `PLAN → CREATE → TEST → DEPLOY` lifecycle (see
`CONTRIBUTING.md`) with human review gates at every stage.

## Environment & tooling constraints (as of 2026-08-07)

- `Bash` was non-functional in the Claude Code dev container used to draft
  this roadmap (`bwrap: No permissions to create a new namespace`).
  `bash -n`/`shellcheck`/`perl -c` could not be run there — they must run on
  the real host or in CI. Re-verify this hasn't recurred before assuming
  static checks can run in-container.
- No git repository existed at the time this roadmap was drafted. All
  "evidence" lived only as uncommitted files on disk — see DRAFT-001 in
  `.github/issue-drafts/`.
- `gh` availability/auth could not be checked (needs Bash). Verify manually
  before any GitHub-publication step.

## Current state (verified 2026-08-07, not assumed)

**Ubuntu** — `automation/` (flat, no subfolders) contains
`dirwatch.c, clone-ubuntu.pl, preconfig-ubuntu.sh, drakvuf-ubuntu.sh,
cleanup.sh, tcpdump.sh, network-setup.sh, run_analysis-ubuntu.sh`.
Architecture: `dirwatch.c` (GThreadPool + inotify, 15-arg CLI contract,
60s/180s per-phase timeouts) calls
`clone-ubuntu.pl → preconfig-ubuntu.sh → drakvuf-ubuntu.sh → cleanup.sh`
plus `tcpdump.sh` on a side thread. **"Ubuntu works" is now
execution-evidenced** (2026-08-08, issue #2): a recorded Dom0 run shows
`ExecProc Status:Success` on `/home/carlos/Desktop/test` followed by ~359k
trace records and a clean `exit_group`. The suspected `<USER>` bug was a
**repository** defect, not a production one — the deployed Dom0 copy was
correctly substituted all along. What that verification exposed was repo↔host
drift, **resolved 2026-08-08** by syncing `automation/` wholesale from the
tested production host and completing issue #1's host-side rename. Repo and
host now agree on every file. See risks #7 and #11 and
`docs/runbooks/verify-user-placeholder.md`.

**Android** — `docs/checklists/android.md` Phase 0 (baseline verification)
and Phase 1 (sandbox VM build) are mostly complete with real evidence
(checksums, config paths, PID records). Two concrete open items inside
otherwise-done territory:
- **§1.3 "Verify sandbox network isolation TODO" is incomplete** — the
  6-row isolation test table is entirely unfilled. Android sandbox network
  containment is **unverified, not just undone**.
- All four Xen guest configs referenced by checklist evidence are tracked
  under `misc/` (confirmed 2026-08-07): `misc/android_sandbox.cfg`
  (`android_sandbox`), `misc/android.cfg` (golden `android`),
  `misc/linux_sandbox.cfg` (`ubuntu_sandbox` — the filename is misleading,
  it does not define a generic "linux" domain), and `misc/linux.cfg`
  (golden `ubuntu` — same naming caveat). No config file is actually
  missing; the earlier assumption that these were untracked was wrong.

Phase 2 through the MVP gate is **100% unstarted** — every item is `[ ]`,
explicitly labelled "Candidate." The Issue log (`AND-001..003`) and Change
log are placeholder rows.

**Windows** — no work started.

## Ecosystem research — what to reuse vs. build

See `docs/architecture/upstream-drakvuf.md` and `docs/architecture/licensing.md`
for full sourced detail. Condensed:

| Component (from CERT-Polska `drakvuf-sandbox`) | Verdict | Why |
|---|---|---|
| Task/job queue (Flask + RQ + Redis) | Reuse/Adapt | Simple, well-understood; adaptable to drive Xen/LVM/OVS clones instead of snapshot restores. |
| Analysis state machine | Reference-only | Good conceptual model; this project's clone-per-run, multi-OS shape needs its own state machine. |
| Network setup (bridge-per-worker + NAT/dnsmasq) | Reference-only | Conceptually close to existing OVS-per-VLAN approach; not a drop-in. |
| TLSMON (TLS key extraction) | **Not applicable** | Confirmed by direct source read: hooks Windows `ncrypt.dll`/Schannel only. No Linux/Android path exists upstream. |
| capa post-processing | Reuse/Adapt | Apache-2.0, no licensing friction. capa v7.2.0 added a native DRAKVUF-log feature extractor. |
| Result/artifact schema | Reference-only / gap | No published JSON Schema found; define this project's own contract. |
| Web/API architecture | Reference-only | Small Flask MVP is a fine reference; frontend stack unconfirmed. |
| VM lifecycle (snapshot-restore) | **Not applicable, and ruled out for Windows too** | This project clones per-run via LVM/OVS. Confirmed 2026-08-07: snapshot-restore is not viable in this nested Xen-inside-Proxmox setup at all — `xl save`/`xl restore` leaves the base and cloned disk images read-only — so the Windows track will also use clone-per-run, not just Ubuntu/Android. |
| Config presets (`[preset.x]` TOML) | Reuse/Adapt | Low-risk pattern, directly portable to per-OS presets. |

## Proposed repository layout

```
docs/
├── roadmap/
│   └── project-roadmap.md          # this file
├── architecture/
│   ├── analysis-pipeline.md
│   ├── networking.md
│   ├── result-schema.md
│   ├── upstream-drakvuf.md
│   └── licensing.md
└── checklists/
    ├── ubuntu.md
    ├── android.md
    ├── windows.md
    └── platform.md
automation/                          # existing — Ubuntu automation scripts, unchanged
misc/                                # existing — tracked Xen guest .cfg files, unchanged
CONTRIBUTING.md
README.md
.gitignore
.github/issue-drafts/
```

## Dependency graph (condensed)

```
governance (git init, README, LICENSE clarity)
   │
   ├──> docs reorg (needs git to track the move as a diff)
   │        │
   │        └──> CONTRIBUTING.md (lifecycle + issue template)
   │
   ├──> job/result state model  ───────────┬──> shared-vs-OS-specific script boundary
   │        │                              │         │
   │        │                              │         ├──> Ubuntu modernization (regression baseline)
   │        │                              │         ├──> Android Phase 2+ (resume checklist)
   │        │                              │         └──> Windows planning spike (baseline + VM-lifecycle decision)
   │        │                              │
   │        └──> artifact/result schema ───┴──> post-processing (capa) [cheap once schema/logs exist]
   │
   ├──> network isolation closure (Android §1.3) ──> broader network/containment design ──> TLS-visibility research spike (tlsmon N/A finding)
   │
   ├──> licensing spike (fast, desk research, already started) ───────────────────────────┐
   ├──> legal/compliance review (Spain) ──────────────────────────────────────────────────┤
   │                                                                                        ▼
   ├──> observability/CI/resource-limits hardening (after ≥2 OS pipelines exist) ──> web platform MVP ──> public security hardening + legal gate
   │
   └──> upstream DRAKVUF engine work (deliberately last; depends on ≥1 stable OS pipeline + repo-strategy decision)
```

Anti-evasion work attaches after each per-OS pipeline is functional — it's a
per-OS quality track, not a gate for anything else.

## Milestones

| # | Milestone | Contents | Gate |
|---|---|---|---|
| M0 | Foundations | git init, README, docs reorg, CONTRIBUTING.md, job/result state model, licensing spike write-up | No Xen changes; pure planning/docs/scaffolding |
| M1 | Ubuntu regression baseline | ~~Verify the `<USER>` bug~~ and ~~reconcile the repo↔Dom0 drift it exposed~~ (both done 2026-08-08, issue #2); document current behavior precisely, retrofit structured status output without changing behavior, add `bash -n`/`shellcheck`/`perl -c` CI plus a drift check | Proves the job model works on the one pipeline that already runs |
| M2 | Containment closure | Finish Android §1.3 network isolation verification; decide shared-vs-per-OS script boundaries | Requires Xen Dom0 for the isolation tests |
| M3 | Android MVP | Resume checklist Phase 2 → MVP gate using the now-defined job model | Bulk of the existing "Candidate" checklist content gets executed here |
| M4 | Artifact schema + enrichment | Result schema, capa integration | After M1/M3 produce real logs to validate against |
| M5 | Windows planning spike | Baseline selection, profile/symbol requirements (VM-lifecycle model already settled: clone-per-run) | Design only |
| M6 | Ops hardening | Observability, CI expansion, resource limits/abuse resistance | After ≥2 OS pipelines exist |
| M7 | Web platform MVP | Job submission API, queue, minimal UI | Only after M0–M6 and the licensing decision are resolved |
| M8 | Public hardening + legal gate | AuthN/Z, rate limiting, tenant isolation, formal legal review | Before any external/paying users |
| M9 | Upstream DRAKVUF contribution | Only after a stable OS pipeline + resolved repo strategy | Deliberately last |

## Issue index

See `.github/issue-drafts/issue-index.md` for the full draft-title index with
areas, priorities, and dependencies, and `.github/issue-drafts/DRAFT-*.md`
for the fully specified first batch (DRAFT-001 through DRAFT-008).

## Risk register

| # | Risk | Impact | Notes |
|---|---|---|---|
| 1 | ~~No git repository existed as of 2026-08-07~~ — resolved 2026-08-07: baseline commit `bb8ad14` created | None — closed | DRAFT-001 complete; `git log`/`git status`/`git show --stat` evidence recorded in DRAFT-001.md |
| 2 | Dev-container `Bash` was non-functional (bwrap error) | `bash -n`/`shellcheck`/`perl -c` couldn't run there | Must run on real host/CI; documented in CONTRIBUTING.md's TEST section |
| 3 | DRAKVUF's GPL-with-exceptions text treats subprocess-orchestration as derivative work; CERT-Polska needed dual consent for proprietary embedding of the closest prior art | Commercial/paywalled web platform (M7+) may not be legally safe as currently envisioned | Real legal consultation needed before M7 business-model decisions; does not block internal lab automation |
| 4 | `tlsmon` is confirmed Windows-only | No known path to TLS visibility on Ubuntu/Android guests | Original engineering or scope reduction required |
| 5 | Android §1.3 network isolation is unverified | Sandbox containment guarantees for Android are currently unproven | Close before any real (non-benign) sample execution with networking enabled |
| 6 | ~~Missing `.cfg` files~~ — corrected 2026-08-07: all four Xen guest configs are tracked under `misc/` | None — closed | Initial research missed the `misc/` directory; DRAFT-006 repurposed to reconcile `misc/` naming (`linux*.cfg` files define `ubuntu`/`ubuntu_sandbox`, not "linux") rather than recover missing files |
| 7 | ~~`drakvuf-ubuntu.sh` has an apparent unsubstituted `<USER>` bug vs. working `preconfig-ubuntu.sh`~~ — resolved 2026-08-08 (issue #2): the deployed Dom0 copy is correctly substituted and samples execute; only this repo's copy carries the placeholder | None — closed. "Ubuntu works" is now execution-evidenced | DRAFT-007 complete; transcript in `docs/runbooks/verify-user-placeholder.md` |
| 11 | ~~`automation/*` had drifted from the deployed Dom0 copies~~ — resolved 2026-08-08: `automation/` synced wholesale from the tested production host (`drakvuf-ubuntu.sh`, `network-setup.sh`, `dirwatch_old.c`; five other files were already byte-identical), and issue #1's host-side `linux_sandbox.cfg` → `ubuntu_sandbox.cfg` rename was completed | None — closed. Repo and host now agree everywhere | Recurrence prevention is the open part: nothing detects drift automatically (see DRAFT-026 CI) |
| 8 | `lfreijo/drakvuf` `memdump` branch has no upstream PR/merge trail (single-maintainer fork) | Bus-factor risk for Linux plugin support | DRAFT-024 |
| 9 | Upstream `dirwatch.c` had a historical timeout/retry bug (issue #140) with the same retry-on-timeout shape this project's copy uses | Possible latent reliability bug | DRAFT-010 |
| 10 | No secrets-management design exists yet | Relevant once CI/deployment automation appears (M6+) | Not urgent now |

## Architecture decisions needing experiments

1. **`dirwatch.c`: keep as C, or move orchestration to Python?** Document
   current interface/callers first (DRAFT-010); do not rewrite merely
   because Python is easier.
2. **Sample OS auto-detection contract** (libmagic/MIME + ELF/PE/APK
   parsing) — ambiguous cases (Android ELF vs. Linux ELF) need experiments
   before the classification contract is finalized (DRAFT-014).
3. ~~Windows VM lifecycle: clone-per-run vs. snapshot-restore~~ — **resolved
   2026-08-07, not an open decision.** Snapshot-restore is ruled out in this
   nested Xen-inside-Proxmox setup entirely (`xl save`/`xl restore` leaves
   disk images read-only), so Windows uses clone-per-run like Ubuntu/Android.
   DRAFT-020 is reframed from "decide the model" to "confirm clone-per-run
   works for a Windows guest specifically and select a baseline."
4. **TLS-visibility strategy for Linux/Android** — hypervisor memory
   scanning vs. in-guest key logging vs. deferring (DRAFT-023).
5. **Upstream DRAKVUF repository strategy** — recommend a separate,
   independently-versioned checkout with pinned-revision documentation (not
   a submodule, not vendoring) — confirm via an actual build-from-pinned-
   revision test before locking this in.
6. **Job-queue technology for the eventual orchestrator** — low urgency,
   revisit near M7.

## Test classification

**Local / no Xen needed:** git/docs scaffolding; job/result state model +
unit tests; `bash -n`/`shellcheck`/`perl -c` on `automation/*`;
OS-classification logic against fixture files; capa-integration prototype
against log fixtures; result-schema validation tests; static-analysis-only
CI pipeline definition; licensing and legal desk research.

**Requires Xen Dom0 / L1** (must be presented for manual execution, per
`CLAUDE.md`'s infra boundary rule): closing Android §1.3 isolation tests;
re-deriving and validating the missing `.cfg` files against the real host;
Windows golden-VM creation; actual execution of
`clone-android.pl`/`preconfig-android.sh`/`drakvuf-android.sh` against a
real BlissOS clone; endurance/concurrency tests; any `dirwatch.c` behavior
change; OVS/iptables isolation smoke tests; building upstream DRAKVUF from a
pinned revision.

**Requires L2 guest execution** (via `injector`, never directly runnable by
Claude): Android process/package correlation, crash/tombstone collection;
Windows PE/DLL guest-side behavior.