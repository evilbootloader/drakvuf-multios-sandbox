# DRAKVUF Multi-OS Sandbox — Project Roadmap

> Last updated: 2026-08-29. This roadmap is a living document — update it as
> milestones close, decisions get made, and new gaps are found. It does not
> replace the per-OS checklists under `docs/checklists/`; those track
> execution evidence, this tracks direction and sequencing.

## Context

The project automates a DRAKVUF malware-analysis sandbox on
`Xen Dom0 on bare metal + DRAKVUF/LibVMI → {Ubuntu, Android/BlissOS, Windows}`,
with a web platform in its own PVH DomU alongside. All three OS targets are
**current**.

> **Updated 2026-08-29.** This paragraph read
> `Proxmox/KVM → Xen Dom0 → …` until the bare-metal migration removed L0 on
> 2026-08-28, and described Android Phase 2 as *"100% unstarted Candidate
> content"* long after it was written and evidenced. `docs/CURRENT-STATE.md`
> §2a lists everything the migration invalidated.

- **Ubuntu** — evidenced end to end, including through the platform. This is
  the protected path: do not change its behaviour without being asked.
- **Android/BlissOS** — Phase 1 (golden→sandbox clone, injection anchor, saved
  memory state) and the Phase 2 automation are both done:
  `preconfig-android.sh`, `drakvuf-android.sh`, `run_analysis-android.sh` and a
  shared `clone.pl`. **Both sample kinds are now evidenced through the
  platform** — native ELF, and APK install + `am start` (operator, 2026-08-29).
  That closes the last "implemented but never run" item on this track.
- **Windows** — no execution evidence. The track is open and its design
  constraints are fixed by issue #6's conformance checklist; DRAFT-034 is its
  head. `catalogue.py` raises rather than defaulting to the Linux options,
  deliberately, so nothing invents evidence for it.
- **The platform** — M7 delivered and serving; M8 partly open. See
  `docs/checklists/platform.md`.

This roadmap exists because writing more automation directly on top of the
brainstormed workstream list would have meant redoing work once the shared
job model, script boundaries, and containment gaps were sorted out. It
restructures that list into a dependency-ordered set of milestones and
issues, using a formal `PLAN → CREATE → TEST → DEPLOY` lifecycle (see
`CONTRIBUTING.md`) with human review gates at every stage.

## Environment & tooling constraints

**All three constraints recorded here on 2026-08-07 are resolved** (updated
2026-08-11, CONF-06). The section previously listed them as live, which
contradicted this file's own risk register two screens further down.

| Was | Now |
|---|---|
| `Bash` non-functional in the dev container (`bwrap: No permissions to create a new namespace`), so `bash -n`/`shellcheck`/`perl -c` could not run there | Lifted. Re-confirmed working in-container on 2026-08-08, 2026-08-09 and 2026-08-11. Current results: `bash -n` and `dash -n` pass on all six `automation/*.sh`; `perl -c` passes on `clone.pl` (named `clone-ubuntu.pl` when those runs were made); `shellcheck` 0.11.0 reports `SC1128` on five of six (licence header above the shebang — DRAFT-031) |
| No git repository existed | Closed as DRAFT-001; baseline commit `7764b77`. See risk #1 |
| `gh` availability/auth unverifiable | Verified — six issues have since been published and closed with it |

The standing instruction that replaces them: **re-verify the toolchain in
whatever container you are in before assuming static checks can run**, and
record the result. It has been non-functional before. `dash -n` matters as
much as `bash -n` here — the scripts execute under `dash` in production
(see `CLAUDE.md`).

## Current state (verified 2026-08-07, not assumed)

**Ubuntu** — `automation/` (flat, no subfolders) contains
`dirwatch.c, clone.pl, preconfig-ubuntu.sh, drakvuf-ubuntu.sh,
cleanup.sh, tcpdump.sh, network-setup.sh, run_analysis-ubuntu.sh`.
Architecture: `dirwatch.c` (GThreadPool + inotify, 15-arg CLI contract,
60s/180s per-phase timeouts) calls
`clone.pl → preconfig-ubuntu.sh → drakvuf-ubuntu.sh → cleanup.sh`
plus `tcpdump.sh` on a side thread. **"Ubuntu works" is now
execution-evidenced** (2026-08-08, issue #2): a recorded Dom0 run shows
`ExecProc Status:Success` on `/home/carlos/Desktop/test` followed by ~359k
trace records and a clean `exit_group`. The suspected `<USER>` bug was a
**repository** defect, not a production one — the deployed Dom0 copy was
correctly substituted all along. What that verification exposed was repo↔host
drift, **resolved 2026-08-08** by syncing `automation/` wholesale from the
tested production host and completing issue #1's host-side rename. Repo and
host now agree on every file. See risks #7 and #11 and
`docs/runbooks/01-verify-user-placeholder.md`.

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
  `misc/ubuntu_sandbox.cfg` (`ubuntu_sandbox`) and `misc/ubuntu.cfg`
  (golden `ubuntu`). No config file is actually missing; the earlier
  assumption that these were untracked was wrong. *(Updated 2026-08-11: the
  last two were named `misc/linux_sandbox.cfg` / `misc/linux.cfg` when this
  paragraph was written, with a caveat here about the misleading "linux"
  naming. Issue #1 renamed them on 2026-08-08 — repo side in `ced4e77`,
  Dom0 side the same day — so the caveat no longer applies.)*

Phase 2 through the MVP gate is **100% unstarted** — every item is `[ ]`,
explicitly labelled "Candidate." The Issue log (`AND-001..003`) and Change
log are placeholder rows.

**Windows** — a current target, with no execution evidence yet. No golden
VM, no baseline selected, no scripts. What it does have is a fixed design
contract rather than an open design space: issue #6's conformance checklist
(C1–C10 in `docs/architecture/analysis-pipeline.md`) already settles the
file set, delivery via `injector -m writefile`, the no-in-guest-collection
rule, and `pipeline-windows.env`'s shape. `docs/checklists/windows.md`
records those. **DRAFT-034 is the track head** and is drafted but not
published.

## Ecosystem research — what to reuse vs. build

See `docs/architecture/upstream-drakvuf.md` and `docs/architecture/licensing.md`
for full sourced detail. Condensed:

| Component (from CERT-Polska `drakvuf-sandbox`) | Verdict | Why |
|---|---|---|
| Task/job queue (Flask + RQ + Redis) | Reuse/Adapt | Simple, well-understood; adaptable to drive Xen/LVM/OVS clones instead of snapshot restores. |
| Analysis state machine | Reference-only | Good conceptual model; this project's clone-per-run, multi-OS shape needs its own state machine. **Defined 2026-08-09** (issue #3) — `docs/architecture/analysis-pipeline.md`. |
| Network setup (bridge-per-worker + NAT/dnsmasq) | Reference-only | Conceptually close to existing OVS-per-VLAN approach; not a drop-in. |
| TLSMON (TLS key extraction) | **Windows only — reuse there, not applicable elsewhere** | Confirmed by direct source read: hooks Windows `ncrypt.dll`/Schannel only; no Linux/Android path exists upstream. *(Updated 2026-08-11: this row read "Not applicable" unqualified, which was written when Windows was deferred. With Windows a current target it inverts — `tlsmon` becomes the only working TLS-visibility path the project has. See risk #4.)* |
| capa post-processing | Reuse/Adapt | Apache-2.0, no licensing friction. capa v7.2.0 added a native DRAKVUF-log feature extractor. |
| Result/artifact schema | Reference-only / gap | No published JSON Schema found; define this project's own contract. |
| Web/API architecture | Reference-only | Small Flask MVP is a fine reference; frontend stack unconfirmed. |
| VM lifecycle (snapshot-restore) | **Not applicable, and ruled out for Windows too** | This project clones per-run via LVM/OVS. Confirmed 2026-08-07: snapshot-restore is not viable in this nested Xen-inside-Proxmox setup at all — `xl save`/`xl restore` leaves the base and cloned disk images read-only — so the Windows track will also use clone-per-run, not just Ubuntu/Android. **Qualified 2026-08-29:** that finding was made on the nested host, which no longer exists, and **has not been re-tested on bare metal**. Treat it as unconfirmed rather than as a standing constraint. It does not change the decision either way — clone-per-run is now load-bearing for thin snapshots, per-VLAN isolation and `sandboxd`'s admission control, none of which snapshot-restore would simplify. |
| Config presets (`[preset.x]` TOML) | Reuse/Adapt | Low-risk pattern, directly portable to per-OS presets. |

## Repository layout

*(Was "Proposed" — this is the layout as built. Updated 2026-08-11 to add
`docs/runbooks/`, `docs/workflow-ci.md`, `profiles/` and `state/`, all of
which now exist.)*

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
├── checklists/
│   ├── ubuntu.md
│   ├── android.md
│   ├── windows.md
│   └── platform.md
├── runbooks/                        # dated execution transcripts (append-only)
└── workflow-ci.md                   # CI design (DRAFT-026a/b)
automation/                          # Ubuntu automation scripts + pipeline-ubuntu.env
misc/                                # tracked Xen guest .cfg files
profiles/                            # LibVMI/DRAKVUF kernel profiles — NOT git-tracked
state/                               # xl save memory images — NOT git-tracked
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
   └──> upstream DRAKVUF *contribution* (last; depends on ≥1 stable OS pipeline + repo-strategy decision)
        note: modifying the engine is near-term, NOT gated here — see CONF-11
```

Anti-evasion work attaches after each per-OS pipeline is functional — it's a
per-OS quality track, not a gate for anything else.

## Milestones

| # | Milestone | Contents | Gate |
|---|---|---|---|
| M0 | Foundations | git init, README, docs reorg, CONTRIBUTING.md, ~~job/result state model~~ (done 2026-08-09, issue #3), licensing spike write-up | No Xen changes; pure planning/docs/scaffolding |
| M1 | Ubuntu regression baseline | ~~Verify the `<USER>` bug~~ and ~~reconcile the repo↔Dom0 drift it exposed~~ (both done 2026-08-08, issue #2); document current behavior precisely, retrofit structured status output without changing behavior, add `bash -n`/`shellcheck`/`perl -c` CI plus a drift check | Proves the job model works on the one pipeline that already runs |
| M2 | Containment closure | Finish Android §1.3 network isolation verification; decide shared-vs-per-OS script boundaries | Requires Xen Dom0 for the isolation tests |
| M3 | Android MVP | Resume checklist Phase 2 → MVP gate using the now-defined job model | Bulk of the existing "Candidate" checklist content gets executed here |
| M4 | Artifact schema + enrichment | Result schema, capa integration | After M1/M3 produce real logs to validate against |
| M5 | Windows track | Baseline selection, profile/symbol requirements, then the pipeline itself against issue #6's C1–C10 contract (VM-lifecycle model already settled: clone-per-run). **DRAFT-034 is the head** | *(Reframed 2026-08-11: was "Windows planning spike … Design only". Windows is a current target, not a design exercise. Milestones are deliberately **not** renumbered here — Windows arguably reorders M2–M5, and DRAFT-034 owns proposing that, so this stays a correction rather than a replan)* |
| M6 | Ops hardening | Observability, CI expansion, resource limits/abuse resistance | After ≥2 OS pipelines exist |
| M7 | Web platform MVP | Job submission API, queue, minimal UI — built on the state model's presentation projection (`display_phase`, the per-state artifact/cancellable/retryable contract) rather than a UI-specific status vocabulary | Only after M0–M6 and the licensing decision are resolved |
| M8 | Public hardening + legal gate | AuthN/Z, rate limiting, tenant isolation, formal legal review | Before any external/paying users |
| M9 | Upstream DRAKVUF contribution | Contributing changes *back* to upstream still belongs here. **Modifying the engine does not** — that is near-term intended work as of 2026-08-11 (CONF-11) | *(Corrected 2026-08-11: this row read "Only after a stable OS pipeline + resolved repo strategy — Deliberately last", which would have an agent decline engine work while citing M9 correctly. Consequences for DRAFT-024 and DRAFT-010 are recorded in `docs/architecture/upstream-drakvuf.md`. Milestones not renumbered)* |

## Issue index

See `.github/issue-drafts/issue-index.md` for the full draft-title index with
areas, priorities, and dependencies. The draft files themselves are filed by
state as of 2026-09-04 — `.github/issue-drafts/{completed,in-progress,todo}/DRAFT-NNN.md`
— with the placement rule in that directory's `README.md`.

## Risk register

| # | Risk | Impact | Notes |
|---|---|---|---|
| 1 | ~~No git repository existed as of 2026-08-07~~ — resolved 2026-08-07: baseline commit `bb8ad14` created | None — closed | DRAFT-001 complete; `git log`/`git status`/`git show --stat` evidence recorded in DRAFT-001.md |
| 2 | Dev-container `Bash` was non-functional (bwrap error) | `bash -n`/`shellcheck`/`perl -c` couldn't run there | Must run on real host/CI; documented in CONTRIBUTING.md's TEST section |
| 3 | DRAKVUF's GPL-with-exceptions text treats subprocess-orchestration as derivative work; CERT-Polska needed dual consent for proprietary embedding of the closest prior art | Commercial/paywalled web platform (M7+) may not be legally safe as currently envisioned | Real legal consultation needed before M7 business-model decisions; does not block internal lab automation |
| 4 | `tlsmon` is confirmed Windows-only | No known path to TLS visibility **on Ubuntu/Android guests**. Not a project-wide gap: with Windows current, `tlsmon` is the one working TLS-visibility path the project has | Original engineering or scope reduction required for Ubuntu/Android; adopt `tlsmon` for Windows. DRAFT-023 is rescoped accordingly *(rescoped 2026-08-11 — the risk was written when Windows was deferred and read as "no TLS visibility anywhere")* |
| 5 | ~~Android §1.3 network isolation is unverified~~ — **verified 2026-08-11 (DRAFT-028), and what it found was that isolation had never worked** | The previous inter-clone rule was `-o !xenbr0`. Current iptables **accepts** that while storing `!xenbr0` as a *literal interface name* — one that has never existed — so the rule installed cleanly, appeared in `iptables -S`, and matched nothing. Every analysis run before that date, Ubuntu and Android alike, had the rule present and inert. No exit-status check could have caught it: the command succeeded. IPv6 was separately unfiltered altogether (no `ip6tables` rules, `disable_ipv6 = 0`), reachable to Dom0 over link-local by any sample that re-enabled it | **Mechanism fixed, measured, and now confirmed on Android** — `docs/checklists/android.md` §1.3, transcript in `docs/runbooks/04-deploy-network-isolation.md`. **The Android half closed 2026-08-14 (DRAFT-013, `docs/runbooks/06-verify-android-isolation.md`):** a clone booted on `xenbr1.1` probed its gateway with ICMP, had 10 packets dropped by `DRAKVUF_INPUT`, and validated the network regardless — so the posture is robust rather than lucky and needs no ICMP exemption. Failed IPv6 provisioning (8 dropped router solicitations) did not affect its verdict either. **One half remains open and is not this risk's:** clones still have deliberate NAT egress, so "no Internet by default" was never the policy — DRAFT-022 and risk #13 |
| 6 | ~~Missing `.cfg` files~~ — corrected 2026-08-07: all four Xen guest configs are tracked under `misc/` | None — closed | Initial research missed the `misc/` directory; DRAFT-006 repurposed to reconcile `misc/` naming (`linux*.cfg` files define `ubuntu`/`ubuntu_sandbox`, not "linux") rather than recover missing files |
| 7 | ~~`drakvuf-ubuntu.sh` has an apparent unsubstituted `<USER>` bug vs. working `preconfig-ubuntu.sh`~~ — resolved 2026-08-08 (issue #2): the deployed Dom0 copy is correctly substituted and samples execute; only this repo's copy carries the placeholder | None — closed. "Ubuntu works" is now execution-evidenced | DRAFT-007 complete; transcript in `docs/runbooks/01-verify-user-placeholder.md` |
| 11 | ~~`automation/*` had drifted from the deployed Dom0 copies~~ — resolved 2026-08-08: `automation/` synced wholesale from the tested production host (`drakvuf-ubuntu.sh`, `network-setup.sh`, `dirwatch_old.c`; five other files were already byte-identical), and issue #1's host-side `linux_sandbox.cfg` → `ubuntu_sandbox.cfg` rename was completed | None — closed. Repo and host now agree everywhere | Recurrence prevention is the open part: nothing detects drift automatically (see DRAFT-026 CI) |
| 8 | `lfreijo/drakvuf` `memdump` branch has no upstream PR/merge trail (single-maintainer fork) | Bus-factor risk for **Linux/Android** plugin support specifically. The Windows track leans on upstream `tklengyel/drakvuf` (~30 Windows-oriented plugins already present), so it is not exposed to this fork — the pinned commit is titled "Add **Linux** support for memdump, filetracer, fileextractor, and syscalls plugins" — ***narrowed 2026-08-24, see below*** | DRAFT-024, which must therefore pin **two** upstreams with different bus-factor profiles. Its priority should rise from P2: with engine work near-term (see the M9 note), a pinned revision is the baseline changes are diffed from, not just insurance |
| 9 | Upstream `dirwatch.c` had a historical timeout/retry bug (issue #140) with the same retry-on-timeout shape this project's copy uses | Possible latent reliability bug | DRAFT-010 |
| 10 | No secrets-management design exists yet | Relevant once CI/deployment automation appears (M6+) | Not urgent now |
| 12 | **Nothing links a saved sandbox state to the golden image it came from.** `state/<domain>.bak` records no provenance, and no check compares the two | A golden-VM change silently invalidates the saved state, and the pipeline keeps restoring it. The injection PID is worse than the state itself: it is a property of the `.bak`, so a stale `INJECTION_PID` makes `injector` attach to whatever now holds that PID — or to nothing | **Realised, not hypothetical.** The golden `android` VM was reinstalled on 2026-08-11 (AND-001), invalidating `state/android_sandbox.bak` and anchor PID 5715; `docs/checklists/android.md` §1.5 recorded them as validated and nothing flagged the conflict. **Android side closed 2026-08-11** by [issue #7](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/7): template rebuilt, new state `1844fc0a…`, anchor PID 3163. That rebuild also found the recorded checksum already stale for a second, more ordinary reason — the template had been re-saved several times during testing and the checklist was never updated. Neither cause was detected by anything. The generic fix — recording golden-image identity alongside the saved state and checking it at restore — is **unowned** and applies to all three OS targets |
| 13 | **The lab is operated personally, over a residential Internet line, and analysis clones have deliberate unrestricted NAT egress** (established 2026-08-12; the egress posture is DRAFT-028's, and intentional) | The binding constraint on live detonation is the ISP's acceptable-use terms, not Spanish criminal law — enforced without a prosecutor, court or complainant, by a party that already knows who the subscriber is. Realistic failure is an abuse report and disconnection of a household line. Personal operation also means civil negligence exposure (`Código Civil` art. 1902) has no corporate veil or institutional insurance behind it | **Costs nothing today — only benign fixtures have ever been detonated — and becomes real on the first non-benign run.** Owned by DRAFT-022, which now carries the entity/uplink facts and the provisional position ("not on this uplink"). The engineering half is the `offline` network mode: proposed in `docs/architecture/networking.md`, listed as undecided M2 design work, and **unowned**. It is small — `network-setup.sh` already isolates the posture in dedicated chains, so `offline` is the `DRAKVUF_NAT` `MASQUERADE` not being installed |

> **Risk #8, narrowed 2026-08-24 by a direct read of the OS-support matrix.**
> `drakvuf_plugin_os_support[plugin][os]` in `src/plugins/plugins.h`,
> compared between `tklengyel/main` and `lfreijo/memdump`:
>
> **The fork adds Linux support for exactly two plugins — `fileextractor` and
> `memdump`.** Upstream has `[VMI_OS_LINUX] = 0` for both and the fork sets
> them to 1. `syscalls` and `filetracer` already carry Linux support upstream,
> despite the fork commit's title naming all four.
>
> So the exposure is **two plugins, not Linux/Android plugin support as a
> whole**. Losing the fork would cost extracted files and memory dumps on
> Ubuntu and Android — serious, but bounded, and both are single-plugin
> reimplementations rather than a platform's worth of work.
>
> The same read found the upside: **`procmon`, `procdump2`, `cpuidmon`,
> `debugmon`, `ipt`, `hidsim`, `ptracemon`, `ebpfmon`, `unixsocketmon` are
> Linux-capable upstream and none is enabled.** No fork dependency, so this
> capability survives the fork disappearing. `docs/workflow-ci.md`'s
> Linux-applicable list was wrong in both directions and is corrected there;
> the full matrix is in `docs/architecture/upstream-drakvuf.md`.
>
> Read from the branch tip, not the pinned `52df0bc` — DRAFT-050 confirms
> against the pinned revision and evidences each plugin per guest.

## Architecture decisions needing experiments

1. ~~**`dirwatch.c`: keep as C, or move orchestration to Python?**~~
   **Decided 2026-08-21 (DRAFT-041): Python.** Not on the "easier" argument,
   which stays rejected — the work itself changed. `sandboxd` takes jobs from
   a Postgres queue over an HTTPS API, holds a state machine, uploads to S3
   with retry, and cancels; `inotify` and a thread pool stop being the
   problem. The callback contract to the five worker scripts is preserved, so
   they do not change. See `docs/architecture/platform.md`.
2. **Sample OS auto-detection contract** (libmagic/MIME + ELF/PE/APK
   parsing) — ambiguous cases (Android ELF vs. Linux ELF) need experiments
   before the classification contract is finalized (DRAFT-014).
3. ~~Windows VM lifecycle: clone-per-run vs. snapshot-restore~~ — **resolved
   2026-08-07, not an open decision.** Snapshot-restore was ruled out in the
   nested Xen-inside-Proxmox setup this project used until 2026-08-28
   (`xl save`/`xl restore` leaves disk images read-only) — **not re-tested on
   bare metal** — so Windows uses clone-per-run like Ubuntu/Android.
   DRAFT-020 is reframed from "decide the model" to "confirm clone-per-run
   works for a Windows guest specifically and select a baseline."
4. **TLS-visibility strategy for Linux/Android** — hypervisor memory
   scanning vs. in-guest key logging vs. deferring (DRAFT-023).
5. **Upstream DRAKVUF repository strategy** — recommend a separate,
   independently-versioned checkout with pinned-revision documentation (not
   a submodule, not vendoring) — confirm via an actual build-from-pinned-
   revision test before locking this in.
6. ~~**Job-queue technology for the eventual orchestrator** — low urgency,
   revisit near M7.~~ **Premise expired 2026-08-19; now DRAFT-040.** The
   "low urgency" reading was correct while the queue served only the web
   platform. Three needs have since converged on it: anti-starvation
   (DRAFT-036 item 3) needs a host-global order over jobs; cancellation
   (DRAFT-035) needs a queued job to have a record at all, which today it
   does not; and M7 needs both. Deferring now means building a
   filesystem-shaped queue and discarding it — the cost the deferral
   existed to avoid. See `.github/issue-drafts/completed/DRAFT-040.md`.
   **Answered 2026-08-21 (DRAFT-041): Postgres**, holding both job state and
   the queue, on a separate platform VM alongside MinIO. Redis was considered
   and deferred rather than rejected — with the queue in Redis and the state
   in Postgres, claiming a job and transitioning it stop being one
   transaction, and cancelling a queued job becomes two writes across two
   stores. The full reasoning, including what would change the answer, is in
   `docs/architecture/platform.md`.

## Test classification

**Local / no Xen needed:** git/docs scaffolding; job/result state model +
unit tests; `bash -n`/`shellcheck`/`perl -c` on `automation/*`;
OS-classification logic against fixture files; capa-integration prototype
against log fixtures; result-schema validation tests; static-analysis-only
CI pipeline definition; licensing and legal desk research.

**Requires Xen Dom0 / L1** (must be presented for manual execution, per
`CLAUDE.md`'s infra boundary rule): closing Android §1.3 isolation tests;
Windows golden-VM creation; actual execution of
`clone-android.pl`/`preconfig-android.sh`/`drakvuf-android.sh` against a
real BlissOS clone; endurance/concurrency tests; any `dirwatch.c` behavior
change; OVS/iptables isolation smoke tests; building upstream DRAKVUF from a
pinned revision.

**Requires L2 guest execution** (via `injector`, never directly runnable by
Claude): Android process/package correlation, crash/tombstone collection;
Windows PE/DLL guest-side behavior.