# DRAKVUF Multi-OS Sandbox

Automation for a DRAKVUF malware-analysis laboratory.

```
Xen Dom0 on bare metal + DRAKVUF/LibVMI
├── Ubuntu analysis guest        (HVM, disposable clone per sample)
├── Android/BlissOS analysis guest
├── Windows analysis guest
└── platform                     (PVH DomU: Postgres, MinIO, the web API)
```

Until 2026-08-28 this ran nested inside Proxmox, three layers deep. Proxmox was
erased in the bare-metal migration; documents naming `pve1`, VM 101 or CT 102
predate it. `docs/CURRENT-STATE.md` §2a lists what that invalidated.

A sample is analysed under DRAKVUF inside a disposable clone of the guest for
its target OS, and the clone is destroyed afterwards. **There are two ways in**,
and they share the clone machinery rather than duplicating it:

| Path | How a sample arrives | Status |
|---|---|---|
| **The platform** | uploaded through the web UI, queued in Postgres, claimed by `sandboxd` on Dom0 over mutual TLS | the current path |
| **The per-OS watcher** | dropped into `/malware_incoming/<os>/`, picked up by `dirwatch` | the original path, still present |

## The components

| | |
|---|---|
| **`automation/`** | the analysis pipeline itself — clone, isolate, trace, collect, destroy. Driven either by `dirwatch` or by `sandboxd` |
| **`sandboxd/`** | the Dom0 orchestrator. Claims jobs from the platform, admits them against real host capacity, runs the pipeline, uploads artifacts, and reports state. Python; runs in the foreground with **no systemd unit** |
| **`platform/`** | the web tier: FastAPI, Postgres job queue, MinIO object store, server-rendered UI, Cloudflare Access at the edge and an internal CA inward. Runs in its own PVH DomU and **never executes a sample** — that asymmetry is what the whole trust boundary rests on |

Dom0 opens every connection and has no inbound listener; the platform answers
requests and never makes them.

## The OS targets

All three are current, at different stages:

| Target | State |
|---|---|
| **Ubuntu** | Evidenced end to end, including through the platform |
| **Android/BlissOS** | Automation complete (`preconfig-android.sh`, `drakvuf-android.sh`, `run_analysis-android.sh`, shared `clone.pl`). **Both sample kinds evidenced through the platform** — native ELF, and APK install + `am start` |
| **Windows** | Track open, design contract fixed (issue #6's C1–C10), no execution evidence yet |

## Running it

The scripts resolve every repository-owned asset from their own location,
so the checkout works at any path — the Dom0 checkout happens to be at
`/root/drakvuf-multios-sandbox`, but nothing requires that. Configuration
lives in one file per OS rather than in the scripts:

```bash
$EDITOR automation/pipeline-ubuntu.env   # injection PID, clone count, guest user, ...
sudo automation/run_analysis-ubuntu.sh
```

A fresh checkout also needs a LibVMI profile in `profiles/` and a saved
guest state in `state/`; neither is git-tracked. See `profiles/README.md`,
`state/README.md`, and `docs/runbooks/02-deploy-repo-relative-paths.md`.

## Repository layout

- `automation/` — the analysis pipeline, shared across all three OS targets.
  `dirwatch.c` (the watcher), `clone.pl` (shared), the per-OS
  `preconfig-<os>.sh` / `drakvuf-<os>.sh` / `run_analysis-<os>.sh`, plus
  `cleanup.sh`, `tcpdump.sh`, `network-setup.sh`. Configuration is
  `pipeline-<os>.env` per target and `platform.env` host-global. See
  `docs/architecture/analysis-pipeline.md`.
- `sandboxd/` — the Dom0 orchestrator and its tests. Runs the same pipeline as
  `dirwatch` but driven by the platform's queue, with host-global admission
  control instead of fixed clone slots.
- `platform/` — the FastAPI service, SQL migrations, MinIO provisioning, the
  server-rendered UI, and its tests. See `docs/architecture/platform.md`.
- `misc/` — tracked Xen guest configs: `ubuntu.cfg` / `ubuntu_sandbox.cfg`,
  `android.cfg` / `android_sandbox.cfg`, `windows.cfg`, and `platform.cfg`
  (the PVH domain the web tier runs in).
- `scripts/` — repository tooling, including `gen-current-state.py`, which
  regenerates the derived half of `docs/CURRENT-STATE.md`.
- `profiles/` — LibVMI/DRAKVUF kernel profiles (`linux.json`, `android.json`).
  **Not git-tracked**: ~48 MB and ~62 MB of `dwarf2json` output regenerated per
  kernel build. `profiles/README.md` has the commands and the SHA-256 of each.
- `state/` — Xen `xl save` memory images for the sandbox templates, named after
  the origin domain. **Not git-tracked** (`*.bak`).
- `docs/INDEX.md` — generated index of every heading in `docs/`, as
  `path:line — heading`. Start here when looking for where a topic is covered.
- `docs/CURRENT-STATE.md` — what the lab actually is right now, with a
  confirmed date per fact and a superseded-facts table. **Read before asserting
  any deployment fact.**
- `docs/roadmap/` — milestones, dependency graph, risk register, architecture
  decisions still needing experiments.
- `docs/architecture/` — the analysis pipeline, the platform, networking, the
  live console, result schema, upstream-DRAKVUF strategy, licensing.
- `docs/checklists/` — per-OS implementation checklists with execution
  evidence. These track what has been done, distinct from the roadmap.
- `docs/runbooks/` — dated execution transcripts from real Dom0 work, numbered
  oldest to newest. Append-only evidence: annotate, never edit in place.
  **01–10 describe the nested Proxmox lab** that was erased on 2026-08-28.
- `docs/reviews/` — dated whole-project assessments.
- `docs/workflow-ci.md` — the CI design: a GitHub-hosted static tier
  (implemented, `.github/workflows/static-checks.yml`) and a self-hosted Xen
  integration tier (DRAFT-026b, not implemented).
- `docs/Project-definition.txt`,
  `docs/drakvuf-on-xen-nested-within-proxmox.md`, `docs/android_setup.md` —
  the original infrastructure setup guides. Historical provenance, kept
  verbatim and not synced with later renames or fixes — see `CLAUDE.md`.
- `.github/issue-drafts/` — locally-drafted GitHub issues, reviewed before
  anything is published with `gh`.

## Development lifecycle

This project uses a `PLAN → CREATE → TEST → DEPLOY` lifecycle with human
review gates. See `CONTRIBUTING.md`.

## Testing

```bash
bash -n SCRIPT       # shell scripts
dash -n SCRIPT       # they execute under dash in production — see CLAUDE.md
shellcheck SCRIPT
perl -c SCRIPT       # Perl scripts

platform/.venv/bin/python -m pytest sandboxd/tests -q   # sandboxd; needs no infrastructure
scripts/dev-services.sh                                  # bring up Postgres + MinIO locally
cd platform && .venv/bin/python -m pytest -q             # platform; needs both
```

**Never run the platform suite against the deployment.** Its `conn` fixture
truncates the jobs table. `TEST_DATABASE_URL` defaults to
`sandbox_platform_test`, which is why it is safe in a development container and
destructive anywhere else.

`shellcheck` exits 0 as of DRAFT-031 (2026-08-11) — run it bare, without a
severity flag, since it reads `.shellcheckrc` automatically and that is the
command CI runs. The baseline disables four codes repository-wide, each
recorded in `.shellcheckrc` with the issue that owns removing it, so a clean
run does not mean the scripts are free of findings. Read that file first.

`dash -n` matters as much as `bash -n`: the worker scripts declare
`#!/bin/sh` and are interpreted by `dash` in production, so `bash -n` alone
accepts bashisms that fail silently there.

## Infrastructure boundary

Commands targeting Xen, LVM, OVS, the Android sandbox, or malware samples
must be presented for manual execution on the real Xen Dom0 host — they are
never assumed runnable in a generic development environment. See
`CLAUDE.md` for the full list of commands this applies to and the current
Ubuntu/Android naming conventions.

## Working with Claude Code on this repo

This project is developed with Claude Code. `CLAUDE.md` carries the
project-specific rules; see Anthropic's
[Claude Code best practices](https://code.claude.com/docs/en/best-practices)
for general guidance on the tool itself.