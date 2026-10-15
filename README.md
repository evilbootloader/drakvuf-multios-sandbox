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
its target OS, and the clone is destroyed afterwards. **There is one way in:**
a sample is uploaded through the web UI, queued in Postgres, and claimed by
`sandboxd` on Dom0 over mutual TLS.

The original path — dropping a file into `/malware_incoming/<os>/` for a per-OS
`dirwatch` watcher to pick up — was **removed on 2026-09-15**, along with the
shell and C pipeline behind it. See
`docs/architecture/automation-files.md` for what each of those files did and
what replaced it.

## The components

| | |
|---|---|
| **`automation/`** | host provisioning and deployment assets — `network-setup.sh` (the per-VLAN isolated networks), `platform.env`, and the egress configs. Not the pipeline; that is `sandboxd/` |
| **`sandboxd/`** | the Dom0 orchestrator. Claims jobs from the platform, admits them against real host capacity, runs the pipeline, uploads artifacts, and reports state. Python; runs in the foreground with **no systemd unit** |
| **`platform/`** | the web tier: FastAPI, Postgres job queue, MinIO object store, server-rendered UI, Cloudflare Access at the edge and an internal CA inward. Runs in its own PVH DomU and **never executes a sample** — that asymmetry is what the whole trust boundary rests on |

Dom0 opens every connection and has no inbound listener; the platform answers
requests and never makes them.

## The OS targets

All three are current, at different stages:

| Target | State |
|---|---|
| **Ubuntu** | Evidenced end to end, including through the platform |
| **Android/BlissOS** | Automation complete, in `sandboxd/guests.py`. **Both sample kinds evidenced through the platform** — native ELF, and APK install + `am start` |
| **Windows** | Track open, design contract fixed (issue #6's C1–C10), no execution evidence yet |

## Running it

Every repository-owned asset resolves from the invoking code's own location,
so the checkout works at any path — the Dom0 checkout happens to be at
`/root/drakvuf-multios-sandbox`, but nothing requires that.

Analyses are submitted through the platform's web UI. On Dom0, `sandboxd` is
started in the foreground with its environment file sourced first; it exits
immediately without `SANDBOXD_API`, `WORKER_TOKEN` and `SANDBOXD_TOTAL_MIB`,
because there is no safe default for how much memory a Dom0 may hand to clones.
`docs/CURRENT-STATE.md` §1.2 has the exact invocation.

Host configuration lives in `sandboxd/config.py`, which is the source of truth;
`scripts/gen-xen-configs.py` pushes its values into `automation/platform.env`
and `misc/*.cfg`, which cannot import Python.

A fresh checkout also needs a LibVMI profile in `profiles/` and a saved
guest state in `state/`; neither is git-tracked. See `profiles/README.md`,
`state/README.md`, and `docs/runbooks/02-deploy-repo-relative-paths.md`.

## Repository layout

- `automation/` — host provisioning and deployment assets: `network-setup.sh`
  (executed by `sandboxd` at every daemon start), host-global `platform.env`,
  and the egress configs (`torrc`, `fakenet.*`, `drakvuf-egress.target`). The
  shell and C pipeline that used to live here was deleted 2026-09-15 — see
  `docs/architecture/automation-files.md`.
- `sandboxd/` — the Dom0 orchestrator and its tests. **This is the analysis
  pipeline**: clone, isolate, preconfigure, trace, collect, destroy, shared
  across all three OS targets and driven by the platform's queue, with
  host-global admission control instead of fixed clone slots. See
  `docs/architecture/analysis-pipeline.md`.
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
command CI runs. The baseline disables **one** code (SC1091) over one file,
recorded in `.shellcheckrc` with the issue that owns removing it. SC2086 and
SC2009 were retired on 2026-09-15 with the scripts that carried their findings,
so both are live again — read that file before reading a clean run as clean
code.

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


## INSTALL PLATFORM DOMU

```
sudo su
cd ~/path/to/repo/misc/xen-vms
ssh-keygen # Don't add a password to the key
# Update Makefile line with the key between the quotes.
# RSA_KEY	:= ""
make web_vm
make web_sandbox
```

At the end of the script you will get something like `WORKER_TOKEN=...`, save it. If you did not save it you can always run

```
ssh <PLATFORM_VM_IP>
sudo -u platform DATABASE_URL=postgresql:///sandbox_platform \
  .venv/bin/python create_worker.py dom0-1 --rotate
```

Creating users when registration is not active
```
ssh <PLATFORM_VM_IP>
cd /opt/platform/src/platform
sudo -u platform DATABASE_URL=postgresql:///sandbox_platform \
  .venv/bin/python create_user.py you@example.com --balance 100000  # balance is in seconds
```

### Cloudflare tunnel on WEB SANDBOX

```
ssh <PLATFORM_VM_IP>

sed 's/TRUSTED_CLIENT_IP_HEADER=/TRUSTED_CLIENT_IP_HEADER=CF-Connecting-IP/g' -i /etc/sandbox_platform/api.env

curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
  -o /usr/share/keyrings/cloudflare-main.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
  > /etc/apt/sources.list.d/cloudflared.list
apt-get update && apt-get install -y cloudflared

cloudflared tunnel login
cloudflared tunnel create sandbox-platform
cloudflared tunnel route dns sandbox-platform <SANDBOX_DOMAIN>

install -d -m 750 /etc/cloudflared
mv ~/.cloudflared/<UUID>.json /etc/cloudflared/
chmod 600 /etc/cloudflared/<UUID>.json

useradd --system --no-create-home --shell /usr/sbin/nologin cloudflared || true
cp /etc/sandbox_platform/tls/ca.crt /etc/cloudflared/ca.crt
chown -R cloudflared:cloudflared /etc/cloudflared

cat > /etc/systemd/system/cloudflared.service <<EOF
[Unit]
Description=Cloudflare Tunnel (browser-facing ingress)
After=network-online.target sandbox-api.service
Wants=network-online.target

[Service]
Type=notify
User=cloudflared
Group=cloudflared
ExecStart=/usr/bin/cloudflared --no-autoupdate --config /etc/cloudflared/config.yml tunnel run
Restart=on-failure
RestartSec=5
TimeoutStartSec=0

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

cat > /etc/cloudflared/config.yml <<EOF
tunnel: UUID
credentials-file: /etc/cloudflared/UUID.json
# /etc/cloudflared/config.yml
ingress:
  # bucket FIRST -- cloudflared matches in order
  - hostname: SANDBOX_DOMAIN
    path: ^/analysis(/|$)
    service: https://VM_IP:9000
    originRequest:
      caPool: /etc/cloudflared/ca.crt
  - hostname: SANDBOX_DOMAIN
    path: ^/api/v1/worker(/|$)
    service: http_status:404
  - hostname: SANDBOX_DOMAIN
    service: https://VM_IP:8000
    originRequest:
      caPool: /etc/cloudflared/ca.crt
  - service: http_status:404
EOF
chown cloudflared:cloudflared /etc/cloudflared/config.yml
cloudflared --config /etc/cloudflared/config.yml tunnel ingress validate
systemctl enable --now cloudflared
systemctl status cloudflared --no-pager | head -5


```