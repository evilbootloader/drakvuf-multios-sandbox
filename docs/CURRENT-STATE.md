# Current state of the lab

**Read this before asserting any fact about the deployment.** It exists because
a 2026-08-27 review produced several confident, wrong statements — a
`dom0_max_vcpus` contradiction the runbooks had already settled, a
`journalctl -u sandboxd` for a daemon that is not a service, a memory figure
read as a core count. All three were answerable from something already written
down, in 26 documents and 25k lines. This is the one place to look first.

**Three sections, three different kinds of trust:**

| Section | Maintained by | How to trust it |
|---|---|---|
| Capabilities | the operator, by hand | each row carries the date it was last confirmed |
| Superseded facts | the operator, by hand | things that *look* current in old runbooks and are not |
| Derived | `scripts/gen-current-state.py` | regenerated from the repo; a test fails if stale |

**Staleness rule.** A capability row older than **30 days** is a hint, not a
fact. Say it is unconfirmed and ask, rather than asserting it. Nothing here
describes the host as it is *now* — only as it was on the date in the row.

---

# 1. Capabilities

## 1.1 L0 — Proxmox host `pve1`

| Fact | Value | Confirmed |
|---|---|---|
| CPU | **hybrid Intel**, 32 logical | 2026-08-27 |
| P-cores | host CPU **0–15** — 8 physical, SMT ×2 (`/sys/devices/cpu_core/cpus`) | 2026-08-27 |
| E-cores | host CPU **16–31** — 16 physical, no SMT (`/sys/devices/cpu_atom/cpus`) | 2026-08-27 |
| Nested virt | `nested=Y ept=Y` via `/etc/modprobe.d/kvm-intel.conf` | 2026-08-11 |
| `enable_shadow_vmcs` | **UNCONFIRMED** — never checked; matters most for a trap-heavy workload | — |
| `enable_apicv` | **UNCONFIRMED** — never checked | — |
| Storage | LVM thin pool `pve/data` | 2026-08-22 |
| Thin pool overcommit | **6.35 TiB provisioned against <1.82 TiB real**, `thin_pool_autoextend_threshold` unset | 2026-08-22 |
| Guests | VM **101** `drakvuf` (Xen L1), CT **102** `platform` | 2026-08-27 |

> **The thin pool is a shared failure domain.** A full pool affects every thin
> volume on it, *including VM 101's disks* — so filling the artifact store with
> memdumps can stop the analysis lab. Isolation of access was designed;
> isolation of capacity was not (`docs/architecture/platform.md`).

## 1.2 L1 — VM 101 `drakvuf`, the Xen host

| Fact | Value | Confirmed |
|---|---|---|
| Proxmox config | **12 vCPU**, 20480 MiB, `affinity: 0-15`, `cpu: host,flags=-hv-evmcs;-hv-tlbflush` | 2026-08-27 |
| Xen | **4.20.1** | 2026-08-26 |
| Dom0 kernel | `6.8.0-136-generic`, Ubuntu 22.04 | 2026-08-12 |
| DRAKVUF | `v1.1-git20260511151619+52df0bc8-1` | 2026-08-26 |
| Xen boot line | `dom0_mem=8192M,max:8192M dom0_max_vcpus=6 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0 sched=credit` | 2026-08-27 |
| Memory as Xen sees it | `total_memory 20479`, Dom0 pinned at 8192 → **12082 free** | 2026-08-26 |
| CPU partition | Dom0 → Xen pCPU **0–5** (pinned 1:1); clones → **6–11** via `cpus="6-11"` in `misc/*_sandbox.cfg` | 2026-08-27 |
| Scheduler | Credit**1** (`sched=credit`), not Xen 4.20's default Credit2 | 2026-08-27 |
| Repo checkout | `/root/drakvuf-multios-sandbox` | 2026-08-19 |
| Volume group | `vg-root` | — |
| Analysis bridge | `xenbr1`, per-VLAN `172.16.<vlan>.0/24` | — |

### How `sandboxd` is started

**There is no systemd unit.** It runs in the foreground, logs to stderr via
`logging.basicConfig`, and **must have its environment file sourced first** —
`Settings.from_env` raises `SystemExit` if `SANDBOXD_API`, `WORKER_TOKEN` or
`SANDBOXD_TOTAL_MIB` is unset, so the bare module invocation exits at once and
looks like a broken install.

```bash
cd /root/drakvuf-multios-sandbox
set -a; . /etc/sandboxd/sandboxd.env; set +a
.venv-sandboxd/bin/python -m sandboxd.daemon
```

| Fact | Value | Confirmed |
|---|---|---|
| Env file | `/etc/sandboxd/sandboxd.env`, mode 600 | 2026-08-26 |
| Virtualenv | `.venv-sandboxd` inside the checkout | 2026-08-26 |
| Logging | stderr on the terminal — **no journal, no logfile** | 2026-08-27 |

To keep a log for later inspection, start it under `tee`; nothing does this for
you:

```bash
… -m sandboxd.daemon 2>&1 | tee -a /var/log/sandboxd/$(date +%Y%m%d-%H%M).log
```

### Capacity — what actually binds

From §F6d and §F7c of `docs/runbooks/09-verify-sandboxd-and-console.md`:

    memory   20479 - 8192 Dom0  ->  12082 free / 2198 per clone  =  5 clones
    cpu      12 - 6 Dom0        ->   6 pCPU    / 1 vCPU per clone =  6 clones

**Memory binds first: 5 concurrent analyses.** `SANDBOXD_MAX_CLONES` is
currently **2**, well under both.

**One Dom0 core is saturated per concurrent trace** — a single DRAKVUF event
loop, measured at 99.x% of 600% with one trace and ~197% with two. Five cores
idle throughout. This is a serialisation bound: adding Dom0 vCPUs does nothing,
and the only lever is fewer events, not faster handling of them.

> **Unmeasured, and the reason `10-tune-nested-cpu.md` exists:** those 12 Xen
> pCPUs sit on **8 physical P-cores**, so at least four cores carry two Xen
> pCPUs. `affinity: 0-15` is a set, not a placement — Xen cannot see the
> sharing and cannot schedule around it.

## 1.3 CT 102 `platform`

| Fact | Value | Confirmed |
|---|---|---|
| Container | Debian 13, **unprivileged**, `nesting=1` | 2026-08-22 |
| Resources | 2 cores, 4096 MiB, 512 swap | 2026-08-22 |
| Services | Postgres 17 (UTF-8 cluster), MinIO, FastAPI | 2026-08-26 |
| Listeners | **8443** mutual-TLS (worker channel), **8000** behind cloudflared (browser) | 2026-08-26 |
| Source | `/opt/platform/src/platform`, venv `.venv`, user `platform` | 2026-08-26 |

> **Two uvicorn processes over the same app**, so the console relay's
> in-process registry differs between them: both ends of a console session must
> reach the *same* listener, which is why `SANDBOXD_CONSOLE_API` exists.

## 1.4 Per-OS names

Moved out of `CLAUDE.md` on 2026-08-27. Note `profiles/linux.json` for Ubuntu —
the filename was never renamed with the rest of the `linux` → `ubuntu` pass.

| | Ubuntu | Android | Windows |
|---|---|---|---|
| Golden domain | `ubuntu` | `android` | — |
| Sandbox domain | `ubuntu_sandbox` | `android_sandbox` | `windows_sandbox` (LV only) |
| LibVMI profile | `profiles/linux.json` | `profiles/android.json` | — |
| Saved state | `state/ubuntu_sandbox.bak` | `state/android_sandbox.bak` | — |
| Guest staging | `/home/carlos/Desktop/` | `/data/local/tmp/` | — |
| Injection PID | 1415 | 3174 | — |
| Clone LV size | 64G | 32G | — |
| Sample dirs | `/malware_{incoming,processing,finished}/ubuntu` | `…/android` | `…/windows` |

Shared by all three: volume group `vg-root`, analysis bridge `xenbr1`.

`profiles/*.json` and `state/*.bak` are **not git-tracked** — a fresh checkout
has neither.

## 1.5 What is evidenced, and what is not

| Target | Status | Confirmed |
|---|---|---|
| Ubuntu pipeline | evidenced end to end | 2026-08-26 |
| Android — native ELF path | evidenced end to end | 2026-08-17 |
| Android — APK install + `am start` | **implemented, never run on Dom0** | 2026-08-17 |
| Windows | design contract only, no execution evidence. Only clean installation + Chrome, Office and Windows Defender disabled. windows_sandbox lv created | — |
| `sandboxd` | evidenced against real `xl`/`drakvuf` | 2026-08-26 |
| Live console | evidenced; off by default on both sides | 2026-08-27 |
| Artifact ZIP downloads | implemented + tested here, **never run on the deployment** | 2026-08-27 |

---

# 2. Superseded facts — do not cite these

Each left-hand value appears in a document that is still accurate *as dated
evidence*. Runbooks are append-only, so the stale value stays where it is and
is corrected here instead.

| Stale value | Where it appears | Actual value |
|---|---|---|
| `dom0_max_vcpus=8` | `09-verify-…:735` | **`=6`**, changed at `09-verify-…:2046` and verified by §F7 |
| `cores: 20` for VM 101 | `09-verify-…:1949` | **12** |
| `drakvuf 6.8.0` | `05-deploy-…:266` | that is the **kernel version** of the host *named* `drakvuf`. DRAKVUF is `v1.1-git…` |
| `/root/sandbox_project` | every runbook | **`/root/drakvuf-multios-sandbox`** |
| `journalctl -u sandboxd` | — | **no systemd unit exists.** It runs in the foreground and logs to stderr |
| `docs/android-drakvuf-automation-checklist.md` | older docs | split into `docs/checklists/{android,ubuntu,windows,platform}.md` |
| `linux.cfg`, `linux_sandbox.cfg` | older docs | `misc/ubuntu.cfg`, `misc/ubuntu_sandbox.cfg` |
| `clone-ubuntu.pl` | older docs | `automation/clone.pl`, shared by all three OS pipelines |
| unnumbered runbook filenames | pre-2026-08-27 links | now `NN-<name>.md`, numbered oldest to newest |

---

# 3. Derived from the repository

<!-- BEGIN GENERATED -- scripts/gen-current-state.py -->

*Derived from the repository. Do not edit by hand — run `scripts/gen-current-state.py`.*

### Runbooks, oldest to newest

**`Executed` counts pasted host prompts, not what the document says about itself.** Status banners are written before execution and are often never updated; a ⚠ means the banner and the evidence disagree and the banner should be corrected at the source.

| Runbook | Date | Executed | Note |
|---|---|---|---|
| `01-verify-user-placeholder.md` | 2026-08-08 | **yes** — 18 prompt(s) |  |
| `02-deploy-repo-relative-paths.md` | 2026-08-09 | **yes** — 27 prompt(s) |  |
| `03-rebuild-android-sandbox.md` | 2026-08-11 | **yes** — 5 prompt(s) |  |
| `04-deploy-network-isolation.md` | 2026-08-11 | **yes** — 16 prompt(s) |  |
| `05-deploy-terminal-chains.md` | 2026-08-12 | **yes** — 115 prompt(s) |  |
| `06-verify-android-isolation.md` | 2026-08-14 | **yes** — 76 prompt(s) |  |
| `07-verify-android-mvp.md` | 2026-08-17 | **yes** — 26 prompt(s) |  |
| `08-deploy-platform-lxc.md` | 2026-08-22 | **yes** — 58 prompt(s) |  |
| `09-verify-sandboxd-and-console.md` | 2026-08-26 | **yes** — 44 prompt(s) |  |
| `10-tune-nested-cpu.md` | 2026-08-27 | no |  |

### How components are started

| Component | Command | Service |
|---|---|---|
| `sandboxd` | **source the env file first**, then `python -m sandboxd.daemon` in the foreground — see §1.2 for the exact Dom0 invocation. Exits immediately without `SANDBOXD_API`, `WORKER_TOKEN`, `SANDBOXD_TOTAL_MIB`. | **no systemd unit anywhere in the repo** |
| legacy pipeline | `run_analysis-android.sh`, `run_analysis-ubuntu.sh` | bash, invoked by an operator |

### Environment read by `sandboxd.daemon`

`SANDBOXD_API`, `SANDBOXD_CACERT`, `SANDBOXD_CLIENT_CERT`, `SANDBOXD_CLIENT_KEY`, `SANDBOXD_CONSOLE_API`, `SANDBOXD_CONSOLE_ENABLED`, `SANDBOXD_LOG_LEVEL`, `SANDBOXD_MAX_CLONES`, `SANDBOXD_MAX_SLOTS`, `SANDBOXD_PLUGINS`, `SANDBOXD_TOTAL_MIB`, `SANDBOXD_WORKER_ID`, `WORKER_TOKEN`

### Repository size

| | |
|---|---|
| sandboxd modules | 14 |
| test files | 12 sandboxd, 14 platform |
| documents under `docs/` | 28 |
| HEAD | `976cbbc` runbook 10: is Dom0 CPU-starved, and can L0 do anything about it |
| branch | `master` |

<!-- END GENERATED -->