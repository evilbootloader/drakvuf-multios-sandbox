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

> **The lab moved to bare metal on 2026-08-28 and Proxmox was erased.** That
> invalidated more facts in one day than everything before it combined — the
> Dom0 hostname, its OS, its CPU and memory totals, the DRAKVUF build, the
> storage pool, and the platform's entire form. **§2a lists them.** Runbooks
> 01–10 are append-only and still describe the nested lab correctly *as dated
> evidence*, so a value read there is not wrong; it is answering a question
> about a machine that no longer exists.

> **Attested is not the same as pasted.** Rows sourced from the operator say so
> in the Confirmed column. They are real facts — the hand-maintained sections
> exist precisely for what cannot be derived — but the derived table in §3
> counts pasted host prompts, so an attested run still leaves its runbook
> reading `no`. **A blank `EVIDENCE` block never proves an operation did not
> happen.** Ask before reporting one as undone.

---

# 1. Capabilities

## 1.1 The host — bare metal since 2026-08-28

**There is no L0.** Proxmox was erased in the migration
(`docs/runbooks/12-baremetal-trial.md` §A1b). Xen boots the physical machine
directly, and the layer that used to sit beneath it is gone — along with VM 101,
CT 102, and everything `qm` and `pct` could do.

| Fact | Value | Confirmed |
|---|---|---|
| Hostname | **`dom0`** — was `drakvuf`, which was the nested VM's name | 2026-08-28 |
| OS | **Ubuntu Server 24.04 (noble)**, not 22.04 — chosen to match the Xen build the operator had | 2026-08-28 |
| Kernel | `6.8.0-138-generic #138-Ubuntu`. The nested host ran `#138~22.04.1`: **same version number, different build**, so a matching `uname -r` is not evidence that nothing changed | 2026-08-28 |
| LAN address | `192.168.1.6` — `.10` now belongs to the platform DomU | 2026-08-28 |
| CPU | **hybrid Intel**, 32 logical | 2026-08-27 |
| P-cores | host CPU **0–15** — 8 physical, SMT ×2 (`/sys/devices/cpu_core/cpus`) | 2026-08-27 |
| E-cores | host CPU **16–31** — 16 physical, no SMT (`/sys/devices/cpu_atom/cpus`) | 2026-08-27 |
| pCPUs Xen sees | **24, not 32** — `smt=0` parks all eight P-core siblings, leaving 8 P + 16 E. `threads_per_core 1`, `cores_per_socket 24` | 2026-08-28 |
| Memory | `xl info total_memory` **32605** | 2026-08-28 |
| Volume group | `vg-root` | 2026-08-28 |
| Storage | LVM thin pool **`vg-root/thinpool`**, 1.38 TiB, inside a VG of <1.82 TiB | 2026-08-28 |
| Thin pool autoextend | **configured** — it was unset under Proxmox | 2026-08-28 |
| Non-thin root | `ubuntu-lv`, 250 G, outside the pool | 2026-08-28 |

> **The thin pool is still a shared failure domain, and its blast radius grew.**
> Under Proxmox the artifact store and the golden images shared `pve/data`. They
> now share `vg-root/thinpool` with **every clone snapshot as well**, so filling
> the artifact store can stop the analysis lab exactly as it could before.
> Autoextend is configured now, but the pool still cannot grow past the VG.
> Watch `data_percent`, and treat MinIO retention as a capacity question and not
> only a GDPR one (DRAFT-041, DRAFT-022).

> **Gone with Proxmox, and no longer facts about this host:** `nested=Y ept=Y`
> in `/etc/modprobe.d/kvm-intel.conf`, and the never-answered
> `enable_shadow_vmcs` / `enable_apicv` questions. Those were about nesting, and
> there is no longer a hypervisor underneath Xen to tune.

## 1.2 Dom0 — the Xen host

| Fact | Value | Confirmed |
|---|---|---|
| Xen | **4.20.1**, the *noble* `.deb` from drakvuf-builds | 2026-08-28 |
| DRAKVUF | **`v1.1-da982ab`**, built from source from `lfreijo/drakvuf` branch `memdump` | 2026-08-28 |
| DRAKVUF provenance | **CONTRADICTED, 2026-09-04.** A failing run printed `DRAKVUF injector v1.1-52df0bc` — the *packaged* build, not `da982ab`. `injector` and `drakvuf` are separate binaries, so this proves the toolchain is mixed or the row above is wrong, not which. Settle with `drakvuf --version` and `injector --version` on Dom0; `git -C ~/drakvuf log -1` still answers what the source tree is | 2026-09-04 |
| Xen boot line | `dom0_mem=8192M,max:8192M dom0_max_vcpus=6 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0 sched=credit no-real-mode edd=off` — the last two were added by the bare-metal install | 2026-08-28 |
| Dom0 resources | 8192 MiB, 6 vCPUs | 2026-08-28 |
| CPU partition **as deployed** | Dom0 → the first six **online** pCPUs **0,2,4,6,8,10**; clones → **12,14**; platform → **16,17**. 14 of 24 online pCPUs idle | 2026-08-29 |
| CPU partition **as committed, NOT YET APPLIED** | Dom0 → all eight P-cores **0,2,4,6,8,10,12,14** (needs `dom0_max_vcpus=8` and a **reboot**); clones → **16-27**; platform → **28-31**. Source of truth is **`sandboxd/config.py`**; `automation/platform.env` and `misc/*.cfg` are generated from it by `scripts/gen-xen-configs.py` | 2026-08-31 |
| Scheduler | Credit**1** (`sched=credit`), not Xen 4.20's default Credit2 | 2026-08-27 |
| Python | **UNCONFIRMED** — noble ships 3.12, but nobody has run `python3 -V` here. `platform/requirements.txt` pins `websockets==16.1.1` on the strength of "Dom0's Python is older", which was written when Dom0 was jammy | — |
| Repo checkout | `/root/drakvuf-multios-sandbox` | 2026-08-19 |
| Volume group | `vg-root` | 2026-08-28 |
| Analysis bridge | `xenbr1`, per-VLAN `172.16.<vlan>.0/24` | — |

> **`0–5` is not the same set as `0,2,4,6,8,10`, and the difference bit once
> already.** `dom0_vcpus_pin` hands Dom0 the first six *online* pCPUs, and under
> `smt=0` the online P-cores are the evens. A range written for the nested
> topology — where Xen saw a contiguous `0-11` — resolves on this host to a
> sparse set that overlaps Dom0. That is exactly how `cpus = "6-11"` in the
> clone configs came to mean `{6,8,10}`, every one of them Dom0's.
> Confirm with `xl cpupool-list -c` before changing either value.

> ## WATCH — `drakvuf-bundle` can silently rewrite the Xen boot line
>
> It installs `/etc/default/grub.d/xen.cfg`, which **computes** Dom0's resources
> and replaces what was set by hand, on any `update-grub` — including one run
> for an unrelated reason. Observed proposing `CPU core(s): 12` and
> `Memory: 16302 MB` against this host's 6 vCPU / 8192 MiB. It did **not** win
> on the 2026-08-28 boot, but nothing stops it winning on the next one.
> After any `update-grub`, re-read `xl info xen_commandline`.

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

Recomputed 2026-08-29 for bare metal, against `xl info total_memory 32605`:

    memory   32605 - 8192 Dom0 - 2048 platform -> 22365 / 4246 per clone = 5
    cpu      pinned to pCPUs 12,14             ->  1 vCPU per clone      = 2

**CPU binds first: 2 concurrent analyses**, and `SANDBOXD_MAX_CLONES` is
already **2**, so the two agree. The bound moved for two reasons that both
landed on 2026-08-29 — the templates went to `memory = 4096` (22.04's desktop
idles near 2 GB and swapped continuously at 2048), and `misc/*_sandbox.cfg`
went to `cpus = "12,14"`, the only two P-cores Dom0 does not hold.

**After the 2026-08-31 repartition, once applied**, the CPU bound is gone and
memory binds again:

    memory   32605 - 8192 Dom0 - 4096 platform -> 20317 / 4246 per clone = 4
    cpu      pinned to pCPUs 16-27             -> 1 vCPU per clone       = 12

**4 concurrent analyses, memory-bound.** `SANDBOXD_MAX_CLONES` may go to 4;
raising it further needs memory, not cores. The trade was deliberate: twelve
E-cores for clones cost −0.5% throughput (`12-baremetal-trial.md` H2, inside the
0.6% run-to-run spread) and the platform's extra 2048 MiB cost the fifth clone.

> **`SANDBOXD_MAX_CLONES` must not be raised before the reboot.** Until
> `dom0_max_vcpus=8` is live, the committed `cpus = "16-27"` is still correct
> but Dom0 holds only `0..10` — the partition is consistent either way. It is
> the *memory* figure that changes underfoot: at `2048` for the platform the
> pool affords 5 clones, at `4096` only 4, and `sandboxd` reads the real
> `xl info` rather than this table.

> **Superseded, and kept only to explain older figures:** the nested host read
> `memory 20479 - 8192 Dom0 -> 12082 / 2198 per clone = 5 clones` against
> `cpu 12 - 6 Dom0 = 6 clones`, so memory bound at 5. Both halves of that are
> now wrong — the memory total was L0's allocation to VM 101, and the pCPU
> count was QEMU's flat 12.

**One Dom0 core is saturated per concurrent trace** — a single DRAKVUF event
loop, measured at 99.x% of 600% with one trace and ~197% with two. Five cores
idle throughout. This is a serialisation bound: adding Dom0 vCPUs does nothing,
and the only lever is fewer events, not faster handling of them.

> **`10-tune-nested-cpu.md`'s question is closed, and the answer was "no".**
> That runbook existed because 12 Xen pCPUs sat on 8 physical P-cores and
> `affinity: 0-15` was a set rather than a placement, so Xen could not see the
> sharing. Bare metal removed the ambiguity — Xen now enumerates the real
> topology — and `12-baremetal-trial.md` Part H then measured **three CPU
> placements within 0.6% of each other**. Dedicated cores removed run-to-run
> outliers and made the guest noticeably more responsive; they did not move
> throughput. Placement is a latency lever here, not a throughput one.

## 1.3 The `platform` DomU

Rebuilt 2026-08-28 as a Xen PVH domain, replacing CT 102. **It was built empty**
— `ct/102`'s backup was encrypted with a key that lived only on the erased
Proxmox host, so job history and every stored artifact are gone
(`platform-domu.md` FINDING E-1). Postgres came from the migrations, MinIO
started empty, and one server certificate was reissued from the workstation CA.

| Fact | Value | Confirmed |
|---|---|---|
| Domain | Debian 13, **PVH**, `misc/platform.cfg` | 2026-08-28 |
| Resources **as deployed** | **2048 MiB**, 2 vCPU, `cpus = "16-17"` (E-cores) | 2026-08-28 |
| Resources **as committed, NOT YET APPLIED** | **4096 MiB**, 4 vCPU, `cpus = "28-31"`. Needs `xl shutdown platform && xl create misc/platform.cfg` — memory and vCPU count are boot-time properties, unlike affinity | 2026-08-31 |
| Address | `192.168.1.10` — deliberately unchanged, so `SANDBOXD_API`, `SANDBOXD_CONSOLE_API` and the mTLS certificates all still resolve | 2026-08-28 |
| Boot | **direct kernel**, from `/var/lib/xen/platform/` on Dom0 | 2026-08-28 |
| Disks | `vg-root/platform` 20 G root, `vg-root/platform_data` 256 G at `/srv/minio` | 2026-08-28 |
| Services | Postgres 17 (UTF-8 cluster), MinIO, FastAPI | 2026-08-28 |
| Listeners | **8443** mutual-TLS (worker channel), **8000** behind cloudflared (browser), 9000 MinIO, 9001 MinIO console (loopback) | 2026-08-28 |
| Source | `/opt/platform/src/platform`, venv `.venv`, user `platform` | 2026-08-26 |

> **A DomU reservation is not a cgroup cap.** CT 102's 4096 MiB was a ceiling
> that unused memory stayed available beneath; a DomU's is taken from the clone
> pool permanently. That is why it was halved on 2026-08-28, and why raising it
> costs concurrent analyses directly.
>
> **Raised back to 4096 on 2026-08-31, with the cost accepted rather than
> overlooked:** at `4246` MiB per clone the free pool goes `22365 → 20317`,
> which is **4 concurrent clones instead of 5**. Drop back to 2048 if a fifth
> matters more. Note the arithmetic changed under this decision — when the
> platform was halved, a clone cost `2198`, and at that size the same raise
> would have cost nothing.

> **Direct kernel boot means Dom0 holds the kernel.** `apt upgrade` inside the
> guest updates `/boot` and the modules but **not what Xen boots**, so the
> domain silently comes back on the old kernel against new modules. The
> re-copy procedure is `platform-domu.md` §F2 and it is a real recurring cost.

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
| Injection PID | **1** — anchor `systemd`; samples run as root, 2026-08-29 | **3251** — anchor is a backgrounded `ping` to loopback. Reverted from PID 1 on 2026-08-31: Android's `init` gives `app_process64` no runtime environment, which the APK path needs. **Re-derive after every re-save** | **4696** — `sandboxd/stages.py`, from the `.bak`; same re-save cost as Android |
| Clone LV size | inherited: **1 T** | inherited: **128 G** | — |
| Sample dirs | `/malware_{incoming,processing,finished}/ubuntu` | `…/android` | `…/windows` |

Shared by all three: volume group `vg-root`, analysis bridge `xenbr1`.

`profiles/*.json` and `state/*.bak` are **not git-tracked** — a fresh checkout
has neither.

## 1.5 What is evidenced, and what is not

| Target | Status | Confirmed |
|---|---|---|
| Ubuntu pipeline | evidenced end to end | 2026-08-26 |
| Android — native ELF path | evidenced end to end | 2026-08-17 |
| Android — APK install + `am start` | **evidenced through the platform** — see the bare-metal table below | operator, 2026-08-29 |
| Windows | design contract only, no execution evidence. Clean install plus Chrome and Office, Defender disabled; `windows_sandbox` LV created | — |
| `sandboxd` | evidenced against real `xl`/`drakvuf` | 2026-08-26 |
| Live console | evidenced; off by default on both sides | 2026-08-27 |
| Artifact ZIP downloads | implemented + tested here, **never run on the deployment** | 2026-08-27 |

### On bare metal, since 2026-08-28

| Target | Status | Confirmed |
|---|---|---|
| `ubuntu_sandbox` restore | **evidenced** — `xl restore` succeeded and `vmi-process-list` read the guest through `profiles/linux.json` | 2026-08-28 |
| DRAKVUF throughput | **evidenced** — six configurations, `12-baremetal-trial.md` Part H | 2026-08-28 |
| platform DomU serving | **evidenced** — five listeners, cloudflared connected, Access verified | 2026-08-28 |
| `sandboxd` registered | **yes** | operator, 2026-08-29 |
| **End-to-end analysis through the platform** | **yes, on both Ubuntu and Android** | operator, 2026-08-29 |
| Android APK — install + `am start` | **yes, successful through the platform.** This closes the last "implemented but never run" item on the Android track | operator, 2026-08-29 |
| Job history and stored artifacts from before the migration | **lost** — CT 102's backup key died with the Proxmox host | 2026-08-28 |

> **Attested by the operator, not by pasted output — and that distinction is the
> point.** `platform-domu.md` EVIDENCE G is still blank and so is EVIDENCE E's
> "end-to-end job through the browser", because nobody pasted the run into them.
> The derived table in §3 counts pasted prompts, so **work that really happened
> reads as `no` until someone records it.** That is the same failure mode as a
> stale banner, arriving from the other direction, and it is why runbook 13
> cannot be filed yet.

---

# 2. Superseded facts — do not cite these

Each left-hand value appears in a document that is still accurate *as dated
evidence*. Runbooks are append-only, so the stale value stays where it is and
is corrected here instead.

## 2a. Superseded by the bare-metal migration, 2026-08-28

**The single largest source of stale facts in this repository.** Everything
below was true of the nested lab and is written down in documents that remain
accurate as dated evidence.

| Stale value | Actual value |
|---|---|
| Dom0 hostname `drakvuf` | **`dom0`**. `drakvuf` was the *nested VM's* name; there is no VM |
| `pve1`, VM **101**, CT **102**, `qm`, `pct`, `vzdump` | **all gone.** Proxmox was erased; there is no L0 |
| L0 → L1 → L2, three layers | **two.** Xen boots the metal; guests are L1 |
| Dom0 on Ubuntu **22.04 (jammy)**, kernel `6.8.0-136-generic` | **24.04 (noble)**, `6.8.0-138-generic #138-Ubuntu` |
| DRAKVUF `v1.1-git20260511151619+52df0bc8-1` | **`v1.1-da982ab`**, built from source. Every measurement before 2026-08-28 was taken on the other build |
| `total_memory 20479`, `free_memory 12082` | **32605**; free depends on what is running |
| `nr_cpus 20`, or 12 | **24** online under `smt=0` — 8 P + 16 E |
| Dom0 pCPUs **`0–5`** | **`0,2,4,6,8,10`** — the first six *online* pCPUs, and under `smt=0` those are the evens |
| Thin pool `pve/data`; autoextend unset | **`vg-root/thinpool`**, 1.38 TiB, autoextend configured |
| The platform is an unprivileged **LXC**, 4096 MiB | a Xen **PVH DomU**, 2048 MiB, `misc/platform.cfg` |
| Dom0 at `192.168.1.10` | Dom0 is **`.6`**; `.10` is the platform DomU, deliberately kept |
| `10-tune-nested-cpu.md`'s open question | **closed** by `12-baremetal-trial.md` Part H: placement moves latency, not throughput |

## 2b. Superseded for other reasons

| Stale value | Where it appears | Actual value |
|---|---|---|
| `dom0_max_vcpus=8` | `09-verify-…:735` | **`=6`**, changed at `09-verify-…:2046` and verified by §F7 |
| `cores: 20` for VM 101 | `09-verify-…:1949` | **12** — and VM 101 itself no longer exists, see §2a |
| `drakvuf 6.8.0` | `05-deploy-…:266` | that is the **kernel version** of the host *named* `drakvuf`. DRAKVUF is `v1.1-git…` |
| `/root/sandbox_project` | every runbook | **`/root/drakvuf-multios-sandbox`** |
| `journalctl -u sandboxd` | — | **no systemd unit exists.** It runs in the foreground and logs to stderr |
| `docs/android-drakvuf-automation-checklist.md` | older docs | split into `docs/checklists/{android,ubuntu,windows,platform}.md` |
| `linux.cfg`, `linux_sandbox.cfg` | older docs | `misc/ubuntu.cfg`, `misc/ubuntu_sandbox.cfg` |
| `clone-ubuntu.pl` | older docs | `automation/clone.pl`, shared by all three OS pipelines |
| unnumbered runbook filenames | pre-2026-08-27 links | now `NN-<name>.md`, numbered oldest to newest |
| Injection PID `1415`, `1490` | `baremetal-trial.md` D5.4/D5.7, `09-verify-…` | **`1`** — the anchor is systemd. `nano` and `gedit` are both unschedulable without guest input, so neither can be injected into unattended |
| Android injection PID `3163`, `3164`, `3174` | `docs/checklists/android.md` §1.4/§1.5 | **`3251`** — same `ping`-to-loopback anchor those PIDs refer to, re-read after a later re-save. Each value is valid only for the `.bak` it came from |
| **"Android anchors on `init` / PID 1"** | `sandboxd/guests.py:439`, `automation/preconfig-android.sh:228`, `sandboxd/tests/test_guests.py:182`, and the *upper* half of `pipeline-android.env`'s anchor block | **Only Ubuntu does.** Android went to PID 1 on 2026-08-29 and **reverted on 2026-08-31**, because Android's `init` provides no runtime environment for `app_process64` and the APK path needs one. `pipeline-android.env:289` records the reversal and deliberately keeps the case *for* PID 1 above it, so text arguing for PID 1 there is history, not the current posture |
| `CLONE_LV_SIZE`, "Clone LV size 64G / 32G" | `pipeline-*.env`, older docs | **retired 2026-08-29.** Clones are thin snapshots and inherit the golden LV's size — 1 T for Ubuntu, 128 G for Android. `-L` never sized the clone; it forced a *thick* snapshot whose exception store came from VG free space |
| `required_mib: 2198`, `memory = 2048` | `platform.md`, older runbooks | **4246** / `memory = 4096` for both templates as of 2026-08-29 |

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
| `11-pbs-backups.md` | 2026-08-27 | **yes** — 19 prompt(s) |  |
| `12-baremetal-trial.md` | 2026-08-27 | **yes** — 32 prompt(s) |  |
| `13-verify-egress-modes.md` | 2026-08-31 | **yes** — 21 prompt(s) |  |

### How components are started

| Component | Command | Service |
|---|---|---|
| `sandboxd` | **source the env file first**, then `python -m sandboxd.daemon` in the foreground — see §1.2 for the exact Dom0 invocation. Exits immediately without `SANDBOXD_API`, `WORKER_TOKEN`, `SANDBOXD_TOTAL_MIB`. | unit: fakenet.service |
| legacy pipeline | `run_analysis-android.sh`, `run_analysis-ubuntu.sh` | bash, invoked by an operator |

### Environment read by `sandboxd.daemon`

`SANDBOXD_ALLOW_DIRECT`, `SANDBOXD_API`, `SANDBOXD_CACERT`, `SANDBOXD_CLIENT_CERT`, `SANDBOXD_CLIENT_KEY`, `SANDBOXD_CONSOLE_API`, `SANDBOXD_CONSOLE_ENABLED`, `SANDBOXD_LOG_LEVEL`, `SANDBOXD_MAX_CLONES`, `SANDBOXD_MAX_SLOTS`, `SANDBOXD_PLUGINS`, `SANDBOXD_TOTAL_MIB`, `SANDBOXD_WORKER_ID`, `WORKER_TOKEN`

### Repository size

| | |
|---|---|
| sandboxd modules | 16 |
| test files | 16 sandboxd, 15 platform |
| documents under `docs/` | 36 |

<!-- END GENERATED -->