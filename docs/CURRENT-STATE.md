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
| Xen | **4.20.1, built from source with the altp2m deadlock fix** — drakvuf's `xen` submodule at `RELEASE-4.20.1` plus `automation/xen-altp2m-pause-vcpu.patch`, the 4.20.1 backport of the fix [posted to xen-devel](https://lists.xenproject.org/archives/html/xen-devel/2026-10/msg01125.html). Packaged by Xen's own `make debball` as **`xen-upstream 4.20.1`**, which installs the tools under `/usr/local`. `xl info`: `cc_compile_date Mon Oct 19 22:19:01 UTC 2026`, `cc_compile_by user`. The drakvuf-builds `xen-hypervisor` package is removed but not purged (`dpkg -l`: `rc`). `make xen` is the procedure; the 2026-10-19 install was done by hand, and the target ran for the first time on 2026-11-04 (two rows down) | 2026-10-20 |
| Xen, 2026-11-01 to 2026-11-04 | **A development build of the operator's `drakvuf-dev/xen` branch `rdtsc-poc`, not `make xen`'s.** The RDTSC search installs its candidates with the same configure/`debball` sequence: `xl info` `cc_compile_date Sun Nov  1 17:00:10 UTC 2026`, then `Mon Nov  2 07:23:55 UTC 2026` (the last search build), boot line with `rdtsc-poc=1`. It was the compensation of `docs/architecture/rdtsc-poc.md` without `RDTSC_USER_PURE` and without the guest identity (`docs/architecture/guest-identity.md`); `make xen` adds both. **Replaced on 2026-11-04 by the row below** | 2026-11-04 |
| Xen, since 2026-11-04 | **`make xen`'s build, the first time the target has run** (`docs/runbooks/18-deploy-with-makefile.md` §2, EVIDENCE 2b and 2c): `xen-upstream 4.20.1` from `drakvuf/xen` at `RELEASE-4.20.1` with `xen-altp2m-pause-vcpu.patch`, `xen-rdtsc-poc.patch` and `xen-guest-identity.patch`, the identity's strings written by `scripts/xen-identity.py patch-xen`, OVMF from tianocore's edk2 and the qemu-xen CD-ROM patch; built on the plain kernel pinned to the E-cores (`taskset -c 16-31`), 13:07 on the `.deb`. `xl info`: `cc_compile_date Wed Nov  4 13:06:39 UTC 2026`, `cc_compile_by root`, `xen_commandline` the configured line plus `rdtsc-poc=1 no-real-mode edd=off`. `xen-rdtsc-poc.service` `active (exited)` with its `ExecStartPost` check passing, `xl dmesg` `RDTSC_POC: compensation enabled`. `xenstored.service` enabled by the target (the one `Created symlink`); `xencommons.service` failed as on every Xen boot, harmless (TROUBLESHOOTING, "`xen-rdtsc-poc.service` — `Dependency failed`"). The platform is not started by any unit: `xl create misc/xen-vms/platform.cfg` after each boot, 20 s to four `active`. `drakvuf/xen/dist/xen-upstream-4.20.1.deb` is now the package the evasion searches keep and put back | 2026-11-04 |
| Why the fix | Without it, `--parallel-events` deadlocks Dom0: a vm_event response switching a vCPU's altp2m view waits, holding the altp2m list lock, for that vCPU to be descheduled, while a log-dirty fault on a third vCPU holds the p2m lock and waits for the altp2m list lock. `TROUBLESHOOTING.md` has the symptom | operator, 2026-10-19 |
| Dom0 checkout of this repository | **At `2b433f4`, the tip of `origin/master`, since 2026-11-04** (`docs/runbooks/18-deploy-with-makefile.md` §1.1, EVIDENCE 1.1c): index and tracked files reset, every submodule at its pin (`drakvuf` `3c3b73a6`, its `libvmi` `ab06c1f`, `drakvuf/xen` `RELEASE-4.20.1`, `sandboxd/data/capa-rules` `v10.0.0-2`, `falco-rules` `falco-rules-5.2.0`). **Two files are modified on purpose and must NOT be committed**: `misc/xen-vms/ubuntu_sandbox.cfg` and `windows_sandbox.cfg` — the saved states of 2026-11-02 were made with Dom0's copies, which carry `shadow_memory = 128`, each guest's `mac=` and the identity's `smbios`, `smbios_firmware`, `acpi_firmware`, `xen_platform_pci = 0` and `device_model_args_hvm` lines; the tracked copies have `32` and none of those, and committing Dom0's would publish the identity (`docs/architecture/guest-identity.md`). Dom0's 2026-11-02 copies were put back the same day (step 1.1e, EVIDENCE 1.1e: five identity lines each, `shadow_memory = 128`, VNC on loopback). `Makefile.local` present and ignored (`RSA_KEY`, `SANDBOX_WEB`, `ANALYSIS_VM_USER := carlos`, the password). `/etc/sandboxd/sandboxd.env` gained `SANDBOXD_REPO_ROOT`, `SANDBOXD_ANALYSIS_USERNAME=carlos`, `SANDBOXD_INJECTION_PID_UBUNTU=1` and `SANDBOXD_INJECTION_PID_WINDOWS=4756` the same day (EVIDENCE 1.1a) — the values the retired `config.py` carried. **What Dom0's `master` was until then**: `e0e368b` "Changes", a merge commit of that morning, the 59th local commit in a chain of "Changes" and merges of `origin/master`, none in this repository; it kept the pre-2026-11-03 Makefile (`:=` values, the operator's public key in the file, no `Makefile.local`), tracked `.venv-sandboxd/` (4,241 files) and `misc/iso/cidata/user-data`, and held the four Makefile-written cfgs under the **skip-worktree** bit, so `git status` read clean while they differed. All of it is kept on `dom0-local-2026-11-02` and `dom0-local-2026-11-04`, both at `e0e368b`; the venv and `user-data` stay on disk, ignored. `git reset --hard origin/master` **fails** on that state and would have deleted the venv (TROUBLESHOOTING, "`git reset --hard origin/master` on Dom0 refused: a cfg is `not uptodate`"). The startup call to `network-setup.sh` is in the deployed daemon (`grep -c` 1), `DRAKVUF_INPUT` exists with the responder DROPs on `xenbr0`, and three `xenbr1.<n>` interfaces are up (2026-11-03) | 2026-11-04 |
| DRAKVUF | **Built from the submodule, `/root/drakvuf-multios-sandbox/drakvuf`, at `3c3b73a6` with its libvmi at `ab06c1f`, by `make sandboxd` on 2026-11-04** (`docs/runbooks/18-deploy-with-makefile.md` §5): `/usr/local/bin/drakvuf` dated 13:45 that day, `volatility3` switched to `7fe200e5` (PR #650) by the target, the Ubuntu job of §5b `completed (clean)` on it. Until then: built at `6f37d02` with the two files of `47baf853` copied in uncommitted — the same tree as `47baf853` — and its libvmi at `c97816c`. `/usr/local/bin/drakvuf` is dated 2026-11-02 18:59, `/usr/local/lib/libvmi.so.0.0.15` 09:08, still `c97816c`. Evidenced by `git log` and `git status` in Dom0's checkout, by `sha256sum` of `win.cpp` and `win.h` against `47baf853`'s, and by a string only `47baf853` has in `drakvuf`: `The syscall dispatcher is not in the kernel profile`. **Until Dom0 pulls, its `git log` names `6f37d02`** and `git status` shows `src/plugins/syscalls/win.cpp` and `win.h` modified. **The banner said `v1.1-3886574`, which was stale** — next row; `make sandboxd` reconfigures the build directory since 2026-11-04, so the banner is to be re-read after that build | 2026-11-04 |
| DRAKVUF provenance | **The banner's version is the commit the build directory was CONFIGURED at, not the one it was built from.** `meson.build` runs `git describe` at configure time; `drakvuf/build` was configured 2026-10-20 18:11, at `3886574`, and every `ninja` build since keeps that string. **There is no `--version` option** (`drakvuf: unrecognized option '--version'`) — the banner is the first line either binary prints. Settle provenance with `git -C /root/drakvuf-multios-sandbox/drakvuf log -1` and a string only the expected commit has, or `meson setup --reconfigure` before building. The 2026-09-04 contradiction (`injector v1.1-52df0bc` against `da982ab`) concerned the binaries these replaced | 2026-10-24 |
| DRAKVUF source | **One tree.** `~/drakvuf` (`lfreijo/drakvuf` branch `memdump`), which this file named as the build tree until 2026-09-26, **does not exist on Dom0** (2026-10-24). The binaries come from `/root/drakvuf-multios-sandbox/drakvuf`, a submodule from our own fork `evilbootloader/drakvuf`, which has both `da982ab` and `52df0bc8` as ancestors | 2026-10-24 |
| DRAKVUF submodule pin | **`3c3b73a6`**, the tip of `develop` (2026-11-04): the engine's share of the 2026-11-02 security review — a Linux memdump sized by the VMA, not by the sample's number (H-1); the `refresh_shadow_copy` use-after-free, upstream `d5b220de` (H-2); caps and bounded walks in the Linux fileextractor and filetracer, the Windows fileextractor's deferred writes and libdrakvuf's ELF and VMA walks (M-3, M-4, M-5, M-7); hooks freed through libdrakvuf's deferred free under parallel events (M-6); a clean exit when the guest shuts down, upstream `3ce4088c` ported, with `ccd60cc4`, `b2f64d8d` and `3a3b69c5` applied (M-14); guest-written strings JSON-escaped (L-13); libmon breakpoints bounded by the kernel's VMA file (L-14); `configure~` removed (L-22). Its own `libvmi` is at **`ab06c1f`** on `feature/vcpu-parallel-events` (M-8: the ring is drained before deferred clears and at destroy; L-17 to L-19). `.gitmodules` names `develop` now (L-23). **Dom0 runs this pin since 2026-11-04** (`make sandboxd`, `docs/runbooks/18-deploy-with-makefile.md` §5). Before it, **`47baf853`**, the tip of `develop` until 2026-11-04. New since `26ad2e2`, the pin this row named until 2026-11-02 (`dbc7fa1` moved it to `6a3c1b0` on 2026-10-24 without this row): a Linux execproc's child is only its vfork child (`2e7960e`), fileextractor keeps a Linux process's descriptors apart (`07d3f9c`), `make_hook_id` tells Linux threads apart (`3197c74`), memdump attributes a Linux dump to its process (`6a3c1b0`), **the syscalls of 32-bit Linux processes are traced**, through `ia32_sys_call` and an i386 number table (`6f37d02`; TROUBLESHOOTING, "A 32-bit Linux sample has no syscall records"), and **Windows syscalls are hooked at the dispatcher**: one breakpoint at `KiSystemServiceCopyEnd` for nt and win32k, x64 and WoW64 processes alike, instead of one per service table entry, with returns at `KiSystemServiceExit` (`47baf853`; per-call sysret mode and 32-bit kernels keep the per-entry breakpoints). Before those: per-vCPU parallel events (`--parallel-events`), `--sysret-mode kernel`, the libmon, filetracer, fileextractor and memdump reworks, the Windows fileextractor fixes for the guest bugchecks (TROUBLESHOOTING, "The Windows guest bugchecks `0x1e`"), apimon's rework: returns through shared breakpoints, one set of hooks per DLL image instead of per process, and WoW64 processes' calls to the 64-bit ntdll; and, new since `a6e0892` (the pin until 2026-10-24), Linux syscall results read from `pt_regs->ax` (`44b6a19`), unixsocketmon on 5.15+ kernels with both ends of a socket (`bfab6ba`, `e58c13a`), and shared user mode breakpoints whose callbacks run in parallel (`7f42924`, `794e1ce`, `3d1798a`, `569bf52`). **`main` is behind it.** [PR #1](https://github.com/evilbootloader/drakvuf/pull/1) takes it into `main`, which `.gitmodules` named as the branch until 2026-11-04, so `git submodule update --remote` would have moved the pin back to `ba39156`. Its `libvmi` was at **`c97816c`** on `feature/vcpu-parallel-events` until `ab06c1f` (from `0f1de3c`: a parallel callback that clears or swaps its copy of an event acts on the registered event), which keeps upstream's ABI. `make sandboxd` builds both, libvmi with `--enable-page-cache=8192` and DRAKVUF with `-Dthreadsafety=true`. **Dom0 ran the previous tree until 2026-11-04**, built from `6f37d02` with `47baf853`'s files copied in (first row above). `26ad2e2` also committed `configure~`, a 28k-line autoconf backup, at the root of the drakvuf tree, removed in `3c3b73a6` | 2026-11-04 |
| Ubuntu clone vCPUs | **4, since 2026-11-04**: the state saved that day (`docs/runbooks/18-deploy-with-makefile.md` §6c) was saved from `ubuntu_analysis_sandbox` running with `vcpus = 4` and 8192 MiB, as `misc/xen-vms/ubuntu_sandbox.cfg` on Dom0 says (the Makefile's values), and the first job on it completed clean. Before: **3**, from the state saved 2026-10-19 22:57 (`"max_vcpus": 3` in its header, events on vCPU 0–2 in job `728fc4a8`), while `misc/ubuntu_sandbox.cfg` and `misc/ubuntu.cfg` said `vcpus = 1` — the generated copies in `misc/`, which nothing restores with (§2b). The capacity figures below assume 1 vCPU per clone and have **not** been re-derived. With more than one vCPU the trace's injection can fail — TROUBLESHOOTING, "The trace's injection fails with `Could not create argv arrays`"; not seen on the two jobs of 2026-11-04 | 2026-11-04 |
| Egress responders | `tor` and `fakenet` **active**, started by `drakvuf-egress.target`, which is **enabled**; `fakenet.service` itself is not, it comes up through the target's `Wants=`. `/etc/tor/torrc` is identical to `automation/torrc`. `make sandboxd` now installs all of it, per runbook 13 steps 4 and 6 | 2026-10-21 |
| Xen boot line, **configured** | `GRUB_CMDLINE_XEN_DEFAULT="dom0_mem=8192M,max:8192M dom0_max_vcpus=6 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0 sched=credit rdtsc-poc=1"` in **`/etc/default/grub.d/xen.cfg`**, written by `make xen` from `XEN_CMDLINE` (`automation/xen-grub.cfg`) on 2026-11-04, with the `#XEN_OVERRIDE_GRUB_DEFAULT=0` switch commented so Xen is the default entry; 9 `multiboot2` entries carry it in `grub.cfg` (one per `xen*.gz` name per kernel). Nothing sets it in `/etc/default/grub`. Until 2026-11-04 the file was the hand-edited one of 2026-10-21, without `rdtsc-poc=1` | 2026-11-04 |
| Xen boot line, **running** | **the configured line, with `dom0_mem=8192M,max:8192M`**, plus `rdtsc-poc=1` and `no-real-mode edd=off` from the bare-metal install (`xl info xen_commandline`, pasted 2026-11-03). The 6144M line this row carried until then was replaced by a reboot before 2026-11-02 — §2b | 2026-11-03 |
| Dom0 resources | **8192 MiB** (`free -m`: 7905 total, 8191 swap, 2026-11-03), 6 vCPUs (`xl list`, 2026-10-21). **Shared by the kernel, DRAKVUF, tcpdump, the daemon and, since 2026-11-03, one postprocessing child per job in its collect phase, each limited to `SANDBOXD_POSTPROCESS_MAX_MIB` (3072)** — TROUBLESHOOTING, "`sandboxd` disappears after a long trace" | 2026-11-03 |
| CPU partition **as deployed** | Dom0 → the first six **online** pCPUs **0,2,4,6,8,10**; clones → **12,14**; platform → **16,17**. 14 of 24 online pCPUs idle | 2026-08-29 |
| CPU partition **as committed, NOT YET APPLIED** | Dom0 → all eight P-cores **0,2,4,6,8,10,12,14** (needs `dom0_max_vcpus=8` and a **reboot**); clones → **16-27**; platform → **28-31**. Source of truth is **`sandboxd/config.py`**; `automation/platform.env` and `misc/*.cfg` are generated from it by `scripts/gen-xen-configs.py` | 2026-08-31 |
| Scheduler | Credit**1** (`sched=credit`), not Xen 4.20's default Credit2 | 2026-08-27 |
| Python | **3.12.3** (`python3 -V`, operator-confirmed). Old enough that the `websockets==16.1.1` pin in both requirements files still stands; new enough for `flare-capa==9.4.0`, which needs ≥3.10. The development container runs 3.14, so a wheel that resolves there is not proof it resolves here — `sandboxd/requirements.txt` says how that was checked | 2026-09-18 |
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

> ## WATCH — `/etc/default/grub.d/xen.cfg` decides the Xen boot line
>
> It came with the drakvuf-builds `xen-hypervisor` package, and its first
> version did two things, both silent:
>
> - **With the bundle installed** it sourced `drak-find-xen-defaults`, which
>   **computed** Dom0's resources and replaced what was set by hand on any
>   `update-grub` — observed proposing `CPU core(s): 12` and `Memory: 16302 MB`
>   against 6 vCPU / 8192 MiB.
> - **With the bundle removed** (2026-10-19) it ran `exit 0`, so `grub-mkconfig`
>   stopped while sourcing it, wrote no `grub.cfg` and still exited 0. Observed
>   2026-10-20: a dry run printed 4 lines and no menu entry.
>
> The operator commented that check out on 2026-10-21, and `automation/xen-grub.cfg`
> — what `make xen` installs there — never had it. **Purging `xen-hypervisor`
> deletes this file**, and with it the line that makes GRUB boot Xen by default.
> After any `update-grub2`, re-read `xl info xen_commandline` and
> `sudo grep -c multiboot2 /boot/grub/grub.cfg`.

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
| Env file template | **`automation/sandboxd.env.example`** — every variable the daemon reads, documented. `make sandboxd` renders it and **replaces** the file (it used to append, duplicating every line on a re-run); `automation/api.env.example` is the platform's, rendered by `make web_sandbox`. Both ran on 2026-11-04 (`docs/runbooks/18-deploy-with-makefile.md` §4 and §5): `web_sandbox` found `api.env` rendered and kept it; `sandboxd` replaced `sandboxd.env` with the token rotated and the injection PIDs carried over, and the daemon started on it | 2026-11-04 |
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

**After the 2026-08-31 repartition — applied 2026-09-12**, the CPU bound is
gone and memory binds again:

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
| Domain | Debian 13 (trixie), **PVH**, `misc/xen-vms/platform.cfg` — the Makefile's `CFG` default; the file was `misc/platform.cfg` before the `xen-vms/` layout. Built by `make web_vm` (debootstrap) and `make web_sandbox`; the current one dates from 2026-11-02 (its TLS material's date), by the pre-2026-11-03 recipe | 2026-11-04 |
| Resources **as deployed** | **4096 MiB, 4 vCPU** — the committed figures, applied 2026-09-12 by the `xl shutdown platform && xl create misc/platform.cfg` the previous row asked for. Evidenced by `xl list`: `platform 10 4096 4 -b---- 8380.7` | 2026-09-12 |
| CPU affinity | `cpus = "28-31"` in `misc/platform.cfg`. **Not evidenced by the line above** — `xl list` reports memory and vCPU *count* and says nothing about pinning. `xl vcpu-list platform` is what would confirm it | 2026-08-31 (committed) |
| Address | **`192.168.1.12`** — the Makefile's `VMADDR` default, where the API binds (`Uvicorn running on https://192.168.1.12:8000`, journal of 2026-11-04) and what `make sandboxd` renders into `sandboxd.env`. This row said `192.168.1.10`, "deliberately unchanged", from 2026-08-28; when it moved is not recorded — the 2026-11-02 rebuild at the latest. Anything still naming `.10` (runbooks 13–17, `platform/garage/objects.conf`'s placeholder, which the recipe `sed`s) is the old address | 2026-11-04 |
| Boot | **direct kernel**, from `/var/lib/xen/platform/` on Dom0 | 2026-08-28 |
| Disks | `vg-root/platform` 20 G root; `vg-root/platform_data` **512 G** (grown from 256 G on 2026-11-03: `lvextend -L 512G` on Dom0, `resize2fs /dev/xvdb` online in the DomU, `df` 511G), `xvdb`, mounted at **`/srv/garagehq`** in the DomU (Garage's `data_dir` and `metadata_dir`; the `/srv/minio` name predates Garage — §2b). Bucket quota **400 GiB** (`garage bucket set-quotas`, 2026-11-03; the Makefile's `S3_QUOTA` matches), 3.8 GiB used. It is a thin volume: the pool `vg-root/thinpool` is 1.38 T at 16.1 % used with 5.62 T of thin volumes provisioned over it (`lvs`, 2026-11-03), so the quota is bounded by the pool's real free space, not by the volume's size | 2026-11-03 |
| Services | Postgres 17 (UTF-8 cluster), **Garage** (MinIO until 2026-10-02, §2b), FastAPI as `sandbox-api.service`, nginx in front of Garage. All four `active` after the 2026-11-04 reboot and after `make web_sandbox`'s re-run the same day | 2026-11-04 |
| Listeners | **8000** — one API listener, browser and worker traffic together, `192.168.1.12` over TLS (`sandbox_web.crt`). **9000 nginx** (`platform/garage/objects.conf`, `s3bucket_web.crt` as `/etc/nginx/tls/objects.crt`) in front of Garage's S3 API on loopback `3900`; Garage's admin API on loopback `3903`; the MinIO console on 9001 went with MinIO. **8443 mutual-TLS was retired 2026-09-15**, runbook 17 step 11. **9100, deployed 2026-11-04**: the Windows installers' mirror, `/srv/vendor/win-installers/` served by nginx with the object front's certificate, GET and HEAD by exact name, no listing (`automation/win-installers-mirror.conf`, installed by `make win_installers_mirror`, which published the eight files of `automation/win-installers.list` and fetched each back through it with its pinned hash — `docs/runbooks/18-deploy-with-makefile.md` EVIDENCE 6b-mirror). LAN only: the live tunnel config routes nothing to it | 2026-11-04 |
| Source | `/opt/platform/src/platform`, venv `.venv`, user `platform`. The checkout is **detached at `2b433f4`**, the tip of `origin/master`, put there by `make web_sandbox` on 2026-11-04 (`platform at 2b433f4`), migrations through `0013_launch_options.sql` applied, the API restarted on it at 13:34 with a clean startup log. `git` there must run as `platform` (`sudo -u platform git -C /opt/platform/src ...`): as root it refuses with "dubious ownership" | 2026-11-04 |
| TLS | `/etc/sandbox_platform/tls/`: `ca.crt` (`notAfter` 2036) and the `sandbox_web`, `s3bucket_web` and `dom0-lab` pairs (825 days), all issued **on the DomU** on 2026-11-02 08:35 by the pre-2026-11-03 `web_sandbox`, owned by `platform`. `ca.key` and `ca.srl` were there until 2026-11-04, which `tls/README.md` Custody forbids and the current recipe refuses to run past — the re-run of `make web_sandbox` stopped exactly there (`docs/runbooks/18-deploy-with-makefile.md` §4). **Removed the same day (§4b)** after a copy of the CA was taken to the operator's workstation checkout, `tls/ca/` (ignored by git), so leaves can still be issued under this CA; the platform now holds `ca.crt` and the three pairs only | 2026-11-04 |

> **A DomU reservation is not a cgroup cap.** CT 102's 4096 MiB was a ceiling
> that unused memory stayed available beneath; a DomU's is taken from the clone
> pool permanently. That is why it was halved on 2026-08-28, and why raising it
> costs concurrent analyses directly.
>
> **Raised back to 4096 on 2026-08-31 and APPLIED 2026-09-12, with the cost
> accepted rather than overlooked:** at `4246` MiB per clone the free pool goes
> `22365 → 20317`, which is **4 concurrent clones instead of 5**. That is no
> longer a prediction — the host is running this way now. Drop back to 2048 if
> a fifth matters more. Note the arithmetic changed under this decision — when
> the platform was halved, a clone cost `2198`, and at that size the same raise
> would have cost nothing.
>
> **`sandboxd` reads the real figure at runtime**, so nothing needs telling
> about the change; what needed telling was this document, which carried the
> pre-reboot state for twelve days.

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
| Injection PID | **1** — anchor `systemd`; samples run as root, 2026-08-29 | **3251** — anchor is a backgrounded `ping` to loopback. Reverted from PID 1 on 2026-08-31: Android's `init` gives `app_process64` no runtime environment, which the APK path needs. **Re-derive after every re-save** | **4696** — read from the `.bak`'s running template by `make setup_hooks_windows` and written to **`/etc/sandboxd/sandboxd.env`** as `SANDBOXD_INJECTION_PID_WINDOWS` (since 2026-11-03; the tracked `sandboxd/config.py` holds only the default **1**, which is no PID on Windows — the daemon logs the effective value at every start); same re-save cost as Android |
| Clone LV size | inherited: **1 T** | inherited: **128 G** | — |
| Sample dirs | `/malware_{incoming,processing,finished}/ubuntu` | `…/android` | `…/windows` |

Guest staging is each guest's **default** drop location. Since 2026-11-01 a
job may choose another location from a per-guest list, plus a subfolder
(`sandboxd/guests.py` `PATHS[os].locations`; §1.5).

Shared by all three: volume group `vg-root`, analysis bridge `xenbr1`.

`profiles/*.json` and `state/*.bak` are **not git-tracked** — a fresh checkout
has neither.

## 1.5 What is evidenced, and what is not

| Target | Status | Confirmed |
|---|---|---|
| Ubuntu pipeline | evidenced end to end; **re-confirmed twice on 2026-11-04**: job `6711d525` `completed (clean)` at 13:50 under `make xen`'s Xen with the compensation on, DRAKVUF `3c3b73a6` and the re-rendered environment (`docs/runbooks/18-deploy-with-makefile.md` §5b), then job `98e60edf` `completed (clean)` at 16:43 on the **golden image rebuilt that day** by `make ubuntu_analysis_vm` and `setup_hooks_ubuntu` (22.04.5 server autoinstall with `ubuntu-desktop`, the debug kernel for `linux.json`, the hardware identity in firmware and cfg, 4 vCPUs, 8192 MiB, `shadow_memory = 128`, saved after 22:33 of uptime, 8.59 GB) (§6c). Postprocessing logs the shared `preconfig.log` and `DumpsCount` errors on every job (TROUBLESHOOTING); falco ran, 1 alert | 2026-11-04 |
| Android — native ELF path | evidenced end to end | 2026-08-17 |
| Android — APK install + `am start` | **evidenced through the platform** — see the bare-metal table below | operator, 2026-08-29 |
| Windows | **Evidenced end to end with a transcript, 2026-11-04**: job `438fb6f9`, a sample `.exe`, claimed 15:26:30 and `completed (clean)` 15:29:05 with the console bridged and the artifacts uploaded (`docs/runbooks/18-deploy-with-makefile.md` EVIDENCE 6b-hooks), on the image rebuilt that day by `make windows_analysis_vm` (23H2, the eight installers of `automation/win-installers.list` vendored on the media, Defender off, updates paused, the hardware identity in firmware and cfg), saved by `xl save` after 20:36 of uptime (8.6 GB) with `explorer.exe` 4724 as the anchor, under `make xen`'s Xen with the compensation on and DRAKVUF `3c3b73a6`. **Still no per-plugin validation**: postprocessing logged the shared `preconfig.log` JSON errors (TROUBLESHOOTING) and fifteen extracted files without a fileextractor record, and nobody has yet opened the job's artifacts plugin by plugin. Before this: one job on 2026-09-05, operator-attested, no transcript; `shellexec` the working injection mode (`createproc` was tried and reverted as a regression) | 2026-11-04 |
| `sandboxd` | evidenced against real `xl`/`drakvuf` | 2026-08-26 |
| Live console | evidenced; off by default on both sides | 2026-08-27 |
| Screenshots (DRAFT-054) | **implemented and tested here, never run on Dom0. ON by default** (operator, 2026-10-30); `SANDBOXD_SCREENSHOTS_ENABLED=0` turns it off. A read-only RFB client on the clone's loopback console, a PNG every 2 s, shown on a **Screenshots tab** (strip, playback) through `/api/v1/jobs/{id}/screenshot` — the one artifact served raw, for display only; downloads stay wrapped. `docs/architecture/screenshots.md` | 2026-10-30 |
| Drop location, subfolder and command line | **implemented and tested here, never run on Dom0.** Optional per job: a location key from a per-guest list, a subfolder made in the guest, and the sample's arguments. None chosen means the evidenced `staging_dir` and no arguments. Every location but each guest's default is **Candidate**. `docs/architecture/analysis-pipeline.md`, "Where the sample is dropped" | 2026-11-01 |
| Results deleted from Dom0 after upload | **implemented and tested here, never run on Dom0.** Once `/complete` has been accepted, `stages.Analysis._remove_results` deletes the job's `/var/lib/sandboxd/results/<job>`. Kept: failed, cancelled and truncated runs, a run whose raw `trace.log` survived its split, and every run when `SANDBOXD_KEEP_RESULTS=1`. Before this, nothing ever removed them (operator, 2026-11-01) | 2026-11-01 |
| Clone destroyed **before** `collecting` | **implemented and tested here, never run on Dom0.** `stages.run` stops the console and the screenshots and destroys the domain when the trace ends; the staged sample stays until postprocessing has scanned it. The platform no longer pairs a console during `collecting` (`enums.CONSOLE_STATES`). Changes the order of the evidenced Ubuntu path, at the operator's request | 2026-10-30 |
| Artifact ZIP downloads | implemented + tested here, **never run on the deployment** | 2026-08-27 |
| Evasion searches (`evasion-tests/`) | **Run from this repository's scripts for the first time on 2026-11-04**, from the development container against Dom0: `rdtsc_search.sh` with `TESTS=1 ONLY=baseline` kept `make xen`'s package, booted the plain kernel, built and booted the variant once, ran the test, and put Dom0 back on `make xen`'s Xen as the default entry — seven minutes end to end. **Verdict: `baseline` passes** on the rebuilt Ubuntu guest, ten detector runs returning false in each of `dev-syscalls` and `dev-all`, 1.5 M and 1.3 M syscall records (`docs/runbooks/18-deploy-with-makefile.md` §7). Needs `psmisc` on Dom0 (`make sandboxd` installs it since that day), `sandboxd` stopped, and `site.conf`'s in-guest paths re-read after a guest rebuild. The variants and the al-khaser search have not run from these scripts yet; `restore_dom0.sh` has not been needed | 2026-11-04 |

### On bare metal, since 2026-08-28

| Target | Status | Confirmed |
|---|---|---|
| `ubuntu_sandbox` restore | **evidenced** — `xl restore` succeeded and `vmi-process-list` read the guest through `profiles/linux.json` | 2026-08-28 |
| DRAKVUF throughput | **evidenced** — six configurations, `12-baremetal-trial.md` Part H | 2026-08-28 |
| platform DomU serving | **evidenced** — five listeners, cloudflared connected, Access verified | 2026-08-28 |
| `sandboxd` registered | **yes** | operator, 2026-08-29 |
| **End-to-end analysis through the platform** | **yes, on both Ubuntu and Android** | operator, 2026-08-29 |
| Android APK — install + `am start` | **yes, successful through the platform.** This closes the last "implemented but never run" item on the Android track | operator, 2026-08-29 |
| `libmon` on Android (BlissOS) | **REFUTED for libmon v1, and not fixable by changing ROM.** BlissOS's bootstrap linker exports 27 dynamic symbols; `_r_debug` is not among them (nor `__dl__r_debug`). `dl_rendezvous.cpp:268` resolves that symbol at the linker's own base, so `try_arm` can never succeed: the plugin exhausts `ARM_MAX_ATTEMPTS` and emits `not_tracked` per process. **Not a layout problem** — bionic's `r_debug`/`link_map` match the SVR4 shape libmon hardcodes | operator, 2026-09-26 |
| …and it is structural, not a build artifact | bionic's export map (`linker/linker.generic.map`, AOSP `main`) is an explicit allowlist: 25 `global:` entries, all `__loader_*` plus `rtld_db_dlactivity`, then `local: *;`. `_r_debug` is not named, so **every bionic hides it** — a newer BlissOS (18, Android 15/16) behaves identically. Android is not a libc question either way: no Android version has ever shipped glibc | 2026-09-26 |
| …the way through, from the same map | **`rtld_db_dlactivity` IS exported**, in canonical upstream bionic rather than only in this ROM — the analogue of glibc's `_dl_debug_state`, which glibc marks `rtld_hidden` and libmon's README records as unresolvable *there*. The two libcs export opposite halves of the protocol, so a bionic port breakpoints that symbol instead of reaching `r_brk` through `_r_debug`. Enumerating `link_map` still wants the `DT_DEBUG` path `dl_rendezvous_abi.hpp` names as v2 | 2026-09-26 |
| Windows guest build | **Windows 11 23H2.** Supersedes `docs/checklists/windows.md:73`, which reads "64-bit Windows 10" from `windows_symbols.md` (2026-09-01) — that was the fallback, and the guest was updated afterwards (commit `3b82376`, "Updated windows version to 23H2"). Note `vmi-win-guid` prints "64-bit Windows 10" for Windows 11 too, since both are NT 10.0, so that output is not evidence either way — `checklists/windows.md:41` already records the trap | operator, 2026-09-27 |
| Windows API hook coverage | **capa-derived, 2026-09-27.** `sandboxd/data/hooks.txt` grew 302 → ~1,330 lines from capa-rules v9.4.0 via `scripts/gen-hook-lists.py`: 1,160 of capa's 947 bare Win32 names resolved to real exports through Microsoft's `win32metadata` (+ `phnt` for the `Nt*`/`Zw*`/`Rtl*` native API), 1,004 carrying Microsoft's own argument lists. **Throughput cost is UNMEASURED** and `hooks.txt` is passed whenever `memdump` is selected, which is every Windows job. Regenerated 2026-11-04 from capa-rules **v10.0.0-2** (the submodule's pin; the file had stayed at v9.4.0, review L-12): 1,270 lines, three APIs added, `GetLastError` moved from `clr.dll` to `kernelbase.dll`, where apimon can resolve it | 2026-11-04 |
| …and 51 inherited hooks look dead on this guest | The curated half of `hooks.txt` came from drakvuf-sandbox when `CreateProcessInternalW`, `CreateRemoteThread`, `DeviceIoControl` and `GetTickCount` lived in **kernel32**; on Win11 23H2 the profiles put them in **kernelbase**, and a hook on the wrong DLL resolves to nothing *silently* (`userhook.cpp:370` is `PRINT_DEBUG`, compiled out). `gen-hook-lists.py --report` lists all 51. The generated block covers the same functions at the right DLL, so coverage is restored; the stale curated lines are dead weight rather than a loss, and are left alone pending a Dom0 run | 2026-09-27 |
| capa's `string:` features were **never** matchable, until 2026-09-27 | capa yields a call argument WHOLE (`extractors/drakvuf/call.py`), so a DRAKVUF string arrived as `0x7ffc1234:"Xen"`. Measured: `substring:` matched, `string:` and `string: /regex/` did not — **835 features silently unreachable**, against 145 that worked. `--userhook-no-addr` is not the fix (it drops the address, keeps the quotes). `capa_processor.normalise_string_arguments` now reduces the value to the bare, unescaped string | 2026-09-27 |
| capa was **discarding every libmon line** | `DrakvufReport.from_raw_report` dispatches on `Plugin` and knows only `syscall` and `apimon` (capa#2181), so the `libmon.lon` → `libmon.log` typo fix made the file be read and then dropped. A `no-retval` record was worse than dropped: `WinApiCall.return_value` is required, so it raised out of `from_raw_report` and **aborted the whole capa pass**. Both handled by `_relabel_libmon_for_capa` | 2026-09-27 |
| Falco rules over the Linux trace | **implemented; checked against benchmark traces only, never through the platform.** `sandboxd/postprocessing/falco`, falcosecurity/rules `falco-rules-5.2.0` stable + incubating (56 rules) plus `sandboxd/data/falco-rules-local`. Over the 2026-10-23 Ubuntu benchmark trace: no alerts, 3.6 s. A benign workload doing one thing per rule fired all 12 it targets; docs/architecture/falco-rules.md | 2026-10-23 |
| Default plugins | **every plugin the platform offers but `ipt` and `hidsim`, on every guest** (operator, 2026-10-23), libmon on Ubuntu only: 12 on Ubuntu, 11 on Android, 13 on Windows. The submit form and `guests.py` hold the same sets (`test_the_defaults_are_the_submit_forms_on_every_guest`). Cost measured on Ubuntu only, for procmon and unixsocketmon beside the old set (none measurable); **on Android and Windows the added plugins' cost is unmeasured**, and Android needed `--disable-sysret` merely to finish with four | 2026-10-23 |
| Linux syscall return values | **every one `0x0` until drakvuf `44b6a19`, pinned here since 2026-10-24 (`26ad2e2`).** The dispatcher hooks report `rax`, and the result is in `pt_regs->ax`; upstream has the same bug. Ubuntu's default went back to keeping returns the same day (`guests.default_trace_options`): 557k-603k syscalls a minute with them against 720k-776k without | 2026-10-23 |
| `unixsocketmon` on Ubuntu 22.04 | **produced no output at all before drakvuf `bfab6ba`** (pinned since 2026-10-24): it failed a profile lookup silently and hooked an inlined function. From `bfab6ba`/`e58c13a` it records every send and connect with both ends, 2,300-4,900 a minute on the idle desktop, at no measurable cost | 2026-10-23 |
| `apimon` is now in the Windows default set | Without it `hooks.txt` was passed (memdump takes the same option) but only chose where memdump dumped: no `apimon.log`, so capa read `syscall.log` alone and the ~1,330 hooks produced no API features. **This is the change that makes them fire**, and the Windows trace cost of that is UNMEASURED | 2026-09-27 |
| Linux string-comparison hooks are **impossible**, not merely expensive | glibc declares `strcmp`, `strncmp`, `strcasecmp`, `strstr` and `memcmp` as `STT_GNU_IFUNC`: the symbol value is a resolver the linker calls once at load time, not the comparison code, and the implementations (`__strcmp_avx2`, …) are absent from `.dynsym`. `libdrakvuf/linux-exports.c` reads `st_value` with no IFUNC handling, so such a hook fires once per process with no strings. The Windows CRT equivalents ARE ordinary exports and are hooked (`ucrtbase.dll`, `msvcrt.dll`); a **statically linked CRT defeats those**, so their absence is not evidence | 2026-09-27 |
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
| The platform is an unprivileged **LXC**, 4096 MiB | a Xen **PVH DomU**, `misc/platform.cfg`. The memory figure coincidentally matches again since 2026-09-12 — it was 2048 from the migration until then, so a runbook quoting 4096 is right about the number and wrong about everything else |
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
| `dom0_mem=6144M` as the **running** boot line | this file until 2026-11-03; `09-verify-…` | **8192M** — `xl info xen_commandline` pasted 2026-11-03; the reboot that applied the configured line happened before 2026-11-02 |
| `/srv/minio` for the platform's data volume | `misc/xen-vms/platform.cfg` until 2026-11-03, this file §1.3, runbook 08 | **`/srv/garagehq`** — the DomU's fstab mounts `LABEL=platform-data` there (Makefile `web_vm`), and Garage's `data_dir`/`metadata_dir` live under it |
| `make sandboxd` and `make setup_hooks_*` `sed -i` the checkout path, the analysis user and the injection PIDs into `sandboxd/config.py` | the Makefile until 2026-11-03; review 2026-11-02 M-10 | **they write `/etc/sandboxd/sandboxd.env`** (`SANDBOXD_REPO_ROOT`, `SANDBOXD_ANALYSIS_USERNAME`, `SANDBOXD_INJECTION_PID_*`), which `config.py` reads; the tracked file carries only defaults and Dom0's checkout stays clean after a deploy |
| `make xen` enables `xencommons.service` | the Makefile until 2026-11-03; review 2026-11-02 M-13 | **`xenstored.service`** — the tree ships no xencommons unit; that name is the init script systemd's generator wraps, which fails on every boot. `xen-rdtsc-poc.service` now fails unless `xl dmesg` shows `RDTSC_POC: compensation enabled`, and `sandboxd` warns at startup when the boot line asks for the compensation and the line is missing. **On the running Dom0 both are still the old state until the unit file is reinstalled** (`make xen`, or the two commands in the 2026-11-03 session's handoff) |
| `setup_hooks_ubuntu` mounts the golden Ubuntu root read-write and leaves `ubuntu-vg` active on a failure; no lvm `global_filter` | the Makefile until 2026-11-03; review 2026-11-02 M-11 | **read-only with `noload`, under an EXIT trap that detaches**; `make sandboxd` appends `automation/lvmlocal.conf` to `/etc/lvm/lvmlocal.conf`, which rejects every `*-clone` volume from lvm2's scans (`lvmconfig devices/global_filter` shows it once installed — C-12) |
| `docs/android-drakvuf-automation-checklist.md` | older docs | split into `docs/checklists/{android,ubuntu,windows,platform}.md` |
| `linux.cfg`, `linux_sandbox.cfg` | older docs | `misc/ubuntu.cfg`, `misc/ubuntu_sandbox.cfg` |
| `clone-ubuntu.pl` | older docs | renamed to `automation/clone.pl` (DRAFT-015), then **deleted 2026-09-15** — see the launcher-pipeline row below |
| unnumbered runbook filenames | pre-2026-08-27 links | now `NN-<name>.md`, numbered oldest to newest |
| Injection PID `1415`, `1490` | `baremetal-trial.md` D5.4/D5.7, `09-verify-…` | **`1`** — the anchor is systemd. `nano` and `gedit` are both unschedulable without guest input, so neither can be injected into unattended |
| Android injection PID `3163`, `3164`, `3174` | `docs/checklists/android.md` §1.4/§1.5 | **`3251`** — same `ping`-to-loopback anchor those PIDs refer to, re-read after a later re-save. Each value is valid only for the `.bak` it came from |
| **"Android anchors on `init` / PID 1"** | `sandboxd/guests.py:439`, `sandboxd/tests/test_guests.py:182`, and older docs | **Only Ubuntu does.** Android went to PID 1 on 2026-08-29 and **reverted on 2026-08-31**, because Android's `init` provides no runtime environment for `app_process64` and the APK path needs one. The contradicting text lived in `automation/pipeline-android.env`, which was deleted 2026-09-15; the value now lives in `StageConfig.injection_pids` (`sandboxd/stages.py`) with nothing arguing against it. Do not put Android back on PID 1 |
| `CLONE_LV_SIZE`, "Clone LV size 64G / 32G" | older docs (was `pipeline-*.env`, deleted) | **retired 2026-08-29.** Clones are thin snapshots and inherit the golden LV's size — 1 T for Ubuntu, 128 G for Android. `-L` never sized the clone; it forced a *thick* snapshot whose exception store came from VG free space |
| `required_mib: 2198`, `memory = 2048` | `platform.md`, older runbooks | **4246** / `memory = 4096` for both templates as of 2026-08-29 |
| **"the browser listener binds `127.0.0.1`"** | `platform-domu.md` §E4a, `16-deploy-…`, DRAFT-047 decision 3 | **Held 2026-09-06 → 2026-09-10, then reversed.** Back on `192.168.1.10:8000`, because `sandboxd` dials the browser listener for the console relay and loopback is unreachable across machines. EVIDENCE E4a is real output of a real change and is kept — it is history, not the current posture. **The gate is no longer `REQUIRE_ACCESS_JWT=1`**: DRAFT-061 landed 2026-09-15 and the listener now authenticates sessions this platform issued, per the row below |
| **"the worker channel is reachable through the tunnel"** (F12) | `09-verify-…` §F12, `live-console.md` §4.1c, `16-deploy-…` "Known gaps", DRAFT-061 context | **Closed 2026-09-10.** True from 2026-08-26, when the rule was written and not applied, until it was applied. `^/api/v1/worker(/\|$)` now matches `http_status:404` ahead of the API catch-all, so **the worker channel is LAN-only again** — reachable on `:8000` and `:8443` from the LAN, not through `sandbox.evilbootloader.com`. Verified past Access, not in front of it: an anonymous request is bounced by the edge and proves nothing either way. EVIDENCE F12 in `16-deploy-…`. The text describing it as open is dated evidence and is kept |
| **The shell/C launcher pipeline** — `dirwatch.c`, `dirwatch_old.c`, `clone.pl`, `cleanup.sh`, `tcpdump.sh`, `run_analysis-{ubuntu,android}.sh`, `drakvuf-{ubuntu,android}.sh`, `preconfig-{ubuntu,android}.sh`, `pipeline-{ubuntu,android}.env` | runbooks 01–15, the issue drafts, the reviews, `project-assessment.md` | **All 13 deleted 2026-09-15** (4,795 lines) once `sandboxd` had replaced every one. Those documents are dated evidence and are **not** rewritten — read the filenames in them as history. `docs/architecture/automation-files.md` maps each file to its successor and carries the facts worth keeping; `scripts/check-refs.py`'s `ALLOW_PATHS` keeps the names resolving. `automation/` now holds only `network-setup.sh`, `platform.env` and the egress assets — and, since 2026-10-21, the Xen patch and GRUB config `make xen` installs |
| **"the console dial is mutual TLS"** | `live-console.md` §4.4 before 2026-09-10 | **Server-authenticated TLS plus the bearer worker token.** The console dials `:8000`, which has no `--ssl-ca-certs`; only `:8443` demanded a client certificate, and that listener no longer exists — see the row below. §4.1c always said so and §4.4 contradicted it for five weeks |
| **"Cloudflare Access is what authenticates a browser"**, and `REQUIRE_ACCESS_JWT=1` as the gate | `platform-domu.md`, `16-deploy-…`, `docs/architecture/platform.md`, DRAFT-047, the §2b row above | **Superseded 2026-09-15**, runbook 17 step 10. The platform issues its own credentials — argon2id passwords, signed access and refresh tokens, TOTP — and the Access *application* was deleted. `REQUIRE_ACCESS_JWT`, `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` are unset on the deployment. **The tunnel is kept**: it is transport, not identity, and it is what means no inbound ports. `access_identity` remains in the code for a deployment that wants an external provider; this one is not it |
| **"the worker channel is mutual TLS on 8443 with a shared `WORKER_TOKEN`"** | `09-verify-…`, `live-console.md`, `docs/architecture/platform.md`, every runbook before 17 | **Superseded 2026-09-15**, runbook 17 steps 7 and 11. One listener on `:8000` carries both; each analysis host has **its own** token, issued by `create_worker.py`, stored as a sha256 and revocable with `--rotate`. The platform no longer reads `WORKER_TOKEN` at all — it is sandboxd's credential, not a shared secret. `SANDBOXD_API` is `https://192.168.1.10:8000`; a host still pointed at `:8443` simply stops claiming, see [TROUBLESHOOTING](TROUBLESHOOTING.md#sandboxd-stopped-claiming-after-the-mtls-listener-was-disabled). `SANDBOXD_CLIENT_CERT`/`_KEY` are inert rather than wrong. **The channel is now one factor on the LAN** — a deliberate decision, recorded at the head of runbook 17 |
| **Xen 4.20.1 is the drakvuf-builds `.deb`** (`xen-hypervisor`) | `12-baremetal-trial.md`, `workflow-ci.md`, this file until 2026-10-20 | **Built from source since 2026-10-19**, with the altp2m deadlock fix: `xen-upstream 4.20.1` from Xen's `make debball`, procedure `make xen`. `xen-hypervisor` is removed, and its `/etc/default/grub.d/xen.cfg` stays as a conffile — see the §1.2 WATCH before purging it |
| **The DRAKVUF submodule is pinned at `86a17d0`**, with upstream `libvmi/libvmi` inside | this file until 2026-10-21 | **`26ad2e2`** on our fork (`a6e0892` from 2026-10-21 to 2026-10-24), `libvmi` at `c97816c` on `evilbootloader/libvmi` `feature/vcpu-parallel-events` — §1.2. An existing checkout needs `git submodule sync` before `update`, or it fetches libvmi from upstream, which does not have the commit |
| **`~/drakvuf` built the deployed DRAKVUF; settle provenance with `drakvuf --version`** | this file until 2026-10-24 | **The submodule built it, and `~/drakvuf` no longer exists.** `drakvuf` has no `--version` option, and the version its banner prints is fixed when the build directory is configured, so it can name an older commit than the binary was built from — §1.2, "DRAKVUF provenance" |

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
| `14-verify-routed-egress.md` | 2026-09-04 | **yes** — 47 prompt(s) |  |
| `15-verify-egress-throttles.md` | 2026-09-05 | **yes** — 50 prompt(s) |  |
| `16-deploy-tenancy-and-quota.md` | 2026-09-10 | **yes** — 3 prompt(s) |  |
| `17-deploy-own-identity.md` | 2026-09-15 | **yes** — 7 prompt(s) |  |
| `18-deploy-with-makefile.md` | 2026-11-04 | **yes** — 58 prompt(s) |  |

### How components are started

| Component | Command | Service |
|---|---|---|
| `sandboxd` | **source the env file first**, then `python -m sandboxd.daemon` in the foreground — see §1.2 for the exact Dom0 invocation. Exits immediately without `SANDBOXD_API`, `WORKER_TOKEN`, `SANDBOXD_TOTAL_MIB`. | unit: fakenet.service, xen-rdtsc-poc.service |

### Environment read by `sandboxd.daemon`

`SANDBOXD_ALLOW_DIRECT`, `SANDBOXD_ANALYSIS_USERNAME`, `SANDBOXD_API`, `SANDBOXD_CACERT`, `SANDBOXD_CLIENT_CERT`, `SANDBOXD_CLIENT_KEY`, `SANDBOXD_CONSOLE_API`, `SANDBOXD_CONSOLE_ENABLED`, `SANDBOXD_INJECTION_PID_ANDROID`, `SANDBOXD_INJECTION_PID_UBUNTU`, `SANDBOXD_INJECTION_PID_WINDOWS`, `SANDBOXD_KEEP_RESULTS`, `SANDBOXD_LOG_LEVEL`, `SANDBOXD_MAX_CLONES`, `SANDBOXD_MAX_SLOTS`, `SANDBOXD_PLUGINS`, `SANDBOXD_POSTPROCESS_MAX_MIB`, `SANDBOXD_REPO_ROOT`, `SANDBOXD_SCREENSHOTS_ENABLED`, `SANDBOXD_TOTAL_MIB`, `SANDBOXD_WORKER_ID`, `WORKER_TOKEN`

### Repository size

| | |
|---|---|
| sandboxd modules | 17 |
| test files | 23 sandboxd, 30 platform |
| documents under `docs/` | 46 |

<!-- END GENERATED -->