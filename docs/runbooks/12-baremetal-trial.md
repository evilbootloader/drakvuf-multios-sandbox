# Bare-metal Xen: does removing L0 make each DRAKVUF event cheaper?

> **Status: written 2026-08-27, EXECUTED 2026-08-28.** Filed 2026-08-29. This
> is the runbook that erased Proxmox and made the host bare metal. Parts 0–D
> and H carry real output; **Parts E, F and G are abandoned, not pending** —
> see the annotation immediately below before waiting on any blank in them.
>
> **It did not answer the question it was written to answer, and that is the
> single most important thing to know about it.** The title asks whether
> removing L0 makes each DRAKVUF event cheaper. Answering that needed a nested
> baseline measured *after* the bare-metal run (Part G2), on a Proxmox host
> that no longer exists. The erase route was taken deliberately (§A1a/§A1b) with
> that cost understood and accepted.
>
> **Part H is what replaced it**, and it is the reason this runbook was worth
> executing: six configurations measured on the rebuilt template on 2026-08-28,
> answering *"what actually moves DRAKVUF throughput on this hardware?"* That
> series produced `--disable-sysret` at **2.06×**, now adopted in
> `sandboxd/guests.py`, and confirmed §F7c by experiment.
>
> **Prerequisite, and it was met:** `11-pbs-backups.md` completed including its
> Part E restore. The golden images came back from that backup after the erase.
>
> Parts B and C needed physical or IPMI console access — not doable over SSH,
> because the machine reboots into a different operating system.

---

## ANNOTATION 2026-08-29 — Parts E, F and G are abandoned, not pending

**Nobody should wait for these blanks. They cannot be filled.** Every `______`
in Parts E, F, G and the closing Decision summary is permanently open, and the
reason is structural rather than a matter of finding time.

| Part | Blank because | Can it ever be filled? |
|---|---|---|
| **E** — parity measurement | The *bare* half was superseded by Part H's better-controlled series; the *nested* half needed §G2 | **No.** The ratio needs both halves |
| **F** — production config | Answered by H2, which measured six production configurations instead of one | **No** — and it does not need to be |
| **G** — roll back to Proxmox, take the nested baseline | `pvesm`, `qm start 101`, `efibootmgr` against EVIDENCE A: **there is no Proxmox host to boot back into** | **No** |
| **Decision summary** | Its `ratio`, `G2` and `E / G2` rows depend on Part G | Partly — the non-ratio rows are answered in 0.2, B, C and D |

**Why the design was sound and the outcome still lost the number.** Part G
deliberately deferred the nested baseline to the *end*, so both measurements
would sit in one Proxmox boot on identical hardware and software. That is the
right way to control such a comparison. It also concentrated the entire nested
half of the experiment behind a rollback that §A1a's erase route removed. The
trade was made knowingly — §A1b lists the four preconditions for erasing, and
they were met — but it is worth stating plainly, because the runbook's own
structure reads as though Part G is merely outstanding.

**What was actually decided, and where the evidence is:**

- **Xen boots on the hybrid CPU** — Part C, and `smt=0` leaves Xen 24 online
  pCPUs of 32 logical, which is where `cpus = "12,14"` comes from.
- **The migration is justified on memory, TCB and failure-domain grounds**,
  which the plan always argued were sufficient on their own. `total_memory`
  went 20479 → 32605 MiB. Part E1 anticipated exactly this reading: *"do not
  let a null performance result be read as a verdict against migrating."* Here
  there is not even a null result — there is no result.
- **What moves throughput on this hardware** — Part H2. CPU placement, `-F` and
  compiler hardening all land within 0.6%; `--disable-sysret` gives 2.06×.

**The open question this leaves.** Whether nesting cost anything measurable is
now unanswerable on this host, and §F7c's *"the only remaining lever is fewer
events"* stands on Part H's evidence rather than on the comparison this runbook
was written to make. Anyone re-opening it needs a second machine, not a
rollback.

---

## What this decides

`09-verify-sandboxd-and-console.md` §F7c measured the bottleneck as **per-event
cost on one saturated DRAKVUF thread** and concluded *"the only remaining lever
is fewer events, not faster handling of them."* That is true of everything Xen
can see. It cannot see L0.

DRAKVUF's altp2m tracing turns every hooked event into an EPT violation in L2,
which KVM must handle before Xen is told, and Xen's own `VMREAD`/`VMWRITE`/
`VMRESUME` handling traps to KVM in turn. **Bare metal deletes that entire
layer.** Whether that is worth a migration is a number nobody here has, and
this runbook exists to produce it.

**The decisive metric is events per second.** The DRAKVUF loop is saturated in
both configurations, so on a saturated single thread `events/sec` *is*
`1 / per-event cost`. Everything else here supports that one comparison.

| Part | Where | What it does |
|---|---|---|
| 0 | current lab | Record versions and locate the two `.deb` files Part B needs |
| A | PVE | Identify the spare disk without endangering the rollback |
| B | console | Install Ubuntu 22.04 + the *same* Xen and DRAKVUF |
| C | trial | **Does Xen boot on the hybrid CPU?** Cheap stop condition |
| D | both | Get a traceable guest onto the trial system |
| E | trial | Measure at **parity** config — isolates nesting alone |
| F | trial | Measure at **production** config — what you would actually get |
| G | PVE | Roll back, **take the nested baseline**, compute the ratio |

> ### Why the baseline is last, not first
>
> An earlier draft opened with the nested measurement and called it
> time-critical. **It is neither.** This is a dual boot: Proxmox stays installed
> and bootable throughout, so the nested lab can be measured on any later boot.
>
> Deferring it earns two things. If §C finds Xen will not run this hybrid CPU,
> the trial ends there and the baseline was never needed. And §G has to boot
> back into Proxmox anyway — so the baseline costs one extra hour inside a
> reboot already on the critical path, rather than a session of its own.
>
> The one thing that genuinely must hold is that both runs use the **same
> sample, the same `state/ubuntu_sandbox.bak` and the same DRAKVUF flags**.
> Nothing about ordering threatens that; §0.1 pins it.

---

# Part 0 — pin the workload and find the packages

No measuring here. This Part fixes the two things Part B and Part G both
depend on: exactly what will be traced, and exactly which binaries.

## 0.1. Fix the workload, and understand what it actually measures

> ### The sample barely matters, and that is not a problem
>
> `09-verify-…md:1274` defines the usual sample as:
>
> ```sh
> printf '#!/bin/sh\nid\nsleep 120\n' > /tmp/slow.sh
> ```
>
> That is one `id` and then 120 seconds of sleeping — nearly zero syscalls. Yet
> Dom0 sat at 99% of a core throughout. **The load is the guest's ambient
> syscall traffic**, because `syscalls` traps everything system-wide and no
> filter file is passed (`09-verify-…md:1753`). systemd, journald and the
> kernel's own timers are the workload; the sample is noise on top.
>
> This is fine for an A/B **provided both runs start from the identical restored
> memory image**, which `xl restore` from the same `state/ubuntu_sandbox.bak`
> guarantees. Same processes, same timers, same starting instant.
>
> It also suggests §F7a's null result for `-F` has a simpler explanation than
> the sample confounding it blamed: the flag made singlestep cheaper for a
> workload the sample was not generating.

**So use whatever sample is already staged in the image, and change nothing.**
Write it down here, and use this exact value in both §E and §G:

    sample path in the guest:  ______________________
    DRAKVUF flags:  -F -o json -t 120 -a syscalls -a filetracer
                    -a fileextractor -a memdump
    injection PID:  ______   (CURRENT-STATE §1.4 says 1415 for Ubuntu -- confirm)

> **A deterministic sample would be better, and is not worth its cost here.**
> A fixed-iteration syscall loop would dominate the ambient noise and remove
> run-to-run variance. But the sample has to live *inside* the guest image, so
> adding one means booting the golden domain, writing the file, **re-saving
> `state/ubuntu_sandbox.bak` and re-deriving the injection PID** — the exact
> expensive per-OS operation this project keeps trying to avoid, and it would
> invalidate the `.bak` currently in the PBS backup.
>
> Since the load is ambient anyway, the identical-restored-state property does
> the work a deterministic sample would have done. Revisit only if §E and §G
> show run-to-run variance large enough to swamp the difference between them.

## 0.2. Capture the exact configuration being compared against

```bash
# DOM0
xl info | grep -E 'xen_version|xen_commandline|nr_cpus|threads_per_core|virt_caps'
drakvuf --version 2>&1 | head -3
uname -a
dpkg -l | grep -iE 'xen-hypervisor|drakvuf'
```

**Keep the two `.deb` files if they are still on disk** — Part B needs the same
builds, and `CURRENT-STATE` §1.2 pins them at Xen **4.20.1** and DRAKVUF
**`v1.1-git20260511151619+52df0bc8-1`**.

```bash
# DOM0 -- look for them before assuming they must be re-fetched
ls -la ~/Downloads/*.deb /root/*.deb 2>/dev/null
find / -name 'xen-hypervisor-4.20.1*' -o -name 'drakvuf*.deb' 2>/dev/null | head
```

> ## DRAKVUF is a SOURCE build, not a package — there is no `.deb` to find
>
> `docs/drakvuf-on-xen-nested-within-proxmox.md:475-520` records it: the
> deployed DRAKVUF is **`lfreijo/drakvuf`, branch `memdump`**, either cloned
> directly or as a `lfreijo` remote added to a `tklengyel/drakvuf` checkout,
> then built and `sudo make install`ed (`:596`). Upstream `tklengyel` alone
> **does not have the memdump functionality this lab depends on** —
> `-a memdump` is in every trace command in this project.
>
> That checkout lives at `~/drakvuf` on `lv-root`, and **`lv-root` is not
> backed up.** Erasing the disk destroys it.
>
> Record its exact coordinates before erasing anything:
>
> ```bash
> # DOM0
> cd ~/drakvuf
> git remote -v
> git branch --show-current
> git log -1 --oneline --decorate
> git status --short          # any uncommitted local changes are unrecoverable
> git submodule status --recursive
> ```
>
> **Check out the commit, not the branch head.** The deployed binary is
> `v1.1-git20260511151619+52df0bc8-1`, so `52df0bc8` is what must be rebuilt.
> `git reset --hard lfreijo/memdump` gives whatever that branch points at
> *today*, which may have moved — and a different DRAKVUF silently invalidates
> the comparison. The build dependency list is the long `apt-get install` line
> at `drakvuf-on-xen-nested-within-proxmox.md:470`.
>
> Safest: `git bundle create ~/drakvuf-tree.bundle --all` and back that up
> alongside any uncommitted work, rather than trusting GitHub to still serve
> that commit.

> ## What `lfreijo/memdump` actually provides — recorded 2026-08-28
>
> This project has asserted the fork is required without ever writing down what
> it contains. `git log --oneline main..memdump` on the rebuilt tree: **23
> commits, 54 files, +3977/−1055.** The oldest is the answer:
>
> ```
> 8dc7788 Add Linux support for memdump, filetracer, fileextractor,
>         and syscalls plugins
> ```
>
> **Upstream's memdump is Windows-only**, and its `--memdump-disable-*` flags
> prove nothing about Linux support — which is how an upstream build passed a
> casual check during this migration
> ([TROUBLESHOOTING](../TROUBLESHOOTING.md#an-upstream-drakvuf-build-passed-a-casual-check-and-was-the-wrong-binary)).
> The fork adds `memdump/linux.cpp` (+487),
> `memdump/linux.h` (+266), splits `memdump.cpp` into `win.cpp`/`linux.cpp`, and
> adds `syscalls/linux.cpp` (+246).
>
> **Those are four of the four plugins in every trace command here**
> (`-a syscalls -a filetracer -a fileextractor -a memdump`). Running upstream
> against an Ubuntu or Android guest degrades or breaks the entire evidenced
> path, silently.
>
> The branch also carries anti-evasion work that `ideas.md` lists as wanted and
> which is therefore **already partly implemented in the deployed build**:
> `hidevm` hiding Xen's PCI `VEN_5853` from registry probes and filtering
> `NtEnumerateKey` for `\Enum\PCI/IDE/SCSI` (`[MAP-1792]`, `[MAP-1826]`), and
> hvmloader emitting SMBIOS types 7/8/9/26/27/28 from a firmware blob
> (`[MAP-1822]`).
>
> ### Read this before attempting timing-based anti-evasion
>
> ```
> 3a17635 [MAP-1828] Drop all Xen-source patches -- every one breaks Win10 HVM boot
> ```
>
> RDTSC VMEXIT-cost compensation, CPUID stealth and ACPI OEM spoofing were
> developed across `[MAP-1793]` and tuned as far as *"bump subtraction 1500 ->
> 2200 cycles"*, then **removed wholesale** because they broke Windows 10 HVM
> boot. At `52df0bc8` there are **no Xen-source patches**. The obvious approach
> has been tried and reverted; that history is the prior art.
>
> **Two build details that fail silently** — `libzstd-dev` before configuring,
> and `dwarf2json` pinned to branch `linux_non_canonical_addr4`. Both are in
> [TROUBLESHOOTING](../TROUBLESHOOTING.md#libzstd-found-no-and-the-build-succeeded-anyway).
> LibVMI needs no separate rebuild: `git diff main..memdump -- libvmi` is empty.

EVIDENCE 0.2

```
root@drakvuf:~/drakvuf-multios-sandbox# cd
root@drakvuf:~# xl info | grep -E 'xen_version|xen_commandline|nr_cpus|threads_per_core|virt_caps'
nr_cpus                : 12
threads_per_core       : 1
virt_caps              : pv hvm hap shadow gnttab-v1 gnttab-v2
xen_version            : 4.20.1
xen_commandline        : placeholder dom0_mem=8192M,max:8192M dom0_max_vcpus=6 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0 sched=credit
root@drakvuf:~# drakvuf --version 2>&1 | head -3
1787864102.055209 DRAKVUF v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel
drakvuf: unrecognized option '--version'
Unrecognized option: json-kernel
root@drakvuf:~# uname -a
Linux drakvuf 6.8.0-138-generic #138~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug  7 13:43:15 UTC  x86_64 x86_64 x86_64 GNU/Linux
root@drakvuf:~# dpkg -l | grep -iE 'xen-hypervisor|drakvuf'
ii  xen-hypervisor                             4.20.1                                           amd64        Xen Hypervisor built for DRAKVUF

root@drakvuf:~# ls -la ~/Downloads/*.deb /root/*.deb 2>/dev/null
root@drakvuf:~# find / -name 'xen-hypervisor-4.20.1*' -o -name 'drakvuf*.deb' 2>/dev/null | head
/home/user/Downloads/drakvuf-bundle-1.1-1eabdbd-ubuntu-jammy.deb
/home/user/Downloads/xen-hypervisor-4.20.1-ubuntu-jammy-amd64.deb

```

---

# Part A — the spare disk, and protecting the rollback

**The rollback is the whole reason this is a trial rather than a migration.**
Everything in this Part exists to keep Proxmox bootable.

## A1. Identify the spare disk (PVE)

```bash
# PVE
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL
pvs
vgs
blkid
cat /proc/mounts | grep -E '^/dev'
```

EVIDENCE A1 — measured 2026-08-27

```
nvme0n1                1.8T  Samsung SSD 980 PRO      <-- the only disk
└─nvme0n1p3            1.8T  LVM2_member -> VG pve
   ├─pve-swap            8G      ├─pve-root          96G  ext4  /
   ├─pve-data_tmeta   15.9G      └─pve-data-tpool   1.7T  thin pool
        vm-102-disk-0 16G   vm-102-disk-1 256G   vm-101-disk-0 1T

PV /dev/nvme0n1p3   VG pve   PSize <1.82t   PFree 16.24g
```

> ## FINDING — there is no spare disk, and the space cannot be freed
>
> **One NVMe holds the entire lab** and VG `pve` has **16.24 GiB free**. The
> trial needs ~100 GB: ~20 GB for Ubuntu + Xen, plus 64 GB for `ubuntu_sandbox`.
>
> **The space cannot be recovered by shrinking, because LVM thin pools cannot be
> reduced.** `lvreduce` extends `pve-data` and refuses to shrink it. The pool has
> permanently claimed 1.7T of the 1.82T VG.
>
> That also explains why deleting `phoenix`, `flare-vm`, `remnux` and `builder`
> did not help: **removing a thin LV returns space to the pool, not to the VG.**
> `lsblk` now shows only the 101 and 102 disks and `PFree` is still 16.24g.
>
> Shrinking `pve-root` needs a live-USB boot, frees perhaps 50 GB — still short —
> and puts a resize under the install whose survival is the point of the trial.

## A1a. Three routes, and what each costs

| Route | Rollback | Cost |
|---|---|---|
| **Add a second SSD** | intact | a 250–500 GB disk; check for a free M.2 or SATA port |
| **Install to external USB** | intact | an enclosure. Biased *against* bare metal — see below |
| **Erase Proxmox entirely** | **gone** | free, but this stops being a trial and becomes the migration |

> ### If USB: the bias runs in the safe direction
>
> The metric is `events/sec` on a saturated CPU thread. §F7c established the
> loop as CPU-bound and §F7 measured guest vCPUs paused ~93% of wall time, so
> neither is waiting on storage. **`memdump` is the exception** — it writes
> dumps, and USB is slower. Keep `-a memdump` in both runs anyway, because
> dropping it changes the workload; the penalty falls on the bare-metal side, so
> the measured ratio is a **conservative lower bound**. Only a result near or
> below 1.0 needs re-testing on real storage.

## A1b. If erasing Proxmox — four preconditions, in this order

Erasing is defensible: the golden LVs, `state/`, `profiles/`, Dom0's `/etc` and
the whole platform container are in PBS and verified restorable (`pbs-backups.md`
§E). But the backups cover **data**, and three things that are not data would go
with the disk.

> ## 1. Confirm the PBS encryption key exists somewhere other than this machine
>
> **Nothing else on this list matters if this one is wrong.** `pbs-backups.md`
> §C1 required an off-host copy before the first backup. If the only copy is at
> `/root/.config/proxmox-backup/encryption-key.json` inside VM 101, erasing the
> disk makes **every backup just taken permanently unreadable** — and the
> failure is silent until a restore is attempted.
>
> Verify by decrypting something *from another machine*, not by remembering
> that the copy was made.

**2. Get the Xen and DRAKVUF `.deb` files off the machine.** §0.2 has not been
run. `/etc` is backed up; the *software* is not. Ubuntu is reinstallable and the
repo is in git, but:

- **Xen 4.20.1** came from a local `.deb`
  (`drakvuf-on-xen-nested-within-proxmox.md:272`), not Ubuntu's archive.
- **DRAKVUF is a fork build**, `v1.1-git20260511151619+52df0bc8-1`. Rebuilding
  from upstream at that commit may not reproduce it.

If either cannot be recovered or re-fetched, **stop** — erasing would cost a lab
that cannot be rebuilt, and the comparison would be invalid anyway.

**3. Take the nested baseline NOW.** This reverses the deferral argued above,
and the reason is specific: that argument assumed dual boot, where Proxmox stays
available. **Erasing destroys the nested configuration permanently**, so §G2
becomes impossible and the ratio can never be computed. Run §G2's
`bench-run.sh nested` before touching the disk, or accept that this runbook's
central question goes unanswered forever.

**4. Sweep `lv-root` for anything unmodelled.** It is not backed up and holds
`/malware_incoming`, `/malware_processing`, `/malware_finished` — any analysis
artifact not yet uploaded to MinIO dies with it.

```bash
# DOM0
du -sh /malware_finished/* /malware_processing/* /malware_incoming/* 2>/dev/null
ls -la /var/log/sandboxd/ 2>/dev/null
```

> ### Erasing removes the answer to §C before you can ask it
>
> §C — *does Xen boot on this hybrid CPU?* — is the one thing no amount of
> reading settles, and it is the only outcome that would make erasing a mistake.
> **Answer it from a USB install first, then erase.** An hour with a USB stick
> converts an irreversible bet into a checked one, and the USB install is
> throwaway: it only has to reach `xl info`.

Record the decision before continuing:

    route taken:  erase
    device:       /dev/________
    §C validated from USB first?  ______

## A2. The failure mode that would cost you the rollback

**A shared EFI System Partition.** If the Ubuntu installer writes its bootloader
to the ESP that Proxmox boots from, it can displace or reorder Proxmox's entry
— and the rollback this whole exercise depends on is a firmware boot-menu
selection away from being gone.

Two rules for the install in Part B:

1. **Create a separate ESP on the spare disk** and point the installer at it.
   Do not let it reuse an existing one.
2. **Switch between systems from the firmware boot menu**, not from a shared
   GRUB. A GRUB entry chaining to the other install is convenient and puts the
   rollback behind the very component the install just modified.

Record the current boot configuration so it can be compared afterwards:

```bash
# PVE
efibootmgr -v
lsblk -o NAME,SIZE,PARTTYPE,MOUNTPOINT | grep -i efi
```

EVIDENCE A

```
target device:            /dev/______
confirmed absent from pvs/mounts/pvesm/qm: ______
efibootmgr BEFORE:        ______
```

---

# Part B — install, holding every variable fixed (console)

The comparison is only meaningful if **nesting is the sole difference**. Same
Dom0 OS, same Xen, same DRAKVUF, same boot line, same guest, same sample.

## B0. Disk layout and the thin pool (erase route)

**Ubuntu's installer cannot create a thin pool.** Subiquity does plain LVM only.
But its installer shell can, and pre-creating the layout there is cleaner than
installing and restructuring afterwards.

> ## Thin for the guest volumes only — NOT for everything
>
> The request was to set up thin provisioning for the whole disk before
> installing. **Do not put `lv-root` or `/boot` on thin**, for three separate
> reasons:
>
> - **`/boot` cannot work at all. GRUB cannot read LVM thin volumes.** Its LVM
>   support covers linear, striped and mirrored LVs only. A thin `/boot` is an
>   unbootable machine, and this one no longer has a rollback.
> - **A thin `/` needs `thin_check` inside the initramfs** to activate the pool
>   before pivot-root. Achievable, and it adds a boot-time failure mode to the
>   one machine that must boot.
> - **The real objection: it would put Dom0's root in the same pool as every
>   clone snapshot.** A disk-filling sample — ransomware, a zip bomb, a
>   deliberate filler — would then exhaust the pool underneath *Dom0's own
>   filesystem*, not just the analysis volumes. Today the blast radius of that
>   sample is one clone's exception store. Thin-everything would make it the
>   whole host.
>
> Dom0's root gains nothing from thin provisioning anyway. The anti-evasion
> goal is about what a *guest* sees on its disk, and guests never see `lv-root`.

### B0a. In the installer shell, before disk configuration

Create the partitions, the VG and a **thick** `lv-root`, then leave the shell
and point the installer at the existing `lv-root`.

```bash
# installer shell
sgdisk --zap-all /dev/nvme0n1
sgdisk -n1:0:+1G   -t1:ef00 -c1:ESP   /dev/nvme0n1
sgdisk -n2:0:+2G   -t2:8300 -c2:boot  /dev/nvme0n1
sgdisk -n3:0:0     -t3:8e00 -c3:lvm   /dev/nvme0n1

pvcreate /dev/nvme0n1p3
vgcreate vg-root /dev/nvme0n1p3
lvcreate -L 150G -n lv-root vg-root      # thick, deliberately
lvs vg-root
```

**Leave the thin pool until after first boot.** A pool created now would need
`thin-provisioning-tools` present in the installed system to activate at boot —
and it is not installed yet. Creating the pool after §B0b removes that ordering
hazard entirely, and costs one command.

Then in the installer: use `/dev/nvme0n1p1` as ESP, `/dev/nvme0n1p2` as `/boot`,
and `vg-root/lv-root` as `/`.

Proposed layout for the 1.8T NVMe:

| Partition | Size | Purpose |
|---|---|---|
| `p1` | 1 G | ESP, vfat |
| `p2` | 2 G | `/boot`, ext4, **plain — not on LVM** |
| `p3` | rest | LVM PV → VG `vg-root` |

Inside `vg-root`:

| LV | Size | Purpose |
|---|---|---|
| `lv-root` | 150 G | `/` — **thick.** Ubuntu, the DRAKVUF source build, `/malware_*` staging |
| `thinpool` | ~1.5 T | **thin.** Golden LVs and every clone snapshot |
| *(unallocated)* | **~150 G** | **left free on purpose — see below** |

150 G for `lv-root` is not arbitrary: it holds the `~/drakvuf` source tree and
its build artifacts, `.venv-sandboxd`, and the `/malware_incoming|processing|
finished` staging directories that artifacts pass through before upload.

`/boot` stays off LVM because GRUB loads Xen and the Dom0 kernel by multiboot;
a plain partition removes a class of boot problem from the one machine whose
bootability is now unrecoverable without a reinstall.

**The VG name must be `vg-root`.** `misc/*_sandbox.cfg` hardcodes
`phy:/dev/vg-root/<name>` and every script derives paths from it.

### B0a. Packages — two that are easy to miss

```bash
sudo apt install -y lvm2 thin-provisioning-tools
sudo modprobe dm-thin-pool
sudo systemctl enable --now lvm2-monitor.service
```

> **Neither package is optional, and neither failure is visible here.** LVM will
> not activate a thin pool without `thin-provisioning-tools`, and autoextend is
> inert without `lvm2-monitor.service`. See
> [TROUBLESHOOTING](../TROUBLESHOOTING.md#a-thin-pool-that-will-not-activate-at-boot-long-after-it-was-created-fine).

### B0b. Create the pool

The PV, VG and `lv-root` already exist from §B0a. This adds only the pool:

```bash
sudo lvcreate --type thin-pool -l 90%FREE --poolmetadatasize 16G \
     -n thinpool vg-root
sudo lvs -o +lv_attr,data_percent,metadata_percent vg-root
sudo vgs vg-root
```

> **`-l 90%FREE`, not `100%FREE`** — the ~150 G left unallocated is what
> autoextend grows into. A pool owning the whole VG makes the guardrail
> decorative, which is the state that made §A1's shrink impossible. See
> [TROUBLESHOOTING](../TROUBLESHOOTING.md#thin_pool_autoextend_-is-configured-and-the-pool-still-filled-up).

`--poolmetadatasize 16G`: metadata exhaustion is nastier than data exhaustion —
the pool flips read-only — and it cannot be fixed by deleting volumes. Proxmox
used 15.9 G for a 1.7 T pool; match that order of magnitude rather than
accepting a computed default.

### B0c. Autoextend

`/etc/lvm/lvm.conf`, in the `activation { }` block:

```
thin_pool_autoextend_threshold = 80
thin_pool_autoextend_percent   = 20
```

```bash
sudo systemctl restart lvm2-monitor
sudo lvs -o +data_percent,metadata_percent vg-root
```

### B0d. What changes for the pipeline

Thin volumes take a **virtual** size — this is the anti-evasion property from
the plan, a guest seeing 1 T while consuming only what it writes:

```bash
sudo lvcreate -V 1T --thin -n ubuntu vg-root/thinpool
```

Thin snapshots take **no `-L`**, which is the `clone.pl` change already
identified — but there is a second one that is easy to miss:

```bash
sudo lvcreate -s -n ubuntu-1-clone vg-root/ubuntu     # no -L, no size
```

> **`clone.pl` needs `-kn` on top of dropping `-L`.** Thin snapshots are created
> with activation skipped, so `/dev/vg-root/<clone>` never appears and
> `xl create` fails on a missing device — and thick snapshots do not behave that
> way, so it surfaces only on the first clone against the new storage. See
> [TROUBLESHOOTING](../TROUBLESHOOTING.md#xl-create-fails-on-a-missing-block-device-after-lvcreate--s).

EVIDENCE B0

```
user@dom0:~$ sudo lvs -o +data_percent,metadata_percent ubuntu-vg
  LV        VG        Attr       LSize   Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert Data%  Meta% 
  thinpool  ubuntu-vg twi-a-tz--   1.38t             0.00   0.14                             0.00   0.14  
  ubuntu-lv ubuntu-vg -wi-ao---- 250.00g   
user@dom0:~$ sudo vgs ubuntu-vg
  VG        #PV #LV #SN Attr   VSize  VFree   
  ubuntu-vg   1   4   0 wz--n- <1.82t <161.00g
systemctl is-active lvm2-monitor: active
thin_check present (dpkg -l thin-provisioning-tools): yes
```

> ### DECISION 2026-08-27: Ubuntu 24.04 (noble), not 22.04 — and what it costs
>
> The operator has a **noble Xen build from drakvuf-builds**, so the packaging
> objection to 24.04 is answered. Two consequences to carry forward rather than
> forget:
>
> - **A noble DRAKVUF `.deb` is needed too.** They are separate packages;
>   `dpkg -l` in EVIDENCE 0.2 shows only `xen-hypervisor` matching. A jammy
>   DRAKVUF on noble is the remaining packaging risk.
> - **The comparison now has two variables, not one** — nesting *and* the Dom0
>   OS (jammy 6.8 vs noble). The DRAKVUF loop reaches Xen through `privcmd`,
>   `xenevtchn` and `xenforeignmemory`, so the kernel is on the hot path,
>   though well behind an entire virtualization layer in significance.
>
>   **This only matters if the ratio lands near 1.0.** At 2× nobody will argue
>   the kernel did it; at 1.05 the kernel is a live alternative explanation.
>   Record it as a caveat on the §G2 verdict, and re-test on jammy only if the
>   result is both close and decision-relevant.

1. **Ubuntu Server 24.04 (noble)**, matching the Xen build obtained. Under the
   erase route this replaces Proxmox entirely — see §B0 for the disk layout.
2. **Xen 4.20.1**, the noble build from drakvuf-builds:
   ```bash
   sudo apt install ./xen-hypervisor-4.20.1-ubuntu-noble-amd64.deb -y
   ```
3. **DRAKVUF, built from source** — `lfreijo/drakvuf` branch `memdump` at the
   commit recorded in §0.2, per
   `drakvuf-on-xen-nested-within-proxmox.md:470-600`. There is no package for
   this; upstream `tklengyel` lacks the memdump work every trace here uses.
   Build after Xen is installed, since it links against Xen's libraries.
4. **The same Xen boot line**, verbatim from `09-verify-…md:2070`:
   ```
   GRUB_CMDLINE_XEN_DEFAULT="dom0_mem=8192M,max:8192M dom0_max_vcpus=6 \
   dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 \
   hpet=legacy-replacement smt=0 sched=credit"
   ```
   **8192M and 6 vCPUs deliberately, on a 32 GB machine.** Part E measures
   nesting; giving bare metal more resources at the same time would measure
   both at once and attribute the gain to the wrong cause. Part F relaxes this.

```bash
sudo update-grub2 && sudo reboot
```

EVIDENCE B

```
root@dom0:~# xl info | grep xen_version
xen_version            : 4.20.1
root@dom0:~# drakvuf 
1787891505.104280 DRAKVUF v1.1-da982ab Copyright (C) 2014-2024 Tamas K Lengyel
No domain name specified (-d)!
root@dom0:~# uname -a
Linux dom0 6.8.0-138-generic #138-Ubuntu SMP PREEMPT_DYNAMIC Fri Jul 31 22:41:49 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
```

---

# Part C — does Xen boot on the hybrid CPU?

**The first stop condition.** `CURRENT-STATE` §1.1 records the host as 8
P-cores (0–15, SMT) plus 16 E-cores (16–31). Xen builds a system-wide CPUID
policy and has historically assumed homogeneous CPUs. Nested, this is hidden by
`affinity: 0-15` confining VM 101 to P-cores — a choice §F5b made because
`cpu: host` makes heterogeneous enumeration a *correctness* problem. Bare metal
removes that shield.

```bash
# TRIAL
root@dom0:~# xl info
host                   : dom0
release                : 6.8.0-138-generic
version                : #138-Ubuntu SMP PREEMPT_DYNAMIC Fri Jul 31 22:41:49 UTC 2026
machine                : x86_64
nr_cpus                : 24
max_cpu_id             : 31
nr_nodes               : 1
cores_per_socket       : 24
threads_per_core       : 1
cpu_mhz                : 2995.200
hw_caps                : bfebfbff:77fafbbf:2c100800:00000121:0000000f:239c27eb:984007ac:00000100
virt_caps              : pv hvm hvm_directio pv_directio hap shadow iommu_hap_pt_share vmtrace gnttab-v1 gnttab-v2
total_memory           : 32605
free_memory            : 24085
sharing_freed_memory   : 0
sharing_used_memory    : 0
outstanding_claims     : 0
free_cpus              : 0
xen_major              : 4
xen_minor              : 20
xen_extra              : .1
xen_version            : 4.20.1
xen_caps               : xen-3.0-x86_64 hvm-3.0-x86_32 hvm-3.0-x86_32p hvm-3.0-x86_64 
xen_scheduler          : credit
xen_pagesize           : 4096
platform_params        : virt_start=0xffff800000000000
xen_changeset          : 
xen_commandline        : placeholder dom0_mem=8192M,max:8192M dom0_max_vcpus=6 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0 sched=credit no-real-mode edd=off
cc_compiler            : gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
cc_compile_by          : root
cc_compile_domain      : 
cc_compile_date        : Thu Aug  6 04:58:41 UTC 2026
build_id               : d04bef7bc2c53c2ac300cd1d5a47525621ab46c0
xend_config_format     : 4
root@dom0:~# xl info -n                        # per-CPU topology as Xen sees it
host                   : dom0
release                : 6.8.0-138-generic
version                : #138-Ubuntu SMP PREEMPT_DYNAMIC Fri Jul 31 22:41:49 UTC 2026
machine                : x86_64
nr_cpus                : 24
max_cpu_id             : 31
nr_nodes               : 1
cores_per_socket       : 24
threads_per_core       : 1
cpu_mhz                : 2995.200
hw_caps                : bfebfbff:77fafbbf:2c100800:00000121:0000000f:239c27eb:984007ac:00000100
virt_caps              : pv hvm hvm_directio pv_directio hap shadow iommu_hap_pt_share vmtrace gnttab-v1 gnttab-v2
total_memory           : 32605
free_memory            : 24085
sharing_freed_memory   : 0
sharing_used_memory    : 0
outstanding_claims     : 0
free_cpus              : 0
cpu_topology           :
cpu:    core    socket     node
  0:       0        0        0
  1:       0        0        0
  2:       4        0        0
  3:       4        0        0
  4:       8        0        0
  5:       8        0        0
  6:      12        0        0
  7:      12        0        0
  8:      16        0        0
  9:      16        0        0
 10:      20        0        0
 11:      20        0        0
 12:      24        0        0
 13:      24        0        0
 14:      28        0        0
 15:      28        0        0
 16:      32        0        0
 17:      33        0        0
 18:      34        0        0
 19:      35        0        0
 20:      36        0        0
 21:      37        0        0
 22:      38        0        0
 23:      39        0        0
 24:      40        0        0
 25:      41        0        0
 26:      42        0        0
 27:      43        0        0
 28:      44        0        0
 29:      45        0        0
 30:      46        0        0
 31:      47        0        0
device topology        :
device           node
No device topology data available
numa_info              :
node:    memsize    memfree    distances
   0:     35840      24085      10
xen_major              : 4
xen_minor              : 20
xen_extra              : .1
xen_version            : 4.20.1
xen_caps               : xen-3.0-x86_64 hvm-3.0-x86_32 hvm-3.0-x86_32p hvm-3.0-x86_64 
xen_scheduler          : credit
xen_pagesize           : 4096
platform_params        : virt_start=0xffff800000000000
xen_changeset          : 
xen_commandline        : placeholder dom0_mem=8192M,max:8192M dom0_max_vcpus=6 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0 sched=credit no-real-mode edd=off
cc_compiler            : gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
cc_compile_by          : root
cc_compile_domain      : 
cc_compile_date        : Thu Aug  6 04:58:41 UTC 2026
build_id               : d04bef7bc2c53c2ac300cd1d5a47525621ab46c0
xend_config_format     : 4
root@dom0:~# xl dmesg | grep -Ei 'cpu|vmx|ept|hap|altp2m|smt|hybrid|core'
(XEN) CPU Vendor: Intel, Family 6 (0x6), Model 183 (0xb7), Stepping 1 (raw 000b0671)
(XEN) Command line: placeholder dom0_mem=8192M,max:8192M dom0_max_vcpus=6 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0 sched=credit no-real-mode edd=off
(XEN) ACPI: SSDT 39118000, 5D34 (r2 CpuRef  CpuSsdt     3000 INTL 20200717)
(XEN) ACPI: WSMT 39101000, 0028 (r1 ALASKA   A M I   1072009 AMI     10013)
(XEN) SMP: Allowing 32 CPUs (0 hotplug CPUs)
(XEN) CPU0: TSC: 38400000 Hz * 156 / 2 = 2995200000 Hz
(XEN) CPU0: bus: 100 MHz base: 3000 MHz max: 5800 MHz
(XEN) CPU0: 800 ... 3000 MHz
(XEN) CPU0: Intel machine check reporting enabled
(XEN) Unrecognised CPU model 0xb7 - assuming vulnerable to LazyFPU
(XEN) Intel VT-d Shared EPT tables enabled.
(XEN) VMX: Supported advanced features:
(XEN)  - Extended Page Tables (EPT)
(XEN)  - Virtualisation Exceptions
(XEN) HVM: VMX enabled
(XEN) HVM: Hardware Assisted Paging (HAP) detected
(XEN) HVM: HAP page sizes: 4kB, 2MB [disabled], 1GB [disabled]
(XEN) Brought up 24 CPUs
(XEN) Parked 8 CPUs
(XEN) Scheduling granularity: cpu, 1 CPU per sched-resource
(XEN) Dom0 has maximum 6 VCPUs
root@dom0:~# xl vcpu-list 0
Name                                ID  VCPU   CPU State   Time(s) Affinity (Hard / Soft)
Domain-0                             0     0    0   -b-     102.2  0 / all
Domain-0                             0     1    2   -b-      83.4  2 / all
Domain-0                             0     2    4   -b-      89.6  4 / all
Domain-0                             0     3    6   r--     111.0  6 / all
Domain-0                             0     4    8   -b-     120.9  8 / all
Domain-0                             0     5   10   -b-      76.5  10 / all
```

Read three things:

| Check | Expect | If not |
|---|---|---|
| `nr_cpus` | 24 with `smt=0` (8 P + 16 E), or 32 without | a lower number may mean Xen dropped CPUs it could not classify — read `xl dmesg` |
| `threads_per_core` / `cores_per_socket` | something coherent | a hybrid host can produce nonsense here; record it verbatim |
| Dom0's 6 vCPUs | pinned to pCPU 0–5 | see below — **which physical cores are those?** |

> ## The measurement's own confounder
>
> `dom0_vcpus_pin` pins Dom0 vCPU *N* to Xen pCPU *N*. **Nothing guarantees Xen
> pCPU 0–5 are P-cores.** If Xen enumerates E-cores early, Dom0's DRAKVUF thread
> runs on an E-core and `events/sec` drops for a reason that has nothing to do
> with nesting — bare metal would look worse while being better.
>
> ### `/sys/devices/cpu_core/cpus` does NOT answer this in Dom0
>
> An earlier draft said to cross-check against that path. **That was valid on
> the Proxmox host and is not valid here.** Native Linux populates
> `cpu_core`/`cpu_atom` from CPUID leaf `0x1A`; **Dom0 is a PV guest**, sees
> Xen's vCPUs rather than physical CPUs, and only gets that leaf if Xen chose to
> expose it. Expect the path to be missing, or to describe Dom0's six pinned
> vCPUs rather than the machine. Look if you like; do not decide on it.

Three ways to identify the core type behind each Xen pCPU, weakest first.
**§C3 always works** and is what EVIDENCE C should rest on.

### C1. Xen's own topology table

```bash
# TRIAL
root@dom0:~# xl info -n
host                   : dom0
release                : 6.8.0-138-generic
version                : #138-Ubuntu SMP PREEMPT_DYNAMIC Fri Jul 31 22:41:49 UTC 2026
machine                : x86_64
nr_cpus                : 24
max_cpu_id             : 31
nr_nodes               : 1
cores_per_socket       : 24
threads_per_core       : 1
cpu_mhz                : 2995.200
hw_caps                : bfebfbff:77fafbbf:2c100800:00000121:0000000f:239c27eb:984007ac:00000100
virt_caps              : pv hvm hvm_directio pv_directio hap shadow iommu_hap_pt_share vmtrace gnttab-v1 gnttab-v2
total_memory           : 32605
free_memory            : 24085
sharing_freed_memory   : 0
sharing_used_memory    : 0
outstanding_claims     : 0
free_cpus              : 0
cpu_topology           :
cpu:    core    socket     node
  0:       0        0        0
  1:       0        0        0
  2:       4        0        0
  3:       4        0        0
  4:       8        0        0
  5:       8        0        0
  6:      12        0        0
  7:      12        0        0
  8:      16        0        0
  9:      16        0        0
 10:      20        0        0
 11:      20        0        0
 12:      24        0        0
 13:      24        0        0
 14:      28        0        0
 15:      28        0        0
 16:      32        0        0
 17:      33        0        0
 18:      34        0        0
 19:      35        0        0
 20:      36        0        0
 21:      37        0        0
 22:      38        0        0
 23:      39        0        0
 24:      40        0        0
 25:      41        0        0
 26:      42        0        0
 27:      43        0        0
 28:      44        0        0
 29:      45        0        0
 30:      46        0        0
 31:      47        0        0
device topology        :
device           node
No device topology data available
numa_info              :
node:    memsize    memfree    distances
   0:     35840      24085      10
xen_major              : 4
xen_minor              : 20
xen_extra              : .1
xen_version            : 4.20.1
xen_caps               : xen-3.0-x86_64 hvm-3.0-x86_32 hvm-3.0-x86_32p hvm-3.0-x86_64 
xen_scheduler          : credit
xen_pagesize           : 4096
platform_params        : virt_start=0xffff800000000000
xen_changeset          : 
xen_commandline        : placeholder dom0_mem=8192M,max:8192M dom0_max_vcpus=6 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0 sched=credit no-real-mode edd=off
cc_compiler            : gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
cc_compile_by          : root
cc_compile_domain      : 
cc_compile_date        : Thu Aug  6 04:58:41 UTC 2026
build_id               : d04bef7bc2c53c2ac300cd1d5a47525621ab46c0
xend_config_format     : 4
```

`cpu_topology` lists `cpu / core / socket / node`. Two signals:

- **Without `smt=0`**, P-cores appear as *two CPUs sharing one `core` id*;
  E-cores have a unique `core` id each — a clean discriminator.
- **With `smt=0`**, which this boot line sets, Xen parks the sibling threads, so
  every online CPU is one-per-core and **that pairing disappears.** `nr_cpus 24`
  is consistent with 8 P + 16 E, but the table alone cannot say which is which.

On Raptor Lake the ACPI MADT usually lists P-cores first, so Xen CPU 0–7 being
the P-cores is the *expected* layout. **Expected is not measured.**

### C2. CPUID leaf 0x1A — definitive when Xen passes it through

Leaf `0x1A` is the architectural hybrid core-type report: `EAX[31:24]` is
**`0x40` for a P-core (Core)** and **`0x20` for an E-core (Atom)**. With
`dom0_vcpus_pin`, Dom0 vCPU *N* sits on Xen pCPU *N*, so pinning the read
identifies that pCPU:

```bash
# TRIAL
root@dom0:~# apt install -y cpuid
for c in 0 1 2 3 4 5; do
    printf 'dom0 vcpu %s -> ' "$c"
    taskset -c "$c" cpuid -1 -l 0x1a 2>/dev/null | grep -i 'core type' \
        || echo 'leaf 0x1A not exposed'
done
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
cpuid is already the newest version (20240330-1ubuntu2).
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
dom0 vcpu 0 ->       core type               = 0x0 (0)
dom0 vcpu 1 ->       core type               = 0x0 (0)
dom0 vcpu 2 ->       core type               = 0x0 (0)
dom0 vcpu 3 ->       core type               = 0x0 (0)
dom0 vcpu 4 ->       core type               = 0x0 (0)
dom0 vcpu 5 ->       core type               = 0x0 (0)
```

**Result 2026-08-27: `core type = 0x0` on all six.** Note what that is and is
not — `0x0` is not a defined core type (`0x20` = Atom, `0x40` = Core), so Xen
**exposed leaf `0x1A` and zeroed its contents** rather than hiding it. The leaf
is readable and carries no information. C2 is inconclusive here, as anticipated;
go to C3.

### C3. Time a fixed loop per vCPU — always works

E-cores are markedly slower single-threaded. Since the real question is *"is the
DRAKVUF thread on a fast core"*, measuring speed answers it directly instead of
by inference:

```bash
# TRIAL -- identical binary and workload, one pinned run per Dom0 vCPU
root@dom0:~# for c in 0 1 2 3 4 5; do
    printf 'vcpu %s: ' "$c"
    /usr/bin/time -f '%e s' taskset -c "$c" \
        sh -c 'i=0; while [ $i -lt 2000000 ]; do i=$((i+1)); done'
done
vcpu 0: 1.15 s
vcpu 1: 1.14 s
vcpu 2: 1.14 s
vcpu 3: 1.12 s
vcpu 4: 1.15 s
vcpu 5: 1.13 s
```

Read the **spread**, not the absolute times. A shell loop is a poor benchmark
absolutely and a perfectly good one relatively, because it is the same binary on
every core. Two distinct clusters means Dom0 spans both core types; uniform
times mean it does not.

**Result 2026-08-27: uniform.** 1.12–1.15 s across all six, a ~2.7% spread that
is noise. Dom0's six vCPUs are all the same core type as each other.

> ### Uniform is only half an answer — C3a supplies the other half
>
> "All the same" does not say *which*. A cluster of six E-cores would also read
> uniform, and 1.14 s means nothing without a contrast on this machine, with
> this shell, on this day.

### C3a. The E-core control — turns "uniform" into "uniform and fast"

Move one Dom0 vCPU onto a known E-core, re-time, put it back. `dom0_vcpus_pin`
sets affinity at boot, but affinity is a **runtime** property and `xl vcpu-pin`
overrides it without a reboot.

```bash
# TRIAL
root@dom0:~# xl vcpu-list 0                    # read it, then capture rather than hand-copy
Name                                ID  VCPU   CPU State   Time(s) Affinity (Hard / Soft)
Domain-0                             0     0    0   -b-     107.1  0 / all
Domain-0                             0     1    2   -b-      87.5  2 / all
Domain-0                             0     2    4   -b-      94.4  4 / all
Domain-0                             0     3    6   ---     113.0  6 / all
Domain-0                             0     4    8   -b-     128.4  8 / all
Domain-0                             0     5    6   r--      79.8  0,2,4,6,8,10 / all
root@dom0:~# ORIG=$(xl vcpu-list 0 | awk '$3==5 {print $7}')
root@dom0:~# echo "vcpu 5 pinned to pCPU $ORIG"      # expect 10, per the C4 decode
vcpu 5 pinned to pCPU 0,2,4,6,8,10
root@dom0:~# xl vcpu-pin 0 5 16                # 16 is an E-core, per C4's pool list
root@dom0:~# /usr/bin/time -f 'E-core: %e s' taskset -c 5 \
    sh -c 'i=0; while [ $i -lt 2000000 ]; do i=$((i+1)); done'
E-core: 1.92 s
root@dom0:~# xl vcpu-pin 0 5 "$ORIG"           # restore
root@dom0:~# xl vcpu-list 0 | awk 'NR==1 || $3==5'
Name                                ID  VCPU   CPU State   Time(s) Affinity (Hard / Soft)
Domain-0                             0     5    0   -b-      81.8  0,2,4,6,8,10 / all
```

> **This cannot do lasting damage.** The pinning comes from
> `dom0_vcpus_pin` on the Xen boot line, so **a reboot restores it in full.** If
> the restore misbehaves, `xl vcpu-pin 0 5 all` unsticks the vCPU and a reboot
> puts the boot-line pinning back.

| Result | Meaning |
|---|---|
| **markedly slower than ~1.13 s** | 0–14-even are P-cores, Dom0 is on them, **and** the loop discriminates — C3's uniform result is now meaningful |
| **≈ 1.14 s, same as before** | the test cannot tell the core types apart, so C3 proved nothing. Use a heavier loop, or accept C4's topology decode as the answer |

### C4. Decode the pool list — and check whether anything needs doing

```bash
# TRIAL
root@dom0:~# xl cpupool-list -c
Name               CPU list
Pool-0             0,2,4,6,8,10,12,14,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
# move the P-cores into a pool, put Dom0 there, then re-run C3
```

> ### The pool list already decodes the topology
>
> ```
> Pool-0  0,2,4,6,8,10,12,14, 16,17,18,19,...,31
>         └─ 8 evens in 0-15 ─┘ └─ 16 contiguous ─┘
> ```
>
> - **Evens 0–14 are the P-cores**, one thread each. The odd siblings
>   1,3,…,15 are absent because **`smt=0` parked them** — they are offline, not
>   renumbered.
> - **16–31 are the E-cores**, all sixteen present, because they have no SMT
>   sibling to park.
>
> 8 + 16 = 24, which matches `nr_cpus` exactly. Xen's pCPU numbering follows the
> firmware/ACPI numbering, so the layout is the *expected* one from §C1 — now
> measured rather than assumed.
>
> **This also explains what `dom0_vcpus_pin` did.** It cannot have pinned Dom0
> vCPU *N* to pCPU *N*, because pCPUs 1, 3 and 5 are offline. Dom0 must have
> taken the first six **online** pCPUs — `0,2,4,6,8,10` — all of them P-cores.
> `xl vcpu-list 0` confirms it, and that is the fact EVIDENCE C needs.

**If C3a and `xl vcpu-list 0` agree that Dom0 is entirely on P-cores, there is
nothing to do here** — skip to C5. A cpupool would be ceremony.

Only if Dom0 straddles both types:

```bash
# TRIAL -- create a P-core-only pool and move Dom0 into it
root@dom0:~# xl cpupool-list -c
Name               CPU list
Pool-0             0,2,4,6,8,10,12,14,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
```

**The confirmation is that C3's spread collapsed**, not that the command
succeeded.

### C5. Smoke test — can Xen run a guest at all?

Part D restores the real guest; this only proves the hypervisor is usable.

```bash
# TRIAL
root@dom0:~# xl info | grep -E 'virt_caps|xen_caps'
virt_caps              : pv hvm hvm_directio pv_directio hap shadow iommu_hap_pt_share vmtrace gnttab-v1 gnttab-v2
xen_caps               : xen-3.0-x86_64 hvm-3.0-x86_32 hvm-3.0-x86_32p hvm-3.0-x86_64 
root@dom0:~# xl list
Name                                        ID   Mem VCPUs	State	Time(s)
Domain-0                                     0  8192     6     r-----     614.6
root@dom0:~# xl dmesg | grep -Ei 'altp2m|ept|vmx'
(XEN) Command line: placeholder dom0_mem=8192M,max:8192M dom0_max_vcpus=6 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0 sched=credit no-real-mode edd=off
(XEN) Intel VT-d Shared EPT tables enabled.
(XEN) VMX: Supported advanced features:
(XEN)  - Extended Page Tables (EPT)
(XEN)  - Virtualisation Exceptions
(XEN) HVM: VMX enabled
```

`virt_caps` must include **`hvm hap`** — without HAP there is no altp2m and
DRAKVUF cannot work at all. If these look right, a guest failing later is a
Part D problem, not a Part C one.

**If Xen does not boot at all**: record `xl dmesg` in full, try a P-core
cpupool, and if that fails too, **stop.** The migration is not viable on this
hardware. That is a valid outcome — and under the erase route it is the
expensive one, which is why §A1b argued for answering it from a USB stick first.

EVIDENCE C

```
xl info nr_cpus:            24        (8 P + 16 E with smt=0)

C4 pool list:               Pool-0  0,2,4,6,8,10,12,14,16..31
  -> decoded:               P-cores = evens 0-14 (odd siblings parked by smt=0)
                            E-cores = 16-31 (no SMT to park)   8+16 = 24 OK

C2 leaf 0x1A:               core type = 0x0 on all six
  -> reading:               Xen EXPOSED the leaf and ZEROED it. 0x0 is not a
                            defined type (0x20 Atom / 0x40 Core). Inconclusive.

C3 per-vcpu loop (0..5):    1.15 1.14 1.14 1.12 1.15 1.13 s
  -> uniform (~2.7% spread, noise). Same core type as each other; type unknown
     from this alone.

C3a vcpu 5 moved to pCPU 16 (E-core):   1.92 s   vs ~1.13 s on a P-core
  -> 1.70x slower. The loop DISCRIMINATES, so C3's uniform result is
     meaningful: all six vCPUs were on P-cores.

xl vcpu-list 0 hard affinity:
     vcpu 0 -> 0        vcpu 3 -> 6
     vcpu 1 -> 2        vcpu 4 -> 8
     vcpu 2 -> 4        vcpu 5 -> 0,2,4,6,8,10    <-- NOT PINNED
  -> vcpus 0-4 pinned 1:1 to the first five ONLINE pCPUs, confirming the C4
     decode. pCPU 10 is claimed by nobody.

Dom0 entirely on P-cores?   YES -- but by mask, not by pinning. vcpu 5's
                            affinity set is all P-cores, so it cannot reach an
                            E-core. Confinement holds; 1:1 pinning does not.
cpupool needed?             NO. Dom0 cannot reach 16-31. See the vcpu-pin fix.
virt_caps includes hvm hap: YES -- "pv hvm hvm_directio pv_directio hap shadow
                            iommu_hap_pt_share vmtrace gnttab-v1 gnttab-v2"
                            EPT + VMX confirmed in xl dmesg. altp2m=1 on the
                            command line.
```

> **FINDING C-1 — `dom0_vcpus_pin` did not pin vCPU 5.** Five of six pinned
> 1:1; the sixth kept the default mask and floated. Bare-metal-only: `smt=0`
> leaves a sparse online pCPU set where nested had contiguous `0-11`.
> `xl vcpu-pin 0 5 10` fixes it and does not survive reboot. See
> [TROUBLESHOOTING](../TROUBLESHOOTING.md#xl-vcpu-list-0-shows-one-vcpu-with-a-multi-cpu-affinity-mask).

---

# Part D — get a traceable guest onto the trial system

**The trial needs `ubuntu_sandbox`, which `pbs-backups.md` deliberately does
not back up.** Clones restore from `state/ubuntu_sandbox.bak` against that LV,
not against the golden `ubuntu` — `clone.pl:126`, `sandboxd/clone.py:89`.

> ### DECISION 2026-08-27: rebuild the `_sandbox` LVs, do not transfer them
>
> The operator will recreate `ubuntu_sandbox`, `android_sandbox` and
> `windows_sandbox` from the restored goldens rather than move them across.
> That is consistent with the backup-scope decision — they were excluded
> *because* they are reproducible — and under the erase route of §A1b there is
> nothing to transfer from anyway.
>
> **The rebuild procedure is not written yet.** It is the
> `03-rebuild-android-sandbox.md` shape applied per OS: copy golden → apply
> preconfig → boot → save state → re-derive the injection PID. Write it as its
> own runbook when §A1b's route is settled, because what it starts from differs
> between the routes.

> ## Record the injection PID for every OS, at the moment it is derived
>
> **This is the step most likely to be lost.** The saved memory image and its
> PID are a matched pair: `state/<origin>.bak` is only usable with the PID that
> was live inside it when it was saved, and re-saving state invalidates the old
> one. `CURRENT-STATE` §1.4 currently records **Ubuntu 1415, Android 3174** —
> both of which become wrong the moment the states are rebuilt.
>
> Capture it as the state is saved, not afterwards from memory:
>
> ```bash
> # DOM0, against the running golden domain before xl save
> vmi-process-list <domain> | head -40
> ```
>
> Write each one here as it is derived, and carry them into `CURRENT-STATE`
> §1.4 in the same change:
>
>     ubuntu_sandbox   injection PID: ______   state saved: ____________
>     android_sandbox  injection PID: ______   state saved: ____________
>     windows_sandbox  injection PID: ______   state saved: ____________
>
> Also update `sandboxd`'s per-OS configuration and `pipeline-*.env` — a stale
> PID does not error, it injects into the wrong process.

**If the route is a second disk or USB (rollback intact), a one-off PBS transfer
is still the faster way to get a guest onto the trial system** — the rebuild can
wait until the migration is actually decided. That is a different decision from
the routine-backup one and does not reopen it: prune the snapshot afterwards.

```bash
# DOM0, booted back into the nested lab (or before starting Part B)
proxmox-backup-client backup \
    ubuntu_sandbox.img:/dev/vg-root/ubuntu_sandbox \
    --backup-type host --backup-id trial-transfer --ns dom0 \
    --keyfile /root/.config/proxmox-backup/encryption-key.json
```

## D1. BLOCKER — the VG is `ubuntu-vg`, and it must be `vg-root`

Observed 2026-08-27 on the trial system:

```
VG          #PV #LV #SN Attr   VSize  VFree
ubuntu-vg     1   4   0 wz--n- <1.82t <161.00g

LV             VG        Attr       LSize   Pool     Origin  Data%
thinpool       ubuntu-vg twi-aotz--   1.38t                  0.00
ubuntu         ubuntu-vg Vwi-a-tz--   1.00t thinpool         0.00
ubuntu-1-clone ubuntu-vg Vwi---tz-k   1.00t thinpool ubuntu
ubuntu-lv      ubuntu-vg -wi-ao---- 250.00g
```

`ubuntu-vg` / `ubuntu-lv` are **subiquity's defaults** — the pre-created layout
from §B0a was not used. Two things follow.

**Rename the VG rather than reconfiguring around it.** `clone.pl:231` reads
`env_or("VG_NAME", "vg-root")` and `:488` rewrites each clone's `disk =` line
from it, so *clones* are parameterised. But **five `misc/*.cfg` files hardcode
`/dev/vg-root/`** (`ubuntu`, `ubuntu_sandbox`, `android`, `android_sandbox`,
`windows`) and those drive the golden domains through `xl create` directly,
unrewritten. Keeping `ubuntu-vg` means editing five tracked config files, adding
a `VG_NAME` export everywhere, and permanently living with device-mapper
dash-escaping (`/dev/mapper/ubuntu--vg-ubuntu`) in anything that reads `kpartx`
output.

```bash
# TRIAL -- root lives on this VG, so regenerate boot config before rebooting
sudo vgrename ubuntu-vg vg-root

# BOTH spellings -- see the correction below
grep -rn 'ubuntu--vg\|ubuntu-vg' \
    /etc/fstab /etc/default/grub /boot/grub/grub.cfg /etc/initramfs-tools/
grep -v '^#' /etc/fstab | grep -w '/'      # the real root entry, not the comment

# update-grub CANNOT succeed before the reboot -- /proc/mounts still carries the
# old name, so grub-probe cannot resolve root. Hand-edit to reach a bootable
# state, reboot, then regenerate.
sudo grep -n 'root=' /boot/grub/grub.cfg           # mode 600 -- sudo needed
sudo cp /boot/grub/grub.cfg /boot/grub/grub.cfg.bak
sudo sed -i 's/ubuntu--vg-ubuntu--lv/vg--root-ubuntu--lv/g' /boot/grub/grub.cfg
sudo grep -n 'root=' /boot/grub/grub.cfg           # must say vg--root-ubuntu--lv
sudo reboot

# AFTER the reboot -- both now succeed
sudo update-grub2 && sudo update-initramfs -u -k all
```

> Why the reboot has to come first, and what `update-grub` failing does and does
> not cost: see
> [TROUBLESHOOTING](../TROUBLESHOOTING.md#update-grub-and-update-initramfs-error-on-a-device-that-no-longer-exists).

> **Both spellings above are required, not belt-and-braces** — a grep for
> `ubuntu-vg` alone cannot match `grub.cfg`. See
> [TROUBLESHOOTING](../TROUBLESHOOTING.md#grep--rn-ubuntu-vg-came-back-clean-while-grub-still-used-the-old-name).

> ## WATCH — `drakvuf-bundle` rewrites the Xen boot line on every `update-grub`
>
> Observed during the post-rename regeneration:
>
> ```
> Including Xen overrides from /etc/default/grub.d/xen.cfg
> Detected that drakvuf-bundle is installed.
> Resources dedicated to Dom0 (host system):
> -> CPU core(s): 12
> -> Memory: 16302 MB
> WARNING: GRUB_DEFAULT changed to boot into Xen by default!
> ```
>
> **Those are not this runbook's parity values** (`dom0_mem=8192M,max:8192M
> dom0_max_vcpus=6`). `drakvuf-bundle` installs `/etc/default/grub.d/xen.cfg`,
> which *computes* Dom0's resources and can silently replace what Part B set —
> on any `update-grub`, including ones run for unrelated reasons.
>
> Two consequences if it wins:
>
> - **Part E stops measuring what Part C characterised.** The parity config is
>   the entire basis of the nested-vs-bare comparison.
> - **12 Dom0 vCPUs against 8 online P-cores** (`0,2,4,…,14`) is oversubscription
>   of exactly the kind `10-tune-nested-cpu.md` exists to chase, reappearing one
>   layer down. FINDING C-1's single floating vCPU would become four.
>
> Verify after **every** `update-grub`, not just this one:
>
> ```bash
> xl list                          # Domain-0: expect 8192 and 6
> xl info | grep xen_commandline
> cat /etc/default/grub.d/xen.cfg  # edit here, not in /etc/default/grub
> ```

> ## `cryptsetup: ERROR: Couldn't resolve device` is expected noise here
>
> Observed 2026-08-27 during `update-initramfs` after the rename:
>
> ```
> cryptsetup: ERROR: Couldn't resolve device /dev/mapper/ubuntu--vg-ubuntu--lv
> cryptsetup: WARNING: Couldn't determine root device
> ```
>
> **Not a failure, and not a reason to interrupt.** There is no LUKS on this
> host. The cryptsetup hook resolves the root device to decide which crypto
> support to bundle, and it reads the **stale** name from `/proc/cmdline` —
> which still carries the pre-rename device because that is what GRUB passed at
> the last boot. It cannot become correct until after the next reboot. The hook
> prints, continues, and the image is built. Judge it by exit status.
>
> **Interrupting it is the actual hazard.** A `^C` mid-generation can leave a
> truncated `/boot/initrd.img-*`, and a fresh install has only one kernel — so
> there is no older initrd to fall back to at the GRUB menu. If it was
> interrupted:
>
> ```bash
> ls -la /boot/initrd.img-*        # a truncated image is conspicuously small
> sudo update-initramfs -u -k all  # let it run to completion
> echo "exit=$?"
> ```

Ubuntu's `/etc/fstab` normally references `dm-uuid-LVM-<uuid>`, which encodes the
VG *UUID* and survives a rename; GRUB's `root=` uses the mapper *name* and does
not. The `# / was on /dev/ubuntu-vg/ubuntu-lv during curtin installation` line
is a comment and needs no edit — check the entry below it. **Verify `grub.cfg`
before rebooting**: that check is the difference between a rename and an
unbootable host. Do it while the system is empty; it only gets more expensive.

> **Confirmed here, not merely predicted:** `ubuntu-1-clone` reads
> `Vwi---tz-k` — activation-skip set, no `/dev` node.

## D2. Restore the golden into the 1 TB thin volume

**`ubuntu` already exists as a 1.00t thin volume at 0.00% data — do not
`lvcreate` it again.** The line this step used to carry
(`lvcreate -L 64G -n ubuntu_sandbox vg-root`) is wrong twice over: the volume
exists, and it is 1 TB thin rather than 64 GB thick.

```bash
# TRIAL
root@dom0:~# blockdev --getsize64 /dev/vg-root/ubuntu       # ~1.1e12, the thin volume
1099511627776
root@dom0:~# proxmox-backup-client snapshot list --ns dom0
┌─────────────────────────────────────────┬───────────┬──────────────────────────────────────
│ snapshot                                │      size │ files                                
╞═════════════════════════════════════════╪═══════════╪══════════════════════════════════════
│ host/dom0-critical/2026-08-27T19:56:08Z │ 4.102 GiB │ catalog.pcat1 etc.pxar index.json pro
├─────────────────────────────────────────┼───────────┼──────────────────────────────────────
│ host/dom0-golden/2026-08-27T19:57:09Z   │   224 GiB │ android.img index.json ubuntu.img win
└─────────────────────────────────────────┴───────────┴──────────────────────────────────────
root@dom0:~# proxmox-backup-client restore host/dom0-golden/2026-08-27T19:57:09Z \
    ubuntu.img - --ns dom0 \
    --keyfile /root/.config/proxmox-backup/encryption-key.json \
  | dd of=/dev/vg-root/ubuntu bs=4M conv=sparse status=progress
Encryption Key Password: ****************************************************************************************************************************************************************
Using encryption key from '/root/.config/proxmox-backup/encryption-key.json'..    
Fingerprint: 4f:15:85:70:27:c5:c4:c0    
1929445376 bytes (1.9 GB, 1.8 GiB) copied, 11 s, 175 MB/sprogress 2% (1.824 GiB of 64 GiB in 5s, 373.233 MiB/s)    
2667642880 bytes (2.7 GB, 2.5 GiB) copied, 21 s, 127 MB/sprogress 3% (2.492 GiB of 64 GiB in 15.1s, 67.964 MiB/s)    
5377163264 bytes (5.4 GB, 5.0 GiB) copied, 41 s, 131 MB/sprogress 7% (5.023 GiB of 64 GiB in 35.1s, 129.318 MiB/s)    
14659289088 bytes (15 GB, 14 GiB) copied, 81 s, 181 MB/sprogress 21% (13.746 GiB of 64 GiB in 1m 15.1s, 223.299 MiB/s)    
23785963520 bytes (24 GB, 22 GiB) copied, 141 s, 169 MB/sprogress 34% (22.164 GiB of 64 GiB in 2m 15.1s, 143.629 MiB/s)    
43847319552 bytes (44 GB, 41 GiB) copied, 201 s, 218 MB/sprogress 63% (40.855 GiB of 64 GiB in 3m 15.2s, 318.801 MiB/s)    
48066789376 bytes (48 GB, 45 GiB) copied, 261 s, 184 MB/sprogress 69% (44.793 GiB of 64 GiB in 4m 15.2s, 67.165 MiB/s)    
54140141568 bytes (54 GB, 50 GiB) copied, 321 s, 169 MB/sprogress 78% (50.457 GiB of 64 GiB in 5m 15.2s, 96.616 MiB/s)    
65603174400 bytes (66 GB, 61 GiB) copied, 381 s, 172 MB/sprogress 95% (61.113 GiB of 64 GiB in 6m 15.2s, 181.834 MiB/s)    
68436164608 bytes (68 GB, 64 GiB) copied, 404 s, 169 MB/srestore complete (64 GiB processed in 6m 38.7s, average 164.366 MiB/s)    

0+1048576 records in
0+1048576 records out
68719476736 bytes (69 GB, 64 GiB) copied, 405.513 s, 169 MB/s
```

Two deliberate differences from `pbs-backups.md` §E1:

- **The size check becomes `target >= image`, not equality.** The archive is the
  old **64 GB** thick LV; the target is **1 TB**. §E1's equality check exists to
  catch truncation, and here a mismatch is the intended design. Verify instead
  that `dd` reports ~64 GB written and exits 0.
- **`conv=sparse`** makes `dd` seek over all-zero blocks instead of writing
  them. Without it the pool allocates real extents for 64 GB of mostly-empty
  image and the thin saving is thrown away on the first command that uses it.
  Check `Data%` in `lvs` afterwards: it should be far below 64 GB / 1.38 T.

**Then grow the filesystem, which is where the 1 TB becomes real.** Until this
happens the guest still sees a 64 GB filesystem on a 1 TB disk, and the
anti-evasion goal buys nothing — a 1 TB LV holding a 64 GB filesystem shows
64 GB to a sample. Boot the golden domain, grow its partition and filesystem to
fill the device, then shut it down.

## D2a. Verify the restored filesystem — mounting is not enough

**A read-only mount proves almost nothing.** `ls /mnt` walks directory entries;
it does not validate extents, reference counts or the journal. Run a real check
on each restored golden before anything is built on it:

```bash
# DOM0 -- takes a minute per image, and nothing may be using the LV
sudo kpartx -av /dev/vg-root/ubuntu
sudo e2fsck -f -y /dev/mapper/vg--root-ubuntu5
sudo kpartx -d /dev/vg-root/ubuntu
```

Read the output, not just the exit code — how much it repaired tells you
whether the image is trustworthy or should be rebuilt from the ISO.

EVIDENCE D2a — 2026-08-28

```
/dev/mapper/vg--root-ubuntu5: 181581/4161536 files (0.2% non-contiguous),
                              4936400/16645376 blocks
Passes 1-5 clean, no repairs. The restored golden is sound.
```

`windows` needs `chkdsk` from a Windows recovery environment, not `e2fsck`.
`android` is ext4 and takes the same treatment as Ubuntu — check both before
building templates on them, since each would otherwise reveal a problem only at
its own first cold boot.

> **FINDING D-1 — a cold boot is the first thing that touches the disk.**
> `ubuntu_sandbox` dropped to an initramfs shell on `xl create`; `e2fsck` on
> the golden came back clean. The `.bak` had been saved from the *old sandbox*
> disk and restored onto a snapshot of the *golden*.
>
> **Rule: never restore a `.bak` against a disk it was not saved from.**
> Rebuild the template per §D5 instead. Every check that passed beforehand was
> memory-only, and the 902 events/sec measured here describes a degraded
> guest — discard it. See
> [TROUBLESHOOTING](../TROUBLESHOOTING.md#a-clone-drops-to-an-initramfs-shell-with-unexpected-inconsistency).

## D3. Then the rest

Restore from the `dom0-critical` snapshot: `state/ubuntu_sandbox.bak`,
`profiles/linux.json`, and `/etc/libvmi.conf`. Then check out the repository at
the same commit.

**`ubuntu_sandbox` is now built as a thin snapshot of `ubuntu`**, not as a
separate full-size volume — instant, and it costs only what diverges:

```bash
sudo lvcreate -s -kn -n ubuntu_sandbox vg-root/ubuntu
sudo lvs -o +lv_attr vg-root          # ubuntu_sandbox must NOT show 'k'
```

That gives a *disk*. It does not give a usable template — see §D5.

---

# Part D5 — rebuilding a `_sandbox` template

Run once per OS. **This is the step that produces a valid `state/*.bak` and a
valid injection PID**, and doing it is the only way to fix the mismatch this
deployment currently has: `ubuntu_sandbox` is a snapshot of the *golden* disk
while `state/ubuntu_sandbox.bak` was saved from the *old sandbox* disk.

> **`preconfig-*.sh` is not part of this** — it runs at *analysis* time against
> a *clone* and never touches the template. What makes a template is booting the
> disk, starting an injection anchor, and `xl save`. See
> [TROUBLESHOOTING](../TROUBLESHOOTING.md#preconfig-sh-does-not-build-a-template--it-runs-at-analysis-time).

## D5.1. What the anchor is, and why the PID is not arbitrary

`injector` needs an existing process to vfork/execve from. `INJECTION_PID`
(`automation/pipeline-ubuntu.env:193`, currently `1415`) names it.

Three properties, each of which has bitten this project:

- **It exists only inside the memory image.** `03-rebuild-android-sandbox.md`
  §5 records it: *"The anchor is not started by init … it survives only inside
  the saved memory image."* Nothing recreates it on boot. Save without it and
  every clone from that template has no injection target.
- **It must be unambiguous.** *"Confirm exactly one match. Zero or several
  means the injection target is ambiguous, and `injector` will not tell you."*
  Pick a process name that appears once — Android used `nano`.
- **Its user is the user your samples run as.** `preconfig-ubuntu.sh:221`
  builds a `NETCFG` string using `sudo`, so the anchor must belong to a user
  with sudo — `GUEST_USER`, `carlos` (`pipeline-ubuntu.env:136`). An anchor
  owned by root or by a system account changes what every analysed sample runs
  as.

## D5.2. Boot the template disk

```bash
# DOM0
sudo xl create /root/drakvuf-multios-sandbox/misc/ubuntu_sandbox.cfg
sudo xl list
```

`misc/ubuntu_sandbox.cfg:78` points `disk=` at `/dev/vg-root/ubuntu_sandbox`.
**Do not edit the tracked config** to aim at a temporary LV — rename the LV, or
pass a temporary config file.

## D5.3. Quiesce the network before saving

`03-rebuild-android-sandbox.md:315-326` records this as a real, measured
defect: **the saved template carries the golden's LAN identity.** Every clone
restored from it boots believing it holds the golden's `xenbr0` address and
ARPs for a residential gateway for its first ~45 seconds on the analysis VLAN
(finding F4 in `06-verify-android-isolation.md`).

It lives in the **memory image**, not on disk, so it cannot be fixed by editing
the golden's filesystem. **Here is the only place it can be fixed.** In the
guest, before saving:

```text
sudo ip addr flush dev eth0
sudo ip route flush dev eth0
```

The template then starts from *no* network rather than the wrong one.
`preconfig-ubuntu.sh` sets the correct VLAN address per clone regardless, so
this costs nothing and removes ARP noise from every future capture.

## D5.4. Start the anchor and record its PID

> **The anchor chosen here is superseded.** Ubuntu now anchors on systemd
> (`INJECTION_PID=1`) and Android on a backgrounded `ping`; `nano` and `gedit`
> both failed, for different reasons. The anchor must be schedulable **without
> input** and single-threaded. Read
> [TROUBLESHOOTING](../TROUBLESHOOTING.md#drakvuf-printed-its-banner-and-hung--no-syscall-breakpoints-no-hooks)
> before reusing anything below.

In the guest, **as `carlos`**, in the desktop session:

```text
gedit
```

On Dom0, confirm exactly one match:

```bash
# DOM0
sudo vmi-process-list -n ubuntu_sandbox \
    -j /root/drakvuf-multios-sandbox/profiles/linux.json | grep -i gedit
```

**Exactly one line, or stop and fix it.** Record the PID — it is the value
D5.7 writes back into the pipeline.

## D5.5. Clean, then save

```text
# in the guest
sync
```

```bash
# DOM0 -- xl save DESTROYS the domain on success
sudo xl save ubuntu_sandbox \
    /root/drakvuf-multios-sandbox/state/ubuntu_sandbox.bak \
    /root/drakvuf-multios-sandbox/misc/ubuntu_sandbox.cfg

sudo xl list                    # the domain must be gone
ls -lh  /root/drakvuf-multios-sandbox/state/ubuntu_sandbox.bak
sha256sum /root/drakvuf-multios-sandbox/state/ubuntu_sandbox.bak
```

**The checksum must differ from the previous one.** `03-rebuild-…` makes this a
required check because an `xl save` that silently wrote nothing new is
indistinguishable from success by every other signal.

> **`misc/*_sandbox.cfg` points at the TEMPLATE, writable.** Use it only for
> edits that end in `xl save` — restoring against it and then `xl destroy`
> advances the disk while the `.bak` stays put, which is how FINDING D-1's
> corruption was produced. Measure and validate on a throwaway snapshot with a
> temp config instead. See
> [TROUBLESHOOTING](../TROUBLESHOOTING.md#a-templates-disk-drifted-away-from-its-saved-memory-image).

## D5.6. Validate on a throwaway, never on the template

```bash
# DOM0
sudo lvcreate -s -kn -n ubuntu_test vg-root/ubuntu_sandbox
sudo sed -e 's|/dev/vg-root/ubuntu_sandbox|/dev/vg-root/ubuntu_test|' \
         -e 's|^name.*|name = "ubuntu_test"|' \
         /root/drakvuf-multios-sandbox/misc/ubuntu_sandbox.cfg > /tmp/ubuntu_test.cfg

sudo xl restore -p -e /tmp/ubuntu_test.cfg \
    /root/drakvuf-multios-sandbox/state/ubuntu_sandbox.bak
sudo vmi-process-list -n ubuntu_test \
    -j /root/drakvuf-multios-sandbox/profiles/linux.json | grep -i nano

sudo xl destroy ubuntu_test
sudo lvremove -f vg-root/ubuntu_test
```

The anchor must appear in the *restored* domain at the PID D5.4 recorded. If it
does not, the template is unusable and no clone will inject.

## D5.7. Write the PID back — three places

A stale `INJECTION_PID` does not error. It injects into whatever process now
holds that number, or nothing at all.

```bash
grep -n INJECTION_PID /root/drakvuf-multios-sandbox/automation/pipeline-*.env
```

- `automation/pipeline-ubuntu.env:193` / `pipeline-android.env`
- `sandboxd`'s per-OS configuration
- `docs/CURRENT-STATE.md` §1.4 — currently records Ubuntu **1415**, Android
  **3174**; both go stale the moment their templates are rebuilt

    ubuntu_sandbox   anchor: gedit   PID: 1490    sha256: 2fa6c31831ccebfe...
                     2026-08-28. Rebuilt from the e2fsck-verified golden.
                     Restored-domain check: [ 1490] gedit, PID matched.
                     Template Data% baseline after save: 1.60
    android_sandbox  anchor: ______  PID: ______  sha256: ____________
    windows_sandbox  anchor: ______  PID: ______  sha256: ____________

> **`Data%` settled at 1.60 after both saves**, from 2.34 on a fresh snapshot.
> The decrease is expected: the guest discards free blocks on boot and the thin
> pool releases those mappings. That it reproduces exactly is the useful part —
> it makes 1.60 a trustworthy drift baseline.
>
> **The `gedit` anchor recorded above is itself superseded.** Ubuntu moved to
> systemd, `INJECTION_PID=1`, on 2026-08-29 — which is why this table's
> re-derive-the-PID step no longer applies to Ubuntu. See
> [TROUBLESHOOTING](../TROUBLESHOOTING.md#drakvuf-printed-its-banner-and-hung--no-syscall-breakpoints-no-hooks).

## D5.8. Per-OS differences

| | Ubuntu | Android | Windows |
|---|---|---|---|
| Guest user | `carlos` | n/a — `/data/local/tmp/` | — |
| Anchor | **systemd, `INJECTION_PID=1`** since 2026-08-29. `nano` and `gedit` both failed — see [TROUBLESHOOTING](../TROUBLESHOOTING.md#drakvuf-printed-its-banner-and-hung--no-syscall-breakpoints-no-hooks) | a backgrounded **`ping`** against 127.0.0.1; PID moves with every re-save | `notepad.exe` is the analogue, untested |
| Quiesce | `ip addr flush dev eth0` | same, plus `logcat -c` | — |
| Pre-save check | — | `getprop sys.boot_completed` → `1` | — |
| Profile | `profiles/linux.json` | `profiles/android.json` | none exists |

**Windows has no LibVMI profile**, so `vmi-process-list` cannot confirm its
anchor and D5.4/D5.6 have no equivalent. Building a Windows template is
blocked on that, not on this procedure.

## D4. Two host prerequisites the fresh install does not have

Both lived on the old `lv-root` and went with it. Neither is mentioned in Part
B, and each stops the sanity check below with a misleading error.

**Open vSwitch.** `misc/ubuntu_sandbox.cfg:88` sets
`script=vif-openvswitch,bridge=xenbr1`, so `xl restore` needs `ovs-vsctl`. Its
absence does not fail the restore — it fails the *vif attach*, and **libxl then
destroys the domain it had already successfully restored**:

```
xc: info: Restore successful
libxl: error: script: Unable to find ovs-vsctl tool
libxl: error: Domain 1:unable to add vif devices
```

```bash
# TRIAL
apt install -y openvswitch-switch
ovs-vsctl add-br xenbr1
ip link set xenbr1 up
ovs-vsctl show
```

OVS bridges live in OVSDB, so `xenbr1` persists across reboots with no netplan
entry. `xenbr0` — the uplink bridge (`networking.md:318`), a plain Linux bridge
carrying the physical NIC, used by the golden domains directly and as
`network-setup.sh`'s `MASQUERADE` target — does need one.

> ### `xenbr0` — DONE 2026-08-28, and Dom0's address changed
>
> `/etc/netplan/50-cloud-init.yaml`, bridging `enp4s0`:
>
> ```yaml
> network:
>   version: 2
>   ethernets:
>     enp4s0:
>       dhcp4: no
>   bridges:
>     xenbr0:
>       dhcp4: no
>       addresses: [192.168.1.6/24]
>       routes:
>         - to: 0.0.0.0/0
>           via: 192.168.1.1
>       nameservers:
>         addresses: [1.1.1.1, 8.8.8.8, 8.8.4.4]
>       interfaces: [enp4s0]
> ```
>
> **Dom0 is now `192.168.1.6/24` static**, not the `192.168.1.144` dynamic
> address Part 0 recorded.
>
> **Use `netplan try`, not `netplan apply`** — bridging the NIC carrying your
> own SSH session is the riskiest step here, and DHCP adds a MAC change on top.
> See
> [TROUBLESHOOTING](../TROUBLESHOOTING.md#a-headless-box-never-came-back-after-bridging-its-nic).

**`/etc/libvmi.conf` paths.** The restored file points at `/root/linux.json` and
`/root/sandbox_project/misc/android.json` — neither exists here, and
`/root/sandbox_project` is the **old repo path** already recorded in
`CURRENT-STATE`'s superseded-facts table. DRAKVUF passes `-r …/profiles/linux.json`
explicitly and does not care; `vmi-process-list` resolves through this file and
does:

```
VMI_ERROR: JSON at /root/linux.json couldn't be opened!
VMI_ERROR: Undefined OS type!
```

Rewrite it against `/root/drakvuf-multios-sandbox/profiles/`. Note `linux.json`,
not `ubuntu.json` — `CURRENT-STATE` §1.4 records that filename as never renamed
in the `linux` → `ubuntu` pass.

```bash
# TRIAL -- sanity before measuring
xl restore /root/drakvuf-multios-sandbox/state/ubuntu_sandbox.bak
xl list
vmi-process-list ubuntu_sandbox | head
xl destroy ubuntu_sandbox
```

`vmi-process-list` succeeding is the real check: it proves LibVMI can read the
guest through the restored profile on this hardware.

EVIDENCE D — 2026-08-28, PASS

```
Restores, conv=sparse working as intended:
  ubuntu   1.00t volume, Data%  2.34   (~24 GB for a 64 GiB image)
  android   128g volume, Data%  6.97   (~9 GB for a 32 GiB image)
  windows  1.00t volume, 128 GiB restored in 16m47s
  -> android deliberately 128g, not 1T: a BlissOS device reporting a 1 TB disk
     is itself an evasion tell. Plausibility, not maximum size.

state.pxar    3.985 GiB -> ubuntu_sandbox.bak, android_sandbox.bak
profiles.pxar 108 MiB   -> linux.json, android.json
etc.pxar      cherry-picked via `proxmox-backup-client mount`, NOT unpacked over
              /etc -- it is 22.04 Dom0's /etc and this host is 24.04 with a
              different VG name. Took libvmi.conf and sandboxd/ only.

xl restore succeeded:      YES, after installing openvswitch-switch (D4)
xl list:                   ubuntu_sandbox  id 2  2032 MB  1 vCPU  -b----
Domain-0 still at parity:  8192 MB / 6 vCPUs -- drakvuf-bundle's xen.cfg did
                           NOT override Part B's values on this boot
vmi-process-list:          PASS -- swapper/0, systemd, kthreadd, rcu_gp, ...
                           read out of guest memory through profiles/linux.json
```

> **Before Part E, two things from Part C are still outstanding:**
> 1. `xl vcpu-pin 0 5 10` — FINDING C-1's floating vCPU. A vCPU sharing a
>    physical core with a pinned one adds noise to `events/sec` that has nothing
>    to do with nesting.
> 2. Confirm the **nested baseline was captured before the erase** (§A1b
>    precondition 3). Without it there is nothing to divide by and §G2 cannot be
>    computed.

---

# Part E — the measurement, at parity

**This is the canonical measurement loop. §G runs it again, unchanged, on the
nested lab** — that is the entire experiment. Save it as a script so the two
runs cannot drift apart:

```bash
# write once, use on BOTH systems
cat > /root/bench-run.sh <<'EOF'
#!/bin/sh
# One DRAKVUF throughput sample. $1 = output tag. See baremetal-trial.md E.
# Every value here must be identical between the nested and bare-metal runs.
set -eu
REPO=/root/drakvuf-multios-sandbox
SAMPLE=/home/carlos/Desktop/slow.sh      # from 0.1 -- CHANGE IN NEITHER PLACE
INJECT_PID=1415                          # confirm against the running domain

mkdir -p /root/bench
for run in 1 2 3; do
    xl restore "$REPO/state/ubuntu_sandbox.bak"
    sleep 5
    dom=$(xl domid ubuntu_sandbox)
    drakvuf -r "$REPO/profiles/linux.json" \
        -d "$dom" -i "$INJECT_PID" -m execproc -e "$SAMPLE" \
        -F -o json -t 120 \
        -a syscalls -a filetracer -a fileextractor -a memdump \
        > "/root/bench/$1-${run}.json" 2>"/root/bench/$1-${run}.err" || true
    xl destroy ubuntu_sandbox 2>/dev/null || true
    sleep 5
done
wc -l /root/bench/$1-*.json
EOF
chmod +x /root/bench-run.sh
```

`xl domid` rather than a hardcoded `-d 6`: the domain id changes between
restores, and a stale one makes DRAKVUF attach to nothing or to the wrong
domain.

```bash
# TRIAL
/root/bench-run.sh bare
```

**Confirm saturation** — `xentop -b -i 10 -d 2` in a second shell, showing Dom0
at ~100% of one core. If bare metal is *not* saturated where nested was, that is
itself the finding: the bottleneck moved, and `events/sec` is measuring
something else. Record it rather than dividing anyway.

EVIDENCE E

```
bare  lines per run:  ______  ______  ______     events/sec = lines / 120
xentop Domain-0 CPU(%):  ______
clone CPU(%):            ______   (nested was ~6-7%, per F7)
```

## E1. The verdict — computed in §G, once both halves exist

    ratio = bare-metal events/sec  /  nested events/sec

| ratio | Reading | Consequence |
|---|---|---|
| **≥ 1.5** | nesting was a large tax | migration justified on performance alone |
| **1.1 – 1.5** | real but modest | decide on the *combination* with memory (5 → ~8 clones) and TCB |
| **≈ 1.0** | nesting costs nothing measurable here | **§F7c stands, confirmed from below.** Migrate only if memory and security carry it alone |
| **< 1.0** | bare metal is slower | almost certainly Dom0 on E-cores — go back to §C's cpupool check before believing it |

**A ratio near 1.0 is a real result, not a failed experiment.** It closes the
one question the Xen layer could never answer about itself, and it would mean
§F7c's *"the only remaining lever is fewer events"* is correct without
qualification.

EVIDENCE E

```
nested   events/sec:  ______  ______  ______
bare     events/sec:  ______  ______  ______
ratio:                ______
Dom0 saturated in both?  ______
```

---

# Part F — what production would actually give

Only if Part E's ratio justifies continuing. Part E answered *"what does
removing nesting alone buy?"*; this answers *"what would we actually run?"*

Relax the artificial parity constraints — Dom0 gets the memory and cores the
machine really has, and the §D2 partition from the plan applies: Dom0 and
DRAKVUF on P-cores, clones on E-cores, which is defensible because §F7 measured
clone vCPUs paused ~93% of wall time.

Re-run §E's loop and record both the single-trace number and, if the guest can
be cloned, concurrency. **The memory ceiling is the headline**: Xen sees ~32 GB
here against `total_memory 20479` nested, so after Dom0 the free pool roughly
doubles.

EVIDENCE F

```
production events/sec:        ______
free memory for clones:       ______   (nested was 12082 MiB -> 5 clones)
```

---

# Part G — roll back, and take the nested baseline

Both happen in this one Proxmox boot, which is why the baseline was deferred
to here rather than opening the runbook.

## G1. Boot back into Proxmox and confirm the lab survived

```bash
# from the firmware boot menu, select the Proxmox disk
# then, on PVE:
qm start 101
pvesm status
```

The existing evidence path: run one analysis end to end and confirm the UI
shows it. **The lab must be exactly as it was.** Also re-check `efibootmgr -v`
against EVIDENCE A — if the Ubuntu install altered the boot order, fix it now
rather than discovering it at the next power cut.

## G2. The nested baseline — the other half of Part E

Copy `/root/bench-run.sh` from the trial system unchanged and run it here.
**Do not retype it.** The whole validity of the comparison rests on the sample
path, injection PID, plugin list, `-t` and `-F` being byte-identical, and
retyping is how one of them quietly differs.

```bash
# DOM0, nested
xl list                       # Domain-0 only; stop sandboxd first
/root/bench-run.sh nested
```

Same saturation check as §E. Then compute:

```bash
# DOM0
for tag in nested bare; do
    printf '%-8s ' "$tag"
    wc -l /root/bench/${tag}-*.json 2>/dev/null | awk '/total/{next} {s+=$1; n++}
        END {if (n) printf "mean %.0f events, %.1f events/sec\n", s/n, s/n/120}'
done
```

    ratio = bare-metal events/sec  /  nested events/sec

EVIDENCE G2

```
nested lines per run:  ______  ______  ______
bare   lines per run:  ______  ______  ______   (from EVIDENCE E)
ratio:                 ______
```

Prune the one-off transfer snapshot from §D:

```bash
# PBS -- it was a transfer medium, not a backup
proxmox-backup-client forget host/trial-transfer/<timestamp> --ns dom0
```

EVIDENCE G

```
Proxmox booted:            ______
analysis completed:        ______
efibootmgr matches A:      ______
trial-transfer pruned:     ______
```

---

---

# Part H — the tuning series, 2026-08-28

Six configurations measured on the rebuilt template. **The nested comparison was
already lost**, so none of this answers "was the migration worth it" — it
answers a different and more actionable question: *what actually moves DRAKVUF
throughput on this hardware?*

## H1. Method

Each run: a fresh thin snapshot of `ubuntu_sandbox`, `xl restore -p` against a
temp config, DRAKVUF for `-t 120`, then destroy and `lvremove`. Three runs per
configuration.

**The metric is `syscall` events per second, not output lines.** Line counts are
not comparable once `--disable-sysret` removes a whole event class:

```bash
grep -c '"Plugin":"syscall"' /root/bench/<tag>-*.json     # / 120 = syscalls/sec
```

## H2. Results

| Configuration | syscalls/s | vs baseline |
|---|---|---|
| clone on P-cores **shared with Dom0** `{6,8,10}`, `-F` | 403 | — |
| clone on P-cores shared, **no `-F`** | 413 | +2% |
| clone on **dedicated P-cores** `12,14`, `-F` | **415** | baseline |
| clone on **E-cores** `16-31`, `-F` | ~413* | −0.5% |
| **hardening disabled**, `12,14`, `-F` | ~415* | +0.16% |
| **`--disable-sysret`**, `12,14`, `-F` | **856** | **2.06×** |

<sub>*compared on total lines; the per-plugin grep was taken between overwrites
of `ecore-*.json`, so those two have no syscall-only count. Both had `sysret`
enabled and identical plugins, so total lines are comparable within that pair.</sub>

**Event composition at baseline** — this is what makes the last row work:

```
syscall  49,700  (47%)
sysret   43,200  (41%)     <- removed by --disable-sysret
other    12,400  (12%)     <- filetracer + fileextractor + memdump COMBINED
```

## H3. What this establishes

**§F7c is confirmed by experiment, not merely by inference.** It concluded *"the
only remaining lever is fewer events, not faster handling of them."* Four levers
that make handling faster without removing events — CPU placement (three
variants), `-F`, and compiler hardening — all landed within **0.6%** of each
other. The one lever that removes events gave **2.06×**.

**`-F` is active and does not help throughput.** `xen_version()` reads
`/sys/hypervisor/version/minor` (= 20 on Xen 4.20) and `vmi.c:2100` gates fast
singlestep on `>= 14`, so it is genuinely enabled — "no effect" means no effect,
not "never switched on". That was the one real doubt about §F7a's null result
and it is now closed. `vmi.c` also shows *why*: `-F` swaps a singlestep round
trip for an altp2m view switch and cannot touch plugin callbacks or
serialisation.

> **`-F` may still help latency, which nobody has measured.** The operator
> reported the guest noticeably more responsive in VNC with `-F` and worse
> without, while throughput was flat. Latency and throughput are different
> quantities and only one has ever been measured here. Keep `-F`: §F7a records
> it as costing no information.

**Compiler hardening is free — keep it.** `-fstack-clash-protection`,
`-fzero-call-used-regs=all` and `-fstrict-flex-arrays=2` cost **0.16%** against
0.6% precision. DRAKVUF parses hostile guest memory as root in Dom0; there is no
speed to buy by weakening that, so the question is closed rather than pending.

## H4. Three method errors worth not repeating

**Clone CPU% is not a valid proxy across core types.** On E-cores it rose 0.8% →
1.3%, which reads like contention relief and is not: C3a measured E-cores 1.7×
slower, and 0.8 × 1.7 = 1.36. Same work, slower core, more CPU-seconds.

**The bench loop accumulated artifacts and penalised run 3.** `/root/memdumps`
and `/root/dump/` were never cleared between runs. Run 3 was the low run in
`clean-*`, `ecore-*` **and** `nosysret-*` — monotonic, not scatter. Clear both
directories per iteration; the true `--disable-sysret` figure is nearer run-1
against run-1, **2.48×**.

**Reproducibility can be an artifact of a shared disk.** Two early runs agreed to
0.003%, which read as excellent precision. They shared one drifting template LV.
With a fresh snapshot per run the real spread appeared: ~0.6% on a stopped
guest, and ~44% once `--disable-sysret` let the guest actually execute — timers
and I/O completions then land differently every run. **A sandbox guest that
diverges between runs is correct behaviour**, and it means future comparisons in
that regime need more than three runs.

## H5. Open, and parked

**Dom0 came off saturation under `--disable-sysret`** — 5–50% against a
rock-solid 103.6% in every other configuration. If real, the bottleneck has left
the DRAKVUF event loop for the first time in this project's history, which would
outrank the 2×. **Not trusted yet**: `xentop -b -i 10 -d 2` samples ~20 s of a
120 s trace and the window looked partly outside it. Re-measure with
`-i 60 -d 2` started immediately after `xl restore`.

**Where the per-event cost actually sits — parked for `perf`.** The suspicion is
`drakvuf_check_return_context` and the return-trap machinery around
`linux_ret_cb` in `src/plugins/syscalls/linux.cpp`: if each syscall entry
installs a breakpoint at the return address and the return callback frees it,
`--disable-sysret` removes ~50,000 altp2m/EPT operations per run rather than
merely 43,000 output events — which would explain both the >2× and the
desaturation. `perf` on the DRAKVUF process answers it directly. See `ideas.md`.

**The bigger lever is the syscall filter, per DRAFT-052.** That draft argues
filtering is *strictly better* than `--disable-sysret`: it removes syscall
entries too — the remaining ~50,000 per run — while keeping return values for
the calls that are actually analysed. `--disable-sysret` is the blunt version,
now quantified at 2×. The gap is a curated list of what detection needs.

## H6. Two changes this justifies, neither yet made

Both touch the **evidenced Ubuntu pipeline**, which `CLAUDE.md` protects:

1. **`cpus = "6-11"` → `"12,14"`** in `misc/ubuntu_sandbox.cfg` and
   `misc/android_sandbox.cfg`. On this topology `"6-11"` resolves to `{6,8,10}`
   — all three of them Dom0's cores, because 7/9/11 are parked by `smt=0`. The
   comments also still describe "Dom0 INTO pCPU 0-5" and "the Proxmox VM's vCPU
   count". Throughput is unaffected, but dedicated cores removed the run-to-run
   outliers and the guest is materially more responsive.
2. **`disable_sysret` for Ubuntu.** Already implemented
   (`sandboxd/guests.py:112`) and already used for Android (`guests.py:21`), so
   this is configuration, not code. **§F7a explicitly declined this trade** on
   the grounds it "costs syscall return values" — the claim that overturns it is
   that nothing downstream consumes them. **Verify and record that**, rather
   than asserting it, or a return-value consumer added later becomes silent data
   loss.

---

# Decision summary

| Question | Answer | Evidence |
|---|---|---|
| **Is the PBS encryption key readable from another machine?** | | A1b |
| Route: second disk / USB / erase | | A1a |
| Was `~/drakvuf` archived, with remote/branch/commit recorded? | | 0.2 |
| Was the rebuilt DRAKVUF at commit `52df0bc8`, not branch head? | | B |
| Injection PID per OS after any state rebuild | | D |
| Nested baseline events/sec (3 runs) | | G2 |
| Were Xen and DRAKVUF byte-identical between the two systems? | | 0.2 / B |
| **Did Xen boot on the hybrid CPU?** | | C |
| Were Dom0's pCPUs P-cores, or did a cpupool have to force it? | | C |
| Was Dom0 saturated at ~100% of one core in *both* runs? | | E / G2 |
| **ratio = bare / nested** | | G2 |
| Production-config events/sec, and free memory for clones | | F |
| Did the lab come back unchanged? | | G |

**If the ratio is ≈ 1.0 and Part C was clean**, the correct outcome is to
record that §F7c is confirmed from below and decide the migration on memory,
TCB and failure-domain grounds alone — which the plan already argues are
sufficient. Do not let a null performance result be read as a verdict against
migrating; it is a verdict against *one of the four arguments* for it.

**If Part C failed**, none of the rest matters and Phase 3 does not happen.
