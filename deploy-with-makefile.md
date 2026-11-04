# Deploy the lab with the Makefile — every target, in order, on Dom0

> **Status: written 2026-11-04 and executed the same day through §6a**
> (EVIDENCE 0 to 6a, pasted by the operator): the checkout reset, `make xen`
> as a target for the first time, the `web_vm` guard, a throwaway platform
> built and provisioned from nothing and torn down, `web_sandbox` re-run on
> the real platform after its CA-key guard fired and the key was moved off,
> `make sandboxd` with DRAKVUF at the pin and an Ubuntu job `completed
> (clean)`, and **§6b complete**: the Windows golden image reinstalled by the
> Makefile after the Chrome pin was refused and re-pinned, the installers
> mirrored on the platform, the sandbox state saved, and **a Windows job
> `completed (clean)` with a transcript, the first ever** (EVIDENCE 6b-hooks);
> **§6c complete** the same evening: the Ubuntu image rebuilt with the
> identity, the hooks target's false `Error 32` found and fixed, the state
> saved, and an Ubuntu job `completed (clean)` on it (EVIDENCE 6c-hooks).
> **§7 and §8 are NOT YET EXECUTED**: every command there is **Candidate**,
> and every `EVIDENCE` block there is empty until an operator pastes real
> output into it.
>
> **Parked at the repository root**, and it belongs at
> `docs/runbooks/18-deploy-with-makefile.md`. `scripts/gen-current-state.py`
> counts `docs/**/*.md` off the filesystem, so a new file under `docs/` fails
> `sandboxd/tests/test_current_state.py` until the generator is re-run. Move
> and rename in the change that fills the evidence (§8).
>
> **What this proves.** That the README's install sequence — `make xen`,
> `web_vm`, `web_sandbox`, `sandboxd`, the two guest chains and the hooks
> targets — runs top to bottom from a checkout, as written, on this project's
> Dom0; and that a first evasion search then starts from what it leaves behind.
> As of 2026-11-04 **no target but the guests' has run as a Makefile target**:
> Xen was installed by hand on 2026-10-19 and by the search's own build since
> 2026-11-01, and the `sandboxd.env` / `api.env` renderings had not run on a
> host (`docs/CURRENT-STATE.md` §1.2).
>
> **What it does not prove.** A fresh host. The OS install, the `vg-root`
> volume group, the `/boot` partition and the two bridges are not in the
> Makefile. §0.2 lists them as prerequisites, read from this host and from
> runbook 12, so a new host can be prepared to the same state; proving that on
> new metal is a separate run of this document.

---

## Where each command runs

This procedure crosses four shells. **Every block says which.** A command
pasted into the wrong one is how real damage happens here.

| Label | What it is | How you get there |
|---|---|---|
| `# WORKSTATION` | your machine with this checkout and an ssh key to Dom0: the development container or a laptop. The evasion searches run from here, because they reboot Dom0 | — |
| `# DOM0 (Xen)` | Dom0 booted on Xen, **as root**, in `/root/drakvuf-multios-sandbox`. Everything but `make xen` runs here | `ssh root@192.168.1.6`; `grep -q control_d /proc/xen/capabilities && echo xen` prints `xen` |
| `# DOM0 (no Xen)` | the same machine booted on its plain kernel. **Only `make xen` runs here**, and it is the only boot it may run on (§2) | §2a; `ls /proc/xen 2>&1` fails |
| `# PLATFORM DOMU` | the platform guest, as root. The Makefile reaches it itself over ssh; you go there only to verify and to create users | `ssh root@192.168.1.12` from Dom0 |
| VNC | the golden guests' consoles, on Dom0's loopback | `ssh -L 5900:127.0.0.1:5900 root@192.168.1.6` from the workstation, then a VNC viewer on `localhost:5900` |

`make` must run **as root** and **from the checkout**: `REPO_ROOT` is
`$(shell pwd)`, and the recipes mix `sudo` with bare `xl`, `lvcreate` and
`apt-get`. Every block below starts with the `cd`.

---

# 0. Before anything

## 0.1 The targets parse

Run in the development container on 2026-11-04, with a two-line
`Makefile.local` (an `RSA_KEY` and a `SANDBOX_WEB`) that was deleted after.
`make -n` expands each recipe without running it: this catches a missing
separator or an unterminated continuation, nothing more. The `# comment \`
lines inside the `set -e; \` chains are harmless under bash, which this
Makefile sets as `SHELL`: a command after one still runs, checked the same day
with `printf 'set -e; \\\n# c \\\nfalse; \\\necho REACHED\n' | bash` printing
nothing and exiting 1.

```
EVIDENCE 0.1 (DEV CONTAINER, not a Dom0 prompt)                    2026-11-04
$ for t in xen web_vm web_sandbox sandboxd ubuntu_analysis_vm win_installers windows_analysis_vm modify_windows modify_ubuntu setup_hooks_windows setup_hooks_ubuntu; do make -n $t >/dev/null 2>&1 && echo "$t: OK" || echo "$t: FAIL"; done
xen: OK
web_vm: OK
web_sandbox: OK
sandboxd: OK
ubuntu_analysis_vm: OK
win_installers: OK
windows_analysis_vm: OK
modify_windows: OK
modify_ubuntu: OK
setup_hooks_windows: OK
setup_hooks_ubuntu: OK
```

CI does not run this. `.github/workflows/static-checks.yml` has no `make -n`
step; adding one is cheap and is not part of this runbook.

## 0.2 What the Makefile assumes the host already has

None of this is in a target. A fresh host is prepared to this state by hand;
this host already is, as §0.3 reads it.

| Needs | Why | Where it came from on this host |
|---|---|---|
| **An Intel CPU with VT-x and EPT** | DRAKVUF's altp2m needs EPT; the RDTSC compensation is VMX code | i9-13900KF, `docs/CURRENT-STATE.md` §1.1 |
| **RAM for Dom0 + the platform + one guest at least**: 8192 + 4096 + 8192 MiB on this host, with 32 GiB total | `XEN_CMDLINE` fixes Dom0 at 8192 MiB; the guests' cfgs say 8192; the platform's 4096 | `Makefile`, `misc/xen-vms/platform.cfg` |
| **Ubuntu Server 24.04** | what Dom0 runs; `make xen`'s package list and GRUB handling are Ubuntu's | `docs/CURRENT-STATE.md` §1.1 |
| **A volume group named `vg-root`**, root on a **thick** LV, the rest of the VG **left free** | every `lvcreate` names `vg-root`; `web_vm` makes `vg-root/thinpool` from `90%FREE` of what is left | runbook 12 [§B0](docs/runbooks/12-baremetal-trial.md#b0-disk-layout-and-the-thin-pool-erase-route): ESP 1 G, `/boot` 2 G, PV on the rest |
| **`/boot` on a plain partition, not LVM** | GRUB boots Xen by multiboot; and the evasion searches need `grub-reboot`, which cannot clear its one-shot entry on LVM or RAID | same; §7.1 checks it |
| `lvm2`, `thin-provisioning-tools`, `lvm2-monitor` enabled, autoextend set | a pool without the tools does not activate at boot; autoextend is inert without the monitor | runbook 12 [§B0a](docs/runbooks/12-baremetal-trial.md#b0a-packages--two-that-are-easy-to-miss); see [TROUBLESHOOTING](docs/TROUBLESHOOTING.md#a-thin-pool-that-will-not-activate-at-boot-long-after-it-was-created-fine) |
| **`xenbr0`**: a Linux bridge carrying the uplink NIC, with Dom0's address | the platform's and the golden guests' `vif` name it; `network-setup.sh` masquerades out of it | runbook 12, the `xenbr0` note after §D2 — netplan, applied with `netplan try`; see [TROUBLESHOOTING](docs/TROUBLESHOOTING.md#a-headless-box-never-came-back-after-bridging-its-nic) |
| **`xenbr1`**: an Open vSwitch bridge, created once | the clone templates' `vif` use `script=vif-openvswitch,bridge=xenbr1`; `network-setup.sh` refuses to run without it | `apt install -y openvswitch-switch && ovs-vsctl add-br xenbr1`, runbook 12 after §D2; `docs/architecture/networking.md` |
| **Root ssh key on Dom0, no passphrase** | `web_vm` installs its public half in the DomU; `web_sandbox` and `sandboxd` then ssh there as root hundreds of lines deep; `ubuntu_analysis_vm` puts it in the guest | `ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519` if `/root/.ssh/id_ed25519.pub` does not exist |
| **A DNS name** for the browser-facing side, `SANDBOX_WEB` | the TLS certificates' SANs, `BROWSER_ORIGIN`, the API's `api.env`. Reaching it from the Internet is the Cloudflare tunnel, after `web_sandbox` (README) | `sandbox.evilbootloader.com` |
| **The checkout, recursive** | `drakvuf/` is a submodule with four submodules of its own; `make xen` builds `drakvuf/xen`, `make sandboxd` builds `drakvuf/libvmi` and `drakvuf` | `git clone --recursive https://github.com/evilbootloader/drakvuf-multios-sandbox.git /root/drakvuf-multios-sandbox` |
| **`Makefile.local`** | the host's values; §1.2 | untracked, repository root |
| **Disk for the ISOs and the builds** on `/` | Ubuntu server 2.1 GB, Windows 6.7 GB, the Xen and DRAKVUF trees | `misc/iso/` is in `.gitignore` |

## 0.3 This host, as read on 2026-11-04

Read over ssh from the development container, read-only, no prompt lines (so
the derived table in `CURRENT-STATE.md` §3 does not count it). It is where
this procedure starts from, and why some steps below take the re-run path.

| | |
|---|---|
| OS, Xen | Ubuntu 24.04.5; Xen 4.20.1, `xen-upstream` package from the **search's** build, `cc_compile_date Mon Nov  2 07:23:55 UTC 2026` (EVIDENCE 0; `CURRENT-STATE.md` §1.2 still names the 2026-11-01 build), boot line with `rdtsc-poc=1`; `xl dmesg` has 289 `RDTSC_POC` lines; `xen-rdtsc-poc`, `tor`, `fakenet`, `drakvuf-egress.target` all `active` |
| Running | `platform` (ID 11, 4096 MiB, 4 vCPUs). **`sandboxd` not running** |
| Checkout `/root/drakvuf-multios-sandbox` | in the morning: at the local commit `b4d6137` "Changes dom0", **11 commits behind `origin/master`**, with an unresolved `UU Makefile` and `M drakvuf`, `M misc/iso/cidata/user-data`, `M sandboxd/config.py`, no `Makefile.local`. By the time §1 ran: at `e0e368b` "Changes", a merge commit resolving that conflict with the old Makefile, `Makefile.local` written, and four cfgs with the skip-worktree bit — §1.1 has the detail |
| `drakvuf/xen/dist/` | has `xen-upstream-4.20.1.deb`, **the search's, not `make xen`'s** |
| Disk | `nvme0n1`: 1 G ESP, 2 G `/boot` ext4 **plain**, LVM `vg-root` 1.8 T. Root `ubuntu-lv` 246 G, 81 G free. `thinpool` 1.38 T at 16 %. `/srv/drakvuf-out` 600 G thin, 489 G free |
| On the pool, ours | `ubuntu`, `ubuntu_sandbox`, `windows`, `windows_sandbox` (1 T virtual each, 2–3 % used), `platform` 20 G, `platform_data` 512 G, `drakvuf-out` 600 G |
| On the pool, **not ours** | `android`, `android_sandbox` (128 G), `debian` (128 G), `router` (20 G), `sistemesinformacio` and its snapshot (64 G). A reinstall of the host erases these; nothing in this repository rebuilds them |
| GRUB | `grub-probe --target=abstraction /boot/grub/grubenv` prints nothing: the one-shot entry works. Menu: `Ubuntu` (6.8.0-147 and -142) and `Ubuntu GNU/Linux, with Xen hypervisor` |
| `/etc/default/grub.d/xen.cfg` | the `automation/xen-grub.cfg` shape, override line commented |
| `misc/iso/` | `ubuntu-22.04.5-live-server-amd64.iso`, `Win11_23H2_EnglishInternational_x64.iso` and `Win11_modified.iso` already present: the guest targets will not download again |
| `state/`, `profiles/` | `ubuntu_sandbox.bak`, `windows_sandbox.bak`, `xen-identity.json`, `firmware/`; `linux.json`, `windows.json` and 20 Windows DLL profiles |
| `/etc/sandboxd/sandboxd.env` | exists, rendered from the example; `.venv-sandboxd` and `/opt/fakenet-ng` exist |
| `/root/evasion-tests` | does not exist: no search has run from this repository's scripts |

> **DECISION — not a reinstall of the host (2026-11-04).** A reinstall tests
> nothing a target does and destroys the five volumes above that nothing
> rebuilds, the output volume and the platform's job history. Every target can
> be exercised from the state it expects by removing exactly what it creates,
> and the golden guests must be reinstalled in any case to pick up the
> hardware identity ([guest-identity.md §4](docs/architecture/guest-identity.md#4-why-a-reinstall)).
> A fresh-host run of this document belongs on a spare Intel machine, or in a
> nested VM for the sequence alone — Xen and DRAKVUF ran nested in this
> project until 2026-08-28 — and not on this Dom0.

Before starting, read the host yourself and paste it:

```bash
# DOM0 (Xen), as root. Read-only
grep -q control_d /proc/xen/capabilities && echo "booted on xen"; xl info | grep -E '^(xen_version|xen_commandline|cc_compile_date|total_memory|free_memory)'; xl list; lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE /dev/nvme0n1 | head -6; vgs vg-root; lvs --noheadings -o lv_name,lv_size,data_percent vg-root; df -h / /boot /srv/drakvuf-out; grub-probe --target=abstraction /boot/grub/grubenv; echo "grub-probe exit $?"; ip -br link show xenbr0; ip -br link show xenbr1; ovs-vsctl list-br; ls /root/.ssh/id_ed25519.pub; cd /root/drakvuf-multios-sandbox && git log --oneline -1 && git status --short && ls Makefile.local state profiles misc/iso
```

Expect: `booted on xen`; `grub-probe` printing nothing and exit 0; both
bridges `UP`; `ovs-vsctl list-br` printing `xenbr1`; the public key present;
and the git lines of §0.3 (a local commit, `UU Makefile`).

EVIDENCE 0 was pasted before two lines of the block were corrected: `ip link
show` takes one device, so the two-bridge form printed `Error: either "dev" is
duplicate, or "xenbr1" is a garbage.` — that line is the command's fault, not
a missing bridge (`ovs-vsctl list-br` found `xenbr1` right after it); and the
`lsblk` filter dropped the `tmeta`/`tdata` rows. `xenbr0` being `UP` is still
to be shown; 2c's ssh into the platform, whose `vif` is on it, shows it
indirectly.

```
root@dom0:~# grep -q control_d /proc/xen/capabilities && echo "booted on xen"; xl info | grep -E '^(xen_version|xen_commandline|cc_compile_date|total_memory|free_memory)'; xl list; lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE /dev/nvme0n1 | grep -v '^  *[├└]' ; vgs vg-root; lvs --noheadings -o lv_name,lv_size,data_percent vg-root; df -h / /boot /srv/drakvuf-out; grub-probe --target=abstraction /boot/grub/grubenv; echo "grub-probe exit $?"; ip -br link show xenbr0 xenbr1; ovs-vsctl list-br; ls /root/.ssh/id_ed25519.pub; cd /root/drakvuf-multios-sandbox && git log --oneline -1 && git status --short && ls Makefile.local state profiles misc/iso
booted on xen
total_memory           : 32605
free_memory            : 19969
xen_version            : 4.20.1
xen_commandline        : placeholder dom0_mem=8192M,max:8192M dom0_max_vcpus=6 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0 sched=credit rdtsc-poc=1 no-real-mode edd=off
cc_compile_date        : Mon Nov  2 07:23:55 UTC 2026
Name                                        ID   Mem VCPUs	State	Time(s)
Domain-0                                     0  8192     6     r-----   19783.8
platform                                    11  4096     4     -b----    4821.9
NAME                                  SIZE TYPE MOUNTPOINT       FSTYPE
nvme0n1                               1.8T disk                  
├─nvme0n1p1                             1G part /boot/efi        vfat
├─nvme0n1p2                             2G part /boot            ext4
└─nvme0n1p3                           1.8T part                  LVM2_member
  │ └─vg--root-thinpool-tpool         1.4T lvm                   
  │   ├─vg--root-thinpool             1.4T lvm                   
  │   ├─vg--root-android              128G lvm                   
  │   ├─vg--root-android_sandbox      128G lvm                   
  │   ├─vg--root-router                20G lvm                   ext4
  │   ├─vg--root-debian               128G lvm                   
  │   ├─vg--root-sistemesinformacio    64G lvm                   
  │   ├─vg--root-drakvuf--out         600G lvm  /srv/drakvuf-out ext4
  │   ├─vg--root-ubuntu                 1T lvm                   
  │   ├─vg--root-windows                1T lvm                   
  │   ├─vg--root-ubuntu_sandbox         1T lvm                   
  │   ├─vg--root-platform              20G lvm                   ext4
  │   ├─vg--root-platform_data        512G lvm                   ext4
  │   └─vg--root-windows_sandbox        1T lvm                   
  VG      #PV #LV #SN Attr   VSize  VFree  
  vg-root   1  15   0 wz--n- <1.82t <48.30g
  android                  128.00g 7.02  
  android_sandbox          128.00g 7.07  
  debian                   128.00g 12.36 
  drakvuf-out              600.00g 23.08 
  platform                  20.00g 15.29 
  platform_data            512.00g 0.38  
  router                    20.00g 7.09  
  sistemesinformacio        64.00g 9.19  
  sistemesinformacio-snap   64.00g       
  thinpool                   1.38t 16.12 
  ubuntu                     1.00t 2.11  
  ubuntu-lv               <362.70g       
  ubuntu_sandbox             1.00t 2.11  
  windows                    1.00t 2.54  
  windows_sandbox            1.00t 2.75  
Filesystem                         Size  Used Avail Use% Mounted on
/dev/mapper/vg--root-ubuntu--lv    246G  153G   81G  66% /
/dev/nvme0n1p2                     2.0G  202M  1.6G  12% /boot
/dev/mapper/vg--root-drakvuf--out  590G   72G  489G  13% /srv/drakvuf-out
grub-probe exit 0
Error: either "dev" is duplicate, or "xenbr1" is a garbage.
xenbr1
/root/.ssh/id_ed25519.pub
b4d6137 (HEAD -> master) Changes dom0
UU Makefile
 M drakvuf
 M misc/iso/cidata/user-data
 M sandboxd/config.py
ls: cannot access 'Makefile.local': No such file or directory
misc/iso:
Win11_23H2_EnglishInternational_x64.iso  cidata  seed.iso                          ubuntu-22.04.5-live-server-amd64.iso  vmlinuz
Win11_modified.iso                       initrd  ubuntu-22.04.5-desktop-amd64.iso  ubuntu-24.04.4-desktop-amd64.iso

profiles:
README.md  clr.json     fwpkclnt.json  iphlpapi.json  kernel32wow.json  linux.json     ndis.json   ntdll.json  services.json  tcpip.json   windows.json
ci.json    fltmgr.json  hal.json       kernel32.json  kernelbase.json   mscorwks.json  netio.json  ole32.json  sspicli.json   win32k.json  wow.json

state:
README.md  firmware  ubuntu_sandbox.bak  windows_sandbox.bak  xen-identity.json
```

---

# 1. The checkout and `Makefile.local`

## 1.1 Bring Dom0's checkout to `origin/master`

**State on 2026-11-04, read over ssh after a first attempt.** Dom0's `master`
is at `e0e368b` "Changes", a merge commit made that morning on top of
`b4d6137`: the 59th local commit in a chain of "Changes" and merges of
`origin/master`, none of them in this repository. The merge kept the
**pre-2026-11-03 Makefile** (`:=` values, the operator's key in the file, no
`Makefile.local`); the local commits track **`.venv-sandboxd/`** (4,241 files)
and **`misc/iso/cidata/user-data`**, both ignored upstream; and the four
Makefile-written cfgs carry git's **skip-worktree** bit, so `git status` reads
clean while they differ from `HEAD`. Three consequences shape the steps:

- The first attempt, `git reset --hard origin/master`, **failed** on the
  skip-worktree files
  ([TROUBLESHOOTING](docs/TROUBLESHOOTING.md#git-reset---hard-originmaster-on-dom0-refused-a-cfg-is-not-uptodate)),
  and had it succeeded it would have **deleted** `.venv-sandboxd/` and
  `user-data` from disk, as files tracked here and absent upstream. So the
  reset below is a **mixed** one followed by a checkout: the index and the
  tracked files move to `origin/master`, and what only Dom0 tracked stays on
  disk, untracked and ignored.
- The values the old `sed -i` put into `sandboxd/config.py` move to the env
  file **first**: `origin/master`'s `config.py` reads them from there, with
  defaults (`user`, PID 1) that are wrong for this host.
- Today's commit is kept on a branch, like the one before it. Nothing is
  deleted from history.

### 1.1a The env file first

Dom0's `config.py` at `e0e368b` carries `INJECTION_PID_UBUNTU = 1`,
`INJECTION_PID_WINDOWS = 4756` (the `explorer.exe` of the state saved
2026-11-02 09:01) and `ANALYSIS_USERNAME = "carlos"`; the env file has none of
the three groups (the first attempt's `grep` printed nothing). Append them:

```bash
# DOM0 (Xen), as root. Appends four lines; mode stays 600
grep -qE '^SANDBOXD_INJECTION_PID_WINDOWS=' /etc/sandboxd/sandboxd.env || printf '%s\n' 'SANDBOXD_REPO_ROOT=/root/drakvuf-multios-sandbox' 'SANDBOXD_ANALYSIS_USERNAME=carlos' 'SANDBOXD_INJECTION_PID_UBUNTU=1' 'SANDBOXD_INJECTION_PID_WINDOWS=4756' >> /etc/sandboxd/sandboxd.env; stat -c '%a %U' /etc/sandboxd/sandboxd.env; grep -nE '^SANDBOXD_(REPO_ROOT|ANALYSIS_USERNAME|INJECTION_PID_)' /etc/sandboxd/sandboxd.env
```

Expect `600 root` and the four lines.

```
EVIDENCE 1.1a                                                     2026-11-04
root@dom0:~/drakvuf-multios-sandbox# grep -qE '^SANDBOXD_INJECTION_PID_WINDOWS=' /etc/sandboxd/sandboxd.env || printf '%s\n' 'SANDBOXD_REPO_ROOT=/root/drakvuf-multios-sandbox' 'SANDBOXD_ANALYSIS_USERNAME=carlos' 'SANDBOXD_INJECTION_PID_UBUNTU=1' 'SANDBOXD_INJECTION_PID_WINDOWS=4756' >> /etc/sandboxd/sandboxd.env; stat -c '%a %U' /etc/sandboxd/sandboxd.env; grep -nE '^SANDBOXD_(REPO_ROOT|ANALYSIS_USERNAME|INJECTION_PID_)' /etc/sandboxd/sandboxd.env
600 root
74:SANDBOXD_REPO_ROOT=/root/drakvuf-multios-sandbox
75:SANDBOXD_ANALYSIS_USERNAME=carlos
76:SANDBOXD_INJECTION_PID_UBUNTU=1
77:SANDBOXD_INJECTION_PID_WINDOWS=4756
```

### 1.1b What the reset will change

```bash
# DOM0 (Xen), as root. Read-only
cd /root/drakvuf-multios-sandbox && git log --oneline -1 && git log --oneline origin/master..HEAD | wc -l && git ls-files -v | grep -v '^H ' && git diff --name-only --diff-filter=A origin/master HEAD | grep -v '^.venv-sandboxd/' && git diff --stat origin/master -- Makefile misc/xen-vms sandboxd/config.py | tail -9
```

Expect `e0e368b`, `59`, four `S` lines, `misc/iso/cidata/user-data` as the
only Dom0-only tracked file outside the venv, and the Makefile, the four cfgs,
`platform.cfg`, `autounattend.xml` and `config.py` in the stat.

```
EVIDENCE 1.1b                                                     2026-11-04
root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && git log --oneline -1 && git log --oneline origin/master..HEAD | wc -l && git ls-files -v | grep -v '^H ' && git diff --name-only --diff-filter=A origin/master HEAD | grep -v '^.venv-sandboxd/' && git diff --stat origin/master -- Makefile misc/xen-vms sandboxd/config.py | tail -9
e0e368b (HEAD -> master, dom0-local-2026-11-02) Changes
59
S misc/xen-vms/ubuntu.cfg
S misc/xen-vms/ubuntu_sandbox.cfg
S misc/xen-vms/windows.cfg
S misc/xen-vms/windows_sandbox.cfg
misc/iso/cidata/user-data
 Makefile                         | 334 ++++++++-------------------------------
 misc/xen-vms/autounattend.xml    |  51 +++---
 misc/xen-vms/platform.cfg        |   3 +-
 misc/xen-vms/ubuntu.cfg          |   2 +-
 misc/xen-vms/ubuntu_sandbox.cfg  |   2 +-
 misc/xen-vms/windows.cfg         |   2 +-
 misc/xen-vms/windows_sandbox.cfg |   2 +-
 sandboxd/config.py               |  89 +----------
 8 files changed, 104 insertions(+), 381 deletions(-)
```

`dom0-local-2026-11-02` already pointed at `e0e368b`: the first attempt's
`git branch` ran after the merge commit, not before it. Nothing is lost by
that; it is one branch name more on the same commit.

### 1.1c Keep, clear, reset, check out

```bash
# DOM0 (Xen), as root. Keeps today's commit on a branch and copies of the Makefile-written files; changes the index and tracked files only
cd /root/drakvuf-multios-sandbox && git branch dom0-local-2026-11-04 && mkdir -p /root/dom0-local-20261104 && cp -a misc/xen-vms misc/iso/cidata /root/dom0-local-20261104/ && git update-index --no-skip-worktree misc/xen-vms/ubuntu.cfg misc/xen-vms/ubuntu_sandbox.cfg misc/xen-vms/windows.cfg misc/xen-vms/windows_sandbox.cfg && git reset -q origin/master && git checkout -- . && git submodule sync --recursive && git submodule update --init --recursive && git log --oneline -1 && git status --short && git -C drakvuf log --oneline -1 && git -C drakvuf/libvmi log --oneline -1 && ls -d .venv-sandboxd misc/iso/cidata/user-data && git check-ignore -v .venv-sandboxd misc/iso/cidata/user-data Makefile.local
```

Expect `HEAD` at the tip of `origin/master` (`2b433f4` on 2026-11-04, or
later), **`git status --short` empty**, `drakvuf` at `3c3b73a6` and its
`libvmi` at `ab06c1f` (the pins in `CURRENT-STATE.md` §1.2; later if they
moved), the venv and `user-data` still on disk, and three `.gitignore:` lines
from `check-ignore`: all three are ignored now, `Makefile.local` included,
which the old `.gitignore` did not list. `git reset -q origin/master` is a
mixed reset — index to `origin/master`, working tree untouched, nothing
deleted — and `git checkout -- .` then gives every tracked file
`origin/master`'s content, the four cfgs with it. `--recursive` on the
submodule update matters: `drakvuf/xen` is what `make xen` builds.

```
EVIDENCE 1.1c                                                     2026-11-04
root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && git branch dom0-local-2026-11-04 && mkdir -p /root/dom0-local-20261104 && cp -a misc/xen-vms misc/iso/cidata /root/dom0-local-20261104/ && git update-index --no-skip-worktree misc/xen-vms/ubuntu.cfg misc/xen-vms/ubuntu_sandbox.cfg misc/xen-vms/windows.cfg misc/xen-vms/windows_sandbox.cfg && git reset -q origin/master && git checkout -- . && git submodule sync --recursive && git submodule update --init --recursive && git log --oneline -1 && git status --short && git -C drakvuf log --oneline -1 && git -C drakvuf/libvmi log --oneline -1 && ls -d .venv-sandboxd misc/iso/cidata/user-data && git check-ignore -v .venv-sandboxd misc/iso/cidata/user-data Makefile.local
Synchronizing submodule url for 'drakvuf'
Synchronizing submodule url for 'drakvuf/dwarf2json'
Synchronizing submodule url for 'drakvuf/libvmi'
Synchronizing submodule url for 'drakvuf/volatility3'
Synchronizing submodule url for 'drakvuf/xen'
Synchronizing submodule url for 'sandboxd/data/capa-rules'
Synchronizing submodule url for 'sandboxd/data/falco-rules'
Synchronizing submodule url for 'sandboxd/data/protections-artifacts'
Submodule path 'drakvuf': checked out '3c3b73a6ad246dbda7d8c44370abcf1150e25ea2'
Submodule path 'drakvuf/libvmi': checked out 'ab06c1fdae4959d26dfe7436f6d5dba489ef5681'
Submodule path 'drakvuf/volatility3': checked out 'b365941f59f4f55843f21bf43ec0e9b7badf0dfc'
2b433f4 (HEAD -> master, origin/master, origin/HEAD) Record the Behaviour tab's KeyError from a loop of parents in TROUBLESHOOTING
3c3b73a (HEAD, origin/develop) Bound guest-driven work, free hooks safely, end the run when the guest shuts down
ab06c1f (HEAD, origin/feature/vcpu-parallel-events) Xen events: drain the ring where it must empty, answer refused requests, keep user emulation buffers
.venv-sandboxd  misc/iso/cidata/user-data
.gitignore:116:.venv-sandboxd    .venv-sandboxd
.gitignore:114:misc/iso    misc/iso/cidata/user-data
.gitignore:127:Makefile.local    Makefile.local
```

`git status --short` printed nothing: the tree matched `origin/master`.
`git submodule status --recursive` afterwards (read over ssh): `drakvuf/xen`
at `RELEASE-4.20.1`, `sandboxd/data/capa-rules` at `v10.0.0-2`,
`falco-rules` at `falco-rules-5.2.0`, `protections-artifacts` at `main`, all
initialised.

### 1.1d What the saved states were made with

The tracked `*_sandbox.cfg` say `shadow_memory = 32`; the Makefile writes
128, and the states of 2026-11-02 were saved under Dom0's copies. This step
put 128 back and compared the result with the copy 1.1c kept, expecting
equality apart from `vnclisten`:

```bash
# DOM0 (Xen), as root. One line in each of two files, then the comparison
cd /root/drakvuf-multios-sandbox && sed -i 's/^shadow_memory = 32$/shadow_memory = 128/' misc/xen-vms/ubuntu_sandbox.cfg misc/xen-vms/windows_sandbox.cfg && git diff --stat && for f in ubuntu_sandbox windows_sandbox; do diff <(grep -v '^vnclisten' /root/dom0-local-20261104/xen-vms/$f.cfg) <(grep -v '^vnclisten' misc/xen-vms/$f.cfg) && echo "$f.cfg: as saved"; done
```

**They were not equal, and that is the finding.** The kept copies also carry
what `scripts/xen-identity.py xl-cfg` and `mac` wrote on 2026-11-02 — the
guest's `mac=`, `smbios`, `smbios_firmware`, `acpi_firmware`,
`xen_platform_pci = 0` and `device_model_args_hvm` — lines the tracked files
have never had, which the skip-worktree bit kept out of every `git diff`
([TROUBLESHOOTING](docs/TROUBLESHOOTING.md#git-reset---hard-originmaster-on-dom0-refused-a-cfg-is-not-uptodate)).
`sandboxd/clone.py::rewrite_config` passes all of them through to every clone
and keeps `mac=`, so every clone since 2026-11-02 has been restored with them;
a template without them gives the restored guest a device model started with
other disk identities, a Xen platform PCI device it never enumerated and a NIC
with another MAC. `shadow_memory` alone is not the state the guests were saved
in: 1.1e puts the kept copies back.

```
EVIDENCE 1.1d                                                     2026-11-04
root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && sed -i 's/^shadow_memory = 32$/shadow_memory = 128/' misc/xen-vms/ubuntu_sandbox.cfg misc/xen-vms/windows_sandbox.cfg && git diff --stat && for f in ubuntu_sandbox windows_sandbox; do diff <(grep -v '^vnclisten' /root/dom0-local-20261104/xen-vms/$f.cfg) <(grep -v '^vnclisten' misc/xen-vms/$f.cfg) && echo "$f.cfg: as saved"; done
 misc/xen-vms/ubuntu_sandbox.cfg  | 2 +-
 misc/xen-vms/windows_sandbox.cfg | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)
22c22
< vif = [ 'type=ioemu,model=e1000,mac=<REDACTED: the Ubuntu guest's MAC>,script=vif-openvswitch,bridge=xenbr1' ]
---
> vif = [ 'type=ioemu,model=e1000,script=vif-openvswitch,bridge=xenbr1' ]
24,28d23
< smbios = [ <REDACTED: the 13 bios_, system_, baseboard_ and enclosure_ values of this deployment's identity> ]
< smbios_firmware = '/root/drakvuf-multios-sandbox/state/firmware/smbios.bin'
< acpi_firmware = '/root/drakvuf-multios-sandbox/state/firmware/ssdt.aml'
< xen_platform_pci = 0
< device_model_args_hvm = [ <REDACTED: the '-global' ide-hd and ide-cd model, serial and version of this deployment's identity> ]
22c22
< vif = [ 'type=ioemu,model=e1000,mac=<REDACTED: the Windows guest's MAC>,script=vif-openvswitch,bridge=xenbr1' ]
---
> vif = [ 'type=ioemu,model=e1000,script=vif-openvswitch,bridge=xenbr1' ]
24,28d23
< smbios = [ <REDACTED, as above> ]
< smbios_firmware = '/root/drakvuf-multios-sandbox/state/firmware/smbios.bin'
< acpi_firmware = '/root/drakvuf-multios-sandbox/state/firmware/ssdt.aml'
< xen_platform_pci = 0
< device_model_args_hvm = [ <REDACTED, as above> ]
```

**Redacted on purpose.** The identity's values were in the operator's paste
and are not in this file: the repository is public, the platform DomU clones
it without credentials, and an identity that is published can be detected by
name (`docs/architecture/guest-identity.md`). Every later EVIDENCE that
prints a guest cfg gets the same treatment.

### 1.1e Put the kept copies back

```bash
# DOM0 (Xen), as root. Two files, from the copy 1.1c made; the tree then shows them modified
cd /root/drakvuf-multios-sandbox && cp /root/dom0-local-20261104/xen-vms/ubuntu_sandbox.cfg /root/dom0-local-20261104/xen-vms/windows_sandbox.cfg misc/xen-vms/ && grep -H '^vnclisten\|^shadow_memory\|^vcpus\|^memory' misc/xen-vms/ubuntu_sandbox.cfg misc/xen-vms/windows_sandbox.cfg && grep -c '^smbios_firmware\|^acpi_firmware\|^xen_platform_pci\|^device_model_args_hvm\|mac=' misc/xen-vms/ubuntu_sandbox.cfg misc/xen-vms/windows_sandbox.cfg && git status --short && git diff --stat
```

Expect `vnclisten = '127.0.0.1'` in both (the clone templates were on loopback
before the 2026-11-03 fix), `shadow_memory = 128`, `memory = 8192`,
`vcpus = 4`, a count of `5` for each file, and two modified files in
`git status`, about 7 lines each in the stat. The `grep -c` prints counts, not
lines, so the paste carries no identity value. **Never `git add` these two
files.** The golden `ubuntu.cfg` and `windows.cfg` (tracked with 4096–6144 MiB
and 2 vCPUs, Dom0's kept copies with 8192 and 4) stay as tracked: nothing
boots them before §6 rewrites them.

> **FINDING (2026-11-04).** The tracked `misc/xen-vms/*.cfg` are stale against
> the Makefile that writes them — `shadow_memory`, the golden guests' memory
> and vCPUs — **and cannot be brought up to date**, because what the Makefile
> writes includes this deployment's identity, which must not be published.
> Dom0 hid the gap with skip-worktree bits for weeks. So either the tracked
> templates stay as examples no deployment should restore with, or they stop
> being tracked and the Makefile writes them under `state/`, which is untracked
> and already holds the identity (`sandboxd/stages.py` would read from there).
> §8's first open question, with that cost attached. `scripts/check-secrets.sh`
> knows nothing of the identity's strings; a pattern for `smbios_firmware =`
> or `device_model_args_hvm =` in a tracked cfg would catch the commit this
> FINDING warns against.

```
EVIDENCE 1.1e                                                     2026-11-04
root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && cp /root/dom0-local-20261104/xen-vms/ubuntu_sandbox.cfg /root/dom0-local-20261104/xen-vms/windows_sandbox.cfg misc/xen-vms/ && grep -H '^vnclisten\|^shadow_memory\|^vcpus\|^memory' misc/xen-vms/ubuntu_sandbox.cfg misc/xen-vms/windows_sandbox.cfg && grep -c '^smbios_firmware\|^acpi_firmware\|^xen_platform_pci\|^device_model_args_hvm\|mac=' misc/xen-vms/ubuntu_sandbox.cfg misc/xen-vms/windows_sandbox.cfg && git status --short && git diff --stat
misc/xen-vms/ubuntu_sandbox.cfg:memory = 8192
misc/xen-vms/ubuntu_sandbox.cfg:vcpus = 4
misc/xen-vms/ubuntu_sandbox.cfg:vnclisten = '127.0.0.1'
misc/xen-vms/ubuntu_sandbox.cfg:shadow_memory = 128
misc/xen-vms/windows_sandbox.cfg:memory = 8192
misc/xen-vms/windows_sandbox.cfg:vcpus = 4
misc/xen-vms/windows_sandbox.cfg:vnclisten = '127.0.0.1'
misc/xen-vms/windows_sandbox.cfg:shadow_memory = 128
misc/xen-vms/ubuntu_sandbox.cfg:5
misc/xen-vms/windows_sandbox.cfg:5
 M misc/xen-vms/ubuntu_sandbox.cfg
 M misc/xen-vms/windows_sandbox.cfg
 misc/xen-vms/ubuntu_sandbox.cfg  | 9 +++++++--
 misc/xen-vms/windows_sandbox.cfg | 9 +++++++--
 2 files changed, 14 insertions(+), 4 deletions(-)
```

Seven insertions and two deletions per file: `shadow_memory` and the `vif`
line changed, the five identity lines added. The two clone templates on Dom0
are the ones the states of 2026-11-02 were saved with.

## 1.2 Write `Makefile.local`

Untracked (`.gitignore`), at the repository root, read by the Makefile first;
every `?=` default yields to it. **Four values are required**, the rest only
when the default is wrong for the host. The values came from the local commit
being retired (the user `carlos`, its password) and from the host. **Written
on 2026-11-04 already**, the four lines, before 1.1c: the Makefile at
`e0e368b` did not read it, the one at `origin/master` does, so the write block
below is done and only the masked check remains to paste.

```make
# /root/drakvuf-multios-sandbox/Makefile.local -- this host's values. UNTRACKED.
#
# Required. Dom0 root's PUBLIC key, one line: web_vm writes it into the platform
# DomU's authorized_keys, ubuntu_analysis_vm into the Ubuntu guest's. The Makefile
# then reaches the DomU as root with the matching private key.
RSA_KEY := ssh-ed25519 AAAA... root@dom0
# Required. The browser-facing name: TLS SANs (web_sandbox), BROWSER_ORIGIN, api.env.
SANDBOX_WEB := sandbox.evilbootloader.com
# Required. The analysis guests' user and password (autoinstall, autounattend.xml);
# the user also becomes SANDBOXD_ANALYSIS_USERNAME in /etc/sandboxd/sandboxd.env.
ANALYSIS_VM_USER := carlos
ANALYSIS_VM_PASS := ...
#
# Only when they differ from the Makefile's defaults:
#VMADDR := 192.168.1.12/24      # the platform DomU's address: written into it by web_vm,
#VMROUTE := 192.168.1.1         # dialled by web_sandbox and sandboxd; its gateway
#SANDBOXDIP := 192.168.1.6      # Dom0's address: a SAN of the dom0-lab certificate
#S3_QUOTA := 400                # GiB: Garage's layout and the bucket quota
#S3_RETENTION := 30             # days
# VM= and CFG= are NOT set here: they name the platform domain and its cfg, and the
# one time they change -- the throwaway of 3b -- they go on the command line.
```

```bash
# DOM0 (Xen), as root. Writes the file with a placeholder password
cd /root/drakvuf-multios-sandbox && (umask 077; printf '%s\n' "RSA_KEY := $(cat /root/.ssh/id_ed25519.pub)" 'SANDBOX_WEB := sandbox.evilbootloader.com' 'ANALYSIS_VM_USER := carlos' 'ANALYSIS_VM_PASS := CHANGE-ME' > Makefile.local) && echo "now put the password in with an editor"
```

Put the password in with an editor, not on a command line that lands in
`~/.bash_history`. Then show the file with the two secrets masked, and paste
**that**:

```bash
# DOM0 (Xen), as root. Read-only
cd /root/drakvuf-multios-sandbox && sed -E 's/^((ANALYSIS_VM_PASS|RSA_KEY) :=).*/\1 <masked>/' Makefile.local && grep -c CHANGE-ME Makefile.local; git status --short --ignored Makefile.local
```

Expect `0` for `CHANGE-ME` and `git status --short --ignored` showing
`!! Makefile.local`: ignored, never staged. `scripts/check-secrets.sh` does
not read a Makefile, so this file's being untracked is the only thing keeping
the password out of history.

```
EVIDENCE 1.2                                                      2026-11-04
root@dom0:~/drakvuf-multios-sandbox# cat Makefile.local 
RSA_KEY := <REDACTED>
SANDBOX_WEB := sandbox.evilbootloader.com
ANALYSIS_VM_USER := carlos
ANALYSIS_VM_PASS := <REDACTED>
```

The operator redacted the two values by hand before pasting. That the file is
ignored is in EVIDENCE 1.1c: `.gitignore:127:Makefile.local`.

---

# 2. `make xen`

Builds Xen from `drakvuf/xen` at `RELEASE-4.20.1` with the three patches and
the host's identity strings, packages it with `debball`, installs it over the
running `xen-upstream`, writes `/etc/default/grub.d/xen.cfg` with
`XEN_CMDLINE`, enables the units and runs `update-grub2`. **Booted on the plain
kernel**, for two reasons: the recipe removes and reinstalls the Xen tools the
running domains' backends come from, and this CPU crashes the toolchain under
full builds unless pinned to its E-cores
([TROUBLESHOOTING](docs/TROUBLESHOOTING.md#make-xen--internal-compiler-error-segmentation-fault-or-the-assemblers-internal-error));
Dom0 under Xen has 6 vCPUs and no E-core to pin to.

**The platform is down from 2a to 2c**, and so is analysis. `sandboxd` is not
running (§0.3); if it were, stop it in its terminal first.

## 2a. Boot Dom0 without Xen

The switch is the one the evasion searches use, `evasion-tests/README.md` §7.7.
Uncommenting the override line makes GRUB boot entry 0 of `/etc/default/grub`.

```bash
# DOM0 (Xen), as root. Stops the platform, reboots into the plain kernel
xl shutdown -w platform; sed -i 's/^#XEN_OVERRIDE_GRUB_DEFAULT=0/XEN_OVERRIDE_GRUB_DEFAULT=0/' /etc/default/grub.d/xen.cfg && grep -q '^XEN_OVERRIDE_GRUB_DEFAULT=0' /etc/default/grub.d/xen.cfg && update-grub2 && reboot
```

Then, once it answers ssh again:

```bash
# DOM0 (no Xen), as root
grep control_d /proc/xen/capabilities 2>&1; uname -r; nproc; cat /sys/devices/cpu_atom/cpus
```

Expect `grep` to fail (no `/proc/xen`), `nproc` **32**, and `16-31` for the
E-cores. If it came back on Xen, see
[TROUBLESHOOTING](docs/TROUBLESHOOTING.md#uncommenting-xen_override_grub_default0-still-boots-xen).

```
EVIDENCE 2a                                                       2026-11-04
root@dom0:~# xen-detect 
Not running on Xen.
```

The operator checked with `xen-detect`, which Xen's tools install and which
answers the same question as the `grep` above; `nproc` and the E-core list
were not pasted, and the build below ran pinned to `16-31` without a `taskset`
warning, which is what that check was for.

## 2b. Build and install

One command. On the lab's Dom0 the Xen build took 2–3 minutes on the E-cores
(`evasion-tests/README.md` §5); the first `apt-get install` of the build
dependencies and the OVMF and qemu-xen clones add to that. `taskset` pins the
build; `nproc` inside the recipe follows the mask.

```bash
# DOM0 (no Xen), as root
cd /root/drakvuf-multios-sandbox && taskset -c 16-31 make xen 2>&1 | tee /root/make-xen-$(date +%Y%m%d-%H%M).log | tail -40
```

Expect the last line `Xen installed, reboot to start it`, after
`update-grub2`'s `Found ...` lines and no `update-grub2 wrote no Xen entry` or
`the Xen entry has no rdtsc-poc=1`. Earlier in the log: `git apply` of the
three patches without `error:`, `xen-identity.py patch-xen` output,
`Config.mk` carrying the pinned OVMF revision, `dpkg` installing
`xen-upstream`, and `Created symlink` lines for `xenstored`,
`xen-qemu-dom0-disk-backend`, `xen-init-dom0`, `xenconsoled` and
`xen-rdtsc-poc`. Paste the tail and the `grep` below, not the whole log.

```bash
# DOM0 (no Xen), as root. Read-only
grep -c . /root/make-xen-*.log | tail -1; grep -nE 'error|Error|FAILED' /root/make-xen-*.log | grep -v 'Werror\|error-' | head; dpkg -l 'xen*' 'libxen*' 2>/dev/null | awk '/^[a-z]/ {print $1, $2, $3}'; ls -la /root/drakvuf-multios-sandbox/drakvuf/xen/dist/*.deb; grep -c 'multiboot2.*rdtsc-poc=1' /boot/grub/grub.cfg; grep -n 'XEN_OVERRIDE_GRUB_DEFAULT' /etc/default/grub.d/xen.cfg
```

Expect `ii xen-upstream 4.20.1`, the `.deb` dated now, **at least one**
`multiboot2` line with `rdtsc-poc=1` (`grub-mkconfig` writes one Xen entry per
`xen*.gz` name in `/boot` and per kernel: 9 on this host), and the override
line **commented again**: `make xen` installed a fresh `xen.cfg` from
`automation/xen-grub.cfg`, so Xen is the default entry without a step of
yours. The `grep` for errors matches `0 Errors` summaries and paths with
`Error` in them; read the hits, do not count them. A `pod2man` failure in `docs/` is
[TROUBLESHOOTING](docs/TROUBLESHOOTING.md#make-xen--pod2man-cant-open-entering-no-such-file-or-directory),
fixed in the recipe since 2026-11-01.

```
EVIDENCE 2b                                                       2026-11-04
root@dom0:~# cd /root/drakvuf-multios-sandbox && taskset -c 16-31 make xen 2>&1 | tee /root/make-xen-$(date +%Y%m%d-%H%M).log | tail -40

The processor microcode seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on this host.
Created symlink /etc/systemd/system/multi-user.target.wants/xenstored.service → /usr/local/lib/systemd/system/xenstored.service.
Sourcing file `/etc/default/grub'
Sourcing file `/etc/default/grub.d/xen.cfg'
Generating grub configuration file ...
Found linux image: /boot/vmlinuz-6.8.0-147-generic
Found initrd image: /boot/initrd.img-6.8.0-147-generic
Found linux image: /boot/vmlinuz-6.8.0-142-generic
Found initrd image: /boot/initrd.img-6.8.0-142-generic
Found linux image: /boot/vmlinuz-6.8.0-147-generic
Found initrd image: /boot/initrd.img-6.8.0-147-generic
Found linux image: /boot/vmlinuz-6.8.0-142-generic
Found initrd image: /boot/initrd.img-6.8.0-142-generic
Found linux image: /boot/vmlinuz-6.8.0-147-generic
Found initrd image: /boot/initrd.img-6.8.0-147-generic
Found linux image: /boot/vmlinuz-6.8.0-142-generic
Found initrd image: /boot/initrd.img-6.8.0-142-generic
Found linux image: /boot/vmlinuz-6.8.0-147-generic
Found initrd image: /boot/initrd.img-6.8.0-147-generic
Found linux image: /boot/vmlinuz-6.8.0-142-generic
Found initrd image: /boot/initrd.img-6.8.0-142-generic
Found linux image: /boot/vmlinuz-6.8.0-147-generic
Found initrd image: /boot/initrd.img-6.8.0-147-generic
Found linux image: /boot/vmlinuz-6.8.0-142-generic
Found initrd image: /boot/initrd.img-6.8.0-142-generic
Warning: os-prober will not be executed to detect other bootable partitions.
Systems on them will not be added to the GRUB boot configuration.
Check GRUB_DISABLE_OS_PROBER documentation entry.
Adding boot menu entry for UEFI Firmware Settings ...
done
Xen installed, reboot to start it
root@dom0:~/drakvuf-multios-sandbox# ls -l drakvuf/xen/dist/
total 108660
-rw-r--r-- 1 root root      2822 Oct 15 16:42 COPYING
-rw-r--r-- 1 root root      8152 Oct 15 16:42 README
drwxr-xr-x 6 root root      4096 Nov  1 18:48 install
-rwxr-xr-x 1 root root       658 Oct 15 16:42 install.sh
-rw-r--r-- 1 root root 111240082 Nov  4 13:07 xen-upstream-4.20.1.deb
```

**`make xen` has run as a Makefile target**, the first time, 2026-11-04 13:07
(the `.deb`'s date). One `Created symlink`, for `xenstored.service`: the other
four units were enabled already on this host, and `xenstored` is the one the
2026-11-03 change substituted for the non-existent `xencommons`. The kernel
images are listed five times because `grub-mkconfig` walks them once for the
plain entry and once for each `xen*.gz` name in `/boot`.

```
EVIDENCE 2b-checks                                                2026-11-04
root@dom0:~/drakvuf-multios-sandbox# dpkg -l 'xen*' 'libxen*' 2>/dev/null | awk '/^[a-z]/ {print $1, $2, $3}'; grep -c 'multiboot2.*rdtsc-poc=1' /boot/grub/grub.cfg; grep -n 'XEN_OVERRIDE_GRUB_DEFAULT' /etc/default/grub.d/xen.cfg; grep -nE 'error|Error|FAILED' /root/make-xen-*.log | grep -v 'Werror\|error-' | head
rc xen-hypervisor 4.20.1
un xen-hypervisor-4.10-amd64 <none>
un xen-hypervisor-4.11-amd64 <none>
un xen-hypervisor-4.12-amd64 <none>
un xen-hypervisor-4.13-amd64 <none>
un xen-hypervisor-4.14-amd64 <none>
un xen-hypervisor-4.15-amd64 <none>
un xen-hypervisor-4.16-amd64 <none>
un xen-hypervisor-4.17-amd64 <none>
un xen-hypervisor-4.18-amd64 <none>
un xen-hypervisor-4.6-amd64 <none>
un xen-hypervisor-4.7-amd64 <none>
un xen-hypervisor-4.8-amd64 <none>
un xen-hypervisor-4.9-amd64 <none>
ii xen-upstream 4.20.1
9
19:# Uncommenting XEN_OVERRIDE_GRUB_DEFAULT=0 below, then update-grub2, boots
23:#XEN_OVERRIDE_GRUB_DEFAULT=0
24:if [ "${XEN_OVERRIDE_GRUB_DEFAULT:-1}" != 0 ]; then
917:Compilation successful. 0 Errors, 0 Warnings, 0 Remarks, 0 Optimizations
922:Compilation successful. 0 Errors, 0 Warnings, 0 Remarks, 4 Optimizations
927:Compilation successful. 0 Errors, 0 Warnings, 0 Remarks, 4 Optimizations
932:Compilation successful. 0 Errors, 0 Warnings, 0 Remarks, 0 Optimizations
937:Compilation successful. 0 Errors, 0 Warnings, 0 Remarks, 0 Optimizations
950:Compilation successful. 0 Errors, 1 Warnings, 0 Remarks, 31 Optimizations
1225:Building ... /root/drakvuf-multios-sandbox/drakvuf/xen/tools/firmware/ovmf-dir-remote/MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf [X64]
1226:make[8]: Entering directory '/root/drakvuf-multios-sandbox/drakvuf/xen/tools/firmware/ovmf-dir-remote/Build/OvmfXen/RELEASE_GCC5/X64/MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib'
1228:make[8]: Leaving directory '/root/drakvuf-multios-sandbox/drakvuf/xen/tools/firmware/ovmf-dir-remote/Build/OvmfXen/RELEASE_GCC5/X64/MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib'
2367:Compilation successful. 0 Errors, 0 Warnings, 0 Remarks, 4 Optimizations
```

The `un` rows are packages dpkg knows the names of and never installed; the
`rc` row is the drakvuf-builds package, removed but not purged
(`CURRENT-STATE.md` §1.2's WATCH says why not to purge it). The `Compilation
successful` lines are `iasl` compiling the identity's SSDT and the firmware
tables: the one warning is at line 950 of the log, in an OVMF module, and is
not ours.

## 2c. Reboot into Xen and verify

```bash
# DOM0 (no Xen), as root
reboot
```

```bash
# DOM0 (Xen), as root. Read-only
xl info | grep -E '^(xen_version|xen_commandline|cc_compile_date|cc_compile_by|free_memory)'; xl dmesg | grep -m2 RDTSC_POC; systemctl status xen-rdtsc-poc --no-pager | head -5; systemctl --failed --no-pager | head; xl list; xl debug-keys t && xl dmesg | grep -c RDTSC_POC
```

Expect `cc_compile_date` today, `xen_commandline` with `rdtsc-poc=1`,
`RDTSC_POC: compensation enabled` in `xl dmesg`, `xen-rdtsc-poc`
`active (exited)` with its `ExecStartPost` check at `status=0`, and
`systemctl --failed` listing **`xencommons.service` and nothing else**: that
unit is generated from the init script the package installs, repeats what the
native units already did, and fails on every Xen boot; what the 2026-11-03
change fixed is that `xen-rdtsc-poc` no longer depends on it
([TROUBLESHOOTING](docs/TROUBLESHOOTING.md#xen-rdtsc-pocservice--dependency-failed-and-no-rdtsc_poc-in-xl-dmesg)).
`xl list` shows `Domain-0` at 8192 MiB and 6 vCPUs and nothing else; the
`grep -c` after `debug-keys t` is `1` on a boot where no guest has run yet,
since the dump is per guest vCPU. The platform is not started by a unit; start
it:

```bash
# DOM0 (Xen), as root
xl list platform 2>/dev/null || xl create /root/drakvuf-multios-sandbox/misc/xen-vms/platform.cfg; sleep 20; xl list; ssh -o ConnectTimeout=10 root@192.168.1.12 'uptime; systemctl is-active postgresql garage sandbox-api nginx'
```

Expect four `active`. `make xen` has now run as a target: a row for
`CURRENT-STATE.md` §1.2 (§8).

```
EVIDENCE 2c                                                       2026-11-04
root@dom0:~# xl info | grep -E '^(xen_version|xen_commandline|cc_compile_date|cc_compile_by|free_memory)'; xl dmesg | grep -m2 RDTSC_POC; systemctl status xen-rdtsc-poc --no-pager | head -5; systemctl --failed --no-pager | head; xl list; xl debug-keys t && xl dmesg | grep -c RDTSC_POC
free_memory            : 24085
xen_version            : 4.20.1
xen_commandline        : placeholder dom0_mem=8192M,max:8192M dom0_max_vcpus=6 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0 sched=credit rdtsc-poc=1 no-real-mode edd=off
cc_compile_by          : root
cc_compile_date        : Wed Nov  4 13:06:39 UTC 2026
(XEN) RDTSC_POC: compensation enabled
● xen-rdtsc-poc.service - Turn on Xen's RDTSC compensation (xl debug-keys d)
     Loaded: loaded (/etc/systemd/system/xen-rdtsc-poc.service; enabled; preset: enabled)
     Active: active (exited) since Wed 2026-11-04 13:10:54 UTC; 21s ago
    Process: 1128 ExecStart=/usr/local/sbin/xl debug-keys d (code=exited, status=0/SUCCESS)
    Process: 1137 ExecStartPost=/bin/sh -c /usr/local/sbin/xl dmesg | grep -q "RDTSC_POC: compensation enabled" (code=exited, status=0/SUCCESS)
  UNIT               LOAD   ACTIVE SUB    DESCRIPTION
● xencommons.service loaded failed failed LSB: Start/stop xenstored and xenconsoled

Legend: LOAD   → Reflects whether the unit definition was properly loaded.
        ACTIVE → The high-level unit activation state, i.e. generalization of SUB.
        SUB    → The low-level unit activation state, values depend on unit type.

1 loaded units listed.
Name                                        ID   Mem VCPUs    State    Time(s)
Domain-0                                     0  8192     6     r-----      13.0
1
root@dom0:~# xl list platform 2>/dev/null || xl create /root/drakvuf-multios-sandbox/misc/xen-vms/platform.cfg; sleep 20; xl list; ssh -o ConnectTimeout=10 root@192.168.1.12 'uptime; systemctl is-active postgresql garage sandbox-api nginx'
Parsing config from /root/drakvuf-multios-sandbox/misc/xen-vms/platform.cfg
Name                                        ID   Mem VCPUs    State    Time(s)
Domain-0                                     0  8192     6     r-----      14.7
platform                                     1  4096     4     -b----       5.9
 13:11:41 up 0 min,  1 user,  load average: 0.00, 0.00, 0.00
active
active
active
active
```

**Dom0 runs `make xen`'s Xen since 2026-11-04 13:10**: compiled 13:06:39 by
root, the three patches, the identity's strings and the QEMU CD-ROM patch in
it, `rdtsc-poc=1` on the line, the compensation on at boot with the unit's own
check passing. `no-real-mode edd=off` come from GRUB's `20_linux_xen`, not
from `xen.cfg`, as `CURRENT-STATE.md` §1.2 already records. The platform
booted in 20 s. `xencommons.service` failed as it does on every Xen boot.

> **FINDING (2026-11-04), Candidate.** `make xen` could
> `systemctl mask xencommons.service` after installing the package: the
> generator would then stop wrapping the init script, and `systemctl --failed`
> would be empty on a healthy boot instead of carrying one line everyone has
> to know to ignore. Not done here; the unit is harmless.

---

# 3. `make web_vm` — the platform DomU from nothing

`web_vm` creates `vg-root/thinpool` if absent, two thin volumes, formats them,
debootstraps Debian trixie into the root, installs the key, copies the kernel
and initrd to `/var/lib/xen/<VM>/` and `xl create`s the domain. **It refuses
to run where its volumes exist**, by design since 2026-11-03: a second run
would format the platform's root and the object store.

## 3a. The refusal, against the real platform

The cheapest test of the guard, and nothing is changed by it: the target
installs `lvm2` and `debootstrap`, finds `vg-root/thinpool`, then stops at the
first existing volume.

```bash
# DOM0 (Xen), as root. Expected to FAIL on purpose
cd /root/drakvuf-multios-sandbox && make web_vm; echo "exit $?"
```

Expect `vg-root/platform exists: refusing to build over a platform. To rebuild
from nothing: xl destroy platform; lvremove vg-root/platform vg-root/platform_data
-- by hand, on purpose.` and `exit 2` (make's exit for a failed recipe). If it
got past that line, **stop and read why before anything else**: the guard is
the only thing between a re-run and `mkfs` on the store.

```
cd /root/drakvuf-multios-sandbox && make web_vm; echo "exit $?"
```

## 3b. The real path, on a throwaway domain

> **DECISION — a second, disposable platform instead of rebuilding the real
> one (2026-11-04).** Rebuilding the real platform costs the job history and
> 3.8 GiB of artifacts, a loss accepted once already on 2026-08-28 and not to be
> repeated for a test. `web_vm` and `web_sandbox` take the domain's name,
> address and cfg as variables, so the fresh path runs beside the real platform
> and is torn down after (3d). `make sandboxd` is **never** pointed at it: it
> would re-point Dom0's worker credential and CA at the throwaway.

The cfg: the real one with the name, the kernel path, the root label and both
volumes renamed. `web_vm` labels the filesystems `<VM>-root` and `<VM>-data`,
copies the kernel to `/var/lib/xen/<VM>/`, and creates `vg-root/<VM>` and
`vg-root/<VM>_data`. **The name is `ptest`, and must stay at 11 characters or
fewer**: an ext4 label is 16 bytes, and `mkfs.ext4` truncates `<VM>-root`
silently past that, which is how the first attempt, `platform-test`, ended in
the initramfs shell
([TROUBLESHOOTING](docs/TROUBLESHOOTING.md#a-make-web_vm-domain-drops-to-the-initramfs-shell-its-root-label-does-not-exist);
its evidence is at the end of this step).

```bash
# DOM0 (Xen), as root. Writes one new file
sed -e 's/^name *=.*/name   = "ptest"/' -e 's|/var/lib/xen/platform/|/var/lib/xen/ptest/|g' -e 's/LABEL=platform-root/LABEL=ptest-root/' -e 's|/dev/vg-root/platform,|/dev/vg-root/ptest,|' -e 's|/dev/vg-root/platform_data,|/dev/vg-root/ptest_data,|' /root/drakvuf-multios-sandbox/misc/xen-vms/platform.cfg > /root/ptest.cfg && grep -nE "^(name|kernel|ramdisk|extra|vif)|phy:" /root/ptest.cfg
```

Expect `ptest` in `name`, both `/var/lib/xen/ptest/` paths,
`root=LABEL=ptest-root`, and `phy:/dev/vg-root/ptest,xvda` and
`ptest_data,xvdb`. `cpus = "28-31"` shared with the real platform is fine for
a test. Pick an address nothing on the LAN has:

```bash
# DOM0 (Xen), as root. Read-only
ping -c1 -W1 192.168.1.13 >/dev/null && echo "192.168.1.13 IN USE: pick another" || echo "192.168.1.13 free"
```

**Interactive**: `web_vm` runs `passwd root` inside the chroot and waits for a
password, twice. Run it in a terminal you watch. The two thin volumes are 20 G
and 512 G virtual; the pool has room (§0.3).

```bash
# DOM0 (Xen), as root. Creates vg-root/ptest and ptest_data, a domain, /var/lib/xen/ptest
cd /root/drakvuf-multios-sandbox && VM=ptest VMADDR=192.168.1.13/24 CFG=/root/ptest.cfg make web_vm 2>&1 | tee /root/make-web_vm-ptest-$(date +%Y%m%d-%H%M).log | tail -30; grep -n 'label too long' /root/make-web_vm-ptest-*.log; e2label /dev/vg-root/ptest; e2label /dev/vg-root/ptest_data; xl list; lvs vg-root | grep ptest; sleep 30; ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new root@192.168.1.13 'hostname; ip -br addr show eth0; findmnt /srv/garagehq; cat /root/.ssh/authorized_keys | cut -c1-30'
```

Expect `debootstrap` ending `I: Base system installed successfully.`, **no
`label too long` line**, `ptest-root` and `ptest-data` from `e2label`, two
`lvcreate` lines, the domain in `xl list`, and over ssh **with the key, no
password prompt**: hostname `ptest`, `eth0` at `192.168.1.13/24`,
`/srv/garagehq` mounted from the data volume, and the key's first 30
characters. A password prompt means the key did not land: the symptom the
2026-11-03 fix in the recipe (the key written from outside the chroot) was
for.

```
EVIDENCE 3b                                                       2026-11-04
root@dom0:~# sed -e 's/^name *=.*/name   = "ptest"/' -e 's|/var/lib/xen/platform/|/var/lib/xen/ptest/|g' -e 's/LABEL=platform-root/LABEL=ptest-root/' -e 's|/dev/vg-root/platform,|/dev/vg-root/ptest,|' -e 's|/dev/vg-root/platform_data,|/dev/vg-root/ptest_data,|' /root/drakvuf-multios-sandbox/misc/xen-vms/platform.cfg > /root/ptest.cfg && grep -nE "^(name|kernel|ramdisk|extra|vif)|phy:" /root/ptest.cfg
25:name   = "ptest"
64:kernel  = "/var/lib/xen/ptest/vmlinuz"
65:ramdisk = "/var/lib/xen/ptest/initrd.img"
72:extra = "root=LABEL=ptest-root ro console=hvc0 net.ifnames=0"
80:    'phy:/dev/vg-root/ptest,xvda,w',
81:    'phy:/dev/vg-root/ptest_data,xvdb,w',
88:vif = [ 'bridge=xenbr0' ]
root@dom0:~# cd /root/drakvuf-multios-sandbox && VM=ptest VMADDR=192.168.1.13/24 CFG=/root/ptest.cfg make web_vm 2>&1 | tee /root/make-web_vm-ptest-$(date +%Y%m%d-%H%M).log | tail -30; grep -n 'label too long' /root/make-web_vm-ptest-*.log; e2label /dev/vg-root/ptest; e2label /dev/vg-root/ptest_data; xl list; lvs vg-root | grep ptest; sleep 30; ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new root@192.168.1.13 'hostname; ip -br addr show eth0; findmnt /srv/garagehq; cat /root/.ssh/authorized_keys | cut -c1-30'
256 SHA256:nBSLeNsDMI1AmK2FqomtKw5JwT+vvoKOzZ5fYo9px2U root@dom0 (ECDSA)
Creating SSH2 ED25519 key; this may take some time ...
256 SHA256:UhQlx4AhwKgtFjaLWy57jcaUQTR+WtRc/moOnSB5rxk root@dom0 (ED25519)
Creating user 'sshd' (sshd user) with UID 990 and GID 65534.
Running in chroot, ignoring request.
Created symlink '/etc/systemd/system/sshd.service' → '/usr/lib/systemd/system/ssh.service'.
Created symlink '/etc/systemd/system/multi-user.target.wants/ssh.service' → '/usr/lib/systemd/system/ssh.service'.
Created symlink '/etc/systemd/system/ssh.service.wants/sshd-keygen.service' → '/usr/lib/systemd/system/sshd-keygen.service'.
Created symlink '/etc/systemd/system/sshd.service.wants/sshd-keygen.service' → '/usr/lib/systemd/system/sshd-keygen.service'.
Created symlink '/etc/systemd/system/sshd@.service.wants/sshd-keygen.service' → '/usr/lib/systemd/system/sshd-keygen.service'.
Created symlink '/etc/systemd/system/ssh.socket.wants/sshd-keygen.service' → '/usr/lib/systemd/system/sshd-keygen.service'.
Setting up linux-image-6.12.107+deb13-amd64 (6.12.107-1) ...
I: /vmlinuz.old is now a symlink to boot/vmlinuz-6.12.107+deb13-amd64
I: /initrd.img.old is now a symlink to boot/initrd.img-6.12.107+deb13-amd64
I: /vmlinuz is now a symlink to boot/vmlinuz-6.12.107+deb13-amd64
I: /initrd.img is now a symlink to boot/initrd.img-6.12.107+deb13-amd64
/etc/kernel/postinst.d/initramfs-tools:
update-initramfs: Generating /boot/initrd.img-6.12.107+deb13-amd64
Setting up linux-image-amd64 (6.12.107-1) ...
Setting up dbus-user-session (1.16.2-2) ...
Processing triggers for systemd (257.13-1~deb13u1) ...
Processing triggers for libc-bin (2.41-12+deb13u4) ...
Processing triggers for ca-certificates (20250419) ...
Updating certificates in /etc/ssl/certs...
0 added, 0 removed; done.
Running hooks in /etc/ca-certificates/update.d...
done.
Processing triggers for initramfs-tools (0.148.4) ...
update-initramfs: Generating /boot/initrd.img-6.12.107+deb13-amd64
Parsing config from /root/ptest.cfg
ptest-root
ptest-data
Name                                        ID   Mem VCPUs	State	Time(s)
Domain-0                                     0  8192     6     r-----     214.1
platform                                     1  4096     4     -b----      27.2
ptest                                        3  4096     1     r-----       0.0
  ptest                   vg-root Vwi-aotz--   20.00g thinpool                    6.64                                   
  ptest_data              vg-root Vwi-aotz--  512.00g thinpool                    0.20                                   
Warning: Permanently added '192.168.1.13' (ED25519) to the list of known hosts.
ptest
eth0             UP             192.168.1.13/24 fe80::216:3eff:fe13:2e4/64 
TARGET        SOURCE    FSTYPE OPTIONS
/srv/garagehq /dev/xvdb ext4   rw,relatime,stripe=16
ssh-ed25519 AAAAC3NzaC1lZDI1NT
```

> **FINDING (2026-11-04).** `web_vm` derives two ext4 labels from `VM` and
> checks neither: a name over 11 characters gets truncated labels, a cfg and
> an fstab that name the untruncated ones, and a domain that boots to the
> initramfs shell. Candidate fix: refuse such a `VM` before the first
> `lvcreate`, or `e2label` after each `mkfs.ext4` and compare.

#### The first attempt, `platform-test`, and its cleanup

Kept as the finding's evidence. The commands were those above with
`platform-test` in place of `ptest`.

```
EVIDENCE 3b-first-attempt                                         2026-11-04
root@dom0:~/drakvuf-multios-sandbox# sed -e 's/^name *=.*/name   = "platform-test"/' -e 's|/var/lib/xen/platform/|/var/lib/xen/platform-test/|g' -e 's/LABEL=platform-root/LABEL=platform-test-root/' -e 's|/dev/vg-root/platform,|/dev/vg-root/platform-test,|' -e 's|/dev/vg-root/platform_data,|/dev/vg-root/platform-test_data,|' /root/drakvuf-multios-sandbox/misc/xen-vms/platform.cfg > /root/platform-test.cfg && grep -nE "^(name|kernel|ramdisk|extra|vif)|phy:" /root/platform-test.cfg
25:name   = "platform-test"
64:kernel  = "/var/lib/xen/platform-test/vmlinuz"
65:ramdisk = "/var/lib/xen/platform-test/initrd.img"
72:extra = "root=LABEL=platform-test-root ro console=hvc0 net.ifnames=0"
80:    'phy:/dev/vg-root/platform-test,xvda,w',
81:    'phy:/dev/vg-root/platform-test_data,xvdb,w',
88:vif = [ 'bridge=xenbr0' ]
root@dom0:~/drakvuf-multios-sandbox# ping -c1 -W1 192.168.1.13 >/dev/null && echo "192.168.1.13 IN USE: pick another" || echo "192.168.1.13 free"
192.168.1.13 free
root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && VM=platform-test VMADDR=192.168.1.13/24 CFG=/root/platform-test.cfg make web_vm 2>&1 | tee /root/make-web_vm-test-$(date +%Y%m%d-%H%M).log | tail -30; xl list; lvs vg-root | grep platform-test; sleep 30; ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new root@192.168.1.13 'hostname; ip -br addr show eth0; findmnt /srv/garagehq; cat /root/.ssh/authorized_keys | cut -c1-30'
256 SHA256:Olp0M9ZS9vuwwN/AXZFK7jlxscpu/nsJXnw0708He9Y root@dom0 (ECDSA)
Creating SSH2 ED25519 key; this may take some time ...
256 SHA256:yJ2t2Eyl/22ARZSYOiogozA15gKg3InsGZhi++Blp3Q root@dom0 (ED25519)
Creating user 'sshd' (sshd user) with UID 990 and GID 65534.
Running in chroot, ignoring request.
Created symlink '/etc/systemd/system/sshd.service' → '/usr/lib/systemd/system/ssh.service'.
Created symlink '/etc/systemd/system/multi-user.target.wants/ssh.service' → '/usr/lib/systemd/system/ssh.service'.
Created symlink '/etc/systemd/system/ssh.service.wants/sshd-keygen.service' → '/usr/lib/systemd/system/sshd-keygen.service'.
Created symlink '/etc/systemd/system/sshd.service.wants/sshd-keygen.service' → '/usr/lib/systemd/system/sshd-keygen.service'.
Created symlink '/etc/systemd/system/sshd@.service.wants/sshd-keygen.service' → '/usr/lib/systemd/system/sshd-keygen.service'.
Created symlink '/etc/systemd/system/ssh.socket.wants/sshd-keygen.service' → '/usr/lib/systemd/system/sshd-keygen.service'.
Setting up linux-image-6.12.107+deb13-amd64 (6.12.107-1) ...
I: /vmlinuz.old is now a symlink to boot/vmlinuz-6.12.107+deb13-amd64
I: /initrd.img.old is now a symlink to boot/initrd.img-6.12.107+deb13-amd64
I: /vmlinuz is now a symlink to boot/vmlinuz-6.12.107+deb13-amd64
I: /initrd.img is now a symlink to boot/initrd.img-6.12.107+deb13-amd64
/etc/kernel/postinst.d/initramfs-tools:
update-initramfs: Generating /boot/initrd.img-6.12.107+deb13-amd64
Setting up linux-image-amd64 (6.12.107-1) ...
Setting up dbus-user-session (1.16.2-2) ...
Processing triggers for systemd (257.13-1~deb13u1) ...
Processing triggers for libc-bin (2.41-12+deb13u4) ...
Processing triggers for ca-certificates (20250419) ...
Updating certificates in /etc/ssl/certs...
0 added, 0 removed; done.
Running hooks in /etc/ca-certificates/update.d...
done.
Processing triggers for initramfs-tools (0.148.4) ...
update-initramfs: Generating /boot/initrd.img-6.12.107+deb13-amd64
Parsing config from /root/platform-test.cfg
Name                                        ID   Mem VCPUs    State    Time(s)
Domain-0                                     0  8192     6     r-----     113.0
platform                                     1  4096     4     -b----      17.3
platform-test                                2  4096     1     r-----       0.0
  platform-test           vg-root Vwi-aotz--   20.00g thinpool                    6.83                                   
  platform-test_data      vg-root Vwi-aotz--  512.00g thinpool                    0.20                                   
ssh: connect to host 192.168.1.13 port 22: No route to host
```

On the domain's console:

```
EVIDENCE 3b-first-attempt, console                                2026-11-04
Begin: Running /scripts/local-block ... done.
done.
Gave up waiting for root file system device.  Common problems:
 - Boot args (cat /proc/cmdline)
   - Check rootdelay= (did the system wait long enough?)
 - Missing modules (cat /proc/modules; ls /dev)
ALERT!  LABEL=platform-test-root does not exist.  Dropping to a shell!


BusyBox v1.37.0 (Debian 1:1.37.0-6+b9) built-in shell (ash)
Enter 'help' for a list of built-in commands.
```

Read over ssh from the development container afterwards, no prompt line:
`e2label /dev/vg-root/platform-test` printed `platform-test-ro`,
`e2label /dev/vg-root/platform-test_data` printed `platform-test-da`, and the
log carried `Warning: label too long; will be truncated to 'platform-test-ro'`
at line 19 and the `-da` one at line 34. The ssh host keys printed in the
first lines are the DomU's own, generated inside the chroot; they are not
Dom0's.

The cleanup, before the retry. Only names with the `-test` suffix:

```bash
# DOM0 (Xen), as root. DESTROYS the half-built throwaway: domain, its two volumes, kernel copy, cfg
xl destroy platform-test && lvremove -y vg-root/platform-test vg-root/platform-test_data && rm -rf /var/lib/xen/platform-test /mnt/platform-test /root/platform-test.cfg && lvs vg-root | grep -c platform; xl list
```

Expect `2` (the real platform's two volumes) and the real `platform` still in
`xl list`. `/mnt/platform-test` was unmounted by the recipe; `rm -rf` on an
empty mount point is a no-op.

```
EVIDENCE 3b-cleanup                                               2026-11-04
root@dom0:~# xl destroy platform-test && lvremove -y vg-root/platform-test vg-root/platform-test_data && rm -rf /var/lib/xen/platform-test /mnt/platform-test /root/platform-test.cfg && lvs vg-root | grep -c platform; xl list
  Consider pruning vg-root VG archive with more then 120 MiB in 14984 files (check archiving is needed in lvm.conf).
  Consider pruning vg-root VG archive with more then 120 MiB in 14985 files (check archiving is needed in lvm.conf).
  Logical volume "platform-test" successfully removed.
  Consider pruning vg-root VG archive with more then 120 MiB in 14986 files (check archiving is needed in lvm.conf).
  Consider pruning vg-root VG archive with more then 120 MiB in 14987 files (check archiving is needed in lvm.conf).
  Logical volume "platform-test_data" successfully removed.
2
Name                                        ID   Mem VCPUs	State	Time(s)
Domain-0                                     0  8192     6     r-----     133.8
platform                                     1  4096     4     -b----      25.6
```

## 3c. `make web_sandbox` on the throwaway

Installs Postgres and creates the database, checks out **this checkout's
`HEAD`** into `/opt/platform/src` on the DomU (so **push first**, or the
checkout fails: `PLATFORM_SHA` is `git rev-parse HEAD`), runs the migrations,
downloads and verifies Garage, writes its config and unit, lays out the store,
provisions the bucket, renders `api.env`, issues the three certificates and
destroys the CA key, writes the API unit, nginx, runs `conformance.py` and
creates the `dom0-1` worker.

```bash
# WORKSTATION. The commit the DomU will check out must be on GitHub
git -C /workspaces/work/sandbox_project status --short | grep -v '^??' ; git -C /workspaces/work/sandbox_project log --oneline -1 origin/master
```

```bash
# DOM0 (Xen), as root. On the THROWAWAY: VM= and CFG= as in 3b
cd /root/drakvuf-multios-sandbox && git log --oneline -1 && VM=ptest VMADDR=192.168.1.13/24 CFG=/root/ptest.cfg make web_sandbox 2>&1 | tee /root/make-web_sandbox-ptest-$(date +%Y%m%d-%H%M).log | tail -60
```

Expect, in order: `platform at <sha> <subject>` naming Dom0's `HEAD`; the
migrations' `--status` then their application; `garage.new: OK` from
`sha256sum -c`; `garage status` with one node; `layout apply` at version 1;
`provision.sh`'s output (bucket, key, quota, CORS); a `SHA256 Fingerprint=` and
`notAfter=` for the CA, then `ca.key destroyed on this host`; `sandbox-api`
`active (running)`; `conformance.py` passing every check; and the worker's
`WORKER_TOKEN=...` line — **which is the throwaway's; do not paste it, and do
not put it anywhere**. Then:

```bash
# DOM0 (Xen), as root. Read-only
ssh root@192.168.1.13 cat /etc/sandbox_platform/tls/ca.crt > /root/ptest-ca.crt && curl -sS --cacert /root/ptest-ca.crt https://192.168.1.13:8000/healthz; echo; ssh root@192.168.1.13 'systemctl is-active postgresql garage sandbox-api nginx; grep -c "@[A-Z_]*@" /etc/sandbox_platform/api.env; ls /etc/sandbox_platform/tls/'
```

Expect the health JSON, four `active`, `0` unrendered placeholders, and a
`tls/` with `ca.crt`, three `.crt`/`.key` pairs and **no `ca.key`**.

```
EVIDENCE 3c                                                       2026-11-04
vscode ➜ /workspaces/work/sandbox_project (master) $ git -C /workspaces/work/sandbox_project status --short | grep -v '^??' ; git -C /workspaces/work/sandbox_project log --oneline -1 origin/master
 M README.md
 M docs/CURRENT-STATE.md
 M docs/INDEX.md
 M docs/TROUBLESHOOTING.md
2b433f4 (HEAD -> master, origin/master, origin/HEAD) Record the Behaviour tab's KeyError from a loop of parents in TROUBLESHOOTING

root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && git log --oneline -1 && VM=ptest VMADDR=192.168.1.13/24 CFG=/root/ptest.cfg make web_sandbox 2>&1 | tee /root/make-web_sandbox-ptest-$(date +%Y%m%d-%H%M).log | tail -60
2b433f4 (HEAD -> master, origin/master, origin/HEAD) Record the Behaviour tab's KeyError from a loop of parents in TROUBLESHOOTING
  ok    versioning is off                                    off
  ok    object lock is not enabled                           501 NotImplemented
  ok    retention: one rule, Enabled, over the whole bucket  (1, 'Enabled', '')
  ok    retention: expires after 30 days                     30

== anonymous access
  ok    an unsigned GET of a real key is refused             403 AccessDenied
  ok      ...by the STORE, not by the front                  True

== CORS
   asserted behaviourally: GetBucketCors needs `owner`, and behaviour is the better evidence anyway
  ok    the configured origin's preflight is answered        (200, 'https://sandbox.evilbootloader.com')
  ok    any other origin's preflight is refused              403
  ok    a real response is not readable cross-origin         (200, None, None)

== region
   the SigV4 scope, and api.env's S3_REGION must match it
  ok    a wrong-region presigned URL is refused              (400, True)

== what api-policy.json withheld -- refused by the front
   `403 403`: nginx answers with an HTML page, so there is no S3 error code. An S3-CODED 403 here means the store refused it and the front did not, which is a weaker posture -- so it is reported rather than accepted.
  ok    CopyObject                                           403 403
  ok    ListObjectsV2                                        403 403
  ok    ListBuckets                                          403 403
  ok    DeleteObject                                         403 403
  ok    DeleteObjects                                        403 403
  ok    PutBucketCors                                        403 403
  ok    a PUT carrying x-amz-copy-source (CVE-2026-97731's shape) 403
  ok    POST ?delete (multi-object delete)                   403
  ok    POST ?uploads (multipart init)                       403
  ok    GET / (ListBuckets, unsigned)                        403
  ok    GET /minio/health/live (gone with MinIO)             403

== the same key straight at Garage -- what the front is holding back
  ok    ListObjectsV2 direct                                 allowed
  ok    CopyObject direct                                    allowed
  ok    DeleteObject direct                                  allowed
  ok    PutBucketCors direct (needs owner)                   403 AccessDenied

   These four are EXPECTED, and they are the residual risk of DECISION A2
   written down: api-policy.json withheld list, copy and delete from the
   CREDENTIAL, where the front withholds them from the PATH. Equivalent for
   anything arriving over TLS; not equivalent for code already running on the
   platform DomU, which can reach Garage's loopback listener and then list,
   copy and delete the whole bucket with the API's own key.

   On this store, a platform compromise is a bucket compromise. Under MinIO it
   was a bucket READ compromise at worst. That is why Garage binds loopback
   only and why provision.sh's owner key is ephemeral.

probe removed: probe/conformance-c1182f7c-961f-4ab7-86b7-c18404824c43.bin

31 ok, 0 unexpected, 0 skipped
database: postgresql:///sandbox_platform
created worker dom0-1

  WORKER_TOKEN=<REDACTED: the throwaway ptest's token; the domain is destroyed, the value is useless and still does not belong in a public file>

Put that in /etc/sandboxd/sandboxd.env on the analysis host.
It is not stored anywhere and cannot be shown again.

```

## 3d. Tear the throwaway down

Destroys only what 3b created. Check the names in the `lvremove` line twice:
`ptest`, never `platform`.

```bash
# DOM0 (Xen), as root. DESTROYS the throwaway: domain, its two volumes, kernel copy, host key
xl destroy ptest && lvremove -y vg-root/ptest vg-root/ptest_data && rm -rf /var/lib/xen/ptest /mnt/ptest /root/ptest.cfg /root/ptest-ca.crt && ssh-keygen -R 192.168.1.13 >/dev/null && lvs vg-root | grep -c platform; xl list
```

Expect `2` (the real platform's two volumes) and the real `platform` still in
`xl list`.

```
EVIDENCE 3d                                                       2026-11-04
root@dom0:~/drakvuf-multios-sandbox# xl destroy ptest && lvremove -y vg-root/ptest vg-root/ptest_data && rm -rf /var/lib/xen/ptest /mnt/ptest /root/ptest.cfg /root/ptest-ca.crt && ssh-keygen -R 192.168.1.13 >/dev/null && lvs vg-root | grep -c platform; xl list
  Consider pruning vg-root VG archive with more then 120 MiB in 14992 files (check archiving is needed in lvm.conf).
  Consider pruning vg-root VG archive with more then 120 MiB in 14993 files (check archiving is needed in lvm.conf).
  Logical volume "ptest" successfully removed.
  Consider pruning vg-root VG archive with more then 120 MiB in 14994 files (check archiving is needed in lvm.conf).
  Consider pruning vg-root VG archive with more then 120 MiB in 14995 files (check archiving is needed in lvm.conf).
  Logical volume "ptest_data" successfully removed.
2
Name                                        ID   Mem VCPUs	State	Time(s)
Domain-0                                     0  8192     6     r-----     227.0
platform                                     1  4096     4     -b----      30.4
```

§3 is complete: the fresh path built a platform from nothing beside the real
one, `web_sandbox` provisioned it to `31 ok, 0 unexpected, 0 skipped` from
`conformance.py`, and the teardown left the two real volumes and the real
domain. The `created worker dom0-1` and its token in EVIDENCE 3c were the
throwaway's; the token is redacted there and the domain no longer exists.

> **FINDING (2026-11-04), housekeeping.** Every `lvremove` above printed
> `Consider pruning vg-root VG archive with more then 120 MiB in 14984 files`:
> `/etc/lvm/archive/` on Dom0 holds about 15,000 metadata archives, one per
> volume operation, which is what months of clone snapshots and removals
> leave. Nothing is wrong, but `lvm.conf`'s `backup { retain_min, retain_days }`
> defaults (10 files, 30 days) are evidently not what this host runs with, or
> the archive would not have grown to that. Candidate: look at the `backup`
> section and prune. Not part of this runbook.

---

# 4. `make web_sandbox` — the re-run path, on the real platform

Re-runnable since 2026-11-03: each thing it would create is kept when it
exists, so this run **upgrades** the real platform to `HEAD` and tests the
"exists: keeping" branches. It is a deploy of the platform, and the recipe
does not stop the API before the migrations nor restart it after
(`systemctl enable --now` leaves a running unit alone). So bracket it as
`docs/DEVELOPING.md` §5.4 does: stop, run, start.

> **FINDING (dry run, 2026-11-04).** On the re-run path `web_sandbox` applies
> migrations under a running API and leaves the old code running on the new
> schema. Until the recipe restarts `sandbox-api` itself, do it by hand as
> below. Candidate fix: a `systemctl restart sandbox-api` after
> `enable --now`.

```bash
# DOM0 (Xen), as root. The platform is down from here to the restart below
ssh root@192.168.1.12 'systemctl stop sandbox-api; systemctl is-active sandbox-api' ; cd /root/drakvuf-multios-sandbox && git log --oneline -1 && make web_sandbox 2>&1 | tee /root/make-web_sandbox-$(date +%Y%m%d-%H%M).log | grep -nE 'exists: keeping|already rendered|platform at|OK$|FAIL|rror|Fingerprint|conformance|worker' | head -40; ssh root@192.168.1.12 'systemctl restart sandbox-api; sleep 3; systemctl is-active postgresql garage sandbox-api nginx'
```

Expect the four keep lines — `sandbox_platform exists: keeping the cluster
and the database`, `/etc/garage.toml exists: keeping the store, its secrets
and its layout`, `api.env already rendered: keeping it`,
`/etc/sandbox_platform/tls exists: keeping the certificates` — `platform at
<HEAD>`, `garage.new: OK`, `conformance.py` passing, `worker dom0-1 exists
already; make sandboxd rotates its token`, and four `active` at the end.
**No `Fingerprint=` line** on this path: no CA was made. Then the deployment's
own checks, `docs/DEVELOPING.md` §7: the UI loads over the tunnel, and the
API's startup log is clean:

```bash
# PLATFORM DOMU, as root. Read-only. git runs as the checkout's owner, or it refuses with "dubious ownership"
journalctl -u sandbox-api -n 30 --no-pager | grep -vE 'GET /healthz' | tail -15; sudo -u platform git -C /opt/platform/src log --oneline -1
```

```
EVIDENCE 4                                                        2026-11-04
root@dom0:~/drakvuf-multios-sandbox# ssh root@192.168.1.12 'systemctl stop sandbox-api; systemctl is-active sandbox-api' ; cd /root/drakvuf-multios-sandbox && git log --oneline -1 && make web_sandbox 2>&1 | tee /root/make-web_sandbox-$(date +%Y%m%d-%H%M).log | grep -nE 'exists: keeping|already rendered|platform at|OK$|FAIL|rror|Fingerprint|conformance|worker' | head -40; ssh root@192.168.1.12 'systemctl restart sandbox-api; sleep 3; systemctl is-active postgresql garage sandbox-api nginx'
inactive
2b433f4 (HEAD -> master, origin/master, origin/HEAD) Record the Behaviour tab's KeyError from a loop of parents in TROUBLESHOOTING
13:if su - postgres -c "psql -lqt" | grep -qw sandbox_platform; then echo "sandbox_platform exists: keeping the cluster and the database"; else \
24:su - platform -s /bin/bash -c "git -C /opt/platform/src fetch --quiet origin && git -C /opt/platform/src checkout --quiet --detach 2b433f48bcdb37fa7068b244cf23d2ea6249e85c && git -C /opt/platform/src log -1 --format=\"platform at %h %s\""; \
37:if [ -f /etc/garage.toml ]; then echo "/etc/garage.toml exists: keeping the store, its secrets and its layout"; FIRST=0; else FIRST=1; \
110:  | ssh root@192.168.1.12 'if grep -q "^JWT_SIGNING_KEY=" /etc/sandbox_platform/api.env 2>/dev/null; then echo "api.env already rendered: keeping it"; cat >/dev/null; else umask 077; cat >> /etc/sandbox_platform/api.env; fi'
122:# platform at any later run stops the run and says how to remove it.
126:if [ -d /etc/sandbox_platform/tls ]; then echo "/etc/sandbox_platform/tls exists: keeping the certificates"; else \
177:  /opt/platform/src/platform/garage/conformance.py \
184: .venv/bin/python create_worker.py dom0-1 || echo "worker dom0-1 exists already; make sandboxd rotates its token"; \
215:sandbox_platform exists: keeping the cluster and the database
222:platform at 2b433f4 Record the Behaviour tab's KeyError from a loop of parents in TROUBLESHOOTING
309:/usr/local/bin/garage.new: OK
310:/etc/garage.toml exists: keeping the store, its secrets and its layout
369:api.env already rendered: keeping it
370:/etc/sandbox_platform/tls exists: keeping the certificates
372:make: *** [Makefile:263: web_sandbox] Error 1
active
active
active
active
root@platform:~# journalctl -u sandbox-api -n 30 --no-pager | grep -vE 'GET /healthz' | tail -15; git -C /opt/platform/src log --oneline -1
Nov 04 13:11:27 platform python[678]: INFO:     Uvicorn running on https://192.168.1.12:8000 (Press CTRL+C to quit)
Nov 04 13:34:19 platform systemd[1]: Stopping sandbox-api.service - DRAKVUF sandbox platform API...
Nov 04 13:34:19 platform python[678]: INFO:     Shutting down
Nov 04 13:34:20 platform python[678]: INFO:     Waiting for application shutdown.
Nov 04 13:34:20 platform python[678]: INFO:     Application shutdown complete.
Nov 04 13:34:20 platform python[678]: INFO:     Finished server process [678]
Nov 04 13:34:20 platform systemd[1]: sandbox-api.service: Deactivated successfully.
Nov 04 13:34:20 platform systemd[1]: sandbox-api.service: Consumed 6.129s CPU time, 118.3M memory peak.
Nov 04 13:34:36 platform systemd[1]: Started sandbox-api.service - DRAKVUF sandbox platform API.
Nov 04 13:34:37 platform python[1511]: INFO:     Started server process [1511]
Nov 04 13:34:37 platform python[1511]: INFO:     Waiting for application startup.
Nov 04 13:34:37 platform python[1511]: Telegram disabled: signup and password reset will not work
Nov 04 13:34:37 platform python[1511]: INFO:     Application startup complete.
Nov 04 13:34:37 platform python[1511]: INFO:     Uvicorn running on https://192.168.1.12:8000 (Press CTRL+C to quit)
fatal: detected dubious ownership in repository at '/opt/platform/src'
To add an exception for this directory, call:

    git config --global --add safe.directory /opt/platform/src
```

**The four keep branches fired, the checkout moved to `2b433f4`, Garage's
binary verified — and the run stopped at line 371 of the log, which the
`grep` above did not match.** Read over ssh afterwards:

```
/etc/sandbox_platform/tls/ca.key exists on the platform. The CA root key must not live here (tls/README.md, Custody): shred -u /etc/sandbox_platform/tls/ca.key /etc/sandbox_platform/tls/ca.srl, then run this again.
```

That is the guard the 2026-11-03 change added, doing its job: the real
platform was built on 2026-11-02 by the previous recipe, which made the CA on
the DomU and left `ca.key` there (`ls -la /etc/sandbox_platform/tls/`: `ca.key`
3272 bytes, Nov 2 08:35, owned by `platform`, the user the API runs as). The
development checkout has no `tls/ca/`, so **this key exists nowhere else**.
Everything after the guard — the unit file, nginx, `conformance.py`, the
worker — did not run on this attempt; the API was started by the operator's
`systemctl restart` at 13:34:36 on the new checkout, with migrations 0010 to
0013 reported `applied`, and `journalctl` is clean. The last line of the
platform paste is the `git` of the verify block run as root; the block above
runs it as `platform` now.

> **DECISION needed — the operator's, before 4b.** `tls/README.md`, Custody,
> wants the root key on a workstation or an encrypted volume and never on the
> platform; the recipe destroys it on a Makefile-built platform. Two ways to
> satisfy the guard: **(a)** copy the key off to a place you control, verify
> the copy, then shred it on the platform — keeps the ability to issue new
> leaf certificates under this CA; **(b)** shred it without a copy — a renewal
> (the leaves last 825 days, to early 2029) is then a new CA, `make
> web_sandbox` after `rm -r /etc/sandbox_platform/tls`, and `make sandboxd`
> to re-trust it on Dom0. Neither touches `ca.crt` or the three leaf
> certificates, so nothing running changes. The grep filter of the command
> above is replaced in 4b by `tail`, so a refusal shows.

## 4b. Satisfy the guard, then the re-run

Option (a), the copy, from the workstation through Dom0; `tls/ca/` is not
tracked:

```bash
# WORKSTATION. Copies the CA's three files via Dom0 and verifies them
mkdir -p /workspaces/work/sandbox_project/tls/ca && chmod 700 /workspaces/work/sandbox_project/tls/ca && for f in ca.key ca.crt ca.srl; do ssh -i /workspaces/work/id_ed25519 root@192.168.1.6 "ssh root@192.168.1.12 cat /etc/sandbox_platform/tls/$f" > /workspaces/work/sandbox_project/tls/ca/$f; done && chmod 600 /workspaces/work/sandbox_project/tls/ca/* && sha256sum /workspaces/work/sandbox_project/tls/ca/* && ssh -i /workspaces/work/id_ed25519 root@192.168.1.6 "ssh root@192.168.1.12 'cd /etc/sandbox_platform/tls && sha256sum ca.key ca.crt ca.srl'" && git -C /workspaces/work/sandbox_project status --short --ignored tls/ca | head -3
```

Expect the two `sha256sum` lists equal, line for line, and `!! tls/ca/` from
`git status`. Then, either way:

```bash
# PLATFORM DOMU, as root. DESTROYS the CA root key on the platform; ca.crt and the leaf certificates stay
shred -u /etc/sandbox_platform/tls/ca.key /etc/sandbox_platform/tls/ca.srl && ls -la /etc/sandbox_platform/tls/
```

Expect `ca.crt` and the three `.crt`/`.key` pairs, no `ca.key`, no `ca.srl`.
Then the re-run, with `tail` so a refusal is visible:

```bash
# DOM0 (Xen), as root. The platform is down from here to the restart
ssh root@192.168.1.12 'systemctl stop sandbox-api; systemctl is-active sandbox-api' ; cd /root/drakvuf-multios-sandbox && git log --oneline -1 && make web_sandbox 2>&1 | tee /root/make-web_sandbox-$(date +%Y%m%d-%H%M).log | tail -45; ssh root@192.168.1.12 'systemctl restart sandbox-api; sleep 3; systemctl is-active postgresql garage sandbox-api nginx'
```

Expect the keep lines again, `platform at 2b433f4`, `garage.new: OK`, the
`sandbox-api` status lines, nginx installed or already current,
`conformance.py` passing every check, `worker dom0-1 exists already; make
sandboxd rotates its token`, and four `active`. Then the verify block above.

```
EVIDENCE 4b

mkdir -p /workspaces/work/sandbox_project/tls/ca && chmod 700 /workspaces/work/sandbox_project/tls/ca && for f in ca.key ca.crt ca.srl; do ssh -i /workspaces/work/id_ed25519 root@192.168.1.6 "ssh root@192.168.1.12 cat /etc/sandbox_platform/tls/$f" > /workspaces/work/sandbox_project/tls/ca/$f; done && chmod 600 /workspaces/work/sandbox_project/tls/ca/* && sha256sum /workspaces/work/sandbox_project/tls/ca/* && ssh -i /workspaces/work/id_ed25519 root@192.168.1.6 "ssh root@192.168.1.12 'cd /etc/sandbox_platform/tls && sha256sum ca.key ca.crt ca.srl'" && git -C /workspaces/work/sandbox_project status --short --ignored tls/ca | head -3
8fa5db290c08a4891fe79c7f0627360398ef099b8c4103f4ef9ff6b66cb9817a  /workspaces/work/sandbox_project/tls/ca/ca.crt
<REDACTED: sha256 of the CA private key, equal on both sides>  /workspaces/work/sandbox_project/tls/ca/ca.key
a44c2ee1843c0611da355cf2e6f661588fd65a461d1b772231dae2f3264b2b5e  /workspaces/work/sandbox_project/tls/ca/ca.srl
<REDACTED: sha256 of the CA private key, equal on both sides>  ca.key
8fa5db290c08a4891fe79c7f0627360398ef099b8c4103f4ef9ff6b66cb9817a  ca.crt
a44c2ee1843c0611da355cf2e6f661588fd65a461d1b772231dae2f3264b2b5e  ca.srl
!! tls/ca/

root@dom0:~/drakvuf-multios-sandbox# ssh root@192.168.1.12 'systemctl stop sandbox-api; systemctl is-active sandbox-api' ; cd /root/drakvuf-multios-sandbox && git log --oneline -1 && make web_sandbox 2>&1 | tee /root/make-web_sandbox-$(date +%Y%m%d-%H%M).log | tail -45; ssh root@192.168.1.12 'systemctl restart sandbox-api; sleep 3; systemctl is-active postgresql garage sandbox-api nginx'
inactive
2b433f4 (HEAD -> master, origin/master, origin/HEAD) Record the Behaviour tab's KeyError from a loop of parents in TROUBLESHOOTING
  ok    the configured origin's preflight is answered        (200, 'https://sandbox.evilbootloader.com')
  ok    any other origin's preflight is refused              403
  ok    a real response is not readable cross-origin         (200, None, None)

== region
   the SigV4 scope, and api.env's S3_REGION must match it
  ok    a wrong-region presigned URL is refused              (400, True)

== what api-policy.json withheld -- refused by the front
   `403 403`: nginx answers with an HTML page, so there is no S3 error code. An S3-CODED 403 here means the store refused it and the front did not, which is a weaker posture -- so it is reported rather than accepted.
  ok    CopyObject                                           403 403
  ok    ListObjectsV2                                        403 403
  ok    ListBuckets                                          403 403
  ok    DeleteObject                                         403 403
  ok    DeleteObjects                                        403 403
  ok    PutBucketCors                                        403 403
  ok    a PUT carrying x-amz-copy-source (CVE-2026-97731's shape) 403
  ok    POST ?delete (multi-object delete)                   403
  ok    POST ?uploads (multipart init)                       403
  ok    GET / (ListBuckets, unsigned)                        403
  ok    GET /minio/health/live (gone with MinIO)             403

== the same key straight at Garage -- what the front is holding back
  ok    ListObjectsV2 direct                                 allowed
  ok    CopyObject direct                                    allowed
  ok    DeleteObject direct                                  allowed
  ok    PutBucketCors direct (needs owner)                   403 AccessDenied

   These four are EXPECTED, and they are the residual risk of DECISION A2
   written down: api-policy.json withheld list, copy and delete from the
   CREDENTIAL, where the front withholds them from the PATH. Equivalent for
   anything arriving over TLS; not equivalent for code already running on the
   platform DomU, which can reach Garage's loopback listener and then list,
   copy and delete the whole bucket with the API's own key.

   On this store, a platform compromise is a bucket compromise. Under MinIO it
   was a bucket READ compromise at worst. That is why Garage binds loopback
   only and why provision.sh's owner key is ephemeral.

probe removed: probe/conformance-c887dd2c-5193-41da-aef0-9fb99fcacdd8.bin

31 ok, 0 unexpected, 0 skipped
database: postgresql:///sandbox_platform
worker 'dom0-1' already exists; pass --rotate to replace its credential (the old one stops working at once)
worker dom0-1 exists already; make sandboxd rotates its token
active
active
active
active
```

---

# 5. `make sandboxd`

Builds and installs libvmi and DRAKVUF from the submodules at their pins
(`3c3b73a6` / `ab06c1f` on 2026-11-04 — **Dom0 does not run that pin yet**,
and this is the step that deploys it), installs tor and FakeNet-NG with the
egress target, copies the certificates from the platform, makes the daemon's
virtualenv, appends the LVM filter once, **rotates Dom0's worker token on the
platform** and renders `/etc/sandboxd/sandboxd.env`, keeping the injection
PIDs from the existing file. Re-runnable. Needs the platform up and `sandboxd`
stopped (it is).

```bash
# DOM0 (Xen), as root
cd /root/drakvuf-multios-sandbox && cp -a /etc/sandboxd/sandboxd.env /root/sandboxd.env.before-$(date +%Y%m%d) && make sandboxd 2>&1 | tee /root/make-sandboxd-$(date +%Y%m%d-%H%M).log | tail -40
```

Expect the libvmi `make install` lines, `git switch -C pr-650`, meson
`--reconfigure` (a `build/` exists) then `ninja` building and installing
`drakvuf` and `injector`, the six FakeNet `test` lines passing silently,
`active` twice for `tor fakenet`, `lvmconfig --validate` without output and
`devices/global_filter` showing the `-clone` reject, and no
`sandboxd.env: unrendered placeholder`. Then:

```bash
# DOM0 (Xen), as root. Read-only; the env file's values are NOT printed
ls -la /usr/local/bin/drakvuf /usr/local/bin/injector /usr/local/lib/libvmi.so.0*; git -C /root/drakvuf-multios-sandbox/drakvuf log --oneline -1; strings /usr/local/bin/drakvuf | grep -c 'The syscall dispatcher is not in the kernel profile'; stat -c '%a %U %s' /etc/sandboxd/sandboxd.env; grep -cE '^[A-Z_]+=' /etc/sandboxd/sandboxd.env; grep -E '^SANDBOXD_(TOTAL_MIB|REPO_ROOT|ANALYSIS_USERNAME|INJECTION_PID_[A-Z]+)=' /etc/sandboxd/sandboxd.env; diff <(grep -E '^SANDBOXD_INJECTION_PID' /root/sandboxd.env.before-*) <(grep -E '^SANDBOXD_INJECTION_PID' /etc/sandboxd/sandboxd.env) && echo "injection PIDs carried over"; grep -c 'LD_LIBRARY_PATH' /root/.bashrc; systemctl is-active tor fakenet drakvuf-egress.target
```

Expect binaries dated now, `3c3b73a6` (or the current pin), `1` for the
string, `600 root`, the five rendered variables with
`SANDBOXD_TOTAL_MIB` = `total_memory` − 8192 − 4096 − 2000 = **18317** on
this host, `injection PIDs carried over`, and three `active`.

> **FINDING (dry run, 2026-11-04).** Two things to watch in this output and
> decide on afterwards, neither blocking. (1) The header comment of
> `automation/sandboxd.env.example` names its placeholders, so the `sed`
> renders the **real worker token into a comment line** of the env file as well
> as into `WORKER_TOKEN=`. The file is mode 600 and the value is Dom0's own, so
> nothing leaks past the file, but a secret has no place in a comment:
> `grep -c "$(grep ^WORKER_TOKEN= /etc/sandboxd/sandboxd.env | cut -d= -f2)" /etc/sandboxd/sandboxd.env`
> prints `2` until the example's comment is reworded. (2) The recipe appends
> an `export LD_LIBRARY_PATH` line to `/root/.bashrc` on **every** run; the
> `grep -c` above counts them.

## 5b. Start the daemon and run one Ubuntu job

The token was rotated, so the daemon **must** be restarted from the new env
file. `docs/DEVELOPING.md` §6 has the invocation; it stays in the foreground in
its own terminal (`tmux`).

```bash
# DOM0 (Xen), as root, in tmux. Foreground; leave it running
cd /root/drakvuf-multios-sandbox && mkdir -p /var/log/sandboxd && set -a && . /etc/sandboxd/sandboxd.env && set +a && .venv-sandboxd/bin/python -m sandboxd.daemon 2>&1 | tee -a /var/log/sandboxd/$(date +%Y%m%d-%H%M).log
```

Expect the startup lines: the network provisioned, registration with the
platform, no warning about `rdtsc-poc=1` without `RDTSC_POC` (2c made sure),
then `POST .../api/v1/worker/claim` → `200` every poll. Submit one benign
Ubuntu sample through the UI with the default plugins and watch it to
`completed`. This is the check that the Ubuntu path is **unchanged** after a
new DRAKVUF, a new Xen and a re-rendered environment: it is the evidenced path,
and nothing in this runbook may leave it worse.

```bash
# DOM0 (Xen), as root, another terminal. Read-only, after the job ends
grep -E 'job [0-9a-f-]{8}.*(claimed|restor|inject|trace|collect|complete|failed)' /var/log/sandboxd/*.log | tail -20
```

Paste that and the job's row from the UI (id, OS, state, duration, which
artifacts).

```
EVIDENCE 5

root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && cp -a /etc/sandboxd/sandboxd.env /root/sandboxd.env.before-$(date +%Y%m%d) && make sandboxd 2>&1 | tee /root/make-sandboxd-$(date +%Y%m%d-%H%M).log | tail -40
  Downloading pip-26.3-py3-none-any.whl (2.0 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.0/2.0 MB 31.9 MB/s  0:00:00
Requirement already satisfied: platformdirs==4.13.3 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 409)) (4.13.3)
Requirement already satisfied: prompt-toolkit==3.0.53 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 415)) (3.0.53)
Requirement already satisfied: protobuf==7.36.2 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 421)) (7.36.2)
Requirement already satisfied: pyasn1==0.6.4 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 433)) (0.6.4)
Requirement already satisfied: pyasn1-modules==0.4.2 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 440)) (0.4.2)
Requirement already satisfied: pycparser==3.11 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 446)) (3.11)
Requirement already satisfied: pydantic==2.13.4 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 452)) (2.13.4)
Requirement already satisfied: pydantic-core==2.46.4 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 460)) (2.46.4)
Requirement already satisfied: pydantic-settings==2.15.0 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 584)) (2.15.0)
Requirement already satisfied: pyelftools==0.33 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 588)) (0.33)
Requirement already satisfied: pygments==2.21.0 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 594)) (2.21.0)
Requirement already satisfied: python-dotenv==1.2.4 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 600)) (1.2.4)
Requirement already satisfied: python-flirt==0.10.0 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 606)) (0.10.0)
Requirement already satisfied: pyyaml==6.0.3 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 661)) (6.0.3)
Requirement already satisfied: questionary==2.1.1 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 738)) (2.1.1)
Requirement already satisfied: rich==15.0.0 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 744)) (15.0.0)
Requirement already satisfied: rich-click==1.9.9 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 752)) (1.9.9)
Requirement already satisfied: ruamel-yaml==0.19.1 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 758)) (0.19.1)
Requirement already satisfied: semantic-version==2.10.0 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 764)) (2.10.0)
Requirement already satisfied: six==1.17.0 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 770)) (1.17.0)
Requirement already satisfied: sortedcontainers==2.4.0 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 776)) (2.4.0)
Requirement already satisfied: tenacity==9.2.1 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 782)) (9.2.1)
Requirement already satisfied: typing-extensions==4.16.0 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 788)) (4.16.0)
Requirement already satisfied: typing-inspection==0.4.4 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 798)) (0.4.4)
Requirement already satisfied: viv-utils==0.8.1 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 805)) (0.8.1)
Requirement already satisfied: vivisect==1.3.2 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 810)) (1.3.2)
Requirement already satisfied: wcwidth==0.9.2 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 817)) (0.9.2)
Requirement already satisfied: websockets==16.1.1 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 850)) (16.1.1)
Requirement already satisfied: xmltodict==1.0.4 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 961)) (1.0.4)
Requirement already satisfied: yara-x==1.21.0 in ./.venv-sandboxd/lib/python3.12/site-packages (from -r sandboxd/requirements.txt (line 967)) (1.21.0)
Installing collected packages: pip
  Attempting uninstall: pip
    Found existing installation: pip 26.2.2
    Uninstalling pip-26.2.2:
      Successfully uninstalled pip-26.2.2
Successfully installed pip-26.3
  LVM configuration valid.
global_filter=["r|^/dev/mapper/vg--root-.*--clone[0-9]*$|","r|^/dev/vg-root/.*-clone[0-9]*$|","a|.*|"]
root@dom0:~/drakvuf-multios-sandbox# ls -la /usr/local/bin/drakvuf /usr/local/bin/injector /usr/local/lib/libvmi.so.0*; git -C /root/drakvuf-multios-sandbox/drakvuf log --oneline -1; strings /usr/local/bin/drakvuf | grep -c 'The syscall dispatcher is not in the kernel profile'; stat -c '%a %U %s' /etc/sandboxd/sandboxd.env; grep -cE '^[A-Z_]+=' /etc/sandboxd/sandboxd.env; grep -E '^SANDBOXD_(TOTAL_MIB|REPO_ROOT|ANALYSIS_USERNAME|INJECTION_PID_[A-Z]+)=' /etc/sandboxd/sandboxd.env; diff <(grep -E '^SANDBOXD_INJECTION_PID' /root/sandboxd.env.before-*) <(grep -E '^SANDBOXD_INJECTION_PID' /etc/sandboxd/sandboxd.env) && echo "injection PIDs carried over"; grep -c 'LD_LIBRARY_PATH' /root/.bashrc; systemctl is-active tor fakenet drakvuf-egress.target
-rwxr-xr-x 1 root root 4807560 Nov  4 13:45 /usr/local/bin/drakvuf
-rwxr-xr-x 1 root root  542088 Nov  4 13:45 /usr/local/bin/injector
lrwxrwxrwx 1 root root      16 Nov  4 13:45 /usr/local/lib/libvmi.so.0 -> libvmi.so.0.0.15
-rwxr-xr-x 1 root root 1787440 Nov  4 13:45 /usr/local/lib/libvmi.so.0.0.15
3c3b73a (HEAD, origin/develop) Bound guest-driven work, free hooks safely, end the run when the guest shuts down
1
600 root 4981
15
SANDBOXD_TOTAL_MIB=18317
SANDBOXD_REPO_ROOT=/root/drakvuf-multios-sandbox
SANDBOXD_ANALYSIS_USERNAME=carlos
SANDBOXD_INJECTION_PID_UBUNTU=1
SANDBOXD_INJECTION_PID_WINDOWS=4756
injection PIDs carried over
8
active
active
active
root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && mkdir -p /var/log/sandboxd && set -a && . /etc/sandboxd/sandboxd.env && set +a && .venv-sandboxd/bin/python -m sandboxd.daemon 2>&1 | tee -a /var/log/sandboxd/$(date +%Y%m%d-%H%M).log
2026-11-04 13:46:24,214 INFO    sandboxd: host values: SANDBOXD_REPO_ROOT=/root/drakvuf-multios-sandbox, SANDBOXD_ANALYSIS_USERNAME=carlos, SANDBOXD_INJECTION_PID_UBUNTU=1, SANDBOXD_INJECTION_PID_WINDOWS=4756, SANDBOXD_INJECTION_PID_ANDROID=<default>
2026-11-04 13:46:24,214 INFO    sandboxd: provisioning the analysis network for 3 clone slot(s)
2026-11-04 13:46:24,337 INFO    sandboxd: egress exits offered: offline (offline), tor-default (tor), sim-local (simulated)
2026-11-04 13:46:24,477 INFO    sandboxd: sweep: nothing to reclaim, Dom0 was already clean
2026-11-04 13:46:24,481 INFO    sandboxd: RDTSC compensation is on (RDTSC_POC: compensation enabled)
2026-11-04 13:46:24,481 INFO    sandboxd: capacity: 3 vlan(s) usable, 18317 MiB, 3 slot(s)
2026-11-04 13:46:24,541 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/register "HTTP/1.1 204 No Content"
2026-11-04 13:46:24,544 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/reconcile "HTTP/1.1 200 OK"
2026-11-04 13:46:44,589 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/claim "HTTP/1.1 200 OK"
2026-11-04 13:47:09,624 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/claim "HTTP/1.1 200 OK"
2026-11-04 13:47:17,654 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/claim "HTTP/1.1 200 OK"
2026-11-04 13:47:17,659 INFO    httpx: HTTP Request: GET https://192.168.1.12:9000/analysis/u/ecf3da57-8c29-4fa1-a910-bb6ae4b8372e/671/samples/6711d525-4d41-4bb0-8e4c-90f73a01c966/ee57ea3a74e03531340825e23245ca219c39717016ce97775522a4523c0d2f37.elf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=REDACTED&X-Amz-Date=20261104T134717Z&X-Amz-Expires=120&X-Amz-SignedHeaders=host&X-Amz-Signature=REDACTED "HTTP/1.1 200 OK"
2026-11-04 13:47:24,499 INFO    sandboxd.stages: job 6711d525-4d41-4bb0-8e4c-90f73a01c966: egress tor via no interface (nothing is forwarded)
2026-11-04 13:47:24,502 INFO    sandboxd.vnc: console dialled out for job 6711d525-4d41-4bb0-8e4c-90f73a01c966
2026-11-04 13:47:24,502 INFO    sandboxd.vnc: console bridged to 127.0.0.1:5900
2026-11-04 13:47:24,510 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/6711d525-4d41-4bb0-8e4c-90f73a01c966/state "HTTP/1.1 204 No Content"
2026-11-04 13:47:24,628 INFO    sandboxd.vnc: viewer left the console for 127.0.0.1:5900; waiting for another
2026-11-04 13:47:24,704 INFO    sandboxd.vnc: console bridged to 127.0.0.1:5900
2026-11-04 13:47:26,927 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/6711d525-4d41-4bb0-8e4c-90f73a01c966/state "HTTP/1.1 204 No Content"
2026-11-04 13:47:27,013 INFO    sandboxd.vnc: viewer left the console for 127.0.0.1:5900; waiting for another
2026-11-04 13:47:27,094 INFO    sandboxd.vnc: console bridged to 127.0.0.1:5900
2026-11-04 13:47:37,673 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/6711d525-4d41-4bb0-8e4c-90f73a01c966/heartbeat "HTTP/1.1 200 OK"
2026-11-04 13:47:37,677 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/claim "HTTP/1.1 200 OK"
2026-11-04 13:47:57,692 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/6711d525-4d41-4bb0-8e4c-90f73a01c966/heartbeat "HTTP/1.1 200 OK"
2026-11-04 13:48:02,699 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/claim "HTTP/1.1 200 OK"
2026-11-04 13:48:17,713 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/6711d525-4d41-4bb0-8e4c-90f73a01c966/heartbeat "HTTP/1.1 200 OK"
2026-11-04 13:48:27,736 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/claim "HTTP/1.1 200 OK"
2026-11-04 13:48:37,734 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/6711d525-4d41-4bb0-8e4c-90f73a01c966/heartbeat "HTTP/1.1 200 OK"
2026-11-04 13:48:52,773 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/claim "HTTP/1.1 200 OK"
2026-11-04 13:48:57,753 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/6711d525-4d41-4bb0-8e4c-90f73a01c966/heartbeat "HTTP/1.1 200 OK"
2026-11-04 13:49:17,775 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/6711d525-4d41-4bb0-8e4c-90f73a01c966/heartbeat "HTTP/1.1 200 OK"
2026-11-04 13:49:17,813 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/claim "HTTP/1.1 200 OK"
2026-11-04 13:49:37,796 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/6711d525-4d41-4bb0-8e4c-90f73a01c966/heartbeat "HTTP/1.1 200 OK"
2026-11-04 13:49:38,742 INFO    sandboxd.vnc: console session for 127.0.0.1:5900 ended
2026-11-04 13:49:41,176 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/6711d525-4d41-4bb0-8e4c-90f73a01c966/state "HTTP/1.1 204 No Content"
2026-11-04 13:49:42,852 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/claim "HTTP/1.1 200 OK"
2026-11-04 13:49:57,807 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/6711d525-4d41-4bb0-8e4c-90f73a01c966/heartbeat "HTTP/1.1 200 OK"
2026-11-04 13:50:00,584 INFO    sandboxd.postprocessing: postprocessing of 6711d525-4d41-4bb0-8e4c-90f73a01c966: peak RSS 282 MiB of the 3072 MiB limit
2026-11-04 13:50:00,584 INFO    sandboxd.postprocessing: postprocessing of 6711d525-4d41-4bb0-8e4c-90f73a01c966:
2026-11-04 13:49:42,459 WARNING sandboxd.postprocessing.plugins.split_drakvuf_log: Failed to parse 5 lines generated by syscall
2026-11-04 13:49:42,470 WARNING sandboxd.postprocessing.postprocess: generate_wireshark_key_file won't be run because tlsmon.log does not exist
2026-11-04 13:49:44,081 ERROR sandboxd.postprocessing.plugins.parse_utils: Failed to parse line 1 of /var/lib/sandboxd/results/6711d525-4d41-4bb0-8e4c-90f73a01c966/memdump.log
Traceback (most recent call last):
  File "/root/drakvuf-multios-sandbox/sandboxd/postprocessing/plugins/parse_utils.py", line 20, in parse_log
    if result := filter_cb(data):
                 ^^^^^^^^^^^^^^^
  File "/root/drakvuf-multios-sandbox/sandboxd/postprocessing/plugins/process_dumps.py", line 31, in parse_memdump
    "index": data["DumpsCount"],
             ~~~~^^^^^^^^^^^^^^
KeyError: 'DumpsCount'
2026-11-04 13:49:44,082 ERROR sandboxd.postprocessing.plugins.parse_utils: Failed to parse line 2 of /var/lib/sandboxd/results/6711d525-4d41-4bb0-8e4c-90f73a01c966/memdump.log
Traceback (most recent call last):
  File "/root/drakvuf-multios-sandbox/sandboxd/postprocessing/plugins/parse_utils.py", line 20, in parse_log
    if result := filter_cb(data):
                 ^^^^^^^^^^^^^^^
  File "/root/drakvuf-multios-sandbox/sandboxd/postprocessing/plugins/process_dumps.py", line 31, in parse_memdump
    "index": data["DumpsCount"],
             ~~~~^^^^^^^^^^^^^^
KeyError: 'DumpsCount'
2026-11-04 13:49:44,082 INFO sandboxd.postprocessing.plugins.process_dumps: Filtered out 0 dumps.
2026-11-04 13:49:55,462 WARNING sandboxd.postprocessing.postprocess: compress_ipt won't be run because ipt does not exist
2026-11-04 13:49:57,462 INFO sandboxd.postprocessing.plugins.falco_analysis: falco: 26651 events, 0 alerts, 60 rules active, 2.0s
2026-11-04 13:49:57,659 WARNING sandboxd.postprocessing.postprocess: get_registry_info won't be run because regmon.log does not exist
2026-11-04 13:50:00,544 WARNING sandboxd.postprocessing.indexer: cpuidmon.log: 64 events from 1 PIDs absent from the process tree were not indexed (PIDs: 1945)
2026-11-04 13:50:00,544 ERROR sandboxd.postprocessing.indexer: Failed to process entry in preconfig.log
Traceback (most recent call last):
  File "/root/drakvuf-multios-sandbox/sandboxd/postprocessing/indexer.py", line 34, in index_log_file
    entry = orjson.loads(entry_data)
            ^^^^^^^^^^^^^^^^^^^^^^^^
orjson.JSONDecodeError: unexpected character, expected a JSON value: line 1 column 1 (char 0)
2026-11-04 13:50:00,553 ERROR sandboxd.postprocessing.indexer: Failed to process entry in preconfig.log
Traceback (most recent call last):
  File "/root/drakvuf-multios-sandbox/sandboxd/postprocessing/indexer.py", line 34, in index_log_file
    entry = orjson.loads(entry_data)
            ^^^^^^^^^^^^^^^^^^^^^^^^
orjson.JSONDecodeError: unexpected character, expected a JSON value: line 1 column 2 (char 1)
2026-11-04 13:50:00,553 ERROR sandboxd.postprocessing.indexer: Failed to process entry in preconfig.log
Traceback (most recent call last):
  File "/root/drakvuf-multios-sandbox/sandboxd/postprocessing/indexer.py", line 34, in index_log_file
    entry = orjson.loads(entry_data)
            ^^^^^^^^^^^^^^^^^^^^^^^^
orjson.JSONDecodeError: unexpected character, expected a JSON value: line 1 column 1 (char 0)
2026-11-04 13:50:00,680 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/6711d525-4d41-4bb0-8e4c-90f73a01c966/artifacts "HTTP/1.1 200 OK"
2026-11-04 13:50:00,688 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,691 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,692 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,695 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,698 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,699 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,702 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,717 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,718 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,753 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,757 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,758 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,758 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,759 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,760 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,763 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,765 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,768 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,770 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,783 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,794 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,795 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,796 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,968 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,971 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,973 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,981 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,990 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:00,998 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,005 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,014 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,021 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,029 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,036 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,044 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,051 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,058 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,064 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,073 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,081 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,089 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,096 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,104 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,113 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,121 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,132 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,138 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,146 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,155 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,164 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,172 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,179 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,186 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,194 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,200 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,207 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,213 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,222 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,229 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,237 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,245 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,253 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,260 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,266 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,275 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/6711d525-4d41-4bb0-8e4c-90f73a01c966/artifacts "HTTP/1.1 200 OK"
2026-11-04 13:50:01,284 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,290 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,298 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,307 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,314 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,321 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,327 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,336 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,342 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,352 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,358 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,366 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,373 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,383 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,391 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,397 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,404 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,410 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,419 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,427 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,434 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,441 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,448 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,455 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,462 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,471 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,477 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,484 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,490 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,495 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/6711d525-4d41-4bb0-8e4c-90f73a01c966/state "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,503 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/6711d525-4d41-4bb0-8e4c-90f73a01c966/complete "HTTP/1.1 204 No Content"
2026-11-04 13:50:01,517 INFO    sandboxd: job 6711d525-4d41-4bb0-8e4c-90f73a01c966 -> completed (clean)
2026-11-04 13:50:07,880 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/claim "HTTP/1.1 200 OK"
2026-11-04 13:50:32,924 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/claim "HTTP/1.1 200 OK"
2026-11-04 13:50:57,966 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/claim "HTTP/1.1 200 OK"

root@dom0:~/drakvuf-multios-sandbox# grep -E 'job [0-9a-f-]{8}.*(claimed|restor|inject|trace|collect|complete|failed)' /var/log/sandboxd/*.log | tail -20
/var/log/sandboxd/20261024-0602.log:2026-10-24 06:19:37,425 INFO    sandboxd: job 83a13904-ded4-44b4-8081-f4e5b612bee3 -> completed (clean)
/var/log/sandboxd/20261024-0905.log:2026-10-24 09:11:19,838 INFO    sandboxd: job 7c54581c-b50d-4d0d-a749-457ecdcd2c68 -> failed (clean)
/var/log/sandboxd/20261024-0924.log:2026-10-24 09:24:51,055 INFO    sandboxd: job aa78028d-4712-4d3b-a5c9-b613cca7b75f -> failed (clean)
/var/log/sandboxd/20261024-0924.log:2026-10-24 09:26:48,979 INFO    sandboxd: job bf232353-333c-4b82-9e6b-63dfd50f71bf -> failed (clean)
/var/log/sandboxd/20261024-0927.log:2026-10-24 09:27:41,072 INFO    sandboxd: job e8aad874-241e-4aef-9544-969cc51f2d40 -> failed (clean)
/var/log/sandboxd/20261024-0927.log:2026-10-24 09:28:34,720 INFO    sandboxd: job f0bc504b-ba27-40c4-9d20-0a9e52fb678f -> failed (clean)
/var/log/sandboxd/20261024-0927.log:2026-10-24 09:28:37,492 INFO    sandboxd: job 4ed5f87a-f898-47c1-bfbe-38ce0e3e266e -> completed (clean)
/var/log/sandboxd/20261024-0933.log:2026-10-24 09:33:59,694 INFO    sandboxd: job 3fdda739-25fc-4b0b-bacc-26bbf4071c14 -> failed (clean)
/var/log/sandboxd/20261024-0938.log:2026-10-24 09:42:42,386 INFO    sandboxd: job e55e7c52-d819-4901-b45d-6df348a2b747 -> completed (clean)
/var/log/sandboxd/20261024-0949.log:2026-10-24 09:49:54,933 INFO    sandboxd: job e504f3c6-774b-4ca9-84df-386a7419185a -> failed (clean)
/var/log/sandboxd/20261024-0952.log:2026-10-24 09:52:29,533 INFO    sandboxd: job b23e2105-f078-463d-9430-1cf424da94de -> failed (clean)
/var/log/sandboxd/20261024-0954.log:2026-10-24 10:02:09,229 INFO    sandboxd: job 8123f3db-f7f5-4887-a241-51697d3dc3d6 -> completed (clean)
/var/log/sandboxd/20261024-0954.log:2026-10-24 10:30:25,582 INFO    sandboxd: job bd3393d9-a947-4bf8-8b56-2e9ab962ac7c -> completed (clean)
/var/log/sandboxd/20261024-0954.log:2026-10-24 10:32:18,756 INFO    sandboxd: job 084e3916-f9e0-4909-b468-1212fb151d1b -> completed (clean)
/var/log/sandboxd/20261024-1123.log:2026-10-24 11:26:55,040 INFO    sandboxd: job 0a5796bf-9429-4e43-b7cc-23a3fd7700a8 -> completed (clean)
/var/log/sandboxd/20261024-1123.log:2026-10-24 11:30:10,531 INFO    sandboxd: job 02e15f54-9b67-478b-932d-0a35f1cb5576 -> completed (clean)
/var/log/sandboxd/20261024-1123.log:2026-10-24 11:31:55,510 INFO    sandboxd: job 80f1f176-5508-473a-8f3d-74f211166a95 -> completed (clean)
/var/log/sandboxd/20261024-1728.log:2026-10-24 17:30:46,374 INFO    sandboxd: job c2d3360c-c86c-42ba-a0ad-156286f83372 -> completed (clean)
/var/log/sandboxd/20261024-1728.log:2026-10-24 17:33:12,365 INFO    sandboxd: job 3aaa445c-333c-4fa5-890a-5c16b38289a2 -> completed (clean)
/var/log/sandboxd/20261104-1346.log:2026-11-04 13:50:01,517 INFO    sandboxd: job 6711d525-4d41-4bb0-8e4c-90f73a01c966 -> completed (clean)

```

---

# 6. The guests: `*_analysis_vm`, `modify_*`, `setup_hooks_*`

> **DECISION — the operator's, not this document's.** These targets cannot
> run against the existing golden images: `lvcreate` fails on an LV that
> exists. Running them means **removing the golden volumes and saved states on
> purpose**, which `CLAUDE.md` forbids without an explicit instruction. The
> case for doing it now: the identity `make xen` installed reaches a guest only
> at a cold install — a saved state keeps the firmware it booted with, and
> Windows keeps the devices it once saw
> ([guest-identity.md §4](docs/architecture/guest-identity.md#4-why-a-reinstall)) —
> so the images have to be rebuilt for that work to count at all. Windows
> first: it is the path to re-confirm (`CURRENT-STATE.md` §1.5). Ubuntu after,
> so the evidenced guest is the last one taken down.

> **FINDING (dry run, 2026-11-04).** `ubuntu_analysis_vm` writes
> `misc/xen-vms/ubuntu.cfg` **before** its `lvcreate` can fail, and the recipe's
> last `sed`, which strips the installer's `kernel`/`ramdisk`/`extra` lines, is
> then never reached. A run against an existing `vg-root/ubuntu` leaves a
> tracked cfg that boots the installer. `windows_analysis_vm` has the same
> shape. Candidate fix: the LV guard first, as `web_vm` has it. Until then,
> run these only after the volumes are gone, and `git status` after.

## 6a. Back up what the targets will replace

`state/*.bak` are the guests' memory, about 8 GB each; the root filesystem
has 81 G free and the output volume 489 G, so the copy goes there.

```bash
# DOM0 (Xen), as root. Copies only
B=/srv/drakvuf-out/backup-$(date +%Y%m%d) && mkdir -p $B && cp -a /root/drakvuf-multios-sandbox/state /root/drakvuf-multios-sandbox/profiles /etc/sandboxd/sandboxd.env /root/drakvuf-multios-sandbox/misc/xen-vms $B/ && du -sh $B && ls $B $B/state
```

```
EVIDENCE 6a
root@dom0:~/drakvuf-multios-sandbox# # DOM0 (Xen), as root. Copies only
B=/srv/drakvuf-out/backup-$(date +%Y%m%d) && mkdir -p $B && cp -a /root/drakvuf-multios-sandbox/state /root/drakvuf-multios-sandbox/profiles /etc/sandboxd/sandboxd.env /root/drakvuf-multios-sandbox/misc/xen-vms $B/ && du -sh $B && ls $B $B/state
17G	/srv/drakvuf-out/backup-20261104
/srv/drakvuf-out/backup-20261104:
profiles  sandboxd.env  state  xen-vms

/srv/drakvuf-out/backup-20261104/state:
README.md  firmware  ubuntu_sandbox.bak  windows_sandbox.bak  xen-identity.json
```

## 6b. Windows

**Shut `sandboxd` down first** (its terminal): the golden volume's snapshot
is what every Windows clone starts from, and the saved state goes away here.

```bash
# DOM0 (Xen), as root. DESTROYS the Windows golden image and its sandbox snapshot
B=/srv/drakvuf-out/backup-$(date +%Y%m%d); mkdir -p $B; xl destroy windows_analysis 2>/dev/null; xl destroy windows_analysis_sandbox 2>/dev/null; lvremove -y vg-root/windows_sandbox vg-root/windows && mv /root/drakvuf-multios-sandbox/state/windows_sandbox.bak $B/windows_sandbox.bak.removed; lvs --noheadings -o lv_name vg-root | tr -d ' ' | grep -cxE 'windows|windows_sandbox'
```

Expect `0`: neither volume left. Then the install. `win_installers` runs first and downloads the
eight installers named in `automation/win-installers.list` once, verifying
each against its SHA-256; the Windows ISO is already in `misc/iso/` (§0.3)
and is verified again before use. The target builds `Win11_modified.iso`,
writes `misc/xen-vms/windows.cfg` with the identity's lines and the guest's
MAC, creates the 1 T thin volume and boots the installer. Expect it to end
within minutes; the install itself then runs unattended in the guest for the
better part of an hour.

```bash
# DOM0 (Xen), as root
cd /root/drakvuf-multios-sandbox && make windows_analysis_vm 2>&1 | tee /root/make-windows_analysis_vm-$(date +%Y%m%d-%H%M).log | grep -vE '^ *[0-9.]+%' | tail -30; xl list; git status --short misc/
```

Expect eight `: OK` lines from `sha256sum`, the ISO's `OK`, `genisoimage`'s
summary, `lvcreate` and `xl list` with `windows_analysis`. `git status` should
show `misc/xen-vms/windows.cfg` modified: the identity's lines are
host-specific, and whether that file should be tracked at all is a question
for §8, not for now.

Watch it over VNC. From the workstation, `ssh -L 5900:127.0.0.1:5900
root@192.168.1.6`, viewer on `localhost:5900`. When the unattended install has
finished and Windows sits at the desktop, **shut it down from inside**
(`on_poweroff = destroy` removes the domain). Then boot it again to tune it,
which is what `modify_windows` is for, and shut it down again the same way:

```bash
# DOM0 (Xen), as root. Boots the golden image for tuning; shut it down from inside when done
cd /root/drakvuf-multios-sandbox && make modify_windows && xl list
```

What was done by hand in the guest (Defender off, Chrome, Office, whatever
else) is a FINDING to write here: it is part of the image and nothing else
records it.

```
EVIDENCE 6b-install, first attempt                                2026-11-04
root@dom0:~/drakvuf-multios-sandbox# B=/srv/drakvuf-out/backup-$(date +%Y%m%d); mkdir -p $B; xl destroy windows_analysis 2>/dev/null; xl destroy windows_analysis_sandbox 2>/dev/null; lvremove -y vg-root/windows_sandbox vg-root/windows && mv /root/drakvuf-multios-sandbox/state/windows_sandbox.bak $B/windows_sandbox.bak.removed; lvs --noheadings -o lv_name vg-root | tr -d ' ' | grep -cxE 'windows|windows_sandbox'
  Consider pruning vg-root VG archive with more then 120 MiB in 15000 files (check archiving is needed in lvm.conf).
  Consider pruning vg-root VG archive with more then 120 MiB in 15001 files (check archiving is needed in lvm.conf).
  Logical volume "windows" successfully removed.
  Consider pruning vg-root VG archive with more then 120 MiB in 15002 files (check archiving is needed in lvm.conf).
  Consider pruning vg-root VG archive with more then 120 MiB in 15003 files (check archiving is needed in lvm.conf).
  Logical volume "windows_sandbox" successfully removed.
0
root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && make windows_analysis_vm 2>&1 | tee /root/make-windows_analysis_vm-$(date +%Y%m%d-%H%M).log | grep -vE '^ *[0-9.]+%' | tail -30; xl list; git status --short misc/
[... wget's progress lines ...]
167900K .......... .......... .......... ..........           100%  210M=3.0s

2026-11-04 13:53:11 (54.1 MB/s) - ‘/root/drakvuf-multios-sandbox/misc/iso/win-installers/googlechromestandaloneenterprise64.msi.part’ saved [171970560/171970560]

/root/drakvuf-multios-sandbox/misc/iso/win-installers/googlechromestandaloneenterprise64.msi: FAILED
sha256sum: WARNING: 1 computed checksum did NOT match
make: *** [Makefile:660: win_installers] Error 1
Name                                        ID   Mem VCPUs    State    Time(s)
Domain-0                                     0  8192     6     r-----     489.8
platform                                     1  4096     4     -b----      74.9
 M misc/xen-vms/ubuntu_sandbox.cfg
 M misc/xen-vms/windows_sandbox.cfg
```

**The golden Windows image and its saved state are gone, by decision, and
the build refused at the first installer**: Google's Chrome MSI no longer
matched the hash pinned on 2026-11-03. The refusal is the recipe doing what
`automation/win-installers.list` promises. Understood the same day: Google's
`Last-Modified` for the file is 2026-11-03 21:21 UTC, after the pin; the file
Dom0 got and the file the development container got minutes later are the
same, `55edacd3…`, 171,970,560 bytes, version strings `157.0.8089.0`
([TROUBLESHOOTING](docs/TROUBLESHOOTING.md#make-win_installers-refuses-the-build-an-installers-checksum-did-not-match)).
The list is re-pinned in this checkout; until that commit reaches Dom0, the
same line by hand there:

```bash
# DOM0 (Xen), as root. One line of a tracked file; the commit with the same change follows
cd /root/drakvuf-multios-sandbox && sed -i 's/^googlechromestandaloneenterprise64.msi  ecf1b28bf4e8e8b3434a844eb915118935e6525768efe3dbe622c2a20cba9ec9/googlechromestandaloneenterprise64.msi  55edacd348b4c1c9b291dab19e4665929c7a127c013d9625970be924f893273f/' automation/win-installers.list && grep -n '^googlechrome' automation/win-installers.list | cut -c1-110 && git diff --stat
```

Expect the line with `55edacd3…` and three modified files in the stat (the
two templates of 1.1e and the list). The file on disk is kept and re-checked;
the seven other installers are downloaded and verified next. Then the install
command above again, in a terminal you watch:

```bash
# DOM0 (Xen), as root
cd /root/drakvuf-multios-sandbox && make windows_analysis_vm 2>&1 | tee /root/make-windows_analysis_vm-$(date +%Y%m%d-%H%M).log | grep -vE '^ *[0-9.]+%' | grep -nE ': OK$|FAILED|did NOT match|genisoimage|Total|lvcreate|Logical volume|Parsing config|Error'; xl list; git status --short misc/
```

Expect eight `: OK` lines (the installers), the ISO's `OK`, `genisoimage`'s
summary, `Logical volume "windows" created`, `Parsing config` and the domain
in `xl list`. No `head` on this pipeline: a `head` that exits early closes
the pipe under wget, which then writes `wget-log` files into the checkout
(6b-mirror's evidence has four of them).

> **FINDING (2026-11-04).** A pin against an unversioned vendor URL rots with
> every release of that product, and Chrome releases about weekly: the first
> run after any pin will usually fail on it. The list's scheme — download,
> refuse on mismatch, understand, re-pin — held, at the cost of a day's
> delay in the first install. **DECISION, the operator's, the same day: the
> lab mirrors its verified installers.** Google publishes no versioned URL
> for the enterprise MSI (three plausible patterns probed, all 404, while its
> version-history API named stable `157.0.8103.39` and the served file still
> read `157.0.8089.0`, so the next change was days away). The mirror is
> `make win_installers_mirror` and `automation/win-installers-mirror.conf`:
> the platform's nginx on 9100, LAN only, the object front's certificate,
> Dom0's verified cache published to it, every file fetched back through it
> and hashed. `win_installers` looks there first. 6b-mirror below runs it.

```
EVIDENCE 6b-install                                               2026-11-04
root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && sed -i 's/^googlechromestandaloneenterprise64.msi  ecf1b28bf4e8e8b3434a844eb915118935e6525768efe3dbe622c2a20cba9ec9/googlechromestandaloneenterprise64.msi  55edacd348b4c1c9b291dab19e4665929c7a127c013d9625970be924f893273f/' automation/win-installers.list && grep -n '^googlechrome' automation/win-installers.list | cut -c1-110 && git diff --stat
22:googlechromestandaloneenterprise64.msi  55edacd348b4c1c9b291dab19e4665929c7a127c013d9625970be924f893273f  h
 automation/win-installers.list   | 2 +-
 drakvuf                          | 0
 misc/xen-vms/ubuntu_sandbox.cfg  | 9 +++++++--
 misc/xen-vms/windows_sandbox.cfg | 9 +++++++--
 4 files changed, 15 insertions(+), 5 deletions(-)
root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && make windows_analysis_vm 2>&1 | tee /root/make-windows_analysis_vm-$(date +%Y%m%d-%H%M).log | grep -vE '^ *[0-9.]+%' | grep -nE ': OK$|FAILED|did NOT match|genisoimage|Total|lvcreate|Logical volume|Parsing config|Error' | head -30; xl list; git status --short misc/
17:/root/drakvuf-multios-sandbox/misc/iso/win-installers/googlechromestandaloneenterprise64.msi: OK
6944:/root/drakvuf-multios-sandbox/misc/iso/win-installers/AcroRdrDCx642100720099_MUI.exe: OK
6997:/root/drakvuf-multios-sandbox/misc/iso/win-installers/7z2408-x64.exe: OK
7526:/root/drakvuf-multios-sandbox/misc/iso/win-installers/python-3.12.0-amd64.exe: OK
9908:/root/drakvuf-multios-sandbox/misc/iso/win-installers/ndp48-x86-x64-allos-enu.exe: OK
10478:/root/drakvuf-multios-sandbox/misc/iso/win-installers/dotnet-runtime-8.0-win-x64.exe: OK
11004:/root/drakvuf-multios-sandbox/misc/iso/win-installers/dotnet-runtime-8.0-win-x86.exe: OK
11085:/root/drakvuf-multios-sandbox/misc/iso/win-installers/officedeploymenttool_20228-20124.exe: OK
11094:genisoimage is already the newest version (9:1.1.11-3.5).
11096:/root/drakvuf-multios-sandbox/misc/iso/Win11_23H2_EnglishInternational_x64.iso: OK
11391:Total translation table size: 2048
11392:Total rockridge attributes bytes: 0
11393:Total directory bytes: 211480
11401:  Logical volume "windows" created.
11402:Parsing config from /root/drakvuf-multios-sandbox/misc/xen-vms/windows.cfg
Name                                        ID   Mem VCPUs    State    Time(s)
Domain-0                                     0  8192     6     r-----     544.1
platform                                     1  4096     4     -b----      90.5
windows_analysis                             5  8192     1     ------       0.0
 M misc/xen-vms/ubuntu_sandbox.cfg
 M misc/xen-vms/windows_sandbox.cfg
 M misc/xen-vms/windows.cfg
```

Eight installers verified, the seven others on their first download; the
ISO verified; `Win11_modified.iso` built; the 1 T volume created; the
installer booted at 14:0x. `misc/xen-vms/windows.cfg` is modified: the
identity's lines and the guest's MAC, host-specific, not to be committed
(1.1e's rule holds for it too). The `drakvuf | 0` in the stat is the
submodule's `volatility3` on `pr-650`, where `make sandboxd` left it.

#### 6b-authenticode — who signed the eight files (Candidate)

The hash pins prove that a file is the one somebody looked at, not who
published it; for Chrome the look was two downloads agreeing (security
review of 2026-11-04, item 2). Windows can say who signed each file, and the
guest has them on its CD-ROM, the modified ISO. Once the desktop is up, in
PowerShell as Administrator:

```powershell
# WINDOWS GUEST, PowerShell as Administrator, the modified ISO still in the CD-ROM
$d = (Get-Volume -FileSystemLabel 'WIN11_SEABIOS').DriveLetter
Get-ChildItem "${d}:\installers\*" | Get-AuthenticodeSignature | Select-Object Status, @{n='Signer';e={$_.SignerCertificate.Subject}}, @{n='File';e={Split-Path $_.Path -Leaf}} | Format-Table -AutoSize
(Get-Item 'C:\Program Files\Google\Chrome\Application\chrome.exe').VersionInfo.ProductVersion
```

Expect `Valid` on all eight, with the vendor as signer: `Google LLC` for the
Chrome MSI, `Microsoft Corporation` for .NET 4.8, both .NET 8 runtimes and
the Office Deployment Tool, `Adobe Inc.` for Acrobat Reader, `Igor Pavlov`
for 7-Zip, `Python Software Foundation` for Python. The last line answers
the open detail of the re-pin: the file's `strings` read `157.0.8089.0`
while Google's API named stable `157.0.8103.39`, and the installed Chrome's
`ProductVersion` is the number that counts. **Anything but `Valid`, or a
signer that is not the vendor, means the file is not what the pin assumed:
do not publish it (6b-mirror) and do not keep the image.** The console is
VNC, so this evidence is transcribed or a screenshot; say which.

```
EVIDENCE 6b-authenticode
```

Attested by the operator on 2026-11-04 ("1 works": the PowerShell block ran
in the guest and passed), not pasted; the console is VNC. A transcription or
screenshot would turn this into pasted evidence. The derived table in
`CURRENT-STATE.md` §3 counts neither, and that is correct.

#### 6b-mirror — publish the verified installers (Candidate)

Runs after 6b-authenticode said who signed the files; it touches the platform
only. Needs the Makefile with the target and
`automation/win-installers-mirror.conf` on Dom0, so the commit carrying them
must be pulled there first (the push goes through the review gate as code).

> **Security review, 2026-11-04**, of the mirror before its push. Item 1:
> the `ssh` inside the publish loop had no `-n` and would have drained the
> loop's stdin, publishing Chrome alone and failing on the second file —
> fixed (`ssh -n`). Item 3: a TLS failure against the mirror was reported as
> "not on the mirror" and fell back to the vendor — fixed: wget's exit code
> decides, `5` (certificate) stops the run, `8` and `4` fall back and say
> why, and `--no-config` keeps a `wgetrc` from turning verification off.
> Item 2: the Chrome pin's publisher — 6b-authenticode above. Item 4: the
> SHA-256 digests of `tls/ca/ca.key` in EVIDENCE 4b — redacted. Checked
> outside the repository, read over ssh the same day: Dom0's `/etc/wgetrc`
> sets only `passive_ftp = on`, there is no `/root/.wgetrc`, wget is 1.21.4;
> the live `/etc/cloudflared/config.yml` routes `^/analysis(/|$)` to 9000
> and everything else on the hostname to 8000, so **9100 is not routed**;
> `/srv/vendor` does not exist yet; nginx is 1.26.3.

```bash
# DOM0 (Xen), as root. Publishes to the platform, installs the nginx listener, fetches every file back through it
cd /root/drakvuf-multios-sandbox && git log --oneline -1 && make win_installers_mirror 2>&1 | tee /root/make-win_installers_mirror-$(date +%Y%m%d-%H%M).log | tail -25
```

Expect eight `: OK`, eight `published`, `nginx: configuration file
/etc/nginx/nginx.conf test is successful`, and eight `served by the mirror,
hash verified`. Then the proof that the next Windows build would not touch a
vendor: move one cached file aside and fetch it again.

```bash
# DOM0 (Xen), as root. One file re-fetched from the mirror, then put back
cd /root/drakvuf-multios-sandbox && mv misc/iso/win-installers/7z2408-x64.exe /root/7z2408-x64.exe.aside && make win_installers 2>&1 | grep -E 'from the mirror|from the vendor|OK$|FAILED' ; cmp /root/7z2408-x64.exe.aside misc/iso/win-installers/7z2408-x64.exe && echo "same bytes" && rm /root/7z2408-x64.exe.aside; curl -sS --cacert /etc/sandboxd/tls/ca.crt -o /dev/null -w '%{http_code}\n' https://192.168.1.12:9100/win-installers/; curl -sS --cacert /etc/sandboxd/tls/ca.crt -o /dev/null -w '%{http_code}\n' https://192.168.1.12:9100/
```

Expect `7z2408-x64.exe: from the mirror`, eight `OK`, `same bytes`, and
`404` twice: no listing, nothing at the root.

```
EVIDENCE 6b-mirror                                                2026-11-04
root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && git checkout -- automation/win-installers.list && git pull --ff-only && git log --oneline -1 && git status --short
remote: Enumerating objects: 21, done.
remote: Counting objects: 100% (21/21), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 12 (delta 8), reused 12 (delta 8), pack-reused 0 (from 0)
Unpacking objects: 100% (12/12), 65.48 KiB | 1.31 MiB/s, done.
From https://github.com/evilbootloader/drakvuf-multios-sandbox
   2b433f4..08688b4  master     -> origin/master
Updating 2b433f4..08688b4
Fast-forward
 Makefile                              |   70 ++++-
 README.md                             |  269 +++++++++++++----
 automation/win-installers-mirror.conf |   51 ++++
 automation/win-installers.list        |   17 +-
 deploy-with-makefile.md               | 2312 ++++++++++++++++++++++++++++++++
 docs/CURRENT-STATE.md                 |   28 +-
 docs/INDEX.md                         |  169 +++++------
 docs/TROUBLESHOOTING.md               |  130 ++++++++
 8 files changed, 2889 insertions(+), 157 deletions(-)
 create mode 100644 automation/win-installers-mirror.conf
 create mode 100644 deploy-with-makefile.md
08688b4 (HEAD -> master, origin/master, origin/HEAD) Mirror the Windows installers on the platform; re-pin Chrome; park runbook 18
 m drakvuf
 M misc/xen-vms/ubuntu_sandbox.cfg
 M misc/xen-vms/windows.cfg
 M misc/xen-vms/windows_sandbox.cfg
?? wget-log
?? wget-log.1
?? wget-log.2
?? wget-log.3
root@dom0:~/drakvuf-multios-sandbox#  make win_installers_mirror
[... the two recipes, echoed by make ...]
/root/drakvuf-multios-sandbox/misc/iso/win-installers/googlechromestandaloneenterprise64.msi: OK
/root/drakvuf-multios-sandbox/misc/iso/win-installers/AcroRdrDCx642100720099_MUI.exe: OK
/root/drakvuf-multios-sandbox/misc/iso/win-installers/7z2408-x64.exe: OK
/root/drakvuf-multios-sandbox/misc/iso/win-installers/python-3.12.0-amd64.exe: OK
/root/drakvuf-multios-sandbox/misc/iso/win-installers/ndp48-x86-x64-allos-enu.exe: OK
/root/drakvuf-multios-sandbox/misc/iso/win-installers/dotnet-runtime-8.0-win-x64.exe: OK
/root/drakvuf-multios-sandbox/misc/iso/win-installers/dotnet-runtime-8.0-win-x86.exe: OK
/root/drakvuf-multios-sandbox/misc/iso/win-installers/officedeploymenttool_20228-20124.exe: OK
googlechromestandaloneenterprise64.msi: published
AcroRdrDCx642100720099_MUI.exe: published
7z2408-x64.exe: published
python-3.12.0-amd64.exe: published
ndp48-x86-x64-allos-enu.exe: published
dotnet-runtime-8.0-win-x64.exe: published
dotnet-runtime-8.0-win-x86.exe: published
officedeploymenttool_20228-20124.exe: published
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
googlechromestandaloneenterprise64.msi: served by the mirror, hash verified
AcroRdrDCx642100720099_MUI.exe: served by the mirror, hash verified
7z2408-x64.exe: served by the mirror, hash verified
python-3.12.0-amd64.exe: served by the mirror, hash verified
ndp48-x86-x64-allos-enu.exe: served by the mirror, hash verified
dotnet-runtime-8.0-win-x64.exe: served by the mirror, hash verified
dotnet-runtime-8.0-win-x86.exe: served by the mirror, hash verified
officedeploymenttool_20228-20124.exe: served by the mirror, hash verified
```

**The mirror is live**, published and proven on 2026-11-04 from the
commit's first pull: eight files re-checked, published, the listener
installed with nginx's test passing, eight fetched back through it with the
pinned hashes. It ran **before** 6b-authenticode, in the other order from
the one written above: if the guest-side check finds a file whose signature
is not `Valid` from its vendor, that file is removed from
`/srv/vendor/win-installers/` on the platform as well as from the image.
The one-file proof (`7z2408-x64.exe` moved aside) is still to run.

The four `wget-log*` files in the checkout are mine: the install command
of 6b piped `make` into `head -30`, which closed the pipe after thirty
lines, and wget, writing progress to a closed pipe, switched to its
`wget-log` fallback. They are noise, not evidence; the command keeps `head`
out from now on. Remove them:

```bash
# DOM0 (Xen), as root
cd /root/drakvuf-multios-sandbox && rm -f wget-log wget-log.[0-9]* && git status --short
```

`setup_hooks_windows` needs the domain **down**: it maps the volume, mounts
the Windows partition read-only to fetch every PDB-derived profile over TLS
into `profiles/`, unmaps, snapshots `windows` into `windows_sandbox`, writes
`windows_sandbox.cfg`, boots it, waits two minutes, finds `explorer.exe`'s
PID with `vmi-process-list` and records it in the env file.

```bash
# DOM0 (Xen), as root. The golden domain must NOT be running
xl list windows_analysis 2>/dev/null && echo "STOP: shut the guest down first" || { cd /root/drakvuf-multios-sandbox && make setup_hooks_windows 2>&1 | tee /root/make-setup_hooks_windows-$(date +%Y%m%d-%H%M).log | tail -25; }
```

Expect the profile script's one line per DLL, `lvcreate` of
`windows_sandbox`, `INJECTION_PID=<one number>`, and the two closing `echo`
lines with the save command. Exactly one number: zero or several stops the
target, and that is correct — an anchor PID is never guessed at.
Now **wait at least 20 minutes** with the domain running and untouched: the
saved state carries its uptime into every clone. Then, by hand, the command
the target printed:

```bash
# DOM0 (Xen), as root. After >= 20 minutes of uptime; destroys the domain as it saves it
cd /root/drakvuf-multios-sandbox && xl uptime windows_analysis_sandbox && xl save windows_analysis_sandbox state/windows_sandbox.bak misc/xen-vms/windows_sandbox.cfg && ls -la state/windows_sandbox.bak && grep SANDBOXD_INJECTION_PID_WINDOWS /etc/sandboxd/sandboxd.env | cut -d= -f1
```

Start `sandboxd` again (5b) and run **one Windows job**. It is the second
end-to-end Windows run ever and the first with a transcript; paste the
daemon's lines for it and the UI row, and note which plugins produced output.

```
EVIDENCE 6b-hooks                                                 2026-11-04
root@dom0:~/drakvuf-multios-sandbox# xl create misc/xen-vms/windows.cfg 
Parsing config from misc/xen-vms/windows.cfg
root@dom0:~/drakvuf-multios-sandbox# xl list
Name                                        ID   Mem VCPUs    State    Time(s)
Domain-0                                     0  8192     6     r-----    2198.1
platform                                     1  4096     4     -b----     152.4
root@dom0:~/drakvuf-multios-sandbox# xl list windows_analysis 2>/dev/null && echo "STOP: shut the guest down first" || { cd /root/drakvuf-multios-sandbox && make setup_hooks_windows 2>&1 | tee /root/make-setup_hooks_windows-$(date +%Y%m%d-%H%M).log | tail -25; }

| `kernel32.json` | `fdebece71ae5484d8f52bcfa608faa3c67f287a1baab28dea2ef251553331638` | 603395 | `kernel32.pdb` a651e6da598d55318b7fbe3a9aa66b081 |
| `kernelbase.json` | `a20890113b68dab174813094d103804c4c429e7d00ee76abf01bb2acfcdc1589` | 6474292 | `kernelbase.pdb` fd716fb42da11292354efd1727dba7751 |
| `kernel32wow.json` | `5e2d9a6efdc3afef3973eafdcc78ec0cc50561c34a65655bfd172eca0ecd4b03` | 918218 | `wkernel32.pdb` 6f8b32c9ba711005892405cb420b9ff81 |
| `ntdll.json` | `30b678d91e6c07e81158c75d110a566d5f097aa309b2a9e53b843229ae4d0327` | 1888554 | `ntdll.pdb` 158a782afae4e837a58b83204612935f1 |
| `iphlpapi.json` | `4c7f3f270c4b09906252946c20fc14a2400e3e19b9819ee6c2344a259f8b98a0` | 105866 | `iphlpapi.pdb` 029a4c798a7df515597e19696269acf11 |
| `ole32.json` | `38a81d80d3703a3d241c6cda4da2622560fc0d370cec22957ad017fbe3b3b7ef` | 8598517 | `ole32.pdb` 1954734c7516142c6be6ef3ede2b5edd1 |
| `clr.json` | `8800398e7db2f12c79e6c10fdafa38706347a278a931feffe741bcb03618b034` | 7338999 | `clr.pdb` cd3a60d2c15743e19d1b3fa75975b4ab3 |
| `mscorwks.json` | `67ecd1cad988f7ce55cf862537f93d96b93f0d6f9afad6e052847336317d16cb` | 9311612 | `mscorwks.pdb` 3fec42966262426db4f7b6d05f9711831 |
| `hal.json` | `7cb521b6e8d7bf30e933a0285ea43644af366ea39925b60f04a027ac28ae0965` | 483 | `hal.pdb` d94118e82a0b0f856dfaf2d544a1afe81 |
| `fwpkclnt.json` | `0bc5fb9979dfdcc12aba5dde48fc8171343810af131325db2a6e49a13fcf0e13` | 227835 | `fwpkclnt.pdb` d365d02e056b9b4201fb95c631afc0611 |
| `fltmgr.json` | `3b3d2b4d98266720cd1d6e5f3cfb22fc262201c59640e30378568f000f26e091` | 764626 | `fltMgr.pdb` 51a8be994a72880ed05e344baf51e04c1 |
| `ci.json` | `a4164f758ded40e9ace66d8a1fb37ff1632f9a330a0692115e5432555dd7f517` | 204910 | `ci.pdb` 61243e0e4335dd435f66b5b5465fae201 |
| `netio.json` | `d3456a22b11a0609b0e458b3b00211d14be72e31131b5a098dace455f3bfe458` | 231474 | `netio.pdb` 856c165442882498f31ce9049ab60fd21 |
| `ndis.json` | `1e6f3e15d1748a046dccdaec90fb600f59a7b1a8502e8d7bb8ad836d56ab6c48` | 2926056 | `ndis.pdb` 5b1895cd6aa48156dd0be888f5e0a1911 |
| `services.json` | `03335e1858dd3480484afdd0df134659aa49930635083129503a4e7449557998` | 482500 | `services.pdb` 4dc9525884803948178db21e987405f01 |
  WARNING: Sum of all thin volume sizes (5.62 TiB) exceeds the size of thin pool vg-root/thinpool and the size of whole volume group (<1.82 TiB).
  Consider pruning vg-root VG archive with more then 120 MiB in 15006 files (check archiving is needed in lvm.conf).
  Consider pruning vg-root VG archive with more then 120 MiB in 15007 files (check archiving is needed in lvm.conf).
  Logical volume "windows_sandbox" created.
Wrote /root/drakvuf-multios-sandbox/state/firmware/smbios.bin and /root/drakvuf-multios-sandbox/state/firmware/ssdt.aml
Parsing config from /root/drakvuf-multios-sandbox/misc/xen-vms/windows_sandbox.cfg
INJECTION_PID=4724
windows_analysis_sandbox is running with INJECTION_PID=4724 recorded.
Leave it running for AT LEAST 20 MINUTES before saving: every clone restores with this uptime, and a two-minute uptime is a sandbox tell samples check. Do not restart the guest. Then, by hand:
  xl save windows_analysis_sandbox /root/drakvuf-multios-sandbox/state/windows_sandbox.bak /root/drakvuf-multios-sandbox/misc/xen-vms/windows_sandbox.cfg
root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && xl uptime windows_analysis_sandbox && xl save windows_analysis_sandbox state/windows_sandbox.bak misc/xen-vms/windows_sandbox.cfg && ls -la state/windows_sandbox.bak && grep SANDBOXD_INJECTION_PID_WINDOWS /etc/sandboxd/sandboxd.env | cut -d= -f1
Name                                ID Uptime
windows_analysis_sandbox            10  0:20:36
Saving to state/windows_sandbox.bak new xl format (info 0x3/0x0/4248)
xc: info: Saving domain 10, type x86 HVM
xc: Frames: 2162816/2162816  100%
xc: End of stream: 0/0    0%
-rw-r--r-- 1 root root 8607815072 Nov  4 15:25 state/windows_sandbox.bak
#SANDBOXD_INJECTION_PID_WINDOWS
SANDBOXD_INJECTION_PID_WINDOWS
root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && mkdir -p /var/log/sandboxd && set -a && . /etc/sandboxd/sandboxd.env && set +a && .venv-sandboxd/bin/python -m sandboxd.daemon 2>&1 | tee -a /var/log/sandboxd/$(date +%Y%m%d-%H%M).log
2026-11-04 15:25:53,949 INFO    sandboxd: host values: SANDBOXD_REPO_ROOT=/root/drakvuf-multios-sandbox, SANDBOXD_ANALYSIS_USERNAME=carlos, SANDBOXD_INJECTION_PID_UBUNTU=1, SANDBOXD_INJECTION_PID_WINDOWS=4724, SANDBOXD_INJECTION_PID_ANDROID=<default>
2026-11-04 15:25:53,949 INFO    sandboxd: provisioning the analysis network for 1 clone slot(s)
2026-11-04 15:25:54,090 INFO    sandboxd: egress exits offered: offline (offline), tor-default (tor), sim-local (simulated)
2026-11-04 15:25:54,203 INFO    sandboxd: sweep: nothing to reclaim, Dom0 was already clean
2026-11-04 15:25:54,208 INFO    sandboxd: RDTSC compensation is on (RDTSC_POC: compensation enabled)
2026-11-04 15:25:54,208 INFO    sandboxd: capacity: 1 vlan(s) usable, 18317 MiB, 1 slot(s)
2026-11-04 15:25:54,221 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/register "HTTP/1.1 204 No Content"
2026-11-04 15:25:54,223 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/reconcile "HTTP/1.1 200 OK"
2026-11-04 15:26:14,271 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/claim "HTTP/1.1 200 OK"
2026-11-04 15:26:30,315 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/claim "HTTP/1.1 200 OK"
2026-11-04 15:26:30,321 INFO    httpx: HTTP Request: GET https://192.168.1.12:9000/analysis/u/ecf3da57-8c29-4fa1-a910-bb6ae4b8372e/438/samples/438fb6f9-8828-4ed2-9076-dd84794608be/31a444b389a43bff77feb8e14c1d776490b998327f4b41aa5d47edccf2557826.exe?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=REDACTED&X-Amz-Date=20261104T152629Z&X-Amz-Expires=120&X-Amz-SignedHeaders=host&X-Amz-Signature=REDACTED "HTTP/1.1 200 OK"
2026-11-04 15:26:37,243 INFO    sandboxd.stages: job 438fb6f9-8828-4ed2-9076-dd84794608be: egress tor via no interface (nothing is forwarded)
2026-11-04 15:26:37,254 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/438fb6f9-8828-4ed2-9076-dd84794608be/state "HTTP/1.1 204 No Content"
2026-11-04 15:26:37,256 INFO    sandboxd.vnc: console dialled out for job 438fb6f9-8828-4ed2-9076-dd84794608be
2026-11-04 15:26:37,256 INFO    sandboxd.vnc: console bridged to 127.0.0.1:5900
2026-11-04 15:26:37,356 INFO    sandboxd.vnc: viewer left the console for 127.0.0.1:5900; waiting for another
2026-11-04 15:26:37,443 INFO    sandboxd.vnc: console bridged to 127.0.0.1:5900
2026-11-04 15:26:37,723 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/438fb6f9-8828-4ed2-9076-dd84794608be/state "HTTP/1.1 204 No Content"
2026-11-04 15:26:37,866 INFO    sandboxd.vnc: viewer left the console for 127.0.0.1:5900; waiting for another
2026-11-04 15:26:37,941 INFO    sandboxd.vnc: console bridged to 127.0.0.1:5900
2026-11-04 15:26:50,336 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/438fb6f9-8828-4ed2-9076-dd84794608be/heartbeat "HTTP/1.1 200 OK"
[... five more heartbeats, 20 s apart ...]
2026-11-04 15:28:43,827 INFO    sandboxd.vnc: console session for 127.0.0.1:5900 ended
2026-11-04 15:28:46,298 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/438fb6f9-8828-4ed2-9076-dd84794608be/state "HTTP/1.1 204 No Content"
2026-11-04 15:28:50,448 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/438fb6f9-8828-4ed2-9076-dd84794608be/heartbeat "HTTP/1.1 200 OK"
2026-11-04 15:29:04,914 INFO    sandboxd.postprocessing: postprocessing of 438fb6f9-8828-4ed2-9076-dd84794608be: peak RSS 144 MiB of the 3072 MiB limit
2026-11-04 15:29:04,914 INFO    sandboxd.postprocessing: postprocessing of 438fb6f9-8828-4ed2-9076-dd84794608be:
…ing.plugins.process_extracted: extracted file file.000021.mm has no fileextractor record; kept unattributed
[... the same WARNING for file.000022.mm to file.000035.mm, fourteen more lines ...]
2026-11-04 15:29:02,732 WARNING sandboxd.postprocessing.postprocess: compress_ipt won't be run because ipt does not exist
2026-11-04 15:29:02,840 WARNING sandboxd.postprocessing.postprocess: get_falco_info won't be run because falco.json does not exist
2026-11-04 15:29:04,760 WARNING sandboxd.postprocessing.indexer: cpuidmon.log: 284 events from 3 PIDs absent from the process tree were not indexed (PIDs: 1648, 4184, 6900)
2026-11-04 15:29:04,864 ERROR sandboxd.postprocessing.indexer: Failed to process entry in preconfig.log
Traceback (most recent call last):
  File "/root/drakvuf-multios-sandbox/sandboxd/postprocessing/indexer.py", line 34, in index_log_file
    entry = orjson.loads(entry_data)
            ^^^^^^^^^^^^^^^^^^^^^^^^
orjson.JSONDecodeError: unexpected character, expected a JSON value: line 1 column 1 (char 0)
[... the same ERROR twice more, columns 2 and 1 ...]
2026-11-04 15:29:04,968 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/438fb6f9-8828-4ed2-9076-dd84794608be/artifacts "HTTP/1.1 200 OK"
2026-11-04 15:29:04,982 INFO    httpx: HTTP Request: POST https://192.168.1.12:9000/analysis "HTTP/1.1 204 No Content"
[... about ninety more artifact POSTs to /analysis, all 204, and a second /artifacts 200 ...]
2026-11-04 15:29:05,532 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/438fb6f9-8828-4ed2-9076-dd84794608be/state "HTTP/1.1 204 No Content"
2026-11-04 15:29:05,542 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/438fb6f9-8828-4ed2-9076-dd84794608be/complete "HTTP/1.1 204 No Content"
2026-11-04 15:29:05,550 INFO    sandboxd: job 438fb6f9-8828-4ed2-9076-dd84794608be -> completed (clean)
```

Elided on purpose, and said so where: the presigned URL's credential and
signature (REDACTED), five heartbeats, fourteen identical `.mm` warnings,
two identical tracebacks, about ninety identical artifact uploads. The
operator booted the golden image once more by hand (`xl create
misc/xen-vms/windows.cfg`, what `modify_windows` does) for the PowerShell
check and shut it down from inside before `setup_hooks_windows` ran.

**Windows is evidenced end to end with a transcript, 2026-11-04**, the first
time: job `438fb6f9`, a sample `.exe`, claimed 15:26:30, traced with the
console bridged, `completed (clean)` 15:29:05, artifacts uploaded, on the
image rebuilt that day with the identity, anchor `explorer.exe` 4724, the
state saved after 20:36 of uptime (8.6 GB), under `make xen`'s Xen with the
compensation on and DRAKVUF `3c3b73a6`. `setup_hooks_windows` fetched the
DLL profiles over TLS, wrote the firmware files from the identity and found
`explorer.exe` exactly once. The env file holds the commented example
`#SANDBOXD_INJECTION_PID_WINDOWS` from the template and the real line: both
`grep` hits are expected.

> **FINDING (2026-11-04), shared, pre-existing.** Postprocessing logs
> `Failed to process entry in preconfig.log` with a `JSONDecodeError` three
> times per job, at ERROR, and the job completes. The indexer parses every
> `*.log` in the results directory as JSON lines (`indexer.py:89`,
> `analysis_dir.glob("*.log")`), and `preconfig.log` is the preconfig
> stage's plain-text output (`stages.py`, `PRECONFIG_LOG`). The Ubuntu job of
> §5b logged the same three. Candidate fix: skip `preconfig.log` in the
> indexer's glob. Not touched here: shared code, the Ubuntu path.
> **Observation, Windows only**: fifteen extracted files `file.000021.mm` to
> `file.000035.mm` had no fileextractor record and were kept unattributed,
> the path `process_extracted.py` handles by design; and `cpuidmon` events
> from three PIDs absent from the process tree (processes older than the
> trace) were not indexed. Neither is a failure; both are what "no
> per-plugin validation" in `CURRENT-STATE.md` §1.5 means in practice, and
> the first per-plugin look at a Windows job's artifacts is still to be done.

## 6c. Ubuntu

Same shape. `sandboxd` down first. The autoinstall powers the guest off when
it finishes (`shutdown: poweroff`), so there is no console step but watching.
`ubuntu_analysis_vm` writes `misc/iso/cidata/user-data` with the password's
hash and the key, builds `seed.iso`, verifies the server ISO against the
signed checksum, takes its kernel and initrd, writes `ubuntu.cfg` and boots
the installer; its final `sed` strips the installer lines from the cfg.

> **Watch the vCPU count.** The cfg the target writes says `vcpus = 4`. The
> trace's injection anchors on PID 1 and has failed on a 3-vCPU guest when
> another `systemd` reached the breakpoint first
> ([TROUBLESHOOTING](docs/TROUBLESHOOTING.md#the-traces-injection-fails-with-could-not-create-argv-arrays)).
> If the first jobs after this rebuild fail that way, that entry is the cause
> to check, and the saved state's `vcpus` is not a knob you can turn without
> saving again.

```bash
# DOM0 (Xen), as root. DESTROYS the Ubuntu golden image and its sandbox snapshot
B=/srv/drakvuf-out/backup-$(date +%Y%m%d); mkdir -p $B; xl destroy ubuntu_analysis 2>/dev/null; xl destroy ubuntu_analysis_sandbox 2>/dev/null; lvremove -y vg-root/ubuntu_sandbox vg-root/ubuntu && mv /root/drakvuf-multios-sandbox/state/ubuntu_sandbox.bak $B/ubuntu_sandbox.bak.removed; lvs --noheadings -o lv_name vg-root | tr -d ' ' | grep -cxE 'ubuntu|ubuntu_sandbox'
```

Expect `0`. The exact-match `grep -x` is deliberate: `ubuntu-lv` is Dom0's
root, and a pattern that merely starts with `ubuntu` would count it.

```bash
# DOM0 (Xen), as root
cd /root/drakvuf-multios-sandbox && make ubuntu_analysis_vm 2>&1 | tee /root/make-ubuntu_analysis_vm-$(date +%Y%m%d-%H%M).log | tail -25; xl list; grep -cE '^(kernel|ramdisk|extra)' misc/xen-vms/ubuntu.cfg; git status --short misc/
```

Expect `ubuntu-22.04.5-live-server-amd64.iso: OK`, `lvcreate`, the domain in
`xl list`, and **`0`** installer lines left in the cfg. Watch the install over
VNC until the domain disappears from `xl list` (it powered itself off). Boot
it once with `make modify_ubuntu` to check the desktop logs in as
`ANALYSIS_VM_USER`, and shut it down from inside.

```
EVIDENCE 6c-install                                               2026-11-04
root@dom0:~/drakvuf-multios-sandbox# B=/srv/drakvuf-out/backup-$(date +%Y%m%d); mkdir -p $B; xl destroy ubuntu_analysis 2>/dev/null; xl destroy ubuntu_analysis_sandbox 2>/dev/null; lvremove -y vg-root/ubuntu_sandbox vg-root/ubuntu && mv /root/drakvuf-multios-sandbox/state/ubuntu_sandbox.bak $B/ubuntu_sandbox.bak.removed; lvs --noheadings -o lv_name vg-root | tr -d ' ' | grep -cxE 'ubuntu|ubuntu_sandbox'
  Consider pruning vg-root VG archive with more then 120 MiB in 15018 files (check archiving is needed in lvm.conf).
  Consider pruning vg-root VG archive with more then 120 MiB in 15019 files (check archiving is needed in lvm.conf).
  Logical volume "ubuntu" successfully removed.
  Failed to find logical volume "vg-root/ubuntu_sandbox"
0
root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && make ubuntu_analysis_vm 2>&1 | tee /root/make-ubuntu_analysis_vm-$(date +%Y%m%d-%H%M).log | tail -25; xl list; grep -cE '^(kernel|ramdisk|extra)' misc/xen-vms/ubuntu.cfg; git status --short misc/
Installing ubuntu analysis VM

WARNING: apt does not have a stable CLI interface. Use with caution in scripts.

Reading package lists...
Building dependency tree...
Reading state information...
cloud-image-utils is already the newest version (0.33-1).
wget is already the newest version (1.21.4-1ubuntu4.5).
0 upgraded, 0 newly installed, 0 to remove and 11 not upgraded.
/root/drakvuf-multios-sandbox/misc/iso/ubuntu-22.04.5-live-server-amd64.iso: OK
mount: /mnt: WARNING: source write-protected, mounted read-only.
Wrote /root/drakvuf-multios-sandbox/state/firmware/smbios.bin and /root/drakvuf-multios-sandbox/state/firmware/ssdt.aml
  WARNING: Sum of all thin volume sizes (4.62 TiB) exceeds the size of thin pool vg-root/thinpool and the size of whole volume group (<1.82 TiB).
  Consider pruning vg-root VG archive with more then 120 MiB in 15020 files (check archiving is needed in lvm.conf).
  Consider pruning vg-root VG archive with more then 120 MiB in 15021 files (check archiving is needed in lvm.conf).
  Logical volume "ubuntu" created.
Parsing config from /root/drakvuf-multios-sandbox/misc/xen-vms/ubuntu.cfg
Name                                        ID   Mem VCPUs    State    Time(s)
Domain-0                                     0  8192     6     r-----    2748.0
platform                                     1  4096     4     -b----     196.4
ubuntu_analysis                             13  8192     1     ------       0.0
0
 M misc/xen-vms/ubuntu.cfg
 M misc/xen-vms/ubuntu_sandbox.cfg
 M misc/xen-vms/windows.cfg
 M misc/xen-vms/windows_sandbox.cfg
```

`ubuntu_sandbox` was already gone when the removal ran (the `Failed to
find`), so `lvremove` exited non-zero and the `&& mv` of the old `.bak` did
not run; the copy 6a made at `/srv/drakvuf-out/backup-20261104/state/` is
the old state's keeper, and the `xl save` below overwrites the file. The
install: ISO verified against the signed checksum, the identity's firmware
written, the 1 T volume created, the installer booted with the cfg's
`kernel`/`ramdisk`/`extra` lines stripped again (`0`). The autoinstall
powered the guest off by itself before the hooks ran.

`setup_hooks_ubuntu` maps the volume, activates the guest's `ubuntu-vg`,
mounts root and `/boot` **read-only with `noload`** under a trap that detaches
everything on exit, builds `dwarf2json` and writes `profiles/linux.json` from
the debug kernel the autoinstall installed, detaches, snapshots, writes
`ubuntu_sandbox.cfg`, boots it and records PID 1.

```bash
# DOM0 (Xen), as root. The golden domain must NOT be running
xl list ubuntu_analysis 2>/dev/null && echo "STOP: shut the guest down first" || { cd /root/drakvuf-multios-sandbox && make setup_hooks_ubuntu 2>&1 | tee /root/make-setup_hooks_ubuntu-$(date +%Y%m%d-%H%M).log | tail -25; ls -la profiles/linux.json; vgs --noheadings -o vg_name | grep -c ubuntu-vg; dmsetup ls | grep -cE 'vg--root-ubuntu[0-9]|ubuntu--vg'; }
```

Expect `go build` silent, a `linux.json` of tens of MB, **`0` and `0`**: the
guest's `ubuntu-vg` no longer visible to Dom0 and none of the `kpartx`
partition mappings (`vg--root-ubuntu1..3`) or the guest's LV left (the trap's
job), the domain running and the two closing `echo` lines. The golden LV's
own mapping, `vg--root-ubuntu`, is supposed to stay and is not matched.
**A Makefile before 2026-11-04's fix ends with `Error 32` after all of that**,
from its own EXIT trap, and the run is still good if the two closing lines
printed — do not re-run it
([TROUBLESHOOTING](docs/TROUBLESHOOTING.md#make-setup_hooks_ubuntu-ends-with-error-32-after-every-step-succeeded)). Then the same 20 minutes and
the printed save:

```bash
# DOM0 (Xen), as root. After >= 20 minutes of uptime
cd /root/drakvuf-multios-sandbox && xl uptime ubuntu_analysis_sandbox && xl save ubuntu_analysis_sandbox state/ubuntu_sandbox.bak misc/xen-vms/ubuntu_sandbox.cfg && ls -la state/ubuntu_sandbox.bak
```

Start `sandboxd` (5b) and run one Ubuntu job: the evidenced path, on the
rebuilt image, is the last thing this part has to show.

```
EVIDENCE 6c-hooks, the hooks                                      2026-11-04
root@dom0:~/drakvuf-multios-sandbox# xl list ubuntu_analysis 2>/dev/null && echo "STOP: shut the guest down first" || { cd /root/drakvuf-multios-sandbox && make setup_hooks_ubuntu 2>&1 | tee /root/make-setup_hooks_ubuntu-$(date +%Y%m%d-%H%M).log | tail -25; ls -la profiles/linux.json; vgs --noheadings -o vg_name | grep -c ubuntu-vg; dmsetup ls | grep -cE 'vg--root-ubuntu[0-9]|ubuntu--vg'; }
[... the recipe's last lines, echoed by make ...]
  1 logical volume(s) in volume group "ubuntu-vg" now active
  0 logical volume(s) in volume group "ubuntu-vg" now active
  WARNING: Sum of all thin volume sizes (5.62 TiB) exceeds the size of thin pool vg-root/thinpool and the size of whole volume group (<1.82 TiB).
  Consider pruning vg-root VG archive with more then 120 MiB in 15022 files (check archiving is needed in lvm.conf).
  Consider pruning vg-root VG archive with more then 120 MiB in 15023 files (check archiving is needed in lvm.conf).
  Logical volume "ubuntu_sandbox" created.
Wrote /root/drakvuf-multios-sandbox/state/firmware/smbios.bin and /root/drakvuf-multios-sandbox/state/firmware/ssdt.aml
Parsing config from /root/drakvuf-multios-sandbox/misc/xen-vms/ubuntu_sandbox.cfg
ubuntu_analysis_sandbox is running.
Leave it running for AT LEAST 20 MINUTES before saving: every clone restores with this uptime, and a two-minute uptime is a sandbox tell samples check. Then, by hand:
  xl save ubuntu_analysis_sandbox /root/drakvuf-multios-sandbox/state/ubuntu_sandbox.bak /root/drakvuf-multios-sandbox/misc/xen-vms/ubuntu_sandbox.cfg
make: *** [Makefile:878: setup_hooks_ubuntu] Error 32
-rw-r--r-- 1 root root 45387399 Nov  4 16:05 profiles/linux.json
0
0
root@dom0:~/drakvuf-multios-sandbox# xl list
Name                                        ID   Mem VCPUs    State    Time(s)
Domain-0                                     0  8192     6     r-----    3315.7
platform                                     1  4096     4     -b----     220.6
ubuntu_analysis_sandbox                     14  8176     4     -b----      17.1
root@dom0:~/drakvuf-multios-sandbox# xl destroy ubuntu_analysis_sandbox
root@dom0:~/drakvuf-multios-sandbox# [the same command again]
[... the recipe's last lines ...]
  1 logical volume(s) in volume group "ubuntu-vg" now active
  0 logical volume(s) in volume group "ubuntu-vg" now active
  Logical Volume "ubuntu_sandbox" already exists in volume group "vg-root"
make: *** [Makefile:878: setup_hooks_ubuntu] Error 32
-rw-r--r-- 1 root root 45387399 Nov  4 16:06 profiles/linux.json
0
0
root@dom0:~/drakvuf-multios-sandbox# lvremove /dev/vg-root/ubuntu_sandbox 
Do you really want to remove active logical volume vg-root/ubuntu_sandbox? [y/n]: y
  Consider pruning vg-root VG archive with more then 120 MiB in 15024 files (check archiving is needed in lvm.conf).
  Consider pruning vg-root VG archive with more then 120 MiB in 15025 files (check archiving is needed in lvm.conf).
  Logical volume "ubuntu_sandbox" successfully removed.
root@dom0:~/drakvuf-multios-sandbox# [the same command a third time]
[... the recipe's last lines ...]
  1 logical volume(s) in volume group "ubuntu-vg" now active
  0 logical volume(s) in volume group "ubuntu-vg" now active
  WARNING: Sum of all thin volume sizes (5.62 TiB) exceeds the size of thin pool vg-root/thinpool and the size of whole volume group (<1.82 TiB).
  Consider pruning vg-root VG archive with more then 120 MiB in 15026 files (check archiving is needed in lvm.conf).
  Consider pruning vg-root VG archive with more then 120 MiB in 15027 files (check archiving is needed in lvm.conf).
  Logical volume "ubuntu_sandbox" created.
Wrote /root/drakvuf-multios-sandbox/state/firmware/smbios.bin and /root/drakvuf-multios-sandbox/state/firmware/ssdt.aml
Parsing config from /root/drakvuf-multios-sandbox/misc/xen-vms/ubuntu_sandbox.cfg
ubuntu_analysis_sandbox is running.
Leave it running for AT LEAST 20 MINUTES before saving: every clone restores with this uptime, and a two-minute uptime is a sandbox tell samples check. Then, by hand:
  xl save ubuntu_analysis_sandbox /root/drakvuf-multios-sandbox/state/ubuntu_sandbox.bak /root/drakvuf-multios-sandbox/misc/xen-vms/ubuntu_sandbox.cfg
make: *** [Makefile:878: setup_hooks_ubuntu] Error 32
-rw-r--r-- 1 root root 45387399 Nov  4 16:06 profiles/linux.json
```

**The first run had already done everything**; the `Error 32` after its
closing lines is the trap bug (the FINDING below), and reading it as a
failure cost two more runs: the second stopped at `lvcreate` because the
snapshot existed, the third, after an `lvremove` by hand, made a new snapshot
and a new domain. Read over ssh right after: `ubuntu_analysis_sandbox` is
domain 15, up since 16:06; the env file has `SANDBOXD_INJECTION_PID_UBUNTU=1`
and `..._WINDOWS=4724`; the template carries its five identity lines,
8192 MiB, 4 vCPUs, `shadow_memory = 128`, VNC on loopback; `vgs` shows
`vg-root` only, no `kpartx` mapping and nothing mounted at `/mnt` — the trap
did its work on every exit, which is why the false code was the only harm.
**The twenty minutes count from 16:06.**

> **FINDING (2026-11-04).** `setup_hooks_ubuntu`'s EXIT trap runs under the
> recipe's `set -e`; on a run that had already unmounted everything the
> trap's first `umount` exits 32 and ends the trap, and 32 becomes the
> target's exit code — on success and on failure alike, so the code tells
> nothing. Fixed in the Makefile the same day (`set +e` first in the trap);
> [TROUBLESHOOTING](docs/TROUBLESHOOTING.md#make-setup_hooks_ubuntu-ends-with-error-32-after-every-step-succeeded).
> `setup_hooks_windows` has no trap and was not affected. The removal block
> of this step also has a small flaw: `lvremove a b && mv` skips the `mv`
> when one of the two volumes is already gone, as it was here; harmless
> because 6a keeps a copy and the save overwrites the file.

```
EVIDENCE 6c-hooks, the re-run, the save and the job               2026-11-04
root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && git pull --ff-only && git log --oneline -1 && git status --short
[... fast-forward 20fed35..8b3f9f4, Makefile 7+/1- ...]
8b3f9f4 (HEAD -> master, origin/master, origin/HEAD) setup_hooks_ubuntu: let the EXIT trap finish, so make reports the recipe's status
 m drakvuf
 M misc/xen-vms/ubuntu.cfg
 M misc/xen-vms/ubuntu_sandbox.cfg
 M misc/xen-vms/windows.cfg
 M misc/xen-vms/windows_sandbox.cfg
root@dom0:~/drakvuf-multios-sandbox# xl list ubuntu_analysis 2>/dev/null && echo "STOP: shut the guest down first" || { cd /root/drakvuf-multios-sandbox && make setup_hooks_ubuntu 2>&1 | tee /root/make-setup_hooks_ubuntu-$(date +%Y%m%d-%H%M).log | tail -12; echo "make exit ${PIPESTATUS[0]}"; ls -la profiles/linux.json; vgs --noheadings -o vg_name | grep -c ubuntu-vg; dmsetup ls | grep -cE 'vg--root-ubuntu[0-9]|ubuntu--vg'; xl uptime ubuntu_analysis_sandbox; }
  1 logical volume(s) in volume group "ubuntu-vg" now active
  0 logical volume(s) in volume group "ubuntu-vg" now active
  WARNING: Sum of all thin volume sizes (5.62 TiB) exceeds the size of thin pool vg-root/thinpool and the size of whole volume group (<1.82 TiB).
  Consider pruning vg-root VG archive with more then 120 MiB in 15030 files (check archiving is needed in lvm.conf).
  Consider pruning vg-root VG archive with more then 120 MiB in 15031 files (check archiving is needed in lvm.conf).
  Logical volume "ubuntu_sandbox" created.
Wrote /root/drakvuf-multios-sandbox/state/firmware/smbios.bin and /root/drakvuf-multios-sandbox/state/firmware/ssdt.aml
Parsing config from /root/drakvuf-multios-sandbox/misc/xen-vms/ubuntu_sandbox.cfg
ubuntu_analysis_sandbox is running.
Leave it running for AT LEAST 20 MINUTES before saving: every clone restores with this uptime, and a two-minute uptime is a sandbox tell samples check. Then, by hand:
  xl save ubuntu_analysis_sandbox /root/drakvuf-multios-sandbox/state/ubuntu_sandbox.bak /root/drakvuf-multios-sandbox/misc/xen-vms/ubuntu_sandbox.cfg
failed to stat() /dev/mapper/vg--root-ubuntu3
make exit 0
-rw-r--r-- 1 root root 45387399 Nov  4 16:18 profiles/linux.json
0
0
Name                                ID Uptime
ubuntu_analysis_sandbox             17  0:00:00
root@dom0:~/drakvuf-multios-sandbox# date
Wed Nov  4 16:34:13 UTC 2026
root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && xl uptime ubuntu_analysis_sandbox && xl save ubuntu_analysis_sandbox state/ubuntu_sandbox.bak misc/xen-vms/ubuntu_sandbox.cfg && ls -la state/ubuntu_sandbox.bak && xl list
Name                                ID Uptime
ubuntu_analysis_sandbox             17  0:22:33
Saving to state/ubuntu_sandbox.bak new xl format (info 0x3/0x0/4246)
xc: info: Saving domain 17, type x86 HVM
xc: Frames: 2162816/2162816  100%
xc: End of stream: 0/0    0%
-rw-r--r-- 1 root root 8591041214 Nov  4 16:40 state/ubuntu_sandbox.bak
Name                                        ID   Mem VCPUs    State    Time(s)
Domain-0                                     0  8192     6     r-----    3574.7
platform                                     1  4096     4     -b----     269.1
root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox && set -a && . /etc/sandboxd/sandboxd.env && set +a && .venv-sandboxd/bin/python -m sandboxd.daemon 2>&1 | tee -a /var/log/sandboxd/$(date +%Y%m%d-%H%M).log
2026-11-04 16:41:06,151 INFO    sandboxd: host values: SANDBOXD_REPO_ROOT=/root/drakvuf-multios-sandbox, SANDBOXD_ANALYSIS_USERNAME=carlos, SANDBOXD_INJECTION_PID_UBUNTU=1, SANDBOXD_INJECTION_PID_WINDOWS=4724, SANDBOXD_INJECTION_PID_ANDROID=<default>
2026-11-04 16:41:06,151 INFO    sandboxd: provisioning the analysis network for 1 clone slot(s)
2026-11-04 16:41:06,274 INFO    sandboxd: egress exits offered: offline (offline), tor-default (tor), sim-local (simulated)
2026-11-04 16:41:06,390 INFO    sandboxd: sweep: nothing to reclaim, Dom0 was already clean
2026-11-04 16:41:06,395 INFO    sandboxd: RDTSC compensation is on (RDTSC_POC: compensation enabled)
2026-11-04 16:41:06,395 INFO    sandboxd: capacity: 1 vlan(s) usable, 18317 MiB, 1 slot(s)
2026-11-04 16:41:06,407 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/register "HTTP/1.1 204 No Content"
2026-11-04 16:41:06,409 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/reconcile "HTTP/1.1 200 OK"
2026-11-04 16:41:18,455 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/claim "HTTP/1.1 200 OK"
2026-11-04 16:41:18,461 INFO    httpx: HTTP Request: GET https://192.168.1.12:9000/analysis/u/ecf3da57-8c29-4fa1-a910-bb6ae4b8372e/98e/samples/98e60edf-932a-4cc5-bfea-35e75c4c87fc/57ebdc5425c44579c7a0b4bbdca3cbe75682d4990c52890406794369d5a8f0c7.sh?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=REDACTED&X-Amz-Date=20261104T164117Z&X-Amz-Expires=120&X-Amz-SignedHeaders=host&X-Amz-Signature=REDACTED "HTTP/1.1 200 OK"
2026-11-04 16:41:25,239 INFO    sandboxd.stages: job 98e60edf-932a-4cc5-bfea-35e75c4c87fc: egress tor via no interface (nothing is forwarded)
2026-11-04 16:41:25,245 INFO    sandboxd.vnc: console dialled out for job 98e60edf-932a-4cc5-bfea-35e75c4c87fc
2026-11-04 16:41:25,246 INFO    sandboxd.vnc: console bridged to 127.0.0.1:5900
[... state changes, the console re-bridged twice, three heartbeats ...]
2026-11-04 16:43:34,637 INFO    sandboxd.vnc: console session for 127.0.0.1:5900 ended
2026-11-04 16:43:37,095 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/98e60edf-932a-4cc5-bfea-35e75c4c87fc/state "HTTP/1.1 204 No Content"
2026-11-04 16:43:59,108 INFO    sandboxd.postprocessing: postprocessing of 98e60edf-932a-4cc5-bfea-35e75c4c87fc: peak RSS 150 MiB of the 3072 MiB limit
2026-11-04 16:43:39,668 ERROR sandboxd.postprocessing.plugins.parse_utils: Failed to parse line 137 of /var/lib/sandboxd/results/98e60edf-932a-4cc5-bfea-35e75c4c87fc/memdump.log
Traceback (most recent call last):
  File "/root/drakvuf-multios-sandbox/sandboxd/postprocessing/plugins/parse_utils.py", line 20, in parse_log
    if result := filter_cb(data):
                 ^^^^^^^^^^^^^^^
  File "/root/drakvuf-multios-sandbox/sandboxd/postprocessing/plugins/process_dumps.py", line 31, in parse_memdump
    "index": data["DumpsCount"],
             ~~~~^^^^^^^^^^^^^^
KeyError: 'DumpsCount'
[... the same for lines 138 and 139 ...]
2026-11-04 16:43:39,668 INFO sandboxd.postprocessing.plugins.process_dumps: Filtered out 0 dumps.
2026-11-04 16:43:55,971 WARNING sandboxd.postprocessing.postprocess: compress_ipt won't be run because ipt does not exist
2026-11-04 16:43:56,511 INFO sandboxd.postprocessing.plugins.falco_analysis: falco: 2965 events, 1 alerts, 60 rules active, 0.5s
2026-11-04 16:43:56,657 WARNING sandboxd.postprocessing.postprocess: get_registry_info won't be run because regmon.log does not exist
2026-11-04 16:43:59,066 WARNING sandboxd.postprocessing.indexer: cpuidmon.log: 9046 events from 136 PIDs absent from the process tree were not indexed (PIDs: 1861, 1866, 1867, 1868, 1869, 1870, 1871, 1872, 1873, 1874, 1875, 1877, 1878, 1879, 1880, 1881, 1882, 1883, 1884, 1885)
2026-11-04 16:43:59,066 ERROR sandboxd.postprocessing.indexer: Failed to process entry in preconfig.log
[... the JSONDecodeError traceback, three times, as on every job ...]
2026-11-04 16:43:59,071 WARNING sandboxd.postprocessing.indexer: procmon.log: 14 events from 11 PIDs absent from the process tree were not indexed (PIDs: 1839, 1877, 1878, 1882, 1886, 1889, 1898, 1914, 1924, 1931, 1986)
2026-11-04 16:43:59,173 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/98e60edf-932a-4cc5-bfea-35e75c4c87fc/artifacts "HTTP/1.1 200 OK"
[... about a hundred artifact POSTs to /analysis, all 204, a heartbeat and a second /artifacts 200 among them ...]
2026-11-04 16:43:59,775 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/98e60edf-932a-4cc5-bfea-35e75c4c87fc/state "HTTP/1.1 204 No Content"
2026-11-04 16:43:59,784 INFO    httpx: HTTP Request: POST https://192.168.1.12:8000/api/v1/worker/jobs/98e60edf-932a-4cc5-bfea-35e75c4c87fc/complete "HTTP/1.1 204 No Content"
2026-11-04 16:43:59,792 INFO    sandboxd: job 98e60edf-932a-4cc5-bfea-35e75c4c87fc -> completed (clean)
```

Elided and said so: the pull's file list, the console and heartbeat lines,
two of three identical tracebacks each time, about a hundred identical
uploads; the presigned URL's credential and signature are REDACTED. The
operator had destroyed the third run's domain and its snapshot by hand before
this re-run, so it started clean.

**§6c is complete, and the fix held**: `make exit 0` after the same steps
that read `Error 32` before. One new line in the output,
`failed to stat() /dev/mapper/vg--root-ubuntu3`, is the trap's second
`kpartx -d` finding its mapping already gone and saying so on stdout,
which `2>/dev/null` does not cover; harmless, and the price of a trap that
now runs to its end. The state was saved after 22:33 of uptime (8.59 GB),
the daemon came up on it at 16:41 with `SANDBOXD_INJECTION_PID_UBUNTU=1`,
and job `98e60edf`, a `.sh` sample, was claimed at 16:41:18 and
`completed (clean)` at 16:43:59: **the evidenced Ubuntu path, on the image
rebuilt today with the identity, under today's Xen and DRAKVUF.** Falco ran
over the trace (2,965 events, 1 alert, 60 rules).

> **FINDING (2026-11-04), shared, pre-existing.** Three
> `KeyError: 'DumpsCount'` at ERROR from `process_dumps.parse_memdump`, on
> lines 137–139 of `memdump.log`; the §5b job had the same three, on the
> image before the rebuild. DRAKVUF's memdump plugin writes two kinds of
> `memdump` record: a dump, with `DumpsCount`, `DumpAddr`, `DumpFilename`,
> and an event with none of those — `RWX mmap detected` with
> `Address`/`Length`/`Protection`, `Remote process memory write` with
> `TargetPID` (`drakvuf/src/plugins/memdump/memdump.cpp`, lines 294, 413 and
> 435 against 315). The parser treats every line as a dump. Candidate fix:
> return `None` for a record without `DumpsCount`, or index it as an event.
> Shared code on the Ubuntu path, not touched here; TROUBLESHOOTING has the
> symptom. **`cpuidmon` on Ubuntu**: 9,046 events from 136 PIDs absent from
> the process tree were not indexed — far more than Windows's 3 — which says
> the Ubuntu guest's boot-time processes outnumber what procmon sees after
> the restore; informational, and a question for the per-plugin look that
> is still to be done on both guests.

---

# 7. The first evasion search

`evasion-tests/README.md` is the procedure; this part only orders its first
run after §2 to §6 and records it. The requirements it lists are met by now:
`make xen` run from Dom0's checkout (its package in `drakvuf/xen/dist/`,
§2b), `make sandboxd` built `drakvuf/build` (§5), guests installed and saved
(§6), `/boot` plain (§0.3), the same commit on both checkouts (§1.1; commit and
push the workstation's changes first, then pull on Dom0), `sandboxd` stopped,
root ssh with a key.

## 7.1 `site.conf` on the workstation

```bash
# WORKSTATION, in evasion-tests/. site.conf is untracked
cd /workspaces/work/sandbox_project/evasion-tests && test -f site.conf || cp site.conf.example site.conf; grep -E '^(DOM0|SSH_KEY|REMOTE_REPO|REMOTE_OUT_BASE|BUILD_CPUS|LINUX_VM[12]|WINDOWS_VM[12])=' site.conf
```

Set, for this host: `DOM0=root@192.168.1.6`, `SSH_KEY=/workspaces/work/id_ed25519`,
`BUILD_CPUS=16-31` (the E-cores, §2), and
`REMOTE_OUT_BASE=/srv/drakvuf-out/evasion-tests` — the default is under
`/root`, on a root filesystem with 81 G free, and an al-khaser test writes
tens of GB. Leave `REMOTE_REPO` and `REMOTE_STATE` at their defaults.

## 7.2 The one-shot boot

§2a proved the plain-kernel boot. The search also boots a variant's Xen
**once** with `grub-reboot` while the plain kernel is the default
(`evasion-tests/README.md` §7.7, second half). Try it once:

```bash
# DOM0 (Xen), as root. Two reboots: plain kernel, then Xen once, then it would be the plain kernel again
xl shutdown -w platform; sed -i 's/^#XEN_OVERRIDE_GRUB_DEFAULT=0/XEN_OVERRIDE_GRUB_DEFAULT=0/' /etc/default/grub.d/xen.cfg && update-grub2 && reboot
```

```bash
# DOM0 (no Xen), as root
grub-probe --target=abstraction /boot/grub/grubenv; echo "exit $?"; grub-reboot 'Ubuntu GNU/Linux, with Xen hypervisor' && grub-editenv list && reboot
```

```bash
# DOM0 (Xen), as root. Back on Xen once; put Xen back as the default now
grep -q control_d /proc/xen/capabilities && echo "xen, one-shot worked"; grub-editenv list; sed -i 's/^XEN_OVERRIDE_GRUB_DEFAULT=0/#XEN_OVERRIDE_GRUB_DEFAULT=0/' /etc/default/grub.d/xen.cfg && update-grub2 && grep -c 'with Xen hypervisor' /boot/grub/grub.cfg; xl create /root/drakvuf-multios-sandbox/misc/xen-vms/platform.cfg
```

Expect `grub-probe` to print nothing, `next_entry=` set before the reboot,
`xen, one-shot worked`, and `grub-editenv list` **without** `next_entry`
after.

```
EVIDENCE 7.2
```

## 7.3 Test VMs and one benchmark by hand

The block of `evasion-tests/README.md` §3.2 for Ubuntu, then its §3.5 step 2.
Never onto the origin: the benchmark refuses a cfg whose `disk` is not its
`CLONE_NAME` ([TROUBLESHOOTING](docs/TROUBLESHOOTING.md#a-templates-disk-drifted-away-from-its-saved-memory-image)).

```bash
# DOM0 (Xen), as root. Writes new files only
mkdir -p /root/evasion-tests && for n in 1 2; do sed -e "s|^name *=.*|name = 'ubuntu_test$n'|" -e "s|/dev/vg-root/ubuntu_sandbox,|/dev/vg-root/ubuntu_sandbox-test$n,|" /root/drakvuf-multios-sandbox/misc/xen-vms/ubuntu_sandbox.cfg > /root/evasion-tests/ubuntu_test$n.cfg && echo "vncdisplay = $((n - 1))" >> /root/evasion-tests/ubuntu_test$n.cfg; done; grep -H -E '^(name|disk|vcpus|memory|vif|vncdisplay|vnclisten)' /root/evasion-tests/ubuntu_test*.cfg
```

Expect each `disk` to name `-test1` or `-test2`. The two VMs share a `vif`
line: give VM2 another MAC or bridge by hand before a two-VM search
(`evasion-tests/README.md` §3.2's table). Then, `sandboxd` stopped:

```bash
# DOM0 (Xen), as root, sandboxd stopped. Snapshot, restore, 30 s of DRAKVUF, teardown
cd /root/drakvuf-multios-sandbox/evasion-tests && GUEST=linux CFG=/root/evasion-tests/ubuntu_test1.cfg CLONE_NAME=ubuntu_sandbox-test1 CONFIGS=dev-syscalls DRAKVUF_TIMEOUT=30 ./benchmark_drakvuf.sh 2>&1 | tail -15; lvs vg-root | grep -c test1; xl list
```

Expect `dev-syscalls: status=0`, an output directory with one log, and `0`:
the snapshot removed and the domain gone.

```
EVIDENCE 7.3
```

## 7.4 One short search

```bash
# WORKSTATION, in evasion-tests/, in tmux. Reboots Dom0 twice; the platform is down meanwhile
cd /workspaces/work/sandbox_project/evasion-tests && TESTS=1 ONLY=baseline ./rdtsc_search.sh
```

Expect the preflight to pass — `sandboxd` down, the two checkouts equal, the
patch identical, `make xen`'s package kept under `REMOTE_STATE/known-good/` —
then `baseline` built, booted once, one test with a `pass` verdict in
`results.csv` (or `fail`: that is a result, not an error), and at the end Dom0
back on Xen as `make xen` left it, with `known-good/` and `orig/` gone. Paste
`results.csv`, `ranking.txt`, and from Dom0 afterwards:

```bash
# DOM0 (Xen), as root. Read-only
grep -q control_d /proc/xen/capabilities && echo xen; xl info | grep cc_compile_date; ls /root/evasion-tests/; grep -n 'XEN_OVERRIDE_GRUB_DEFAULT' /etc/default/grub.d/xen.cfg; xl list
```

If the search stopped without putting Dom0 back, `./restore_dom0.sh` from the
workstation, or [TROUBLESHOOTING](docs/TROUBLESHOOTING.md#dom0-comes-back-on-the-plain-kernel-after-an-evasion-search).

```
EVIDENCE 7.4
```

---

# 8. Record what happened

In the change that fills the evidence:

1. `git mv deploy-with-makefile.md docs/runbooks/18-deploy-with-makefile.md`,
   point `README.md`'s links at the new path (`scripts/check-refs.py` fails
   until they are), and rewrite the status banner to what ran and what did
   not. Parts not run are **pending**, not abandoned, unless §6's decision
   went the other way; say which.
2. `docs/CURRENT-STATE.md` rows, dated: §1.2 Xen (`make xen` **has** run as
   a target; `cc_compile_date`), "Dom0 checkout" (at `origin/master`, the
   local commit on a branch, `Makefile.local` present), DRAKVUF (built from
   the pin), "Env file template" (the renderings have run); §1.5 Windows if
   6b ran; the evasion README's status paragraph.
3. Whatever went wrong → `docs/TROUBLESHOOTING.md`, symptom-first, and the
   wrong step here **replaced** with a pointer.
4. The FINDINGs above that turned into fixes → the Makefile and
   `automation/sandboxd.env.example`, in their own commits, with this
   runbook's step updated to match.
5. Regenerate and check:

   ```bash
   # DEV CONTAINER
   scripts/gen-current-state.py && scripts/gen-doc-index.py && scripts/check-refs.py && platform/.venv/bin/python -m pytest sandboxd/tests -q
   ```

6. Confirm the new row reads `yes` in `CURRENT-STATE.md` §3.

## Open questions this run should settle

- **Two copies of the guest configs.** `misc/*.cfg` is what
  `scripts/gen-xen-configs.py` writes the CPU partition into (`cpus =
  "16-27"`, 1 vCPU, 4096 MiB); `misc/xen-vms/*.cfg` is what the Makefile
  writes and what `sandboxd/stages.py` reads (4 vCPUs, 8192 MiB, **no
  `cpus`**). The pin never reaches a clone. One of the two directories has to
  go, or the generator has to write the other. Not decided here.
- **Whether the Makefile-written cfgs should be tracked.** They carry the
  host's identity lines and MAC — the two clone templates already do, since
  1.1e — so every run dirties the checkout, and a commit publishes the
  identity. Candidate: the Makefile writes them under `state/xen-vms/`
  (untracked), `sandboxd/stages.py` reads from there, and `misc/xen-vms/`
  keeps only the identity-free examples, with the Makefile's sizes.
- **`xl save` by hand.** The 20-minute wait is the operator's; a target that
  checks `xl uptime` and refuses under 20 minutes would make the rule
  mechanical.
