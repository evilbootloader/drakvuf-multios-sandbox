# Rebuild the platform as a Debian 13 PVH DomU

> **Status: written 2026-08-28, NOT YET EXECUTED.** Every `EVIDENCE` block is
> empty until an operator pastes real output into it.
>
> **Parked at the repository root**, and it belongs at
> `docs/runbooks/13-platform-domu.md`. `scripts/gen-current-state.py:141` counts
> `docs.rglob("*.md")` off the filesystem, so a new `.md` under `docs/` fails
> `test_current_state.py` while still untracked. Move and rename at commit time.
>
> **Every command here is Candidate.** None has been run on this lab.

## Why this exists

CT 102 was an unprivileged LXC on Proxmox. **Proxmox is gone**, erased in the
bare-metal migration (`baremetal-trial.md` §A1b).

**And its backup cannot be read** — `ct/102` was encrypted with PVE's own key,
which lived on the erased host. See FINDING E-1. **This domain is therefore
built empty**: fresh Postgres from the migrations, empty MinIO, one reissued
server certificate. Job history and stored artifacts are gone, accepted
2026-08-28 as not worth reconstructing.

`sandboxd` has nothing to register with until this domain exists. It is the last
thing between the lab and an end-to-end analysis.

**This runbook is a delta, not a replacement.** `08-deploy-platform-lxc.md` is
2000 lines of executed evidence for Postgres, MinIO, the API, TLS and
Cloudflare, and almost all of it applies unchanged. Read that; this covers only
what differs.

## What carries over from runbook 08, and what does not

| Runbook 08 | Status here |
|---|---|
| 1–2 create container | **Replaced** — Parts C and D below |
| 3 base packages | Carries over, **but its list is incomplete for a debootstrap base** — see FINDING E-4. Plus a kernel and initramfs a container never needed |
| 4 MinIO on its own volume | Carries over; the volume is an LV, not `mp0` |
| 5 network reachability | Carries over; `vif` instead of `veth` |
| 6, 14 `pct snapshot` | **Replaced** — thin LV snapshots, §F1 |
| **7 Postgres as UTF-8** | **Carries over verbatim, and read finding F2 first** |
| 8–10 local-only, role, deploy key | Carry over unchanged |
| 11–13 migrations, verify schema | **Run as written** — the restore is impossible, see FINDING E-1 |
| 4 MinIO install | Carries over, **but see FINDING E-2** — it never creates `minio.env` or the systemd unit that later steps use |
| 15 bucket + service account | **Superseded** by `platform/minio/provision.sh` — §E3d |
| 16 CA on workstation | **Skip** — the CA already exists |
| 17 Cloudflare, Zero Trust, AUD | **Skip** — external state, unaffected by the migration |
| 18 environment file | Carries over |
| 19 TLS material | **Reissue the server cert** from the workstation CA — §E2. Do NOT regenerate the CA |
| 19a MinIO on TLS · 20 API · 20a cloudflared · 20b browser listener | Carry over unchanged |
| 21–27 verification, object store, UI | Carry over unchanged |

---

# Part A — the three decisions, made

**Debian 13 (trixie).** Runbook 08:110 already settled this: *"Debian 13
recommended over Ubuntu: smaller, and nothing here needs Ubuntu's packaging."*
CT 102 was Debian 13, so every command in that runbook is a Debian command that
has been executed once against this exact stack.

**2048 MiB, not 4096.** Runbook 08 sized it at 4096 while noting *"2048 works"*.
That was written when an LXC's `--memory` was a **cgroup cap** — unused memory
stayed available to everything else. **A DomU reservation is not a cap.** It is
taken from the clone pool permanently:

    32 GB total - 8192 Dom0 - platform  ->  pool / 2198 MiB per clone
      platform 4096  ->  ~19.4 GB  ->  8 clones
      platform 2048  ->  ~21.4 GB  ->  9 clones

4096 now costs **one concurrent analysis**. Start at 2048 and raise only if
Postgres shows cache pressure.

**E-cores, `cpus = "16-17"`.** Postgres, MinIO and uvicorn are throughput work,
not latency-bound — the plan's §D2 argument, and the E-cores are otherwise
completely idle. This keeps P-cores `12,14` for clones and `0–10` for Dom0, so
the platform competes with nothing. **That, rather than a smaller distribution,
is what "light resource usage" actually buys here.**

## A1. Why PVH, and why the analysis guests must stay HVM

Xen has three guest modes. The split is principled rather than incidental, and
it runs the opposite way for the platform than for the analysis guests.

| | **PV** (2003, legacy) | **HVM** | **PVH** |
|---|---|---|---|
| CPU / memory | paravirtualized; every page-table update is a hypercall Xen validates | VT-x + EPT | **VT-x + EPT** |
| Syscalls | **trap to Xen and bounce** — guest kernel and user share an address space on 64-bit | native `SYSCALL`/`SYSRET` | **native** |
| Devices | paravirtual only | **emulated by QEMU** — BIOS, VGA, IDE, PIT, APIC | **paravirtual only** |
| QEMU in Dom0 | none | **one process per guest** | **none** |
| Boot | direct kernel / pvgrub | firmware → GRUB, like a real PC | direct kernel / pvgrub |
| Guest kernel | must be Xen-aware | unmodified, any OS | needs `CONFIG_XEN_PVH` |

### Throughput

**PV is the slowest and is legacy.** Page-table updates are hypercalls rather
than hardware, and 64-bit PV syscalls trap into Xen instead of executing
natively — a permanent tax on exactly the workload a database is. Meltdown
mitigation (XPTI) made it substantially worse. Xen upstream treats it as
deprecated; there is no reason to choose it here.

**HVM's cost is the device model.** CPU and memory are native — EPT does
second-level translation in hardware — but every access to an emulated device
(IDE registers, VGA, the PIT) is a VM exit into a **QEMU process running in
Dom0**. Guests mitigate this with PV drivers for disk and network (PVHVM), which
is what `misc/ubuntu_sandbox.cfg` effectively gets, but the emulated legacy
devices and their exits remain.

**PVH is HVM's CPU and memory with PV's devices and no device model.** Native
syscalls, hardware page tables, ring-buffer I/O, and **no QEMU exits at all**.
For a Postgres/MinIO/uvicorn workload it is the fastest of the three.

### The throughput argument that matters most here is memory, not CPU

**Every HVM guest costs a QEMU process in Dom0's 8192 MiB.** PVH costs none.
That is not an abstraction — Dom0's memory holds the DRAKVUF event loop, one
QEMU per running clone, `tcpdump` per VLAN, and `sandboxd`. Measure it:

```bash
# DOM0, with clones running
ps -o pid,rss,comm -C qemu-system-i386
```

So choosing PVH for the platform buys Dom0 memory back, and Dom0 memory is
adjacent to the constraint that caps concurrent analyses. It also avoids a
`qemu-dm-platform.log` and a VNC listener that this domain has no use for.

### Why the analysis guests are HVM anyway, and must stay so

Three reasons, any one of them sufficient:

- **DRAKVUF needs altp2m**, an HVM/EPT facility. The entire tracing mechanism
  rests on it — `altp2m=1` is on the Xen command line for this reason.
- **Anti-evasion.** A PVH guest has no BIOS, no emulated chipset, no VGA. It is
  *conspicuously* a virtual machine to anything that looks. HVM's emulated
  hardware is what makes `ideas.md`'s *"make vms more user computer like"*
  achievable at all, and what the fork's `hidevm` plugin and its SMBIOS work
  (`[MAP-1822]`) build on.
- **Windows cannot run PVH.**

And their throughput is not a consideration: §F7 measured clone vCPUs paused
**~93% of wall time** waiting on Dom0, and `baremetal-trial.md` Part H found
throughput unmoved by every CPU-placement variant tried. HVM's device-model
overhead is invisible next to the serialisation bound.

> **The split, stated once:** PVH for the platform *because it does not need to
> look like a real machine*, HVM for analysis guests *because they do*.

## A2. The boot method — decide before partitioning

PVH has no bootloader inside the guest. Two options and they partition
differently:

| | How | Cost |
|---|---|---|
| **Direct kernel boot** | `kernel=` / `ramdisk=` in the `.cfg`, files living **on Dom0** | every guest kernel upgrade means shutting the domain down and copying the new kernel out to Dom0. Forget it and the guest boots an old kernel against new modules |
| **`pygrub` / `pvgrub2`** | reads the kernel from the guest's own `/boot` | `apt upgrade` just works |

**Take direct kernel boot to start**, and treat §F2's kernel-update procedure as
a real recurring cost. Whether `bootloader = "pygrub"` works against a **PVH**
domain on Xen 4.20 is something to verify on this host rather than assume —
`pygrub` is long-established for PV and the PVH story is newer. If it works,
switch; the change is two lines in the `.cfg`.

EVIDENCE A

```
memory chosen:        2048
cpus chosen:          16-17
boot method:          direct   (direct kernel / pygrub — and if pygrub, did it work?)
```

---

# Part B — storage

Two thin LVs. Sizes are *virtual*; thin means they cost what is written.

```bash
# DOM0
sudo lvcreate -V 20G  --thin -n platform      vg-root/thinpool
sudo lvcreate -V 256G --thin -n platform_data vg-root/thinpool
sudo lvs -o +data_percent vg-root
```

`platform` is the root filesystem — 20G rather than the container's 16G, because
a VM carries a kernel, an initramfs and `/boot`. `platform_data` becomes
`/srv/minio`, matching the container's `mp0`.

> **This is where artifacts accumulate.** `CURRENT-STATE` §1.1 recorded the
> Proxmox thin pool as a shared failure domain — filling the artifact store
> could stop the analysis lab. **That hazard is now inside `vg-root`**, sharing
> a pool with the golden images and every clone snapshot. Autoextend is
> configured (`baremetal-trial.md` §B0c) but the pool cannot grow past the VG.
> Watch `data_percent`, and treat MinIO retention as a capacity question rather
> than only a GDPR one (DRAFT-041, DRAFT-022).

```bash
# DOM0
sudo mkfs.ext4 -L platform-root /dev/vg-root/platform
sudo mkfs.ext4 -T largefile -L minio-data /dev/vg-root/platform_data
```

> **`-T largefile` on the data volume, and it matters more on thin than on
> thick.** `mkfs.ext4`'s default allocates one inode per 16 KB — on 256 G that
> is ~16 million inodes whose tables are **written**, and on a thin volume every
> written block is a real allocation out of the shared pool. `largefile` is one
> inode per 1 MB, so ~256 thousand, and MinIO stores large objects: memdumps,
> pcaps, artifact ZIPs. The default would consume gigabytes of pool before a
> single artifact was stored.
>
> Do **not** apply it to the root volume — that one holds many small files.

EVIDENCE B

```
root@dom0:~# sudo lvcreate -V 20G  --thin -n platform      vg-root/thinpool
sudo lvcreate -V 256G --thin -n platform_data vg-root/thinpool
sudo lvs -o +data_percent vg-root
  WARNING: Sum of all thin volume sizes (3.14 TiB) exceeds the size of thin pool vg-root/thinpool and the size of whole volume group (<1.82 TiB).
  Logical volume "platform" created.
  WARNING: Sum of all thin volume sizes (3.39 TiB) exceeds the size of thin pool vg-root/thinpool and the size of whole volume group (<1.82 TiB).
  Logical volume "platform_data" created.
  LV             VG      Attr       LSize   Pool     Origin Data%  Meta%  Move Log Cpy%Sync Convert Data% 
  android        vg-root Vwi-a-tz-- 128.00g thinpool        6.97                                    6.97  
  platform       vg-root Vwi-a-tz--  20.00g thinpool        0.00                                    0.00  
  platform_data  vg-root Vwi-a-tz-- 256.00g thinpool        0.00                                    0.00  
  thinpool       vg-root twi-aotz--   1.38t                 5.33   0.27                             5.33  
  ubuntu         vg-root Vwi-a-tz--   1.00t thinpool        2.34                                    2.34  
  ubuntu-lv      vg-root -wi-ao---- 250.00g                                                               
  ubuntu_sandbox vg-root Vwi-a-tz--   1.00t thinpool ubuntu 1.60                                    1.60  
  windows        vg-root Vwi-a-tz--   1.00t thinpool        4.16                                    4.16  
root@dom0:~# sudo mkfs.ext4 -L platform-root /dev/vg-root/platform
sudo mkfs.ext4 -T largefile -L minio-data /dev/vg-root/platform_data
mke2fs 1.47.0 (5-Feb-2023)
Discarding device blocks: done                            
Creating filesystem with 5242880 4k blocks and 1310720 inodes
Filesystem UUID: 665e6d26-cee9-4961-ac21-fd8a8afdfc99
Superblock backups stored on blocks: 
	32768, 98304, 163840, 229376, 294912, 819200, 884736, 1605632, 2654208, 
	4096000

Allocating group tables: done                            
Writing inode tables: done                            
Creating journal (32768 blocks): done
Writing superblocks and filesystem accounting information: done   

mke2fs 1.47.0 (5-Feb-2023)
Discarding device blocks: done                            
Creating filesystem with 67108864 4k blocks and 262144 inodes
Filesystem UUID: 9e3a3aa6-fdfc-40c4-a4b5-8afa1a49bfdf
Superblock backups stored on blocks: 
	32768, 98304, 163840, 229376, 294912, 819200, 884736, 1605632, 2654208, 
	4096000, 7962624, 11239424, 20480000, 23887872

Allocating group tables: done                            
Writing inode tables: done                            
Creating journal (262144 blocks): done
Writing superblocks and filesystem accounting information: done   
```

---

# Part C — build the filesystem with debootstrap

**PVH cannot easily run the Debian installer** — no VGA, no CD-ROM path. Build
the filesystem directly from Dom0 instead. This is the standard approach for Xen
guests, is fully scriptable, and avoids cloud-init.

```bash
# DOM0
sudo apt install -y debootstrap
sudo mkdir -p /mnt/platform
sudo mount /dev/vg-root/platform /mnt/platform
sudo debootstrap --arch=amd64 trixie /mnt/platform https://ftp.caliu.cat/debian/
```

Then configure inside the chroot:

```bash
# DOM0
for d in dev dev/pts proc sys; do sudo mount --bind /$d /mnt/platform/$d; done
sudo chroot /mnt/platform /bin/bash
```

Inside the chroot — the parts a container never needed are the kernel and fstab:

```bash
echo platform > /etc/hostname
passwd root

apt update
apt install -y linux-image-amd64 systemd-sysv ifupdown2 openssh-server \
               ca-certificates locales sudo

cat > /etc/fstab <<'EOF'
LABEL=platform-root  /            ext4  errors=remount-ro  0 1
LABEL=minio-data     /srv/minio   ext4  defaults           0 2
EOF
mkdir -p /srv/minio

cat > /etc/network/interfaces <<'EOF'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address 192.168.1.10/24
    gateway 192.168.1.1
EOF

# NOT dns-nameservers in the stanza above -- that is a `resolvconf` directive
# and a minimal debootstrap has no resolvconf, so it is silently ignored and
# /etc/resolv.conf is left EMPTY. Symptom: routing works, `ping 1.1.1.1`
# succeeds, and every name lookup fails with "Temporary failure in name
# resolution". Write the file directly instead -- this domain has a static
# address and two fixed nameservers, so there is nothing to manage.
cat > /etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF

dpkg-reconfigure locales     # C.UTF-8 -- see runbook 08 finding F2
exit
```

> **`192.168.1.10` is not negotiable.** `SANDBOXD_API`, `SANDBOXD_CONSOLE_API`
> and the mTLS certificates all name it (`CURRENT-STATE` §1.3). Keeping the
> address means none of that changes. Note Dom0 itself moved to `.6` during the
> migration, so `.10` is free.

Copy the kernel out for §D's direct boot, then unmount:

```bash
# DOM0
sudo mkdir -p /var/lib/xen/platform
sudo cp /mnt/platform/boot/vmlinuz-* /var/lib/xen/platform/vmlinuz
sudo cp /mnt/platform/boot/initrd.img-* /var/lib/xen/platform/initrd.img

for d in sys proc dev/pts dev; do sudo umount /mnt/platform/$d; done
sudo umount /mnt/platform
```

EVIDENCE C

```
# Debootstrap worked correctly -> Everything smooth

root@dom0:~# ls -la /var/lib/xen/platform/
total 46872
drwxr-xr-x 2 root root     4096 Aug 28 16:25 .
drwxr-xr-x 5 root root     4096 Aug 28 16:25 ..
-rw-r--r-- 1 root root 35864121 Aug 28 16:25 initrd.img
-rw-r--r-- 1 root root 12122048 Aug 28 16:25 vmlinuz
```

---

# Part D — the domain config, and first boot

`misc/platform.cfg`:

```
# The platform DomU: Postgres, MinIO, the FastAPI service.
# It NEVER executes a sample -- that asymmetry is why runbook 08 judged a
# container proportionate, and it still governs what may run here.
type = "pvh"

name   = "platform"
memory = 2048
vcpus  = 2

# E-cores. Postgres/MinIO/uvicorn are throughput work, not latency-bound, and
# 16-31 are otherwise idle -- so this competes with neither Dom0 (0-10) nor the
# analysis clones (12,14).
cpus = "16-17"

# Direct kernel boot: PVH has no in-guest bootloader. These live on DOM0 and
# MUST be re-copied after any kernel upgrade inside the guest -- see F2.
kernel  = "/var/lib/xen/platform/vmlinuz"
ramdisk = "/var/lib/xen/platform/initrd.img"
# net.ifnames=0 forces eth0. WITHOUT it, systemd's predictable naming renames a
# Xen netfront device to something like enX0, /etc/network/interfaces matches
# nothing, and the domain boots with no address and no error -- diagnosable only
# from `xl console`. The name cannot be discovered in advance: a chroot shares
# Dom0's network namespace, so it has no guest interface to inspect.
extra   = "root=LABEL=platform-root ro console=hvc0 net.ifnames=0"

disk = [
    'phy:/dev/vg-root/platform,xvda,w',
    'phy:/dev/vg-root/platform_data,xvdb,w',
]

# xenbr0 -- the UPLINK bridge. NOT xenbr1: this is not an analysis guest and
# must never sit on the analysis network.
vif = [ 'bridge=xenbr0' ]

on_poweroff = "destroy"
on_reboot   = "restart"
on_crash    = "destroy"
```

```bash
# DOM0
sudo xl create -c /root/drakvuf-multios-sandbox/misc/platform.cfg
```

`-c` attaches the console immediately, which is the only way to see a PVH boot
failure. `Ctrl-]` detaches.

```bash
# DOM0, once it is up
sudo xl list
ping -c3 192.168.1.10
ssh root@192.168.1.10
```

EVIDENCE D

```
root@dom0:/home/user# sudo xl list
ping -c3 192.168.1.10
ssh root@192.168.1.10
Name                                        ID   Mem VCPUs	State	Time(s)
Domain-0                                     0  8192     6     r-----     300.3
platform                                     2  2048     2     -b----       4.4
PING 192.168.1.10 (192.168.1.10) 56(84) bytes of data.
64 bytes from 192.168.1.10: icmp_seq=1 ttl=64 time=0.211 ms
64 bytes from 192.168.1.10: icmp_seq=2 ttl=64 time=0.192 ms
64 bytes from 192.168.1.10: icmp_seq=3 ttl=64 time=0.275 ms

--- 192.168.1.10 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2027ms

# I won't enable SSH root login
```

---

# Part E — build it empty

> ## FINDING E-1 — CT 102's backup is unreadable. Its key died with Proxmox.
>
> 2026-08-28, attempting the restore this Part originally described:
>
> ```
> Error: wrong key - unable to verify signature since manifest's key
> 7b:c9:b4:05:63:84:7c:a9 does not match provided key 4f:15:85:70:27:c5:c4:c0
> ```
>
> **`ct/102` was written by `vzdump` on PVE, not by Dom0.** The vzdump log shows
> it: `--crypt-mode=encrypt --keyfd=12`. PVE supplied **its own** encryption key,
> the one held in `/etc/pve/priv/storage/` on the Proxmox host — **erased in the
> migration.** PBS never holds client keys, so there is nothing to recover from
> that side.
>
> **`pbs-backups.md` §C1 warned about exactly this and we applied it too
> narrowly.** That block says an encrypted backup whose key exists only on the
> machine being backed up is not a backup. We verified it for the key we
> *created* and never asked the same question about the key PVE was *already
> using*, because that backup predated the session and looked handled.
>
> **The lesson is one word wider than the runbook had it: audit every key in
> use, not only the one you make.**
>
> ### What was actually lost, and what was not
>
> | | |
> |---|---|
> | Job history (~48 jobs) | **lost** — accepted 2026-08-28, not worth reconstructing |
> | MinIO artifacts | **lost** |
> | The CA | **safe** — runbook 08 step 16 put it on the operator's workstation, deliberately |
> | Dom0's client certificate | **safe** — restored from `dom0-critical`, still validates against that CA |
> | The schema | **safe** — it is the migrations, in git |
> | Cloudflare, Zero Trust, the AUD | **safe** — external state |
> | MinIO bucket + service-account policy | **recreatable** — runbook 08 step 15 |
>
> So the platform is built **empty**. The only thing needing reissue is the API
> server certificate, and only because the old one's private key was on CT 102.

## E1. Postgres — migrations, not a restore

Runbook 08 **steps 7–13, all as written.** Step 7's finding F2 is the one to
read first: an SQL_ASCII cluster made the migration runner fail *silently*, and
the fix was ordering — create the UTF-8 cluster **before** any database exists.

Steps 11–12 run the migrations; step 13 verifies the schema landed. The
carry-over table's "mostly replaced — restore the dump instead" no longer
applies.

## E2. Reissue the API server certificate

The CA is on the workstation. Issue a new server certificate from it for
**`192.168.1.10`** — same address, so nothing else changes:

- **Dom0's client cert is unchanged** and still validates against the CA.
- **The API still validates Dom0's client cert** against that same CA.

Mutual TLS therefore works again with one new server certificate. Follow runbook
08 **step 19** for placement and **19a** for MinIO's own certificate, skipping
step 16 — the CA already exists and must not be regenerated, or Dom0's client
cert stops validating.

## E3. MinIO — empty

`/srv/minio` starts empty.

> ## FINDING E-2 — two prerequisites runbook 08 never documents
>
> Found rebuilding from scratch 2026-08-28. Both are *sourced* or *used* by
> later steps and never created by any step, because they were made ad hoc
> during the original execution:
>
> - **`/etc/minio/minio.env`.** Step 19a (`:1137`) documents three of its lines;
>   step 15 (`:764`) sources it for `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD`,
>   which nothing sets. Step 4 (`:252`) carries only a bare note — *"We need to
>   change default credentials for minio"* — never resolved.
> - **The `minio.service` unit.** Step 19a (`:1154`) runs
>   `systemctl restart minio` against a unit no step creates.
>
> Runbook 08 is append-only evidence, so this is recorded here rather than
> patched there.

### E3a. The environment file

```bash
# on the platform DomU
install -d -m 750 -o root -g minio-user /etc/minio
# NOT `umask 077` -- it persists for the rest of the shell session and silently
# creates every later file mode 600. That broke `apt-get update` several steps
# on, because apt verifies signatures sandboxed as the _apt user and could not
# read a 600 keyring in /usr/share/keyrings. A 600 /etc/resolv.conf is worse:
# name resolution keeps working for root and fails for every service user.
# Set the mode on the one file that needs it instead.
cat > /etc/minio/minio.env <<EOF
MINIO_ROOT_USER=$(openssl rand -hex 12)
MINIO_ROOT_PASSWORD=$(openssl rand -hex 24)
MINIO_VOLUMES="/srv/minio/data"
MINIO_OPTS="--address 192.168.1.10:9000 --console-address 127.0.0.1:9001 --certs-dir /etc/minio/certs"
MINIO_SITE_REGION=eu-central-1
EOF
chown root:minio-user /etc/minio/minio.env && chmod 640 /etc/minio/minio.env
```

**Hex, not base64.** `-hex 24` is 192 bits, far past MinIO's 8-character
minimum, and contains no shell or systemd metacharacter — so it cannot
misbehave in an `EnvironmentFile`, in `mc alias set`, or anywhere else. Base64
works and buys nothing at this length.

**New credentials are correct.** The old ones died with CT 102, and
`platform/minio/provision.sh` uses root credentials *only* to create the bucket,
policy and service account — the API receives the service account and never
these.

`MINIO_SITE_REGION` **must equal `S3_REGION`** in step 18: the region is part of
the SigV4 signing scope, and a mismatch fails every presigned URL with a 403
that discusses signatures and never mentions regions. **Do not probe it with
`mc admin config get local region`** — that reports empty for an env-set value,
which runbook 08:2351 records as having *"made `MINIO_SITE_REGION` look unset
through two investigations."* Use `mc admin config get local site`.

### E3b. Certificates — exact filenames

MinIO takes no path to an arbitrary pair (runbook 08:1107):

```bash
install -d -m 750 -o root -g minio-user /etc/minio/certs /etc/minio/certs/CAs
install -m 640 -o root -g minio-user minio.crt /etc/minio/certs/public.crt
install -m 640 -o root -g minio-user minio.key /etc/minio/certs/private.key
install -m 644 -o root -g minio-user ca.crt    /etc/minio/certs/CAs/ca.crt

su -s /bin/sh minio-user -c 'ls -l /etc/minio/certs/ /etc/minio/certs/CAs/'
```

**`/etc/minio` itself must be traversable by `minio-user`, not just `certs/`.**
Runbook 08:1118 records this costing three rounds of debugging: the directory
was `root:root`, `minio-user` could not descend into it whatever the certs' own
ownership said, and **MinIO started anyway, on HTTP, without logging a reason.**
The `su` check above is the one that catches it.

> ### No other private key belongs on this domain
>
> The platform holds **its own** server certs (`api`, `minio`) and **`ca.crt`**
> to verify clients. It must not hold:
>
> | | |
> |---|---|
> | `ca.key`, `ca.srl` | the CA **signing** key. On this machine, a platform compromise mints worker certificates and walks through the mTLS boundary. Runbook 08 step 16 put the CA on the operator's workstation deliberately |
> | `dom0-lab.key` | Dom0's **client** key. Dom0 has its own at `/etc/sandboxd/tls/`; the platform needs only `ca.crt` to verify the certificate |
> | `fake-worker.key` | same, for the step 21 test worker |

### E3c. The systemd unit

```bash
install -d -o minio-user -g minio-user /srv/minio/data
df -h /srv/minio          # MUST be xvdb, not the rootfs

cat > /etc/systemd/system/minio.service <<'EOF'
[Unit]
Description=MinIO
Wants=network-online.target
After=network-online.target
AssertFileIsExecutable=/usr/local/bin/minio

[Service]
Type=notify
WorkingDirectory=/usr/local
User=minio-user
Group=minio-user
EnvironmentFile=/etc/minio/minio.env
ExecStart=/usr/local/bin/minio server $MINIO_OPTS $MINIO_VOLUMES
Restart=always
LimitNOFILE=65536
TasksMax=infinity
TimeoutStopSec=infinity
SendSIGKILL=no

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload && systemctl enable --now minio
ss -lntp | grep 9000      # expect 192.168.1.10:9000 and 127.0.0.1:9001
```

### E3d. Provision — `provision.sh`, not step 15

> **This runbook reverses runbook 08's ordering, and that changes one URL.**
> Step 4 brought MinIO up on **plain HTTP** bound to loopback — step 19a says
> that was *"right for step 15's bucket creation and wrong for everything after
> it"* — so step 15's `mc alias set` names `http://127.0.0.1:9000`.
>
> §E3b and §E3c above install the certificates and the unit **before**
> provisioning, so MinIO is already on TLS when this runs and the endpoint is
> **`https://`**. `provision.sh` defaults to `https://127.0.0.1:9000` and is
> therefore correct as-is; runbook 08's `http://` is correct for *its* ordering
> and must not be edited to match — it is dated evidence of a different
> sequence.

`platform/minio/provision.sh` **supersedes step 15's hand-run `mc` blocks.** Its
header says why: the policy was a heredoc inside a document, so *"there was no
copy a test could load and no way to re-apply it after a rebuild"*. It is
idempotent, and `platform/tests/test_objects.py` asserts against the
`api-policy.json` it applies.

```bash
set -a; . /etc/minio/minio.env; set +a
BROWSER_ORIGIN=https://sandbox.evilbootloader.com BUCKET_QUOTA=200GiB \
  /opt/platform/src/platform/minio/provision.sh
```

> ## FINDING E-4 — runbook 08 step 3's package list is short of `libmagic1`
>
> Both API services failed identically on first start:
>
> ```
> File ".../sandbox_platform/routers/jobs.py", line 22, in <module>
>     import magic
> ImportError: failed to find libmagic.  Check your installation
> ```
>
> `platform/requirements.txt:23` pins `python-magic==0.4.27`, which is a
> **ctypes wrapper**: pip installs the Python side and never the C library.
> Step 3 installs `postgresql python3-venv python3-pip ca-certificates curl
> gnupg` — no `libmagic1`.
>
> **It worked on CT 102 because the Debian *standard* LXC template already
> carried `file`/libmagic. A `debootstrap` base does not.** That is a general
> difference between the two build methods, not a one-off: anything the
> template happened to include is absent here and surfaces as a runtime import
> error rather than an install failure.
>
> ```bash
> apt-get install -y libmagic1t64 || apt-get install -y libmagic1
> ```
>
> `libmagic1t64` on trixie — the 64-bit `time_t` transition renamed it.
>
> **`python-magic` is the only dependency of this shape.** `psycopg-binary`
> bundles libpq and `pyjwt[crypto]` pulls `cryptography`, both shipping
> manylinux wheels with their libraries inside. `pytest-playwright` needs a
> browser but is tests-only and never loaded by the service.

## E4. Then the rest

Runbook 08 **18, 20, 20a, 20b** unchanged.

> ### Step 20b's `sed` genuinely does not work — use the written-out unit
>
> Runbook 08 flags this in its own header, and it reproduces exactly. The `sed`
> at `:1437` deletes the `--ssl-cert-reqs` line, which is the **last** line of a
> backslash-continued `ExecStart`; the preceding `--ssl-ca-certs` line then ends
> in `\` and swallows whatever follows:
>
> ```
> ExecStart=... --ssl-ca-certs /etc/sandbox-platform/tls/ca.crt Restart=on-failure
> Error: Got unexpected extra argument (Restart=on-failure)
> ```
>
> Use the written-out unit at `:1466`. With a **quoted** heredoc (`<<'EOF'`)
> write single backslashes, not the `\\` the runbook shows — that doubling is
> only needed because its heredoc is unquoted.
>
> `systemd-analyze verify` before `enable` is what catches this class of thing.
> `enable` only creates a symlink, so it succeeds against a unit that can never
> start.

> ## FINDING E-5 — the Access team domain: both work, only `iss` discriminates
>
> Cloudflare gives an account an auto-generated team domain
> (`REDACTED-AUTO.cloudflareaccess.com`) and, if configured, a custom one
> (`REDACTED-CUSTOM.cloudflareaccess.com`). **The dashboard showed the
> auto-generated one; Access issues tokens from the custom one.**
>
> Setting `ACCESS_TEAM_DOMAIN` to the auto-generated value produced
> `{"detail":"invalid access token"}` — a 401 from `auth.py:252`, with the
> reason deliberately withheld from the client because *"which check failed is
> a hint to whoever is probing."* The journal named it.
>
> **Both team domains serve the same JWKS.** `auth.py:196` builds
> `{team_domain}/cdn-cgi/access/certs` and the fetch *succeeded* against the
> wrong one — so signature verification passed and only the `iss` comparison at
> `auth.py:245` failed. **A "does the JWKS endpoint work" check cannot detect
> this.** Read the log, or decode a real `CF_Authorization` cookie.
>
> The reliable source is the `location:` header of the Access redirect:
>
> ```bash
> curl -sSI https://sandbox.evilbootloader.com | grep -i '^location'
> # -> https://<TEAM>.cloudflareaccess.com/cdn-cgi/access/login/...?kid=<AUD>
> ```
>
> **That one line carries both values.** The host is `ACCESS_TEAM_DOMAIN`, and
> the `kid=` parameter is the Application Audience tag — confirmed by decoding
> the `meta=` JWT in the same URL, whose `aud` claim matches it.
>
> Symptoms are distinguishable, which is worth knowing before guessing:
>
> | Symptom | Cause |
> |---|---|
> | 401, journal says `Invalid issuer` | wrong team domain |
> | 401, journal says `Invalid audience` | AUD belongs to another application |
> | **500** `access verification misconfigured` | a variable never reached the process (`auth.py:231`) — check `systemctl show -p Environment` |
>
> The drop-in goes on the **browser unit only**. The worker channel on 8443
> authenticates by client certificate and worker token and must not require an
> Access JWT.

EVIDENCE E

```
PVE encryption key found?     no -- see FINDING E-1
migrations applied:           ______
step 13 schema verification:  ______
API cert reissued from CA:    ______
Dom0 client cert validates:   ______

minio.env created (E3a):      yes -- see FINDING E-2, runbook 08 never creates it
libmagic1t64 installed:       yes -- FINDING E-4, both API services failed without it
provision.sh:                 bucket, 200GiB quota, 30d lifecycle, CORS, svcacct -- all ok

Listeners after the rebuild:
  192.168.1.10:8443   sandbox-api          worker channel, mTLS
  192.168.1.10:8000   sandbox-api-browser  browser origin
  192.168.1.10:9000   minio                S3   (+ 127.0.0.1:9000, [::1]:9000)
  127.0.0.1:9001      minio console        loopback only, as designed
  127.0.0.1:20241     cloudflared          metrics

cloudflared:  4 ready connections, 2xbcn01 2xmad05, tunnel 88c2e326-...
              QUIC failed to region2; fell back to http2. Benign.
Access:       302 -> REDACTED-CUSTOM.cloudflareaccess.com, verified after
              FINDING E-5 (the dashboard's team domain was the wrong one)

STILL TO RECORD:
service account secret in api.env matches provision.sh output: DONE
end-to-end job through the browser:                            ______
```

---

# Part F — operating it

## F1. Snapshots replace `pct snapshot`

Runbook 08 used `pct snapshot` at steps 6 and 14. The equivalent:

```bash
# DOM0 -- shut down first; a snapshot of a live Postgres is crash-consistent only
sudo xl shutdown platform && sleep 20
sudo lvcreate -s -kn -n platform-snap vg-root/platform
sudo xl create /root/drakvuf-multios-sandbox/misc/platform.cfg
```

For routine protection prefer `pg_dump` over a filesystem snapshot — a logical
dump restores into a different Postgres version and survives a corrupted
cluster, which a block-level copy cannot.

## F2. After ANY kernel upgrade inside the guest

Direct kernel boot means Dom0 holds the kernel. **`apt upgrade` inside the guest
updates `/boot` and the modules but not what Xen boots**, so the domain silently
comes up on the old kernel against new modules.

```bash
# on the guest
apt upgrade && shutdown -h now

# DOM0 -- while the domain is DOWN
sudo mount /dev/vg-root/platform /mnt/platform
sudo cp /mnt/platform/boot/vmlinuz-*    /var/lib/xen/platform/vmlinuz
sudo cp /mnt/platform/boot/initrd.img-* /var/lib/xen/platform/initrd.img
sudo umount /mnt/platform
sudo xl create /root/drakvuf-multios-sandbox/misc/platform.cfg
uname -r        # on the guest -- must match what apt installed
```

If several kernels are present the glob copies the wrong one. Name the version
explicitly once there is more than one.

## F3. Back it up

`pbs-backups.md` §D2 relied on `vzdump 102`, which no longer exists. The DomU
needs its own client invocation:

```bash
# on the platform DomU
proxmox-backup-client backup \
    root.pxar:/ minio.pxar:/srv/minio \
    --backup-type host --backup-id platform --ns dom0 \
    --keyfile /root/.config/proxmox-backup/encryption-key.json
```

> ## FINDING E-3 — three credentials were lost the same way in one rebuild
>
> Each existed in exactly one place, on the machine that got wiped:
>
> | | Where it lived | Recoverable? |
> |---|---|---|
> | PVE's PBS encryption key | `/etc/pve/priv/storage/` on the Proxmox host | **No** — took `ct/102` with it (FINDING E-1) |
> | MinIO root credentials | `/etc/minio/minio.env` on CT 102 | No, but regenerating costs nothing |
> | **The tunnel credential** | `/etc/cloudflared/<UUID>.json` on CT 102 | **No.** `cloudflared` issues it once at `tunnel create` and Cloudflare will not re-issue it. The tunnel *object* survives with the UUID visible in `tunnel list`; without the JSON nothing can connect to it |
>
> `pbs-backups.md` §C3 backs up **Dom0's** `/etc`. The platform's `/etc` was
> only ever inside `vzdump 102`, so all three sat behind the one key that was
> lost.
>
> **`root.pxar:/` above now covers `/etc/cloudflared/` and `/etc/minio/`** —
> that is the point of backing up the whole root rather than selected paths.
> Verify it rather than assuming, since these are the files that make the
> difference between a rebuild and a reconstruction:
>
> ```bash
> proxmox-backup-client mount host/platform/<timestamp> root.pxar /mnt/check \
>     --ns dom0 --keyfile /root/.config/proxmox-backup/encryption-key.json
> ls /mnt/check/etc/cloudflared/ /mnt/check/etc/minio/ \
>    /mnt/check/etc/sandbox-platform/tls/
> ```

Plus the `pg_dump` into `/var/backups/platform/` so the filesystem archive
carries a logical dump, exactly as §D1 did for the container.

---

# Part G — verify

The existing evidence path, unchanged from runbook 08:

```bash
# DOM0
curl -sk https://192.168.1.10:8000/healthz; echo
curl --cacert /etc/sandboxd/tls/ca.crt \
     --cert /etc/sandboxd/tls/dom0-lab.crt \
     --key  /etc/sandboxd/tls/dom0-lab.key \
     -s https://192.168.1.10:8443/healthz; echo
```

Then start `sandboxd` per `CURRENT-STATE` §1.2 — source the env file first, it
exits immediately otherwise — and confirm it registers. Then a real job end to
end, runbook 08 steps 22–23.

> **Never run the platform pytest suite against this domain.** `CLAUDE.md` is
> explicit: the `conn` fixture runs `TRUNCATE jobs, worker_pipelines, workers
> RESTART IDENTITY CASCADE`. It was attempted on the old deployment 2026-08-25
> and failed only because the test database did not exist — **creating it is not
> the fix.** Verification here is `curl` and the UI.

EVIDENCE G

```
8000/healthz:            ______
8443/healthz (mTLS):     ______
sandboxd registered:     ______
end-to-end job:          ______
```

---

# Decision summary

| Question | Answer | Evidence |
|---|---|---|
| Memory: 2048 or 4096, and what did it cost in clones? | | A |
| Did `pygrub` work with PVH on Xen 4.20, or is it direct kernel boot? | | A2 |
| Dom0 RSS per QEMU process, with clones running | | A1 |
| Did the domain boot and reach `192.168.1.10`? | | D |
| Did `pg_restore` land the schema (step 13 check)? | | E2 |
| Does Dom0's client cert still validate against the restored CA? | | G |
| Is the kernel-copy step in F2 written somewhere an operator will see it? | | F2 |
| Thin pool `data_percent` after MinIO restore | | B |