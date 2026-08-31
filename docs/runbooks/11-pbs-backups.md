# Back the lab up to a Proxmox Backup Server on another machine

> **Status: written 2026-08-27, EXECUTED 2026-08-27/28.** Filed 2026-08-29.
> Every `EVIDENCE` block below carries real output; the one remaining blank is
> the PBS datastore free-space row in §0's prerequisites table, which is
> cosmetic and not a gate on anything.
>
> **This runbook did its job, and the proof is what happened next.** It was
> written as the prerequisite for `12-baremetal-trial.md`, which erases the
> Proxmox host. That erase went ahead on 2026-08-28 and the golden images came
> back from this backup. EVIDENCE E records the restore, and an `e2fsck -f`
> added retrospectively on 2026-08-28 — passes 1–5 clean, no repairs — confirms
> the restored image was sound rather than merely mountable.
>
> **Read §"Why this runbook exists" for its own history, not for this host.**
> It argues from the *nested* lab's thin pool and VM 101's virtual disk, both
> of which the migration erased the day after. The argument was correct and the
> facts it rests on are superseded; `docs/CURRENT-STATE.md` §2a lists them.
>
> **Commands remain Candidate for re-execution.** They ran against the Proxmox
> host and `pbs1`, and PVE-side steps (`vzdump`, `pct`, `qm`) have no host to
> run on any more. The PBS side is unchanged. None can be run from the
> development container.

## Why this runbook exists

**Nothing in this lab is backed up, and its most valuable state is not in git.**
`docs/CURRENT-STATE.md` §1.4 records it plainly: `profiles/*.json` and
`state/*.bak` are not git-tracked, so a fresh checkout has neither. Neither are
the golden OS images. Today they exist in exactly one place — inside VM 101's
virtual disk on a thin pool that `CURRENT-STATE` §1.1 records as **6.35 TiB
provisioned against <1.82 TiB real with `thin_pool_autoextend_threshold`
unset.**

| What | Why losing it hurts |
|---|---|
| Golden LVs `ubuntu`, `android`, `windows` | Hand-installed, and **not reconstructible from anything**. Windows is a clean install plus Chrome, Office and Defender-disabled with no build script. The `*_sandbox` LVs are deliberately excluded — see §C2 |
| `state/*.bak` | `misc/*_sandbox.cfg:19-24`: a clone's vCPU count comes from the *saved image*, not the config. Rebuilding one means booting the golden domain at `vcpus = 1` and re-saving, then re-deriving the injection PID (Ubuntu 1415, Android 3174) |
| `profiles/*.json` | Regenerable with `dwarf2json`, but only from matching kernel debug symbols. Android's comes from a separate BlissOS build host |
| CT 102's Postgres + MinIO | Every job record and every retained artifact |

This is worth doing **whether or not the bare-metal migration ever happens**.
It also happens to be its precondition: that migration rebuilds `vg-root`, and
there is currently no second copy of anything to rebuild it from.

## Shape

> **Revised during execution, 2026-08-27.** This section originally argued for
> a coarse `vzdump 101` safety net first, on the assumption that datastore
> space was free. §0's evidence came back at **211G available, 89% full**, and
> that assumption does not hold — `vzdump 101` reads VM 101's entire 1022G
> virtual disk, *including `lv-root`'s 256G* of Dom0 root, which holds only the
> DRAKVUF build and the repo checkout, both reproducible.
>
> **The order that follows from the real numbers is C → D → E, then F, with A
> optional.** Part C walks 224G of golden LVs; Part D's `vzdump 102` is
> file-level and costs only what MinIO has actually written.

**Part B is where the only real difficulty lives** (§B1) — the client is built
for Debian and Dom0 is Ubuntu jammy. Everything after it is mechanical.

**Part C is the core.** It is the only thing here that produces per-LV backups
which survive the move off Proxmox, and it covers the three artifacts that
cannot be reconstructed from anything.

| Part | Where | What it does |
|---|---|---|
| 0 | both | Identifiers, and confirming the PBS host exists |
| A | PVE | `vzdump 101` — **demoted to optional on space grounds, see §C3** |
| B | Dom0 | `proxmox-backup-client` on Ubuntu 22.04 — the risky step |
| C | Dom0 | The golden LVs and the untracked state. **The core of this runbook** |
| D | PVE | The platform's Postgres and MinIO. **`vzdump 102` is not optional** |
| E | Dom0 | **Verify a restore.** The load-bearing step |
| F | Dom0 | Schedule it, and set retention |

Shells:

- **PBS** — root on the backup machine
- **PVE** — `root@pve1`
- **DOM0** — `root@drakvuf`

---

# Part 0 — identifiers

Fill these in; later commands paste directly.

| # | Value | Yours |
|---|---|---|
| 1 | PBS hostname or IP | `192.168.1.5` |
| 2 | PBS datastore name | `datastore1` |
| 3 | Free space on the PBS datastore | `____________` |
| 4 | Dom0's LAN address | `192.168.1.144 (dynamic)` |

**Sizing before anything else.** The golden LVs are 64G + 32G + Windows, and
Part A's whole-VM image is ~1 TB provisioned. PBS deduplicates and compresses,
and the images are mostly empty, so the stored size will be far below the
provisioned size — but confirm the datastore has room rather than discovering
it three hours into the first run.

```bash
# PBS
proxmox-backup-manager datastore list
df -h /path/to/datastore
```

```bash
# DOM0 -- what actually has to fit
lvs vg-root
vgs vg-root
du -sh /root/drakvuf-multios-sandbox/profiles /root/drakvuf-multios-sandbox/state
```

EVIDENCE 0

```
root@pbs1:~# proxmox-backup-manager datastore list
┌────────────┬────────────────────┬─────────┐
│ name       │ path               │ comment │
╞════════════╪════════════════════╪═════════╡
│ datastore1 │ /backup/datastore1 │         │
└────────────┴────────────────────┴─────────┘
root@pbs1:~# df -h /backup/datastore1/
Filesystem        Size  Used Avail Use% Mounted on
rpool/ROOT/pbs-1  1.8T  1.6T  211G  89% /

root@drakvuf:~# lvs vg-root
  LV              VG      Attr       LSize   Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  android         vg-root -wi-a-----  32,00g                                                    
  android_sandbox vg-root -wi-a-----  32,00g                                                    
  lv-root         vg-root -wi-ao---- 256,00g                                                    
  ubuntu          vg-root -wi-a-----  64,00g                                                    
  ubuntu_sandbox  vg-root -wi-a-----  64,00g                                                    
  windows         vg-root -wi-a----- 128,00g                                                    
  windows_sandbox vg-root -wi-a----- 128,00g                                                    
root@drakvuf:~# vgs vg-root
  VG      #PV #LV #SN Attr   VSize     VFree   
  vg-root   1   7   0 wz--n- <1022,00g <318,00g
root@drakvuf:~# du -sh /root/drakvuf-multios-sandbox/profiles /root/drakvuf-multios-sandbox/state
109M	/root/drakvuf-multios-sandbox/profiles
4,0G	/root/drakvuf-multios-sandbox/state
```

## 0.1. If PBS is not installed yet

Install it from the Proxmox ISO or on top of Debian, per the official
documentation, then create a datastore. Then create a **dedicated user with a
token**, rather than backing up as `root@pam`:

```bash
# PBS
proxmox-backup-manager user create backup@pbs --email ''
proxmox-backup-manager user generate-token backup@pbs dom0
#   ^ prints the token value ONCE. Record it now; it cannot be shown again.
proxmox-backup-manager acl update /datastore/<datastore> DatastoreBackup \
    --auth-id 'backup@pbs!dom0'
```

`DatastoreBackup` grants create-and-read, **not prune or delete**. That is the
point: a Dom0 compromise should not be able to erase the backups of the machine
it just compromised. Run prunes from the PBS side (§F2) with a separate
credential.

EVIDENCE 0.1

```
Already have a user with perms on datastore1, namespace dom0
```

---

# Part A — the safety net, today

## A1. Add PBS as a Proxmox storage (PVE)

```bash
pvesm add pbs pbs-backup \
    --server <pbs-host> \
    --datastore <datastore> \
    --username 'backup@pbs!dom0' \
    --password '<token-value>' \
    --fingerprint <sha256-fingerprint-from-the-PBS-web-UI>
pvesm status
```

The fingerprint is shown in the PBS UI under **Dashboard → Show Fingerprint**.
Without it the first connection is refused rather than silently trusted, which
is the correct behaviour and not an error.

EVIDENCE A1

```
# Already set up in PVE

root@pve1:~# pvesm status
Name             Type     Status     Total (KiB)      Used (KiB) Available (KiB)        %
local             dir     active        98497780        65135708        28312524   66.13%
local-lvm     lvmthin     active      1793077248      1559977205       233100042   87.00%
pbs1              pbs     active      1885792896      1664585856       221207040   88.27%

```

## A2. Back up VM 101 and CT 102 (PVE)

**Read this before running it.** `vzdump` on a running VM defaults to
`--mode snapshot`, which is crash-consistent: it captures the disk as if the
power had been cut. For the golden LVs that is fine — they are not being
written. For anything mid-write it is not, which is why Part D dumps Postgres
properly rather than relying on this.

```bash
# PVE -- expect this to take a long time and a lot of I/O
vzdump 101 --storage pbs-backup --mode snapshot --notes-template 'pre-baremetal safety net'
vzdump 102 --storage pbs-backup --mode snapshot
```

Then confirm from the PBS side that the snapshots actually landed:

```bash
# PBS
proxmox-backup-client list --repository <datastore> --ns proxmox
```

`--ns proxmox` because `vzdump` writes into the namespace configured on the
PVE *storage*, not the one Dom0 uses. Omitting it lists the root namespace and
finds nothing, which looks identical to a backup that never ran.

**Do not treat Part A as complete until §E verifies a restore.** A backup that
has never been restored is a belief, not a backup.

EVIDENCE A2

```
root@pbs1:~# proxmox-backup-client list --repository datastore1 --ns proxmox
┌────────┬─────────────────────────────┬──────────────┬───────────────────────────
│ group  │ last snapshot               │ backup-count │ files                     
╞════════╪═════════════════════════════╪══════════════╪═══════════════════════════
│ ct/102 │ ct/102/2026-08-27T19:32:38Z │            1 │ catalog.pcat1 client.log i
├────────┼─────────────────────────────┼──────────────┼───────────────────────────
│ vm/101 │ vm/101/2026-08-27T19:20:26Z │            3 │ client.log drive-scsi0.img
└────────┴─────────────────────────────┴──────────────┴───────────────────────────
---

# Part B — `proxmox-backup-client` on Ubuntu 22.04

**This is the step most likely to cost a day.** Proxmox builds the client for
Debian; Dom0 is Ubuntu 22.04 jammy (`CURRENT-STATE` §1.2).

## B1. What NOT to do

**Do not add a Debian apt repository to Dom0's sources.** Mixing a Debian suite
into an Ubuntu system lets `apt` pull Debian's libc and dependency chain in to
satisfy the client, and the realistic outcome is a Dom0 that no longer boots or
no longer runs DRAKVUF. Dom0 is the machine the whole lab is, and it is not
reinstallable in an afternoon.

Three approaches, cheapest first. Stop at the first that works.

## B2. Approach 1 — the .deb alone, dependencies checked first

Download the package without installing, and read what it actually needs:

```bash
# DOM0
cd /tmp
# Confirm the current filename by browsing the index first -- do not assume it:
#   http://download.proxmox.com/debian/pbs-client/dists/bookworm/main/binary-amd64/
wget http://download.proxmox.com/debian/pbs-client/dists/bookworm/main/binary-amd64/<file>.deb

dpkg -I <file>.deb | grep -A2 Depends
```

Check each dependency against jammy **before** installing:

```bash
for p in $(dpkg -I <file>.deb | sed -n 's/^ Depends: //p' | tr ',' '\n' \
           | awk '{print $1}'); do
    printf '%-30s ' "$p"; apt-cache policy "$p" 2>/dev/null \
      | sed -n '2p' || echo MISSING
done
```

If everything resolves, install it and verify:

```bash
apt-get install -y ./<file>.deb
proxmox-backup-client version
```

If `apt` proposes removing anything, **abort** — answer no and go to B3.

EVIDENCE B2

```
# I've installed through the guide: https://pbs.proxmox.com/docs/installation.html#install-proxmox-backup-client-on-debian (Debian 12)
wget https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg -O /usr/share/keyrings/proxmox-archive-keyring.gpg

cat /etc/apt/sources.list.d/pbs-client.sources
Types: deb
URIs: http://download.proxmox.com/debian/pbs-client
Suites: bookworm
Components: main
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg

sudo apt install proxmox-backup-client-static```
```

## B3. Approach 2 — a bookworm chroot, Dom0's packages untouched

Isolates the client's dependency tree from Dom0's entirely. `--bind /dev` is
what lets it read the snapshot block devices in Part C.

```bash
# DOM0
apt-get install -y debootstrap
debootstrap --variant=minbase bookworm /opt/pbs-chroot http://deb.debian.org/debian
echo "deb http://download.proxmox.com/debian/pbs-client bookworm main" \
    > /opt/pbs-chroot/etc/apt/sources.list.d/pbs-client.list
# the release key -- confirm the current filename on download.proxmox.com
wget -O /opt/pbs-chroot/etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg \
    http://download.proxmox.com/debian/proxmox-release-bookworm.gpg
chroot /opt/pbs-chroot apt-get update
chroot /opt/pbs-chroot apt-get install -y proxmox-backup-client
chroot /opt/pbs-chroot proxmox-backup-client version
```

A wrapper so Part C's commands read the same either way:

```bash
cat > /usr/local/bin/pbc <<'EOF'
#!/bin/sh
# proxmox-backup-client, run from the bookworm chroot. See docs/runbooks/
# pbs-backups.md B3 -- Dom0 is Ubuntu jammy and the client is built for Debian.
mount --bind /dev  /opt/pbs-chroot/dev  2>/dev/null
mount --bind /proc /opt/pbs-chroot/proc 2>/dev/null
mount --bind /root /opt/pbs-chroot/root 2>/dev/null
exec chroot /opt/pbs-chroot /usr/bin/proxmox-backup-client "$@"
EOF
chmod +x /usr/local/bin/pbc
pbc version
```

EVIDENCE B3

```
(paste the version output, or the failure)
```

## B4. Approach 3 — accept Part A only, for now

If both fail, the lab is still protected by Part A and the migration is not.
Record that here and treat it as a blocker on the bare-metal work rather than
something to work around under time pressure.

EVIDENCE B4

```
approach that worked: B2   (B2 / B3 / neither)
```

---

# Part C — backups that outlive Proxmox

Everything below uses `proxmox-backup-client`; substitute `pbc` if B3 applied.

## C1. Set up credentials and encryption (DOM0)

```bash
# DOM0
export PBS_REPOSITORY='backup@pbs!dom0@<pbs-host>:<datastore>'
export PBS_PASSWORD='<token-value>'
export PBS_FINGERPRINT='<sha256-fingerprint>'
```

Generate an encryption key. The datastore holds golden malware-analysis images
and the platform's job history; it lives on a machine with a different threat
profile from this one.

```bash
proxmox-backup-client key create /root/.config/proxmox-backup/encryption-key.json
chmod 600 /root/.config/proxmox-backup/encryption-key.json
```

> ## Copy the key off this machine, now, before the first backup
>
> **An encrypted backup whose key existed only on the machine being backed up
> is not a backup.** If Dom0's disk dies, the key dies with it and every
> snapshot on PBS is permanently unreadable. That failure is silent until the
> exact moment it matters most.
>
> Print it, or put it on removable media, or store it in a password manager —
> anywhere that is not this host and not the PBS datastore. Do it before §C3
> runs, not after.
>
> ### Audit EVERY key already in use, not only the one you just made
>
> Added 2026-08-28, after this exact failure. The datastore already held
> `ct/102`, written months earlier by `vzdump` on PVE with **PVE's** encryption
> key — held in `/etc/pve/priv/storage/` on the Proxmox host. That host was
> later erased, and the backup became permanently unreadable:
>
> ```
> Error: wrong key - unable to verify signature since manifest's key
> 7b:c9:b4:05:63:84:7c:a9 does not match provided key 4f:15:85:70:27:c5:c4:c0
> ```
>
> The warning above was applied to the key this runbook *creates* and never to
> the key that was *already in use*, because that backup predated the session
> and looked handled. **A datastore can hold snapshots under several keys.**
> List them and account for where each key lives before trusting any of it:
>
> ```bash
> # PBS -- every namespace, not just yours
> proxmox-backup-manager datastore list
> proxmox-backup-client snapshot list --ns <each namespace>
> ```
>
> A snapshot whose key is on a machine you are about to wipe is not a backup of
> that machine.

Persist the credentials for the timer in §F1, mode 600:

```bash
umask 077
cat > /etc/pbs-backup.env <<EOF
PBS_REPOSITORY=backup@pbs!dom0@<pbs-host>:<datastore>
PBS_PASSWORD=<token-value>
PBS_FINGERPRINT=<sha256-fingerprint>
EOF
chmod 600 /etc/pbs-backup.env
```

EVIDENCE C1

```
root@drakvuf:~/drakvuf-multios-sandbox# proxmox-backup-client key create /root/.config/proxmox-backup/encryption-key.json
Encryption Key Password: ****************************************************************************************************************************************************************
Verify Password: ****************************************************************************************************************************************************************
root@drakvuf:~/drakvuf-multios-sandbox# chmod 600 /root/.config/proxmox-backup/encryption-key.json


root@drakvuf:~# cat /etc/pbs-backup.env 
PBS_REPOSITORY=REDACTED
PBS_PASSWORD=REDACTED
PBS_FINGERPRINT=REDACTED
```

## C2. Confirm the golden LVs are quiescent (DOM0)

**Read them directly. No snapshots.** An earlier version of this step created
an `lvcreate -s` snapshot per LV, on the reasoning that a golden domain which
happened to be running would otherwise produce a torn image. The evidence
below shows that reasoning does not apply here, and the snapshots cost more
than they buy.

```bash
# DOM0
xl list                      # expect Domain-0 only
lvs vg-root
```

Two things to read off that output, both of which must hold:

| Check | What you want | Why |
|---|---|---|
| `xl list` | **`Domain-0` and nothing else** | no golden domain is booted, so nothing is issuing writes |
| `lvs` attr, 6th character | **`-`, not `o`** | `o` means the device is *open*. `lv-root` shows `-wi-a**o**----` because it is Dom0's root; the goldens show `-wi-a-----` — active but held open by nothing |

An LV that is active, unopened, and belongs to no running domain has no writer,
so a direct read cannot tear. Confirm both **immediately before** §C3 rather
than trusting an earlier check — this is the only thing standing in for the
atomicity a snapshot would have given.

> ### Why not snapshot anyway
>
> - **The indirection caused a real bug in this runbook.** With a `-bk` layer,
>   `windows.img:` pointed at `windows_sandbox-bk` and looked correct.
>   `ubuntu.img:/dev/vg-root/ubuntu` cannot be wrong in that way.
> - A thick snapshot has an exception store that can fill and **invalidate
>   mid-backup**, turning a working procedure into a failed one.
> - It slows every write to the origin while it exists, and leaves a cleanup
>   step to forget.
> - It consumes VFree for no benefit when the origin is provably idle.
>
> **The scheduled version in §F1 is different and should snapshot.** Nothing is
> watching `xl list` at 03:00, and the golden domains *are* booted occasionally
> — during a sandbox rebuild, or to update an image. There, a check-then-act
> guard races and a snapshot does not.

Remove the snapshots created by the earlier version of this step:

```bash
# DOM0
lvremove -f /dev/vg-root/ubuntu-bk /dev/vg-root/android-bk \
            /dev/vg-root/windows_sandbox-bk
lvs vg-root                  # expect the original seven LVs, no -bk
```

> ### The three golden LVs, and why not the `_sandbox` ones
>
> **Decision, 2026-08-27: back up `ubuntu`, `android`, `windows` only.**
>
> `lvs` shows six LVs in three pairs. The golden half is the hand-installed OS
> and **cannot be reconstructed from anything** — Windows in particular is a
> clean install plus Chrome, Office and Defender-disabled with no build script.
> The `_sandbox` half is *derived* from it, and the derivation is a documented
> procedure (`03-rebuild-android-sandbox.md`): copy the golden, apply preconfig,
> boot, save state, re-derive the injection PID.
>
> So the goldens are irreplaceable and the sandboxes are expensive-but-
> reproducible. **At 211G free on the datastore that is the trade worth making**
> — three LVs is 224G walked instead of 448G.
>
> Two consequences to be aware of rather than surprised by:
>
> - **`state/*.bak` loses most of its value in a restore-from-golden.**
>   `clone.py:92` derives the saved memory image as `state/<origin>.bak` where
>   the origin is the *sandbox* domain, so a `.bak` only matches the exact LV it
>   was saved against. Rebuilding `ubuntu_sandbox` produces a new one and
>   overwrites it. It is still backed up in C3 because it is 4 GB and covers the
>   other direction — the LV surviving while the repo checkout does not.
> - **Recovery is not immediate.** Restoring the goldens gets the OS images
>   back; the lab does not run again until the sandbox LVs are rebuilt, per OS.
>
> Also worth recording: this step originally read `windows_sandbox`, from
> `CURRENT-STATE` §1.4, which lists Windows as *"`windows_sandbox` (LV only)"*
> with no golden domain. **§1.4 is out of date** — `lvs` below shows a `windows`
> LV of 128G. That needs a superseded-facts row.

EVIDENCE C2

```
root@drakvuf:~# xl list                      # golden domains should not be running
Name                                        ID   Mem VCPUs	State	Time(s)
Domain-0                                     0  8192     6     r-----    1304.0
root@drakvuf:~# vgs vg-root                  # VFree must cover the snapshots below
  VG      #PV #LV #SN Attr   VSize     VFree   
  vg-root   1   7   0 wz--n- <1022,00g <318,00g
root@drakvuf:~# lvs vg-root
  LV              VG      Attr       LSize   Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  android         vg-root -wi-a-----  32,00g                                                    
  android_sandbox vg-root -wi-a-----  32,00g                                                    
  lv-root         vg-root -wi-ao---- 256,00g                                                    
  ubuntu          vg-root -wi-a-----  64,00g                                                    
  ubuntu_sandbox  vg-root -wi-a-----  64,00g                                                    
  windows         vg-root -wi-a----- 128,00g                                                    
  windows_sandbox vg-root -wi-a----- 128,00g                                                    
root@drakvuf:~# # DOM0
for lv in ubuntu android windows_sandbox; do
    lvcreate -s -L 4G -n "${lv}-bk" "/dev/vg-root/${lv}" || continue
done
lvs vg-root | grep -- -bk
  Logical volume "ubuntu-bk" created.
  Logical volume "android-bk" created.
  Logical volume "windows_sandbox-bk" created.
  android-bk         vg-root swi-a-s---   4,00g      android         0,00                                   
  ubuntu-bk          vg-root swi-a-s---   4,00g      ubuntu          0,00                                   
  windows_sandbox-bk vg-root swi-a-s---   4,00g      windows_sandbox 0,00   
```

## C3. Back up (DOM0)

Block devices use the `name.img:` form (fixed index); directories use
`name.pxar:` (dynamic index).

> ## The datastore does not obviously have room
>
> §0's evidence came back tighter than this runbook assumed:
>
> ```
> PBS datastore    1.8T size, 1.6T used, 211G available, 89% full
> the three LVs    64 + 32 + 128  =  224G provisioned
> ```
>
> Thick LVs are read block by block, so 224G is what the client walks.
> Never-written blocks are zeros and cost almost nothing stored, so the figure
> should land well below 224G — **but 211G free is not a comfortable margin and
> nothing here can predict the number.**
>
> **This also inverts Part A and Part C.** The "coarse safety net first" advice
> at the top of this runbook assumed space was free. It is not: `vzdump 101`
> reads VM 101's whole 1022G virtual disk *including `lv-root`'s 256G* — Dom0's
> root, holding the DRAKVUF build and the repo checkout, both reproducible.
> **Part C is now both the smaller job and the more valuable one. Do it first
> and treat Part A as optional.**
>
> Before starting, try to reclaim space. Pruning only *marks* chunks; garbage
> collection is what frees them, and it is the step most often missed:
>
> ```bash
> # PBS
> proxmox-backup-manager garbage-collection start datastore1
> proxmox-backup-manager task list
> df -h /backup/datastore1
> ```

**Two invocations, smallest and most irreplaceable first.** One `backup` call
is one snapshot: if it runs out of space partway, nothing in it is finalised.
Splitting means a space failure on the 224G half still leaves the 4G half
safely stored.

```bash
# DOM0 -- ~4 GB, and the hardest things here to reconstruct by hand
cd /root/drakvuf-multios-sandbox

proxmox-backup-client backup \
    state.pxar:./state \
    profiles.pxar:./profiles \
    etc.pxar:/etc \
    --backup-type host --backup-id dom0-critical --ns dom0 \
    --keyfile /root/.config/proxmox-backup/encryption-key.json
```

`/etc` carries `libvmi.conf`, the Xen boot configuration,
`/etc/sandboxd/sandboxd.env` and the TLS material — small, and every one of
them is hand-made.

```bash
# DOM0 -- 224 GB walked, far less stored. This is the long one.
proxmox-backup-client backup \
    ubuntu.img:/dev/vg-root/ubuntu \
    android.img:/dev/vg-root/android \
    windows.img:/dev/vg-root/windows \
    --backup-type host --backup-id dom0-golden --ns dom0 \
    --keyfile /root/.config/proxmox-backup/encryption-key.json
```

Each archive names the LV it reads, so there is no cleanup step and no way for
a name to disagree with its target. **Do not boot a golden domain while this
runs** — that is the one condition §C2 verified, and it is now the only thing
protecting the read.

EVIDENCE C3

```
root@drakvuf:~/drakvuf-multios-sandbox# proxmox-backup-client backup     state.pxar:./state     profiles.pxar:./profiles     etc.pxar:/etc     --backup-type host --backup-id dom0-critical     --keyfile /root/.config/proxmox-backup/encryption-key.json --ns dom0
Starting backup: [dom0]:host/dom0-critical/2026-08-27T19:56:08Z    
Client name: drakvuf    
Starting backup protocol: Thu Aug 27 21:56:08 2026    
Using encryption key from '/root/.config/proxmox-backup/encryption-key.json'..    
Encryption Key Password: ****************************************************************************************************************************************************************
Encryption key fingerprint: 4f:15:85:70:27:c5:c4:c0    
No previous manifest available.    
Upload directory './state' to 'x90sh@pbs!client1@192.168.1.5:8007:datastore1' as state.pxar.didx    
state.pxar: had to backup 3.983 GiB of 3.985 GiB (compressed 988.206 MiB) in 35.51 s (average 114.855 MiB/s)
state.pxar: backup was done incrementally, reused 1.978 MiB (0.0%)
Upload directory './profiles' to 'x90sh@pbs!client1@192.168.1.5:8007:datastore1' as profiles.pxar.didx    
profiles.pxar: had to backup 108.465 MiB of 108.465 MiB (compressed 8.432 MiB) in 0.33 s (average 329.868 MiB/s)
Upload directory '/etc' to 'x90sh@pbs!client1@192.168.1.5:8007:datastore1' as etc.pxar.didx    
etc.pxar: had to backup 10.971 MiB of 10.971 MiB (compressed 1.413 MiB) in 0.44 s (average 24.775 MiB/s)
Uploaded backup catalog (106.861 KiB)
Duration: 41.83s    
End Time: Thu Aug 27 21:56:49 2026 

root@drakvuf:~/drakvuf-multios-sandbox# proxmox-backup-client backup \
    ubuntu.img:/dev/vg-root/ubuntu \
    android.img:/dev/vg-root/android \
    windows.img:/dev/vg-root/windows \
    --backup-type host --backup-id dom0-golden \
    --keyfile /root/.config/proxmox-backup/encryption-key.json --ns dom0
Starting backup: [dom0]:host/dom0-golden/2026-08-27T19:57:09Z    
Client name: drakvuf    
Starting backup protocol: Thu Aug 27 21:57:09 2026    
Using encryption key from '/root/.config/proxmox-backup/encryption-key.json'..    
Encryption Key Password: ****************************************************************************************************************************************************************
Encryption key fingerprint: 4f:15:85:70:27:c5:c4:c0    
No previous manifest available.    
Upload image '/dev/vg-root/ubuntu' to 'x90sh@pbs!client1@192.168.1.5:8007:datastore1' as ubuntu.img.fidx    
processed 21.898 GiB in 1m, uploaded 7.387 GiB
processed 44.727 GiB in 2m, uploaded 13.246 GiB
processed 55.875 GiB in 3m, uploaded 22.629 GiB
ubuntu.img: had to backup 24.422 GiB of 64 GiB (compressed 8.388 GiB) in 198.28 s (average 126.126 MiB/s)
ubuntu.img: backup was done incrementally, reused 39.578 GiB (61.8%)
Upload image '/dev/vg-root/android' to 'x90sh@pbs!client1@192.168.1.5:8007:datastore1' as android.img.fidx    
processed 14.445 GiB in 1m, uploaded 6.859 GiB
android.img: had to backup 7.328 GiB of 32 GiB (compressed 2.971 GiB) in 79.27 s (average 94.668 MiB/s)
android.img: backup was done incrementally, reused 24.672 GiB (77.1%)
Upload image '/dev/vg-root/windows' to 'x90sh@pbs!client1@192.168.1.5:8007:datastore1' as windows.img.fidx    
processed 4.867 GiB in 1m, uploaded 4.449 GiB
processed 9.121 GiB in 2m, uploaded 8.824 GiB
processed 13.043 GiB in 3m, uploaded 12.648 GiB
processed 17.129 GiB in 4m, uploaded 16.711 GiB
processed 25.176 GiB in 5m, uploaded 21.73 GiB
processed 29.332 GiB in 6m, uploaded 26.074 GiB
processed 34.785 GiB in 7m, uploaded 31.34 GiB
processed 44.172 GiB in 8m, uploaded 40.727 GiB
processed 53.688 GiB in 9m, uploaded 50.242 GiB
processed 68.211 GiB in 10m, uploaded 64.801 GiB
processed 80.879 GiB in 11m, uploaded 77.434 GiB
processed 93.5 GiB in 12m, uploaded 90.055 GiB
windows.img: had to backup 93.59 GiB of 128 GiB (compressed 29.208 GiB) in 768.32 s (average 124.735 MiB/s)
windows.img: backup was done incrementally, reused 34.41 GiB (26.9%)
Duration: 1052.12s    
End Time: Thu Aug 27 22:14:41 2026    
```

---

# Part D — the platform's data (PVE)

> ## D0. CORRECTION — as first written, this part backed up nothing
>
> `pg_dump` went to `/tmp` on the *host* while `vzdump 102` captured the
> *container*, so the dump was never collected. Survivable only while Part A
> was mandatory; §C3 made Part A optional and this was not revisited, leaving
> Postgres and MinIO with no backup at all. §D1 and §D2 replace it — the dump
> itself is fine and only needs to land somewhere collected. See
> [TROUBLESHOOTING](../TROUBLESHOOTING.md#a-backup-step-that-backed-up-nothing).

## D1. Dump Postgres *inside* the container (PVE)

Writing it into the container's own filesystem means the existing container
backup collects it, with no new credentials, no encryption key on a second
machine, and no new software anywhere.

Confirm the database name from `/etc/sandbox-platform/` or the API's
environment first — do not assume it.

```bash
# PVE
pct exec 102 -- sh -c 'mkdir -p /var/backups/platform && chown postgres:postgres /var/backups/ -R'
pct exec 102 -- su - postgres -c \
    'pg_dump -Fc sandbox_platform > /var/backups/platform/sandbox_platform.dump'
pct exec 102 -- ls -la /var/backups/platform/
```

A logical dump is worth having *in addition to* the filesystem backup: it
restores into a different Postgres version and survives a corrupted cluster,
neither of which a file-level copy of `/var/lib/postgresql` can do.

## D2. `vzdump 102` — and this one is NOT optional

**Container backups are file-level; VM backups are block-level.** That single
difference is why `vzdump 101` was demoted to optional and `vzdump 102` is not:

| | Reads | Cost against 211G free |
|---|---|---|
| `vzdump 101` (VM) | the whole 1022G virtual disk, allocated or not | the reason Part A was demoted |
| `vzdump 102` (LXC) | **only files that exist** | a few GB — the artifacts actually stored |

So the 256G `mp0` MinIO volume costs whatever MinIO has really written, not
256G. This is the cheapest item in the whole runbook and it covers Postgres,
MinIO, the API source and §D1's dump in one command.

```bash
# PVE
vzdump 102 --storage pbs-backup --mode snapshot \
    --notes-template 'platform: postgres + minio + D1 dump'
```

```bash
# PBS -- confirm it landed
proxmox-backup-client list --repository datastore1 --ns proxmox
```

**After the migration this stops working** — the platform becomes a Xen DomU
and there is no `vzdump`. It will need its own `proxmox-backup-client`
invocation from inside itself, of the same shape as §C3. Recorded here so the
migration does not silently drop the platform's backups.

EVIDENCE D

```
root@pve1:~# pct exec 102 -- sh -c 'mkdir -p /var/backups/platform && chown postgres:postgres /var/backups/ -R'
pct exec 102 -- su - postgres -c \
    'pg_dump -Fc sandbox_platform > /var/backups/platform/sandbox_platform.dump' 
pct exec 102 -- ls -la /var/backups/platform/
total 60
drwxr-xr-x 2 postgres postgres  4096 Aug 27 20:14 .
drwxr-xr-x 4 postgres postgres  4096 Aug 27 20:14 ..
-rw-r--r-- 1 postgres postgres 50941 Aug 27 20:15 sandbox_platform.dump

root@pve1:~# vzdump 102 --storage pbs1 --mode snapshot     --notes-template 'platform: postgres + minio + D1 dump'
INFO: starting new backup job: vzdump 102 --mode snapshot --storage pbs1 --notes-template 'platform: postgres + minio + D1 dump'
INFO: Starting Backup of VM 102 (lxc)
INFO: Backup started at 2026-08-27 22:16:17
INFO: status = running
INFO: CT Name: platform
INFO: including mount point rootfs ('/') in backup
INFO: excluding volume mount point mp0 ('/srv/minio') from backup (disabled)
INFO: backup mode: snapshot
INFO: ionice priority: 7
INFO: create storage snapshot 'vzdump'
freeze guest filesystem
  WARNING: You have not turned on protection against thin pools running out of space.
  WARNING: Set activation/thin_pool_autoextend_threshold below 100 to trigger automatic extension of thin pools before they get full.
  Logical volume "snap_vm-102-disk-0_vzdump" created.
  WARNING: Sum of all thin volume sizes (<6.63 TiB) exceeds the size of thin pool pve/data and the size of whole volume group (<1.82 TiB).
thaw guest filesystem
INFO: creating Proxmox Backup Server archive 'ct/102/2026-08-27T20:16:17Z'
INFO: set max number of entries in memory for file-based backups to 1048576
INFO: run: lxc-usernsexec -m u:0:100000:65536 -m g:0:100000:65536 -- /usr/bin/proxmox-backup-client backup --crypt-mode=encrypt --keyfd=12 pct.conf:/var/tmp/vzdumptmp624410_102/etc/vzdump/pct.conf root.pxar:/mnt/vzsnap0 --include-dev /mnt/vzsnap0/./ --skip-lost-and-found --exclude=/tmp/?* --exclude=/var/tmp/?* --exclude=/var/run/?*.pid --backup-type ct --backup-id 102 --backup-time 1787861777 --entries-max 1048576 --repository x90sh@pbs!client1@pbs1.tailcd681c.ts.net:datastore1 --ns proxmox
INFO: Starting backup: [proxmox]:ct/102/2026-08-27T20:16:17Z    
INFO: Client name: pve1    
INFO: Starting backup protocol: Thu Aug 27 22:16:18 2026    
INFO: Using encryption key from file descriptor..    
INFO: Encryption key fingerprint: 7b:c9:b4:05:63:84:7c:a9    
INFO: Downloading previous manifest (Thu Aug 27 21:32:38 2026)    
INFO: Upload config file '/var/tmp/vzdumptmp624410_102/etc/vzdump/pct.conf' to 'x90sh@pbs!client1@pbs1.tailcd681c.ts.net:8007:datastore1' as pct.conf.blob    
INFO: Upload directory '/mnt/vzsnap0' to 'x90sh@pbs!client1@pbs1.tailcd681c.ts.net:8007:datastore1' as root.pxar.didx    
INFO: root.pxar: had to backup 47.346 MiB of 1.98 GiB (compressed 12.995 MiB) in 5.54 s (average 8.551 MiB/s)
INFO: root.pxar: backup was done incrementally, reused 1.934 GiB (97.7%)
INFO: Uploaded backup catalog (1007.573 KiB)
INFO: Duration: 5.83s    
INFO: End Time: Thu Aug 27 22:16:23 2026    
INFO: adding notes to backup
INFO: cleanup temporary 'vzdump' snapshot
  Logical volume "snap_vm-102-disk-0_vzdump" successfully removed.
INFO: Finished Backup of VM 102 (00:00:07)
INFO: Backup finished at 2026-08-27 22:16:24
INFO: Backup job finished successfully
INFO: notified via target `mail-to-root`

root@pbs1:~# proxmox-backup-client list --repository datastore1 --ns proxmox
┌────────┬─────────────────────────────┬──────────────┬────────────────────────────────────────────────────────┐
│ group  │ last snapshot               │ backup-count │ files                                                  │
╞════════╪═════════════════════════════╪══════════════╪════════════════════════════════════════════════════════╡
│ ct/102 │ ct/102/2026-08-27T20:16:17Z │            2 │ catalog.pcat1 client.log index.json pct.conf root.pxar │
├────────┼─────────────────────────────┼──────────────┼────────────────────────────────────────────────────────┤
│ vm/101 │ vm/101/2026-08-27T19:20:26Z │            2 │ client.log drive-scsi0.img index.json qemu-server.conf │
└────────┴─────────────────────────────┴──────────────┴────────────────────────────────────────────────────────┘
```

---

# Part E — verify a restore

**Nothing above counts until this passes.** Every prior part produced a belief.

## E1. Restore a golden LV to scratch (DOM0)

> ### CORRECTION — `restore` will not write onto an existing device
>
> The step originally pre-created the LV and named it as the restore target,
> which can never work: `restore` creates its target and refuses on `EEXIST`.
> **Use `-` and stream onto the device**, which also avoids 64G of scratch. See
> [TROUBLESHOOTING](../TROUBLESHOOTING.md#proxmox-backup-client-restore--file-exists-os-error-17):
>
> ```bash
> # DOM0
> proxmox-backup-client restore host/dom0-golden/<timestamp> \
>     ubuntu.img - --ns dom0 \
>     --keyfile /root/.config/proxmox-backup/encryption-key.json \
>   | dd of=/dev/vg-root/restore-test bs=4M status=progress
> ```

> ### This datastore uses TWO namespaces, and no command here said so
>
> None of the commands as written passed `--ns`, and the evidence shows the
> lab is in fact split across two:
>
> | Namespace | Holds | Written by |
> |---|---|---|
> | **`dom0`** | `dom0-critical`, `dom0-golden` | Dom0's own `proxmox-backup-client` (§C3) |
> | **`proxmox`** | `ct/102`, and `vm/101` if Part A ran | `vzdump` on PVE — the namespace comes from the `pvesm add pbs` storage config, not from the command line (see the client invocation `vzdump` logs at §D2) |
>
> **A command with the wrong `--ns`, or none, does not error — it reports
> nothing found**, which reads exactly like a backup that was never taken. That
> is the failure mode to watch for in this Part.
>
> So: `--ns dom0` for everything below, because §E restores what §C3 wrote.
> Use `--ns proxmox` when checking or restoring the container backup.

```bash
# DOM0
proxmox-backup-client snapshot list --ns dom0
vgs vg-root                        # confirm VFree >= 64G before creating this
lvcreate -L 64G -n restore-test vg-root

# sizes must match, or dd silently truncates the tail of the image
blockdev --getsize64 /dev/vg-root/ubuntu
blockdev --getsize64 /dev/vg-root/restore-test

proxmox-backup-client restore host/dom0-golden/<timestamp> \
    ubuntu.img - --ns dom0 \
    --keyfile /root/.config/proxmox-backup/encryption-key.json \
  | dd of=/dev/vg-root/restore-test bs=4M status=progress
```

**Check `dd`'s byte count against `blockdev --getsize64`.** A short write is
the one failure mode this pipeline hides: `restore` exiting non-zero mid-stream
still leaves `dd` reporting success for what it did receive, and a truncated
image can still mount if the damage falls past the filesystem's last used
block. `set -o pipefail` if you wrap this in a script.

> ### Cheaper alternative when you only want to *look* at an image
>
> `map` exposes the archive as a read-only block device without materialising
> it — no LV, no disk space, no wait:
>
> ```bash
> # DOM0
> proxmox-backup-client map host/dom0-golden/<timestamp> ubuntu.img --ns dom0 \
>     --keyfile /root/.config/proxmox-backup/encryption-key.json
> # prints a /dev/loopN -- mount it read-only, inspect, then:
> proxmox-backup-client unmap /dev/loopN
> ```
>
> Good for §E2's filesystem check and for spot-checking any future backup.
> **Not** a substitute for the full restore below: it is read-only and remote,
> so it cannot be booted, and it proves the chunks *read* rather than proving a
> real restore reproduces a working volume.

## E2. Prove it is a real filesystem, then boot it

Cheap check first:

```bash
# DOM0
kpartx -a /dev/vg-root/restore-test
lsblk /dev/vg-root/restore-test
fdisk -l /dev/vg-root/restore-test        # partition table sane?

# A MOUNT IS NOT A CHECK -- run fsck, see below
e2fsck -f -y /dev/mapper/vg--root-restore--test5

mount -o ro /dev/mapper/vg--root-restore--test5 /mnt
ls /mnt
umount /mnt
kpartx -d /dev/vg-root/restore-test
```

> ### `mount -o ro` plus `ls` is not evidence of a good image
>
> Added 2026-08-28, after a restored golden mounted cleanly, listed a complete
> root tree, and then dropped its guest to an initramfs shell on the first cold
> boot with *"Inode … has an invalid extent node"*.
>
> `ls` walks directory entries. It does not validate extents, reference counts,
> or the journal — and a filesystem can be badly damaged in ways that never
> touch the directories you happen to list. **`e2fsck -f` is the check; the
> mount is a convenience.**
>
> Two further traps in the same area:
>
> - **`mount -o ro` on ext4 still replays the journal.** It is not a read-only
>   operation on a dirty filesystem — it writes. Use `-o ro,norecovery` if the
>   image must not be modified, and be aware that a "read-only" verification
>   mount can silently change what you are verifying.
> - **The corruption in that incident was not in the backup.** `e2fsck` on the
>   restored golden came back clean with no repairs. The damage was inflicted
>   afterwards, by restoring a `state/*.bak` onto a disk it had not been saved
>   from. So this step is a *verification*, not a defence against §C2 — reading
>   the quiescent LVs directly, without snapshots, produced a sound image.
>
> `windows.img` needs `chkdsk` from a Windows recovery environment; `e2fsck`
> only covers the Ubuntu and Android images.

Then the real one. **Booting it is the test that matters** — a mountable
filesystem is not the same as a bootable golden image. Copy `misc/ubuntu.cfg`,
point `disk=` at `restore-test`, give it a distinct `name=`, and leave it on
`xenbr0` exactly as the golden domain is.

```bash
# DOM0
sed -e 's|/dev/vg-root/ubuntu|/dev/vg-root/restore-test|' \
    -e 's|^name.*|name = "restore-test"|' \
    misc/ubuntu.cfg > /tmp/restore-test.cfg
diff misc/ubuntu.cfg /tmp/restore-test.cfg      # read this before creating
xl create /tmp/restore-test.cfg
xl list
# connect with vncviewer per the golden-domain procedure, confirm it boots
```

## E3. Clean up

```bash
# DOM0
xl destroy restore-test
lvremove -f /dev/vg-root/restore-test
lvs vg-root
```

EVIDENCE E

```
restore completed:        Y
filesystem mounted:       Y
domain booted:            Y
scratch LV removed:       Y

e2fsck -f:                not run at the time -- this step did not exist yet.
                          Run retrospectively on the restored golden 2026-08-28:
                          181581/4161536 files, 4936400/16645376 blocks,
                          passes 1-5 clean, NO repairs. The backup was sound.
```

---

# Part F — schedule and retention

**What this part is for, and what is actually load-bearing.** Parts A–E produce
one backup, verified once. Part F is what stops that from being the only one —
and on this datastore, two of its three pieces are not optional:

| | Without it | Urgency here |
|---|---|---|
| **F1 timer** | the backup ages. In a month it restores a month-old lab | do it, but it can wait a day |
| **F2 prune + GC** | the datastore fills and **future backups start failing** | **the datastore is already 89% full** |
| **F2 verify** | silent corruption on the PBS disk is discovered during a restore, which is the worst possible moment | the only thing that checks the backup is still readable |

The verify job is the one that looks skippable and is not. §E proves the backup
was good *when written*; nothing else here ever re-reads it.

If time is short, **F2 before F1** — a backup that fails to write because the
disk is full is worse than one that runs weekly instead of nightly.

## F1. A timer on Dom0

`sandboxd` deliberately has no systemd unit (`CURRENT-STATE` §1.2). That
reasoning does not extend here — a backup is exactly the kind of thing that
should run without an operator remembering it.

> ### The scheduled run SHOULD snapshot, unlike §C3
>
> §C2 dropped snapshots because an operator can read `xl list`, see only
> `Domain-0`, and start the backup seconds later. **A timer cannot.** Nothing
> watches at 03:00, and the golden domains are booted occasionally — during a
> sandbox rebuild, or to update an image. A script that checks `xl list` and
> then reads the LV is a check-then-act race; `lvcreate -s` is atomic.
>
> So the unattended path pays the snapshot cost that the manual one does not.
> This is a real difference between the two, not an inconsistency.

Write `/usr/local/sbin/pbs-backup.sh` taking an `lvcreate -s -L 4G` snapshot
per golden LV, backing up the snapshots, and removing them in an `EXIT` trap so
a failed run leaves nothing behind. Then a `.service` + `.timer` pair reading
`EnvironmentFile=/etc/pbs-backup.env`.

**Guard the archive names.** The `-bk` indirection is what produced this
runbook's `windows.img:/dev/vg-root/windows_sandbox-bk` bug. In a script, derive
both sides from one list rather than writing them out twice:

```sh
for lv in ubuntu android windows; do
    set -- "$@" "${lv}.img:/dev/vg-root/${lv}-bk"
done
```

**Do not schedule it against the analysis workload.** The snapshots slow every
write to the origin while they exist, and §F7c of
`09-verify-sandboxd-and-console.md` establishes Dom0's DRAKVUF thread as the
lab's bottleneck. Pick an hour when nothing is expected to be tracing, and have
the script exit early if `xl list` shows more than `Domain-0`.

EVIDENCE F1

```
(paste systemctl list-timers for the unit, and one successful triggered run)
```

## F2. Retention, from the PBS side

Prune runs on PBS, not Dom0 — §0.1 deliberately withheld prune rights from the
Dom0 token so a compromised Dom0 cannot erase its own history.

```bash
# PBS
proxmox-backup-manager prune-job create dom0-golden \
    --store <datastore> --schedule daily \
    --keep-daily 7 --keep-weekly 4 --keep-monthly 6
proxmox-backup-manager verify-job create dom0-verify \
    --store <datastore> --schedule 'sat 02:00'
```

**The verify job matters more than it looks.** It re-reads and checksums
stored chunks, which is how silent corruption on the PBS disk is found while
there is still a good copy elsewhere, rather than during a restore.

Retention interacts with an open decision — `DRAFT-041` on artifact retention,
and `DRAFT-022`'s GDPR position, since pcaps carry third-party traffic. The
numbers above are a starting point, not a decision.

EVIDENCE F2

```
(paste the job listings and the first verify result)
```

---

# Decision summary

| Question | Answer | Evidence |
|---|---|---|
| Datastore free space, against what must fit | | 0 |
| Did `vzdump 101` complete, and how large was it? | | A2 |
| Which client approach worked — B2, B3 or neither? | | B4 |
| **Where did the off-host copy of the encryption key go?** | | C1 |
| Did GC reclaim enough to clear 224G comfortably? | | C3 |
| Did `vzdump 102` run, and how large was it? | | D2 |
| Total size of the per-LV backup | | C3 |
| **Did a restored golden image boot?** | | E2 |
| Which namespace holds what — `dom0` vs `proxmox`? | | E1 |
| Were the leftover `-bk` snapshots removed, and the scratch LV? | | C2 / E3 |
| Timer schedule, and does it avoid analysis hours? | | F1 |
| Retention chosen, and is it consistent with DRAFT-041? | | F2 |

**Part A alone changes the lab's risk profile more than everything else here
combined**, because it moves the state from one copy to two. Parts B–F make
that survivable across the migration and repeatable without an operator. If the
session runs out of time, stop after Part A **and §E** — never after a backup
that has not been restored.

---

# Sources

- [Proxmox Backup Server documentation](https://pbs.proxmox.com/docs/)
- [`proxmox-backup-client` usage](https://pbs.proxmox.com/docs/backup-client.html)
- [PBS client on non-Proxmox hosts](https://pbs.proxmox.com/docs/installation.html#client-installation)
- [`vzdump` — PVE backup](https://pve.proxmox.com/pve-docs/chapter-vzdump.html)
- [PBS user management and ACL paths](https://pbs.proxmox.com/docs/user-management.html)
- [LVM snapshot sizing — `lvcreate(8)`](https://man7.org/linux/man-pages/man8/lvcreate.8.html)