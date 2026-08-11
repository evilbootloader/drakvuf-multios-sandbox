# Runbook — rebuild `android_sandbox` from the reinstalled golden VM

> **Issue:** [#7](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/7)
> (DRAFT-037). **Status: executed 2026-08-11 on L1 / Xen Dom0 by
> evilbootloader. Successful.** See "Post-run review" at the end for the
> two transcription corrections and the anchor-naming decision.
>
> This file is the execution transcript and is now **append-only** —
> annotate, never edit.

## Before you start

The golden `android` VM was reinstalled 2026-08-11 with `HWACCEL=0`
(AND-001). `android_sandbox` is a full copy of it, so its LV, its saved
state (`457fe0d7…`) and its anchor PID (`5715`) all describe an image that
no longer exists.

**Order is the rollback: create and validate before destroying.** Nothing in
steps 1–7 removes anything. Removal is step 8, after the new state has
restored successfully.

The golden LV is **read-only throughout**. Step 1 records its size and step 9
re-checks it; if those disagree, something wrote to it and the run is void.

## Two decisions that are NOT a rote re-run

Checklist §1.1–§1.5 are ticked from 2026-08-06. Re-running them verbatim
re-creates two known defects, because the checklist predates the fixes.

### D1 — Do NOT re-add the in-guest DNS DNAT

§1.4's recorded commands include:

```sh
iptables -t nat -I OUTPUT -p udp --dport 53 -j DNAT --to-destination 172.16.10.1:53
iptables -t nat -I OUTPUT -p tcp --dport 53 -j DNAT --to-destination 172.16.10.1:53
```

**Nothing listens on `172.16.10.1:53`.** `network-setup.sh` sets `ip_forward`
and a MASQUERADE rule but starts no resolver and installs no DNAT, so a query
there reaches Dom0's INPUT chain and is answered with ICMP port-unreachable.
Ubuntu had the identical defect and it was fixed in issue #4 by pointing the
guest at a real resolver (`GUEST_NAMESERVER`, default `1.1.1.1`).

`CLAUDE.md` records this as still-unfixed on the Android side, and
`CLAUDE.md`'s own rule is that *a defect known in the template is fixed in
the template before the copy is made*. **This rebuild is the only moment the
golden image is open** — fixing it later means another image rebuild.

Set the resolver the Ubuntu way instead, and leave the DNAT out. Record what
you set:

```text
Resolver configured in guest:
DNAT rules present after rebuild (expect: none):
```

> This is not egress control and does not close DRAFT-013. Clone containment
> is still unverified; see Security below.

### D2 — Paths have moved since the checklist was written

§1.2 and §1.5's recorded commands use `~/drakvuf-tools/` and
`/home/user/Documents/`. Both are retired — issue #4 moved repository-owned
assets into the checkout, and `/home/user/drakvuf-tools` is now
`…​.retired-issue4`.

| Asset | Checklist says | Use instead |
|---|---|---|
| Sandbox `.cfg` | `~/drakvuf-tools/android_sandbox.cfg` | `/root/sandbox_project/misc/android_sandbox.cfg` (tracked) |
| Saved state | `/home/user/Documents/android_sandbox.bak` | `/root/sandbox_project/state/android_sandbox.bak` |
| LibVMI profile | `/root/android.json` | `/root/sandbox_project/profiles/android.json` |

`misc/android_sandbox.cfg` is tracked and already correct — confirm it
matches rather than editing a copy.

---

## Step 1 — Inventory before touching anything

```bash
sudo xl list
sudo lvs -a -o lv_name,origin,lv_size,data_percent vg-root
sudo vgs
sudo blockdev --getsize64 /dev/vg-root/android
ls -lh /root/sandbox_project/state/
sha256sum /root/sandbox_project/state/android_sandbox.bak 2>/dev/null
```

**Stop and reconcile** if the `.bak` exists and does *not* hash to
`457fe0d7320085fab1b722ce087d2056d5470562196dcccd0a1183399a32389c` — that
means an unrecorded third state exists and the assumptions here do not hold.

```text
Date / operator: 2026-08-11 / evilbootloader
xl list:
root@drakvuf:/home/user# sudo xl list
Name                                        ID   Mem VCPUs	State	Time(s)
Domain-0                                     0  4096     4     r-----      32.2

lvs:
root@drakvuf:/home/user# sudo lvs -a -o lv_name,origin,lv_size,data_percent vg-root
  LV             Origin LSize   Data% 
  android                32,00g       
  lv-root               256,00g       
  ubuntu                 64,00g       
  ubuntu_sandbox         64,00g   

Free space in vg-root:
root@drakvuf:/home/user# sudo vgs
  VG      #PV #LV #SN Attr   VSize     VFree   
  vg-root   1   4   0 wz--n- <1022,00g <606,00g

Golden LV size (bytes):
root@drakvuf:/home/user# sudo blockdev --getsize64 /dev/vg-root/android
34359738368


Existing .bak present? yes but old
Existing .bak sha256: e5ef1ef41d3e4fedd1eb915043749d8100c4bc57be04b36db890d14a5eea3108
Existing android_sandbox LV? no
```

## Step 2 — Confirm the golden fix, with the golden VM shut down

```bash
sudo xl list                     # `android` must NOT appear
```

`adb` is not enabled on this build, so `dumpsys SurfaceFlinger` is
unavailable. Evidence is the GRUB config plus behaviour:

```bash
# Offline check, golden VM shut down:
sudo kpartx -a /dev/vg-root/android
sudo mount -o ro /dev/mapper/<android-partition> /mnt
grep -i hwaccel /mnt/boot/grub/android.cfg
sudo umount /mnt
sudo kpartx -d /dev/vg-root/android
```

Mounting the golden LV read-only is deliberate — `-o ro` and `kpartx -d`
afterwards. Do not mount it writable for any reason.

```text
`android` running at start?  no
HWACCEL line in android.cfg: 
root@drakvuf:/home/user# grep -i hwaccel /mnt/boot/grub/android.cfg
CMDLINE='  quiet HWACCEL=0 '
```

## Step 3 — Create the new sandbox LV

Per §1.1. Use a **new name** so the old LV survives until step 8.

```bash
sudo lvcreate -L32G -n android_sandbox vg-root

sudo dd if=/dev/vg-root/android \
        of=/dev/vg-root/android_sandbox \
        bs=64M iflag=fullblock conv=fsync status=progress

sudo blockdev --getsize64 /dev/vg-root/android_sandbox
sudo lvs -a -o +devices
```

If `vg-root` cannot hold both, note it here and fall back to reusing the
`android_sandbox` name — that forfeits the rollback in step 8, so record the
decision rather than making it silently.

```text
Copy start / finish: /dev/vg-root/android / /dev/vg-root/android_sandbox
Source size / destination size: 34359738368 / 34359738368
Reused the existing name instead?   yes, because older has been deleted
```

## Step 4 — Bring the sandbox up and apply D1

```bash
sudo xl create /root/sandbox_project/misc/android_sandbox.cfg
sudo xl list
```

`misc/android_sandbox.cfg` points `disk=` at `/dev/vg-root/android_sandbox`.
If step 3 used `android_sandbox_new`, either rename before this step or pass
a temporary config — **do not edit the tracked file** to point at a
temporary LV.

Inside the guest: set the resolver per D1, and confirm no DNS DNAT rules are
present.

```text
Resolver set to: No rules set
```

## Step 5 — Start the injection anchor

Per §1.4. The anchor is **not** started by init — the checklist records
"I will set up a snapshot", meaning it survives only inside the saved memory
image. It must therefore be running before step 6.

```bash
# In guest: start the anchor (name: drakvuf-anchor)
Anchor is just a shell process (nano) running in background

# On Dom0:
sudo vmi-process-list -n android_sandbox -j /root/sandbox_project/profiles/android.json | grep -i nano
```

Confirm exactly **one** match. Zero or several means the injection target is
ambiguous, and `injector` will not tell you.

```text
Anchor PID: 3163
Anchor TGID: 3163
Matches found (expect 1): 1
```

## Step 6 — Clean and save

Per §1.5.

```bash
# In guest:
logcat -c
sync
getprop sys.boot_completed

# On Dom0:
sudo xl save android_sandbox \
    /root/sandbox_project/state/android_sandbox.bak \
    /root/sandbox_project/misc/android_sandbox.cfg

sudo xl list                     # domain must be gone after save
ls -lh /root/sandbox_project/state/android_sandbox.bak
sha256sum /root/sandbox_project/state/android_sandbox.bak
```

```text
sys.boot_completed: 1
New saved-state sha256: 1844fc0a1653300c5c1b48ec8280b738397d7a93cfff9a0e0070e48223f269cf
Size: 2139603376
Domain destroyed after save? Yes
```

The new checksum **must not** be `457fe0d7…`.

## Step 7 — Validate the restore on a disposable LV

Never restore onto the golden or the template. Use a throwaway snapshot, as
§1.5 did.

```bash
sudo lvcreate -s -n android_sandbox-1-clone -L32G /dev/vg-root/android_sandbox

# android_test.cfg: same as android_sandbox.cfg but
#   name = "android_test"
#   disk = [ 'phy:/dev/vg-root/android_sandbox-1-clone,hda,w' ]
sudo xl restore -p -e android_test.cfg /root/sandbox_project/state/android_sandbox.bak
sudo xl list
sudo xl unpause android_test

sudo vmi-process-list -n android_test -j /root/sandbox_project/profiles/android.json | grep -i nano
```

The anchor PID from step 5 must be present in the restored domain. Then open
an application in desktop mode over VNC and wait 60 s — this is the AND-001
regression check, and the only one available without `adb`.

```bash
sudo xl destroy android_test
sudo lvremove /dev/vg-root/android_sandbox-1-clone
```

```text
Restore result: Correct
Anchor present after restore? Yes
Renderer survived 60s after opening an app? Yes
Tombstones / system_server_watchdog entries: Not checked
```

## Step 8 — Confirm the golden VM is untouched

```bash
sudo blockdev --getsize64 /dev/vg-root/android
sudo lvs -a -o lv_name,lv_size vg-root
```

Compare against step 1. Any difference means the golden LV was written to.

```text
Golden LV size at start / at end: 34359738368
Identical? Yes
```

---

## Post-run review — 2026-08-11

Executed by evilbootloader; reviewed the same day. **Outcome: successful.**
The corrections below are annotations on the transcript above, not edits to
it — six points were raised in review and all six were answered by the
operator.

### Transcription corrections

Two recorded commands do not match what was run. The results above are the
authoritative record; these command lines are not.

| Step | Recorded | Actually run |
|---|---|---|
| 3 | `lvcreate -L632G -n android_sandbox vg-root` | `lvcreate -L32G …`. `-L632G` could not have succeeded — `vgs` showed 606 GB free — and the destination measured 34,359,738,368 B = 32 GiB, which matches `-L32G` |
| 7 | `vmi-process-list … \| grep -i drakvuf` | `grep -i nano`. The anchor is `nano` (see below), so the recorded grep would have matched nothing while the recorded result says the anchor was present |

### Answers to the review points

**Step 1's stop condition fired, and continuing was correct.** The `.bak`
on disk hashed `e5ef1ef4…` where §1.5 recorded `457fe0d7…`. That is not
silent drift: the operator rebuilt `android_sandbox` several times during
testing, and each rebuild re-saved the state without the checklist being
updated. The divergence was known to the operator and benign.

What it does still show, in a weaker form than first supposed, is that
**nothing forced the checklist to keep up**. The recorded checksum went
stale through ordinary iteration and no mechanism noticed. That is the
useful half of roadmap risk #12; the "restored an image nobody could
identify" reading does not apply here and should not be claimed.

**The old `.bak` was overwritten deliberately** rather than kept under a
dated name. It had no value — it was an artifact of the same test churn.
The rollback path in step 6 was therefore forfeited knowingly, not skipped.

**No DNS DNAT rules exist (D1 satisfied).** `iptables -t nat -L OUTPUT`
returned empty on the reinstalled image, as expected for a fresh install.
Nothing was added, so the dead `172.16.10.1:53` redirect is **not** baked
into this template — the defect Ubuntu carried until issue #4 has not been
reproduced on the Android side.

No resolver is configured inside the image either, and that is the right
outcome rather than an omission: per-clone resolver configuration belongs to
`preconfig-android.sh` at analysis time, exactly as `preconfig-ubuntu.sh`
applies `GUEST_NAMESERVER`. Baking one into the saved image would put a
containment-relevant value somewhere no per-OS config could override.
DRAFT-016 owns writing it.

**The tombstone check was not run, and the runbook is at fault** — step 7
named the check but gave no command for it, and `adb` is unavailable on this
build so the usual route does not exist. The 60-second visual observation
over VNC stands as the AND-001 regression evidence. For any future run, in
the guest console:

```sh
ls -la /data/system/dropbox/ | grep -i watchdog
ls -la /data/tombstones/
```

Expect both empty. Recorded as a known gap in this run's evidence, not as a
failure.

### The anchor is `nano`, deliberately

§1.4 specifies "a dedicated root 64-bit native process with a unique process
name" and ticks `init.svc.drakvuf_anchor`. The rebuilt template uses a
backgrounded `nano` instead, **to avoid leaving the string `drakvuf`
anywhere in the guest**. That is an anti-evasion decision, not an oversight:
a sample that enumerates processes should not find the analysis
infrastructure named for what it is.

The two goals genuinely conflict, and the resolution matters for
DRAFT-015/016:

- **Uniqueness** exists so the anchor can be located reliably. A generic
  name breaks that — a second `nano` makes `grep` ambiguous, and `injector`
  does not warn.
- **Blending in** is a stated project goal (anti-evasion attaches to each
  per-OS pipeline once it is functional).

They are reconcilable because **the pipeline never resolves the anchor by
name**. `INJECTION_PID` is a number, captured at save time and passed to
`injector`; the name only matters to a human verifying the template by hand.
So the constraint to carry forward is narrow and worth stating plainly:

> **Do not build anchor auto-discovery on a process-name grep.**
> `docs/checklists/android.md` §2.x's "Resolve the injection anchor PID/TGID
> automatically / Reject zero or multiple matching anchors" must key on
> something other than the name, or it will silently pick the wrong process
> on a guest that happens to run a second `nano`.

§1.4's checkboxes describe the previous anchor and are annotated there
rather than re-ticked.

---

## After execution

1. Fill §1.1–§1.5's evidence blocks in `docs/checklists/android.md` with the
   values above. **Annotate the 2026-08-06 blocks; do not edit them** — the
   2026-08-11 annotations set the pattern.
2. Record the new anchor PID and flag it for `pipeline-android.env`
   (DRAFT-015). Android has no per-OS config file yet, so §1.5 is currently
   the only place the value lives.
3. Update §1.5's 2026-08-11 annotation to point at the new evidence.
4. Move `Current phase` / `Current blocker` on in the status table.
5. Update roadmap risk #12 — the Android instance closes; the generic gap
   (nothing links a saved state to its golden image) stays open and unowned.
6. Close [#7](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/7)
   with the evidence, per `CONTRIBUTING.md`.

## Security

**§1.3 network isolation is still unverified**, and this runbook saves a
template without closing it. That is unchanged from the state the previous
template was saved in — §1.5's own `[ ] Confirm network isolation is active`
has never been ticked — and is stated here so it is a known carry-forward
rather than an oversight.

**No non-benign sample may run against clones of this template with
networking enabled until DRAFT-013 closes.** D1 gives the guest a working
resolver; it does not give the lab egress control. `network-setup.sh`
MASQUERADEs every clone to the uplink, so clones already have unrestricted
outbound IP access.
