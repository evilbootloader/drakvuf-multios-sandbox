# Android DRAKVUF Automated Analysis — Implementation Checklist and Command Log

> **Purpose:** Working checklist for building, testing, and recording the Android malware-analysis automation derived from the current Ubuntu automation scripts.
>
> Tick each item only after the command output or another form of evidence has been recorded.
>
> Commands labelled **Existing** come from the current project files. Commands labelled **Candidate** are proposed commands and must be validated in this environment before being treated as final documentation.

---

## Project status

| Field | Value |
|---|---|
| Project owner | evilbootloader |
| Xen Dom0 host | on-prem pc |
| Android build | BlissOS x86_64 |
| Golden VM/domain | `android` |
| Sandbox VM/domain | `android_sandbox` |
| Android LibVMI profile | `profiles/android.json` (repo-relative since issue #4; was `/root/android.json`) |
| Volume group | `vg-root` |
| Isolated bridge | `xenbr1` |
| Start date | 2026-08-06 |
| Last update | 2026-08-14 |
| Current phase | Phase 2 — Android automation scripts (not started, **now unblocked**). Phase 1 complete: template rebuilt and restore-validated 2026-08-11 (issue #7), ROM rebuilt with EthernetConfig and re-validated 2026-08-14 (DRAFT-013) |
| Current blocker | **None for containment — cleared 2026-08-14 (DRAFT-013, `docs/runbooks/verify-android-isolation.md`).** An Android clone booted on `xenbr1.1` under the current rules, probed its gateway with ICMP, had 10 packets dropped by `DRAKVUF_INPUT`, and validated the network anyway — the posture is robust rather than lucky, and no ICMP exemption is needed. Failed IPv6 provisioning did not change its verdict. Connectivity parity was established in the same run and is in §1.6. **Two constraints still bind Phase 2:** `preconfig-android.sh` must set `private_dns_mode off` or the pcap records DoT instead of DNS queries (§1.6), and clones retain deliberate NAT egress, so no non-benign sample should run with networking enabled until the `offline`/`simulated` modes exist (DRAFT-022) |

### Status legend

- [ ] Not started
- [x] Completed and evidenced
- `BLOCKED:` Waiting on a dependency or unresolved fault
- `SKIPPED:` Deliberately excluded, with reason recorded

---

## General evidence template

Copy this block under a task when more evidence is needed.

```text
Status:
Date:
Operator:
Host / layer: L0 Proxmox | L1 Xen Dom0 | L2 Android guest
Command(s):
Result:
Expected result:
Files changed:
Logs / evidence:
Issue or follow-up:
Git commit:
```

---

# Phase 0 — Preserve and verify the working baseline

## 0.1 Record platform versions

- [x] Record the Proxmox version -> pve-manager/9.2.6/7f8d010005bd72cb
- [x] Record the L0 kernel version -> 7.0.14-8-pve
- [x] Record the Xen version -> V4.20
- [x] Record the Xen Dom0 kernel version -> 6.8.0-136-generic
- [x] Record the DRAKVUF version and Git commit -> DRAKVUF v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel
- [x] Record the LibVMI version and Git commit -> commit df8547ff075d4352db2eb802775b7fa7a92756db (HEAD)
- [x] Record the `lfreijo/drakvuf` branch and revision -> commit 52df0bc8044d3033af3259312787560dbb8caa12 (HEAD -> memdump, lfreijo/memdump)
- [x] Record the Android/BlissOS build identifiers -> In android/Artifacts
- [x] Record the Android kernel version -> Linux localhost 6.6.129-crimson-xanmod1 #1 SMP PREEMPT_DYNAMIC Thu Aug 6 09:54:46 UTC 2026 x86_64 Android
- [x] Record the checksum of `android.json` -> 9505bdc9987df066142e82cf6abeb1c5bb30e59a9ec7dc4f63ef6b8902f440af  android.json

### Commands used

### Evidence and notes

#### Record the Android/BlissOS build identifiers
```text
source build/envsetup.sh
lunch bliss_x86_64-trunk_staging-userdebug

OUT_DIR_PATH="$(get_build_var PRODUCT_OUT)"

{
    echo "Recorded: $(date --iso-8601=seconds)"
    echo
    echo "TARGET_PRODUCT=$(get_build_var TARGET_PRODUCT)"
    echo "TARGET_BUILD_VARIANT=$(get_build_var TARGET_BUILD_VARIANT)"
    echo "TARGET_BUILD_TYPE=$(get_build_var TARGET_BUILD_TYPE)"
    echo "TARGET_ARCH=$(get_build_var TARGET_ARCH)"
    echo "TARGET_DEVICE=$(get_build_var TARGET_DEVICE)"
    echo "PRODUCT_OUT=$OUT_DIR_PATH"
    echo
    echo "BUILD_ID=$(get_build_var BUILD_ID)"
    echo "BUILD_NUMBER=$(get_build_var BUILD_NUMBER)"
    echo "PLATFORM_VERSION=$(get_build_var PLATFORM_VERSION)"
    echo "PLATFORM_VERSION_CODENAME=$(get_build_var PLATFORM_VERSION_CODENAME)"
    echo "PLATFORM_SECURITY_PATCH=$(get_build_var PLATFORM_SECURITY_PATCH)"
} | tee "$OUT_DIR_PATH/build-identifiers.txt"

{
    echo "BLISS_VERSION=${BLISS_VERSION:-unknown}"
    echo "BLISS_BUILD_VERSION=${BLISS_BUILD_VERSION:-unknown}"
    echo "BLISS_CODENAME=${BLISS_CODENAME:-unknown}"
    echo "BLISS_BUILD_VARIANT=${BLISS_BUILD_VARIANT:-unknown}"
    echo "BLISS_BUILDTYPE=${BLISS_BUILDTYPE:-unknown}"
} >> "$OUT_DIR_PATH/build-identifiers.txt"

repo manifest -r -o "$OUT_DIR_PATH/source-manifest.xml"

repo status > "$OUT_DIR_PATH/repo-status.txt"

repo forall -c '
    if ! git diff --quiet || ! git diff --cached --quiet; then
        echo "===== $REPO_PATH ====="
        git status --short
        git diff
        git diff --cached
    fi
' > "$OUT_DIR_PATH/local-changes.patch"

find "$OUT_DIR_PATH" \
    \( -name build.prop -o -name system-build.prop -o -name vendor-build.prop \) \
    -print \
    -exec grep -E \
    '^(ro\.(build|product|system|vendor|system_ext|odm)\.)' {} \; \
    > "$OUT_DIR_PATH/generated-build-properties.txt"

KERNEL_OUT="$OUT_DIR_PATH/obj/kernel"

{
    echo "Kernel source revision:"
    git -C kernel/x86/common rev-parse HEAD
    git -C kernel/x86/common describe --always --dirty --tags 2>/dev/null || true

    echo
    echo "Kernel release:"
    make -s -C kernel/x86/common \
        O="$KERNEL_OUT" \
        kernelrelease 2>/dev/null || true

    echo
    echo "Compiler:"
    grep '^CONFIG_CC_VERSION_TEXT=' "$KERNEL_OUT/.config" || true
} > "$OUT_DIR_PATH/kernel-identifiers.txt"

cp "$KERNEL_OUT/.config" "$OUT_DIR_PATH/kernel-config.txt"

sha256sum \
    "$KERNEL_OUT/vmlinux" \
    "$KERNEL_OUT/System.map" \
    >> "$OUT_DIR_PATH/kernel-identifiers.txt"

find "$OUT_DIR_PATH" -maxdepth 1 \
    \( -name '*.iso' -o -name '*.img' -o -name '*.zip' \) \
    -type f -exec sha256sum {} \; \
    > "$OUT_DIR_PATH/artifact-checksums.sha256"
```

---

## 0.2 Preserve reproducibility artifacts

- [x] Copy `android.json` to a versioned backup directory.
- [x] Copy `android.cfg` and `android_sandbox.cfg`.
- [x] Preserve the BlissOS kernel `.config`.
- [x] Preserve the pinned Android manifest.
- [x] Preserve local Android source patches.
- [x] Preserve the ISO checksum.
- [x] Preserve the existing Ubuntu automation scripts before editing anything.
- [x] Extract and inventory `drakvuf-tools.zip`.

### Existing ZIP inventory

The uploaded ZIP currently contains:

```text
clone-ubuntu.pl
drakvuf-ubuntu.sh
preconfig-ubuntu.sh
run_analysis-ubuntu.sh
```

The current Ubuntu launcher also references files not present in that ZIP:

```text
network-setup.sh
cleanup.sh
tcpdump.sh
linux_sandbox.cfg
```

- [x] Locate and preserve the missing referenced files.

### Commands used

### Evidence and notes

```text
Backup directory:
Missing files located at:
Checksum file:
```

---

## 0.3 Verify the Android guest boot state

- [x] Start `android` from a powered-off state.
- [x] Confirm the domain remains running.
- [x] Confirm Android reaches userspace.
- [x] Confirm `zygote` is running. 
- [x] Confirm `surfaceflinger` is running.
- [ ] Confirm `sys.boot_completed=1`.
- [ ] Confirm the Android kernel matches the kernel used for `android.json`.

### Commands used

```bash
# Run on L1 / Xen Dom0
root@drakvuf:/home/user/drakvuf-tools# vmi-process-list android | grep -Ei "zygote|surface"
[ 1682] surfaceflinger (struct addr:ffff9b771058bf00)
[ 2172] webview_zygote (struct addr:ffff9b778da46900)

root@drakvuf:/home/user/drakvuf-tools# vmi-process-list android | grep init
[    1] init (struct addr:ffff9b7701290000)
[ 1352] init (struct addr:ffff9b7701fae900)
```

> **Annotation 2026-08-11 — the evidence above is superseded by a
> reinstall.** It was captured against the *first* golden `android` install.
> That image rendered through Mesa llvmpipe and its `surfaceflinger` died on
> the first window opened in desktop mode (AND-001), so "Confirm
> `surfaceflinger` is running" was true at the moment sampled and false
> shortly afterwards — a process list cannot distinguish the two.
>
> The golden VM was **reinstalled with `HWACCEL=0` on 2026-08-11**. The
> remaining unchecked boxes should be re-run against that image, not the one
> above; `sys.boot_completed=1` is already known to fire on it. Nothing in
> the block above is edited — it records what was observed on 2026-08-06.

### Evidence and notes

```text

```

---

## 0.4 Verify LibVMI and DRAKVUF against Android

- [x] Confirm the `android` profile is present in `/etc/libvmi.conf`.
- [x] Confirm the `android_sandbox` profile is present in `/etc/libvmi.conf`.
- [x] Enumerate Android processes through LibVMI.
- [x] Run DRAKVUF briefly with a minimal plugin set.
- [x] Test every intended plugin separately.
- [x] Save one known-good startup log for future comparisons.

### Commands used

```bash
sudo grep -n -A4 -B1 -E '^android(_sandbox)?[[:space:]]*\{' /etc/libvmi.conf
sudo vmi-process-list android
```

```bash
# Candidate minimal monitoring run; validate supported options first.
sudo timeout 120 drakvuf \
    -r /root/android.json \
    -d android \
    -o json \
    -a syscalls \
    > /tmp/android-drakvuf-baseline.json 2> /tmp/android-drakvuf-baseline.err
```

### Plugin validation matrix

| Plugin | Starts | Produces events | Guest stable | Notes / log path |
|---|---:|---:|---:|---|
| `syscalls` | [x] | [x] | [x] | |
| `filetracer` | [x] | [x] | [x] | |
| `fileextractor` | [x] | [x] | [x] | |
| `memdump` | [x] | [x] | [x] | |
| Other: | [x] | [ ] | [ ] | |

### Evidence and notes

```text

```

---

# Phase 1 — Build the Android sandbox VM

## 1.1 Create the `android_sandbox` LV

- [x] Confirm the golden `android` VM is shut down before copying.
- [x] Confirm `/dev/vg-root/android` exists.
- [x] Confirm there is enough free space in `vg-root`.
- [x] Create `/dev/vg-root/android_sandbox`.
- [x] Copy the golden Android LV into the sandbox LV.
- [x] Verify both block devices have the expected size.

### Commands used

```bash
# Existing project pattern, adapted from the Ubuntu sandbox procedure.
sudo xl shutdown android
sudo xl list

sudo lvs
sudo vgs
sudo blockdev --getsize64 /dev/vg-root/android

sudo lvcreate \
    -L64G \
    -n android_sandbox \
    vg-root

sudo dd \
    if=/dev/vg-root/android \
    of=/dev/vg-root/android_sandbox \
    bs=64M \
    iflag=fullblock \
    conv=fsync \
    status=progress

sudo blockdev --getsize64 /dev/vg-root/android_sandbox
sudo lvs -a -o +devices
```

### Evidence and notes

```text
Copy start:
Copy finish:
Source size:
Destination size:
```

> **Re-run 2026-08-11 (issue #7) against the reinstalled golden VM.** The
> block above is the 2026-08-06 record and is left as-is. The LV was
> recreated from scratch; the golden LV is 32 GiB, not the `-L64G` the
> command block above uses.
>
> ```text
> lvcreate -L32G -n android_sandbox vg-root
> dd if=/dev/vg-root/android of=/dev/vg-root/android_sandbox \
>    bs=64M iflag=fullblock conv=fsync status=progress
>
> Source size:      34359738368  (/dev/vg-root/android)
> Destination size: 34359738368  (/dev/vg-root/android_sandbox)
> vg-root free before: <606,00g of <1022,00g
> Golden VM shut down for the duration: yes (`xl list` showed Domain-0 only)
> ```
>
> No previous `android_sandbox` LV existed at the time of this run, so the
> create-alongside rollback in the runbook was not needed.
> Full transcript: `docs/runbooks/rebuild-android-sandbox.md`.

---

## 1.2 Create `android_sandbox.cfg`

- [x] Copy the working Android configuration.
- [x] Change the domain name to `android_sandbox`.
- [x] Change the disk to `/dev/vg-root/android_sandbox`.
- [x] Remove the installer ISO.
- [x] Connect the sandbox to `xenbr1`, not the production bridge.
- [x] Keep `altp2m = 2`.
- `SKIPPED: Not needed by now` Keep serial console access for troubleshooting.
- [x] Set lifecycle behavior suitable for debugging during setup. 
- [x] Validate the config with `xl create`.

### Candidate configuration

```python
arch = 'x86_64'
name = "android_sandbox"
maxmem = 2048
memory = 2048
vcpus = 1
maxvcpus = 1
builder = "hvm"
boot = "c"
hap = 1
on_reboot   = "restart"
on_crash    = "destroy"
on_poweroff = "destroy"
on_watchdog = "destroy"
vnc = 1
vnclisten = "127.0.0.1"
vga = "stdvga"
usb = 1
usbdevice = "tablet"
audio = 1
#soundhw = "hda"
viridian = 1
altp2m = 2
shadow_memory = 32
vif = [ 'type=ioemu,model=e1000,script=vif-openvswitch,bridge=xenbr1' ]
disk = [ 'phy:/dev/vg-root/android_sandbox,hda,w' ]
```

### Commands used

```bash
cp /path/to/android.cfg ~/drakvuf-tools/android_sandbox.cfg
editor ~/drakvuf-tools/android_sandbox.cfg

sudo xl create ~/drakvuf-tools/android_sandbox.cfg
sudo xl list
sudo xl list -l android_sandbox
sudo xl console android_sandbox
```

### Evidence and notes

```text
Final config path: drakvuf-tools/android_sandbox.cfg
Boot result: Successful
```

---

## 1.3 Verify sandbox network isolation

- [x] Confirm `xenbr1` exists.
- [x] Confirm `xenbr1` is up.
- [x] Confirm the sandbox VIF is attached to the expected bridge or OVS VLAN port.
- [x] Confirm there is no route from the analysis network to the management
  network. *(2026-08-11, DRAFT-028. Measured on Ubuntu clones — the
  mechanism is shared and matches on interface, not on guest OS.
  **Re-measured on an Android clone 2026-08-14, DRAFT-013:** the LAN probe
  was dropped by `DRAKVUF_ISOLATION` rule 4 — `192.168.0.0/16`, 2 packets —
  and `ping` to a LAN host returned 100% loss from inside the guest.)*
- [x] **Confirm Android tolerates the rules.** *(2026-08-14, DRAFT-013 —
  `docs/runbooks/verify-android-isolation.md`. It probed the gateway with
  ICMP, `DRAKVUF_INPUT` dropped 10 packets, and it reported "Internet
  through Ethernet" regardless. This is the row §1.3 could not fill while
  every measurement came from Ubuntu.)*
- [ ] ~~Confirm there is no Internet access by default.~~ **Premise
  conflicts with the decided policy** — clones have deliberate NAT egress.
  Needs re-scoping against the network modes in
  `docs/architecture/networking.md`; see note 2 below. Not a failed test.
- [x] Confirm IPv6 is either isolated or disabled. *(2026-08-11: isolated.
  Blanket DROP in `DRAKVUF_ISOLATION6`/`DRAKVUF_INPUT6`, counter-confirmed.
  It was previously neither — no v6 rules existed at all. **2026-08-14: and
  Android does not mind.** It sent router solicitations to `ff02::2` from
  16:14 to 16:31, all 8 dropped by `DRAKVUF_INPUT6`, obtained no v6 address,
  and still validated the network with no visible complaint. `ISOLATION6`
  stayed at 0, correctly — RS is link-local multicast to Dom0, so it is
  `INPUT`, not `FORWARD`.)*
- [x] Record the intended per-clone VLAN design. *(One `xenbr1.<vlan>`
  sub-interface per clone slot, `172.16.<vlan>.1/24` gateway on Dom0,
  clone at `.2`. `docs/architecture/networking.md`.)*


### Commands used

```bash
# Run on L1 / Xen Dom0
ip -br link
ip -br addr
bridge link
sudo ovs-vsctl show
sudo xl network-list android_sandbox
sudo nft list ruleset
sudo iptables-save
sudo ip6tables-save
```

```sh
# Run inside L2 / Android guest
ip -br link 2>/dev/null || ip link
ip addr
ip route
ip -6 route
getprop | grep -iE 'dns|net\.'
```

### Isolation test record

| Test | Expected | Actual | Passed |
|---|---|---|---:|
| Reach Xen Dom0 analysis gateway | Only intended service ports | Blocked entirely — see note 1 | [x] |
| Reach Xen Dom0 management IP | Blocked | Blocked | [x] |
| Reach Proxmox management IP | Blocked | Blocked by the RFC1918 rules — not separately addressed, see note 3 | [x] |
| Reach another LAN host | Blocked | Blocked | [x] |
| Reach Internet IPv4 | Blocked | **ALLOWED, by design** — see note 2 | [ ] |
| Reach Internet IPv6 | Blocked | Blocked | [x] |

### Evidence and notes

**Filled 2026-08-11 from the DRAFT-028 deployment**, transcript in
`docs/runbooks/deploy-network-isolation.md` steps 8 and 8b.

> **Read the provenance before relying on this table.** The measurements
> were taken from **Ubuntu** analysis clones, not Android ones. That is
> sound for the rows above because the mechanism is
> `automation/network-setup.sh`, one of the four shared scripts: its rules
> match on interface (`-i xenbr1.+`), never on anything guest-specific, so
> a clone of any OS on an analysis VLAN is filtered identically. What it
> does **not** establish is Android-specific behaviour — see "Still open
> for Android" below.

Measured from a clone on `172.16.1.2`, with per-rule packet counters
confirming the rules fired rather than the traffic simply never existing:

```text
clone -> other clone (172.16.2.2)     blocked
clone -> gateway 172.16.1.1 (ping)    blocked
clone -> gateway 172.16.1.1 (HTTP)    blocked
clone -> router 192.168.1.1 (ping)    blocked
clone -> router 192.168.1.1 :80       blocked
clone -> router 192.168.1.1 :443      blocked
clone -> LAN host                     blocked
clone -> 1.1.1.1 (HTTPS)              WORKS   -- deliberate, see note 2
clone -> DNS via 1.1.1.1              WORKS   -- deliberate, see note 2
Dom0  -> clone (ping)                 works   -- ESTABLISHED,RELATED exception

DRAKVUF_ISOLATION counters:  3 pkts on the clone-to-clone DROP
                            14 pkts on the 192.168.0.0/16 DROP
DRAKVUF_INPUT6 counter:     20 pkts (2397 bytes)
```

**Note 1 — the gateway is now fully blocked, not port-restricted.** The
original expectation ("only intended service ports") assumed the clone
needed something from Dom0. It needs nothing: ARP is L2 and unfiltered,
addresses are static so no DHCP, the resolver is `1.1.1.1` and therefore
forwarded rather than local, and sample delivery and tracing are VMI
operations with no network path at all. So the row is satisfied more
strictly than it asked.

**Note 2 — "no Internet access by default" is NOT the lab's policy, and
this row is left unticked deliberately.** `network-setup.sh` MASQUERADEs
every clone to the uplink; that is the current deliberate default, stated
in the script and in `docs/architecture/networking.md`. The row records an
expectation that predates the decision and conflicts with it. It is **not**
a failed test — it is a checklist item that needs re-scoping against the
`offline` / `simulated` / `controlled-internet` modes proposed in the
networking doc, none of which exist yet. Do not "fix" it by blocking
egress without deciding that question first.

**Note 3 — the Proxmox management IP was not addressed directly.** It is
covered by the `10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16`
destination DROPs, so it is blocked whichever of those ranges it sits in.
Ticked on that basis rather than on a targeted probe; if the L0 host is
reachable at a public address, this row is not covered and needs re-testing.

**IPv6 was a live hole, not a latent one.** Before DRAFT-028 there were no
`ip6tables` rules at all (`-P INPUT ACCEPT`, `-P FORWARD ACCEPT`) and
`net.ipv6.conf.all.disable_ipv6 = 0`. Dom0's own VLAN gateway interface
carries an `fe80::` address, and a clone that runs
`ip link set eth0 down; ip link set eth0 up` regenerates its link-local —
confirmed on 2026-08-11. The clone then sent 20 packets at Dom0's
link-local and `DRAKVUF_INPUT6` dropped every one. Before the change those
packets would have arrived.

**The mechanism these rows test never worked until 2026-08-11.** The
previous inter-clone rule was `-o !xenbr0`, which current iptables accepts
while storing `!xenbr0` as a *literal interface name* — one that has never
existed. It installed cleanly, appeared in `iptables -S`, and matched
nothing. Every analysis run before that date, Ubuntu and Android alike, had
the rule present and inert. See `docs/runbooks/deploy-network-isolation.md`
step 2 and roadmap risk #5.

### Still open for Android specifically

The rules are OS-independent; the guest's reaction to them is not. None of
the following is established, and DRAFT-013 should carry them:

- **Whether an Android clone tolerates an unreachable gateway.** Android
  does connectivity probing and may mark the network unvalidated when it
  cannot reach its gateway. Ubuntu does not care; Android might. First boot
  of a clone after this lands is the case to watch.
- **Whether Android attempts IPv6 and how it behaves when dropped.** The
  v6 rules are blanket DROP with no ICMPv6 exception, so neighbour
  discovery is dropped too.
- **Whether Android's own DNS path honours the injected resolver.** The
  golden image previously carried an in-guest DNAT to `172.16.10.1:53`;
  that was not re-applied when the template was rebuilt (§1.4 annotation),
  so per-clone resolver configuration is `preconfig-android.sh`'s to write
  and does not exist yet (DRAFT-016).

---

## 1.4 Create a dedicated long-lived injection process

- [x] Decide whether to use a custom native anchor or an existing stable Android process.
- [x] Prefer a dedicated 64-bit native process with a unique process name.
- [x] Build or install the anchor in the Android lab image.
- [x] Create an Android init service for the anchor -> `androidboot.enable_console=1` in GRUB, ALT+F1 or ALT+F2 +  `dmesg -n 1`
- [x] Start the anchor automatically at boot. -> I will set up a snapshot
- [x] Confirm the process remains alive for at least 30 minutes.
- [x] Confirm the process is visible through `vmi-process-list`.
- [x] Record PID and TGID behavior across three boots.
- [x] Confirm the anchor creates no unnecessary files, sockets, or recurring logs.
- [x] Set dns


### Commands used

```sh
settings put global private_dns_mode off

iptables -t nat -I OUTPUT -p udp --dport 53 \
    -j DNAT --to-destination 172.16.10.1:53

iptables -t nat -I OUTPUT -p tcp --dport 53 \
    -j DNAT --to-destination 172.16.10.1:53
```

```bash
# On L1 / Xen Dom0
sudo vmi-process-list android_sandbox | grep -i drakvuf
```

### PID/TGID observations

| Android PID | LibVMI PID/TGID | Runtime stable | Notes |
|---:|---:|---:|---|
| 5715 |  5715  | Yes | Pre-reinstall image; superseded — see below |
| 3163 |  3163  | Yes | 2026-08-11 rebuild (issue #7); exactly one match. Superseded — see below |
| 3164 |  3164  | Yes | Undated re-save before DRAFT-013; saved state `516644e2…`. Superseded |
| 3174 |  3174  | Yes | **Current.** 2026-08-17 re-save; saved state `465aa4d7…`; backgrounded `ping` |

> **Re-run 2026-08-11 (issue #7). Two things above no longer describe the
> template**, and both are deliberate rather than drift. The block above is
> the 2026-08-06 record and is left as-is.
>
> **1. The anchor is a backgrounded `nano`, not `drakvuf-anchor`.** Chosen
> so the string `drakvuf` appears nowhere in the guest — a sample that
> enumerates processes should not find the analysis infrastructure named for
> what it is. That is an anti-evasion decision and it conflicts with the
> ticked item "Prefer a dedicated 64-bit native process with a unique
> process name", which is now **not** satisfied. `init.svc.drakvuf_anchor`
> does not exist on this image either.
>
> The conflict is real but narrow, because **the pipeline never resolves the
> anchor by name** — `INJECTION_PID` is a number captured at save time and
> passed to `injector`. The name matters only to a human verifying by hand.
> The constraint that follows:
>
> > **Do not build anchor auto-discovery on a process-name grep.** §7.2's
> > "Resolve the injection anchor PID/TGID automatically / Reject zero or
> > multiple matching anchors" must key on something other than the name, or
> > a guest that happens to run a second `nano` gets the wrong process
> > injected — and `injector` does not warn.

> **Re-run 2026-08-17. The `nano` anchor was replaced, because it could not
> be injected into.** The 2026-08-11 block above is left as written.
>
> **Why it had to change.** `nano` was backgrounded on a console VT and took
> `SIGTTIN` on its first tty read, so `xl save` captured it **stopped**.
> `injector` waits for the target PID to be scheduled onto a vCPU, has no
> timeout, and prints nothing while waiting — so on every clone restored
> from that image, every injection hung silently and forever. It was
> reachable only by switching to the console VT and typing `fg`, one
> injection per nudge. Full diagnosis and evidence:
> `docs/runbooks/verify-android-mvp.md` F1.
>
> **This invalidates §1.5's "Confirm the injection anchor is running".** A
> `vmi-process-list` match proves the task *exists*; it says nothing about
> whether it is ever *scheduled*, which is the property `injector` actually
> needs. The two are not the same check and the checklist conflated them.
>
> **The replacement is a backgrounded `ping` against loopback**, PID 3174,
> saved state `465aa4d7…`. Self-scheduling — one packet per interval, no
> tty, no fork — and because the target is `127.0.0.1` **nothing reaches the
> vif**, so `tcpdump.sh`'s per-sample pcaps stay free of anchor traffic and
> nothing appears on the analysis VLAN. The anti-evasion constraint above is
> unchanged: the string `drakvuf` appears nowhere, and the name-grep warning
> still applies.
>
> **Acceptance evidence:** three full analyses completed with no console
> interaction. That is nine consecutive injections (two per preconfig, one
> per trace), against zero unattended injections under `nano`.
>
> **New requirements this episode adds for any future anchor**, all
> evidenced rather than assumed:
>
> 1. **It must be scheduled on its own.** Existence is not enough. The
>    acceptance test is three back-to-back `writefile`s on a fresh clone
>    with the console untouched, or one full unattended analysis.
> 2. **It must run as root.** `preconfig-android.sh` imports
>    `/data/system/environ/classpath`, which is `0600 system:system`. A
>    non-root anchor reads nothing, `app_process64` aborts 134, and the
>    clone's network configuration fails **silently**
>    (`verify-android-mvp.md` F5).
> 3. **It must be 64-bit.** `injector --help`: the Linux `execproc` path is
>    64-bit only.
> 4. **It must not put traffic on the analysis VLAN.** The anchor runs for
>    the whole analysis and `tcpdump.sh` captures the vif throughout, so
>    anything it emits lands in the primary network evidence for every
>    sample. Loopback satisfies this; an external ping target would not.
> 5. **It should not hold a console VT**, so the guest can sit on the
>    Android GUI rather than a text console (F7).
>
> The ticked item "Confirm the anchor creates no unnecessary files, sockets,
> or recurring logs" is **partially** satisfied rather than fully: `ping`
> holds a raw socket and wakes on an interval by construction. It writes no
> files and no logs, and emits nothing observable outside the guest, which
> is the part that matters for evidence integrity.
>
> **2. The DNS DNAT was NOT re-applied.** `iptables -t nat -L OUTPUT` was
> empty on the reinstalled image and nothing was added, so the redirect to
> `172.16.10.1:53` in the command block above is **not** present in this
> template. Nothing has ever listened at that address: `network-setup.sh`
> sets `ip_forward` and MASQUERADE but starts no resolver and installs no
> DNAT, so queries there reach Dom0's INPUT chain and get ICMP
> port-unreachable. Ubuntu carried the identical defect until issue #4.
>
> No resolver is configured in the image at all, which is the intended
> outcome: per-clone resolver configuration belongs to
> `preconfig-android.sh` at analysis time, the way `preconfig-ubuntu.sh`
> applies `GUEST_NAMESERVER`. Baking one in would put a
> containment-relevant value where no per-OS config could override it.
> DRAFT-016 owns writing it. **This closes the Android half of the
> `CLAUDE.md` known issue** that recorded the dead DNAT as still unfixed.


### Evidence and notes

```text

```

---

## 1.5 Clean and save the sandbox memory state

- [x] Remove all test samples and packages.
- [x] Clear temporary files created during setup.
- [x] Clear old logcat buffers where appropriate.
- [x] Confirm Android is fully booted.
- [x] Confirm the injection anchor is running.
- [ ] Confirm network isolation is active.
- [x] Record the anchor PID/TGID at save time.
- [x] Save the sandbox VM.
- [x] Confirm the domain is destroyed after `xl save`.
- [x] Restore the saved state once manually and validate it.

### Commands used

```sh
# Inside L2 / Android — adapt cleanup paths to the actual image.
rm -rf /data/local/tmp/drakvuf/*
logcat -c
sync
getprop sys.boot_completed
getprop init.svc.drakvuf_anchor
```

```bash
# On L1 / Xen Dom0
sudo xl save \
    android_sandbox \
    /home/user/Documents/android_sandbox.bak \
    ~/drakvuf-tools/android_sandbox.cfg

sudo xl list
ls -lh /home/user/Documents/android_sandbox.bak
sha256sum /home/user/Documents/android_sandbox.bak
```

### Manual restore validation

```bash
# Use a disposable LV or restore procedure that does not modify the golden sandbox.
# Record the exact tested restore command here.
sudo lvcreate -s -n android_sandbox-1-clone -L64G /dev/vg-root/android_sandbox

user@drakvuf:~/drakvuf-tools$ cat android_test.cfg 
arch = 'x86_64'
name = "android_test"
maxmem = 2048
memory = 2048
vcpus = 1
maxvcpus = 1
builder = "hvm"
boot = "c"
hap = 1
on_reboot   = "restart"
on_crash    = "destroy"
on_poweroff = "destroy"
on_watchdog = "destroy"
vnc = 1
vnclisten = "127.0.0.1"
vga = "stdvga"
usb = 1
usbdevice = "tablet"
audio = 1
#soundhw = "hda"
viridian = 1
altp2m = 2
shadow_memory = 32
vif = [ 'type=ioemu,model=e1000,script=vif-openvswitch,bridge=xenbr1' ]
disk = [ 'phy:/dev/vg-root/android_sandbox-1-clone,hda,w' ]



sudo xl restore -p -e android_test.cfg /home/user/Documents/android_sandbox.bak

vmi-process-list -n android_test -j /root/android.json
```

### Evidence and notes

```text
Saved-state checksum: 457fe0d7320085fab1b722ce087d2056d5470562196dcccd0a1183399a32389c  android_sandbox.bak
Anchor PID/TGID at save: 5715
Restore result: Correct
```

> **Annotation 2026-08-11 — superseded and re-run; artifacts above are
> historical.** The golden `android` VM was reinstalled on 2026-08-11 to
> resolve AND-001, and `android_sandbox` is a copy of the golden, so the
> saved state `457fe0d7…` and anchor PID `5715` both describe an image that
> no longer exists. The ticked boxes above are **not** edited — they are the
> record of what was done on 2026-08-06.
>
> **Re-run completed the same day** under **DRAFT-037 / [issue #7][i7]**.
> Full transcript: `docs/runbooks/rebuild-android-sandbox.md`.
>
> ```text
> Operator / date:       evilbootloader, 2026-08-11 (L1 / Xen Dom0)
> Saved-state path:      /root/sandbox_project/state/android_sandbox.bak
> Saved-state checksum:  1844fc0a1653300c5c1b48ec8280b738397d7a93cfff9a0e0070e48223f269cf
> Saved-state size:      2139603376
> Anchor PID/TGID:       3163  (backgrounded `nano` — see §1.4 annotation)
> sys.boot_completed:    1
> Domain destroyed after xl save: yes
>
> Restore validation (disposable snapshot, golden and template untouched):
>   lvcreate -s -n android_sandbox-1-clone -L32G /dev/vg-root/android_sandbox
>   xl restore -p -e android_test.cfg .../state/android_sandbox.bak
>   xl unpause android_test
>   vmi-process-list -n android_test -j .../profiles/android.json | grep -i nano
>   -> Restore result: Correct.  Anchor present: yes.
>
> AND-001 regression check: application opened in desktop mode over VNC,
>   renderer survived 60 s. (Tombstone/dropbox check not run — the runbook
>   named it but supplied no command, and adb is unavailable on this build.)
>
> Golden LV size before / after: 34359738368 / 34359738368 — unmodified.
> ```
>
> **Still not ticked, and unchanged by this run:** `[ ] Confirm network
> isolation is active`. This template was saved with containment unverified,
> exactly as the previous one was. DRAFT-013 owns it, and no non-benign
> sample may run against clones of this template with networking enabled
> until it closes.
>
> **The new anchor PID must reach `pipeline-android.env`** when DRAFT-015
> creates it. §1.5 is currently the only place the value exists.
>
> [i7]: https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/7
>
> **One thing this run showed about the checklist itself.** At the start of
> the rebuild the `.bak` on disk hashed `e5ef1ef4…`, not the `457fe0d7…`
> recorded above. The cause was benign — the operator rebuilt the template
> several times while testing, and each re-save moved the checksum without
> the checklist being updated. Nothing was lost. What it does show is that
> **nothing forces this record to keep up with the artifact it describes**;
> the value went stale through ordinary iteration and no mechanism noticed.
> That is the half of roadmap risk #12 this run actually evidences.

---

## 1.6 Connectivity parity with Ubuntu — the DRAFT-016 specification

**Measured 2026-08-14 on an Android clone.** Full transcript and evidence in
`docs/runbooks/verify-android-isolation.md`. This section is what
`preconfig-android.sh` is written from; it is a specification, not a summary.

### The result: one framework call replaces the whole `ip` chain

On the pre-EthernetConfig image, five commands were needed — including
`ip route replace … table eth0`, Android's per-network policy routing, which
nothing in the Ubuntu implementation hints at and which a translated script
would never have produced. The ROM was rebuilt with **Bliss-Bass
EthernetConfig** as a platform-signed privileged app
(`docs/android_setup_good.md`), and that entire chain is now subsumed.

| Step | Ubuntu (`preconfig-ubuntu.sh:206`) | Android — measured | Still needed? |
|---|---|---|---|
| privilege | `sudo` on each command | already root; no `sudo` binary, and upstream's `su -c` is dropped too | **n/a** |
| interface | `eth0` | `eth0` | confirmed |
| **prerequisite** | *(none)* | **import `/data/system/environ/classpath`** — without it `app_process64` aborts with exit 134 before `main()` | **YES** |
| link up | *(implicit)* | done by the framework | No |
| flush | `ip addr flush dev eth0` | not needed | No |
| address | `ip addr add 172.16.<vlan>.2/24 dev eth0` | helper's `STATIC` args | No |
| route | `ip route replace default via 172.16.<vlan>.1 dev eth0` | helper's `STATIC` args | No |
| **route (2nd)** | *(none)* | `table eth0` populated by the framework | No — the old trap is gone |
| resolver | `echo 'nameserver …' > /etc/resolv.conf` | helper's `STATIC` args; **no file equivalent exists on Android** | No |
| persistence | *(n/a)* | `/data/misc/ethernet/ipconfig.txt` **not** written — configured live, not persisted | Correct for a disposable clone |
| **private DNS** | *(n/a)* | `settings put global private_dns_mode off` — **not** handled by EthernetConfig | **YES** |
| shell for the chain | `/bin/sh` | `/system/bin/sh` | confirmed |
| verification | `getent hosts google.com` | `ping -c2 google.com` — `getent` absent, bionic ships no such tool | confirmed |

### The sequence

```sh
# 1. ART classpath. Measured NOT already present on this image, so required.
while IFS=' ' read -r action name value; do
    [ "$action" = "export" ] && export "$name=$value"
done < /data/system/environ/classpath

# 2. Address, prefix, gateway AND resolver in one framework call.
#    Note app_process64, not app_process.
APK="$(pm path com.example.ethernetconfig | sed 's/^package://')"
CLASSPATH="$APK" /system/bin/app_process64 / \
    com.example.ethernetconfig.network.EthernetConfigurator \
    STATIC eth0 172.16.<vlan>.2 24 172.16.<vlan>.1 "$GUEST_NAMESERVER" none

# 3. Force plaintext DNS. Not optional -- see below.
settings put global private_dns_mode off
```

Expected: `SUCCESS` from (2), exit 0. Verified from Dom0 rather than inferred
from the guest — the pcap shows `A? connectivitycheck.gstatic.com` leaving
for `1.1.1.1` and being answered.

> **`private_dns_mode off` is a required step, not a tuning knob.** Android
> defaults to `opportunistic` DoT and `1.1.1.1` supports it, so a clone left
> alone resolves over TLS to port 853 and the per-sample pcap records an
> encrypted stream instead of the domains a sample looked up — silently,
> with nothing failing. Evidence and the Dom0-side alternative are in
> `docs/architecture/networking.md`.

> **The single-argv form is untested.** `injector -m execproc` is
> execve-direct with no guest shell (issue #2), and the classpath import is a
> `while` loop, so all three commands must go to `/system/bin/sh -c '…'` as
> one argument. The three are evidenced individually from the console;
> collapsing them is DRAFT-016's work and the quoting is the risk.

### What `preconfig-android.sh` must not assume

- **That the clone starts from a clean network state.** It does not. A
  restored clone holds the *golden* VM's LAN identity (`192.168.1.122`) until
  this runs, and spends its first seconds ARPing for a residential gateway.
  Containment held — the traffic reached nothing — but anything reading the
  interface before configuration sees the wrong network, and the ARP is noise
  in every Android pcap. Runbook finding F4.
- **That the classpath import can be dropped.** Keep it unconditionally; it
  is idempotent and costs nothing.

---

# Phase 2 — Create the Android automation scripts

## 2.0 Version-control the Dom0 working copies

> **Scope clarification (2026-08-09).** This section applies to the working
> copies **on Dom0** — the DRAKVUF source checkout (`~/drakvuf`) and the
> `drakvuf-tools` deployment directory (`~/drakvuf-tools`). Those are the
> trees where DRAKVUF functionality and engine changes get developed, and
> branching and committing there is correct.
>
> It does **not** apply to this repository (`drakvuf-multios-sandbox`).
> Here, `CLAUDE.md` and `CONTRIBUTING.md` govern: no branch, no commit, no
> push without an explicit request; commits are made by the project owner.
> The four script names below also exist here under `automation/`, so the
> commands are ambiguous about which tree they mean unless you read this
> note first.

- [x] Put the automation scripts under version control. *(Done for this
  repository — DRAFT-001, baseline commit `7764b77`. The Dom0 copies are a
  separate question, below.)*
- [ ] Branch the Dom0 DRAKVUF / `drakvuf-tools` checkouts before starting
  Android work.
- [ ] Commit the untouched Ubuntu baseline there.
- [ ] Never modify the only copy of a working script without a commit or backup.

### Commands used

```bash
# On Dom0, in ~/drakvuf-tools (NOT in this repository).
cd ~/drakvuf-tools
git status
git switch -c android-analysis

git add clone-ubuntu.pl drakvuf-ubuntu.sh preconfig-ubuntu.sh run_analysis-ubuntu.sh
git commit -m "Preserve Ubuntu automation baseline"
```

### Evidence and notes

```text
Repository:
Branch:
Baseline commit:
```

---

## 2.1 Create Android script copies

> **Sequencing constraint added 2026-08-09.** Do not run the `cp -a`
> commands below as-is yet. The Ubuntu scripts are a working template but
> carry known defects catalogued in `project-assessment.md`, and copying
> them verbatim duplicates every one of them into the Android pipeline —
> and then into Windows:
>
> - **DRAFT-033** must land first. `clone-ubuntu.pl` has its per-origin
>   `flock` commented out while `dirwatch` runs concurrent workers
>   (DRAKVUF-05), checks no exit status on `lvremove`/`lvcreate`/`xl
>   restore` (DRAKVUF-06), and hard-codes `-L64G`.
> - **DRAFT-027** must land first. `preconfig-ubuntu.sh` stages the sample
>   over HTTP from Apache; that path is being removed outright, so an
>   Android copy must never be built against it. See §5.2.
> - **DRAFT-009** should land first — it defines which scripts are shared
>   versus per-OS, which decides whether some of these copies should exist
>   at all. `cleanup.sh` and `tcpdump.sh` already take only `DOMAIN`/`VLAN`
>   and folders, so the two "decide whether Android needs…" boxes below are
>   that issue's to answer, not this section's.
> - **DRAFT-030** covers the untrusted-filename handling that the last
>   checkbox in §2.7 also demands.
> - **DRAFT-031** covers the licence-header-before-shebang layout
>   (SC1128), which these copies would inherit six more times.
>
> Also note `clone-ubuntu.pl` hard-codes the Ubuntu saved-state path while
> taking the origin domain as an argument, so a naive copy restores Ubuntu
> memory into an Android clone. That one is flagged in the script's own
> header comment.

> **Annotation 2026-08-15 (DRAFT-015) — the clone copy is cancelled, and
> the saved-state warning above is obsolete.**
>
> **There is no `clone-android.pl`.** The file was renamed
> `automation/clone.pl` and is now shared by all three pipelines: it held
> exactly one OS-specific value, `-L64G`, which is now `CLONE_LV_SIZE` in
> `pipeline-<os>.env`. C1/C2 in `analysis-pipeline.md` are amended to
> match. Handed `android_sandbox 1 misc/android_sandbox.cfg`, it reproduces
> byte-for-byte the config `verify-android-isolation.md` step 2 wrote by
> hand — verified 2026-08-15 before the rename was made.
>
> The saved-state paragraph above describes behaviour issue #4 removed on
> 2026-08-09: the path has been derived from the origin argument as
> `<repo root>/state/<origin>.bak` since then, so a naive copy could not
> have restored Ubuntu memory into an Android clone. Left in place as the
> 2026-08-09 record; do not act on it.
>
> DRAFT-033 has **not** landed, and its constraint above still stands for
> the remaining copies. It now applies to `clone.pl`, which makes it more
> pressing rather than less — one file with no exit-status checks now
> serves three pipelines.

- [x] ~~Create `clone-android.pl` from `clone-ubuntu.pl`.~~ Cancelled
      2026-08-15 — `automation/clone.pl` is shared instead. See the
      annotation above.
- [ ] Create `preconfig-android.sh` from `preconfig-ubuntu.sh`.
- [ ] Create `drakvuf-android.sh` from `drakvuf-ubuntu.sh`.
- [ ] Create `run_analysis-android.sh` from `run_analysis-ubuntu.sh`.
- [ ] Decide whether Android needs `cleanup-android.sh`.
- [ ] Decide whether Android needs `tcpdump-android.sh`.
- [ ] Keep shared scripts shared only when their behavior is truly guest-independent.

### Commands used

```bash
cd ~/drakvuf-tools
# NOT run: clone-android.pl is cancelled -- automation/clone.pl is shared.
# cp -a clone-ubuntu.pl clone-android.pl
cp -a preconfig-ubuntu.sh preconfig-android.sh
cp -a drakvuf-ubuntu.sh drakvuf-android.sh
cp -a run_analysis-ubuntu.sh run_analysis-android.sh

chmod 0755 preconfig-android.sh drakvuf-android.sh run_analysis-android.sh
ls -l *-android.*
```

### Evidence and notes

```text

```

---

## 2.2 Add a top-level `run_analysis.sh` dispatcher

- [ ] Create a dispatcher that accepts `ubuntu` or `android`.
- [ ] Reject an unknown target with a nonzero exit code.
- [ ] Display usage when no target is supplied.
- [ ] Preserve the existing Ubuntu launcher.
- [ ] Pass additional arguments through to the selected launcher if needed.

### Candidate implementation

```bash
#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-}"

case "$TARGET" in
    ubuntu)
        shift
        exec "$SCRIPT_DIR/run_analysis-ubuntu.sh" "$@"
        ;;
    android)
        shift
        exec "$SCRIPT_DIR/run_analysis-android.sh" "$@"
        ;;
    *)
        printf 'Usage: %s {ubuntu|android} [arguments...]\n' "$0" >&2
        exit 64
        ;;
esac
```

### Commands used

```bash
editor ~/drakvuf-tools/run_analysis.sh
chmod 0755 ~/drakvuf-tools/run_analysis.sh

~/drakvuf-tools/run_analysis.sh
printf 'exit=%s\n' "$?"

~/drakvuf-tools/run_analysis.sh invalid
printf 'exit=%s\n' "$?"
```

### Test result

| Invocation | Expected | Actual | Passed |
|---|---|---|---:|
| `run_analysis.sh` | Usage, nonzero | | [ ] |
| `run_analysis.sh invalid` | Usage, nonzero | | [ ] |
| `run_analysis.sh ubuntu` | Ubuntu launcher | | [ ] |
| `run_analysis.sh android` | Android launcher | | [ ] |

### Evidence and notes

```text

```

---

## 2.3 Add one Android configuration file

- [ ] Move hard-coded Android values into one configuration file.
- [ ] Include the sandbox domain, config, profile, save file, LV/VG, bridge, paths, duration, clone count, and plugin list.
- [ ] Make the launcher fail when a required value is empty.
- [ ] Keep secrets out of this file.

### Candidate `android-analysis.conf`

```bash
ANDROID_ORIGIN_DOMAIN="android_sandbox"
ANDROID_XL_CONFIG="/home/user/drakvuf-tools/android_sandbox.cfg"
ANDROID_PROFILE="/root/android.json"
ANDROID_SAVE_FILE="/home/user/Documents/android_sandbox.bak"
ANDROID_VOLUME_GROUP="vg-root"
ANDROID_BRIDGE="xenbr1"
ANDROID_ANCHOR_NAME="drakvuf-anchor"

MALWARE_INCOMING="/malware_incoming"
MALWARE_PROCESSING="/malware_processing"
MALWARE_FINISHED="/malware_finished"

CLONE_COUNT="2"
ANALYSIS_TIMEOUT="120"
DRAKVUF_PLUGINS="filetracer fileextractor"
```

### Commands used

```bash
editor ~/drakvuf-tools/android-analysis.conf
chmod 0640 ~/drakvuf-tools/android-analysis.conf

bash -n ~/drakvuf-tools/android-analysis.conf
```

### Evidence and notes

```text

```

---

## 2.4 Implement `run_analysis-android.sh`

### Existing Ubuntu behavior to replace

The current Ubuntu launcher hard-codes:

```text
origin domain: ubuntu_sandbox
config: /home/user/drakvuf-tools/linux_sandbox.cfg
profile: /root/linux.json
injection PID: 1415
clone count: 2
```

- [ ] Load `android-analysis.conf`.
- [ ] Enable strict shell behavior.
- [ ] Verify execution as root or through the required privileges.
- [ ] Verify all required commands exist.
- [ ] Verify every required file exists.
- [ ] Verify the analysis directories exist and have correct ownership.
- [ ] Bring `xenbr1` up.
- [ ] Run the existing network setup with the Android clone count.
- [ ] Resolve the injection anchor PID/TGID automatically.
- [ ] Reject zero or multiple matching anchors.
- [ ] Prevent two Android launchers from running simultaneously.
- [ ] Call `dirwatch` with Android values and scripts.
- [ ] Record the final `dirwatch` command in a startup log.

### Candidate preflight commands

```bash
command -v dirwatch
command -v drakvuf
command -v injector
command -v xl
command -v lvcreate
command -v ovs-vsctl

test -r /root/android.json
test -r /home/user/Documents/android_sandbox.bak
test -r ~/drakvuf-tools/android_sandbox.cfg
test -x ~/drakvuf-tools/clone-android.pl
test -x ~/drakvuf-tools/preconfig-android.sh
test -x ~/drakvuf-tools/drakvuf-android.sh

ip link set xenbr1 up
~/drakvuf-tools/network-setup.sh 2
```

### Candidate `dirwatch` invocation

```bash
dirwatch 1 \
    android_sandbox \
    /home/user/drakvuf-tools/android_sandbox.cfg \
    /root/android.json \
    "$ANDROID_ANCHOR_PID" \
    /malware_incoming \
    /malware_processing \
    /malware_finished \
    2 \
    /home/user/drakvuf-tools/clone-android.pl \
    /home/user/drakvuf-tools/preconfig-android.sh \
    /home/user/drakvuf-tools/drakvuf-android.sh \
    /home/user/drakvuf-tools/cleanup.sh \
    /home/user/drakvuf-tools/tcpdump.sh
```

> The exact meaning and order of `dirwatch` arguments must be confirmed from the installed source/help before finalizing this command.

### Commands used

```bash
# Record the real help or source definition.
dirwatch --help 2>&1 | tee /tmp/dirwatch-help.txt

editor ~/drakvuf-tools/run_analysis-android.sh
bash -n ~/drakvuf-tools/run_analysis-android.sh
shellcheck ~/drakvuf-tools/run_analysis-android.sh
```

### Evidence and notes

```text
Resolved anchor PID/TGID method:
Final dirwatch command:
Startup log:
```

---

## 2.5 ~~Implement `clone-android.pl`~~ — superseded 2026-08-15

> **This section no longer describes work that will be done.** DRAFT-015
> established that the clone script holds no OS-specific value and renamed
> `clone-ubuntu.pl` to the shared `automation/clone.pl` rather than
> creating an Android copy. C1/C2 in `analysis-pipeline.md` are amended.
>
> Disposition of the eighteen "required Android changes" below, worked
> through in `.github/issue-drafts/DRAFT-015.md`:
>
> - **1 was already done** — "change the saved-state path to
>   `android_sandbox.bak`". Derived from the origin argument since issue #4
>   (2026-08-09); passing `android_sandbox` already yields it.
> - **1 landed with the rename** — the snapshot size, now
>   `$ENV{CLONE_LV_SIZE}` (`clone.pl:185`), `32G` for Android against
>   Ubuntu's `64G`, measured from the 32,00g `android_sandbox` LV.
> - **2 are answered by evidence, not code** — "preserve disk
>   frontend/options" and "do not blindly assume `hda`".
>   `misc/android_sandbox.cfg:59` and `misc/ubuntu_sandbox.cfg:54` are the
>   same line but for the LV name, and the manual clone in
>   `verify-android-isolation.md` restored, ran 99 s and passed eleven
>   isolation steps on `hda`.
> - **12 belong to DRAFT-033**, which has not landed: locking, the four
>   exit-status checks, snapshot removal on failure, the restore timeout,
>   stdout-only-on-success, stderr diagnostics, config-path validation, and
>   the VLAN/name validation. They apply to `clone.pl` now.
> - **1 is owned by nobody** — "remove the temporary config after success
>   or failure". `clone.pl:190` writes `/tmp/$clone.config` and never
>   unlinks it. Recommended for DRAFT-033; not yet assigned.
> - **1 was already true** — keeping the origin parameterized.
>
> The "manual clone test" and "clone test evidence" blocks below are still
> the right test; run them against `clone.pl`, per DRAFT-015's TEST
> section.

### Existing Ubuntu behavior to review

The current clone script:

- creates clone names as `<origin>-<vlan>-clone`;
- rewrites `name`, `vif`, and `disk` in a temporary Xen config;
- attaches the clone to `xenbr1.<vlan>`;
- creates an LVM snapshot with `-L64G`;
- restores `/home/user/Documents/ubuntu_sandbox.bak` paused;
- contains disabled per-origin locking;
- removes an existing clone domain and LV.

### Required Android changes

- [ ] Change the saved-state path to `android_sandbox.bak`.
- [ ] Keep the origin domain parameterized.
- [ ] Keep the volume group configurable.
- [ ] Preserve disk frontend/options compatible with the Android Xen config.
- [ ] Do not blindly assume `hda` without verifying the restored VM expects it.
- [ ] Re-enable per-origin file locking.
- [ ] Validate the VLAN is numeric and in the allowed range.
- [ ] Validate the origin and generated clone names.
- [ ] Validate the config file path.
- [ ] Check the exit status of `xl destroy`.
- [ ] Check the exit status of `lvremove`.
- [ ] Check the exit status of `lvcreate`.
- [ ] Check the exit status of `xl restore`.
- [ ] Remove the snapshot if restore fails.
- [ ] Remove the temporary config after success or failure.
- [ ] Add a timeout around restore.
- [ ] Print only the clone domain ID on stdout if `dirwatch` requires that.
- [ ] Send diagnostic messages to stderr.

### Commands used

```bash
editor ~/drakvuf-tools/clone-android.pl
perl -c ~/drakvuf-tools/clone-android.pl

# Inspect syntax and unsafe shell interpolation.
grep -nE '`|system|open|lvcreate|lvremove|xl restore|xl destroy' \
    ~/drakvuf-tools/clone-android.pl
```

### Manual clone test

```bash
sudo ~/drakvuf-tools/clone-android.pl \
    android_sandbox \
    101 \
    ~/drakvuf-tools/android_sandbox.cfg
```

### Expected resources

```text
Domain: android_sandbox-101-clone
LV: /dev/vg-root/android_sandbox-101-clone
Bridge/VLAN: xenbr1.101
State: restored and paused if required by dirwatch
```

### Clone test evidence

```bash
sudo xl list
sudo xl list -l android_sandbox-101-clone
sudo lvs -a -o lv_name,origin,lv_size,data_percent,devices
sudo ovs-vsctl show
```

```text
stdout returned by clone script:
stderr/log:
cleanup result:
```

---

## 2.6 Implement sample classification

- [ ] Classify samples by file contents, not only extension.
- [ ] Compute SHA-256 before analysis.
- [ ] Optionally preserve MD5 for compatibility with the existing result layout.
- [ ] Sanitize the original filename before using it in paths or commands.
- [ ] Reject directory traversal and control characters.
- [ ] Enforce a maximum sample size.
- [ ] Record the detected type in metadata.
- [ ] Route only supported types.
- [ ] Return a clear `unsupported_type` status for everything else.

### Proposed initial types

| Type | Initial support | Execution path | Status |
|---|---:|---|---:|
| APK | Yes | `pm install` + launch component | [ ] |
| Split APK set / APKS | Yes, after APK | Package Manager session | [ ] |
| AAB | Later | Convert on Dom0, then APK path | [ ] |
| XAPK / APKM | Later | Unpack and route contents | [ ] |
| DEX / JAR | Later | `dalvikvm` or `app_process` | [ ] |
| x86_64 ELF | Yes, after APK MVP | Direct execution | [ ] |
| x86 ELF | Validate guest support | Direct execution | [ ] |
| ARM ELF | No until validated | Translation-specific | [ ] |
| `.so` | Later | Dedicated loader harness | [ ] |
| Shell script | Optional | `/system/bin/sh` | [ ] |
| OBB | Data only | Install with associated package | [ ] |
| OAT / ODEX / VDEX | Separate workflow | ART-specific | [ ] |
| Boot/system/vendor image | Separate workflow | Firmware analysis | [ ] |

### Candidate host-side inspection commands

```bash
SAMPLE="/malware_processing/example"

sha256sum "$SAMPLE"
md5sum "$SAMPLE"
stat --printf='size=%s bytes\n' "$SAMPLE"
file --brief --mime-type "$SAMPLE"
file "$SAMPLE"

# APK/archive checks
unzip -t "$SAMPLE"
unzip -l "$SAMPLE" | head -n 100
```

### Evidence and notes

```text
Classifier implementation location:
Filename sanitization rules:
Maximum size:
```

---

## 2.7 Implement `preconfig-android.sh`

### Existing Ubuntu behavior to remove

The current Ubuntu preconfiguration script:

- computes an MD5 result directory;
- executes `/usr/bin/sh -c ...` inside the guest;
- configures `eth0` with `172.16.<VLAN>.2/24`;
- sets the gateway to `172.16.<VLAN>.1`;
- overwrites `/etc/resolv.conf`;
- downloads the sample with `wget`;
- writes it to `/home/carlos/Desktop/test` (the guest username is
  hard-coded in `preconfig-ubuntu.sh:119`; parameterizing it is open M1
  work);
- makes the file executable.

### Android requirements

- [ ] Enable strict shell behavior.
- [ ] Validate all seven expected arguments from `dirwatch`.
- [ ] Return a nonzero code on invalid input.
- [ ] Create a SHA-256 result directory.
- [ ] ~~Create a per-analysis guest directory under `/data/local/tmp/drakvuf/<SHA256>`.~~
      **Superseded 2026-08-10 (issue #6).** Staging is flat into
      `/data/local/tmp`, which pre-exists; `writefile` cannot create
      parents. **No per-analysis guest directory is needed at all** — it
      existed to hold in-guest collection output, and in-guest collection is
      withdrawn (see the note above §4.2). The guest filesystem is written
      once and never read back.
      See "Staging directory — execution evidence" below.
- [ ] Transfer the sample without relying on a guest web browser or desktop path.
- [ ] Prefer `injector -m writefile` if supported by the installed branch.
- [ ] Verify the guest copy with SHA-256.
- [ ] Configure Android networking only when network simulation is enabled.
- [ ] Record all commands and injector output in `preconfig.log`.
- [ ] Produce a metadata file before execution.
- [ ] Never include the untrusted filename directly in a guest shell command.

### Candidate result directory

```bash
SHA256="$(sha256sum -- "$RUNFOLDER/$RUNFILE" | awk '{print $1}')"
RESULT_DIR="$OUTPUTFOLDER/$SHA256"
mkdir -p -- "$RESULT_DIR"
```

### Check installed injector syntax

```bash
injector --help 2>&1 | tee /tmp/injector-help.txt
injector -h 2>&1 | tee -a /tmp/injector-help.txt
```

### Candidate host-to-guest transfer

> **Corrected 2026-08-09 (issue #4 / DRAFT-027). The original candidate
> below had the arguments wrong.** It is kept verbatim because it is what
> the Android delivery design said, and `preconfig-android.sh`
> (DRAFT-016) would have inherited it:
>
> ```bash
> # WRONG -- do not use. Superseded by the validated form further down.
> injector -r "$REKALL" -d "$DOMAIN" -i "$PID" -m writefile \
>     -e "$RUNFOLDER/$RUNFILE" \
>     -f "/data/local/tmp/drakvuf/$SHA256/sample.bin" \
>     > "$RESULT_DIR/writefile.log" 2>&1
> ```
>
> Two defects, both settled by the `injector --help` capture taken on Dom0
> 2026-08-08 and recorded at
> `docs/runbooks/verify-user-placeholder.md:154-157`:
>
> ```text
> writefile - push a file (specified by host path -B) to the VM and store it on guest path specified by -e
> -f <args for execproc>    [BOTH] - Arguments specified for exec to include (requires -m execproc or -m shellexec)
> ```
>
> 1. `-e` is the **guest destination**, not the host source; the host
>    source is `-B`. The candidate has them swapped, so it would have
>    tried to write the guest file *to* the Dom0 sample path.
> 2. `-f` is accepted only with `-m execproc` or `-m shellexec`. Passing
>    it with `-m writefile` supplies the destination through an option
>    that mode does not read.
>
> This is why the section above says to check the installed help first.
> It had not been checked when the candidate was written.

Validated argument shape — and as of 2026-08-09 the invocation itself is
**execution-evidenced**, not just help-evidenced: the Ubuntu pipeline ran
this exact form end to end on Dom0 with `apache2` stopped, and a `readfile`
pull confirmed the delivered bytes hashed identically to the Dom0 source
(`docs/runbooks/deploy-repo-relative-paths.md`, D5/D6). Android inherits a
working mechanism rather than a candidate one:

```bash
injector \
    -r "$REKALL" \
    -d "$DOMAIN" \
    -i "$PID" \
    -m writefile \
    -B "$RUNFOLDER/$RUNFILE" \
    -e "/data/local/tmp/drakvuf/$SHA256/sample.bin" \
    > "$RESULT_DIR/writefile.log" 2>&1
```

`-B` takes the Dom0-side source and `-e` the guest-side destination. The
destination contains no component derived from the submitted filename —
`$SHA256` is computed Dom0-side from the file's contents. The Ubuntu
implementation of exactly this shape is in
`automation/preconfig-ubuntu.sh`.

**No `chmod` step is needed after it.** `writefile` leaves the staged file
executable on its own — established on Dom0 2026-08-09 by removing a
`chmod` injection and confirming analyses still traced. `injector --help`
does not state this either way, which is why the Ubuntu implementation
carried the extra injection until it was tested. Verify it holds on
Android before relying on it: the Ubuntu guest is `execve`-based, and an
APK is installed rather than `execve`'d, so the relevant question there is
whether the file lands readable by the installer, not executable.

### Candidate guest preparation command

```bash
GUEST_DIR="/data/local/tmp/drakvuf/$SHA256"
GUEST_CMD="umask 077; mkdir -p '$GUEST_DIR'"

injector \
    -r "$REKALL" \
    -d "$DOMAIN" \
    -i "$PID" \
    -m execproc \
    -e /system/bin/sh \
    -f -c \
    -f "$GUEST_CMD" \
    > "$RESULT_DIR/guest-prepare.log" 2>&1
```

> The candidate command still requires careful quoting validation. A fixed guest destination derived only from SHA-256 is safer than using the uploaded filename.

### Staging directory — execution evidence, Dom0/guest 2026-08-10 (issue #6)

Run on the working BlissOS guest by the maintainer, against the live
injection anchor (PID 5715). This settles the Android half of issue #6's
guest-path decision and **supersedes the candidate guest-preparation
command above**, which is no longer required.

Three hypotheses were tested with another process as the unique terminal 
that was usable was showing process 5715 (nano). One was refuted:

| Hypothesis | Result | Evidence |
|---|---|---|
| `/storage/self/primary` resolves per-process, so the anchor may not see it | **REFUTED** | `ls -ld /proc/6248/root/storage/self/primary/Download/` → `drwxrwx--- root everybody`; `readlink -f` → `/storage/emulated/0` |
| External storage is mounted `noexec` | **CONFIRMED** | `/dev/fuse /storage/emulated fuse rw,lazytime,nosuid,nodev,noexec,…` |
| FUSE synthesizes mode, so `chmod` does not stick | **CONFIRMED** | `chmod 755` on a file in `Download/` left it `-rw-rw---- root everybody u:object_r:fuse:s0` |

Execution probe, both locations, same binary (`/system/bin/toybox`):

```text
/storage/self/primary/Download/probe echo OK
  -> /system/bin/sh: …/probe: can't execute: Permission denied   (execve refused)

/data/local/tmp/probe echo OK
  -> toybox: Unknown command /data/local/tmp/probe               (binary RAN)
  -> ls -lZ: -rwxr-xr-x 1 root shell u:object_r:shell_data_file:s0
```

The second is a **successful execution**. The message is toybox's own
multi-call applet dispatch failing on an unrecognized `argv[0]`, not an
`execve` failure — the shell reports those itself, as it did for the first.
Incidentally this is a live demonstration of the `argv[0]`-dependent
behaviour that `docs/architecture/analysis-pipeline.md`'s "Filenames: two
namespaces" cites as the reason the guest keeps the submitted name.

**None of this is SELinux.** `noexec` is a mount option enforced by the VFS
before any LSM hook, and FUSE mode synthesis is the daemon's `derive=multi`
/ `default_normal` behaviour. Neither is reachable by policy, and no `avc`
denial is produced by either. Setting the guest permissive would change
nothing here — and would make observed malware behaviour unrepresentative,
so it is not a workaround to reach for.

**Decision: `GUEST_STAGING_DIR=/data/local/tmp` for Android**, with no
`drakvuf/` subdirectory. `/data/local/tmp` already exists in the saved
image, which the contract requires because `injector -m writefile` does not
create parent directories. Creating a subdirectory instead would mean
modifying and re-saving the golden image, and also giving proof of being 
analyzed, changing the injection anchor PID — a real cost for tidiness only.

`/storage/self/primary/Download` is **not** ruled out for APK-only analysis,
where `pm install` reads the file and never executes it, and where the
provenance realism is genuinely useful. It is deferred rather than adopted:
it cannot serve native ELF, `.so` or `dalvikvm`/`CLASSPATH` samples, and
selecting a staging directory from `detected_type` would make that field
load-bearing when the state model deliberately keeps it advisory.

### Candidate metadata

```json
{
  "analysis_id": "SHA256",
  "original_filename": "",
  "sanitized_filename": "sample.bin",
  "sha256": "",
  "md5": "",
  "size": 0,
  "detected_type": "",
  "domain": "",
  "vlan": 0,
  "started_at": ""
}
```

### Commands used

```bash
editor ~/drakvuf-tools/preconfig-android.sh
bash -n ~/drakvuf-tools/preconfig-android.sh
shellcheck ~/drakvuf-tools/preconfig-android.sh
```

### Evidence and notes

```text
Final guest directory:
Transfer method:
Hash verification method:
Network setup behavior:
```

---

## 2.8 Implement `drakvuf-android.sh`

### Existing Ubuntu behavior to replace

The current Ubuntu execution script:

- executes one fixed guest path;
- waits five seconds before starting DRAKVUF;
- uses `execproc` injection;
- runs for 120 seconds;
- enables `filetracer` and `fileextractor`;
- treats return code `1` as the condition for moving the sample;
- finds tcpdump with `ps | grep` and sends `SIGKILL`.

### Android requirements

- [ ] Enable strict shell behavior.
- [ ] Validate all expected arguments.
- [ ] Load the sample metadata and detected type.
- [ ] Build commands using arrays or fixed argument files, not a single unsafe command string.
- [ ] Start DRAKVUF before installation or execution.
- [ ] Install or execute the sample while DRAKVUF is active.
- [ ] Keep installation, launch, stimulation, observation, and collection as separate recorded stages.
- [ ] Record each stage result.
- [ ] Use explicit final statuses rather than interpreting one DRAKVUF return code as success.
- [ ] Stop tcpdump using its recorded PID.
- [ ] Try graceful termination before `kill -9`.
- [ ] Move the original sample and metadata into the final result regardless of success or failure.
- [ ] Preserve all logs on failure.

### Proposed stage order

- [ ] `00-preflight`
- [ ] `10-start-capture`
- [ ] `20-start-drakvuf`
- [ ] `30-install-or-prepare`
- [ ] `40-launch`
- [ ] `50-stimulate`
- [ ] `60-observe`
- [ ] `70-collect`
- [ ] `80-stop-monitoring`
- [ ] `90-finalize`

### Candidate DRAKVUF command

```bash
drakvuf \
    -r "$REKALL" \
    -d "$DOMAIN" \
    -i "$PID" \
    -m execproc \
    -e /system/bin/sh \
    -D "$RESULT_DIR/files" \
    -o json \
    -t "$ANALYSIS_TIMEOUT" \
    -a filetracer \
    -a fileextractor \
    > "$RESULT_DIR/drakvuf.log" 2>&1
```

> This is only a starting point. Validate whether the current DRAKVUF invocation can monitor first and inject later, or whether orchestration needs a different process model.

### Candidate status values

```text
success
install_failed
unsupported_type
transfer_failed
hash_mismatch
injection_failed
guest_crashed
guest_rebooted
analysis_timeout
plugin_failed
collection_failed
cleanup_failed
```

### Commands used

```bash
editor ~/drakvuf-tools/drakvuf-android.sh
bash -n ~/drakvuf-tools/drakvuf-android.sh
shellcheck ~/drakvuf-tools/drakvuf-android.sh
```

### Evidence and notes

```text
Final process model:
DRAKVUF PID handling:
Tcpdump PID handling:
Final status file:
```

---

## 2.9 Review `cleanup.sh`

- [ ] Locate the exact `cleanup.sh` used by the current Ubuntu automation.
- [ ] Confirm its argument order.
- [ ] Confirm it destroys only the intended clone domain.
- [ ] Confirm it removes only the intended clone LV.
- [ ] Confirm it removes the clone VLAN/OVS resources.
- [ ] Confirm it removes temporary Xen config files.
- [ ] Add Android-specific handling only if necessary.
- [ ] Make cleanup idempotent.
- [ ] Make cleanup safe after partial clone creation.
- [ ] Make cleanup safe after failed restoration.
- [ ] Make cleanup safe after Ctrl+C.

### Commands used

```bash
sed -n '1,260p' ~/drakvuf-tools/cleanup.sh
bash -n ~/drakvuf-tools/cleanup.sh
shellcheck ~/drakvuf-tools/cleanup.sh
```

### Manual cleanup test

```bash
# Record the exact tested invocation after confirming the script interface.

```

### Evidence and notes

```text
Domain removed:
LV removed:
VLAN/OVS removed:
Temporary files removed:
Second cleanup invocation safe:
```

---

## 2.10 Review `tcpdump.sh`

- [ ] Locate the exact `tcpdump.sh` used by the current Ubuntu automation.
- [ ] Confirm its argument order.
- [ ] Confirm it captures only the clone VLAN/interface.
- [ ] Store the tcpdump PID in a per-analysis PID file.
- [ ] Confirm captures use unique paths.
- [ ] Confirm captures are closed cleanly.
- [ ] Avoid `ps | grep` PID discovery.
- [ ] Ensure a stale PID file cannot kill an unrelated process.

### Commands used

```bash
sed -n '1,260p' ~/drakvuf-tools/tcpdump.sh
bash -n ~/drakvuf-tools/tcpdump.sh
shellcheck ~/drakvuf-tools/tcpdump.sh
```

### Candidate PID-safe capture pattern

```bash
tcpdump \
    -i "xenbr1.$VLAN" \
    -U \
    -w "$RESULT_DIR/network.pcap" \
    > "$RESULT_DIR/tcpdump.log" 2>&1 &

TCPDUMP_PID=$!
printf '%s\n' "$TCPDUMP_PID" > "$RESULT_DIR/tcpdump.pid"
```

### Candidate graceful stop

```bash
if kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    kill -INT "$TCPDUMP_PID"
    wait "$TCPDUMP_PID" || true
fi
```

### Evidence and notes

```text

```

---

# Phase 3 — Implement Android sample branches

## 3.1 APK static metadata extraction on Dom0

- [ ] Install or locate `aapt`, `aapt2`, `apkanalyzer`, and `apksigner` as available.
- [ ] Extract the package ID.
- [ ] Extract version name and version code.
- [ ] Extract minimum and target SDK.
- [ ] Extract requested permissions.
- [ ] Resolve the launchable activity.
- [ ] Record exported components where tooling supports it.
- [ ] Record native library ABIs.
- [ ] Verify and record signing-certificate information.
- [ ] Save raw tool output in the result directory.

### Commands used

```bash
command -v aapt || true
command -v aapt2 || true
command -v apkanalyzer || true
command -v apksigner || true

APK="/path/to/sample.apk"

aapt dump badging "$APK" | tee aapt-badging.txt
aapt dump permissions "$APK" | tee aapt-permissions.txt
apksigner verify --verbose --print-certs "$APK" | tee apksigner.txt
unzip -l "$APK" | tee apk-file-list.txt
```

### Extracted metadata

```text
Package:
Version code:
Version name:
Min SDK:
Target SDK:
Launchable activity:
Native ABIs:
Certificate SHA-256:
```

---

## 3.2 APK installation branch

- [ ] Transfer the APK into the fixed guest analysis directory.
- [ ] Verify the APK hash inside the guest.
- [ ] Record package-manager output.
- [ ] Install with test/debug permissions allowed where required.
- [ ] Grant runtime permissions only when deliberately configured.
- [ ] Verify the package appears in `pm list packages`.
- [ ] Record `pm path` output.
- [ ] Record the installed UID.
- [ ] Record install failure reasons.

### Candidate Android commands

```sh
APK=/data/local/tmp/drakvuf/ANALYSIS_ID/sample.apk
PACKAGE=com.example.package

sha256sum "$APK"
pm install -r -t -g "$APK"
pm list packages | grep -F "$PACKAGE"
pm path "$PACKAGE"
dumpsys package "$PACKAGE"
```

### Evidence and notes

```text
Install exit status:
Package:
UID:
Installed APK path(s):
Failure reason:
```

---

## 3.3 APK launch branch

- [ ] Launch the resolved activity with `am start -W`.
- [ ] Record activity-manager output.
- [ ] Record the first application PID.
- [ ] Record subsequent PIDs if the process restarts.
- [ ] Add a launcher-category fallback using `monkey`.
- [ ] Handle APKs without a launcher activity.
- [ ] Record the exact component or fallback used.

### Candidate Android commands

```sh
PACKAGE=com.example.package
ACTIVITY=com.example.package.MainActivity

am start -W -n "$PACKAGE/$ACTIVITY"
pidof "$PACKAGE" || true
ps -A | grep -F "$PACKAGE" || true
```

```sh
# Fallback when a launcher component exists but was not resolved reliably.
monkey \
    -p "$PACKAGE" \
    -c android.intent.category.LAUNCHER \
    1
```

### Evidence and notes

```text
Launch method:
Component:
First PID:
Restarted PIDs:
Launch output:
```

---

## 3.4 APK exported-component stimulation

- [ ] Enumerate exported activities.
- [ ] Enumerate exported services.
- [ ] Enumerate exported receivers.
- [ ] Enumerate exported providers.
- [ ] Define safe limits for automatic invocation.
- [ ] Record every invoked component and argument.
- [ ] Avoid infinite or destructive stimulation loops.

### Candidate commands

```sh
# Record actual package metadata first.
dumpsys package "$PACKAGE" > /data/local/tmp/drakvuf/ANALYSIS_ID/dumpsys-package.txt

# Activity example
am start -W -n "$PACKAGE/$EXPORTED_ACTIVITY"

# Service example; command availability varies by Android version.
am startservice -n "$PACKAGE/$EXPORTED_SERVICE"

# Broadcast example
am broadcast -n "$PACKAGE/$EXPORTED_RECEIVER" -a android.intent.action.BOOT_COMPLETED
```

### Evidence and notes

```text
Invocation policy:
Maximum components:
Maximum time:
```

---

## 3.5 Split APK / APKS branch

- [ ] Identify the base APK.
- [ ] Identify ABI, density, language, and feature splits.
- [ ] Reject incomplete or incompatible split sets.
- [ ] Transfer all selected APKs.
- [ ] Create an install session.
- [ ] Parse the numeric session ID safely.
- [ ] Write every APK into the session.
- [ ] Commit the session.
- [ ] Abandon the session after a failed write.
- [ ] Route the installed package to the normal launch branch.

### Candidate Android commands

```sh
SESSION_OUTPUT="$(pm install-create -r -t -g)"
printf '%s\n' "$SESSION_OUTPUT"

# Parse and validate the session ID in the host script before continuing.
SESSION_ID=123

pm install-write "$SESSION_ID" base /data/local/tmp/drakvuf/ANALYSIS_ID/base.apk
pm install-write "$SESSION_ID" split_abi /data/local/tmp/drakvuf/ANALYSIS_ID/config.x86_64.apk
pm install-commit "$SESSION_ID"
```

### Failure cleanup

```sh
pm install-abandon "$SESSION_ID"
```

### Evidence and notes

```text
Selected splits:
Session ID:
Commit output:
```

---

## 3.6 AAB branch

- [ ] Keep AAB disabled until the APK branch is stable.
- [ ] Install a known `bundletool` version on Dom0.
- [ ] Create a disposable analysis signing key.
- [ ] Convert AAB to a universal APK or APK set.
- [ ] Preserve bundletool output and generated files.
- [ ] Route the generated APK/APKS to an already tested branch.
- [ ] Record that the installed APK was generated from an AAB.

### Commands used

```bash
# Record the exact installed bundletool invocation and version here.
java -jar /path/to/bundletool.jar version

# Candidate only; fill in validated keystore parameters.
java -jar /path/to/bundletool.jar build-apks \
    --bundle=/path/to/sample.aab \
    --output=/path/to/generated.apks \
    --mode=universal \
    --ks=/path/to/analysis.jks \
    --ks-key-alias=analysis
```

### Evidence and notes

```text
Bundletool version:
Signing key identifier:
Generated APK/APKS checksum:
```

---

## 3.7 XAPK / APKM branch

- [ ] Keep disabled until split APK support is stable.
- [ ] Treat the file as an archive and validate it before extraction.
- [ ] Prevent archive path traversal.
- [ ] Identify base and split APKs.
- [ ] Identify associated OBB files.
- [ ] Extract package metadata.
- [ ] Route APKs to split installation.
- [ ] Copy OBB only after the package name is known.

### Candidate host commands

```bash
ARCHIVE=/path/to/sample.xapk
unzip -t "$ARCHIVE"
unzip -l "$ARCHIVE"

# Use a safe extraction implementation; do not use untrusted archive paths blindly.
```

### Evidence and notes

```text

```

---

## 3.8 DEX / JAR branch

- [ ] Keep disabled until APK MVP is stable.
- [ ] Require or derive an entry class.
- [ ] Record the source of the entry-class decision.
- [ ] Test `dalvikvm` availability.
- [ ] Test `app_process` availability.
- [ ] Execute a known benign fixture first.
- [ ] Return `missing_entry_class` rather than guessing without bounds.

### Candidate Android commands

```sh
command -v dalvikvm || true
command -v app_process || true

# DEX/JAR candidate
 dalvikvm -cp /data/local/tmp/drakvuf/ANALYSIS_ID/sample.dex com.example.Main
```

```sh
CLASSPATH=/data/local/tmp/drakvuf/ANALYSIS_ID/sample.jar \
    app_process /system/bin com.example.Main
```

### Evidence and notes

```text
Runner selected:
Entry class:
Arguments:
```

---

## 3.9 Native ELF branch

- [ ] Inspect ELF architecture on Dom0.
- [ ] Initially permit only verified x86_64 executables.
- [ ] Validate x86 32-bit support before enabling it.
- [ ] Do not assume raw ARM ELF works through NDK translation.
- [ ] Transfer to a fixed guest path.
- [ ] Apply restrictive permissions, then add execute permission.
- [ ] Run with a controlled working directory and environment.
- [ ] Record stdout, stderr, exit status, signals, and crashes.

### Host inspection commands

```bash
file /path/to/sample
readelf -h /path/to/sample
readelf -l /path/to/sample
readelf -d /path/to/sample
```

### Candidate Android commands

```sh
SAMPLE=/data/local/tmp/drakvuf/ANALYSIS_ID/sample.elf
chmod 0700 "$SAMPLE"
cd /data/local/tmp/drakvuf/ANALYSIS_ID
"$SAMPLE"
```

### Evidence and notes

```text
Architecture:
Interpreter:
Dynamic dependencies:
Exit status:
```

---

## 3.10 Native shared-library branch

- [ ] Do not execute `.so` files directly.
- [ ] Build a dedicated x86_64 loader fixture.
- [ ] Support `dlopen` and error reporting.
- [ ] Optionally call one configured exported symbol.
- [ ] Set a maximum runtime.
- [ ] Record the requested symbol and arguments.

### Commands used

```bash
# Record loader build command here.

```

```sh
# Candidate guest invocation
/system/bin/drakvuf-so-loader \
    /data/local/tmp/drakvuf/ANALYSIS_ID/sample.so \
    OPTIONAL_SYMBOL
```

### Evidence and notes

```text

```

---

# Phase 4 — Artifact collection

## 4.1 Standard result directory

- [ ] Use SHA-256 as the result directory name.
- [ ] Create the result directory atomically.
- [ ] Store the original sample.
- [ ] Store metadata.
- [ ] Store all command logs.
- [ ] Store DRAKVUF output.
- [ ] Store extracted files.
- [ ] Store pcap.
- [ ] Store Android logs.
- [ ] Store final status.
- [ ] Store cleanup status.

### Proposed result layout

```text
<SHA256>/
├── sample/
│   └── original
├── metadata.json
├── status.json
├── commands.log
├── preconfig.log
├── install.log
├── launch.log
├── stimulation.log
├── drakvuf.log
├── drakvuf.json
├── network.pcap
├── tcpdump.log
├── logcat.txt
├── package/
│   ├── dumpsys-package.txt
│   ├── pm-path.txt
│   └── permissions.txt
├── crashes/
├── files/
└── cleanup.log
```

> **Reconciled 2026-08-09 (issue #3).** The OS-independent state model in
> `docs/architecture/analysis-pipeline.md` adopts this layout's substance —
> one self-contained directory per run, the original sample preserved
> beside its artifacts, and the atomic temp-then-`mv` publication pattern
> in "Commands used" below — with **one change: the directory is named by
> `analysis_id`, not by SHA-256.** Keying a directory by content hash means
> a second run of the same sample collides with the first; `analysis_id` is
> per-run, and SHA-256 becomes an indexed field so that "every run of this
> sample" remains a single lookup. The stored sample inside the directory
> stays content-addressed (`sample/<sha256>`). Everything else here is
> unchanged and is still the Android target.

### Commands used

```bash
RESULT_TMP="$OUTPUTFOLDER/.${SHA256}.tmp.$$"
RESULT_FINAL="$OUTPUTFOLDER/$SHA256"

mkdir -p -- "$RESULT_TMP"
# Populate result directory.
mv -- "$RESULT_TMP" "$RESULT_FINAL"
```

### Evidence and notes

```text

```

---

> **WITHDRAWN 2026-08-10 (issue #6) — applies to §4.2, §4.3 and §4.4.**
> `logcat`, `logd`, `dumpsys` and `dmesg` are not used, for the time being.
> No in-guest collection runs on any target; analysis output comes from
> hypervisor introspection and the host-side pcap, and the guest filesystem
> is written once (the sample) and never read back.
>
> **Not because these are installed agents** — they ship with Android, so by
> the narrow criterion ("nothing persistent is installed in the guest") they
> would pass. Because a collector inside the guest is visible to the sample
> in `ps`/`/proc`, writes a file the sample can truncate or poison, needs
> in-guest state to stop, and duplicates inside the trust boundary what
> introspection provides from outside it. `injector`'s drakshell stays the
> one accepted entry because it self-terminates before the sample runs.
>
> The §4.2 candidate is the clearest case: `logcat -b all -f … &` plus a
> PID file and a `kill -TERM` runs for the entire analysis, alongside the
> malware.
>
> **The cost is accepted knowingly.** These carried Android framework
> semantics — ActivityManager, PackageManager, ART, Intent dispatch,
> permission grants — that kernel-syscall tracing does not reconstruct. The
> Android track has less semantic visibility as a result. Revisiting means
> finding an *external* source for those events (reading `logd`'s buffers
> through LibVMI, say), not re-admitting an in-guest process.
>
> Sections 4.2–4.4 are kept below as the historical candidate. Do not
> implement them. Rationale in `docs/architecture/analysis-pipeline.md`,
> "Shared and per-OS code boundary" → decision 4.

## 4.2 Capture logcat

- [ ] Clear inherited logcat state before sample execution if desired.
- [ ] Start logcat capture before installation.
- [ ] Capture all useful buffers supported by the image.
- [ ] Stop logcat cleanly.
- [ ] Retrieve the file from the guest.
- [ ] Preserve logcat even when installation fails.

### Candidate Android commands

```sh
logcat -c
logcat -b all -v threadtime \
    -f /data/local/tmp/drakvuf/ANALYSIS_ID/logcat.txt &
printf '%s\n' "$!" > /data/local/tmp/drakvuf/ANALYSIS_ID/logcat.pid
```

### Candidate stop

```sh
LOGCAT_PID="$(cat /data/local/tmp/drakvuf/ANALYSIS_ID/logcat.pid)"
kill -TERM "$LOGCAT_PID"
```

### Host retrieval command

```bash
# Fill in after validating injector readfile syntax.

```

### Evidence and notes

```text

```

---

## 4.3 Collect package state

- [ ] Record the package name.
- [ ] Record UID and installed paths.
- [ ] Record granted permissions.
- [ ] Record app-ops.
- [ ] Record running processes.
- [ ] Record services and activities where useful.

### Candidate Android commands

```sh
pm path "$PACKAGE"
dumpsys package "$PACKAGE"
cmd package list packages -U | grep -F "$PACKAGE"
cmd appops get "$PACKAGE"
pidof "$PACKAGE" || true
ps -A -o USER,PID,PPID,NAME,ARGS | grep -F "$PACKAGE" || true
```

### Evidence and notes

```text

```

---

## 4.4 Collect crashes and system diagnostics

- [ ] Record tombstones created during the analysis.
- [ ] Record ANR traces created during the analysis.
- [ ] Record DropBox entries created during the analysis.
- [ ] Record kernel messages relevant to the sample.
- [ ] Record SELinux denials separately.
- [ ] Avoid collecting unrelated stale artifacts from the saved image.

### Candidate Android paths

```text
/data/tombstones/
/data/anr/
/data/system/dropbox/
```

### Candidate Android commands

```sh
dmesg | tail -n 1000 > /data/local/tmp/drakvuf/ANALYSIS_ID/dmesg-tail.txt
logcat -b all -d | grep -i 'avc: denied' \
    > /data/local/tmp/drakvuf/ANALYSIS_ID/selinux-denials.txt
```

### Evidence and notes

```text

```

---

## 4.5 Optional process memory dump

- [ ] Keep memory dumping disabled until the base analysis is reliable.
- [ ] Confirm the installed memdump plugin works against Android/Linux.
- [ ] Map the Android package to the correct process or processes.
- [ ] Select the memory-dump time point.
- [ ] Record the selected PID/TGID.
- [ ] Preserve plugin output and errors.
- [ ] Test against a benign fixture first.

### Commands used

```bash
# Record the validated DRAKVUF memdump command here.

```

### Evidence and notes

```text

```

---

# Phase 5 — Network containment and stimulation

## 5.1 Default-deny network mode

- [ ] Default to no Internet access.
- [ ] Allow only explicitly required Dom0 analysis services.
- [ ] Block management networks.
- [ ] Block unrelated RFC1918 destinations.
- [ ] Block metadata service addresses.
- [ ] Block IPv6 unless deliberately supported.
- [ ] Log denied traffic without overwhelming storage.
- [ ] Verify each clone is isolated from other clones.

### Commands used

```bash
sudo ovs-vsctl show
sudo nft list ruleset
sudo iptables-save
sudo ip6tables-save
sudo tcpdump -ni xenbr1
```

### Evidence and notes

```text
Firewall implementation:
Allowed services:
Blocked ranges:
```

---

## 5.2 Sample delivery mode

- [ ] Prefer direct host-to-guest file injection.
- [ ] ~~Keep HTTP download only as an optional compatibility path.~~
      **Superseded 2026-08-08 (owner decision, DRAFT-027).** The
      HTTP/Apache delivery path is removed outright — no fallback branch,
      no off-by-default flag, no configuration switch. Delivery is
      `injector -m writefile`. Rationale: a retained fallback in a
      malware-analysis pipeline is an untested code path whose only effect
      is to restore the exposure the change exists to close. Kept here as
      history; do not implement it.
- [ ] Do not expose `/malware_processing` beyond the isolated analysis network.
- [ ] Verify sample delivery cannot reach the management network.
- [ ] Verify the guest-side hash after delivery.

### Commands used

```bash
# Record validated injector writefile command here.

```

### Evidence and notes

```text

```

---

## 5.3 Optional simulated services

- [ ] Add only after default isolation is proven.
- [ ] Decide whether to provide fake DNS.
- [ ] Decide whether to provide HTTP/HTTPS responses.
- [ ] Decide whether to provide fake SMTP.
- [ ] Decide whether to provide fake NTP.
- [ ] Record every service version and configuration.
- [ ] Ensure no service forwards traffic to the Internet.

### Commands used

```bash
# Record installation and service commands only when this phase is implemented.

```

### Evidence and notes

```text

```

---

# Phase 6 — Testing

## 6.1 Script syntax and static checks

- [ ] `bash -n` passes for all shell scripts.
- [ ] `dash -n` passes for all shell scripts — they execute under `dash` in
  production, so `bash -n` alone accepts syntax that fails silently there.
- [ ] `shellcheck` passes against the DRAFT-031 baseline, or every
  suppression is documented. *(The baseline now exists — landed 2026-08-11,
  recorded in `.shellcheckrc` and in `docs/checklists/ubuntu.md`'s
  "Static-check gate" section. This gate is therefore achievable rather
  than aspirational. New Android scripts follow `CONTRIBUTING.md`'s
  "Script layout convention": `#!/bin/sh` on line 1, licence header below
  it, every suppression naming its owning issue.)*
- [ ] `perl -c` passes for clone scripts.
- [ ] Scripts are executable with correct owner and permissions.
- [ ] No remaining `<USER>` or placeholder paths exist.
- [ ] No unquoted sample path expansions remain.
- [ ] No `ps | grep` process discovery remains.
- [ ] No expected failure returns exit code `0`.

### Commands used

```bash
cd /root/sandbox_project/automation   # the Dom0 checkout; ~/drakvuf-tools is retired

for script in *.sh; do
    bash -n "$script" || echo "FAIL bash -n $script"
    dash -n "$script" || echo "FAIL dash -n $script"
done

shellcheck *.sh
# One shared clone script since DRAFT-015 -- there is no clone-android.pl.
perl -c clone.pl

# Note the inverted exit status: grep returns 0 when it FINDS something, so
# a clean result here is exit 1. Written as an explicit gate rather than a
# bare command.
# Comment lines excluded: a comment explaining the issue #2 placeholder
# necessarily quotes it, and a guard that forbids describing a bug is a
# guard against documentation. Requires the first non-whitespace character
# of the line to not be `#`.
if grep -REn '^[[:space:]]*[^#[:space:]].*<USER>' .; then
    echo "FAIL: placeholder remains in code"
fi
if grep -Rns 'ps aux.*grep' .; then echo "NOTE: ps|grep sites remain (DRAFT-011)"; fi
```

> **Corrected 2026-08-11 (TODO-03).** The gate previously grepped
> `'<USER>\|TODO\|FIXME'` as a bare command, which had two defects. The exit
> status inverts the intended meaning — the same defect as CI-02 in
> `docs/workflow-ci.md` — and the `TODO|FIXME` clause would now fail on two
> **legitimate** markers: `clone-ubuntu.pl`'s stubdomain TODO and §1.3's own
> heading. A zero-TODO policy is not this repository's policy, so the clause
> is dropped and the gate narrowed to `<USER>` and placeholder paths.

### Evidence and notes

```text

```

---

## 6.2 Infrastructure smoke tests

- [ ] Restore one Android clone.
- [ ] Confirm its domain ID is returned correctly.
- [ ] Confirm it is attached to the intended VLAN.
- [ ] Confirm LibVMI process enumeration works after restore.
- [ ] Resolve the anchor PID/TGID.
- [ ] Execute `/system/bin/true` through injection.
- [ ] Execute `/system/bin/sh -c id` through injection.
- [ ] Transfer a text fixture into the guest.
- [ ] Verify SHA-256 inside the guest.
- [ ] Retrieve a guest-created text file.
- [ ] Destroy the clone and remove all resources.

### Commands used

```bash
# Clone
sudo ~/drakvuf-tools/clone-android.pl \
    android_sandbox 101 ~/drakvuf-tools/android_sandbox.cfg

# Inventory
sudo xl list
sudo lvs -a -o lv_name,origin,lv_size,data_percent
sudo ovs-vsctl show
sudo vmi-process-list android_sandbox-101-clone

# Injector syntax must be filled in after local validation.

```

### Evidence and notes

```text

```

---

## 6.3 Repeated restore test

- [ ] Complete 20 consecutive clone/restore/cleanup cycles.
- [ ] Confirm no stale domains remain.
- [ ] Confirm no stale LVs remain.
- [ ] Confirm no stale VLANs/OVS ports remain.
- [ ] Confirm no stale temporary configs remain.
- [ ] Record duration and failures for every cycle.

### Test table

| Cycle | Clone result | Restore result | LibVMI result | Cleanup result | Duration | Notes |
|---:|---|---|---|---|---|---|
| 1 | | | | | | |
| 2 | | | | | | |
| 3 | | | | | | |
| 4 | | | | | | |
| 5 | | | | | | |
| 6 | | | | | | |
| 7 | | | | | | |
| 8 | | | | | | |
| 9 | | | | | | |
| 10 | | | | | | |
| 11 | | | | | | |
| 12 | | | | | | |
| 13 | | | | | | |
| 14 | | | | | | |
| 15 | | | | | | |
| 16 | | | | | | |
| 17 | | | | | | |
| 18 | | | | | | |
| 19 | | | | | | |
| 20 | | | | | | |

### Commands used

```bash
# Paste the final automated loop or test harness here after it is written.

```

---

## 6.4 Benign fixture set

- [ ] Launcher APK.
- [ ] APK that creates, modifies, and deletes files.
- [ ] APK that opens TCP and UDP connections.
- [ ] APK with an exported service and no launcher.
- [ ] APK with a broadcast receiver.
- [ ] Split APK set.
- [ ] AAB converted to APK/APKS.
- [ ] x86_64 native executable.
- [ ] DEX/JAR with a known entry class.
- [ ] APK that intentionally crashes.
- [ ] APK with ARM native code for NDK-translation testing.

### Fixture inventory

| Fixture | SHA-256 | Source/build command | Expected behavior | Result |
|---|---|---|---|---|
| Launcher APK | | | | [ ] |
| File activity APK | | | | [ ] |
| Network activity APK | | | | [ ] |
| Exported service APK | | | | [ ] |
| Broadcast APK | | | | [ ] |
| Split APK | | | | [ ] |
| AAB | | | | [ ] |
| x86_64 ELF | | | | [ ] |
| DEX/JAR | | | | [ ] |
| Crash APK | | | | [ ] |
| ARM-native APK | | | | [ ] |

### Commands used

```bash
# Record fixture build commands or repository revisions here.

```

---

## 6.5 APK end-to-end MVP test

- [ ] Place a benign APK in `/malware_incoming`.
- [ ] Confirm `dirwatch` claims the file.
- [ ] Confirm one clone is created.
- [ ] Confirm tcpdump starts.
- [ ] Confirm DRAKVUF starts.
- [ ] Confirm sample transfer succeeds.
- [ ] Confirm guest and host SHA-256 match.
- [ ] Confirm APK installation succeeds.
- [ ] Confirm the main activity launches.
- [ ] Confirm DRAKVUF events are recorded.
- [ ] Confirm logcat is collected.
- [ ] Confirm pcap is collected.
- [ ] Confirm extracted files are collected where generated.
- [ ] Confirm the original sample is preserved.
- [ ] Confirm final status is `success`.
- [ ] Confirm clone, LV, VLAN, and capture processes are removed.

### Commands used

```bash
cp /path/to/benign.apk /malware_incoming/

watch -n1 'xl list; echo; lvs; echo; ps -ef | grep -E "dirwatch|drakvuf|tcpdump" | grep -v grep'
```

### Expected final files

```text
metadata.json
status.json
drakvuf.log
network.pcap
logcat.txt
original sample
cleanup.log
```

### Evidence and notes

```text
Analysis SHA-256:
Result directory:
Clone domain:
Duration:
Final status:
```

---

## 6.6 Failure tests

| Failure case | Expected status | Resources cleaned | Logs preserved | Passed |
|---|---|---:|---:|---:|
| Corrupt APK | `install_failed` | [ ] | [ ] | [ ] |
| Invalid signature | Recorded/report policy | [ ] | [ ] | [ ] |
| Incompatible ABI | `install_failed` or `unsupported_abi` | [ ] | [ ] | [ ] |
| Missing base split | `install_failed` | [ ] | [ ] | [ ] |
| No launchable component | `no_launchable_component` | [ ] | [ ] | [ ] |
| Oversized sample | `rejected_size` | [ ] | [ ] | [ ] |
| Transfer timeout | `transfer_failed` | [ ] | [ ] | [ ] |
| Guest hash mismatch | `hash_mismatch` | [ ] | [ ] | [ ] |
| Injector failure | `injection_failed` | [ ] | [ ] | [ ] |
| Plugin startup failure | `plugin_failed` | [ ] | [ ] | [ ] |
| Guest reboot | `guest_rebooted` | [ ] | [ ] | [ ] |
| Guest crash | `guest_crashed` | [ ] | [ ] | [ ] |
| Analysis timeout | `analysis_timeout` | [ ] | [ ] | [ ] |
| Full output filesystem | Explicit storage failure | [ ] | [ ] | [ ] |
| Full VG / snapshot failure | Explicit clone failure | [ ] | [ ] | [ ] |
| Duplicate filename | Separate SHA-256-safe result | [ ] | [ ] | [ ] |
| Malicious filename | No command/path injection | [ ] | [ ] | [ ] |
| Ctrl+C interruption | Interrupted status | [ ] | [ ] | [ ] |

### Commands used

```bash
# Record exact commands used to trigger each failure case here.

```

### Evidence and notes

```text

```

---

## 6.7 Concurrency tests

- [ ] Run with one clone.
- [ ] Run with two concurrent clones.
- [ ] Submit two different APKs simultaneously.
- [ ] Submit the same APK twice simultaneously.
- [ ] Confirm domains are unique.
- [ ] Confirm LVs are unique.
- [ ] Confirm VLANs are unique.
- [ ] Confirm pcaps are unique.
- [ ] Confirm result directories are unique and complete.
- [ ] Confirm logs do not cross between analyses.
- [ ] Confirm cleanup does not remove another active clone.

### Concurrency evidence

| Analysis ID | Domain | LV | VLAN | Pcap | Result directory | Result |
|---|---|---|---:|---|---|---|
| | | | | | | |
| | | | | | | |

### Commands used

```bash
# Record the exact concurrent submission commands here.

```

---

## 6.8 Endurance test

- [ ] Complete at least 50 benign automated analyses.
- [ ] Record every non-success result.
- [ ] Confirm no stale domains.
- [ ] Confirm no stale LVs.
- [ ] Confirm no stale VLANs.
- [ ] Confirm no stale tcpdump processes.
- [ ] Confirm no stale DRAKVUF processes.
- [ ] Confirm disk usage stays within expected bounds.
- [ ] Confirm the saved sandbox remains unchanged.

### Summary

```text
Runs attempted:
Runs successful:
Clone failures:
Injection failures:
Install failures:
Plugin failures:
Cleanup failures:
Median duration:
Maximum disk use:
```

### Commands used

```bash
sudo xl list
sudo lvs -a
sudo ovs-vsctl show
ps -ef | grep -E 'dirwatch|drakvuf|injector|tcpdump' | grep -v grep
df -h
sudo vgs
```

---

# Phase 7 — Reliability and maintainability

## 7.1 Shell and Perl reliability

- [ ] Use `set -Eeuo pipefail` in new shell scripts.
- [ ] Add `trap` handlers for failure, interrupt, and exit.
- [ ] Quote all variable expansions unless splitting is intentional.
- [ ] Use arrays for commands where possible.
- [ ] Validate numeric values before using them.
- [ ] Use `mktemp` for temporary files.
- [ ] Use `flock` for per-origin and per-launcher locking.
- [ ] Use `timeout` for clone restore and injection operations.
- [ ] Check every external command's exit status.
- [ ] Write diagnostics to stderr.
- [ ] Keep machine-readable stdout clean where required by `dirwatch`.

### Commands used

```bash
shellcheck ~/drakvuf-tools/*.sh
perl -c ~/drakvuf-tools/clone-android.pl
```

### Evidence and notes

```text

```

---

## 7.2 Storage checks

- [ ] Check free space before accepting a sample.
- [ ] Check free VG space before creating snapshots.
- [ ] Set a minimum free-space threshold.
- [ ] Set a maximum sample size.
- [ ] Set a maximum extracted-file total.
- [ ] Set a maximum pcap size or capture duration.
- [ ] Set a maximum logcat size or duration.
- [ ] Fail safely when a threshold is reached.

### Commands used

```bash
df -P /malware_incoming /malware_processing /malware_finished
sudo vgs --units b --nosuffix -o vg_name,vg_size,vg_free
stat --printf='%s\n' /path/to/sample
```

### Configured thresholds

```text
Minimum output free space:
Minimum VG free space:
Maximum sample size:
Maximum extracted total:
Maximum pcap size:
Maximum logcat size:
```

---

## 7.3 Structured status and command logging

- [ ] Record every host command generated for an analysis.
- [ ] Record every guest command generated for an analysis.
- [ ] Redact secrets if future services add credentials.
- [ ] Store timestamps in UTC and optionally local time.
- [ ] Record tool versions with every analysis.
- [ ] Record the script Git commit with every analysis.
- [ ] Use atomic writes for `status.json`.
- [ ] Record cleanup success independently from analysis success.

### Candidate status document

```json
{
  "analysis_id": "",
  "status": "",
  "stage": "",
  "started_at": "",
  "finished_at": "",
  "duration_seconds": 0,
  "domain": "",
  "vlan": 0,
  "sample_sha256": "",
  "sample_type": "",
  "package": null,
  "drakvuf_exit": null,
  "install_exit": null,
  "launch_exit": null,
  "cleanup_status": "",
  "errors": []
}
```

> **Reconciled 2026-08-09 (issue #3).** This document is the direct ancestor
> of the shared job record in `docs/architecture/analysis-pipeline.md`,
> which adopts its `status` + `stage` split, its atomic-write requirement,
> and the candidate status vocabulary from §2.8. Three differences to carry
> into the implementation:
>
> - **`status` is now a closed, OS-independent set** — `completed`,
>   `failed`, `rejected`, `cancelled`, `interrupted`. The richer vocabulary
>   at §2.8 (`install_failed`, `hash_mismatch`, `analysis_timeout`, …)
>   becomes `failure_reason`, paired with `failure_stage`, and stays
>   Android-scoped where it is Android-specific. Nothing was discarded —
>   every value maps, and the mapping table is in the shared model.
> - **`cleanup_status` keeps its own axis**, which is what this section's
>   "Record cleanup success independently from analysis success" already
>   asked for; the shared model promotes it from a checkbox to a rule.
> - **`stimulate` is a stage, not a state**, because only Android has one.
>
> Fields the shared model adds that are missing here: `analysis_id` (which
> also names the result directory), `attempt` — `dirwatch` retries a
> timed-out sample on a *fresh* clone, so one submission can produce
> several clone lifecycles — `guest_filename`, `queue_reason`, the SHA-1
> and MD5 identification hashes, and `cancel_requested_at`/`cancelled_by`
> for user-initiated stops.

### Evidence and notes

```text

```

---

## 7.4 Recovery command

- [ ] Create a recovery script that accepts one analysis ID or clone identity.
- [ ] Display intended resources before deleting them.
- [ ] Restrict deletions to exact Android clone naming patterns.
- [ ] Destroy only the matching domain.
- [ ] Remove only the matching snapshot LV.
- [ ] Remove only the matching VLAN/OVS port.
- [ ] Stop only PIDs verified to belong to that analysis.
- [ ] Preserve logs and the original sample.
- [ ] Make repeated recovery safe.

### Commands used

```bash
# Record the final recovery-script invocation here.

```

### Evidence and notes

```text

```

---

# Phase 8 — Future Android-specific improvements

These are not prerequisites for the first working APK pipeline.

- [ ] Host-side static analysis to choose likely entry points.
- [ ] Sidecar analysis-recipe JSON.
- [ ] Automatic exported-component stimulation.
- [ ] Controlled UI stimulation.
- [ ] Screen unlock and orientation handling.
- [ ] Seeded contacts, SMS, files, and browser data.
- [ ] Multiple Android API-level sandboxes.
- [ ] Permissive and enforcing SELinux profiles.
- [ ] Android package-to-UID-to-process correlation.
- [ ] Binder activity monitoring.
- [ ] Android property-service monitoring.
- [ ] Package-manager event monitoring.
- [ ] Pre/post filesystem-state comparison.
- [ ] Anti-analysis and emulator-detection indicators.
- [ ] Refresh selected time/network state after clone restoration.

### Commands and notes

```text

```

---

# MVP completion gate

The first Android automated-analysis version is complete only when every item below is checked.

- [ ] `android_sandbox` restores reliably from its saved state.
- [ ] The injection anchor is found automatically.
- [ ] A sample is transferred into the Android guest.
- [ ] Host and guest SHA-256 values match.
- [ ] A benign APK installs under active DRAKVUF monitoring.
- [ ] Its launchable activity starts successfully.
- [ ] DRAKVUF output is saved.
- [ ] File-extraction output is saved when generated.
- [ ] Logcat is saved.
- [ ] Pcap is saved.
- [ ] Metadata and final status are saved.
- [ ] Failed installation produces a clear result and preserved logs.
- [ ] Two analyses can run without sharing resources or results.
- [ ] Success, failure, timeout, and interruption all clean up domains, LVs, VLANs, and capture processes.
- [ ] The golden Android LV is unchanged.
- [ ] The saved Android sandbox state is unchanged.
- [ ] The Ubuntu workflow still operates as before.
- [ ] The 50-run endurance test has no unexplained resource leaks.

### Final validation commands

```bash
sudo xl list
sudo lvs -a -o lv_name,origin,lv_size,data_percent
sudo ovs-vsctl show
ps -ef | grep -E 'dirwatch|drakvuf|injector|tcpdump' | grep -v grep
df -h /malware_incoming /malware_processing /malware_finished
sha256sum /home/user/Documents/android_sandbox.bak
sha256sum /root/android.json
```

### Final sign-off

```text
MVP version/tag:
Git commit:
Date:
Validated by:
Known limitations:
Next phase:
```

---

# Change log

| Date | Change | Commands / commit | Result | Author |
|---|---|---|---|---|
| 2026-08-06 | Initial checklist created | | | evilbootloader |
| 2026-08-11 | Golden `android` VM **reinstalled** with `HWACCEL=0` | BlissOS installer, Options → Graphics → Hardware Acceleration → Disable hardware acceleration; procedure in `docs/android_setup.md` | Golden VM boots to a usable UI; AND-001 resolved | evilbootloader |
| 2026-08-11 | Issue log populated from the 2026-08-11 diagnostic capture; §0.3 and §1.5 annotated | — | Phase 1 reopened: `android_sandbox` must be rebuilt from the reinstalled golden — DRAFT-037, published as [#7](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/7) | evilbootloader |
| 2026-08-11 | **`android_sandbox` rebuilt and restore-validated** from the reinstalled golden. New saved state `1844fc0a…`, anchor PID 3163. DNS DNAT deliberately not re-applied; anchor renamed to `nano` for anti-evasion | `docs/runbooks/rebuild-android-sandbox.md` | Phase 1 complete; issue #7 closed. §1.3 isolation still open | evilbootloader |
| 2026-08-17 | **Android MVP bring-up run.** `injector` proven against BlissOS (12 MB APK `writefile`/`readfile` byte-exact), clone 32G, network injection, native ELF traced, APK installed and launched. Every injection required a manual `fg` at the guest console — the `nano` anchor is never scheduled | `docs/runbooks/verify-android-mvp.md` (F1–F8) | `monkey` rejected in favour of `am start -n`; APK install exceeds the 120 s trace window | evilbootloader |
| 2026-08-17 | **`android_sandbox` re-saved to replace the injection anchor.** New saved state `465aa4d7…`, anchor PID **3174**, anchor is a backgrounded `ping` — self-scheduling, which the `nano` anchor was not. `pipeline-android.env` and `CLAUDE.md` updated the same day | §1.4/§1.5 annotations below | Three full unattended analyses completed; F1 closed pending the pcap question in §1.4 | evilbootloader |

---

# Issue log

Populated 2026-08-11 from a deliberate diagnostic capture of the golden
`android` domain (serial console, `logcat -b all -v threadtime` with a
`TRIGGER` marker, `dumpsys`, `lshal`, `getprop`, `/proc/mounts`). The raw
captures were prepared for BlissOS upstream and are not kept in this
repository, so **the excerpts below are the record** — reproduced verbatim
rather than cited.

Environment for every row: BlissOS `Android-x86/Blissful/x86_64:14/AP2A.240905.003/0:user/release-keys`,
kernel `6.6.129-crimson-xanmod1`, Xen 4.20 HVM domU nested in Proxmox/KVM,
1 vCPU / 2048 MB, `stdvga` + `bochs-drm` at 800x600, **no GPU passthrough**,
SELinux permissive.

| ID | Date | Phase/task | Symptom | Diagnostic commands | Resolution | Status |
|---|---|---|---|---|---|---|
| AND-001 | 2026-08-11 | §0.3 boot state | `surfaceflinger` SIGSEGVs reproducibly on opening a window in desktop mode, taking `system_server` into a 60-second watchdog loop — presents as a permanent boot animation. The faulting thread is an `llvmpipe-N` rasteriser worker executing JIT-generated shader code: `Fatal signal 11 (SIGSEGV), code 128 (SI_KERNEL), fault addr 0x0 in tid 1913 (llvmpipe-1)`, with `rip 0x7b1f119294a9` inside an anonymous mapping based at `0x7b1f11929000` — offset `0x4a9`, matching the single backtrace frame. An `avc: denied { execmem } for comm="RenderEngine"` precedes it by 2.6 s: the JIT allocating executable pages for the shader permutations the new window requires. With no GPU passthrough, all composition went through a software renderer that JIT-compiles shaders | `adb shell dumpsys SurfaceFlinger \| grep -i 'GLES:'` → `GLES: Mesa, llvmpipe (LLVM 16.0.0, 256 bits), OpenGL ES 3.2 Mesa 25.0.3`, `vulkan_renderengine: false`; `logcat -b all -v threadtime` across the fault | **`HWACCEL=0`**, confirmed by BlissOS upstream 2026-08-11: *"llvmpipe currently is still unstable on Android."* Set on the installer's Options → Graphics screen, which writes it into `/boot/grub/android.cfg` so it applies on every boot — typed at the GRUB prompt it lasts one boot only. Golden VM reinstalled with it the same day. The `execmem` denials went away with it: no llvmpipe JIT, no W^X request | **Closed 2026-08-11.** Fixed on the golden VM and inherited by the rebuilt `android_sandbox` (issue #7). Regression-checked after `xl restore`: an application opened in desktop mode over VNC and the renderer survived 60 s |
| AND-002 | 2026-08-11 | §0.4 / Phase 2 | `android.hardware.thermal.IThermal/default` is declared in VINTF but not installed. `servicemanager` retries the lazy start roughly once per second, indefinitely, three log lines each time — a measurable share of CPU on a 1-vCPU guest, and it floods the log. The same pattern appears for `aidl/activity` and `aidl/sensor_privacy` | `lshal`; `ls /apex /vendor/bin/hw`; `servicemanager: Tried to start aidl service … but was unable to` | **Self-inflicted, root cause known.** This build removes `com.android.hardware.thermal.intel` from `device/generic/common/treble.mk`: it and `com.android.hardware.thermal` both advertise the same `IThermal/default` instance, and the device manifest was rejected with `HAL "android.hardware.thermal" has a conflict`, restart-looping `zygote` and `surfaceflinger`. The kept generic APEX **does not appear in the resulting image** (absent from both `/apex` and `/vendor/bin/hw`), so the build now has a declared HAL with no implementation. Dropping the generic entry instead may be the correct fix if the Intel APEX is the only one that builds for x86. Raised with upstream; no answer yet | **Open.** Log noise and CPU cost only — no functional failure observed |
| AND-003 | 2026-08-11 | Diagnostics | Two symptoms seen during debugging that are **artifacts of the debug boot line, not defects**: (1) the guest suspending to S3 ~12 s after `boot_completed` with no wake source, and (2) `prng_seeder: Hanging forever because setup failed: Unable to open hwrng /dev/hw_random`. Both were chased as real faults before their cause was identified | Serial console under `DEBUG=2 … console=tty0 console=ttyS0,115200n8 androidboot.console=ttyS0 androidboot.enable_console=1 loglevel=7 ignore_loglevel no_console_suspend` | **Not defects.** Neither reproduces on a normal boot; they appear only under the debugging cmdline above. Recorded so they are not re-diagnosed — the S3 symptom in particular cost real time, because without `no_console_suspend` the serial log stops dead at `Suspending console(s)` and a sleeping guest is indistinguishable from a hung one | **Closed — no action.** Expect both to reappear whenever the debug boot line is used |

## Ruled out — do not re-investigate

Recorded 2026-08-11 alongside the rows above:

- **SELinux enforcement** as a cause of AND-001. Every `avc` line in the
  captures carries `permissive=1`, so the `execmem` request was *granted*
  and llvmpipe faulted anyway.
- **Unmounted partitions** — `/apex` and `/vendor` are both populated.
- **Kernel GPU faults / OOM** — no `i915`, `drm` error, oops or OOM kill in
  any `dmesg` capture.
- **A boot-time UI failure** — `bootanim` exits status 0 and
  `sys.boot_completed=1` fires. The UI came up; the renderer then died on
  the first window (AND-001).

---

# Source files used for this checklist

- `Project-definition.txt`
- `drakvuf-on-xen-nested-within-proxmox.md`
- `android_setup.md`
- `drakvuf-tools.zip`
  - `clone-ubuntu.pl`
  - `preconfig-ubuntu.sh`
  - `drakvuf-ubuntu.sh`
  - `run_analysis-ubuntu.sh`

> **2026-08-07 provenance note (added during the docs/ reorganization, not part of the original checklist content above):** `automation/` in this repository also contains `network-setup.sh`, `cleanup.sh`, `tcpdump.sh`, and `dirwatch.c`, which are discussed in checklist sections 2.9/2.10 above but were not listed in the original source inventory. It also inherits DRAKVUF's `LICENSE`. None of these were part of the `drakvuf-tools.zip` inventory recorded when this checklist was first written. Separately, the Xen guest configs referenced throughout this checklist (§1.2, §1.5) — `android_sandbox.cfg` and the golden `android.cfg` — are tracked in this repository under `misc/`, alongside the Ubuntu equivalents `misc/ubuntu.cfg` (golden `ubuntu`) and `misc/ubuntu_sandbox.cfg` (`ubuntu_sandbox`). *(Corrected 2026-08-11: those two were named `misc/linux.cfg` / `misc/linux_sandbox.cfg` when this note was written on 2026-08-07, and it flagged the misleading "linux" naming; issue #1 renamed them the following day, so the caveat is gone. This footer is editable despite the file-wide annotate-only rule — it is itself an editorial annotation, marked as such below, not recorded evidence.)* The filename `automated_drakvuf_on_xen_nested_within.md` in the original list above has also been corrected to `drakvuf-on-xen-nested-within-proxmox.md`, the actual filename on disk — no other content in this document was altered.
