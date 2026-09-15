# LibVMI / DRAKVUF kernel profiles

`linux.json` and `android.json` live here but are **not tracked in git**
(`.gitignore`). They are host-generated build products, not source: each
one is `dwarf2json` output for one exact kernel build, ~48 MB and ~62 MB
respectively. They were tracked until issue #4 and were removed from the
index then — the old blobs remain reachable in history at
`misc/linux.json` / `misc/android.json`, since untracking a file does not
rewrite history.

A fresh checkout therefore has no profiles and cannot run an analysis
until they are staged here. That is a deliberate trade: lean checkouts on
every CI job, at the cost of one deployment step.

## How the pipeline finds them

`sandboxd/stages.py` maps each `TargetOs` to a profile path relative to
the repository root (`StageConfig.profiles` — `profiles/linux.json` for
Ubuntu, `profiles/android.json`, `profiles/windows.json`), and
`sandboxd/guests.py` passes it to `drakvuf` and `injector` as `-r`.

**`-r` is the only way the profile is ever resolved for an analysis run.**
Clone domains are created with rewritten names (`<origin>-<vlan>-clone`)
and have no `/etc/libvmi.conf` stanza, so the LibVMI config file plays no
part in the pipeline. No copy or symlink to `/root/*.json` is needed.

`/etc/libvmi.conf` still matters for ad-hoc operator tooling run against
the *golden* and *template* domains by name (`vmi-process-list`, and the
setup guides' verification steps). Those stanzas should be repointed at
this directory so there is one copy of each profile on the host rather
than two that can silently diverge:

```
ubuntu {
	volatility_ist = "/root/sandbox_project/profiles/linux.json";
}
ubuntu_sandbox {
	volatility_ist = "/root/sandbox_project/profiles/linux.json";
}
```

## Current files

Recorded 2026-08-09, from the copies tracked immediately before they were
untracked. Use these to confirm a staged profile is the one this
repository was developed against.

| File | SHA-256 | Size | Kernel |
|---|---|---|---|
| `linux.json` | `cbaf50ede2f1cca3152cf2d2f8e19067081e38a600903ebc92f80805e5f5cda5` | 48632705 | `vmlinux-5.15.0-139-generic` |
| `android.json` | `9505bdc9987df066142e82cf6abeb1c5bb30e59a9ec7dc4f63ef6b8902f440af` | 65096793 | BlissOS v17.8.3 `vmlinux`, `dd4f5be2f56a…` |

The Android profile's kernel identity is pinned further in
`misc/Artifacts/kernel-identifiers.txt` — it is valid for that exact
BlissOS build only.

## Regenerating

### `linux.json` (Ubuntu golden VM)

From `docs/drakvuf-on-xen-nested-within-proxmox.md:388-396`. Adjust the 
kernel version to match `uname -r` in the guest, and install `linux-image-$(uname -r)-dbgsym`
 there beforehand.

Shut the golden VM down now; 

```bash
# Run on L1: Xen Dom0, as root
kpartx -a /dev/vg-root/ubuntu
mount -o ro /dev/mapper/vg--root-ubuntu5 /mnt
./dwarf2json-linux-amd64 linux \
    --system-map /mnt/boot/System.map-5.15.0-139-generic \
    --elf /mnt/usr/lib/debug/boot/vmlinux-5.15.0-139-generic \
    > /root/sandbox_project/profiles/linux.json
umount /mnt
kpartx -d /dev/vg-root/ubuntu
```

### `android.json` (BlissOS golden VM)

From `docs/android_setup.md:640-706`. Built on the **Android build
machine**, not on Dom0, then copied across. Requires the PR-65 branch of
`dwarf2json` — mainline mishandles the multiple compile units in the
BlissOS kernel.

```bash
# Run on the BlissOS build machine
cd "$HOME/BlissOS"
export ANDROID_USE_NDK_TRANSLATION=true
. build/envsetup.sh
lunch bliss_x86_64-ap2a-userdebug

"$HOME/dwarf2json-pr65-bin" linux \
    --elf "$OUT/obj/kernel/vmlinux" \
    --system-map "$OUT/obj/kernel/System.map" \
    > "$HOME/android.json"

# Validate before copying
test -s android.json
python3 -m json.tool android.json >/dev/null
```

Then, on Dom0:

```bash
sudo install -o root -g root -m 0600 \
    /tmp/android.json \
    /root/sandbox_project/profiles/android.json
```

Mode `0600` matches what `docs/android_setup.md:696-703` prescribed for
`/root/android.json`. The profiles are not secret — they are symbol
tables for public kernel builds — but they identify the exact guest
kernel under analysis, which is worth not publishing by accident.