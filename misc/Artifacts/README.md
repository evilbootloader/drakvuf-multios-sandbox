# BlissOS build provenance

Reproducibility record for the Android analysis guest, captured
**2026-08-06** from the BlissOS build host at the end of the build that
produced the ISO the `android` golden VM was installed from.

These files are a record, not inputs to anything. Nothing in
`automation/` reads them. They exist so the guest image can be rebuilt, or
a future image compared against this one, without relying on the build
host still existing.

## Which ISO this describes

Three ISOs were produced across the 2026-08-04 → 2026-08-06 build
iterations. **Only the final one is retained:**

```
Bliss-v17.8.3-x86_64-UNOFFICIAL-vanilla-20260806.iso
sha256 f113aae0754682751d8d6a6c1bc9a1f0ab77372160bb1b7fe1c335f2b040bfff
```

That is the image `misc/android.cfg` boots and the one `/root/android.json`
was generated against. The 0804 and 0805 builds were intermediate, are not
kept, and will not be recreated — their checksum rows were removed from
`artifact-checksums.sha256` on 2026-08-09, since a hash for an
unobtainable artifact verifies nothing. This note is the surviving record
that they existed.

The ISO itself is **not tracked by git** (`.gitignore`'s `*.iso` rule — it
is 4.1 GB). It lives beside this directory at
`misc/Bliss-v17.8.3-x86_64-UNOFFICIAL-vanilla-20260806.iso` on the
development machine, and on Dom0 at the path `misc/android.cfg` names.
Verified 2026-08-09: the local copy's sha256 matches the value above.

## Paths inside these files are build-host paths

Every path recorded here is rooted at `/home/user/BlissOS/out/...` on the
AOSP build host — a machine that is neither Dom0 nor this repository. Do
not read them as paths on any system this repo touches.

## What each file is

| File | Contents |
|---|---|
| `artifact-checksums.sha256` | sha256 of the retained build outputs — ISO, `kernel.img`, `ramdisk.img`, `initrd.img`, `ramdisk-recovery.img`. |
| `source-manifest.xml` | The full pinned `repo` manifest: every upstream project and revision the build was assembled from. This is the file that makes the build reproducible. |
| `kernel-identifiers.txt` | Kernel source revision `447ff15184f6dd2e0d010f7fba9af1d886bd7443`, release `6.6.129-crimson-xanmod1`, the Clang version string, and sha256 of `vmlinux` and `System.map`. |
| `kernel-config.txt` | The generated `.config` for that kernel — 10,963 lines. |
| `local-changes.patch` | The only two local modifications to the manifest sources: `BOARD_SYSTEMIMAGE_PARTITION_SIZE` raised 5 GB → 9 GB, and the `com.android.hardware.thermal.intel` HAL dropped from `treble.mk`. A rebuild without these will not match. |
| `repo-status.txt` | `repo status` at build time, showing which projects carried those modifications. |
| `build-identifiers.txt` | `TARGET_PRODUCT=bliss_x86_64`, `userdebug`, `BUILD_ID=AP2A.240905.003`, platform 14, security patch 2026-05-01. |
| `generated-build-properties.txt` | The resulting `build.prop` files across all partitions. |

## Why the kernel identifiers matter most

`kernel-identifiers.txt` and `kernel-config.txt` are the load-bearing pair.
The Android LibVMI profile (`misc/android.json`, deployed as
`/root/android.json`) is generated with `dwarf2json` against **this exact
kernel build**. A kernel rebuilt from a different revision or config
produces different symbol offsets, and DRAKVUF then attaches to the guest
and reports nothing useful — a failure that surfaces at analysis time, not
at boot.

If the golden Android VM is ever rebuilt, regenerate the profile from the
new kernel rather than reusing `android.json`.

## Related

- `docs/android_setup.md` §1–9 — the build procedure that produced these.
- `docs/android_setup.md` §14 — profile generation with `dwarf2json`.
- `docs/checklists/android.md` §0.1–0.2 — platform versions and the
  reproducibility-artifact checklist these files satisfy.