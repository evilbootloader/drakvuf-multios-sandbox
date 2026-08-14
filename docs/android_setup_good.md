# BlissOS Android 14 x86_64 for Xen/DRAKVUF with Debug Symbols and EthernetConfig

## Purpose

This build produces a BlissOS Android 14 x86_64 `userdebug` guest for the Xen/DRAKVUF analysis environment with:

* Xen-compatible kernel configuration.
* Kernel DWARF debug information.
* `KALLSYMS` support.
* An unstripped `vmlinux` and matching `System.map`.
* Bliss-Bass EthernetConfig integrated as a platform privileged application.
* A new `android.json` generated from the exact kernel used by the VM.

The tested build target is:

```text
Manifest branch: universe-x86
Lunch target:    bliss_x86_64-ap2a-userdebug
Android:         14 / AP2A
Architecture:    x86_64
```

Do not reuse an `android.json` from another kernel build.

---

# 1. Prepare the build environment

The tested build host uses Ubuntu Server 26.04 with approximately 28 GiB RAM, 24 CPU threads, and 30 GiB swap.

Install the build dependencies:

```bash
sudo apt update
sudo apt upgrade -y

sudo apt-get install -y \
    git-core gnupg flex bison gperf build-essential zip curl \
    zlib1g-dev gcc-multilib g++-multilib libc6-dev-i386 \
    x11proto-core-dev libx11-dev lib32z-dev ccache \
    libgl1-mesa-dev libxml2-utils xsltproc unzip squashfs-tools \
    python3 python3-mako libssl-dev ninja-build lunzip \
    syslinux syslinux-utils gettext genisoimage bc xorriso \
    xmlstarlet meson glslang-tools git-lfs libelf-dev aapt \
    zstd rdfind nasm pkg-config repo libncurses-dev rsync \
    fontconfig wget
```

Initialize Git LFS:

```bash
git lfs install
```

Install the Rust tooling used by the BlissOS tree:

```bash
sudo apt remove -y rustc bindgen cargo

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"

cargo install cargo-ndk
rustup target add x86_64-linux-android i686-linux-android
cargo install --version 0.69.1 bindgen-cli
cargo install cbindgen
```

The tested host uses 30 GiB swap:

```bash
sudo fallocate -l 30G "$HOME/swapfile"
sudo chmod 0600 "$HOME/swapfile"
sudo mkswap "$HOME/swapfile"
sudo swapon "$HOME/swapfile"

swapon --show
free -h
```

---

# 2. Fetch BlissOS

```bash
mkdir -p "$HOME/BlissOS"
cd "$HOME/BlissOS"

repo init \
    -u https://github.com/BlissOS/platform_manifest.git \
    -b universe-x86 \
    --git-lfs

sed -i \
    -e 's#path="external/alsa-lib" name="external_alsa-lib" remote="ag-github" revision="pie-x86"#path="external/alsa-lib" name="external_alsa-lib" remote="ag-github" revision="bp"#' \
    -e 's#path="external/alsa-utils" name="external_alsa-utils" remote="ag-github" revision="pie-x86"#path="external/alsa-utils" name="external_alsa-utils" remote="ag-github" revision="bp"#' \
    .repo/manifests/android-x86/02-android-x86.xml

repo sync \
    -c \
    --force-sync \
    --no-tags \
    --no-clone-bundle \
    -j8 \
    --optimized-fetch \
    --prune
```

Allow substantial free disk space for the complete checkout and build output.

---

# 3. Add NDK translation

```bash
cd "$HOME/BlissOS"

mkdir -p vendor/google/proprietary

git clone \
    https://github.com/supremegamers/vendor_google_proprietary_ndk_translation-prebuilt.git \
    vendor/google/proprietary/ndk_translation-prebuilt
```

Enable it:

```bash
export ANDROID_USE_NDK_TRANSLATION=true
```

This must be exported in every new build shell.

---

# 4. Select the build target

```bash
cd "$HOME/BlissOS"

export ANDROID_USE_NDK_TRANSLATION=true

. build/envsetup.sh
lunch bliss_x86_64-ap2a-userdebug

cd "$ANDROID_BUILD_TOP/external/htop"
git switch --detach 9a4879b48f9ca1a39aa4eaa67bccc171cd5bca35

cd "$ANDROID_BUILD_TOP"

```

Verify:

```bash
echo "ANDROID_BUILD_TOP=$ANDROID_BUILD_TOP"
echo "TARGET_PRODUCT=$TARGET_PRODUCT"
echo "TARGET_BUILD_VARIANT=$TARGET_BUILD_VARIANT"
echo "OUT=$OUT"
```

Expected:

```text
TARGET_PRODUCT=bliss_x86_64
TARGET_BUILD_VARIANT=userdebug
```

The tested output directory is:

```text
/home/user/BlissOS/out/target/product/x86_64
```

---

# 5. Check the thermal HAL fix

The previous working tree required removal of the duplicate Intel thermal implementation.

Check first:

```bash
grep -n 'com.android.hardware.thermal' \
    device/generic/common/treble.mk
```

If both are present:

```text
com.android.hardware.thermal.intel
com.android.hardware.thermal
```

remove the Intel entry:

```bash
sed -i \
  '/^[[:space:]]*com\.android\.hardware\.thermal\.intel[[:space:]]*\\/d' \
  device/generic/common/treble.mk
```

Verify:

```bash
grep -n 'com.android.hardware.thermal' \
    device/generic/common/treble.mk
```

The intended remaining implementation is:

```text
com.android.hardware.thermal
```

If upstream has already fixed the duplication, do not modify the file.

---

# 6. Add EthernetConfig

Clone the application into the AOSP applications tree:

```bash
cd "$HOME/BlissOS/packages/apps"

git clone \
    https://github.com/Bliss-Bass/packages_apps_EthernetConfig.git \
    EthernetConfig
```

Record the revision:

```bash
git -C "$HOME/BlissOS/packages/apps/EthernetConfig" \
    log -1 --oneline
```

Verify its product file:

```bash
cd "$HOME/BlissOS"

cat packages/apps/EthernetConfig/ethernet_config.mk
```

It should add:

```make
PRODUCT_PACKAGES += \
    EthernetConfig
```

and copy:

```text
privapp-permissions-ethernetconfig.xml
```

to the `system_ext` permission directory.

---

# 7. Include EthernetConfig in bliss_x86_64

The correct product definition is:

```text
device/generic/x86_64/bliss_x86_64.mk
```

Edit:

```bash
nano device/generic/x86_64/bliss_x86_64.mk
```

The beginning should contain:

```make
# includes the base of Android-x86 platform
$(call inherit-product,device/generic/common/x86_64.mk)

# Bliss Bass Ethernet configuration service
$(call inherit-product-if-exists, packages/apps/EthernetConfig/ethernet_config.mk)

# Overrides
PRODUCT_NAME := bliss_x86_64
PRODUCT_BRAND := Android-x86
PRODUCT_DEVICE := x86_64
PRODUCT_MODEL := Generic Android-x86_64
```

Verify:

```bash
grep -n -C 3 'EthernetConfig' \
    device/generic/x86_64/bliss_x86_64.mk
```

---

# 8. Validate EthernetConfig integration

Initialize the environment:

```bash
cd "$HOME/BlissOS"

export ANDROID_USE_NDK_TRANSLATION=true
. build/envsetup.sh
lunch bliss_x86_64-ap2a-userdebug
```

Verify product inclusion:

```bash
get_build_var PRODUCT_PACKAGES |
    tr ' ' '\n' |
    grep -x EthernetConfig
```

Expected:

```text
EthernetConfig
```

Verify the permission file:

```bash
get_build_var PRODUCT_COPY_FILES |
    tr ' ' '\n' |
    grep -i ethernetconfig
```

The tested result is:

```text
packages/apps/EthernetConfig/magisk-module/system/etc/permissions/privapp-permissions-ethernetconfig.xml:system/system_ext/etc/permissions/privapp-permissions-ethernetconfig.xml
```

Build only EthernetConfig first:

```bash
m EthernetConfig -j"$(nproc)"
```

The tested successful build generated:

```text
/home/user/BlissOS/out/target/product/x86_64/system/system_ext/priv-app/EthernetConfig/EthernetConfig.apk
```

Verify generically:

```bash
find "$OUT" -type f \
    -iname '*EthernetConfig*.apk' \
    -print
```

Do not continue to the complete ISO until these checks work.

## 8.1 Make the root console APEX- and ART-classpath-aware

The EthernetConfig helper is launched with `app_process`. On this Android 14
build, two independent conditions must be satisfied before a serial-console
`app_process` can start correctly:

1. the console must be created in the post-APEX/default mount namespace so
   `/apex/com.android.art` is visible; and
2. the console must inherit Android's generated runtime classpath variables
   (`BOOTCLASSPATH`, `DEX2OATBOOTCLASSPATH`, and `SYSTEMSERVERCLASSPATH`).

The failure mode was measured on 2026-08-14. Before the fix, `app_process`
first failed to resolve `libnativeloader.so`; after delaying the service for
APEX it could see `/apex/com.android.art`, but still aborted with exit 134
before `EthernetConfigurator.main()` because the generated classpath exports
were absent from the console environment. Importing
`/data/system/environ/classpath` manually made the helper start successfully.

### 8.1.1 Mark the console service as updatable

Edit:

```bash
nano system/core/rootdir/init.rc
```

Find the console service. In this tree it is:

```rc
service console /system/bin/sh
    class core
    console
    disabled
#   user shell
    group shell log readproc
    seclabel u:r:shell:s0
    setenv HOSTNAME console
    shutdown critical
```

Add `updatable`:

```rc
service console /system/bin/sh
    class core
    console
    disabled
    updatable
#   user shell
    group shell log readproc
    seclabel u:r:shell:s0
    setenv HOSTNAME console
    shutdown critical
```

`# user shell` deliberately remains commented in this analysis build. The
serial console therefore has uid 0 while retaining the `u:r:shell:s0` SELinux
domain.

### 8.1.2 Proposed permanent fix: start the console only after Android exports its classpaths

Do **not** leave the original early trigger active:

```rc
on init && property:ro.debuggable=1
    start console
```

A service started there can be created before the generated ART classpath
variables have been loaded. Merely killing or restarting that shell is not a
reliable fix for the first-start environment.

Locate the Android 14 classpath setup in `system/core/rootdir/init.rc`:

```rc
exec_start derive_classpath
load_exports /data/system/environ/classpath
```

Immediately after `load_exports`, add a private readiness property:

```rc
exec_start derive_classpath
load_exports /data/system/environ/classpath
setprop sys.console.classpath_ready 1
```

Replace the early console trigger with:

```rc
on property:sys.console.classpath_ready=1 && property:ro.debuggable=1
    start console
```

The intended ordering is therefore:

```text
APEX activation
    -> /apex/com.android.art visible
    -> derive_classpath
    -> load_exports /data/system/environ/classpath
    -> sys.console.classpath_ready=1
    -> first start of console
    -> app_process can initialize ART
```

Verify the source change before building:

```bash
grep -n -A12 -B4 'service console /system/bin/sh' \
    system/core/rootdir/init.rc

grep -n -A8 -B8 'load_exports /data/system/environ/classpath' \
    system/core/rootdir/init.rc

grep -n -A3 -B2 'sys.console.classpath_ready' \
    system/core/rootdir/init.rc

git -C system/core diff -- rootdir/init.rc
```

The important properties of the final source are:

```text
console service contains: updatable
old "on init ... start console" trigger: absent
load_exports is followed by: setprop sys.console.classpath_ready 1
console starts on: sys.console.classpath_ready=1 && ro.debuggable=1
```

---

# 9. Configure the kernel for Xen and DRAKVUF

Use the kernel output directory:

```bash
cd "$ANDROID_BUILD_TOP"

make -C "$ANDROID_BUILD_TOP/kernel/x86/common" \
    O="$OUT/obj/kernel" \
    ARCH=x86_64 \
    menuconfig
```

The active configuration is:

```text
$OUT/obj/kernel/.config
```

Do not accidentally configure another `.config` without `O="$OUT/obj/kernel"`.

## Xen

The project-tested settings include:

```text
CONFIG_XEN=y
CONFIG_XEN_BLKDEV_BACKEND=y
CONFIG_XEN_BLKDEV_FRONTEND=y
```

and:

```text
CONFIG_XEN_NETDEV_BACKEND=n
CONFIG_XEN_NETDEV_FRONTEND=n
```

Keep these values unless intentionally changing the Xen guest-device architecture.

## Debug symbols

Enable:

```text
CONFIG_DEBUG_INFO=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
```

Use one appropriate DWARF selection, for example:

```text
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
```

or:

```text
CONFIG_DEBUG_INFO_DWARF5=y
```

Do not select mutually exclusive DWARF formats simultaneously.

## SELINUX

```text
CONFIG_DEFAULT_SECURITY_SELINUX=y
CONFIG_SECURITY_SELINUX_BOOTPARAM=y
``` 

## KernelSU

KernelSU is independent from DRAKVUF symbol generation.

Check:

```bash
grep -Ei 'KSU|KERNELSU' \
    "$OUT/obj/kernel/.config"
```

The later verified project build contained:

```text
CONFIG_KSU=y
# CONFIG_KSU_DEBUG is not set
```

Keeping KernelSU enabled for the initial EthernetConfig analysis image is acceptable. It can later be removed in a separate hardened build once the platform-integrated EthernetConfig functionality has been fully tested.

Save the complete kernel config:

```bash
cp "$OUT/obj/kernel/.config" \
    "$HOME/blissos-xen-ethernetconfig-kernel.config"
```

---

# 10. Increase the system partition

Check:

```bash
grep -n '^BOARD_SYSTEMIMAGE_PARTITION_SIZE' \
    device/generic/common/BoardConfig.mk
```

The project uses 9 GB:

```text
BOARD_SYSTEMIMAGE_PARTITION_SIZE := 9000000000
```

If it is still 5 GB:

```bash
sed -i \
  's/^BOARD_SYSTEMIMAGE_PARTITION_SIZE := 5000000000$/BOARD_SYSTEMIMAGE_PARTITION_SIZE := 9000000000/' \
  device/generic/common/BoardConfig.mk
```

Verify:

```bash
grep -n '^BOARD_SYSTEMIMAGE_PARTITION_SIZE' \
    device/generic/common/BoardConfig.mk
```

---

# 11. Final pre-build checks

```bash
cd "$HOME/BlissOS"

export ANDROID_USE_NDK_TRANSLATION=true
. build/envsetup.sh
lunch bliss_x86_64-ap2a-userdebug
```

Check EthernetConfig:

```bash
get_build_var PRODUCT_PACKAGES |
    tr ' ' '\n' |
    grep -x EthernetConfig

get_build_var PRODUCT_COPY_FILES |
    tr ' ' '\n' |
    grep -i ethernetconfig
```

Check kernel settings:

```bash
grep -E \
'^(CONFIG_DEBUG_INFO|CONFIG_DEBUG_INFO_DWARF|CONFIG_KALLSYMS|CONFIG_KALLSYMS_ALL|CONFIG_XEN|CONFIG_XEN_BLKDEV|CONFIG_XEN_NETDEV|CONFIG_KSU)' \
"$OUT/obj/kernel/.config" || true
```

Check the console/APEX/classpath source fix:

```bash
grep -n -A12 -B4 'service console /system/bin/sh' \
    system/core/rootdir/init.rc

grep -n -A8 -B8 'load_exports /data/system/environ/classpath' \
    system/core/rootdir/init.rc

grep -n -A3 -B2 'sys.console.classpath_ready' \
    system/core/rootdir/init.rc
```

Confirm that the service contains `updatable`, the original early
`on init ... start console` trigger has been removed, and the late readiness
trigger is present.

Check partition size:

```bash
grep -n '^BOARD_SYSTEMIMAGE_PARTITION_SIZE' \
    device/generic/common/BoardConfig.mk
```


---

# 12. Build the ISO

```bash
cd "$ANDROID_BUILD_TOP"

export ANDROID_USE_NDK_TRANSLATION=true
. build/envsetup.sh
lunch bliss_x86_64-ap2a-userdebug

make iso_img -j"$(nproc --all)"
```

If memory pressure becomes excessive:

```bash
make iso_img -j12
```

or:

```bash
make iso_img -j8
```

Locate the resulting image:

```bash
find "$OUT" \
    -maxdepth 3 \
    -type f \
    -iname '*.iso' \
    -print
```

Checksum it:

```bash
ISO_PATH="$(
    find "$OUT" \
        -maxdepth 3 \
        -type f \
        -iname '*.iso' |
    head -n1
)"

test -n "$ISO_PATH" || exit 1

sha256sum "$ISO_PATH" |
    tee "$HOME/blissos-xen-ethernetconfig.iso.sha256"
```

---

# 13. Verify EthernetConfig in the final product

```bash
find "$OUT/system" \
    \( -iname '*EthernetConfig*' -o -iname '*ethernetconfig*' \) \
    -print
```

Expected APK:

```text
$OUT/system/system_ext/priv-app/EthernetConfig/EthernetConfig.apk
```

Expected permission XML:

```text
$OUT/system/system_ext/etc/permissions/privapp-permissions-ethernetconfig.xml
```

Explicitly verify:

```bash
test -f \
    "$OUT/system/system_ext/priv-app/EthernetConfig/EthernetConfig.apk"

test -f \
    "$OUT/system/system_ext/etc/permissions/privapp-permissions-ethernetconfig.xml"
```

---

# 14. Verify the kernel debug artifacts

Set:

```bash
VMLINUX="$OUT/obj/kernel/vmlinux"
SYSTEM_MAP="$OUT/obj/kernel/System.map"
```

Check:

```bash
test -s "$VMLINUX"
test -s "$SYSTEM_MAP"

ls -lh "$VMLINUX" "$SYSTEM_MAP"
file "$VMLINUX"
```

Verify DWARF sections:

```bash
readelf -S "$VMLINUX" |
    grep -E '\.debug_info|\.debug_abbrev|\.debug_line'
```

Check symbols:

```bash
nm "$VMLINUX" | head
```

Record checksums:

```bash
sha256sum \
    "$VMLINUX" \
    "$SYSTEM_MAP" \
    | tee "$HOME/blissos-xen-ethernetconfig-kernel.sha256"
```

---

# 15. Generate a new dwarf2json profile

Install Go:

```bash
sudo apt update
sudo apt install -y golang-go git
```

Build the project-tested PR-65 version:

```bash
cd "$HOME"

rm -rf dwarf2json-pr65

git clone \
    https://github.com/volatilityfoundation/dwarf2json.git \
    dwarf2json-pr65

cd dwarf2json-pr65

git fetch origin \
    pull/65/head:handle-multiple-compile-units

git switch handle-multiple-compile-units

go build \
    -o "$HOME/dwarf2json-pr65-bin" \
    .
```

Record the dwarf2json revision:

```bash
git rev-parse HEAD |
    tee "$HOME/dwarf2json-pr65.commit"
```

Return to BlissOS:

```bash
cd "$HOME/BlissOS"

export ANDROID_USE_NDK_TRANSLATION=true
. build/envsetup.sh
lunch bliss_x86_64-ap2a-userdebug
```

Generate a profile from the exact kernel:

```bash
VMLINUX="$OUT/obj/kernel/vmlinux"
SYSTEM_MAP="$OUT/obj/kernel/System.map"

"$HOME/dwarf2json-pr65-bin" linux \
    --elf "$VMLINUX" \
    --system-map "$SYSTEM_MAP" \
    > "$HOME/android-ethernetconfig.json"
```

Validate:

```bash
test -s "$HOME/android-ethernetconfig.json"

python3 -m json.tool \
    "$HOME/android-ethernetconfig.json" \
    >/dev/null

ls -lh "$HOME/android-ethernetconfig.json"

sha256sum "$HOME/android-ethernetconfig.json" |
    tee "$HOME/android-ethernetconfig.json.sha256"
```

Any kernel rebuild requires a new profile.

---

# 16. Copy the profile to Xen Dom0

From the builder:

```bash
scp "$HOME/android-ethernetconfig.json" \
    user@XEN_DOM0_HOST:/tmp/android.json
```

On Dom0:

```bash
sudo install \
    -o root \
    -g root \
    -m 0600 \
    /tmp/android.json \
    /root/android.json
```

Verify:

```bash
sudo test -s /root/android.json
sudo sha256sum /root/android.json
```

The corresponding LibVMI definitions are:

```conf
android {
    volatility_ist = "/root/android.json";
}

android_sandbox {
    volatility_ist = "/root/android.json";
}
```

Check for existing entries before adding duplicates:

```bash
sudo grep -n -A3 -B1 \
    -E '^android(_sandbox)?[[:space:]]*\{' \
    /etc/libvmi.conf
```

---

# 17. Verify EthernetConfig after boot

Once the newly built system is running:

```bash
pm list packages | grep -i ethernet
```

Determine the application path:

```bash
pm path com.example.ethernetconfig
```

The relevant distinction is that the application should come from the ROM's `system_ext` partition rather than `/data/app`.

Check:

```bash
ls -l \
    /system/system_ext/priv-app/EthernetConfig/ \
    2>/dev/null || true

ls -l \
    /system_ext/priv-app/EthernetConfig/ \
    2>/dev/null || true
```

Check the permission whitelist:

```bash
ls -l \
    /system/system_ext/etc/permissions/privapp-permissions-ethernetconfig.xml \
    2>/dev/null || true

ls -l \
    /system_ext/etc/permissions/privapp-permissions-ethernetconfig.xml \
    2>/dev/null || true
```

Inspect package state:

```bash
dumpsys package com.example.ethernetconfig
```

Inspect networking:

```bash
ip addr
ip route
getprop | grep -i ethernet # Nothing found in this one
```

## 17.1 Why this app was built into the ROM

**This is the reason for the rebuild, so it is worth stating plainly.**

`docs/runbooks/verify-android-isolation.md` established by measurement on
2026-08-12 that this Android 14 build has **no shell command that sets the
Ethernet resolver**: `/etc/resolv.conf` is a no-op, `setprop net.dns1` is a
no-op, `ndc resolver` does not exist, and `cmd ethernet help` returns
`No shell command implementation.` Android 14 moved resolver configuration
behind binder (`IDnsResolver`) with no shell client.

`preconfig-android.sh` (DRAFT-016) cannot click a UI. Without a
non-interactive path, the only remaining options were baking a resolver into
the golden image — reversing issue #7 — or a Dom0-side DNS redirect, which
reopens part of the containment posture DRAFT-029 closed.

EthernetConfig removes that choice. It is not merely a settings UI: it ships
a **standalone `main()` entry point** that talks to `IEthernetManager`
directly, and that entry point is drivable from a shell.

## 17.2 The non-interactive command — the DRAFT-016 mechanism

Read from the upstream source at
`app/src/main/java/com/example/ethernetconfig/network/`
(`RootEthernetHelper.kt` builds the command, `EthernetConfigurator.kt`
implements it), revision recorded in §6:

```text
CLASSPATH=<apk> app_process / \
    com.example.ethernetconfig.network.EthernetConfigurator \
    STATIC <iface> <ip> <prefix> <gw> <dns1> <dns2>

CLASSPATH=<apk> app_process / \
    com.example.ethernetconfig.network.EthernetConfigurator \
    DHCP <iface>
```

Positional, in that order. `<gw>`, `<dns1>` and `<dns2>` accept the literal
string `none`.

> **That is the upstream form, not the one to run here.** On this image it
> needs two changes, both established by measurement on 2026-08-14: the
> explicit 64-bit launcher `/system/bin/app_process64`, and the ART classpath
> environment imported first. **Use §17.2.2**; the block above is recorded
> only to show what the upstream helper builds.

### 17.2.1 Required ART classpath environment

**Validated on this image on 2026-08-14:** the root serial console could see
`/apex/com.android.art` after the console-service namespace fix, but
`app_process` still aborted with exit 134 before reaching
`EthernetConfigurator.main()` because the console environment did not contain
the generated ART classpath exports.

The working runtime fix was:

```sh
while IFS=' ' read -r action name value; do
    [ "$action" = "export" ] && export "$name=$value"
done < /data/system/environ/classpath
```

Verify that it populated the important variables:

```sh
env | grep -E \
    '^(BOOTCLASSPATH|DEX2OATBOOTCLASSPATH|SYSTEMSERVERCLASSPATH)='
```

Also verify that the ART APEX is visible:

```sh
ls -ld /apex/com.android.art
ls -l /apex/com.android.art/lib64/libnativeloader.so
```

The §8.1.2 late-start change is a proposed permanent fix and must be verified on the next rebuilt image. It is intended to make these variables
present automatically on future boots. The import loop above remains the
safe runtime fallback and should also be used by automation unless/until the
late-console build is verified on the deployed image.

### 17.2.2 Run EthernetConfig non-interactively

Derive the APK path rather than hard-coding it:

```sh
APK="$(pm path com.example.ethernetconfig | sed 's/^package://')"
echo "$APK"
```

For this x86_64 image, use the explicit 64-bit launcher:

```sh
CLASSPATH="$APK" /system/bin/app_process64 / \
    com.example.ethernetconfig.network.EthernetConfigurator \
    STATIC eth0 172.16.1.2 24 172.16.1.1 1.1.1.1 none

echo "exit: $?"
```

DHCP is:

```sh
CLASSPATH="$APK" /system/bin/app_process64 / \
    com.example.ethernetconfig.network.EthernetConfigurator \
    DHCP eth0

echo "exit: $?"
```

For scripts that must work even on an image where the console did not inherit
the classpath exports, use the complete sequence:

```sh
while IFS=' ' read -r action name value; do [ "$action" = "export" ] && export "$name=$value"; done < /data/system/environ/classpath
APK="$(pm path com.example.ethernetconfig | sed 's/^package://')"
CLASSPATH="$APK" /system/bin/app_process64 / com.example.ethernetconfig.network.EthernetConfigurator STATIC eth0 172.16.1.2 24 172.16.1.1 1.1.1.1 none
```

Or as a single line:

```sh
while IFS=' ' read -r action name value; do [ "$action" = "export" ] && export "$name=$value"; done < /data/system/environ/classpath && APK="$(pm path com.example.ethernetconfig | sed 's/^package://')" && CLASSPATH="$APK" /system/bin/app_process64 / com.example.ethernetconfig.network.EthernetConfigurator STATIC eth0 172.16.1.2 24 172.16.1.1 1.1.1.1 none
```

**No `su` is required for this console path.** The analysis console is already
uid 0. Keep in mind that it still runs in SELinux context `u:r:shell:s0`; the
analysis boot currently uses permissive SELinux (§24), so SELinux denials can
be observed without blocking the call.

Internally the helper resolves the Android Ethernet binder service and uses
the framework Ethernet configuration APIs, including DNS in
`StaticIpConfiguration`. This is why it is preferable to direct `ip`/property
workarounds for the final automation path.

### Verify it, and record the result

**Partially validated on 2026-08-14.** The shell launch path was confirmed to proceed once `/data/system/environ/classpath` was imported. The remaining deployment validation is to confirm address/route/DNS state and observe the expected DNS traffic in DRAFT-013's pcap.

```bash
ip -br addr show dev eth0
ip route
ip route show table eth0

ping -c2 1.1.1.1
ping -c2 google.com

dumpsys connectivity | grep -iA5 dns
cat -v /data/misc/ethernet/ipconfig.txt 2>/dev/null | head -40
```

Three things to establish, because each changes what `preconfig-android.sh`
has to do:

1. **Does it replace the manual `ip` chain entirely?** The measured working
   sequence on the **previous** image needed five commands, including
   `ip route replace … table eth0` — Android's per-network policy routing,
   which a translated Ubuntu script would never have produced. Configuring
   through `IEthernetManager` should make the framework install address,
   route and per-network table itself. If it does, seven parity-matrix rows
   collapse into one command.
2. **Does it take effect without a reboot?** `preconfig-android.sh` runs
   against an already-booted clone, so a mechanism needing a restart is a
   different design.
3. **Is `private_dns_mode` still `opportunistic`?** EthernetConfig does not
   touch it, so this is unchanged and still live:

   ```bash
   settings get global private_dns_mode
   settings put global private_dns_mode off
   ```

   Left at `opportunistic`, Android upgrades DNS to DNS-over-TLS on port 853
   because `1.1.1.1` supports it — and the per-sample pcap then records TLS
   instead of the domains a sample looked up, silently, with nothing failing.
   `docs/architecture/networking.md`'s claim that a public resolver "costs no
   visibility" depends on plaintext UDP/53 and does not hold on Android
   without this.

### If `app_process` aborts before `main()`

The two failure modes below were actually observed on this build and should
be checked before investigating the EthernetConfig code itself.

1. **ART APEX not visible / `libnativeloader.so` not found.**

   Check:

   ```sh
   ls -ld /apex/com.android.art
   ls -l /apex/com.android.art/lib64/libnativeloader.so
   ```

   If the console cannot see the ART APEX while Zygote can, the console was
   started in the wrong/pre-APEX mount namespace. Recheck §8.1 and confirm the
   `console` service is `updatable` and is not first-started by the old early
   trigger.

2. **ART APEX visible, but `app_process` aborts with exit 134 before
   `EthernetConfigurator.main()`.**

   Check:

   ```sh
   env | grep -E \
       '^(BOOTCLASSPATH|DEX2OATBOOTCLASSPATH|SYSTEMSERVERCLASSPATH)='
   ```

   If those variables are missing, import the generated Android environment:

   ```sh
   while IFS=' ' read -r action name value; do
       [ "$action" = "export" ] && export "$name=$value"
   done < /data/system/environ/classpath
   ```

   Then retry `app_process`. This exact import was confirmed to make the
   helper start on the 2026-08-14 image.

If ART starts but the class itself cannot be found, then investigate dexpreopt
or the APK contents. `Android.bp` sets `optimize: { enabled: false }`, so the
fully-qualified class name is not expected to be obfuscated.

For native abort diagnostics:

```sh
logcat -b crash -d -v threadtime
ls -lt /data/tombstones 2>/dev/null | head
```

For SELinux diagnostics:

```sh
cat /proc/self/attr/current
dmesg | grep -i 'avc: denied' | tail -50
```

---

# 18. Validate DRAKVUF

With the new guest kernel and corresponding `android.json`, verify that:

```text
LibVMI initializes against the Android guest.
The new profile loads without symbol errors.
Process enumeration works.
DRAKVUF attaches successfully.
Required Android/Linux hooks initialize.
```

Never use an old symbol profile merely because the visible kernel version string appears unchanged.

---

# 19. Preserve reproducibility artifacts

Pin the source manifest:

```bash
cd "$ANDROID_BUILD_TOP"

repo manifest -r \
    -o "$HOME/blissos-pinned-manifest.xml"
```

Preserve kernel config:

```bash
cp "$OUT/obj/kernel/.config" \
    "$HOME/blissos-xen-ethernetconfig-kernel.config"
```

Save source changes:

```bash
git -C device/generic/common diff \
    > "$HOME/blissos-device-generic-common.patch"

git -C device/generic/x86_64 diff \
    > "$HOME/blissos-device-x86_64-ethernetconfig.patch"
```

Preserve the console/APEX/classpath init change:

```bash
git -C system/core diff -- rootdir/init.rc \
    > "$HOME/blissos-system-core-console-runtime.patch"
```

Record EthernetConfig commit:

```bash
git -C packages/apps/EthernetConfig rev-parse HEAD \
    > "$HOME/ethernetconfig.commit"
```

Record tool versions:

```bash
{
    date -Is
    rustc --version
    cargo --version
    repo version
    git --version
    python3 --version
    go version 2>/dev/null || true
    uname -a
} > "$HOME/blissos-build-versions.txt"
```

Preserve together:

```text
blissos-pinned-manifest.xml
blissos-xen-ethernetconfig-kernel.config
blissos-device-generic-common.patch
blissos-device-x86_64-ethernetconfig.patch
blissos-system-core-console-runtime.patch
ethernetconfig.commit
blissos-build-versions.txt
blissos-xen-ethernetconfig.iso.sha256
blissos-xen-ethernetconfig-kernel.sha256
dwarf2json-pr65.commit
android-ethernetconfig.json
android-ethernetconfig.json.sha256
android.cfg
```

---

# 20. Short rebuild procedure

For the already configured source tree:

```bash
cd "$HOME/BlissOS"

export ANDROID_USE_NDK_TRANSLATION=true
. build/envsetup.sh
lunch bliss_x86_64-ap2a-userdebug
```

Verify EthernetConfig:

```bash
get_build_var PRODUCT_PACKAGES |
    tr ' ' '\n' |
    grep -x EthernetConfig

get_build_var PRODUCT_COPY_FILES |
    tr ' ' '\n' |
    grep -i ethernetconfig
```

Verify debug configuration:

```bash
grep -E \
'^(CONFIG_DEBUG_INFO|CONFIG_DEBUG_INFO_DWARF|CONFIG_KALLSYMS|CONFIG_KALLSYMS_ALL|CONFIG_XEN|CONFIG_KSU)' \
"$OUT/obj/kernel/.config" || true
```

Verify the console runtime fix is still present:

```bash
grep -n -A12 -B4 'service console /system/bin/sh' system/core/rootdir/init.rc
grep -n -A8 -B8 'load_exports /data/system/environ/classpath' system/core/rootdir/init.rc
grep -n -A3 -B2 'sys.console.classpath_ready' system/core/rootdir/init.rc
```

Build:

```bash
make iso_img -j"$(nproc --all)"
```

Verify:

```bash
test -s "$OUT/obj/kernel/vmlinux"
test -s "$OUT/obj/kernel/System.map"

test -f \
    "$OUT/system/system_ext/priv-app/EthernetConfig/EthernetConfig.apk"

test -f \
    "$OUT/system/system_ext/etc/permissions/privapp-permissions-ethernetconfig.xml"
```

If the kernel changed, regenerate:

```bash
"$HOME/dwarf2json-pr65-bin" linux \
    --elf "$OUT/obj/kernel/vmlinux" \
    --system-map "$OUT/obj/kernel/System.map" \
    > "$HOME/android-ethernetconfig.json"
```

---

# Part II — Deploying the built image on Xen Dom0

Everything below runs on **L1 / Xen Dom0**, not on the build host. It was
absent from the first draft of this guide; the procedure is carried over from
`docs/android_setup.md` §11–§13 and §16–§17, updated for what the repository
now owns.

**Sections 1–20 describe the current reproducible build.** Part II covers
deployment and validation on Xen Dom0.

The numbering is build-order, not run-order. Three sections above run late:

| Section | When it actually runs |
|---|---|
| §16 copy the profile to Dom0 | after §23, once the new image is installed |
| §17 verify EthernetConfig after boot | after §23 — it needs a booted guest |
| §18 validate DRAKVUF | last, after §25 rebuilds the template |

**Read §26 before deploying.** A new kernel makes the existing
`android.json`, `state/android_sandbox.bak` and the anchor PID from issue #7
all stale, and they fail in ways that do not look like a stale profile.

> **`docs/android_setup.md` stays authoritative for diagnosis.** Its §18–§24
> — the two `DEBUG=2` initrd shells, the Android userspace shell, the
> `update_verifier` bypass and the thermal-VINTF conflict — are not
> reproduced here. Read them there when a boot fails.

---

# 21. The LV, and what must not be touched

The golden LV already exists from the original build:

```bash
sudo lvs -a -o lv_name,lv_size,origin vg-root
sudo blockdev --getsize64 /dev/vg-root/android
```

Creating it from scratch, if it does not:

```bash
sudo lvcreate -L32G -n android vg-root
```

> **Reinstalling over `/dev/vg-root/android` destroys the existing golden
> image.** That image is a manual, multi-hour BlissOS install —
> `misc/android.cfg` sets `on_crash = "preserve"` for exactly that reason.
> Confirm it is genuinely being replaced before §23 writes to it, and never
> point an install at `android_sandbox` or at a clone LV.

---

# 22. Domain configuration

**The repository owns these files now; do not hand-write a new `android.cfg`
on the host.** `docs/android_setup.md` §12 embeds one inline, and that copy
predates the repo↔host reconciliation:

```text
misc/android.cfg           golden `android`
misc/android_sandbox.cfg   template `android_sandbox`
```

Deploy from the checkout rather than editing in place — the same rule the
automation scripts follow:

```bash
git -C /root/sandbox_project log -1
git -C /root/sandbox_project status --porcelain     # expect empty
```

## 22.1 The cdrom path is broken, and this rebuild is what needs it

`misc/android.cfg`'s `disk =` line still names the install ISO under
`/home/user/drakvuf-tools/`, a path issue #4's deployment renamed to
`…​.retired-issue4`. The file records this as **BROKEN AS OF 2026-08-09** and
deliberately left it rather than pointing at the rollback copy.

Nothing in the analysis pipeline reads that line — clones never see it, and
the clone script rewrites `disk =` wholesale — so it has cost nothing so far.
**Installing a new ISO is the one operation it blocks.** Fix it as part of
this rebuild: put the new ISO somewhere stable, update the line, and commit
that change rather than editing the deployed copy.

```bash
sha256sum /path/to/new/blissos-xen-ethernetconfig.iso
# compare against $HOME/blissos-xen-ethernetconfig.iso.sha256 from §12
```

---

# 23. Install into the LV

```bash
sudo xl create /root/sandbox_project/misc/android.cfg
sudo xl list
sudo xl vncviewer android
```

Through VNC:

1. Choose the installation option.
2. Select `/dev/xvda`.
3. Create an ext4 partition.
4. On the **Options** screen (Additional options), go to
   Graphics → Hardware Acceleration → **Disable hardware acceleration**,
   which sets `HWACCEL=0`.
5. Install GRUB when prompted.
6. Finish and shut down.

**Step 4 comes before step 5.** Options chosen there are written into
`/boot/grub/android.cfg` and apply on every boot; typed at the GRUB prompt
instead, they last one boot.

> **`HWACCEL=0` is required, not cosmetic.** Without it the guest renders
> through Mesa llvmpipe, and SurfaceFlinger dies whenever a window opens in
> desktop mode — taking `system_server` into a watchdog loop that presents as
> a permanent boot animation. Confirmed by BlissOS upstream 2026-08-11:
> **"llvmpipe currently is still unstable on Android"**, with `HWACCEL=0` given
> as the fix.

Verify it took effect on first boot — the option is silent when it does not
apply. There is no `adb` on this build, so run it from the root console
rather than `docs/android_setup.md`'s `adb shell` form:

```sh
dumpsys SurfaceFlinger | grep -i 'GLES:'
```

Anything still reporting `llvmpipe` means the option did not reach the kernel
line; check `/boot/grub/android.cfg`. Recorded on the previous build **before**
the fix, for comparison:

```text
GLES: Mesa, llvmpipe (LLVM 16.0.0, 256 bits), OpenGL ES 3.2 Mesa 25.0.3
```

---

# 24. Serial console and the kernel command line

`serial = "pty"` is already in `misc/android.cfg`. Capture a boot:

```bash
sudo xl create /root/sandbox_project/misc/android.cfg

# second terminal
sudo script -q -f -c 'xl console android' /tmp/bliss-console.log
```

Detach with `Ctrl+]`.

At the BlissOS GRUB menu press `e`, find the kernel line, remove `quiet` and
any duplicate console parameters, then append:

```text
androidboot.selinux=permissive console=tty0 console=ttyS0,115200n8 androidboot.console=ttyS0 androidboot.enable_console=1 loglevel=7 ignore_loglevel no_console_suspend
```

Boot with `Ctrl+X` or `F10`.

> **`androidboot.enable_console=1` is what makes the rest of this project
> work.** It is the root console every in-guest step depends on: §17's
> `app_process` invocation, DRAFT-013's manual configuration, and the anchor
> process the sandbox template is saved around. Without it there is no shell
> at all, because this build ships no `adb`.
>
> **`DEBUG=2` is deliberately absent from the line above.** It stops the boot
> at two successive initrd shells that each wait for `exit`, so an unattended
> guest looks hung. Add it only for `docs/android_setup.md` §18–§20. Drop
> `console=tty0` too when capturing a normal boot — it makes fbcon draw
> kernel messages onto the same framebuffer SurfaceFlinger composites on.
>
> Keep `no_console_suspend` either way: without it the log stops dead at
> `Suspending console(s)` and a suspended guest cannot be told apart from a
> hung one.

Inspect:

```bash
tail -n 300 /tmp/bliss-console.log

grep -iE 'panic|fatal|reboot|shutdown|update_verifier|bootctrl|apex|vintf|zygote|surfaceflinger|linker|mount|failed|cannot' \
    /tmp/bliss-console.log | tail -n 400
```

Successful-boot indicators, from the Android userspace shell:

```sh
getprop init.svc.zygote            # running
getprop init.svc.surfaceflinger    # running
getprop sys.boot_completed         # 1
```

Verify the console runtime environment required by §17:

```sh
ls -ld /apex/com.android.art
ls -l /apex/com.android.art/lib64/libnativeloader.so

env | grep -E \
    '^(BOOTCLASSPATH|DEX2OATBOOTCLASSPATH|SYSTEMSERVERCLASSPATH)='
```

If the ART APEX exists but the classpath variables are absent, the runtime
fallback is:

```sh
while IFS=' ' read -r action name value; do
    [ "$action" = "export" ] && export "$name=$value"
done < /data/system/environ/classpath
```

After importing, rerun the `env | grep ...` check. This exact command was
validated on 2026-08-14 and allowed `app_process` to proceed past ART startup.
If the rebuilt image still requires the manual import, recheck the §8.1
`load_exports` readiness trigger before making the image the new golden VM.

---

# 25. Rebuild the sandbox template

**Do not improvise this.** The procedure is
`docs/runbooks/rebuild-android-sandbox.md` (issue #7 / DRAFT-037), which
covers snapshotting the golden LV into `android_sandbox`, booting it, opening
the anchor process, and `xl save`-ing to
`/root/sandbox_project/state/android_sandbox.bak`.

Two things about that runbook to carry into this rebuild:

- **It is append-only evidence.** Record a new dated execution block; do not
  edit the 2026-08-11 one.
- **Its step 7 restore-validation config attaches the throwaway domain to
  `bridge=xenbr1` — the bare OVS bridge.** The isolation rules match
  `xenbr1.+`, which deliberately does **not** match `xenbr1`
  (`automation/network-setup.sh:369-372`), so a guest attached there has no
  isolation applied. Specify `bridge=xenbr1.<vlan>` and confirm the
  attachment with `ovs-vsctl show` before unpausing.

---

# 26. What this rebuild invalidates

A new kernel and a new system image make the following stale. Each fails in a
way that does not obviously point back here:

| Artifact | Why | Consequence if reused |
|---|---|---|
| `android.json` / `profiles/android.json` | New `vmlinux`, new symbol offsets | LibVMI initialises, DRAKVUF attaches, introspection returns garbage |
| `state/android_sandbox.bak` | Saved memory image of the **old** kernel | `xl restore` produces a domain the new profile cannot read |
| **Anchor PID 3163** | Belongs to the old saved state | Injection targets a PID that is not the anchor, or does not exist |
| `1844fc0a…` checksum | `verify-android-isolation.md` step 0 checks it | Step 0 aborts — correctly; update the expected value with the new one |
| `/etc/libvmi.conf` | Path unchanged, contents behind it are not | Silent: same path, wrong symbols |
| `docs/checklists/android.md` §1.4, AND-001 | Recorded against the old build fingerprint | Stale environment line |

**The build fingerprint is the thing to re-record**, because every one of the
above is keyed to it:

```sh
getprop ro.build.version.release
getprop ro.build.version.sdk
getprop ro.build.flavor
getprop ro.build.fingerprint
```

The previous image was
`Android-x86/Blissful/x86_64:14/AP2A.240905.003/0:user/release-keys`. This
build is `userdebug`, so the fingerprint changes — which is itself a useful
check that the guest is running the new image.

> Never reuse a symbol profile because the visible kernel version string
> looks unchanged.

---

# 27. General Xen commands

```bash
sudo xl create android.cfg
sudo xl create -c android.cfg
sudo xl list
sudo xl console android
sudo xl vncviewer android
sudo xl shutdown android
sudo xl destroy android
sudo xl pause android
sudo xl unpause android
sudo xl list -l android
sudo xl dmesg | tail -n 300
sudo tail -n 300 /var/log/xen/qemu-dm-android.log
```

For unexplained shutdowns or reboots, preserve the domain instead of tearing
it down:

```python
on_poweroff = "preserve"
on_reboot   = "preserve"
on_crash    = "preserve"
on_watchdog = "preserve"
```

`misc/android.cfg` already preserves on crash and watchdog. Clean up a
preserved domain with `sudo xl destroy android` once diagnostics are
collected.

---

# 28. Gaps against `docs/android_setup.md`

Recorded rather than merged, because sections 1–20 are the build as it was
actually executed and are not edited after the fact. Each item below is in
the older guide and absent above; fold any of them in deliberately, at the
section named.

| Old guide | Missing from | What it is | Worth folding in? |
|---|---|---|---|
| §1.2 verify block | §1 | `git lfs version`, `repo version`, `ninja --version`, `rustc`/`cargo`/`bindgen`/`cbindgen` version checks | **Yes** — a `repo sync` of this size is expensive to repeat because a prerequisite was missing |
| §3.1 | §1 | `sudo usermod -aG disk "$USER"`, then log out and back in | **Yes** — the failure surfaces hours later during `make iso_img` |
| §3.2 tail | §1 | `/etc/fstab` swap persistence | Optional |
| §7.1 / §7.2 menu paths | §9 | The `menuconfig` navigation paths for each Xen and SELinux symbol | Useful — §9 lists symbols but not where to find them |
| §1.3 note | §1 | The `libncurses.so.5` symlinks were **not** required; do not create them | Yes, as a negative finding |
| §10 | §2 | `external/alsa-utils` detached revision — not required for the successful build | No |
| §18–§24 | — | `DEBUG=2` initrd shells, Android userspace shell, `update_verifier` bypass, thermal-VINTF diagnosis | **No — read them in place.** Diagnosis, not build procedure |

## 28.1 Two SELinux symbols in the old guide do not exist in this kernel

`docs/android_setup.md` §7.2 lists four symbols. **Only two of them are valid
for this build**, and §9 above is correct to carry only those:

```text
CONFIG_DEFAULT_SECURITY_SELINUX=y      valid
CONFIG_SECURITY_SELINUX_BOOTPARAM=y    valid

CONFIG_SECURITY_SELINUX_BOOTPARAM_VALUE=1    REMOVED upstream — not in this kernel
CONFIG_SECURITY_SELINUX_DISABLE=y            REMOVED upstream — not in this kernel
```

Do not add them back. They are a historical artefact of the older
Android-x86/Qubes configuration the imported guide was derived from; setting
them in `menuconfig` is not possible and hand-adding them to `.config` leaves
entries the build silently drops.

**This does not affect `androidboot.selinux=permissive`** in §24. That is an
Android **init** parameter consumed by userspace, not the kernel's `selinux=`
bootparam, so it works independently of any of the four symbols above.

## 28.2 The `external/htop` pin — resolved

An earlier revision of this guide placed the `external/htop` pin in §2, where
`$ANDROID_BUILD_TOP` is not yet set: `. build/envsetup.sh` does not run until
§4, so the variable expanded to empty and the `cd` targeted `/external/htop`.

**Fixed 2026-08-14** — the block now sits inside §4's code block, after
`lunch`, where `$ANDROID_BUILD_TOP` is defined. Nothing to do; recorded only
so the same pin is not moved back to §2 on the reasoning that it belongs with
the `repo sync`.

---

# References

- Bliss-Bass EthernetConfig:
  https://github.com/Bliss-Bass/packages_apps_EthernetConfig
- AOSP build requirements:
  https://source.android.com/docs/setup/start/requirements
- BlissOS build documentation:
  https://docs.blissos.org/development/build-bliss-os-15.x/
- BlissOS platform manifest:
  https://github.com/BlissOS/platform_manifest
- Android-x86/Qubes Xen configuration discussion:
  https://groups.google.com/g/qubes-users/c/99jtKuNv7pc
- Xen `xl.cfg` reference:
  https://xenbits.xen.org/docs/unstable/man/xl.cfg.5.html
- Android init console behaviour:
  https://android.googlesource.com/platform/system/core/+/master/init/README.md
- AOSP VINTF manifest documentation:
  https://source.android.com/docs/core/architecture/vintf/objects