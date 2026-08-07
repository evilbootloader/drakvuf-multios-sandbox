# BlissOS x86_64 on Xen for DRAKVUF

Working build, Xen VM, symbol-profile, and troubleshooting notes for a BlissOS x86_64 analysis guest.

## Tested layout

```text
L0: Proxmox/KVM
└── L1: Ubuntu Xen Dom0 + DRAKVUF
    └── L2: BlissOS x86_64 HVM guest
```

Tested build host:

```text
Ubuntu Server 26.04
28 GiB RAM
24 CPU threads
30 GiB swap
BlissOS manifest branch: universe-x86
Lunch target: bliss_x86_64-ap2a-userdebug
```

This is a laboratory configuration. Ubuntu 26.04 and the exact `universe-x86` combination are based on this working environment, not a general BlissOS support guarantee. Allow roughly 350–400 GiB of free disk space for the checkout and output.

---

# 1. Build-host preparation

## 1.1 Update the host

```bash
sudo apt update
sudo apt upgrade -y
```

## 1.2 Install dependencies

```bash
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

Verify the important tools:

```bash
git --version
git lfs version
repo version
python3 --version
ninja --version
```

Initialize Git LFS:

```bash
git lfs install
```

Optional Git identity configuration if `repo init` requests it:

```bash
git config --global user.name "YOUR NAME"
git config --global user.email "YOUR EMAIL"
```

## 1.3 Install Rust with `rustup`

```bash
sudo apt remove -y rustc bindgen cargo

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"

cargo install cargo-ndk
rustup target add x86_64-linux-android i686-linux-android
cargo install --version 0.69.1 bindgen-cli
cargo install cbindgen
```

Verify:

```bash
rustc --version
cargo --version
cargo ndk --version
bindgen --version
cbindgen --version
```

The old `libncurses.so.5` compatibility symlinks were not required in the successful build. Do not create them unless a specific prebuilt tool fails because it requires SONAME 5.

```bash
# sudo ln -s /lib/x86_64-linux-gnu/libncurses.so.6 \
#     /lib/x86_64-linux-gnu/libncurses.so.5
# sudo ln -s /lib/x86_64-linux-gnu/libncursesw.so.6 \
#     /lib/x86_64-linux-gnu/libncursesw.so.5
# sudo ln -s /lib/x86_64-linux-gnu/libtinfo.so.6 \
#     /lib/x86_64-linux-gnu/libtinfo.so.5
# sudo ln -s /lib/i386-linux-gnu/libncurses.so.6 \
#     /lib/i386-linux-gnu/libncurses.so.5
# sudo ln -s /lib/i386-linux-gnu/libncursesw.so.6 \
#     /lib/i386-linux-gnu/libncursesw.so.5
# sudo ln -s /lib/i386-linux-gnu/libtinfo.so.6 \
#     /lib/i386-linux-gnu/libtinfo.so.5
```

---

# 2. Download BlissOS

```bash
mkdir -p "$HOME/BlissOS"
cd "$HOME/BlissOS"
```

Initialize the manifest:

```bash
repo init \
    -u https://github.com/BlissOS/platform_manifest.git \
    -b universe-x86 \
    --git-lfs
```

Synchronize:

```bash
repo sync \
    -c \
    --force-sync \
    --no-tags \
    --no-clone-bundle \
    -j"$(nproc --all)" \
    --optimized-fetch \
    --prune
```

---

# 3. Permissions and swap

## 3.1 Add the user to the `disk` group

```bash
sudo usermod -aG disk "$USER"
```

Log out and log back in, then verify:

```bash
id
```

## 3.2 Add 30 GiB swap

```bash
sudo fallocate -l 30G "$HOME/swapfile"
sudo chmod 0600 "$HOME/swapfile"
sudo mkswap "$HOME/swapfile"
sudo swapon "$HOME/swapfile"

swapon --show
free -h
```

Optional persistence:

```bash
SWAP_PATH="$HOME/swapfile"

grep -Fq "$SWAP_PATH none swap sw 0 0" /etc/fstab ||
    echo "$SWAP_PATH none swap sw 0 0" |
    sudo tee -a /etc/fstab
```

---

# 4. Add NDK translation

```bash
cd "$HOME/BlissOS"
mkdir -p vendor/google/proprietary

git clone \
    https://github.com/supremegamers/vendor_google_proprietary_ndk_translation-prebuilt.git \
    vendor/google/proprietary/ndk_translation-prebuilt
```

If already cloned:

```bash
git -C vendor/google/proprietary/ndk_translation-prebuilt pull --ff-only
```

Enable it:

```bash
export ANDROID_USE_NDK_TRANSLATION=true
```

This variable must be exported again in every new build shell.

Optional helper:

```bash
cat > "$HOME/BlissOS/build-local-env.sh" <<'EOS'
#!/usr/bin/env bash
export ANDROID_USE_NDK_TRANSLATION=true
. build/envsetup.sh
lunch bliss_x86_64-ap2a-userdebug
EOS

chmod +x "$HOME/BlissOS/build-local-env.sh"
```

---

# 5. Select the build target

```bash
cd "$HOME/BlissOS"
export ANDROID_USE_NDK_TRANSLATION=true
. build/envsetup.sh
lunch bliss_x86_64-ap2a-userdebug
```

Verify:

```bash
echo "ANDROID_BUILD_TOP=$ANDROID_BUILD_TOP"
echo "TARGET_PRODUCT=$TARGET_PRODUCT"
echo "TARGET_BUILD_VARIANT=$TARGET_BUILD_VARIANT"
echo "OUT=$OUT"
```

Run `export`, `envsetup.sh` and `lunch` again in every new shell.

---

# 6. Remove the duplicate thermal HAL

The original product list included both:

```make
com.android.hardware.thermal.intel
com.android.hardware.thermal
```

Both advertised the same `IThermal/default` VINTF instance. Android rejected the device manifest, and `zygote` and `surfaceflinger` repeatedly restarted.

Keep the generic implementation and remove the Intel APEX:

```bash
cd "$ANDROID_BUILD_TOP"

sed -i \
  '/^[[:space:]]*com\.android\.hardware\.thermal\.intel[[:space:]]*\\/d' \
  device/generic/common/treble.mk
```

Verify:

```bash
grep -n 'com.android.hardware.thermal' \
    device/generic/common/treble.mk
```

Expected:

```text
com.android.hardware.thermal
```

Review the local change:

```bash
git -C device/generic/common diff -- treble.mk
```

If changing this after an earlier build:

```bash
m installclean
```

---

# 7. Configure the kernel

Use only the output-tree `menuconfig` command:

```bash
cd "$ANDROID_BUILD_TOP"

make -C "$ANDROID_BUILD_TOP/kernel/x86/common" \
    O="$OUT/obj/kernel" \
    ARCH=x86_64 \
    menuconfig
```

Do not also run a second `menuconfig` without `O="$OUT/obj/kernel"`; that can create or use a different `.config`.

The active configuration should be:

```text
$OUT/obj/kernel/.config
```

## 7.1 Xen settings used in the working build

Enable (can be that some options are missing):

```text
CONFIG_XEN=y
CONFIG_XEN_BLKDEV_BACKEND=y
CONFIG_XEN_BLKDEV_FRONTEND=y
```

Disable:

```text
CONFIG_XEN_NETDEV_BACKEND=n
CONFIG_XEN_NETDEV_FRONTEND=n
```

Menu paths:

```text
Processor type and features
  -> Linux guest support
     -> Enable paravirtualization code
        -> Xen guest support (Y)

Device Drivers
  -> Block devices
     -> Xen virtual block device support (Y)
     -> Xen block-device backend driver (Y)

Device Drivers
  -> Network device support
     -> Xen network device frontend driver (N)
     -> Xen backend network device (N)
```

These reproduce the tested values from the older Android-x86/Qubes setup. The block backend is unusual for a normal guest but was retained because it was part of the working configuration.

## 7.2 SELinux debugging settings

Enable (can be that some options are missing):

```text
CONFIG_DEFAULT_SECURITY_SELINUX=y
CONFIG_SECURITY_SELINUX_BOOTPARAM=y
CONFIG_SECURITY_SELINUX_BOOTPARAM_VALUE=1
CONFIG_SECURITY_SELINUX_DISABLE=y
```

Menu paths:

```text
Security options
  -> NSA SELinux Support (Y)
  -> NSA SELinux boot parameter (Y)
  -> NSA SELinux boot parameter default value (1)
  -> NSA SELinux runtime disable (Y)
```

## 7.3 DWARF and symbols

Enable (can be that some options are missing):

```text
CONFIG_DEBUG_INFO=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
```

Select one supported DWARF format, normally:

```text
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
```

or:

```text
CONFIG_DEBUG_INFO_DWARF5=y
```

Do not enable two mutually exclusive DWARF-format choices.

## 7.4 Disable KernelSU

The exact KernelSU menu path or patch was not recorded in the original notes, so this part is not fully reproducible from the supplied information.

Verify common symbols after saving:

```bash
grep -E \
'^(CONFIG_KSU|CONFIG_KSU_SUSFS|CONFIG_KSU_DEBUG)=' \
"$OUT/obj/kernel/.config" || true
```

Expected values are `n`, or the symbols should be absent.

Search the tree if needed:

```bash
grep -RnsE \
'CONFIG_KSU|KERNELSU|KernelSU' \
kernel device vendor 2>/dev/null | head -n 200
```

## 7.5 Verify and save the configuration

```bash
grep -E \
'^(CONFIG_XEN|CONFIG_XEN_BLKDEV|CONFIG_XEN_NETDEV|CONFIG_DEBUG_INFO|CONFIG_KALLSYMS|CONFIG_DEFAULT_SECURITY_SELINUX|CONFIG_SECURITY_SELINUX)' \
"$OUT/obj/kernel/.config"

cp "$OUT/obj/kernel/.config" \
    "$HOME/blissos-xen-kernel.config"
```

---

# 8. Increase the system-image partition

Inspect the value:

```bash
cd "$ANDROID_BUILD_TOP"

grep -n '^BOARD_SYSTEMIMAGE_PARTITION_SIZE' \
    device/generic/common/BoardConfig.mk
```

Change 5 GB to 9 GB:

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

Expected:

```text
BOARD_SYSTEMIMAGE_PARTITION_SIZE := 9000000000
```

If the original line no longer contains exactly `5000000000`, the `sed` command makes no change; edit it manually.

---

# 9. Build the ISO

```bash
cd "$ANDROID_BUILD_TOP"
export ANDROID_USE_NDK_TRANSLATION=true
. build/envsetup.sh
lunch bliss_x86_64-ap2a-userdebug

make iso_img -j"$(nproc --all)"
```

If memory is exhausted:

```bash
make iso_img -j12
# or
make iso_img -j8
```

Locate the ISO:

```bash
find "$OUT" \
    -maxdepth 3 \
    -type f \
    -iname '*.iso' \
    -print
```

Record its checksum:

```bash
ISO_PATH="$(find "$OUT" -maxdepth 3 -type f -iname '*.iso' | head -n1)"

test -n "$ISO_PATH" &&
    sha256sum "$ISO_PATH" |
    tee "$HOME/blissos-xen.iso.sha256"
```

Locate the kernel symbol files:

```bash
find "$OUT/obj/kernel" \
    -maxdepth 3 \
    -type f \
    \( -name vmlinux -o -name System.map -o -name bzImage \) \
    -print
```

---

# 10. Optional historical source changes

These detached revisions were not required for the successful build:

```bash
cd "$ANDROID_BUILD_TOP/external/alsa-utils"
export UTILS_1213_COMMIT="7c894ab7ad0a79602fb4215cd0a66ba3c6731337"
git checkout --detach "$UTILS_1213_COMMIT"

cd "$ANDROID_BUILD_TOP/external/htop"
git switch --detach 9a4879b48f9ca1a39aa4eaa67bccc171cd5bca35

cd "$ANDROID_BUILD_TOP"
```

---

# 11. Create the Xen LV

Run on **L1 / Xen Dom0**:

```bash
sudo lvcreate \
    -L64G \
    -n android \
    vg-root

sudo lvs
sudo blockdev --getsize64 /dev/vg-root/android
```

---

# 12. Xen VM configuration

Create `android.cfg` on Xen Dom0. Replace the ISO path and bridge.

```python
arch = 'x86_64'
name = "android"
maxmem = 3000
memory = 3000
vcpus = 2
maxvcpus = 2
builder = "hvm"
boot = "c"
hap = 1
on_reboot   = "restart"
on_crash    = "preserve"
on_poweroff = "destroy"
on_watchdog = "preserve"
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
vif = [ 'type=ioemu,model=e1000,bridge=xenbr0' ]
disk = [ 'phy:/dev/vg-root/android,hda,w', 'file:/home/user/drakvuf-tools/Bliss-v17.8.3-x86_64-UNOFFICIAL-vanilla-20260806.iso,hdc:cdrom,r' ]
serial = "pty"
```

Notes:

- `type = "hvm"` is the current form; `builder = "hvm"` is older but accepted by Xen 4.20.
- `vga = "stdvga"` avoids the default Cirrus VGA.
- `serial = "pty"` provides the endpoint for `xl console`.
- `altp2m = 2` is included for DRAKVUF.
- Do not attach a malware-analysis VM directly to a production bridge.

Start and inspect:

```bash
sudo xl create android.cfg
sudo xl list
sudo xl vncviewer android
```

---

# 13. Install BlissOS into the LV


Through VNC:

1. Choose the installation option.
2. Select `/dev/xvda`.
3. Create an ext4 partition.
4. Install GRUB when prompted.
5. Finish and shut down.


Start the installed guest:

```bash
sudo xl create android.cfg
sudo xl vncviewer android
```

---

# 14. Generate the `dwarf2json` profile

On the build host:

```bash
VMLINUX="$(find "$OUT/obj/kernel" -type f -name vmlinux | head -n1)"
SYSTEM_MAP="$(find "$OUT/obj/kernel" -type f -name System.map | head -n1)"

printf 'VMLINUX=%s\nSYSTEM_MAP=%s\n' \
    "$VMLINUX" \
    "$SYSTEM_MAP"
```

Generate:

```bash
sudo apt update
sudo apt install -y golang-go git

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

cd "$HOME/BlissOS"

export ANDROID_USE_NDK_TRANSLATION=true
. build/envsetup.sh
lunch bliss_x86_64-ap2a-userdebug

VMLINUX="$OUT/obj/kernel/vmlinux"
SYSTEM_MAP="$OUT/obj/kernel/System.map"

"$HOME/dwarf2json-pr65-bin" linux \
    --elf "$VMLINUX" \
    --system-map "$SYSTEM_MAP" \
    > "$HOME/android.json"
```

Validate:

```bash
test -s android.json
python3 -m json.tool android.json >/dev/null
ls -lh android.json
```

Copy to Xen Dom0:

```bash
scp android.json user@XEN_DOM0_HOST:/tmp/android.json
```

On Xen Dom0:

```bash
sudo install \
    -o root \
    -g root \
    -m 0600 \
    /tmp/android.json \
    /root/android.json
```

---

# 15. LibVMI configuration

On Xen Dom0:

```bash
sudo tee -a /etc/libvmi.conf >/dev/null <<'EOS'
android {
    volatility_ist = "/root/android.json";
}

android_sandbox {
    volatility_ist = "/root/android.json";
}
EOS
```

Check for duplicates before appending again:

```bash
sudo grep -n -A3 -B1 \
    -E '^android(_sandbox)?[[:space:]]*\{' \
    /etc/libvmi.conf
```

Optional sanity check if installed:

```bash
sudo vmi-process-list android
```

---

# 16. Xen serial debugging mode (after install machine just reboots)

Normal lifecycle settings:

```python
on_poweroff = "destroy"
on_reboot = "restart"
on_crash = "destroy"
```

For unexplained shutdowns or reboots:

```python
serial = "pty"

on_poweroff = "preserve"
on_reboot = "preserve"
on_crash = "preserve"
on_watchdog = "preserve"
```

Clean up a preserved domain after collecting diagnostics:

```bash
sudo xl destroy android
```

For a quick reboot-loop stop, `on_reboot = "destroy"` is useful, but the domain disappears immediately.

---

# 17. Record the serial console

Start the VM:

```bash
sudo xl create android.cfg
```

In a second terminal:

```bash
sudo script \
    -q \
    -f \
    -c 'xl console android' \
    /tmp/bliss-console.log
```


At the BlissOS GRUB menu:

1. Select the boot entry.
2. Press `e`.
3. Find the kernel line.
4. Remove `quiet`.
5. Remove duplicate console parameters.
6. Append:

```text
DEBUG=2 androidboot.selinux=permissive console=tty0 console=ttyS0,115200n8 androidboot.console=ttyS0 androidboot.enable_console=1 loglevel=7 ignore_loglevel
```

Correct spellings:

```text
androidboot.console=ttyS0
ignore_loglevel
```

Incorrect spellings encountered earlier:

```text
androidboot,console=ttyS0
ignore_loglever
```

Boot with `Ctrl+X` or `F10`.

---

Detach with:

```text
Ctrl+]
```

Inspect:

```bash
tail -n 300 /tmp/bliss-console.log

grep -iE \
'panic|fatal|reboot|shutdown|update_verifier|bootctrl|apex|vintf|zygote|surfaceflinger|linker|mount|failed|cannot' \
/tmp/bliss-console.log |
tail -n 400
```

---

# 18. First `DEBUG=2` shell

Prompt:

```text
Type 'exit' to continue booting...

~ #
```

Commands:

```sh
pwd
cat /proc/1/comm
cat /proc/cmdline
mount
cat /proc/partitions
ls -l /android/init
ls -l /android/system/bin/init
tail -n 300 /tmp/log
dmesg | tail -n 300
```

`getprop` may fail here because Android's final linker/APEX environment is not ready.

Continue:

```sh
exit
```

---

# 19. Second `DEBUG=2` shell

Prompt:

```text
Use Alt-F1/F2/F3 to switch between virtual consoles
Type 'exit' to enter Android...

~ #
```

Inspect:

```sh
mount
ls -l /android/init
ls -l /android/system/bin/init
ls -l /android/system/bin/linker64
tail -n 200 /tmp/log
```

After the final root switch, `/android/...` paths become `/system/...`, `/vendor/...`, and so on.

---

# 20. Temporary one-boot `update_verifier` bypass

Use only if the permanent lab patch was not built into the ISO.

At the **second** `~ #` shell:

```sh
ls -l \
    /android/system/bin/true \
    /android/system/bin/update_verifier
```

Bind `true` over the verifier:

```sh
mount --bind \
    /android/system/bin/true \
    /android/system/bin/update_verifier
```

Verify:

```sh
mount | grep update_verifier
```

The output may show `/dev/loop0` rather than explicitly displaying the word `bind` because both paths are on the same loop-mounted ext4 filesystem.

Continue:

```sh
exit
```

The bypass disappears at reboot.

---

# 21. Android userspace shell

Prompt:

```text
console:/ #
```

This is the real Android shell, not another initramfs shell. Do not type `exit` merely because it appears to be a third shell.

Reduce console noise:

```sh
dmesg -n 4
```

Check the shell and PID 1:

```sh
echo "ANDROID SHELL ACTIVE"
cat /proc/1/comm
```

Expected PID 1:

```text
init
```

Check services:

```sh
getprop init.svc.update_verifier
getprop init.svc.zygote
getprop init.svc.zygote_secondary
getprop init.svc.surfaceflinger
getprop init.svc.bootanim
getprop sys.boot_completed
```

Check processes:

```sh
ps -A | grep -E \
'surfaceflinger|zygote|system_server|servicemanager|apexd'
```

Successful boot indicators:

```text
init.svc.zygote=running
init.svc.surfaceflinger=running
sys.boot_completed=1
```


# 22. Diagnose an immediate reboot

On Xen Dom0:

```bash
sudo xl list -v
sudo xl list -l android
sudo xl dmesg | tail -n 300

sudo grep -RiE \
'reboot|crash|shutdown|panic|android' \
/var/log/xen 2>/dev/null |
tail -n 300
```

Typical shutdown reasons:

```text
reboot   -> guest requested reboot
crash    -> Xen observed a guest crash
poweroff -> guest requested shutdown
watchdog -> watchdog timeout
```

Clean a preserved domain:

```bash
sudo xl destroy android
```

---

# 23. Diagnose missing Boot Control HAL

Original failure:

```text
update_verifier: AIDL IBootControl not available, falling back to HIDL.
update_verifier: Error getting bootctrl v1.0 module.
update_verifier: Error getting bootctrl module.
apexd: Started. subcommand = --unmount-all
reboot: Restarting system
```

Search:

```bash
grep -iE \
'update_verifier|bootctrl|unmount-all|Restarting system' \
/tmp/bliss-console.log
```

Corrective choices:

1. Temporary bind-mount bypass in the second shell.
2. Permanent lab-only source patch.
3. A proper compatible Boot Control HAL implementation.

---

# 24. Diagnose the thermal VINTF conflict

Symptoms:

```text
getprop init.svc.zygote
restarting

getprop init.svc.surfaceflinger
restarting
```

Log error:

```text
VINTF parse error:
HAL "android.hardware.thermal" has a conflict
```

Search the serial log:

```bash
grep -iE \
'thermal|VINTF parse error|NULL VINTF MANIFEST' \
/tmp/bliss-console.log |
tail -n 300
```

Search the source tree:

```bash
cd "$ANDROID_BUILD_TOP"

grep -RnsE \
'com\.android\.hardware\.thermal(\.intel)?|android\.hardware\.thermal\.example' \
device vendor hardware packages system 2>/dev/null

grep -RnsE \
'PRODUCT_PACKAGES.*thermal|com\.android\.hardware\.thermal(\.intel)?' \
device vendor 2>/dev/null
```

Correct result in `device/generic/common/treble.mk`:

```make
com.android.hardware.thermal
```

Rebuild after correction:

```bash
m installclean
make iso_img -j"$(nproc --all)"
```

---

# 25. General Xen commands

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

---

# 26. Reproducibility checklist

```bash
cd "$ANDROID_BUILD_TOP"

repo manifest -r -o "$HOME/blissos-pinned-manifest.xml"

cp "$OUT/obj/kernel/.config" \
    "$HOME/blissos-xen-kernel.config"

git -C device/generic/common diff \
    > "$HOME/blissos-device-generic-common.patch"

git -C bootable/recovery diff \
    > "$HOME/blissos-update-verifier.patch"

sha256sum "$ISO_PATH" \
    > "$HOME/blissos-xen.iso.sha256"

{
    rustc --version
    cargo --version
    repo version
    uname -a
} > "$HOME/blissos-build-versions.txt"
```

Archive:

```text
blissos-pinned-manifest.xml
blissos-xen-kernel.config
blissos-device-generic-common.patch
blissos-update-verifier.patch
blissos-xen.iso.sha256
blissos-build-versions.txt
android.cfg
android.json
/tmp/bliss-console.log
```

---

# References

- AOSP build requirements:  
  https://source.android.com/docs/setup/start/requirements

- AOSP build workflow:  
  https://source.android.com/docs/setup/build/building

- BlissOS build documentation:  
  https://docs.blissos.org/development/build-bliss-os-15.x/

- BlissOS platform manifest:  
  https://github.com/BlissOS/platform_manifest

- Android-x86/Qubes Xen configuration discussion:  
  https://groups.google.com/g/qubes-users/c/99jtKuNv7pc

- Xen `xl.cfg` reference:  
  https://xenbits.xen.org/docs/unstable/man/xl.cfg.5.html

- Android init console behavior:  
  https://android.googlesource.com/platform/system/core/+/master/init/README.md

- AOSP `update_verifier` source:  
  https://android.googlesource.com/platform/bootable/recovery/+/master/update_verifier/update_verifier.cpp

- Android VINTF manifest documentation:  
  https://source.android.com/docs/core/architecture/vintf/objects
