---
description: Drakvuf setup for automated analysis in Ubuntu VMs
---

# automated drakvuf on xen nested within proxmox

## Virtualization architecture

This setup uses three virtualization levels:

```
L0: Physical server running Proxmox VE and KVM
 └── L1: Virtual machine running Xen, Dom0 and DRAKVUF
      └── L2: Windows or Linux analysis guest monitored by DRAKVUF
```

Throughout this guide, commands are labelled according to where they must be executed:

* **L0 / Proxmox host:** the physical server running Proxmox VE.
* **L1 / Xen Dom0:** the Proxmox virtual machine in which Xen and DRAKVUF are installed.
* **L2 / Analysis guest:** the virtual machine monitored by DRAKVUF.

Do not run an L0 command inside Xen Dom0 or an L1 command directly on the Proxmox host.

## Proxmox VM setup

### Hardware requirements

The physical Proxmox server must use a compatible Intel processor with the following features:

* Intel VT-x.
* Extended Page Tables, or EPT.
* Nested virtualization support in KVM.
* VMX exposed from Proxmox to the Xen Dom0 virtual machine.

DRAKVUF currently requires Intel virtualization extensions and does not support AMD processors.

Running Xen inside a KVM virtual machine is a nested virtualization configuration:

```
KVM → Xen → HVM guest
```

This configuration is useful for development, testing and laboratory environments. Nested Xen should, however, be treated as experimental and may behave differently from Xen installed directly on physical hardware.

Do not use this architecture as a production malware-analysis environment without additional testing, monitoring and isolation.

My specific cpu:

```
root@pve1:~# lscpu
Architecture:                x86_64
  CPU op-mode(s):            32-bit, 64-bit
  Address sizes:             39 bits physical, 48 bits virtual
  Byte Order:                Little Endian
CPU(s):                      32
  On-line CPU(s) list:       0-31
Vendor ID:                   GenuineIntel
  Model name:                13th Gen Intel(R) Core(TM) i9-13900KF
    CPU family:              6
    Model:                   183
    Thread(s) per core:      2
    Core(s) per socket:      24
    Socket(s):               1
    Stepping:                1
    CPU(s) scaling MHz:      23%
    CPU max MHz:             5800.0000
    CPU min MHz:             800.0000
    BogoMIPS:                5990.40
    Flags:                   fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall 
                             nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq 
                             pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadlin
                             e_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow flexpriori
                             ty ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt clwb intel_pt sha_ni xsaveopt
                              xsavec xgetbv1 xsaves split_lock_detect user_shstk avx_vnni dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp hwp_p
                             kg_req hfi vnmi umip pku ospke waitpkg gfni vaes vpclmulqdq rdpid movdiri movdir64b fsrm md_clear serialize arch_lbr ibt flush_l
                             1d arch_capabilities
Virtualization features:     
  Virtualization:            VT-x
Caches (sum of all):         
  L1d:                       896 KiB (24 instances)
  L1i:                       1.3 MiB (24 instances)
  L2:                        32 MiB (12 instances)
  L3:                        36 MiB (1 instance)
NUMA:                        
  NUMA node(s):              1
  NUMA node0 CPU(s):         0-31
Vulnerabilities:             
  Gather data sampling:      Not affected
  Ghostwrite:                Not affected
  Indirect target selection: Not affected
  Itlb multihit:             Not affected
  L1tf:                      Not affected
  Mds:                       Not affected
  Meltdown:                  Not affected
  Mmio stale data:           Not affected
  Old microcode:             Not affected
  Reg file data sampling:    Mitigation; Clear Register File
  Retbleed:                  Not affected
  Spec rstack overflow:      Not affected
  Spec store bypass:         Mitigation; Speculative Store Bypass disabled via prctl
  Spectre v1:                Mitigation; usercopy/swapgs barriers and __user pointer sanitization
  Spectre v2:                Mitigation; Enhanced / Automatic IBRS; IBPB conditional; PBRSB-eIBRS SW sequence; BHI BHI_DIS_S
  Srbds:                     Not affected
  Tsa:                       Not affected
  Tsx async abort:           Not affected
  Vmscape:                   Mitigation; IBPB before exit to userspace
```

### Xen VM Setup

#### Verify nested virtualization on the Proxmox host

Run the following commands on the physical Proxmox server.

```bash
# Run on L0: Physical server running Proxmox VE and KVM

grep -E -m1 'vmx' /proc/cpuinfo
```

The command must print:

```
vmx
```

Verify that nested virtualization is enabled in the Intel KVM module:

```bash
# Run on L0: Physical server running Proxmox VE and KVM

cat /sys/module/kvm_intel/parameters/nested
```

The expected result is normally one of the following:

```
Y
```

or:

```
1
```

If the result is `N` or `0`, enable nested virtualization before continuing.

Also edit the following module configuration to be as follows:

```bash
# Run on L0: Physical server running Proxmox VE and KVM

root@pve1:~# cat /etc/modprobe.d/kvm-intel.conf 
options kvm ignore_msrs=y
options kvm_intel nested=Y ept=Y
options kvm_intel emulate_invalid_guest_state=0
```

Regenerate the initramfs:

```bash
# Run on L0: Physical server running Proxmox VE and KVM

update-initramfs -u -k all
```

Reboot the physical Proxmox server:

```bash
# Run on L0: Physical server running Proxmox VE and KVM

reboot
```

After rebooting, verify the value again:

```bash
# Run on L0: Physical server running Proxmox VE and KVM

cat /sys/module/kvm_intel/parameters/nested
```

Do not continue until nested virtualization is enabled. You can also check your BIOS for required settings.

#### Hardware

The minimum RAM required for a basic installation is lower, but the allocated memory must be sufficient for:

* Xen Dom0.
* DRAKVUF.
* LibVMI.
* The analysis guest.
* Concurrent clones.
* Xen and QEMU overhead.

For a small laboratory with two low memory analysis guests, use at least 16 GB. For multiple clones or memory-intensive guests, 32 GB or more is strongly recommended.

<figure><img src="../.gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

#### Options

<figure><img src="../.gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

#### Launch Ubuntu and select **Try Ubuntu**

```
Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF
```

<figure><img src="../.gitbook/assets/image (15).png" alt="Ubuntu live installer welcome screen. Choose **Try Ubuntu** to prepare the custom LVM layout before launching the installer."><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (24).png" alt="&#x60;fdisk /dev/sda&#x60;: create GPT, a 2 GiB first partition, and a second partition using the remaining disk, then set partition 2 to type Linux LVM."><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (25).png" alt="Create &#x60;/dev/sda2&#x60; as an LVM PV, create volume group &#x60;vg-root&#x60;, and create a 256 GiB logical volume named &#x60;lv-root&#x60;."><figcaption></figcaption></figure>

#### Launch the Ubuntu installer from the live desktop after creating the LVM layout.

Continue installation as usual until **Installation type**.

<figure><img src="../.gitbook/assets/image (27).png" alt="At **Installation type**, select **Something else** to assign mount points to the pre-created partitions and LV."><figcaption></figcaption></figure>

Select as follows and **Install Now**

<figure><img src="../.gitbook/assets/image (28).png" alt="Manual partitioning: &#x60;/dev/sda1&#x60; is formatted as ext4 and mounted at &#x60;/boot&#x60;; &#x60;/dev/mapper/vg--root-lv--root&#x60; is formatted as ext4 and mounted at &#x60;/&#x60;; the bootloader target is &#x60;/dev/sda&#x60;."><figcaption></figcaption></figure>

Finish the installation.

## DRAKVUF VM configuration

<pre class="language-bash"><code class="lang-bash"># Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF
<strong>
</strong><strong>sudo apt update &#x26;&#x26; sudo apt upgrade
</strong>sudo apt install qemu-guest-agent spice-vdagent git -y
git clone https://github.com/evilbootloader/drakvuf-tools.git
reboot
</code></pre>

Reboot and configure Netplan by editing **`/etc/netplan/01-network-manager-all.yaml`** as follows.

```yaml
# Let NetworkManager manage all devices on this system
network:
  version: 2
  renderer: NetworkManager
  ethernets:
    ens18:
      dhcp4: no
  bridges:
    xenbr0:
      dhcp4: yes
      interfaces:
        - ens18
```

This transfers the Proxmox-facing NIC into a Linux bridge inside the Xen Dom0 guest. After applying, verify `ip -br addr`, `bridge link`, the default route, and Proxmox QEMU-agent connectivity. If remote access is critical, use `netplan try` to avoid locking yourself out.

```bash
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

sudo netplan apply
```

Download the package from:

{% embed url="https://github.com/tklengyel/drakvuf-builds/releases" %}

```bash
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

sudo apt install ~/Downloads/xen-hypervisor-4.20.1-ubuntu-jammy-amd64.deb -y
```

Edit the following lines in **`/etc/default/grub.d/xen.cfg`**; for this setup, use:

These Xen command-line options are derived from DRAKVUF’s recommended configuration. Because this is Xen nested under KVM. The nested x86 HVM is experimental and checkpoint/device-model behavior should be tested on the exact hardware and Xen build.

```
GRUB_CMDLINE_XEN_DEFAULT="dom0_mem=4096M,max:4096M dom0_max_vcpus=4 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0 sched=credit"
GRUB_CMDLINE_LINUX_XEN_REPLACE_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT quiet splash"
```

```bash
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

sudo update-grub2
reboot
```

After rebooting into Xen, verify the Xen context and install DRAKVUF.

```bash
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

user@drakvuf:~$ sudo xen-detect 
Running in PV context on Xen V4.20.
user@drakvuf:~$ sudo xl dmesg | grep -iE "VMX|EPT"
(XEN) Command line: placeholder dom0_mem=4096M,max:4096M dom0_max_vcpus=4 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0 sched=credit
(XEN) VMX: Supported advanced features:
(XEN)  - Extended Page Tables (EPT)
(XEN) HVM: VMX enabled

```

If the old DRAKVUF bundle was installed previously, remove it before installing the source build to avoid loading stale binaries or libraries:

```bash
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

if dpkg-query -W -f='${Status}' drakvuf-bundle 2>/dev/null |
   grep -q 'install ok installed'; then
    sudo apt autoremove --purge -y drakvuf-bundle
fi

sudo ldconfig
```

Create an Ubuntu 20.04 target golden VM. First create the Xen configuration file and adjust the ISO path.&#x20;

```bash
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

user@drakvuf:~/Documents$ cat ~/drakvuf-tools/linux.cfg 
arch = 'x86_64'
name = "ubuntu"
maxmem = 3000
memory = 3000
vcpus = 2
maxvcpus = 2
builder = "hvm"
boot = "c"
hap = 1
on_poweroff = "destroy"
on_reboot = "restart"
on_crash = "destroy"
vnc = 1
vnclisten = "0.0.0.0"
vga = "stdvga"
usb = 1
usbdevice = "tablet"
audio = 1
#soundhw = "hda"
viridian = 1
altp2m = 2
shadow_memory = 32
vif = [ 'type=ioemu,model=e1000,bridge=xenbr0' ]
disk = [ 'phy:/dev/vg-root/ubuntu,hda,w', 'file:/home/user/Documents/ubuntu-20.04.6-desktop-amd64.iso,hdc:cdrom,r' ]
```

Then create a logical volume for the VM. `lvcreate -L64G` creates a normal thick LV and reserves the full 64 GiB from the volume group immediately. It is not allocated on demand. If sparse/on-demand allocation is required, create an LVM thin pool and a thin LV.

Then we can start our vm.

```bash
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

sudo lvcreate -L64g -n ubuntu vg-root
sudo apt install virt-viewer
sudo xl create linux.cfg

# If above command fails, check if vm is running
sudo xl list
# If not running check the following
sudo cat /var/log/xen/qemu-dm-ubuntu.log
```

Launch **Remote Viewer** and connect to **`vnc://127.0.0.1:5900`**. You can edit vncviewer defaults so it only listens on localhost. If more than one vm exists apart from Dom0, the listening ports start at 5900 onwards.

<figure><img src="../.gitbook/assets/image (29).png" alt="Remote Viewer connection dialog using &#x60;vnc://127.0.0.1:5900&#x60;."><figcaption><p>Remote Viewer connection dialog using `vnc://127.0.0.1:5900`.</p></figcaption></figure>

Install the Ubuntu analysis VM. You may update, upgrade, and reboot it after installation, but leave it powered on for the LibVMI process-enumeration test.

To create the Linux kernel symbol profile used by LibVMI/DRAKVUF, do the following:

1.  For Linux you need to install the target kernel's (target golden vm) debug package (to get the DWARF symbols for the kernel), if need help check this [link](https://ubuntu.com/server/docs/how-to/debugging/debug-symbol-packages/):

    ```bash
    # Run on L2: Windows or Linux analysis guest monitored by DRAKVUF

    echo "Kernel version: "$(uname -r)
    apt-get install linux-image-$(uname -r)-dbgsym
    exit 
    ```
2.  We will use the dwarf2json tool to convert the debug information into the required JSON configuration file. Make note of the Kernel version of the target and make sure to update the System.map and vmlinux paths to reflect the correct kernel version (download dwarf2json from this [link](https://github.com/volatilityfoundation/dwarf2json/releases/tag/v0.9.0)). **Shutdown the VM before starting**:

    <pre class="language-bash"><code class="lang-bash"># Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

    sudo su
    <strong>kpartx -a /dev/vg-root/ubuntu
    </strong>mount -o ro /dev/mapper/vg--root-ubuntu5 /mnt
    ./dwarf2json-linux-amd64 linux --system-map /mnt/boot/System.map-5.15.0-139-generic --elf /mnt/usr/lib/debug/boot/vmlinux-5.15.0-139-generic > /root/linux.json
    umount /mnt
    kpartx -d /dev/vg-root/ubuntu
    printf "ubuntu {\n\tvolatility_ist = \"/root/linux.json\";\n}" >> /etc/libvmi.conf
    printf "ubuntu_sandbox {\n\tvolatility_ist = \"/root/linux.json\";\n}" >> /etc/libvmi.conf
    </code></pre>

#### Setting up the sandbox VM

```bash
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

sudo lvcreate \
    -L64G \
    -n ubuntu_sandbox \
    vg-root
    
sudo dd \
    if=/dev/vg-root/ubuntu \
    of=/dev/vg-root/ubuntu_sandbox \
    bs=64M \
    iflag=fullblock \
    conv=fsync \
    status=progress
    
sudo apt install screen apache2 tcpdump vlan openvswitch-switch -y

sudo ovs-vsctl add-br xenbr1
sudo ip link set xenbr1 up

sudo xl create ~/drakvuf-tools/linux_sandbox.cfg
```

Inside the sandbox analysis VM, start a long-lived privileged process that can be used as the injection target.

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

We can check with the following for knowing if everything is ok. First time of using [LibVMI](https://libvmi.com/)!

```
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF
```

<figure><img src="../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

**NICE!** Record the PID/TGID; in this example it is `1438`.

```bash
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

sudo xl save ubuntu_sandbox ~/Documents/ubuntu_sandbox.bak linux_sandbox.cfg
```

Ubuntu sandbox will be destroyed. Any time you need to run the command above again run the copy of the lvm and launch the vm.

```bash
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

sudo dd \
    if=/dev/vg-root/ubuntu \
    of=/dev/vg-root/ubuntu_sandbox \
    bs=64M \
    iflag=fullblock \
    conv=fsync \
    status=progress

# Relaunch
sudo xl create ~/drakvuf-tools/linux_sandbox.cfg
```

The nested Xen host and Ubuntu analysis VM are now prepared for basic DRAKVUF/LibVMI testing. A follow-up can cover isolated networking, injector argument handling, logging, and automated clone analysis.

## Automated analysis setup

### Install build and automation dependencies

<pre class="language-bash"><code class="lang-bash"># Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF
<strong>
</strong><strong>sudo apt-get install wget git bcc bin86 gawk bridge-utils iproute2 libcurl4-openssl-dev bzip2 libpci-dev build-essential make gcc clang libc6-dev linux-libc-dev zlib1g-dev libncurses5-dev patch libvncserver-dev libssl-dev libsdl1.2-dev iasl libbz2-dev e2fslibs-dev git-core uuid-dev ocaml libx11-dev bison flex ocaml-findlib xz-utils gettext libyajl-dev libpixman-1-dev libaio-dev libfdt-dev cabextract libglib2.0-dev autoconf automake libtool libjson-c-dev libfuse-dev liblzma-dev autoconf-archive kpartx python3-dev python3-pip golang python2.7-dev libsystemd-dev nasm ninja-build llvm lld meson python3-tomli -y
</strong><strong>sudo pip3 install pefile construct
</strong>
</code></pre>

#### Check out the `lfreijo/memdump` branch <a href="#check-out-the-lfreijomemdump-branch" id="check-out-the-lfreijomemdump-branch"></a>

For a new source installation, clone the `lfreijo` repository directly and check out its `memdump` branch:

```bash
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

cd ~

git clone     --branch memdump     --single-branch     https://github.com/lfreijo/drakvuf.git

cd ~/drakvuf
git submodule update --init --recursive
```

The cloned branch tracks `origin/memdump`, where `origin` now refers to the `lfreijo/drakvuf` repository.

If `~/drakvuf` is an existing checkout originally cloned from `tklengyel/drakvuf`, retain it and add the `lfreijo` remote:

```bash
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

cd ~/drakvuf

git remote get-url lfreijo >/dev/null 2>&1 ||
    git remote add lfreijo https://github.com/lfreijo/drakvuf.git

git fetch lfreijo memdump

if git show-ref --verify --quiet refs/heads/memdump; then
    git switch memdump
    git reset --hard lfreijo/memdump
else
    git switch -c memdump --track lfreijo/memdump
fi

git submodule update --init --recursive
```

Verify the selected repository, branch and revision:

```bash
git remote -v
git branch --show-current
git log -1 --oneline --decorate
git status
git submodule status
```

The branch should be `memdump`, and the current commit should match the fetched tip of either `origin/memdump` for a direct `lfreijo` clone or `lfreijo/memdump` for an existing upstream checkout.

#### Build DRAKVUF after LibVMI initialization <a href="#build-drakvuf-after-libvmi-initialization" id="build-drakvuf-after-libvmi-initialization"></a>

```bash
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

cp ~/drakvuf-tools/dirwatch.c ~/drakvuf/src/dirwatch/
```

Copy the custom directory watcher used by the automation:

The `memdump` branch references the Linux and Windows memdump backends from `memdump.cpp`. Its Meson source list includes those files, but the branch's Autotools source list may omit them. When omitted, the final link fails with errors similar to:

```
undefined reference to `win_memdump::win_memdump(...)'
undefined reference to `linux_memdump::linux_memdump(...)'
```

Patch `src/plugins/Makefile.am` before running `autogen.sh`. The script is idempotent and does not add duplicate entries:

```bash
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

cd ~/drakvuf

python3 - <<'PY'
from pathlib import Path

path = Path("src/plugins/Makefile.am")
text = path.read_text()

required = [
    "sources += memdump/win.cpp",
    "sources += memdump/win.h",
    "sources += memdump/linux.cpp",
    "sources += memdump/linux.h",
]

if all(line in text for line in required):
    print("Autotools memdump backends are already present")
    raise SystemExit(0)

needle = "sources += memdump/private.h\n"
if needle not in text:
    raise SystemExit(
        "Could not find the PLUGIN_MEMDUMP source block in "
        "src/plugins/Makefile.am; inspect it manually"
    )

addition = "".join(f"{line}\n" for line in required if line not in text)
path.write_text(text.replace(needle, needle + addition, 1))
print(f"Patched {path}")
PY

grep -n -A14 '^if PLUGIN_MEMDUMP' src/plugins/Makefile.am
git diff --check
git diff -- src/plugins/Makefile.am
```

Regenerate the Autotools files and build:

```bash
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

cd ~/drakvuf

make distclean 2>/dev/null || true
./autogen.sh
./configure

make -j"$(nproc)"
sudo make install
sudo ldconfig
```

Do not skip `autogen.sh` after changing `Makefile.am`; otherwise the generated Makefiles can retain the old source list.

#### Create the analysis directories

```bash
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

sudo mkdir -p \
    /malware_incoming \
    /malware_processing \
    /malware_finished

sudo chown www-data:www-data /malware_processing
```

Edit **/etc/apache2/apache2.conf**, change this:

```
<Directory /var/www/>
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
</Directory>
```

To this:

```
<Directory /malware_processing>
	Options FollowSymLinks
	AllowOverride None
	Require all granted
</Directory>
```

And also edit **/etc/apache2/sites-enabled/000-default.conf**, change this:

```
DocumentRoot /var/www/html
```

To this:

```
DocumentRoot /malware_processing
```

### Setup automation scripts

```bash
# Run on L1: Virtual machine running Xen, Dom0 and DRAKVUF

sudo systemctl restart apache2
sudo ~/drakvuf-tools/network-setup.sh <number-of-clones>
```

Go to your drakvuf-tools downloaded repository and edit **linux\_sandbox.cfg** as necessary.

Then edit **run\_analysis.sh**, change **\<injection\_pid>** and **\<number-of-clones>**

Also edit **preconfig.sh** and **drakvuf.sh**, change **\<USER>** to the target analysis VM user.

### Running the analysis

```bash
sudo su
./run_analysis
```

{% embed url="https://youtu.be/5DiVS-Qp5Og" %}

### Reproducibility notice

This guide describes a nested laboratory architecture:

```
Proxmox/KVM → Xen → DRAKVUF analysis guest
```

The behavior of this setup depends on the interaction between:

* The physical CPU.
* The Proxmox kernel.
* KVM nested virtualization.
* QEMU.
* The Xen version.
* The Dom0 Linux kernel.
* LibVMI.
* DRAKVUF.
* The analysis guest.

A configuration that works with one combination of versions may regress after updating one of these components.

Before performing upgrades:

1. Record all current versions.
2. Back up the Proxmox VM configuration.
3. Back up the Xen Dom0 operating system.
4. Preserve the DRAKVUF and LibVMI Git revisions.
5. Test the upgrade on a disposable clone.
6. Verify VMX, EPT and altp2m again.
7. Confirm that an analysis guest can start, pause, clone and restore correctly.



```
pve version: pve-manager/9.2.6/7f8d010005bd72cb (running kernel: 7.0.14-4-pve)
drakvuf automated build: https://github.com/tklengyel/drakvuf-builds/releases/tag/build-1eabdbde6fe24e991e0ef8ead1afa8c0a9392e78
drakvuf lfreijo: commit 52df0bc8044d3033af3259312787560dbb8caa12 (HEAD -> memdump, lfreijo/memdump)
libmi: commit df8547ff075d4352db2eb802775b7fa7a92756db (HEAD)
```

