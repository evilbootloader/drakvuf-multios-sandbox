# Guest identity — what the analysis guests look like from inside

> **Status (2026-11-02): PARTLY EVIDENCED.** The guests were reinstalled with
> it and al-khaser run on Windows on 2026-11-02 (`alkhaser_search.sh`, outside
> the repository, run `20261102-003810`: two Xen variants, two tests each, in
> `dev-syscalls` and `dev-all`). Of the 2026-11-01 detections below, 4064,
> 4073, 4074, 4078, 4080, 4084, 4085, 4087–4094, 4096, 9001 and 9003 were gone
> in every run. Three that should have gone did not: 4097, 4098 and 8010. Their
> fixes (the rows marked 2026-11-02) are **CANDIDATE**: compiled and checked as
> §1 says, never booted. Like the rest, they take effect only on guests
> **installed after** `make xen` has run with them (§4). The red pill on a
> reinstalled Ubuntu guest has not been run.

Malware asks the machine what it is before it does anything. Xen answers with
its own name: SMBIOS says `Xen` and `HVM domU`, the BIOS release is Xen's
version, every ACPI table names `Xen`/`HVM` as OEM and hvmloader as creator,
CPUID sets the hypervisor bit and leaf `0x40000000` says `XenVMMXenVMM` (or
`Microsoft Hv` with Viridian), the MAC starts `00:16:3E`, the disk is a `QEMU
HARDDISK`, a `XenSource` PCI device sits on the bus. And a guest lacks what
every real machine has: caches, port connectors, slots, fans, probes, a thermal
zone.

---

## 1. The evidence it answers

al-khaser on the Windows 11 guest under DRAKVUF, 2026-11-01, before any of
this (`alkhaser_search.sh`, outside the repository). Each line is a check that
detected the sandbox, and what here answers it:

| al-khaser check | Gave away | Answered by |
|---|---|---|
| 4073, 4074 model, manufacturer (WMI) | `HVM domU`, `Xen` | identity in hvmloader and `smbios=` |
| 4078, 4080, 4084, 4085, 4087–4094 fan, cache, probes, ports, slots, thermal zone (WMI) | none present | `smbios_firmware` (SMBIOS types 7, 8, 9, 26–29) and `acpi_firmware` (a thermal zone) |
| 4098 SMBIOS tables | 40 or fewer structures: 15 of hvmloader's, then 36 with these | the same structures, 55 with hvmloader's (2026-11-02) |
| 8010 ACPI tables (QEMU check) | the FADT's power profile, 0 (unspecified), as QEMU's tables have it, not Xen's headers | 1, desktop, in the identity patch (2026-11-02) |
| 4064, 4096, 4097 disk (SetupDi, registry) | `QEMU HARDDISK` | `ide-hd.model`/`serial` |
| 4097 CD-ROM (registry) | `Enum\IDE\CdRomQEMU_QEMU_DVD-ROM_…`, the installer's drive: Windows names it from INQUIRY, where QEMU says `QEMU` whatever `ide-cd.model` | `automation/qemu-xen-cdrom-inquiry.patch`; `ide-cd.ver`/`serial` and `ide-hd.ver` for QEMU's `2.5+` (2026-11-02) |
| 9001 PCI vendor 5853 | the Xen platform device | `xen_platform_pci = 0` |
| 9003 MAC `00:16:3E` | Xen's OUI | an Intel OUI, the e1000's |
| 13002 Hyper-V objects | not Viridian: still detected with it off (§5) | nothing to answer |
| 4067, 4068 CPUID hypervisor bit and vendor | hidden only by DRAKVUF's `-s` | `cpuid = 'host,hypervisor=0'` and the Xen patch |

How the 2026-11-02 rows were found and checked. 4097: the golden LV's
`SYSTEM` hive, read on Dom0; the patched `atapi.c` compiled with QEMU's own
flags, and the patch applied to Dom0's qemu-xen tree with `git apply --check`.
4098: the structures counted from `smbios.bin` and hvmloader's
`write_smbios_tables`; `sandboxd/tests/test_xen_identity.py` keeps the total
over 40. 8010: `static_tables.c` compiled with hvmloader's flags, and byte 45
of the FADT, which al-khaser reads, is 1.

Not in the table: 2029 (`NtYieldExecution`), which al-khaser's source calls
unreliable itself, and the checks that fire on real hardware too (§5).

---

## 2. The identity

`scripts/xen-identity.py` draws one per deployment, at random from real desktop
models (Dell OptiPlex, HP EliteDesk, Lenovo ThinkCentre, ASUS and MSI boards
with AMI firmware): vendor, product, BIOS vendor, version and date, board,
chassis, serial numbers in each vendor's format, OEM strings, ACPI OEM and table
IDs and creator, an EISA ID, a disk and an optical drive model with their
firmware revisions and the drive's serial — and an Intel MAC for each guest,
drawn the first time that guest's targets ask for it. An identity drawn before
the revisions and the drive's serial existed gets them the next time the script
reads it, for the models it already has: a new model would be a new device to
an installed Windows.

It is kept in **`state/xen-identity.json`, which is not tracked** (nor are the
files drawn from it). An identity that is not published cannot be detected by
name, and a sandbox detected by a string another sandbox also uses is the
failure this avoids. Keep the file: drawing a new one gives the guests new
hardware, which needs them reinstalled (§4).

```
scripts/xen-identity.py show              the identity, drawn now if there is none
scripts/xen-identity.py patch-xen TREE    Xen's own strings in hvmloader and libacpi
scripts/xen-identity.py guest-files DIR   smbios.bin and ssdt.aml
scripts/xen-identity.py xl-cfg DIR        the guest config lines
scripts/xen-identity.py get KEY           one value, e.g. bios_vendor
scripts/xen-identity.py mac GUEST         GUEST's own MAC, drawn the first time
```

---

## 3. Where it goes

**Xen, at `make xen`.** The submodule is reset to its pin, the three patches
applied (`xen-altp2m-pause-vcpu`, `xen-rdtsc-poc`, `xen-guest-identity`), then
`patch-xen` rewrites: every libacpi table header (OEM ID, table ID, revision,
creator), the DefinitionBlocks of the DSDT and SSDTs, the VM generation
counter's `XEN0000` ID, and hvmloader's SMBIOS defaults (BIOS vendor and
version, its release numbers, the build date as release date, system and
chassis maker, product, version, the type 11 and battery strings).
`automation/xen-guest-identity.patch` adds three things to Xen:

- hvmloader copies in `smbios_firmware` structures of the types it does not
  write itself, as it did for vendor types only;
- the FADT's preferred power-management profile is 1, desktop. Xen left it 0,
  unspecified, which is what QEMU's own tables say and real firmware does not;
- a guest whose CPUID policy clears the hypervisor bit finds no Xen or Viridian
  leaves **from user mode**. Its kernel and hvmloader, which finds Xen there at
  boot, still see them. Windows does not look with the bit clear; Linux scans
  for Xen's signature whatever the bit (`hypervisor_cpuid_base`,
  `arch/x86/include/asm/cpuid.h`), so it still runs as a Xen guest (§4).

**QEMU, at `make xen`.** Xen's build clones qemu-xen at its pin; `make xen`
clones it first, resets it and applies `automation/qemu-xen-cdrom-inquiry.patch`.
A CD-ROM given a model answered with it only in IDENTIFY PACKET, and Windows
names the drive from INQUIRY, where QEMU said vendor `QEMU`, product `QEMU
DVD-ROM`. The patch reports the model there too, split as a real drive's is:
the vendor its first word, at most 8 characters, the product the rest. A drive
given no model answers as before.

**The guest configs, at the four install targets** (`ubuntu_analysis_vm`,
`setup_hooks_ubuntu`, `windows_analysis_vm`, `setup_hooks_windows`):

```
viridian = 0
cpuid = 'host,hypervisor=0'
vif = [ '...,model=e1000,mac=<this guest's MAC>,...' ]
smbios = [ <identity strings, serial numbers, OEM strings> ]
smbios_firmware = '<repo>/state/firmware/smbios.bin'
acpi_firmware = '<repo>/state/firmware/ssdt.aml'
xen_platform_pci = 0
device_model_args_hvm = [ '-global', 'ide-hd.model=...', '-global', 'ide-hd.serial=...', '-global', 'ide-hd.ver=...',
                          '-global', 'ide-cd.model=...', '-global', 'ide-cd.serial=...', '-global', 'ide-cd.ver=...' ]
```

The tracked templates (`misc/*.cfg` and the `misc/xen-vms/` copies) carry the
first two lines and say where the rest comes from; they never carry the
identity's values. **On Dom0 the four `misc/xen-vms/` configs `make` writes do,**
and `sandboxd` reads them there. Never commit them from Dom0, whose checkout
has commits of its own: `git update-index --skip-worktree` on the four keeps a
`git commit -a` from taking them, and makes a pull that changes them stop.
**Each guest has its own MAC** (`xen-identity.py mac GUEST`). The golden VMs
share untagged `xenbr0`, and the templates share untagged `xenbr1` while
`setup_hooks_*` runs. On one bridge, two guests with one MAC are a collision,
which is how Windows' first-logon downloads failed on 2026-11-01
(`docs/TROUBLESHOOTING.md`, "Windows first logon"). An identity drawn before
then had one MAC; Ubuntu keeps it and Windows draws a new one.

`clone.py`'s rewrite keeps `mac=`, so every clone has its guest's MAC. That is
safe: a clone is alone on its own VLAN, with Dom0's `xenbr1.N` as its only
neighbour, and OVS learns MACs per VLAN. A per-clone `mac=` would also do
nothing. A clone is an `xl restore`, and QEMU's e1000 save state carries the
EEPROM and receive-address registers, so the restored guest keeps answering
to the MAC it was saved with. `xl network-list` would show the new MAC,
and the guest would still use the old one.

**DRAKVUF.** With the configs hiding the hypervisor, `sandboxd` no longer passes
`-s` for Ubuntu and Windows (`TraceOptions.cpuid_stealth`); Android, whose
config is unchanged, keeps it.

---

## 4. Why a reinstall

A guest keeps the firmware it booted with: a saved state restores hvmloader's
tables as they were, so a restored clone of today's guests would still say
`Xen`. And Windows keeps every device it ever saw in its registry: a cold boot
with the new disk model leaves `QEMU HARDDISK` and `VEN_5853` under `Enum`, where
checks 4096, 4097 and 9001 read them. A guest installed on the new hardware has
neither. So, in order:

1. `make xen`, reboot.
2. `make windows_analysis_vm`, then `modify_windows` and `setup_hooks_windows`.
3. `make ubuntu_analysis_vm`, then `setup_hooks_ubuntu`.

**Until then, `sandboxd` without `-s` lets today's guests see the hypervisor
bit.** Deploy the `sandboxd` change with the reinstalled guests, not before.

**A Xen built any other way has none of it in hvmloader, libacpi or QEMU.** The
RDTSC and al-khaser searches (outside the repository) build and install Xen from
a `drakvuf-dev/xen` checkout: restored guests do not notice, but a guest
installed or cold-booted on it gets Xen's strings back. Run `make xen` first.

**The Ubuntu guest still knows it runs on Xen.** Linux finds Xen's signature
whatever the hypervisor bit, and the patch hides the leaves from user mode
only, so the kernel keeps the `xen` clocksource and clockevent the RDTSC
compensation was designed and measured on (`rdtsc-poc.md` §1.1). Hiding them
from the kernel too would take that clock away; `/sys/hypervisor/type` reading
`xen` is the cost (§5).

What does change is the platform device. Without it Linux cannot unplug the
emulated devices, so it is expected to run on them rather than on its PV
drivers: the disk on the IDE controller, the network card the e1000. Under
systemd's naming a PCI e1000 would be `ens*` or `enp*`, and `sandboxd`
configures `eth0` (`guests.py`, `_ubuntu_netcfg`), so `ubuntu_analysis_vm` puts
`net.ifnames=0` on the installer's command line and in the installed system's
GRUB. Not yet seen on a guest; the RDTSC compensation has to be measured again
on the reinstalled one too.

---

## 5. What it does not answer

- **2025, the sample's parent is not `explorer.exe`**: sandboxd starts Windows
  samples through `cmd.exe`. A launch question, not an identity one.
- **4033, the user name `user`** (`ANALYSIS_VM_USER` in the Makefile).
- **What DRAKVUF's own load shows**: process memory walks (3007, 3008) and the
  genuine-Windows check (4095) block past al-khaser's two minutes, and every
  plugin at once trips `NtYieldExecution` (2029).
- **4099, ACPI tables**: al-khaser wants five PNP device IDs in every ACPI
  table, which no real machine has either: FACP, APIC and the rest never
  carry them, so it fires on real hardware too. Two things it reads besides
  are real tells, but the PNP test fails first on any machine: a `WAET`
  table, which hvmloader always writes, and no `WSMT`, which current real
  firmware has.
- **13002, `\GLOBAL??` objects**: still detected with `viridian = 0`, so not
  `VMBUS#` or `VmGid`, and not `VmGenerationCounter`: Xen's generation counter
  device has `_STA` 0 without `ms_vm_genid`, and the guest's `Enum\ACPI` has no
  such device. That leaves `VDRVROOT`, the Virtual Drive Enumerator every
  Windows installs (`Enum\ROOT\vdrvroot` is there from setup). Worked out by
  elimination, not seen: al-khaser on a real Windows 11 PC would confirm it.
- **14010, RDTSC Locky**: detected in every run with Xen's RDTSC compensation
  as deployed, and in one of four with `RDTSC_USER_PURE=1`. Whether a real
  Windows 11 passes it has not been measured (`rdtsc-poc.md`).
- **CPUID from kernel mode** still finds Xen's leaves. On Linux that is
  visible from user mode too: `/sys/hypervisor/type` reads `xen` and `dmesg`
  says `Hypervisor detected: Xen HVM`.
- **QEMU's other devices keep their IDs** (the `1234:1111` VGA, the USB
  tablet).
- **Android** is unchanged: `viridian = 1` in its configs and DRAKVUF's `-s`.
  Changing its config means re-saving the Android state, which is not done
  without an explicit instruction.