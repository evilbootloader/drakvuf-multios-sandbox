# Guest identity — what the analysis guests look like from inside

> **Status (2026-11-01): CANDIDATE. Implemented and checked in parts, never run
> end to end.** `scripts/xen-identity.py` was run against a copy of the Xen
> source and its output compiled on Dom0 (the ACPI tables and the thermal zone
> with `iasl`); a rendered guest config passed `xl -N create`. Nothing below has
> booted a guest. It takes effect only on guests **installed after** `make xen`
> has run with it (§4), so the evidence for it is an al-khaser run on a
> reinstalled Windows guest and the red pill on a reinstalled Ubuntu guest,
> compared with the 2026-11-01 baseline below.

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
| 4098 SMBIOS tables | too few | the same structures |
| 8010 ACPI tables (QEMU check) | Xen's ACPI headers | identity in libacpi |
| 4064, 4096, 4097 disk (SetupDi, registry) | `QEMU HARDDISK` | `ide-hd.model`/`serial` |
| 9001 PCI vendor 5853 | the Xen platform device | `xen_platform_pci = 0` |
| 9003 MAC `00:16:3E` | Xen's OUI | an Intel OUI, the e1000's |
| 13002 Hyper-V objects | possibly Viridian (§5) | `viridian = 0` |
| 4067, 4068 CPUID hypervisor bit and vendor | hidden only by DRAKVUF's `-s` | `cpuid = 'host,hypervisor=0'` and the Xen patch |

---

## 2. The identity

`scripts/xen-identity.py` draws one per deployment, at random from real desktop
models (Dell OptiPlex, HP EliteDesk, Lenovo ThinkCentre, ASUS and MSI boards
with AMI firmware): vendor, product, BIOS vendor, version and date, board,
chassis, serial numbers in each vendor's format, OEM strings, ACPI OEM and table
IDs and creator, an EISA ID, an Intel MAC, a disk and an optical drive model.

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
scripts/xen-identity.py get KEY           one value, e.g. mac
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
`automation/xen-guest-identity.patch` adds two things to Xen:

- hvmloader copies in `smbios_firmware` structures of the types it does not
  write itself, as it did for vendor types only;
- a guest whose CPUID policy clears the hypervisor bit finds no Xen or Viridian
  leaves **from user mode**. Its kernel and hvmloader, which finds Xen there at
  boot, still see them. Windows does not look with the bit clear; Linux scans
  for Xen's signature whatever the bit (`hypervisor_cpuid_base`,
  `arch/x86/include/asm/cpuid.h`), so it still runs as a Xen guest (§4).

**The guest configs, at the four install targets** (`ubuntu_analysis_vm`,
`setup_hooks_ubuntu`, `windows_analysis_vm`, `setup_hooks_windows`):

```
viridian = 0
cpuid = 'host,hypervisor=0'
vif = [ '...,model=e1000,mac=<identity>,...' ]
smbios = [ <identity strings, serial numbers, OEM strings> ]
smbios_firmware = '<repo>/state/firmware/smbios.bin'
acpi_firmware = '<repo>/state/firmware/ssdt.aml'
xen_platform_pci = 0
device_model_args_hvm = [ '-global', 'ide-hd.model=...', '-global', 'ide-hd.serial=...', '-global', 'ide-cd.model=...' ]
```

The tracked templates (`misc/*.cfg` and the `misc/xen-vms/` copies) carry the
first two lines and say where the rest comes from; they never carry the
identity's values. **On Dom0 the four `misc/xen-vms/` configs `make` writes do,**
and `sandboxd` reads them there: Dom0 only pulls, so never commit them from it.
`clone.py`'s rewrite keeps `mac=`, so every clone has the guest's MAC, each on its
own VLAN.

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
  table, which no real machine has either.
- **13002** may be `VDRVROOT`, which every Windows has, rather than Viridian's
  `VmGid`/`VmGenerationCounter`; which object matched has not been looked at.
- **CPUID from kernel mode** still finds Xen's leaves. On Linux that is
  visible from user mode too: `/sys/hypervisor/type` reads `xen` and `dmesg`
  says `Hypervisor detected: Xen HVM`.
- **QEMU's other devices keep their IDs** (the `1234:1111` VGA, the USB
  tablet).
- **Android** is unchanged: `viridian = 1` in its configs and DRAKVUF's `-s`.
  Changing its config means re-saving the Android state, which is not done
  without an explicit instruction.