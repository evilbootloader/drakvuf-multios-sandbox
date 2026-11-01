#!/usr/bin/env python3
"""The guests' hardware identity: what this deployment's analysis guests see as their
firmware and devices, in place of Xen's and QEMU's.

Xen writes its own name into every guest: SMBIOS says "Xen" and "HVM domU", its BIOS
release is Xen's version, every ACPI table names "Xen"/"HVM" as OEM and hvmloader as
creator, the MAC starts with Xen's 00:16:3E, the disk is a "QEMU HARDDISK". A guest also
lacks what every real machine has: caches, port connectors, slots, fans, probes, a
thermal zone. Malware checks for all of it.

The identity is drawn once per deployment, at random from real desktop models, and kept
in state/xen-identity.json, which is not tracked: an identity that is not published
cannot be detected by name. The same file then patches the Xen source, writes the
firmware files the guests are given and the lines of their xl configs:

  xen-identity.py show                     the identity, drawn now if there is none
  xen-identity.py patch-xen XEN_TREE       Xen's own strings in hvmloader and libacpi
  xen-identity.py guest-files OUT_DIR      smbios.bin and ssdt.aml (iasl) for xl
  xen-identity.py xl-cfg OUT_DIR           smbios, firmware, platform device and disk lines
  xen-identity.py get KEY                  one value, e.g. mac

`make xen` runs patch-xen on the pristine source after the patches; the Windows targets
run guest-files and add xl-cfg's lines and the MAC to the configs they write. A guest
only sees a new identity after a cold boot: a saved state keeps the firmware it booted
with, and Windows keeps the devices it once saw in its registry, so change it before a
guest is installed. docs/architecture/guest-identity.md has the details.
"""
import argparse
import json
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_STATE = REPO_ROOT / "state" / "xen-identity.json"

# Real desktop models, their firmware's usual strings and ACPI header fields. The
# serial formats are the vendors'; DIY boards really carry the placeholders.
PROFILES = [
    {
        "manufacturer": "Dell Inc.", "products": ["OptiPlex 7090", "OptiPlex 7080", "OptiPlex 5090"],
        "family": "OptiPlex", "system_version": "", "bios_vendor": "Dell Inc.",
        "bios_versions": ["1.18.0", "1.21.0", "1.24.0", "1.27.0"], "bios_release": (1, 24),
        "boards": ["0K240Y", "05RFJ8", "0YK1N8"], "board_version": "A00", "serial": "dell",
        "oem_strings": ["Dell System", "1[0A3F]", "3[1.0]"],
        "acpi": ("DELL  ", "CBX3   ", 0x01072009, "AMI ", 0x00010013), "eisa": "DEL",
    },
    {
        "manufacturer": "HP", "products": ["HP EliteDesk 800 G6 Small Form Factor PC",
                                           "HP ProDesk 600 G6 Small Form Factor PC"],
        "family": "103C_53307F HP EliteDesk", "system_version": "", "bios_vendor": "HP",
        "bios_versions": ["S01 Ver. 02.11.00", "S01 Ver. 02.14.01", "S01 Ver. 02.16.00"],
        "bios_release": (2, 14), "boards": ["870E", "8715"], "board_version": "KBC Version 08.81.00",
        "serial": "hp", "oem_strings": ["FBYTE#3X476J6S6b7B7M7Q7W7maBapaqawbkbr.", "BUILDID#20WWDTA8601#SABA#DABA;"],
        "acpi": ("HPQOEM", "SLIC-BPC", 0x00000000, "HP  ", 0x00000001), "eisa": "HWP",
    },
    {
        "manufacturer": "LENOVO", "products": ["11EX0012US", "11DF0041GE", "11EX001CMX"],
        "family": "ThinkCentre M70s", "system_version": "ThinkCentre M70s", "bios_vendor": "LENOVO",
        "bios_versions": ["M3BKT4AA", "M3BKT4FA", "M3BKT52A"], "bios_release": (1, 79),
        "boards": ["3136"], "board_version": "SDK0J40697 WIN 3305136342186", "serial": "lenovo",
        "oem_strings": ["SKU: LENOVO_MT_11EX_BU_Think_FM_ThinkCentre M70s"],
        "acpi": ("LENOVO", "TC-M3B  ", 0x00001790, "PTEC", 0x00000002), "eisa": "LEN",
    },
    {
        "manufacturer": "ASUS", "products": ["System Product Name"], "family": "To be filled by O.E.M.",
        "system_version": "System Version", "bios_vendor": "American Megatrends Inc.",
        "bios_versions": ["1601", "1801", "2001", "2101"], "bios_release": (5, 19),
        "boards": ["PRIME B560M-A", "TUF GAMING B560M-PLUS", "PRIME H570-PLUS"],
        "board_vendor": "ASUSTeK COMPUTER INC.", "board_version": "Rev 1.xx", "serial": "diy",
        "oem_strings": ["Default string"],
        "acpi": ("ALASKA", "A M I ", 0x01072009, "AMI ", 0x00010013), "eisa": "AMI",
    },
    {
        "manufacturer": "Micro-Star International Co., Ltd.", "products": ["MS-7D09", "MS-7D15"],
        "family": "To be filled by O.E.M.", "system_version": "1.0",
        "bios_vendor": "American Megatrends International, LLC.",
        "bios_versions": ["1.A0", "1.B0", "1.C0"], "bios_release": (5, 19),
        "boards": ["MAG B560M MORTAR WIFI (MS-7D17)", "PRO B560M-A (MS-7D20)"], "board_version": "1.0",
        "serial": "diy", "oem_strings": ["To Be Filled By O.E.M."],
        "acpi": ("ALASKA", "A M I ", 0x01072009, "AMI ", 0x00010013), "eisa": "MSI",
    },
]

# QEMU emulates an Intel 82540EM for model=e1000: an Intel OUI matches the device
INTEL_OUIS = ["00:1B:21", "3C:FD:FE", "A0:36:9F", "68:05:CA", "00:15:17", "F8:F2:1E"]

DISKS = [
    ("Samsung SSD 870 EVO 500GB", "S6PXNM0T{d6}A"),
    ("WDC WDS500G2B0A-00SM50", "{d12}"),
    ("CT500MX500SSD1", "2108E5{h6}"),
    ("KINGSTON SA400S37480G", "50026B7784{h6}"),
]
OPTICAL = ["HL-DT-ST DVD+-RW GTA0N", "TSSTcorp DVD+-RW SU-208FB", "ASUS DRW-24D5MT"]


def pick(seq):
    return seq[secrets.randbelow(len(seq))]


def chars(alphabet, n):
    return "".join(pick(alphabet) for _ in range(n))


def fill(template):
    """{dN} N digits, {hN} N uppercase hex digits"""
    return re.sub(r"\{([dh])(\d+)\}",
                  lambda m: chars("0123456789" if m.group(1) == "d" else "0123456789ABCDEF",
                                  int(m.group(2))), template)


def serials(kind):
    """System, board and chassis serial numbers in the vendor's format"""
    upper_digits = "0123456789ABCDEFGHJKLMNPRSTVWXYZ"
    if kind == "dell":
        tag = chars("0123456789BCDFGHJKLMNPQRSTVWXYZ", 7)
        return tag, "/%s/CNCMK00%s/" % (tag, chars("0123456789", 6)), tag
    if kind == "hp":
        serial = "CZC" + chars(upper_digits, 7)
        return serial, "PFWUC0%sB" % chars("0123456789ABCDEF", 6), serial
    if kind == "lenovo":
        serial = "MJ0" + chars(upper_digits, 5)
        return serial, "L1HF%s0%s" % (chars("0123456789", 3), chars(upper_digits, 4)), serial
    return "System Serial Number", chars("0123456789", 15), "Default string"


def draw():
    p = pick(PROFILES)
    system_serial, board_serial, chassis_serial = serials(p["serial"])
    oem_id, table_id, oem_rev, creator, creator_rev = p["acpi"]
    month, day, year = 1 + secrets.randbelow(12), 1 + secrets.randbelow(28), 2023 + secrets.randbelow(3)
    disk_model, disk_serial = pick(DISKS)
    return {
        "manufacturer": p["manufacturer"],
        "product": pick(p["products"]),
        "family": p["family"],
        "system_version": p["system_version"],
        "system_serial": system_serial,
        "bios_vendor": p["bios_vendor"],
        "bios_version": pick(p["bios_versions"]),
        "bios_date": "%02d/%02d/%d" % (month, day, year),
        "bios_release": list(p["bios_release"]),
        "board_vendor": p.get("board_vendor", p["manufacturer"]),
        "board_product": pick(p["boards"]),
        "board_version": p["board_version"],
        "board_serial": board_serial,
        "chassis_vendor": p["manufacturer"],
        "chassis_serial": chassis_serial,
        "oem_strings": p["oem_strings"],
        "acpi_oem_id": oem_id,
        "acpi_table_id": table_id,
        "acpi_oem_revision": oem_rev,
        "acpi_creator_id": creator,
        "acpi_creator_revision": creator_rev,
        "eisa_id": p["eisa"] + chars("0123456789ABCDEF", 4),
        "mac": "%s:%s" % (pick(INTEL_OUIS), ":".join("%02X" % secrets.randbelow(256) for _ in range(3))),
        "disk_model": disk_model,
        "disk_serial": fill(disk_serial),
        "cdrom_model": pick(OPTICAL),
    }


def load(path, create=True):
    if path.exists():
        return json.loads(path.read_text())
    if not create:
        sys.exit("No identity in %s: run `%s show` first" % (path, sys.argv[0]))
    identity = draw()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(identity, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    print("Drew a new guest identity into %s" % path, file=sys.stderr)
    return identity


def c_string(s):
    return '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"')


def substitute(path, pattern, replacement, count):
    """Replace pattern exactly count times in path, or stop: Xen changed under us"""
    text = path.read_text()
    new, n = re.subn(pattern, replacement, text)
    if n != count:
        sys.exit("%s: %r matched %d times, expected %d" % (path, pattern, n, count))
    path.write_text(new)


def patch_xen(identity, tree):
    tree = Path(tree)
    acpi = tree / "tools" / "libacpi"
    hvmloader = tree / "tools" / "firmware" / "hvmloader"
    if not (acpi / "acpi2_0.h").exists():
        sys.exit("%s is not a Xen source tree" % tree)

    oem, table = identity["acpi_oem_id"], identity["acpi_table_id"]
    creator = identity["acpi_creator_id"]
    subs = [
        # The header of every table libacpi builds
        (acpi / "acpi2_0.h", r'(#define ACPI_OEM_ID\s+)"Xen"', r'\g<1>' + c_string(oem), 1),
        (acpi / "acpi2_0.h", r'(#define ACPI_OEM_TABLE_ID\s+)"HVM"', r'\g<1>' + c_string(table), 1),
        (acpi / "acpi2_0.h", r'(#define ACPI_OEM_REVISION\s+)0\b',
         r'\g<1>0x%08x' % identity["acpi_oem_revision"], 1),
        (acpi / "acpi2_0.h", r"(#define ACPI_CREATOR_ID\s+)ASCII32\('H','V','M','L'\) /\* HVMLoader \*/",
         r"\g<1>ASCII32(%s)" % ",".join("'%s'" % c for c in creator), 1),
        (acpi / "acpi2_0.h", r'(#define ACPI_CREATOR_REVISION\s+)0\b',
         r'\g<1>0x%08x' % identity["acpi_creator_revision"], 1),
        # The VM generation counter's ID (Windows binds its driver by _CID)
        (acpi / "dsdt.asl", r'EisaId \("XEN0000"\)', 'EisaId ("%s")' % identity["eisa_id"], 1),
        # SMBIOS defaults, which xl's smbios= strings override
        (hvmloader / "smbios.c", r'xenstore_read\(HVM_XS_BIOS_VENDOR, "Xen"\)',
         "xenstore_read(HVM_XS_BIOS_VENDOR, %s)" % c_string(identity["bios_vendor"]), 1),
        (hvmloader / "smbios.c", r'xenstore_read\(HVM_XS_BIOS_VERSION, xen_version\)',
         "xenstore_read(HVM_XS_BIOS_VERSION, %s)" % c_string(identity["bios_version"]), 1),
        (hvmloader / "smbios.c", r'xenstore_read\(HVM_XS_SYSTEM_MANUFACTURER, "Xen"\)',
         "xenstore_read(HVM_XS_SYSTEM_MANUFACTURER, %s)" % c_string(identity["manufacturer"]), 1),
        (hvmloader / "smbios.c", r'xenstore_read\(HVM_XS_SYSTEM_PRODUCT_NAME, "HVM domU"\)',
         "xenstore_read(HVM_XS_SYSTEM_PRODUCT_NAME, %s)" % c_string(identity["product"]), 1),
        (hvmloader / "smbios.c", r'xenstore_read\(HVM_XS_SYSTEM_VERSION, xen_version\)',
         "xenstore_read(HVM_XS_SYSTEM_VERSION, %s)" % c_string(identity["system_version"]), 1),
        (hvmloader / "smbios.c", r'xenstore_read\(HVM_XS_ENCLOSURE_MANUFACTURER, "Xen"\)',
         "xenstore_read(HVM_XS_ENCLOSURE_MANUFACTURER, %s)" % c_string(identity["chassis_vendor"]), 1),
        (hvmloader / "smbios.c", r'xenstore_read\(HVM_XS_BATTERY_MANUFACTURER, "Xen"\)',
         "xenstore_read(HVM_XS_BATTERY_MANUFACTURER, %s)" % c_string(identity["manufacturer"]), 1),
        (hvmloader / "smbios.c", r'xenstore_read\(HVM_XS_BATTERY_DEVICE_NAME, "XEN-VBAT"\)',
         'xenstore_read(HVM_XS_BATTERY_DEVICE_NAME, "Primary Battery")', 1),
        # The type 11 string written when no OEM string is given
        (hvmloader / "smbios.c", r'strcpy\(\(char \*\)start, "Xen"\);\n(\s+)start \+= strlen\("Xen"\) \+ 1;',
         'strcpy((char *)start, %s);\n\\g<1>start += strlen(%s) + 1;'
         % (c_string(identity["oem_strings"][0]), c_string(identity["oem_strings"][0])), 1),
        # BIOS release: Xen's major and minor version, the build date
        (hvmloader / "smbios.c", r'p->major_release = \(uint8_t\) xen_major_version;',
         "p->major_release = %d;" % identity["bios_release"][0], 1),
        (hvmloader / "smbios.c", r'p->minor_release = \(uint8_t\) xen_minor_version;',
         "p->minor_release = %d;" % identity["bios_release"][1], 1),
        (hvmloader / "Makefile", r'SMBIOS_REL_DATE \?= \$\(call date,"\+%m/%d/%Y"\)',
         "SMBIOS_REL_DATE ?= %s" % identity["bios_date"], 1),
    ]
    for asl in sorted(acpi.glob("*.asl")):
        n = len(re.findall(r'DefinitionBlock \("[^"]+", "[A-Z]{4}", 2, "Xen", "HVM", 0\)', asl.read_text()))
        if n:
            subs.append((asl, r'(DefinitionBlock \("[^"]+", "[A-Z]{4}", 2, )"Xen", "HVM", 0\)',
                         r'\g<1>"%s", "%s", 0x%08x)' % (oem, table, identity["acpi_oem_revision"]), n))
    for path, pattern, replacement, count in subs:
        substitute(path, pattern, replacement, count)
    left = subprocess.run(["grep", "-rnI", "-e", '"Xen"', "-e", '"HVM domU"', "-e", '"HVM"', "-e", "XEN0000",
                           str(acpi), str(hvmloader / "smbios.c")], capture_output=True, text=True).stdout
    print("Patched %s as %s %s, ACPI %r %r" % (tree, identity["manufacturer"], identity["product"], oem, table))
    if left.strip():
        print("Xen strings left, check them:\n" + left, file=sys.stderr)


def smbios_struct(type_, handle, formatted, strings):
    """One SMBIOS structure with its strings, preceded by its length as xl wants it"""
    body = struct.pack("<BBH", type_, 4 + len(formatted), handle) + formatted
    text = b"".join(s.encode("ascii") + b"\0" for s in strings) + b"\0"
    if not strings:
        text = b"\0\0"
    structure = body + text
    return struct.pack("<I", len(structure)) + structure


def smbios_file(identity):
    """The hardware hvmloader does not describe: caches (7), port connectors (8), slots (9),
    voltage (26), temperature (28) and current (29) probes, a cooling device (27). Handles
    follow hvmloader's type << 8 numbering, which these types do not use."""
    out = []
    # Type 7, SMBIOS 3.1: designation, configuration, max size, installed size, supported and
    # current SRAM type, speed, error correction, system cache type, associativity, sizes 2
    for i, (name, level, kib, ecc, kind, assoc) in enumerate([
            ("L1 Cache", 0, 384, 4, 4, 7), ("L2 Cache", 1, 3072, 5, 5, 7), ("L3 Cache", 2, 16384, 6, 5, 9)]):
        config = 0x0180 | level  # enabled, write back, internal, not socketed
        size = 0x8000 | (kib // 64) if kib >= 32768 else kib
        out.append(smbios_struct(7, 0x0700 + i, struct.pack(
            "<BHHHHHBBBBII", 1, config, size, size, 0x0020, 0x0020, 0, ecc, kind, assoc, kib, kib), [name]))
    # Type 8: internal designator, internal type, external designator, external type, port type
    ports = [("J1A1", "USB 1", 0x12, 0x10), ("J1A2", "USB 2", 0x12, 0x10), ("J2A1", "USB 3", 0x12, 0x10),
             ("J2A2", "USB 4", 0x12, 0x10), ("J3A1", "Network", 0x0B, 0x1F), ("J4A1", "Audio Line Out", 0x1F, 0x1D),
             ("J4A2", "Microphone", 0x1F, 0x1D), ("J5A1", "DisplayPort", 0xFF, 0x1C)]
    for i, (internal, external, connector, port) in enumerate(ports):
        out.append(smbios_struct(8, 0x0800 + i, struct.pack("<BBBBB", 1, 0, 2, connector, port),
                                 [internal, external]))
    # Type 9, SMBIOS 2.6: designation, type, width, usage, length, id, characteristics 1 and 2,
    # segment, bus, device/function
    for i, (name, kind, width, usage, bus) in enumerate([
            ("PCIEX16_1", 0xB6, 0x0D, 4, 0x01), ("PCIEX1_1", 0xB3, 0x08, 3, 0xFF), ("M.2_1", 0x16, 0x0B, 4, 0x02)]):
        out.append(smbios_struct(9, 0x0900 + i, struct.pack(
            "<BBBBBHBBHBB", 1, kind, width, usage, 0x04, i + 1, 0x0C, 0x01, 0, bus, 0), [name]))
    # Types 26, 28, 29: description, location and status, maximum, minimum, resolution,
    # tolerance, accuracy, OEM, nominal value (values 0x8000 are unknown)
    probes = [(26, "CPU Core Voltage", 0x63, 1500, 500, 10, 0x8000, 0x8000, 1100),
              (26, "+12V", 0x64, 13200, 10800, 10, 0x8000, 0x8000, 12000),
              (28, "CPU Thermal Probe", 0x63, 1000, 0, 10, 0x8000, 0x8000, 450),
              (28, "Motherboard Thermal Probe", 0x64, 900, 0, 10, 0x8000, 0x8000, 380),
              (29, "CPU Current Probe", 0x63, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000)]
    count = {}
    for type_, name, location, high, low, resolution, tolerance, accuracy, nominal in probes:
        handle = (type_ << 8) + count.get(type_, 0)
        count[type_] = count.get(type_, 0) + 1
        out.append(smbios_struct(type_, handle, struct.pack(
            "<BBHHHHHIH", 1, location, high, low, resolution, tolerance, accuracy, 0, nominal), [name]))
    # Type 27, SMBIOS 2.7: its temperature probe (the CPU's, handle 0x1C00), type and status
    # (fan, OK), group, OEM, speed, description
    for i, (name, rpm) in enumerate([("CPU Fan", 1200), ("System Fan", 900)]):
        out.append(smbios_struct(27, 0x1B00 + i, struct.pack(
            "<HBBIHB", 0x1C00, 0x63, 1, 0, rpm, 1), [name]))
    return b"".join(out)


def ssdt_asl(identity):
    """A thermal zone, which every real board's firmware describes: Windows' thermal zone
    counters and MSAcpi_ThermalZoneTemperature are empty without one"""
    return """/* Generated by scripts/xen-identity.py: a thermal zone for the guest */
DefinitionBlock ("ssdt.aml", "SSDT", 2, "%s", "%s", 0x%08x)
{
    Scope (\\_TZ)
    {
        ThermalZone (TZ00)
        {
            Method (_TMP, 0, Serialized)
            {
                Return (0x0C3C)     /* 40.0 C, in tenths of a kelvin */
            }

            Method (_CRT, 0, Serialized)
            {
                Return (0x0E8C)     /* 100.0 C */
            }

            Method (_PSV, 0, Serialized)
            {
                Return (0x0E28)     /* 90.0 C */
            }

            Name (_TC1, 0x02)
            Name (_TC2, 0x05)
            Name (_TSP, 0x0258)     /* sampled every 60 s */
        }
    }
}
""" % (identity["acpi_oem_id"], identity["acpi_table_id"], identity["acpi_oem_revision"])


def guest_files(identity, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "smbios.bin").write_bytes(smbios_file(identity))
    (out / "ssdt.asl").write_text(ssdt_asl(identity))
    iasl = shutil.which("iasl")
    if not iasl:
        sys.exit("No iasl to compile %s (apt-get install acpica-tools)" % (out / "ssdt.asl"))
    subprocess.run([iasl, "-p", str(out / "ssdt"), str(out / "ssdt.asl")], check=True,
                   stdout=subprocess.DEVNULL)
    print("Wrote %s/smbios.bin and %s/ssdt.aml" % (out, out))


def xl_cfg(identity, out_dir):
    out = Path(out_dir).resolve()
    smbios = [
        "bios_vendor=" + identity["bios_vendor"], "bios_version=" + identity["bios_version"],
        "system_manufacturer=" + identity["manufacturer"], "system_product_name=" + identity["product"],
        "system_version=" + identity["system_version"], "system_serial_number=" + identity["system_serial"],
        "baseboard_manufacturer=" + identity["board_vendor"],
        "baseboard_product_name=" + identity["board_product"],
        "baseboard_version=" + identity["board_version"], "baseboard_serial_number=" + identity["board_serial"],
        "enclosure_manufacturer=" + identity["chassis_vendor"],
        "enclosure_serial_number=" + identity["chassis_serial"],
    ] + ["oem=" + s for s in identity["oem_strings"]]
    for value in smbios:
        if "'" in value or "," in value.split("=", 1)[0]:
            sys.exit("Cannot quote %r in an xl config" % value)
    print("smbios = [ %s ]" % ", ".join("'%s'" % v for v in smbios))
    print("smbios_firmware = '%s'" % (out / "smbios.bin"))
    print("acpi_firmware = '%s'" % (out / "ssdt.aml"))
    # The Xen platform PCI device (5853:0001) serves PV drivers, which the guests do not use
    print("xen_platform_pci = 0")
    print("device_model_args_hvm = [ '-global', 'ide-hd.model=%s', '-global', 'ide-hd.serial=%s', "
          "'-global', 'ide-cd.model=%s' ]" % (identity["disk_model"], identity["disk_serial"],
                                              identity["cdrom_model"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE, help="the identity file (%(default)s)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("show")
    sub.add_parser("patch-xen").add_argument("tree")
    sub.add_parser("guest-files").add_argument("out_dir")
    sub.add_parser("xl-cfg").add_argument("out_dir")
    sub.add_parser("get").add_argument("key")
    args = parser.parse_args()

    identity = load(args.state)
    if args.command == "show":
        print(json.dumps(identity, indent=2))
    elif args.command == "patch-xen":
        patch_xen(identity, args.tree)
    elif args.command == "guest-files":
        guest_files(identity, args.out_dir)
    elif args.command == "xl-cfg":
        xl_cfg(identity, args.out_dir)
    elif args.command == "get":
        if args.key not in identity:
            sys.exit("No %r in the identity: %s" % (args.key, ", ".join(sorted(identity))))
        print(identity[args.key])


if __name__ == "__main__":
    main()
