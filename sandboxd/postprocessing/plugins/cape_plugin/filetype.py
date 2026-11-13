"""A file's type from its own bytes, in the words of `file(1)`, and the CAPE
analysis package a sample of that type is run with.

`target.file.type` is libmagic's output in CAPE, and its readers match
substrings of it: scoring's `"executable" in type`, signatures' `"PE32" in`,
`"ELF" in`, `"DLL" in`, `"Mono/.Net" in`. Dom0 has no python-magic
(sandboxd/requirements.txt does not list it), and until 2026-11-12 an empty
type fell back to the guest's -- so a .js, a .sh, a 32-bit PE and an i386 ELF
were all reported as 64-bit executables and scored as such. `sniff` is what
answers when libmagic does not: far less than libmagic knows, but the truth
about the formats a sample comes in. With python-magic installed its answer
is used and this is not asked.
"""
from __future__ import annotations

import struct
from pathlib import Path

# IMAGE_FILE_MACHINE_* / EM_* as file(1) words them
_PE_MACHINES = {0x014C: "Intel 80386", 0x8664: "x86-64", 0x01C0: "ARM", 0x01C4: "ARMv7 Thumb",
                0xAA64: "Aarch64", 0x0200: "Intel Itanium"}
_ELF_MACHINES = {3: "Intel 80386", 62: "x86-64", 40: "ARM", 183: "ARM aarch64", 8: "MIPS",
                 20: "PowerPC or cisco 4500", 21: "64-bit PowerPC or cisco 7500", 2: "SPARC",
                 42: "Renesas SH", 4: "Motorola m68k", 243: "UCB RISC-V", 93: "ARC Cores Tangent-A5"}
_ELF_TYPES = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core file"}
_PE_SUBSYSTEMS = {1: "native", 2: "GUI", 3: "console", 9: "Windows CE", 10: "EFI application"}
_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_LNK = b"L\x00\x00\x00\x01\x14\x02\x00"

# What a text file is by its name: libmagic says "ASCII text" of most of
# these, which names no interpreter; the extension is what Windows runs it by.
_TEXT_BY_SUFFIX = {
    ".js": "JavaScript source", ".jse": "JScript.Encode script", ".vbs": "VBScript source",
    ".vbe": "VBScript.Encode script", ".wsf": "Windows Script File, XML document",
    ".ps1": "PowerShell script", ".bat": "DOS batch file", ".cmd": "DOS batch file",
    ".hta": "HTML Application, HTML document", ".sh": "POSIX shell script",
    ".py": "Python script",
}
_SHEBANGS = (("python", "Python script"), ("perl", "Perl script"), ("bash", "Bourne-Again shell script"),
             ("sh", "POSIX shell script"))

# CAPE's analysis packages (analyzer/windows/modules/packages), by suffix;
# `elf` and `sh` are ours -- CAPE's Linux analyzer has no package per format.
_PACKAGE_BY_SUFFIX = {
    ".dll": "dll", ".js": "js", ".jse": "vbejse", ".vbe": "vbejse", ".vbs": "vbs", ".wsf": "wsf",
    ".ps1": "ps1", ".bat": "batch", ".cmd": "batch", ".hta": "hta", ".lnk": "lnk", ".msi": "msi",
    ".jar": "jar", ".py": "python", ".sh": "sh", ".cpl": "cpl", ".chm": "chm", ".pdf": "pdf",
    ".zip": "zip", ".rar": "rar", ".html": "html", ".htm": "html", ".reg": "reg", ".sct": "sct",
}


def _text_kind(head: bytes) -> str:
    """How file(1) words text: "" for what is not text."""
    if not head:
        return "empty"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "Unicode text, UTF-16"
    if b"\x00" in head:
        return ""
    try:
        head.decode("ascii")
        return "ASCII text"
    except UnicodeDecodeError:
        pass
    try:
        # A multi-byte character cut by the end of the head is still UTF-8
        head[:-3].decode("utf-8")
        return "Unicode text, UTF-8 text"
    except UnicodeDecodeError:
        return ""


def _pe(head: bytes) -> str:
    if len(head) < 0x40 or head[:2] != b"MZ":
        return ""
    offset = struct.unpack_from("<I", head, 0x3C)[0]
    if offset + 24 + 96 > len(head) or head[offset:offset + 4] != b"PE\0\0":
        return "MS-DOS executable"
    machine, _, _, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", head, offset + 4)
    optional = offset + 24
    magic = struct.unpack_from("<H", head, optional)[0]
    plus = magic == 0x20B
    subsystem = struct.unpack_from("<H", head, optional + 68)[0]
    kind = "DLL" if characteristics & 0x2000 else _PE_SUBSYSTEMS.get(subsystem, "unknown subsystem")
    # The CLR header's data directory (15th): present in every .NET assembly
    directories = optional + (112 if plus else 96)
    count = struct.unpack_from("<I", head, directories - 4)[0] if directories <= len(head) else 0
    clr = directories + 14 * 8
    dotnet = (count > 14 and clr + 8 <= min(len(head), optional + optional_size)
              and struct.unpack_from("<I", head, clr)[0] != 0)
    return (f"{'PE32+' if plus else 'PE32'} executable ({kind}) "
            f"{_PE_MACHINES.get(machine, f'unknown machine 0x{machine:x}')}"
            f"{' Mono/.Net assembly' if dotnet else ''}, for MS Windows")


def _elf(head: bytes) -> str:
    if len(head) < 0x34 or head[:4] != b"\x7fELF":
        return ""
    bits, order = head[4], "<" if head[5] != 2 else ">"
    kind, machine = struct.unpack_from(order + "HH", head, 16)
    text = (f"ELF {'64' if bits == 2 else '32'}-bit {'LSB' if order == '<' else 'MSB'} "
            f"{_ELF_TYPES.get(kind, 'unknown type')}, {_ELF_MACHINES.get(machine, f'unknown arch 0x{machine:x}')}, "
            f"version 1 (SYSV)")
    # Statically linked is no PT_INTERP and no PT_DYNAMIC among the program
    # headers; they sit right after the header, within the bytes read, in
    # every ELF a linker wrote.
    try:
        if bits == 2:
            phoff, = struct.unpack_from(order + "Q", head, 0x20)
            phentsize, phnum = struct.unpack_from(order + "HH", head, 0x36)
        else:
            phoff, = struct.unpack_from(order + "I", head, 0x1C)
            phentsize, phnum = struct.unpack_from(order + "HH", head, 0x2A)
        if kind in (2, 3) and phnum and phoff + phentsize * phnum <= len(head):
            types = {struct.unpack_from(order + "I", head, phoff + i * phentsize)[0] for i in range(phnum)}
            text += ", dynamically linked" if types & {2, 3} else ", statically linked"
    except struct.error:
        pass
    return text


def sniff(path: Path) -> str:
    """`path`'s type in file(1)'s words; "data" for what nothing here knows,
    "" only for a file that cannot be read."""
    try:
        with path.open("rb") as f:
            head = f.read(1 << 16)
    except OSError:
        return ""
    suffix = path.suffix.lower()
    found = _pe(head) or _elf(head)
    if found:
        return found
    if head.startswith(_LNK):
        return "MS Windows shortcut"
    if head.startswith(_OLE):
        return "Composite Document File V2 Document" + (", MSI Installer" if suffix == ".msi" else "")
    if head.startswith(b"PK\x03\x04"):
        return "Java archive data (JAR)" if suffix == ".jar" else "Zip archive data"
    if head.startswith(b"%PDF-"):
        return "PDF document"
    if head.startswith(b"\x1f\x8b"):
        return "gzip compressed data"
    text = _text_kind(head)
    if not text:
        return "data"
    if head.startswith(b"#!"):
        interpreter = head[2:head.find(b"\n") if b"\n" in head else 256].decode("latin-1").strip()
        program = interpreter.split()[0].rsplit("/", 1)[-1] if interpreter.split() else ""
        if program == "env" and len(interpreter.split()) > 1:
            program = interpreter.split()[1]
        what = next((words for name, words in _SHEBANGS if name in program), f"a {interpreter} script")
        return f"{what}, {text} executable"
    if suffix in _TEXT_BY_SUFFIX:
        return f"{_TEXT_BY_SUFFIX[suffix]}, {text}"
    return text


def package(file_type: str, name: str) -> str:
    """The CAPE package name for a sample of `file_type` called `name`:
    what `info.package` says, which signatures gate on (`in ["exe", "dll",
    "msi"]`, the office packages). "generic" where nothing is known."""
    suffix = Path(name or "").suffix.lower()
    file_type = file_type or ""
    if file_type.startswith(("PE32", "MS-DOS executable")):
        return "dll" if "(DLL)" in file_type or suffix == ".dll" else "exe"
    if file_type.startswith("ELF"):
        return "elf"
    if suffix in _PACKAGE_BY_SUFFIX:
        return _PACKAGE_BY_SUFFIX[suffix]
    if "shell script" in file_type:
        return "sh"
    if "Python script" in file_type:
        return "python"
    return "generic"
