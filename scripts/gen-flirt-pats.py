#!/usr/bin/env python3
"""FLIRT patterns of the functions in static libraries, for sandboxd/samplehooks.py.

    scripts/gen-flirt-pats.py --name glibc-2.35-amd64 /usr/lib/x86_64-linux-gnu/libc.a
    scripts/gen-flirt-pats.py --name openssl-3.0 libssl.a libcrypto.a --out sandboxd/data/flirt

A statically linked program carries its C library as code of its own, at
addresses nobody published and, stripped, under no name. FLIRT names such a
function by its bytes: the first 32, a CRC of the bytes after them, the total
length, and the bytes after the CRC. The bytes a linker fills in (the operand
of a call, the address of a global) differ from one program to the next and
are left out of the comparison.

This writes those patterns from the libraries themselves: every function of
every object in an `ar` archive (or of an object file), with each byte a
relocation covers wildcarded -- which is exactly the set a linker rewrites.
One `<name>.pat.gz` per run, which python-flirt reads as it is, and beside it
`<name>.yar`: a YARA rule that recognises the library in a program
(identity_rule), by which samplehooks chooses the sets worth loading.

`scripts/fetch-flirt-sets.py` runs this over the C libraries and compiler
runtimes of published toolchains, version by version.

**A pattern set is for the library build it was made from.** A function
compiled by another compiler version, or with other flags, has other bytes.
A sample built against uClibc or musl needs their sets; which archives to
feed this is the operator's knowledge of what samples are built with, and
`sandboxd/data/flirt/` (not tracked, like the YARA sets) is where sets go.

Functions shorter than MIN_BYTES are left out: four bytes name nothing.
x86 and x86-64 objects only.
"""
from __future__ import annotations

import argparse
import gzip
import io
import json
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

#: FLIRT's own numbers: the leading bytes, and the most a CRC covers.
LEAD = 32
CRC_MAX = 255
MIN_BYTES = 8
#: Bytes of a function no relocation covers, at least: fewer name nothing.
MIN_FIXED = 16
#: Bytes a relocation of each type rewrites. Types not listed are taken for 4,
#: the size of every x86 relocation but the 64-bit absolute ones.
WIDTH_64 = frozenset(("R_X86_64_64", "R_X86_64_PC64", "R_X86_64_GOTOFF64", "R_X86_64_RELATIVE64"))
#: Relocations a static link rewrites the instruction of, not only its
#: operand: an access through the GOT becomes a direct one (`mov rdx,[rip+x]`,
#: 48 8B 15, is linked as `mov rdx,imm32`, 48 C7 C2, or as `lea`), and a
#: thread-local sequence is replaced whole. The bytes before the operand are
#: then the linker's too: (bytes before, bytes after the 4 of the operand).
#: uClibc's `socket` reads errno this way eleven bytes in; without this its
#: pattern never matched the linked function (2026-11-14).
RELAXED = {
    "R_X86_64_GOTPCREL": (3, 0), "R_X86_64_GOTPCRELX": (3, 0), "R_X86_64_REX_GOTPCRELX": (3, 0),
    "R_X86_64_GOTTPOFF": (3, 0), "R_X86_64_GOTPC32_TLSDESC": (3, 0), "R_X86_64_TLSDESC_CALL": (0, 2),
    "R_X86_64_TLSGD": (4, 8), "R_X86_64_TLSLD": (3, 5),
    "R_386_GOT32": (2, 0), "R_386_GOT32X": (2, 0), "R_386_TLS_IE": (2, 0), "R_386_TLS_GOTIE": (2, 0),
    "R_386_TLS_GD": (3, 5), "R_386_TLS_LDM": (2, 5),
}


def crc16(data: bytes) -> int:
    """The checksum FLAIR's tools write (CRC-16/X-25 with its bytes swapped)."""
    if not data:
        return 0
    crc = 0xFFFF
    for byte in data:
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if (crc ^ byte) & 1 else crc >> 1
            byte >>= 1
    crc = ~crc & 0xFFFF
    return ((crc << 8) | (crc >> 8)) & 0xFFFF


def members(path: Path):
    """(member name, bytes) of an `ar` archive, or the file itself."""
    data = path.read_bytes()
    if not data.startswith(b"!<arch>\n"):
        yield path.name, data
        return
    at, names = 8, b""
    while at + 60 <= len(data):
        header = data[at:at + 60]
        size = int(header[48:58])
        name = header[:16].rstrip()
        body = data[at + 60:at + 60 + size]
        at += 60 + size + (size & 1)
        if name == b"//":
            names = body                    # the table of long names
        elif name in (b"/", b"/SYM64/"):
            continue                        # the archive's symbol index
        else:
            if name.startswith(b"/") and name[1:].isdigit():
                name = names[int(name[1:]):].split(b"/\n", 1)[0]
            yield name.rstrip(b"/").decode("utf-8", "replace"), body


def outbound_branches(code: bytes, start: int) -> set:
    """Offsets (from the section's start) of the operand of every `call
    rel32` and `jmp rel32` in a function's bytes that goes outside it. An E8
    or E9 that is part of another instruction gives a target that is
    anywhere, mostly outside too: its four bytes are left out as well, which
    costs a pattern a little of its precision and nothing else."""
    holes = set()
    for at in range(len(code) - 4):
        if code[at] in (0xE8, 0xE9):
            target = at + 5 + int.from_bytes(code[at + 1:at + 5], "little", signed=True)
            if not 0 <= target < len(code):
                holes.update(range(start + at + 1, start + at + 5))
    return holes


def patterns(obj: bytes, local: bool = False):
    """One pattern line per function of a relocatable object. `local`: Go's
    object (scripts/fetch-flirt-sets.py --go) -- every Go function in it is
    file-local, and its linker has already resolved the calls between them,
    leaving no relocation to say where a program's linker puts other bytes:
    the calls and jumps that leave a function are left out by their shape."""
    elf = ELFFile(io.BytesIO(obj))
    if elf["e_type"] != "ET_REL" or elf["e_machine"] not in ("EM_X86_64", "EM_386"):
        return
    symtab = next((s for s in elf.iter_sections() if isinstance(s, SymbolTableSection)), None)
    if symtab is None:
        return
    from elftools.elf.descriptions import describe_reloc_type

    # section index -> bytes a relocation rewrites
    masked: dict = {}
    for section in elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        holes = masked.setdefault(section["sh_info"], set())
        for reloc in section.iter_relocations():
            kind = describe_reloc_type(reloc["r_info_type"], elf)
            before, after = RELAXED.get(kind, (0, 0))
            width = 8 if kind in WIDTH_64 else 4
            holes.update(range(max(0, reloc["r_offset"] - before), reloc["r_offset"] + width + after))

    # (section, offset) -> names; a function's aliases share its bytes
    functions: dict = {}
    for symbol in symtab.iter_symbols():
        if (symbol["st_info"]["type"] == "STT_FUNC" and isinstance(symbol["st_shndx"], int)
                and symbol["st_size"] >= MIN_BYTES and symbol.name
                # a line's fields are cut at spaces: Go's `type:.eq.struct { ... }`
                and not any(c.isspace() for c in symbol.name)
                and (local or symbol["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK"))):
            functions.setdefault((symbol["st_shndx"], symbol["st_value"], symbol["st_size"]), []).append(symbol.name)

    for (index, start, size), names in sorted(functions.items()):
        section = elf.get_section(index)
        if not section["sh_flags"] & 0x4:       # SHF_EXECINSTR
            continue
        code = section.data()[start:start + size]
        if len(code) != size:
            continue
        holes = masked.get(index, set())
        if local:
            holes = holes | outbound_branches(code, start)
        text = ["%02X" % b if start + i not in holes else ".." for i, b in enumerate(code)]
        # A pattern that is wildcards but for a few bytes matches every stub
        # of its shape (`sub rsp,8; lea rdi,[rip+..]; call ..` is half of
        # glibc's error paths): what the linker left fixed has to name it
        if (sum(1 for t in text[:LEAD] if t != "..") < MIN_BYTES
                or sum(1 for t in text if t != "..") < MIN_FIXED):
            continue
        lead = "".join(text[:LEAD]).ljust(2 * LEAD, ".")
        # The CRC covers what follows the lead, up to the first rewritten byte
        covered = 0
        while LEAD + covered < size and covered < CRC_MAX and text[LEAD + covered] != "..":
            covered += 1
        crc = crc16(code[LEAD:LEAD + covered])
        tail = "".join(text[LEAD + covered:])
        names_text = " ".join(":0000 " + name for name in sorted(set(names)))
        yield "%s %02X %04X %04X %s%s" % (lead, covered, crc, size, names_text, " " + tail if tail else "")


def outbound_calls(obj: bytes) -> dict:
    """function name -> [[offset of a call's operand in it, [names of the
    function it calls]], ...] for Go's object, whose linker resolved the
    calls between its functions. What tells apart two functions with the
    same bytes but for whom they call -- `os.Getenv` and `os.Stat` are each
    a frame around one call (samplehooks.from_flirt)."""
    elf = ELFFile(io.BytesIO(obj))
    symtab = next((s for s in elf.iter_sections() if isinstance(s, SymbolTableSection)), None)
    if symtab is None:
        return {}
    starts: dict = {}
    for symbol in symtab.iter_symbols():
        if (symbol["st_info"]["type"] == "STT_FUNC" and isinstance(symbol["st_shndx"], int)
                and symbol["st_size"] >= MIN_BYTES and symbol.name
                and not any(c.isspace() for c in symbol.name)):
            starts.setdefault((symbol["st_shndx"], symbol["st_value"]), (symbol["st_size"], []))[1].append(symbol.name)
    found: dict = {}
    for (index, start), (size, names) in starts.items():
        code = elf.get_section(index).data()[start:start + size]
        calls = []
        for at in range(len(code) - 4):
            if code[at] == 0xE8:
                target = start + at + 5 + int.from_bytes(code[at + 1:at + 5], "little", signed=True)
                callee = starts.get((index, target))
                if callee and not start <= target < start + size:
                    calls.append([at + 1, sorted(callee[1])])
        if calls:
            for name in names:
                found[name] = calls
    return found


#: Functions nearly every static program has from its C library, whatever it
#: does: what a set is recognised in a sample by (identity_rule).
COMMON = (
    "__libc_start_main", "__uClibc_main", "__libc_start_call_main", "_start_c", "__libc_setup_tls",
    "__libc_csu_init", "_dl_relocate_static_pie", "__init_libc", "__libc_init_first", "_dl_aux_init",
    "exit", "_exit", "abort", "malloc", "free", "calloc", "realloc", "memcpy", "memset", "memmove",
    "memcmp", "strlen", "strcmp", "strncmp", "strcpy", "strchr", "strrchr", "write", "read", "open",
    "close", "mmap", "munmap", "brk", "sbrk", "sigaction", "raise", "getpid", "vfprintf", "printf",
    "fwrite", "fflush", "__stack_chk_fail", "__errno_location", "strtol", "atoi", "socket", "connect",
    "send", "recv", "select", "fork", "execve", "time", "nanosleep", "ioctl", "fcntl",
)
#: Fixed leading bytes a function needs to be one of a rule's strings, and
#: how many strings a rule has at most.
IDENTITY_BYTES = 24
IDENTITY_STRINGS = 40


def identity_rule(name: str, lines) -> str:
    """A YARA rule that says "this program was linked against this set's
    library": the leading bytes of the set's COMMON functions, three of them
    in one file. samplehooks scans a sample with every set's rule first and
    loads only the sets that match, so a hundred sets cost one scan and not
    a hundred signature matchers. Sets of neighbouring versions share
    functions byte for byte and then both match, and both are loaded.
    '' when the set has too few such functions to say anything."""
    strings = {}
    for line in lines:
        fields = line.split(" ")
        lead = fields[0]
        fixed = lead.split(".", 1)[0]
        fixed = fixed[:len(fixed) & ~1]
        names = [fields[i + 1] for i, f in enumerate(fields[:-1]) if f == ":0000"]
        wanted = [n for n in names if n.lstrip("_") in COMMON or n in COMMON]
        if wanted and len(fixed) >= 2 * IDENTITY_BYTES:
            strings.setdefault(fixed, wanted[0])
    if len(strings) < 6:
        return ""
    chosen = sorted(strings.items(), key=lambda kv: (COMMON.index(kv[1].lstrip("_")) if kv[1].lstrip("_") in COMMON
                                                     else COMMON.index(kv[1]), kv[0]))[:IDENTITY_STRINGS]
    identifier = "flirt_set_" + "".join(c if c.isalnum() else "_" for c in name)
    body = "\n".join("        $f%d = { %s }  // %s" % (i, " ".join(h[j:j + 2] for j in range(0, len(h), 2)), n)
                     for i, (h, n) in enumerate(chosen))
    return ('rule %s\n{\n    meta:\n        flirt_set = "%s"\n    strings:\n%s\n'
            '    condition:\n        3 of them\n}\n' % (identifier, name, body))


def write_set(name: str, libraries, out: Path, local: bool = False) -> int:
    """`<out>/<name>.pat.gz` and `<name>.yar` from the libraries; the number
    of functions, 0 (and nothing written) when there is none."""
    lines = set()
    for library in libraries:
        for member, body in members(library):
            if not body.startswith(b"\x7fELF"):
                continue
            try:
                lines.update(patterns(body, local))
            except Exception as exc:  # noqa: BLE001 - one object nobody can read is not the library
                print(f"{library}({member}): {type(exc).__name__}: {exc}", file=sys.stderr)
    if not lines:
        return 0
    out.mkdir(parents=True, exist_ok=True)
    ordered = sorted(lines)
    (out / f"{name}.pat.gz").write_bytes(gzip.compress(("\n".join(ordered) + "\n---\n").encode()))
    if local:
        calls: dict = {}
        for library in libraries:
            for _, body in members(library):
                if body.startswith(b"\x7fELF"):
                    calls.update(outbound_calls(body))
        (out / f"{name}.calls.json.gz").write_bytes(gzip.compress(json.dumps(calls, separators=(",", ":")).encode()))
    rule = identity_rule(name, ordered)
    if rule:
        (out / f"{name}.yar").write_text(rule)
    else:
        (out / f"{name}.yar").unlink(missing_ok=True)
    return len(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("\n\n", 1)[1])
    p.add_argument("libraries", nargs="+", type=Path, help="static libraries (.a) or object files")
    p.add_argument("--name", required=True, help="the set's name: the library, its version, the architecture")
    p.add_argument("--out", type=Path, default=Path(__file__).resolve().parent.parent / "sandboxd" / "data" / "flirt")
    args = p.parse_args(argv)

    count = write_set(args.name, args.libraries, args.out)
    if not count:
        print("no function in any of the libraries: nothing written", file=sys.stderr)
        return 1
    print(f"{args.out / (args.name + '.pat.gz')}: {count} functions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
