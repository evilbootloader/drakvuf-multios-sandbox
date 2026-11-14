"""Functions inside the sample's own image, located before it runs, as lines
of the tracer's hook list.

`python -m sandboxd.samplehooks SAMPLE --guest-path P --static LIST --out OUT`

**Why.** libmon and apimon hook what a process imports: an exported name of a
shared object or a DLL. A statically linked program imports nothing, so its
`connect` and `send` are code of its own at addresses nobody published, and a
trace of it is syscalls and no more (a Mirai build; libmon's README, "Statically
linked binaries are invisible"). The hook list's grammar already takes an
offset in place of an export --

    <module>,<label>,<hex offset>,log,<arguments>

-- so what is missing is the offsets. This finds them:

1. **the symbol table**, when the program still has one;
2. **FLIRT signatures** (python-flirt, the matcher capa ships): each function
   start the code itself points at (the target of a `call rel32`) is offered to
   the signature sets under `sandboxd/data/flirt/`, which name library
   functions by their first bytes whatever the program was stripped of;
3. **YARA code signatures** under `sandboxd/data/code-signatures/`: a rule
   with `meta: hook = "<name>"` names the function its match starts at.

Of what is found, a function the static hook list already has a line for is
hooked, with that line's arguments: the list is where argument types are
written down, and a breakpoint on every named function of a binary is a cost
nobody asked for. Everything found is reported (`--json`), hooked or not.

**What it does not find**, said in the report rather than left to be noticed:
a function no signature set knows (generic code a Rust or C++ compiler wrote
for this program alone; a C library no set was built from), and anything a
packer unpacks at run time.

**A child, as postprocessing is** (`postprocessing/child.py`): the sample is
hostile input to two parsers, and a memory limit here is a `MemoryError` in
this process and not the daemon's death. It never fails the job: no list, or
the static one alone, is every job before 2026-11-14.

The offset is the function's virtual address in the file's own terms: what
libmon adds a main executable's load bias to (0 for ET_EXEC), and for a PE
the RVA.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import resource
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

DATA = Path(__file__).resolve().parent / "data"
FLIRT_DIR = DATA / "flirt"
CODE_SIGNATURES_DIR = DATA / "code-signatures"
#: The Go functions worth a hook, and where their arguments are
GO_HOOKS = DATA / "go-hooks.txt"

#: Candidate function starts offered to FLIRT, and bytes of each: a set's
#: longest pattern is its 32 leading bytes, a CRC over at most 255 more, and
#: tail bytes after that.
MAX_CANDIDATES = 400_000
MATCH_BYTES = 0x8000
#: Symbols taken from a symbol table: a program with more is not helped by
#: a list of them.
MAX_SYMBOLS = 200_000
#: Lines added to the hook list for one sample.
MAX_HOOKS = 512


@dataclass(frozen=True)
class Located:
    name: str       # as the source spelled it
    offset: int     # virtual address (ELF) or RVA (PE)
    how: str        # "symtab", "flirt:<set>", "yara:<rule>"


@dataclass
class Image:
    """What of a program the locators read."""
    kind: str                                   # "elf" or "pe"
    bits: int
    #: What a hook's offset is counted from, in the file's own addresses: the
    #: PE ImageBase; for ELF the page of the program headers, which is the one
    #: address of a running executable the tracer has without reading it (the
    #: aux vector's AT_PHDR). None: the headers are in no loaded segment, the
    #: kernel passes no AT_PHDR and nothing can be placed.
    base: Optional[int] = 0
    entry: int = 0
    #: (virtual address, file offset, bytes) of each executable range
    code: list = field(default_factory=list)
    symbols: dict = field(default_factory=dict)  # name -> virtual address
    stripped: bool = True
    static: bool = False
    toolchain: str = ""
    compiler: str = ""                          # what the compiler wrote of itself
    sets: list = field(default_factory=list)    # signature sets tried
    go_version: str = ""                        # "go1.21.3", when the program says
    go_table: str = ""                          # its function table's layout: "1.2", "1.16", "1.18", "1.20"


# --- reading the program -----------------------------------------------------

#: What a toolchain leaves in its programs, stripped or not: which language
#: wrote the code decides what a signature set can be expected to know.
_TOOLCHAINS = (
    ("go", re.compile(rb"\xff Go build ID: |\x00go\.buildinfo\x00|runtime\.gopanic")),
    ("rust", re.compile(rb"/rustc/[0-9a-f]{40}/|rust_begin_unwind|rust_panic")),
    ("nim", re.compile(rb"\x00NimMain\x00|@[a-z]+\.nim\.c\x00|nimGC_")),
    ("zig", re.compile(rb"zig_panic|\x00std\.builtin\.|__zig_")),
)


def toolchain(data: bytes) -> str:
    for name, pattern in _TOOLCHAINS:
        if pattern.search(data):
            return name
    return ""


def read_elf(path: Path, data: bytes) -> Optional[Image]:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    with path.open("rb") as f:
        elf = ELFFile(f)
        if elf["e_machine"] not in ("EM_X86_64", "EM_386"):
            return None     # FLIRT's call scan below is x86's
        image = Image("elf", 64 if elf.elfclass == 64 else 32, entry=elf["e_entry"])
        dynamic = False
        image.base = None
        phoff = elf["e_phoff"]
        for segment in elf.iter_segments():
            kind = segment["p_type"]
            # As load_elf_binary() works AT_PHDR out
            if (kind == "PT_LOAD" and image.base is None
                    and segment["p_offset"] <= phoff < segment["p_offset"] + segment["p_filesz"]):
                image.base = (segment["p_vaddr"] + phoff - segment["p_offset"]) & ~0xFFF
            if kind in ("PT_INTERP", "PT_DYNAMIC"):
                dynamic = True
            if kind == "PT_LOAD" and segment["p_flags"] & 1 and segment["p_filesz"]:
                start, size = segment["p_offset"], segment["p_filesz"]
                image.code.append((segment["p_vaddr"], start, data[start:start + size]))
        image.static = not dynamic
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection) and section.name == ".symtab":
                image.stripped = False
                for n, symbol in enumerate(section.iter_symbols()):
                    if n >= MAX_SYMBOLS:
                        break
                    if (symbol["st_info"]["type"] == "STT_FUNC" and symbol["st_value"]
                            and symbol["st_shndx"] != "SHN_UNDEF" and symbol.name):
                        image.symbols.setdefault(symbol.name, symbol["st_value"])
    return image


def read_pe(path: Path, data: bytes) -> Optional[Image]:
    import pefile

    pe = pefile.PE(data=data, fast_load=True)
    try:
        if pe.FILE_HEADER.Machine not in (0x14C, 0x8664):
            return None
        base = pe.OPTIONAL_HEADER.ImageBase
        # Addresses as the file has them in its own code and tables: from
        # ImageBase, which the hook lines take off again
        image = Image("pe", 64 if pe.FILE_HEADER.Machine == 0x8664 else 32, base=base,
                      entry=base + pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        for section in pe.sections:
            if section.Characteristics & 0x20000000 and section.SizeOfRawData:     # MEM_EXECUTE
                start = section.PointerToRawData
                image.code.append((base + section.VirtualAddress, start, data[start:start + section.SizeOfRawData]))
        # A PE's own symbols are its imports, which apimon hooks where they
        # live. What is linked into it has no name left.
        image.static = True
    finally:
        pe.close()
    return image


def read_image(path: Path) -> Optional[Image]:
    data = path.read_bytes()
    if data[:4] == b"\x7fELF":
        image = read_elf(path, data)
    elif data[:2] == b"MZ":
        image = read_pe(path, data)
    else:
        return None
    if image is not None:
        image.toolchain = toolchain(data)
        # `GCC: (Buildroot 2021.11) 10.3.0`, `clang version 15.0.7`: the
        # .comment section, which strip leaves in
        said = re.search(rb"(GCC: \([^)\x00]{0,80}\) [0-9][0-9.]{2,12}|clang version [0-9][0-9.]{2,12})", data)
        image.compiler = said.group(1).decode("ascii", "replace") if said else ""
    return image


# --- the locators ------------------------------------------------------------

def from_symbols(image: Image) -> list:
    return [Located(name, address, "symtab") for name, address in image.symbols.items()]


# Go keeps a table of every function for its own stack traces and garbage
# collector, and `strip` cannot take it: the runtime reads it. Name and
# address of everything in the program, its own code included.
#
#   magic        Go          functions are              names are at
#   0xFFFFFFFB   1.2-1.15    (pc, offset) words         table + nameoff
#   0xFFFFFFFA   1.16-1.17   (pc, offset) words         table + funcnametab + nameoff
#   0xFFFFFFF0   1.18-1.19   (pc - text, offset) u32    the same
#   0xFFFFFFF1   1.20-       the same                   the same
#
# Before Go 1.2 (2013) the table was another format; such a program is left
# to the signatures.
_GO_TABLES = {b"\xfb\xff\xff\xff": "1.2", b"\xfa\xff\xff\xff": "1.16",
              b"\xf0\xff\xff\xff": "1.18", b"\xf1\xff\xff\xff": "1.20"}
_GO_VERSION = re.compile(rb"go1\.\d{1,3}(?:\.\d{1,3}|rc\d{1,2}|beta\d{1,2})?")
MAX_GO_FUNCTIONS = 2_000_000


def go_version(data: bytes) -> str:
    """What the toolchain called itself. Go 1.18 on writes it in the build
    information; before that it is a string among the others, and the one
    said most often is taken."""
    at = data.find(b"\xff Go buildinf:")
    if at != -1 and len(data) > at + 34 and data[at + 15] & 2:
        size = data[at + 32]
        said = data[at + 33:at + 33 + size]
        if size < 0x80 and _GO_VERSION.fullmatch(said):
            return said.decode()
    count: dict = {}
    for said in _GO_VERSION.findall(data):
        count[said] = count.get(said, 0) + 1
    return max(count, key=count.get).decode() if count else ""


def _go_functions(data: bytes, at: int, layout: str, spans: list) -> Optional[dict]:
    """address -> name from the table at `at`, None for bytes that only look
    like one."""
    if data[at + 4:at + 6] != b"\0\0" or data[at + 6] not in (1, 2, 4) or data[at + 7] not in (4, 8):
        return None
    size = data[at + 7]
    word = "<Q" if size == 8 else "<I"

    def header(n: int) -> int:
        return struct.unpack_from(word, data, at + 8 + n * size)[0]

    def name_at(start: int) -> str:
        end = data.find(b"\0", start, start + 512)
        return data[start:end].decode("utf-8", "replace") if end > start else ""

    count = header(0)
    if not 0 < count <= MAX_GO_FUNCTIONS:
        return None
    text = 0
    if layout == "1.2":
        table, names = at + 8 + size, at
        records = at
    elif layout == "1.16":
        names, table = at + header(2), at + header(6)
        records = table
    else:
        # runtime.text, which a position-independent program may have left
        # to a relocation: the code's start then
        text, names, table = header(2), at + header(3), at + header(7)
        if not any(a <= text < b for a, b in spans):
            text = min((a for a, _ in spans), default=0)
        records = table
    found: dict = {}
    inside = 0
    for i in range(count):
        if layout in ("1.2", "1.16"):
            entry, offset = struct.unpack_from(word[0] + word[1] * 2, data, table + 2 * size * i)
            name_offset = struct.unpack_from("<i", data, records + offset + size)[0]
        else:
            entry, offset = struct.unpack_from("<II", data, table + 8 * i)
            entry += text
            name_offset = struct.unpack_from("<i", data, records + offset + 4)[0]
        name = name_at(names + name_offset) if name_offset >= 0 else ""
        if name and any(a <= entry < b for a, b in spans):
            inside += 1
            found.setdefault(entry, name)
        # a table is believed when its first functions are code with names
        if i == 63 and inside < 48:
            return None
    return found if inside >= min(count, 64) * 3 // 4 else None


def from_gopclntab(image: Image, data: bytes) -> list:
    spans = [(va, va + len(code)) for va, _, code in image.code]
    for magic, layout in _GO_TABLES.items():
        at = data.find(magic)
        while at != -1:
            try:
                found = _go_functions(data, at, layout, spans)
            except (struct.error, IndexError):
                found = None
            if found:
                image.go_table = layout
                image.go_version = go_version(data)
                return [Located(name, address, "gopclntab") for address, name in sorted(found.items())]
            at = data.find(magic, at + 1)
    return []


def go_abi(image: Image) -> str:
    """The hook-list marker for where this program's Go functions take their
    arguments: "goabi" (registers), "goabi0" (the stack), "" when the program
    does not say which. Registers came with Go 1.17, on amd64 only."""
    if image.bits == 32 or image.go_table == "1.2":
        return "goabi0"
    if image.go_table in ("1.18", "1.20"):
        return "goabi"
    said = re.match(r"go1\.(\d+)", image.go_version)      # the 1.16 table: Go 1.16 or 1.17
    if not said:
        return ""
    return "goabi" if int(said.group(1)) >= 17 else "goabi0"


def call_targets(image: Image) -> list:
    """Addresses the code calls: where functions start, for a program with no
    table of them. Every `call rel32` and `jmp rel32` whose target lies in
    executable code, and the entry point. A byte E8 that is no call gives a
    target that is no function, which no signature then matches."""
    spans = [(va, va + len(code)) for va, _, code in image.code]
    found = set()
    if any(a <= image.entry < b for a, b in spans):
        found.add(image.entry)
    mask = (1 << image.bits) - 1
    for va, _, code in image.code:
        # call rel32, and jmp rel32: a tail call is how a wrapper reaches the
        # function that does the work
        for opcode in (b"\xe8", b"\xe9"):
            at = code.find(opcode)
            while at != -1 and at + 5 <= len(code):
                target = (va + at + 5 + struct.unpack_from("<i", code, at + 1)[0]) & mask
                if any(a <= target < b for a, b in spans):
                    found.add(target)
                    if len(found) >= MAX_CANDIDATES:
                        return sorted(found)
                at = code.find(opcode, at + 1)
    return sorted(found)


#: Sets loaded for one sample at most, of those whose rule recognised it.
MAX_SETS = 6


def recognised_sets(directory: Path, data: bytes) -> Optional[dict]:
    """set name -> how many of its rule's strings are in the sample, for the
    sets that have a rule (`<set>.yar`, scripts/gen-flirt-pats.py) and match.
    None when no set has a rule: then every set is loaded, as before there
    were a hundred of them."""
    rules = sorted(directory.rglob("*.yar")) if directory.is_dir() else []
    if not rules:
        return None
    import yara_x

    compiler = yara_x.Compiler()
    for rule in rules:
        try:
            compiler.add_source(rule.read_text(), origin=str(rule))
        except Exception as exc:  # noqa: BLE001 - one bad rule is not the others'
            print(f"samplehooks: {rule}: {exc}", file=sys.stderr)
    found = {}
    for rule in yara_x.Scanner(compiler.build()).scan(data).matching_rules:
        name = dict(rule.metadata).get("flirt_set")
        if isinstance(name, str):
            found[name] = sum(1 for pattern in rule.patterns if pattern.matches)
    return found


def load_signatures(directory: Path, data: Optional[bytes] = None) -> list:
    """[(set name, matcher)] of the `.sig` and `.pat` sets under `directory`
    (gzipped or not) worth trying on a sample: a set with a rule beside it
    only if the rule recognised the sample -- the MAX_SETS that matched most
    of their strings, a library's neighbouring versions sharing many -- and a
    set with no rule always. A set that does not parse is skipped and said."""
    import flirt

    recognised = recognised_sets(directory, data) if data is not None else None
    best = set(sorted(recognised, key=lambda n: (-recognised[n], n))[:MAX_SETS]) if recognised else set()
    sets = []
    for path in sorted(directory.rglob("*")) if directory.is_dir() else ():
        name = path.name
        plain = name[:-3] if name.endswith(".gz") else name
        if not path.is_file() or not plain.endswith((".sig", ".pat")):
            continue
        stem = plain.rsplit(".", 1)[0]
        if recognised is not None and path.with_name(stem + ".yar").is_file() and stem not in best:
            continue
        try:
            raw = gzip.decompress(path.read_bytes()) if name.endswith(".gz") else path.read_bytes()
            parsed = flirt.parse_sig(raw) if plain.endswith(".sig") else flirt.parse_pat(raw.decode("utf-8", "replace"))
            sets.append((plain.rsplit(".", 1)[0], flirt.compile(parsed)))
        except Exception as exc:  # noqa: BLE001 - one bad set is not the others'
            print(f"samplehooks: {path}: not a signature set ({exc})", file=sys.stderr)
    return sets


def from_flirt(image: Image, sets: list, candidates: Optional[Iterable[int]] = None) -> list:
    if not sets:
        return []
    found = []
    for target in call_targets(image) if candidates is None else candidates:
        for va, _, code in image.code:
            if va <= target < va + len(code):
                window = code[target - va:target - va + MATCH_BYTES]
                break
        else:
            continue
        for set_name, matcher in sets:
            # One signature's names are aliases of one function. Two
            # signatures matching the same bytes are two functions nothing
            # here tells apart: naming it either way is a guess, so neither.
            matched = [sorted({name for name, kind, offset in signature.names
                               if offset == 0 and kind in ("public", "local")})
                       for signature in matcher.match(window)]
            matched = [names for names in matched if names]
            if len({tuple(sorted({plain_name(n) for n in names})) for names in matched}) == 1:
                found += [Located(name, target, f"flirt:{set_name}") for name in matched[0]]
                break
            if matched:
                break       # ambiguous in this set: another set does not settle it
    return found


def from_yara(image: Image, path: Path, directory: Path) -> list:
    """Functions named by a code signature: a rule with `meta: hook = "name"`
    names the function at the address its first string matched."""
    rules = sorted(directory.rglob("*.yar")) + sorted(directory.rglob("*.yara")) if directory.is_dir() else []
    if not rules:
        return []
    import yara_x

    compiler = yara_x.Compiler()
    for rule in rules:
        try:
            compiler.add_source(rule.read_text(), origin=str(rule))
        except Exception as exc:  # noqa: BLE001 - one bad rule file is not the others'
            print(f"samplehooks: {rule}: {exc}", file=sys.stderr)
    found = []
    for rule in yara_x.Scanner(compiler.build()).scan(path.read_bytes()).matching_rules:
        hook = dict(rule.metadata).get("hook")
        offsets = sorted(m.offset for pattern in rule.patterns for m in pattern.matches)
        if not isinstance(hook, str) or not offsets:
            continue
        for va, start, code in image.code:
            if start <= offsets[0] < start + len(code):
                found.append(Located(hook, va + offsets[0] - start, f"yara:{rule.identifier}"))
    return found


def locate(path: Path, flirt_dir: Path = FLIRT_DIR,
           yara_dir: Path = CODE_SIGNATURES_DIR) -> tuple:
    """(image, located) of a program; (None, []) for what is not one."""
    image = read_image(path)
    if image is None:
        return None, []
    located = from_symbols(image)
    data = path.read_bytes()
    if image.toolchain == "go":
        # First of an address: the table has every function, the symbol
        # table, when there is one, the same names
        seen = {found.offset for found in located}
        located += [f for f in from_gopclntab(image, data) if f.offset not in seen]
    known = {found.offset for found in located}
    sets = load_signatures(flirt_dir, data)
    image.sets = [name for name, _ in sets]
    located += [f for f in from_flirt(image, sets) if f.offset not in known]
    located += from_yara(image, path, yara_dir)
    return image, located


# --- the hook list -----------------------------------------------------------

#: A library's name for a function and the name the hook list has it under:
#: glibc's `__libc_connect`, `__GI_memcpy`, `__send`, a compiler's leading
#: underscore, a symbol version.
_DECORATION = re.compile(r"^(?:__GI_|__libc_|__|_)+")


def plain_name(name: str) -> str:
    return _DECORATION.sub("", name.split("@", 1)[0])


def static_hooks(text: str) -> dict:
    """function name -> the rest of its line from the action on
    (`log,Fd:int,...`), for every by-name line of a hook list. The first line
    of a name is the one kept, as the tracer's own loader keeps every one."""
    known: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(",")
        i = 2
        while i < len(fields) and fields[i] not in ("log", "log+stack"):
            if fields[i] == "clsid":
                i += 2
            elif fields[i] == "no-retval":
                i += 1
            else:
                i = len(fields)     # an offset: a line by address names no function
        if i < len(fields):
            known.setdefault(fields[1], ",".join(fields[2:]))
    return known


#: A module pattern the grammar and both loaders can carry: fields are cut at
#: commas, and a line is a line.
_MODULE_OK = re.compile(r"^[^,\r\n#]+$")


def go_hooks(text: str) -> dict:
    """Go function -> the rest of its line (`goabi,log,Network:...`) from the
    list of Go functions, whose lines are a hook list's with `go` for a module."""
    known: dict = {}
    for line in text.splitlines():
        fields = line.strip().split(",")
        if len(fields) >= 4 and fields[0] == "go" and fields[2] in ("goabi", "goabi0"):
            known.setdefault(fields[1], ",".join(fields[2:]))
    return known


def sample_lines(located: list, known: dict, module: str, base: Optional[int] = 0,
                 go: Optional[dict] = None, abi: str = "") -> list:
    """The hook-list lines for what was located and the list knows, one per
    address. [] for a module name the list cannot spell, and for an image
    with no base to count from. A Go function's line says where its arguments
    are (`abi`, per go_abi()); with no saying, the call is logged bare."""
    if base is None or not _MODULE_OK.match(module) or module != module.strip():
        return []
    lines, seen = [], set()
    for found in sorted(located, key=lambda f: (f.offset, f.name)):
        offset = found.offset - base
        if offset in seen or offset <= 0:
            continue
        if found.how == "gopclntab":
            if not go or found.name not in go:
                continue
            marker, rest = go[found.name].split(",", 1)
            # a function written in assembly is on the stack in every version
            marker = marker if marker == "goabi0" else abi
            seen.add(offset)
            lines.append(f"{module},{found.name},{offset:x},{marker},{rest}" if marker
                         else f"{module},{found.name},{offset:x},no-retval,log")
            if len(lines) >= MAX_HOOKS:
                break
            continue
        name = found.name if found.name in known else plain_name(found.name)
        if name not in known:
            continue
        seen.add(offset)
        lines.append(f"{module},{name},{offset:x},{known[name]}")
        if len(lines) >= MAX_HOOKS:
            break
    return lines


def module_name(image: Image, guest_path: str) -> str:
    """How the tracer knows the sample's image. Windows names a mapped file
    from the root of its volume, with no drive, and libusermode compares the
    end of that from a `\\` on; Linux has the path as it is."""
    if image.kind == "pe":
        # `C:\\x`, and the kernel's names for the same file, as fileextractor
        # has them: `\\Device\\HarddiskVolume2\\x`, `\\??\\C:\\x`
        return re.sub(r"^(?:\\\?\?\\)?(?:[A-Za-z]:|\\Device\\HarddiskVolume\d+)?\\+", "", guest_path)
    return guest_path


def append_list(lines: list, out: Path, what: str) -> list:
    """Add lines the list does not have to its end; the ones added. The list
    is replaced by rename and only ever grows after what it held: DRAKVUF
    reads what was added from where it had read to (hook_list_tail)."""
    text = out.read_text()
    have = set(text.splitlines())
    new = [line for line in lines if line not in have]
    if new:
        text = text if text.endswith("\n") else text + "\n"
        text += f"\n# {what}\n" + "\n".join(new) + "\n"
        tmp = out.with_name(out.name + ".tmp")
        tmp.write_text(text)
        os.replace(tmp, out)
    return new


def write_list(static_text: str, lines: list, out: Path) -> None:
    """The static list with the sample's lines after it, written beside `out`
    and renamed over it: the tracer reads either the list before or this one."""
    text = static_text if static_text.endswith("\n") else static_text + "\n"
    if lines:
        text += "\n# The sample's own functions, located before the run (sandboxd/samplehooks.py)\n"
        text += "\n".join(lines) + "\n"
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, out)


def report(image: Optional[Image], located: list, lines: list) -> dict:
    """What the job's report says of it (`static.located`)."""
    if image is None:
        return {"analysed": False}
    hooked = {int(line.split(",")[2], 16) + (image.base or 0) for line in lines}
    by_how: dict = {}
    for found in located:
        by_how[found.how.split(":", 1)[0]] = by_how.get(found.how.split(":", 1)[0], 0) + 1
    return {
        "analysed": True, "format": image.kind, "bits": image.bits, "static": image.static,
        "stripped": image.stripped, "toolchain": image.toolchain or None,
        "compiler": image.compiler or None, "signature_sets": image.sets,
        "go": {"version": image.go_version or None, "table": image.go_table,
               "arguments": go_abi(image) or None} if image.go_table else None,
        "found": by_how, "hooked": len(lines),
        "functions": [{"name": f.name, "address": f.offset, "how": f.how, "hooked": f.offset in hooked}
                      for f in sorted(located, key=lambda f: f.offset)[:MAX_SYMBOLS]],
    }


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m sandboxd.samplehooks")
    p.add_argument("sample", type=Path)
    p.add_argument("--guest-path", required=True, help="the sample's path in the guest: the list's module")
    p.add_argument("--static", type=Path, required=True, help="the hook list every job gets")
    p.add_argument("--out", type=Path, help="the list for this job")
    p.add_argument("--append-to", type=Path,
                   help="a job's list that is in use: add this program's lines to its end "
                        "(what the sample dropped, sandboxd/stagehooks.py)")
    p.add_argument("--json", type=Path, help="what was found, for the report")
    p.add_argument("--flirt", type=Path, default=FLIRT_DIR)
    p.add_argument("--code-signatures", type=Path, default=CODE_SIGNATURES_DIR)
    p.add_argument("--go-hooks", type=Path, default=GO_HOOKS)
    p.add_argument("--also", type=Path, action="append", default=[],
                   help="a list made for this deployment, added to the job's when it exists "
                        "(profiles/hooks-dotnet.txt, from scripts/dotnet-index.py)")
    p.add_argument("--max-mib", type=int, default=1024, help="RLIMIT_DATA in MiB; 0 sets no limit")
    args = p.parse_args(argv)
    if args.max_mib > 0:
        limit = args.max_mib << 20
        resource.setrlimit(resource.RLIMIT_DATA, (limit, limit))

    static_text = args.static.read_text()
    for also in args.also:
        if also.is_file():
            static_text = static_text.rstrip("\n") + f"\n\n# {also.name}\n" + also.read_text()
    image, located, lines = None, [], []
    try:
        image, located = locate(args.sample, args.flirt, args.code_signatures)
        if image is not None:
            go = go_hooks(args.go_hooks.read_text()) if image.go_table and args.go_hooks.is_file() else {}
            lines = sample_lines(located, static_hooks(static_text),
                                 module_name(image, args.guest_path), image.base, go, go_abi(image))
    except Exception as exc:  # noqa: BLE001 - a program no parser reads gets the static list
        print(f"samplehooks: {args.sample.name}: {type(exc).__name__}: {exc}", file=sys.stderr)
        image, located, lines = None, [], []
    if args.append_to:
        # no `#` or line end reaches the comment: a name with either got no lines
        lines = append_list(lines, args.append_to, f"Dropped during the run: {args.guest_path}") if lines else []
    elif args.out:
        write_list(static_text, lines, args.out)
    else:
        p.error("one of --out and --append-to")
    if args.json:
        args.json.write_text(json.dumps(report(image, located, lines)))
    print(f"samplehooks: {len(located)} functions located, {len(lines)} hooked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
