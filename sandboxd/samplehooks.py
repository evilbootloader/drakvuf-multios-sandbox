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

A Go program is read through its own function table, and when that names
nothing -- garble hashes every name in it -- through the signature sets of
Go's standard library, one per release, the one that names most (go_sets).

Of what is found, a function the static hook list already has a line for is
hooked, with that line's arguments: the list is where argument types are
written down, and a breakpoint on every named function of a binary is a cost
nobody asked for. Everything found is reported (`--json`), hooked or not.

**What it does not find**, said in the report rather than left to be noticed:
a function no signature set knows (generic code a Rust or C++ compiler wrote
for this program alone; a C library no set was built from), and anything a
packer unpacks at run time -- which a job that asks for a second pass gets
from its first run's memory (sandboxd/stagehints.py, `--hints`).

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
import shutil
import subprocess
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
#: Entry-only Rust-native hook templates (demangled function paths).
RUST_HOOKS = DATA / "rust_hooks.txt"

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
    rust: dict = field(default_factory=dict)    # {"commit", "version"}, what a Rust program says
    go_version: str = ""                        # "go1.21.3", when the program says
    go_table: str = ""                          # its function table's layout: "1.2", "1.16", "1.18", "1.20"
    go_set: str = ""                            # the Go signature set that named its functions (go_sets)
    #: Of a running image (sandboxd/stagehints.py): how far it is from where
    #: it was linked, and the RVAs of the bytes its loader rewrote for that
    moved: int = 0
    relocated: set = field(default_factory=set)
    #: How far from `base` a running PE image reaches (its SizeOfImage)
    extent: int = 0


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
        if image.toolchain == "rust":
            # The compiler's commit, in every panic path; its release, in
            # .comment when that was left in. Either names the signature set
            # (scripts/fetch-flirt-sets.py --rust <version>).
            commit = re.search(rb"/rustc/([0-9a-f]{40})/", data)
            version = re.search(rb"rustc version (\d+\.\d+\.\d+)", data)
            image.rust = {"commit": commit.group(1).decode() if commit else None,
                          "version": version.group(1).decode() if version else None}
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
MAX_SETS = 10


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
            # A set recognised by something exact (a Rust set, by its
            # compiler's commit) is not ranked below libc's forty strings
            if dict(rule.metadata).get("flirt_exact") is True:
                found[name] += 1000
    return found


#: The sets of Go's standard library (scripts/fetch-flirt-sets.py --go), by
#: name: tried on Go programs only (go_sets), never with the others
GO_SET = re.compile(r"^go-(\d+\.\d+(?:\.\d+)?)-(?:(linux|windows)-)?(amd64|386)$")
#: Rust's standard library uses different ELF and Windows COFF objects for
#: every target, although all targets built by one compiler share its commit.
RUST_SET = re.compile(r"^rust-\d+\.\d+\.\d+-(x86_64|i686)-(unknown-linux-(?:gnu|musl)|pc-windows-(?:msvc|gnu|gnullvm))$")


def signature_target(name: str, image: Optional[Image]) -> bool:
    """Don't apply Go or Rust patterns to another OS/architecture.

    The old `go-X.Y.Z-amd64` sets were built on Linux, before the target
    was recorded in the name. Other libraries keep their current rules.
    """
    if image is None:
        return True
    os_name = "windows" if image.kind == "pe" else "linux" if image.kind == "elf" else ""
    arch_name = ("amd64" if image.bits == 64 else "386")
    go = GO_SET.fullmatch(name)
    if go:
        return (go.group(2) or "linux") == os_name and go.group(3) == arch_name
    rust = RUST_SET.fullmatch(name)
    if rust:
        rust_os = "windows" if rust.group(2).startswith("pc-windows-") else "linux"
        return rust_os == os_name and rust.group(1) == ("x86_64" if image.bits == 64 else "i686")
    return True


def load_signatures(directory: Path, data: Optional[bytes] = None, go: bool = False,
                    image: Optional[Image] = None) -> list:
    """[(set name, matcher)] of the `.sig` and `.pat` sets under `directory`
    (gzipped or not) worth trying on a sample: a set with a rule beside it
    only if the rule recognised the sample -- the MAX_SETS that matched most
    of their strings, a library's neighbouring versions sharing many -- and a
    set with no rule always. A set that does not parse is skipped and said.
    `go`: Go's sets instead, every one of them."""
    import flirt

    recognised = recognised_sets(directory, data) if data is not None and not go else None
    # Select among compatible targets BEFORE the MAX_SETS cap. Rust sets
    # for different platforms share the same compiler-commit YARA rule.
    best = (set(sorted((n for n in recognised if signature_target(n, image)),
                       key=lambda n: (-recognised[n], n))[:MAX_SETS]) if recognised else set())
    sets = []
    for path in sorted(directory.rglob("*")) if directory.is_dir() else ():
        name = path.name
        plain = name[:-3] if name.endswith(".gz") else name
        if not path.is_file() or not plain.endswith((".sig", ".pat")):
            continue
        stem = plain.rsplit(".", 1)[0]
        if bool(GO_SET.fullmatch(stem)) != go or not signature_target(stem, image):
            continue
        if recognised is not None and path.with_name(stem + ".yar").is_file() and stem not in best:
            continue
        try:
            raw = gzip.decompress(path.read_bytes()) if name.endswith(".gz") else path.read_bytes()
            parsed = flirt.parse_sig(raw) if plain.endswith(".sig") else flirt.parse_pat(raw.decode("utf-8", "replace"))
            sets.append((plain.rsplit(".", 1)[0], flirt.compile(parsed)))
        except Exception as exc:  # noqa: BLE001 - one bad set is not the others'
            print(f"samplehooks: {path}: not a signature set ({exc})", file=sys.stderr)
    return sets


def from_flirt(image: Image, sets: list, candidates: Optional[Iterable[int]] = None,
               calls: Optional[dict] = None) -> list:
    """Functions named by the signature sets, at the candidate starts.

    `calls` (a Go set's, name -> where it calls whom): two functions whose
    bytes are the same but for whom they call are told apart by whom the
    sample's function calls, once that callee is named itself -- a few
    rounds, as each settles others."""
    if not sets:
        return []
    found = []
    named: dict = {}            # address -> names, of what one signature named
    undecided = []              # (address, its bytes, set name, [names of each signature])
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
                named[target] = set(matched[0])
                break
            if matched:
                if calls:
                    undecided.append((target, window, set_name, matched))
                break       # ambiguous in this set: another set does not settle it

    def verdict(target: int, window: bytes, names) -> tuple:
        """(calls landing on the callee the set says, calls landing on
        another named function or not being calls at all, calls looked at)
        of the function at `target` under `names`. A callee nothing named
        yet says neither; nor does the stack-growth call every Go function
        makes, which is hand-written and seldom named."""
        said = next((calls[n] for n in names if n in calls), None)
        agreed = against = looked = 0
        for operand, callees in said or ():
            if any(c.startswith("runtime.morestack") for c in callees):
                continue
            looked += 1
            if operand < 1 or operand + 4 > len(window) or window[operand - 1] != 0xE8:
                against += 1
                continue
            callee = target + operand + 4 + int.from_bytes(window[operand:operand + 4], "little", signed=True)
            if callee in named:
                if named[callee] & set(callees):
                    agreed += 1
                else:
                    against += 1
        return agreed, against, looked

    def calls_check(target: int, window: bytes, names: list) -> bool:
        agreed, against, _ = verdict(target, window, names)
        return agreed > 0 and not against

    for _ in range(4):
        settled = []
        for item in undecided:
            target, window, set_name, matched = item
            fits = [names for names in matched if calls_check(target, window, names)]
            if len(fits) == 1:
                found += [Located(name, target, f"flirt:{set_name}") for name in fits[0]]
                named[target] = set(fits[0])
                settled.append(item)
        if not settled:
            break
        undecided = [item for item in undecided if item not in settled]
    return _backed_by_calls(image, found, named, verdict) if calls else found


def _window(image: Image, target: int) -> bytes:
    for va, _, code in image.code:
        if va <= target < va + len(code):
            return code[target - va:target - va + MATCH_BYTES]
    return b""


def _backed_by_calls(image: Image, found: list, named: dict, verdict) -> list:
    """Of what a Go set named by bytes, what whom it calls bears out.

    A function that calls nothing keeps the name its bytes gave it. One
    that does keeps it only if at least one of its calls lands on the
    function the set says, named in the sample, and none on another: its
    own bytes are mostly a shape, and a wrapper's shape -- "pass the string
    to a method of a global" -- is other functions' too (job b2c2771a,
    2026-11-15: `net/http.Get` was named at a function called 300 times
    with method names, and `os.Rename` at one calling another than
    `os.rename`). A name the evidence does not reach is left off: a wrong
    one is a wrong record on every call, a missing one a call seen below."""
    verdicts = {target: verdict(target, _window(image, target), names) for target, names in named.items()}
    kept = []
    for f in found:
        agreed, against, looked = verdicts.get(f.offset, (0, 0, 0))
        if against or (looked and not agreed):
            continue
        kept.append(f)
    return kept


#: Function starts each Go set is tried on to choose between them, and the
#: names the best must give to be taken at all
GO_TRIAL = 20_000
GO_MIN_NAMED = 10


def go_starts(image: Image) -> list:
    """Where Go's functions start that nothing calls directly -- methods
    reached through an interface, functions passed as values: Go's linker
    starts every function on 32 bytes and fills the gap before it with
    INT3, so an aligned address after a 0xCC is one."""
    found = []
    for va, _, code in image.code:
        first = (-va) % 32
        for at in range(first or 32, len(code), 32):
            if code[at - 1] == 0xCC and code[at] != 0xCC:
                found.append(va + at)
                if len(found) >= MAX_CANDIDATES:
                    return found
    return found


def go_sets(image: Image, directory: Path) -> list:
    """The functions of a Go program whose table names nothing it lists --
    garble's: its names are hashes and its table's magic random -- named by
    their bytes with the set of the Go release that built it. Which release
    the program does not say, so each set is tried on a spread of its
    function starts and the one that names most is used, alone: two
    releases' names mixed would be two guesses. Sets the program is not
    built with name little, because a function's bytes change from one
    release to the next."""
    sets = load_signatures(directory, go=True, image=image)
    if not sets:
        return []
    candidates = sorted(set(call_targets(image)) | set(go_starts(image)))
    trial = candidates[::max(1, len(candidates) // GO_TRIAL)]
    scored = sorted(((len(from_flirt(image, [one], trial)), one[0], one) for one in sets),
                    key=lambda s: (-s[0], s[1]))
    named, name, best = scored[0]
    image.sets = [n for _, n, _ in scored]
    if named < GO_MIN_NAMED * len(trial) // max(1, GO_TRIAL):
        return []
    image.go_set = name
    image.go_version = "go" + GO_SET.match(name).group(1)
    return from_flirt(image, [best], candidates, go_calls(directory, name))


def go_calls(directory: Path, name: str) -> dict:
    """A Go set's record of whom each of its functions calls
    (`<set>.calls.json.gz`, gen-flirt-pats.outbound_calls); {} without."""
    for path in directory.rglob(f"{name}.calls.json.gz") if directory.is_dir() else ():
        try:
            return json.loads(gzip.decompress(path.read_bytes()))
        except (OSError, ValueError, EOFError) as exc:
            print(f"samplehooks: {path}: {exc}", file=sys.stderr)
    return {}


def from_yara(image: Image, data: bytes, directory: Path) -> list:
    """Functions named by a code signature: a rule with `meta: hook = "name"`
    names the function at the address its first string matched. `data` is
    what `image.code`'s offsets count in."""
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
    for rule in yara_x.Scanner(compiler.build()).scan(data).matching_rules:
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
    return image, locate_in(image, path.read_bytes(), flirt_dir, yara_dir)


def locate_in(image: Image, data: bytes, flirt_dir: Path = FLIRT_DIR,
              yara_dir: Path = CODE_SIGNATURES_DIR) -> list:
    """What every locator finds in an image that is read already: a file's,
    or a running program's memory (sandboxd/stagehints.py). `data` is the
    bytes `image.code`'s offsets count in."""
    located = from_symbols(image)
    go_tried: list = []
    if image.toolchain == "go":
        # First of an address: the table has every function, the symbol
        # table, when there is one, the same names
        seen = {found.offset for found in located}
        located += [f for f in from_gopclntab(image, data) if f.offset not in seen]
        if not image.go_table:
            # No table read: garble's, or one torn by a packer
            located += [f for f in go_sets(image, flirt_dir) if f.offset not in seen]
            go_tried = image.sets
    known = {found.offset for found in located}
    sets = load_signatures(flirt_dir, data, image=image)
    image.sets = [name for name, _ in sets] + go_tried
    located += [f for f in from_flirt(image, sets) if f.offset not in known]
    located += from_yara(image, data, yara_dir)
    return located


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


def rust_hooks(text: str) -> dict:
    """Demangled Rust path -> safe hook action, never a Rust ABI guess.

    The `rust` pseudo-module in the template is replaced with the sample's
    actual module and the located function's address at emission time.
    """
    hooks = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if (len(parts) != 4 or parts[0] != "rust"
                or parts[2:] != ["no-retval", "log"]
                or not parts[1].startswith("std::")
                or not _MODULE_OK.match(parts[1])):
            raise ValueError(f"invalid rust_hooks.txt entry: {line!r}")
        if parts[1] in hooks:
            raise ValueError(f"duplicate rust_hooks.txt entry: {parts[1]}")
        hooks[parts[1]] = "no-retval,log"
    return hooks


# Keep these reexport aliases explicit; a suffix-only lookup could confuse
# different Rust types or trait methods sharing a method name.
_RUST_PUBLIC_TYPES = {
    "std::net::tcp::TcpStream": "std::net::TcpStream",
    "std::net::tcp::TcpListener": "std::net::TcpListener",
    "std::net::udp::UdpSocket": "std::net::UdpSocket",
}


def _rust_hook_path(decoded: str) -> str:
    """Normalize Rust demangler output for allowlist comparison."""
    decoded = re.sub(r"\[[0-9a-fA-F]{8,}\]", "", decoded)
    decoded = re.sub(r"::h[0-9a-fA-F]{16,}$", "", decoded)

    # Rust v0 inherent methods are demangled as `<Type>::method`, not
    # `Type::method`. Trait impls (`<Type as Trait>::method`) must NOT be
    # treated as inherent methods.
    if decoded.startswith("<") and ">::" in decoded:
        ty, sep, method = decoded[1:].partition(">::")
        if (sep and ty.startswith("std::") and " as " not in ty
                and not any(c in ty for c in "<>") and method):
            decoded = ty + "::" + method

    for internal, public in _RUST_PUBLIC_TYPES.items():
        if decoded.startswith(internal + "::"):
            return public + decoded[len(internal):]
    return decoded


def _rust_paths(located: list, hooks: dict) -> dict:
    """Raw Rust symbol -> allowlisted demangled path (or none).

    Rust v0 mangling isn't equivalent to removing an `_ZN` prefix. Binutils'
    Rust demangler handles both v0 and legacy symbols. If it isn't installed,
    accept already-demangled paths only; never guess a mangled symbol's name.
    """
    raw = sorted({f.name for f in located
                  if f.name.startswith(("__R", "__ZN", "_R", "R", "_ZN", "ZN", "std::"))
                  and "\n" not in f.name and "\r" not in f.name
                  and len(f.name) < 4096})
    if not raw:
        return {}
    demangled = raw
    filt = shutil.which("c++filt")
    if filt is not None:
        try:
            result = subprocess.run([filt, "--format=rust"],
                                    input="\n".join(n[1:] if n.startswith(("__R", "__ZN"))
                                                    else n for n in raw) + "\n",
                                    capture_output=True, text=True, timeout=15,
                                    check=True)
            rows = result.stdout.splitlines()
            if len(rows) == len(raw):
                demangled = rows
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    result = {}
    for symbol, decoded in zip(raw, demangled):
        decoded = _rust_hook_path(decoded)
        # Generic monomorphizations may be `std::fs::read::<&str>`; do not
        # mistake `read_dir` for `read` or match a different method by prefix.
        if decoded in hooks:
            result[symbol] = decoded
        else:
            for path in hooks:
                if decoded.startswith(path + "::<") or decoded.startswith(path + "<"):
                    result[symbol] = path
                    break
    return result


def sample_lines(located: list, known: dict, module: str, base: Optional[int] = 0,
                 go: Optional[dict] = None, abi: str = "", when=None,
                 rust: Optional[dict] = None) -> list:
    """The hook-list lines for what was located and the list knows, one per
    address. [] for a module name the list cannot spell, and for an image
    with no base to count from. A Go function's line says where its arguments
    are (`abi`, per go_abi()); with no saying, the call is logged bare.

    `rust`: Rust hook templates, selected only when the caller established
    this is a Rust sample. Rust arguments and return values are not decoded.

    `when`: for code that is not in the file (stagehints). Called with a
    function's address, it gives the line's `when:<hex>` marker -- the bytes
    the tracer waits to see there before it places the hook -- or "" for a
    function that gets no line."""
    if base is None or not _MODULE_OK.match(module) or module != module.strip():
        return []
    lines, seen = [], set()
    rust_names = _rust_paths(located, rust) if rust else {}
    for found in sorted(located, key=lambda f: (f.offset, f.name)):
        offset = found.offset - base
        # Code a program unpacks may lie below where it was loaded (UPX puts
        # it at 0x400000, under the packed file): counted backwards, as the
        # tracer's 64-bit sum of base and offset wraps to it
        if when is not None and offset < 0:
            offset &= (1 << 64) - 1
        if offset in seen or offset <= 0:
            continue
        if found.how == "gopclntab" or GO_SET.match(found.how.removeprefix("flirt:")):
            if not go or found.name not in go:
                continue
            marker, rest = go[found.name].split(",", 1)
            # a function written in assembly is on the stack in every version
            marker = marker if marker == "goabi0" else abi
            rest = f"{marker},{rest}" if marker else "no-retval,log"
            name = found.name
        elif found.name in rust_names:
            name = rust_names[found.name]
            rest = rust[name]
        else:
            name = found.name if found.name in known else plain_name(found.name)
            if name not in known:
                continue
            rest = known[name]
        if when is not None:
            waits = when(found.offset)
            if not waits:
                continue
            rest = f"{waits},{rest}"
        seen.add(offset)
        lines.append(f"{module},{name},{offset:x},{rest}")
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


#: A line sandboxd/stagehints.py writes, and nothing else: by offset, waiting
#: for its code. What is read back may have been through the object store.
_HINT = re.compile(r"^[^,\r\n#]+,[^,\r\n]+,[0-9a-f]{1,16},when:(?:[0-9a-f]{2}|\?\?){1,32},[\x20-\x7e]+$")


def hint_lines(text: str) -> list:
    """The lines of a hints file the tracer's list can take, MAX_HOOKS at
    most: one that is not a hint would stop DRAKVUF at its start."""
    return [line for line in text.splitlines() if _HINT.match(line)][:MAX_HOOKS]


def write_list(static_text: str, lines: list, out: Path, hints: str = "") -> None:
    """The static list with the sample's lines after it, written beside `out`
    and renamed over it: the tracer reads either the list before or this one.
    `hints`: the lines a first run's memory gave (sandboxd/stagehints.py)."""
    text = static_text if static_text.endswith("\n") else static_text + "\n"
    if lines:
        text += "\n# The sample's own functions, located before the run (sandboxd/samplehooks.py)\n"
        text += "\n".join(lines) + "\n"
    if hint_lines(hints):
        text += "\n# Located in the first run's memory (sandboxd/stagehints.py)\n"
        text += "\n".join(hint_lines(hints)) + "\n"
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
        "rust": image.rust or None,
        "go": {"version": image.go_version or None, "table": image.go_table or None,
               "signature_set": image.go_set or None,
               "arguments": go_abi(image) or None} if image.go_table or image.go_set else None,
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
    p.add_argument("--rust-hooks", type=Path, default=RUST_HOOKS)
    p.add_argument("--also", type=Path, action="append", default=[],
                   help="a list made for this deployment, added to the job's when it exists "
                        "(profiles/hooks-dotnet.txt, from scripts/dotnet-index.py)")
    p.add_argument("--hints", type=Path,
                   help="lines from a first run's memory, added to --out when the file exists "
                        "(sandboxd/stagehints.py)")
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
            go = (go_hooks(args.go_hooks.read_text())
                  if (image.go_table or image.go_set) and args.go_hooks.is_file() else {})
            rust = (rust_hooks(args.rust_hooks.read_text())
                    if image.toolchain == "rust" and args.rust_hooks.is_file() else {})
            lines = sample_lines(located, static_hooks(static_text),
                                 module_name(image, args.guest_path), image.base, go, go_abi(image),
                                 rust=rust)
    except Exception as exc:  # noqa: BLE001 - a program no parser reads gets the static list
        print(f"samplehooks: {args.sample.name}: {type(exc).__name__}: {exc}", file=sys.stderr)
        image, located, lines = None, [], []
    if args.append_to:
        # no `#` or line end reaches the comment: a name with either got no lines
        lines = append_list(lines, args.append_to, f"Dropped during the run: {args.guest_path}") if lines else []
    elif args.out:
        hints = args.hints.read_text() if args.hints and args.hints.is_file() else ""
        write_list(static_text, lines, args.out, hints)
    else:
        p.error("one of --out and --append-to")
    if args.json:
        args.json.write_text(json.dumps(report(image, located, lines)))
    print(f"samplehooks: {len(located)} functions located, {len(lines)} hooked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
