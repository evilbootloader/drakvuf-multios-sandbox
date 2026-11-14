#!/usr/bin/env python3
"""Index the precompiled methods of .NET framework assemblies: name -> where
its native code starts.

A managed method is not an export, so apimon cannot be told of
`System.Net.WebClient::DownloadString` by name. But the framework assemblies
of .NET (Core) 5 and later ship precompiled ("ReadyToRun"): each DLL carries
native code for most of its methods and a table from method to entry point.
This reads that table, offline, from the files themselves:

    scripts/dotnet-index.py /mnt/Program\\ Files/dotnet/shared -o profiles/dotnet-index.json

and writes, per `Namespace.Type::Method`, every overload with its module, the
entry point's RVA, the image's width and what each argument is as a hook-list
type. `scripts/gen-hook-lists.py --dotnet` turns the entries capa's rules name
into hook lines (by offset, `clrcall`).

Runs on Dom0 against the mounted golden image, like
windows-symbol-profiles.py; nothing runs in the guest. Needs `pefile` and
`dnfile`. `make setup_hooks_windows` runs it over the whole image, after the
symbol profiles it takes the JIT compilers' entry from:

    scripts/dotnet-index.py --image /mnt

What it does not cover, and why:

- **32-bit .NET Framework native images.** The 64-bit ones are read (below);
  the 32-bit ones have no exception table to take function starts from and
  were not worked out. They are skipped and counted.
- **Generic instantiations**, which live in a separate hash table keyed by
  signature, and methods the image has no code for (the JIT compiles those).
- **A method the runtime re-compiles.** Tiered compilation replaces a
  precompiled method by JIT code once it has been called about 30 times, and
  calls stop passing through the address indexed here. Each method is seen
  for its first calls.

The format is the runtime's `docs/design/coreclr/botr/readytorun-format.md`:
a `READYTORUN_HEADER` (`RTR\\0`) reached from the CLI header's
ManagedNativeHeader directory, section 103 (MethodDefEntryPoints, a
NativeArray indexed by method row) and section 102 (RuntimeFunctions).

**.NET Framework 4.x** (`C:\\Windows\\assembly\\NativeImages_v4.0.30319_64`,
made by ngen on the machine) is an older format nobody documents; what is
read of it was worked out on this project's guest image, 4.8, 2026-11-14,
and is checked on every image it reads (see `index_native_image`). The
header (`NGE\\0`) has a code manager entry naming the hot and the unprofiled
code range, and a table of the image's "virtual sections". For each code
range one of those sections is an array of 32-bit entries, one per function
of the range in the order of the PE's exception table: 0, or the RVA of the
method's descriptor (two flag bits low). A descriptor gives the method's
metadata row: 14 bits in its own first word, 10 in its chunk's header.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

RTR_SIGNATURE = 0x00525452       # "RTR\0"
SECTION_RUNTIME_FUNCTIONS = 102
SECTION_METHODDEF_ENTRYPOINTS = 103
BLOCK = 16                       # NativeArray's block size

#: Hook-list types for the element types an argument reader can do something
#: with. Everything else is a word (`lpvoid`).
_ELEMENT = {0x02: "bool", 0x03: "word", 0x04: "dword", 0x05: "dword", 0x06: "word", 0x07: "word",
            0x08: "dword", 0x09: "dword", 0x0A: "ulong", 0x0B: "ulong", 0x0E: "clrstring",
            0x18: "ulong", 0x19: "ulong"}
_NAMES = {0x01: "void", 0x02: "bool", 0x03: "char", 0x04: "sbyte", 0x05: "byte", 0x06: "short",
          0x07: "ushort", 0x08: "int", 0x09: "uint", 0x0A: "long", 0x0B: "ulong", 0x0C: "float",
          0x0D: "double", 0x0E: "string", 0x18: "nint", 0x19: "nuint", 0x1C: "object"}


class Unreadable(Exception):
    pass


def decode_unsigned(data: bytes, at: int) -> tuple:
    """(value, next offset) of the native format's variable-length unsigned."""
    first = data[at]
    if first & 1 == 0:
        return first >> 1, at + 1
    if first & 2 == 0:
        return (first | data[at + 1] << 8) >> 2, at + 2
    if first & 4 == 0:
        return (first | data[at + 1] << 8 | data[at + 2] << 16) >> 3, at + 3
    if first & 8 == 0:
        return struct.unpack_from("<I", data, at)[0] >> 4, at + 4
    if first & 16 == 0:
        return struct.unpack_from("<I", data, at + 1)[0], at + 5
    raise Unreadable("a 64-bit value where an index belongs")


class NativeArray:
    """The sparse array of the native format: `at(index)` is the offset of
    the element's data, or None."""

    def __init__(self, data: bytes, at: int) -> None:
        self.data = data
        header, self.base = decode_unsigned(data, at)
        self.count = header >> 2
        self.index_size = header & 3

    def at(self, index: int):
        if index >= self.count:
            return None
        data, block = self.data, index // BLOCK
        if self.index_size == 0:
            offset = data[self.base + block]
        elif self.index_size == 1:
            offset = struct.unpack_from("<H", data, self.base + 2 * block)[0]
        else:
            offset = struct.unpack_from("<I", data, self.base + 4 * block)[0]
        offset += self.base
        bit = BLOCK >> 1
        while bit:
            value, after = decode_unsigned(data, offset)
            if index & bit:
                if value & 2:
                    offset += value >> 2
                    bit >>= 1
                    continue
            elif value & 1:
                offset = after
                bit >>= 1
                continue
            # a leaf standing for one element of the block
            if value & 3 == 0 and value >> 2 == index & (BLOCK - 1):
                return after
            return None
        return offset


def compressed(blob: bytes, at: int) -> tuple:
    """ECMA-335 II.23.2 compressed unsigned: (value, next offset)."""
    first = blob[at]
    if first & 0x80 == 0:
        return first, at + 1
    if first & 0xC0 == 0x80:
        return (first & 0x3F) << 8 | blob[at + 1], at + 2
    return (first & 0x1F) << 24 | blob[at + 1] << 16 | blob[at + 2] << 8 | blob[at + 3], at + 4


def read_type(blob: bytes, at: int) -> tuple:
    """(hook-list type, a name for the signature, next offset) of one type in
    a signature blob."""
    kind = blob[at]
    at += 1
    while kind in (0x1F, 0x20):                 # CMOD_REQD, CMOD_OPT
        _, at = compressed(blob, at)
        kind = blob[at]
        at += 1
    if kind in (0x45,):                         # PINNED
        return read_type(blob, at)
    if kind == 0x1D:                            # SZARRAY
        inner, name, at = read_type(blob, at)
        return ("clrbytes" if name in ("byte", "sbyte") else "lpvoid"), name + "[]", at
    if kind in (0x0F, 0x10):                    # PTR, BYREF
        _, name, at = read_type(blob, at)
        return "lpvoid", name + ("*" if kind == 0x0F else "&"), at
    if kind in (0x11, 0x12):                    # VALUETYPE, CLASS
        _, at = compressed(blob, at)
        return "lpvoid", "valuetype" if kind == 0x11 else "class", at
    if kind in (0x13, 0x1E):                    # VAR, MVAR
        number, at = compressed(blob, at)
        return "lpvoid", ("!" if kind == 0x13 else "!!") + str(number), at
    if kind == 0x15:                            # GENERICINST
        at += 1
        _, at = compressed(blob, at)
        count, at = compressed(blob, at)
        for _ in range(count):
            _, _, at = read_type(blob, at)
        return "lpvoid", "generic", at
    if kind == 0x14:                            # ARRAY
        _, name, at = read_type(blob, at)
        rank, at = compressed(blob, at)
        for _ in range(2):
            count, at = compressed(blob, at)
            for _ in range(count):
                _, at = compressed(blob, at)
        return "lpvoid", f"{name}[{',' * (rank - 1)}]", at
    if kind == 0x1B:                            # FNPTR
        _, _, _, at = read_signature(blob, at)
        return "lpvoid", "fnptr", at
    if kind in _NAMES or kind in (0x16,):       # primitives, TYPEDBYREF
        return _ELEMENT.get(kind, "lpvoid"), _NAMES.get(kind, "typedref"), at
    raise Unreadable(f"element type 0x{kind:x}")


def read_signature(blob: bytes, at: int = 0) -> tuple:
    """(has `this`, [hook-list type], [name, the return type's first], next
    offset) of a method signature."""
    convention = blob[at]
    at += 1
    if convention & 0x10:                       # GENERIC: its parameter count
        _, at = compressed(blob, at)
    count, at = compressed(blob, at)
    _, returns, at = read_type(blob, at)
    kinds, names = [], [returns]
    for _ in range(count):
        if blob[at] == 0x41:                    # SENTINEL, before a vararg's extras
            at += 1
        kind, name, at = read_type(blob, at)
        kinds.append(kind)
        names.append(name)
    return bool(convention & 0x20), kinds, names, at


NGEN_SIGNATURE = 0x0045474E      # "NGE\0"
#: A method descriptor's chunk header on x64: method table, next chunk
#: (pointers), size, count (bytes), flags and token range (a word); padded
CHUNK_HEADER = 24
DESCRIPTOR_ALIGNMENT = 8
TOKEN_REMAINDER_BITS = 14


def index_native_image(pe, path: Path, module: str, header_rva: int) -> tuple:
    """([entry], reason it has none) for a .NET Framework native image.

    Nothing documents this layout, so no method is taken on its word alone.
    A descriptor's chunk points at the method table of the type the method
    belongs to, and a method table carries its type's metadata row: a method
    is indexed only when that row is the one the metadata says owns the
    method. On this project's image every plain method of both images tried
    passed (23,025 and 15,586) and the ones that did not were what should
    not: stubs, and instantiations of another assembly's generic types,
    whose rows are that assembly's. An image whose layout differs fails the
    check throughout and yields nothing."""
    if pe.FILE_HEADER.Machine != 0x8664:
        return [], "a 32-bit .NET Framework native image (not read)"
    image = pe.get_memory_mapped_image()
    manager_rva = struct.unpack_from("<I", image, header_rva + 72)[0]
    sections_rva, sections_size = struct.unpack_from("<II", image, header_rva + 96)
    exceptions = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    if not manager_rva or not sections_rva or not exceptions.VirtualAddress:
        return [], "a native image without the tables read here"
    starts = [struct.unpack_from("<I", image, exceptions.VirtualAddress + 12 * n)[0]
              for n in range(exceptions.Size // 12)]
    sections = [struct.unpack_from("<III", image, sections_rva + 12 * n) for n in range(sections_size // 12)]

    tables = pe.net.mdtables
    rows = tables.MethodDef.num_rows
    owner, owner_row = {}, {}
    for type_row, row in enumerate(tables.TypeDef.rows, start=1):
        name = f"{row.TypeNamespace}.{row.TypeName}" if row.TypeNamespace else str(row.TypeName)
        for method in row.MethodList or ():
            owner[method.row_index] = name
            owner_row[method.row_index] = type_row

    entries, seen = [], set()
    for n in range(2):                          # HotCode, Code (unprofiled)
        range_rva, range_size = struct.unpack_from("<II", image, manager_rva + 8 * n)
        if not range_size:
            continue
        functions = [s for s in starts if range_rva <= s < range_rva + range_size]
        arrays = [rva for rva, size, _ in sections if size == 4 * len(functions) and rva != range_rva]
        if len(arrays) != 1:
            raise Unreadable(f"{len(arrays)} sections could be the methods of the code at 0x{range_rva:x}")
        for start, value in zip(functions, struct.unpack_from(f"<{len(functions)}I", image, arrays[0])):
            descriptor = value & ~3
            if not descriptor:
                continue                        # a funclet, or a stub
            if not 0x1000 <= descriptor < len(image) - 8:
                continue
            word, chunk_index = struct.unpack_from("<HB", image, descriptor)
            if struct.unpack_from("<H", image, descriptor + 6)[0] & 7:
                continue                        # not IL: a P/Invoke, a generic method's instantiation, a stub
            chunk = descriptor - CHUNK_HEADER - chunk_index * DESCRIPTOR_ALIGNMENT
            if chunk < 0x1000:
                continue
            token_range = struct.unpack_from("<H", image, chunk + 18)[0] & ((1 << (24 - TOKEN_REMAINDER_BITS)) - 1)
            rid = token_range << TOKEN_REMAINDER_BITS | word & ((1 << TOKEN_REMAINDER_BITS) - 1)
            # The chunk's method table: an offset from the field itself, odd
            # when it goes through an import (another assembly's type)
            relative = struct.unpack_from("<q", image, chunk)[0]
            table = chunk + relative
            if relative & 1 or not 0x1000 <= table < len(image) - 16:
                continue
            # MethodTable: flags, base size (dwords), flags2, the type's row (words)
            type_row = struct.unpack_from("<H", image, table + 10)[0]
            if not 0 < rid <= rows or owner_row.get(rid, 0) & 0xFFFF != type_row:
                continue
            if (rid, start) in seen:
                continue
            seen.add((rid, start))
            method = tables.MethodDef.rows[rid - 1]
            try:
                has_this, kinds, names, _ = read_signature(method.Signature.value)
                returns, names = names[0], names[1:]
            except (Unreadable, IndexError, AttributeError):
                has_this, kinds, names, returns = not method.Flags.mdStatic, None, None, None
            entries.append({
                "name": f"{owner.get(rid, '?')}::{method.Name}",
                "module": module, "rva": start, "bits": 64,
                "this": has_this, "args": kinds, "returns": returns,
                "signature": "(" + ", ".join(names) + ")" if names is not None else None,
            })
    return entries, ""


def index_assembly(path: Path, module: str) -> tuple:
    """([entry], reason it has none) for one DLL, `module` being how a hook
    list names it."""
    import dnfile

    try:
        pe = dnfile.dnPE(str(path), fast_load=False)
    except Exception as exc:  # noqa: BLE001 - whatever a parser says of a file that is no assembly
        return [], f"not read: {type(exc).__name__}"
    try:
        if pe.net is None or pe.net.mdtables is None or pe.net.mdtables.MethodDef is None:
            return [], "not managed"
        header_rva = pe.net.struct.ManagedNativeHeaderRva
        if not header_rva:
            return [], "no precompiled code"
        image = pe.get_memory_mapped_image()
        signature, _major, _minor, _flags, sections = struct.unpack_from("<IHHII", image, header_rva)
        if signature == NGEN_SIGNATURE:
            return index_native_image(pe, path, module, header_rva)
        if signature != RTR_SIGNATURE:
            return [], "a native image of no known kind"
        found = {}
        for n in range(sections):
            kind, rva, size = struct.unpack_from("<III", image, header_rva + 16 + 12 * n)
            found[kind] = (rva, size)
        if SECTION_METHODDEF_ENTRYPOINTS not in found or SECTION_RUNTIME_FUNCTIONS not in found:
            return [], "no method table (a composite image's component)"
        bits = 64 if pe.FILE_HEADER.Machine == 0x8664 else 32 if pe.FILE_HEADER.Machine == 0x14C else 0
        if not bits:
            return [], "not x86"
        # RUNTIME_FUNCTION: begin, end, unwind on x64; begin, unwind on x86
        functions_rva, functions_size = found[SECTION_RUNTIME_FUNCTIONS]
        function_size = 12 if bits == 64 else 8
        function_count = functions_size // function_size
        entry_points = NativeArray(image, found[SECTION_METHODDEF_ENTRYPOINTS][0])

        tables = pe.net.mdtables
        owner = {}
        for row in tables.TypeDef.rows:
            name = f"{row.TypeNamespace}.{row.TypeName}" if row.TypeNamespace else str(row.TypeName)
            for method in row.MethodList or ():
                owner[method.row_index] = name
        entries = []
        for rid, method in enumerate(tables.MethodDef.rows, start=1):
            at = entry_points.at(rid - 1)
            if at is None:
                continue
            ident, at = decode_unsigned(image, at)
            # bit 0: fixups follow; bit 1 with it: they are a delta away
            function = ident >> 2 if ident & 1 else ident >> 1
            if function >= function_count:
                raise Unreadable(f"method {rid} names runtime function {function} of {function_count}")
            rva = struct.unpack_from("<I", image, functions_rva + function * function_size)[0]
            try:
                has_this, kinds, names, _ = read_signature(method.Signature.value)
                returns, names = names[0], names[1:]
            except (Unreadable, IndexError, AttributeError):
                has_this, kinds, names, returns = not method.Flags.mdStatic, None, None, None
            entries.append({
                "name": f"{owner.get(rid, '?')}::{method.Name}",
                "module": module, "rva": rva, "bits": bits,
                "this": has_this, "args": kinds, "returns": returns,
                "signature": "(" + ", ".join(names) + ")" if names is not None else None,
            })
        return entries, ""
    except (Unreadable, struct.error, IndexError) as exc:
        return [], f"not read: {exc}"
    finally:
        pe.close()


#: Where the arguments of a method are cannot be said from its signature
#: alone when one of these is in it: a struct returned by value adds a hidden
#: argument, and on x86 a 64-bit or floating point argument is not in the
#: registers or takes two stack slots.
_HIDDEN_RETURN = ("valuetype", "generic", "typedref")
_NOT_A_WORD = ("long", "ulong", "float", "double", "valuetype", "generic", "typedref")


def hook_line(name: str, entry: dict) -> str:
    """The hook-list line for one overload: by offset in its module, the
    arguments typed where the signature says where they are, bare otherwise."""
    head = f"{entry['module']},{name},{entry['rva']:x}"
    kinds = entry["args"]
    signature = (entry["signature"] or "()")[1:-1]
    words = [n.rstrip("[]*&") for n in signature.split(", ")] if signature else []
    if (kinds is None or entry["returns"] in _HIDDEN_RETURN
            or (entry["bits"] == 32 and any(w in _NOT_A_WORD for w in words))):
        return f"{head},log"
    arguments = (["This:lpvoid"] if entry["this"] else []) + [f"Arg{n}:{kind}" for n, kind in enumerate(kinds, 1)]
    return ",".join([head, "clrcall", "log"] + arguments)


#: `CILJit::compileMethod(ICorJitInfo*, CORINFO_METHOD_INFO*, unsigned, BYTE**, ULONG*)`,
#: as MSVC decorates it
JIT_SYMBOL = "?compileMethod@CILJit@@"
JIT_ARGUMENTS = "This:lpvoid,Comp:lpvoid,Info:pcorinfo_method_info,Flags:dword,NativeEntry:lpvoid*,NativeSize:pulong"


def jit_line(module: str, profile: Path) -> str:
    """The hook line for a JIT compiler's entry, from its symbol profile."""
    symbols = json.loads(profile.read_text()).get("symbols", {})
    found = [s["address"] for name, s in symbols.items() if name.startswith(JIT_SYMBOL) and "address" in s]
    if len(found) != 1:
        raise Unreadable(f"{profile.name} has {len(found)} symbols starting {JIT_SYMBOL}")
    return f"{module},CILJit::compileMethod,{found[0]:x},log,{JIT_ARGUMENTS}"


def capa_methods(rules: Path) -> set:
    """Every `Namespace.Type::Method` a capa rule matches on."""
    import re
    said = re.compile(r"^\s*- (?:api|property/read|property/write): ([A-Za-z0-9_.`]+::[A-Za-z0-9_.`]+)", re.M)
    found: set = set()
    for rule in rules.rglob("*.yml"):
        found.update(said.findall(rule.read_text(errors="replace")))
    return found


#: In a mounted Windows volume, where the precompiled framework code is
IMAGE_ROOTS = ("Windows/assembly", "Program Files/dotnet/shared", "Program Files (x86)/dotnet/shared")


def whole_image(args, error) -> None:
    """`--image`: every argument a mounted volume answers for itself. The
    roots that exist, modules named from the mount, and each JIT compiler
    that is there and has a profile (scripts/windows-symbol-profiles.py: its
    table of them, and its way of finding a path whatever its case)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "windows_symbol_profiles", Path(__file__).resolve().parent / "windows-symbol-profiles.py")
    profiles = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(profiles)

    args.roots = [found for found in (profiles.locate(args.image, root) for root in IMAGE_ROOTS) if found]
    if not args.roots:
        error(f"none of {', '.join(IMAGE_ROOTS)} under {args.image}: is the Windows volume mounted there?")
    args.root = args.image
    args.out = args.out or args.profiles / "dotnet-index.json"
    args.hooks = args.hooks or args.profiles / "hooks-dotnet.txt"
    for _, name, relpath in profiles.JIT:
        dll = profiles.locate(args.image, relpath)
        if dll is not None and (args.profiles / name).is_file():
            args.jit.append((dll, args.profiles / name))
        elif dll is not None:
            print(f"  no JIT hook for {dll}: {args.profiles / name} is not made "
                  f"(scripts/windows-symbol-profiles.py {name.removesuffix('.json')})", file=sys.stderr)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("roots", nargs="*", type=Path,
                   help="directories (searched for *.dll) or DLLs: the image's Program Files/dotnet/shared")
    p.add_argument("-o", "--out", type=Path)
    p.add_argument("--image", type=Path,
                   help="a mounted Windows volume: index everything in it, with no other argument. "
                        "Writes dotnet-index.json and hooks-dotnet.txt into --profiles")
    p.add_argument("--profiles", type=Path, default=Path(__file__).resolve().parent.parent / "profiles",
                   help="with --image: where the symbol profiles are and the results go (default %(default)s)")
    p.add_argument("--root", type=Path,
                   help="where the Windows volume is mounted. A module is then named by its path "
                        "from there (`Program Files\\dotnet\\shared\\...\\8.0.11\\X.dll`), which "
                        "tells two versions and two widths of one assembly apart; without it, by "
                        "file name, which is only safe for an image with one runtime")
    p.add_argument("--hooks", type=Path, help="also write the hook list (profiles/hooks-dotnet.txt)")
    p.add_argument("--jit", nargs=2, action="append", default=[], metavar=("CLRJIT_DLL", "PROFILE"),
                   help="a JIT compiler and its symbol profile (windows-symbol-profiles.py's "
                        "clrjit*.json): its compileMethod gets a hook line, which is what the "
                        "report's list of the sample's own methods is made from")
    p.add_argument("--capa-rules", type=Path,
                   default=Path(__file__).resolve().parent.parent / "sandboxd" / "data" / "capa-rules",
                   help="the rules whose .NET methods get a hook")
    args = p.parse_args(argv)
    if args.image:
        if args.roots:
            p.error("--image finds the directories itself")
        whole_image(args, p.error)
    elif not args.roots or not args.out:
        p.error("directories to index and -o, or --image")

    files = []
    for root in args.roots:
        files += sorted(root.rglob("*.dll")) if root.is_dir() else [root]
    index: dict = {}
    skipped: dict = {}
    methods = 0
    for path in files:
        module = path.name
        if args.root:
            try:
                module = "\\".join(path.resolve().relative_to(args.root.resolve()).parts)
            except ValueError:
                p.error(f"{path} is not under --root {args.root}")
        if "," in module or "#" in module:
            skipped["a name a hook list cannot spell"] = skipped.get("a name a hook list cannot spell", 0) + 1
            continue
        entries, why = index_assembly(path, module)
        if why:
            skipped[why] = skipped.get(why, 0) + 1
            continue
        for entry in entries:
            index.setdefault(entry.pop("name"), []).append(entry)
        methods += len(entries)
    args.out.write_text(json.dumps({"methods": index}, separators=(",", ":"), sort_keys=True))
    print(f"dotnet-index: {methods} methods under {len(index)} names from "
          f"{len(files) - sum(skipped.values())} of {len(files)} files -> {args.out}")
    for why, count in sorted(skipped.items()):
        print(f"  {count} skipped: {why}")
    if args.hooks:
        wanted = capa_methods(args.capa_rules)
        # a property is a pair of methods
        names = {n for n in index if n in wanted or n.replace("::get_", "::").replace("::set_", "::") in wanted}
        lines = [hook_line(name, entry) for name in sorted(names) for entry in index[name]]
        for dll, profile in args.jit:
            dll = Path(dll)
            module = dll.name
            if args.root:
                module = "\\".join(dll.resolve().relative_to(args.root.resolve()).parts)
            try:
                lines.append(jit_line(module, Path(profile)))
            except (Unreadable, OSError, ValueError) as exc:
                print(f"  no JIT hook for {dll}: {exc}", file=sys.stderr)
        args.hooks.write_text(
            "# .NET framework methods capa's rules name, where this image's precompiled code has them.\n"
            "# Generated by scripts/dotnet-index.py for one image: regenerate after a runtime update.\n"
            + "\n".join(lines) + "\n")
        print(f"  {len(lines)} hook lines for {len(names)} of the {len(wanted)} methods "
              f"the rules name -> {args.hooks}")
    return 0 if methods else 1


if __name__ == "__main__":
    sys.exit(main())
