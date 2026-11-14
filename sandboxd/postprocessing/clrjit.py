"""The sample's managed methods as the runtime compiled them: a JIT timeline.

A .NET program's own code is IL until a method is first called, when the
runtime's JIT compiler turns it into native code. apimon hooks the compiler's
entry (`CILJit::compileMethod` in clrjit.dll, a hook line that
scripts/dotnet-index.py writes for the deployment's image), and each call is
one method about to run for the first time: its IL's address, size and first
bytes, and where the native code went.

The call does not say the method's NAME -- that is in the runtime's own
structures, which nothing here walks. It is found from the other side: the
sample's metadata lists every method with its IL body, and a body of the same
size starting with the same bytes is the method. That works however the
runtime mapped the assembly (as an image, as a flat file, from a byte array),
which an address would not. Two methods with identical bodies (empty
constructors, one-line getters) are both named, as candidates.

The sample is not the only assembly a sample runs. One it downloads or
unpacks to disk is in the job's `extracted/`, and one it decrypts and loads
from a byte array is in `dumps/` (memdump's `AssemblyNative::LoadImage` hook
writes the array). Every managed PE found in either is read the same way, and
a method named from one of them says which file.

Not named: dynamic methods (Reflection.Emit), which have no metadata, and the
methods of an assembly that reached memory by a path nothing dumped.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

JIT_API = "CILJit::compileMethod"
#: Other assemblies read per job, and the largest one read
MAX_ASSEMBLIES = 64
MAX_ASSEMBLY_BYTES = 64 << 20
#: IL bytes the hook prints of each method (printers.cpp, CorinfoMethodInfoPrinter)
PREFIX_BYTES = 32
MAX_METHODS = 20_000
_INFO = re.compile(r"il=0x([0-9a-fA-F]+),size=(\d+),code=\"?([0-9a-fA-F]*)")


def method_bodies(path: Path) -> dict:
    """(IL size, hex of its first bytes) -> [Namespace.Type::Method] for a
    managed PE; {} for anything else."""
    try:
        import dnfile
        pe = dnfile.dnPE(str(path))
    except Exception:  # noqa: BLE001 - not a PE, or no parser for it
        return {}
    try:
        if pe.net is None or pe.net.mdtables is None or pe.net.mdtables.MethodDef is None:
            return {}
        tables = pe.net.mdtables
        owner = {}
        for row in tables.TypeDef.rows:
            name = f"{row.TypeNamespace}.{row.TypeName}" if row.TypeNamespace else str(row.TypeName)
            for method in row.MethodList or ():
                owner[method.row_index] = name
        bodies: dict = {}
        for rid, method in enumerate(tables.MethodDef.rows, start=1):
            if not method.Rva:
                continue
            try:
                head = pe.get_data(method.Rva, 12)
                if head[0] & 3 == 2:                    # tiny: the size in the byte
                    size, code_rva = head[0] >> 2, method.Rva + 1
                elif head[0] & 3 == 3:                  # fat: 12 bytes, the size at 4
                    size = int.from_bytes(head[4:8], "little")
                    code_rva = method.Rva + 4 * (head[1] >> 4)
                else:
                    continue
                prefix = pe.get_data(code_rva, min(size, PREFIX_BYTES)).hex()
            except Exception:  # noqa: BLE001 - an RVA outside the file
                continue
            bodies.setdefault((size, prefix), []).append(f"{owner.get(rid, '?')}::{method.Name}")
        return bodies
    finally:
        pe.close()


def assemblies(directories) -> list:
    """The files under the directories that start like a PE, smallest first:
    what a job dropped or loaded from memory is seldom its largest file."""
    found = []
    for directory in directories:
        if not directory.is_dir():
            continue
        for path in directory.iterdir():
            try:
                if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_ASSEMBLY_BYTES:
                    continue
                with path.open("rb") as fh:
                    if fh.read(2) == b"MZ":
                        found.append(path)
            except OSError:
                continue
    return sorted(found, key=lambda p: p.stat().st_size)[:MAX_ASSEMBLIES]


class Timeline:
    """Collects the compiler's calls as the report's calls are written.
    `directories`: where the job's other assemblies may be (extracted/, dumps/)."""

    def __init__(self, sample: Optional[Path], directories=()) -> None:
        self._sample = sample
        self._directories = tuple(directories)
        self._bodies: Optional[dict] = None
        self.methods: list = []
        self.dropped = 0

    def _read_bodies(self) -> dict:
        """(size, prefix) -> [(method, file it is from, None for the sample)]"""
        bodies: dict = {}
        sources = [(self._sample, None)] if self._sample is not None else []
        sources += [(path, path.name) for path in assemblies(self._directories)]
        for path, origin in sources:
            for key, names in method_bodies(path).items():
                known = {name for name, _ in bodies.get(key, ())}
                # the same assembly dumped twice names a method once
                bodies.setdefault(key, []).extend((n, origin) for n in names if n not in known)
        return bodies

    def add(self, pid, row: dict) -> None:
        if row.get("api") != JIT_API:
            return
        if len(self.methods) >= MAX_METHODS:
            self.dropped += 1
            return
        arguments = {a.get("name"): a.get("value") for a in row.get("arguments") or ()}
        said = _INFO.search(str(arguments.get("Info") or ""))
        if not said:
            return
        if self._bodies is None:
            self._bodies = self._read_bodies()
        size, prefix = int(said.group(2)), said.group(3).lower()
        found = self._bodies.get((size, prefix), [])
        names = [name for name, _ in found]
        self.methods.append({
            "time": row.get("ts"), "pid": pid, "tid": row.get("tid"),
            "il": "0x" + said.group(1), "il_size": size,
            "method": names[0] if len(names) == 1 else None,
            "candidates": names if len(names) > 1 else None,
            # which dropped or dumped file it is in; None: the sample itself
            "assembly": found[0][1] if len(found) == 1 else None,
            "native": arguments.get("NativeEntry"), "native_size": arguments.get("NativeSize"),
        })

    def result(self) -> Optional[dict]:
        if not self.methods:
            return None
        named = sum(1 for m in self.methods if m["method"] or m["candidates"])
        return {"compiled": len(self.methods), "named": named, "dropped": self.dropped,
                "methods": self.methods}
