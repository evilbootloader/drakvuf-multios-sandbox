"""Hooks for a second run of the sample, from the memory of its first.

`python -m sandboxd.stagehints --procdumps DIR --trace-log LOG --sample S
     --guest-path P --list JOBLIST --how core|minidump --out HINTS`

**Why.** `samplehooks` reads the file before it runs and `stagehooks` the
files it drops. Code that is in no file is seen by neither: what a packer
unpacks over its own image (UPX, and most of what is called a crypter), and a
program run from memory (memfd on Linux). The first run's process dumps hold
that code, at the addresses it ran at. So the locators are run over those
dumps after every run that has them, and the sample can be run again with
what they found, in one of two ways:

- any job keeps the lines as an artifact, `hints.txt`, and its report
  offers "Run again with unpacked code hooked" beside its memory dumps and
  dropped files, where the first run can be read before a second is spent
  (operator, 2026-11-14): a new job, made by the platform from
  this one, leased a URL to that file (`stages._given_hints`). Both reports
  stay;
- a job submitted through the API with `second_pass` runs twice itself, and
  its report is the second run's. The submit form does not offer it.

**What a hint is.** A hook-list line by offset in the program's own image,
like the ones `samplehooks` writes, with one marker more:

    <module>,<label>,<hex offset>,when:<hex bytes>,log,<arguments>

`when:` is the code the function starts with. In the second run the address
holds something else until the packer has done its work -- compressed data,
or the packer's own running code, and a breakpoint inside another instruction
corrupts it -- so the tracer places the hook when it sees those bytes there
and not before (libmon: at the process's page faults; libusermode: where the
process maps a view or changes a protection, which a packer's stub does
between unpacking and jumping). Bytes a loader rewrites for where the image
landed (a PE's relocations) are written `??`.

**Which memory.** The program's own image only: on Windows the mapped image
whose header is the sample's; on Linux what lies above the executable's base,
which libmon says for every process (`Event: executable`), a program run from
a memfd included. Not followed, and not said to be: code in memory the
program allocates elsewhere (a reflectively loaded DLL, shellcode), which no
hook-list line can name; and a process whose image is another file, which is
`stagehooks`' when the file was written to disk.

**The two runs need not lay memory out alike.** Offsets count from where the
image is in each run, and the bytes decide when. What does have to repeat is
the sample: one that unpacks something else the second time gets no hooks
from the hints, and its trace is what the first run's was.

A child, as `samplehooks` is: the dumps are the guest's memory, parsed.
"""
from __future__ import annotations

import argparse
import gzip
import json
import resource
import struct
import sys
from pathlib import Path
from typing import Callable, Iterator, Optional

from . import samplehooks as sh

#: Read of one process's image, and how far above its base a Linux
#: executable's own memory is looked for (its libraries are further)
MAX_IMAGE = 256 << 20
SPAN = 1 << 30
#: Below this a 64-bit Linux process has its executable, its heap and what it
#: maps at an address of its own choosing -- where UPX puts the program it
#: unpacks (0x400000, below the packed file). Libraries, other mmaps, the
#: stack and the vDSO are above.
LOW_MEMORY = 0x7F0000000000
#: Dumps of the sample's processes read per job, and bytes of a function a
#: hint waits for
MAX_DUMPS = 16
WHEN_BYTES = 16
#: Of those, how many must be the same in every run for a hint to be written
MIN_FIXED = 6


def _open(path: Path, compression: str):
    """The dump as a stream read forwards only; None for a compression not
    read here (zstd: sandboxd asks procdump2 for gzip)."""
    if compression in ("gzip", "gz"):
        return gzip.open(path, "rb")
    if compression in ("", "none", "disabled", "off"):
        return path.open("rb")
    return None


def _skip_to(stream, position: int, at: int) -> bool:
    """Read forwards to `position` from `at`. A gzip stream seeks forwards by
    decompressing, and backwards by starting over: never asked for."""
    if position < at:
        return False
    left = position - at
    while left:
        chunk = stream.read(min(left, 1 << 20))
        if not chunk:
            return False
        left -= len(chunk)
    return True


def sidecars(directory: Path) -> Iterator[tuple]:
    """(pid, dump file, compression) of each finished dump, newest first: a
    process dumped twice is read as it was last. Every process the guest
    dumped, the sample's among a hundred others: `hints` picks."""
    found = []
    for sidecar in directory.glob("*.metadata"):
        try:
            meta = json.loads(sidecar.read_text(errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(meta, dict) or meta.get("Status") != "Success":
            continue
        pid = meta.get("TargetPID", meta.get("PID"))
        # The name only: the sidecar is DRAKVUF's, the directory ours
        data = directory / Path(str(meta.get("DataFileName") or sidecar.stem)).name
        order = meta.get("SequenceNumber")
        if isinstance(pid, int) and data.is_file():
            found.append((order if isinstance(order, int) else 0, pid, data, str(meta.get("Compression") or "")))
    seen = set()
    for _, pid, data, compression in sorted(found, key=lambda f: (-f[0], f[2].name)):
        if pid not in seen:
            seen.add(pid)
            yield pid, data, compression


# --- Linux: an ELF core, and libmon's word for where the executable is --------

def linux_executables(trace_log: Path) -> dict:
    """pid -> (path, base) of each process's executable as libmon last said
    it: at exec, and at fork for the child."""
    found: dict = {}
    try:
        with trace_log.open("rb") as fh:
            for line in fh:
                if b'"executable"' not in line:
                    continue
                try:
                    record = json.loads(line)
                    if record.get("Plugin") != "libmon" or record.get("Event") != "executable":
                        continue
                    base = record["Base"]
                    found[int(record["PID"])] = (str(record["Path"]),
                                                 int(base, 16) if isinstance(base, str) else int(base))
                except (ValueError, KeyError, TypeError):
                    continue
    except OSError:
        pass
    return found


def _core_headers(stream) -> Optional[tuple]:
    """(program headers as (type, flags, offset, vaddr, filesz), where the
    stream is) of an ELF64 core read from its start."""
    header = stream.read(64)
    if len(header) < 64 or header[:5] != b"\x7fELF\x02":
        return None
    phoff, = struct.unpack_from("<Q", header, 0x20)
    entsize, count = struct.unpack_from("<HH", header, 0x36)
    if entsize < 56 or not _skip_to(stream, phoff, 64):
        return None
    table = stream.read(entsize * count)
    rows = [struct.unpack_from("<IIQQ8xQ", table, i * entsize) for i in range(len(table) // entsize)]
    return rows, phoff + len(table)


def core_files(stream) -> list:
    """[(start, end, file)] of the core's NT_FILE note: which of the memory
    is mapped from which file. procdump2 writes the note after the memory,
    so this is a pass of its own over a stream read forwards."""
    found = _core_headers(stream)
    if found is None:
        return []
    rows, at = found
    note = next(((offset, size) for kind, _, offset, _, size in rows if kind == 4 and size), None)
    if note is None or note[1] > 16 << 20 or not _skip_to(stream, note[0], at):
        return []
    raw = stream.read(note[1])
    try:
        namesz, descsz, kind = struct.unpack_from("<III", raw, 0)
        desc = 12 + ((namesz + 3) & ~3)
        if kind != 0x46494C45:                                   # NT_FILE
            return []
        count, _ = struct.unpack_from("<QQ", raw, desc)
        count = min(count, 1 << 16)
        spans = [struct.unpack_from("<QQ", raw, desc + 16 + 24 * i) for i in range(count)]
        names = raw[desc + 16 + 24 * count:desc + descsz].split(b"\0")
    except struct.error:
        return []
    return [(start, end, name.decode("utf-8", "replace")) for (start, end), name in zip(spans, names)]


def _same_file(a: str, b: str) -> bool:
    return a.removesuffix(" (deleted)") == b.removesuffix(" (deleted)")


def program_ranges(rows: list, files: list, base: int, path: str) -> list:
    """The program's own memory in a core, as (offset in the core, vaddr,
    size, executable): from its base up, and what lies low (LOW_MEMORY) --
    neither part mapped from a file that is not its own. Low anonymous memory
    is where a packer like UPX writes the program it unpacks."""
    wanted = []
    for kind, flags, offset, vaddr, filesz in rows:
        if kind != 1 or not filesz:
            continue
        if not (base <= vaddr < base + SPAN or vaddr < LOW_MEMORY):
            continue
        mapped = next((name for start, end, name in files if start <= vaddr < end), None)
        if mapped is not None and not _same_file(mapped, path):
            continue
        wanted.append((offset, vaddr, filesz, bool(flags & 1)))
    return sorted(wanted)


def read_core(opener: Callable, base: int, path: str = "") -> tuple:
    """(data, [(virtual address, offset in data, size, executable)]) of the
    program's memory in a core (program_ranges). `opener` gives the dump
    from its start, once for its file map and once for its memory. procdump2
    writes ELF64 whatever the process, its memory in program-header order."""
    with opener() as stream:
        files = core_files(stream)
    with opener() as stream:
        return _read_ranges(stream, base, path, files)


def _read_ranges(stream, base: int, path: str, files: list) -> tuple:
    found = _core_headers(stream)
    if found is None:
        return b"", []
    rows, at = found
    wanted = program_ranges(rows, files, base, path)
    data, ranges = bytearray(), []
    for offset, vaddr, size, executable in sorted(wanted):
        if len(data) + size > MAX_IMAGE or not _skip_to(stream, offset, at):
            break
        chunk = stream.read(size)
        at = offset + len(chunk)
        ranges.append((vaddr, len(data), len(chunk), executable))
        data += chunk
    return bytes(data), ranges


def core_image(data: bytes, ranges: list, base: int, like: Optional[sh.Image]) -> Optional[sh.Image]:
    """The locators' view of an executable's memory. `like`: the sample's own
    image when this is a process of it, for what the memory does not say."""
    if not ranges:
        return None
    if like is not None and like.kind != "elf":
        like = None
    bits = like.bits if like is not None else 64
    linked_at = like.base if like is not None else None
    for vaddr, start, size, _ in ranges:
        if vaddr == base and data[start:start + 4] == b"\x7fELF" and size >= 20:
            bits = 32 if data[start + 4] == 1 else 64
            if struct.unpack_from("<H", data, start + 18)[0] not in (3, 62):      # EM_386, EM_X86_64
                return None
            if linked_at is None:
                # A position-independent program is linked from 0; another is where it was linked
                linked_at = 0 if struct.unpack_from("<H", data, start + 16)[0] == 3 else base
    image = sh.Image("elf", bits, base=base)
    image.code = [(vaddr, start, data[start:start + size]) for vaddr, start, size, executable in ranges if executable]
    image.static = True
    image.moved = base - linked_at if linked_at is not None else 0
    return image if image.code else None


# --- Windows: a minidump, and the image whose header is the sample's ----------

def pe_header(page: bytes) -> Optional[dict]:
    """What identifies and lays out a PE, from its first page: the file's, or
    the mapped image's (the same bytes but for ImageBase)."""
    try:
        if page[:2] != b"MZ":
            return None
        pe, = struct.unpack_from("<I", page, 0x3C)
        if page[pe:pe + 4] != b"PE\0\0":
            return None
        machine, nsections, stamp = struct.unpack_from("<HHI", page, pe + 4)
        optsize, characteristics = struct.unpack_from("<HH", page, pe + 20)
        opt = pe + 24
        magic, = struct.unpack_from("<H", page, opt)
        if machine not in (0x14C, 0x8664) or magic not in (0x10B, 0x20B):
            return None
        plus = magic == 0x20B
        image_base, = struct.unpack_from("<Q" if plus else "<I", page, opt + (24 if plus else 28))
        size_of_image, = struct.unpack_from("<I", page, opt + 56)
        ndirs, = struct.unpack_from("<I", page, opt + (108 if plus else 92))
        relocs = struct.unpack_from("<II", page, opt + (112 if plus else 96) + 5 * 8) if ndirs > 5 else (0, 0)
        sections = []
        for i in range(min(nsections, 96)):
            at = opt + optsize + 40 * i
            vsize, va, rawsize = struct.unpack_from("<III", page, at + 8)
            flags, = struct.unpack_from("<I", page, at + 36)
            sections.append((va, max(vsize, rawsize), flags))
        return {"bits": 64 if plus else 32, "stamp": stamp, "size": size_of_image, "base": image_base,
                "dll": bool(characteristics & 0x2000), "relocs": relocs, "sections": sections}
    except struct.error:
        return None


def windows_images(trace_log: Path, module: str) -> dict:
    """pid -> base of the sample's image in each process whose image it is:
    apimon's `dll_discovered` for the module (the EXE is offered to the hook
    lists like a DLL), in a process the trace names after the sample. Other
    processes map the file as an image too -- explorer for its icon, the
    antivirus to scan it -- and are not the sample. {} without apimon."""
    want = module.lower()
    needle = module.rsplit("\\", 1)[-1].encode()
    bases: dict = {}
    pids: set = set()
    try:
        with trace_log.open("rb") as fh:
            for line in fh:
                if needle not in line:
                    continue
                try:
                    record = json.loads(line)
                    pid = int(record["PID"])
                except (ValueError, KeyError, TypeError):
                    continue
                name = record.get("ProcessName")
                if isinstance(name, str) and sh.module_name(sh.Image("pe", 64), name).lower() == want:
                    pids.add(pid)
                if (record.get("Plugin") == "apimon" and record.get("Event") == "dll_discovered"
                        and str(record.get("DllName", "")).lstrip("\\").lower() == want):
                    try:
                        bases.setdefault(pid, int(str(record["DllBase"]), 16))
                    except (KeyError, ValueError):
                        continue
    except OSError:
        pass
    return {pid: base for pid, base in bases.items() if pid in pids}


def read_minidump(stream, sample: dict, base: Optional[int] = None) -> tuple:
    """(base, the mapped image, its header) of the sample in a procdump2
    minidump. With `base` (windows_images), the range there, whatever its
    first page holds: a packer may wipe its header or put the payload's in
    its place; the sample's own layout then stands in for a wiped one.
    Without, the range that starts with the sample's own header. The memory
    list has one range a VAD, the memory following in that order (win.cpp)."""
    nothing = (0, b"", None)
    head = stream.read(32)
    if len(head) < 32 or head[:4] != b"MDMP":
        return nothing
    nstreams, directory = struct.unpack_from("<II", head, 8)
    if not _skip_to(stream, directory, 32):
        return nothing
    entries = stream.read(12 * min(nstreams, 64))
    at = directory + len(entries)
    where = next((struct.unpack_from("<III", entries, i)[2] for i in range(0, len(entries) - 11, 12)
                  if struct.unpack_from("<I", entries, i)[0] == 5), None)      # MemoryListStream
    if where is None or not _skip_to(stream, where, at):
        return nothing
    raw = stream.read(4)
    if len(raw) < 4:
        return nothing
    count = min(struct.unpack("<I", raw)[0], 1 << 16)
    table = stream.read(16 * count)
    at = where + 4 + len(table)
    if len(table) < 16:
        return nothing
    # The descriptors' own offsets are 32 bits and a dump is not: counted here
    offset = struct.unpack_from("<I", table, 12)[0]
    for i in range(len(table) // 16):
        start, size = struct.unpack_from("<QI", table, 16 * i)
        if base is not None:
            if start == base and size >= 0x1000 and _skip_to(stream, offset, at):
                page = stream.read(0x1000)
                header = pe_header(page) or sample
                return start, page + stream.read(min(header["size"], size, MAX_IMAGE) - len(page)), header
        elif size >= 0x1000 and size >= sample["size"] and _skip_to(stream, offset, at):
            page = stream.read(0x1000)
            at = offset + len(page)
            header = pe_header(page)
            # A sample that is a DLL is some host's module, and found the same way
            if (header and header["dll"] == sample["dll"] and header["stamp"] == sample["stamp"]
                    and header["size"] == sample["size"]):
                return start, page + stream.read(min(header["size"], size, MAX_IMAGE) - len(page)), header
        offset += size
    return nothing


def relocated(data: bytes, header: dict) -> set:
    """RVAs of the bytes the loader rewrites for where the image is: the
    relocation directory, when the mapped image still has one."""
    rva, size = header["relocs"]
    found: set = set()
    end = min(rva + size, len(data))
    while rva and rva + 8 <= end and len(found) < 8_000_000:
        page, block = struct.unpack_from("<II", data, rva)
        if block < 8 or rva + block > end:
            break
        for entry in struct.unpack_from(f"<{(block - 8) // 2}H", data, rva + 8):
            width = {3: 4, 10: 8}.get(entry >> 12)
            if width:
                found.update(range(page + (entry & 0xFFF), page + (entry & 0xFFF) + width))
        rva += block
    return found


def minidump_image(base: int, data: bytes, sample: dict, header: Optional[dict] = None) -> Optional[sh.Image]:
    header = header or pe_header(data[:0x1000])
    if header is None:
        return None
    image = sh.Image("pe", header["bits"], base=base)
    image.code = [(base + va, va, data[va:va + size]) for va, size, flags in header["sections"]
                  if flags & 0x20000000 and va < len(data)]
    image.static = True
    image.moved = base - sample["base"]
    image.relocated = relocated(data, header)
    return image if image.code else None


# --- from an image to lines ---------------------------------------------------

def when(image: sh.Image, data: bytes) -> Callable[[int], str]:
    """The `when:` marker of the function at an address: its first bytes as
    the memory has them. "" for what cannot be told from anything else: too
    short, or nothing in it that is the same in every run."""
    moving = image.relocated

    def marker(address: int) -> str:
        for va, start, code in image.code:
            if va <= address < va + len(code):
                raw = data[start + address - va:start + address - va + WHEN_BYTES]
                break
        else:
            return ""
        fixed = [address - image.base + i not in moving for i in range(len(raw))]
        if sum(fixed) < MIN_FIXED or not any(byte for byte, keep in zip(raw, fixed) if keep):
            return ""
        return "when:" + "".join(f"{byte:02x}" if keep else "??" for byte, keep in zip(raw, fixed))
    return marker


def locate(image: sh.Image, data: bytes, flirt_dir: Path, yara_dir: Path) -> list:
    """`samplehooks.locate_in`, and Go's table read where the program was
    linked: its addresses are the linker's, and the memory is elsewhere when
    the program was moved (a PIE; a PE under ASLR)."""
    image.toolchain = sh.toolchain(data)
    located = sh.locate_in(image, data, flirt_dir, yara_dir)
    moved = image.moved
    if image.toolchain == "go" and moved and not image.go_table:
        linked = sh.Image(image.kind, image.bits, base=image.base - moved)
        linked.code = [(va - moved, start, code) for va, start, code in image.code]
        seen = {found.offset for found in located}
        located += [sh.Located(found.name, found.offset + moved, found.how)
                    for found in sh.from_gopclntab(linked, data) if found.offset + moved not in seen]
        image.go_table, image.go_version = linked.go_table, linked.go_version
    return located


def listed(text: str, module: str) -> set:
    """The offsets a list already has a line for in `module`."""
    offsets = set()
    for line in text.splitlines():
        fields = line.split(",")
        if len(fields) > 3 and fields[0] == module:
            try:
                offsets.add(int(fields[2], 16))
            except ValueError:
                pass
    return offsets


def is_module(path: str, guest_path: str) -> Optional[str]:
    """The hook-list module of a Linux process's executable when it is the
    sample's to follow: the sample itself, as the job's list names it, or a
    program in memory, as libmon names it. None for any other program."""
    if path == guest_path or path.endswith("/" + guest_path.lstrip("/")):
        return guest_path
    if path.startswith(("/memfd:", "memfd:")):
        return path
    return None


def hints(how: str, procdumps: Path, trace_log: Path, sample: Path, guest_path: str,
          list_text: str, known: dict, go: dict, flirt_dir: Path, yara_dir: Path) -> tuple:
    """(lines, report) from every dump that is a process of the sample."""
    try:
        own = sh.read_image(sample)
    except Exception:  # noqa: BLE001 - a sample no parser reads has no image to find
        own = None
    executables = linux_executables(trace_log) if how == "core" else {}
    facts = pe_header(sample.read_bytes()[:0x1000]) if how == "minidump" else None
    lines, report, have = [], [], {}
    if how == "minidump" and facts is None:
        return lines, report        # not a program whose image a dump could hold
    images = (windows_images(trace_log, sh.module_name(sh.Image("pe", facts["bits"]), guest_path))
              if how == "minidump" else {})

    # The sample's dumps, picked before any is read: procdump2 dumps every
    # process that exits, and a job's hundred dumps of the guest's services
    # are newer than the sample's own (job ac66493d, 2026-11-15: its one
    # dump was the 118th). Linux: a process libmon saw running the sample.
    # Windows: one apimon saw with the sample as its image, else every dump,
    # looked into for the sample's header.
    def wanted(pid: int) -> bool:
        if how == "core":
            path, base = executables.get(pid, ("", 0))
            return bool(base) and is_module(path, guest_path) is not None
        return not images or pid in images
    picked = [dump for dump in sidecars(procdumps) if wanted(dump[0])][:MAX_DUMPS]

    for pid, dump, compression in picked:
        entry = {"pid": pid, "dump": dump.name}
        stream = _open(dump, compression)
        if stream is None:
            report.append({**entry, "skipped": f"{compression} is not read"})
            continue
        stream.close()
        if how == "core":
            path, base = executables[pid]
            module = is_module(path, guest_path)
            data, ranges = read_core(lambda: _open(dump, compression), base, path)
            image = core_image(data, ranges, base, own if module == guest_path else None)
        else:
            module = sh.module_name(sh.Image("pe", facts["bits"]), guest_path)
            with _open(dump, compression) as stream:
                base, data, header = read_minidump(stream, facts, images.get(pid))
            if not data:
                if pid in images:
                    report.append({**entry, "module": module, "base": images[pid],
                                   "skipped": "the image is not in the dump"})
                continue
            image = minidump_image(base, data, facts, header)
        entry.update(module=module, base=base)
        if image is None:
            report.append({**entry, "skipped": "no code of the program in the dump"})
            continue
        located = locate(image, data, flirt_dir, yara_dir)
        offsets = have.setdefault(module, listed(list_text, module))
        new = [line for line in sh.sample_lines(located, known, module, image.base, go, sh.go_abi(image),
                                                when(image, data))
               if int(line.split(",")[2], 16) not in offsets]
        offsets.update(int(line.split(",")[2], 16) for line in new)
        lines += new
        by_how: dict = {}
        for found in located:
            by_how[found.how.split(":", 1)[0]] = by_how.get(found.how.split(":", 1)[0], 0) + 1
        report.append({**entry, "toolchain": image.toolchain or None, "signature_sets": image.sets,
                       "found": by_how, "hooked": len(new),
                       "functions": [{"name": line.split(",")[1], "offset": int(line.split(",")[2], 16)}
                                     for line in new]})
    return lines[:sh.MAX_HOOKS], report


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m sandboxd.stagehints")
    p.add_argument("--procdumps", type=Path, required=True, help="the first run's procdump2 directory")
    p.add_argument("--trace-log", type=Path, required=True, help="the first run's trace")
    p.add_argument("--sample", type=Path, required=True)
    p.add_argument("--guest-path", required=True, help="the sample's path in the guest")
    p.add_argument("--list", type=Path, required=True, help="the first run's hook list: what is hooked already")
    p.add_argument("--how", choices=("core", "minidump"), required=True,
                   help="what procdump2 writes for this guest (guests.PROCESS_DUMPS)")
    p.add_argument("--out", type=Path, required=True, help="the lines; not written when there are none")
    p.add_argument("--json", type=Path, help="what was found, for the report")
    p.add_argument("--flirt", type=Path, default=sh.FLIRT_DIR)
    p.add_argument("--code-signatures", type=Path, default=sh.CODE_SIGNATURES_DIR)
    p.add_argument("--go-hooks", type=Path, default=sh.GO_HOOKS)
    p.add_argument("--max-mib", type=int, default=2048, help="RLIMIT_DATA in MiB; 0 sets no limit")
    args = p.parse_args(argv)
    if args.max_mib > 0:
        limit = args.max_mib << 20
        resource.setrlimit(resource.RLIMIT_DATA, (limit, limit))

    list_text = args.list.read_text()
    go = sh.go_hooks(args.go_hooks.read_text()) if args.go_hooks.is_file() else {}
    lines, report = [], []
    try:
        lines, report = hints(args.how, args.procdumps, args.trace_log, args.sample, args.guest_path,
                              list_text, sh.static_hooks(list_text), go, args.flirt, args.code_signatures)
    except Exception as exc:  # noqa: BLE001 - no hints is one run, as every job was
        print(f"stagehints: {type(exc).__name__}: {exc}", file=sys.stderr)
        lines = []
    if lines:
        args.out.write_text("\n".join(lines) + "\n")
    if args.json:
        args.json.write_text(json.dumps({"hooked": len(lines), "dumps": report}))
    print(f"stagehints: {len(report)} dumps of the sample read, {len(lines)} functions to hook in a second run")
    return 0


if __name__ == "__main__":
    sys.exit(main())
