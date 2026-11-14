"""The sample itself: `results["target"]["file"]`, as CAPE's static pass
fills it -- hashes, type, YARA, and for a PE the header fields signatures
read.

The PE part follows CAPEv2 lib/cuckoo/common/integrations/parse_pe.py
(c7f57d04) in the names and formats of what it emits, with pefile alone:
`sections` (the most-read field: the packer signatures), `imports`,
`exports`, `versioninfo`, `overlay`, `imphash`, `timestamp`, `entrypoint`,
`imagebase`, `pdbpath`. Not ported: the Authenticode signers (`digital_signers`
is an empty list, which reads as "unsigned" -- KNOWN GAP), PEiD signatures,
resources and the icon fields.

**An ELF** (`elf_info`, added 2026-11-14) follows CAPEv2's
lib/cuckoo/common/integrations/parse_elf.py in its names: `file_header`,
`section_headers`, `program_headers`, `dynamic_tags`, `symbol_tables`,
`notes`, stored as `target.file["elf"]` -- the key CAPE's own (commented-out)
call in file_extra_info.py would use. Upstream never calls it, so no
signature reads it and adding it moves no score. Not ported: `relocations`,
which upstream builds into a `set()` of dicts and would raise on any ELF that
has one. Added beside CAPE's fields, each a superset: offsets, flags and
entropy per section, the interpreter, the NEEDED libraries, the build-id, and
each symbol's section (`UND` is an import). Every list is bounded, since the
counts are the sample's to choose.

**Every file** (`file_static`) gets what does not depend on its format: the
entropy of its bytes, its printable strings and the indicators among them,
an archive's member list (APK, JAR, OOXML, ZIP -- the central directory only,
nothing is inflated), and a text file's first characters. Under
`target.file["static"]`, a key of ours that no CAPE signature reads: a URL in
a sample's strings must not become a verdict by the back door.
"""
from __future__ import annotations

import logging
import math
import mmap
import re
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None

try:
    from elftools.elf import descriptions as elfdesc
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import NoteSection, SymbolTableSection
except ImportError:  # pragma: no cover
    ELFFile = None

# Bounds on what one sample can make this write: a header can claim 65,535
# sections, and a stripped-of-nothing binary has tens of thousands of symbols.
MAX_SECTIONS = 1000
MAX_SYMBOLS = 5000
MAX_STRINGS = 2000
MAX_STRING_CHARS = 300
MAX_IOCS = 500
MAX_ARCHIVE_ENTRIES = 1000
# Under the platform's per-string bound (cape.py MAX_STRING, 16 KiB), so the
# preview arrives whole rather than cut a second time.
MAX_TEXT_CHARS = 16000
_CHUNK = 1 << 20


def _text(raw) -> str:
    if isinstance(raw, bytes):
        return raw.rstrip(b"\x00").decode("latin-1", "replace")
    return str(raw)


def pe_info(path: Path) -> dict:
    """{} for a file pefile will not parse."""
    if pefile is None:
        return {}
    try:
        pe = pefile.PE(str(path), fast_load=False)
    except Exception as e:  # noqa: BLE001 - pefile.PEFormatError and whatever a hostile header finds
        log.debug("%s is not a PE pefile reads: %s", path.name, e)
        return {}
    try:
        sections = [{
            "name": _text(s.Name),
            "raw_address": f"0x{s.PointerToRawData:08x}",
            "virtual_address": f"0x{s.VirtualAddress:08x}",
            "virtual_size": f"0x{s.Misc_VirtualSize:08x}",
            "size_of_data": f"0x{s.SizeOfRawData:08x}",
            "characteristics": "|".join(
                name for name, bit in (("IMAGE_SCN_CNT_CODE", 0x20), ("IMAGE_SCN_MEM_EXECUTE", 0x20000000),
                                       ("IMAGE_SCN_MEM_READ", 0x40000000), ("IMAGE_SCN_MEM_WRITE", 0x80000000))
                if s.Characteristics & bit),
            "characteristics_raw": f"0x{s.Characteristics:08x}",
            "entropy": f"{s.get_entropy():.02f}",
        } for s in pe.sections]

        imports = {}
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = _text(entry.dll)
            imports[dll.rsplit(".", 1)[0]] = {"dll": dll, "imports": [
                {"address": f"0x{imp.address:x}", "name": _text(imp.name) if imp.name else str(imp.ordinal)}
                for imp in entry.imports]}
        exports = [{"address": f"0x{pe.OPTIONAL_HEADER.ImageBase + sym.address:x}",
                    "name": _text(sym.name) if sym.name else "", "ordinal": sym.ordinal}
                   for sym in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])]

        # Each (name, value) once. pefile reads one StringTable per language
        # of the version resource, and an installer carrying 29 translations
        # of the same four strings listed them 29 times (SteamSetup.exe, job
        # bd31b474, 2026-11-14). A name whose value differs by language keeps
        # every distinct value.
        versioninfo, seen = [], set()
        for info in getattr(pe, "FileInfo", []) or []:
            for entry in info if isinstance(info, list) else [info]:
                for table in getattr(entry, "StringTable", []) or []:
                    for key, value in table.entries.items():
                        pair = (_text(key), _text(value))
                        if pair not in seen:
                            seen.add(pair)
                            versioninfo.append({"name": pair[0], "value": pair[1]})

        overlay_offset = pe.get_overlay_data_start_offset()
        overlay = None
        if overlay_offset:
            overlay = {"offset": f"0x{overlay_offset:08x}",
                       "size": f"0x{len(pe.__data__) - overlay_offset:08x}"}

        pdbpath = None
        for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
            name = getattr(getattr(dbg, "entry", None), "PdbFileName", None)
            if name:
                pdbpath = _text(name)
                break

        stamp = pe.FILE_HEADER.TimeDateStamp
        return {
            "imagebase": f"0x{pe.OPTIONAL_HEADER.ImageBase:08x}",
            # An RVA, as CAPE's and as the sections' addresses above: the
            # signatures compare the two (pe_entrypoint_outside_sections
            # fired on every PE while this held the VA)
            "entrypoint": f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}",
            "machine_type": pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)),
            "timestamp": datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "imphash": pe.get_imphash(),
            "sections": sections,
            "imports": imports,
            "imported_dll_count": len(imports),
            "exports": exports,
            "versioninfo": versioninfo,
            "overlay": overlay,
            "pdbpath": pdbpath,
            "digital_signers": [],
            "guest_signers": {},
            "resources": [],
        }
    except Exception as e:  # noqa: BLE001 - a malformed directory must not cost the target entry
        log.warning("PE fields of %s not read: %s", path.name, e)
        return {}
    finally:
        pe.close()


# --- ELF ------------------------------------------------------------------------

def _entropy(counts: Counter, total: int) -> float:
    if not total:
        return 0.0
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def elf_info(path: Path) -> dict:
    """{} for a file that is not an ELF pyelftools reads."""
    if ELFFile is None:
        return {}
    try:
        with path.open("rb") as f:
            if f.read(4) != b"\x7fELF":
                return {}
            f.seek(0)
            return _elf(ELFFile(f))
    except Exception as e:  # noqa: BLE001 - ELFError and whatever a hostile header finds
        log.warning("ELF fields of %s not read: %s", path.name, e)
        return {}


def _elf(elf) -> dict:
    width = 8 if elf.elfclass == 32 else 16

    def addr(value) -> str:
        return f"0x{value:0{width}x}"

    h = elf.header
    ident = h["e_ident"]
    machine = h["e_machine"]
    file_header = {
        "magic": "\\x7fELF",
        "class": elfdesc.describe_ei_class(ident["EI_CLASS"]),
        "data": elfdesc.describe_ei_data(ident["EI_DATA"]),
        "ei_version": elfdesc.describe_ei_version(ident["EI_VERSION"]),
        "os_abi": elfdesc.describe_ei_osabi(ident["EI_OSABI"]),
        "abi_version": ident["EI_ABIVERSION"],
        "type": elfdesc.describe_e_type(h["e_type"]),
        "machine": elfdesc.describe_e_machine(machine),
        "version": elfdesc.describe_e_version_numeric(h["e_version"]),
        "entry_point_address": addr(h["e_entry"]),
        "start_of_program_headers": h["e_phoff"],
        "start_of_section_headers": h["e_shoff"],
        "flags": addr(h["e_flags"]),
        "number_of_program_headers": h["e_phnum"],
        "number_of_section_headers": h["e_shnum"],
    }

    sections, symbols, notes, tags = [], [], [], []
    needed, symbols_total = [], 0
    soname = rpath = runpath = build_id = None
    has_symtab = has_dynamic = False
    for i, s in enumerate(elf.iter_sections()):
        if i < MAX_SECTIONS:
            entry = {"name": s.name, "type": elfdesc.describe_sh_type(s["sh_type"]),
                     "addr": addr(s["sh_addr"]), "size": s["sh_size"],
                     "offset": f"0x{s['sh_offset']:x}", "flags": elfdesc.describe_sh_flags(s["sh_flags"])}
            if s["sh_type"] != "SHT_NOBITS" and s["sh_size"]:
                data = s.data()
                entry["entropy"] = f"{_entropy(Counter(data), len(data)):.02f}"
            sections.append(entry)
        if isinstance(s, SymbolTableSection):
            has_symtab |= s.name == ".symtab"
            for sym in s.iter_symbols():
                if not sym.name:
                    continue
                symbols_total += 1
                if len(symbols) < MAX_SYMBOLS:
                    symbols.append({"value": addr(sym["st_value"]),
                                    "type": elfdesc.describe_symbol_type(sym["st_info"]["type"]),
                                    "bind": elfdesc.describe_symbol_bind(sym["st_info"]["bind"]),
                                    "ndx_name": sym.name, "table": s.name,
                                    "section": elfdesc.describe_symbol_shndx(sym["st_shndx"]).strip()})
        elif isinstance(s, DynamicSection):
            has_dynamic = True
            for tag in s.iter_tags():
                kind = str(tag.entry.d_tag)
                if kind == "DT_NULL":
                    break
                value = None
                if kind == "DT_NEEDED":
                    value = tag.needed
                    needed.append(value)
                elif kind == "DT_SONAME":
                    value = soname = tag.soname
                elif kind == "DT_RPATH":
                    value = rpath = tag.rpath
                elif kind == "DT_RUNPATH":
                    value = runpath = tag.runpath
                if len(tags) < MAX_SECTIONS:
                    tags.append({"tag": kind, "type": kind[3:],
                                 "value": value if value is not None else f"0x{tag.entry.d_val:x}"})
        elif isinstance(s, NoteSection):
            for note in s.iter_notes():
                if len(notes) >= MAX_SECTIONS:
                    break
                text = elfdesc.describe_note(note, machine)
                # Owner too: libc's stapsdt probe notes reuse type 3
                if (note["n_type"] == "NT_GNU_BUILD_ID" and note["n_name"] == "GNU"
                        and isinstance(note["n_desc"], str)):
                    build_id = note["n_desc"]
                notes.append({"owner": note["n_name"], "name": note["n_name"],
                              "size": note["n_descsz"], "type": str(note["n_type"]),
                              "note": text.strip()})

    segments, interpreter = [], None
    for i, seg in enumerate(elf.iter_segments()):
        if seg["p_type"] == "PT_INTERP":
            interpreter = seg.get_interp_name()
        if i < MAX_SECTIONS:
            segments.append({"type": elfdesc.describe_p_type(seg["p_type"]), "addr": addr(seg["p_vaddr"]),
                             "flags": elfdesc.describe_p_flags(seg["p_flags"]).strip(), "size": seg["p_memsz"],
                             "offset": f"0x{seg['p_offset']:x}", "filesz": seg["p_filesz"]})

    return {
        "file_header": file_header,
        "section_headers": sections,
        "program_headers": segments,
        "dynamic_tags": tags,
        "symbol_tables": symbols,
        "symbols_total": symbols_total,
        "notes": notes,
        "interpreter": interpreter,
        "needed": needed,
        "soname": soname,
        "rpath": rpath,
        "runpath": runpath,
        "build_id": build_id,
        "stripped": not has_symtab,
        "linking": "dynamic" if (interpreter or has_dynamic) else "static",
    }


# --- any file ---------------------------------------------------------------------

_ASCII = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
# What a reader scans a sample's strings for. Hints, not detections: a URL in
# a binary may be a certificate's or a library's.
_IOCS = (
    ("url", re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>]{4,}", re.I)),
    ("ip", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?\b")),
    ("email", re.compile(r"\b[\w.+-]{2,}@[\w-]+(?:\.[\w-]+)+\b")),
    ("registry", re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\[^\s\"']+", re.I)),
    ("path", re.compile(r"(?:\b[A-Za-z]:\\|%[A-Za-z]+%\\)[^\s\"'<>|*?]{3,}")),
    ("path", re.compile(r"(?<![\w/])/(?:bin|sbin|etc|tmp|usr|var|dev|proc|home|root|opt|lib|data|system)/[^\s\"'<>]*")),
)


def _strings(view) -> tuple[list[str], int, list[dict]]:
    """The printable runs of a file, ASCII and UTF-16LE, in file order: the
    first MAX_STRINGS, the total, and the indicators among all of them."""
    out, total, iocs, seen = [], 0, [], set()

    def take(text: str) -> None:
        nonlocal total
        total += 1
        if len(out) < MAX_STRINGS:
            out.append(text[:MAX_STRING_CHARS])
        if len(iocs) < MAX_IOCS:
            for kind, pattern in _IOCS:
                for m in pattern.finditer(text):
                    # A closing bracket or quote is the text around it
                    key = (kind, m.group(0).rstrip(")]}>,;.'\"")[:MAX_STRING_CHARS])
                    if key not in seen and len(iocs) < MAX_IOCS:
                        seen.add(key)
                        iocs.append({"kind": kind, "value": key[1]})

    for m in _ASCII.finditer(view):
        take(m.group(0).decode("ascii"))
    for m in _UTF16.finditer(view):
        take(m.group(0).decode("utf-16-le"))
    return out, total, iocs


def _archive(path: Path) -> dict | None:
    """A ZIP-family file's members, from its central directory: nothing in
    it is inflated or written anywhere."""
    try:
        if not zipfile.is_zipfile(path):
            return None
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
    except Exception as e:  # noqa: BLE001 - a broken directory is no archive to list
        log.debug("%s: archive not listed: %s", path.name, e)
        return None
    names = {i.filename for i in infos}
    kind = ("APK" if "AndroidManifest.xml" in names and any(n.endswith(".dex") for n in names)
            else "JAR" if "META-INF/MANIFEST.MF" in names
            else "OOXML" if "[Content_Types].xml" in names else "ZIP")
    return {
        "kind": kind,
        "count": len(infos),
        "encrypted": sum(1 for i in infos if i.flag_bits & 0x1),
        "entries": [{"name": i.filename[:MAX_STRING_CHARS], "size": i.file_size,
                     "compressed": i.compress_size, "encrypted": bool(i.flag_bits & 0x1),
                     "date": "%04d-%02d-%02d %02d:%02d:%02d" % i.date_time}
                    for i in infos[:MAX_ARCHIVE_ENTRIES]],
    }


def _text(head: bytes) -> str | None:
    """The opening characters of a text file (a script, a config, a batch
    file); None for one with a NUL that is not UTF-16."""
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return head.decode("utf-16", "replace")[:MAX_TEXT_CHARS]
    if b"\x00" in head[:8192]:
        return None
    text = head.decode("utf-8", "replace")
    # Mostly printable, or it is a binary format without NULs up front
    printable = sum(1 for c in text[:4096] if c.isprintable() or c in "\r\n\t")
    if printable < 0.9 * min(len(text), 4096):
        return None
    return text[:MAX_TEXT_CHARS]


def file_static(path: Path) -> dict:
    """What any file's bytes say whatever their format; {} for one that
    cannot be read."""
    try:
        size = path.stat().st_size
        counts: Counter = Counter()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(_CHUNK), b""):
                counts.update(chunk)
            if size:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as view:
                    strings, total, iocs = _strings(view)
                    head = view[:MAX_TEXT_CHARS * 4]
            else:
                strings, total, iocs, head = [], 0, [], b""
    except Exception as e:  # noqa: BLE001 - the target entry must survive a read error
        log.warning("static facts of %s not read: %s", path.name, e)
        return {}
    out = {"entropy": f"{_entropy(counts, size):.03f}", "strings": strings,
           "strings_total": total, "iocs": iocs}
    archive = _archive(path)
    if archive:
        out["archive"] = archive
    text = _text(head) if size and not archive else None
    if text is not None:
        out["text"] = text
        out["text_truncated"] = size > len(text.encode("utf-8", "replace"))
    return out
