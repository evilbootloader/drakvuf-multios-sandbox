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
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None


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

        versioninfo = []
        for info in getattr(pe, "FileInfo", []) or []:
            for entry in info if isinstance(info, list) else [info]:
                for table in getattr(entry, "StringTable", []) or []:
                    for key, value in table.entries.items():
                        versioninfo.append({"name": _text(key), "value": _text(value)})

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
