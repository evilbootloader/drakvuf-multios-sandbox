"""filetracer's symbolic flags, back to the numbers CAPE's signatures parse.

DRAKVUF's filetracer prints NtCreateFile/NtOpenFile's access mask, share
mode, attributes, disposition and options as names joined with ` | `
(`plugin_utils.cpp::parse_flags` over the tables in
`drakvuf/src/plugins/filetracer/private.h`); capemon logs the same arguments
as hex, and signatures do `int(value, 16)` on them. The tables below are
those of private.h, transcribed 2026-11-10; `symbolic_to_hex` turns the text
back into the value, and the call keeps the text as `pretty_value`, CAPE's
own field for it.

`parse_flags` is bitmask matching -- it prints every name whose bits are all
set -- which is exact for a mask and wrong for an enumeration:
CreateDisposition FILE_OPEN_IF (3) prints as `FILE_OPEN | FILE_CREATE |
FILE_OPEN_IF`, and FILE_SUPERSEDE (0) as nothing. So a mask is the OR of its
names and an enumeration is its LAST name.
"""
from __future__ import annotations

from typing import Dict, Optional

GENERIC_ACCESS = {
    "DELETE": 0x00010000, "READ_CONTROL": 0x00020000, "WRITE_DAC": 0x00040000,
    "WRITE_OWNER": 0x00080000, "SYNCHRONIZE": 0x00100000, "ACCESS_SYSTEM_SECURITY": 0x01000000,
    "GENERIC_ALL": 0x10000000, "GENERIC_EXECUTE": 0x20000000, "GENERIC_WRITE": 0x40000000,
    "GENERIC_READ": 0x80000000, "SPECIFIC_RIGHTS_ALL": 0x0000FFFF, "STANDARD_RIGHTS_ALL": 0x001F0000,
}
FILE_ACCESS = {
    "FILE_ANY_ACCESS": 0x0, "FILE_READ_DATA": 0x1, "FILE_WRITE_DATA": 0x2, "FILE_APPEND_DATA": 0x4,
    "FILE_READ_EA": 0x8, "FILE_WRITE_EA": 0x10, "FILE_EXECUTE": 0x20, "FILE_READ_ATTRIBUTES": 0x80,
    "FILE_WRITE_ATTRIBUTES": 0x100,
}
DIRECTORY_ACCESS = {
    "FILE_LIST_DIRECTORY": 0x1, "FILE_ADD_FILE": 0x2, "FILE_ADD_SUBDIRECTORY": 0x4,
    "FILE_TRAVERSE": 0x20, "FILE_DELETE_CHILD": 0x40,
}
DESIRED_ACCESS = {**GENERIC_ACCESS, **FILE_ACCESS, **DIRECTORY_ACCESS}
SHARE_ACCESS = {"FILE_SHARE_NONE": 0x0, "FILE_SHARE_READ": 0x1, "FILE_SHARE_WRITE": 0x2,
                "FILE_SHARE_DELETE": 0x4}
CREATE_DISPOSITION = {"FILE_SUPERSEDE": 0x0, "FILE_OPEN": 0x1, "FILE_CREATE": 0x2,
                      "FILE_OPEN_IF": 0x3, "FILE_OVERWRITE": 0x4, "FILE_OVERWRITE_IF": 0x5}
CREATE_OPTIONS = {
    "FILE_DIRECTORY_FILE": 0x1, "FILE_WRITE_THROUGH": 0x2, "FILE_SEQUENTIAL_ONLY": 0x4,
    "FILE_NO_INTERMEDIATE_BUFFERING": 0x8, "FILE_SYNCHRONOUS_IO_ALERT": 0x10,
    "FILE_SYNCHRONOUS_IO_NONALERT": 0x20, "FILE_NON_DIRECTORY_FILE": 0x40,
    "FILE_CREATE_TREE_CONNECTION": 0x80, "FILE_COMPLETE_IF_OPLOCKED": 0x100,
    "FILE_NO_EA_KNOWLEDGE": 0x200, "FILE_OPEN_REMOTE_INSTANCE": 0x400, "FILE_RANDOM_ACCESS": 0x800,
    "FILE_DELETE_ON_CLOSE": 0x1000, "FILE_OPEN_BY_FILE_ID": 0x2000,
    "FILE_OPEN_FOR_BACKUP_INTENT": 0x4000, "FILE_NO_COMPRESSION": 0x8000,
    "FILE_OPEN_REQUIRING_OPLOCK": 0x10000, "FILE_RESERVE_OPFILTER": 0x100000,
    "FILE_OPEN_REPARSE_POINT": 0x200000, "FILE_OPEN_NO_RECALL": 0x400000,
    "FILE_OPEN_FOR_FREE_SPACE_QUERY": 0x800000,
}
FILE_ATTRIBUTES = {
    "FILE_ATTRIBUTE_READONLY": 0x1, "FILE_ATTRIBUTE_HIDDEN": 0x2, "FILE_ATTRIBUTE_SYSTEM": 0x4,
    "FILE_ATTRIBUTE_DIRECTORY": 0x10, "FILE_ATTRIBUTE_ARCHIVE": 0x20, "FILE_ATTRIBUTE_DEVICE": 0x40,
    "FILE_ATTRIBUTE_NORMAL": 0x80, "FILE_ATTRIBUTE_TEMPORARY": 0x100,
    "FILE_ATTRIBUTE_SPARSE_FILE": 0x200, "FILE_ATTRIBUTE_REPARSE_POINT": 0x400,
    "FILE_ATTRIBUTE_COMPRESSED": 0x800, "FILE_ATTRIBUTE_OFFLINE": 0x1000,
    "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED": 0x2000, "FILE_ATTRIBUTE_ENCRYPTED": 0x4000,
    "FILE_ATTRIBUTE_INTEGRITY_STREAM": 0x8000, "FILE_ATTRIBUTE_VIRTUAL": 0x10000,
    "FILE_ATTRIBUTE_NO_SCRUB_DATA": 0x20000, "FILE_ATTRIBUTE_RECALL_ON_OPEN": 0x40000,
    "FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS": 0x400000,
    "FILE_FLAG_OPEN_NO_RECALL": 0x00100000, "FILE_FLAG_OPEN_REPARSE_POINT": 0x00200000,
    "FILE_FLAG_POSIX_SEMANTICS": 0x01000000, "FILE_FLAG_BACKUP_SEMANTICS": 0x02000000,
    "FILE_FLAG_DELETE_ON_CLOSE": 0x04000000, "FILE_FLAG_SEQUENTIAL_SCAN": 0x08000000,
    "FILE_FLAG_RANDOM_ACCESS": 0x10000000, "FILE_FLAG_NO_BUFFERING": 0x20000000,
    "FILE_FLAG_OVERLAPPED": 0x40000000, "FILE_FLAG_WRITE_THROUGH": 0x80000000,
}
OBJECT_ATTRIBUTES = {
    "OBJ_INHERIT": 0x2, "OBJ_PERMANENT": 0x10, "OBJ_EXCLUSIVE": 0x20, "OBJ_CASE_INSENSITIVE": 0x40,
    "OBJ_OPENIF": 0x80, "OBJ_OPENLINK": 0x100, "OBJ_KERNEL_HANDLE": 0x200,
    "OBJ_FORCE_ACCESS_CHECK": 0x400, "OBJ_VALID_ATTRIBUTES": 0x7F2,
}

# filetracer argument -> (table, is an enumeration). `ObjectAttributes` here
# is the OBJ_* flags filetracer prints under that name, not the path the
# syscall plugin resolves under it.
FILETRACER_FLAGS = {
    "DesiredAccess": (DESIRED_ACCESS, False),
    "ShareAccess": (SHARE_ACCESS, False),
    "FileAttributes": (FILE_ATTRIBUTES, False),
    "CreateDisposition": (CREATE_DISPOSITION, True),
    "CreateOptions": (CREATE_OPTIONS, False),
    "OpenOptions": (CREATE_OPTIONS, False),
    "ObjectAttributes": (OBJECT_ATTRIBUTES, False),
}


def flags_to_int(text: str, table: Dict[str, int], enumeration: bool = False) -> Optional[int]:
    """The value `text` (`A | B | C`) names in `table`; None when a name is
    not in it, so a value that was never symbolic is left alone."""
    names = [n.strip() for n in text.split("|") if n.strip()]
    if not names:
        return 0
    value = 0
    for name in names:
        bits = table.get(name)
        if bits is None:
            return None
        value = bits if enumeration else value | bits
    return value


def symbolic_to_hex(arguments: list) -> list:
    """filetracer's `{name, value}` arguments with each symbolic flag
    replaced by its hex value, the text kept as `pretty_value`."""
    for arg in arguments:
        spec = FILETRACER_FLAGS.get(arg.get("name"))
        value = arg.get("value")
        if spec is None or not isinstance(value, str) or value.startswith("0x"):
            continue
        number = flags_to_int(value, *spec)
        if number is not None:
            arg["pretty_value"] = value
            arg["value"] = f"0x{number:08x}"
    return arguments
