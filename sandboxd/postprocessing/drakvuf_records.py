"""How DRAKVUF writes a string argument, for every reader of its records.

Here rather than in `capa_processor`, which imports capa and vivisect at the
top: `falco` reads libmon's string arguments the same way and must not pay
for capa to do it.
"""
import re

# `[0xADDR:]"escaped string"` -- what DRAKVUF's string printers emit for an
# argument (`libusermode/printers/printers.cpp::StringPrinterInterface::print`).
# The address half is absent under `--userhook-no-addr`; the quotes never are.
DRAKVUF_STRING_ARG = re.compile(r'\A(?:0x[0-9a-fA-F]+:)?"(.*)"\Z', re.S)

# DRAKVUF's own escaping, from `printers/utils.cpp::escape_str` and pinned by
# its tests in `printers/check.cpp`: backslash, tab, CR, LF and double quote
# get a backslash, anything below 0x20 becomes `\xHH`, UTF-8 passes through.
# Not JSON escaping -- JSON has no `\xHH` -- so `json.loads` cannot do this.
_UNESCAPE = {"\\\\": "\\", "\\t": "\t", "\\r": "\r", "\\n": "\n", "\\\"": "\""}
_ESCAPE_SEQ = re.compile(r"\\\\|\\t|\\r|\\n|\\\"|\\x([0-9A-Fa-f]{2})")


def unescape_drakvuf(text: str) -> str:
    def sub(m: "re.Match[str]") -> str:
        if m.group(1) is not None:
            return chr(int(m.group(1), 16))
        return _UNESCAPE[m.group(0)]

    return _ESCAPE_SEQ.sub(sub, text)


# The same value WITH its address, and only then: `0xADDR:"escaped string"`.
# For a reader of records that also carry values DRAKVUF appended as they
# are -- apimon's resolved `FileName=`, `Key=`, `CommandLine=` -- where a
# value that merely starts and ends with a quote (a command line does) is
# not an escaped string and must not be unescaped. sandboxd never passes
# `--userhook-no-addr`, so a printed string always has the address.
DRAKVUF_ADDRESSED_STRING = re.compile(r'\A0x[0-9a-fA-F]+:"(.*)"\Z', re.S)

# procmon prints a command line through GLib's `g_strescape` (procmon/win.cpp),
# not through the printers above: backslash, quote and `\b \f \n \r \t \v` get
# a backslash, and every other byte below 0x20 or above 0x7e becomes three
# octal digits -- a non-ASCII character is the octal of its UTF-8 bytes.
_GLIB_ESCAPE = re.compile(rb"\\([0-7]{1,3}|.)", re.S)
_GLIB_SIMPLE = {b"b": b"\b", b"f": b"\f", b"n": b"\n", b"r": b"\r", b"t": b"\t", b"v": b"\v"}


def unescape_glib(text: str) -> str:
    """The inverse of `g_strescape` (GLib's `g_strcompress`), over the UTF-8
    bytes so an escaped multi-byte character comes back as one character."""
    def sub(m: "re.Match[bytes]") -> bytes:
        token = m.group(1)
        if token[:1].isdigit():
            return bytes([int(token, 8) & 0xFF])
        return _GLIB_SIMPLE.get(token, token)

    return _GLIB_ESCAPE.sub(sub, text.encode("utf-8", "surrogateescape")).decode("utf-8", "replace")
