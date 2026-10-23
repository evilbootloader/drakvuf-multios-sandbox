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
