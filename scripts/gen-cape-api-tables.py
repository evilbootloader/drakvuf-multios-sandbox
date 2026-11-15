#!/usr/bin/env python3
"""Generate what CAPE knows about each Windows API DRAKVUF can record:
its category, and the names CAPE gives its arguments.

    scripts/gen-cape-api-tables.py --capemon <capemon> --cuckoo-monitor <monitor> \\
        --logtbl <CAPEv2>/lib/cuckoo/common/logtbl.py \\
        --win32json <win32json> --phnt <phnt>
    scripts/gen-cape-api-tables.py ... --check    # exit 1 if a table is stale
    scripts/gen-cape-api-tables.py ... --report   # coverage and unresolved names

Writes `cape_plugin/data/api_categories.json` and `api_arguments.json` (under
sandboxd/postprocessing/plugins/), read by `cape_plugin/api_tables.py`. **Not one of the suite-enforced
generators**, for gen-hook-lists.py's reason: none of its five inputs is in
the repository, so the output is committed and `sandboxd/tests` pins
invariants of it instead. Re-run it when hooks.txt changes.

Every name gets the category of the FIRST source that knows it:

1. **capemon** -- CAPE's own monitor. The category is the first argument of
   each `LOQ_*("category", ...)` in a `HOOKDEF` body (`hook_*.c`); this is
   literally what CAPE's reports carry, so its spellings are the vocabulary
   every other source is renamed into.
2. **Cuckoo monitor** `sigs/*.rst`, one `Category:` per file; it adds
   netapi, certificate, resource and ole.
3. **CAPEv2 `logtbl.py`**, CAPE's hand-kept fallback table.
4. **win32json**, the API's namespace (`Networking.WinSock` -> network),
   with name rules where a namespace mixes subjects (`System.Threading` holds
   CreateProcess, CreateThread and WaitForSingleObject).
5. **phnt**, the header that declares a native API (`ntregapi.h` -> registry).
6. **the DLL hooks.txt hooks it in**, for names nothing above knows.

The names are those hooks.txt hooks, every native API phnt declares (the
syscall plugin records any of them), and every name the three CAPE/Cuckoo
sources categorise. Names are keyed by `api_tables.canonical` (A/W dropped,
Zw read as Nt), loaded from the module by path so the two cannot drift.

**Argument names** come from capemon alone: in each `HOOKDEF`, every
`LOQ_*(..., "Name", expr, ...)` whose value is one of the hook's own
parameters, as it stands, maps that parameter to the name CAPE logs it under
(`lpSubKey` -> `SubKey`). The prototype names are Microsoft's on both sides
-- capemon's hook signatures and DRAKVUF's hook list (win32metadata, phnt)
-- which is what makes the match by name sound. A value capemon computes
(`FullName` from a handle and a subkey) has no parameter to map from and is
not here. The format string says how many values each name takes
(`_LOQ_ARITY`, from capemon's log.c `loq`); for a buffer, the parameter is
the last of them, after its length.
"""
from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAPE = ROOT / "sandboxd" / "postprocessing" / "plugins" / "cape_plugin"
OUT = CAPE / "data" / "api_categories.json"
OUT_ARGS = CAPE / "data" / "api_arguments.json"
OUT_OUTPUTS = CAPE / "data" / "api_outputs.json"
HOOKS = ROOT / "sandboxd" / "data" / "hooks.txt"

_spec = importlib.util.spec_from_file_location("_api_tables", CAPE / "api_tables.py")
_api_tables = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_api_tables)
canonical = _api_tables.canonical

# capemon's spellings, plus what the other sources call the same thing.
RENAME = {
    "file": "filesystem", "synchronisation": "synchronization", "ui": "windows",
    "iexplore": "browser", "exception": "system", "office": "misc", "socket": "network",
    "go_crypto": "crypto", "go_tls": "network", "go_trace": "misc",
}


def rev(path: Path) -> str:
    out = subprocess.run(["git", "-C", str(path), "rev-parse", "--short", "HEAD"],
                         capture_output=True, text=True, check=False).stdout.strip()
    return out or "revision UNRECORDED"


# -- 1. capemon ---------------------------------------------------------------

_HOOKDEF = re.compile(r"^HOOKDEF(?:_ALT)?\(\s*[^,]+,\s*[^,]+,\s*(\w+)|^HOOKDEF_NOTAIL\(\s*[^,]+,\s*(\w+)")
_LOQ = re.compile(r'\bLOQ_\w+\(\s*"(\w+)"')


def from_capemon(capemon: Path) -> dict[str, str]:
    """Each HOOKDEF's first LOQ category. A body that logs under two
    categories (NtDeviceIoControlFile: device, and network for AFD) keeps
    the first."""
    out: dict[str, str] = {}
    for src in sorted(capemon.glob("hook_*.c")):
        api = None
        for line in src.read_text(errors="replace").splitlines():
            m = _HOOKDEF.match(line)
            if m:
                api = m.group(1) or m.group(2)
                continue
            if api:
                m = _LOQ.search(line)
                if m:
                    out.setdefault(canonical(api), RENAME.get(m.group(1), m.group(1)))
    return out


# Values each `loq` format character reads (capemon log.c, the second switch
# of `loq`): a length and a buffer, a registry handle and a subkey, or a
# type, size and data. Every other character reads one.
_LOQ_ARITY = {c: 2 for c in "SUbBcCeEkvVaA"} | {"r": 3, "R": 3}
# A registry handle and a subkey logged as ONE path capemon resolves
# (`FullName`): no parameter holds that value, so it is not an alias of
# the subkey.
_LOQ_COMPUTED = set("eEkvV")
# Read THROUGH the pointer, after the call: a pointer-sized value (P, L), a
# 32-bit one (I, H), a 64-bit one (X). What capemon logs under these is the
# call's output; what DRAKVUF's syscall plugin prints for the same argument,
# at entry, is the address of the caller's variable.
_LOQ_DEREF = {"P": "ptr", "L": "ptr", "I": "u32", "H": "u32", "X": "u64"}


def _split_top(text: str) -> list[str]:
    """`text` split on the commas outside parentheses and string literals."""
    out, cur, depth, quoted, i = [], [], 0, False, 0
    while i < len(text):
        ch = text[i]
        if quoted:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(text):
                i += 1
                cur.append(text[i])
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    if "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


def _balanced(text: str) -> str:
    """`text` up to the parenthesis closing the one just before it."""
    depth = 1
    for i, ch in enumerate(text):
        depth += {"(": 1, ")": -1}.get(ch, 0)
        if depth == 0:
            return text[:i]
    return text


_HOOKDEF_START = re.compile(r"^HOOKDEF(?:_ALT)?\(\s*[^,]+,\s*[^,]+,\s*(\w+)|"
                            r"^HOOKDEF_NOTAIL\(\s*[^,]+,\s*(\w+)", re.M)


def capemon_arguments(capemon: Path) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    """`{canonical api: {parameter: CAPE's name}}`, where they differ, and
    `{canonical api: {name: width}}` for the output arguments -- under the
    parameter's name and under CAPE's."""
    out: dict[str, dict[str, str]] = {}
    outputs: dict[str, dict[str, str]] = {}
    for src in sorted(capemon.glob("hook_*.c")):
        text = src.read_text(errors="replace")
        starts = list(_HOOKDEF_START.finditer(text))
        for k, m in enumerate(starts):
            api = m.group(1) or m.group(2)
            body = text[m.end():starts[k + 1].start() if k + 1 < len(starts) else len(text)]
            # HOOKDEF(ret, conv, name, params...) -- the rest of the macro's
            # arguments are the parameters, each `[annotations] type name`.
            sig = _balanced(body)
            params = {mm.group(1) for p in _split_top(sig)
                      if (mm := re.search(r"(\w+)\s*(?:\[\s*\])?\s*$", p))}
            names = out.setdefault(canonical(api), {})
            for loq in re.finditer(r"\bLOQ_\w+\(", body[len(sig):]):
                args = _split_top(_balanced(body[len(sig) + loq.end():]))
                if len(args) < 2 or not args[1].startswith('"'):
                    continue
                fmt, values = args[1].strip('"'), args[2:]
                for ch in fmt:
                    n = _LOQ_ARITY.get(ch, 1)
                    if len(values) < 1 + n:
                        break
                    name, exprs, values = values[0].strip('"'), values[1:1 + n], values[1 + n:]
                    if ch in _LOQ_COMPUTED:
                        continue
                    expr = exprs[-1].strip().lstrip("&*(").rstrip(")").strip()
                    is_param = bool(re.fullmatch(r"\w+", expr)) and expr in params
                    if ch in _LOQ_DEREF:
                        outs = outputs.setdefault(canonical(api), {})
                        outs.setdefault(name, _LOQ_DEREF[ch])
                        if is_param:
                            outs.setdefault(expr, _LOQ_DEREF[ch])
                    if is_param and expr != name:
                        names.setdefault(expr, name)
    return ({api: names for api, names in sorted(out.items()) if names},
            {api: dict(sorted(o.items())) for api, o in sorted(outputs.items())})


# -- 2. Cuckoo monitor ---------------------------------------------------------

def from_cuckoo_monitor(monitor: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for rst in sorted((monitor / "sigs").glob("*.rst")):
        lines = rst.read_text(errors="replace").splitlines()
        cat = next((l.split(":", 1)[1].strip() for l in lines if "* Category:" in l), None)
        if not cat:
            continue
        cat = RENAME.get(cat, cat)
        for i in range(len(lines) - 1):
            # An API section: its name, underlined with `=` of the same length.
            if re.fullmatch(r"\w+", lines[i]) and re.fullmatch(r"=+", lines[i + 1]) \
                    and len(lines[i + 1]) == len(lines[i]):
                out.setdefault(canonical(lines[i]), cat)
    return out


# -- 3. CAPEv2 logtbl ------------------------------------------------------------

def from_logtbl(logtbl: Path) -> dict[str, str]:
    tree = ast.parse(logtbl.read_text())
    table = next(node.value for node in tree.body if isinstance(node, ast.Assign)
                 and any(getattr(t, "id", None) == "table" for t in node.targets))
    out: dict[str, str] = {}
    for api, cat, *_ in ast.literal_eval(table):
        if not api.startswith("__"):
            out.setdefault(canonical(api), RENAME.get(cat, cat))
    return out


# -- 4. win32json --------------------------------------------------------------

def load_win32json(win32json: Path) -> dict[str, str]:
    """`{canonical name: namespace}`; the first namespace wins for a name
    declared in two."""
    api_dir = win32json / "api" if (win32json / "api").is_dir() else win32json
    out: dict[str, str] = {}
    for path in sorted(api_dir.glob("*.json")):
        for fn in json.loads(path.read_text()).get("Functions", []):
            if fn.get("Name"):
                out.setdefault(canonical(fn["Name"]), path.stem)
    return out


_SYNC = re.compile(r"Wait|Mutex|Event|Semaphore|Sleep|CriticalSection|SRWLock|"
                   r"ConditionVariable|Timer|InitOnce|Barrier|Interlocked")


def namespace_category(ns: str, name: str) -> str | None:
    """A namespace, and where it mixes subjects the name, to a category."""
    if ns.startswith(("Networking.WinSock", "Networking.WinHttp", "Networking.WinInet",
                      "Networking.HttpServer", "NetworkManagement.Dns",
                      "NetworkManagement.IpHelper", "NetworkManagement.WindowsFirewall",
                      "Networking.Ldap", "Networking.ActiveDirectory", "System.Com.Urlmon",
                      "NetworkManagement.Rras", "NetworkManagement.WiFi", "Networking.")):
        return "network"
    if ns.startswith(("NetworkManagement.WindowsFilteringPlatform", "System.RemoteManagement")):
        return "network"
    if ns.startswith(("NetworkManagement.NetManagement", "NetworkManagement.WNet",
                      "NetworkManagement.NetShell")):
        return "netapi"
    if ns.startswith("System.Registry"):
        return "registry"
    if ns.startswith(("Storage.", "System.IO", "System.Pipes", "System.Mailslots")):
        return "device" if "DeviceIoControl" in name else "filesystem"
    if ns.startswith(("Devices.", "Media.")):
        return "device"
    if ns.startswith("System.RestartManager"):
        return "process"
    if ns.startswith("System.Services"):
        return "services"
    if ns.startswith(("Security.Cryptography.Certificates", "Security.Cryptography.Catalog",
                      "Security.Cryptography.Sip", "Security.WinTrust")):
        return "certificate"
    if ns.startswith("Security.Cryptography"):
        return "certificate" if name.startswith(("Cert", "PFX")) else "crypto"
    if ns.startswith("System.Threading"):
        if "Process" in name:
            return "process"
        if _SYNC.search(name):
            return "synchronization"
        return "threading"
    if ns.startswith(("System.Memory", "System.ProcessStatus", "System.Diagnostics.ToolHelp",
                      "System.JobObjects")):
        return "process"
    if ns.startswith("System.LibraryLoader"):
        return "resource" if "Resource" in name else "system"
    if ns.startswith(("System.Com", "System.Wmi")):
        return "com"
    if ns.startswith("System.Ole"):
        return "ole"
    if ns.startswith(("UI.", "Graphics.")):
        return "hooking" if name.startswith(("SetWindowsHook", "UnhookWindowsHook")) else "windows"
    if ns.startswith(("System.SystemInformation", "System.Environment", "System.WindowsProgramming",
                      "System.Time", "System.Diagnostics", "Security", "System.Shutdown",
                      "System.Power", "System.Console", "System.ErrorReporting",
                      "System.SystemServices", "System.Kernel", "System.Rpc", "Foundation",
                      "Globalization", "System.EventLog", "System.Performance",
                      "System.RemoteDesktop", "System.ApplicationVerifier")):
        return "system"
    if ns.startswith(("UI.Shell", "System.DataExchange")):
        return "windows"
    return None


# -- 5. hooks.txt DLL ----------------------------------------------------------

DLL_CATEGORY = {
    "ws2_32": "network", "mswsock": "network", "wininet": "network", "winhttp": "network",
    "dnsapi": "network", "iphlpapi": "network", "urlmon": "network", "httpapi": "network",
    "netapi32": "netapi", "mpr": "netapi", "srvcli": "netapi",
    "bcrypt": "crypto", "ncrypt": "crypto", "cryptsp": "crypto", "rsaenh": "crypto",
    "crypt32": "certificate", "wintrust": "certificate",
    "user32": "windows", "gdi32": "windows", "win32u": "windows", "shell32": "windows",
    "ucrtbase": "misc", "msvcrt": "misc", "shlwapi": "misc",
    "ole32": "com", "oleaut32": "ole", "combase": "com",
    "sechost": "services", "wevtapi": "system", "psapi": "process", "mscoree": "dotnet",
    "msxfs": "device", "dinput": "device", "dinput8": "device", "wudfplatform": "system",
    # Last, and only after phnt: ntdll's syscall stubs have their own header,
    # so what reaches this is Rtl*/Dbg* helpers (RtlCopyMemory, DbgPrint).
    "ntdll": "misc",
}


def load_hooks(hooks: Path) -> dict[str, str]:
    """`{canonical name: dll stem}` for every hook line."""
    out: dict[str, str] = {}
    for line in hooks.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        dll, name = line.split(",")[:2]
        if not name.startswith("0x"):
            out.setdefault(canonical(name), dll.lower().removesuffix(".dll"))
    return out


# -- 6. phnt -------------------------------------------------------------------

_PHNT_DECL = re.compile(
    r"(?:NTSYSCALLAPI|NTSYSAPI)\s+[A-Za-z_][\w \t\*]*?\s*\n?\s*"
    r"(?:NTAPI|WINAPI)?\s*\n?\s*([A-Z][A-Za-z0-9_]{2,})\s*\(")


def load_phnt(phnt: Path) -> dict[str, str]:
    """`{canonical name: header stem}`; ntzwapi.h only repeats ntdll's
    exports under Zw, so it names no subject."""
    root = phnt / "phnt" / "include" if (phnt / "phnt" / "include").is_dir() else phnt
    out: dict[str, str] = {}
    for header in sorted(root.glob("*.h")):
        if header.stem in ("ntzwapi", "phnt", "phnt_ntdef", "phnt_windows"):
            continue
        for name in _PHNT_DECL.findall(header.read_text(errors="replace")):
            out.setdefault(canonical(name), header.stem)
    return out


_NT_SYNC = re.compile(r"Mutant|Event|Semaphore|Timer|KeyedEvent|WaitFor|Wait|Delay|Alert")


def header_category(header: str, name: str) -> str | None:
    if header == "ntioapi":
        return "device" if name in ("NtDeviceIoControlFile", "NtFsControlFile") else "filesystem"
    if header == "ntregapi":
        return "registry"
    if header in ("ntpsapi", "ntmmapi"):
        return "threading" if "Thread" in name else "process"
    if header == "ntobapi":
        return "synchronization" if _NT_SYNC.search(name) else "system"
    if header == "ntexapi":
        return "synchronization" if _NT_SYNC.search(name) else "system"
    if header in ("ntseapi", "ntldr", "ntkeapi", "ntxcapi", "ntwmi", "ntpoapi", "ntlpcapi",
                  "ntdbg", "ntmisc", "ntsmss", "ntpfapi", "ntbcd", "ntsxs", "ntnls", "ntsam",
                  "nttmapi", "ntpebteb", "nttp", "winsta"):
        return "system"
    if header in ("ntpnpapi", "ntafd"):
        return "network" if header == "ntafd" else "device"
    if header == "ntrtl":
        return "misc"
    if header in ("ntuser", "ntgdi", "ntd3dkmt"):
        return "windows"
    return None


# -----------------------------------------------------------------------------

def build(args) -> tuple[dict, dict[str, list[str]]]:
    capemon = from_capemon(args.capemon)
    cuckoo = from_cuckoo_monitor(args.cuckoo_monitor)
    logtbl = from_logtbl(args.logtbl)
    namespaces = load_win32json(args.win32json)
    hooks = load_hooks(args.hooks)
    phnt = load_phnt(args.phnt)

    names = set(hooks) | set(phnt) | set(capemon) | set(cuckoo) | set(logtbl)
    table: dict[str, str] = {}
    by_layer: dict[str, list[str]] = {}
    for name in sorted(names):
        for layer, cat in (
            ("capemon", capemon.get(name)),
            ("cuckoo-monitor", cuckoo.get(name)),
            ("logtbl", logtbl.get(name)),
            ("win32json", namespace_category(namespaces[name], name) if name in namespaces else None),
            ("phnt", header_category(phnt[name], name) if name in phnt else None),
            ("hooks.txt dll", DLL_CATEGORY.get(hooks.get(name, ""))),
        ):
            if cat:
                table[name] = cat
                by_layer.setdefault(layer, []).append(name)
                break
        else:
            by_layer.setdefault("unresolved", []).append(name)

    doc = {
        "_generated": "scripts/gen-api-categories.py -- do not edit by hand; re-run it",
        "sources": {
            "capemon": rev(args.capemon),
            "cuckoo-monitor": rev(args.cuckoo_monitor),
            "logtbl": args.logtbl_rev,
            "win32json": rev(args.win32json),
            "phnt": rev(args.phnt),
            "hooks.txt": "sandboxd/data/hooks.txt",
        },
        "categories": dict(sorted(table.items())),
    }
    return doc, by_layer


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--capemon", type=Path, required=True, help="kevoreilly/capemon checkout")
    ap.add_argument("--cuckoo-monitor", type=Path, required=True, help="cuckoosandbox/monitor checkout")
    ap.add_argument("--logtbl", type=Path, required=True, help="CAPEv2 lib/cuckoo/common/logtbl.py")
    ap.add_argument("--logtbl-rev", default="CAPEv2 revision UNRECORDED",
                    help="the CAPEv2 revision logtbl.py was taken from")
    ap.add_argument("--win32json", type=Path, required=True, help="marlersoft/win32json checkout")
    ap.add_argument("--phnt", type=Path, required=True, help="winsiderss/phnt checkout")
    ap.add_argument("--hooks", type=Path, default=HOOKS)
    ap.add_argument("--check", action="store_true", help="exit 1 if the table is stale")
    ap.add_argument("--report", action="store_true", help="print coverage per source")
    args = ap.parse_args()

    doc, by_layer = build(args)
    arguments, api_outputs = capemon_arguments(args.capemon)
    # capemon's name for NtProtectVirtualMemory's new protection is computed
    # (a local), so no parameter maps to it mechanically; both of DRAKVUF's
    # spellings of the parameter do.
    arguments.setdefault("NtProtectVirtualMemory", {}).update(
        {"NewProtectWin32": "NewAccessProtection", "NewProtection": "NewAccessProtection",
         "NewProtect": "NewAccessProtection"})
    arguments.setdefault("VirtualProtectEx", {}).setdefault("flNewProtect", "Protection")
    args_doc = {
        "_generated": doc["_generated"],
        "sources": {"capemon": doc["sources"]["capemon"]},
        "arguments": arguments,
    }
    outputs = {
        OUT: json.dumps(doc, indent=1, sort_keys=False) + "\n",
        OUT_ARGS: json.dumps(args_doc, indent=1, sort_keys=False) + "\n",
        OUT_OUTPUTS: json.dumps({"_generated": doc["_generated"],
                                 "sources": {"capemon": doc["sources"]["capemon"]},
                                 "outputs": api_outputs}, indent=1) + "\n",
    }
    if args.report:
        for layer, names in by_layer.items():
            print(f"{layer:16} {len(names)}")
        hooked = load_hooks(args.hooks)
        missing = sorted(n for n in hooked if n not in doc["categories"])
        print(f"hooks.txt names without a category: {len(missing)}")
        for n in missing:
            print("   ", n, hooked[n])
        print(f"argument names: {len(arguments)} APIs, "
              f"{sum(1 for n in hooked if n in arguments)} of them hooked")
    if args.check:
        stale = [p for p, text in outputs.items() if (p.read_text() if p.exists() else "") != text]
        for p in stale:
            print(f"{p.relative_to(ROOT)} is stale; re-run without --check", file=sys.stderr)
        return 1 if stale else 0
    for path, text in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    print(f"wrote {OUT.relative_to(ROOT)}: {len(doc['categories'])} names; "
          f"{OUT_ARGS.relative_to(ROOT)}: {len(arguments)} APIs")
    return 0


if __name__ == "__main__":
    sys.exit(main())