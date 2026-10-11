#!/usr/bin/env python3
"""Derive both DRAKVUF hook lists from the APIs capa actually looks for.

**Why this exists.** `capa_analysis` matches rules against the calls in
`apimon.log` (Windows) and `libmon.log` (Linux), and those logs contain only
what the hook lists asked DRAKVUF to hook. A capa rule naming an API we do not
hook can never fire, however good the rule is. Neither list was derived from
what capa looks for: `hooks.txt` came from drakvuf-sandbox and
`so-hooks-linux.txt` was written by hand. Measured against capa-rules v9.4.0,
**811 Windows API names capa can match were not hooked at all**.

    scripts/gen-hook-lists.py --rules <capa-rules> --win32json <win32json>
    scripts/gen-hook-lists.py ... --check      # exit 1 if either file is stale
    scripts/gen-hook-lists.py ... --report     # what resolved, what did not

**This is NOT one of the three suite-enforced generators.** `gen-current-state`,
`gen-doc-index` and `gen-xen-configs` are re-run by `sandboxd/tests` because
their inputs are all in the repository. This one needs capa-rules and win32json,
neither of which a fresh checkout has, so its output is committed and the tests
pin invariants of that output instead. Re-run it when the `flare-capa` pin in
`sandboxd/requirements.txt` changes major version.

## How capa matches, which is why this generator looks the way it does

Read out of the installed capa, not recalled:

- **The DLL prefix does not participate in matching.** `capa.rules.trim_dll_part`
  strips the module from a rule's `api:` value, and
  `capa/features/extractors/drakvuf/call.py` calls `generate_symbols("", name)`
  with an EMPTY module. `extractors/helpers.py` says it outright: "for `api`
  features dll names are good for documentation but not used during matching."
  So the DLL we write matters only for finding the export -- it is never what
  makes a rule match.

- **capa trims A/W from the OBSERVED name and over-generates.** Hooking
  `CreateFileW` yields both `CreateFileW` and `CreateFile`, so it matches a rule
  written `kernel32.CreateFile`. The consequence for us is the important half:
  we must hook the REAL EXPORT, and capa bridges to the documented name. Hooking
  a documented name that is not an export (`CreateFile` has no such export)
  hooks nothing.

- **Arguments become `Number` and `String` features.** So a surplus argument
  type is not free: apimon reads that many arguments, and anything past the real
  arity is stack garbage that becomes a feature and can cause a FALSE match.
  Under-typing loses features; over-typing invents them -- which is why argument
  lists come from win32metadata's own `Params` (exact arity, Microsoft's types)
  rather than from a table in this file.

- **An unresolvable hook is silent, but a MALFORMED LINE IS FATAL.** Two
  different failures, and it matters which is which:
    * a symbol that does not resolve is reported only through `PRINT_DEBUG`
      (`libusermode/userhook.cpp:370`), compiled out of a release build, so the
      running system never says a hook did not take -- hence `--report`;
    * a line `parse_entry` cannot read makes
      `drakvuf_load_dll_hook_config` rethrow as "Invalid entry on line N"
      (`userhook.cpp:1035`), and **DRAKVUF does not start at all**. One bad
      generated line breaks every Windows job, which is why the grammar tests in
      `sandboxd/tests` are not decoration.
  `parse_entry` is also unforgiving about order: every token before the
  `log`/`log+stack` action that is not `clsid` or `no-retval` is read as a hex
  offset, and throws "Invalid offset" when it is not hex.

## Where the Windows DLL names come from

`marlersoft/win32json`, a JSON projection of Microsoft's own `win32metadata`:
17,104 functions each carrying `DllImport`, with A/W variants as DISTINCT
entries. That is what makes this generator verified rather than guesswork -- the
DLL and the exact export name are Microsoft's, not this file's opinion.

    git clone https://github.com/marlersoft/win32json     # ~64 MB extracted

Not vendored: too large for a repository this deliberately lean, and it is an
input like capa-rules rather than something we maintain. The revision used is
recorded in the generated block header so a regeneration is reproducible.

## What is deliberately NOT generated

- **.NET (`Namespace::Method`, 395 features).** These are managed calls in
  JIT-compiled code; no export-table hook can see them. We DO hook .NET, but as
  one CLR internal -- `AssemblyNative::LoadImage`, by RVA out of `--json-clr`
  (`memdump/userhook.cpp:209`) -- which exists to notice assembly loads so
  memdump can dump them. capa reaches those 395 features through its STATIC
  `BACKEND_DOTNET` pass over the dumped assemblies
  (`capa_processor.static_capa_analysis`), not through any call log. That pass is
  gated behind `analyze_memdumps`.
- **Ordinal imports (`dll.#N`, 26 features).** The drakvuf extractor passes
  `dll=""` to `generate_symbols`, so an ordinal can only ever yield `.#N` and
  never matches. Nothing to hook.
- **Kernel-mode modules.** apimon finds a DLL through its VAD and reads its
  export table; a kernel module has no VAD. See `KERNEL_MODULES`.
- **Hot functions.** See `HOT_LIBC`.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOKS_WIN = ROOT / "sandboxd" / "data" / "hooks.txt"
HOOKS_LINUX = ROOT / "sandboxd" / "data" / "so-hooks-linux.txt"

BEGIN = "# BEGIN GENERATED -- scripts/gen-hook-lists.py"
END = "# END GENERATED"

# `api:` feature lines. Both suffixes have to come off: capa-rules writes
# `- api: CreateFile = description` and also `- api: syscall # https://man7...`,
# and a regex that strips only the first captured the URL as part of an API
# name on the first run of this.
_API = re.compile(r"^\s*-?\s*api:\s*(.+?)\s*$", re.M)


def api_names(rules_dir: Path) -> set[str]:
    """Every distinct `api:` feature in capa-rules, cleaned."""
    out: set[str] = set()
    for path in rules_dir.rglob("*.yml"):
        text = path.read_text(errors="replace")
        for raw in _API.findall(text):
            name = raw.split("#")[0].split(" = ")[0].strip()
            if name:
                out.add(name)
    return out


def _trim_dll_part(api: str) -> str:
    """`capa.rules.trim_dll_part`, imported when capa is installed.

    Reimplemented only as a fallback, because this generator must agree with
    capa exactly: if our idea of a rule's bare name differs from capa's, we
    generate hooks for names capa never looks for.
    """
    try:
        from capa.rules import trim_dll_part  # noqa: PLC0415
        return trim_dll_part(api)
    except Exception:
        if ".#" in api:
            return api
        if api.count(".") == 1 and "::" not in api:
            return api.split(".")[1]
        return api


# --- Windows ---------------------------------------------------------------

# apimon locates a DLL through its VAD and reads its export table, so anything
# that never maps as a user-mode DLL cannot be hooked by it. `ntoskrn` is a
# typo in capa-rules (for `ntoskrnl`), kept here so it is filtered rather than
# silently emitted as `ntoskrn.dll`.
KERNEL_MODULES = frozenset({"ntoskrnl", "ntoskrn", "fwpkclnt", "fltmgr",
                            "ndis", "hal", "ci", "netio"})

# Native-API families that ntdll.dll exports to user mode. Anything outside
# these lives in ntoskrnl even when phnt declares it.
NTDLL_PREFIXES = ("Nt", "Zw", "Rtl", "Ldr", "Csr", "Dbg")


def load_phnt(phnt: Path | None) -> frozenset[str]:
    """Native API names phnt declares `NTSYSAPI`/`NTSYSCALLAPI`.

    Those macros mark a function ntdll exports, which is exactly the question
    "can apimon hook it by name". Optional: without `--phnt` the native API
    falls through to capa's module hint or is reported unresolved.
    """
    if not phnt:
        return frozenset()
    root = phnt / "phnt" / "include" if (phnt / "phnt" / "include").is_dir() else phnt
    pat = re.compile(
        r"(?:NTSYSCALLAPI|NTSYSAPI)\s+[A-Za-z_][\w \t\*]*?\s*\n?\s*"
        r"(?:NTAPI|WINAPI)?\s*\n?\s*([A-Z][A-Za-z0-9_]{2,})\s*\(")
    names: set[str] = set()
    for header in root.glob("*.h"):
        names |= set(pat.findall(header.read_text(errors="replace")))
    return frozenset(names)

# Argument types come from win32metadata's own `Params`, never from this file.
#
# **Only twelve type tokens do anything** (`libusermode/utils.cpp`,
# `make_arg_printer`): lpstr/lpcstr/lpctstr read ASCII, lpcwstr/lpwstr/bstr read
# wide strings, punicode_string / pulong / pulonglong / lpvoid* dereference, and
# refclsid/refiid/binary16 format. Every other token -- `dword`, `int`,
# `lpvoid` -- falls through to the base printer and is DOCUMENTATION ONLY.
#
# So a generated argument list does two things: it makes apimon READ THE STRINGS
# (which is how capa gets its `String` features, and half of what a rule matches
# on), and it declares ARITY. Arity is the part that must be exact -- apimon
# reads as many arguments as there are printers, so a list longer than the real
# signature reads stack garbage and turns it into capa features that look real.
#
# Taking both from Microsoft's metadata is what makes this safe at 1,300
# functions: the earlier version of this file carried a hand-written table of
# ~30 signatures, which was both a rounding error against the need and exactly
# the kind of asserted-from-memory data this project forbids.
_METADATA_TO_APIMON = {
    # wide strings -- WideStringPrinter
    "PWSTR": "lpcwstr", "PCWSTR": "lpcwstr",
    "LPWSTR": "lpcwstr", "LPCWSTR": "lpcwstr",
    # ANSI strings -- AsciiPrinter
    "PSTR": "lpcstr", "PCSTR": "lpcstr",
    "LPSTR": "lpcstr", "LPCSTR": "lpcstr",
    # COM string -- also WideStringPrinter
    "BSTR": "bstr",
}

# Pointed-to types that have a printer of their own.
_POINTER_TO_APIMON = {
    "UNICODE_STRING": "punicode_string",
    "Guid": "refiid",
}


def apimon_type(param: dict) -> str:
    """One win32metadata parameter -> one apimon type token.

    Anything without a dedicated printer becomes `lpvoid` (pointer) or `dword`
    (scalar). Both are documentation -- they select the base printer, which
    prints the raw value -- so an imprecise choice here costs nothing, while a
    WRONG string type would make apimon dereference a non-pointer. Hence only
    the names metadata states outright are mapped to a string printer.
    """
    t = param.get("Type", {})
    kind = t.get("Kind")
    if kind == "ApiRef":
        name = t.get("Name", "")
        if name in _METADATA_TO_APIMON:
            return _METADATA_TO_APIMON[name]
        return "dword"
    if kind == "PointerTo":
        child = t.get("Child", {})
        if child.get("Kind") == "ApiRef":
            mapped = _POINTER_TO_APIMON.get(child.get("Name", ""))
            if mapped:
                return mapped
            # A pointer to a string type is a string-out parameter; reading it
            # as a string is right, and is where output paths come from.
            if child.get("Name") in _METADATA_TO_APIMON:
                return _METADATA_TO_APIMON[child["Name"]]
        if child.get("Kind") == "PointerTo":
            return "lpvoid*"
        return "lpvoid"
    if kind == "Native":
        return "dword"
    return "lpvoid" if kind else "dword"


def arg_list(fn: dict) -> str:
    """Bare type per parameter, in order, exactly as long as the signature.

    **Bare, not `Name:type`.** The grammar allows both and nothing in this
    repository reads argument names -- every consumer is positional
    (`parse_apimon_arguments`, `get_http_info`) or takes `Arguments` whole
    (capa's `extractors/drakvuf/models.py`) -- so the metadata parameter names
    bought readability in the raw log at the cost of a format that differs from
    the 302 curated lines above the block and from upstream's. DRAKVUF names
    them `Arg<n>` itself (`libusermode/utils.cpp::parse_arguments`, numbered
    from 0).

    What matters here is the COUNT and the string types, both of which come
    from Microsoft's `Params` rather than from this file.
    """
    return ",".join(apimon_type(p) for p in fn.get("Params", []))


def load_win32json(win32json: Path, rev_override: str | None = None
                   ) -> tuple[dict[str, tuple[str, str]], str]:
    """`{function name: (dll, argument list)}` from every namespace file.

    A/W variants are separate entries in win32metadata, which is what makes A/W
    resolution exact here rather than a guess; `Params` is what makes the
    argument lists Microsoft's rather than ours.
    """
    api_dir = win32json / "api" if (win32json / "api").is_dir() else win32json
    by_name: dict[str, tuple[str, str]] = {}
    for path in sorted(api_dir.glob("*.json")):
        data = json.loads(path.read_text())
        for fn in data.get("Functions", []):
            dll = fn.get("DllImport")
            if dll and fn.get("Name"):
                by_name.setdefault(fn["Name"], (dll.lower(), arg_list(fn)))
    # A tarball download is not a git checkout, so `--win32json-rev` records
    # what was fetched. An unrecorded revision is stated as such rather than
    # left to look like a pin.
    rev = rev_override or subprocess.run(
        ["git", "-C", str(win32json), "rev-parse", "--short", "HEAD"],
        capture_output=True, text=True, check=False).stdout.strip()
    return by_name, rev or "revision UNRECORDED"


def resolve_windows(
    names: set[str], hints: dict[str, str],
    by_name: dict[str, tuple[str, str]],
    phnt: frozenset[str] = frozenset(),
    profiles: dict[str, set[str]] | None = None,
) -> tuple[dict[tuple[str, str], tuple[str, str]], list[str], list[str]]:
    """capa's bare names -> `{(dll, export): (provenance, args)}`.

    Also returns what could not be resolved, and what was REDIRECTED to a
    different DLL than win32metadata names -- both reported, because DRAKVUF
    reports neither.

    Provenance is recorded per line because the last rung is a documentation
    hint rather than a verified export, and a reader must be able to tell which
    is which without re-deriving it.
    """
    profiles = profiles or {}
    lines: dict[tuple[str, str], tuple[str, str]] = {}
    unresolved: list[str] = []
    redirected: list[str] = []
    for name in sorted(names):
        found = False
        # 1 and 2: win32json, exact then A/W. Both rungs are authoritative;
        # A/W entries are real exports in win32metadata, not synthesised here,
        # and the argument list is metadata's own `Params`.
        for candidate in (name, name + "A", name + "W"):
            entry = by_name.get(candidate)
            if not entry:
                continue
            dll, args = entry
            if dll.rsplit(".", 1)[0] in KERNEL_MODULES:
                continue
            prov = "win32metadata"
            # **Prefer the DLL that actually holds the code.** On Windows 10
            # and 11 kernel32 forwards a great many APIs into kernelbase: this
            # guest (Win11 23H2) has no `OpenProcess` in `kernel32.json` while
            # its `kernelbase.json` does. win32metadata names the DOCUMENTED dll,
            # which for a forwarder is not where the function body is, and
            # apimon hooks a symbol it finds in a DLL's own export table.
            #
            # Only ever redirects when a profile for the named DLL exists AND
            # lacks the symbol AND another profile has it -- so a DLL we have no
            # profile for is left exactly as metadata says.
            stem = dll.rsplit(".", 1)[0]
            if stem in profiles and candidate not in profiles[stem]:
                better = [d for d, syms in profiles.items()
                          if candidate in syms and d not in KERNEL_MODULES]
                if better:
                    dll = f"{better[0]}.dll"
                    prov = f"win32metadata, redirected to {dll} (profile)"
                    redirected.append(f"{candidate}: {stem}.dll -> {dll}")
            lines[(dll, candidate)] = (prov, args)
            found = True
        if found:
            continue
        # 3: psapi. win32metadata lists these under their kernel32 `K32` names,
        # because that is where they are implemented -- but `psapi.dll` exports
        # the un-prefixed name as a wrapper, and Microsoft documents it:
        # "If PSAPI_VERSION is 1, this function is defined as EnumProcesses ...
        # and exported in Psapi.lib and Psapi.dll as a wrapper that calls
        # K32EnumProcesses" (learn.microsoft.com, psapi/nf-psapi-enumprocesses).
        #
        # **The wrapper is the one worth hooking**, not the K32 implementation:
        # apimon reports the hooked symbol's own name, so a hook on
        # `K32EnumProcesses` emits a Method no capa rule looks for, while a hook
        # on `psapi.dll,EnumProcesses` emits exactly the documented name the
        # rules use. A caller compiled with PSAPI_VERSION=2 calls into kernel32
        # directly and is missed -- recorded here rather than papered over.
        # A/W applies here too: the kernel32 implementation of a string-taking
        # psapi call is `K32GetModuleFileNameExW`, and psapi.dll wraps it as
        # `GetModuleFileNameExW`.
        psapi = [f"{name}{s}" for s in ("", "A", "W") if f"K32{name}{s}" in by_name]
        if psapi:
            for export in psapi:
                # Args from the K32 implementation: psapi.dll's wrapper has the
                # same signature, which is what "wrapper that calls
                # K32EnumProcesses" means.
                _, args = by_name[f"K32{export}"]
                lines[("psapi.dll", export)] = (
                    "win32metadata (psapi K32 wrapper)", args)
            continue
        # 4: the native API, from phnt. win32metadata covers the documented
        # Win32 API and deliberately not this, but `Nt*`/`Zw*`/`Rtl*`/`Ldr*` are
        # USER-MODE exports of ntdll.dll and perfectly hookable -- and they are
        # the families malware reaches for. (`Zw*` and `Nt*` are the same address
        # in ntdll; they differ only in the kernel.) This is the second half of
        # the pairing capa's own maintainer used in mandiant/speakeasy#324.
        #
        # Gated on the prefix as well as on phnt, because phnt also declares
        # kernel-only routines: `Io*`, `Ke*`, `Mm*`, `Ob*`, `Ps*`, `Ex*` live in
        # ntoskrnl, which has no VAD for apimon to find, so they stay dropped.
        if name.startswith(NTDLL_PREFIXES) and name in phnt:
            # No argument list: phnt is C headers, and the native API's strings
            # arrive inside OBJECT_ATTRIBUTES/UNICODE_STRING rather than as
            # plain char pointers, so a parsed signature would buy almost no
            # String features while risking a wrong arity. Name-only still
            # yields capa the `api` feature, which is what matches.
            lines[("ntdll.dll", name)] = ("phnt (native API, ntdll export)", "")
            continue
        # 5: capa-rules' own module prefix. Documentation, so it is marked.
        hint = hints.get(name)
        if hint and hint not in KERNEL_MODULES:
            lines[(f"{hint}.dll", name)] = ("capa-hint (UNVERIFIED export)", "")
            continue
        # 6: nothing. Reported, because DRAKVUF never will.
        unresolved.append(name)
    return lines, unresolved, redirected


# Profiles for things that are not user-mode DLLs, so a symbol found only in
# one of these is not evidence that apimon can hook it.
_NON_DLL_PROFILES = frozenset({"windows", "win32k", "tcpip", "ndis", "netio",
                               "ci", "fltmgr", "fwpkclnt", "hal", "services",
                               "android", "linux", "wow", "kernel32wow"})


def load_profiles(profiles_dir: Path) -> dict[str, set[str]]:
    """`{dll stem: symbol names}` from the volatility3 profiles in `profiles/`.

    **This is ground truth for the actual golden image**, where win32metadata is
    the SDK's documented view. The two disagree in a way that matters: modern
    kernel32 forwards a great many APIs into kernelbase, so `kernel32.json` has
    no `OpenProcess` while `kernelbase.json` does, and apimon resolves a symbol
    in the export table of the DLL it is told to look in.

    Only user-mode DLL profiles are returned. `windows.json` is the kernel,
    `win32k`/`tcpip`/`ndis`/`netio`/`ci`/`fltmgr`/`fwpkclnt`/`hal` are drivers,
    `services` is an exe, and `wow`/`kernel32wow` are the 32-bit-on-64 path --
    none is a DLL whose exports apimon walks in a normal process.

    Absent or unreadable profiles simply yield nothing: a fresh checkout has
    none (they are not git-tracked), and the generator must still run there.
    """
    out: dict[str, set[str]] = {}
    if not profiles_dir.is_dir():
        return out
    for path in sorted(profiles_dir.glob("*.json")):
        stem = path.stem
        if stem in _NON_DLL_PROFILES:
            continue
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        symbols = data.get("symbols")
        if isinstance(symbols, dict) and symbols:
            out[stem] = set(symbols)
    return out


# --- Linux -----------------------------------------------------------------

# Functions whose cost outweighs anything they tell us. One Dom0 core saturates
# per concurrent trace and measured syscall throughput is 415-856/s
# (CURRENT-STATE.md, `12-baremetal-trial.md` Part H); a breakpoint on any of
# these fires thousands of times a second inside ordinary library code.
#
# capa-rules names every one of them, so this list is the reason a generated
# hook list is safe to ship at all. Each entry is here on purpose:
# **Comparison functions, hooked on purpose since 2026-09-27 despite the cost.**
# capa has 835 `string:` and 145 `substring:` features in call-scope rules, and
# a string only becomes a feature if it is an ARGUMENT of a hooked call. An
# anti-VM check is usually `strcmp(buf, "VMware")`, so without these the whole
# family is invisible however many APIs are hooked.
#
# **This is the most expensive thing in either list.** These are the most
# frequently called functions in any program -- thousands per second inside
# ordinary library code -- and every trace now pays for them, on a host where
# one core already saturates per trace at 415-856 syscalls/s. The operator took
# that trade explicitly with the cost stated; it is UNMEASURED on Dom0.
#
# **Reversing it is two edits**: move these names back into HOT_LIBC and
# regenerate. They are a separate table for exactly that reason.
#
# Both string parameters are typed so apimon READS them -- an untyped argument
# arrives as a number and yields capa a `Number`, not the `String` the rule
# needs.
# **On Linux this is NOT POSSIBLE, and the reason is worth keeping.** glibc
# declares `strcmp`, `strncmp`, `strcasecmp`, `strstr` and `memcmp` as
# `STT_GNU_IFUNC`, not `STT_FUNC` (checked with `readelf --dyn-syms` against
# this container's glibc, 2026-09-27). An IFUNC symbol's `st_value` is the
# address of a RESOLVER, which the dynamic linker calls once at load time to
# pick a CPU-specific implementation -- it is not the comparison code.
#
# `libdrakvuf/linux-exports.c` reads `st_value` straight out of `.dynsym` and
# has no IFUNC handling, so a hook on `libc.so.6,strcmp` would breakpoint the
# resolver: one junk event per process at startup, and not one string
# comparison. The implementations (`__strcmp_avx2` and friends) are not in
# `.dynsym` either, so there is no name to hook instead.
#
# Emitting them anyway is exactly the silent-no-op this project keeps writing
# down, so nothing is emitted. What would unblock it: IFUNC support in
# `linux-exports.c` (resolve the symbol, then read the resolver's return value
# at first call), which is a DRAKVUF change, not a hook-list one.
STRING_FUNCS_LINUX: dict[str, str] = {}

# The CRT, where the same functions live on Windows. Both DLLs: modern builds
# link ucrtbase, older ones msvcrt, and which a sample used is not knowable
# here. **A statically linked CRT defeats both** -- much malware links it in,
# leaving no export to hook -- so absence of these calls is not evidence the
# sample made none.
STRING_FUNCS_WINDOWS = {
    "strcmp": "lpcstr,lpcstr",
    "_stricmp": "lpcstr,lpcstr",
    "strstr": "lpcstr,lpcstr",
    "memcmp": "lpvoid,lpvoid,size_t",
    "wcscmp": "lpcwstr,lpcwstr",
    "_wcsicmp": "lpcwstr,lpcwstr",
    "wcsstr": "lpcwstr,lpcwstr",
}
CRT_DLLS = ("ucrtbase.dll", "msvcrt.dll")

HOT_LIBC = frozenset({
    # string and memory primitives, called constantly by everything.
    # `strcmp`, `strstr` and `memcmp` were here until 2026-09-27 and are now in
    # STRING_FUNCS_LINUX above -- deliberately, for capa's string features.
    "strlen", "memcpy", "memfrob", "atoi",
    # unbuffered and buffered I/O, per byte or per line
    "read", "write", "fread", "fwrite", "getc", "putc", "fgetc", "fputc",
    "getchar", "putwchar", "fgets", "fputs", "fgetwc", "fputwc", "getwc",
    "putwc", "getdelim", "getline",
    # formatted I/O
    "fprintf", "vfprintf", "fscanf", "vfscanf", "dprintf", "vdprintf",
    # stat and fd churn -- `filetracer` already reports the interesting half
    "stat", "fstat", "lstat", "access", "fcntl",
    # trivially cheap to call, so called in loops
    "getpid", "getppid", "sysconf",
    # `open`/`openat` are the judgement call: busy, but they are how a sample
    # reaches the filesystem and filetracer does not report the path asked for.
    # Kept OUT of this list deliberately -- revisit if a trace saturates.
    #
    # the raw syscall wrapper: hot, and redundant with the `syscalls` plugin
    "syscall",
})

# Where a Linux name lives, when it is not libc. capa-rules names no curl or
# OpenSSL API at all (checked: zero curl/SSL/gnutls `api:` features at v9.4.0),
# so these come from the hand-written half of so-hooks-linux.txt, not from here.
LINUX_SO = "libc.so.6"


def libc_exports(libc: Path) -> set[str]:
    """Every `FUNC` in a real glibc's `.dynsym`.

    **This is the gate that makes the Linux half need no invention.** It removes
    40 of capa's 182 lowercase names by itself: MSVC CRT names that are not libc
    (`_wsystem`, `_allmul`, `__p__pgmptr`), bionic (`__android_log_print`),
    kernel symbols libmon cannot reach (`commit_creds`, `prepare_kernel_cred`,
    `nf_register_hook`), libm (`sin`, `pow`, `sqrt`), names that do not exist
    (`pthread_terminate`, `wsystem`) and syscall-only names with no libc wrapper
    (`exit_group`, `getdents`).
    """
    out = subprocess.run(["readelf", "--dyn-syms", "-W", str(libc)],
                         capture_output=True, text=True, check=False).stdout
    exports = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[3] == "FUNC" and parts[6] != "UND":
            exports.add(parts[7].split("@")[0])
    return exports


# --- block rewriting -------------------------------------------------------

def existing_hooks(path: Path) -> set[tuple[str, str]]:
    """`(module, function)` already named ABOVE the generated block.

    Hand-curated lines must survive regeneration. `hooks.txt` deliberately
    hooks `kernel32.dll,CreateProcessInternalW` rather than `CreateProcess`,
    and `jscript.dll,COleScript_ParseScriptText`, which is not an export at
    all -- a generator that rewrote the whole file would destroy both.
    """
    curated: set[tuple[str, str]] = set()
    for line in path.read_text().splitlines():
        if line.strip() == BEGIN:
            break
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split(",")
        if len(fields) >= 2:
            curated.add((fields[0], fields[1]))
    return curated


def splice(path: Path, body: list[str], header: str) -> str:
    """Everything above BEGIN, unchanged, then a fresh block."""
    text = path.read_text() if path.exists() else ""
    head = text.split(BEGIN)[0].rstrip("\n")
    block = "\n".join([BEGIN, header, *body, END])
    return f"{head}\n\n{block}\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", type=Path, help="capa-rules checkout at the tag matching the flare-capa pin")
    ap.add_argument("--win32json", type=Path, help="marlersoft/win32json checkout")
    ap.add_argument("--phnt", type=Path, help="winsiderss/phnt checkout, for the native API (Nt*/Zw*/Rtl*)")
    ap.add_argument("--profiles", type=Path, default=ROOT / "profiles",
                    help="volatility3 symbol profiles, to prefer the DLL that really holds a symbol")
    ap.add_argument("--win32json-rev", help="revision of the win32json tree, when it is not a git checkout")
    ap.add_argument("--libc", type=Path, default=Path("/lib/x86_64-linux-gnu/libc.so.6"))
    ap.add_argument("--check", action="store_true", help="exit 1 if either file is stale")
    ap.add_argument("--report", action="store_true", help="print what resolved and what did not")
    args = ap.parse_args()

    if not args.rules or not args.rules.is_dir():
        print("--rules must point at a capa-rules checkout", file=sys.stderr)
        return 2
    if not args.win32json or not args.win32json.is_dir():
        print("--win32json must point at a marlersoft/win32json checkout", file=sys.stderr)
        return 2

    raw = api_names(args.rules)
    rules_rev = subprocess.run(["git", "-C", str(args.rules), "describe", "--tags", "--always"],
                               capture_output=True, text=True, check=False).stdout.strip()
    by_name, w32_rev = load_win32json(args.win32json, args.win32json_rev)

    # Module hints, for rung 3. Taken before trimming, since trimming is what
    # throws the module away.
    hints: dict[str, str] = {}
    for api in raw:
        if ".#" in api or "::" in api or api.count(".") != 1:
            continue
        module, fn = api.split(".")
        if fn and fn != fn.lower():
            hints.setdefault(fn, module.lower())

    bare = {_trim_dll_part(a) for a in raw if ".#" not in a and "::" not in a}
    bare.discard("")
    # **A lowercase name is not automatically Linux.** The split used to be
    # case alone, which sent every lowercase name to the Linux list and dropped
    # it there if glibc did not export it. That discarded two real Windows
    # families: the MSVC CRT (`_wsystem`, `_mkdir`, `_read`, `_beginthreadex`
    # -- in capa-rules because one rule covers both platforms) and plain
    # lowercase Win32 exports like `keybd_event`, `mouse_event`, `socket`.
    #
    # So every name is offered to BOTH resolvers; each keeps what its own
    # source of truth recognises, and a name in both (`socket`, `connect`) is
    # correctly hooked on both guests.
    win_names = {a for a in bare if a != a.lower()} | {
        a for a in bare if a == a.lower() and (
            a in by_name or f"{a}A" in by_name or f"{a}W" in by_name
            or a.startswith("_"))}
    lin_names = {a for a in bare if a == a.lower()}

    # --- Windows
    phnt = load_phnt(args.phnt)
    profiles = load_profiles(args.profiles)
    win_lines, unresolved, redirected = resolve_windows(
        win_names, hints, by_name, phnt, profiles)
    curated_win = existing_hooks(HOOKS_WIN)
    new_win = {k: v for k, v in win_lines.items() if k not in curated_win}
    # The CRT is not in win32metadata and has no profile here, so these are
    # marked UNVERIFIED. `windows-symbol-profiles.py` gaining a `ucrtbase` row
    # would settle them; that is a Dom0 step and its own change.
    for fn, args_ in STRING_FUNCS_WINDOWS.items():
        for dll in CRT_DLLS:
            win_lines.setdefault((dll, fn), ("CRT (UNVERIFIED export)", args_))
    for fn in sorted(n for n in win_names if n.startswith("_")):
        if any((d, fn) in win_lines for d in CRT_DLLS):
            continue
        for dll in CRT_DLLS:
            win_lines.setdefault((dll, fn), ("CRT (UNVERIFIED export)", ""))

    new_win = {k: v for k, v in win_lines.items() if k not in curated_win}
    win_body = [
        f"{dll},{fn},log" + (f",{args_}" if args_ else "")
        for (dll, fn), (prov, args_) in sorted(new_win.items())
    ]
    win_header = (
        f"# capa-rules {rules_rev}, win32json {w32_rev}. Regenerate with\n"
        f"# scripts/gen-hook-lists.py; hand-curated lines above are preserved.\n"
        f"#\n"
        f"# {len(win_names)} bare Win32 names in capa-rules -> {len(win_lines)} hookable\n"
        f"# lines ({len(unresolved)} unresolved, see --report). A line with no argument\n"
        f"# types still yields capa its `api` feature, which is what matches a rule;\n"
        f"# arguments only add String/Number features, and a WRONG arity manufactures\n"
        f"# them. DLL names never participate in matching (capa.rules.trim_dll_part)."
    )

    # --- Linux
    exports = libc_exports(args.libc)
    keep = sorted((lin_names & exports) - HOT_LIBC)
    curated_lin = existing_hooks(HOOKS_LINUX)
    new_lin = [f"{LINUX_SO},{fn},log" for fn in keep
               if (LINUX_SO, fn) not in curated_lin]
    # Typed, because the typing is the entire point: an untyped argument
    # reaches capa as a Number, not the String a `string:` rule matches.
    # `fn in exports` is the guard that matters: `libc_exports` keeps only
    # STT_FUNC, so an IFUNC name can never be emitted here even if someone
    # refills STRING_FUNCS_LINUX without reading why it is empty.
    new_lin += [f"{LINUX_SO},{fn},log,{args_}"
                for fn, args_ in sorted(STRING_FUNCS_LINUX.items())
                if (LINUX_SO, fn) not in curated_lin and fn in exports]
    dropped_hot = sorted(lin_names & exports & HOT_LIBC)
    lin_header = (
        f"# capa-rules {rules_rev}, verified against {args.libc}. Regenerate with\n"
        f"# scripts/gen-hook-lists.py; hand-curated lines above are preserved.\n"
        f"#\n"
        f"# {len(lin_names)} lowercase names in capa-rules; {len(lin_names & exports)} are real glibc\n"
        f"# exports; {len(dropped_hot)} of those dropped as hot (see HOT_LIBC in the\n"
        f"# generator for why each one). Names glibc does not export are MSVC CRT,\n"
        f"# bionic, kernel symbols, libm or simply nonexistent -- none is hookable\n"
        f"# here, and that check is what keeps this list free of invention."
    )

    if args.report:
        print(f"capa-rules {rules_rev}: {len(raw)} distinct api: features")
        # psapi wrappers count as verified: the export is documented by
        # Microsoft, not inferred from capa's module hint.
        verified = sum(1 for prov, _ in win_lines.values()
                       if prov.startswith(("win32metadata", "phnt")))
        typed = sum(1 for _, a in win_lines.values() if a)
        print(f"  Windows bare names {len(win_names)} -> {len(win_lines)} lines "
              f"({verified} verified, {len(win_lines) - verified} hint-only, "
              f"{typed} with metadata argument lists), "
              f"{len(unresolved)} unresolved")
        print(f"  Linux lowercase {len(lin_names)} -> {len(keep)} kept, "
              f"{len(dropped_hot)} hot, {len(lin_names - exports)} not glibc exports")
        # The curated lines are never rewritten, but a stale DLL in them is
        # worth saying out loud: `hooks.txt` was inherited from
        # drakvuf-sandbox, written when `CreateProcessInternalW` lived in
        # kernel32. On this Win11 23H2 image it is in kernelbase, and a hook on
        # the wrong DLL resolves to nothing -- silently, in a release build.
        stale = []
        for dll, fn in sorted(existing_hooks(HOOKS_WIN)):
            stem = dll.rsplit(".", 1)[0]
            if stem in profiles and fn not in profiles[stem]:
                elsewhere = [d for d, syms in profiles.items() if fn in syms]
                stale.append(f"{dll},{fn}"
                             + (f" -> in {elsewhere[0]}.dll" if elsewhere else
                                " -> in no profile we have"))
        print(f"\nCURATED lines whose DLL profile lacks the symbol ({len(stale)}):")
        for line in stale[:25]:
            print(f"  {line}")
        if len(stale) > 25:
            print(f"  ... and {len(stale) - 25} more")

        print(f"\nredirected to the DLL that holds the symbol ({len(redirected)}):")
        for r in redirected[:40]:
            print(f"  {r}")
        if len(redirected) > 40:
            print(f"  ... and {len(redirected) - 40} more")
        print(f"\nunresolved Windows names ({len(unresolved)}):")
        for n in unresolved:
            print(f"  {n}")
        return 0

    stale = False
    for path, body, header in ((HOOKS_WIN, win_body, win_header),
                              (HOOKS_LINUX, new_lin, lin_header)):
        want = splice(path, body, header)
        if path.read_text() == want:
            continue
        stale = True
        if args.check:
            print(f"{path.relative_to(ROOT)} is out of date -- run scripts/gen-hook-lists.py",
                  file=sys.stderr)
        else:
            path.write_text(want)
            print(f"updated {path.relative_to(ROOT)}")
    if args.check:
        return 1 if stale else 0
    if not stale:
        print("already up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())