#!/usr/bin/env python3
"""Generate the per-binary symbol profiles a Windows analysis takes.

`sandboxd/guests.py::SYMBOL_PROFILES` passes DRAKVUF one `--json-<name>`
profile per Windows DLL or driver its plugins hook, beside the kernel one.
Each is volatility3 `pdbconv.py` output for the exact build of that binary in
the golden image: `tools/pdbguid.py` reads the PDB GUID and name off the file,
`pdbconv.py` fetches that PDB from Microsoft's symbol server and converts it.
`windows_symbols.md` has the two done by hand; this does the whole table.

Run on Dom0, as root, with the golden Windows LV mounted read-only:

    kpartx -a /dev/vg-root/windows
    mount -o ro /dev/mapper/vg--root-windows2 /mnt
    scripts/windows-symbol-profiles.py                 # every row
    scripts/windows-symbol-profiles.py tcpip ntdll     # some rows, by stem
    umount /mnt && kpartx -d /dev/vg-root/windows

Every row is attempted. One whose binary is missing, whose PDB the symbol
server does not have, or whose conversion fails is reported and skipped, the
rest still land, and the exit status is 1 if any row failed. Nothing is
written under the final name until `pdbconv.py` has succeeded, so a failed row
cannot leave a truncated profile for DRAKVUF to open. `--dry-run` prints the
commands and touches nothing.

The Windows paths are the `C:\\...` ones from DRAKVUF's option table, under
the mount root. NTFS keeps whatever case the installer wrote and Windows never
cared, so each path component is matched ignoring case rather than spelled to
match one image.

The output names are guests.py's, and `sandboxd/tests/test_guests.py` fails
when the two tables disagree. `--json-ole32` and `--json-ndis` are rows here
and not there: their PDBs could not be produced on 2026-09-19. Retry them
after a Windows update, and restore them to guests.py if they succeed.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: DRAKVUF option, profile file name as guests.py spells it, and the binary's
#: path under the mounted Windows volume.
PROFILES: tuple[tuple[str, str, str], ...] = (
    ("--json-wow",          "wow.json",         "Windows/SysWOW64/ntdll.dll"),
    ("--json-tcpip",        "tcpip.json",       "Windows/System32/drivers/tcpip.sys"),
    ("--json-win32k",       "win32k.json",      "Windows/System32/win32k.sys"),
    ("--json-sspicli",      "sspicli.json",     "Windows/System32/sspicli.dll"),
    ("--json-kernel32",     "kernel32.json",    "Windows/System32/kernel32.dll"),
    ("--json-kernelbase",   "kernelbase.json",  "Windows/System32/KernelBase.dll"),
    ("--json-wow-kernel32", "kernel32wow.json", "Windows/SysWOW64/kernel32.dll"),
    ("--json-ntdll",        "ntdll.json",       "Windows/System32/ntdll.dll"),
    ("--json-iphlpapi",     "iphlpapi.json",    "Windows/System32/iphlpapi.dll"),
    ("--json-ole32",        "ole32.json",       "Windows/System32/ole32.dll"),
    ("--json-clr",          "clr.json",         "Windows/Microsoft.NET/Framework64/v4.0.30319/clr.dll"),
    ("--json-mscorwks",     "mscorwks.json",    "Windows/Microsoft.NET/Framework64/v2.0.50727/mscorwks.dll"),
    ("--json-hal",          "hal.json",         "Windows/System32/hal.dll"),
    ("--json-fwpkclnt",     "fwpkclnt.json",    "Windows/System32/drivers/fwpkclnt.sys"),
    ("--json-fltmgr",       "fltmgr.json",      "Windows/System32/drivers/fltmgr.sys"),
    ("--json-ci",           "ci.json",          "Windows/System32/ci.dll"),
    ("--json-netio",        "netio.json",       "Windows/System32/drivers/netio.sys"),
    ("--json-ndis",         "ndis.json",        "Windows/System32/drivers/ndis.sys"),
    ("--json-services",     "services.json",    "Windows/System32/services.exe"),
)

# Where the evidence in windows_symbols.md found them.
DEFAULT_MOUNT = Path("/mnt")
DEFAULT_DRAKVUF = ROOT / "drakvuf"
PDBGUID = Path("tools/pdbguid.py")
PDBCONV = Path("volatility3/volatility3/framework/symbols/windows/pdbconv.py")


def locate(mount: Path, relpath: str) -> Path | None:
    """`mount/relpath`, matching each component without regard to case."""
    here = mount
    for part in relpath.split("/"):
        exact = here / part
        if exact.exists():
            here = exact
            continue
        try:
            matches = [c for c in here.iterdir() if c.name.lower() == part.lower()]
        except OSError:
            return None
        if len(matches) != 1:
            return None
        here = matches[0]
    return here


def run(argv: list[str], *, env: dict[str, str] | None = None) -> str:
    """Echo the command the way a runbook would, run it, return its stdout.

    stderr passes straight through so a symbol-server error is seen where it
    happens rather than in a summary line."""
    print("+ " + shlex.join(argv), flush=True)
    return subprocess.run(
        argv, check=True, stdout=subprocess.PIPE, text=True, env=env
    ).stdout


def volatility_environment(drakvuf: Path) -> dict[str, str]:
    """Import Volatility from this checkout rather than a system-wide install.

    Invoking a script by path does not put the *package root* on sys.path.
    In particular, setup.py install may have left an older volatility3 in
    site-packages, which then loads a different windows/pdb.json.
    """
    env = os.environ.copy()
    source_root = str((drakvuf / "volatility3").resolve())
    inherited = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = source_root + (os.pathsep + inherited if inherited else "")
    return env


def verify_volatility(drakvuf: Path, env: dict[str, str]) -> None:
    """Fail early if pdbconv and the PDB ISF do not come from PR #650 checkout."""
    checkout = (drakvuf / "volatility3").resolve()
    # Run in the same interpreter and environment as pdbconv.py; validating
    # the on-disk file alone would miss a stale installed Volatility package.
    code = r"""
import json
import sys
from pathlib import Path
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import pdbconv

checkout = Path(sys.argv[1]).resolve()
expected_conv = checkout / 'volatility3/framework/symbols/windows/pdbconv.py'
expected_json = checkout / 'volatility3/framework/symbols/windows/pdb.json'
actual_conv = Path(pdbconv.__file__).resolve()
if actual_conv != expected_conv:
    sys.exit(f'Wrong Volatility converter imported: {actual_conv}; expected {expected_conv}')
urls = list(intermed.IntermediateSymbolTable.file_symbol_url('windows', 'pdb'))
if not urls or urls[0] != expected_json.as_uri():
    sys.exit(f'Wrong PDB symbol file selected: {urls[0] if urls else None}; expected {expected_json}')
with expected_json.open(encoding='utf-8') as fp:
    data = json.load(fp)
required = {'LF_NESTTYPE': 5392, 'LF_MFUNCTION': 4105}
missing_types = required.keys() - data.get('user_types', {}).keys()
leaf_values = data.get('enums', {}).get('LEAF_TYPE', {}).get('constants', {})
invalid_values = [name for name, value in required.items() if leaf_values.get(name) != value]
if missing_types or invalid_values:
    sys.exit(f'PR #650 PDB definitions incomplete: missing user_types={sorted(missing_types)}, '
             f'wrong LEAF_TYPE values={invalid_values}')
print(f'Volatility converter: {actual_conv}')
print(f'PDB symbol definitions: {expected_json}')
"""
    print(f"+ verifying Volatility checkout: {checkout}", flush=True)
    output = subprocess.run(
        [sys.executable, "-c", code, str(checkout)],
        check=True, stdout=subprocess.PIPE, text=True, env=env,
    ).stdout
    print(output, end="")


def pdb_identity(drakvuf: Path, binary: Path) -> tuple[str, str]:
    """The (GUID, PDB file name) `pdbguid.py` prints for a PE file."""
    out = run([sys.executable, str(drakvuf / PDBGUID), str(binary)])
    print(out, end="" if out.endswith("\n") else "\n")
    guid = re.search(r"^GUID:\s*([0-9A-Fa-f]+)\s*$", out, re.M)
    name = re.search(r"^Filename:\s*(\S+)\s*$", out, re.M)
    if not guid or not name:
        raise RuntimeError("pdbguid.py printed no GUID/Filename pair")
    # The CodeView entry may carry the PDB's build-time path; the symbol
    # server is keyed on the bare name.
    return guid.group(1), name.group(1).replace("\\", "/").rsplit("/", 1)[-1]


def convert(drakvuf: Path, guid: str, pdb: str, out: Path) -> None:
    """Fetch `pdb` by `guid` and write the profile to `out`, atomically."""
    part = out.with_name(out.name + ".part")
    try:
        run([sys.executable, str(drakvuf / PDBCONV),
             "--guid", guid, "-p", pdb, "-o", str(part)],
            env=volatility_environment(drakvuf))
        if not part.is_file() or part.stat().st_size == 0:
            raise RuntimeError("pdbconv.py exited 0 but wrote nothing")
        os.replace(part, out)
    finally:
        part.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=__doc__.split("\n\n", 1)[1])
    parser.add_argument("names", nargs="*", metavar="NAME",
                        help="rows to build, by profile stem (tcpip, kernel32wow); "
                             "default is every row")
    parser.add_argument("--mount", type=Path, default=DEFAULT_MOUNT,
                        help="where the Windows volume is mounted (default %(default)s)")
    parser.add_argument("--drakvuf", type=Path, default=DEFAULT_DRAKVUF,
                        help="DRAKVUF checkout holding tools/pdbguid.py and the "
                             "volatility3 submodule (default %(default)s)")
    parser.add_argument("--out", type=Path, default=ROOT / "profiles",
                        help="directory the profiles are written to (default %(default)s)")
    parser.add_argument("-n", "--dry-run", action="store_true",
                        help="print the commands without running them")
    args = parser.parse_args(argv)

    known = {row[1].removesuffix(".json"): row for row in PROFILES}
    unknown = [n for n in args.names if n not in known]
    if unknown:
        parser.error(f"not in the table: {', '.join(unknown)}; rows are {', '.join(known)}")
    rows = [known[n] for n in args.names] if args.names else list(PROFILES)

    for tool in (PDBGUID, PDBCONV):
        if not (args.drakvuf / tool).is_file():
            parser.error(f"{args.drakvuf / tool} is missing; pass --drakvuf")
    if locate(args.mount, "Windows") is None:
        parser.error(f"no Windows/ under {args.mount}; is the LV mounted? pass --mount")
    if not args.dry_run:
        # Verify the exact checkout and its JSON definitions before fetching
        # any PDBs. Missing/stale installs used to fail halfway through a run.
        try:
            verify_volatility(args.drakvuf, volatility_environment(args.drakvuf))
        except subprocess.CalledProcessError as exc:
            print(f"Volatility preflight failed (exit {exc.returncode})", file=sys.stderr)
            return 1
        args.out.mkdir(parents=True, exist_ok=True)

    results: list[tuple[str, str]] = []
    for option, name, relpath in rows:
        print(f"\n=== {option} -> {name}", flush=True)
        binary = locate(args.mount, relpath)
        if binary is None:
            results.append((name, f"FAILED: {args.mount / relpath} not found"))
            continue
        if args.dry_run:
            print("+ " + shlex.join([sys.executable, str(args.drakvuf / PDBGUID), str(binary)]))
            print("+ " + shlex.join(["env", "PYTHONPATH=" + volatility_environment(args.drakvuf)["PYTHONPATH"],
                                     sys.executable, str(args.drakvuf / PDBCONV),
                                     "--guid", "<GUID>", "-p", "<Filename>",
                                     "-o", str(args.out / name)]))
            results.append((name, f"dry run, from {binary}"))
            continue
        try:
            guid, pdb = pdb_identity(args.drakvuf, binary)
            convert(args.drakvuf, guid, pdb, args.out / name)
        except subprocess.CalledProcessError as e:
            # The tool's own stderr went straight through above.
            results.append((name, f"FAILED: {Path(e.cmd[1]).name} exited {e.returncode}"))
            continue
        except (RuntimeError, OSError) as e:
            results.append((name, f"FAILED: {e}"))
            continue
        size = (args.out / name).stat().st_size
        results.append((name, f"ok  {guid} {pdb}  {size / 1e6:.1f} MB"))

    width = max(len(name) for name, _ in results)
    print("\n=== summary")
    for name, outcome in results:
        print(f"{name:<{width}}  {outcome}")
    failed = sum(outcome.startswith("FAILED") for _, outcome in results)
    if failed:
        print(f"\n{failed} of {len(results)} failed", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())