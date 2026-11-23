#!/usr/bin/env python3
"""How right sandboxd/samplehooks.py is on a program whose answer is known.

Takes a build that still has its symbol table, strips a copy (or takes the
stripped one), locates functions in the stripped one as a job would, and
compares each name and each hook line with what the symbol table has at
that address. A malware sample has no such answer: build a program with the
same toolchain and C library, with and without symbols, and check that.

    python scripts/check-samplehooks.py with-symbols [stripped]

Exit status 1 when a hook line is on a function other than the one it names:
that is the error the trace pays for (a wrong name in the report is only a
wrong name).
"""
import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sandboxd import samplehooks as sh  # noqa: E402


def symbols(path: Path) -> dict:
    """address -> the plain names of the functions there, by `nm` (binutils
    reads ELF and PE alike)."""
    found: dict = {}
    out = subprocess.run(["nm", "--defined-only", str(path)], capture_output=True, text=True, check=True).stdout
    for row in out.splitlines():
        parts = row.split()
        if len(parts) == 3 and parts[1] in "TtWw":
            found.setdefault(int(parts[0], 16), set()).add(sh.plain_name(parts[2]))
    return found


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("with_symbols", type=Path)
    p.add_argument("stripped", type=Path, nargs="?", help="default: a copy of with_symbols, stripped")
    p.add_argument("--static", type=Path,
                   help="the hook list (default: the one a job for the program's system gets)")
    p.add_argument("--flirt", type=Path, default=sh.FLIRT_DIR)
    p.add_argument("--flirt-sets", type=Path, default=sh.FLIRT_SETS)
    args = p.parse_args(argv)

    truth = symbols(args.with_symbols)
    if not truth:
        p.error(f"{args.with_symbols}: no function symbols")
    with tempfile.TemporaryDirectory() as tmp:
        stripped = args.stripped
        if stripped is None:
            stripped = Path(tmp) / args.with_symbols.name
            subprocess.run(["strip", "-o", str(stripped), str(args.with_symbols)], check=True)
        image, located = sh.locate(stripped, args.flirt, sh.CODE_SIGNATURES_DIR, args.flirt_sets)
    if image is None:
        p.error(f"{stripped}: not a program samplehooks reads")
    static = args.static or (sh.DATA / ("hooks.txt" if image.kind == "pe" else "so-hooks-linux.txt"))
    known = sh.static_hooks(static.read_text())

    print(f"{image.kind} {image.bits}-bit, toolchain {image.toolchain or 'c'}, sets loaded: {', '.join(image.sets)}")
    wrong = [f for f in located if sh.plain_name(f.name) not in truth.get(f.offset, ())]
    for f in sorted(wrong, key=lambda f: f.offset):
        print(f"  wrong name  {f.offset:#x} {f.name} ({f.how}); the symbol table: "
              f"{', '.join(sorted(truth.get(f.offset, ()))) or 'no function starts here'}")
    print(f"names: {len(located)} located, {len(located) - len(wrong)} right, {len(wrong)} wrong")

    lines = sh.sample_lines(located, known, "m", image.base)
    bad = 0
    for line in lines:
        name, offset = line.split(",")[1], int(line.split(",")[2], 16) + (image.base or 0)
        ok = sh.plain_name(name) in truth.get(offset, ())
        bad += not ok
        print(f"  {'ok   ' if ok else 'WRONG'}  {offset:#x} {name}"
              + ("" if ok else f"; the symbol table: {', '.join(sorted(truth.get(offset, ()))) or 'nothing'}"))
    print(f"hook lines: {len(lines)}, {bad} on the wrong function")
    listed = {sh.plain_name(name) for name in known}
    missed = sorted({n for names in truth.values() for n in names if n in listed}
                    - {sh.plain_name(f.name) for f in located})
    print(f"in the program and the hook list, not located: {', '.join(missed) or 'none'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
