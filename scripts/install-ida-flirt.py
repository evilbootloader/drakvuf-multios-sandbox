#!/usr/bin/env python3
"""Hex-Rays' FLIRT signatures for sandboxd/samplehooks.py: the sets
sandboxd/data/flirt-sets.txt names, out of an IDA signature bundle.

    scripts/install-ida-flirt.py ~/signatures-bundles-9.5.zip
    scripts/install-ida-flirt.py ~/signatures-bundles-9.5        # unpacked
    scripts/install-ida-flirt.py --list ~/signatures-bundles-9.5.zip

Hex-Rays publishes the FLIRT signatures IDA uses as a bundle beside IDA
Free, `signatures-bundles-<version>.zip`: a `.sig` per library and processor
with a `.metadata` beside it naming what it was made from. Debian's and
Ubuntu's -dev packages over two decades of releases, Visual C++'s static
runtimes and the SDKs' static libraries, Go's standard library from 1.10
and Rust's for every release and target, each set covering every version
of its library it was made from. python-flirt reads them as they are, so
there is nothing to build: the toolchains scripts/fetch-flirt-sets.py
downloaded and compiled for an hour are not needed for any of it. The
bundle comes from Hex-Rays' download portal, which needs an account, and
is not fetched here.

Only what a line of the list can name is unpacked: the bundle is 1.8 GB,
and most of it is ARM, MIPS, PowerPC, s390x and Apple, which no sample here
is. A line's `{rust}` is every release. Into `sandboxd/data/flirt/ida/flirt/`
-- the list's `ida/flirt/` -- which is not tracked: data made from other
people's binaries, installed by running this again, which leaves a file
with the same bytes alone. The wrapper directory of the zip
(`signatures-bundles-9.5/`) and what macOS left in it (`__MACOSX/`, `._*`)
are not part of a set's path.

**The release that built a Rust program** is in its `.comment` when that is
left in, and otherwise only its compiler's commit is (`/rustc/<commit>/`, in
every panic path). The bundle's Rust sets are by release, so this also
writes `sandboxd/data/flirt/rust-releases.txt`: each release's commit, from
the tags of github.com/rust-lang/rust (`git ls-remote`, one request;
`--no-rust-releases` to skip it).
"""
from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# The list's grammar is samplehooks'
from sandboxd import samplehooks as sh  # noqa: E402

#: Where the list's sets of this bundle are, under sh.FLIRT_DIR
PREFIX = "ida/flirt/"
#: What a set is, in the bundle, and what is read beside it
KEPT = (".sig", ".metadata")
#: The largest file of the 9.5 bundle is 15 MB
MAX_FILE = 256 << 20
RUST_REPOSITORY = "https://github.com/rust-lang/rust"
_RUST_TAG = re.compile(r"^refs/tags/(\d+\.\d+\.\d+)(\^\{\})?$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def bundle_path(name: str):
    """A set's path in the bundle, from a member's -- None for what is no
    part of one, and for a name that would reach out of the directory it is
    unpacked to."""
    parts = PurePosixPath(name).parts
    if (not parts or name.startswith("/") or "\\" in name or ".." in parts or "__MACOSX" in parts
            or parts[-1].startswith("._") or not parts[-1].endswith(KEPT)):
        return None
    while len(parts) > 1 and parts[0].startswith("signatures-bundles"):
        parts = parts[1:]
    return PurePosixPath(*parts)


def members(bundle: Path):
    """(path in the bundle, size, reader) of each set file and its metadata,
    from the zip or the directory it was unpacked to."""
    if bundle.is_dir():
        for directory, subdirectories, files in os.walk(bundle):
            subdirectories[:] = sorted(d for d in subdirectories if d != "__MACOSX")
            for name in sorted(files):
                path = Path(directory) / name
                found = bundle_path(path.relative_to(bundle).as_posix())
                if found is not None and path.is_file() and not path.is_symlink():
                    yield found, path.stat().st_size, path.read_bytes
        return
    with zipfile.ZipFile(bundle) as archive:
        for info in archive.infolist():
            found = None if info.is_dir() else bundle_path(info.filename)
            if found is not None:
                yield found, info.file_size, lambda info=info: archive.read(info)


def wanted(lines: list) -> list:
    """[(line, glob in the bundle)] of the list's lines under PREFIX."""
    return [(line, line.pattern[len(PREFIX):].replace(sh.RUST_RELEASE, "*"))
            for line in lines if line.pattern.startswith(PREFIX)]


def install(bundle: Path, out: Path, lines: list, listing: bool = False) -> tuple:
    """(sets written, sets already there, {line number: sets it names})."""
    globs = wanted(lines)
    written = present = 0
    named: dict = {line.number: 0 for line, _ in globs}
    for path, size, read in members(bundle):
        stem = path.as_posix()
        stem = stem[:-len(path.suffix)]
        lines_of = [line for line, glob in globs if fnmatch.fnmatchcase(stem, glob)]
        if not lines_of:
            continue
        is_set = path.suffix == ".sig"
        if is_set:
            for line in lines_of:
                named[line.number] += 1
        if listing:
            if is_set:
                print(f"{PREFIX}{path}")
            continue
        if size > MAX_FILE:
            print(f"{path}: {size} bytes, more than a set is", file=sys.stderr)
            continue
        target = out / path
        data = read()
        if target.is_file() and target.stat().st_size == len(data) and target.read_bytes() == data:
            present += is_set
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, target)
        written += is_set
    return written, present, named


def rust_tags() -> str:
    """`git ls-remote --tags` of Rust's repository."""
    return subprocess.run(["git", "ls-remote", "--tags", RUST_REPOSITORY], capture_output=True, text=True,
                          timeout=300, check=True,
                          env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_TERMINAL_PROMPT": "0"}).stdout


def rust_releases(tags: str) -> dict:
    """release -> commit, of every Rust release in rust_tags()."""
    found: dict = {}
    for row in tags.splitlines():
        commit, _, ref = row.partition("\t")
        tag = _RUST_TAG.match(ref)
        # An annotated tag's own line names the tag object; `^{}`, the commit
        if tag and _COMMIT.match(commit) and (tag[2] or tag[1] not in found):
            found[tag[1]] = commit
    return found


def write_rust_releases(path: Path, releases: dict) -> None:
    def key(version: str) -> tuple:
        return tuple(int(n) for n in version.split("."))
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("".join(f"{releases[v]} {v}\n" for v in sorted(releases, key=key)))
    os.replace(tmp, path)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("\n\n", 1)[1])
    p.add_argument("bundle", type=Path, help="signatures-bundles-<version>.zip, or the directory it unpacks to")
    p.add_argument("--sets", type=Path, default=sh.FLIRT_SETS, help="the list of the sets samplehooks loads")
    p.add_argument("--out", type=Path, default=sh.FLIRT_DIR / PREFIX,
                   help="where the list's ida/flirt/ is (default %(default)s)")
    p.add_argument("--rust-releases", type=Path, default=sh.FLIRT_DIR / sh.RUST_RELEASES,
                   help="where each Rust release's commit is written (default %(default)s)")
    p.add_argument("--no-rust-releases", action="store_true", help="do not ask GitHub for Rust's releases")
    p.add_argument("--list", action="store_true", help="print the sets that would be installed and stop")
    args = p.parse_args(argv)
    if not args.bundle.exists():
        p.error(f"{args.bundle}: no such file or directory")
    try:
        lines = sh.flirt_sets(args.sets.read_text())
        written, present, named = install(args.bundle, args.out, lines, args.list)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"{args.bundle}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    by_number = {line.number: line for line in lines}
    for number, count in named.items():
        if not count:
            print(f"{args.sets.name}:{number}: {by_number[number].pattern}: no set of that name in {args.bundle}",
                  file=sys.stderr)
    if args.list:
        return 0
    print(f"{written} sets written to {args.out}, {present} already there")
    if not args.no_rust_releases and any(sh.RUST_RELEASE in line.pattern for line in lines):
        try:
            releases = rust_releases(rust_tags())
            if not releases:
                raise ValueError("no release tag")
            write_rust_releases(args.rust_releases, releases)
            print(f"{len(releases)} Rust releases' commits written to {args.rust_releases}")
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            # Not the sets' failure: a Rust program then needs its .comment
            print(f"Rust releases: {type(exc).__name__}: {exc}", file=sys.stderr)
    return 0 if written + present else 1


if __name__ == "__main__":
    sys.exit(main())
