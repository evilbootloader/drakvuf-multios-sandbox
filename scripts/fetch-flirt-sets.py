#!/usr/bin/env python3
"""FLIRT sets for many versions of glibc, musl and uClibc, each with the GCC
that built it, from published toolchains.

    scripts/fetch-flirt-sets.py                      # every stable release, x86-64 and i686
    scripts/fetch-flirt-sets.py --libc uclibc --newest 3
    scripts/fetch-flirt-sets.py --list               # what the index has; nothing downloaded

A statically linked sample carries the C library of whoever built it, in the
version and with the compiler they had. A signature set made from another
build names nothing in it (scripts/gen-flirt-pats.py), so the sets have to
cover the builds samples come from: three C libraries, a decade of versions,
two architectures.

**Where they come from.** Bootlin publishes Buildroot cross toolchains for
every combination of architecture, C library (glibc, musl, uClibc-ng) and
release, each with a checksum and a summary naming the versions inside:
https://toolchains.bootlin.com. One index for all three libraries, so nothing
here is a list of URLs: the script reads the index, and a release published
tomorrow is fetched the next time it runs. From each toolchain only the
static libraries are read -- the C library's (`libc.a`, `libpthread.a`,
`libm.a` and the rest of `sysroot/usr/lib`) and the compiler's `libgcc.a` --
straight off the download; the 150 MB archive is never written to disk.

A set is named `<libc>-<version>-gcc-<version>-<arch>`, and a toolchain whose
versions are already a set is skipped, so a second run fetches only what is
new. Each archive is checked against the index's sha256 before its set is
kept.

**What this does not have:** uClibc 0.9.x, the library of the IoT bots of
2016-2018 -- Bootlin starts at uClibc-ng 1.0, in 2017 -- and any vendor's
own build (a distribution's glibc is compiled with its own flags and
patches: for those, `gen-flirt-pats.py` on that distribution's `libc.a`).

Sets go to `sandboxd/data/flirt/`, which is not tracked: they are data made
from other people's binaries, rebuilt by running this.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import io
import re
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("gen_flirt_pats", HERE / "gen-flirt-pats.py")
pats = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pats)

INDEX = "https://toolchains.bootlin.com/downloads/releases/toolchains"
ARCHES = ("x86-64", "x86-i686")
LIBCS = ("glibc", "musl", "uclibc")
#: The summary's package name of each C library.
PACKAGE = {"glibc": "glibc", "musl": "musl", "uclibc": "uclibc"}
#: Static libraries taken from a toolchain: the C library's own, and the
#: compiler's runtime. Not libstdc++: tens of megabytes of templates that
#: match nothing but the program they were instantiated for.
WANTED = re.compile(r"(?:^|/)sysroot/(?:usr/)?lib(?:32|64)?/lib(?:c|pthread|m|rt|dl|resolv|util|crypt|nsl|anl)\.a$"
                    r"|(?:^|/)lib/gcc/[^/]+/[^/]+/libgcc(?:_eh)?\.a$")
#: Most a single static library may be: libc.a is 5 to 30 MB.
MAX_LIBRARY = 256 << 20
USER_AGENT = "sandbox-flirt-sets/1"


def get(url: str, timeout: float = 120):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": USER_AGENT}), timeout=timeout)


def releases(arch: str) -> list:
    """[(file name, libc, channel, release)] of an architecture's toolchains,
    oldest first, as its index lists them."""
    html = get(f"{INDEX}/{arch}/tarballs/").read().decode("utf-8", "replace")
    found = re.findall(r'href="(%s--(\w+)--([a-z-]+)-(\d{4}\.\d{2}-\d+)\.tar\.\w+)"' % re.escape(arch), html)
    return sorted(set(found), key=lambda r: (r[3], r[2], r[1]))


def versions(arch: str, stem: str) -> dict:
    """package -> version, from the toolchain's summary."""
    text = get(f"{INDEX}/{arch}/summaries/{stem}.csv").read().decode("utf-8", "replace")
    return {row[0]: row[1] for row in csv.reader(io.StringIO(text)) if len(row) > 1}


def set_name(libc: str, arch: str, found: dict) -> str | None:
    library, compiler = found.get(PACKAGE[libc]), found.get("gcc-final") or found.get("gcc")
    if not library or not compiler:
        return None
    # glibc's is `git describe` of its release branch, at times with the
    # project's name in front: glibc-2.26-144-gbbabb868... is 2.26-144
    library = re.sub(r"-g[0-9a-f]{7,}$", "", library.removeprefix(libc + "-"))
    return f"{libc}-{library}-gcc-{compiler}-{arch}"


class Hashed:
    """A response read through, with the sha256 of what went by."""

    def __init__(self, raw):
        self.raw, self.sha = raw, hashlib.sha256()

    def read(self, n=-1):
        data = self.raw.read(n)
        self.sha.update(data)
        return data


def libraries(arch: str, name: str, into: Path) -> tuple:
    """The wanted static libraries of a toolchain, written under `into`, and
    the archive's sha256. The archive is read as it downloads."""
    stream = Hashed(get(f"{INDEX}/{arch}/tarballs/{name}", timeout=600))
    kept = []
    with tarfile.open(fileobj=stream, mode="r|*") as tar:
        for member in tar:
            if not member.isfile() or not WANTED.search(member.name) or member.size > MAX_LIBRARY:
                continue
            # by number, never by the archive's own path
            target = into / f"{len(kept):03d}-{Path(member.name).name}"
            with tar.extractfile(member) as src, target.open("wb") as dst:
                while block := src.read(1 << 20):
                    dst.write(block)
            kept.append(target)
    while stream.read(1 << 20):
        pass        # the padding after the last member is part of the checksum
    return kept, stream.sha.hexdigest()


def expected_sha256(arch: str, stem: str) -> str:
    return get(f"{INDEX}/{arch}/tarballs/{stem}.sha256").read().decode().split()[0]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("\n\n", 1)[1])
    p.add_argument("--arch", default=",".join(ARCHES), help=f"comma-separated, of {', '.join(ARCHES)}")
    p.add_argument("--libc", default=",".join(LIBCS), help=f"comma-separated, of {', '.join(LIBCS)}")
    p.add_argument("--channel", default="stable", choices=["stable", "bleeding-edge", "all"],
                   help="stable (default) is each release's older, settled versions; bleeding-edge its newest")
    p.add_argument("--newest", type=int, default=0, help="only the N newest releases of each library and architecture")
    p.add_argument("--list", action="store_true", help="print what would be fetched and stop")
    p.add_argument("--out", type=Path, default=HERE.parent / "sandboxd" / "data" / "flirt")
    args = p.parse_args(argv)
    arches, libcs = args.arch.split(","), args.libc.split(",")
    if set(arches) - set(ARCHES) or set(libcs) - set(LIBCS):
        p.error("unknown --arch or --libc")

    made = failed = 0
    for arch in arches:
        listed = [r for r in releases(arch) if r[1] in libcs and args.channel in ("all", r[2])]
        for libc in libcs:
            mine = [r for r in listed if r[1] == libc]
            for name, _, channel, release in mine[-args.newest:] if args.newest else mine:
                stem = name.split(".tar.")[0]
                try:
                    title = set_name(libc, arch, versions(arch, stem))
                except OSError as exc:
                    print(f"{stem}: no summary ({exc})", file=sys.stderr)
                    failed += 1
                    continue
                if title is None:
                    print(f"{stem}: its summary names no {libc} or no gcc", file=sys.stderr)
                    failed += 1
                    continue
                if (args.out / f"{title}.pat.gz").exists():
                    print(f"{title}: already there ({stem})")
                    continue
                if args.list:
                    print(f"{title}  <-  {stem}")
                    continue
                with tempfile.TemporaryDirectory(prefix="flirt-") as tmp:
                    try:
                        found, digest = libraries(arch, name, Path(tmp))
                        if digest != expected_sha256(arch, stem):
                            raise ValueError("sha256 differs from the index's")
                        count = pats.write_set(title, found, args.out)
                    except (OSError, ValueError, tarfile.TarError) as exc:
                        print(f"{stem}: {type(exc).__name__}: {exc}", file=sys.stderr)
                        failed += 1
                        continue
                if count:
                    made += 1
                    print(f"{title}: {count} functions from {len(found)} libraries ({stem})")
                else:
                    print(f"{stem}: no static library with a function in it", file=sys.stderr)
                    failed += 1
    if not args.list:
        print(f"{made} sets written to {args.out}" + (f", {failed} toolchains failed" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
