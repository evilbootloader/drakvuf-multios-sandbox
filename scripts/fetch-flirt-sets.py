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

**Go** (`--go newest:6`, `--go 1.24,1.25.3`). A Go program carries its
standard library compiled into it, and a stripped one still has its function
table -- unless garble built it: then every name in that table but the
runtime's is a hash, and the table's magic is random, so the names that
`go-hooks.txt` lists are found by their bytes or not at all. Go publishes
no compiled library to read, so each release is downloaded (go.dev/dl, its
sha256 from the same index) and made to compile a probe program that refers
to every function `go-hooks.txt` names, linked externally: the linker then
leaves `go.o`, one ELF object with every function the probe has and its
relocations, which is what `gen-flirt-pats.py` reads. Built as a malware
author builds Go, without cgo's own code (`netgo`, `osusergo`) and for the
baseline amd64. A set is named `go-<version>-amd64` and has no rule: Go's
sets are tried on Go programs only, all of them, and the one that names
most is used (samplehooks.go_sets). Needs gcc, for the external link.
`--go-root` builds one set from a Go that is installed instead.

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
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

import struct


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


# --- Rust's standard library ---------------------------------------------------
#
# A stripped Rust program has no names left, but it does say which compiler
# built it: panic messages carry `/rustc/<commit>/library/...` paths. The
# standard library of exactly that compiler is published
# (static.rust-lang.org/dist/rust-std-<version>-<target>.tar.xz, with a
# sha256 beside it), its `.rlib` files are `ar` archives of ordinary objects,
# and the archive names its own commit. So a set per release, recognised in a
# sample by the commit and by nothing weaker.
#
# What such a set names is the non-generic part of std, core and alloc.
# Generic code is compiled into each program anew and matches nothing. ELF
# targets only: the patterns are made from ELF objects.
RUST_DIST = "https://static.rust-lang.org/dist"
RUST_TARGETS = ("x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl",
                "i686-unknown-linux-gnu", "i686-unknown-linux-musl")
RUST_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
RUST_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def rust_libraries(version: str, target: str, into: Path) -> tuple:
    """(the release's .rlib files under `into`, its commit, the archive's sha256)."""
    stream = Hashed(get(f"{RUST_DIST}/rust-std-{version}-{target}.tar.xz", timeout=900))
    kept, commit = [], ""
    with tarfile.open(fileobj=stream, mode="r|*") as tar:
        for member in tar:
            if not member.isfile() or member.size > MAX_LIBRARY:
                continue
            if member.name.count("/") == 1 and member.name.endswith("/git-commit-hash"):
                commit = tar.extractfile(member).read(64).decode("ascii", "replace").strip()
            elif member.name.endswith(".rlib") and f"/lib/rustlib/{target}/lib/" in member.name:
                target_file = into / f"{len(kept):03d}.rlib"
                with tar.extractfile(member) as src, target_file.open("wb") as dst:
                    while block := src.read(1 << 20):
                        dst.write(block)
                kept.append(target_file)
    while stream.read(1 << 20):
        pass
    return kept, commit, stream.sha.hexdigest()


def rust_rule(name: str, commit: str) -> str:
    identifier = "flirt_set_" + "".join(c if c.isalnum() else "_" for c in name)
    return ('rule %s\n{\n    meta:\n        flirt_set = "%s"\n        flirt_exact = true\n'
            '    strings:\n        $commit = "/rustc/%s/"\n    condition:\n        $commit\n}\n'
            % (identifier, name, commit))


def fetch_rust(versions: list, targets: list, out: Path, listing: bool) -> tuple:
    made = failed = 0
    for version in versions:
        for target in targets:
            title = f"rust-{version}-{target}"
            if (out / f"{title}.pat.gz").exists():
                print(f"{title}: already there")
                continue
            if listing:
                print(f"{title}  <-  {RUST_DIST}/rust-std-{version}-{target}.tar.xz")
                continue
            with tempfile.TemporaryDirectory(prefix="flirt-") as tmp:
                try:
                    found, commit, digest = rust_libraries(version, target, Path(tmp))
                    said = get(f"{RUST_DIST}/rust-std-{version}-{target}.tar.xz.sha256").read().decode().split()[0]
                    if digest != said:
                        raise ValueError("sha256 differs from the one published beside it")
                    if not RUST_COMMIT.match(commit):
                        raise ValueError("the archive does not name its commit")
                    count = pats.write_set(title, found, out)
                except (OSError, ValueError, tarfile.TarError) as exc:
                    print(f"{title}: {type(exc).__name__}: {exc}", file=sys.stderr)
                    failed += 1
                    continue
            if not count:
                print(f"{title}: no function in its libraries", file=sys.stderr)
                failed += 1
                continue
            # recognised by its compiler's commit, not by libc's functions
            (out / f"{title}.yar").write_text(rust_rule(title, commit))
            made += 1
            print(f"{title}: {count} functions from {len(found)} libraries (rustc {commit[:12]})")
    return made, failed


GO_INDEX = "https://go.dev/dl/?mode=json&include=all"
GO_DL = "https://go.dev/dl"
GO_HOOKS = HERE.parent / "sandboxd" / "data" / "go-hooks.txt"
GO_RELEASE = re.compile(r"^go(\d+)\.(\d+)(?:\.(\d+))?$")
#: `net.Dial`, `net/http.(*Client).Do`, `registry.Key.GetStringValue`: an
#: exported function or method of a package, as Go's table spells it
GO_NAME = re.compile(r"^([a-z0-9_]+(?:/[a-z0-9_.]+)*)\.(?:\((\*?)([A-Z]\w*)\)\.|([A-Z]\w*)\.)?([A-Z]\w*)$")
#: Compile errors the probe is trimmed of before giving up on a release
GO_ATTEMPTS = 8
#: The oldest release the probe is built with: modules came in Go 1.11, and
#: an older one is said and passed over, not counted as a failure
GO_OLDEST = (1, 11)


def go_releases(index: list, wanted: str) -> list:
    """The stable releases `wanted` names, oldest first: `newest:N` (the
    newest patch of each of the N newest minor versions), `1.24` (its newest
    patch), `1.25.3`. Comma-separated."""
    stable: dict = {}
    for release in index:
        found = GO_RELEASE.match(str(release.get("version", "")))
        if release.get("stable") and found:
            stable[(int(found[1]), int(found[2]), int(found[3] or 0))] = release["version"]
    minors: dict = {}
    for key in sorted(stable):
        minors[key[:2]] = key
    chosen = set()
    for spec in filter(None, (w.strip() for w in wanted.split(","))):
        if spec.startswith("newest:"):
            chosen.update(sorted(minors.values())[-int(spec.split(":", 1)[1]):])
            continue
        parts = tuple(int(n) for n in spec.removeprefix("go").split("."))
        if len(parts) == 2 and parts in minors:
            chosen.add(minors[parts])
        elif len(parts) == 3 and parts in stable:
            chosen.add(parts)
        else:
            raise ValueError(f"no stable Go release {spec}")
    return [stable[key] for key in sorted(chosen)]


def go_archive(index: list, version: str, platform: str, arch: str) -> dict:
    return next(f for release in index if release["version"] == version for f in release["files"]
                if f["os"] == platform and f["arch"] == arch and f["kind"] == "archive")


def go_probe(names) -> str:
    """A Go program referring to each exported function or method of the
    standard library that `names` has, as a value: the linker keeps a
    function a program refers to, and with it everything it calls. Packages
    outside it (golang.org/x/...) are left out: nothing is downloaded."""
    imports: dict = {}
    lines = []
    for name in sorted(set(names)):
        found = GO_NAME.match(name)
        if not found:
            continue
        path, star, pointer_type, value_type, function = found.groups()
        if path.startswith("vendor/") or path == "internal" or path.startswith("internal/") or "/internal/" in path:
            continue
        alias = imports.setdefault(path, f"p{len(imports)}")
        if pointer_type:
            lines.append(f"\t({star}{alias}.{pointer_type}).{function}, // {name}")
        elif value_type:
            lines.append(f"\t{alias}.{value_type}.{function}, // {name}")
        else:
            lines.append(f"\t{alias}.{function}, // {name}")
    head = "".join(f'\t{alias} "{path}"\n' for path, alias in imports.items())
    return ("package main\n\nimport (\n" + head + ")\n\nvar probe = []interface{}{\n"
            + "\n".join(lines) + "\n}\n\nfunc main() { println(len(probe)) }\n")


def _trim(source: str, errors: str) -> str:
    """The probe without the lines the compiler refused: a function this
    release does not have, an import nothing is left to use."""
    bad = {int(n) for n in re.findall(r"main\.go:(\d+):\d+:", errors)}
    kept = [line for n, line in enumerate(source.splitlines(), 1) if n not in bad]
    return "\n".join(kept) + "\n"


def go_version(goroot: Path, home: Path) -> str:
    """`go1.22.2`, from `go version` (`go env GOVERSION` is Go 1.16's)."""
    said = subprocess.run([str(goroot / "bin" / "go"), "version"], capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", "GOROOT": str(goroot), "HOME": str(home)},
                          check=True).stdout.split()
    return said[2] if len(said) > 2 else ""


def build_go_set(goroot: Path, title: str, out: Path, tmp: Path, names, goos: str, goarch: str) -> int:
    """`title`'s set from the Go at `goroot`: the probe, linked externally,
    and gen-flirt-pats over the `go.o` its linker leaves. The number of
    functions; raises on a build that does not succeed."""
    go = goroot / "bin" / "go"
    version = go_version(goroot, tmp)
    found = GO_RELEASE.match(version)
    if not found:
        raise ValueError(f"{goroot} says it is {version!r}")
    minor = (int(found[1]), int(found[2]))
    probe, link = tmp / "probe", tmp / "link"
    probe.mkdir()
    link.mkdir()
    (probe / "go.mod").write_text(f"module probe\n\ngo {found[1]}.{found[2]}\n")
    env = {"PATH": f"{goroot}/bin:/usr/bin:/bin", "GOROOT": str(goroot), "HOME": str(tmp),
           "GOCACHE": str(tmp / "cache"), "GOPATH": str(tmp / "gopath"), "GOTOOLCHAIN": "local",
           "GOPROXY": "off", "GOSUMDB": "off", "GOFLAGS": "", "GO111MODULE": "on",
           "GOOS": goos, "GOARCH": goarch, "GOAMD64": "v1", "CGO_ENABLED": "1"}
    if goos == "windows" and goarch == "386":
        env.update({"CXX": "i686-w64-mingw32-g++", "CC": "i686-w64-mingw32-gcc"})
    elif goos == "windows" and goarch == "amd64":
        env.update({"CXX": "x86_64-w64-mingw32-g++", "CC": "x86_64-w64-mingw32-gcc"})
    # -trimpath is Go 1.13's, and changes file names, not code
    trim = ["-trimpath"] if minor >= (1, 13) else []
    source = go_probe(names)
    for _ in range(GO_ATTEMPTS):
        (probe / "main.go").write_text(source)
        for stale in link.iterdir():
            stale.unlink()
        tags = "netgo osusergo" if minor < (1, 13) else "netgo,osusergo"
        built = subprocess.run(
            [str(go), "build", *trim, "-tags", tags,
             "-ldflags", f"-linkmode=external -tmpdir={link}", "-o", str(tmp / "probe.bin"), "."],
            cwd=probe, env=env, capture_output=True, text=True, timeout=900)
        if built.returncode == 0:
            break
        trimmed = _trim(source, built.stderr)
        if trimmed != source:
            source = trimmed
            continue
        # The system linker refusing an old Go's object (a PIE default it
        # predates) comes after go.o is written, and go.o is all that is read
        if (link / "go.o").is_file() and "main.go:" not in built.stderr:
            break
        raise ValueError(f"the probe does not build: {built.stderr.strip()[-400:]}")
    else:
        raise ValueError("the probe does not build")
    if not (link / "go.o").is_file():
        raise ValueError("the linker left no go.o")

    return pats.write_set(title, [link / "go.o"], out, local=True)


def go_hook_names(path: Path = GO_HOOKS) -> list:
    return [line.split(",")[1] for line in path.read_text().splitlines() if line.startswith("go,")]

GO_TARGETS =  [("linux", "amd64"), ("linux", "386"), ("windows", "amd64"), ("windows", "386")]


def fetch_go(
    wanted: str,
    out: Path,
    listing: bool,
    goroot: Path | None = None,
) -> tuple:
    names = go_hook_names()
    made = failed = 0

    if goroot is not None:
        with tempfile.TemporaryDirectory(prefix="flirt-go-") as tmp:
            versions = [go_version(goroot, Path(tmp))]
        index = None
    else:
        index = json.load(get(GO_INDEX))
        versions = go_releases(index, wanted)

    for version in versions:
        found = GO_RELEASE.match(version)
        if not found:
            raise ValueError(f"invalid Go version: {version}")

        if (int(found[1]), int(found[2])) < GO_OLDEST:
            print(f"{version}: too old; skipped")
            continue

        pending = []

        for goos, goarch in GO_TARGETS:
            title = (
                f"go-{version.removeprefix('go')}"
                f"-{goos}-{goarch}"
            )

            if (out / f"{title}.pat.gz").exists():
                print(f"{title}: already there")
            else:
                pending.append((goos, goarch, title))

        if not pending:
            continue

        # The Go compiler runs on Linux, even when the
        # target executable is Windows.
        archive = None
        if goroot is None:
            try:
                archive = go_archive(
                    index, version, "linux", "amd64"
                )
            except (KeyError, StopIteration) as exc:
                print(f"{version}: {exc}", file=sys.stderr)
                failed += len(pending)
                continue

        if listing:
            source = (
                str(goroot) if goroot is not None
                else f"{GO_DL}/{archive['filename']}"
            )
            for goos, goarch, title in pending:
                print(
                    f"{title}  <-  {source}"
                    f" (target {goos}/{goarch})"
                )
            continue

        with tempfile.TemporaryDirectory(
            prefix="flirt-go-"
        ) as tmp:
            base = Path(tmp)
            root = goroot

            if root is None:
                try:
                    tarball = base / archive["filename"]
                    digest = hashlib.sha256()

                    with get(
                        f"{GO_DL}/{archive['filename']}",
                        timeout=600,
                    ) as response, tarball.open("wb") as fh:
                        for chunk in iter(
                            lambda: response.read(1 << 20),
                            b"",
                        ):
                            digest.update(chunk)
                            fh.write(chunk)

                    if digest.hexdigest() != archive["sha256"]:
                        raise ValueError("Go archive SHA256 mismatch")

                    with tarfile.open(tarball) as tar:
                        tar.extractall(base / "root", filter="data")

                    tarball.unlink()
                    root = base / "root" / "go"

                except (
                    OSError,
                    ValueError,
                    tarfile.TarError,
                ) as exc:
                    print(
                        f"{version}: download failed: {exc}",
                        file=sys.stderr,
                    )
                    failed += len(pending)
                    continue

            for goos, goarch, title in pending:
                work = base / f"work-{goos}-{goarch}"
                work.mkdir()

                try:
                    count = build_go_set(
                        root,
                        title,
                        out,
                        work,
                        names,
                        goos=goos,
                        goarch=goarch,
                    )

                    if not count:
                        raise ValueError(
                            "no functions extracted from go.o"
                        )

                except (
                    OSError,
                    ValueError,
                    subprocess.SubprocessError,
                ) as exc:
                    print(
                        f"{title}: {type(exc).__name__}: {exc}",
                        file=sys.stderr,
                    )
                    failed += 1
                    continue

                made += 1
                print(f"{title}: {count} functions")

    print(made)
    return made, failed



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
    p.add_argument("--rust", default="",
                   help="comma-separated Rust releases (1.75.0): sets from their standard library "
                        "instead of the C libraries. A job's report says which release a sample needs")
    p.add_argument("--rust-target", default=",".join(RUST_TARGETS[:2]),
                   help=f"comma-separated, of {', '.join(RUST_TARGETS)}")
    p.add_argument("--go", default="",
                   help="Go releases to build sets of, instead of the C libraries: newest:N, "
                        "a minor version (1.24) or a release (1.25.3), comma-separated")
    p.add_argument("--go-root", type=Path, help="build one Go set from this installed Go (its GOROOT)")
    args = p.parse_args(argv)
    if args.go or args.go_root:
        try:
            made, failed = fetch_go(args.go, args.out, args.list, args.go_root)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            p.error(f"Go: {exc}")
        if not args.list:
            print(f"{made} Go sets written to {args.out}" + (f", {failed} failed" if failed else ""))
        return 1 if failed else 0
    if args.rust:
        versions_, targets = args.rust.split(","), args.rust_target.split(",")
        if not all(RUST_VERSION.match(v) for v in versions_) or set(targets) - set(RUST_TARGETS):
            p.error("unknown --rust release or --rust-target")
        made, failed = fetch_rust(versions_, targets, args.out, args.list)
        if not args.list:
            print(f"{made} sets written to {args.out}" + (f", {failed} failed" if failed else ""))
        return 1 if failed else 0
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
