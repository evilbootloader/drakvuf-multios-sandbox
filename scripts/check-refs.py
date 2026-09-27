#!/usr/bin/env python3
"""Resolve every cross-reference in the repository's markdown, and fail on a dead one.

**Why this exists.** Prose is the largest artifact in this repository and the
only one with no verification loop. Shell has `shellcheck`, Perl has `perl -c`,
Python has the test suite; 43k lines of markdown dense with load-bearing
`file:line` references had nothing. Two real examples, neither of which turned
anything red:

- Runbooks 11 and 12 both cited `scripts/gen-current-state.py:141` for the
  `docs.rglob` count. Editing the generator moved it to `:155`.
- `docs/INDEX.md` now carries ~1000 `#anchor` links, and an anchor is derived
  from heading *text*. Rewording a heading breaks every link to it, silently.

Three reference kinds are checked:

    [text](path)            path exists
    [text](path#anchor)     path exists AND the heading slug exists in it
    `path:line`             path exists AND the file has at least that many lines

    scripts/check-refs.py           # report and exit 1 on any failure
    scripts/check-refs.py --list    # print every reference found, then exit 0

**It ships with an allowlist, deliberately** — the same device `.shellcheckrc`
already is here. Living documents legitimately name files that were renamed,
files not yet built, and upstream DRAKVUF sources that this repository does not
own. A gate that is red by default gets ignored (the DRAFT-031 lesson), so those
are enumerated below with a reason each, and anything *not* enumerated is a
defect.

**Submodule working trees are not walked** — see `_SUBMODULES` below. Since
2026-09-26 upstream DRAKVUF is checked out at `drakvuf/`, so "not in this tree"
became "not ours", and the distinction is now load-bearing rather than
incidental.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _index_module():
    """Reuse `gen-doc-index.py`'s slug and cleanup functions rather than
    reimplementing them.

    Two copies of GitHub's undocumented algorithm would drift, and the failure
    would be links that this gate calls fine and GitHub 404s. That is not
    hypothetical -- the first version of this file reimplemented only `anchor`
    and reported five false failures against headings of the form
    `# Deploying the database — issue [#35](url)`. **GitHub slugs the RENDERED
    text**, so the link has to be flattened to `issue #35` first. The generator
    already did that and the checker did not.
    """
    spec = importlib.util.spec_from_file_location(
        "gen_doc_index", ROOT / "scripts" / "gen-doc-index.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_gen = _index_module()
anchor, clean = _gen.anchor, _gen._clean

# Markdown link, excluding images. Bare `<url>` autolinks are not matched.
_MDLINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)")

# Inline code spans, stripped before link matching. **Link syntax inside
# backticks is an example, not a link** -- documentation that explains the
# convention has to show it, and `.claude/skills/runbook/SKILL.md` does exactly
# that. Scanning it raw produced a failure against a path that was never meant
# to resolve, which is the kind of false positive that gets a gate switched off.
_CODESPAN = re.compile(r"`[^`]*`")

# `path:line` inside backticks. The extension list is deliberate: an open
# pattern matches things like `172.16.1.1/24` and `08:2351`, which are not paths.
_FILELINE = re.compile(
    r"`([\w./-]+\.(?:py|sh|c|h|pl|md|env|cfg|json|txt|yml|yaml|service|ini)):(\d+)`")

_HEADING = re.compile(r"^(#{1,6}) +(\S.*?)\s*#*\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")

_SKIP_SCHEME = ("http://", "https://", "mailto:", "ftp://", "#")

# Directories with nothing worth checking, or nothing we own.
_PRUNE = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache",
          "build", "dist", ".mypy_cache"}


def _submodule_paths() -> frozenset[Path]:
    """Every submodule working tree, read from `.gitmodules` rather than named
    here so a second submodule needs no code change.

    **Pruning these is correctness, not speed.** `ALLOW_PATHS` below lists
    upstream DRAKVUF sources (`src/main.cpp`, `src/libdrakvuf/vmi.c`, …) as
    deliberately unresolvable, because a reference to them means "go read the
    engine", not "this repository ships that file". Walking `drakvuf/` would
    make `suffix_resolve` match them for real, turning six reviewed allowlist
    entries into silent passes against files nobody here maintains -- and the
    `:line` check would then start failing whenever upstream edits a file.

    Only the top-level `.gitmodules` is read. The nested trees (`xen`,
    `libvmi`, `volatility3`, `dwarf2json`) need no entry of their own: they sit
    underneath `drakvuf/`, so pruning the parent already excludes them.
    """
    gitmodules = ROOT / ".gitmodules"
    if not gitmodules.is_file():
        return frozenset()
    return frozenset(
        ROOT / m.group(1).strip()
        for m in re.finditer(r"^\s*path\s*=\s*(.+?)\s*$",
                             gitmodules.read_text(), re.M))


_SUBMODULES = _submodule_paths()


def _walk(pattern: str) -> list[Path]:
    """`ROOT.rglob(pattern)`, but pruning `_PRUNE` and submodules as it
    descends rather than filtering afterwards.

    `rglob` has no way to skip a subtree, so it would stat all 4,300 files
    under `drakvuf/` on every run -- and this gate runs inside the sandboxd
    suite, where that is paid on every `pytest` invocation.
    """
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        here = Path(dirpath)
        dirnames[:] = [d for d in dirnames
                       if d not in _PRUNE and here / d not in _SUBMODULES]
        out.extend(p for name in filenames
                   if (p := here / name).match(pattern))
    return out


# ---------------------------------------------------------------------------
# Reviewed allowlist. Every entry names WHY it cannot resolve.
#
# Add a line here only when the reference is deliberate and the target genuinely
# is not in this tree. A reference that is simply stale is a defect: fix the
# reference, do not silence it.
# ---------------------------------------------------------------------------
ALLOW_PATHS = {
    # Renamed or deleted, and named on purpose so the old name stays findable.
    # CURRENT-STATE.md's superseded-facts table exists to carry exactly these.
    "automation/clone-ubuntu.pl",
    "misc/linux.cfg",
    "profiles/linux.json",
    "docs/runbooks/verify-android-mvp.md",
    "docs/runbooks/verify-user-placeholder.md",
    "docs/runbooks/deploy-vlan-lease.md",
    "docs/runbooks/tune-nested-cpu.md",

    # The shell/C launcher pipeline, removed 2026-09-15 once `sandboxd` had
    # replaced all of it. Runbooks 01-15, the issue drafts and the reviews cite
    # these paths as DATED EVIDENCE and are never rewritten, so the names have
    # to keep resolving here. What replaced each one:
    #
    #   dirwatch.c, dirwatch_old.c  -> sandboxd/daemon.py (the watch loop and
    #                                  the single-instance guard) and
    #                                  sandboxd/stages.py (the phase sequence)
    #   clone.pl                    -> sandboxd/clone.py
    #   cleanup.sh                  -> sandboxd/proc.py + sandboxd/sweep.py
    #   tcpdump.sh                  -> sandboxd/guests.py::argv_tcpdump
    #   run_analysis-{ubuntu,android}.sh -> sandboxd/daemon.py
    #   drakvuf-{ubuntu,android}.sh      -> sandboxd/guests.py
    #   preconfig-{ubuntu,android}.sh    -> sandboxd/guests.py
    #   pipeline-{ubuntu,android}.env    -> sandboxd/config.py + sandboxd/timing.py
    #
    # `docs/architecture/automation-files.md` holds the full mapping and the
    # facts worth keeping from their comments.
    "automation/dirwatch.c",
    "automation/dirwatch_old.c",
    "automation/clone.pl",
    "automation/cleanup.sh",
    "automation/tcpdump.sh",
    "automation/run_analysis-ubuntu.sh",
    "automation/run_analysis-android.sh",
    "automation/drakvuf-ubuntu.sh",
    "automation/drakvuf-android.sh",
    "automation/preconfig-ubuntu.sh",
    "automation/preconfig-android.sh",
    "automation/pipeline-ubuntu.env",
    "automation/pipeline-android.env",

    # Not built yet. Named by the Windows track, which is open.
    "profiles/windows.json",
    "misc/windows_sandbox.cfg",
    "automation/pipeline-windows.env",

    # Not git-tracked -- a fresh checkout has neither, by design.
    "profiles/android.json",
    "profiles/ubuntu.json",

    # Upstream DRAKVUF, a separate checkout. Paths are relative to ITS tree.
    "src/plugins/plugins.h",
    "src/main.cpp",
    "src/libdrakvuf/vmi.c",
    "src/plugins/syscalls/linux.cpp",
    "src/dirwatch/dirwatch.c",
    "tools/cleanup.sh",
}

# Anchors that are correct but unresolvable here: they point into files this
# gate does not parse for headings (non-markdown), or into generated output.
ALLOW_ANCHORS: set[tuple[str, str]] = set()


def tracked_files() -> list[Path]:
    return _walk("*")


def suffix_resolve(ref: str, files: list[Path]) -> Path | None:
    """`network-setup.sh` -> `automation/network-setup.sh`;
    `routers/worker.py` -> `platform/sandbox_platform/routers/worker.py`.

    **Partial paths are a deliberate convention here**, not sloppiness: the
    issue drafts and checklists say `preconfig-ubuntu.sh:206` because the
    directory was obvious in context and the full path was noise. A checker that
    rejected those produced 167 false positives on its first run and would have
    been turned off within the day. (That particular file is now deleted and its
    bare name lands in the `skipped` bucket below -- which is the same outcome,
    for the same reason.)

    Only a *unique* suffix match resolves. An ambiguous one is skipped rather
    than guessed -- checking the wrong file is worse than not checking, because
    it reports a confident pass.
    """
    want = tuple(ref.split("/"))
    hits = [p for p in files
            if tuple(p.relative_to(ROOT).parts)[-len(want):] == want]
    return hits[0] if len(hits) == 1 else None


def markdown_files() -> list[Path]:
    return sorted(_walk("*.md"))


def headings_of(path: Path) -> set[str]:
    """Every anchor slug the file offers, fences excluded."""
    slugs, in_fence = set(), False
    for line in path.read_text(errors="replace").splitlines():
        if _FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = _HEADING.match(line)
        if m:
            slugs.add(anchor(clean(m.group(2))))
    return slugs


def check() -> tuple[list[str], list[str], int]:
    problems: list[str] = []
    skipped: list[str] = []
    checked = 0
    heading_cache: dict[Path, set[str]] = {}
    files = tracked_files()

    for src in markdown_files():
        text = src.read_text(errors="replace")
        rel_src = src.relative_to(ROOT)

        for n, raw in enumerate(text.splitlines(), 1):
            # `path:line` references are *expected* inside backticks, so they
            # are matched against the raw line; markdown links are not.
            line = _CODESPAN.sub("``", raw)
            for target in _MDLINK.findall(line):
                if target.startswith(_SKIP_SCHEME):
                    continue
                path_part, _, frag = target.partition("#")
                if not path_part:
                    continue
                checked += 1
                resolved = (src.parent / path_part).resolve()
                try:
                    rel_t = resolved.relative_to(ROOT).as_posix()
                except ValueError:
                    rel_t = path_part

                if not resolved.exists():
                    if rel_t in ALLOW_PATHS or path_part in ALLOW_PATHS:
                        continue
                    problems.append(f"{rel_src}:{n}: link target missing: {target}")
                    continue

                if frag and resolved.suffix == ".md":
                    if (rel_t, frag) in ALLOW_ANCHORS:
                        continue
                    if resolved not in heading_cache:
                        heading_cache[resolved] = headings_of(resolved)
                    if frag not in heading_cache[resolved]:
                        problems.append(
                            f"{rel_src}:{n}: no such heading in {rel_t}: #{frag}")

            for path_part, number in _FILELINE.findall(raw):
                checked += 1
                resolved = (ROOT / path_part)
                if not resolved.exists():
                    alt = (src.parent / path_part).resolve()
                    if alt.exists():
                        resolved = alt
                    else:
                        hit = suffix_resolve(path_part, files)
                        if hit is not None:
                            resolved = hit
                        elif path_part in ALLOW_PATHS or "/" not in path_part:
                            # **A known gap, counted rather than hidden.** A
                            # bare name that resolves nowhere is either a
                            # deliberately-named renamed file (`clone-ubuntu.pl`)
                            # or a typo, and nothing distinguishes them. Failing
                            # on it would reject the convention above; so it is
                            # reported as a number and never as an error.
                            skipped.append(f"{rel_src}:{n}: `{path_part}`")
                            continue
                        else:
                            problems.append(
                                f"{rel_src}:{n}: `{path_part}:{number}` -- "
                                f"no such file")
                            continue
                if resolved.is_dir():
                    continue
                total = len(resolved.read_text(errors="replace").splitlines())
                if int(number) > total:
                    problems.append(
                        f"{rel_src}:{n}: `{path_part}:{number}` is past EOF "
                        f"({total} lines)")

    return problems, skipped, checked


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true",
                    help="report counts only, never fail")
    args = ap.parse_args()

    problems, skipped, checked = check()

    if args.list:
        print(f"{checked} references checked, {len(problems)} unresolved, "
              f"{len(skipped)} bare names not resolvable")
        for s_ in skipped:
            print(f"  skip {s_}")
        for p in problems:
            print(f"  {p}")
        return 0

    if problems:
        print(f"{len(problems)} unresolved reference(s) of {checked} checked:\n",
              file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print("\nFix the reference, or -- if the target genuinely is not in this "
              "tree -- add it to ALLOW_PATHS in scripts/check-refs.py with a "
              "reason.", file=sys.stderr)
        return 1

    print(f"{checked} references checked, all resolve "
          f"({len(skipped)} bare names skipped -- see --list)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
