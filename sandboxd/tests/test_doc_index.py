"""`docs/INDEX.md` must match the headings actually present under `docs/`.

An index that drifts is worse than none: it sends a reader to a line number
that used to hold the section, and a wrong `Read(path, offset=N)` looks like a
correct answer. That is the same failure mode `docs/CURRENT-STATE.md` exists to
remove, one axis over, so it gets the same treatment — generated, then tested.

Lives beside `test_current_state.py` for the same reason: it is a
repository-wide check and needs no infrastructure, which `platform/tests/`
cannot offer.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts" / "gen-doc-index.py"
INDEX = ROOT / "docs" / "INDEX.md"


def _generator():
    """Import the script as a module. It is not on the import path."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("gen_doc_index", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_index_is_up_to_date():
    """Add or rename a heading and run `scripts/gen-doc-index.py`."""
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--check"],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert result.returncode == 0, (
        f"{result.stdout}{result.stderr}\n"
        f"docs/INDEX.md no longer matches the headings under docs/. "
        f"Run: scripts/gen-doc-index.py"
    )


def test_every_entry_resolves():
    """**The property that makes the index worth having.**

    Each entry claims `path:line` holds a specific heading. Parse them back out
    and check the file, because an entry pointing at the wrong line is not a
    cosmetic defect -- it is a confident wrong answer, delivered by the one file
    the reader consulted precisely to avoid guessing.
    """
    # `path:line` stays bare so a grep hit is copy-pasteable; the heading is a
    # link so the same line works in a browser. Both halves are parsed back.
    entry = re.compile(r"^\s*- `([^`:]+):(\d+)` — \[(.*)\]\(([^)]*)\)$")
    checked = 0

    for line in INDEX.read_text().splitlines():
        m = entry.match(line)
        if not m:
            continue
        rel, number, text = m.group(1), int(m.group(2)), m.group(3)
        target = ROOT / rel

        assert target.exists(), f"{rel} does not exist (from docs/INDEX.md)"
        lines = target.read_text(errors="replace").splitlines()
        assert number <= len(lines), (
            f"{rel}:{number} is past the end of the file ({len(lines)} lines)"
        )

        heading = lines[number - 1]
        assert heading.lstrip().startswith("#"), (
            f"{rel}:{number} is not a heading: {heading!r}"
        )
        # The generator strips links and collapses whitespace, so compare on the
        # first few words rather than demanding an exact match.
        first = text.split(" — ")[0].split()[:3]
        assert all(w.strip("`") in heading for w in first), (
            f"{rel}:{number} holds {heading!r}, index says {text!r}"
        )
        checked += 1

    assert checked > 500, f"only {checked} entries parsed; the format changed"


def test_fenced_code_is_not_indexed():
    """A shell comment is not a heading.

    Runbooks are mostly pasted shell, and `# start the daemon` inside a fence
    is indistinguishable from a heading line-by-line. Ignoring fences inflated
    a trial run by 83 entries -- concentrated in the runbooks, where a wrong
    line number costs the most.
    """
    gen = _generator()
    sample = ROOT / "docs" / "runbooks" / "09-verify-sandboxd-and-console.md"
    found = gen.headings(sample)

    for _, _, text in found:
        assert not text.startswith("DOM0"), f"indexed a fenced comment: {text!r}"

    # Same file, hard evidence rather than a spot-check: every heading the
    # generator returned must sit outside a fence.
    lines = sample.read_text(errors="replace").splitlines()
    in_fence = False
    outside = set()
    for n, line in enumerate(lines, 1):
        if gen._FENCE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            outside.add(n)
    assert {n for n, _, _ in found} <= outside


def test_the_index_does_not_index_itself():
    """It would grow on every run, each pass indexing the last pass's output."""
    gen = _generator()
    assert gen.TARGET not in gen.documents()
    assert "`docs/INDEX.md:" not in INDEX.read_text()
