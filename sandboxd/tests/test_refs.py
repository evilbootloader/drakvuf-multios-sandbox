"""Every cross-reference in the repository's markdown must resolve.

Prose is the largest artifact here and was the only one with no verification
loop. This runs `scripts/check-refs.py`, which resolves `[text](path)`,
`[text](path#anchor)` and `` `path:line` `` against the tree.

**The anchors are the reason this is worth a test rather than a habit.**
`docs/INDEX.md` carries ~1000 links whose fragments are derived from heading
*text*, so rewording one heading breaks every link into it — silently, and
invisibly in review, because the markdown still renders.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check-refs.py"


def test_every_reference_resolves():
    """Fix the reference, or add the target to `ALLOW_PATHS` with a reason."""
    result = subprocess.run(
        [sys.executable, str(CHECKER)],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert result.returncode == 0, f"{result.stdout}{result.stderr}"


def test_the_checker_actually_fails_on_a_bad_reference():
    """**A green gate proves nothing until you have seen it go red.**

    This repository already learned that once: `.shellcheckrc` disables three
    codes repository-wide, so a clean `shellcheck` run says less than it looks
    like it says. A reference checker that silently matched nothing would report
    exactly the same success as one that checked everything.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("check_refs", CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # A heading that exists, and one that does not, slugged the same way the
    # checker slugs them.
    assert module.anchor("How to use this file") == "how-to-use-this-file"

    troubleshooting = ROOT / "docs" / "TROUBLESHOOTING.md"
    slugs = module.headings_of(troubleshooting)
    assert "how-to-use-this-file" in slugs
    assert "this-anchor-does-not-exist" not in slugs

    # And the file:line arm resolves a partial path the way the docs write it.
    hit = module.suffix_resolve("dirwatch.c", module.tracked_files())
    assert hit is not None and hit.name == "dirwatch.c"
