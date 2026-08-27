"""`docs/CURRENT-STATE.md`'s generated section must match the repository.

**Why this lives in `sandboxd/tests/` rather than `platform/tests/`.** It is a
repository-wide check and belongs to neither component, but `platform/tests/`
requires a real Postgres and MinIO (`conftest.migrated` is session-scoped and
autouse), so a test placed there could not run without infrastructure. This
suite needs nothing, which is the property that matters for a check whose whole
job is to fail in CI when someone forgets to regenerate a file.

The check exists because a state file that silently drifts is worse than no
state file: it is a document that *looks* authoritative while being wrong, which
is the failure mode CURRENT-STATE.md was written to remove.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts" / "gen-current-state.py"
STATE = ROOT / "docs" / "CURRENT-STATE.md"


def test_the_generated_section_is_up_to_date():
    """Run `scripts/gen-current-state.py` and commit the result."""
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--check"],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert result.returncode == 0, (
        f"{result.stdout}{result.stderr}\n"
        f"docs/CURRENT-STATE.md's generated block no longer matches the "
        f"repository. Run: scripts/gen-current-state.py"
    )


def _generator():
    """Import the script as a module. It is not on the import path."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("gen_current_state", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_hand_maintained_sections_survive_regeneration():
    """The generator replaces only what is between its markers.

    Everything an operator wrote -- the capability tables and their confirmed
    dates, the superseded-facts list -- is outside them and must be untouched.
    A generator that clobbered those would destroy the half of the file it
    cannot reproduce.

    **Spliced in memory, never on disk.** An earlier version of this test ran
    the generator in write mode, which meant a stale file was silently fixed as
    a side effect of running the suite -- masking the check above on the next
    run. A test that repairs the thing it is testing proves nothing.
    """
    gen = _generator()
    text = STATE.read_text()

    start = text.index(gen.BEGIN)
    stop = text.index(gen.END) + len(gen.END)
    spliced = text[:start] + gen.build() + text[stop:]

    for marker in ("# 1. Capabilities", "# 2. Superseded facts",
                   "## 1.1 L0", "## 1.2 L1", "## 1.3 CT 102"):
        assert marker in spliced, f"regeneration would lose {marker!r}"

    # The operator's half is byte-identical either side of the generated block.
    assert spliced[:start] == text[:start]
    assert spliced[len(spliced) - (len(text) - stop):] == text[stop:]


@pytest.mark.parametrize("fact", [
    # Each of these was asserted wrongly in the 2026-08-27 review. If the file
    # stops carrying the correction, the trap is open again.
    "no systemd unit exists",
    "/root/drakvuf-multios-sandbox",
    "dom0_max_vcpus=8",
])
def test_the_superseded_traps_are_still_recorded(fact):
    assert fact in STATE.read_text(), (
        f"CURRENT-STATE.md no longer warns about {fact!r}; it is a fact that "
        f"looks current in an old runbook and is not"
    )