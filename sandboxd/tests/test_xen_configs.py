"""`automation/platform.env` and `misc/*.cfg` must match `sandboxd/config.py`.

**Why this is worth a test.** The partition has to agree across the Xen boot
line, both `_sandbox` configs and `platform.cfg`, and **disagreement is
silent**: a clone pinned onto Dom0's cores still runs and still produces a
trace, it just contends with the DRAKVUF process tracing it. Nothing in the
pipeline notices, and no output says so.

That has already happened once. `cpus = "6-11"` was inherited from the nested
topology where Xen saw a contiguous `0-11`; on this host it resolves to
`{6,8,10}` — three cores, all three of them Dom0's.

`sandboxd/config.py` is the source; the shell env file and the Xen configs are
generated from it because neither can import Python.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts" / "gen-xen-configs.py"


def _generator():
    import importlib.util

    spec = importlib.util.spec_from_file_location("gen_xen_configs", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_configs_are_up_to_date():
    """Edit `sandboxd/config.py`, then run `scripts/gen-xen-configs.py`."""
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--check"],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert result.returncode == 0, f"{result.stdout}{result.stderr}"


def test_dom0_and_the_guests_do_not_share_a_core():
    """**The property the partition exists to guarantee.**

    Expanded to explicit core sets rather than compared as strings, because
    `"16-27"` and `"16,17,...,27"` are the same partition and a string compare
    would call them different — while `"6-11"` and `{6,8,10}` are *not* the
    same, which is exactly the bug that motivated all of this.
    """
    cfg = _generator()._config()
    values = {"DOM0_PCPUS": cfg.DOM0_PCPUS,
              "CLONE_PCPUS": cfg.CLONE_PCPUS,
              "PLATFORM_PCPUS": cfg.PLATFORM_PCPUS}

    def expand(spec: str) -> set[int]:
        out: set[int] = set()
        for part in spec.split(","):
            if "-" in part:
                lo, hi = part.split("-")
                out |= set(range(int(lo), int(hi) + 1))
            else:
                out.add(int(part))
        return out

    dom0 = expand(values["DOM0_PCPUS"])
    clones = expand(values["CLONE_PCPUS"])
    platform = expand(values["PLATFORM_PCPUS"])

    assert not dom0 & clones, f"clones share {sorted(dom0 & clones)} with Dom0"
    assert not dom0 & platform, f"platform shares {sorted(dom0 & platform)} with Dom0"
    assert not clones & platform, (
        f"the platform DomU shares {sorted(clones & platform)} with analysis "
        f"clones; it is what records the analysis and should not compete with it"
    )

    # Xen sees 24 online pCPUs under `smt=0`: P-cores are the EVENS 0..14, and
    # E-cores are 16..31. An odd number below 16 is a parked SMT sibling and
    # does not exist to schedule on.
    online = set(range(0, 16, 2)) | set(range(16, 32))
    for name, cpus in (("DOM0_PCPUS", dom0), ("CLONE_PCPUS", clones),
                       ("PLATFORM_PCPUS", platform)):
        offline = cpus - online
        assert not offline, (
            f"{name} names pCPU(s) {sorted(offline)}, which are not online "
            f"under smt=0. Odd pCPUs below 16 are parked P-core siblings."
        )


def test_the_generator_does_not_serve_stale_bytecode(tmp_path):
    """**A same-length edit inside one second used to produce a false pass.**

    `importlib` validates `__pycache__` on `(mtime, size)`. Changing
    `ANALYSIS_BRIDGE` from `xenbr1` to `xenbr2` does not change the size, and an
    edit-then-generate script lands both in the same filesystem-timestamp
    second — so Python served the previous bytecode, and `--check` compared
    stale values against the files and reported them in agreement. Reproduced
    2026-08-31; the loader now `exec`s the source text, which has no cache.

    This is the gate's own failure mode, so it is worth a test: a config
    mechanism that silently reports agreement is worse than none.
    """
    gen = _generator()
    original = gen.CONFIG_PY.read_text()
    assert 'ANALYSIS_BRIDGE = "' in original

    swapped = original.replace('ANALYSIS_BRIDGE = "xenbr1"',
                               'ANALYSIS_BRIDGE = "xenbrX"')
    assert len(swapped) == len(original), "the probe must be length-preserving"

    try:
        gen.CONFIG_PY.write_text(swapped)
        assert gen._config().ANALYSIS_BRIDGE == "xenbrX"
        gen.CONFIG_PY.write_text(original)
        assert gen._config().ANALYSIS_BRIDGE == "xenbr1"
    finally:
        gen.CONFIG_PY.write_text(original)


def test_the_golden_configs_are_left_alone():
    """`ubuntu.cfg`, `android.cfg` and `windows.cfg` are booted by hand for
    template maintenance, not run under load. They have no `cpus =` line and
    the generator must not give them one."""
    gen = _generator()
    for name in ("ubuntu.cfg", "android.cfg", "windows.cfg"):
        assert name not in gen.CFG_TARGETS
        text = (ROOT / "misc" / name).read_text()
        assert not re.search(r'^cpus\s*=', text, re.M), (
            f"misc/{name} grew a cpus= line; decide whether it belongs in "
            f"CFG_TARGETS rather than leaving it unmanaged"
        )
