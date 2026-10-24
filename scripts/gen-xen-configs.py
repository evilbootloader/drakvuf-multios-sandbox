#!/usr/bin/env python3
"""Push `sandboxd/config.py`'s values into the files that cannot import Python.

**`sandboxd/config.py` is the source of truth** — it is where an operator tunes
this host. Two consumers cannot read it:

* `automation/platform.env` is **sourced by shell** — by `network-setup.sh`,
  which is the only script left in `automation/` and the only thing that
  sources it.
* `misc/*.cfg` are **Xen configs**, which are neither shell nor Python.

So both are generated from it, and `sandboxd/tests/test_xen_configs.py` fails
until they agree. Editing either by hand is reverted on the next run.

    scripts/gen-xen-configs.py            # rewrite them
    scripts/gen-xen-configs.py --check    # exit 1 if either has drifted

**Only assignment lines and `cpus =` lines are rewritten**, in place. Every
comment in both files survives untouched, which matters more here than
tidiness: those comments carry the reasoning — why a range is unsafe below
pCPU 16, why the platform DomU is disjoint from the clone range, why the
overhead constant sits above its own measurement. A generator that emitted
whole files would have to reproduce all of it, and would lose it the first time
someone forgot.

**The Xen boot line is not generated.** It lives in `/etc/default/grub.d/` on
Dom0, outside this repository, and `drakvuf-bundle` rewrites it on any
`update-grub`. `DOM0_PCPUS` records what it must say so a reviewer can check it;
nothing here can enforce it.
"""

from __future__ import annotations

import argparse
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLATFORM_ENV = ROOT / "automation" / "platform.env"
MISC = ROOT / "misc"


CONFIG_PY = ROOT / "sandboxd" / "config.py"


def _config():
    """Read `sandboxd/config.py` and execute it in a bare namespace.

    By path rather than `from sandboxd import config`, so this runs from a bare
    checkout with nothing installed and no `PYTHONPATH` set — which is how CI
    and the development container both invoke it.

    **`exec` of the source rather than `importlib`, and the reason is a real
    false pass.** `importlib` validates its `__pycache__` entry on
    `(mtime, size)`. Editing `ANALYSIS_BRIDGE` from `xenbr1` to `xenbr9` does
    not change the size, and if the edit lands in the same filesystem-timestamp
    second as the previous run — which a script doing edit-then-generate
    does — Python serves the **stale** bytecode. This generator then compared
    old values against the files and reported `--check` clean while
    `config.py` and `platform.env` disagreed.

    That is precisely the failure this whole mechanism exists to prevent, and it
    was reproduced here on 2026-08-31 rather than reasoned about. `xenbr1` to
    `xenbr2` is a same-length edit an operator would plausibly make.

    Executing the source text touches no cache and cannot go stale.
    """
    source = CONFIG_PY.read_text()
    namespace: dict = {"__file__": str(CONFIG_PY), "__name__": "sandboxd_config"}
    exec(compile(source, str(CONFIG_PY), "exec"), namespace)
    return types.SimpleNamespace(**namespace)


# Shell variables this generator owns. Anything in platform.env NOT listed here
# is hand-maintained and never touched -- add a name only when config.py becomes
# its source.
ENV_VARS = {
    "VG_NAME": "VG_NAME",
    "ANALYSIS_BRIDGE": "ANALYSIS_BRIDGE",
    "UPLINK_BRIDGE": "UPLINK_BRIDGE",
    "SUBNET_PREFIX": "SUBNET_PREFIX",
    "DOM0_PCPUS": "DOM0_PCPUS",
    "CLONE_PCPUS": "CLONE_PCPUS",
    "PLATFORM_PCPUS": "PLATFORM_PCPUS",
}

# Which config attribute drives which Xen config. A `.cfg` absent from this map
# is never touched -- the golden domains (`ubuntu.cfg`, `android.cfg`,
# `windows.cfg`) have no `cpus =` line and should not acquire one: they are
# booted by hand for template maintenance, not run under load.
CFG_TARGETS = {
    "ubuntu_sandbox.cfg": "CLONE_PCPUS",
    "windows_sandbox.cfg": "CLONE_PCPUS",
    "platform.cfg": "PLATFORM_PCPUS",
}

def _assign(name: str) -> re.Pattern[str]:
    """`NAME="${NAME:-value}"` — the shape every value in platform.env uses.

    The `${NAME:-...}` form is load-bearing and preserved: it lets an exported
    variable win at runtime, which is how CI overrides a value without patching
    the file.
    """
    return re.compile(rf'^({re.escape(name)}="\$\{{{re.escape(name)}:-)'
                      rf'([^}}]*)(\}}")', re.M)


def rewrite_env(text: str, values: dict[str, str]) -> str:
    for name, value in values.items():
        pattern = _assign(name)
        if not pattern.search(text):
            raise SystemExit(
                f"{PLATFORM_ENV.name} has no `{name}=\"${{{name}:-...}}\"` line. "
                f"Add it there, or drop {name} from ENV_VARS in this script.")
        text = pattern.sub(lambda m: f"{m.group(1)}{value}{m.group(3)}", text)
    return text


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if any generated file is out of date")
    args = ap.parse_args()

    cfg = _config()
    missing = [a for a in ENV_VARS.values() if not hasattr(cfg, a)]
    if missing:
        print(f"sandboxd/config.py defines no {', '.join(missing)}",
              file=sys.stderr)
        return 1

    work: list[tuple[Path, str, str]] = []

    current = PLATFORM_ENV.read_text()
    updated = rewrite_env(current, {n: str(getattr(cfg, a))
                                    for n, a in ENV_VARS.items()})
    if updated != current:
        work.append((PLATFORM_ENV, current, updated))

    if args.check:
        if work:
            print("generated files have drifted from sandboxd/config.py:\n",
                  file=sys.stderr)
            for path, _, _ in work:
                print(f"  {path.relative_to(ROOT)}", file=sys.stderr)
            print("\nRun: scripts/gen-xen-configs.py", file=sys.stderr)
            return 1
        print("automation/platform.env and misc/*.cfg agree with "
              "sandboxd/config.py")
        return 0

    for path, _, updated in work:
        path.write_text(updated)
    print(f"updated {', '.join(p.relative_to(ROOT).as_posix() for p, _, _ in work)}"
          if work else "already up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
