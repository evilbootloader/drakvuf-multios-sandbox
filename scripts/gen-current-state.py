#!/usr/bin/env python3
"""Regenerate the derived section of `docs/CURRENT-STATE.md`.

**Why this exists.** A code review on 2026-08-27 produced several confidently
wrong statements about the lab — a `dom0_max_vcpus` contradiction that the
runbooks had already resolved, `journalctl -u sandboxd` for a daemon that is
not a service, a VM's memory figure read as a core count. Every one of those
was answerable from something already written down; none was findable in less
than several greps across 26 documents and 25k lines.

So the facts that can be *derived* are derived, on demand, and a test fails if
the committed file disagrees. Facts that live only on the operator's machines
cannot be derived and are maintained by hand above the generated block, each
with the date it was last confirmed.

    scripts/gen-current-state.py            # rewrite the block in place
    scripts/gen-current-state.py --check    # exit 1 if out of date

The markers are load-bearing: everything between them is replaced wholesale,
and everything outside them is never touched.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "docs" / "CURRENT-STATE.md"

BEGIN = "<!-- BEGIN GENERATED -- scripts/gen-current-state.py -->"
END = "<!-- END GENERATED -->"


def sh(*argv: str) -> str:
    return subprocess.run(argv, cwd=ROOT, capture_output=True,
                          text=True, check=False).stdout.strip()


# Submodule working trees, read from `.gitmodules` so adding a second submodule
# needs no code change here. **This is the second live copy of this idiom** --
# `scripts/check-refs.py::_submodule_paths` is the other, and it prunes for a
# different reason (its allowlist deliberately names upstream DRAKVUF paths as
# unresolvable). They are two short readers of the same file rather than a
# shared helper because these scripts import nothing from each other; if a third
# appears, give them one home.
_SUBMODULES = frozenset(
    ROOT / m.group(1).strip()
    for m in re.finditer(r"^\s*path\s*=\s*(.+?)\s*$",
                         (ROOT / ".gitmodules").read_text(), re.M)
) if (ROOT / ".gitmodules").is_file() else frozenset()


def _under_submodule(p: Path) -> bool:
    return any(sm in p.parents for sm in _SUBMODULES)


# Every host whose shell prompt counts as evidence. **This list is the one part
# of the generator that a host rename silently invalidates**, and the
# 2026-08-28 migration did exactly that: Dom0 stopped being the nested VM
# `drakvuf` and became bare-metal `dom0`. Until `dom0` was added here,
# `platform-domu.md` -- four pasted Dom0 prompts and a booted domain -- would
# have been published as `no`, evidence-free, which is the precise error class
# this file exists to remove.
#
# **Add a host here whenever one joins the lab**, and prefer an explicit list to
# a wildcard: a bare `root@\S+` would also match prompts quoted inside prose,
# examples and findings, which are not evidence of anything.
_EVIDENCE_HOSTS = ("pve1", "drakvuf", "dom0", "platform", "pbs1")

# A pasted shell prompt from one of the real hosts. This is the only reliable
# signal that a runbook was actually run: the status banner is written before
# execution and is frequently never updated afterwards.
_PROMPT = re.compile(r"^\s*root@(" + "|".join(_EVIDENCE_HOSTS) + r")[^\n]*[#$]",
                     re.M)

# The document's own claim, matched on the **Status:** line specifically rather
# than anywhere in the header. A corrected runbook quotes its superseded banner
# for the record -- 09 does -- and a bare substring search would read that quote
# as a live claim and re-flag a row that was just fixed.
_UNRUN_BANNER = re.compile(r"\*\*Status:[^*]*NOT YET EXECUTED")


def runbooks() -> list[str]:
    """Numbered oldest to newest. **Executed is decided by evidence, not claim.**

    An earlier version reported a runbook's status banner. That got
    `09-verify-sandboxd-and-console.md` exactly wrong: it still carried its
    "NOT YET EXECUTED" header while containing 44 pasted Dom0 prompts, because
    the banner was written before execution and never updated. Reporting an
    executed runbook as evidence-free is the precise class of error
    CURRENT-STATE.md exists to stop, so the banner no longer gets a vote.

    Pasted host prompts are the signal. A stale banner is downgraded to a note
    against the row, because it is worth fixing at the source rather than
    silently tolerating.
    """
    rows = []
    for path in sorted((ROOT / "docs" / "runbooks").glob("[0-9][0-9]-*.md")):
        text = path.read_text(errors="replace")
        pasted = len(_PROMPT.findall(text))
        claims_unrun = bool(_UNRUN_BANNER.search(text[:2000]))

        if pasted:
            executed = f"**yes** — {pasted} prompt(s)"
            note = "⚠ banner still says NOT YET EXECUTED" if claims_unrun else ""
        else:
            executed = "no"
            note = "" if claims_unrun else "⚠ no banner and no output"

        dates = re.findall(r"20\d\d-\d\d-\d\d", text[:1200])
        rows.append(f"| `{path.name}` | {dates[0] if dates else '?'} | "
                    f"{executed} | {note} |")
    return rows


def required_env() -> list[str]:
    """The variables `Settings.from_env` refuses to start without.

    Parsed from the source rather than listed here, so the two cannot drift.
    """
    text = (ROOT / "sandboxd" / "daemon.py").read_text()
    block = re.search(r"missing\s*=\s*\[k for k in \((.*?)\)", text, re.S)
    return re.findall(r'"([A-Z_]+)"', block.group(1)) if block else []


def entrypoints() -> list[str]:
    """How each component is actually started.

    **The environment file comes first, and omitting it is not a small
    difference.** `python -m sandboxd.daemon` on its own exits immediately:
    `Settings.from_env` raises `SystemExit` when any of the variables below is
    unset, deliberately, because there is no safe default for how much memory a
    Dom0 may hand to clones. A reader who copies the bare module invocation gets
    a failure that looks like a broken install.

    The `journalctl` mistake came from assuming a systemd unit existed. This
    reports what the repository can prove, and says so when the answer is
    "nothing".

    **Submodules are excluded, and that is load-bearing.** The row means "units
    this repository ships". Since 2026-09-26 `drakvuf/` carries xen, whose
    `tools/hotplug/Linux/systemd/` holds seven `.service.in` templates that
    `make` renders to real `.service` files *in tree* -- so the first person to
    build the engine would otherwise regenerate this row as `xenconsoled,
    xendomains, xenstored, ...`, claim the lab ships Xen's units, and fail
    `test_current_state.py` for everyone who had not built.
    """
    units = sorted(p.name for p in ROOT.rglob("*.service")
                   if ".git" not in p.parts and not _under_submodule(p))
    service = ("unit: " + ", ".join(units) if units
               else "**no systemd unit anywhere in the repo**")
    need = ", ".join(f"`{v}`" for v in required_env())

    # **One row, and that is the point.** This used to carry a second "legacy
    # pipeline" row globbed from `automation/run_analysis-*.sh`. Those were
    # deleted on 2026-09-15 with the rest of the shell/C launcher, so the glob
    # matched nothing and the row rendered with an empty Command cell — a
    # malformed table claiming a component this host does not have. There is
    # exactly one way to start an analysis on Dom0 now.
    return [
        "| `sandboxd` | **source the env file first**, then "
        "`python -m sandboxd.daemon` in the foreground — see §1.2 for the "
        f"exact Dom0 invocation. Exits immediately without {need}. | "
        f"{service} |",
    ]


def env_vars() -> list[str]:
    """Every SANDBOXD_* the daemon reads, from the source rather than the docs."""
    text = (ROOT / "sandboxd" / "daemon.py").read_text()
    found = sorted(set(re.findall(r'"(SANDBOXD_[A-Z_]+|WORKER_TOKEN)"', text)))
    return [f"`{v}`" for v in found]


def counts() -> list[str]:
    py = len(list((ROOT / "sandboxd").glob("*.py")))
    tests_s = len(list((ROOT / "sandboxd" / "tests").glob("test_*.py")))
    tests_p = len(list((ROOT / "platform" / "tests").glob("test_*.py")))
    docs = len(list((ROOT / "docs").rglob("*.md")))
    return [
        f"| sandboxd modules | {py} |",
        f"| test files | {tests_s} sandboxd, {tests_p} platform |",
        f"| documents under `docs/` | {docs} |",
    ]


# **Nothing here may depend on HEAD.** The first version of this generator put
# the commit sha and subject in the table, which made the file invalidate itself
# the instant it was committed: the block recorded the sha of the commit before
# the one that contained it, so `--check` failed forever after. A generated file
# that is committed can only derive from things a commit does not change.


def build() -> str:
    out = [
        BEGIN,
        "",
        "*Derived from the repository. Do not edit by hand — run "
        "`scripts/gen-current-state.py`.*",
        "",
        "### Runbooks, oldest to newest",
        "",
        "**`Executed` counts pasted host prompts, not what the document says "
        "about itself.** Status banners are written before execution and are "
        "often never updated; a ⚠ means the banner and the evidence disagree "
        "and the banner should be corrected at the source.",
        "",
        "| Runbook | Date | Executed | Note |",
        "|---|---|---|---|",
        *runbooks(),
        "",
        "### How components are started",
        "",
        "| Component | Command | Service |",
        "|---|---|---|",
        *entrypoints(),
        "",
        "### Environment read by `sandboxd.daemon`",
        "",
        ", ".join(env_vars()),
        "",
        "### Repository size",
        "",
        "| | |",
        "|---|---|",
        *counts(),
        "",
        END,
    ]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the committed file is out of date")
    args = ap.parse_args()

    if not TARGET.exists():
        print(f"{TARGET} does not exist", file=sys.stderr)
        return 1

    text = TARGET.read_text()
    if BEGIN not in text or END not in text:
        print(f"{TARGET} is missing the generated-block markers", file=sys.stderr)
        return 1

    start = text.index(BEGIN)
    stop = text.index(END) + len(END)
    updated = text[:start] + build() + text[stop:]

    if args.check:
        if updated != text:
            print("docs/CURRENT-STATE.md is out of date -- run "
                  "scripts/gen-current-state.py", file=sys.stderr)
            return 1
        return 0

    if updated != text:
        TARGET.write_text(updated)
        print(f"updated {TARGET.relative_to(ROOT)}")
    else:
        print("already up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
