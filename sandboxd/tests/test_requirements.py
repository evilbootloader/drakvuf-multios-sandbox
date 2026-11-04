"""The hashed requirement files and their sources agree (review M-1).

Each `requirements.txt` is generated from a `requirements.in` by uv with the
sha256 of every distribution file, and pip installs it in hash-checking mode.
That mode is only as good as the file: a pin edited in the `.in` and not
regenerated installs the old version, a line without `--hash` makes pip
refuse the whole file, and CI installs sandboxd's and the platform's into one
interpreter, where a package the two pin differently resolves to nothing.
No network: this reads the files.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

PAIRS = (
    ("sandboxd/requirements.in", "sandboxd/requirements.txt"),
    ("platform/requirements.in", "platform/requirements.txt"),
    ("automation/fakenet-requirements.in", "automation/fakenet-requirements.txt"),
)

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;\\]+)")


def _name(s: str) -> str:
    return re.sub(r"[-_.]+", "-", s).lower()


def _pins(path: Path) -> dict[str, str]:
    """name -> version of every `==` line that is not a comment."""
    pins = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("--"):
            continue
        m = _PIN.match(line)
        if m:
            pins[_name(m.group(1))] = m.group(2)
    return pins


def _requirement_lines(path: Path) -> list[str]:
    """The generated file's logical lines: a requirement joined with its
    `--hash` continuations."""
    logical, current = [], ""
    for raw in path.read_text().splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        current += " " + s.rstrip("\\")
        if not s.endswith("\\"):
            logical.append(current.strip())
            current = ""
    return logical


@pytest.mark.parametrize("src,generated", PAIRS)
def test_every_pin_of_the_source_is_in_the_generated_file(src, generated):
    wanted = _pins(ROOT / src)
    got = _pins(ROOT / generated)
    stale = {n: (v, got.get(n)) for n, v in wanted.items() if got.get(n) != v}
    assert not stale, f"{src} pins not in {generated}, regenerate it: {stale}"


@pytest.mark.parametrize("src,generated", PAIRS)
def test_every_requirement_of_the_generated_file_carries_a_hash(src, generated):
    lines = _requirement_lines(ROOT / generated)
    assert lines, f"{generated} is empty"
    unhashed = [l.split()[0] for l in lines if "--hash=sha256:" not in l]
    assert not unhashed, f"{generated}: no --hash on {unhashed}; pip refuses the whole file"
    unpinned = [l.split()[0] for l in lines if not _PIN.match(l)]
    assert not unpinned, f"{generated}: not pinned with ==: {unpinned}"


def test_sandboxd_and_the_platform_pin_their_shared_packages_alike():
    """CI installs both files into one interpreter."""
    a = _pins(ROOT / "sandboxd/requirements.txt")
    b = _pins(ROOT / "platform/requirements.txt")
    differ = {n: (a[n], b[n]) for n in a.keys() & b.keys() if a[n] != b[n]}
    assert not differ, (
        "regenerate platform/requirements.txt with -c sandboxd/requirements.in: "
        f"{differ}"
    )