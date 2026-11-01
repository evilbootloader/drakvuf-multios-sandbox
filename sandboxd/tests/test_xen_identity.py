"""`scripts/xen-identity.py mac GUEST`: every guest has its own MAC.

**Why this is worth a test.** One MAC shared by the Ubuntu and Windows golden
VMs on `xenbr0` gave the bridge and DHCP one machine where there were two, and
nothing said so: Windows' first-logon downloads were reset and timed out, and
the network looked fine by the time anyone checked. `docs/TROUBLESHOOTING.md`,
"Windows first logon", has the entry.

The Makefile calls the script as a command, so most of these do too.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "xen-identity.py"
LEGACY_MAC = "68:05:CA:55:6C:A3"


def _run(state: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), "--state", str(state), *args],
                          capture_output=True, text=True, check=check)


def _mac(state: Path, guest: str) -> str:
    return _run(state, "mac", guest).stdout.strip()


def _script():
    spec = importlib.util.spec_from_file_location("xen_identity", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_each_guest_gets_its_own_mac_and_keeps_it(tmp_path):
    state = tmp_path / "xen-identity.json"
    ubuntu, windows = _mac(state, "ubuntu"), _mac(state, "windows")

    assert ubuntu != windows
    assert (_mac(state, "ubuntu"), _mac(state, "windows")) == (ubuntu, windows)


def test_an_identity_from_before_gives_its_one_mac_to_ubuntu(tmp_path):
    """Ubuntu's golden image and saved state were made with it: its configs must not change."""
    state = tmp_path / "xen-identity.json"
    _run(state, "show")
    identity = json.loads(state.read_text())
    del identity["macs"]
    identity["mac"] = LEGACY_MAC
    state.write_text(json.dumps(identity))

    windows = _mac(state, "windows")

    assert _mac(state, "ubuntu") == LEGACY_MAC
    assert windows != LEGACY_MAC
    assert "mac" not in json.loads(state.read_text())


def test_get_mac_fails_rather_than_handing_every_guest_one(tmp_path):
    result = _run(tmp_path / "xen-identity.json", "get", "mac", check=False)

    assert result.returncode != 0
    assert "mac GUEST" in result.stderr
    assert result.stdout == ""


def test_a_new_mac_is_never_another_guests(monkeypatch):
    module = _script()
    draws = iter([0, 0, 0, 0, 1, 1, 1, 1])  # the OUI pick, then three octets, twice
    monkeypatch.setattr(module, "secrets", SimpleNamespace(randbelow=lambda n: next(draws)))
    taken = "%s:00:00:00" % module.INTEL_OUIS[0]

    assert module.draw_mac({taken}) == "%s:01:01:01" % module.INTEL_OUIS[1]
