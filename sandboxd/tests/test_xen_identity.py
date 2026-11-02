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
import struct
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


# --- the drives and the SMBIOS table -----------------------------------------------------
#
# al-khaser on the reinstalled Windows guest, 2026-11-02: the install CD-ROM stayed in the
# registry as Enum\IDE\CdRomQEMU_QEMU_DVD-ROM_..._2.5+____ (check 4097), and 36 SMBIOS
# structures were 40 or fewer (4098). docs/architecture/guest-identity.md has both.

def _structures(data: bytes):
    """(type, length, handle) of each structure of an smbios_firmware file"""
    out, offset = [], 0
    while offset < len(data):
        size = struct.unpack_from("<I", data, offset)[0]
        structure = data[offset + 4:offset + 4 + size]
        assert structure.endswith(b"\0\0"), structure
        out.append(struct.unpack_from("<BBH", structure))
        offset += 4 + size
    return out


def test_the_smbios_table_has_more_structures_than_al_khaser_takes_for_a_vm(tmp_path):
    module = _script()
    _run(tmp_path / "xen-identity.json", "show")
    structures = _structures(module.smbios_file(json.loads((tmp_path / "xen-identity.json").read_text())))

    assert len(structures) + module.HVMLOADER_STRUCTURES > 40
    # hvmloader drops a passed in structure of a type it writes itself
    assert not {t for t, _, _ in structures} & {0, 1, 2, 3, 4, 11, 16, 17, 19, 20, 22, 32, 39, 127}
    assert len({h for _, _, h in structures}) == len(structures)
    lengths = {7: 0x1B, 8: 0x09, 9: 0x11, 13: 0x16, 26: 0x16, 27: 0x0F, 28: 0x16, 29: 0x16, 41: 0x0B}
    assert all(length == lengths[t] for t, length, _ in structures)


def test_drive_details_fit_the_fields_qemu_reports_them_in():
    module = _script()
    for model, _, revisions in module.DISKS:
        assert len(model) <= 40 and all(len(r) <= 8 for r in revisions)
    for model, _, revisions in module.OPTICAL:
        vendor, product = model.split(" ", 1)  # as qemu-xen-cdrom-inquiry.patch splits it
        assert len(vendor) <= 8 and len(product) <= 16, model
        assert all(len(r) <= 4 for r in revisions)


def test_an_identity_from_before_gets_drive_details_for_its_own_models(tmp_path):
    """A new model would be a new device to the Windows already installed with the old one."""
    state = tmp_path / "xen-identity.json"
    _run(state, "show")
    identity = json.loads(state.read_text())
    for key in ("disk_firmware", "cdrom_firmware", "cdrom_serial"):
        del identity[key]
    state.write_text(json.dumps(identity))

    lines = _run(state, "xl-cfg", str(tmp_path)).stdout
    after = json.loads(state.read_text())

    module = _script()
    assert (after["disk_model"], after["cdrom_model"]) == (identity["disk_model"], identity["cdrom_model"])
    assert after["disk_firmware"] in dict((m, r) for m, _, r in module.DISKS)[after["disk_model"]]
    assert after["cdrom_firmware"] in dict((m, r) for m, _, r in module.OPTICAL)[after["cdrom_model"]]
    for option in ("ide-hd.ver=", "ide-cd.ver=", "ide-cd.serial="):
        assert "'%s" % option in lines
    assert "2.5+" not in lines and "QM000" not in lines
