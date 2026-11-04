"""The pure parts of scripts/bazaar-submit.py: what a header is read as, which
guest it goes to, what it is called, and the trace-length bounds.

The script's name has a hyphen, so it is loaded by path, as test_xen_identity
does for its script. Nothing here touches the network or a sample.
"""
from __future__ import annotations

import importlib.util
import random
import struct
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "bazaar-submit.py"
_spec = importlib.util.spec_from_file_location("bazaar_submit", _SCRIPT)
bz = importlib.util.module_from_spec(_spec)
# Registered before execution: the script's frozen dataclass resolves its
# postponed annotations through sys.modules[cls.__module__].
sys.modules["bazaar_submit"] = bz
_spec.loader.exec_module(bz)


def elf(machine: int, e_type: int = 2, cls: int = 2) -> bytes:
    head = bytearray(b"\x7fELF" + bytes([cls, 1, 1, 0]) + b"\0" * 8)
    head += struct.pack("<HH", e_type, machine)
    return bytes(head) + b"\0" * 44


def pe(machine: int, characteristics: int = 0x0102) -> bytes:
    dos = bytearray(b"MZ" + b"\0" * 58 + struct.pack("<I", 0x80))
    dos += b"\0" * (0x80 - len(dos))
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", machine, 3, 0, 0, 0, 0xE0, characteristics)
    return bytes(dos) + coff + b"\0" * 32


@pytest.mark.parametrize("data, kind, arch, runnable", [
    (elf(0x3E), "elf", "x86_64", True),
    (elf(0x03, cls=1), "elf", "x86", True),
    (elf(0x3E, e_type=3), "elf", "x86_64", True),      # PIE
    (elf(0x3E, e_type=1), "elf", "x86_64", False),     # relocatable object
    (pe(0x8664), "pe", "x86_64", True),
    (pe(0x14C), "pe", "x86", True),
    (pe(0x8664, characteristics=0x2102), "pe", "x86_64", False),  # DLL
])
def test_sniff_reads_the_header(data, kind, arch, runnable):
    s = bz.sniff(data)
    assert s == bz.Sniff(kind, arch, runnable)


@pytest.mark.parametrize("data", [
    elf(0x28),            # ARM
    elf(0x08),            # MIPS
    pe(0x01C4),           # ARM Thumb-2
    b"#!/bin/sh\n",
    b"%PDF-1.7",
    b"MZ" + b"\0" * 10,   # truncated DOS header
    b"\x7fELF\x02\x01",   # truncated ELF header
    b"",
])
def test_sniff_rejects_everything_else(data):
    assert bz.sniff(data) is None


def test_target_and_filename():
    s64 = bz.sniff(pe(0x8664))
    assert bz.target_for(s64) == "windows"
    assert bz.sample_filename("ab" * 32, s64) == "ab" * 32 + ".exe"
    e = bz.sniff(elf(0x03, cls=1))
    assert bz.target_for(e) == "ubuntu"
    assert bz.sample_filename("cd" * 32, e) == "cd" * 32 + ".elf"
    assert bz.target_for(bz.sniff(pe(0x8664, characteristics=0x2102))) is None
    assert bz.target_for(None) is None


@pytest.mark.parametrize("spec, bounds", [
    ("120", (120, 120)), ("1200", (1200, 1200)), ("120-1200", (120, 1200)), ("300-600", (300, 600)),
])
def test_seconds_within_the_platforms_cap(spec, bounds):
    assert bz.parse_seconds(spec) == bounds
    rng = random.Random(7)
    for _ in range(20):
        assert bounds[0] <= bz.pick_seconds(bounds, rng) <= bounds[1]


@pytest.mark.parametrize("spec", ["60", "1201", "600-300", "0-1200", "x", "120-"])
def test_seconds_outside_are_refused(spec):
    with pytest.raises(ValueError):
        bz.parse_seconds(spec)


@pytest.mark.parametrize("row, refused", [
    ({"file_size": 99 * 1000 * 1000 + 1}, True),
    ({"file_size": 99 * 1000 * 1000}, False),
    ({"file_size": "123456789"}, True),       # abuse.ch has served numbers as strings
    ({"file_size": 4096}, False),
    ({"file_size": None}, False),             # unknown: the real size decides after the download
    ({}, False),
])
def test_too_big_reads_the_listing(row, refused):
    assert bz.too_big(row, bz.MAX_BYTES_DEFAULT) is refused


def test_default_cap_sits_under_cloudflares():
    # The upload crosses the tunnel, and Cloudflare's free plan stops a request
    # body at 100 MB with its own 413 page; the multipart envelope needs room too.
    assert 90 * 1000 * 1000 < bz.MAX_BYTES_DEFAULT < 100 * 1000 * 1000


@pytest.mark.parametrize("status, location, lost", [
    (401, None, True),
    (303, "/ui/login", True),                                 # auth.caller_identity's answer
    (303, "/ui/login?next=%2Fui%2Fjobs", True),
    (303, "https://sandbox.example.com/ui/login", True),      # a proxy that absolutises it
    (302, "/ui", False),                                      # the root redirect
    (303, "/ui/jobs/abc", False),
    (200, None, False),
    (403, None, False),
    (413, None, False),
])
def test_session_lost_is_a_401_or_the_login_redirect(status, location, lost):
    assert bz.session_lost(status, location) is lost


def test_default_plugins_come_from_the_catalogue():
    win = bz.default_plugins("windows")
    ubu = bz.default_plugins("ubuntu")
    assert "syscalls" in win and "apimon" in win and "ipt" not in win and "hidsim" not in win
    assert "syscalls" in ubu and "libmon" in ubu and "apimon" not in ubu
    assert bz.default_plugins("android") != ubu


def test_terminal_states_match_the_platforms():
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "platform"))
    from sandbox_platform.enums import TERMINAL_STATES
    assert bz.TERMINAL_STATES == frozenset(s.value for s in TERMINAL_STATES)
