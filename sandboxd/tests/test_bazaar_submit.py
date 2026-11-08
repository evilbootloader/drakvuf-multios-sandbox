"""The pure parts of scripts/bazaar-submit.py: what a header is read as, which
guest it goes to, what it is called, and the trace-length bounds; and how many
jobs its loop keeps in flight, against a fake platform.

The script's name has a hyphen, so it is loaded by path, as test_xen_identity
does for its script. Nothing here touches the network or a sample.
"""
from __future__ import annotations

import importlib.util
import json
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


class FakeLab:
    """A platform whose nth job ends after `polls[n]` polls (default one)."""

    def __init__(self, polls=(), refuse_submission=None, final=None):
        self.polls = iter(polls)
        self.refuse_submission = refuse_submission
        self.final = final or {"state": "completed"}
        self.left: dict[str, int] = {}
        self.submitted = 0
        self.most_running = 0
        self.published: list[str] = []

    def balance(self):
        return 100000

    def submit(self, path, filename, target_os, seconds, plugins, egress):
        self.submitted += 1
        if self.submitted == self.refuse_submission:
            raise SystemExit("create refused: 503")
        job_id = f"job-{self.submitted}"
        self.left[job_id] = next(self.polls, 1)
        self.most_running = max(self.most_running, sum(n > 0 for n in self.left.values()))
        return {"id": job_id, "state": "queued"}

    def job(self, job_id):
        self.left[job_id] -= 1
        return {"state": "executing"} if self.left[job_id] else self.final

    def publish(self, job_id):
        self.published.append(job_id)
        return "public"


def feed(monkeypatch, tmp_path, lab, *flags, rows=3):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "key")
    monkeypatch.setenv("SANDBOX_PASSWORD", "password")
    monkeypatch.setattr(bz, "Platform", lambda *a: lab)
    monkeypatch.setattr(bz, "candidates", lambda *a: [
        {"sha256_hash": f"{i:064x}", "file_type": "exe", "file_size": 4096} for i in range(rows)])
    monkeypatch.setattr(bz, "mb_download", lambda *a: b"PK")
    monkeypatch.setattr(bz, "default_plugins", lambda os_: ["syscalls"])

    def extract(zip_path, out_dir):
        sample = out_dir / "sample"
        sample.write_bytes(pe(0x8664))
        return sample

    monkeypatch.setattr(bz, "extract_sample", extract)
    return bz.main(["--platform", "https://lab.invalid", "--email", "a@lab.invalid",
                    "--count", str(rows), "--seconds", "120", "--poll", "0",
                    "--workdir", str(tmp_path), *flags])


def saved(tmp_path) -> dict:
    return {e["job_id"]: e for e in json.loads((tmp_path / "state.json").read_text()).values()}


def test_two_jobs_in_flight_by_default_and_the_next_takes_the_first_free_slot(monkeypatch, tmp_path):
    # job-2 ends first and job-3 starts while job-1 is still running: a rolling
    # window, not pairs that wait for each other.
    lab = FakeLab(polls=[3, 1, 1])
    assert feed(monkeypatch, tmp_path, lab) == 0
    assert lab.most_running == 2
    assert lab.published == ["job-2", "job-3", "job-1"]
    assert {e["state"] for e in saved(tmp_path).values()} == {"completed"}
    assert [p for p in tmp_path.iterdir() if p.is_dir()] == []


def test_concurrent_one_is_one_at_a_time(monkeypatch, tmp_path):
    lab = FakeLab(polls=[2, 2, 2])
    assert feed(monkeypatch, tmp_path, lab, "--concurrent", "1") == 0
    assert lab.most_running == 1
    assert lab.published == ["job-1", "job-2", "job-3"]


def test_a_refusal_still_finishes_the_job_in_flight(monkeypatch, tmp_path):
    lab = FakeLab(polls=[2], refuse_submission=2)
    with pytest.raises(SystemExit, match="create refused"):
        feed(monkeypatch, tmp_path, lab)
    assert lab.published == ["job-1"]
    assert saved(tmp_path)["job-1"]["state"] == "completed"


def test_a_failed_job_is_recorded_and_still_published(monkeypatch, tmp_path):
    lab = FakeLab(final={"state": "failed", "failure_stage": "trace", "failure_reason": "boom"})
    assert feed(monkeypatch, tmp_path, lab, rows=1) == 0
    assert saved(tmp_path)["job-1"]["failure"] == "trace: boom"
    assert lab.published == ["job-1"]


def test_private_publishes_nothing(monkeypatch, tmp_path):
    lab = FakeLab()
    assert feed(monkeypatch, tmp_path, lab, "--private") == 0
    assert lab.submitted == 3 and lab.published == []


def test_dry_run_submits_and_polls_nothing(monkeypatch, tmp_path):
    lab = FakeLab()
    assert feed(monkeypatch, tmp_path, lab, "--dry-run") == 0
    assert lab.submitted == 0


def test_concurrent_must_be_positive(monkeypatch, tmp_path):
    with pytest.raises(SystemExit):
        feed(monkeypatch, tmp_path, FakeLab(), "--concurrent", "0")
