"""The pure parts of scripts/detection-eval.py: which Scoop manifests and
Ubuntu packages become benign samples and how their program is taken out,
how the signature checkout is read, how a report is trimmed and its score
replayed, and how a report comes back through the platform's own wrapper.

The script's name has a hyphen, so it is loaded by path, as
test_bazaar_submit does. Nothing here touches the network or a sample: the
"programs" are ELF and PE headers written by hand.
"""
from __future__ import annotations

import importlib.util
import io
import json
import lzma
import random
import struct
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("detection_eval", _REPO / "scripts" / "detection-eval.py")
de = importlib.util.module_from_spec(_spec)
sys.modules["detection_eval"] = de
_spec.loader.exec_module(de)
scoring = de._load("cape_scoring", de.SCORING_PY)

HEX = "ab" * 32


def elf(machine: int = 0x3E) -> bytes:
    head = bytearray(b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8)
    head += struct.pack("<HH", 2, machine)
    return bytes(head) + b"\0" * 44


# --- Scoop -------------------------------------------------------------------

def test_scoop_app_is_one_download_with_its_program():
    app = de.scoop_app("ripgrep", {
        "version": "15.2.0",
        "architecture": {"64bit": {"url": "https://example.org/rg-x86_64.zip", "hash": HEX}},
        "bin": "rg.exe"})
    assert app == de.ScoopApp("ripgrep", "15.2.0", "https://example.org/rg-x86_64.zip",
                              ("sha256", HEX), "rg-x86_64.zip", "rg.exe")


@pytest.mark.parametrize("manifest, expect", [
    # bin as [path, alias] lists, under a folder, and Scoop's `#/name` rename
    ({"url": "https://e.org/dl?id=1#/tool.zip", "hash": HEX, "bin": [["bin\\tool.exe", "t"]]}, ("tool.zip", "tool.exe")),
    ({"url": "https://e.org/x.exe", "hash": f"sha512:{'cd' * 64}", "bin": "x.exe"}, ("x.exe", "x.exe")),
    ({"url": "https://e.org/x.tar.gz", "hash": f"sha1:{'ef' * 20}", "bin": ["x.exe"]}, ("x.tar.gz", "x.exe")),
    # a 32-bit-only app still runs on the guest
    ({"architecture": {"32bit": {"url": "https://e.org/x.zip", "hash": HEX}}, "bin": "x.exe"}, ("x.zip", "x.exe")),
])
def test_scoop_app_shapes_it_reads(manifest, expect):
    app = de.scoop_app("a", manifest)
    assert (app.file_name, app.program) == expect


@pytest.mark.parametrize("manifest", [
    {"url": "https://e.org/x.zip", "hash": HEX, "bin": "x.exe", "installer": {"script": "..."}},
    {"url": "https://e.org/x.zip", "hash": HEX, "bin": "x.exe", "depends": "7zip"},
    {"url": ["https://e.org/a.zip", "https://e.org/b.zip"], "hash": [HEX, HEX], "bin": "x.exe"},
    {"url": "https://e.org/x.msi", "hash": HEX, "bin": "x.exe"},
    {"url": "https://e.org/x.7z", "hash": HEX, "bin": "x.exe"},
    {"url": "https://e.org/x.zip", "hash": HEX, "bin": "x.ps1"},
    {"url": "https://e.org/x.zip", "hash": HEX},
    {"url": "https://e.org/x.zip", "hash": f"crc32:{HEX}", "bin": "x.exe"},
])
def test_scoop_app_passes_over_more_than_a_download(manifest):
    assert de.scoop_app("a", manifest) is None


def _tar(files: dict[str, bytes], mode: str = "w:gz") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_scoop_apps_reads_the_bucket_directory_only():
    good = json.dumps({"version": "1", "url": "https://e.org/b.zip", "hash": HEX, "bin": "b.exe"}).encode()
    blob = _tar({"Main-master/bucket/b.json": good, "Main-master/bucket/a.json": good,
                 "Main-master/bucket/broken.json": b"{", "Main-master/scripts/c.json": good})
    assert [a.name for a in de.scoop_apps(blob)] == ["a", "b"]


# --- taking the program out ----------------------------------------------------

def test_extract_member_takes_the_shortest_path_and_never_the_archive_name(tmp_path):
    archive = tmp_path / "x.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("../../escape/rg.exe", b"evil")
        z.writestr("pkg/doc/rg.exe", b"copy")
        z.writestr("pkg/rg.exe", b"real")
    out = tmp_path / "out" / "sample"
    out.parent.mkdir()
    assert de.extract_member(archive, "x.zip", "rg.exe", out, 100) == "pkg/rg.exe"
    assert out.read_bytes() == b"real"
    assert not (tmp_path.parent / "escape").exists()


def test_extract_member_reads_tars_and_refuses_oversize(tmp_path):
    archive = tmp_path / "x.tar.xz"
    archive.write_bytes(_tar({"x-1.0/bin/tool": b"t" * 50}, mode="w:xz"))
    assert de.extract_member(archive, "x.tar.xz", "tool", tmp_path / "a", 100) == "x-1.0/bin/tool"
    with pytest.raises(de.TooBig):
        de.extract_member(archive, "x.tar.xz", "tool", tmp_path / "b", 10)
    with pytest.raises(LookupError):
        de.extract_member(archive, "x.tar.xz", "other", tmp_path / "c", 100)


# --- the Ubuntu archive ------------------------------------------------------------

PACKAGES = """\
Package: tool
Architecture: amd64
Section: utils
Filename: pool/main/t/tool/tool_1_amd64.deb
Size: 1000
SHA256: aa
Description: a tool
 with a continuation: line that is not a field

Package: tool-doc
Architecture: all
Section: doc
Filename: pool/main/t/tool/tool-doc_1_all.deb
Size: 10
SHA256: bb

Package: libtool1
Architecture: amd64
Section: libs
Filename: pool/main/t/tool/libtool1_1_amd64.deb
Size: 10
SHA256: cc

Package: big
Architecture: amd64
Section: universe/net
Filename: pool/universe/b/big/big_1_amd64.deb
Size: 999999
SHA256: dd

Package: netthing
Architecture: amd64
Section: universe/net
Filename: pool/universe/n/netthing/netthing_1_amd64.deb
Size: 10
SHA256: ee
"""


def test_archive_candidates_are_amd64_programs_under_the_cap():
    packages = de.parse_packages(PACKAGES)
    assert packages[0]["Description"] == "a tool"
    assert [p["Package"] for p in de.archive_candidates(packages, 5000)] == ["tool", "netthing"]


def _deb(data_files: dict[str, tuple[bytes, int]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, (data, mode) in data_files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), mode
            t.addfile(info, io.BytesIO(data))
    members = [("debian-binary", b"2.0\n"), ("control.tar.xz", lzma.compress(b"")),
               ("data.tar.xz", lzma.compress(buf.getvalue()))]
    out = bytearray(b"!<arch>\n")
    for name, body in members:
        out += f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(body):<10}`\n".encode()
        out += body + (b"\n" if len(body) % 2 else b"")
    return bytes(out)


def test_deb_program_prefers_the_package_name_and_x86_elf(tmp_path):
    deb = _deb({"./usr/bin/helper": (elf(), 0o755), "./usr/bin/tool": (elf(), 0o755),
                "./usr/bin/script": (b"#!/bin/sh\n", 0o755), "./usr/bin/armthing": (elf(0x28), 0o755),
                "./usr/bin/notexec": (elf(), 0o644), "./usr/lib/tool/bin/deep": (elf(), 0o755)})
    assert de.deb_program(deb, "tool", random.Random(1), tmp_path / "a", 1000) == "usr/bin/tool"
    # No program named after the package: an x86 ELF one, never the script,
    # the ARM build, the non-executable or the one out of a bin directory.
    assert de.deb_program(deb, "other", random.Random(1), tmp_path / "b", 1000) in ("usr/bin/helper", "usr/bin/tool")


def test_deb_program_none_without_an_elf_program(tmp_path):
    deb = _deb({"./usr/bin/script": (b"#!/bin/sh\n", 0o755), "./usr/share/doc/x": (b"doc", 0o644)})
    assert de.deb_program(deb, "x", random.Random(1), tmp_path / "a", 1000) is None


# --- the signature checkout ---------------------------------------------------------

def test_signature_index_reads_literals_and_run_time_fields(tmp_path):
    (tmp_path / "linux").mkdir()
    (tmp_path / "windows").mkdir()
    (tmp_path / "all").mkdir()
    (tmp_path / "linux" / "a.py").write_text(
        "class A(Signature):\n"
        "    name = 'shared'\n"
        "    severity = 2\n"
        "    categories = ['discovery']\n"
        "    def on_complete(self):\n"
        "        self.severity = max(self.severity, 3)\n")
    (tmp_path / "windows" / "b.py").write_text(
        "class B(Signature):\n    name = 'shared'\n    severity = 3\n    weight = 2\n")
    (tmp_path / "all" / "c.py").write_text(
        "class C(Signature):\n    name = 'common'\n    severity = 1\n    confidence = 50 + 0\n"
        "    description = '\\d is an invalid escape'\n")
    index = de.signature_index(tmp_path)
    linux = de.lookup(index, "shared", "ubuntu")
    assert (linux["severity"], linux["line"], linux["dynamic"]) == (2, 3, ["severity"])
    assert de.lookup(index, "shared", "windows")["weight"] == 2
    common = de.lookup(index, "common", "ubuntu")
    assert common["dir"] == "all" and "confidence" not in common   # not a literal
    assert de.lookup(index, "absent", "ubuntu") is None


def test_with_checkout_keeps_what_a_signature_sets_at_run_time():
    index = {"dyn": [{"severity": 1, "dynamic": ["severity"], "dir": "linux"}],
             "lit": [{"severity": 1, "confidence": 40, "dynamic": [], "dir": "linux"}]}
    hits = [{"name": "dyn", "severity": 3, "confidence": 100, "weight": 1, "categories": []},
            {"name": "lit", "severity": 3, "confidence": 100, "weight": 1, "categories": []}]
    dyn, lit = de.with_checkout(hits, index, "ubuntu")
    assert dyn["severity"] == 3
    assert (lit["severity"], lit["confidence"]) == (1, 40)


# --- a report, trimmed and replayed -------------------------------------------------

def results(sigs: list[dict], file_type: str = "ELF 64-bit LSB executable, x86-64") -> dict:
    return {"target": {"category": "file", "file": {"type": file_type, "yara": []}},
            "behavior": {"processes": [{"process_id": 1}], "processtree": [{"pid": 1}]},
            "signatures": sigs, "info": {"duration": 120}}


def sig(name: str, severity: int, categories: list[str], confidence: int = 100) -> dict:
    return {"name": name, "severity": severity, "confidence": confidence, "weight": 1,
            "categories": categories, "data": [{"x": 1}]}


def test_summary_replays_to_what_cape_scored():
    for sigs in ([sig("a", 3, ["network"]), sig("b", 2, ["anti-vm"])],
                 [sig("c", 3, ["rootkit"]), sig("d", 1, ["discovery"])],
                 [sig("e", 2, ["evasion"])],
                 []):
        full = results(sigs)
        expected = scoring.calc_scoring(json.loads(json.dumps(full)), [dict(s) for s in sigs])
        summary = de.summarize(full)
        assert de.score(scoring, summary, summary["signatures"]) == (round(expected[0], 2), expected[1])


def test_bucket_asks_scoring_which_list_a_category_is_in():
    assert de.bucket(scoring, {"categories": ["rootkit"]}) == "malicious"
    assert de.bucket(scoring, {"categories": ["discovery"]}) == "suspicious"
    assert de.bucket(scoring, {"categories": ["evasion"]}) == "-"


def test_analyse_hints():
    runs = []
    for i in range(10):
        noisy = [sig("noisy", 3, ["anti-vm"]), sig("loud", 3, ["network"]), sig("quiet", 2, ["evasion"])] if i < 5 else []
        runs.append({"job_id": f"b{i}", "label": "benign", "os": "ubuntu", "name": f"b{i}", "state": "completed",
                     "report": de.summarize(results(noisy))})
        mal = [sig("noisy", 3, ["anti-vm"])] if i < 5 else []
        mal += [sig("only_bad", 2, ["persistence"])] if i < 6 else []
        runs.append({"job_id": f"m{i}", "label": "malicious", "os": "ubuntu", "name": f"m{i}", "state": "completed",
                     "report": de.summarize(results(mal))})
    runs.append({"job_id": "p", "label": "benign", "os": "ubuntu", "name": "p", "state": "running"})
    a = de.analyse(runs, {}, scoring, "ubuntu")
    rows = {r["signature"]: r for r in a["signatures"]}
    assert rows["noisy"]["hint"] == "noisy fp-driver"
    assert rows["only_bad"]["hint"] == "discriminative"
    assert rows["quiet"]["hint"] == "unscored noisy"
    assert rows["noisy"]["in_flagged_benign"] == 5
    ben = a["sides"]["benign"]
    assert (ben["scored"], ben["pending"], ben["flagged_now"]) == (10, 1, 5)
    assert "noisy" in de.render(a, 10)


# --- what comes back from the platform -------------------------------------------------

class FakeResponse:
    def __init__(self, status: int, content: bytes = b"", payload=None):
        self.status_code, self.content, self.text, self._payload = status, content, "", payload

    def json(self):
        return self._payload


class FakePlatform:
    def __init__(self, detail: dict, blob: bytes = b""):
        self.detail, self.blob, self.calls = detail, blob, []

    def job(self, job_id):
        return self.detail

    def _call(self, method, path, **kw):
        self.calls.append((method, path, kw))
        return FakeResponse(200, self.blob)


def test_fetch_opens_the_platforms_own_wrapper():
    sys.path.insert(0, str(_REPO / "platform"))
    from sandbox_platform import packaging
    raw = json.dumps(results([sig("a", 2, ["network"])])).encode()
    blob = b"".join(packaging.stream([(de.RESULTS_NAME, iter([raw]))]))
    p = FakePlatform({"state": "completed", "artifacts": {de.RESULTS_NAME: "/x"}}, blob)
    got = de.fetch(p, "j1")
    assert [s["name"] for s in got["report"]["signatures"]] == ["a"]
    assert p.calls == [("GET", "/api/v1/jobs/j1/artifact.zip", {"params": {"name": de.RESULTS_NAME}})]


def test_fetch_without_a_report():
    assert "report" not in de.fetch(FakePlatform({"state": "running"}), "j")
    gone = de.fetch(FakePlatform({"state": "failed", "artifacts": {}, "failure_stage": "trace",
                                  "failure_reason": "x"}), "j")
    assert (gone["report"], gone["why"], gone["failure"]) == (None, f"no {de.RESULTS_NAME}", "trace: x")


class FakeBazaar:
    def __init__(self, payload):
        self.payload = payload

    def post(self, url, data, headers):
        assert data == {"query": "get_info", "hash": HEX}
        return FakeResponse(200, payload=self.payload)


def test_known_to_bazaar():
    assert de.known_to_bazaar(FakeBazaar({"query_status": "ok", "data": [{"signature": "Mirai"}]}), "k", HEX) == "Mirai"
    assert de.known_to_bazaar(FakeBazaar({"query_status": "hash_not_found"}), "k", HEX) is None
    with pytest.raises(SystemExit):
        de.known_to_bazaar(FakeBazaar({"query_status": "illegal_hash"}), "k", HEX)


def test_by_family_gives_every_family_a_turn_and_the_least_run_the_first():
    rows = [{"sha256_hash": f"m{i}", "signature": "Mirai"} for i in range(3)]
    rows += [{"sha256_hash": "g0", "signature": "Gafgyt"}, {"sha256_hash": "u0", "signature": None}]
    out = [r["sha256_hash"] for r in de.by_family(rows, de.Counter({"Mirai": 5}), random.Random(1))]
    assert out == ["g0", "m0", "u0", "m1", "m2"]


class FakeJobs:
    """The platform's job list, answering for the hashes it is given."""

    def __init__(self, jobs):
        self.jobs, self.asked = jobs, []

    def _call(self, method, path, params):
        assert (method, path) == ("GET", "/api/v1/jobs")
        self.asked.append(params["sha256"])
        return FakeResponse(200, payload=self.jobs.get(params["sha256"], []))


class FakeDetections:
    """get_info for recent_detections rows: the file type they do not carry."""

    def __init__(self, types):
        self.types, self.asked = types, []

    def post(self, url, data, headers):
        assert data["query"] == "get_info"
        self.asked.append(data["hash"])
        return FakeResponse(200, payload={"query_status": "ok", "data": [
            {"file_type": self.types[data["hash"]], "file_size": 64, "tags": ["t"]}]})


def feeder(tmp_path, monkeypatch, state=None, **over):
    args = de.argparse.Namespace(**{"benign_exclude": None, "max_bytes": 1 << 20, "bazaar_state": [],
                                    "per_family": 1, "lookups": 10, "keep": False, **over})
    monkeypatch.setattr(de.bz, "mb_download", lambda mb, key, sha: b"PK")

    def extract(zip_path, out_dir):
        path = out_dir / "sample"
        path.write_bytes(elf() + zip_path.stem.encode())   # one file per hash
        return path
    monkeypatch.setattr(de.bz, "extract_sample", extract)
    state = {} if state is None else state
    return de.Feeder(args, state, lambda: None, random.Random(0), tmp_path), state


def test_detections_are_described_capped_per_family_and_never_run_twice(tmp_path, monkeypatch):
    bazaar_state = tmp_path / "bazaar.json"
    bazaar_state.write_text(json.dumps({"in-bazaar-state": {"job_id": "j1", "state": "completed"}}))
    f, state = feeder(tmp_path, monkeypatch, bazaar_state=[str(bazaar_state)])
    f.platform = FakeJobs({"on-platform": [{"id": "j2", "state": "completed"}],
                           "failed-there": [{"id": "j3", "state": "failed"}]})
    rows = [{"sha256_hash": s, "signature": fam} for s, fam in [
        ("in-bazaar-state", "A"), ("on-platform", "B"), ("failed-there", "C"), ("a-pe", "D"),
        ("mirai-1", "Mirai"), ("mirai-2", "Mirai")]]
    mb = FakeDetections({"on-platform": "elf", "failed-there": "elf", "a-pe": "exe", "mirai-1": "elf", "mirai-2": "elf"})
    got = [p.sid for p in f.malicious("ubuntu", mb, "k", rows)]
    assert sorted(got) == ["mb:failed-there", "mb:mirai-1"]   # --per-family 1 keeps the second Mirai out
    assert "in-bazaar-state" not in mb.asked and "mirai-2" not in mb.asked
    assert state["mb:on-platform"]["skipped"] == "already run: job j2 on the platform (completed)"
    assert "mb:a-pe" not in state   # another guest's file is not this guest's skip


def test_detections_stop_when_the_lookups_are_spent(tmp_path, monkeypatch):
    f, _ = feeder(tmp_path, monkeypatch, lookups=2)
    rows = [{"sha256_hash": f"pe-{i}", "signature": f"F{i}"} for i in range(5)]
    mb = FakeDetections({r["sha256_hash"]: "exe" for r in rows})
    assert list(f.malicious("ubuntu", mb, "k", rows)) == []
    assert len(mb.asked) == 2
