"""`sandbox_platform.logview`: a process's lines out of the stored logs.

The index is built here the way `sandboxd/postprocessing/indexer.py` builds
it -- a msgpack table of contents, then one msgpack entry per (process,
plugin) -- so the reader is tested against the writer's format without
importing the writer. Paging is tested against a fake store first, for the
arithmetic, then against MinIO through the page, for the property that
matters: a page shows one process's lines and nothing else's, escaped.
"""

from __future__ import annotations

import hashlib
import json
import uuid

import msgpack
import pytest

from sandbox_platform import logview as L
from tests.conftest import owner_id
from tests.test_report import sample_report


# --- building an index the way the indexer does -----------------------------

def build_log(events: list[tuple[int, str, str]]) -> tuple[bytes, dict[int, dict]]:
    """A JSONL log from (pid, method, payload) triples, and the per-PID entry
    the indexer would write for it: one block per run of adjacent lines with
    the same PID and method."""
    entries: dict[int, dict] = {}
    out = bytearray()
    for pid, method, payload in events:
        start = len(out)
        out += json.dumps({"Plugin": "x", "PID": pid, "EventUID": hex(start + 1),
                           "Method": method, "Data": payload}).encode() + b"\n"
        entry = entries.setdefault(pid, {"blocks": [], "values": [], "mapping": []})
        if method not in entry["values"]:
            entry["values"].append(method)
        idx = entry["values"].index(method)
        if entry["blocks"] and entry["blocks"][-1][1] == start and entry["mapping"][-1] == idx:
            entry["blocks"][-1][1] = len(out)
        else:
            entry["blocks"].append([start, len(out)])
            entry["mapping"].append(idx)
    return bytes(out), entries


def build_index(per_seqid: dict[int, dict[str, dict]]) -> bytes:
    """`log_index` bytes: toc then entries, as indexer.build_log_index."""
    n = max(per_seqid) + 1 if per_seqid else 0
    toc: list[dict] = [dict() for _ in range(n)]
    blobs = []
    pos = 0
    for seqid, plugins in per_seqid.items():
        for plugin, entry in plugins.items():
            packed = msgpack.packb(entry)
            toc[seqid][plugin] = pos
            blobs.append(packed)
            pos += len(packed)
    return msgpack.packb(toc) + b"".join(blobs)


# --- parse --------------------------------------------------------------------

def test_the_writers_format_round_trips():
    log, entries = build_log([(7208, "NtOpenFile", "a"), (4, "NtClose", "b"),
                              (7208, "NtOpenFile", "c"), (7208, "NtClose", "d")])
    index = L.parse_index(build_index({4: {"syscall": entries[7208]}, 0: {"syscall": entries[4]}}))
    assert index.plugins_for(4) == ["syscall"] and index.plugins_for(9) == []
    entry = index.entry(4, "syscall")
    assert len(entry.blocks) == 3 and entry.values == ("NtOpenFile", "NtClose")
    assert entry.select("NtClose") == [entry.blocks[2]]
    assert entry.select("NtNothing") == []
    assert index.entry(4, "apimon") is None


@pytest.mark.parametrize("raw", [
    b"", b"\x00", msgpack.packb({"not": "a list"}), msgpack.packb([["not a dict"]]),
    msgpack.packb([{"syscall": -1}]),
])
def test_a_malformed_table_of_contents_is_refused(raw):
    with pytest.raises(L.IndexError_):
        L.parse_index(raw)


@pytest.mark.parametrize("entry", [
    {"blocks": [[5, 2]], "values": [], "mapping": []},        # end before start
    {"blocks": [[0, 5]], "values": ["m"], "mapping": [7]},   # mapping outside values
    {"blocks": "no", "values": [], "mapping": []},
    [1, 2, 3],
])
def test_a_malformed_entry_is_none_not_a_crash(entry):
    index = L.parse_index(build_index({0: {"syscall": entry}}))
    assert index.entry(0, "syscall") is None


# --- paging, against a fake store -------------------------------------------

@pytest.fixture
def store(monkeypatch):
    """`objects.range_bytes` over an in-memory object, counting requests."""
    objects_: dict[str, bytes] = {}
    calls: list[tuple[int, int]] = []

    def range_bytes(key, start, end):
        calls.append((start, end))
        return objects_.get(key, b"")[start:end]

    monkeypatch.setattr(L.objects, "range_bytes", range_bytes)
    monkeypatch.setattr(L.objects, "result_prefix", lambda job_id, prefix: "")
    store_ = type("S", (), {})()
    store_.objects, store_.calls = objects_, calls
    return store_


def available_for(log: bytes, entries: dict, store) -> L.Available:
    store.objects["syscall.log"] = log
    index = L.parse_index(build_index({1: {"syscall": entries[7208]}}))
    return L.Available(index, frozenset({"syscall"}), frozenset(), "", uuid.uuid4())


def test_a_page_holds_one_process_and_cuts_on_a_line(store, monkeypatch):
    events = [(7208 if i % 2 else 4, "M", f"line{i:04d}" + "x" * 40) for i in range(400)]
    log, entries = build_log(events)
    av = available_for(log, entries, store)
    monkeypatch.setattr(L, "PAGE_BYTES", 1000)

    first = L.page(av, 1, "syscall", None, 0)
    assert first.lines and all('"PID": 7208' in ln for ln in first.lines)
    assert first.next_skip is not None
    # Whole lines only: the last one parses.
    json.loads(first.lines[-1])

    pages = [first]
    while pages[-1].next_skip is not None:
        pages.append(L.page(av, 1, "syscall", None, pages[-1].next_skip))
    every = [ln for p in pages for ln in p.lines]
    assert len(every) == 200 and len({ln for ln in every}) == 200
    assert sum(len(ln) + 1 for ln in every) == first.total_bytes
    # Interleaved with PID 4 on every other line, yet the store was not asked
    # for each line separately: the spans coalesce.
    assert len(store.calls) < len(every) / 4


def test_the_method_filter_selects_blocks(store):
    log, entries = build_log([(7208, "NtOpenFile", "a"), (7208, "NtClose", "b"),
                              (7208, "NtOpenFile", "c")])
    av = available_for(log, entries, store)
    page = L.page(av, 1, "syscall", "NtClose", 0)
    assert len(page.lines) == 1 and '"NtClose"' in page.lines[0]
    assert page.next_skip is None
    assert L.page(av, 1, "syscall", "NtNothing", 0).lines == []


def test_the_request_budget_bounds_a_page(store, monkeypatch):
    # Every line of the process is 200 KiB away from the previous one.
    log, entries = build_log([(7208, "M", "a")])
    entry = entries[7208]
    entry["blocks"] = [[i * 200_000, i * 200_000 + 10] for i in range(100)]
    entry["mapping"] = [0] * 100
    store.objects["syscall.log"] = b"x" * (100 * 200_000 + 10)
    index = L.parse_index(build_index({1: {"syscall": entry}}))
    av = L.Available(index, frozenset({"syscall"}), frozenset(), "", uuid.uuid4())
    monkeypatch.setattr(L, "MAX_REQUESTS_PER_PAGE", 5)

    page = L.page(av, 1, "syscall", None, 0)
    assert len(store.calls) == 5
    assert page.truncated_by_requests and page.next_skip == 50


def test_an_index_that_lies_gets_only_what_exists(store):
    log, entries = build_log([(7208, "M", "a")])
    entry = entries[7208]
    entry["blocks"] = [[0, len(log)], [10_000_000, 10_000_100]]
    entry["mapping"] = [0, 0]
    store.objects["syscall.log"] = log
    index = L.parse_index(build_index({1: {"syscall": entry}}))
    av = L.Available(index, frozenset({"syscall"}), frozenset(), "", uuid.uuid4())
    page = L.page(av, 1, "syscall", None, 0)
    assert len(page.lines) == 1


# --- through the page -----------------------------------------------------------

HOSTILE = "<script>alert(1)</script>\"'&"


def _job(conn, put_object, log_by_plugin: dict[str, bytes], index: bytes,
         doc: dict | None = None, extra_names=()) -> uuid.UUID:
    doc = doc or sample_report()
    report = json.dumps(doc).encode()
    artifacts = [{"name": "report.json", "size_bytes": len(report),
                  "sha256": hashlib.sha256(report).hexdigest()},
                 {"name": "log_index", "size_bytes": len(index),
                  "sha256": hashlib.sha256(index).hexdigest()}]
    for name, body in log_by_plugin.items():
        artifacts.append({"name": name, "size_bytes": len(body),
                          "sha256": hashlib.sha256(body).hexdigest()})
    for name in extra_names:
        artifacts.append({"name": name, "size_bytes": 1, "sha256": "0" * 64})
    manifest = {"schema_version": 1, "truncated": False, "documents": [],
                "artifacts": artifacts}
    job_id = conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, sha256, size_bytes,"
        " detected_type, owner, manifest) VALUES ('windows', 'x.exe', 'completed',"
        " 'af9c4ea0', 19, 'PE32', %s, %s) RETURNING id",
        (owner_id(conn), json.dumps(manifest))).fetchone()[0]
    put_object(f"results/{job_id}/report.json", report)
    put_object(f"results/{job_id}/log_index", index)
    for name, body in log_by_plugin.items():
        put_object(f"results/{job_id}/{name}", body)
    L._load.cache_clear()
    from sandbox_platform import report as R
    R._load.cache_clear()
    return job_id


def test_the_panel_shows_one_process_out_of_the_stored_log(client, conn, put_object):
    log, entries = build_log([(7208, "NtOpenFile", "mine-1"), (628, "NtClose", "theirs"),
                              (7208, "NtClose", "mine-2"), (7208, "NtOpenFile", HOSTILE)])
    index = build_index({4: {"apimon": entries[7208]}, 1: {"apimon": entries[628]}})
    job_id = _job(conn, put_object, {"apimon.log": log, "syscall.log.gz": b"gz"}, index)

    panel = client.get(f"/ui/jobs/{job_id}/process/4").text
    assert "sample.exe" in panel and 'aria-selected="true">apimon' in panel
    assert "mine-1" in panel and "mine-2" in panel and "theirs" not in panel
    # The line is JSON, so the payload's quotes arrive backslash-escaped; the
    # markup in it is what must be inert.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in panel
    assert "<script>" not in panel and HOSTILE not in panel
    # The gzipped syscall log is offered as a download, not a view.
    assert "syscall ↓" in panel
    assert "end of apimon.log" in panel

    filtered = client.get(f"/ui/jobs/{job_id}/process/4?plugin=apimon&method=NtClose").text
    assert "mine-2" in filtered and "mine-1" not in filtered
    assert '<option value="NtClose" selected>' in filtered

    # A process the tree has, with nothing indexed for it.
    assert "No log lines indexed" in client.get(f"/ui/jobs/{job_id}/process/0").text
    assert client.get(f"/ui/jobs/{job_id}/process/99").status_code == 404


def test_more_fetches_the_next_page_of_lines_only(client, conn, put_object, monkeypatch):
    monkeypatch.setattr(L, "PAGE_BYTES", 300)
    log, entries = build_log([(7208, "M", f"line{i:03d}" + "y" * 60) for i in range(10)])
    index = build_index({4: {"apimon": entries[7208]}})
    job_id = _job(conn, put_object, {"apimon.log": log}, index)

    first = client.get(f"/ui/jobs/{job_id}/process/4?plugin=apimon").text
    assert "line000" in first and "line009" not in first
    assert "part=lines" in first
    skip = int(first.split("skip=")[1].split("&")[0])

    rest = client.get(f"/ui/jobs/{job_id}/process/4?plugin=apimon&skip={skip}&part=lines").text
    assert "<section" not in rest and "<pre" in rest
    assert "line000" not in rest
    # Every line lands on exactly one page.
    seen = []
    skip = 0
    while True:
        part = client.get(f"/ui/jobs/{job_id}/process/4?plugin=apimon&skip={skip}&part=lines").text
        seen += [f"line{i:03d}" for i in range(10) if f"line{i:03d}" in part]
        if "skip=" not in part:
            break
        skip = int(part.split("skip=")[1].split("&")[0])
    assert seen == [f"line{i:03d}" for i in range(10)]


def test_a_missing_index_is_a_sentence_not_a_fault(client, conn, put_object):
    doc = sample_report()
    report = json.dumps(doc).encode()
    manifest = {"schema_version": 1, "truncated": False, "documents": [],
                "artifacts": [{"name": "report.json", "size_bytes": len(report),
                               "sha256": hashlib.sha256(report).hexdigest()}]}
    job_id = conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, sha256, size_bytes,"
        " detected_type, owner, manifest) VALUES ('windows', 'x.exe', 'completed',"
        " 'af9c4ea0', 19, 'PE32', %s, %s) RETURNING id",
        (owner_id(conn), json.dumps(manifest))).fetchone()[0]
    put_object(f"results/{job_id}/report.json", report)
    from sandbox_platform import report as R
    R._load.cache_clear()

    page = client.get(f"/ui/jobs/{job_id}/process/4")
    assert page.status_code == 200 and "No log lines indexed" in page.text