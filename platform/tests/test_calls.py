"""calls.py: a process's calls, a page at a time out of the calls log."""

from __future__ import annotations

import gzip
import json

import cape_fixture as F
import pytest
from sandbox_platform import calls


@pytest.fixture
def store():
    index, log = F.calls_log(F.CALL_COUNTS)
    reads = []

    def reader(key, start, end):
        reads.append((start, end))
        return log[start:end]
    available = calls.Available(calls.parse_index(index), "results/job/calls.jsonl.gz")
    return available, reader, reads


def test_a_page_is_one_member_and_the_cursor_walks_on(store):
    available, reader, reads = store
    first = calls.page(available, 10, reader=reader)
    assert [c.cid for c in first.calls] == list(range(calls.PAGE_CALLS))
    assert first.next == f"0.{calls.PAGE_CALLS}" and first.matching == 450
    assert len(reads) == 1
    seen = [c.cid for c in first.calls]
    cursor = first.next
    while cursor:
        page = calls.page(available, 10, cursor, reader=reader)
        seen += [c.cid for c in page.calls]
        cursor = page.next
    assert seen == list(range(450))


def test_a_category_reads_only_the_members_that_hold_it(store):
    available, reader, reads = store
    page = calls.page(available, 10, category="crypto", reader=reader)
    assert {c.api for c in page.calls} == {"CryptEncrypt"}
    assert page.matching == 90 and len(page.calls) == 90 and page.next is None


def test_api_thread_and_failed_filters(store):
    available, reader, _ = store
    by_api = calls.page(available, 11, api="connect", reader=reader)
    assert {c.api for c in by_api.calls} == {"connect"}
    tid = by_api.calls[0].tid
    assert {c.tid for c in calls.page(available, 11, tid=tid, reader=reader).calls} == {tid}
    failed = calls.page(available, 10, failed=True, reader=reader).calls
    assert failed and all(c.failed for c in failed)


def test_a_call_by_cid_is_the_same_call_the_page_shows(store):
    available, reader, _ = store
    on_page = calls.page(available, 10, "2.0", reader=reader).calls[3]
    assert calls.call(available, 10, on_page.cid, reader=reader) == on_page
    assert calls.call(available, 10, 10_000, reader=reader) is None
    assert calls.call(available, 99, 0, reader=reader) is None


def test_arguments_are_parsed_and_bounded():
    row = {"api": "x", "arguments": [{"name": "a", "value": "v" * (calls.MAX_VALUE + 9)}] * 100}
    member = gzip.compress(json.dumps(row).encode() + b"\n")
    index = {"version": 1, "chunk": 200, "processes": {"1": {"pid": 5, "count": 1, "threads": [],
             "categories": {"": 1}, "apis": {"x": 1}, "chunks": [[0, len(member), 0, {"": 1}]]}}}
    available = calls.Available(calls.parse_index(json.dumps(index).encode()), "k")
    c = calls.call(available, 1, 0, reader=lambda k, s, e: member[s:e])
    assert len(c.arguments) == calls.MAX_ARGUMENTS
    assert c.arguments[0].value.endswith("…[truncated]")


def test_a_member_that_is_not_gzip_is_an_empty_page_not_an_error(store):
    available, _, _ = store
    page = calls.page(available, 10, reader=lambda k, s, e: b"garbage" * 10)
    assert page.calls == [] and page.next is None


@pytest.mark.parametrize("doc", [
    {"version": 2, "chunk": 200, "processes": {}},
    {"version": 1, "chunk": 0, "processes": {}},
    {"version": 1, "chunk": 200, "processes": {"x": {}}},
    {"version": 1, "chunk": 200, "processes": {"1": {"chunks": [[0, 0, 0, {}]]}}},
    {"version": 1, "chunk": 200, "processes": {"1": {"chunks": [[-1, 5, 0, {}]]}}},
    {"version": 1, "chunk": 200, "processes": {"1": {"chunks": [], "categories": {"a": "b"}}}},
])
def test_an_index_of_the_wrong_shape_is_refused(doc):
    with pytest.raises(calls.IndexError_):
        calls.parse_index(json.dumps(doc).encode())


def test_a_search_stops_at_the_member_budget_and_says_where_to_go_on():
    # Many members, the matching call only in the last
    rows = [{"api": "NtClose", "category": "system"}] * (200 * (calls.MAX_MEMBERS_PER_PAGE + 3))
    rows[-1] = {"api": "connect", "category": "network"}
    log, chunks, offset = bytearray(), [], 0
    for start in range(0, len(rows), 200):
        part = rows[start:start + 200]
        member = gzip.compress(b"\n".join(json.dumps(r).encode() for r in part))
        cats = {}
        for r in part:
            cats[r["category"]] = cats.get(r["category"], 0) + 1
        chunks.append([offset, len(member), start, cats])
        log += member
        offset += len(member)
    index = {"version": 1, "chunk": 200, "processes": {"1": {"pid": 1, "count": len(rows), "threads": [],
             "categories": {}, "apis": {}, "chunks": chunks}}}
    available = calls.Available(calls.parse_index(json.dumps(index).encode()), "k")
    reader = lambda k, s, e: bytes(log[s:e])
    page = calls.page(available, 1, api="connect", reader=reader)
    assert page.calls == [] and page.stopped and page.next == f"{calls.MAX_MEMBERS_PER_PAGE}.0"
    again = calls.page(available, 1, page.next, api="connect", reader=reader)
    assert [c.api for c in again.calls] == ["connect"]


def test_a_category_skips_the_members_without_it():
    """The index counts each member's categories: a filter reads only the
    members that hold one."""
    rows = [{"api": "NtClose", "category": "system"}] * 1000
    rows[-1] = {"api": "connect", "category": "network"}
    log, chunks, offset = bytearray(), [], 0
    for start in range(0, len(rows), 200):
        part = rows[start:start + 200]
        member = gzip.compress(b"\n".join(json.dumps(r).encode() for r in part))
        cats = {}
        for r in part:
            cats[r["category"]] = cats.get(r["category"], 0) + 1
        chunks.append([offset, len(member), start, cats])
        log += member
        offset += len(member)
    index = {"version": 1, "chunk": 200, "processes": {"1": {"pid": 1, "count": len(rows), "threads": [],
             "categories": {"system": 999, "network": 1}, "apis": {}, "chunks": chunks}}}
    available = calls.Available(calls.parse_index(json.dumps(index).encode()), "k")
    reads = []

    def reader(k, s, e):
        reads.append(s)
        return bytes(log[s:e])
    page = calls.page(available, 1, category="network", reader=reader)
    assert [c.cid for c in page.calls] == [999] and len(reads) == 1
