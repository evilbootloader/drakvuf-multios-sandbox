"""The job page over a CAPE report: every tab, every fragment a row opens,
the escaping of the sample's text, and the sample-only rule -- through the
routes, against the database and the object store."""

from __future__ import annotations

import hashlib
import json
import re
import uuid

import cape_fixture as F
import pytest
from conftest import owner_id
from markupsafe import escape
from sandbox_platform import calls as calls_store
from sandbox_platform import cape

TABS = ("overview", "signatures", "behaviour", "timeline", "summary", "network", "dropped",
        "memory", "static")


def _job(conn, put_object, *, target_os="windows", objects=None) -> uuid.UUID:
    job_id = conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, sha256, size_bytes, detected_type, owner)"
        " VALUES (%s, 'invoice.exe', 'completed', %s, 19, 'PE32+', %s) RETURNING id",
        (target_os, "2" * 64, owner_id(conn))).fetchone()[0]
    if objects is None:
        index, log = F.calls_log(F.CALL_COUNTS)
        objects = {"cape_results.json": json.dumps(F.document()).encode(),
                   "calls_index.json": index, "calls.jsonl.gz": log}
    manifest = {"schema_version": 1, "truncated": False, "documents": [],
                "artifacts": [{"name": n, "size_bytes": len(b), "sha256": hashlib.sha256(b).hexdigest()}
                              for n, b in objects.items()]}
    conn.execute("UPDATE jobs SET manifest = %s WHERE id = %s", (json.dumps(manifest), job_id))
    for name, body in objects.items():
        put_object(f"results/{job_id}/{name}", body)
    cape._load.cache_clear()
    calls_store._load.cache_clear()
    return job_id


@pytest.fixture
def job(conn, put_object):
    return _job(conn, put_object)


GUEST_MARKS = ("GUEST-ONLY", "guest-only.example", "192.0.2.99", "guest_only_signature", "svchost.exe")


@pytest.mark.parametrize("tab", TABS)
def test_every_tab_renders_the_samples_and_nothing_of_the_guests(client, job, tab):
    page = client.get(f"/ui/jobs/{job}/tabs?tab={tab}")
    assert page.status_code == 200
    for mark in GUEST_MARKS:
        assert mark not in page.text, (tab, mark)


@pytest.mark.parametrize("tab", TABS)
def test_the_samples_text_is_escaped_on_every_tab(client, job, tab):
    page = client.get(f"/ui/jobs/{job}/tabs?tab={tab}").text
    assert F.HOSTILE not in page
    assert "<script>alert" not in page and "<img src=x" not in page


def test_the_hostile_text_is_there_as_text(client, job):
    """Escaped, not dropped: the reader sees what the sample wrote."""
    page = client.get(f"/ui/jobs/{job}/tabs?tab=summary").text
    assert str(escape(F.HOSTILE)) in page


def test_every_panel_sits_directly_below_the_row_that_opens_it(client, job):
    """The operator's rule (2026-11-11): a panel opens below its line, and
    hides nothing. In the markup: each toggle's panel is the next row."""
    for tab in ("signatures", "behaviour", "timeline", "summary", "network", "dropped", "memory", "static"):
        page = client.get(f"/ui/jobs/{job}/tabs?tab={tab}").text
        ids = re.findall(r'class="xr" data-x="([^"]+)"|class="pline xr" data-x="([^"]+)"', page)
        for pair in ids:
            x = pair[0] or pair[1]
            row_end = page.index(f'data-x="{x}"')
            panel = page.index(f'id="x-{x}"')
            between = page[row_end:panel]
            # nothing that is another row starts between a row and its panel
            assert 'class="xr"' not in between and 'class="pline xr"' not in between, (tab, x)
            assert " hidden>" in page[panel:panel + 40] or " hidden" in page[panel:panel + 40]


def test_the_process_panel_has_its_facts_categories_activity_and_calls(client, job):
    page = client.get(f"/ui/jobs/{job}/process/10").text
    assert "invoice.exe" in page and "Calls by category" in page and "Its own activity" in page
    assert page.count('class="call xr"') == calls_store.PAGE_CALLS
    assert "persistence_autorun" in page and "203.0.113.7:443" in page
    assert str(escape(F.SAMPLE[10][4])) in page


def test_a_guests_process_is_not_a_panel(client, job):
    assert client.get(f"/ui/jobs/{job}/process/20").status_code == 404


def test_calls_filter_page_and_open_one(client, job):
    crypto = client.get(f"/ui/jobs/{job}/process/10/calls?category=crypto").text
    assert set(re.findall(r'<span class="api">([^<]+)</span>', crypto)) == {"CryptEncrypt"}
    rows = client.get(f"/ui/jobs/{job}/process/10/calls?part=rows&cursor=0.100").text
    assert "<form" not in rows and 'data-x="call-10-100"' in rows
    one = client.get(f"/ui/jobs/{job}/call?seqid=10&cid=3").text
    assert "CryptEncrypt" in one and 'class="hex"' in one
    # As a signature names it: by PID
    assert "RegSetValueExW" in client.get(f"/ui/jobs/{job}/call?pid=4100&cid=1").text
    assert client.get(f"/ui/jobs/{job}/call?pid=900&cid=0").status_code == 404


def test_a_signatures_data_opens_with_its_calls(client, job):
    page = client.get(f"/ui/jobs/{job}/signature/0").text
    assert "/call?pid=4100&amp;cid=403" in page
    assert str(escape(F.HOSTILE)) in page
    assert client.get(f"/ui/jobs/{job}/signature/9").status_code == 404


def test_the_timeline_filters_and_pages(client, job):
    page = client.get(f"/ui/jobs/{job}/timeline?object=registry").text
    assert page.count('<tr class="xr"') == 1 and "CurrentVersion\\Run\\upd" in page


def test_a_long_list_shows_a_page_and_the_rest_in_place(client, job):
    tab = client.get(f"/ui/jobs/{job}/tabs?tab=summary").text
    # 25 at first: invoice.exe, then file000 to file023
    assert "file023.dll" in tab and "file024.dll" not in tab
    assert "/list/read_files?offset=25&amp;seqid=10" in tab
    more = client.get(f"/ui/jobs/{job}/list/read_files?offset=25&seqid=10").text
    assert "file024.dll" in more and "file123.dll" in more and "file124.dll" not in more
    assert "offset=125&amp;seqid=10" in more
    rest = client.get(f"/ui/jobs/{job}/list/read_files?offset=125&seqid=10").text
    assert "file129.dll" in rest and "Show more" not in rest
    assert client.get(f"/ui/jobs/{job}/list/not_a_list").status_code == 404
    # The guest's process has no list on the page, and none behind it either
    assert client.get(f"/ui/jobs/{job}/list/write_files?seqid=20").status_code == 404


def test_summary_is_split_by_process_in_the_trees_order(client, job):
    """The operator's choice (2026-11-12): a section per process, each with
    only its own lists; the ones with nothing named in one line at the end."""
    page = client.get(f"/ui/jobs/{job}/tabs?tab=summary").text
    sections = [page.index(f'id="summary-{s}"') for s in (10, 11, 12)]
    assert sections == sorted(sections)
    assert 'id="summary-13"' not in page
    nothing = page.index("Nothing summarised")
    assert nothing > sections[-1] and "explorer.exe" in page[nothing:]
    # A list is under the process that made it: schtasks wrote one key
    schtasks = page[sections[2]:nothing]
    assert "Registry written" in schtasks and "Files written" not in schtasks
    # autostart first, and marked
    invoice = page[sections[0]:sections[1]]
    assert invoice.index("CurrentVersion\\Run\\upd") < invoice.index("Software\\upd\\cfg")
    assert "1 autostart" in invoice


def test_a_report_without_per_process_lists_shows_them_together(client, conn, put_object):
    doc = F.document()
    del doc["behavior"]["summary"]["by_process"]
    index, log = F.calls_log(F.CALL_COUNTS)
    job_id = _job(conn, put_object, objects={"cape_results.json": json.dumps(doc).encode(),
                                             "calls_index.json": index, "calls.jsonl.gz": log})
    page = client.get(f"/ui/jobs/{job_id}/tabs?tab=summary").text
    assert "All of the sample" in page and "Files written" in page and 'id="summary-10"' not in page
    assert "/list/read_files?offset=25" in page and "seqid=" not in page


def test_a_job_from_before_the_cape_chain_says_so(client, conn, put_object):
    job_id = _job(conn, put_object, objects={"report.json": b"{}"})
    for tab in TABS:
        page = client.get(f"/ui/jobs/{job_id}/tabs?tab={tab}")
        assert page.status_code == 200
    assert "No CAPE report for this run" in client.get(f"/ui/jobs/{job_id}/tabs?tab=behaviour").text
    assert client.get(f"/ui/jobs/{job_id}/process/10").status_code == 404


def test_a_report_that_cannot_be_read_names_why(client, conn, put_object):
    job_id = _job(conn, put_object, objects={"cape_results.json": b"not json"})
    page = client.get(f"/ui/jobs/{job_id}/tabs?tab=overview").text
    assert "could not be read" in page and "not JSON" in page


def test_control_bytes_reach_the_page_as_text(client, job):
    """A NUL or an escape sequence in a buffer is shown as `\\x00`, not sent
    as a character the browser drops or a terminal copying it interprets."""
    for url in (f"/ui/jobs/{job}/tabs?tab=summary", f"/ui/jobs/{job}/call?seqid=10&cid=3",
                f"/ui/jobs/{job}/process/10"):
        page = client.get(url).text
        assert not re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", page), url
        assert "\\x00\\x01\\x02\\x03" in page, url
