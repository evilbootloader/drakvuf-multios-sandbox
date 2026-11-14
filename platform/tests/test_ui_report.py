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
from sandbox_platform import timeline as timeline_store

TABS = ("overview", "signatures", "behaviour", "timeline", "summary", "network", "dropped",
        "memory", "static")


def _job(conn, put_object, *, target_os="windows", objects=None) -> uuid.UUID:
    job_id = conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, sha256, size_bytes, detected_type, owner)"
        " VALUES (%s, 'invoice.exe', 'completed', %s, 19, 'PE32+', %s) RETURNING id",
        (target_os, "2" * 64, owner_id(conn))).fetchone()[0]
    if objects is None:
        index, log = F.calls_log(F.CALL_COUNTS)
        tindex, tlog = F.timeline_log()
        objects = {"cape_results.json": json.dumps(F.document()).encode(),
                   "calls_index.json": index, "calls.jsonl.gz": log,
                   "timeline_index.json": tindex, "timeline.jsonl.gz": tlog}
    manifest = {"schema_version": 1, "truncated": False, "documents": [],
                "artifacts": [{"name": n, "size_bytes": len(b), "sha256": hashlib.sha256(b).hexdigest()}
                              for n, b in objects.items()]}
    conn.execute("UPDATE jobs SET manifest = %s WHERE id = %s", (json.dumps(manifest), job_id))
    for name, body in objects.items():
        put_object(f"results/{job_id}/{name}", body)
    cape._load.cache_clear()
    calls_store._load.cache_clear()
    timeline_store._load.cache_clear()
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


def _rows(page: str) -> list[int]:
    return [int(i) for i in re.findall(r'<tr class="tl-row[^"]*"[^>]* data-i="(\d+)"', page)]


def test_the_timeline_is_every_plugins_rows_twenty_at_a_time(client, job):
    """Every plugin's rows of the sample, in time order, in a window of 20
    that loads the next 20 as it scrolls (operator, 2026-11-14)."""
    tab = client.get(f"/ui/jobs/{job}/tabs?tab=timeline").text
    assert _rows(tab) == list(range(20))
    for plugin in ("apimon", "memdump", "rootkitmon"):
        assert f'<span class="kind">{plugin}<b>' in tab
    assert "/timeline?part=rows&amp;start=20" in tab and 'data-edge="up"' not in tab
    # The tab bar counts the timeline's rows, not CAPE's events
    assert re.search(r'tab=timeline"[^>]*>Timeline<span class="n"> 510</span>', tab)
    more = client.get(f"/ui/jobs/{job}/timeline?part=rows&start=20").text
    assert _rows(more) == list(range(20, 40)) and "start=40" in more
    # Records no call holds sit among the calls by time, the kernel's too
    assert "NtWriteVirtualMemory heuristic" in tab and ">kernel<" in tab
    # A call's row opens the whole call, out of the calls log
    assert "/call?seqid=10&amp;cid=" in tab


def test_a_row_number_opens_the_window_at_that_row(client, job):
    tab = client.get(f"/ui/jobs/{job}/tabs?tab=timeline&at=300").text
    assert _rows(tab)[0] == 300 and 'data-i="300" data-target="1"' in tab.replace(' data-hit="1"', "")
    assert "part=before&amp;end=300" in tab
    up = client.get(f"/ui/jobs/{job}/timeline?part=before&end=300").text
    assert _rows(up) == list(range(280, 300)) and "end=280" in up


def test_a_search_moves_to_the_next_match_and_marks_it(client, job):
    """Down the list, not a filter: the block opens at the match, every row
    holding the text is marked, and the next search starts after it."""
    first = client.get(f"/ui/jobs/{job}/timeline/find?q=203.0.113.7&start=0")
    assert first.headers["HX-Retarget"] == "#timeline" and first.headers["HX-Reswap"] == "outerHTML"
    at = _rows(first.text)[0]
    assert f'data-i="{at}" data-hit="1" data-target="1"' in first.text
    # Rows that do not hold it are still there, unmarked
    assert len(_rows(first.text)) == 20 and first.text.count('data-hit="1"') < 20
    second = client.get(f"/ui/jobs/{job}/timeline/find?q=203.0.113.7&start={at + 1}")
    nxt = _rows(second.text)[0]
    assert nxt > at
    back = client.get(f"/ui/jobs/{job}/timeline/find?q=203.0.113.7&start={nxt}&dir=prev")
    assert _rows(back.text)[0] == at


def test_a_search_with_no_match_says_so(client, job):
    page = client.get(f"/ui/jobs/{job}/timeline/find?q=nowhere-in-it&start=0")
    assert "HX-Retarget" not in page.headers and "No later row" in page.text


def test_a_long_search_says_how_far_it_got_and_asks_again(client, job, monkeypatch):
    """One request reads one run of members; the status line it returns
    asks for the next as soon as it is drawn."""
    monkeypatch.setattr(timeline_store, "SEARCH_BYTES", 1)
    page = client.get(f"/ui/jobs/{job}/timeline/find?q=nowhere-in-it&start=0").text
    assert 'hx-trigger="load"' in page and "start=50" in page and "data-tl-stop" in page


def test_a_process_keeps_the_whole_timelines_row_numbers(client, job):
    tab = client.get(f"/ui/jobs/{job}/tabs?tab=timeline&seqid=11").text
    rows = _rows(tab)
    assert len(rows) == 20 and rows != list(range(20)) and rows == sorted(rows)
    assert '<option value="11" selected>' in tab
    assert client.get(f"/ui/jobs/{job}/timeline?seqid=").status_code == 200


def test_a_run_without_the_timeline_file_gets_its_events(client, conn, put_object):
    index, log = F.calls_log(F.CALL_COUNTS)
    job_id = _job(conn, put_object, objects={"cape_results.json": json.dumps(F.document()).encode(),
                                             "calls_index.json": index, "calls.jsonl.gz": log})
    tab = client.get(f"/ui/jobs/{job_id}/tabs?tab=timeline").text
    assert "predates the full timeline" in tab and len(_rows(tab)) == 5
    found = client.get(f"/ui/jobs/{job_id}/timeline/find?q=CurrentVersion&start=0")
    assert _rows(found.text)[0] == 1 and 'data-target="1"' in found.text


def test_each_network_detection_opens_its_own_timeline(client, job):
    tab = client.get(f"/ui/jobs/{job}/tabs?tab=network").text
    assert "/timeline/matches?q=203.0.113.7" in tab and "/timeline/matches?q=c2.example" in tab
    rows = client.get(f"/ui/jobs/{job}/timeline/matches?q=203.0.113.7").text
    found = _rows(rows)
    assert len(found) == 20 and rows.count('data-hit="1"') == 20
    assert f"?tab=timeline&amp;at={found[0]}&amp;q=203.0.113.7" in rows


def test_the_process_panel_links_to_its_timeline_and_draws_none(client, job):
    panel = client.get(f"/ui/jobs/{job}/process/10").text
    assert "?tab=timeline&amp;seqid=10" in panel
    assert "of its events" not in panel and 'hx-target="next .xslot"' not in panel


def test_the_category_bar_filters_the_table_below_it_and_scrolls_there(client, job):
    """Clicking a category filtered a table a screen below and seemed to do
    nothing (operator, 2026-11-14): the bar is now inside the swapped block,
    marks its choice, and the swap scrolls the block into view."""
    panel = client.get(f"/ui/jobs/{job}/process/10").text
    calls_at = panel.index('id="calls-10"')
    assert panel.index('class="catbar"') > calls_at
    assert 'hx-swap="outerHTML show:#calls-10:top"' in panel
    block = client.get(f"/ui/jobs/{job}/process/10/calls?category=crypto").text
    assert 'aria-current="true"' in block
    # The chosen category's link clears the filter
    assert re.search(r'href="/ui/jobs/[^"]+/process/10/calls"[^>]*aria-current', block)


def test_a_long_list_shows_a_page_and_the_rest_in_place(client, job):
    tab = client.get(f"/ui/jobs/{job}/tabs?tab=summary").text
    # 20 at first: invoice.exe, then file000 to file018
    assert "file018.dll" in tab and "file019.dll" not in tab
    assert "/list/read_files?offset=20&amp;seqid=10" in tab
    more = client.get(f"/ui/jobs/{job}/list/read_files?offset=20&seqid=10").text
    assert "file019.dll" in more and "file038.dll" in more and "file039.dll" not in more
    assert "offset=40&amp;seqid=10" in more and 'hx-trigger="intersect once root:(closest .window), click"' in more
    rest = client.get(f"/ui/jobs/{job}/list/read_files?offset=120&seqid=10").text
    assert "file129.dll" in rest and "Show more" not in rest
    assert client.get(f"/ui/jobs/{job}/list/not_a_list").status_code == 404
    # The guest's process has no list on the page, and none behind it either
    assert client.get(f"/ui/jobs/{job}/list/write_files?seqid=20").status_code == 404


def test_every_process_in_summary_starts_closed(client, job):
    """A drop-down per process, opened by a click (operator, 2026-11-14),
    whose closed line still counts each of its lists."""
    page = client.get(f"/ui/jobs/{job}/tabs?tab=summary").text
    groups = re.findall(r'<details class="group proc-group"[^>]*>', page)
    assert len(groups) == 3 and not any(" open" in g for g in groups)
    head = page[page.index('id="summary-12"'):]
    assert "registry written<b>1</b>" in head[:head.index("</summary>")]


def test_the_score_is_on_overview_and_beside_the_state(client, job):
    page = client.get(f"/ui/jobs/{job}?tab=overview").text
    facts = page[page.index('class="facts"'):]
    assert "<dt>Score</dt>" in facts[:600] and "7.5" in facts[:900]
    assert 'class="scorecard" data-status="Malicious"' in page


def test_the_static_tab_draws_an_elf_and_any_files_facts(client, job):
    tab = client.get(f"/ui/jobs/{job}/tabs?tab=static").text
    for heading in ("PE header", "ELF header", "Imported symbols", "Defined symbols", "Indicators in its strings",
                    "ZIP members", "Text", "Strings"):
        assert f"<h2>{heading}" in tab, heading
    # The sample's text arrives as text, in every part
    assert str(escape(".text" + F.HOSTILE)) in tab and str(escape(F.HOSTILE + ".so")) in tab
    assert F.HOSTILE not in tab
    # A segment both writable and executable is marked
    assert '<tr data-alert="1"><td class="mono">LOAD</td>' in tab


def test_version_information_is_listed_once_per_value():
    doc = F.document()
    doc["target"]["file"]["pe"]["versioninfo"] = [{"name": "FileDescription", "value": "Steam"}] * 29 + [
        {"name": "FileVersion", "value": "2.10"}, {"name": "FileDescription", "value": "Steam (de)"}]
    pe = cape.parse(json.dumps(doc).encode()).report.target.file.pe
    assert [(v.name, v.value) for v in pe.versioninfo] == [
        ("FileDescription", "Steam"), ("FileVersion", "2.10"), ("FileDescription", "Steam (de)")]


def test_an_odd_elf_part_costs_the_elf_part_not_the_hashes():
    doc = F.document()
    doc["target"]["file"]["elf"]["section_headers"] = "not a list"
    f = cape.parse(json.dumps(doc).encode()).report.target.file
    assert f.elf is None and f.sha256 == "2" * 64 and f.pe is not None


def test_the_history_lists_each_runs_score_from_its_row(client, conn, job):
    """The row's copy (0014): the list reads no report."""
    other = _job(conn, put_object=lambda *a: None, objects={})
    conn.execute("UPDATE jobs SET malscore = 7.5, malstatus = 'Malicious' WHERE id = %s", (job,))
    page = client.get("/ui/jobs").text
    rows = {m.group(1): m.group(0) for m in re.finditer(r'<tr>\s*<td class="mono"><a href="/ui/jobs/([0-9a-f-]+)">.*?</tr>', page, re.S)}
    assert 'data-status="Malicious"' in rows[str(job)] and "<b>7.5</b>" in rows[str(job)]
    assert '<span class="dim">—</span>' in rows[str(other)]


def test_the_job_page_takes_the_score_from_the_row_before_the_report(client, conn, job):
    conn.execute("UPDATE jobs SET malscore = 9.0, malstatus = 'Malicious' WHERE id = %s", (job,))
    facts = client.get(f"/ui/jobs/{job}").text.split('class="facts"', 1)[1][:900]
    assert "<b>9.0</b>" in facts
    # Not yet backfilled: the report's
    conn.execute("UPDATE jobs SET malscore = NULL, malstatus = NULL WHERE id = %s", (job,))
    facts = client.get(f"/ui/jobs/{job}").text.split('class="facts"', 1)[1][:900]
    assert "<b>7.5</b>" in facts


def test_backfill_scores_the_runs_from_before_the_column(conn, job, monkeypatch):
    import dataclasses

    import backfill_scores
    from sandbox_platform.config import settings
    unscored = _job(conn, put_object=lambda *a: None, objects={"report.json": b"{}"})

    dry = backfill_scores.backfill(conn, dry_run=True)
    assert dry["scored"] == 1 and conn.execute(
        "SELECT malscore FROM jobs WHERE id = %s", (job,)).fetchone()[0] is None

    done = backfill_scores.backfill(conn)
    assert done == {"scored": 1, "no score in a report": 1}
    assert conn.execute("SELECT malscore, malstatus FROM jobs WHERE id = %s",
                        (job,)).fetchone() == (7.5, "Malicious")
    assert conn.execute("SELECT malscore FROM jobs WHERE id = %s", (unscored,)).fetchone()[0] is None
    # Again: only the one with nothing to give is looked at
    assert backfill_scores.backfill(conn) == {"no score in a report": 1}

    # Past retention the store has expired the report: not read
    conn.execute("UPDATE jobs SET malscore = NULL, created_at = now() - interval '400 days' WHERE id = %s", (job,))
    monkeypatch.setattr(backfill_scores, "settings", dataclasses.replace(settings, retention_days=30))
    assert backfill_scores.backfill(conn)["expired"] == 1


def test_a_dropped_file_names_its_member_of_the_archive(client, job):
    tab = client.get(f"/ui/jobs/{job}/tabs?tab=dropped").text
    assert "extracted/" in tab and "<dt>File</dt>" in tab


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
    assert "/list/read_files?offset=20" in page and "seqid=" not in page


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
