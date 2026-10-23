"""`sandbox_platform.report`: report.json read back for the UI.

Two halves. `parse` and the layout are pure and tested directly with the
shapes `sandboxd/postprocessing/plugins/generate_report.py` writes and with
hostile ones. The rendering tests put a real report in the bucket behind a
completed job and read the tabs back, because the thing that matters -- that
sample-chosen text is inert on the page -- is a property of the templates,
not of the parser.
"""

from __future__ import annotations

import hashlib
import json
import uuid

import pytest
from markupsafe import escape

from sandbox_platform import report as R
from tests.conftest import owner_id


# --- fixtures: a report shaped like the real one -----------------------------

def process(seqid, pid, parent, name, **kw):
    return {"seqid": seqid, "pid": pid, "parent_seqid": parent, "name": name,
            "args": kw.pop("args", []), "started_at": kw.pop("started_at", 1.0),
            "exited_at": None, "exit_code": None, "exit_code_str": None,
            "killed_by": None, **kw}


def sample_report(**overrides) -> dict:
    """Five processes, the sample under the fourth root, one technique.

    Mirrors trace-windows.log's shape in miniature: several roots, the
    injected process deep under a later one, an unattributed memdump group."""
    doc = {
        "schema_version": 1,
        "startup": {"status": "Success", "process_name": "C:\\Users\\x\\sample.exe",
                    "arguments": "", "pid": 7208, "process": 4},
        "processes": [
            process(0, 4, None, "System", started_at=0.0),
            process(1, 628, None, "\\Device\\HarddiskVolume2\\Windows\\System32\\csrss.exe"),
            process(2, 764, None, "\\Device\\HarddiskVolume2\\Windows\\System32\\winlogon.exe"),
            process(3, 5076, 2, "\\Device\\HarddiskVolume2\\Windows\\explorer.exe"),
            process(4, 7208, 3, "\\Device\\HarddiskVolume2\\Users\\x\\sample.exe",
                    args=["sample.exe", "/quiet"]),
            process(5, 7300, 4, "\\Device\\HarddiskVolume2\\Windows\\System32\\cmd.exe",
                    exited_at=9.0, exit_code=0xC0000005, exit_code_str="STATUS_ACCESS_VIOLATION"),
        ],
        "ttps": [{"name": "query or enumerate registry value",
                  "att&ck": ["Discovery::Query Registry [T1012]"],
                  "mbc": ["Operating System::Registry::Query Registry Value [C0036.006]"],
                  "process_seqids": [4]}],
        "http_requests": [{"verb": "GET", "path": "/gate.php", "server_name": "evil.example",
                           "server_port": 80, "user_agent": "Mozilla/5.0", "extra_headers": [],
                           "process_seqid": 4}],
        "cracked_urls": [{"url": "http://evil.example/gate.php", "process_seqids": [4]}],
        "modified_files": [{"filename": "C:\\Users\\x\\AppData\\Local\\Temp\\a.tmp", "process_seqids": [4]}],
        "deleted_files": [],
        "connections": [{"protocol": "tcp", "local_ip": "172.16.3.10", "local_port": 49700,
                         "remote_ip": "203.0.113.5", "remote_port": 443, "process_seqids": [4]}],
        "dns_queries": [{"domain": "evil.example", "process_seqids": [4]}],
        "memdumps": [{"process_seqid": 4, "dumps": [
                          {"index": 1, "dump_reason": "NtFreeVirtualMemory", "method": "NtFreeVirtualMemory",
                           "pid": 7208, "address": "0x400000", "size": 4096, "filename": "aa.dmp"}]},
                     {"process_seqid": None, "dumps": [
                          {"index": 2, "dump_reason": "x", "method": "x", "pid": 99999,
                           "address": "0x1", "size": 512, "filename": "bb.dmp"}]}],
        "registry_set_values": [
            {"key": "\\REGISTRY\\USER\\S-1-5-21-1\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
             "value_name": "Updater", "value": "C:\\Users\\x\\sample.exe", "autostart": True,
             "process_seqids": [4]},
            {"key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor", "value_name": "v",
             "value": "01 00", "autostart": False, "process_seqids": [None]}],
        "registry_created_keys": [
            {"key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor\\Sub", "autostart": False,
             "process_seqids": [4]}],
        "registry_deleted_keys": [],
        "registry_deleted_values": [
            {"key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor", "value_name": "Old",
             "process_seqids": [4]}],
        "metadata": {},
    }
    doc.update(overrides)
    return doc


# --- parse -----------------------------------------------------------------

def test_the_real_shape_parses_and_derives_the_tree():
    loaded = R.parse(json.dumps(sample_report()).encode())
    assert loaded.error is None
    r = loaded.report
    assert [n.process.pid for n in r.tree] == [4, 628, 764]
    assert r.startup_process.basename == "sample.exe"
    assert r.by_seqid[5].exited_with_error
    assert r.ttps[0].attck == ["Discovery::Query Registry [T1012]"]
    assert r.connections[0].service == "https"
    assert r.filled_tabs() == {"behaviour", "network", "memory", "registry"}
    assert r.dump_count == 2
    assert [a.value_name for a in r.registry_autostart] == ["Updater"]
    assert r.registry_count == 4


def test_missing_sections_are_empty_not_errors():
    """A run without socketmon has no `connections` key at all."""
    doc = sample_report()
    for key in ("connections", "dns_queries", "http_requests", "cracked_urls", "memdumps",
                "registry_set_values", "registry_created_keys", "registry_deleted_keys",
                "registry_deleted_values"):
        del doc[key]
    r = R.parse(json.dumps(doc).encode()).report
    assert r.connections == [] and r.memdumps == []
    assert r.filled_tabs() == {"behaviour"}


def test_an_unknown_key_is_ignored_and_a_wrong_type_is_refused():
    ok = R.parse(json.dumps(sample_report(yara=[{"rule": "x"}])).encode())
    assert ok.error is None
    bad = R.parse(json.dumps(sample_report(processes=[{"seqid": "one", "pid": 1}])).encode())
    assert bad.report is None and "processes.0.seqid" in bad.error


@pytest.mark.parametrize("raw, fragment", [
    (b"", "not JSON"),
    (b"[1, 2]", "not a JSON object"),
    (b'{"schema_version": 7}', "schema version 7"),
])
def test_unusable_documents_get_a_sentence(raw, fragment):
    loaded = R.parse(raw)
    assert loaded.report is None and fragment in loaded.error


def test_strings_and_lists_are_bounded_before_parsing():
    doc = sample_report(
        processes=[process(i, i, None, "x" * 10_000) for i in range(R.MAX_ITEMS + 50)])
    r = R.parse(json.dumps(doc).encode()).report
    assert len(r.processes) == R.MAX_ITEMS
    assert len(r.processes[0].name) == R.MAX_STRING + len(R.TRUNCATED)
    assert r.processes[0].name.endswith(R.TRUNCATED)


def test_a_dangling_parent_makes_a_root_not_a_missing_process():
    doc = sample_report(processes=[process(0, 10, 99, "orphan.exe")])
    r = R.parse(json.dumps(doc).encode()).report
    assert [n.process.pid for n in r.tree] == [10]


# --- the diagram -------------------------------------------------------------

def test_the_lineage_is_the_path_to_the_sample_and_its_subtree():
    r = R.parse(json.dumps(sample_report()).encode()).report
    [root] = r.lineage()
    chain = []
    node = root
    while node:
        chain.append(node.process.basename)
        node = node.children[0] if node.children else None
    assert chain == ["winlogon.exe", "explorer.exe", "sample.exe", "cmd.exe"]


def test_the_layout_is_one_row_per_leaf_and_marks_the_sample_subtree():
    r = R.parse(json.dumps(sample_report()).encode()).report
    d = r.diagram(everything=True)
    assert d.shown == d.total == 6
    # Leaves: System, csrss, cmd -> three rows.
    assert d.height == R.PAD * 2 + 3 * (R.NODE_H + R.ROW_GAP) - R.ROW_GAP
    # Depth: winlogon > explorer > sample > cmd -> four columns.
    assert d.width == R.PAD * 2 + 4 * R.NODE_W + 3 * R.COL_GAP
    flagged = {b.process.pid for b in d.boxes if b.in_sample_tree}
    assert flagged == {7208, 7300}
    assert len(d.edges) == 3
    # A parent sits between its children, never off the grid.
    by_pid = {b.process.pid: b for b in d.boxes}
    assert by_pid[764].y == by_pid[5076].y == by_pid[7208].y == by_pid[7300].y


def test_without_a_known_sample_the_diagram_is_everything():
    doc = sample_report(startup={"status": "Success", "pid": 1, "process": None})
    r = R.parse(json.dumps(doc).encode()).report
    assert r.lineage() == []
    assert r.diagram().shown == 6


# --- rendered -----------------------------------------------------------------

HOSTILE = "<script>alert(1)</script>\"'&"


def _job_with_report(conn, put_object, doc: dict, *, target_os="windows",
                     with_capture=True) -> uuid.UUID:
    raw = json.dumps(doc).encode()
    digest = hashlib.sha256(raw).hexdigest()
    artifacts = [{"name": "report.json", "size_bytes": len(raw), "sha256": digest},
                 {"name": "dumps.zip", "size_bytes": 2, "sha256": "1" * 64}]
    if with_capture:
        artifacts.append({"name": "capture.pcap", "size_bytes": 0, "sha256": "0" * 64})
    manifest = {"schema_version": 1, "truncated": False, "documents": [],
                "artifacts": artifacts}
    job_id = conn.execute(
        """
        INSERT INTO jobs (target_os, submitted_filename, state, sha256,
                          size_bytes, detected_type, owner, manifest)
        VALUES (%s, 'x.exe', 'completed', 'af9c4ea0', 19, 'PE32', %s, %s)
        RETURNING id
        """,
        (target_os, owner_id(conn), json.dumps(manifest)),
    ).fetchone()[0]
    put_object(f"results/{job_id}/report.json", raw)
    R._load.cache_clear()
    return job_id


def test_the_tabs_render_the_report(client, conn, put_object):
    job_id = _job_with_report(conn, put_object, sample_report())

    overview = client.get(f"/ui/jobs/{job_id}?tab=overview").text
    assert "query or enumerate registry value" in overview
    assert "T1012" in overview and "sample.exe" in overview
    assert "STATUS_ACCESS_VIOLATION" not in overview  # that is cmd's, not the sample's
    assert "No techniques mapped" not in overview

    behaviour = client.get(f"/ui/jobs/{job_id}/tabs?tab=behaviour").text
    assert 'id="proc-4"' in behaviour and "data-sample" in behaviour
    assert "STATUS_ACCESS_VIOLATION" in behaviour
    assert "<svg" in behaviour and "All 6 processes as a diagram" in behaviour
    assert "a.tmp" in behaviour

    network = client.get(f"/ui/jobs/{job_id}/tabs?tab=network").text
    assert "evil.example" in network and "203.0.113.5:443" in network
    assert "https" in network and "/gate.php" in network
    assert "capture.pcap" in network
    # Sample-named hosts and URLs are never links.
    assert 'href="http://evil.example' not in network

    memory = client.get(f"/ui/jobs/{job_id}/tabs?tab=memory").text
    assert "aa.dmp" in memory and "bb.dmp" in memory
    assert "unattributed" in memory and "dumps.zip" in memory

    registry = client.get(f"/ui/jobs/{job_id}/tabs?tab=registry").text
    assert "Autostart locations" in registry and "Updater" in registry
    assert "CurrentVersion\\Run" in registry
    assert "Vendor\\Sub" in registry and "Old" in registry
    assert "unattributed" in registry


def test_filled_tabs_follow_the_report(client, conn, put_object):
    doc = sample_report()
    for key in ("connections", "dns_queries", "http_requests", "cracked_urls"):
        doc[key] = []
    # No capture either: the pcap alone fills Network, tested below.
    job_id = _job_with_report(conn, put_object, doc, with_capture=False)

    page = client.get(f"/ui/jobs/{job_id}").text
    start = page.index('<nav class="tabs"')
    nav = page[start:page.index("</nav>", start)]
    # One <a> per tab, attributes over several lines, label at the end.
    anchor = {chunk.split(">", 1)[1].split("<", 1)[0]: chunk
              for chunk in nav.split("<a ")[1:]}
    assert "data-empty" not in anchor["Behaviour"]
    assert "data-empty" in anchor["Network"]
    assert "data-empty" not in anchor["Memory"]
    assert "data-empty" not in anchor["Registry"]


def test_the_capture_alone_fills_the_network_tab(client, conn, put_object):
    """tcpdump runs on every trace outside DRAKVUF, so a pcap is network data
    whether or not the guest attributed any to a process."""
    doc = sample_report()
    for key in ("connections", "dns_queries", "http_requests", "cracked_urls"):
        doc[key] = []
    job_id = _job_with_report(conn, put_object, doc, with_capture=True)

    page = client.get(f"/ui/jobs/{job_id}").text
    start = page.index('<nav class="tabs"')
    nav = page[start:page.index("</nav>", start)]
    anchor = {chunk.split(">", 1)[1].split("<", 1)[0]: chunk
              for chunk in nav.split("<a ")[1:]}
    assert "data-empty" not in anchor["Network"]
    body = client.get(f"/ui/jobs/{job_id}/tabs?tab=network").text
    assert "capture.pcap" in body and "attributes no network activity" in body


def falco_sections() -> dict:
    """What get_falco_info and get_socket_info add for a Linux run."""
    return {
        "falco": [
            {"rule": "Read sensitive file untrusted", "priority": "WARNING", "source": "syscall",
             "tags": ["maturity_stable", "host", "filesystem", "mitre_credential_access", "T1555"],
             "output": "Sensitive file opened for reading | file=/etc/shadow process=cat",
             "first_seen": 1.5, "count": 3, "pid": 7208, "process_seqids": [4]},
            {"rule": "Unexpected UDP Traffic", "priority": "NOTICE", "source": "syscall",
             "tags": ["maturity_incubating", "network", "mitre_exfiltration", "TA0011"],
             "output": "Unexpected UDP Traffic Seen | connection=172.16.3.10:5353->198.51.100.7:53",
             "first_seen": 2.0, "count": 1, "pid": 7208, "process_seqids": [4]},
        ],
        "falco_coverage": {"rules_evaluated": 60, "rules_unsupported": 0, "rules_disabled": 0,
                           "scope": "sample", "sysret": True, "procmon": True, "libmon": True,
                           "undetermined": [{"rule": "Run shell untrusted", "count": 2,
                                             "missing": ["proc.pexe", "proc.pcmdline"]}]},
        "unix_sockets": [{"path": "", "peer_path": "/run/dbus/system_bus_socket",
                          "messages": 12, "bytes": 4096, "process_seqids": [4]}],
    }


def test_falco_findings_and_unix_sockets_render(client, conn, put_object):
    job_id = _job_with_report(conn, put_object, sample_report(**falco_sections()), target_os="ubuntu")

    overview = client.get(f"/ui/jobs/{job_id}/tabs?tab=overview").text
    assert "Read sensitive file untrusted" in overview and "file=/etc/shadow" in overview
    assert "×3" in overview and "T1555" in overview
    # Falco's own categories are not technique tags
    assert ">maturity_stable<" not in overview
    assert "60 rules evaluated" in overview and "Run shell untrusted" in overview

    network = client.get(f"/ui/jobs/{job_id}/tabs?tab=network").text
    assert "Falco network findings" in network and "Unexpected UDP Traffic" in network
    assert "Read sensitive file untrusted" not in network
    assert "/run/dbus/system_bus_socket" in network


def test_unix_sockets_alone_fill_the_network_tab(client, conn, put_object):
    doc = sample_report(unix_sockets=falco_sections()["unix_sockets"])
    for key in ("connections", "dns_queries", "http_requests", "cracked_urls"):
        doc[key] = []
    job_id = _job_with_report(conn, put_object, doc, with_capture=False)
    page = client.get(f"/ui/jobs/{job_id}").text
    start = page.index('<nav class="tabs"')
    nav = page[start:page.index("</nav>", start)]
    anchor = {chunk.split(">", 1)[1].split("<", 1)[0]: chunk
              for chunk in nav.split("<a ")[1:]}
    assert "data-empty" not in anchor["Network"]


@pytest.mark.parametrize("where", [
    "process_name", "process_args", "ttp", "domain", "url", "path", "header",
    "filename", "dump_reason", "exit_code_str", "registry", "falco", "unix_socket",
])
def test_hostile_report_text_renders_inert(client, conn, put_object, where):
    """Every string in the report is the sample's. The name reaches the page
    -- it must, an analyst needs to read it -- and its markup is escaped.
    markupsafe.escape is the oracle because it is what autoescape applies."""
    doc = sample_report()
    if where == "process_name":
        doc["processes"][4]["name"] = HOSTILE
    elif where == "process_args":
        doc["processes"][4]["args"] = [HOSTILE]
    elif where == "ttp":
        doc["ttps"][0]["name"] = HOSTILE
        doc["ttps"][0]["att&ck"] = [HOSTILE]
    elif where == "domain":
        doc["dns_queries"][0]["domain"] = HOSTILE
    elif where == "url":
        doc["cracked_urls"][0]["url"] = HOSTILE
    elif where == "path":
        doc["http_requests"][0]["path"] = HOSTILE
        doc["http_requests"][0]["user_agent"] = HOSTILE
    elif where == "header":
        doc["http_requests"][0]["extra_headers"] = [HOSTILE]
    elif where == "filename":
        doc["modified_files"][0]["filename"] = HOSTILE
    elif where == "dump_reason":
        doc["memdumps"][0]["dumps"][0]["dump_reason"] = HOSTILE
        doc["memdumps"][0]["dumps"][0]["filename"] = HOSTILE
    elif where == "exit_code_str":
        doc["processes"][5]["exit_code_str"] = HOSTILE
    elif where == "registry":
        doc["registry_set_values"][0]["key"] = HOSTILE
        doc["registry_set_values"][0]["value_name"] = HOSTILE
        doc["registry_set_values"][0]["value"] = HOSTILE
    elif where == "falco":
        doc.update(falco_sections())
        for finding in doc["falco"]:
            finding["output"] = HOSTILE
        doc["falco"][0]["rule"] = HOSTILE
    elif where == "unix_socket":
        doc.update(falco_sections())
        doc["unix_sockets"][0]["peer_path"] = HOSTILE
    job_id = _job_with_report(conn, put_object, doc)

    pages = "".join(client.get(f"/ui/jobs/{job_id}/tabs?tab={t}").text
                    for t in ("overview", "behaviour", "network", "memory", "registry"))
    assert str(escape(HOSTILE)) in pages
    assert HOSTILE not in pages
    assert "<script>" not in pages


def test_a_report_that_cannot_be_read_says_so_and_the_page_survives(client, conn, put_object):
    job_id = _job_with_report(conn, put_object, {"schema_version": 9})
    page = client.get(f"/ui/jobs/{job_id}?tab=behaviour").text
    assert "could not be read" in page and "schema version 9" in page
    assert client.get(f"/ui/jobs/{job_id}?tab=artifacts").status_code == 200


def test_a_report_over_the_cap_is_not_read(client, conn, put_object, monkeypatch):
    monkeypatch.setattr(R, "MAX_REPORT_BYTES", 64)
    job_id = _job_with_report(conn, put_object, sample_report())
    page = client.get(f"/ui/jobs/{job_id}?tab=behaviour").text
    assert "over 64 bytes" in page


def test_a_job_without_a_report_still_says_where_one_comes_from(client, conn):
    from tests.test_ui import _job
    job_id = _job(conn, "x.bin", target_os="windows")
    page = client.get(f"/ui/jobs/{job_id}?tab=behaviour").text
    assert "Not collected" in page
    overview = client.get(f"/ui/jobs/{job_id}").text
    assert "No report for this run" in overview