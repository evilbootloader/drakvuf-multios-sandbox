"""cape.py: the CAPE report read back, bounded, cut to the sample's processes."""

from __future__ import annotations

import json

import cape_fixture as F
import pytest
from sandbox_platform import cape


def report(**kw) -> cape.Report:
    loaded = cape.parse(json.dumps(F.document(**kw)).encode())
    assert loaded.error is None
    return loaded.report


GUEST_PID = F.GUEST[20][0]


@pytest.mark.parametrize("scope_all", [False, True])
def test_nothing_of_the_guests_reaches_the_page(scope_all):
    """The operator's rule (2026-11-11): every section is the sample's.
    Under scope "all" sandboxd writes the guest's processes too; the reader
    cuts them, and everything credited to them, the same."""
    r = report(scope_all=scope_all)
    assert {p.seqid for p in r.processes} == set(F.SAMPLE)
    assert GUEST_PID not in {e.pid for e in r.events}
    assert all("GUEST-ONLY" not in str(e.data) for e in r.events)
    assert [a.funcname for a in r.anomalies] == ["cpuid", "DriverCRC"]   # the kernel's stays
    assert [b.pid for b in r.encrypted] == [4100]
    assert [e.ip_port for e in r.network_map.endpoint_map] == ["203.0.113.7:443"]
    assert [d.domain for d in r.network_map.dns_intents] == ["c2.example"]
    assert [d.pid for d in r.dropped] == [4100]
    assert [m.pid for m in r.procmemory] == [4100]
    assert [s.name for s in r.signatures] == ["persistence_autorun", "injection_createremotethread"]
    # A capture flow the sample's processes are not credited with, to a host
    # they never used, is the guest's
    assert [f.dst for f in r.network.tcp] == ["203.0.113.7"]
    assert [h.ip for h in r.network.hosts] == ["203.0.113.7"]


def test_under_scope_all_the_summary_is_rebuilt_from_the_samples_activity():
    r = report(scope_all=True)
    assert "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd" in r.summary["write_keys"]
    assert F.SAMPLE[11][4] in r.summary["executed_commands"]
    assert "C:\\Windows\\Prefetch\\GUEST-ONLY.pf" not in r.summary["write_files"]


def test_the_tree_links_by_seqid_and_marks_the_injected_and_the_taken_over():
    r = report()
    shape = [(n.process.seqid, [(c.process.seqid, [g.process.seqid for g in c.children]) for c in n.children])
             for n in r.tree]
    assert shape == [(10, [(11, [12])]), (13, [])]
    assert r.roots == {10}
    assert r.followed_seqids == {13}
    assert r.root_process.process_id == 4100
    d = r.diagram()
    assert d.shown == 4 and {b.process.seqid for b in d.boxes if b.root} == {10}


def test_a_loop_of_parents_is_cut_rather_than_hiding_the_processes():
    doc = F.document()
    by_seqid = {p["seqid"]: p for p in doc["behavior"]["processes"]}
    by_seqid[10]["parent_seqid"] = 12          # 10 -> 11 -> 12 -> 10
    r = cape.parse(json.dumps(doc).encode()).report
    assert sorted(n.process.seqid for root in r.tree for n in root.walk()) == sorted(F.SAMPLE)


def test_times_are_seconds_into_the_trace_and_unknown_is_none():
    r = report()
    assert r.t(F.T0 + 2.5) == pytest.approx(2.5)
    assert r.t(0) is None and r.t("not a time") is None and r.t(None) is None


def test_one_bad_section_is_named_and_the_rest_still_renders():
    doc = F.document()
    doc["behavior"]["enhanced"][0]["eid"] = "not a number"
    doc["dropped"] = "not a list"
    r = cape.parse(json.dumps(doc).encode()).report
    assert "enhanced" in r.section_errors
    assert len(r.events) == 4 and len(r.processes) == 4 and r.signatures


@pytest.mark.parametrize("raw, fragment", [
    (b"not json", "not JSON"), (b"[]", "not a JSON object"),
])
def test_unusable_documents_get_a_sentence(raw, fragment):
    loaded = cape.parse(raw)
    assert loaded.report is None and fragment in loaded.error


def test_strings_and_lists_are_bounded_before_parsing():
    doc = F.document()
    doc["behavior"]["summary"]["read_files"] = ["x" * (cape.MAX_STRING + 50)] * (cape.MAX_ITEMS + 10)
    r = cape.parse(json.dumps(doc).encode()).report
    files = r.summary["read_files"]
    assert len(files) == cape.MAX_ITEMS
    assert files[0].endswith(cape.TRUNCATED) and len(files[0]) == cape.MAX_STRING + len(cape.TRUNCATED)


def test_signature_data_is_classified_and_joined_to_its_ttps():
    r = report()
    sig = r.signatures[0]
    assert sig.ttps == ["T1547.001"] and sig.level == "high"
    kinds = [(m.kind, m.label) for m in r.signature_marks(sig)]
    assert kinds == [("call", ""), ("call", ""), ("field", "regkey"), ("process", "process"),
                     ("ioc", "file"), ("ioc", "cmdline")]
    calls = [m for m in r.signature_marks(sig) if m.kind == "call"]
    assert [(m.pid, m.cid) for m in calls] == [(4100, 1), (4100, 403)]


def test_attack_merges_capa_and_signatures_by_technique():
    r = report()
    by_id = {t.id: t for t in r.techniques}
    assert by_id["T1055"].capa and by_id["T1055"].signatures == ("injection_createremotethread",)
    assert by_id["T1547.001"].tactic == "Persistence"


def test_a_process_has_its_own_share_of_the_report():
    r = report()
    a = r.activity(r.by_seqid[10])
    assert [e.event for e in a["events"]] == ["write", "write", "execute", "load", "move"]
    assert [e.ip_port for e in a["endpoints"]] == ["203.0.113.7:443"]
    assert a["dns"] == ["c2.example"] and len(a["http"]) == 1
    assert [s.name for s in a["signatures"]] == ["persistence_autorun", "injection_createremotethread"]
    assert r.activity(r.by_seqid[12])["events"] == []


def test_tabs_are_filled_by_what_the_sample_did():
    r = report()
    assert r.filled_tabs() == {"overview", "signatures", "behaviour", "timeline", "summary",
                               "network", "dropped", "memory", "static"}
    assert r.tab_counts()["behaviour"] == 4 and r.tab_counts()["signatures"] == 2


def test_autostart_writes_are_known_by_their_location():
    assert cape.is_autostart("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x")
    assert cape.is_autostart("HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\evil\\ImagePath")
    assert not cape.is_autostart("HKEY_CURRENT_USER\\Software\\upd\\cfg")


def test_a_report_from_before_seqids_still_renders_its_processes():
    doc = F.document()
    del doc["trace_split"]["sample"]
    for p in doc["behavior"]["processes"]:
        p.pop("seqid"), p.pop("parent_seqid")
    r = cape.parse(json.dumps(doc).encode()).report
    assert len(r.processes) == 4 and len(r.tree) == 4


@pytest.mark.parametrize("scope_all", [False, True])
def test_summary_is_kept_per_process_and_the_samples_only(scope_all):
    r = report(scope_all=scope_all)
    assert set(r.summary_by_process) == {10, 11, 12}
    groups = r.summary_groups()
    assert [p.seqid for p, _, _ in groups] == [10, 11, 12, 13]
    assert groups[3][1] == {} and groups[3][2] == []
    assert [b.api_call for b in groups[0][2]] == ["CryptEncrypt"]
    # autostart keys first, per process and in the merged lists
    assert r.summary_by_process[10]["write_keys"][0].endswith("CurrentVersion\\Run\\upd")
    assert r.summary["write_keys"][0].endswith("CurrentVersion\\Run\\upd")
    if scope_all:
        # rebuilt from the sample's own lists: the guest's file is not in it
        assert "C:\\Windows\\Prefetch\\GUEST-ONLY.pf" not in r.summary["write_files"]
        assert r.summary["executed_commands"] == [F.SAMPLE[11][4], F.SAMPLE[12][4]]
