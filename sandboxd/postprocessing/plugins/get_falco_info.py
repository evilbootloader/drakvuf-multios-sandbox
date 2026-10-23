"""Falco's alerts and coverage, into the report.

`falco` is one entry per rule and process: the first rendered output and how
many times the rule matched there, so a rule that fires on every open of one
loop is one line rather than a thousand. `falco_coverage` says what the run
could and could not evaluate -- the undetermined rules are the ones a reader
should not read as "did not happen".
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

import orjson

from .falco_analysis import FALCO_ALERTS, FALCO_COVERAGE
from .parse_utils import parse_log
from .plugin_base import PostprocessContext

# Rules listed as undetermined in the report: the most often, the rest are
# in falco-rules.json.
MAX_UNDETERMINED_LISTED = 20


def _seqid(context: PostprocessContext, pid: Optional[int], evt_num: Optional[int]) -> Optional[int]:
    tree = context._process_tree
    if tree is None or pid is None:
        return None
    process = tree.get_process_for_evtid(pid, evt_num) if evt_num is not None else None
    process = process or tree.get_process(pid)
    return process.seqid if process else None


def get_falco_info(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    grouped: Dict[Tuple[str, Optional[int]], dict] = {}
    for alert in parse_log(analysis_dir / FALCO_ALERTS, lambda a: a):
        seqid = _seqid(context, alert.get("pid"), alert.get("evt_num"))
        key = (alert["rule"], seqid if seqid is not None else alert.get("pid"))
        entry = grouped.get(key)
        if entry is None:
            grouped[key] = {
                "rule": alert["rule"],
                "priority": alert.get("priority", ""),
                "source": alert.get("source", ""),
                "tags": alert.get("tags") or [],
                "output": alert.get("output", ""),
                "first_seen": alert.get("time"),
                "count": 1,
                "pid": alert.get("pid"),
                "process_seqids": [seqid] if seqid is not None else [],
            }
        else:
            entry["count"] += 1

    coverage_path = analysis_dir / FALCO_COVERAGE
    coverage = orjson.loads(coverage_path.read_bytes()) if coverage_path.exists() else {}
    rules = coverage.get("rules", [])
    undetermined = sorted((r for r in rules if r.get("undetermined")),
                          key=lambda r: -r["undetermined"])
    trace = coverage.get("trace", {})
    context.update_report({
        "falco": sorted(grouped.values(), key=lambda e: (e["first_seen"] or 0)),
        "falco_coverage": {
            "rules_evaluated": sum(1 for r in rules if r.get("status") == "ok"),
            "rules_unsupported": sum(1 for r in rules if r.get("status") == "unsupported"),
            "rules_disabled": sum(1 for r in rules if r.get("status") == "disabled"),
            "alerts_dropped": coverage.get("alerts_dropped", 0),
            "scope": coverage.get("scope"),
            "sysret": trace.get("sysret"),
            "procmon": trace.get("procmon"),
            "libmon": trace.get("libmon"),
            "undetermined": [
                {"rule": r["rule"], "count": r["undetermined"],
                 "missing": sorted(r.get("missing", {}), key=lambda f: -r["missing"][f])}
                for r in undetermined[:MAX_UNDETERMINED_LISTED]
            ],
        },
    })
