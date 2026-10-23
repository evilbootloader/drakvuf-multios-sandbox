"""Falco's rules over the Linux trace: writes falco.json and falco-rules.json.

`falco.json` is one alert per line. `falco-rules.json` is the coverage: every
rule loaded, whether it ran, how often it matched, and how often it could not
be decided and for want of which fields -- without it, "no alerts" could not
be told apart from "the trace could not answer".

Runs before `gzip_syscalls`, which replaces syscall.log and sysret.log, and
after `build_process_tree`; it does not need the tree, because a job without
procmon still has a sample scope from the PPIDs the syscall records carry
(`falco.events.sample_scope`).

**A guest is a row in FALCO_PROFILES, not a branch.** Windows has none:
Falco's rules are written against Linux syscalls.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import orjson

from ...egress import vlan_subnet
from ...guests import TargetOs
from ..falco import events as falco_events
from ..falco import linux as falco_linux
from ..falco.engine import Engine
from ..falco.fields import FieldTable
from ..falco.rules import RuleSet
from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)

FALCO_ALERTS = "falco.json"
FALCO_COVERAGE = "falco-rules.json"


@dataclass(frozen=True)
class FalcoProfile:
    # Rule sources this guest's trace can feed: `syscall` from procmon,
    # syscalls, sysret and filetracer; `libmon` from libmon's calls.
    sources: Tuple[str, ...]
    users: Dict[int, str]


FALCO_PROFILES: Dict[TargetOs, FalcoProfile] = {
    # uid 1000 is the golden image's desktop account: `UserId` 1000 with
    # `PWD=/home/user` throughout the 2026-10-23 benchmark trace.
    TargetOs.UBUNTU: FalcoProfile(("syscall", "libmon"),
                                  {**falco_linux.DEBIAN_BASE_USERS, 1000: "user"}),
    # libmon has no Android path yet (`_ANDROID_PLUGINS` in guests.py).
    TargetOs.ANDROID: FalcoProfile(("syscall",), {0: "root"}),
}


def _lab_network_overrides(ruleset: RuleSet, vlan: Optional[int]) -> None:
    """Make the clone's own /24 the only private network that is local.

    The vendored rules treat all of RFC 1918 as local (`rfc_1918_addresses`).
    A clone has exactly one network of its own, and egress denies the rest of
    the analysis range (network-setup.sh), so a sample reaching for any other
    private address is reaching outside -- which is what `outbound` and
    `network_local_subnet` exist to notice.
    """
    if vlan is None:
        return
    subnet = vlan_subnet(vlan)
    ruleset._apply({"list": "sandbox_lab_network", "items": [f'"{subnet}"']}, "sandboxd")
    ruleset._apply({"list": "rfc_1918_addresses", "items": ["sandbox_lab_network"],
                    "override": {"items": "replace"}}, "sandboxd")


def falco_analysis(context: PostprocessContext) -> None:
    config = context.config.falco
    profile = FALCO_PROFILES.get(context.target_os)
    if not config.enabled or profile is None:
        return
    analysis_dir = context.analysis_dir
    started = time.monotonic()

    ruleset = RuleSet()
    for path in config.rules_files:
        ruleset.load_file(path)
    local = config.local_rules_directory
    if local.is_dir():
        for path in sorted(local.glob("*.yaml")):
            ruleset.load_file(path)
    _lab_network_overrides(ruleset, context.vlan)

    tables = {src: FieldTable(src, profile.users, config.procmon_env_filter)
              for src in profile.sources}
    ruleset.compile(tables)
    engine = Engine(ruleset, tables, config.max_alerts)

    scope = None
    if config.scope == "sample":
        scope = falco_events.sample_scope(analysis_dir)
    trace = falco_events.Trace(
        analysis_dir,
        falco_events.TraceConfig(env_filter=frozenset(config.procmon_env_filter),
                                 users=profile.users),
        syscall_types=engine.event_types("syscall"),
        libmon_types=engine.event_types("libmon") if "libmon" in tables else set(),
        scope=scope,
    )
    result = engine.run(trace)

    with (analysis_dir / FALCO_ALERTS).open("wb") as f:
        for alert in result.alerts:
            f.write(orjson.dumps(alert))
            f.write(b"\n")

    coverage = {
        "scope": config.scope,
        "scope_pids": sorted(scope) if scope is not None else None,
        "lab_network": vlan_subnet(context.vlan) if context.vlan is not None else None,
        "seconds": round(time.monotonic() - started, 3),
        "trace": {
            "sysret": trace.stats.sysret,
            "procmon": trace.stats.procmon,
            "libmon": trace.stats.libmon,
            "records": trace.stats.records,
            "events": trace.stats.events,
            "results_unknown": trace.stats.unpaired,
            "results_from_libmon": trace.stats.results_from_libmon,
        },
        "alerts_written": len(result.alerts),
        "alerts_dropped": result.dropped_alerts,
        "warnings": ruleset.warnings,
        "rules": [
            {
                "rule": rule.name,
                "priority": rule.priority,
                "source": rule.source,
                "origin": rule.origin,
                "tags": rule.tags,
                "status": rule.status,
                "reason": rule.reason,
                "matched": result.outcomes[rule.name].matched if rule.name in result.outcomes else 0,
                "undetermined": (result.outcomes[rule.name].undetermined
                                 if rule.name in result.outcomes else 0),
                "missing": (dict(result.outcomes[rule.name].missing.most_common(8))
                            if rule.name in result.outcomes else {}),
            }
            for rule in ruleset.rules.values()
        ],
    }
    (analysis_dir / FALCO_COVERAGE).write_bytes(orjson.dumps(coverage, option=orjson.OPT_INDENT_2))
    logger.info("falco: %d events, %d alerts, %d rules active, %.1fs",
                result.events, sum(o.matched for o in result.outcomes.values()),
                len(ruleset.active()), coverage["seconds"])
