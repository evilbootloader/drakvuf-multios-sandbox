"""Run compiled rules over a trace's events.

Rules are indexed by (source, event type), as Falco indexes them, so an event
is only tested against the rules that can match it. A definite True is an
alert; an UNKNOWN is counted against the rule as undetermined, with the
fields that made it so, which is what tells a reader that a rule did not fire
because the trace could not say -- not because nothing happened.
"""
from __future__ import annotations

import collections
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set

from .condition import UNKNOWN
from .events import Event
from .fields import FieldTable, render_output
from .rules import Rule, RuleSet


@dataclass
class RuleOutcome:
    matched: int = 0
    undetermined: int = 0
    missing: collections.Counter = field(default_factory=collections.Counter)


@dataclass
class Result:
    alerts: List[dict] = field(default_factory=list)
    dropped_alerts: int = 0
    outcomes: Dict[str, RuleOutcome] = field(default_factory=dict)
    events: int = 0


class Engine:
    def __init__(self, ruleset: RuleSet, tables: Dict[str, FieldTable], max_alerts: int) -> None:
        self.ruleset = ruleset
        self.tables = tables
        self.max_alerts = max_alerts
        self.by_type: Dict[tuple, List[Rule]] = collections.defaultdict(list)
        self.any_type: Dict[str, List[Rule]] = collections.defaultdict(list)
        for rule in ruleset.active():
            if rule.event_types is None:
                self.any_type[rule.source].append(rule)
            else:
                for t in rule.event_types:
                    self.by_type[(rule.source, t)].append(rule)

    def event_types(self, source: str) -> Optional[Set[str]]:
        """What the trace must emit for `source`: None when some rule has no
        type restriction and so needs every event."""
        if self.any_type.get(source):
            return None
        return {t for (src, t) in self.by_type if src == source}

    def run(self, events: Iterable[Event]) -> Result:
        result = Result()
        outcomes = result.outcomes
        for ev in events:
            result.events += 1
            rules = self.by_type.get((ev.source, ev.type), ())
            extra = self.any_type.get(ev.source, ())
            for rule in (*rules, *extra) if extra else rules:
                missing: Set[str] = set()
                r = rule.compiled(ev, missing)
                if r is False:
                    continue
                outcome = outcomes.get(rule.name)
                if outcome is None:
                    outcome = outcomes[rule.name] = RuleOutcome()
                if r is UNKNOWN:
                    outcome.undetermined += 1
                    outcome.missing.update(missing)
                    continue
                outcome.matched += 1
                if len(result.alerts) >= self.max_alerts:
                    result.dropped_alerts += 1
                    continue
                result.alerts.append(self._alert(rule, ev))
        return result

    def _alert(self, rule: Rule, ev: Event) -> dict:
        table = self.tables[ev.source]
        output, fields = render_output(rule.output, ev, table)
        ppid = ev.proc.ppid
        return {
            "time": ev.time,
            "rule": rule.name,
            "priority": rule.priority,
            "source": rule.source,
            "tags": rule.tags,
            "output": output,
            "output_fields": fields,
            "evt_type": ev.type,
            "evt_num": ev.num,
            "pid": ev.pid,
            "ppid": ppid if isinstance(ppid, int) else None,
            "tid": ev.tid,
        }
