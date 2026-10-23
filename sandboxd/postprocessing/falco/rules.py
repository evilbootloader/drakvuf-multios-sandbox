"""Load Falco rule files: lists, macros and rules, with append and override.

Items are applied in file order, as Falco applies them, and compiled only once
everything is loaded, because a macro may name a list or macro defined after
it. A rule this evaluator cannot run -- a parse error, a field without an
extractor, a source no plugin feeds -- is kept and marked `unsupported` with
the reason, so the coverage report can say what was not evaluated instead of
the rule vanishing.
"""
from __future__ import annotations

import logging
import pathlib
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, Iterable, List, Optional, Set

import yaml

from .condition import (Compiled, Compiler, ConditionError, Extractor, Node,
                        event_types, fields_used, parse)

logger = logging.getLogger(__name__)

PRIORITIES = ("EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE",
              "INFORMATIONAL", "DEBUG")
_PRIORITY_ALIASES = {"INFO": "INFORMATIONAL", "WARN": "WARNING"}


def normalise_priority(p: object) -> str:
    s = str(p or "WARNING").upper()
    s = _PRIORITY_ALIASES.get(s, s)
    return s if s in PRIORITIES else "WARNING"


@dataclass
class Rule:
    name: str
    condition: str
    output: str = ""
    desc: str = ""
    priority: str = "WARNING"
    tags: List[str] = field(default_factory=list)
    source: str = "syscall"
    enabled: bool = True
    origin: str = ""
    exceptions: List[dict] = field(default_factory=list)

    # Filled by RuleSet.compile
    status: str = "pending"          # ok | disabled | unsupported
    reason: str = ""
    compiled: Optional[Compiled] = None
    event_types: Optional[FrozenSet[str]] = None
    fields: Set[str] = field(default_factory=set)


@dataclass
class RuleSet:
    rules: Dict[str, Rule] = field(default_factory=dict)
    lists: Dict[str, list] = field(default_factory=dict)
    macros: Dict[str, str] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    # -- loading ----------------------------------------------------------

    def load_file(self, path: pathlib.Path) -> None:
        with path.open("r", encoding="utf-8") as f:
            docs = yaml.safe_load(f) or []
        if not isinstance(docs, list):
            raise ValueError(f"{path}: a rules file is a YAML list")
        for item in docs:
            if not isinstance(item, dict):
                self.warnings.append(f"{path}: skipped a non-mapping item")
                continue
            self._apply(item, path.name)

    def _apply(self, item: dict, origin: str) -> None:
        override = item.get("override") or {}
        append = bool(item.get("append"))
        if "list" in item:
            name = item["list"]
            items = list(item.get("items") or [])
            mode = override.get("items")
            if (append or mode == "append") and name in self.lists:
                self.lists[name] = self.lists[name] + items
            elif mode == "append" or append:
                self.warnings.append(f"{origin}: append to undefined list {name}")
            else:
                self.lists[name] = items
        elif "macro" in item:
            name = item["macro"]
            cond = str(item.get("condition", ""))
            mode = override.get("condition")
            if (append or mode == "append") and name in self.macros:
                self.macros[name] = f"{self.macros[name]} {cond}"
            elif mode == "append" or append:
                self.warnings.append(f"{origin}: append to undefined macro {name}")
            else:
                self.macros[name] = cond
        elif "rule" in item:
            self._apply_rule(item, origin, override, append)
        elif "required_engine_version" in item or "required_plugin_versions" in item:
            pass  # recorded by Falco, meaningless here
        else:
            self.warnings.append(f"{origin}: unknown item {sorted(item)}")

    def _apply_rule(self, item: dict, origin: str, override: dict, append: bool) -> None:
        name = item["rule"]
        existing = self.rules.get(name)
        if existing is not None and (append or override or "condition" not in item):
            for key in ("condition", "output", "desc", "priority", "tags",
                        "exceptions", "enabled", "source"):
                if key not in item:
                    continue
                mode = override.get(key, "append" if append else "replace")
                value = item[key]
                if key == "condition" and mode == "append":
                    existing.condition = f"{existing.condition} {value}"
                elif key in ("exceptions", "tags") and mode == "append":
                    getattr(existing, key).extend(value or [])
                elif key == "output" and mode == "append":
                    existing.output = f"{existing.output} {value}"
                elif key == "priority":
                    existing.priority = normalise_priority(value)
                elif key == "enabled":
                    existing.enabled = bool(value)
                else:
                    setattr(existing, key, value)
            return
        if existing is None and "condition" not in item:
            self.warnings.append(f"{origin}: rule {name!r} changes a rule that does not exist")
            return
        self.rules[name] = Rule(
            name=name,
            condition=str(item.get("condition", "")),
            output=str(item.get("output", "")).strip(),
            desc=str(item.get("desc", "")).strip(),
            priority=normalise_priority(item.get("priority")),
            tags=[str(t) for t in (item.get("tags") or [])],
            source=str(item.get("source", "syscall")),
            enabled=bool(item.get("enabled", True)),
            origin=origin,
            exceptions=list(item.get("exceptions") or []),
        )

    # -- compiling --------------------------------------------------------

    def compile(self, sources: Dict[str, Callable[[str, Optional[str]], Extractor]]) -> None:
        """Compile every rule against the field resolvers of `sources`.

        `sources` maps a rule source (`syscall`, `libmon`) to its resolver; a
        rule whose source is not there is unsupported for this trace.
        """
        macro_ast: Dict[str, Node] = {}
        macro_errors: Dict[str, str] = {}
        for name, text in self.macros.items():
            try:
                macro_ast[name] = parse(text, self.lists)
            except ConditionError as exc:
                macro_errors[name] = str(exc)
        compilers = {src: Compiler(macro_ast, resolve) for src, resolve in sources.items()}
        for rule in self.rules.values():
            if not rule.enabled:
                rule.status, rule.reason = "disabled", "disabled in the rules files"
                continue
            if rule.source not in compilers:
                rule.status = "unsupported"
                rule.reason = f"source {rule.source!r} is not available"
                continue
            try:
                text = rule.condition
                if rule.exceptions:
                    text = f"({text}) and not ({exceptions_condition(rule.exceptions)})"
                ast = parse(text, self.lists)
                rule.fields = fields_used(_checked(ast, macro_ast, macro_errors), macro_ast)
                rule.event_types = event_types(ast, macro_ast)
                rule.compiled = compilers[rule.source].compile(ast)
                rule.status, rule.reason = "ok", ""
            except ConditionError as exc:
                rule.status, rule.reason = "unsupported", str(exc)
            except KeyError as exc:
                rule.status, rule.reason = "unsupported", f"undefined macro {exc}"

    def active(self) -> List[Rule]:
        return [r for r in self.rules.values() if r.status == "ok"]


def _checked(ast: Node, macro_ast: Dict[str, Node], macro_errors: Dict[str, str]) -> Node:
    """Raise the parse error of a macro the rule uses, rather than a KeyError."""
    from .condition import And, MacroRef, Not, Or

    def walk(node, depth=0):
        if depth > 64:
            raise ConditionError("macros nest too deeply")
        if isinstance(node, MacroRef):
            if node.name in macro_errors:
                raise ConditionError(f"macro {node.name}: {macro_errors[node.name]}")
            if node.name not in macro_ast:
                raise ConditionError(f"undefined macro {node.name!r}")
            walk(macro_ast[node.name], depth + 1)
        elif isinstance(node, Not):
            walk(node.item, depth + 1)
        elif isinstance(node, (And, Or)):
            for i in node.items:
                walk(i, depth + 1)
    walk(ast)
    return ast


def _quote(v: object) -> str:
    s = str(v)
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def exceptions_condition(exceptions: Iterable[dict]) -> str:
    """Falco's `exceptions:` as a condition that is true for an excepted event.

    `fields` is a list (each value is a tuple, `comps` defaults to `=`) or a
    single field (each value is one value, `comps` defaults to `in` over all
    of them).
    """
    parts = []
    for exc in exceptions:
        fields = exc.get("fields")
        comps = exc.get("comps")
        values = exc.get("values") or []
        if not fields or not values:
            continue
        if isinstance(fields, str):
            comp = comps if isinstance(comps, str) else "in"
            items = ", ".join(_quote(v) for v in values)
            parts.append(f"{fields} {comp} ({items})")
            continue
        comps = comps if isinstance(comps, list) else [comps or "="] * len(fields)
        for row in values:
            checks = []
            for f, c, v in zip(fields, comps, row):
                if c in ("in", "intersects", "pmatch"):
                    seq = v if isinstance(v, list) else [v]
                    checks.append(f"{f} {c} ({', '.join(_quote(x) for x in seq)})")
                else:
                    checks.append(f"{f} {c} {_quote(v)}")
            parts.append("(" + " and ".join(checks) + ")")
    return " or ".join(parts) if parts else "evt.num < 0"


def load(paths: Iterable[pathlib.Path]) -> RuleSet:
    rs = RuleSet()
    for p in paths:
        rs.load_file(p)
    return rs