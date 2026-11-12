# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
"""capa over the CAPE behaviour, as CAPE runs it at the end of BehaviorAnalysis.

Ported from CAPEv2 lib/cuckoo/common/integrations/capa.py at c7f57d04
(2026-11-09). The render helpers are upstream's, unchanged. What differs:

* no CAPE `Config`: the rules directory is an argument, and there is no
  malcat or vivisect backend -- there is no sample file here, only the trace;
* `capa_report` builds the report capa's CAPE extractor validates
  (capa/features/extractors/cape/models.py, flare-capa 9.4.0) from
  `results["behavior"]`, which on this side carries DRAKVUF's syscalls next
  to apimon/libmon's calls -- capa matches `api: NtCreateFile` against them.

What capa's model insists on, and `capa_report` therefore guarantees: a
numeric `return` (an unpaired syscall has none -- 0 stands in; capa makes no
feature of it), every call's thread listed in `threads` (capa never visits a
call on a thread it was not told about), `process_id > 0` and
`parent_id >= 0` (address assertions), and a `static.pe` stub (without one
the extractor refuses the report as an unsupported format).
"""
import collections
import logging
import re
from contextlib import suppress
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, Optional, Set, Tuple

log = logging.getLogger(__name__)

# sandboxd/data/capa-rules, the tree the old capa plugin reads too
# (PostprocessingConfig.capa.rules_directory).
DEFAULT_RULES = Path(__file__).resolve().parents[3] / "data" / "capa-rules"

# The CAPE versions capa 9.4.0 says it was tested against
# (capa/features/extractors/cape/extractor.py, TESTED_VERSIONS).
CAPE_REPORT_VERSION = "2.5-CAPE"

HAVE_FLARE_CAPA = False
try:
    import capa.capabilities.common
    import capa.features.common
    import capa.features.extractors.cape.extractor
    import capa.features.freeze.features as frzf
    import capa.loader
    import capa.render.result_document as rd
    import capa.render.utils as rutils
    import capa.rules
    import capa.rules.cache
    from capa.exceptions import EmptyReportError, UnsupportedFormatError
    from capa.features.address import DynamicCallAddress
    from capa.features.common import FORMAT_CAPE, OS_AUTO
    from capa.features.extractors.base_extractor import CallHandle
    from capa.features.extractors.cape.models import Call as CapeCall
    from capa.features.extractors.cape.models import CapeReport
    from capa.features.extractors.helpers import generate_symbols
    from pydantic import ValidationError

    HAVE_FLARE_CAPA = True
except ImportError as e:  # pragma: no cover - flare-capa is pinned in requirements.txt
    log.warning("FLARE-CAPA unavailable: %s", e)


@lru_cache(maxsize=2)
def _rules(rules_path: str):
    return capa.rules.get_rules([Path(rules_path)])


# == Render ddictionary helpers
def render_meta(doc, result):
    result["md5"] = doc.meta.sample.md5
    result["sha1"] = doc.meta.sample.sha1
    result["sha256"] = doc.meta.sample.sha256
    result["path"] = doc.meta.sample.path


def find_subrule_matches(doc) -> Set[str]:
    """
    collect the rule names that have been matched as a subrule match.
    this way we can avoid displaying entries for things that are too specific.
    """
    matches = set([])

    def rec(node):
        if not node.success:
            # there's probably a bug here for rules that do `not: match: ...`
            # but we don't have any examples of this yet
            return

        # capa's own Result tree (_SummaryDoc): a statement has children, a
        # `match:` feature names the rule it matched.
        if isinstance(node, capa.features.common.Result):
            if isinstance(node.statement, capa.features.common.MatchedRule):
                matches.add(node.statement.value)
            for child in node.children:
                rec(child)

        elif isinstance(node.node, rd.StatementNode):
            for child in node.children:
                rec(child)

        elif isinstance(node.node, rd.FeatureNode):
            if isinstance(node.node.feature, frzf.MatchFeature):
                matches.add(node.node.feature.match)

    for rule in rutils.capability_rules(doc):
        for _, node in rule.matches:
            rec(node)

    return matches


def render_capabilities(doc, result):
    """
    example::
        {'CAPABILITY': {'accept command line arguments': 'host-interaction/cli',
                'allocate thread local storage (2 matches)': 'host-interaction/process',
                'check for time delay via GetTickCount': 'anti-analysis/anti-debugging/debugger-detection',
                'check if process is running under wine': 'anti-analysis/anti-emulation/wine',
                'contain a resource (.rsrc) section': 'executable/pe/section/rsrc',
                'write file (3 matches)': 'host-interaction/file-system/write'}
        }
    """
    subrule_matches = find_subrule_matches(doc)

    result["CAPABILITY"] = {}
    for rule in rutils.capability_rules(doc):
        if rule.meta.name in subrule_matches:
            # rules that are also matched by other rules should not get rendered by default.
            # this cuts down on the amount of output while giving approx the same detail.
            # see #224
            continue

        count = len(rule.matches)
        if count == 1:
            capability = rule.meta.name
        else:
            capability = "%s (%d matches)" % (rule.meta.name, count)

        result["CAPABILITY"].setdefault(rule.meta.namespace, [])
        result["CAPABILITY"][rule.meta.namespace].append(capability)


def render_attack(doc, result):
    """
    example::
        {'ATT&CK': {'COLLECTION': ['Input Capture::Keylogging [T1056.001]'],
            'DEFENSE EVASION': ['Obfuscated Files or Information [T1027]',
                                'Virtualization/Sandbox Evasion::System Checks '
                                '[T1497.001]'],
            'DISCOVERY': ['File and Directory Discovery [T1083]',
                            'Query Registry [T1012]',
                            'System Information Discovery [T1082]'],
            'EXECUTION': ['Shared Modules [T1129]']}
        }
    """
    result["ATTCK"] = {}
    tactics = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule.meta.attack:
            continue
        for attack in rule.meta.attack:
            tactics[attack.tactic].add((attack.technique, attack.subtechnique, attack.id))

    for tactic, techniques in sorted(tactics.items()):
        inner_rows = []
        for technique, subtechnique, id in sorted(techniques):
            if subtechnique is None:
                inner_rows.append("%s %s" % (technique, id))
            else:
                inner_rows.append("%s::%s %s" % (technique, subtechnique, id))
        result["ATTCK"].setdefault(tactic.upper(), inner_rows)


def render_mbc(doc, result):
    """
    example::
        {'MBC': {'ANTI-BEHAVIORAL ANALYSIS': [
            'Debugger Detection::Timing/Delay Check '
            'GetTickCount [B0001.032]',
            'Emulator Detection [B0004]',
            'Virtual Machine Detection::Instruction '
            'Testing [B0009.029]',
            'Virtual Machine Detection [B0009]'],
        'COLLECTION': ['Keylogging::Polling [F0002.002]'],
        'CRYPTOGRAPHY': [
            'Encrypt Data::RC4 [C0027.009]',
            'Generate Pseudo-random Sequence::RC4 PRGA [C0021.004]']}
        }
    """
    result["MBC"] = {}
    objectives = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule.meta.mbc:
            continue

        for mbc in rule.meta.mbc:
            objectives[mbc.objective].add((mbc.behavior, mbc.method, mbc.id))

    for objective, behaviors in sorted(objectives.items()):
        inner_rows = []
        for behavior, method, id in sorted(behaviors):
            if method is None:
                inner_rows.append("%s [%s]" % (behavior, id))
            else:
                inner_rows.append("%s::%s [%s]" % (behavior, method, id))
        result["MBC"].setdefault(objective.upper(), inner_rows)


def render_dictionary(doc) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    render_meta(doc, result)
    render_attack(doc, result)
    render_mbc(doc, result)
    render_capabilities(doc, result)
    return result

# ===== CAPA END


def _int(value) -> Optional[int]:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        with suppress(ValueError):
            return int(value, 0)
    return None


def _arg_value(value):
    """What capa's `Argument.value` (HexInt | int | str) accepts: numbers and
    strings as they are -- a `0x...` string becomes a Number feature, anything
    else a String -- and everything else (None, a nested record) as text."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, str)):
        return value
    return "" if value is None else str(value)


def _capa_call(call: dict, tid: int) -> dict:
    ret = _int(call.get("return"))
    return {
        "thread_id": tid,
        # A `syscall` call (the syscall plugin, regmon, filetracer, procmon)
        # under its service's name: capa matches `api: NtCreateFile` either way.
        "api": call.get("api") or call.get("syscall") or "",
        "arguments": [{"name": str(a.get("name", "")), "value": _arg_value(a.get("value"))}
                      for a in call.get("arguments", ()) if isinstance(a, dict)],
        "return": ret if ret is not None else 0,
    }


# The TID key of a trace_split line, as orjson writes it: an argument value
# that contains the same text has its quotes escaped, so it cannot match.
_TID = re.compile(rb'"TID":(-?\d+)')


class _ThreadIndex:
    """Where each thread's lines are in one per-process log (behaviour's
    ParseProcessLog), so capa can read one thread's calls at a time -- and
    hold one call at a time -- rather than the report's every call at once.
    capa's own CapeExtractor validates the whole report into pydantic models
    up front: 2.3 GiB for the 8 processes of samples/job-windows (2026-11-09),
    the shape of the problem streaming.py solved for the old capa plugin."""

    def __init__(self, log):
        self.log = log
        self.offsets: Dict[int, list] = collections.defaultdict(list)
        with open(log._log_path, "rb") as f:
            offset = 0
            for n, line in enumerate(f):
                m = _TID.search(line)
                if m:
                    tid = int(m.group(1))
                    if tid >= 0:
                        self.offsets[tid].append((n, offset))
                offset += len(line)

    def calls(self, tid: int):
        """(line number, behaviour call) for each call of thread `tid`."""
        with open(self.log._log_path, "rb") as f:
            for n, offset in self.offsets.get(tid, ()):
                f.seek(offset)
                call = self.log.call_from_line(f.readline())
                if call is not None:
                    yield n, call


def capa_inputs(results: dict, pids: Optional[Iterable[int]] = None) -> Tuple[dict, dict]:
    """The report capa's CAPE extractor validates, limited to `pids` (None:
    every process), and `{(pid, ppid): _ThreadIndex}` for the processes whose
    calls stay in their log. Their report entry lists threads and no calls;
    a process whose `calls` is a plain list (a test) is copied in whole."""
    wanted = set(pids) if pids is not None else None
    processes, sources = [], {}
    for proc in results["behavior"]["processes"]:
        pid = _int(proc.get("process_id"))
        if pid is None or pid <= 0 or (wanted is not None and pid not in wanted):
            continue
        ppid = max(_int(proc.get("parent_id")) or 0, 0)
        entry = {
            "process_id": pid,
            "process_name": str(proc.get("process_name") or ""),
            "parent_id": ppid,
            "threads": [],
            "environ": {str(k): str(v) for k, v in (proc.get("environ") or {}).items()},
            "calls": [],
        }
        calls = proc["calls"]
        if hasattr(calls, "call_from_line") and getattr(calls, "_log_path", None):
            index = _ThreadIndex(calls)
            entry["threads"] = sorted(index.offsets)
            sources[(pid, ppid)] = index
        else:
            threads = set()
            for call in calls:
                tid = _int(call.get("thread_id"))
                if tid is None or tid < 0:
                    continue
                threads.add(tid)
                entry["calls"].append(_capa_call(call, tid))
            with suppress(AttributeError):
                calls.reset()
            entry["threads"] = sorted(threads)
        processes.append(entry)

    target = dict(results.get("target", {}).get("file", {}))
    # The guest's type string, not the sample's: see cape_analysis._target.
    target["type"] = (results.get("info") or {}).get("guest_type") or target.get("type", "")
    report = {
        "info": {"version": CAPE_REPORT_VERSION},
        "target": {"file": {
            "type": target.get("type", ""),
            "md5": target.get("md5", ""),
            "sha1": target.get("sha1", ""),
            "sha256": target.get("sha256", ""),
        }},
        "static": {"pe": {"imagebase": 0}},
        "behavior": {"processes": processes},
    }
    return report, sources


def capa_report(results: dict, pids: Optional[Iterable[int]] = None) -> dict:
    """capa_inputs' report with every process's calls in it: what capa's
    stock `CapeExtractor.from_report` takes. Tests and one-off use only."""
    report, sources = capa_inputs(results, pids)
    for proc in report["behavior"]["processes"]:
        index = sources.get((proc["process_id"], proc["parent_id"]))
        if index is not None:
            proc["calls"] = [_capa_call(call, tid) for tid in proc["threads"]
                             for _, call in index.calls(tid)]
    return report


if HAVE_FLARE_CAPA:
    class StreamingCapeExtractor(capa.features.extractors.cape.extractor.CapeExtractor):
        """capa's CapeExtractor, with each thread's calls read from its
        per-process log when capa asks for them (`_ThreadIndex`)."""

        def __init__(self, report, sources):
            super().__init__(report)
            self._sources = sources

        def get_calls(self, ph, th):
            source = self._sources.get((ph.address.pid, ph.address.ppid))
            if source is None:
                yield from super().get_calls(ph, th)
                return
            tid = th.address.tid
            for index, raw in source.calls(tid):
                call = CapeCall.model_validate(_capa_call(raw, tid))
                # As capa's cape/thread.py: one handle per symbol variant
                # (CreateFileW, CreateFile), the call renamed for each.
                for symbol in generate_symbols("", call.api):
                    call.api = symbol
                    yield CallHandle(address=DynamicCallAddress(thread=th.address, id=index), inner=call)

        @classmethod
        def from_inputs(cls, report: dict, sources: dict) -> "StreamingCapeExtractor":
            cr = CapeReport.model_validate(report)
            if not cr.behavior.processes:
                raise EmptyReportError("no processes to analyse")
            return cls(cr, sources)


class _SummaryDoc:
    """What the render helpers read of a capa ResultDocument -- each matched
    rule's metadata and its matches, and the sample's hashes -- over capa's
    own match results. `ResultDocument.from_capa` copies every match's whole
    evaluation tree into pydantic models: 112 251 matches on
    samples/job-windows took the pass from 610 MiB to 2.3 GiB (2026-11-10)
    to print a count per rule."""

    def __init__(self, rules, matches, extractor, results):
        hashes = extractor.get_sample_hashes()
        path = results.get("target", {}).get("file", {}).get("path") or "trace.log"
        self.meta = SimpleNamespace(sample=SimpleNamespace(
            md5=hashes.md5, sha1=hashes.sha1, sha256=hashes.sha256, path=path))
        self.rules = {
            name: SimpleNamespace(meta=self._meta(rules[name]), matches=found)
            for name, found in matches.items()
        }


    @staticmethod
    def _meta(rule):
        """The fields of rd.RuleMetadata the helpers and
        rutils.capability_rules read. Not RuleMetadata.from_capa: a subscope
        rule capa generates has no authors and fails its validation."""
        meta = rule.meta
        return SimpleNamespace(
            name=meta.get("name"),
            namespace=meta.get("namespace"),
            lib=meta.get("lib", False),
            is_subscope_rule=meta.get("capa/subscope", False),
            attack=tuple(map(rd.AttackSpec.from_str, meta.get("att&ck", []))),
            mbc=tuple(map(rd.MBCSpec.from_str, meta.get("mbc", []))),
            maec=SimpleNamespace(
                analysis_conclusion=meta.get("maec/analysis-conclusion"),
                analysis_conclusion_ov=meta.get("maec/analysis-conclusion-ov"),
                malware_family=meta.get("maec/malware-family"),
                malware_category=meta.get("maec/malware-category"),
                malware_category_ov=meta.get("maec/malware-category-ov"),
            ),
        )


def flare_capa_details(results: dict, rules_path=None, pids: Optional[Iterable[int]] = None,
                       disable_progress: bool = True) -> Dict[str, Any]:
    """capa's capabilities over `results["behavior"]`, rendered as CAPE's
    `capa_summary`. {} when capa is missing, the report is empty, or capa
    refuses it."""
    if not HAVE_FLARE_CAPA:
        return {}
    rules_path = Path(rules_path or DEFAULT_RULES)
    if not rules_path.exists():
        log.error("FLARE CAPA rules missing at %s", rules_path)
        return {}
    capa_output: Dict[str, Any] = {}
    try:
        rules = _rules(str(rules_path))
        try:
            extractor = StreamingCapeExtractor.from_inputs(*capa_inputs(results, pids))
        except ValidationError as e:
            log.warning("CAPA ValidationError %s", e)
            return {}

        capabilities = capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=disable_progress)
        doc = _SummaryDoc(rules, capabilities.matches, extractor, results)
        capa_output = render_dictionary(doc)
    except MemoryError:
        log.warning("FLARE CAPA -> MemoryError")
    except UnsupportedFormatError:
        log.error("FLARE CAPA -> UnsupportedFormatError")
    except EmptyReportError:
        log.info("FLARE CAPA -> No process data available")
    except Exception as e:
        log.exception(e)

    return capa_output