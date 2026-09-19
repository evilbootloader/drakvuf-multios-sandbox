import logging
from pathlib import Path
from typing import Dict, Optional

import orjson

from ..process_tree import ProcessTree
from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)

# Bumped when a key changes meaning or shape. The platform's reader
# (platform/sandbox_platform/report.py) is lenient about keys it does not
# know, so adding one is not a bump; renaming or retyping one is.
REPORT_SCHEMA_VERSION = 1


def get_inject_info(analysis_dir: Path, process_tree: Optional[ProcessTree]) -> Dict:
    inject_file = analysis_dir / "inject.log"
    if not inject_file.exists():
        return {}
    with inject_file.open("r") as f:
        inject = orjson.loads(f.read().strip())
    status = inject.get("Status")
    if status == "Success":
        pid = inject.get("InjectedPid")
        if pid and process_tree:
            # Upstream asked get_process_for_evtid(pid, 0), which only finds
            # a process whose evtid_from is 0 -- one procmon enumerated at
            # start, never one it saw created. The injected process is
            # exactly the latter, so `startup.process` was always null.
            process = process_tree.get_process(pid)
        else:
            process = None
        inject_info = {
            "status": inject["Status"],
            "process_name": inject.get("ProcessName"),
            "arguments": inject.get("Arguments"),
            "pid": pid,
            "process": process.seqid if process else None,
        }
    elif status == "Error":
        inject_info = {
            "status": inject["Status"],
            "error_code": inject.get("ErrorCode"),
            "error": inject.get("Error"),
        }
    else:
        logger.warning("Unknown status found in inject.log")
        inject_info = {}

    return inject_info


def generate_report(context: PostprocessContext) -> None:
    """Write report.json: what the other plugins put in `context.report`.

    Upstream's version also carried an `info` block from its analysis
    metadata store. There is no such store here -- the job row on the platform
    holds the sample, the options and the timings -- so the report is the
    observations only, and the platform joins them to the job it already has.
    Without this plugin every `update_report` call above is thrown away.
    """
    analysis_dir = context.analysis_dir
    process_tree = context._process_tree
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "startup": get_inject_info(analysis_dir, process_tree),
        **context.report,
        # What process_dumps and screenshot_metadata put aside for upstream's
        # metadata store; folded in here for the same reason `info` is gone.
        "metadata": context.extra_metadata,
    }

    with (analysis_dir / "report.json").open("wb") as f:
        f.write(orjson.dumps(report, option=orjson.OPT_INDENT_2))