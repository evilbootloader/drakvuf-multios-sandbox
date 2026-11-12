"""The postprocessing chain: CAPE's processing over trace.log, and nothing else.

Until 2026-11-10 this was drakvuf-sandbox's chain -- split trace.log into one
log per plugin, then some twenty plugins each reading the logs it wanted and
adding to report.json. All of it is now CAPE processing modules
(`cape_plugin/`: behaviour, dropped, procdump, procmemory, network, falco,
tlskeys, capa) and CAPE signatures, run by `cape_analysis` in one pass over
the raw trace; `cape_results.json` is the result.

The old plugin modules are still in this directory. `cape_plugin` imports
what it reuses from them (the falco package, falco_analysis's profiles);
the rest is reference until it is deleted, and none of it runs.

The platform's job page reads `cape_results.json` and, for the process
panels' calls, `calls.jsonl.gz` through `calls_index.json` (since
2026-11-11; `platform/sandbox_platform/cape.py`, `calls.py`).
"""
from ..paths import IPT_DIR, IPT_ZIP, TRACE_LOG
from .cape_analysis import CAPE_RESULTS, cape_analysis
from .compress_ipt import compress_ipt
from .plugin_base import PostprocessPlugin

POSTPROCESS_PLUGINS = [
    PostprocessPlugin(
        function=cape_analysis, requires=[TRACE_LOG], generates=[CAPE_RESULTS]
    ),
    # Packaging, not analysis, and nothing CAPE has a module for: `ipt/`
    # exists only for a job that selected the `ipt` plugin, and is uploaded
    # as one archive.
    PostprocessPlugin(function=compress_ipt, requires=[IPT_DIR], generates=[IPT_ZIP]),
]
