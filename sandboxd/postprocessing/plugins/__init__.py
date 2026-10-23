from ..paths import (
    DUMPS_DIR, DUMPS_ZIP, EXTRACTED_DIR, EXTRACTED_ZIP, IPT_DIR, IPT_ZIP,
    TRACE_LOG,
)
from .build_process_tree import build_process_tree
from .capa_plugin.capa_processor import capa_analysis
from .compress_ipt import compress_ipt
from .falco_analysis import FALCO_ALERTS, falco_analysis
#from .generate_html_report import generate_html_report
from .generate_report import generate_report
from .generate_wireshark_key_file import generate_wireshark_key_file
from .get_http_info import get_http_info
from .get_modified_files_info import get_modified_files_info
from .get_registry_info import get_registry_info
from .get_socket_info import get_socket_info
from .get_ttps_info import get_ttps_info
from .gzip_syscalls import gzip_syscalls
from .index_logs import index_logs
#from .karton_integration import analyze_in_karton
from .plugin_base import PostprocessPlugin
from .process_dumps import process_dumps
from .process_extracted import process_extracted
from .screenshot_metadata import screenshot_metadata
from .split_drakvuf_log import split_drakvuf_log
from .yara_analysis import yara_analysis
from .get_yara_info import get_yara_info
from .get_falco_info import get_falco_info

POSTPROCESS_PLUGINS = [
    PostprocessPlugin(
        function=split_drakvuf_log, requires=[TRACE_LOG], generates=[]
    ),
    PostprocessPlugin(
        function=generate_wireshark_key_file,
        requires=["tlsmon.log"],
        generates=["wireshark_key_file.txt"],
    ),
    PostprocessPlugin(
        function=build_process_tree,
        requires=["procmon.log"],
        generates=[],  # Always regenerate
    ),
    PostprocessPlugin(
        function=yara_analysis,
        requires=[],
        generates=["yara.json"],
    ),
    PostprocessPlugin(
        function=capa_analysis,
        requires=[
            "process_tree.json",
            "inject.log",
        ],
        generates=["ttps.json"],
    ),
    # Before capa_analysis, not after it as upstream orders them: with
    # analyze_memdumps on, capa's static pass reads DUMPS_ZIP, which this is
    # what produces. Upstream never hit that because it ships the option off.
    PostprocessPlugin(
        function=process_dumps,
        requires=[DUMPS_DIR, "memdump.log", "process_tree.json"],
        generates=[DUMPS_ZIP],
    ),
    # inject.log is the `"Plugin": "inject"` line of the trace, split out
    # above -- DRAKVUF's own -i/-e launch, whose InjectedPid is the sample's
    # process. preconfig.log is the injector's writefile step and names no
    # process (INJECTED_PID:0).
    # Same DIR/ZIP contract as process_dumps above, and placed beside it for
    # the same reason: `stages._collect` uploads the directory only while no
    # archive exists next to it, so whichever of the two runs decides what is
    # uploaded. Gated on the directory alone -- `fileextractor.log` is
    # attribution, and a run that produced files but no parsable log must
    # still pack the files (process_extracted's docstring says why).
    PostprocessPlugin(
        function=process_extracted,
        requires=[EXTRACTED_DIR, "process_tree.json"],
        generates=[EXTRACTED_ZIP],
    ),
#    PostprocessPlugin(
#        function=screenshot_metadata,
#        requires=["screenshots.json"],
#        generates=[],
#    ),
    # Gated on the directory, which exists only for a job that selected the
    # `ipt` plugin (`stages._trace` creates it, `argv_trace` passes it as
    # `--ipt-dir`); every other job skips this.
    PostprocessPlugin(function=compress_ipt, requires=[IPT_DIR], generates=[IPT_ZIP]),
    # Before gzip_syscalls, which replaces the syscall and sysret logs this
    # reads, and after build_process_tree -- though it does not need the tree:
    # a job without procmon still has a sample scope (falco/events.py,
    # sample_scope). Requires nothing for the same reason get_http_info
    # requires no log: what it reads is per-OS (falco_analysis.FALCO_PROFILES).
    PostprocessPlugin(function=falco_analysis, requires=[], generates=[FALCO_ALERTS]),
    PostprocessPlugin(
        function=gzip_syscalls,
        requires=["syscall.log"],
        generates=["syscall.log.gz", "sysret.log.gz"],
    ),
    # **`apimon.log` is deliberately NOT required.** The log this reads is
    # per-OS (apimon on Windows, libmon on Linux -- get_http_info.HTTP_SOURCES),
    # and `requires` is one static list for every guest, so naming either one
    # here would skip the plugin on the guests that write the other. The
    # function checks for its own log and reports an empty result when absent.
    PostprocessPlugin(
        function=get_http_info,
        requires=["process_tree.json"],
        generates=[],
    ),
    PostprocessPlugin(
        function=get_modified_files_info,
        requires=["process_tree.json", "filetracer.log"],
        generates=[],
    ),
    # The log is per-OS -- socketmon on Windows, unixsocketmon on Linux
    # (get_socket_info.SOCKET_SOURCES) -- so it is checked there, for
    # get_http_info's reason.
    PostprocessPlugin(
        function=get_socket_info,
        requires=["process_tree.json"],
        generates=[],
    ),
    PostprocessPlugin(
        function=get_registry_info,
        requires=["process_tree.json", "regmon.log"],
        generates=[],
    ),
    PostprocessPlugin(
        function=get_ttps_info,
        requires=["process_tree.json", "ttps.json"],
        generates=[],
    ),
    PostprocessPlugin(
        function=get_yara_info,
        requires=["process_tree.json","yara.json"],
        generates=[],
    ),
    # Not gated on process_tree.json: alerts from a job without procmon are
    # still alerts, reported by PID with no process to link to.
    PostprocessPlugin(function=get_falco_info, requires=[FALCO_ALERTS], generates=[]),
    # After every plugin that calls update_report and before index_logs,
    # which adds nothing to it. Always regenerated: the report is a function
    # of the files above it, and a stale one would describe a different run.
    PostprocessPlugin(
        function=generate_report,
        requires=[],
        generates=[],
    ),
    PostprocessPlugin(
        function=index_logs, requires=["process_tree.json"], generates=["log_index"]
    ),
]
