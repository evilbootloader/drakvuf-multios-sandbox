import pathlib
from typing import Any, Dict, List, NamedTuple, Optional, Protocol

from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

from ..process_tree import ProcessTree


class CapaConfigSection(BaseModel):
    rules_directory: pathlib.Path = pathlib.Path(__file__).parent.parent.absolute() / "data" / "capa-rules"
    analyze_drakvuf_log: bool = True
    # KNOWN GAP (no draft filed yet): True runs vivisect -- a disassembler and
    # x86 emulator -- over the sample's memory dumps in worker processes
    # forked from this daemon, which is root on Dom0. Nothing lowers their
    # privileges or bounds their time or memory. Upstream ships this False.
    # It is True here by the operator's decision (2026-09-18); the
    # "Postprocessing" section of sandboxd/requirements.txt has the trade.
    analyze_memdumps: bool = True
    # True here where upstream defaults to False: it is what bounds the memory
    # of the capa pass to the sample's own processes (capa_processor.py,
    # decode_json_lines). It needs the `inject` line in trace.log, which
    # DRAKVUF's own -i/-e injection always writes.
    analyze_only_malware_pids: bool = True
    worker_pool_processes: int = 2


class MemdumpConfigSection(BaseModel):
    # Upstream's values (drakrun/lib/config.py). process_dumps reads all four;
    # the port shipped this class empty, which failed on the first dump.
    # Maximum total size of collected, uncompressed dumps
    max_total_dumps_size: int = 500 * 1024 * 1024
    # Minimal accepted size of a single memory dump
    min_single_dump_size: int = 512
    # Maximal accepted size of a single memory dump
    max_single_dump_size: int = 32 * 1024 * 1024
    # Drop dumps from System process
    filter_out_system_pid: bool = True


class PostprocessingConfig(BaseSettings):
    # Prefixed, because BaseSettings reads its field names from the
    # environment case-insensitively: unprefixed, a variable called CAPA or
    # MEMDUMP in the daemon's environment would be JSON-parsed as this config,
    # and a parse failure here is not inside any plugin's exception handler.
    model_config = SettingsConfigDict(env_prefix="SANDBOXD_POSTPROCESS_")

    capa: CapaConfigSection = CapaConfigSection()
    memdump: MemdumpConfigSection = MemdumpConfigSection()
    # Replace syscall.log / sysret.log with .gz copies. On by default where
    # upstream defaults to False: a Windows syscall.log is over 1 GB
    # (trace-windows.log, 2026-09-18; 50 MB gzipped), a quarter of the 4 GiB
    # per-job result budget (platform config.py, max_job_result_bytes) on its
    # own, before sysret.log, dumps.zip and the pcap are counted.
    gzip_syscalls: bool = True


def load_postprocessing_config() -> PostprocessingConfig:
    return PostprocessingConfig()


class PostprocessContext:
    def __init__(
        self,
        analysis_dir: pathlib.Path,
        config: PostprocessingConfig,
    ) -> None:
        self.analysis_dir = analysis_dir
        self.config = config
        self._process_tree: Optional[ProcessTree] = None
        # Quick metadata fetched along with analysis status
        self.extra_metadata = {}
        # More verbose data to be placed in report.json
        self.report = {}

    @property
    def process_tree(self) -> ProcessTree:
        if self._process_tree is None:
            raise RuntimeError("Process tree not initialized")
        return self._process_tree

    @process_tree.setter
    def process_tree(self, value: ProcessTree) -> None:
        self._process_tree = value

    def update_metadata(self, metadata: Dict[str, Any]) -> None:
        self.extra_metadata.update(metadata)

    def update_report(self, report: Dict[str, Any]) -> None:
        self.report.update(report)


class PostprocessFunction(Protocol):
    def __call__(self, context: PostprocessContext) -> None: ...


class PostprocessPlugin(NamedTuple):
    function: PostprocessFunction
    # Paths that are required by plugin to run
    requires: List[str]
    # Paths that are products of processing and plugin is not run when they exist
    generates: List[str]


