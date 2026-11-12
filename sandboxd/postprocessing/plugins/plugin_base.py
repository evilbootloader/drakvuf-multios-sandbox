import pathlib
from typing import Any, Dict, List, Literal, NamedTuple, Optional, Protocol

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from ..process_tree import ProcessTree
from ...guests import TargetOs


class CapaConfigSection(BaseModel):
    rules_directory: pathlib.Path = pathlib.Path(__file__).parent.parent.parent.absolute() / "data" / "capa-rules"
    analyze_drakvuf_log: bool = True
    # KNOWN GAP (no draft filed yet): True runs vivisect -- a disassembler and
    # x86 emulator -- over the sample's memory dumps in worker processes
    # forked from this daemon, which is root on Dom0. Nothing lowers their
    # privileges or bounds their time or memory. Upstream ships this False.
    # It is True here by the operator's decision (2026-09-18); the
    # "Postprocessing" section of sandboxd/requirements.txt has the trade.
    analyze_memdumps: bool = False
    # True here where upstream defaults to False: it is what bounds the memory
    # of the capa pass to the sample's own processes (capa_plugin/streaming.py
    # drops the others at its index pass). It needs the `inject` line in
    # trace.log, which DRAKVUF's own -i/-e injection always writes.
    analyze_only_malware_pids: bool = True
    worker_pool_processes: int = 2

class YaraConfigSection(BaseModel):
    rules_directory: pathlib.Path = pathlib.Path(__file__).parent.parent.parent.absolute() / "data" / "protections-artifacts" / "yara" / "rules"


_DATA = pathlib.Path(__file__).parent.parent.parent.absolute() / "data"


def _procmon_envs() -> List[str]:
    from ...guests import PROCMON_ENVS_LIST
    try:
        return [n.strip() for n in PROCMON_ENVS_LIST.read_text().splitlines() if n.strip()]
    except OSError:
        return ["LD_PRELOAD", "PWD", "OLDPWD"]


class FalcoConfigSection(BaseModel):
    """Falco rules over the Linux trace (`falco_analysis`).

    The vendored files are falcosecurity/rules at the submodule's pinned tag;
    stable and incubating only, the sandbox file's rules being both noisier and
    largely about containers. The local directory is read after them, in name
    order, so it can append to and override their lists, macros and rules.
    """
    enabled: bool = True
    rules_files: List[pathlib.Path] = [
        _DATA / "falco-rules" / "rules" / "falco_rules.yaml",
        _DATA / "falco-rules" / "rules" / "falco-incubating_rules.yaml",
    ]
    local_rules_directory: pathlib.Path = _DATA / "falco-rules-local"
    # "sample": the injected process and its descendants, as capa's
    # analyze_only_malware_pids. "all": every process, for tuning the
    # overrides against what an idle guest does on its own.
    scope: Literal["sample", "all"] = "sample"
    # falco.json holds at most this many alerts; the coverage file still
    # counts every match.
    max_alerts: int = 10000
    # The variables procmon prints: the list `argv_trace` passes as
    # --procmon-envs-list. `proc.env` is unknown outside them.
    procmon_env_filter: List[str] = Field(default_factory=_procmon_envs)


class CapeConfigSection(BaseModel):
    """CAPE's processing over trace.log (`cape_analysis`).

    The whole chain since 2026-11-10 (plugins/__init__.py). A section is set
    as JSON, as every section here is read:
    `SANDBOXD_POSTPROCESS_CAPE='{"scope": "all"}'`.
    """
    enabled: bool = True
    # "sample": the injected process and its descendants, which is what
    # CAPE's monitor follows and its signatures assume -- and a process one
    # of them made run code (a remote thread, a context set and resumed, a
    # ptrace register write; trace_split.follow_transfers), with what that
    # one starts afterwards. "all": every process on the guest.
    scope: Literal["sample", "all"] = "sample"
    # Windows syscalls with PreviousMode Kernel: a driver's own calls, made
    # in whatever process was current. Never the sample's; off.
    kernel_syscalls: bool = False
    # Calls per process, CAPE's analysis_call_limit; 0 is no limit.
    call_limit: int = 0
    # capa over the behaviour (syscalls included), as CAPE's capa_summary.
    # Always on the sample's processes only, whatever `scope` says.
    capa: bool = True
    capa_rules: pathlib.Path = _DATA / "capa-rules"
    # CAPE's behavioural signatures over `results` (RunSignatures). The
    # directory is a checkout of CAPESandbox/community: its
    # modules/signatures and the data/ files they read. Absent, no signature
    # runs and the log says so.
    # Replace trace.log with trace.log.gz once it has been processed. The
    # raw trace is the only copy of the calls now that nothing splits it,
    # `stages._collect` never uploads a file named trace.log, and one left
    # behind keeps the job directory on Dom0 (`_remove_results`).
    compress_trace: bool = True
    signatures: bool = True
    # Signatures not run, by `name`. The default is what DRAKVUF can never
    # feed -- capemon's own anomaly events -- and capemon's two readers of
    # the `syscall` calls syscall_origin logs, which tell a technique by
    # address range or a seen allocation; all/evasive_syscalls.py reads the
    # technique syscall_origin found. (`direct_syscall` here would be that
    # file's own signature.)
    signatures_disabled: List[str] = ["antisandbox_unhook", "direct_syscall_evasion",
                                      "unbacked_syscall_execution"]
    community: pathlib.Path = _DATA / "cape-community"
    # The behaviour's network_map (cape_plugin/network_map.py): domains and
    # networks it leaves out, and ones it keeps whatever the exclusions say.
    # A domain is a glob that also covers every name under it; a network a
    # CIDR. None is network_map.py's default list -- the guest's own
    # libraries' traffic, multicast, link-local -- and [] excludes nothing.
    # What is left out is counted in network_map.filtered.
    network_exclude_domains: Optional[List[str]] = None
    network_exclude_networks: Optional[List[str]] = None
    network_include_domains: List[str] = []
    network_include_networks: List[str] = []


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


class ExtractedConfigSection(BaseModel):
    """Bounds on `process_extracted`, in the shape MemdumpConfigSection has.

    Upstream has no equivalent -- it never passes `-D` and has no plugin for
    the directory -- so these are this project's, not carried across. They
    exist because an extracted file is chosen by the SAMPLE: its size is
    attacker-controlled, and the per-job result budget (platform config.py,
    `max_job_result_bytes`) is 8 GiB for everything a job uploads (4 until
    2026-11-03).
    """

    # Generous relative to a memory dump's 32 MiB: a file the sample wrote is
    # the artifact most likely to be wanted whole, and unlike a dump there is
    # no second copy of it anywhere. DRAKVUF's Linux fileextractor stops
    # extracting a file at the same 128 MiB (fileextractor/linux.h,
    # MAX_FILE_BYTES), so the two agree on what a file may be.
    max_single_extracted_size: int = 128 * 1024 * 1024
    # 3.5 GiB since 2026-11-03 (512 MiB before), the operator's decision when
    # DRAKVUF's per-trace extraction cap went to 4 GiB. Everything under this
    # is packed into ONE artifact, extracted.zip, and the download path
    # refuses an entry over 4 GiB minus 16 bytes (platform packaging.py,
    # _MAX_ENTRY), so this stays half a gigabyte under that: incompressible
    # files make the archive slightly larger than its contents, never smaller.
    max_total_extracted_size: int = 3584 * 1024 * 1024


class PostprocessingConfig(BaseSettings):
    # Prefixed, because BaseSettings reads its field names from the
    # environment case-insensitively: unprefixed, a variable called CAPA or
    # MEMDUMP in the daemon's environment would be JSON-parsed as this config,
    # and a parse failure here is not inside any plugin's exception handler.
    model_config = SettingsConfigDict(env_prefix="SANDBOXD_POSTPROCESS_")

    capa: CapaConfigSection = CapaConfigSection()
    memdump: MemdumpConfigSection = MemdumpConfigSection()
    extracted: ExtractedConfigSection = ExtractedConfigSection()
    yara: YaraConfigSection = YaraConfigSection()
    falco: FalcoConfigSection = FalcoConfigSection()
    cape: CapeConfigSection = CapeConfigSection()
    # Replace syscall.log / sysret.log / apimon.log with .gz copies
    # (gzip_syscalls.GZIPPED_LOGS). On by default where upstream defaults to
    # False: a Windows syscall.log is over 1 GB (trace-windows.log,
    # 2026-09-18; 50 MB gzipped), an eighth of the 8 GiB per-job result
    # budget (platform config.py, max_job_result_bytes) on its own, before
    # sysret.log, dumps.zip and the pcap are counted -- and that was a 180 s
    # trace. The 20-minute one of 2026-11-02 left 2.9 GB of syscall.log and
    # 3.9 GB of apimon.log, which is why apimon joined the list.
    gzip_syscalls: bool = True


def load_postprocessing_config() -> PostprocessingConfig:
    return PostprocessingConfig()


class PostprocessContext:
    def __init__(
        self,
        analysis_dir: pathlib.Path,
        config: PostprocessingConfig,
        target_os: TargetOs,
        vlan: Optional[int] = None,
    ) -> None:
        self.analysis_dir = analysis_dir
        self.config = config
        # The clone's VLAN, which names its /24 (`egress.vlan_subnet`): what
        # the Falco rules count as the local network. None when postprocessing
        # runs outside a job, as in the tests.
        self.vlan = vlan
        # Here and not on `config`: that is a BaseSettings of daemon-wide
        # knobs, and this is the job's. It picks the procmon events that
        # build the process tree (process_tree.METHOD_PARSERS).
        self.target_os = target_os
        self._process_tree: Optional[ProcessTree] = None
        # Quick metadata fetched along with analysis status
        self.extra_metadata = {}
        # More verbose data to be placed in report.json
        self.report = {}

    def record_failure(self, plugin: str, exc: BaseException) -> None:
        """A plugin that raised, for report.json (`generate_report` folds
        `report` in). A job without `ttps.json` must say why where a reader
        looks, not only in a log line on Dom0 -- and under the child's memory
        limit (sandboxd/postprocessing/__main__.py) the usual reason is a
        `MemoryError`, which is a fact about the trace's size worth keeping."""
        self.report.setdefault("postprocessing_failures", []).append(
            {"plugin": plugin,
             "error": f"{type(exc).__name__}: {str(exc)[:300]}"})

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


