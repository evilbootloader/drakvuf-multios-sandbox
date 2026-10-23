import functools
import itertools
import logging
import multiprocessing
import re
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, Iterable, Iterator, List, Optional, TextIO, Tuple, Union

import capa.features.address as ca
import orjson
from capa.capabilities.common import find_capabilities
from capa.engine import MatchResults as EngineMatchResults
from capa.features.common import Result
from capa.features.extractors.base_extractor import ProcessFilter
from capa.features.extractors.drakvuf.extractor import DrakvufExtractor
from capa.helpers import get_auto_format
from capa.loader import get_extractor
from capa.main import (
    BACKEND_DOTNET,
    BACKEND_VIV,
    FORMAT_DOTNET,
    OS_WINDOWS,
    UnsupportedFormatError,
)
from capa.render.result_document import MatchResults as ResultDocumentMatchResults
from capa.rules import Rule, RuleSet, get_rules, get_rules_and_dependencies

from ...paths import DUMPS_DIR, DUMPS_ZIP
from ...drakvuf_records import DRAKVUF_STRING_ARG, unescape_drakvuf
from ..plugin_base import PostprocessContext

logger = logging.getLogger(__name__)


def check_rules_directory_exist(path: Path) -> bool:
    # this method checks whether a non-empty directory exists
    return path.is_dir() and any(path.iterdir())


def find_process_in_pstree(pstree: List, pid: int) -> Dict:
    """This methods searches for a process in the generated process_tree.json file"""

    def search(subtree: List) -> Optional[Dict]:
        for process in subtree:
            if process["pid"] == pid:
                return process
            found = search(process["children"])
            if found:
                return found
        return None

    # Only the top level may fail: upstream raised from inside the recursion,
    # so a PID under any root but the first was reported as missing
    # (trace-windows.log, 2026-09-18: the injected Notepad.exe sits at depth 4
    # under the fifth root).
    process = search(pstree)
    if process is None:
        raise RuntimeError(f"PID {pid} not found in the process tree")
    return process


def get_all_child_processes(process: Dict) -> Iterator[int]:
    """This method returns all of the child processes pids (recursively), including their parent's"""
    for p in process["children"]:
        yield from get_all_child_processes(p)

    # yield current node's pid
    yield process["pid"]


def filter_rules(rules: RuleSet, filter_function=None) -> RuleSet:
    """this method filters the given rules folder following arbitrary logic (specified by filter_function)"""
    rules = list(rules.rules.values())
    reduced_rules = list(filter(filter_function, rules))

    # filter the given rules folder using the specified boolean function
    filtered_rules = set()
    for rule in reduced_rules:
        filtered_rules.update(get_rules_and_dependencies(rules, rule.name))

    # generate the new ruleset, and return it
    return RuleSet(list(filtered_rules))


def get_malware_processes(inject_path: Path, pstree_path: Path) -> List[int]:
    # this method gets all the pids in the Drakvuf report that are associated with malware
    with inject_path.open("r") as f:
        # we use the injected processes log to get the malware process' parent pid
        injected_processes = [orjson.loads(line) for line in f]

    with pstree_path.open("r") as f:
        # we use the process tree to get all of the malware process' child processes
        pstree = orjson.loads(f.read())

    # make sure that inject.log has exactly one entry. Upstream tested
    # `if len(...)`, which raised on the one entry every trace has; it never
    # noticed because its analyze_only_malware_pids defaults to False.
    if not injected_processes:
        raise ValueError("inject.log is empty")
    if len(injected_processes) > 1:
        raise ValueError("inject.log has more than one entry")

    malware_injection_log = injected_processes[0]

    # get the parent malware process' pid and process name
    malware_pid: int = malware_injection_log["InjectedPid"]

    # find the malware process' sub-tree in the overall process tree
    malware_process: Dict = find_process_in_pstree(pstree, malware_pid)

    # return a list of all spawned malware processes (does not include process injection)
    return list(get_all_child_processes(malware_process))


def get_drakvuf_feature_extractor(
    calls: Iterator[Dict],
) -> DrakvufExtractor:
    """Wrapper routing for initializing the Drakvuf feature extractor"""
    return DrakvufExtractor.from_report(calls)


def decode_json_lines(
    fd: TextIO, pids: Optional[Iterable[int]] = None
) -> Iterator[Dict]:
    # read and decode json lines into a list of dictionaries.
    #
    # `pids` drops every other process's lines HERE, before anything is
    # materialised. capa's ProcessFilter does the same thing after the whole
    # log has become pydantic models, and a Windows syscall.log runs to
    # millions of lines: measured 1.7 KiB per decoded line, ~3.7 GiB for the
    # 2.27M-line trace of 2026-09-18, on a Dom0 with 8 GiB. Lines without a
    # PID are kept, so nothing capa might need is filtered on a guess.
    wanted = set(pids) if pids is not None else None
    for line in fd:
        try:
            # we use orjson for a small performance improvement
            data = orjson.loads(line.strip())
            if wanted is not None and "PID" in data and data["PID"] not in wanted:
                continue
            if data.get("Plugin") == "libmon":
                _relabel_libmon_for_capa(data)
            if (
                data.get("Plugin") == "apimon"
                and data.get("Event") == "api_called"
            ):
                if "Arguments" not in data:
                    data["Arguments"] = []
                else:
                    # After the relabel above, so libmon's arguments are
                    # normalised too -- both plugins emit the same shape.
                    normalise_string_arguments(data)
            if data.get("Plugin") == "syscall" and "FromParentModule" in data:
                del data["FromParentModule"]
            if data.get("Plugin") == "syscall" and "FromModule" in data:
                del data["FromModule"]
            yield data
        except orjson.JSONDecodeError:
            # sometimes Drakvuf reports bad method names and/or malformed JSON
            logger.debug("bad drakvuf log line: %s", line)


# DRAKVUF's string-argument format and escaping, shared with `falco`.
_DRAKVUF_STRING_ARG = DRAKVUF_STRING_ARG
_unescape_drakvuf = unescape_drakvuf


def normalise_string_arguments(data: Dict) -> None:
    """Reduce `Name=0xADDR:"C:\\\\Windows"` to `Name=C:\\Windows`, in place.

    **Without this every one of capa's 835 `string:` features is unmatchable.**
    capa reads `call.arguments.values()` and yields the value WHOLE
    (`extractors/drakvuf/call.py`), deliberately -- its comment says the raw form
    is "helpful for an analyst looking at the verbose output". The cost is that
    the feature value is `0x7ffc1234:"Xen"`, so measured 2026-09-27:

        rule feature              raw      --userhook-no-addr   normalised
        string: /^Xen/i           no       no                   MATCH
        string: Xen (exact)       no       no                   MATCH
        substring: Xen            MATCH    MATCH                MATCH

    So `substring:` (145 features) already worked and `string:` (835) never did.
    `--userhook-no-addr` is NOT the fix -- it removes the address and leaves the
    quotes, which is still not the string -- and it would break
    `parse_apimon_arguments`, which splits a value on its first colon.

    Unescaping is required, not cosmetic: a Windows path is escaped to
    `C:\\\\Windows`, and a rule matching `C:\\Windows` would miss it.

    Two deliberate limits:

    - **A string whose content is all digits becomes a `Number`.** capa tries
      `int(value, 0)` before falling back to `String`, so `Path=0x7f:"123"`
      normalises to `123` and is extracted as `Number(123)`. Accepted: it is
      rare, a bare numeric string is genuinely ambiguous, and the alternative
      (keeping the quotes) breaks all 835 of the features this exists for.
    - **Non-string arguments are untouched.** `Arg2=0x10` does not match the
      pattern, so it still reaches capa as `Number(16)`.
    """
    args = data.get("Arguments")
    if not isinstance(args, list):
        return
    out = []
    for arg in args:
        if not isinstance(arg, str):
            continue
        name, sep, value = arg.partition("=")
        if not sep:
            out.append(arg)
            continue
        m = _DRAKVUF_STRING_ARG.match(value)
        out.append(f"{name}={_unescape_drakvuf(m.group(1))}" if m else arg)
    data["Arguments"] = out


def _relabel_libmon_for_capa(data: Dict) -> None:
    """Make a libmon record legible to capa, in place.

    **capa knows only two plugins.** `DrakvufReport.from_raw_report` dispatches
    on `Plugin` and handles `"syscall"` and `"apimon"`; anything else is silently
    dropped, with a TODO to add more (capa issue #2181). So reading `libmon.log`
    is not enough -- verified 2026-09-27: a record labelled `libmon` yields
    `apicalls=0, syscalls=0`, and the same record labelled `apimon` parses.

    Two fixes, both narrow:

    - **Relabel the plugin.** Defensible rather than a hack: libmon emits
      deliberately the same `api_called` shape as apimon -- `Event`, `Method`,
      `Arguments`, `ReturnValue`, plus the common fields
      (`libmon.cpp::print_call`) -- which is why it was written that way. Only
      this feed is relabelled; `libmon.log` on disk, and therefore the uploaded
      artifact, still says `libmon`.

    - **Default a missing `ReturnValue`.** `WinApiCall.return_value` is a
      REQUIRED field, so a record from a `no-retval` hook raises
      `ValidationError` out of `from_raw_report` and takes the whole capa pass
      with it -- not just that line. `so-hooks-linux.txt` has such a hook
      (`SSL_read`), so this is reachable today, and the failure would look like
      capa finding nothing rather than like an error.

      **The value is synthetic**, and capa turns argument and return values into
      `Number` features, so this manufactures a `Number(0)` the guest never
      produced. Zero is chosen because it is what a `no-retval` hook means --
      the return was not observed -- and because a rule matching `number: 0` on
      a return value would be matching noise anyway.

    Delete all of this when capa learns about libmon upstream.
    """
    data["Plugin"] = "apimon"
    data.setdefault("ReturnValue", "0x0")


# libmon is the Linux counterpart of apimon and writes the same record shape,
# so capa consumes it on the same path -- after `_relabel_libmon_for_capa`,
# without which every line is read and then discarded. A name that does not
# match a written log is not an error here (`iter_calls` skips a missing file at
# debug level), so a typo in this tuple costs the whole feature silently.
CALL_LOGS = ("libmon.log", "apimon.log", "syscall.log")


def iter_calls(
    analysis_dir: Path, malware_pids: Optional[List[int]]
) -> Iterator[Dict]:
    # api calls first, then syscalls, one line at a time; capa sorts them.
    for name in CALL_LOGS:
        path = analysis_dir / name
        if not path.exists():
            logger.debug("missing %s file", name)
            continue
        with path.open("r", errors="ignore") as fd:
            yield from decode_json_lines(fd, malware_pids)


def dynamic_capa_analysis(
    analysis_dir: Path,
    rules: RuleSet,
    malware_pids: Optional[List[int]] = None,
) -> Tuple[Path, ResultDocumentMatchResults]:
    # No log at all is a configuration problem (neither apimon nor syscalls
    # was enabled) and is reported as one. A log with nothing from the
    # sample's processes is a result, and produces an empty ttps.json.
    if not any((analysis_dir / name).exists() for name in CALL_LOGS):
        raise RuntimeError(
            "both syscall.log and apimon.log are either empty or non-existent"
        )

    # initialize the Drakvuf capa feature extractor with the captured calls.
    # `from_raw_report` consumes an iterator, so the log is never held as a
    # list of dicts; only the retained lines exist, as capa's own models.
    extractor = get_drakvuf_feature_extractor(
        iter_calls(analysis_dir, malware_pids)
    )

    # apply a filter to the extractor if we wish to only analyze a specific set of processes
    if malware_pids:
        extractor = ProcessFilter(extractor, malware_pids)

    # extract dymamic capabilities. flare-capa 9 returns a Capabilities
    # dataclass; the 7.4 this was written against returned a tuple.
    capabilities = find_capabilities(rules, extractor, disable_progress=True).matches

    # analysis_dir is returned for conformity reasons with the ttp generation function (same routine for both static and dynamic capability extraction)
    return analysis_dir, capabilities


def get_process_memory_dumps(analysis_dir: Path, pid: int) -> Iterator[str]:
    """get the memory dumps from a specific process."""
    # this is used mainly to get the memdumps by a malware process
    with (analysis_dir / "memdump.log").open("r") as f:
        for line in f:
            dump = orjson.loads(line)
            if dump["PID"] == pid:
                yield dump["DumpFilename"]


def static_capa_analysis(
    dump_path: Path, rules: RuleSet
) -> Optional[Tuple[Path, ResultDocumentMatchResults]]:
    """get the input file's capa format"""
    try:
        input_format = get_auto_format(dump_path)
    except UnsupportedFormatError:
        logger.debug("dump %s has an unsupported format", dump_path)
        return None

    # get the input file's adequate analysis backend
    if input_format == FORMAT_DOTNET:
        backend = BACKEND_DOTNET
    else:
        backend = BACKEND_VIV

    # get the right capa feature extractor for the input: Vivisect, .NET, etc.
    extractor = get_extractor(
        dump_path,
        input_format,
        OS_WINDOWS,
        backend=backend,
        sigpaths=[],
        should_save_workspace=False,
        disable_progress=False,
        sample_path=dump_path,
    )

    # extract capabilities from the file, and ignore the returned metadata
    capabilities = find_capabilities(rules, extractor, disable_progress=True).matches

    # return the capabilities alongside the memdump's path (for TTP categorization purposes)
    return dump_path, capabilities


def static_memory_dumps_capa_analysis(
    analysis_dir: Path,
    rules: RuleSet,
    worker_pool_processes: int,
    malware_pids: List[int],
) -> Iterator[Tuple[Path, ResultDocumentMatchResults]]:
    malware_dumps = list(
        itertools.chain(
            *(get_process_memory_dumps(analysis_dir, pid) for pid in malware_pids)
        )
    )

    with TemporaryDirectory() as dump_extraction_directory:
        # extract all memory dumps temporarily into a dumps/ folder
        with zipfile.ZipFile(analysis_dir / DUMPS_ZIP, "r") as zip_ref:
            # extract the memory dumps into the temporary directory
            zip_ref.extractall(dump_extraction_directory)
            dumps = Path(dump_extraction_directory) / DUMPS_DIR

        # extract the capabilities within each memory dump, one per thread.
        # Unsupported formats come back as None and are dropped here rather
        # than unpacked by the caller.
        with multiprocessing.Pool(processes=worker_pool_processes) as pool:
            results = pool.starmap(
                static_capa_analysis,
                map(lambda dump: (dumps / dump, rules), malware_dumps),
            )
        yield from (result for result in results if result is not None)


def format_capa_address(address: Union[Tuple, ca.Address]) -> Dict:
    """This method formats capa address (in the format of tuples) into a single dictionary"""
    if isinstance(address, tuple):
        return functools.reduce(
            lambda a, b: a | b, [format_capa_address(addr) for addr in address]
        )
    elif isinstance(
        address,
        (ca.AbsoluteVirtualAddress, ca.RelativeVirtualAddress, ca.FileOffsetAddress),
    ):
        return {"address": hex(address)}
    elif isinstance(address, ca.DNTokenAddress):
        return {"token": hex(address)}
    elif isinstance(address, ca.DNTokenOffsetAddress):
        return {
            **format_capa_address(ca.DNTokenAddress(address.token)),
            "offset": address.offset,
        }
    elif isinstance(address, ca.ProcessAddress):
        return {"ppid": address.ppid, "pid": address.pid}
    elif isinstance(address, ca.ThreadAddress):
        # for the time being, we only collect the PID and PPID of a TTP
        return {**format_capa_address(address.process)}
    elif isinstance(address, ca.DynamicCallAddress):
        # for the time being, we only collect the PID and PPID of a TTP
        return {**format_capa_address(address.thread)}
    elif isinstance(address, ca._NoAddress):
        # empty address
        return {}
    else:
        logger.debug("Encountered unknown address type: %s", type(address))
        return {"address": address}


def construct_ttp_block(
    rule: Rule, addresses: List[Tuple[ca.Address, Result]]
) -> Dict[str, Any]:
    name = rule.name.split("/")[0]
    mbc = rule.meta.get("mbc", None)
    attck = rule.meta.get("att&ck", None)
    occurrences = [format_capa_address(address=address) for address, _ in addresses]
    occurrences = [
        dict(t) for t in {tuple(d.items()) for d in occurrences}
    ]  # remove duplicate addresses

    ttp_block = dict()
    ttp_block.update({"name": name})
    ttp_block.update({"mbc": mbc} if mbc else {})
    ttp_block.update({"att&ck": attck} if attck else {})
    ttp_block.update({"occurrences": occurrences})
    return ttp_block


def construct_ttp_blocks(
    rules: RuleSet,
    capabilities_per_file: List[Tuple[Path, EngineMatchResults]],
    filter_function=None,
) -> Iterator[Dict[str, Any]]:
    """construct a ttp block for each extracted capability"""
    for _, capabilities in capabilities_per_file:
        for name, addresses in capabilities.items():
            if not filter_function or filter_function(rules[name]):
                yield construct_ttp_block(rules[name], addresses)


def capa_analysis(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    config = context.config.capa

    # capa rules directory
    capa_rules_dir = config.rules_directory

    """check and prepare the rules folder"""
    if not check_rules_directory_exist(capa_rules_dir):
        # in case of a missing/empty rules folder, clone the official capa rules
        raise RuntimeError("capa rules directory is empty or non-existant")

    # get rules and filter them
    rules = get_rules([capa_rules_dir])
    rules = filter_rules(
        rules, filter_function=lambda rule: rule.meta.get("att&ck", None)
    )  # select only rules with an att&ck entry specified

    # get malware-related pids if requested by configuration
    malware_pids = None
    if config.analyze_only_malware_pids:
        malware_pids = get_malware_processes(
            inject_path=analysis_dir / "inject.log",
            pstree_path=analysis_dir / "process_tree.json",
        )

    # extract capabilities from the Drakvuf report
    if config.analyze_drakvuf_log:
        dynamic_capabilities = dynamic_capa_analysis(
            analysis_dir, rules, malware_pids=malware_pids
        )

        # write the extracted TTPs to the analysis dir
        with (analysis_dir / "ttps.json").open("wb") as f:
            for ttp in construct_ttp_blocks(
                rules,
                [dynamic_capabilities],
                filter_function=lambda rule: rule.meta.get("att&ck", None),
            ):
                f.write(orjson.dumps(ttp))
                f.write(b"\n")

    # extract capabilities from the memory dumps
    if config.analyze_memdumps:
        static_capabilities_per_file = static_memory_dumps_capa_analysis(
            analysis_dir, rules, config.worker_pool_processes, malware_pids=malware_pids
        )

        # create a folder containing the TTPs corresponding to each dump
        dumps_ttp_path = analysis_dir / "dumps_ttp"
        dumps_ttp_path.mkdir(parents=True, exist_ok=True)

        # dump the TTPs for each memdump into a jsonl file. `dump_name` is the
        # dump's ABSOLUTE path inside the temporary extraction directory, and
        # joining an absolute path discards the left operand -- upstream wrote
        # each TTP file over the dump itself, in a directory about to be
        # removed, and dumps_ttp/ stayed empty (2026-09-19).
        for dump_name, static_capabilities in static_capabilities_per_file:
            with (dumps_ttp_path / Path(dump_name).name).open("wb") as f:
                for ttp in construct_ttp_blocks(
                    rules, [(dump_name, static_capabilities)]
                ):
                    f.write(orjson.dumps(ttp))
                    f.write(b"\n")
