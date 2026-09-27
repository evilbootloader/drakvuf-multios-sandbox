"""The postprocessing package, ported from drakvuf-sandbox on 2026-09-15.

**Every test here is a defect that was found by running the port against
`samples/trace-windows.log` on 2026-09-18**, not a property imagined at the
desk. The port shipped with the whole chain a no-op (wrong trace filename),
and behind that a second layer of failures the no-op had hidden. Each test
names the one it pins, so a re-port from a newer upstream that brings it back
fails here rather than on Dom0.

None of these needs the 1.2 GB trace; they use a few lines shaped like it.
"""

from __future__ import annotations

import gzip
import json
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd import stages  # noqa: E402
from sandboxd.guests import TargetOs  # noqa: E402
from sandboxd.postprocessing import paths  # noqa: E402
from sandboxd.postprocessing.plugins import plugin_base  # noqa: E402
from sandboxd.postprocessing.plugins.capa_plugin import capa_processor as capa  # noqa: E402
from sandboxd.postprocessing.plugins.compress_ipt import compress_ipt  # noqa: E402
from sandboxd.postprocessing.plugins.gzip_syscalls import gzip_syscalls  # noqa: E402
from sandboxd.postprocessing.plugins.get_http_info import get_http_info  # noqa: E402
from sandboxd.postprocessing.plugins.process_dumps import process_dumps  # noqa: E402
from sandboxd.postprocessing.plugins.process_extracted import process_extracted  # noqa: E402
from sandboxd.postprocessing.plugins.split_drakvuf_log import split_drakvuf_log  # noqa: E402
from sandboxd.postprocessing import indexer, postprocess, process_tree  # noqa: E402


SAMPLES = ROOT / "samples"


def context(tmp_path, os_=TargetOs.WINDOWS, **env) -> plugin_base.PostprocessContext:
    return plugin_base.PostprocessContext(tmp_path, plugin_base.PostprocessingConfig(**env), os_)


def jsonl(path: Path, *objs) -> Path:
    path.write_text("".join(json.dumps(o) + "\n" for o in objs))
    return path


def libmon_line(method, arguments, retval="0x0", pid=4242, evtid="0x30"):
    """One `api_called` record in libmon's shape.

    Taken from `drakvuf/src/plugins/libmon/libmon.cpp::print_call`, not
    invented: `Event`, `Library`, `CalledFrom`, `ReturnValue`, `FromModule`,
    `Arguments`, plus `Method` from the common formatter -- the same shape
    apimon emits, which is what lets `get_http_info` run one algorithm over
    both."""
    return {"Plugin": "libmon", "Event": "api_called", "Method": method,
            "PID": pid, "EventUID": evtid, "Library": "/lib/x86_64-linux-gnu/libcurl.so.4",
            "CalledFrom": "0x7f0000000000", "ReturnValue": retval,
            "Arguments": arguments}


# Shaped like trace-windows.log: five roots, the injected process (7208,
# Notepad.exe) under the LAST of them, not the first.
def pstree_with_late_root() -> list:
    def node(pid, ppid, children=()):
        return {"seqid": pid, "pid": pid, "ppid": ppid, "procname": f"p{pid}",
                "args": [], "ts_from": 0.0, "ts_to": None, "evtid_from": 0,
                "evtid_to": None, "exit_code": None, "exit_code_str": None,
                "killed_by": None, "children": list(children)}
    return [node(4, 0, [node(96, 4)]), node(500, 4), node(600, 4), node(700, 4),
            node(4696, 700, [node(7208, 4696, [node(7300, 7208)])])]


# --- the trace filename ------------------------------------------------------

def test_the_split_reads_the_file_the_trace_stage_writes():
    """The port read `drakvuf.log`; `_trace` writes TRACE_LOG. Nothing ran.

    Restated in paths.py rather than imported, because stages.py imports the
    package; this is what keeps the two spellings one value."""
    assert paths.TRACE_LOG == stages.TRACE_LOG


# --- split_drakvuf_log ---------------------------------------------------------

def test_the_split_yields_inject_log_and_attributes_undecodable_lines(tmp_path):
    """`inject.log` is the sample's launch (DRAKVUF's -i/-e), which is what
    capa's malware-PID filter keys on; and a line with raw non-UTF-8 bytes --
    a Linux `readlink` buffer produced one -- goes to parse_errors.log under
    the plugin that wrote it, where upstream's heuristic (`re.match` on a line
    starting with `{`, against a spaced form DRAKVUF does not emit) counted
    every one as "unknown"."""
    trace = tmp_path / paths.TRACE_LOG
    with trace.open("wb") as f:
        f.write(b'{"Plugin": "inject", "Method": "ShellExec", "Status": "Success", "InjectedPid": 7208}\n')
        f.write(b'{"Plugin":"syscall","PID":7208,"Method":"NtOpenFile"}\n')
        f.write(b'{"Plugin":"syscall","PID":207,"buf":"\xff\xfeA"}\n')
        f.write(b'{"Plugin":"../escape","PID":1}\n')

    split_drakvuf_log(context(tmp_path))

    assert not trace.exists()
    assert json.loads((tmp_path / "inject.log").read_text())["InjectedPid"] == 7208
    assert (tmp_path / "syscall.log").read_text().count("\n") == 1
    assert (tmp_path / "parse_errors.log").read_bytes().startswith(b'{"Plugin":"syscall"')
    # A Plugin value that is not a plain word never becomes a filename.
    assert (tmp_path / "unknown.log").exists()
    assert not any("escape" in p.name for p in tmp_path.iterdir())


# --- capa: the malware-PID path ------------------------------------------------

def test_the_injected_pid_is_found_under_any_root(tmp_path):
    """Upstream raised from inside the recursion, so only the first root's
    subtree was ever searched; trace-windows.log has Notepad at depth 4 under
    the fifth root."""
    found = capa.find_process_in_pstree(pstree_with_late_root(), 7208)
    assert found["pid"] == 7208
    assert sorted(capa.get_all_child_processes(found)) == [7208, 7300]
    with pytest.raises(RuntimeError):
        capa.find_process_in_pstree(pstree_with_late_root(), 424242)


def test_exactly_one_inject_entry_is_the_normal_case(tmp_path):
    """Upstream tested `if len(...)`, which raised on the single entry every
    trace has. It never noticed: its analyze_only_malware_pids defaults off."""
    tree = jsonl(tmp_path / "process_tree.json")
    tree.write_text(json.dumps(pstree_with_late_root()))
    inject = jsonl(tmp_path / "inject.log", {"InjectedPid": 7208})

    assert sorted(capa.get_malware_processes(inject, tree)) == [7208, 7300]

    inject.write_text("")
    with pytest.raises(ValueError):
        capa.get_malware_processes(inject, tree)
    jsonl(inject, {"InjectedPid": 7208}, {"InjectedPid": 7300})
    with pytest.raises(ValueError):
        capa.get_malware_processes(inject, tree)


def test_other_processes_lines_are_dropped_before_they_are_materialised(tmp_path):
    """1.7 KiB per decoded line, 2.27M lines: ~3.7 GiB on an 8 GiB Dom0.
    The filter runs in the reader, so the rest never exists. Lines without a
    PID are kept -- the filter is not allowed to guess."""
    log = jsonl(tmp_path / "syscall.log",
                {"Plugin": "syscall", "PID": 7208, "Method": "a"},
                {"Plugin": "syscall", "PID": 4, "Method": "b"},
                {"Plugin": "syscall", "Method": "no-pid"})
    with log.open() as f:
        kept = list(capa.decode_json_lines(f, pids=[7208]))
    assert [e["Method"] for e in kept] == ["a", "no-pid"]
    with log.open() as f:
        assert len(list(capa.decode_json_lines(f))) == 3


def test_capa_9_returns_a_capabilities_object_not_a_tuple():
    """The code was written against flare-capa 7.4, where find_capabilities
    returned `(matches, meta)`. requirements.txt pins 9.4, where it returns a
    dataclass and tuple-unpacking raises TypeError."""
    import dataclasses
    from capa.capabilities.common import Capabilities
    assert "matches" in {f.name for f in dataclasses.fields(Capabilities)}
    src = Path(capa.__file__).read_text()
    assert "capabilities, _ = find_capabilities" not in src


# --- process_dumps -------------------------------------------------------------

def make_windows_tree() -> process_tree.ProcessTree:
    tree = process_tree.ProcessTree()
    system = tree.add_process(4, 0, 0, 0.0, "System", None)
    tree.add_process(7208, 4, 0, 0.0, "notepad.exe", system)
    return tree


def write_dump(dumps: Path, index: int, data: bytes) -> str:
    name = f"dump{index}.dmp"
    (dumps / name).write_bytes(data)
    (dumps / f"memdump.{index:06d}.metadata").write_text("{}")
    return name


def memdump_line(index, pid, name, size, **extra):
    return {"Plugin": "memdump", "PID": pid, "EventUID": "0x10", "Method": "NtFreeVirtualMemory",
            "DumpReason": "test", "DumpAddr": "0x400000", "DumpSize": hex(size),
            "DumpFilename": name, "DumpsCount": index, **extra}


def test_a_dump_from_a_pid_the_tree_never_saw_is_kept(tmp_path):
    """Operator's rule, 2026-09-18: a dump is evidence whether or not procmon
    saw the process. It is packed, and reported under seqid None; System's
    is filtered as configured; the config class the port shipped empty has
    the four fields this reads."""
    dumps = tmp_path / paths.DUMPS_DIR
    dumps.mkdir()
    known = write_dump(dumps, 1, b"K" * 1024)
    orphan = write_dump(dumps, 2, b"O" * 1024)
    system = write_dump(dumps, 3, b"S" * 1024)
    jsonl(tmp_path / "memdump.log",
          memdump_line(1, 7208, known, 1024),
          memdump_line(2, 99999, orphan, 1024, TargetPID=88888, WriteAddr="0x1"),
          memdump_line(3, 4, system, 1024))
    ctx = context(tmp_path)
    ctx.process_tree = make_windows_tree()

    process_dumps(ctx)

    members = {i.filename for i in zipfile.ZipFile(tmp_path / paths.DUMPS_ZIP).infolist()}
    assert members == {f"{paths.DUMPS_DIR}/{known}", f"{paths.DUMPS_DIR}/{orphan}"}
    assert not dumps.exists()
    groups = {g["process_seqid"]: g["dumps"] for g in ctx.report["memdumps"]}
    assert set(groups) == {1, None}
    assert groups[None][0]["pid"] == 99999
    assert groups[None][0]["target_process"] is None


# --- gzip_syscalls -------------------------------------------------------------

def test_gzip_replaces_syscall_log_and_tolerates_a_missing_sysret(tmp_path):
    """The port read `config.drakrun.gzip_syscalls`, a section that does not
    exist here, so this raised on every run -- and upstream's unlink sat
    outside the exists() test, so a trace run with sysret disabled raised
    FileNotFoundError after compressing syscall.log."""
    (tmp_path / "syscall.log").write_bytes(b"x" * 10_000)

    gzip_syscalls(context(tmp_path))

    assert not (tmp_path / "syscall.log").exists()
    assert not (tmp_path / "sysret.log.gz").exists()
    with gzip.open(tmp_path / "syscall.log.gz") as f:
        assert f.read() == b"x" * 10_000

    (tmp_path / "syscall.log").write_bytes(b"y")
    gzip_syscalls(context(tmp_path, gzip_syscalls=False))
    assert (tmp_path / "syscall.log").exists()


# --- compress_ipt --------------------------------------------------------------

def test_ipt_is_packed_with_its_prefix_and_the_directory_removed(tmp_path):
    """The port imported IPT_DIR/IPT_ZIP from drakrun (NameError on the first
    call) and sat unregistered. Upstream's body also rglob'd subdirectories
    into `write` and then `unlink`ed them, which raises on the first one, and
    never closed the zip. The member layout is dumps.zip's: `ipt/<file>`."""
    ipt = tmp_path / paths.IPT_DIR
    (ipt / "vcpu0").mkdir(parents=True)
    (ipt / "vcpu0" / "trace.bin").write_bytes(b"\x02" * 4096)
    (ipt / "ipt.json").write_text("{}")

    compress_ipt(context(tmp_path))

    assert not ipt.exists()
    with zipfile.ZipFile(tmp_path / paths.IPT_ZIP) as z:
        assert sorted(i.filename for i in z.infolist()) == [
            f"{paths.IPT_DIR}/ipt.json", f"{paths.IPT_DIR}/vcpu0/trace.bin"]
        assert z.read(f"{paths.IPT_DIR}/vcpu0/trace.bin") == b"\x02" * 4096


def test_a_failed_ipt_pack_leaves_the_raw_traces_and_no_zip(tmp_path, monkeypatch):
    """`_collect` skips IPT_DIR whenever IPT_ZIP is beside it, so a partial
    zip would hide the raw traces from the upload while carrying only some
    of them. The directory stays, the zip does not."""
    ipt = tmp_path / paths.IPT_DIR
    ipt.mkdir()
    (ipt / "trace.bin").write_bytes(b"\x02" * 64)

    def refuse(self, *a, **kw):
        raise OSError("disk full")
    monkeypatch.setattr(zipfile.ZipFile, "write", refuse)

    with pytest.raises(OSError):
        compress_ipt(context(tmp_path))
    assert (ipt / "trace.bin").exists()
    assert not (tmp_path / paths.IPT_ZIP).exists()


# --- the index and the tree survive PIDs procmon never saw ---------------------

def test_events_from_unknown_pids_are_counted_not_raised(tmp_path, caplog):
    """968 tracebacks from one trace, mostly cpuidmon events. One warning."""
    jsonl(tmp_path / "cpuidmon.log",
          *({"PID": 1432, "EventUID": hex(i), "Method": "cpuid"} for i in range(50)),
          {"PID": 7208, "EventUID": "0x99", "Method": "cpuid"})
    with caplog.at_level("WARNING"):
        index = indexer.index_log_file(tmp_path / "cpuidmon.log", make_windows_tree(), key="Method")
    assert set(index) == {1}
    assert sum("absent from the process tree" in r.message for r in caplog.records) == 1
    assert not any(r.exc_info for r in caplog.records)


def test_a_terminate_from_an_unknown_killer_does_not_take_the_tree_down():
    """Upstream warned that the killer was missing and then dereferenced it;
    tree_from_log re-raises non-JSON errors, so one such line lost the whole
    process tree and every plugin behind it."""
    tree = make_windows_tree()
    process_tree.parse_mm_terminate_process(tree, {
        "ExitPid": 7208, "PID": 31337, "ExitStatus": "0x0", "ExitStatusStr": "STATUS_SUCCESS"})
    assert tree.get_process(7208).exit_code == 0
    assert tree.get_process(7208).killed_by is None


# --- the tree is built per guest OS ---------------------------------------------

def test_the_windows_tree_is_what_the_method_chain_built(tmp_path):
    """The per-OS parser table (2026-09-19) replaced an if/elif chain on
    Method. This is what that chain built for the four procmon lines
    trace-windows.log carries, and a Linux event under Windows falls through
    to the PID/PPID branch as any unknown Method always did."""
    log = jsonl(
        tmp_path / "procmon.log",
        {"Plugin": "procmon", "TimeStamp": "1.0", "PID": 4, "PPID": 0, "RunningProcess": "System"},
        {"Plugin": "procmon", "TimeStamp": "1.5", "PID": 976, "PPID": 4, "RunningProcess": "svchost.exe"},
        {"Plugin": "procmon", "TimeStamp": "2.0", "PID": 976, "PPID": 4, "Method": "NtCreateUserProcess",
         "EventUID": "0x10", "Status": "0x0", "NewPid": 5084,
         "ImagePathName": "C:\\Windows\\System32\\DataExchangeHost.exe",
         "CommandLine": "C:\\\\Windows\\\\System32\\\\DataExchangeHost.exe -Embedding"},
        {"Plugin": "procmon", "TimeStamp": "3.0", "PID": 5084, "PPID": 976, "Method": "NtTerminateProcess",
         "EventUID": "0x20", "ExitPid": 0, "ExitStatus": "0x1", "ExitStatusStr": "STATUS_UNSUCCESSFUL"},
        {"Plugin": "procmon", "TimeStamp": "4.0", "PID": 5084, "PPID": 976, "Method": "MmCleanProcessAddressSpace",
         "EventUID": "0x30", "ExitPid": 5084},
        {"Plugin": "procmon", "TimeStamp": "5.0", "PID": 976, "PPID": 4, "TID": 976, "Method": "do_exit",
         "EventUID": "0x40", "ExitStatus": 0, "ExitStatusStr": "EXIT_SUCCESS"})
    with log.open() as f:
        tree = process_tree.tree_from_log(f, TargetOs.WINDOWS)

    assert [p.pid for p in tree.processes] == [4, 976, 5084]
    deh = tree.get_process(5084)
    assert deh.parent is tree.get_process(976)
    assert deh.procname == "C:\\Windows\\System32\\DataExchangeHost.exe"
    assert deh.args == ["C:\\Windows\\System32\\DataExchangeHost.exe", "-Embedding"]
    assert (deh.ts_from, deh.evtid_from, deh.ts_to, deh.evtid_to) == (2.0, 0x10, 4.0, 0x30)
    assert (deh.exit_code, deh.exit_code_str, deh.killed_by) == (1, "STATUS_UNSUCCESSFUL", None)
    assert tree.get_process(976).ts_to is None


def test_the_linux_tree_is_built_from_the_procmon_sample():
    """samples/procmon-linux.log (2026-09-19): dash (2001, the injected
    process) vforks `id` and `sleep 120`; systemd forks two services. The
    first cut of the Linux parsers, run against it, made two nodes per
    process -- under vfork the child's execve is logged BEFORE the parent's
    kernel_clone returns, and a plain fork is a clone and then an execve --
    grew evolution-calendar-factory six `Unnamed` children (kernel_clone is
    every pthread_create) and killed it six times (do_exit is every thread's
    exit), and died on the first do_exit anyway: ExitStatus is an integer
    here where the Windows parser's int(x, 16) wants a hex string."""
    with (SAMPLES / "procmon-linux.log").open() as f:
        tree = process_tree.tree_from_log(f, TargetOs.UBUNTU)

    pids = [p.pid for p in tree.processes]
    assert len(pids) == len(set(pids)), "one node per process"
    assert not any(p.procname == "Unnamed" for p in tree.processes)
    assert not ({*range(2004, 2012), 2014, 2015} & set(pids)), "threads are not processes"

    dash = tree.get_process(2001)
    assert [c.pid for c in dash.children] == [2002, 2003]
    id_, sleep = dash.children
    assert (id_.procname, id_.args) == ("/usr/bin/id", ["id"])
    assert (sleep.procname, sleep.args) == ("/usr/bin/sleep", ["sleep", "120"])
    # The execve came first and made the node; the clone that followed did
    # not replace it.
    assert (id_.ts_from, id_.evtid_from) == (1789814003.999584, 0x807)
    # do_exit is where a Linux process ends: no MmCleanProcessAddressSpace.
    assert (id_.ts_to, id_.evtid_to) == (1789814004.013067, 0x888)
    for p in (id_, sleep, dash):
        assert p.ts_to is not None
        assert (p.exit_code, p.exit_code_str, p.killed_by) == (0, "EXIT_SUCCESS", None)
    # Six of its threads exited; it did not.
    assert tree.get_process(1300).ts_to is None
    # Clone first, then execve: the clone's node renamed in place, and a
    # script's name is the script (FileName), not the interpreter.
    downloader = tree.get_process(2012)
    assert downloader.parent is tree.get_process(1)
    assert (downloader.ts_from, downloader.evtid_from) == (1789814041.369118, 0x364e)
    assert downloader.procname == "/usr/lib/update-notifier/package-data-downloader"
    assert downloader.args == ["/usr/bin/python3", "/usr/lib/update-notifier/package-data-downloader"]
    assert (downloader.ts_to, downloader.evtid_to) == (1789814041.662300, 0x4bba)


def test_android_shares_the_linux_parsers_and_an_unknown_os_is_loud():
    assert process_tree.METHOD_PARSERS[TargetOs.ANDROID] is process_tree.METHOD_PARSERS[TargetOs.UBUNTU]
    assert set(process_tree.METHOD_PARSERS) == set(TargetOs)


# --- the entry point and the config --------------------------------------------

def test_postprocessing_never_raises_into_the_analysis(tmp_path, monkeypatch):
    """It runs inside the try that turns exceptions into a `failed` job. A
    fault in derived data must not discard a completed trace."""
    def boom(_context):
        raise RuntimeError("plugin table is broken")
    monkeypatch.setattr(postprocess, "run_postprocessing", boom)
    postprocess.postprocess_analysis_dir(
        tmp_path, plugin_base.PostprocessingConfig(), TargetOs.WINDOWS)


def test_the_config_reads_only_prefixed_environment(tmp_path, monkeypatch):
    """BaseSettings reads field names from the environment case-insensitively.
    Unprefixed, a stray CAPA or MEMDUMP variable on Dom0 would be parsed as
    this config, and a parse failure there is outside every plugin handler."""
    monkeypatch.setenv("CAPA", "not json at all")
    monkeypatch.setenv("SANDBOXD_POSTPROCESS_CAPA", json.dumps({"rules_directory": str(tmp_path)}))
    config = plugin_base.load_postprocessing_config()
    assert config.capa.rules_directory == tmp_path
    assert config.capa.analyze_only_malware_pids is True


def test_the_plugin_table_names_the_shared_paths():
    """process_dumps packs DUMPS_DIR into DUMPS_ZIP and capa's static pass
    unpacks it expecting the same names; the table must say the same, and
    process_dumps must run first, or the static pass reads a zip that does
    not exist yet (upstream's order, hidden by its analyze_memdumps=False)."""
    from sandboxd.postprocessing.plugins import POSTPROCESS_PLUGINS
    names = [p.function.__name__ for p in POSTPROCESS_PLUGINS]
    assert names.index("process_dumps") < names.index("capa_analysis")
    by_name = {p.function.__name__: p for p in POSTPROCESS_PLUGINS}
    assert paths.TRACE_LOG in by_name["split_drakvuf_log"].requires
    assert paths.DUMPS_DIR in by_name["process_dumps"].requires
    assert by_name["process_dumps"].generates == [paths.DUMPS_ZIP]
    assert "inject.log" in by_name["capa_analysis"].requires
    # Registered and gated on its directory, which nothing creates until
    # argv_trace passes --ipt-dir; the table is ready for that day.
    assert by_name["compress_ipt"].requires == [paths.IPT_DIR]
    assert by_name["compress_ipt"].generates == [paths.IPT_ZIP]

# --- get_registry_info (not upstream) -------------------------------------------

def test_registry_writes_are_summarised_and_reads_are_not(tmp_path):
    """One row per (key, value): the last data seen and every writer; reads
    stay out; an autostart location is flagged; a writer the tree does not
    know is kept as None rather than dropped."""
    from sandboxd.postprocessing.plugins.get_registry_info import get_registry_info
    run = "\\REGISTRY\\USER\\S-1-5-21-1\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    line = lambda method, pid, key, name=None, value=None: {  # noqa: E731
        "Plugin": "regmon", "PID": pid, "EventUID": "0x10", "Method": method,
        "Key": key, "ValueName": name, "Value": value, "RegOptions": ""}
    jsonl(tmp_path / "regmon.log",
          line("NtQueryValueKey", 7208, run, "x"),
          line("NtSetValueKey", 7208, run, "Updater", "C:\\evil.exe"),
          line("NtSetValueKey", 7208, run, "Updater", "C:\\evil2.exe"),
          line("NtSetValueKey", 31337, "\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor", "v", "1"),
          line("NtCreateKey", 7208, "\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor\\Sub"),
          line("NtDeleteValueKey", 7208, run, "Old"),
          line("NtDeleteKey", 7208, "\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor\\Gone"),
          line("NtSetValueKey", 7208, "\\REGISTRY\\MACHINE\\SOFTWARE\\Big", "blob", "ff " * 1000))
    ctx = context(tmp_path)
    ctx.process_tree = make_windows_tree()

    get_registry_info(ctx)

    r = ctx.report
    by_name = {(v["key"], v["value_name"]): v for v in r["registry_set_values"]}
    updater = by_name[(run, "Updater")]
    assert updater["value"] == "C:\\evil2.exe" and updater["autostart"] is True
    assert updater["process_seqids"] == [1]
    assert by_name[("\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor", "v")]["process_seqids"] == [None]
    assert by_name[("\\REGISTRY\\MACHINE\\SOFTWARE\\Big", "blob")]["value"].endswith("…")
    assert [k["key"] for k in r["registry_created_keys"]] == ["\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor\\Sub"]
    # A service opening its own key is not an autostart write; setting a
    # value under Services is.
    from sandboxd.postprocessing.plugins.get_registry_info import is_autostart
    svc = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
    assert is_autostart(svc, created=True) is False and is_autostart(svc) is True
    assert is_autostart(run, created=True) is True
    assert [k["key"] for k in r["registry_deleted_keys"]] == ["\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor\\Gone"]
    assert r["registry_deleted_values"] == [
        {"key": run, "value_name": "Old", "process_seqids": [1]}]
    assert not any("QueryValue" in str(v) for v in r.values())


# --- process_extracted ---------------------------------------------------------

def make_linux_tree() -> process_tree.ProcessTree:
    tree = process_tree.ProcessTree()
    init = tree.add_process(1, 0, 0, 0.0, "init", None)
    tree.add_process(4242, 1, 0, 0.0, "sample.bin", init)
    return tree


def test_linux_extracted_files_survive_having_no_metadata_sidecar(tmp_path):
    """`process_dumps` skips any dump whose `.metadata` is missing, because
    memdump writes one for every dump. **fileextractor does not** -- only
    `win.cpp::save_file_metadata` does, so a Linux guest produces none at all.

    Copying that guard would have dropped every extracted file on Ubuntu and
    Android: the whole output of the plugin, on two of the three guests, with
    nothing in the report to say so."""
    extracted = tmp_path / paths.EXTRACTED_DIR
    extracted.mkdir()
    (extracted / "00000001_payload.sh").write_bytes(b"#!/bin/sh\n")
    jsonl(tmp_path / "fileextractor.log",
          {"Plugin": "fileextractor", "PID": 4242, "EventUID": "0x20",
           "Reason": "write", "FileName": "/tmp/payload.sh", "Size": 10,
           "DumpFile": "/root/results/extracted/00000001_payload.sh",
           "ProcessName": "sample.bin"})
    ctx = context(tmp_path, TargetOs.UBUNTU)
    ctx.process_tree = make_linux_tree()

    process_extracted(ctx)

    members = {i.filename for i in
               zipfile.ZipFile(tmp_path / paths.EXTRACTED_ZIP).infolist()}
    assert members == {f"{paths.EXTRACTED_DIR}/00000001_payload.sh"}
    assert not extracted.exists()
    groups = {g["process_seqid"]: g["files"] for g in ctx.report["extracted_files"]}
    # Attributed to the sample, and carrying the guest's own path for it.
    assert list(groups) == [1]
    assert groups[1][0]["guest_path"] == "/tmp/payload.sh"
    assert groups[1][0]["guest_basename"] == "payload.sh"


def test_an_extracted_file_with_no_log_record_is_kept_unattributed(tmp_path):
    """The directory is the ground truth, not the log. A file DRAKVUF wrote
    but did not log -- a truncated run, a line lost to a parse error -- is
    still a file the sample wrote, so it is packed and reported under seqid
    None. Same rule the operator set for memory dumps on 2026-09-18."""
    extracted = tmp_path / paths.EXTRACTED_DIR
    extracted.mkdir()
    (extracted / "00000001_known.bin").write_bytes(b"K")
    (extracted / "00000002_orphan.bin").write_bytes(b"O")
    jsonl(tmp_path / "fileextractor.log",
          {"Plugin": "fileextractor", "PID": 4242, "EventUID": "0x20",
           "Reason": "write", "FileName": "/tmp/known.bin", "Size": 1,
           "DumpFile": "/x/00000001_known.bin"})
    ctx = context(tmp_path, TargetOs.UBUNTU)
    ctx.process_tree = make_linux_tree()

    process_extracted(ctx)

    members = {i.filename for i in
               zipfile.ZipFile(tmp_path / paths.EXTRACTED_ZIP).infolist()}
    assert members == {f"{paths.EXTRACTED_DIR}/00000001_known.bin",
                       f"{paths.EXTRACTED_DIR}/00000002_orphan.bin"}
    groups = {g["process_seqid"]: g["files"] for g in ctx.report["extracted_files"]}
    assert set(groups) == {1, None}
    assert groups[None][0]["name"] == "00000002_orphan.bin"


def test_windows_extracted_files_are_found_through_seqnum(tmp_path):
    """Windows writes `file.%06d.mm` and names no path in the log, so SeqNum
    is the only link to the file on disk; Linux writes `%08d_<name>` and puts
    the full path in DumpFile. Per-OS table, not a branch.

    The `.metadata` sidecar is packed with its data file -- it is evidence
    about the extraction -- but is not itself a file the sample wrote, so it
    does not become a report entry."""
    extracted = tmp_path / paths.EXTRACTED_DIR
    extracted.mkdir()
    (extracted / "file.000007.mm").write_bytes(b"MZ")
    # `file.000007.metadata`, NOT `file.000007.mm.metadata`: both names come
    # from win.cpp::get_filename(folder, idx, ext), which REPLACES the
    # extension. Appending finds nothing.
    (extracted / "file.000007.metadata").write_text('{"FileName": "x"}')
    jsonl(tmp_path / "fileextractor.log",
          {"Plugin": "fileextractor", "PID": 7208, "EventUID": "0x20",
           "Reason": "close", "FileName": "C:\\Users\\u\\drop.exe",
           "Size": 2, "SeqNum": 7, "FileHash": "ab" * 32})
    ctx = context(tmp_path, TargetOs.WINDOWS)
    ctx.process_tree = make_windows_tree()

    process_extracted(ctx)

    members = {i.filename for i in
               zipfile.ZipFile(tmp_path / paths.EXTRACTED_ZIP).infolist()}
    assert members == {f"{paths.EXTRACTED_DIR}/file.000007.mm",
                       f"{paths.EXTRACTED_DIR}/file.000007.metadata"}
    files = ctx.report["extracted_files"][0]["files"]
    assert [f["name"] for f in files] == ["file.000007.mm"]
    # A Windows path, split with Windows separators rather than the host's.
    assert files[0]["guest_basename"] == "drop.exe"
    assert files[0]["sha256"] == "ab" * 32


def test_a_linux_file_the_sample_named_metadata_is_still_evidence(tmp_path):
    """Why the sidecar skip reads the per-OS table instead of the `.metadata`
    suffix.

    `linux.cpp::sanitize_filename` replaces separators and non-printables and
    nothing else, so the sample's own extension reaches the disk:
    `/tmp/payload.metadata` becomes `00000001_payload.metadata`. A suffix test
    skipped that file, said nothing about it in the report, and the `rmtree`
    then deleted it -- so a sample could erase one of its own dropped files from
    the evidence just by choosing its name. Linux writes no sidecars at all, so
    there is nothing here to skip."""
    extracted = tmp_path / paths.EXTRACTED_DIR
    extracted.mkdir()
    (extracted / "00000001_payload.metadata").write_bytes(b"payload")
    jsonl(tmp_path / "fileextractor.log",
          {"Plugin": "fileextractor", "PID": 4242, "EventUID": "0x20",
           "Reason": "write", "FileName": "/tmp/payload.metadata", "Size": 7,
           "DumpFile": "/root/results/extracted/00000001_payload.metadata"})
    ctx = context(tmp_path, TargetOs.UBUNTU)
    ctx.process_tree = make_linux_tree()

    process_extracted(ctx)

    members = {i.filename for i in
               zipfile.ZipFile(tmp_path / paths.EXTRACTED_ZIP).infolist()}
    assert members == {f"{paths.EXTRACTED_DIR}/00000001_payload.metadata"}
    files = ctx.report["extracted_files"][0]["files"]
    assert [f["guest_path"] for f in files] == ["/tmp/payload.metadata"]


def test_a_windows_sidecar_with_no_data_file_is_kept(tmp_path):
    """A sidecar is skipped because it belongs to a data file that is itself
    packed, not because of what it is called. One standing alone -- a run that
    died between `win.cpp`'s two writes -- is the only surviving record of that
    extraction, so the directory-is-ground-truth rule keeps it."""
    extracted = tmp_path / paths.EXTRACTED_DIR
    extracted.mkdir()
    (extracted / "file.000007.metadata").write_text('{"FileName": "x"}')
    ctx = context(tmp_path, TargetOs.WINDOWS)
    ctx.process_tree = make_windows_tree()

    process_extracted(ctx)

    members = {i.filename for i in
               zipfile.ZipFile(tmp_path / paths.EXTRACTED_ZIP).infolist()}
    assert members == {f"{paths.EXTRACTED_DIR}/file.000007.metadata"}
    groups = {g["process_seqid"] for g in ctx.report["extracted_files"]}
    assert groups == {None}


def test_a_failed_extraction_is_not_reported_as_a_file(tmp_path):
    """`fileextractor_fail` and `_skip` name a file that was NOT written.
    Treating them as extractions would invent artifacts that are not on disk
    and cannot be uploaded."""
    extracted = tmp_path / paths.EXTRACTED_DIR
    extracted.mkdir()
    jsonl(tmp_path / "fileextractor.log",
          {"Plugin": "fileextractor_fail", "PID": 4242, "EventUID": "0x20",
           "FileName": "/tmp/toobig.bin", "Message": "file too large"},
          {"Plugin": "fileextractor_skip", "PID": 4242, "EventUID": "0x21",
           "FileName": "/tmp/boring.txt", "Message": "Excluded by filter"})
    ctx = context(tmp_path, TargetOs.UBUNTU)
    ctx.process_tree = make_linux_tree()

    process_extracted(ctx)

    assert ctx.report["extracted_files"] == []
    assert [f["filename"] for f in ctx.report["extraction_failures"]] == [
        "/tmp/toobig.bin", "/tmp/boring.txt"]


def test_extracted_is_packed_so_collect_uploads_the_zip(tmp_path):
    """The DIR/ZIP pairing `stages._collect` reads. Without the pair the raw
    directory uploads alongside the archive and every file counts twice
    against the 4 GiB per-job budget."""
    assert (paths.EXTRACTED_DIR, paths.EXTRACTED_ZIP) in [
        (paths.DUMPS_DIR, paths.DUMPS_ZIP), (paths.IPT_DIR, paths.IPT_ZIP),
        (paths.EXTRACTED_DIR, paths.EXTRACTED_ZIP)]
    src = Path(stages.__file__).read_text()
    assert "EXTRACTED_ZIP" in src, "stages._collect must know the pair"


# --- get_http_info, per OS -----------------------------------------------------

def test_http_info_reads_libmon_on_linux_and_apimon_on_windows():
    """One algorithm, two vocabularies -- the shape `process_tree
    .METHOD_PARSERS` established. A guest this does not know fails on the
    lookup rather than silently reporting no HTTP."""
    from sandboxd.postprocessing.plugins.get_http_info import HTTP_SOURCES

    assert HTTP_SOURCES[TargetOs.WINDOWS][0] == "apimon.log"
    assert HTTP_SOURCES[TargetOs.UBUNTU][0] == "libmon.log"
    assert HTTP_SOURCES[TargetOs.ANDROID][0] == "libmon.log"
    assert set(HTTP_SOURCES) == set(TargetOs)


def test_a_curl_request_is_reconstructed_from_the_handle_chain(tmp_path):
    """libcurl carries the same information WinINet does, in a different
    order: options accumulate onto one handle and the request exists only
    when `curl_easy_perform` runs it."""
    jsonl(tmp_path / "libmon.log",
          libmon_line("curl_easy_init", [], retval="0x55aa"),
          libmon_line("curl_easy_setopt",
                      ["Handle=0x55aa", "Option=0x2712", "Value=0x7f:\"http://evil.test/x\""]),
          libmon_line("curl_easy_setopt",
                      ["Handle=0x55aa", "Option=0x2722", "Value=0x7f:\"curl/8.5.0\""]),
          libmon_line("curl_easy_perform", ["Handle=0x55aa"]))
    ctx = context(tmp_path, TargetOs.UBUNTU)
    ctx.process_tree = make_linux_tree()

    get_http_info(ctx)

    assert len(ctx.report["http_requests"]) == 1
    req = ctx.report["http_requests"][0]
    assert req["url"] == "http://evil.test/x"
    assert req["user_agent"] == "curl/8.5.0"
    assert [u["url"] for u in ctx.report["cracked_urls"]] == ["http://evil.test/x"]


def test_a_reused_curl_handle_reports_each_url_not_the_last(tmp_path):
    """curl handles are routinely reused for a second request with a new URL.
    Reporting the live dict would show BOTH requests with the last URL set on
    it, which is a false attribution rather than a missing one."""
    jsonl(tmp_path / "libmon.log",
          libmon_line("curl_easy_init", [], retval="0x55aa"),
          libmon_line("curl_easy_setopt",
                      ["Handle=0x55aa", "Option=0x2712", "Value=0x7f:\"http://first.test/\""]),
          libmon_line("curl_easy_perform", ["Handle=0x55aa"]),
          libmon_line("curl_easy_setopt",
                      ["Handle=0x55aa", "Option=0x2712", "Value=0x7f:\"http://second.test/\""]),
          libmon_line("curl_easy_perform", ["Handle=0x55aa"]))
    ctx = context(tmp_path, TargetOs.UBUNTU)
    ctx.process_tree = make_linux_tree()

    get_http_info(ctx)

    assert [r["url"] for r in ctx.report["http_requests"]] == [
        "http://first.test/", "http://second.test/"]


def test_an_http_call_from_an_unknown_pid_does_not_crash_the_plugin(tmp_path):
    """`data["process"].seqid` was read unguarded until 2026-09-26. A call
    from a process the tree never saw raised AttributeError, and because
    `run_postprocessing` catches per plugin, that lost EVERY request in the
    run rather than the one line."""
    jsonl(tmp_path / "libmon.log",
          libmon_line("curl_easy_init", [], retval="0x1", pid=999999),
          libmon_line("curl_easy_setopt",
                      ["Handle=0x1", "Option=0x2712", "Value=0x7f:\"http://orphan.test/\""],
                      pid=999999),
          libmon_line("curl_easy_perform", ["Handle=0x1"], pid=999999))
    ctx = context(tmp_path, TargetOs.UBUNTU)
    ctx.process_tree = make_linux_tree()

    get_http_info(ctx)  # must not raise

    assert [r["url"] for r in ctx.report["http_requests"]] == ["http://orphan.test/"]
    assert ctx.report["http_requests"][0]["process_seqid"] is None


def test_an_ssl_write_is_reported_only_when_it_is_an_http_request(tmp_path):
    """Plaintext at the library boundary is the only place an HTTPS body is
    readable without the session key -- but an arbitrary TLS payload is not a
    URL, so only a buffer whose first line parses as a request line counts."""
    jsonl(tmp_path / "libmon.log",
          libmon_line("SSL_write",
                      ["Ssl=0x1", "Buf=0x7f:\"GET /beacon HTTP/1.1\\r\\nHost: c2.test\\r\\n\\r\\n\"",
                       "Num=0x20"]),
          libmon_line("SSL_write",
                      ["Ssl=0x1", "Buf=0x7f:\"\\x17\\x03\\x03 binary junk\"", "Num=0x10"]))
    ctx = context(tmp_path, TargetOs.UBUNTU)
    ctx.process_tree = make_linux_tree()

    get_http_info(ctx)

    assert len(ctx.report["http_requests"]) == 1
    req = ctx.report["http_requests"][0]
    assert (req["verb"], req["path"], req["over_tls"]) == ("GET", "/beacon", True)


def test_http_info_reports_empty_rather_than_skipping_when_no_api_log(tmp_path):
    """The plugin that writes the log is selectable, so a job that ran
    neither apimon nor libmon has no HTTP evidence. That is a result, not a
    missing key: a consumer must be able to tell "nothing was seen" from
    "this run did not look"."""
    ctx = context(tmp_path, TargetOs.UBUNTU)
    ctx.process_tree = make_linux_tree()

    get_http_info(ctx)

    assert ctx.report["http_requests"] == []
    assert ctx.report["cracked_urls"] == []


def test_named_hook_arguments_parse_as_positionally_as_ArgN_ones():
    """DRAKVUF names an argument from the hook list, not always `ArgN`
    (`libusermode/utils.cpp:216`): a bare type gets `Arg1`, `Arg2`, ..., a
    `Name:type` entry gets its own name. `hooks.txt` is all bare types;
    `so-hooks-linux.txt` names its arguments because a libmon line is far
    easier to read as `Path=` than `Arg2=`.

    The parser required the literal prefix `Arg` and raised otherwise --
    which `parse_log` catches per line and logs, so a named hook list would
    have produced an empty result for every consumer rather than an error."""
    from sandboxd.postprocessing.plugins.parse_utils import parse_apimon_arguments

    assert parse_apimon_arguments(
        ["Arg1=0x4", 'Arg2=0x7f:"/tmp/x"']) == [4, "/tmp/x"]
    assert parse_apimon_arguments(
        ["Fd=0x4", 'Path=0x7f:"/tmp/x"']) == [4, "/tmp/x"]
    # A colon inside the string never splits early: the VALUE is split, and
    # only on its first colon, so a URL survives intact.
    assert parse_apimon_arguments(
        ['Value=0x7f:"http://evil.test/a:b"']) == ["http://evil.test/a:b"]
    # Still rejects something that is not `name=value` at all.
    with pytest.raises(RuntimeError):
        parse_apimon_arguments(["0x4"])


def test_the_shipped_linux_hook_list_parses_as_libmon_expects():
    """The file `argv_trace` passes as `--so-hooks-list`. Grammar from
    `src/plugins/libmon/README.md`:
        <so name>,<function|hex offset>[,no-retval],<log|log+stack>[,<arg>,...]

    Pinned because a malformed line is FATAL: the loader rethrows it as
    "Invalid entry on line N" and DRAKVUF does not start, so a typo here costs
    every Ubuntu job rather than one hook."""
    hooks = ROOT / "sandboxd" / "data" / "so-hooks-linux.txt"
    lines = [ln.strip() for ln in hooks.read_text().splitlines()]
    entries = [ln for ln in lines if ln and not ln.startswith("#")]

    assert entries, "the hook list must not be all comments"
    for entry in entries:
        fields = entry.split(",")
        assert len(fields) >= 3, entry
        so, func, *rest = fields
        assert so.endswith(".so") or ".so." in so, f"not a shared object: {entry}"
        assert func, f"no function or offset: {entry}"
        # `log` or `log+stack`, optionally preceded by `no-retval`.
        assert "log" in rest[:2], f"no log action: {entry}"
        for arg in rest[rest.index("log") + 1:] if "log" in rest else []:
            assert arg, f"empty argument spec: {entry}"

    # The HTTP hooks get_http_info keys on must actually be here, or the
    # Linux side of that plugin is dead code.
    from sandboxd.postprocessing.plugins.get_http_info import (
        _CURL_METHODS, _OPENSSL_METHODS)
    hooked = {ln.split(",")[1] for ln in entries}
    assert {"curl_easy_init", "curl_easy_setopt", "curl_easy_perform"} <= hooked
    assert "SSL_write" in hooked
    # Everything the replayer handles is hooked; the reverse need not hold.
    from sandboxd.postprocessing.plugins.get_http_info import _linux_handlers
    assert set(_linux_handlers()) <= hooked


def test_hot_libc_functions_are_not_hooked():
    """One Dom0 core saturates per concurrent trace at 415-856 syscalls/s
    (CURRENT-STATE.md), so `read`, `write`, `memcpy` and `getpid` stay out.

    **`strcmp` is no longer on this list, and not for the reason it left.**
    The operator chose on 2026-09-27 to accept the cost of comparison functions
    for capa's 835 `string:` features. On Windows they are hooked
    (`ucrtbase.dll`/`msvcrt.dll`, ordinary exports). On Linux they STILL cannot
    be: glibc declares `strcmp`, `strstr`, `memcmp`, `strncmp` and
    `strcasecmp` as `STT_GNU_IFUNC`, whose symbol value is a resolver the
    linker calls once at load time, and `linux-exports.c` has no IFUNC
    handling -- so the hook would fire once per process with no strings. This
    test therefore still keeps them out of the LINUX list, on correctness
    rather than cost grounds."""
    hooks = ROOT / "sandboxd" / "data" / "so-hooks-linux.txt"
    hooked = {ln.split(",")[1] for ln in
              (l.strip() for l in hooks.read_text().splitlines())
              if ln and not ln.startswith("#")}
    # Hot (cost) and IFUNC (cannot work) both belong out of the Linux list.
    forbidden = {"strlen", "memcpy", "atoi", "read", "write",
                 "fread", "fwrite", "getc", "putc", "fgetc", "fputc",
                 "malloc", "free",
                 "strcmp", "strstr", "memcmp", "strncmp", "strcasecmp"}
    assert not (hooked & forbidden), f"hot functions hooked: {hooked & forbidden}"
    # Kernel symbols cannot be resolved in a shared object's .dynsym.
    assert not (hooked & {"commit_creds", "prepare_kernel_cred",
                          "nf_register_hook", "nf_register_net_hook"})


# --- the capa-derived hook lists -----------------------------------------------

def _hook_lines(path: Path) -> list[tuple[str, str, list[str]]]:
    """`(module, function, arg specs)` for every hook, comments stripped.

    The action field is found rather than assumed at index 2: `no-retval` may
    precede it (`libssl.so,SSL_read,no-retval,log,...`), and taking `fields[3:]`
    blindly counted the literal `log` as an argument type.
    """
    out = []
    for raw in path.read_text().splitlines():
        line = raw.split("#")[0].strip()
        if not line:
            continue
        fields = line.split(",")
        assert len(fields) >= 3, f"too few fields: {raw}"
        action = next((i for i, f in enumerate(fields)
                       if f in ("log", "log+stack")), None)
        assert action is not None, f"no log action: {raw}"
        args = [f for f in fields[action + 1:] if f]
        out.append((fields[0], fields[1], args))
    return out


HOOKS_WIN = ROOT / "sandboxd" / "data" / "hooks.txt"
HOOKS_LINUX = ROOT / "sandboxd" / "data" / "so-hooks-linux.txt"

# The only type tokens `libusermode/utils.cpp::make_arg_printer` dispatches on.
# Anything else reaches the base ArgumentPrinter and prints the raw value, which
# is harmless -- but a TYPO in one of these is not, because it silently
# downgrades a string read to a hex number and the log looks fine.
PRINTER_TYPES = {
    "lpstr", "lpcstr", "lpctstr",          # AsciiPrinter
    "lpcwstr", "lpwstr", "bstr",           # WideStringPrinter
    "punicode_string", "pulong", "pulonglong", "lpvoid*",
    "refclsid", "refiid", "binary16",
}


def test_every_hook_line_parses_under_the_documented_grammar():
    """`<module>,<function|hex offset>[,no-retval],<log|log+stack>[,<arg>,...]`
    -- `src/plugins/libmon/README.md`, and the same grammar apimon's
    `--dll-hooks-list` takes (both go through `libusermode/utils.cpp`).

    **A malformed line is fatal, not skipped.**
    `drakvuf_load_dll_hook_config` catches the parse error and rethrows it as
    "Invalid entry on line N" (`libusermode/userhook.cpp:1035`), so DRAKVUF
    never starts and every Windows job fails. With ~1,040 generated lines that
    makes this test load-bearing rather than tidy.

    Order is unforgiving too: `parse_entry` reads any token before the
    `log`/`log+stack` action that is not `clsid` or `no-retval` as a HEX OFFSET
    and throws "Invalid offset" when it will not parse."""
    for path in (HOOKS_WIN, HOOKS_LINUX):
        hooks = _hook_lines(path)
        assert hooks, f"{path.name} has no hooks"
        for module, fn, args in hooks:
            assert module.endswith((".dll", ".so")) or ".so." in module, \
                f"{path.name}: not a module name: {module}"
            assert fn, f"{path.name}: empty function"
            for arg in args:
                # `[Name:]type`; a bare type is legal and means ArgN.
                assert arg.count(":") <= 1, f"{path.name}: bad arg spec {arg!r}"


def test_every_string_argument_uses_a_real_printer_type():
    """The generated lines may only use type tokens this project has decided on.

    A token outside the twelve printer types falls through to the base printer
    and prints the raw value, which is fine and is what most generated arguments
    do. The failure this guards is narrower and silent: `lpcwstr` misspelled
    stops being a string read, the log still looks well formed, and capa quietly
    loses the String feature the rule needed. So the generator is restricted to
    a closed vocabulary and anything new has to be added here deliberately.

    The CURATED half of hooks.txt is exempt -- it carries ~150 Windows SDK type
    names inherited from drakvuf-sandbox (`lpsecurity_attributes`, `hcryptkey`,
    `pdns_record`, ...) which are all documentation-only fall-throughs."""
    generated = HOOKS_WIN.read_text().split("# BEGIN GENERATED")[1]
    # `apimon_type` maps every win32metadata parameter onto `dword`/`lpvoid`
    # plus the printer types; `size_t` is the one hand-written addition, used
    # for the length argument of the CRT comparison functions. All three are
    # fall-throughs -- documentation, not behaviour.
    allowed = PRINTER_TYPES | {"dword", "lpvoid", "size_t"}
    seen = set()
    for raw in generated.splitlines():
        line = raw.split("#")[0].strip()
        if not line or "," not in line:
            continue
        fields = line.split(",")
        action = next((i for i, f in enumerate(fields)
                       if f in ("log", "log+stack")), None)
        if action is None:
            continue
        seen.update(f for f in fields[action + 1:] if f)
    assert seen, "no typed arguments in the generated block"
    assert seen <= allowed, f"unexpected type tokens: {sorted(seen - allowed)}"
    # The string readers must actually be in use -- if a refactor stopped
    # emitting them, every generated hook would silently lose its String
    # features and capa would match far less, with nothing failing.
    assert {"lpcstr", "lpcwstr"} <= seen


def test_no_kernel_mode_module_is_hooked():
    """apimon finds a DLL through its VAD and reads its export table; a kernel
    driver has no VAD in a process. capa-rules names `ntoskrnl`, `fwpkclnt`,
    `fltmgr` and a typo'd `ntoskrn`, all of which must be filtered out."""
    kernel = {"ntoskrnl.dll", "ntoskrn.dll", "fwpkclnt.dll", "fltmgr.dll",
              "ndis.dll", "hal.dll", "ci.dll", "netio.dll", "win32k.dll",
              "tcpip.dll"}
    got = {m for m, _, _ in _hook_lines(HOOKS_WIN)} & kernel
    assert not got, f"kernel-mode modules hooked: {got}"


def test_the_curated_hooks_survive_regeneration():
    """`gen-hook-lists.py` appends a block and never rewrites what is above it.
    Two lines prove it: `CreateProcessInternalW` is hooked deliberately instead
    of `CreateProcess`, and `COleScript_ParseScriptText` is not an export at
    all -- a generator that rewrote the file would lose both."""
    functions = {fn for _, fn, _ in _hook_lines(HOOKS_WIN)}
    assert "CreateProcessInternalW" in functions
    assert "COleScript_ParseScriptText" in functions


def test_the_generated_block_is_marked_and_last():
    """Everything above the marker is hand-maintained. If the marker moved or
    vanished, the next regeneration would either duplicate the block or eat the
    curated lines."""
    for path in (HOOKS_WIN, HOOKS_LINUX):
        text = path.read_text()
        assert text.count("# BEGIN GENERATED") == 1, path.name
        assert text.count("# END GENERATED") == 1, path.name
        assert text.index("# BEGIN GENERATED") < text.index("# END GENERATED")


def test_the_generator_defers_to_capa_for_what_a_rule_name_means():
    """`trim_dll_part` decides whether `kernel32.CreateFile` means
    `CreateFile`. If this generator disagreed with capa, it would hook names
    capa never looks for -- so it imports capa's function rather than keeping a
    second copy of that rule."""
    src = (ROOT / "scripts" / "gen-hook-lists.py").read_text()
    assert "from capa.rules import trim_dll_part" in src


def test_windows_hooks_grew_from_capa_but_stayed_finite():
    """A regression guard with a real number behind it, not a round one: 302
    curated lines plus ~1,040 generated. If this doubles again, someone has
    started generating A/W/bare for everything and the throughput cost of the
    Windows path needs re-deciding before it ships."""
    hooks = _hook_lines(HOOKS_WIN)
    assert 1200 < len(hooks) < 1600, len(hooks)


# --- capa actually receiving what we hook ---------------------------------------

def test_a_libmon_record_reaches_capa_at_all(tmp_path):
    """**Reading `libmon.log` is not enough.** capa's
    `DrakvufReport.from_raw_report` dispatches on `Plugin` and knows only
    `syscall` and `apimon` (capa#2181), so before the relabel every libmon line
    was read and then dropped -- the `libmon.lon` typo fix on its own changed
    nothing measurable.

    Also pins the `no-retval` case: `WinApiCall.return_value` is REQUIRED, so a
    record without `ReturnValue` raised a pydantic error out of
    `from_raw_report` and took the entire capa pass with it, not just the line.
    `so-hooks-linux.txt` has such a hook (`SSL_read`), so it was reachable."""
    import io
    from capa.features.extractors.drakvuf.models import DrakvufReport

    rec = {"Plugin": "libmon", "Event": "api_called", "Method": "getaddrinfo",
           "TimeStamp": "1.0", "ProcessName": "s", "PID": 1, "PPID": 0, "TID": 1,
           "Arguments": ['Node=0x7f:"c2.test"']}          # note: no ReturnValue
    decoded = list(capa.decode_json_lines(io.StringIO(json.dumps(rec) + "\n")))

    assert decoded[0]["Plugin"] == "apimon"
    assert decoded[0]["ReturnValue"] == "0x0"             # synthetic, documented
    report = DrakvufReport.from_raw_report(iter(decoded))  # must not raise
    assert len(report.apicalls) == 1
    assert report.apicalls[0].name == "getaddrinfo"


def test_a_string_argument_becomes_a_matchable_string_feature(tmp_path):
    """**The single thing that made capa's 835 `string:` features reachable.**

    capa yields an argument value WHOLE (`extractors/drakvuf/call.py`), so a
    DRAKVUF string arrived as `0x7ffc1234:"Xen"` and measured 2026-09-27:
    `substring: Xen` matched, `string: /^Xen/i` and `string: Xen` did not.
    `--userhook-no-addr` does not fix it either -- it drops the address and
    leaves the quotes.

    Unescaping is part of it: DRAKVUF escapes a backslash, so a Windows path
    arrives as `C:\\\\Windows` and a rule naming `C:\\Windows` would miss."""
    import io
    from capa.features.common import String, Regex, Substring
    from capa.features.extractors.drakvuf.models import DrakvufReport
    from capa.features.extractors.drakvuf.call import extract_call_features
    from capa.features.address import ProcessAddress, ThreadAddress, DynamicCallAddress
    from capa.features.extractors.base_extractor import (
        ProcessHandle, ThreadHandle, CallHandle)

    rec = {"Plugin": "apimon", "Event": "api_called", "Method": "strcmp",
           "TimeStamp": "1.0", "ProcessName": "s", "PID": 1, "PPID": 0, "TID": 1,
           "ReturnValue": "0x0",
           "Arguments": ['a=0x7ffc1234:"Xen"', 'b=0x1:"C:\\\\Windows"', "n=0x10"]}
    decoded = list(capa.decode_json_lines(io.StringIO(json.dumps(rec) + "\n")))
    assert decoded[0]["Arguments"] == ["a=Xen", "b=C:\\Windows", "n=0x10"]

    report = DrakvufReport.from_raw_report(iter(decoded))
    pa = ProcessAddress(pid=1, ppid=0)
    ta = ThreadAddress(process=pa, tid=1)
    ch = CallHandle(DynamicCallAddress(thread=ta, id=0), inner=report.apicalls[0])
    feats: dict = {}
    for feature, addr in extract_call_features(
            ProcessHandle(pa, inner={}), ThreadHandle(ta, inner={}), ch):
        feats.setdefault(feature, set()).add(addr)

    assert bool(Regex("/^Xen/i").evaluate(feats))
    assert bool(String("Xen").evaluate(feats))
    assert bool(Substring("Xen").evaluate(feats))
    assert bool(String("C:\\Windows").evaluate(feats))     # unescaped
    # A non-string argument is untouched and still arrives as a Number.
    from capa.features.insn import Number
    assert bool(Number(16).evaluate(feats))


def test_windows_gets_apimon_or_the_hook_list_is_only_a_memdump_trigger(tmp_path):
    """`hooks.txt` is passed whenever memdump is selected, but memdump only uses
    it to decide where to dump. Without apimon there is no `apimon.log`, so
    capa's Windows dynamic pass reads `syscall.log` alone and the ~1,330 hooks
    produce no API features at all -- and the 175 file-scope rules get nothing,
    since `Import` comes from apimon's `dll_loaded` event."""
    from sandboxd import guests as G
    opts = G.default_trace_options(TargetOs.WINDOWS, G.SampleKind.PE)
    assert "apimon" in opts.plugins
