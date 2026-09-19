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
from sandboxd.postprocessing.plugins.process_dumps import process_dumps  # noqa: E402
from sandboxd.postprocessing.plugins.split_drakvuf_log import split_drakvuf_log  # noqa: E402
from sandboxd.postprocessing import indexer, postprocess, process_tree  # noqa: E402


SAMPLES = ROOT / "samples"


def context(tmp_path, os_=TargetOs.WINDOWS, **env) -> plugin_base.PostprocessContext:
    return plugin_base.PostprocessContext(tmp_path, plugin_base.PostprocessingConfig(**env), os_)


def jsonl(path: Path, *objs) -> Path:
    path.write_text("".join(json.dumps(o) + "\n" for o in objs))
    return path


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
