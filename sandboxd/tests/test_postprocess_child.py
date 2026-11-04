"""The postprocessing child: sandboxd/postprocessing/{child,__main__}.py.

Why there is one, in a sentence: on 2026-11-02 a 20-minute trace had the
daemon itself at 6.7 GiB and OOM-killed, because capa and falco build the
whole in-scope log in memory and did so in the daemon's own process.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd.postprocessing import child as C  # noqa: E402
from sandboxd.tests.fake import FakeRunner  # noqa: E402


def _runner(rc=0, stdout="", stderr="", timed_out=False) -> FakeRunner:
    r = FakeRunner()
    r.script((sys.executable, "-m", C.MODULE), rc=rc, stdout=stdout,
             stderr=stderr, timed_out=timed_out)
    return r


# --- the parent's side: argv, budget, notes ----------------------------------

def test_a_clean_run_has_no_note_and_the_exact_argv(tmp_path):
    r = _runner()
    note = C.postprocess_in_child(r, tmp_path, "ubuntu", 3, max_mib=1024,
                                  timeout=10.0)

    assert note is None
    (call,) = r.calls
    assert call.argv == (sys.executable, "-m", C.MODULE, str(tmp_path),
                         "--os", "ubuntu", "--max-mib", "1024", "--vlan", "3")
    assert call.timeout == 10.0
    assert call.what == "postprocess"


def test_no_vlan_means_no_vlan_argument(tmp_path):
    """Postprocessing outside a job -- the tests, a runbook -- has no clone
    and so no /24 for the Falco rules to call local."""
    r = _runner()
    C.postprocess_in_child(r, tmp_path, "windows", None, max_mib=1, timeout=1)

    assert "--vlan" not in r.calls[0].argv


def test_failed_plugins_are_named_in_the_note(tmp_path):
    r = _runner(rc=C.EXIT_PLUGIN_FAILED,
                stdout="some log line\n"
                       f"{C.FAILED_PREFIX} capa_analysis falco_analysis\n")
    note = C.postprocess_in_child(r, tmp_path, "ubuntu", 3, max_mib=1, timeout=1)

    assert note == ("postprocessing: capa_analysis, falco_analysis failed; "
                    "see sandboxd's log on Dom0")


def test_the_childs_peak_memory_reaches_the_daemons_log(tmp_path, caplog):
    """The number that sizes SANDBOXD_POSTPROCESS_MAX_MIB on a real trace,
    read in the child where the limit applies."""
    import logging
    r = _runner(stdout=f"{C.PEAK_PREFIX} 2621440\n")
    with caplog.at_level(logging.INFO, logger="sandboxd.postprocessing"):
        C.postprocess_in_child(r, tmp_path, "ubuntu", 3, max_mib=3072, timeout=1)

    assert "peak RSS 2560 MiB of the 3072 MiB limit" in caplog.text
    assert C._peak_mib("noise\npostprocessing-peak-rss-kib: notanumber\n") is None
    assert C._peak_mib("") is None


def test_a_failure_exit_without_the_summary_line_still_notes(tmp_path):
    r = _runner(rc=C.EXIT_PLUGIN_FAILED, stdout="")
    note = C.postprocess_in_child(r, tmp_path, "ubuntu", 3, max_mib=1, timeout=1)

    assert note == "postprocessing: a plugin failed; see sandboxd's log on Dom0"


def test_a_timeout_is_a_note(tmp_path):
    r = _runner(rc=None, timed_out=True)
    note = C.postprocess_in_child(r, tmp_path, "ubuntu", 3, max_mib=1,
                                  timeout=1800)

    assert "stopped at its 1800s budget" in note


def test_an_unexpected_exit_is_a_note(tmp_path):
    """137 is what SIGKILL from the kernel's OOM killer looks like -- the
    child with its limit off (SANDBOXD_POSTPROCESS_MAX_MIB=0)."""
    r = _runner(rc=137, stderr="Killed")
    note = C.postprocess_in_child(r, tmp_path, "ubuntu", 3, max_mib=0, timeout=1)

    assert "exited 137" in note


# --- the child's side: the limit, and the plugin loop ------------------------

def test_the_memory_limit_turns_an_overrun_into_a_memory_error():
    """What the whole arrangement relies on: under RLIMIT_DATA an allocation
    past the limit raises inside the plugin instead of growing until the
    kernel kills the largest process on the host -- which on 2026-11-02 was
    the daemon."""
    code = (
        f"import sys; sys.path.insert(0, {str(ROOT)!r})\n"
        "from sandboxd.postprocessing.__main__ import apply_memory_limit\n"
        "apply_memory_limit(256)\n"
        "try:\n"
        "    block = bytearray(512 * 1024 * 1024)\n"
        "except MemoryError:\n"
        "    print('contained')\n"
        "else:\n"
        "    print('not contained', len(block))\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, timeout=60)

    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "contained"


def test_a_plugin_that_raises_is_recorded_and_the_rest_still_run(tmp_path, monkeypatch):
    """`MemoryError` is an `Exception`, so the per-plugin handler catches it:
    one pass loses its output, the next runs, and report.json says which."""
    pytest.importorskip("capa")
    from sandboxd.guests import TargetOs
    from sandboxd.postprocessing import postprocess as P
    from sandboxd.postprocessing.plugins.plugin_base import (
        PostprocessContext, PostprocessingConfig, PostprocessPlugin)

    ran = []

    def boom(ctx):
        raise MemoryError("the trace is larger than the limit")

    def fine(ctx):
        ran.append("fine")

    monkeypatch.setattr(P, "POSTPROCESS_PLUGINS", [
        PostprocessPlugin(function=boom, requires=[], generates=[]),
        PostprocessPlugin(function=fine, requires=[], generates=[]),
    ])
    ctx = PostprocessContext(tmp_path, PostprocessingConfig(), TargetOs.UBUNTU)

    assert P.run_postprocessing(ctx) == ["boom"]
    assert ran == ["fine"]
    assert ctx.report["postprocessing_failures"] == [
        {"plugin": "boom",
         "error": "MemoryError: the trace is larger than the limit"}]
    assert P.postprocess_analysis_dir(tmp_path, PostprocessingConfig(),
                                      TargetOs.UBUNTU) == ["boom"]


# --- keeping less: capa by offset, falco by merge ----------------------------

def _call_logs(d: Path) -> None:
    """Two processes, one of them two threads, calls across two logs."""
    sys_lines = [
        {"Plugin": "syscall", "TimeStamp": "1000.000100", "PID": 10, "PPID": 1, "TID": 10,
         "UserName": "u", "UserId": 1000, "ProcessName": "/tmp/s", "Method": "openat",
         "EventUID": "0x1", "Module": "linux", "vCPU": 0, "CR3": "0x1", "Syscall": 257,
         "NArgs": 2, "pathname": '"/etc/passwd"', "flags": "0x0", "FromModule": "libc"},
        {"Plugin": "syscall", "TimeStamp": "1000.000300", "PID": 10, "PPID": 1, "TID": 11,
         "UserName": "u", "UserId": 1000, "ProcessName": "/tmp/s", "Method": "write",
         "EventUID": "0x3", "Module": "linux", "vCPU": 0, "CR3": "0x1", "Syscall": 1,
         "NArgs": 1, "fd": "0x1"},
        {"Plugin": "syscall", "TimeStamp": "1000.000400", "PID": 20, "PPID": 10, "TID": 20,
         "UserName": "u", "UserId": 1000, "ProcessName": "/bin/cat", "Method": "read",
         "EventUID": "0x4", "Module": "linux", "vCPU": 0, "CR3": "0x2", "Syscall": 0,
         "NArgs": 1, "fd": "0x3"},
        {"Plugin": "syscall", "TimeStamp": "1000.000500", "PID": 99, "PPID": 1, "TID": 99,
         "UserName": "u", "UserId": 0, "ProcessName": "/usr/sbin/cron", "Method": "nanosleep",
         "EventUID": "0x5", "Module": "linux", "vCPU": 0, "CR3": "0x3", "Syscall": 35, "NArgs": 0},
    ]
    lib_lines = [
        {"Plugin": "libmon", "TimeStamp": "1000.000200", "PID": 10, "PPID": 1, "TID": 10,
         "UserId": 1000, "ProcessName": "/tmp/s", "Method": "fopen", "Event": "api_called",
         "Library": "/lib/libc.so.6", "CalledFrom": "0x1", "ReturnValue": "0x55",
         "Arguments": ['Path=0x7f:"/etc/passwd"', "Mode=0x1"], "EventUID": "0x2"},
    ]
    import json
    (d / "syscall.log").write_text("".join(json.dumps(x) + "\n" for x in sys_lines))
    (d / "libmon.log").write_text("".join(json.dumps(x) + "\n" for x in lib_lines))


def test_the_streaming_extractor_sees_what_capas_own_sees(tmp_path):
    """Same processes, threads, calls in the same order with the same
    features -- the only difference is what stays in memory."""
    pytest.importorskip("capa")
    from capa.features.extractors.drakvuf.extractor import DrakvufExtractor
    from sandboxd.postprocessing.plugins.capa_plugin import capa_processor as CP
    from sandboxd.postprocessing.plugins.capa_plugin.streaming import StreamingDrakvufExtractor

    _call_logs(tmp_path)

    def walk(extractor):
        out = []
        for ph in extractor.get_processes():
            for th in extractor.get_threads(ph):
                for ch in extractor.get_calls(ph, th):
                    feats = sorted(str(f) for f, _ in extractor.extract_call_features(ph, th, ch))
                    out.append((ph.address.pid, th.address.tid, ch.address.id,
                                extractor.get_call_name(ph, th, ch), feats))
        return out

    def records():
        for name in CP.CALL_LOGS:
            p = tmp_path / name
            if p.exists():
                with p.open() as fd:
                    yield from CP.decode_json_lines(fd, [10, 20])

    theirs = walk(DrakvufExtractor.from_report(records()))
    ours_x = StreamingDrakvufExtractor(tmp_path, CP.CALL_LOGS, CP.normalise_record, {10, 20})
    ours = walk(ours_x)

    assert ours == theirs
    assert [c[0] for c in ours] == [10, 10, 10, 20]      # pid 99 filtered out
    assert ours_x.records == 4 and ours_x.rejected == 0
    # The libmon call was relabelled, its string argument unwrapped, and the
    # syscall's FromModule did not become a feature.
    names = [c[3] for c in ours]
    assert any(n.startswith("fopen(Path=/etc/passwd") for n in names)
    assert not any("FromModule" in n for n in names)
    assert sorted(str(f) for f, _ in ours_x.extract_global_features()) == sorted(
        str(f) for f, _ in DrakvufExtractor.from_report(records()).extract_global_features())


def test_falcos_merge_replays_logs_in_event_order_without_holding_them(tmp_path):
    """A sysret written three lines before its syscall still pairs; records
    further apart than the window arrive late rather than never."""
    from sandboxd.postprocessing.falco import events as E
    import json

    def rec(plugin, uid, **extra):
        base = {"Plugin": plugin, "TimeStamp": f"{1000 + uid / 1000:.6f}", "PID": 100,
                "PPID": 1, "TID": 100, "UserId": 0, "ProcessName": "/bin/sh",
                "EventUID": hex(uid), "ThreadName": "sh"}
        return {**base, **extra}

    def write(name, objs):
        (tmp_path / name).write_text("".join(json.dumps(o) + "\n" for o in objs))

    write("inject.log", [{"Plugin": "inject", "Method": "ExecProc", "Status": "Success",
                          "ProcessName": "/bin/sh", "InjectedPid": 100, "InjectedTid": 100}])
    # syscall.log slightly out of order on purpose: 0x12 before 0x11.
    write("syscall.log", [rec("syscall", 0x10, Method="openat", Syscall=257, NArgs=1, pathname='"/a"'),
                          rec("syscall", 0x12, Method="close", Syscall=3, NArgs=1, fd="0x3"),
                          rec("syscall", 0x11, Method="read", Syscall=0, NArgs=1, fd="0x3")])
    write("sysret.log", [rec("sysret", 0x13, Method="close", Syscall=3, Ret="0x0"),
                         rec("sysret", 0x14, Method="openat", Syscall=257, Ret="0x3")])
    write("filetracer.log", [rec("filetracer", 0x10, Method="do_syscall_64", Syscall="openat",
                                 FileName="/resolved/a")])

    trace = E.Trace(tmp_path, E.TraceConfig(reorder_window=8), None, set(), {100})
    order = [(uid, kind) for uid, _, kind, _ in trace._records()]
    assert [u for u, _ in order] == sorted(u for u, _ in order)
    assert order[0] == (-1, "inject")
    assert order[1:3] == [(0x10, "filetracer"), (0x10, "syscall")]

    events = list(trace)
    by_type = {e.type: e for e in events}
    # filetracer's reading replaced the raw path (rendered as Falco's `name`
    # argument), and was dropped once used.
    assert by_type["openat"].args.get("name") == "/resolved/a"
    assert trace.filetracer == {}
    assert trace.stats.records == {"inject": 1, "filetracer": 1, "syscall": 3, "sysret": 2}

    # A record further out than the window is late, not lost: a small UID
    # arriving after more than `window` larger ones is yielded when it
    # arrives, behind records it should have preceded. Nothing is dropped,
    # and a large UID that came early simply waits in the heap.
    stream = [(2, 0, "a", {}), (3, 0, "b", {}), (4, 0, "c", {}), (5, 0, "d", {}), (1, 0, "e", {})]
    late = list(E._windowed(stream, 2))
    assert [x[0] for x in late] == [2, 3, 1, 4, 5]
    exact = list(E._windowed(stream, 4))
    assert [x[0] for x in exact] == [1, 2, 3, 4, 5]
    early_large = list(E._windowed([(9, 0, "a", {}), (1, 0, "b", {}), (2, 0, "c", {})], 1))
    assert [x[0] for x in early_large] == [1, 2, 9]


def test_gzip_covers_apimon_and_runs_after_everything_that_reads_it(tmp_path):
    """3.9 GB of raw apimon.log from one 20-minute Windows trace (2026-11-02)
    is why it joined syscall and sysret; get_http_info reads it, so the step
    has to come after that plugin and before index_logs."""
    pytest.importorskip("capa")
    import gzip
    from sandboxd.guests import TargetOs
    from sandboxd.postprocessing.plugins import POSTPROCESS_PLUGINS
    from sandboxd.postprocessing.plugins.gzip_syscalls import GZIPPED_LOGS, gzip_syscalls
    from sandboxd.postprocessing.plugins.plugin_base import PostprocessContext, PostprocessingConfig

    names = [p.function.__name__ for p in POSTPROCESS_PLUGINS]
    assert names.index("gzip_syscalls") > names.index("get_http_info")
    assert names.index("gzip_syscalls") > names.index("falco_analysis")
    assert names.index("gzip_syscalls") < names.index("index_logs")
    gz = next(p for p in POSTPROCESS_PLUGINS if p.function is gzip_syscalls)
    assert gz.requires == [], "a job without syscall.log still has apimon.log to compress"
    assert set(gz.generates) == {f"{n}.log.gz" for n in GZIPPED_LOGS}

    for name in ("syscall", "apimon", "regmon"):
        (tmp_path / f"{name}.log").write_bytes(b'{"Plugin":"%s"}\n' % name.encode())
    gzip_syscalls(PostprocessContext(tmp_path, PostprocessingConfig(), TargetOs.WINDOWS))

    assert not (tmp_path / "apimon.log").exists()
    assert gzip.open(tmp_path / "apimon.log.gz").read() == b'{"Plugin":"apimon"}\n'
    assert not (tmp_path / "syscall.log").exists()
    assert (tmp_path / "regmon.log").exists(), "only the listed logs are replaced"
    assert not (tmp_path / "sysret.log.gz").exists(), "absent logs are skipped, not invented"


def test_the_split_writes_compact_lines(tmp_path):
    from sandboxd.guests import TargetOs
    from sandboxd.postprocessing.plugins.plugin_base import PostprocessContext, PostprocessingConfig
    from sandboxd.postprocessing.plugins.split_drakvuf_log import split_drakvuf_log

    (tmp_path / "trace.log").write_bytes(
        b'{"Plugin": "syscall", "PID": 1, "Method": "openat", "Name": "caf\\u00e9"}\n'
        b'not json\n'
        b'{"Plugin": "../x", "PID": 2}\n')
    split_drakvuf_log(PostprocessContext(tmp_path, PostprocessingConfig(), TargetOs.UBUNTU))

    assert (tmp_path / "syscall.log").read_bytes() == \
        '{"Plugin":"syscall","PID":1,"Method":"openat","Name":"café"}\n'.encode()
    assert (tmp_path / "unknown.log").read_bytes() == b'{"Plugin":"../x","PID":2}\n'
    assert (tmp_path / "parse_errors.log").read_bytes() == b"not json\n"
    assert not (tmp_path / "trace.log").exists()


def test_the_entry_point_runs_and_names_what_failed(tmp_path):
    """Through the real `python -m sandboxd.postprocessing`, on a directory
    with no trace: whatever plugins run must end in the exit code and the
    summary line the parent parses, never a traceback out of main."""
    pytest.importorskip("capa")
    out = subprocess.run(
        [sys.executable, "-m", C.MODULE, str(tmp_path), "--os", "ubuntu",
         "--max-mib", "0"],
        capture_output=True, text=True, cwd=ROOT, timeout=300)

    assert out.returncode in (0, C.EXIT_PLUGIN_FAILED), out.stderr[-2000:]
    if out.returncode == C.EXIT_PLUGIN_FAILED:
        assert out.stdout.splitlines()[-1].startswith(C.FAILED_PREFIX)
    else:
        assert C.FAILED_PREFIX not in out.stdout
