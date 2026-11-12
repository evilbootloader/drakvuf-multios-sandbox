"""CAPE's processing over a DRAKVUF trace.log (postprocessing/plugins/cape_plugin).

Synthetic traces shaped like `samples/job-windows` and `samples/job-linux`,
surveyed 2026-11-09: EventUID as a hex string, out of order by a few
positions, absent on apimon's dll events and `0x0` on cpuidmon; syscall and
sysret paired by (PID, TID, Syscall) and nothing else.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd.guests import TargetOs  # noqa: E402
import importlib  # noqa: E402

# The module, not the plugin function `plugins/__init__` binds under its name.
cape_analysis = importlib.import_module("sandboxd.postprocessing.plugins.cape_analysis")
from sandboxd.postprocessing.plugins.cape_plugin import api_tables, capa_integration  # noqa: E402
from sandboxd.postprocessing.plugins.cape_plugin.behaviour import CapeOptions, Processes, resolved_path  # noqa: E402
from sandboxd.postprocessing.plugins.cape_plugin.trace_split import split_by_process  # noqa: E402
from sandboxd.postprocessing.plugins.plugin_base import (  # noqa: E402
    CapeConfigSection, PostprocessContext, PostprocessingConfig,
)

CMD = "\\Device\\HarddiskVolume2\\Windows\\System32\\cmd.exe"


def rec(plugin, uid, pid, tid=1, ppid=4, method="X", **extra):
    out = {"Plugin": plugin, "TimeStamp": f"{1000 + (uid or 0) / 1000:.6f}", "PID": pid,
           "PPID": ppid, "TID": tid, "ProcessName": CMD, "Method": method}
    if uid is not None:
        out["EventUID"] = hex(uid)
    out.update(extra)
    return out


def inject(pid):
    return {"Plugin": "inject", "TimeStamp": "1000.0", "Method": "ShellExec",
            "Status": "Success", "ProcessName": CMD, "InjectedPid": pid}


def running(pid, ppid, name):
    return {"Plugin": "procmon", "PID": pid, "PPID": ppid, "RunningProcess": name}


def create(uid, pid, new_pid, image="C:\\Windows\\System32\\PING.EXE"):
    # Windows procmon prints the command line through g_strescape
    # (procmon/win.cpp): a backslash doubled, a quote escaped.
    escaped = image.replace("\\", "\\\\").replace('"', '\\"')
    return rec("procmon", uid, pid, method="NtCreateUserProcess", Status="0x0", NewPid=new_pid,
               CommandLine=escaped, ImagePathName=image)


def write_trace(tmp_path, *records) -> Path:
    (tmp_path / "trace.log").write_text("".join(json.dumps(r) + "\n" for r in records))
    return tmp_path


def split(tmp_path, *records, os_=TargetOs.WINDOWS, **kw):
    job = write_trace(tmp_path, *records)
    return split_by_process(job, tmp_path / "logs", os_, **kw)


def lines(path: Path) -> list:
    return [json.loads(line) for line in path.read_text().splitlines()]


def by_pid(result) -> dict:
    return {result.tree.processes[s].pid: lines(f) for s, f in result.files.items()}


BASE = [inject(100), running(4, 0, "System"), running(50, 4, "explorer.exe"),
        running(100, 50, CMD)]


# --- the split ---------------------------------------------------------------

def test_only_the_sample_and_its_descendants_get_a_log(tmp_path):
    r = split(tmp_path, *BASE, create(0x10, 100, 200),
              rec("apimon", 0x11, 200, Event="api_called", Method="Sleep", ReturnValue="0x0"),
              rec("apimon", 0x12, 50, Event="api_called", Method="Sleep", ReturnValue="0x0"))
    assert set(by_pid(r)) == {100, 200}
    assert r.sample_pids == {100, 200}
    assert r.stats.out_of_scope == 1


def test_scope_all_keeps_every_process_and_still_names_the_sample(tmp_path):
    r = split(tmp_path, *BASE, rec("regmon", 0x10, 100, method="NtOpenKey", Key="k"),
              rec("regmon", 0x11, 50, method="NtOpenKey", Key="k"), scope="all")
    assert set(by_pid(r)) == {50, 100}
    assert r.sample_pids == {100}


def test_every_log_starts_with_the_process_header(tmp_path):
    r = split(tmp_path, *BASE, create(0x10, 100, 200),
              rec("regmon", 0x11, 200, ppid=100, method="NtOpenKey", Key="k"))
    for pid, recs in by_pid(r).items():
        assert recs[0]["Plugin"] == "__process__" and recs[0]["PID"] == pid
        assert all(x["Plugin"] != "__process__" for x in recs[1:])
    assert by_pid(r)[200][0]["ProcessName"] == "PING.EXE"
    assert by_pid(r)[200][0]["PPID"] == 100


def test_records_come_out_in_eventuid_order(tmp_path):
    uids = [0x15, 0x12, 0x14, 0x11, 0x13]
    r = split(tmp_path, *BASE, *(rec("regmon", u, 100, method="NtOpenKey", Key="k") for u in uids))
    assert [x["EventUID"] for x in by_pid(r)[100][1:]] == [hex(u) for u in sorted(uids)]


def test_a_reused_pid_is_two_processes_split_at_the_second_creation(tmp_path):
    r = split(tmp_path, *BASE,
              create(0x10, 100, 200),
              rec("regmon", 0x11, 200, method="NtOpenKey", Key="first"),
              rec("procmon", 0x12, 200, method="NtTerminateProcess", ExitPid=200,
                  ExitStatus="0x0", ExitStatusStr="STATUS_SUCCESS"),
              create(0x20, 100, 200, image="C:\\second.exe"),
              rec("regmon", 0x21, 200, method="NtOpenKey", Key="second"))
    logs = [lines(f) for s, f in r.files.items() if r.tree.processes[s].pid == 200]
    assert len(logs) == 2
    keys = [[x.get("Key") for x in recs if x["Plugin"] == "regmon"] for recs in logs]
    assert sorted(keys) == [["first"], ["second"]]


def test_records_without_an_eventuid_stay_where_drakvuf_wrote_them(tmp_path):
    # apimon's dll events carry none, and cpuidmon's is always 0x0.
    r = split(tmp_path, *BASE,
              rec("regmon", 0x30, 100, method="NtOpenKey", Key="before"),
              {"Plugin": "apimon", "Event": "dll_loaded", "PID": 100, "DllName": "a.dll",
               "DllBase": "0x1000"},
              rec("cpuidmon", 0, 100, Leaf=1, Subleaf=0, RAX=1, RBX=2, RCX=3, RDX=4),
              rec("regmon", 0x31, 100, method="NtOpenKey", Key="after"))
    assert [x["Plugin"] for x in by_pid(r)[100][1:]] == ["regmon", "apimon", "cpuidmon", "regmon"]


def test_a_syscall_is_written_at_its_return_with_the_result(tmp_path):
    r = split(tmp_path, *BASE,
              rec("syscall", 0x10, 100, method="NtCreateFile", Syscall=85, PreviousMode="User"),
              rec("regmon", 0x11, 100, method="NtOpenKey", Key="during"),
              rec("sysret", 0x12, 100, method="NtCreateFile", Syscall=85, Ret="0x0",
                  Info="STATUS_SUCCESS"))
    recs = by_pid(r)[100][1:]
    assert [x["Plugin"] for x in recs] == ["regmon", "syscall"]
    assert recs[1]["Ret"] == "0x0" and recs[1]["Info"] == "STATUS_SUCCESS"
    assert (r.stats.syscalls_paired, r.stats.syscalls_unpaired) == (1, 0)


def test_a_nested_kernel_syscall_does_not_take_its_parents_return(tmp_path):
    r = split(tmp_path, *BASE,
              rec("syscall", 0x10, 100, method="NtDeviceIoControlFile", Syscall=7, PreviousMode="User"),
              rec("syscall", 0x11, 100, method="NtQueryInformationToken", Syscall=33,
                  PreviousMode="Kernel"),
              rec("sysret", 0x12, 100, method="NtQueryInformationToken", Syscall=33, Ret="0x5"),
              rec("sysret", 0x13, 100, method="NtDeviceIoControlFile", Syscall=7, Ret="0x103"))
    recs = by_pid(r)[100][1:]
    assert [(x["Method"], x["Ret"]) for x in recs] == [("NtDeviceIoControlFile", "0x103")]
    assert r.stats.kernel_syscalls_dropped == 1


def test_a_syscall_that_never_returns_is_kept_without_a_result(tmp_path):
    r = split(tmp_path, *BASE,
              rec("syscall", 0x10, 100, method="NtContinue", Syscall=67, PreviousMode="User"),
              rec("syscall", 0x11, 100, method="NtClose", Syscall=15, PreviousMode="User"),
              rec("sysret", 0x12, 100, method="NtClose", Syscall=15, Ret="0x0"))
    recs = by_pid(r)[100][1:]
    assert [(x["Method"], x.get("Ret")) for x in recs] == [("NtContinue", None), ("NtClose", "0x0")]
    assert r.stats.syscalls_unpaired == 1


def test_a_trace_without_sysret_keeps_every_syscall(tmp_path):
    r = split(tmp_path, *BASE,
              rec("syscall", 0x10, 100, method="NtClose", Syscall=15, PreviousMode="User"),
              rec("syscall", 0x11, 100, method="NtClose", Syscall=15, PreviousMode="User"))
    assert len(by_pid(r)[100]) == 3


def test_a_process_the_sample_makes_run_code_is_the_samples(tmp_path):
    # explorer (50) starts 60, then the sample (100) starts a thread in it,
    # then explorer starts 70: 70 may run the sample's code, 60 never did
    r = split(tmp_path, *BASE,
              create(0x10, 50, 60),
              rec("memdump", 0x20, 100, method="NtCreateThreadEx", DumpReason="CreateRemoteThread heuristic",
                  DumpPID=50, DumpAddr="0x1000", DumpSize="0x1000", DumpFilename="x"),
              create(0x30, 50, 70),
              rec("syscall", 0x40, 50, method="NtClose", Syscall=15, PreviousMode="User"))
    assert r.sample_pids == {100, 50, 70}
    assert r.followed == [{"pid": 100, "target_pid": 50, "time": 1000.032,
                           "how": "memdump CreateRemoteThread heuristic"}]
    assert 50 in by_pid(r)


def test_a_write_alone_is_not_followed_but_a_register_change_is(tmp_path):
    # Linux, no procmon: the targets join at their first record
    r = split(tmp_path, inject(100),
              # Bytes placed in 200, nothing makes it run them
              rec("ptracemon", 0x10, 100, ppid=1, method="ptrace", Type="PTRACE_POKEDATA", TargetPID=200),
              # 300's instruction pointer set: it runs what 100 chose
              rec("ptracemon", 0x11, 100, ppid=1, method="ptrace", Type="PTRACE_SETREGS", TargetPID=300),
              rec("syscall", 0x12, 200, ppid=1, method="openat", Syscall=257),
              rec("syscall", 0x13, 300, ppid=1, method="openat", Syscall=257),
              os_=TargetOs.UBUNTU)
    assert r.sample_pids == {100, 300}
    assert [(f["target_pid"], f["how"]) for f in r.followed] == [(300, "ptrace PTRACE_SETREGS")]


def test_a_followed_process_is_followed_in_turn_from_then_on(tmp_path):
    r = split(tmp_path, *BASE,
              running(400, 4, "svchost.exe"), running(500, 4, "spoolsv.exe"),
              # explorer's own, before the sample took it over: not followed
              rec("memdump", 0x10, 50, method="NtResumeThread", DumpReason="SetThreadContext heuristic",
                  DumpPID=500),
              rec("memdump", 0x20, 100, method="NtCreateThreadEx", DumpReason="CreateRemoteThread heuristic",
                  DumpPID=50),
              # after: the sample's code in explorer did it
              rec("memdump", 0x30, 50, method="NtResumeThread", DumpReason="SetThreadContext heuristic",
                  DumpPID=400))
    assert r.sample_pids == {100, 50, 400}
    assert [(f["pid"], f["target_pid"]) for f in r.followed] == [(100, 50), (50, 400)]


def test_without_procmon_the_sample_is_found_by_pid_and_ppid(tmp_path):
    # sandbox_project/samples/trace-linux.log: no procmon at all.
    r = split(tmp_path, inject(100),
              rec("syscall", 0x10, 100, ppid=1, method="openat", Syscall=257),
              rec("syscall", 0x11, 200, ppid=100, method="openat", Syscall=257),
              rec("syscall", 0x12, 300, ppid=1, method="openat", Syscall=257),
              os_=TargetOs.UBUNTU)
    assert set(by_pid(r)) == {100, 200}
    assert r.stats.nodes_added == 3


# --- the CAPE process list -----------------------------------------------------

def processes(tmp_path, *records, os_=TargetOs.WINDOWS):
    split(tmp_path, *records, os_=os_)
    return Processes(str(tmp_path / "logs"), None, CapeOptions(), os_).run()


def test_processes_have_capes_schema_and_calls_that_iterate_twice(tmp_path):
    procs = processes(
        tmp_path, *BASE,
        rec("apimon", 0x10, 100, tid=7, Event="api_called", Method="RegOpenKeyExW",
            ReturnValue="0x0", CalledFrom="0x7ff0",
            Arguments=["hKey=0x80000002", 'lpSubKey=0x1f0:"SOFTWARE\\\\Valve"']),
        rec("regmon", 0x11, 100, tid=7, method="NtSetValueKey", Key="\\REGISTRY\\K",
            ValueName="v", Value="01"))
    assert len(procs) == 1
    p = procs[0]
    # CAPE's process, and trace_split's identity of it for the platform
    assert set(p) == {"process_id", "process_name", "parent_id", "module_path", "first_seen",
                      "calls", "threads", "environ", "file_activities",
                      "seqid", "parent_seqid", "started_ts", "exited_ts", "exit_code",
                      "exit_code_str", "killed_by"}
    assert (p["process_id"], p["process_name"], p["parent_id"]) == (100, "cmd.exe", 50)
    first, second = list(p["calls"]), list(p["calls"])
    # apimon's record is an `api` call; regmon's, from the kernel, a `syscall` one.
    names = [(c.get("api"), c.get("syscall")) for c in first]
    assert names == [("RegOpenKeyExW", None), (None, "NtSetValueKey")]
    assert names == [(c.get("api"), c.get("syscall")) for c in second]
    for call in first:
        assert {"category", "status", "return", "arguments", "repeated", "thread_id",
                "timestamp", "id"} <= set(call)
        # Every value text, as capemon logs it, and its raw_value beside it.
        assert all(isinstance(a["value"], str) and a["raw_value"] == a["value"]
                   for a in call["arguments"])
    assert p["threads"] == ["7"]


def test_arguments_carry_capes_names_beside_the_prototypes(tmp_path):
    procs = processes(
        tmp_path, *BASE,
        rec("apimon", 0x10, 100, Event="api_called", Method="RegOpenKeyExW", ReturnValue="0x0",
            Arguments=["hKey=0x80000002", 'lpSubKey=0x1f0:"SOFTWARE\\\\Valve"']),
        rec("regmon", 0x11, 100, method="NtSetValueKey", Key="\\REGISTRY\\K", ValueName="v",
            Value="01"))
    reg_open, set_value = list(procs[0]["calls"])
    args = {a["name"]: a["value"] for a in reg_open["arguments"]}
    # The string is unquoted and unescaped, and present under both names.
    assert args["lpSubKey"] == args["SubKey"] == "SOFTWARE\\Valve"
    args = {a["name"]: a["value"] for a in set_value["arguments"]}
    assert args["FullName"] == "\\REGISTRY\\K\\v" and args["Buffer"] == "01"
    # A predefined key and a sub-key, with nothing kernel-side to resolve them.
    args = {a["name"]: a["value"] for a in reg_open["arguments"]}
    assert args["FullName"] == "HKEY_LOCAL_MACHINE\\SOFTWARE\\Valve"


# The interactive user's hive, as regmon prints it.
USER_KEY = "\\REGISTRY\\USER\\S-1-5-21-11-22-33-1000\\SOFTWARE\\Valve"


def set_value(uid, value_name="Count", tid=1):
    """One RegSetValueExW reaching the trace as DRAKVUF records it, in order:
    the service's entry, regmon inside it, its return, apimon's ntdll stub,
    then the Win32 function apimon also hooks."""
    return [
        rec("syscall", uid, 100, tid=tid, method="NtSetValueKey", Syscall=96, PreviousMode="User",
            KeyHandle="0x49c", ValueName=value_name, Type="0x4", Data="0x40b5d8", DataSize="0x4"),
        rec("regmon", uid + 1, 100, tid=tid, method="NtSetValueKey", Key=USER_KEY,
            ValueName=value_name, Value="0d 00 00 00"),
        rec("sysret", uid + 2, 100, tid=tid, method="NtSetValueKey", Syscall=96, Ret="0x0",
            Info="STATUS_SUCCESS"),
        rec("apimon", uid + 3, 100, tid=tid, Event="api_called", Method="NtSetValueKey",
            ReturnValue="0x0", Caller="0x402005",
            Arguments=["KeyHandle=0x49c", f'ValueName=0x1:"{value_name}"', "TitleIndex=0x0",
                       "Type=0x4", "Data=0x40b5d8", "DataSize=0x4"]),
        rec("apimon", uid + 4, 100, tid=tid, Event="api_called", Method="RegSetValueExW",
            # capemon's caller: the first return address outside the system
            # DLLs, the sample's -- the same for the ntdll stub under it.
            # No ParentCaller: DRAKVUF prints none.
            ReturnValue="0x0", Caller="0x402005",
            Arguments=["hKey=0x49c", "Key=" + USER_KEY, f'lpValueName=0x2:"{value_name}"',
                       "Reserved=0x0", "dwType=0x4", 'lpData=0x3:"\\r"', "cbData=0x4"]),
    ]


def by_name(call):
    return {a["name"]: a["value"] for a in call["arguments"]}


def test_an_api_call_takes_what_the_kernel_saw_of_it(tmp_path):
    calls = list(processes(tmp_path, *BASE, *set_value(0x20))[0]["calls"])
    kinds = [("api" if "api" in c else "syscall", c.get("api") or c.get("syscall"), c["plugin"])
             for c in calls]
    # Nothing dropped: the service as a syscall call (regmon folded in), and
    # both API records as api calls.
    assert kinds == [("syscall", "NtSetValueKey", "syscall"),
                     ("api", "NtSetValueKey", "apimon"),
                     ("api", "RegSetValueExW", "apimon")]
    for call in calls:
        args = by_name(call)
        # capemon's names: the key in HKEY form with the value's name, and
        # the data decoded by its type -- a DWORD in decimal.
        assert args["FullName"] == "HKEY_CURRENT_USER\\SOFTWARE\\Valve\\Count", call
        assert args["Buffer"] == "13", call
    assert (calls[2]["caller"], calls[2]["parentcaller"]) == ("0x402005", "0x00000000")


@pytest.mark.parametrize("source", ["apimon", "syscall"])
def test_an_object_is_named_as_capemon_names_it(tmp_path, source):
    # DRAKVUF puts what an OBJECT_ATTRIBUTES names under capemon's name for
    # it (drakvuf plugins/helpers/object_attributes.h), from apimon as an
    # appended argument and from the syscall plugin as a key of its record.
    services = [
        ("NtOpenKey", [("KeyHandle", "0x5ffd38")], "Key", USER_KEY),
        ("NtCreateMutant", [("MutantHandle", "0x5ffd30")], "MutexName", "Local\\OnlyOne"),
        ("NtCreateSection", [("SectionHandle", "0x5ffd28")], "ObjectName", "Local\\SharedMap"),
    ]
    records = []
    for n, (service, before, label, value) in enumerate(services):
        if source == "apimon":
            records.append(rec("apimon", 0x10 + n, 100, Event="api_called", Method=service,
                               ReturnValue="0x0",
                               Arguments=[f"{k}={v}" for k, v in before]
                               + ["DesiredAccess=0x1", "ObjectAttributes=0x5ffd00", f"{label}={value}"]))
        else:
            records.append(rec("syscall", 0x10 + n, 100, method=service, Syscall=0x20 + n,
                               PreviousMode="User", DesiredAccess="0x1",
                               ObjectAttributes="0x5ffd00", **dict(before), **{label: value}))
    calls = {c.get("api") or c.get("syscall"): by_name(c)
             for c in processes(tmp_path, *BASE, *records)[0]["calls"]}

    assert calls["NtOpenKey"]["FullName"] == "HKEY_CURRENT_USER\\SOFTWARE\\Valve"
    # Where capemon logs the name in place of the argument (creates_nullvalue,
    # injection_explorer and others read it there).
    assert calls["NtOpenKey"]["ObjectAttributes"] == USER_KEY
    assert calls["NtCreateSection"]["ObjectAttributes"] == "Local\\SharedMap"
    assert calls["NtCreateMutant"]["MutexName"] == "Local\\OnlyOne"
    assert calls["NtCreateMutant"]["ObjectAttributes"] == "0x5ffd00"   # it has a name of its own
    assert "FileName" not in calls["NtCreateMutant"]


def test_an_api_call_takes_the_key_the_syscall_plugin_named(tmp_path):
    # RegOpenKeyExW on a handle apimon could not resolve: the key comes from
    # the service under it, and is the key OPENED -- the sub-key is in it.
    calls = list(processes(
        tmp_path, *BASE,
        rec("syscall", 0x10, 100, method="NtOpenKeyEx", Syscall=0x30, PreviousMode="User",
            KeyHandle="0x5ffd38", DesiredAccess="0x20019", ObjectAttributes="0x5ffd00",
            OpenOptions="0x0", Key=USER_KEY),
        rec("sysret", 0x11, 100, method="NtOpenKeyEx", Syscall=0x30, Ret="0x0"),
        rec("apimon", 0x12, 100, Event="api_called", Method="RegOpenKeyExW", ReturnValue="0x0",
            Arguments=["hKey=0x49c", 'lpSubKey=0x5ffd40:"Valve"', "ulOptions=0x0",
                       "samDesired=0x20019", "phkResult=0x5ffd38"]),
    )[0]["calls"])
    wrapper = next(c for c in calls if c.get("api") == "RegOpenKeyExW")
    assert "syscall" in wrapper["sources"]
    assert by_name(wrapper)["FullName"] == "HKEY_CURRENT_USER\\SOFTWARE\\Valve"


def test_a_kernel_record_belongs_to_one_call_of_an_api(tmp_path):
    second = set_value(0x30)[4]                 # RegSetValueExW alone, no service under it
    calls = list(processes(tmp_path, *BASE, *set_value(0x20), second)[0]["calls"])
    first_wrapper, second_wrapper = calls[2], calls[3]
    assert "regmon" in first_wrapper["sources"]
    assert "sources" not in second_wrapper      # the record was the first call's
    # Still named, from what apimon resolved itself (`Key=`).
    assert by_name(second_wrapper)["FullName"] == "HKEY_CURRENT_USER\\SOFTWARE\\Valve\\Count"


def test_a_wrapper_takes_the_record_of_the_value_it_names(tmp_path):
    # The nearest record names another value: the wrapper looks past it.
    records = set_value(0x20, "Count")[:3] + set_value(0x30, "Other")[:3] + [set_value(0x40)[4]]
    calls = list(processes(tmp_path, *BASE, *records)[0]["calls"])
    wrapper = calls[-1]
    assert wrapper["api"] == "RegSetValueExW" and "regmon" in wrapper["sources"]
    assert by_name(wrapper)["FullName"].endswith("\\Count") and by_name(wrapper)["Buffer"] == "13"


def test_procmon_is_a_syscall_call_with_capes_names(tmp_path):
    calls = list(processes(tmp_path, *BASE, create(0x10, 100, 200))[0]["calls"])
    assert [(c.get("syscall"), c["plugin"]) for c in calls] == [("NtCreateUserProcess", "procmon")]
    args = by_name(calls[0])
    assert args["CommandLine"] == "C:\\Windows\\System32\\PING.EXE"     # g_strescape undone
    assert args["ProcessId"] == "200"                                   # decimal, as capemon


def test_a_path_is_given_as_capemon_gives_it(tmp_path):
    calls = list(processes(
        tmp_path, *BASE,
        rec("filetracer", 0x10, 100, method="NtCreateFile", FileName="\\??\\C:\\x.txt",
            FileHandle="0x60", DesiredAccess="GENERIC_WRITE"))[0]["calls"])
    assert by_name(calls[0])["FileName"] == "C:\\x.txt"
    assert by_name(calls[0])["DesiredAccess"] == "0x40000000"
    assert calls[0]["filename"] == "\\??\\C:\\x.txt"


def test_a_line_with_a_raw_control_character_is_kept(tmp_path):
    # apimon appends what it resolves unescaped (jsonfmt.h quotes an Rstr
    # with std::quoted): a file named \x01 makes the line invalid JSON.
    good = json.dumps(rec("apimon", 0x10, 100, Event="api_called", Method="NtCreateFile",
                          ReturnValue="0x0", Arguments=["FileName=\\X\x01"]))
    raw = good.replace("\\u0001", "\x01")
    assert "\x01" in raw
    job = write_trace(tmp_path, *BASE)
    with (job / "trace.log").open("a") as f:
        f.write(raw + "\n")
    result = split_by_process(job, tmp_path / "logs", TargetOs.WINDOWS)
    assert result.stats.bad_control == 1 and result.stats.bad_json == 0
    calls = list(Processes(str(tmp_path / "logs"), None, CapeOptions(), TargetOs.WINDOWS).run()[0]["calls"])
    assert by_name(calls[0])["FileName"] == "\\X\x01"


def test_a_value_apimon_appended_is_not_unescaped(tmp_path):
    calls = list(processes(
        tmp_path, *BASE,
        rec("apimon", 0x10, 100, Event="api_called", Method="NtCreateUserProcess",
            ReturnValue="0x0",
            Arguments=['ProcessParameters=0x1f0', 'CommandLine="C:\\a b\\x.exe" -n 1',
                       'ImageName=0x2:"C:\\\\a b\\\\x.exe"']))[0]["calls"])
    args = by_name(calls[0])
    # Appended (no address): as it is, quotes and all. Printed (an address):
    # DRAKVUF's escaping undone.
    assert args["CommandLine"] == '"C:\\a b\\x.exe" -n 1'
    assert args["ImageName"] == "C:\\a b\\x.exe"


@pytest.mark.parametrize("api,plugin,linux,expected", [
    ("CreateFileW", "apimon", False, "filesystem"),
    ("connect", "apimon", False, "network"),
    ("WinHttpOpen", "apimon", False, "network"),
    ("CryptEncrypt", "apimon", False, "crypto"),
    ("NtSetValueKey", "syscall", False, "registry"),
    ("ZwCreateFile", "syscall", False, "filesystem"),
    ("NtUserGetMessage", "syscall", False, "windows"),
    ("CreateProcessInternalW", "apimon", False, "process"),
    ("openat", "syscall", True, "filesystem"),
    ("connect", "libmon", True, "network"),
    ("SSL_write", "libmon", True, "crypto"),
    ("NoSuchApi", "regmon", False, "registry"),
])
def test_the_category_is_the_apis_not_the_plugins(api, plugin, linux, expected):
    assert api_tables.category(api, plugin, linux) == expected


def test_every_hooked_api_has_a_category_in_capes_vocabulary():
    table = json.loads(api_tables.TABLE.read_text())["categories"]
    hooked = set()
    for line in (ROOT / "sandboxd" / "data" / "hooks.txt").read_text().splitlines():
        if line and not line.startswith("#"):
            hooked.add(api_tables.canonical(line.split(",")[1]))
    # ElfClearEventLogFile: in no source, 2026-11-09.
    assert len(hooked - set(table)) <= 1
    assert all(re.fullmatch(r"[A-Za-z_]+", c) for c in set(table.values()))
    assert {"network", "filesystem", "registry", "process", "crypto"} <= set(table.values())


# --- capa over the behaviour ---------------------------------------------------

def test_the_capa_report_is_one_capas_cape_model_accepts(tmp_path):
    from capa.features.extractors.cape.models import CapeReport
    procs = processes(
        tmp_path, *BASE,
        # No return (unpaired), and an argument that is neither str nor int.
        rec("syscall", 0x10, 100, tid=9, method="NtCreateFile", Syscall=85, PreviousMode="User",
            ObjectAttributes="\\??\\C:\\x", AllocationSize=None),
        {"Plugin": "apimon", "Event": "dll_loaded", "PID": 100, "DllName": "a.dll",
         "DllBase": "0x1000"})
    results = {"behavior": {"processes": procs},
               "target": {"file": {"type": cape_analysis.TARGET_FILE_TYPE[TargetOs.WINDOWS]}}}
    report = CapeReport.model_validate(capa_integration.capa_report(results, {100}))
    proc = report.behavior.processes[0]
    assert proc.threads == [9]
    assert [c.api for c in proc.calls] == ["NtCreateFile"] and proc.calls[0].return_ == 0
    assert capa_integration.capa_report(results, {12345})["behavior"]["processes"] == []


# --- end to end ---------------------------------------------------------------

def test_a_loaded_library_is_the_file_windows_opens(tmp_path):
    # combase joins System32 and a proxy DLL's name with a separator too
    # many; Windows' path normalization opens the file without it.
    path = "C:\\\\Windows\\\\System32\\\\\\\\Windows.StateRepositoryPS.dll"   # DRAKVUF-escaped
    records = [
        rec("apimon", 0x10, 100, Event="api_called", Method="LoadLibraryExW", ReturnValue="0x7ffa10000000",
            Arguments=[f'lpLibFileName=0x1:"{path}"', "hFile=0x0", "dwFlags=0x800"]),
        rec("apimon", 0x11, 100, Event="api_called", Method="LdrLoadDll", ReturnValue="0x0",
            Arguments=['DllPath=0x2:"C:\\\\Windows\\\\System32"', "DllCharacteristics=0x0",
                       f'FileName=0x3:"{path}"', "DllHandle=0x7ffa10000000"]),
    ]
    (tmp_path / "job").mkdir()
    (tmp_path / "split").mkdir()
    job = write_trace(tmp_path / "job", *BASE, *records)
    cape_analysis.run_cape(PostprocessContext(job, PostprocessingConfig(), TargetOs.WINDOWS),
                           CapeConfigSection(capa=False, signatures=False))
    doc = json.loads((job / cape_analysis.CAPE_RESULTS).read_text())

    loads = [e["data"] for e in doc["behavior"]["enhanced"] if e["object"] == "library"]
    resolved = "C:\\Windows\\System32\\Windows.StateRepositoryPS.dll"
    assert loads == [
        {"file": resolved, "pathtofile": None, "moduleaddress": "0x7ffa10000000"},
        {"file": resolved, "pathtofile": "C:\\Windows\\System32", "moduleaddress": "0x7ffa10000000"},
    ]
    # The calls keep the argument as it was passed
    calls = list(processes(tmp_path / "split", *BASE, *records)[0]["calls"])
    assert by_name(calls[1])["FileName"] == "C:\\Windows\\System32\\\\Windows.StateRepositoryPS.dll"


def test_structures_drakvuf_decoded_have_capemons_names(tmp_path):
    calls = {c["api"]: by_name(c) for c in processes(
        tmp_path, *BASE,
        api(0x10, 100, "NtOpenProcess", ProcessHandle="0x5ffd38", DesiredAccess="0x1fffff",
            ObjectAttributes="0x5ffd00", ClientId='0x5ffd20:"4321:0"'),
        api(0x11, 100, "NtDelayExecution", Alertable="0x0", DelayInterval='0x5ffd10:"-50000000"'),
        # buffer[nSize]: every byte that is not printable ASCII as \xHH
        api(0x12, 100, "WriteProcessMemory", "0x1", hProcess="0x2a4", lpBaseAddress="0x400000",
            lpBuffer='0x7ff0000:"MZ\\x90\\x00\\x03"', nSize="0x5", lpNumberOfBytesWritten="0x0"),
        api(0x13, 100, "NtSetContextThread", ThreadHandle="0x2b0",
            Context='0x5ffa00:"Dr0=0x7ffe1000;Dr1=0x0;Dr2=0x0;Dr3=0x0;Dr6=0x0;Dr7=0x1;Rip=0x401000"'))[0]["calls"]}
    context = calls["NtSetContextThread"]
    assert (context["Dr0"], context["Dr7"], context["Rip"]) == ("0x7ffe1000", "0x1", "0x401000")
    open_process = calls["NtOpenProcess"]
    assert (open_process["ProcessIdentifier"], open_process["ProcessId"]) == ("4321", "4321")
    assert calls["NtDelayExecution"]["Milliseconds"] == "5000"
    assert calls["WriteProcessMemory"]["Buffer"] == "MZ\x90\x00\x03"
    assert calls["WriteProcessMemory"]["Buffer"].startswith("MZ")


# --- Anomaly and ProcessTree -----------------------------------------------------

def behaviour_results(tmp_path, *records, os_=TargetOs.WINDOWS):
    (tmp_path / "b").mkdir()
    job = write_trace(tmp_path / "b", *records)
    return cape_analysis.run_cape(PostprocessContext(job, PostprocessingConfig(), os_),
                                  CapeConfigSection(capa=False, signatures=False))


def behaviour(tmp_path, *records, os_=TargetOs.WINDOWS):
    return behaviour_results(tmp_path, *records, os_=os_)["behavior"]


def test_anomalies_are_what_drakvufs_detection_plugins_saw(tmp_path):
    linux = behaviour(
        tmp_path, inject(100),
        rec("cpuidmon", 0, 100, ppid=1, Leaf=0x40000000, Subleaf=0, RAX=1, RBX=2, RCX=3, RDX=4),
        rec("cpuidmon", 0, 100, ppid=1, Leaf=0x40000000, Subleaf=0, RAX=1, RBX=2, RCX=3, RDX=4),
        rec("cpuidmon", 0, 100, ppid=1, Leaf=1, Subleaf=0, RAX=1, RBX=2, RCX=3, RDX=4),       # ordinary
        rec("ptracemon", 0x10, 100, ppid=1, method="ptrace", Type="PTRACE_TRACEME", TargetPID=100,
            TargetProcessName="x"),
        rec("ptracemon", 0x11, 100, ppid=1, method="ptrace", Type="PTRACE_POKEDATA", TargetPID=300,
            TargetProcessName="sshd"),
        # its own PID, which the behaviour prints in hex: no other process
        rec("ptracemon", 0x11, 100, ppid=1, method="ptrace", Type="PTRACE_ATTACH", TargetPID=100,
            TargetProcessName="x"),
        rec("ebpfmon", 0x12, 100, ppid=1, method="bpf", Value="BPF_PROG_LOAD", Type="BPF_PROG_TYPE_KPROBE"),
        rec("debugmon", 0x13, 100, ppid=1, method="debugmon", RIP="0x401000", DebugType=3,
            DebugTypeStr="software exception"),
        rec("debugmon", 0x14, 100, ppid=1, method="debugmon", RIP="0x401000", DebugType=0,
            DebugTypeStr="external interrupt"),                                          # the hardware's
        os_=TargetOs.UBUNTU)
    assert [(a["pid"], a["category"], a["funcname"]) for a in linux["anomaly"]] == [
        (100, "anti-vm", "cpuid"), (100, "anti-debug", "ptrace"), (100, "injection", "ptrace"),
        (100, "kernel", "bpf"), (100, "anti-debug", "software exception")]

    (tmp_path / "w").mkdir()
    windows = behaviour(
        tmp_path / "w", *BASE,
        rec("syscall", 0x10, 100, method="NtClose", Syscall=15, PreviousMode="User"),
        # The kernel's, no process's: from rootkitmon's aux log
        {"Plugin": "rootkitmon", "TimeStamp": "1000.5", "Type": "SystemStruct", "Action": "Modified",
         "Name": "HalPrivateDispatchTable"})
    assert windows["anomaly"] == [{"name": "kernel", "pid": 4, "category": "rootkit",
                                   "funcname": "SystemStruct", "message": "Modified HalPrivateDispatchTable"}]


def test_the_tree_has_every_process_and_a_reused_pid_once_each(tmp_path):
    tree = behaviour(
        tmp_path, *BASE,
        # 100 starts 200 twice, the PID reused. The first starts 250 and
        # exits, the second starts 300; only 250 and 300 make calls
        create(0x10, 100, 200), create(0x11, 200, 250),
        rec("syscall", 0x12, 250, ppid=200, method="NtClose", Syscall=15, PreviousMode="User"),
        rec("procmon", 0x13, 200, ppid=100, method="NtTerminateProcess", ExitPid=200,
            ExitStatus="0x0", ExitStatusStr="STATUS_SUCCESS"),
        create(0x20, 100, 200), create(0x21, 200, 300),
        rec("syscall", 0x22, 300, ppid=200, method="NtClose", Syscall=15, PreviousMode="User"))["processtree"]

    def shape(nodes):
        return [(n["pid"], shape(n["children"])) for n in nodes]
    # Each child under the 200 that started it, both 200s under 100
    assert shape(tree) == [(100, [(200, [(250, [])]), (200, [(300, [])])])]


# --- Summary ---------------------------------------------------------------------

def win_command(uid, pid, new_pid, cmdline, image):
    # procmon's command line through g_strescape (see create)
    return rec("procmon", uid, pid, method="NtCreateUserProcess", Status="0x0", NewPid=new_pid,
               CommandLine=cmdline.replace("\\", "\\\\").replace('"', '\\"'), ImagePathName=image)


def test_summary_keeps_each_processs_own_lists(tmp_path):
    """The platform's Summary is one section per process: each process's
    lists beside the global ones, an item two processes touched in both."""
    results = behaviour_results(
        tmp_path, *BASE,
        create(0x10, 100, 200),
        rec("filetracer", 0x11, 100, method="NtWriteFile", FileName="\\??\\C:\\shared.txt", FileHandle="0x10"),
        rec("filetracer", 0x12, 200, ppid=100, method="NtWriteFile", FileName="\\??\\C:\\shared.txt",
            FileHandle="0x10"),
        rec("filetracer", 0x13, 200, ppid=100, method="NtReadFile", FileName="\\??\\C:\\child.txt",
            FileHandle="0x14"),
        rec("regmon", 0x14, 200, ppid=100, method="NtSetValueKey",
            Key="\\REGISTRY\\USER\\S-1-5-21\\Software\\x", ValueName="v", Value="01"))
    summary = results["behavior"]["summary"]
    seqid = {p["process_id"]: str(p["seqid"]) for p in results["behavior"]["processes"]}
    mine = summary["by_process"]
    assert mine[seqid[100]]["write_files"] == ["C:\\shared.txt"]
    assert mine[seqid[200]]["write_files"] == ["C:\\shared.txt"]
    assert mine[seqid[200]]["read_files"] == ["C:\\child.txt"]
    assert mine[seqid[200]]["write_keys"] == ["HKEY_USERS\\S-1-5-21\\Software\\x\\v"]
    assert "write_keys" not in mine[seqid[100]]
    # The global lists are unchanged: each item once
    assert summary["write_files"] == ["C:\\shared.txt"]


def test_summary_has_windows_deletes_renames_and_services(tmp_path):
    s = behaviour(
        tmp_path, *BASE,
        # DeleteFileW since Windows 10: the Ex class, by its flag
        rec("filetracer", 0x10, 100, method="NtSetInformationFile", Operation="FileDispositionInformationEx",
            FileName="\\??\\C:\\Users\\u\\a.txt", FileHandle="0x10",
            Flags="FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS"),
        # A pending delete taken back, and an Ex call that does not delete
        rec("filetracer", 0x11, 100, method="NtSetInformationFile", Operation="FileDispositionInformation",
            FileName="\\??\\C:\\Users\\u\\keep.txt", FileHandle="0x14", DeleteFile=0),
        rec("filetracer", 0x12, 100, method="NtSetInformationFile", Operation="FileDispositionInformationEx",
            FileName="\\??\\C:\\Users\\u\\keep2.txt", FileHandle="0x14", Flags="FILE_DISPOSITION_DO_NOT_DELETE"),
        # A rename has two names and no FileName
        rec("filetracer", 0x13, 100, method="NtSetInformationFile", Operation="FileRenameInformation",
            FileSrc="\\??\\C:\\Users\\u\\b.tmp", FileDst="\\??\\C:\\Users\\u\\b.exe", FileHandle="0x18"),
        # Services: a command, a handle, a key
        win_command(0x14, 100, 300, '"C:\\Windows\\system32\\sc.exe" create evil binPath= C:\\x.exe',
                    "C:\\Windows\\system32\\sc.exe"),
        win_command(0x15, 100, 301, 'net start "Evil Two"', "C:\\Windows\\system32\\net.exe"),
        rec("apimon", 0x16, 100, Event="api_called", Method="OpenServiceW", ReturnValue="0x2a0",
            Arguments=["hSCManager=0x1f0", 'lpServiceName=0x1f8:"Spooler"', "dwDesiredAccess=0x10"]),
        rec("apimon", 0x17, 100, Event="api_called", Method="StartServiceW", ReturnValue="0x1",
            Arguments=["hService=0x2a0", "dwNumServiceArgs=0x0", "lpServiceArgVectors=0x0"]),
        rec("regmon", 0x18, 100, method="NtSetValueKey",
            Key="\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\evil3", ValueName="ImagePath",
            Value="43 00 3a 00"))["summary"]
    assert s["delete_files"] == ["C:\\Users\\u\\a.txt", "C:\\Users\\u\\b.tmp"]
    assert s["write_files"] == ["C:\\Users\\u\\b.exe"]
    assert sorted(s["created_services"]) == ["evil", "evil3"]
    assert sorted(s["started_services"]) == ["Evil Two", "Spooler"]


def test_summary_has_linux_renames_services_and_resolved_symbols(tmp_path):
    lib = dict(Event="api_called", Library="/usr/lib/x86_64-linux-gnu/libc.so.6")

    def ftrace(uid, syscall, name, **extra):
        return rec("filetracer", uid, 100, ppid=1, method="do_syscall_64", Syscall=syscall,
                   FileName=name, **extra)
    s = behaviour(
        tmp_path, inject(100),
        rec("procmon", 0x0f, 100, ppid=1, method="do_execveat_common", FileName="/tmp/s",
            ImagePathName="/tmp/s", CommandLine="/tmp/s"),
        ftrace(0x10, "renameat2", "/home/u/.x/run", old_name="/tmp/dl.bin"),
        ftrace(0x11, "linkat", "/usr/bin/id", link_name="/home/u/.x/id"),
        # A unit file is a service; one under /run is one too, though /run
        # is no file list's
        ftrace(0x12, "write", "/etc/systemd/system/evil.service"),
        ftrace(0x13, "write", "/run/systemd/system/evil2.service"),
        # systemctl enable's link: a service that exists, not a new one
        ftrace(0x14, "symlink", "/etc/systemd/system/multi-user.target.wants/ssh.service",
               oldname="/lib/systemd/system/ssh.service"),
        rec("procmon", 0x15, 200, ppid=100, method="do_execveat_common", FileName="/usr/bin/systemctl",
            ImagePathName="/usr/bin/systemctl", CommandLine="systemctl --quiet start evil.service"),
        rec("procmon", 0x16, 201, ppid=100, method="do_execveat_common", FileName="/usr/sbin/service",
            ImagePathName="/usr/sbin/service", CommandLine="service cron restart"),
        rec("libmon", 0x17, 100, ppid=1, method="dlopen", ReturnValue="0x5555b000", **lib,
            Arguments=['Path=0x7f00:"/usr/lib/x86_64-linux-gnu/libcrypto.so.3"', "Flags=0x2"]),
        rec("libmon", 0x18, 100, ppid=1, method="dlsym", ReturnValue="0x7f3a0010", **lib,
            Arguments=["Handle=0x5555b000", 'Symbol=0x4010:"EVP_EncryptInit_ex"']),
        rec("libmon", 0x19, 100, ppid=1, method="dlsym", ReturnValue="0x7f3a0020", **lib,
            Arguments=["Handle=0x0", 'Symbol=0x4020:"ptrace"']),
        # not found
        rec("libmon", 0x1a, 100, ppid=1, method="dlsym", ReturnValue="0x0", **lib,
            Arguments=["Handle=0x5555b000", 'Symbol=0x4030:"nope"']),
        os_=TargetOs.UBUNTU)["summary"]
    assert s["write_files"] == ["/home/u/.x/run", "/home/u/.x/id", "/etc/systemd/system/evil.service",
                                "/etc/systemd/system/multi-user.target.wants/ssh.service"]
    assert s["delete_files"] == ["/tmp/dl.bin"]
    assert s["created_services"] == ["evil", "evil2"]
    assert s["started_services"] == ["evil", "cron"]
    assert s["resolved_apis"] == ["libcrypto.so.3.EVP_EncryptInit_ex", "RTLD_DEFAULT.ptrace"]


# --- Enhanced --------------------------------------------------------------------

def events(enhanced):
    return [(e["event"], e["object"], e["data"]) for e in enhanced]


def test_enhanced_adds_what_the_windows_kernel_saw_once_and_not_over_the_api(tmp_path):
    enhanced = behaviour(
        tmp_path, *BASE,
        # Twice the same file: one event. Not one after the other, which
        # the parser folds into one call (`repeated`) on its own
        rec("filetracer", 0x10, 100, method="NtWriteFile", FileName="\\??\\C:\\Users\\u\\log.txt",
            FileHandle="0x10"),
        rec("filetracer", 0x11, 100, method="NtReadFile", FileName="\\??\\C:\\Users\\u\\in.txt",
            FileHandle="0x14"),
        rec("filetracer", 0x11, 100, method="NtWriteFile", FileName="\\??\\C:\\Users\\u\\log.txt",
            FileHandle="0x10"),
        # The kernel's record of DeleteFileW, which apimon prints at its
        # return, after: the API's event stands for both
        rec("filetracer", 0x12, 100, method="NtSetInformationFile", Operation="FileDispositionInformationEx",
            FileName="\\??\\C:\\Users\\u\\a.txt", FileHandle="0x14", Flags="FILE_DISPOSITION_DELETE"),
        rec("apimon", 0x13, 100, tid=2, Event="api_called", Method="DeleteFileW", ReturnValue="0x1",
            Arguments=['lpFileName=0x1f8:"C:\\\\Users\\\\u\\\\a.txt"']),
        rec("filetracer", 0x14, 100, method="NtSetInformationFile", Operation="FileRenameInformation",
            FileSrc="\\??\\C:\\Users\\u\\b.tmp", FileDst="\\??\\C:\\Users\\u\\b.exe", FileHandle="0x18"),
        rec("filetracer", 0x15, 100, method="NtCreateFile", FileName="\\??\\C:\\Users\\u\\new",
            FileHandle="0x1c", IoStatusBlock=2, CreateOptions="FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT",
            Status="0x0"),
        win_command(0x16, 100, 300, "cmd.exe /c whoami", "C:\\Windows\\System32\\cmd.exe"),
        rec("regmon", 0x17, 100, method="NtSetValueKey",
            Key="\\REGISTRY\\USER\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            ValueName="x", Value="43 00 00 00"),
        # The system's DLL is left out, the sample's own kept
        {"Plugin": "apimon", "Event": "dll_discovered", "PID": 100,
         "DllName": "\\Device\\HarddiskVolume2\\Windows\\System32\\kernel32.dll", "DllBase": "0x7ff0000"},
        # how apimon names most of them: no drive, no device
        {"Plugin": "apimon", "Event": "dll_discovered", "PID": 100,
         "DllName": "\\Windows\\System32\\ntdll.dll", "DllBase": "0x7ff1000"},
        {"Plugin": "apimon", "Event": "dll_loaded", "PID": 100,
         "DllName": "C:\\Users\\u\\AppData\\evil.dll", "DllBase": "0x180000000"},
        # ControlService's code is hex text, the service the handle's
        rec("apimon", 0x18, 100, Event="api_called", Method="OpenServiceW", ReturnValue="0x2a0",
            Arguments=["hSCManager=0x1f0", 'lpServiceName=0x1f8:"WinDefend"', "dwDesiredAccess=0x20"]),
        rec("apimon", 0x19, 100, Event="api_called", Method="ControlService", ReturnValue="0x1",
            Arguments=["hService=0x2a0", "dwControl=0x1", "lpServiceStatus=0x5000"]))["enhanced"]
    got = events(enhanced)
    assert ("write", "file", {"file": "C:\\Users\\u\\log.txt"}) in got
    assert [e for e in got if e[0] == "write" and e[1] == "file"] == [
        ("write", "file", {"file": "C:\\Users\\u\\log.txt"})]
    assert [e for e in got if e[0] == "delete"] == [("delete", "file", {"file": "C:\\Users\\u\\a.txt"})]
    assert ("move", "file", {"from": "C:\\Users\\u\\b.tmp", "to": "C:\\Users\\u\\b.exe"}) in got
    assert ("create", "dir", {"file": "C:\\Users\\u\\new"}) in got
    assert ("execute", "file", {"file": "cmd.exe /c whoami"}) in got
    reg = [e for e in got if e[1] == "registry"]
    assert [e[2]["regkey"] for e in reg] == [
        "HKEY_USERS\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x"]
    assert [e[2]["file"] for e in got if e[1] == "library"] == ["evil.dll"]
    service = [e for e in got if e[1] == "service"]
    assert service == [("modify", "service", {"service": "WinDefend", "controlcode": "0x1", "action": "stop"})]
    # In time order, numbered
    assert [e["eid"] for e in enhanced] == list(range(1, len(enhanced) + 1))
    assert [float(e["timestamp"]) for e in enhanced] == sorted(float(e["timestamp"]) for e in enhanced)


def test_enhanced_has_linux_events(tmp_path):
    lib = dict(Event="api_called", Library="/usr/lib/x86_64-linux-gnu/libc.so.6")

    def ftrace(uid, syscall, name, **extra):
        return rec("filetracer", uid, 100, ppid=1, method="do_syscall_64", Syscall=syscall,
                   FileName=name, **extra)
    got = events(behaviour(
        tmp_path, inject(100),
        rec("procmon", 0x0f, 100, ppid=1, method="do_execveat_common", FileName="/tmp/s",
            ImagePathName="/tmp/s", CommandLine="/tmp/s -d"),
        ftrace(0x10, "renameat2", "/home/u/.x/run", old_name="/tmp/dl.bin"),
        ftrace(0x11, "mkdir", "/home/u/.x"),
        ftrace(0x12, "unlink", "/tmp/s"),
        ftrace(0x13, "read", "/proc/self/maps"),
        ftrace(0x14, "write", "/home/u/.bashrc"),
        rec("libmon", 0x15, 100, ppid=1, method="dlopen", ReturnValue="0x5555b000", **lib,
            Arguments=['Path=0x7f00:"/usr/lib/x86_64-linux-gnu/libcrypto.so.3"', "Flags=0x2"]),
        rec("libmon", 0x16, 100, ppid=1, method="system", ReturnValue="0x0", **lib,
            Arguments=['Command=0x7f10:"crontab -l"']),
        os_=TargetOs.UBUNTU)["enhanced"])
    assert got == [
        ("execute", "file", {"file": "/tmp/s -d"}),
        ("move", "file", {"from": "/tmp/dl.bin", "to": "/home/u/.x/run"}),
        ("create", "dir", {"file": "/home/u/.x"}),
        ("delete", "file", {"file": "/tmp/s"}),
        ("write", "file", {"file": "/home/u/.bashrc"}),
        ("load", "library", {"file": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
                             "moduleaddress": "0x5555b000"}),
        ("execute", "file", {"file": "crontab -l"}),
    ]


# --- EncryptedBuffers ------------------------------------------------------------

def crypto_call(uid, method, *arguments, ret="0x1", pid=100, **extra):
    return rec("apimon", uid, pid, Event="api_called", Method=method, ReturnValue=ret,
               Arguments=list(arguments), **extra)


def test_encrypted_buffers_carry_the_key_they_were_enciphered_with(tmp_path):
    bufs = behaviour(
        tmp_path, *BASE,
        crypto_call(0x10, "CryptGenKey", "hProv=0x10", "Algid=0x6610", "dwFlags=0x1", "phKey=0x5550"),
        crypto_call(0x11, "CryptEncrypt", "hKey=0x5550", "hHash=0x0", "Final=0x1", "dwFlags=0x0",
            'pbData=0x1000:"beacon"', "pdwDataLen=0x6", "dwBufLen=0x10"),
        # The same buffer again: once
        crypto_call(0x12, "Sleep", "dwMilliseconds=0x0"),
        crypto_call(0x13, "CryptEncrypt", "hKey=0x5550", "hHash=0x0", "Final=0x1", "dwFlags=0x0",
            'pbData=0x1000:"beacon"', "pdwDataLen=0x6", "dwBufLen=0x10"),
        # BCrypt: the algorithm by its provider, the key's bytes by the secret
        crypto_call(0x14, "BCryptOpenAlgorithmProvider", "phAlgorithm=0x7000", 'pszAlgId=0x2000:"AES"',
            "pszImplementation=0x0", "dwFlags=0x0", ret="0x0"),
        crypto_call(0x15, "BCryptGenerateSymmetricKey", "hAlgorithm=0x7000", "phKey=0x7100", "pbKeyObject=0x0",
            "cbKeyObject=0x0", 'pbSecret=0x3000:"\\x01\\x02\\x03\\x04"', "cbSecret=0x4", "dwFlags=0x0", ret="0x0"),
        crypto_call(0x16, "BCryptEncrypt", "hKey=0x7100", 'pbInput=0x4000:"config"', "cbInput=0x6",
            "pPaddingInfo=0x0", "pbIV=0x0", "cbIV=0x0", "pbOutput=0x5000", "cbOutput=0x10",
            "pcbResult=0x10", "dwFlags=0x1", ret="0x0"),
        # A key imported in the clear: PLAINTEXTKEYBLOB, RC4, 4 bytes
        crypto_call(0x17, "CryptImportKey", "hProv=0x10",
            'pbData=0x1000:"\\x08\\x02\\x00\\x00\\x01h\\x00\\x00\\x04\\x00\\x00\\x00k3y!"',
            "dwDataLen=0x10", "hPubKey=0x0", "dwFlags=0x0", "phKey=0x5560"),
        crypto_call(0x18, "CryptEncrypt", "hKey=0x5560", "hHash=0x0", "Final=0x1", "dwFlags=0x0",
            'pbData=0x1000:"rc4 data"', "pdwDataLen=0x8", "dwBufLen=0x8"),
        crypto_call(0x19, "EncryptMessage", "phContext=0x60", "fQOP=0x0", 'pMessage=0x6000:"GET / HTTP/1.1"',
            "MessageSeqNo=0x0", ret="0x0"),
        crypto_call(0x1a, "CryptUnprotectData", "pDataIn=0x10", "ppszDataDescr=0x0", "pOptionalEntropy=0x0",
            "pvReserved=0x0", "pPromptStruct=0x0", "dwFlags=0x0", 'pDataOut=0x7000:"hunter2"'),
        # A pointer DRAKVUF could not read: no buffer
        crypto_call(0x1b, "SslEncryptPacket", "hSslProvider=0x1", "hKey=0x2", "pbInput=0x8000", "cbInput=0x10",
            "pbOutput=0x0", "cbOutput=0x0", "pcbResult=0x0", "SequenceNumber=0x0",
            "dwContentType=0x17", "dwFlags=0x0", ret="0x0"))["encryptedbuffers"]
    got = [(b["api_call"], b["direction"], b["buffer"], b.get("algorithm"), b.get("key")) for b in bufs]
    assert got == [
        ("CryptEncrypt", "encrypt", "beacon", "AES_256", None),
        ("BCryptEncrypt", "encrypt", "config", "AES", "01020304"),
        ("CryptEncrypt", "encrypt", "rc4 data", "RC4", "6b337921"),
        ("EncryptMessage", "encrypt", "GET / HTTP/1.1", None, None),
        ("CryptUnprotectData", "decrypt", "hunter2", None, None),
    ]
    assert bufs[0]["crypt_key"] == "0x5550" and bufs[1]["buffer_size"] == 6


def test_encrypted_buffers_on_linux(tmp_path):
    lib = dict(Library="/usr/lib/x86_64-linux-gnu/libssl.so.3")
    bufs = behaviour(
        tmp_path, inject(100),
        crypto_call(0x10, "SSL_write", "Ssl=0x10", 'Buf=0x2000:"POST /gate HTTP/1.1"', "Num=0x13", pid=100,
            ppid=1, ret="0x13", **lib),
        crypto_call(0x11, "EVP_DecryptUpdate", "Ctx=0x20", 'Out=0x3000:"stage2"', "OutLen=0x6", "In=0x4000",
            "InLen=0x10", pid=100, ppid=1, **lib),
        crypto_call(0x12, "gnutls_record_send", "Session=0x30", 'Data=0x5000:"hello"', "Size=0x5", pid=100,
            ppid=1, ret="0x5", **lib),
        os_=TargetOs.UBUNTU)["encryptedbuffers"]
    assert [(b["api_call"], b["direction"], b["buffer"], b["buffer_size"]) for b in bufs] == [
        ("SSL_write", "encrypt", "POST /gate HTTP/1.1", 0x13),
        ("EVP_DecryptUpdate", "decrypt", "stage2", 6),
        ("gnutls_record_send", "encrypt", "hello", 5),
    ]


# --- NetworkMap ------------------------------------------------------------------

def network_map(tmp_path, *records, os_=TargetOs.WINDOWS, **cape):
    """The behaviour's network_map for a trace, through the whole chain."""
    (tmp_path / "nm").mkdir()
    job = write_trace(tmp_path / "nm", *records)
    cape_analysis.run_cape(PostprocessContext(job, PostprocessingConfig(), os_),
                           CapeConfigSection(capa=False, signatures=False, **cape))
    return json.loads((job / cape_analysis.CAPE_RESULTS).read_text())["behavior"]["network_map"]


def api(uid, pid, method, ret="0x0", **args):
    return rec("apimon", uid, pid, Event="api_called", Method=method, ReturnValue=ret,
               Arguments=[f"{k}={v}" for k, v in args.items()])


def test_a_connection_is_one_endpoint_whatever_saw_it(tmp_path):
    nmap = network_map(
        tmp_path, *BASE,
        rec("socketmon", 0x10, 100, method="TcpCreateAndConnectTcbComplete", Protocol="TCPv4",
            RemoteIp="203.0.113.7", RemotePort=443, LocalIp="10.0.0.5", LocalPort=49200),
        api(0x11, 100, "connect", s="0x1a4", name='0x5ffd00:"203.0.113.7:443"', namelen="0x10"),
        # Multicast (SSDP), by default left out -- and counted
        api(0x12, 100, "sendto", s="0x1a8", buf='0x1:"M-SEARCH * HTTP/1.1"', len="0x14", flags="0x0",
            to='0x2:"239.255.255.250:1900"', tolen="0x10"))
    assert [(e["ip_port"], [(p["process_id"], p["events"], sorted(p["sources"])) for p in e["pinfo"]])
            for e in nmap["endpoint_map"]] == \
        [("203.0.113.7:443", [(100, ["connect"], ["apimon", "socketmon"])])]
    assert nmap["filtered"] == {"endpoints": 1}


def test_capemons_ip_and_port_are_beside_the_address(tmp_path):
    calls = list(processes(tmp_path, *BASE, api(0x10, 100, "connect", s="0x1a4",
                                                  name='0x5ffd00:"203.0.113.7:443"', namelen="0x10"))[0]["calls"])
    args = by_name(calls[0])
    assert (args["socket"], args["ip"], args["port"]) == ("0x1a4", "203.0.113.7", "443")


def test_a_wininet_request_is_followed_from_session_to_send(tmp_path):
    nmap = network_map(
        tmp_path, *BASE,
        api(0x10, 100, "InternetOpenW", "0xcc0004", lpszAgent='0x1:"Mozilla/5.0 X"', dwAccessType="0x0"),
        api(0x11, 100, "InternetConnectW", "0xcc0008", hInternet="0xcc0004",
            lpszServerName='0x2:"evil.example"', nServerPort="0x1bb", dwService="0x3"),
        api(0x12, 100, "HttpOpenRequestW", "0xcc000c", hConnect="0xcc0008", lpszVerb='0x3:"POST"',
            lpszObjectName='0x4:"/gate.php"', dwFlags="0x800000"),
        api(0x13, 100, "HttpSendRequestW", "0x1", hRequest="0xcc000c",
            lpszHeaders='0x5:"User-Agent: Custom\\r\\n"', dwHeadersLength="0x14"))   # DRAKVUF-escaped CR LF
    assert [(r["url"], r["method"], r["user_agent"], r["process_id"]) for r in nmap["http_requests"]] == \
        [("https://evil.example/gate.php", "POST", "Custom", 100)]
    assert [h["host"] for h in nmap["http_host_map"]] == ["evil.example"]
    assert [u["user_agent"] for u in nmap["user_agents"]] == ["Mozilla/5.0 X", "Custom"]


def test_a_name_asked_twice_is_one_intent_and_noise_is_counted(tmp_path):
    nmap = network_map(
        tmp_path, *BASE,
        rec("socketmon", 0x10, 100, method="DnsQuery_W", DnsName="evil.example"),
        api(0x11, 100, "getaddrinfo", pNodeName='0x1:"evil.example"', pServiceName='0x2:"443"'),
        api(0x12, 100, "getaddrinfo", pNodeName='0x3:"203.0.113.7"'),       # a literal: no question
        rec("socketmon", 0x13, 100, method="DnsQuery_W", DnsName="wpad.lab.local"))
    [intent] = [i for d in nmap["dns_intents"] if d["domain"] == "evil.example" for i in d["intents"]]
    assert (intent["apis"], intent["sources"]) == (["DnsQuery_W", "getaddrinfo"], ["apimon", "socketmon"])
    assert [d["domain"] for d in nmap["dns_intents"]] == ["evil.example"]
    assert nmap["filtered"] == {"dns": 1}


def test_the_resolvers_answer_names_the_host_it_connects_to(tmp_path):
    job = write_trace(
        tmp_path, *BASE,
        # ppaddrinfo: the answer's addresses, read at the return
        api(0x10, 100, "getaddrinfo", pNodeName='0x1:"c2.example"', pServiceName='0x2:"443"',
            pHints="0x0", ppResult='0x3:"203.0.113.7,2001:db8::7"'),
        rec("socketmon", 0x11, 100, method="TcpCreateAndConnectTcbComplete", Protocol="TCPv4",
            RemoteIp="203.0.113.7", RemotePort=443, LocalIp="10.0.0.5", LocalPort=49200))
    results = cape_analysis.run_cape(PostprocessContext(job, PostprocessingConfig(), TargetOs.WINDOWS),
                                     CapeConfigSection(capa=False, signatures=False))
    nmap = results["behavior"]["network_map"]
    assert nmap["dns_answers"] == [{"domain": "c2.example", "answers": ["203.0.113.7", "2001:db8::7"]}]
    assert nmap["dns_intents"][0]["intents"][0]["answers"] == ["203.0.113.7", "2001:db8::7"]
    [query] = [d for d in results["network"]["dns"] if d["request"] == "c2.example"]
    assert query["answers"] == [{"type": "A", "data": "203.0.113.7"}, {"type": "AAAA", "data": "2001:db8::7"}]
    [host] = [h for h in results["network"]["hosts"] if h["ip"] == "203.0.113.7"]
    assert (host["hostname"], host["ports"]) == ("c2.example", [443])


def test_an_include_keeps_what_an_exclude_would_drop(tmp_path):
    nmap = network_map(
        tmp_path, *BASE,
        api(0x10, 100, "sendto", s="0x1a8", buf='0x1:"x"', len="0x1", flags="0x0",
            to='0x2:"224.0.0.251:5353"', tolen="0x10"),
        network_include_networks=["224.0.0.251/32"])
    assert [e["ip_port"] for e in nmap["endpoint_map"]] == ["224.0.0.251:5353"]


def test_linux_kernel_and_library_records_build_one_map(tmp_path):
    request = "GET /x HTTP/1.1\\r\\nHost: c2.example\\r\\nUser-Agent: curl/8.5\\r\\n\\r\\n"
    lib = dict(Event="api_called", ReturnValue="0x0", Library="/usr/lib/x86_64-linux-gnu/libc.so.6")
    nmap = network_map(
        tmp_path, inject(100),
        rec("unixsocketmon", 0x10, 100, ppid=1, method="connect", Type="AF_INET", Protocol="TCP",
            RemoteIp="198.51.100.9", RemotePort=80, LocalIp="10.0.0.6", LocalPort=40100),
        rec("unixsocketmon", 0x11, 100, ppid=1, method="sock_sendmsg", Type="AF_INET", Protocol="TCP",
            RemoteIp="198.51.100.9", RemotePort=80, LocalIp="10.0.0.6", LocalPort=40100,
            Size=60, Value=request.replace("\\r\\n", "\r\n")),
        rec("libmon", 0x12, 100, ppid=1, method="curl_easy_setopt", **lib,
            Arguments=["Handle=0x5555a000", "Option=0x2712", 'Value=0x1:"https://c2.example/beacon"']),
        rec("libmon", 0x13, 100, ppid=1, method="curl_easy_perform", **lib, Arguments=["Handle=0x5555a000"]),
        rec("libmon", 0x14, 100, ppid=1, method="connect", **lib,
            Arguments=["Fd=0x3", 'SockAddr=0x2:"/run/dbus/system_bus_socket"', "AddrLen=0x6e"]),
        # The syscall plugin's record of what unixsocketmon saw adds nothing;
        # of what it did not see, it is the only source
        rec("syscall", 0x15, 100, ppid=1, method="connect", Syscall=42,
            sockfd="0x3", addr="198.51.100.9:80", addrlen="0x10"),
        rec("syscall", 0x16, 100, ppid=1, method="connect", Syscall=42,
            sockfd="0x4", addr="192.0.2.44:8443", addrlen="0x10"),
        os_=TargetOs.UBUNTU)
    assert [(e["ip_port"], [sorted(p["sources"]) for p in e["pinfo"]]) for e in nmap["endpoint_map"]] == [
        ("192.0.2.44:8443", [["syscall"]]),
        ("198.51.100.9:80", [["unixsocketmon"]]),
    ]
    assert [u["path"] for u in nmap["unix_sockets"]] == ["/run/dbus/system_bus_socket"]
    assert sorted((r["url"], r["method"], r["user_agent"]) for r in nmap["http_requests"]) == [
        ("http://c2.example/x", "GET", "curl/8.5"),
        ("https://c2.example/beacon", "GET", ""),
    ]


def test_a_server_is_a_listener_and_its_peers_are_endpoints(tmp_path):
    request = "POST /up HTTP/1.1\r\nHost: drop.example\r\n\r\n"
    windows = network_map(
        tmp_path, *BASE,
        # socketmon's AFD requests: bind, listen, and a send on a connected socket
        rec("socketmon", 0x10, 100, method="AfdBind", LocalIp="0.0.0.0", LocalPort=4444),
        rec("socketmon", 0x11, 100, method="AfdListen", LocalIp="0.0.0.0", LocalPort=4444, Backlog=5),
        rec("socketmon", 0x12, 100, method="AfdSend", RemoteIp="198.51.100.20", RemotePort=80,
            Size=len(request), Value=request),
        # A client AcceptEx took: its address where GetAcceptExSockaddrs
        # says it is, read at the return (printers' ppsockaddr)
        rec("apimon", 0x13, 100, Event="api_called", Method="GetAcceptExSockaddrs", ReturnValue="0x0",
            Arguments=['lpOutputBuffer=0x5000:"id\\n"', "dwReceiveDataLength=0x3",
                       "dwLocalAddressLength=0x20", "dwRemoteAddressLength=0x20",
                       'LocalSockaddr=0x5010:"10.0.0.5:4444"', "LocalSockaddrLength=0x10",
                       'RemoteSockaddr=0x5030:"203.0.113.9:50123"', "RemoteSockaddrLength=0x10"]))
    assert [(e["ip_port"], e["pinfo"][0]["events"]) for e in windows["listeners"]] == \
        [("0.0.0.0:4444", ["bind", "listen"])]
    assert {e["ip_port"]: e["pinfo"][0]["events"] for e in windows["endpoint_map"]} == \
        {"198.51.100.20:80": ["send"], "203.0.113.9:50123": ["accept"]}
    assert [(r["url"], r["method"], r["source"]) for r in windows["http_requests"]] == \
        [("http://drop.example/up", "POST", "socketmon")]

    (tmp_path / "linux").mkdir()
    linux = network_map(
        tmp_path / "linux", inject(100),
        rec("unixsocketmon", 0x10, 100, ppid=1, method="accept", Type="AF_INET", Protocol="TCP",
            LocalIp="10.0.0.6", LocalPort=8080, RemoteIp="203.0.113.50", RemotePort=51000, Connected=1),
        # The request a client made of the sample: not the sample's own
        rec("unixsocketmon", 0x11, 100, ppid=1, method="sock_recvmsg", Type="AF_INET", Protocol="TCP",
            LocalIp="10.0.0.6", LocalPort=8080, RemoteIp="203.0.113.50", RemotePort=51000,
            Size=30, Value="GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        os_=TargetOs.UBUNTU)
    assert [(e["ip_port"], e["pinfo"][0]["events"]) for e in linux["endpoint_map"]] == \
        [("203.0.113.50:51000", ["accept", "recv"])]
    assert linux["http_requests"] == []


@pytest.mark.parametrize("given,resolved", [
    ("C:\\a\\\\b.dll", "C:\\a\\b.dll"),
    ("C:\\a\\\\\\b\\\\c", "C:\\a\\b\\c"),
    ("\\\\server\\\\share\\x", "\\\\server\\share\\x"),
    ("\\\\?\\C:\\a\\\\b", "\\\\?\\C:\\a\\\\b"),
    ("C:\\a\\b.dll", "C:\\a\\b.dll"),
])
def test_resolved_path(given, resolved):
    assert resolved_path(given) == resolved


def test_cape_analysis_writes_results_and_leaves_no_working_directory(tmp_path):
    job = write_trace(
        tmp_path, *BASE, create(0x10, 100, 200),
        rec("filetracer", 0x11, 100, method="NtWriteFile", FileName="\\??\\C:\\out.txt",
            FileHandle="0x60"),
        rec("apimon", 0x12, 100, Event="api_called", Method="CreateMutexW", ReturnValue="0x2d8",
            Arguments=["lpMutexAttributes=0x0", "bInitialOwner=0x0", 'lpName=0x1:"OnlyOne"']),
        rec("regmon", 0x13, 100, method="NtSetValueKey", Key=USER_KEY, ValueName="Count",
            Value="0d 00 00 00"))
    config = PostprocessingConfig()
    context = PostprocessContext(job, config, TargetOs.WINDOWS)

    off = PostprocessingConfig(cape=CapeConfigSection(enabled=False))
    cape_analysis.cape_analysis(PostprocessContext(job, off, TargetOs.WINDOWS))
    assert not (job / cape_analysis.CAPE_RESULTS).exists()

    cape_analysis.run_cape(context, CapeConfigSection(capa=False, signatures=False))
    doc = json.loads((job / cape_analysis.CAPE_RESULTS).read_text())
    summary = doc["behavior"]["summary"]
    assert summary["write_files"] == ["C:\\out.txt"]
    assert summary["mutexes"] == ["OnlyOne"]
    assert summary["executed_commands"] == ["C:\\Windows\\System32\\PING.EXE"]
    # Registry lists by capemon's FullName, as upstream's Summary reads them.
    assert summary["write_keys"] == ["HKEY_CURRENT_USER\\SOFTWARE\\Valve\\Count"]
    assert summary["keys"] == ["HKEY_CURRENT_USER\\SOFTWARE\\Valve\\Count"]
    assert [p["call_count"] for p in doc["behavior"]["processes"]] == [4]
    assert doc["behavior"]["processtree"][0]["pid"] == 100
    assert not list(job.glob(".cape-*"))
    # The raw trace is replaced by its compressed copy, which is what uploads.
    assert not (job / "trace.log").exists() and (job / "trace.log.gz").exists()


def test_the_modules_put_files_dumps_and_connections_under_capes_keys(tmp_path):
    job = write_trace(
        tmp_path, *BASE,
        rec("socketmon", 0x10, 100, method="TcpConnect", Protocol="TCPv4", LocalIp="10.0.0.5",
            LocalPort=49152, RemoteIp="203.0.113.7", RemotePort=443),
        rec("socketmon", 0x11, 50, method="TcpConnect", Protocol="TCPv4", LocalIp="10.0.0.5",
            LocalPort=49153, RemoteIp="198.51.100.1", RemotePort=80),
        rec("memdump", 0x12, 100, method="NtWriteVirtualMemory", DumpReason="write", DumpPID=100,
            DumpAddr="0x1000", DumpSize="0x4", DumpFilename="1000_aa"),
        {"Plugin": "tlsmon", "client_random": "aa", "master_key": "bb"})
    (job / "extracted").mkdir()
    (job / "extracted" / "file.000001.mm").write_bytes(b"MZ dropped")
    (job / "extracted" / "file.000001.metadata").write_text(json.dumps(
        {"FileName": "\\Users\\u\\evil.exe", "PID": 100, "ProcessName": CMD}))
    (job / "extracted" / "file.000002.mm").write_bytes(b"someone else's")
    (job / "extracted" / "file.000002.metadata").write_text(json.dumps(
        {"FileName": "\\Windows\\x.pf", "PID": 50, "ProcessName": "explorer.exe"}))
    (job / "dumps").mkdir()
    (job / "dumps" / "1000_aa").write_bytes(b"\x90\x90\x90\x90")
    (job / "procdumps").mkdir()
    (job / "procdumps" / "procdump.0").write_bytes(b"dump")
    (job / "procdumps" / "procdump.0.metadata").write_text(json.dumps(
        {"DataFileName": "procdump.0", "PID": 100, "ProcessName": "cmd.exe", "Compression": "gzip",
         "DumpSize": "0x4", "Status": "Success"}))
    context = PostprocessContext(job, PostprocessingConfig(), TargetOs.WINDOWS)

    results = cape_analysis.run_cape(
        context, CapeConfigSection(capa=False, signatures=False, compress_trace=False))

    # Only the sample's (PID 100) file and connection, not explorer's.
    assert [(d["name"], d["guest_paths"], d["pid"]) for d in results["dropped"]] == \
        [(["evil.exe"], ["\\Users\\u\\evil.exe"], 100)]
    assert len(results["dropped"][0]["sha256"]) == 64
    assert [(c["dst"], c["dport"], c["process_id"]) for c in results["network"]["tcp"]] == \
        [("203.0.113.7", 443, 100)]
    assert results["network"]["hosts"][0]["ports"] == [443]
    assert [(p["pid"], p["address_space"][0]["start"]) for p in results["procmemory"]] == \
        [(100, "0x1000")]
    assert [(p["pid"], p["compression"]) for p in results["procdump"]] == [(100, "gzip")]
    assert results["tlskeys"] == {"keys": 1}
    assert (job / "wireshark_key_file.txt").read_text() == "CLIENT_RANDOM aa bb\n"


def test_dumps_drops_and_calls_are_the_samples_even_with_scope_all(tmp_path):
    job = write_trace(
        tmp_path, *BASE,
        rec("syscall", 0x10, 100, method="NtClose", Syscall=15, PreviousMode="User"),
        rec("syscall", 0x11, 50, method="NtClose", Syscall=15, PreviousMode="User"),
        rec("memdump", 0x12, 100, method="NtWriteVirtualMemory", DumpReason="write", DumpPID=100,
            DumpAddr="0x1000", DumpSize="0x4", DumpFilename="1000_aa"),
        rec("memdump", 0x13, 50, method="NtWriteVirtualMemory", DumpReason="write", DumpPID=50,
            DumpAddr="0x2000", DumpSize="0x4", DumpFilename="2000_bb"))
    (job / "dumps").mkdir()
    for name in ("1000_aa", "2000_bb"):
        (job / "dumps" / name).write_bytes(b"\x90\x90\x90\x90")
    (job / "procdumps").mkdir()
    for n, pid in ((0, 100), (1, 50)):
        (job / "procdumps" / f"procdump.{n}").write_bytes(b"dump")
        (job / "procdumps" / f"procdump.{n}.metadata").write_text(json.dumps(
            {"DataFileName": f"procdump.{n}", "PID": pid, "ProcessName": "x.exe",
             "Compression": "none", "DumpSize": "0x4", "Status": "Success"}))
    (job / "extracted").mkdir()
    (job / "extracted" / "file.000002.mm").write_bytes(b"someone else's")
    (job / "extracted" / "file.000002.metadata").write_text(json.dumps(
        {"FileName": "\\Windows\\x.pf", "PID": 50, "ProcessName": "explorer.exe"}))
    context = PostprocessContext(job, PostprocessingConfig(), TargetOs.WINDOWS)

    results = cape_analysis.run_cape(
        context, CapeConfigSection(scope="all", capa=False, signatures=False, compress_trace=False))

    # Every process is behaviour's under scope "all"...
    assert {p["process_id"] for p in results["behavior"]["processes"]} >= {100, 50}
    # ...but the dumps, the drops and the call log are the sample's alone
    assert [p["pid"] for p in results["procmemory"]] == [100]
    assert [p["pid"] for p in results["procdump"]] == [100]
    assert results["dropped"] == []
    index = json.loads((job / cape_analysis.CALLS_INDEX).read_text())
    assert [v["pid"] for v in index["processes"].values()] == [100]


def test_a_process_dump_is_read_from_its_own_directory_only(tmp_path):
    # procdump2 names its data file "procdump.N". A sidecar naming a file
    # elsewhere on Dom0 has its name alone looked up, as the other two do.
    job = write_trace(tmp_path, *BASE)
    (job / "elsewhere").write_bytes(b"not a dump")
    (job / "procdumps").mkdir()
    for n, name in enumerate((str(job / "elsewhere"), "../elsewhere")):
        (job / "procdumps" / f"procdump.{n}.metadata").write_text(json.dumps(
            {"DataFileName": name, "PID": 100, "ProcessName": "cmd.exe", "Compression": "none"}))
    context = PostprocessContext(job, PostprocessingConfig(), TargetOs.WINDOWS)

    results = cape_analysis.run_cape(
        context, CapeConfigSection(capa=False, signatures=False, compress_trace=False))

    assert results["procdump"] == []


def test_the_report_knows_the_sample_by_seqid(tmp_path):
    results = behaviour_results(
        tmp_path, *BASE,
        create(0x10, 100, 200),
        rec("syscall", 0x11, 200, ppid=100, method="NtClose", Syscall=15, PreviousMode="User"),
        rec("filetracer", 0x12, 200, ppid=100, method="NtWriteFile", FileName="\\??\\C:\\x.txt",
            FileHandle="0x10"),
        rec("apimon", 0x13, 200, ppid=100, Event="api_called", Method="DeleteFileW", ReturnValue="0x1",
            Arguments=['lpFileName=0x1:"C:\\\\y.txt"']))
    split = results["trace_split"]
    by_pid = {p["process_id"]: p for p in results["behavior"]["processes"]}
    assert split["roots"] == [by_pid[100]["seqid"]]
    assert set(split["sample"]) == {by_pid[100]["seqid"], by_pid[200]["seqid"]}
    # The child names its parent by seqid, in the processes and the tree
    assert by_pid[200]["parent_seqid"] == by_pid[100]["seqid"]
    tree = results["behavior"]["processtree"]
    assert tree[0]["seqid"] == by_pid[100]["seqid"]
    assert tree[0]["children"][0]["seqid"] == by_pid[200]["seqid"]
    # Times as numbers, the trace's start among them
    assert isinstance(results["info"]["started_ts"], float)
    assert isinstance(by_pid[200]["started_ts"], float)
    # A timeline event says which process made it
    events = results["behavior"]["enhanced"]
    for kind in ("write", "delete"):     # the kernel's, and an API's
        event = next(e for e in events if e["event"] == kind)
        assert (event["pid"], event["seqid"]) == (200, by_pid[200]["seqid"])


def test_the_samples_calls_are_written_in_chunks_the_index_finds(tmp_path):
    import gzip as _gzip
    chunk = cape_analysis.CALLS_PER_CHUNK
    calls = [rec("syscall", 0x100 + n, 100, method="NtClose", Syscall=15, PreviousMode="User",
                 Handle=hex(n)) for n in range(chunk * 2 + 5)]
    results = behaviour_results(
        tmp_path, *BASE, *calls,
        # explorer is not the sample: no calls of it are written
        rec("syscall", 0x10, 50, method="NtClose", Syscall=15, PreviousMode="User"))
    job = tmp_path / "b"
    index = json.loads((job / cape_analysis.CALLS_INDEX).read_text())
    written = json.loads((job / cape_analysis.CAPE_RESULTS).read_text())
    sample = next(p for p in written["behavior"]["processes"] if p["process_id"] == 100)
    entry = index["processes"][str(sample["seqid"])]
    assert list(index["processes"]) == [str(sample["seqid"])]
    assert entry["count"] == sample["call_count"] == chunk * 2 + 5
    assert [c[2] for c in entry["chunks"]] == [0, chunk, chunk * 2]
    # A chunk is one gzip member at its offset: inflated alone, its calls
    # are the ones at those cids, in order
    log_bytes = (job / cape_analysis.CALLS_LOG).read_bytes()
    offset, length, first, categories = entry["chunks"][1]
    rows = [json.loads(line) for line in _gzip.decompress(log_bytes[offset:offset + length]).splitlines()]
    assert len(rows) == chunk and sum(categories.values()) == chunk
    assert rows[0]["api"] == "NtClose" and rows[0]["kernel"] is True
    assert {a["name"]: a["value"] for a in rows[0]["arguments"]}["Handle"] == hex(chunk)


# --- Signatures --------------------------------------------------------------------

def test_signatures_written_for_cape_load_and_run(tmp_path):
    """A signature in CAPE's own layout and imports, as the community tree's
    are, is loaded, filtered by platform and run over the calls."""
    from sandboxd.postprocessing.plugins.cape_plugin import signatures as loader

    sigs = tmp_path / "community" / "modules" / "signatures"
    for group in ("windows", "linux"):
        (sigs / group).mkdir(parents=True)
    (sigs / "utils.py").write_text("import re\n")
    (sigs / "windows" / "opens_valve.py").write_text(
        "from lib.cuckoo.common.abstracts import Signature\n"
        "from modules.signatures.utils import re\n"
        "class OpensValve(Signature):\n"
        "    name = 'opens_valve'\n    description = 'd'\n    severity = 2\n"
        "    categories = ['generic']\n    evented = True\n    ttps = ['T1012']\n"
        "    filter_apinames = set(['RegOpenKeyExW'])\n"
        "    def on_call(self, call, process):\n"
        "        if re.search('valve', self.get_argument(call, 'SubKey') or '', re.I):\n"
        "            self.mark_call()\n            return True\n")
    (sigs / "linux" / "never.py").write_text(
        "from lib.cuckoo.common.abstracts import Signature\n"
        "class Never(Signature):\n    name = 'never'\n    evented = True\n"
        "    def on_call(self, call, process):\n        return True\n")
    job = tmp_path / "job"
    job.mkdir()
    write_trace(job, *BASE,
                rec("apimon", 0x10, 100, Event="api_called", Method="RegOpenKeyExW",
                    ReturnValue="0x0", Arguments=['lpSubKey=0x1:"SOFTWARE\\\\Valve"']))
    context = PostprocessContext(job, PostprocessingConfig(), TargetOs.WINDOWS)
    try:
        results = cape_analysis.run_cape(context, CapeConfigSection(
            capa=False, community=tmp_path / "community", compress_trace=False))
    finally:
        # The registry and the import shims are process-wide.
        loader._loaded_from = None
        loader.list_plugins("signatures").clear()
        for name in [n for n in sys.modules if n.startswith("modules.signatures")]:
            del sys.modules[name]

    assert [s["name"] for s in results["signatures"]] == ["opens_valve"]
    assert results["signatures"][0]["data"] == [{"type": "call", "pid": 100, "cid": 0}]
    assert results["ttps"] == [{"signature": "opens_valve", "ttps": ["T1012"], "mbcs": []}]
    assert results["malscore"] > 0
