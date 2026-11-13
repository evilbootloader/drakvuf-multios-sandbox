"""What is not the sample's and was reported as if it were, and what was the
sample's and was not reported: the launch sandboxd wraps a Windows sample in,
the guest's other traffic on the wire, an API call swallowed by the kernel's
record of it, a status that was always True, and Linux paths as filetracer
prints them at the syscall.

Each shape is from the five jobs of 2026-11-12 (a benign installer, a script
and a RAT on Windows; a shell dropper and a bot on Ubuntu).
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd.guests import TargetOs  # noqa: E402
from sandboxd.postprocessing.plugins.cape_plugin.modules import Network  # noqa: E402
from sandboxd.postprocessing.plugins.plugin_base import (  # noqa: E402
    CapeConfigSection, PostprocessContext, PostprocessingConfig,
)
from sandboxd.tests.test_cape_split import (  # noqa: E402
    BASE, behaviour, cape_analysis, inject, processes, rec, running, write_trace,
)

PING = "C:\\Windows\\System32\\PING.EXE"
SAMPLE = "C:\\Users\\u\\Desktop\\sample.exe"


def created(uid, pid, new_pid, image, command_line):
    """procmon's record of a process creation (g_strescape'd, as win.cpp prints it)."""
    return rec("procmon", uid, pid, method="NtCreateUserProcess", Status="0x0", NewPid=new_pid,
               CommandLine=command_line.replace("\\", "\\\\"), ImagePathName=image)


def key_set(uid, pid, name):
    return rec("regmon", uid, pid, method="NtSetValueKey", Key=f"\\REGISTRY\\MACHINE\\SOFTWARE\\{name}",
               ValueName="v", Value="01")


def launched(*sample_records):
    """sandboxd's launch: the injected cmd.exe (100) with its console host
    (110), the wait (120) and the sample (130)."""
    return (*BASE,
            created(0x10, 100, 110, "C:\\Windows\\System32\\conhost.exe",
                    "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1"),
            created(0x11, 100, 120, PING, f"{PING}  -n 5 127.0.0.1"),
            key_set(0x12, 100, "ByTheShell"),
            key_set(0x13, 110, "ByTheConsoleHost"),
            key_set(0x14, 120, "ByTheWait"),
            created(0x15, 100, 130, SAMPLE, f'"{SAMPLE}"'),
            key_set(0x16, 130, "ByTheSample"),
            *sample_records)


def run(tmp_path, *records, os_=TargetOs.WINDOWS, sample=None, **cfg):
    (tmp_path / "job").mkdir()
    job = write_trace(tmp_path / "job", *records)
    return cape_analysis.run_cape(PostprocessContext(job, PostprocessingConfig(), os_),
                                  CapeConfigSection(capa=cfg.pop("with_capa", False), signatures=False, **cfg),
                                  sample)


def launchers(results):
    return sorted(p["process_id"] for p in results["behavior"]["processes"] if p.get("launcher"))


# --- the launch is sandboxd's, not the sample's ------------------------------------------

def test_the_launch_is_in_the_tree_and_out_of_the_behaviour(tmp_path):
    results = run(tmp_path, *launched())
    behavior = results["behavior"]
    assert launchers(results) == [100, 110, 120]
    # Every process is still a process of the report, with its calls
    assert sorted(p["process_id"] for p in behavior["processes"]) == [100, 110, 120, 130]
    assert all(len(list(p["calls"])) for p in behavior["processes"])
    written = behavior["summary"]["write_keys"]
    assert len(written) == 1 and "ByTheSample" in written[0]
    # the shell starting the wait and the sample is no command the sample ran
    assert behavior["summary"]["executed_commands"] == []


def test_the_launch_is_scored_when_asked_to(tmp_path):
    results = run(tmp_path, *launched(), skip_launcher=False)
    assert launchers(results) == []
    assert len(results["behavior"]["summary"]["write_keys"]) == 4


def test_a_batch_file_runs_in_the_shell_which_then_is_the_sample(tmp_path):
    script = tmp_path / "sample.bat"
    script.write_text("@echo off\n")
    results = run(tmp_path, *launched(), sample=script)
    assert launchers(results) == [110, 120]
    written = " ".join(results["behavior"]["summary"]["write_keys"])
    assert "ByTheShell" in written and "ByTheSample" in written and "ByTheWait" not in written


def test_a_shell_that_started_no_wait_is_the_sample(tmp_path):
    # A direct launch (a name cmd.exe cannot be given), or a sample that is cmd.exe
    results = run(tmp_path, *BASE, key_set(0x10, 100, "ByTheShell"),
                  created(0x11, 100, 120, PING, f"{PING} -n 1 example.com"))
    assert launchers(results) == []
    assert len(results["behavior"]["summary"]["write_keys"]) == 1


# --- an API call is not a repeat of the kernel's record of it ------------------------------

def test_ntdlls_stub_is_a_call_beside_the_syscall_it_makes(tmp_path):
    same = dict(KeyHandle="0x10", DesiredAccess="0x20019")
    [p] = processes(
        tmp_path, *BASE,
        rec("syscall", 0x10, 100, method="NtOpenKeyEx", Module="nt", Syscall=18, PreviousMode="User", **same),
        rec("apimon", 0x11, 100, Event="api_called", Method="NtOpenKeyEx", ReturnValue=None,
            Arguments=[f"{k}={v}" for k, v in same.items()]))
    calls = list(p["calls"])
    assert [(c.get("syscall"), c.get("api"), c["repeated"]) for c in calls] == [
        ("NtOpenKeyEx", None, 0), (None, "NtOpenKeyEx", 0)]


# --- status ----------------------------------------------------------------------------

def test_an_ntstatus_that_failed_is_a_call_that_failed(tmp_path):
    def api(uid, name, ret):
        return rec("apimon", uid, 100, Event="api_called", Method=name, ReturnValue=ret, Arguments=[])
    [p] = processes(tmp_path, *BASE,
                    api(0x10, "NtCreateFile", "0xc0000034"),          # STATUS_OBJECT_NAME_NOT_FOUND
                    api(0x11, "NtCreateFile", "0x0"),
                    api(0x12, "NtQueryValueKey", "0x80000005"),       # STATUS_BUFFER_OVERFLOW, a warning
                    api(0x13, "LdrLoadDll", "0xc0000135"),
                    api(0x14, "NtReadFile", "0x103"),                 # STATUS_PENDING
                    api(0x15, "CreateFileW", "0xffffffffffffffff"))   # its own convention: not judged
    assert [(c["api"], c["status"]) for c in p["calls"]] == [
        ("NtCreateFile", False), ("NtCreateFile", True), ("NtQueryValueKey", False),
        ("LdrLoadDll", False), ("NtReadFile", True), ("CreateFileW", True)]


def test_a_process_creation_that_failed_is_no_executed_command(tmp_path):
    # wscript.exe given a .js as an image: STATUS_INVALID_IMAGE_NOT_MZ, then ShellExecute
    failed = rec("procmon", 0x10, 100, method="NtCreateUserProcess", Status="0xc000012f", NewPid=0,
                 CommandLine="C:\\\\Users\\\\u\\\\x.js", ImagePathName="C:\\Users\\u\\x.js")
    summary = behaviour(tmp_path, *BASE, failed)["summary"]
    assert summary["executed_commands"] == []


# --- Linux paths, as filetracer prints them at the syscall -----------------------------------

def ftrace(uid, pid, syscall, name, **extra):
    return rec("filetracer", uid, pid, ppid=1, method="do_syscall_64", Syscall=syscall, FileName=name, **extra)


def test_a_relative_path_is_in_the_directory_the_process_is_in(tmp_path):
    exec_ = dict(ppid=1, method="do_execveat_common", FileName="/tmp/s", ImagePathName="/usr/bin/dash",
                 CommandLine="/bin/sh /tmp/s")
    summary = behaviour(
        tmp_path, inject(100),
        rec("procmon", 0x0f, 100, Environment="PWD=/", **exec_),
        rec("syscall", 0x10, 100, ppid=1, method="chdir", Module="linux", Syscall=80, path="/tmp"),
        ftrace(0x11, 100, "openat", "jva", dirfd="-100", flags="577"),          # O_WRONLY|O_CREAT|O_TRUNC
        ftrace(0x12, 100, "fchmodat", "jva", dirfd="-100"),
        # FileName is the old path here, `newpath` the new one
        ftrace(0x13, 100, "renameat2", "jva", olddirfd="-100", newdirfd="-100", newpath="sshd"),
        ftrace(0x14, 100, "unlinkat", "./sshd", dirfd="-100"),
        # A log removed is behaviour; one written is every daemon's
        ftrace(0x15, 100, "unlinkat", "/var/log/auth.log", dirfd="-100"),
        ftrace(0x16, 100, "write", "/var/log/syslog"),
        os_=TargetOs.UBUNTU)["summary"]
    assert summary["write_files"] == ["/tmp/jva", "/tmp/sshd"]
    assert summary["delete_files"] == ["/tmp/jva", "/tmp/sshd", "/var/log/auth.log"]
    assert "/var/log/syslog" not in summary["files"]


def test_a_rename_is_a_move_whichever_end_filetracer_names(tmp_path):
    exec_ = rec("procmon", 0x0f, 100, ppid=1, method="do_execveat_common", FileName="/tmp/s",
                ImagePathName="/tmp/s", CommandLine="/tmp/s", Environment="PWD=/tmp")
    enhanced = behaviour(
        tmp_path, inject(100), exec_,
        ftrace(0x10, 100, "renameat2", "jva", newpath="sshd"),                   # hooked at the syscall
        ftrace(0x11, 100, "rename", "/home/u/.x/run", old_name="/tmp/dl.bin"),   # hooked at the VFS function
        os_=TargetOs.UBUNTU)["enhanced"]
    assert [e["data"] for e in enhanced if e["event"] == "move"] == [
        {"from": "/tmp/jva", "to": "/tmp/sshd"}, {"from": "/tmp/dl.bin", "to": "/home/u/.x/run"}]


def test_a_fork_is_named_as_the_program_it_runs(tmp_path):
    exec_ = rec("procmon", 0x0f, 100, ppid=1, method="do_execveat_common", FileName="/tmp/bot",
                ImagePathName="/tmp/bot", CommandLine="/tmp/bot -d", Environment="PWD=/")
    fork = rec("procmon", 0x10, 100, ppid=1, method="kernel_clone", Flags="(null)", NewPid=200)
    procs = processes(tmp_path, inject(100), exec_, fork,
                      rec("syscall", 0x11, 200, ppid=100, method="setsid", Module="linux", Syscall=112),
                      os_=TargetOs.UBUNTU)
    child = next(p for p in procs if p["process_id"] == 200)
    assert (child["process_name"], child["module_path"]) == ("bot", "/tmp/bot")
    assert child["environ"]["CommandLine"] == "/tmp/bot -d"


# --- the wire is the guest's; the report is the sample's ------------------------------------

def network(scope="sample"):
    module = Network.__new__(Network)
    module.options = SimpleNamespace(scope=scope, sample_pids={100})
    return module


def wire():
    return {
        "hosts": [{"ip": "13.107.4.52", "ports": [80]}, {"ip": "203.0.113.9", "ports": [4444]},
                  {"ip": "198.51.100.7", "ports": [443]}],
        "tcp": [{"src": "172.16.1.2", "sport": 50000, "dst": "13.107.4.52", "dport": 80},
                {"src": "172.16.1.2", "sport": 50001, "dst": "203.0.113.9", "dport": 4444}],
        "udp": [], "icmp": [],
        "http": [{"uri": "http://www.msftconnecttest.com/connecttest.txt", "dst": "13.107.4.52"}],
        "tls": [{"dst": "198.51.100.7", "sni": "unattributed.example"}],
        "dns": [{"request": "www.msftconnecttest.com", "answers": [{"type": "A", "data": "13.107.4.52"}]},
                {"request": "c2.example", "answers": [{"type": "A", "data": "203.0.113.9"}]}],
        "domains": [{"domain": "www.msftconnecttest.com", "ip": "13.107.4.52"},
                    {"domain": "c2.example", "ip": "203.0.113.9"}],
    }


def test_what_only_other_processes_talked_to_is_not_the_samples(tmp_path):
    net = wire()
    network()._drop_background(net, {"13.107.4.52"}, {"www.msftconnecttest.com"})
    assert [h["ip"] for h in net["hosts"]] == ["203.0.113.9", "198.51.100.7"]
    assert [f["dst"] for f in net["tcp"]] == ["203.0.113.9"]
    assert net["http"] == []
    # nobody's, as far as any plugin saw: it stays
    assert [t["sni"] for t in net["tls"]] == ["unattributed.example"]
    assert [d["request"] for d in net["dns"]] == ["c2.example"]
    assert [d["domain"] for d in net["domains"]] == ["c2.example"]
    assert net["background"] == {"hosts": 1, "tcp": 1, "http": 1, "dns": 1, "domains": 1}


def test_the_whole_guest_is_the_report_when_asked_for(tmp_path):
    net = wire()
    network(scope="all")._drop_background(net, {"13.107.4.52"}, {"www.msftconnecttest.com"})
    assert net == wire()


def test_a_socket_is_its_owners_not_the_process_that_was_running(tmp_path):
    # NetBIOS from System, sent while a console host was current
    assert Network._owner({"PID": 428, "OwnerPID": 4}) == 4
    assert Network._owner({"PID": 428}) == 428


# --- a process the sample makes run its code is the sample's -------------------------------

def opened(uid, pid, handle, target, tid=None):
    """procmon's NtOpenProcess / NtOpenThread: the handle given, and whose it
    is. With the opener's real parent: a procmon line naming another one
    moves the process there (tree_from_log, an elevated process)."""
    ppid = {130: 100, 100: 50}[pid]
    if tid is None:
        return rec("procmon", uid, pid, ppid=ppid, method="NtOpenProcess", ProcessHandle=handle,
                   ClientID=target)
    return rec("procmon", uid, pid, ppid=ppid, method="NtOpenThread", ThreadHandle=handle,
               ClientID=target, UniqueThread=tid)


def service(uid, pid, name, ret="0x0", **arguments):
    """A system service as the syscall plugin prints it, and its return."""
    return (rec("syscall", uid, pid, method=name, Module="nt", Syscall=199, PreviousMode="User", **arguments),
            rec("sysret", uid + 1, pid, method=name, Module="nt", Syscall=199, Ret=ret))


def api(uid, pid, name, ret="0x0", **arguments):
    return rec("apimon", uid, pid, Event="api_called", Method=name, ReturnValue=ret,
               Arguments=[f"{k}={v}" for k, v in arguments.items()])


def followed(results):
    return [(f["pid"], f["target_pid"], f["how"]) for f in results["trace_split"]["followed"]]


def test_a_thread_started_in_a_process_outside_the_tree_makes_it_the_samples(tmp_path):
    results = run(tmp_path, *launched(
        key_set(0x20, 50, "ExplorersOwn"),
        opened(0x21, 130, "0x1c4", 50),
        rec("memdump", 0x22, 130, method="NtWriteVirtualMemory", DumpReason="NtWriteVirtualMemory called",
            DumpPID=130, TargetPID=50),
        *service(0x23, 130, "NtCreateThreadEx", ProcessHandle="0x1c4", StartRoutine="0x1000"),
        # apimon's record of the same call is not a second one
        api(0x25, 130, "NtCreateThreadEx", ProcessHandle="0x1c4"),
        key_set(0x26, 50, "ByTheSampleInExplorer")))
    assert followed(results) == [(130, 50, "remote thread (NtCreateThreadEx) after NtWriteVirtualMemory")]
    assert 50 in {p["process_id"] for p in results["behavior"]["processes"]}
    # the whole process, as a followed process always was: the split is by process
    written = " ".join(results["behavior"]["summary"]["write_keys"])
    assert "ByTheSampleInExplorer" in written and "ExplorersOwn" in written
    assert launchers(results) == [100, 110, 120]
    assert results["trace_split"]["launcher_followed"] == []


def test_a_launch_process_the_sample_injects_into_is_the_samples(tmp_path):
    # An APC to a thread of the console host; apimon resolves the thread handle
    results = run(tmp_path, *launched(
        api(0x20, 130, "NtQueueApcThread", ThreadHandle="0x2a8", ProcessId=110, ThreadId=7,
            ApcRoutine="0x1000")))
    assert followed(results) == [(130, 110, "APC queued to a thread (NtQueueApcThread)")]
    assert launchers(results) == [100, 120]
    conhost = next(p for p in results["behavior"]["processes"] if p["process_id"] == 110)
    assert results["trace_split"]["launcher_followed"] == [conhost["seqid"]]
    written = " ".join(results["behavior"]["summary"]["write_keys"])
    assert "ByTheConsoleHost" in written and "ByTheSample" in written and "ByTheShell" not in written


def test_the_shell_of_the_launch_taken_over_is_scored_and_given_to_capa(tmp_path, monkeypatch):
    from sandboxd.postprocessing.plugins.cape_plugin import behaviour as behaviour_module
    seen = {}
    monkeypatch.setattr(behaviour_module, "HAVE_FLARE_CAPA", True)
    monkeypatch.setattr(behaviour_module, "flare_capa_details",
                        lambda results, rules_path, pids, status: seen.update(pids=set(pids)) or {})
    results = run(tmp_path, *launched(
        opened(0x20, 130, "0x1d0", 100, tid=1),
        *service(0x21, 130, "NtSetContextThread", ThreadHandle="0x1d0", Context="0x2000")),
        with_capa=True)
    assert followed(results) == [(130, 100, "thread context set (NtSetContextThread)")]
    assert launchers(results) == [110, 120]
    assert "ByTheShell" in " ".join(results["behavior"]["summary"]["write_keys"])
    assert seen["pids"] == {100, 130}


def test_the_shell_creating_the_sample_is_a_creation_not_an_injection(tmp_path):
    # What cmd.exe did to each child in three jobs of 2026-11-12: two writes
    # (the parameters) and a resume; csrss wrote too. And a hook, a write to
    # itself and a thread of its own, which are nobody's injection.
    results = run(tmp_path, *launched(
        rec("memdump", 0x20, 100, method="NtWriteVirtualMemory", DumpReason="NtWriteVirtualMemory called",
            DumpPID=100, TargetPID=130),
        api(0x21, 100, "NtResumeThread", ThreadHandle="0xd8", ProcessId=130, ThreadId=9),
        *service(0x22, 130, "NtCreateThreadEx", ProcessHandle="0xffffffffffffffff"),
        api(0x24, 130, "NtQueueApcThread", ThreadHandle="0x10", ProcessId=130, ThreadId=9),
        *service(0x25, 130, "NtSetInformationThread", ThreadHandle="0x10", ThreadInformationClass="0x5")))
    assert followed(results) == []
    assert launchers(results) == [100, 110, 120]
    assert sorted(results["trace_split"]["sample"]) == sorted(
        p["seqid"] for p in results["behavior"]["processes"])


def test_what_the_launch_does_to_another_process_is_not_the_samples(tmp_path):
    results = run(tmp_path, *launched(
        opened(0x20, 100, "0x1c4", 50),
        *service(0x21, 100, "NtCreateThreadEx", ProcessHandle="0x1c4")))
    assert followed(results) == []
    assert 50 not in {p["process_id"] for p in results["behavior"]["processes"]}
    # ...and is, when the launch is to be scored as the sample
    (tmp_path / "again").mkdir()
    results = run(tmp_path / "again", *launched(
        opened(0x20, 100, "0x1c4", 50),
        *service(0x21, 100, "NtCreateThreadEx", ProcessHandle="0x1c4")), skip_launcher=False)
    assert followed(results) == [(100, 50, "remote thread (NtCreateThreadEx)")]


def test_a_call_that_failed_or_on_a_handle_since_closed_transfers_nothing(tmp_path):
    results = run(tmp_path, *launched(
        opened(0x20, 130, "0x1c4", 50),
        *service(0x21, 130, "NtCreateThreadEx", ret="0xc0000022", ProcessHandle="0x1c4"),
        rec("syscall", 0x23, 130, method="NtClose", Module="nt", Syscall=15, PreviousMode="User",
            Handle="0x1c4"),
        # the value given again, to a handle nothing here saw opened (a duplicate)
        *service(0x24, 130, "NtCreateThreadEx", ProcessHandle="0x1c4"),
        # a driver's own, in whatever process was current
        rec("syscall", 0x26, 130, method="NtCreateThreadEx", Module="nt", Syscall=199,
            PreviousMode="Kernel", ProcessHandle="0xffffffff80001178")))
    assert followed(results) == []
    assert [(u["pid"], u["call"]) for u in results["trace_split"]["transfers_unresolved"]] == [
        (130, "NtCreateThreadEx")]


def test_a_32_bit_threads_context_set_from_outside_is_a_transfer(tmp_path):
    results = run(tmp_path, *launched(
        opened(0x20, 130, "0x1d0", 50, tid=3),
        *service(0x21, 130, "NtSetInformationThread", ThreadHandle="0x1d0", ThreadInformationClass="0x1d")))
    assert followed(results) == [(130, 50, "thread context set (NtSetInformationThread)")]


def by_broker(uid, broker_pid, name, new_pid, command_line):
    out = created(uid, broker_pid, new_pid, command_line.split('"')[1] if '"' in command_line
                  else command_line.split()[0], command_line)
    out["ProcessName"] = f"\\Device\\HarddiskVolume2\\Windows\\System32\\{name}"
    return out


def test_a_service_the_sample_registered_is_followed_when_services_starts_it(tmp_path):
    binary = "C:\\Users\\u\\AppData\\svc.exe"
    results = run(tmp_path, *launched(
        running(60, 4, "services.exe"),
        api(0x20, 130, "CreateServiceW", ret="0x5f0", lpServiceName='0x1:"upd"',
            lpBinaryPathName='0x2:"\\"C:\\\\Users\\\\u\\\\AppData\\\\svc.exe\\" -k run"'),
        # another service, which the sample named nothing of
        by_broker(0x30, 60, "services.exe", 300, "C:\\Windows\\system32\\sppsvc.exe"),
        by_broker(0x31, 60, "services.exe", 310, f'"{binary}" -k run'),
        key_set(0x32, 300, "ByAnotherService"), key_set(0x33, 310, "ByTheService")))
    assert followed(results) == [
        (130, 310, "services.exe started the service binary it registered (CreateServiceW)")]
    written = " ".join(results["behavior"]["summary"]["write_keys"])
    assert "ByTheService" in written and "ByAnotherService" not in written


def test_a_task_or_a_wmi_command_the_sample_asked_for_is_followed(tmp_path):
    schtasks = "C:\\Windows\\System32\\schtasks.exe"
    wmic = "C:\\Windows\\System32\\wbem\\WMIC.exe"
    results = run(tmp_path, *launched(
        running(60, 4, "svchost.exe"), running(70, 4, "WmiPrvSE.exe"),
        created(0x20, 130, 140, schtasks,
                f'{schtasks} /Create /SC ONLOGON /TN upd /TR "C:\\Users\\u\\t.exe -a" /F'),
        created(0x21, 130, 150, wmic, f'{wmic} process call create "C:\\Users\\u\\w.exe -b"'),
        by_broker(0x30, 60, "svchost.exe", 300, "C:\\Users\\u\\t.exe -a"),
        by_broker(0x31, 70, "WmiPrvSE.exe", 310, "C:\\Users\\u\\w.exe -b"),
        # the same broker, a command nobody of the sample's named
        by_broker(0x32, 60, "svchost.exe", 320, "C:\\Windows\\system32\\wermgr.exe -upload"),
        key_set(0x40, 300, "ByTheTask"), key_set(0x41, 310, "ByWmi"), key_set(0x42, 320, "ByWer")))
    assert followed(results) == [
        (130, 300, "svchost.exe started the /TR command of the schtasks.exe it ran"),
        (130, 310, "wmiprvse.exe started the command of the `wmic process call create` it ran")]
    written = " ".join(results["behavior"]["summary"]["write_keys"])
    assert "ByTheTask" in written and "ByWmi" in written and "ByWer" not in written


def test_a_followed_processs_traffic_is_the_samples(tmp_path):
    # Network reads the sample's PIDs as they are after following
    records = launched(opened(0x21, 130, "0x1c4", 50),
                       *service(0x23, 130, "NtCreateThreadEx", ProcessHandle="0x1c4"))
    (tmp_path / "job").mkdir()
    from sandboxd.postprocessing.plugins.cape_plugin.trace_split import split_by_process
    result = split_by_process(write_trace(tmp_path / "job", *records), tmp_path / "logs", TargetOs.WINDOWS)
    assert result.sample_pids == {50, 100, 110, 120, 130}
    module = network()
    module.options.sample_pids = result.sample_pids
    assert module._in_scope(50) and module._sample_only(50) and not module._in_scope(4)


# --- a compressed process dump is scanned as what it holds --------------------------------

def test_a_gzip_process_dump_is_scanned_inflated_and_left_as_it_was(tmp_path):
    import gzip
    import json
    rules, community = tmp_path / "rules", tmp_path / "community"
    rules.mkdir()
    (rules / "general.yar").write_text('rule general_marker { strings: $a = "BOTNET-MARKER" condition: $a }')
    (community / "data" / "yara" / "CAPE").mkdir(parents=True)
    (community / "data" / "yara" / "CAPE" / "Family.yar").write_text(
        'rule Family { meta: cape_type = "Family Payload" strings: $a = "BOTNET-MARKER" condition: $a }')
    (tmp_path / "job").mkdir()
    job = write_trace(tmp_path / "job", *BASE)
    (job / "procdumps").mkdir()
    packed = gzip.compress(b"\x7fELF" + b"\0" * 4096 + b"BOTNET-MARKER")
    assert b"BOTNET-MARKER" not in packed
    for n, (data, compression) in enumerate(((packed, "gzip"), (b"not gzip at all", "gzip"))):
        (job / "procdumps" / f"procdump.{n}").write_bytes(data)
        (job / "procdumps" / f"procdump.{n}.metadata").write_text(json.dumps(
            {"DataFileName": f"procdump.{n}", "PID": 100, "ProcessName": "bot", "Compression": compression}))
    config = PostprocessingConfig()
    config.yara.rules_directory = rules
    before = sorted(p.name for p in job.rglob("*"))
    results = cape_analysis.run_cape(
        PostprocessContext(job, config, TargetOs.UBUNTU),
        CapeConfigSection(capa=False, signatures=False, compress_trace=False, community=community))
    dump, broken = results["procdump"]
    assert [h["name"] for h in dump["yara"]] == ["general_marker"]
    assert [(h["name"], h["meta"]["cape_type"]) for h in dump["cape_yara"]] == [("Family", "Family Payload")]
    assert dump["scanned_size"] == 4 + 4096 + 13 and dump["size"] == len(packed)
    # listed, not scanned, and the reason kept
    assert broken["yara"] == [] and "scan_error" in broken
    # nothing inflated is left in the job
    after = sorted(p.name for p in job.rglob("*"))
    assert [n for n in after if n not in before] == ["calls.jsonl.gz", "calls_index.json", "cape_results.json"]


# --- capa is fed a bounded number of the same call, and says how it ended -----------------

def test_capa_is_fed_a_bounded_number_of_identical_calls(tmp_path):
    from sandboxd.postprocessing.plugins.cape_plugin import capa_integration as ci
    cap = ci.REPEAT_CAP

    def stat(uid, path):
        return rec("syscall", uid, 100, tid=7, ppid=1, method="stat", Module="linux", Syscall=4, filename=path)
    procs = processes(tmp_path, inject(100),
                      *(stat(0x10 + i, "/proc/1/exe") for i in range(cap + 40)),
                      stat(0x900, "/proc/2/exe"), os_=TargetOs.UBUNTU)
    results = {"behavior": {"processes": procs},
               "target": {"file": {"type": cape_analysis.TARGET_FILE_TYPE[TargetOs.UBUNTU]}}}
    extractor = ci.StreamingCapeExtractor.from_inputs(*ci.capa_inputs(results, {100}))
    [ph] = extractor.get_processes()
    [th] = extractor.get_threads(ph)
    fed = list(extractor.get_calls(ph, th))
    assert len(fed) == cap + 1
    assert (extractor.calls_seen, extractor.calls_fed) == (cap + 41, cap + 1)


def test_the_repeat_cap_is_above_every_count_a_capa_rule_asks_for():
    import re
    from sandboxd.postprocessing.plugins.cape_plugin import capa_integration as ci
    if not ci.DEFAULT_RULES.is_dir():
        import pytest
        pytest.skip("sandboxd/data/capa-rules is not checked out")
    largest = 0
    for path in ci.DEFAULT_RULES.rglob("*.yml"):
        for numbers in re.findall(r"^\s*- count\([^\n]*\):\s*\(?(\d+)(?:,\s*(\d+)\))?", path.read_text(errors="replace"), re.M):
            largest = max(largest, *(int(n) for n in numbers if n))
    assert 0 < largest < ci.REPEAT_CAP


def test_a_capa_run_that_did_not_finish_says_so(tmp_path, monkeypatch):
    from sandboxd.postprocessing.plugins.cape_plugin import capa_integration as ci

    def out_of_memory(*args, **kwargs):
        raise MemoryError()
    monkeypatch.setattr(ci.capa.capabilities.common, "find_capabilities", out_of_memory)
    monkeypatch.setattr(ci, "_rules", lambda path: None)
    procs = processes(tmp_path, inject(100),
                      rec("syscall", 0x10, 100, tid=7, ppid=1, method="getpid", Module="linux", Syscall=39),
                      os_=TargetOs.UBUNTU)
    status = {}
    summary = ci.flare_capa_details(
        {"behavior": {"processes": procs},
         "target": {"file": {"type": cape_analysis.TARGET_FILE_TYPE[TargetOs.UBUNTU]}}},
        rules_path=tmp_path, pids={100}, status=status)
    assert summary == {}
    assert status["completed"] is False and status["error"].startswith("MemoryError")


# --- the sample's type is the sample's, not the guest's -------------------------------------

def pe_file(path, machine=0x14C, plus=False, dll=False, subsystem=2, dotnet=False):
    """The smallest header `file` would call a PE."""
    import struct
    optional = bytearray(240 if plus else 224)
    struct.pack_into("<H", optional, 0, 0x20B if plus else 0x10B)
    struct.pack_into("<H", optional, 68, subsystem)
    directories = 112 if plus else 96
    struct.pack_into("<I", optional, directories - 4, 16)
    if dotnet:
        struct.pack_into("<II", optional, directories + 14 * 8, 0x2008, 72)
    coff = struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, len(optional), 0x2002 if dll else 0x0002)
    dos = bytearray(0x80)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    path.write_bytes(bytes(dos) + b"PE\0\0" + coff + bytes(optional))
    return path


def elf_file(path, bits=32, machine=3, kind=2, dynamic=False):
    import struct
    ident = b"\x7fELF" + bytes([1 if bits == 32 else 2, 1, 1, 0]) + bytes(8)
    if bits == 32:
        header = struct.pack("<HHIIIIIHHHHHH", kind, machine, 1, 0, 0x34, 0, 0, 0x34, 32, 1, 0, 0, 0)
        program = struct.pack("<IIIIIIII", 2 if dynamic else 1, 0, 0, 0, 0, 0, 0, 0)
    else:
        header = struct.pack("<HHIQQQIHHHHHH", kind, machine, 1, 0, 0x40, 0, 0, 0x40, 56, 1, 0, 0, 0)
        program = struct.pack("<IIQQQQQQ", 2 if dynamic else 1, 0, 0, 0, 0, 0, 0, 0)
    path.write_bytes(ident + header + program)
    return path


def test_a_file_is_typed_from_its_own_bytes(tmp_path):
    from sandboxd.postprocessing.plugins.cape_plugin.filetype import package, sniff

    def text(name, content):
        (tmp_path / name).write_text(content)
        return tmp_path / name
    cases = [
        (pe_file(tmp_path / "a.exe"), "PE32 executable (GUI) Intel 80386, for MS Windows", "exe"),
        (pe_file(tmp_path / "b.exe", machine=0x8664, plus=True, subsystem=3),
         "PE32+ executable (console) x86-64, for MS Windows", "exe"),
        (pe_file(tmp_path / "c.bin", dll=True), "PE32 executable (DLL) Intel 80386, for MS Windows", "dll"),
        (pe_file(tmp_path / "d.exe", dotnet=True, subsystem=3),
         "PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows", "exe"),
        (elf_file(tmp_path / "e.elf"),
         "ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked", "elf"),
        (elf_file(tmp_path / "f", bits=64, machine=62, kind=3, dynamic=True),
         "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked", "elf"),
        (text("g.sh", "#!/bin/sh\necho x\n"), "POSIX shell script, ASCII text executable", "sh"),
        (text("h", "#!/usr/bin/env python3\n"), "Python script, ASCII text executable", "python"),
        (text("i.js", "var a = 1;\n"), "JavaScript source, ASCII text", "js"),
        (text("j.vbs", "WScript.Echo 1\n"), "VBScript source, ASCII text", "vbs"),
        (text("k.ps1", "Write-Host 1\n"), "PowerShell script, ASCII text", "ps1"),
        (text("l.bat", "@echo off\n"), "DOS batch file, ASCII text", "batch"),
        (text("m.txt", "plain\n"), "ASCII text", "generic"),
    ]
    (tmp_path / "n.lnk").write_bytes(b"L\x00\x00\x00\x01\x14\x02\x00" + bytes(64))
    (tmp_path / "o.jar").write_bytes(b"PK\x03\x04" + bytes(64))
    (tmp_path / "p.bin").write_bytes(bytes(range(256)))
    cases += [(tmp_path / "n.lnk", "MS Windows shortcut", "lnk"),
              (tmp_path / "o.jar", "Java archive data (JAR)", "jar"),
              (tmp_path / "p.bin", "data", "generic")]
    for path, file_type, package_name in cases:
        assert sniff(path) == file_type, path.name
        assert package(file_type, path.name) == package_name, path.name


def test_the_target_is_the_sample_and_capa_still_reads_the_guest(tmp_path, monkeypatch):
    from sandboxd.postprocessing.plugins.cape_plugin import capa_integration, modules
    from sandboxd.postprocessing.plugins.cape_plugin.scoring import calc_scoring
    monkeypatch.setattr(modules, "magic", None)      # Dom0
    script = tmp_path / "dropper.js"
    script.write_text("WScript.Sleep(1);\n")
    results = run(tmp_path, *launched(), sample=script)
    assert results["target"]["file"]["type"] == "JavaScript source, ASCII text"
    assert results["info"]["package"] == "js"
    assert results["info"]["guest_type"] == cape_analysis.TARGET_FILE_TYPE[TargetOs.WINDOWS]
    # a script is scored as one: no status from the executables' branch
    assert calc_scoring(results, [{"name": "x", "severity": 3, "confidence": 100, "weight": 1,
                                   "categories": ["malware"]}])[1] is None
    # capa: the guest's format and arch, whatever the sample is
    report, _ = capa_integration.capa_inputs({**results, "behavior": {"processes": []}}, None)
    assert report["target"]["file"]["type"] == cape_analysis.TARGET_FILE_TYPE[TargetOs.WINDOWS]

    (tmp_path / "pe").mkdir()
    results = run(tmp_path / "pe", *launched(), sample=pe_file(tmp_path / "old.exe"))
    assert results["target"]["file"]["type"].startswith("PE32 executable (GUI) Intel 80386")
    assert results["info"]["package"] == "exe"
    # no sample file: the guest's type and the old package, as before
    (tmp_path / "none").mkdir()
    results = run(tmp_path / "none", *launched())
    assert results["target"]["file"]["type"] == cape_analysis.TARGET_FILE_TYPE[TargetOs.WINDOWS]
    assert results["info"]["package"] == "exe"


# --- a handle is a process: capemon's ProcessId -----------------------------------------

def test_a_call_on_a_process_handle_says_whose_process_it_is(tmp_path):
    def read(uid, handle):
        return api(uid, 100, "ReadProcessMemory", ret="0x1", hProcess=handle, lpBaseAddress="0x1000")
    opened_other = api(0x12, 100, "NtOpenProcess", ProcessHandle="0xd7f947e508", DesiredAccess="0x10",
                       ClientId='0xd7f947e4a0:"50:0"')
    # procmon's record of the same service: the handle that was given
    opened_other["Kernel"] = [{"Plugin": "procmon", "Method": "NtOpenProcess", "ProcessHandle": "0x1c4",
                               "ClientID": 50}]
    [p] = processes(
        tmp_path, *BASE,
        api(0x10, 100, "OpenProcess", ret="0x18c", dwDesiredAccess="0x10", dwProcessId="0x64"),   # itself
        read(0x11, "0x18c"),
        opened_other,
        read(0x13, "0x1c4"),
        read(0x14, "0xffffffffffffffff"),
        read(0x15, "0x2f0"),                                   # duplicated, inherited: nobody's
        rec("syscall", 0x16, 100, method="NtClose", Module="nt", Syscall=15, PreviousMode="User",
            Handle="0x18c"),
        read(0x17, "0x18c"),
        api(0x18, 100, "NtTerminateProcess", ProcessHandle="0x0", ExitStatus="0x0"))

    def pid_of(call):
        return next((a["value"] for a in call["arguments"] if a["name"] == "ProcessId"), None)
    reads = [pid_of(c) for c in p["calls"] if c.get("api") == "ReadProcessMemory"]
    assert reads == ["100", "50", "100", None, None]
    assert [pid_of(c) for c in p["calls"] if c.get("api") == "NtTerminateProcess"] == ["100"]
    # and a second reading of the calls says the same (the handles start over)
    assert [pid_of(c) for c in p["calls"] if c.get("api") == "ReadProcessMemory"] == reads


# --- the community's signatures over DRAKVUF's calls ---------------------------------------

COMMUNITY = ROOT / "sandboxd" / "data" / "cape-community"


def signed(tmp_path, *records, community=COMMUNITY, sample=None):
    """{name: matched signature} and the results, the signatures run."""
    import pytest
    if not (community / "modules" / "signatures").is_dir():
        pytest.skip("the community checkout is not here")
    job = tmp_path / f"job{len(list(tmp_path.iterdir()))}"
    job.mkdir()
    write_trace(job, *launched(*records))
    results = cape_analysis.run_cape(PostprocessContext(job, PostprocessingConfig(), TargetOs.WINDOWS),
                                     CapeConfigSection(capa=False, community=community), sample)
    return {s["name"]: s for s in results["signatures"]}, results


def key_opened(uid, key, access):
    return api(uid, 130, "NtOpenKeyEx", KeyHandle="0x10", DesiredAccess=access, ObjectAttributes="0x20",
               Key=f"\\REGISTRY\\MACHINE\\{key}")


def test_a_script_host_initialising_amsi_is_not_enumerating_it(tmp_path):
    providers = "Software\\Microsoft\\AMSI\\Providers"
    # AmsiInitialize in WScript.exe, 2026-11-12: both keys, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS
    quiet, _ = signed(tmp_path, key_opened(0x20, providers, "0x9"), key_opened(0x21, providers + "2", "0x9"))
    assert "amsi_enumeration" not in quiet
    for records in ([key_opened(0x20, providers, "0x2001f")],                       # to write
                    [key_opened(0x20, providers + "\\{2781761E-28E0-4109-99FE-B9D127C57AFE}", "0x9")]):
        loud, _ = signed(tmp_path, *records)
        assert "amsi_enumeration" in loud


def test_opening_ntdll_is_not_loading_it_from_disk(tmp_path):
    ntdll = "C:\\Windows\\SYSTEM32\\ntdll.dll"
    # the WoW64 loader, at every 32-bit process start: READ_CONTROL, nothing read
    opened_ = api(0x20, 130, "NtOpenFile", FileHandle="0x19f1d0", DesiredAccess="0x20000", FileName=ntdll)
    quiet, _ = signed(tmp_path, opened_)
    assert "suspicious_ntdll_disk_load" not in quiet
    read, _ = signed(tmp_path, opened_,
                     api(0x21, 130, "NtReadFile", FileHandle="0x1a4", Length="0x1000", HandleName=ntdll))
    assert "suspicious_ntdll_disk_load" in read
    mapped, _ = signed(tmp_path, opened_,
                       api(0x21, 130, "NtCreateSection", SectionHandle="0x30", FileHandle="0x1a4", FileName=ntdll),
                       api(0x22, 130, "NtProtectVirtualMemory", ProcessHandle="0xffffffffffffffff",
                           BaseAddress="0x1000", NewAccessProtection="0x40"))
    assert "suspicious_ntdll_disk_load" in mapped


def test_reading_its_own_memory_through_a_handle_is_not_reading_anothers(tmp_path):
    def reading(pid):
        return (api(0x20, 130, "OpenProcess", ret="0x18c", dwDesiredAccess="0x10", dwProcessId=hex(pid)),
                api(0x21, 130, "ReadProcessMemory", ret="0x1", hProcess="0x18c", ProcessHandle="0x18c",
                    Buffer="MZ", lpBaseAddress="0x1000"))
    own, _ = signed(tmp_path, *reading(130))
    assert "reads_memory_remote_process" not in own
    other, _ = signed(tmp_path, *reading(50))
    assert "reads_memory_remote_process" in other


def test_a_hashed_binary_block_names_no_ioc_and_marks_are_bounded(tmp_path):
    from sandboxd.postprocessing.plugins.cape_plugin.abstracts import Signature

    def hashed(uid, buffer):
        return api(uid, 130, "CryptHashData", ret="0x1", hHash="0x10", Buffer=buffer, Length="0x20")
    binary = "\\x8a\\x01k.io\\xff\\x00a.bc\\x10"
    quiet, _ = signed(tmp_path, *(hashed(0x20 + i, binary) for i in range(5)))
    assert "encrypted_ioc" not in quiet
    many = Signature.MAX_CALL_MARKS + 50
    loud, _ = signed(tmp_path, hashed(0x20, "http://c2.example.net/gate.php"),
                     # (told apart: identical calls in a row are one call, `repeated`)
                     *(hashed(0x21 + i, f"{binary}{i}") for i in range(many - 1)))
    found = loud["encrypted_ioc"]
    assert {"ioc": "http://c2.example.net/gate.php"} in found["data"]
    assert sum(1 for d in found["data"] if d.get("type") == "call") == Signature.MAX_CALL_MARKS
    assert found["call_marks"] == many


def test_a_resolved_function_nobody_named_is_not_listed(tmp_path):
    def resolved(uid, **names):
        return api(uid, 130, "LdrGetProcedureAddress", DllHandle="0x7ffa54430000", ProcedureNumber=hex(uid),
                   ProcedureAddress="0x10", **names)
    found, _ = signed(tmp_path, api(0x20, 130, "LdrLoadDll", FileName="a.dll", DllHandle="0x10"),
                      *(resolved(0x21 + i) for i in range(8)),
                      resolved(0x40, ProcedureName='0x1:"VirtualAlloc"'))
    data = found["dynamic_function_loading"]["data"]
    assert [d["DynamicLoader"] for d in data if "DynamicLoader" in d] == ["None/VirtualAlloc"]


def test_a_signature_that_raised_is_recorded_not_only_logged(tmp_path):
    import sys as _sys
    from sandboxd.postprocessing.plugins.cape_plugin import signatures as loader
    sigs = tmp_path / "community" / "modules" / "signatures" / "windows"
    sigs.mkdir(parents=True)
    (sigs / "broken.py").write_text(
        "from lib.cuckoo.common.abstracts import Signature\n"
        "class BrokenRun(Signature):\n    name = 'broken_run'\n    description = 'd'\n"
        "    def run(self):\n        return self.results['nowhere']['x']\n"
        "class BrokenEnd(Signature):\n    name = 'broken_end'\n    description = 'd'\n    evented = True\n"
        "    filter_apinames = set(['Sleep'])\n"
        "    def on_call(self, call, process):\n        return None\n"
        "    def on_complete(self):\n        return self.never_set\n")
    saved = (loader._loaded_from, list(loader.list_plugins("signatures")))
    try:
        loader._loaded_from = None
        loader.list_plugins("signatures").clear()
        _, results = signed(tmp_path, api(0x20, 130, "Sleep"), community=tmp_path / "community")
    finally:
        loader._loaded_from = None
        loader.list_plugins("signatures").clear()
        for name in [n for n in _sys.modules if n.startswith("modules.signatures")]:
            del _sys.modules[name]
    failures = {(f["name"], f["stage"], f["error"]) for f in results["statistics"]["signature_failures"]}
    assert failures == {("broken_run", "run", "KeyError"), ("broken_end", "on_complete", "AttributeError")}
    assert all(f["where"].startswith("broken.py:") for f in results["statistics"]["signature_failures"])


def test_a_job_without_a_sample_file_still_names_its_target(tmp_path):
    # mimics_extension reads target.file.name without asking
    _, results = signed(tmp_path)
    assert results["target"]["file"]["name"] == ""
    assert results["statistics"]["signature_failures"] == []


# --- smaller facts of the report ---------------------------------------------------------

def test_a_key_opened_to_read_through_a_create_is_not_written(tmp_path):
    def create_key(uid, name, access, **extra):
        return api(uid, 100, "RegCreateKeyExW", hKey="0x80000001", lpSubKey=f'0x1:"Software\\\\{name}"',
                   samDesired=access, **extra)
    summary = behaviour(tmp_path, *BASE,
                        create_key(0x10, "ReadOnly", "0x20019", lpdwDisposition="0x0"),
                        create_key(0x11, "ToWrite", "0x2001f", lpdwDisposition="0x5e60fe9b8"),
                        # MAXIMUM_ALLOWED: advapi32 walking the path above the key
                        create_key(0x12, "Any", "0x2000000"),
                        # a disposition DRAKVUF printed says it outright
                        create_key(0x13, "Existed", "0xf003f", lpdwDisposition="0x2"),
                        create_key(0x14, "Created", "0x20019", lpdwDisposition="0x1"))["summary"]
    assert [k.rsplit("\\", 1)[-1] for k in summary["write_keys"]] == ["ToWrite", "Created"]
    assert len(summary["keys"]) == 5


def test_the_image_base_is_the_images_not_ntdlls(tmp_path):
    def discovered(name, base):
        return {"Plugin": "apimon", "Event": "dll_discovered", "PID": 100, "DllName": name, "DllBase": base}
    [p] = processes(tmp_path, *BASE,
                    discovered("\\Windows\\System32\\ntdll.dll", "0x7ffa54430000"),
                    discovered("\\Windows\\System32\\cmd.exe", "0x8d0000"),
                    discovered("\\Windows\\System32\\kernel32.dll", "0x7ffa537c0000"))
    list(p["calls"])
    assert p["environ"]["MainExeBase"] == p["environ"]["DllBase"] == "0x8d0000"


def test_a_record_cut_by_a_newline_in_its_value_is_put_together(tmp_path):
    import json
    from sandboxd.postprocessing.plugins.cape_plugin.trace_split import split_by_process
    cut = rec("regmon", 0x10, 100, method="NtSetValueKey", Key="\\REGISTRY\\USER\\S\\State", ValueName="v",
              Value="{\n  \\\"Version\\\":0,\n  \\\"Last\\\":\\\"x\\\"\n}")
    whole = rec("regmon", 0x11, 100, method="NtSetValueKey", Key="\\REGISTRY\\USER\\S\\After", ValueName="v",
                Value="1")
    text = "".join(json.dumps(r) + "\n" for r in BASE)
    # regmon writes the value as it is: the newlines raw, the record on four lines
    text += json.dumps(cut).replace("\\n", "\n") + "\n" + json.dumps(whole) + "\n"
    # ...and one cut that never ends: its lines are what they were, bad JSON
    text += '{"Plugin":"regmon","PID":100,"EventUID":"0x12","Value":"never\n'
    text += json.dumps({**whole, "EventUID": "0x13"}) + "\n"
    (tmp_path / "trace.log").write_text(text)
    result = split_by_process(tmp_path, tmp_path / "logs", TargetOs.WINDOWS)
    assert (result.stats.joined, result.stats.bad_json) == (1, 1)
    [log_file] = result.files.values()
    records = [json.loads(line) for line in log_file.read_text().splitlines()[1:]]
    assert [r["EventUID"] for r in records] == ["0x10", "0x11", "0x13"]
    assert records[0]["Value"] == '{\n  \\"Version\\":0,\n  \\"Last\\":\\"x\\"\n}'


def test_falcos_coverage_says_what_each_rule_came_to(tmp_path):
    import json
    from sandboxd.postprocessing.plugins.plugin_base import FalcoConfigSection
    OPEN_SHADOW = {"rule": "shadow opened", "desc": "d",
                   "condition": "evt.type = openat and fd.name = /etc/shadow"}
    rules = tmp_path / "rules.yaml"
    rules.write_text(json.dumps([
        {**OPEN_SHADOW, "output": "%fd.name", "priority": "WARNING"},
        {"rule": "Never Evaluated", "desc": "d", "condition": "no.such.field = 1", "output": "x",
         "priority": "WARNING"}]))
    (tmp_path / "job").mkdir()
    job = write_trace(
        tmp_path / "job", inject(100),
        rec("procmon", 0x0f, 100, ppid=1, method="do_execveat_common", FileName="/usr/bin/cat",
            ImagePathName="/usr/bin/cat", CommandLine="cat /etc/shadow"),
        rec("syscall", 0x10, 100, ppid=1, method="openat", Module="linux", Syscall=257, dirfd="0xffffff9c",
            pathname="/etc/shadow", flags="0x0", mode="0x0"),
        rec("sysret", 0x11, 100, ppid=1, method="openat", Module="linux", Syscall=257, Ret="0x3"))
    config = PostprocessingConfig(falco=FalcoConfigSection(rules_files=[rules],
                                                           local_rules_directory=tmp_path / "none"))
    results = cape_analysis.run_cape(PostprocessContext(job, config, TargetOs.UBUNTU),
                                     CapeConfigSection(capa=False, signatures=False, compress_trace=False))
    coverage = results["falco"]["coverage"]
    by_rule = {r["rule"]: r for r in coverage["rules"]}
    assert by_rule[OPEN_SHADOW["rule"]]["matched"] == 1 and by_rule[OPEN_SHADOW["rule"]]["status"] == "ok"
    assert by_rule["Never Evaluated"]["status"] != "ok" and by_rule["Never Evaluated"]["reason"]
    assert sum(coverage["rules_by_status"].values()) == 2


def test_a_file_named_by_its_device_is_the_file_named_by_its_drive(tmp_path):
    # A handle's name carries the volume's device, a path argument the drive: one file
    def written(uid, name):
        return rec("filetracer", uid, 100, method="NtWriteFile", FileName=name, FileHandle=hex(uid))
    summary = behaviour(
        tmp_path, *BASE,
        written(0x10, "\\??\\C:\\Users\\u\\a.tmp"),
        written(0x11, "\\Device\\HarddiskVolume2\\Users\\u\\a.tmp"),
        written(0x12, "\\Device\\HarddiskVolume5\\other\\b.tmp"))["summary"]
    assert summary["write_files"] == ["C:\\Users\\u\\a.tmp", "\\Device\\HarddiskVolume5\\other\\b.tmp"]
