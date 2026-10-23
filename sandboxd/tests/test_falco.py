"""Falco's rules over DRAKVUF's Linux records (sandboxd/postprocessing/falco).

The records here are shaped like the 2026-10-23 Ubuntu benchmark trace
(`procmon`, `syscall`, `sysret`, `libmon`, `inject` lines as DRAKVUF prints
them), a few lines each. What they pin is the part that is not Falco's: the
three-valued logic that keeps a gap in the trace from becoming an alert, and
the state -- processes, file descriptors, working directory -- rebuilt from
records that arrive in EventUID order rather than in the order things happened.
"""
from __future__ import annotations

import ipaddress
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd.postprocessing.falco import condition as C  # noqa: E402
from sandboxd.postprocessing.falco import events as E  # noqa: E402
from sandboxd.postprocessing.falco.engine import Engine  # noqa: E402
from sandboxd.postprocessing.falco.fields import FieldTable  # noqa: E402
from sandboxd.postprocessing.falco.rules import RuleSet  # noqa: E402

VENDORED = ROOT / "sandboxd" / "data" / "falco-rules" / "rules"
LOCAL = ROOT / "sandboxd" / "data" / "falco-rules-local"
USERS = {0: "root", 1000: "user"}


# --- the condition language ---------------------------------------------------

def compile_with(text, values, lists=None, macros=None):
    """Compile `text` against fields read from a dict, the event."""
    macro_ast = {k: C.parse(v, lists or {}) for k, v in (macros or {}).items()}
    compiler = C.Compiler(macro_ast, lambda name, arg: (lambda ev: ev.get(name if arg is None else f"{name}[{arg}]")))
    return compiler.compile(C.parse(text, lists or {}))


def test_not_binds_tighter_than_and_and_and_tighter_than_or():
    node = C.parse("a.x = 1 or a.y = 2 and not a.z = 3")
    assert isinstance(node, C.Or)
    assert isinstance(node.items[1], C.And)
    assert isinstance(node.items[1].items[1], C.Not)


def test_a_list_item_quoted_in_yaml_is_a_string_not_a_quoted_string():
    # falco_rules.yaml writes `items: ['"10.0.0.0/8"', ...]`: YAML keeps the
    # inner quotes, Falco expands the list as text, so they are a literal's.
    lists = {"nets": ['"10.0.0.0/8"', "inner"], "inner": ["/etc/shadow"]}
    node = C.parse("fd.snet in (nets)", lists)
    assert node.value == ("10.0.0.0/8", "/etc/shadow")


def test_symbolic_operators_need_no_spaces():
    node = C.parse("(fd.num>=0 and evt.dir=<)")
    assert [c.op for c in node.items] == [">=", "="]
    assert node.items[1].value == "<"


@pytest.mark.parametrize("a,b,conj,disj", [
    (True, C.UNKNOWN, C.UNKNOWN, True),
    (False, C.UNKNOWN, False, C.UNKNOWN),
    (C.UNKNOWN, C.UNKNOWN, C.UNKNOWN, C.UNKNOWN),
])
def test_and_or_follow_kleene(a, b, conj, disj):
    values = {"p.a": "yes" if a is True else ("no" if a is False else C.UNKNOWN),
              "p.b": "yes" if b is True else ("no" if b is False else C.UNKNOWN)}
    assert compile_with("p.a = yes and p.b = yes", values)(values, set()) is conj
    assert compile_with("p.a = yes or p.b = yes", values)(values, set()) is disj


def test_a_negated_check_on_an_unknown_field_is_undetermined_not_an_alert():
    # Falco reads an unextractable field as false, so this would be true for
    # every process whose parent it never saw.
    fn = compile_with("not proc.pname in (bash, sh)", {})
    missing = set()
    assert fn({"proc.pname": C.UNKNOWN}, missing) is C.UNKNOWN
    assert missing == {"proc.pname"}


def test_a_field_with_no_value_compares_false_as_in_falco():
    fn = compile_with("container.image != nginx", {})
    assert fn({"container.image": None}, set()) is False
    assert compile_with("container.image exists", {})({"container.image": None}, set()) is False


def test_an_incomplete_ancestry_decides_only_a_match():
    fn = compile_with("proc.aname in (sshd)", {})
    assert fn({"proc.aname": C.Multi(["bash", "sshd"], complete=False)}, set()) is True
    assert fn({"proc.aname": C.Multi(["bash"], complete=False)}, set()) is C.UNKNOWN
    assert fn({"proc.aname": C.Multi(["bash"], complete=True)}, set()) is False


def test_a_network_field_is_compared_by_containment():
    fn = compile_with("fd.snet in (nets)", {}, lists={"nets": ['"172.16.5.0/24"']})
    assert fn({"fd.snet": ipaddress.ip_address("172.16.5.20")}, set()) is True
    assert fn({"fd.snet": ipaddress.ip_address("10.1.1.1")}, set()) is False


def test_an_unsupported_field_makes_the_rule_unsupported_not_silent():
    rs = RuleSet()
    rs._apply({"rule": "r", "condition": "evt.type = open and fd.inode = 3",
               "output": "x", "priority": "WARNING"}, "t")
    rs.compile({"syscall": FieldTable("syscall", USERS, ())})
    assert rs.rules["r"].status == "unsupported"
    assert "fd.inode" in rs.rules["r"].reason


def test_append_override_enabled_and_exceptions():
    rs = RuleSet()
    for item in (
        {"list": "shells", "items": ["bash"]},
        {"list": "shells", "items": ["zsh"], "override": {"items": "append"}},
        {"macro": "m", "condition": "proc.name = never"},
        {"macro": "m", "condition": "proc.name in (shells)", "override": {"condition": "replace"}},
        {"rule": "r", "condition": "evt.type = execve and m", "output": "o", "priority": "NOTICE",
         "exceptions": [{"name": "e", "fields": ["proc.pname"], "values": [["sshd"]]}]},
        {"rule": "r", "condition": "and user.uid = 0", "override": {"condition": "append"}},
        {"rule": "off", "condition": "evt.type = open", "output": "o", "priority": "INFO"},
        {"rule": "off", "enabled": False},
    ):
        rs._apply(item, "t")
    rs.compile({"syscall": FieldTable("syscall", USERS, ())})
    assert rs.lists["shells"] == ["bash", "zsh"]
    assert rs.rules["off"].status == "disabled"
    r = rs.rules["r"]
    assert r.status == "ok" and r.event_types == frozenset({"execve"})
    assert {"proc.pname", "user.uid", "proc.name"} <= r.fields


def test_every_vendored_rule_compiles():
    """falcosecurity/rules at the submodule's tag, stable and incubating.

    A rule that stops compiling after a submodule bump fails here, rather than
    being reported as unsupported on Dom0 where nobody reads the coverage."""
    files = [VENDORED / "falco_rules.yaml", VENDORED / "falco-incubating_rules.yaml"]
    if not all(f.exists() for f in files):
        pytest.skip("sandboxd/data/falco-rules is not checked out (git submodule update --init)")
    rs = RuleSet()
    for f in files + sorted(LOCAL.glob("*.yaml")):
        rs.load_file(f)
    rs.compile({"syscall": FieldTable("syscall", USERS, ()), "libmon": FieldTable("libmon", USERS, ())})
    unsupported = {r.name: r.reason for r in rs.rules.values() if r.status == "unsupported"}
    assert unsupported == {}
    assert not rs.warnings
    assert all(r.event_types for r in rs.active()), "a rule without evt.type runs on every event"


# --- traces -------------------------------------------------------------------

def jsonl(path: Path, objs) -> None:
    path.write_text("".join(json.dumps(o) + "\n" for o in objs))


def common(plugin, pid, ppid, uid, name="/usr/bin/bash", thread="bash", user=1000, tid=None):
    return {"Plugin": plugin, "TimeStamp": f"{1000 + uid / 1000:.6f}", "PID": pid, "PPID": ppid,
            "TID": tid or pid, "UserId": user, "ProcessName": name, "EventUID": hex(uid),
            "ThreadName": thread}


def clone(uid, parent, ppid, child, flags="CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID"):
    return {**common("procmon", parent, ppid, uid), "Method": "kernel_clone",
            "Flags": flags, "NewPid": child}


def execve(uid, pid, ppid, image, cmdline, env="PWD=/home/user", user=1000):
    return {**common("procmon", pid, ppid, uid, user=user), "Method": "do_execveat_common",
            "CommandLine": cmdline, "ImagePathName": image, "FileName": image,
            "Environment": env, "euid": user, "PGID": pid}


def syscall(uid, pid, ppid, method, nr, name="/usr/bin/cat", thread="cat", **args):
    return {**common("syscall", pid, ppid, uid, name, thread), "Method": method,
            "Module": "linux", "Syscall": nr, "NArgs": len(args), "Type": "x64",
            **{k: v for k, v in args.items()}}


def sysret(uid, pid, ppid, method, nr, ret):
    return {**common("sysret", pid, ppid, uid), "Method": method, "Syscall": nr,
            "Ret": hex(ret & 0xFFFFFFFFFFFFFFFF), "Info": ""}


def libmon(uid, pid, ppid, method, arguments, ret):
    return {**common("libmon", pid, ppid, uid), "Method": method, "Event": "api_called",
            "Library": "/lib/x86_64-linux-gnu/libc.so.6", "CalledFrom": "0x55aa00001000",
            "ReturnValue": hex(ret & 0xFFFFFFFFFFFFFFFF), "FromModule": None,
            "Arguments": arguments}


def job(tmp_path, procmon=(), syscalls=(), sysrets=None, libmons=(), injected=100) -> Path:
    """A job directory after split_drakvuf_log: one log per plugin."""
    running = [{"Plugin": "procmon", "TimeStamp": "999.0", "PID": 1, "PPID": 0,
                "RunningProcess": "/usr/lib/systemd/systemd", "Bitness": 0},
               {"Plugin": "procmon", "TimeStamp": "999.0", "PID": 50, "PPID": 1,
                "RunningProcess": "/usr/sbin/sshd", "Bitness": 0}]
    jsonl(tmp_path / "procmon.log", running + list(procmon))
    jsonl(tmp_path / "inject.log", [{"Plugin": "inject", "Method": "ExecProc", "Status": "Success",
                                    "ProcessName": "/bin/sh", "Arguments": "/tmp/s.sh",
                                    "InjectedPid": injected, "InjectedTid": injected}])
    jsonl(tmp_path / "syscall.log", syscalls)
    if sysrets is not None:
        jsonl(tmp_path / "sysret.log", sysrets)
    if libmons:
        jsonl(tmp_path / "libmon.log", libmons)
    return tmp_path


def evaluate(directory: Path, rules: list, env_filter=("LD_PRELOAD", "PWD", "OLDPWD"), scope="sample"):
    rs = RuleSet()
    for item in rules:
        rs._apply({"output": "%proc.name %fd.name", "priority": "WARNING", **item}, "test")
    tables = {"syscall": FieldTable("syscall", USERS, env_filter),
              "libmon": FieldTable("libmon", USERS, env_filter)}
    rs.compile(tables)
    assert all(r.status == "ok" for r in rs.rules.values()), {r.name: r.reason for r in rs.rules.values()}
    engine = Engine(rs, tables, max_alerts=100)
    trace = E.Trace(directory, E.TraceConfig(env_filter=frozenset(env_filter), users=USERS),
                    engine.event_types("syscall"), engine.event_types("libmon"),
                    E.sample_scope(directory) if scope == "sample" else None)
    return engine.run(trace), trace


OPEN_SHADOW = {
    "rule": "shadow read by cat under a shell under sshd",
    "condition": ("evt.type = openat and evt.is_open_read = true and fd.typechar = f and fd.num >= 0"
                  " and fd.name = /etc/shadow and proc.name = cat and proc.pname = bash"
                  " and proc.aname[2] = sshd and user.name = user"),
}


def shell_and_cat():
    # sshd(50) -> bash(100, the injected process) -> cat(101)
    return [clone(0x10, 50, 1, 100), execve(0x11, 100, 50, "/usr/bin/bash", "bash /tmp/s.sh"),
            clone(0x20, 100, 50, 101), execve(0x21, 101, 100, "/usr/bin/cat", "cat /etc/shadow")]


def test_a_successful_open_with_its_ancestry_is_an_alert(tmp_path):
    d = job(tmp_path, procmon=shell_and_cat(),
            syscalls=[syscall(0x30, 101, 100, "openat", 257, dirfd="0xffffff9c",
                              pathname="/etc/shadow", flags="0x0", mode="0x0")],
            sysrets=[sysret(0x31, 101, 100, "openat", 257, 3)])
    result, _ = evaluate(d, [OPEN_SHADOW])
    assert [a["rule"] for a in result.alerts] == [OPEN_SHADOW["rule"]]
    assert result.alerts[0]["output"] == "cat /etc/shadow"


def test_a_failed_open_is_not_an_alert(tmp_path):
    d = job(tmp_path, procmon=shell_and_cat(),
            syscalls=[syscall(0x30, 101, 100, "openat", 257, dirfd="0xffffff9c",
                              pathname="/etc/shadow", flags="0x0", mode="0x0")],
            sysrets=[sysret(0x31, 101, 100, "openat", 257, -13)])   # EACCES
    result, _ = evaluate(d, [OPEN_SHADOW])
    assert result.alerts == []
    assert OPEN_SHADOW["rule"] not in result.outcomes


def test_without_sysret_the_open_is_undetermined(tmp_path):
    d = job(tmp_path, procmon=shell_and_cat(),
            syscalls=[syscall(0x30, 101, 100, "openat", 257, dirfd="0xffffff9c",
                              pathname="/etc/shadow", flags="0x0", mode="0x0")])
    result, _ = evaluate(d, [OPEN_SHADOW])
    assert result.alerts == []
    outcome = result.outcomes[OPEN_SHADOW["rule"]]
    assert outcome.undetermined == 1 and "fd.num" in outcome.missing


def test_without_sysret_libcs_return_value_decides(tmp_path):
    # glibc's open() is openat underneath: libmon reports open's result after it
    d = job(tmp_path, procmon=shell_and_cat(),
            syscalls=[syscall(0x30, 101, 100, "openat", 257, dirfd="0xffffff9c",
                              pathname="/etc/shadow", flags="0x0", mode="0x0")],
            libmons=[libmon(0x31, 101, 100, "open", ['Path=0x55aa00002000:"/etc/shadow"', "Flags=0x0"], 3)])
    result, trace = evaluate(d, [OPEN_SHADOW])
    assert len(result.alerts) == 1
    assert trace.stats.results_from_libmon == 1


def test_a_relative_path_resolves_against_the_working_directory(tmp_path):
    procmon = shell_and_cat()
    procmon[-1] = execve(0x21, 101, 100, "/usr/bin/cat", "cat shadow", env="PWD=/etc")
    d = job(tmp_path, procmon=procmon,
            syscalls=[syscall(0x30, 101, 100, "openat", 257, dirfd="0xffffff9c",
                              pathname="shadow", flags="0x0", mode="0x0")],
            sysrets=[sysret(0x31, 101, 100, "openat", 257, 3)])
    result, _ = evaluate(d, [OPEN_SHADOW])
    assert len(result.alerts) == 1


def test_filetracers_reading_of_a_path_wins(tmp_path):
    # renameat2's newpath came out "H=" from the syscall plugin and right from
    # filetracer under the same EventUID, in the 2026-10-23 trace.
    d = job(tmp_path, procmon=shell_and_cat(),
            syscalls=[syscall(0x30, 101, 100, "renameat2", 316, olddirfd="0xffffff9c", oldpath="a",
                              newdirfd="0xffffff9c", newpath="H=", flags="0x1")],
            sysrets=[sysret(0x31, 101, 100, "renameat2", 316, 0)])
    jsonl(d / "filetracer.log", [{**common("filetracer", 101, 100, 0x30), "Method": "do_syscall_64",
                                  "Syscall": "renameat2", "FileName": "a", "newpath": ".bash_history"}])
    result, _ = evaluate(d, [{"rule": "history renamed",
                              "condition": "evt.type = renameat2 and evt.arg.newpath endswith ash_history"}])
    assert len(result.alerts) == 1


def test_a_dup2_of_a_socket_onto_stdout_is_seen_through_the_fd_table(tmp_path):
    d = job(tmp_path, procmon=shell_and_cat(),
            syscalls=[syscall(0x30, 101, 100, "socket", 41, domain="0x2", type="0x1", protocol="0x0"),
                      syscall(0x32, 101, 100, "dup2", 33, oldfd="0x3", newfd="0x1"),
                      syscall(0x34, 101, 100, "close", 3, fd="0x3"),
                      syscall(0x36, 101, 100, "dup2", 33, oldfd="0x3", newfd="0x2")],
            sysrets=[sysret(0x31, 101, 100, "socket", 41, 3), sysret(0x33, 101, 100, "dup2", 33, 1),
                     sysret(0x35, 101, 100, "close", 3, 0), sysret(0x37, 101, 100, "dup2", 33, -9)])
    result, _ = evaluate(d, [{"rule": "redirect", "condition":
                              "evt.type in (dup, dup2, dup3) and evt.rawres in (0, 1, 2) and fd.type in (ipv4, ipv6)"}])
    # the second dup2 names fd 3 after it was closed, in a process whose
    # table is complete (forked inside the trace): nothing, not unknown
    assert [a["evt_num"] for a in result.alerts] == [0x32]


def test_a_vfork_childs_exec_before_its_parents_clone_record_keeps_its_ancestry(tmp_path):
    # The clone record is printed when the clone returns in the parent, which
    # a vfork child outruns: the 2026-10-23 trace has 1601's exec at 0x2571
    # and its parent's kernel_clone at 0x2572.
    procmon = [clone(0x10, 50, 1, 100), execve(0x11, 100, 50, "/usr/bin/bash", "bash /tmp/s.sh"),
               execve(0x21, 101, 100, "/usr/bin/cat", "cat /etc/shadow"),
               clone(0x22, 100, 50, 101, flags="CLONE_VM | CLONE_VFORK")]
    d = job(tmp_path, procmon=procmon,
            syscalls=[syscall(0x30, 101, 100, "openat", 257, dirfd="0xffffff9c",
                              pathname="/etc/shadow", flags="0x0", mode="0x0")],
            sysrets=[sysret(0x31, 101, 100, "openat", 257, 3)])
    result, _ = evaluate(d, [OPEN_SHADOW])
    assert len(result.alerts) == 1


def test_a_process_outside_the_samples_subtree_is_not_evaluated(tmp_path):
    d = job(tmp_path, procmon=shell_and_cat(),
            syscalls=[syscall(0x30, 101, 100, "openat", 257, dirfd="0xffffff9c",
                              pathname="/etc/shadow", flags="0x0", mode="0x0")],
            sysrets=[sysret(0x31, 101, 100, "openat", 257, 3)],
            injected=4000)
    result, _ = evaluate(d, [OPEN_SHADOW])
    assert result.alerts == [] and result.events == 0


@pytest.mark.parametrize("env_filter,expected", [
    (("PWD", "GLIBC_TUNABLES"), False),      # on procmon's list and not printed: unset
    (("PWD",), C.UNKNOWN),                    # not on the list: procmon could not say
])
def test_an_environment_variable_on_procmons_list_is_decided(tmp_path, env_filter, expected):
    d = job(tmp_path, procmon=shell_and_cat(), sysrets=[])
    rule = {"rule": "tunables", "condition": "evt.type = execve and proc.env icontains GLIBC_TUNABLES"}
    result, _ = evaluate(d, [rule], env_filter=env_filter)
    outcome = result.outcomes.get("tunables")
    if expected is False:
        assert outcome is None
    else:
        assert outcome.undetermined == 2 and result.alerts == []


def test_a_variable_that_is_set_is_an_alert(tmp_path):
    procmon = shell_and_cat()
    procmon[-1] = execve(0x21, 101, 100, "/usr/bin/cat", "cat x", env="GLIBC_TUNABLES=glibc.x=1,PWD=/tmp")
    d = job(tmp_path, procmon=procmon, sysrets=[])
    rule = {"rule": "tunables", "condition": "evt.type = execve and proc.env icontains GLIBC_TUNABLES"}
    result, _ = evaluate(d, [rule], env_filter=("PWD", "GLIBC_TUNABLES"))
    assert [a["pid"] for a in result.alerts] == [101]


def test_libmon_calls_are_a_source_of_their_own(tmp_path):
    d = job(tmp_path, procmon=shell_and_cat(), sysrets=[],
            libmons=[libmon(0x30, 101, 100, "dlopen", ['Path=0x55aa00002000:"/tmp/x.so"', "Flags=0x101"], 0x7f00)])
    result, _ = evaluate(d, [{"rule": "dlopen tmp", "source": "libmon",
                              "condition": "evt.type = dlopen and api.arg[Path] startswith /tmp/",
                              "output": "%api.arg[Path] %proc.pname"}])
    assert [a["output"] for a in result.alerts] == ["/tmp/x.so bash"]


def test_the_shipped_libmon_rules_name_hooked_functions_and_arguments():
    hooks = {}
    for line in (ROOT / "sandboxd" / "data" / "so-hooks-linux.txt").read_text().splitlines():
        if line and not line.startswith("#"):
            parts = line.split(",")
            hooks[parts[1]] = {a.split(":")[0] for a in parts[3:] if ":" in a}
    rs = RuleSet()
    rs.load_file(LOCAL / "libmon.yaml")
    rs.compile({"libmon": FieldTable("libmon", USERS, ())})
    for rule in rs.rules.values():
        assert rule.status == "ok", rule.reason
        for fn in rule.event_types:
            assert fn in hooks, f"{rule.name}: {fn} is not hooked"
        text = rule.condition + rule.output
        for name in (n for n in __import__("re").findall(r"api\.arg\[([A-Za-z]\w*)\]", text)):
            assert any(name in hooks[fn] for fn in rule.event_types), f"{rule.name}: no argument {name}"


def test_the_plugin_writes_alerts_and_coverage_and_the_report_groups_them(tmp_path):
    pytest.importorskip("yara_x")   # the plugins package imports it
    from sandboxd.guests import TargetOs
    from sandboxd.postprocessing.plugins import plugin_base
    from sandboxd.postprocessing.plugins.falco_analysis import falco_analysis
    from sandboxd.postprocessing.plugins.get_falco_info import get_falco_info

    rules = tmp_path / "rules.yaml"
    rules.write_text(json.dumps([{**OPEN_SHADOW, "output": "%fd.name", "priority": "WARNING"}]))
    (tmp_path / "job").mkdir()
    d = job(tmp_path / "job", procmon=shell_and_cat(),
            syscalls=[syscall(0x30 + i, 101, 100, "openat", 257, dirfd="0xffffff9c",
                              pathname="/etc/shadow", flags="0x0", mode="0x0") for i in (0, 2)],
            sysrets=[sysret(0x31 + i, 101, 100, "openat", 257, 3) for i in (0, 2)])
    config = plugin_base.PostprocessingConfig(falco=plugin_base.FalcoConfigSection(
        rules_files=[rules], local_rules_directory=tmp_path / "none"))
    ctx = plugin_base.PostprocessContext(d, config, TargetOs.UBUNTU, vlan=5)
    falco_analysis(ctx)
    coverage = json.loads((d / "falco-rules.json").read_text())
    # The clone's own /24, from the same helper the NAT rules use
    from sandboxd.egress import vlan_subnet
    assert coverage["lab_network"] == vlan_subnet(5)
    get_falco_info(ctx)
    [entry] = ctx.report["falco"]
    assert entry["count"] == 2 and entry["output"] == "/etc/shadow"


def test_windows_has_no_falco_profile():
    pytest.importorskip("yara_x")
    from sandboxd.guests import TargetOs
    from sandboxd.postprocessing.plugins.falco_analysis import FALCO_PROFILES
    assert TargetOs.WINDOWS not in FALCO_PROFILES


# --- network, from unixsocketmon -----------------------------------------------

def usm(uid, pid, ppid, method, **endpoints):
    """A unixsocketmon record as the fork's plugin prints it (bfab6ba and after)."""
    return {**common("unixsocketmon", pid, ppid, uid, "/usr/bin/ssh", "ssh"), "Method": method, **endpoints}


def ssh_connect(tmp_path, remote_ip, ret):
    procmon = [clone(0x10, 50, 1, 100), execve(0x11, 100, 50, "/usr/bin/bash", "bash /tmp/s.sh"),
               clone(0x20, 100, 50, 101), execve(0x21, 101, 100, "/usr/bin/ssh", "ssh -p 443 user@" + remote_ip)]
    d = job(tmp_path, procmon=procmon,
            syscalls=[syscall(0x30, 101, 100, "socket", 41, "/usr/bin/ssh", "ssh", domain="0x2", type="0x1", protocol="0x6"),
                      syscall(0x32, 101, 100, "connect", 42, "/usr/bin/ssh", "ssh", sockfd="0x3", addr="0x7ffd0000", addrlen="0x10")],
            sysrets=[sysret(0x31, 101, 100, "socket", 41, 3), sysret(0x34, 101, 100, "connect", 42, ret)])
    jsonl(d / "unixsocketmon.log", [usm(0x33, 101, 100, "connect", Type="AF_INET", Protocol="TCP",
                                        RemoteIp=remote_ip, RemotePort=443)])
    return d


def vendored_network_rules(lab_subnet=None) -> RuleSet:
    if not (VENDORED / "falco_rules.yaml").exists():
        pytest.skip("sandboxd/data/falco-rules is not checked out")
    rs = RuleSet()
    rs.load_file(VENDORED / "falco_rules.yaml")
    if lab_subnet:
        # what falco_analysis._lab_network_overrides adds for the job's VLAN
        rs._apply({"list": "sandbox_lab_network", "items": [f'"{lab_subnet}"']}, "t")
        rs._apply({"list": "rfc_1918_addresses", "items": ["sandbox_lab_network"],
                   "override": {"items": "replace"}}, "t")
    for name in list(rs.rules):
        rs.rules[name].enabled = name == "Disallowed SSH Connection Non Standard Port"
    return rs


def run_rules(d, rs):
    tables = {"syscall": FieldTable("syscall", USERS, ())}
    rs.compile(tables)
    engine = Engine(rs, tables, max_alerts=10)
    trace = E.Trace(d, E.TraceConfig(users=USERS), engine.event_types("syscall"), set(), E.sample_scope(d))
    return engine.run(trace)


@pytest.mark.parametrize("ret,alerts", [(-115, 1), (0, 1), (-101, 0)])   # EINPROGRESS, done, ENETUNREACH
def test_an_outbound_ssh_connect_is_judged_by_its_result(tmp_path, ret, alerts):
    """The local end is not bound when unixsocketmon sees the connect: the
    rule's `fd.ip != "0.0.0.0"` is decided by the remote end alone."""
    result = run_rules(ssh_connect(tmp_path, "203.0.113.9", ret), vendored_network_rules())
    assert len(result.alerts) == alerts
    assert not any(o.undetermined for o in result.outcomes.values())
    if alerts:
        assert "->203.0.113.9:443" in result.alerts[0]["output"]


@pytest.mark.parametrize("lab,alerts", [(None, 0), ("172.16.5.0/24", 1)])
def test_only_the_clones_own_network_is_local(tmp_path, lab, alerts):
    """Upstream counts all of RFC 1918 as local. In the sandbox the clone's
    /24 is the only local network, so 10.1.2.3 is outbound there."""
    result = run_rules(ssh_connect(tmp_path, "10.1.2.3", -115), vendored_network_rules(lab))
    assert len(result.alerts) == alerts


def test_linux_connections_and_unix_sockets_come_from_unixsocketmon(tmp_path):
    pytest.importorskip("yara_x")
    from sandboxd.guests import TargetOs
    from sandboxd.postprocessing.plugins import plugin_base
    from sandboxd.postprocessing.plugins.build_process_tree import build_process_tree
    from sandboxd.postprocessing.plugins.get_socket_info import get_socket_info

    d = ssh_connect(tmp_path, "203.0.113.9", -115)
    jsonl(d / "unixsocketmon.log", [
        usm(0x33, 101, 100, "connect", Type="AF_INET", Protocol="TCP", RemoteIp="203.0.113.9", RemotePort=443),
        usm(0x40, 101, 100, "sock_sendmsg", Type="AF_INET", Protocol="TCP", LocalIp="172.16.5.2",
            LocalPort=40000, RemoteIp="203.0.113.9", RemotePort=443, Connected=1, Size=21),
        usm(0x42, 101, 100, "sock_sendmsg", Type="AF_LOCAL", RemotePath="/run/systemd/journal/stdout",
            Connected=1, Size=64),
        # the desktop's own D-Bus traffic, outside the sample's subtree
        {**usm(0x44, 910, 1, "sock_sendmsg", Type="AF_LOCAL", RemotePath="/run/dbus/system_bus_socket",
               Connected=1, Size=300), "ProcessName": "/usr/bin/dbus-daemon"},
    ])
    ctx = plugin_base.PostprocessContext(d, plugin_base.PostprocessingConfig(), TargetOs.UBUNTU)
    build_process_tree(ctx)
    get_socket_info(ctx)
    [conn] = ctx.report["connections"]
    assert (conn["protocol"], conn["local_ip"], conn["local_port"], conn["remote_ip"], conn["remote_port"]) \
        == ("tcp", "172.16.5.2", 40000, "203.0.113.9", 443)
    [unix] = ctx.report["unix_sockets"]
    assert unix["peer_path"] == "/run/systemd/journal/stdout" and unix["bytes"] == 64
