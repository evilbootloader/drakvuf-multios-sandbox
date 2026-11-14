"""The sample's own functions, located before it runs (sandboxd/samplehooks.py)
and written as lines of the tracer's hook list; and the FLIRT patterns they
are located with (scripts/gen-flirt-pats.py).

The end-to-end test builds a statically linked program with the host's
compiler, strips it, makes patterns from the host's own libc.a and checks
every name the patterns give against the symbol table the stripped copy
lost. Skipped, loudly, where there is no compiler or no static libc.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd import guests as G  # noqa: E402
from sandboxd import samplehooks as sh  # noqa: E402
from sandboxd.guests import SampleKind, TargetOs, TraceOptions  # noqa: E402
from sandboxd.tests.test_guests import job  # noqa: E402

_spec = importlib.util.spec_from_file_location("gen_flirt_pats", ROOT / "scripts" / "gen-flirt-pats.py")
pats = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pats)

STATIC_LIST = """# a comment
libc.so.6,connect,log,Fd:int,SockAddr:lpsockaddr,AddrLen:int
libc.so.6,send,log,Fd:int,Buf:buffer[Len],Len:ulong,Flags:int
libc.so.6,exit,no-retval,log
taskschd.dll,ITaskFolder::RegisterTaskDefinition,clsid,0F87369F-A4E5-4CFC-BD3E-73E6154572DD,13cd3,log,lpvoid
libc.so.6,connect,log,Other:int
"""


def test_the_static_list_says_which_functions_are_worth_a_hook():
    known = sh.static_hooks(STATIC_LIST)
    # by name only, the first line of a name, with everything after the name
    assert known == {"connect": "log,Fd:int,SockAddr:lpsockaddr,AddrLen:int",
                     "send": "log,Fd:int,Buf:buffer[Len],Len:ulong,Flags:int",
                     "exit": "no-retval,log"}
    # and every line of the real lists is one this reads without tripping
    for path in set(G.STATIC_HOOKS.values()):
        assert len(sh.static_hooks(path.read_text())) > 100


def test_a_librarys_decorated_name_is_the_lists_plain_one():
    assert [sh.plain_name(n) for n in ("__libc_connect", "__GI_memcpy", "__send", "_start", "connect@@GLIBC_2.2.5")] \
        == ["connect", "memcpy", "send", "start", "connect"]


def test_lines_are_by_offset_one_an_address_and_only_for_known_functions():
    located = [sh.Located("__libc_connect", 0x401000, "flirt:glibc"), sh.Located("connect", 0x401000, "flirt:glibc"),
               sh.Located("send", 0x401040, "symtab"), sh.Located("helper", 0x401080, "symtab"),
               sh.Located("exit", 0x400f00, "symtab")]
    lines = sh.sample_lines(located, sh.static_hooks(STATIC_LIST), "/home/u/Desktop/s.elf")
    assert lines == ["/home/u/Desktop/s.elf,exit,400f00,no-retval,log",
                     "/home/u/Desktop/s.elf,connect,401000,log,Fd:int,SockAddr:lpsockaddr,AddrLen:int",
                     "/home/u/Desktop/s.elf,send,401040,log,Fd:int,Buf:buffer[Len],Len:ulong,Flags:int"]
    # a PE's are RVAs
    assert sh.sample_lines(located[2:3], sh.static_hooks(STATIC_LIST), "C:\\s.exe", base=0x400000)[0].split(",")[2] == "1040"


@pytest.mark.parametrize("module", ["/home/u/a,b.elf", "/home/u/a\nb", " /home/u/a", "#x", ""])
def test_a_name_the_list_cannot_spell_gets_no_lines(module):
    """Fields are cut at commas and a line is a line: a sample named to break
    one gets the static list, never a line DRAKVUF would refuse to start on."""
    located = [sh.Located("connect", 0x401000, "symtab")]
    assert sh.sample_lines(located, sh.static_hooks(STATIC_LIST), module) == []


def test_the_jobs_list_is_the_static_one_with_the_samples_lines_after(tmp_path):
    out = tmp_path / "hooks.txt"
    sh.write_list(STATIC_LIST, ["/s,connect,401000,log,Fd:int"], out)
    text = out.read_text()
    assert text.startswith(STATIC_LIST) and text.rstrip().endswith("/s,connect,401000,log,Fd:int")
    sh.write_list(STATIC_LIST, [], out)
    assert out.read_text() == STATIC_LIST and not list(tmp_path.glob("*.tmp"))


def test_call_targets_are_inside_the_code_and_include_the_entry():
    code = bytearray(b"\x90" * 64)
    code[0:5] = b"\xe8" + (0x20 - 5).to_bytes(4, "little", signed=True)        # call +0x20
    code[8:13] = b"\xe9" + (0x30 - 13).to_bytes(4, "little", signed=True)      # jmp  +0x30
    code[16:21] = b"\xe8" + (0x7000).to_bytes(4, "little")                     # outside the code
    image = sh.Image("elf", 64, entry=0x401004, code=[(0x401000, 0, bytes(code))])
    assert sh.call_targets(image) == [0x401004, 0x401020, 0x401030]


def test_two_signatures_for_one_address_name_nothing():
    """`sub rsp,8; lea rdi,[rip+..]; call ..` is half of glibc's error paths:
    bytes two functions share are no evidence for either."""
    import flirt
    body = bytes.fromhex("554889e54883ec10897dfc8b45fc89c7") * 2
    lead = "".join("%02X" % b for b in body)

    def matcher(*names):
        return flirt.compile(flirt.parse_pat("".join(
            "%s 00 0000 %04X :0000 %s\n" % (lead, len(body) + i, n) for i, n in enumerate(names)) + "---\n"))
    image = sh.Image("elf", 64, code=[(0x1000, 0, body + b"\x90" * 64)])
    assert [f.name for f in sh.from_flirt(image, [("one", matcher("connect"))], [0x1000])] == ["connect"]
    assert sh.from_flirt(image, [("two", matcher("connect", "bind"))], [0x1000]) == []


def test_flairs_checksum():
    # FLAIR's crc16 of "123456789" and of nothing, as its own tools print them
    assert pats.crc16(b"") == 0 and pats.crc16(b"123456789") == 0x6E90


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    """(static program with symbols, the same stripped, a pattern directory)."""
    libc = Path("/usr/lib/x86_64-linux-gnu/libc.a")
    if not (shutil.which("gcc") and shutil.which("strip") and libc.is_file()):
        pytest.skip("no gcc, strip or static libc: the end-to-end locator test was not run")
    tmp = tmp_path_factory.mktemp("static")
    (tmp / "t.c").write_text(
        "#include <sys/socket.h>\n#include <netinet/in.h>\n#include <string.h>\n#include <unistd.h>\n"
        "int main(void){struct sockaddr_in a;memset(&a,0,sizeof a);a.sin_family=AF_INET;\n"
        "int s=socket(AF_INET,SOCK_STREAM,0);connect(s,(struct sockaddr*)&a,sizeof a);send(s,\"hi\",2,0);"
        "close(s);return 0;}\n")
    subprocess.run(["gcc", "-static", "-O1", "-o", str(tmp / "with"), str(tmp / "t.c")], check=True, capture_output=True)
    shutil.copy(tmp / "with", tmp / "stripped")
    subprocess.run(["strip", str(tmp / "stripped")], check=True)
    assert pats.main(["--name", "libc-host", "--out", str(tmp / "flirt"), str(libc)]) == 0
    return tmp / "with", tmp / "stripped", tmp / "flirt"


def test_a_stripped_static_program_gets_its_library_calls_back(built, tmp_path):
    with_symbols, stripped, flirt_dir = built
    nothing = tmp_path / "none"

    image, truth = sh.locate(with_symbols, nothing, nothing)
    assert image.static and not image.stripped and {"symtab"} == {f.how for f in truth}
    by_address: dict = {}
    for f in truth:
        by_address.setdefault(f.offset, set()).add(sh.plain_name(f.name))

    image, located = sh.locate(stripped, flirt_dir, nothing)
    assert image.static and image.stripped and len(located) > 100
    # every name the patterns gave is the function's own
    wrong = [(hex(f.offset), f.name) for f in located if sh.plain_name(f.name) not in by_address.get(f.offset, ())]
    assert wrong == []

    known = sh.static_hooks(G.STATIC_HOOKS[TargetOs.UBUNTU].read_text())
    hooked = {line.split(",")[1]: int(line.split(",")[2], 16)
              for line in sh.sample_lines(located, known, "/home/u/Desktop/s.elf")}
    assert {"connect", "send"} <= set(hooked)
    assert all(name in by_address[address] for name, address in hooked.items())
    # and with no pattern set, a stripped program has nothing to offer
    assert sh.locate(stripped, nothing, nothing)[1] == []


def test_the_child_writes_the_list_and_the_report(built, tmp_path):
    _, stripped, flirt_dir = built
    out, found = tmp_path / "hooks.txt", tmp_path / "located.json"
    static = G.STATIC_HOOKS[TargetOs.UBUNTU]
    assert sh.main([str(stripped), "--guest-path", "/home/u/Desktop/s.elf", "--static", str(static),
                    "--out", str(out), "--json", str(found), "--flirt", str(flirt_dir), "--max-mib", "0"]) == 0
    assert out.read_text().startswith(static.read_text())
    assert "/home/u/Desktop/s.elf,connect," in out.read_text()
    report = json.loads(found.read_text())
    assert report["analysed"] and report["static"] and report["stripped"] and report["hooked"] >= 2
    assert any(f["name"].endswith("connect") and f["hooked"] for f in report["functions"])


def test_offsets_count_from_where_the_tracer_finds_the_program(built, tmp_path):
    """libmon knows one address of an executable before it has run, the aux
    vector's AT_PHDR, and takes its page as the base; libusermode has the
    image's base. An offset counted from anything else lands a breakpoint in
    the middle of some other instruction."""
    from elftools.elf.elffile import ELFFile

    with_symbols, _, _ = built
    image = sh.read_image(with_symbols)
    with with_symbols.open("rb") as f:
        elf = ELFFile(f)
        load = next(s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD")
        # the kernel: AT_PHDR = where the segment holding the headers put them
        at_phdr = load["p_vaddr"] + elf["e_phoff"] - load["p_offset"]
    assert image.base == at_phdr & ~0xFFF
    line = next(l for l in sh.sample_lines(sh.from_symbols(image), {"connect": "log"}, "/s", image.base)
                if l.split(",")[1] == "connect")
    assert int(line.split(",")[2], 16) + image.base in {a for n, a in image.symbols.items()
                                                         if sh.plain_name(n) == "connect"}

    # headers no segment loads: no AT_PHDR, nothing to count from, no lines
    assert sh.sample_lines([sh.Located("connect", 0x401000, "symtab")], {"connect": "log"}, "/s", None) == []

    # Windows names a mapped file without its drive
    pe = sh.Image("pe", 64)
    assert sh.module_name(pe, r"C:\Users\u\Desktop\s.exe") == r"Users\u\Desktop\s.exe"
    assert sh.module_name(image, "/home/u/Desktop/s.elf") == "/home/u/Desktop/s.elf"


def test_what_is_no_program_gets_the_static_list(tmp_path):
    sample = tmp_path / "s"
    out = tmp_path / "hooks.txt"
    static = G.STATIC_HOOKS[TargetOs.UBUNTU]
    for content in (b"#!/bin/sh\necho hi\n", b"\x7fELF" + b"\xff" * 40, b"MZ" + b"\x00" * 10):
        sample.write_bytes(content)
        assert sh.main([str(sample), "--guest-path", "/s", "--static", str(static), "--out", str(out),
                        "--json", str(tmp_path / "r.json"), "--max-mib", "0"]) == 0
        assert out.read_text() == static.read_text()
        assert json.loads((tmp_path / "r.json").read_text()) == {"analysed": False}


@pytest.mark.parametrize("os_,kind,option", [
    (TargetOs.UBUNTU, SampleKind.ELF, "--so-hooks-list"), (TargetOs.WINDOWS, SampleKind.PE, "--dll-hooks-list")])
def test_the_tracer_gets_the_jobs_list_when_there_is_one(tmp_path, os_, kind, option):
    argv = G.argv_trace(job(tmp_path, os_, kind))
    assert argv[argv.index(option) + 1] == str(G.STATIC_HOOKS[os_])
    own = tmp_path / "hooks.txt"
    argv = G.argv_trace(job(tmp_path, os_, kind, hooks_list=own))
    assert argv[argv.index(option) + 1] == str(own) and argv.count(option) == 1


# --- many sets: a library, its versions, its compilers (scripts/fetch-flirt-sets.py) ----------

_fspec = importlib.util.spec_from_file_location("fetch_flirt_sets", ROOT / "scripts" / "fetch-flirt-sets.py")
fetch = importlib.util.module_from_spec(_fspec)
_fspec.loader.exec_module(fetch)


def test_a_set_is_named_by_library_compiler_and_architecture():
    summary = {"gcc-final": "12.3.0", "uclibc": "1.0.45", "linux-headers": "4.19.307"}
    assert fetch.set_name("uclibc", "x86-64", summary) == "uclibc-1.0.45-gcc-12.3.0-x86-64"
    # glibc's version is `git describe` of its branch, at times with its name in front
    for said in ("2.35-134-gb6aade18a7e5719c942aa2da6cf3157aca993fa4", "glibc-2.35-134-gb6aade18a7e5719c"):
        assert fetch.set_name("glibc", "x86-i686", {"gcc-final": "11.3.0", "glibc": said}) \
            == "glibc-2.35-134-gcc-11.3.0-x86-i686"
    assert fetch.set_name("musl", "x86-64", {"musl": "1.2.5"}) is None      # no compiler named


@pytest.mark.parametrize("member,wanted", [
    ("x86-64--uclibc--stable-2026.08-1/x86_64-buildroot-linux-uclibc/sysroot/usr/lib/libc.a", True),
    ("x86-64--musl--stable-2026.08-1/x86_64-buildroot-linux-musl/sysroot/lib/libc.a", True),      # musl: no usr/
    ("x86-64--glibc--stable-2026.08-1/x86_64-buildroot-linux-gnu/sysroot/usr/lib64/libpthread.a", True),
    ("x86-64--glibc--stable-2026.08-1/lib/gcc/x86_64-buildroot-linux-gnu/15.3.0/libgcc.a", True),
    ("x86-64--glibc--stable-2026.08-1/lib/gcc/x86_64-buildroot-linux-gnu/15.3.0/libgcc_eh.a", True),
    ("x86-64--glibc--stable-2026.08-1/x86_64-buildroot-linux-gnu/sysroot/usr/lib/libstdc++.a", False),
    ("x86-64--glibc--stable-2026.08-1/x86_64-buildroot-linux-gnu/sysroot/usr/lib/libc.so", False),
    ("x86-64--glibc--stable-2026.08-1/bin/x86_64-linux-gcc", False),
])
def test_only_the_static_libraries_are_taken_from_a_toolchain(member, wanted):
    assert bool(fetch.WANTED.search(member)) is wanted


def test_a_sample_is_matched_against_the_sets_that_recognise_it(built, tmp_path):
    """A hundred sets are a hundred matchers to build for every sample. Each
    set's YARA rule says whether the sample was linked against its library;
    only those are loaded, and a set without a rule always is."""
    _, stripped, flirt_dir = built
    sets = tmp_path / "sets"
    sets.mkdir()
    for path in flirt_dir.iterdir():
        shutil.copy(path, sets / path.name)
    assert (sets / "libc-host.yar").is_file()        # written beside the patterns
    # a library this program was not linked against: its own functions, other bytes
    lead = "DEADBEEF" * 8
    other = "".join("%s%02X 00 0000 0040 :0000 %s\n" % (lead[:62], i, name)
                    for i, name in enumerate(pats.COMMON[:12]))
    (sets / "other-1.0.pat").write_text(other + "---\n")
    rule = pats.identity_rule("other-1.0", other.splitlines())
    assert 'flirt_set = "other-1.0"' in rule and "3 of them" in rule
    (sets / "other-1.0.yar").write_text(rule)

    data = stripped.read_bytes()
    assert set(sh.recognised_sets(sets, data)) == {"libc-host"}
    assert [name for name, _ in sh.load_signatures(sets, data)] == ["libc-host"]
    # without a rule a set is always tried
    (sets / "other-1.0.yar").unlink()
    assert [name for name, _ in sh.load_signatures(sets, data)] == ["libc-host", "other-1.0"]
    # and the report names the sets and what the compiler wrote of itself
    image, located = sh.locate(stripped, sets, tmp_path / "none")
    summary = sh.report(image, located, [])
    assert "libc-host" in summary["signature_sets"] and summary["compiler"].startswith("GCC: (")
