"""A second run's hooks from the first run's memory (sandboxd/stagehints.py),
and the two runs of a job that asks for them (stages.Analysis.run).

The dumps are built here the way procdump2 lays them out (linux.cpp, win.cpp
in the fork): an ELF64 core whose memory follows its program headers, a
minidump whose memory follows its header one VAD after another.
"""
from __future__ import annotations

import gzip
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd import guests as G  # noqa: E402
from sandboxd import samplehooks as sh  # noqa: E402
from sandboxd import stagehints as hints  # noqa: E402
from sandboxd.proc import Completed  # noqa: E402
from sandboxd.tests import test_stages as stages  # noqa: E402
from sandboxd.tests.fake import FakeRunner  # noqa: E402

LIST = "libc.so.6,connect,log,Fd:int,SockAddr:lpsockaddr,AddrLen:int\n"
#: A function no other bytes here look like, and the pattern that names it
BODY = bytes.fromhex("554889e54883ec10897dfc8b45fc89c7") * 2
#: `call +0x40`, then the function at 0x40 of a page
CODE = (b"\xe8" + (0x40 - 5).to_bytes(4, "little") + b"\x90" * 0x3B + BODY).ljust(0x1000, b"\xcc")


def signatures(tmp_path: Path) -> Path:
    directory = tmp_path / "flirt"
    directory.mkdir(exist_ok=True)
    (directory / "libc-test.pat").write_text(
        "%s 00 0000 %04X :0000 connect\n---\n" % ("".join("%02X" % b for b in BODY), len(BODY)))
    return directory


def sidecar(directory: Path, pid: int, data: bytes, n: int = 0, **extra) -> None:
    directory.mkdir(exist_ok=True)
    (directory / f"procdump.{n}").write_bytes(gzip.compress(data))
    (directory / f"procdump.{n}.metadata").write_text(json.dumps(
        {"PID": pid, "TargetPID": pid, "Status": "Success", "Compression": "gzip",
         "DataFileName": f"procdump.{n}", "SequenceNumber": n, **extra}))


# --- Linux ------------------------------------------------------------------

def core(ranges: list, files: tuple = ()) -> bytes:
    """[(virtual address, flags, bytes)] as procdump2 writes a process, and
    its NT_FILE note of [(start, end, file)] after the memory."""
    count = len(ranges) + 1
    out = bytearray(b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack("<HHIQQQIHHHHHH", 4, 62, 1, 0, 64, 0, 0, 64, 56,
                                                                     count, 64, 0, 0))
    offset = 64 + 56 * count
    desc = struct.pack("<QQ", len(files), 8) + b"".join(struct.pack("<QQQ", a, b, 0) for a, b, _ in files) \
        + b"".join(name.encode() + b"\0" for _, _, name in files)
    note = struct.pack("<III", 5, len(desc), 0x46494C45) + b"CORE\0\0\0\0" + desc
    note_at = offset + sum(len(data) for _, _, data in ranges)
    out += struct.pack("<IIQQQQQQ", 4, 0, note_at, 0, 0, len(note), 0, 0)        # PT_NOTE, after the memory
    for vaddr, flags, data in ranges:
        out += struct.pack("<IIQQQQQQ", 1, flags, offset, vaddr, 0, len(data), len(data), 0x1000)
        offset += len(data)
    for _, _, data in ranges:
        out += data
    return bytes(out + note)


def elf_page(kind: int = 2) -> bytes:
    return (b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack("<HH", kind, 62)).ljust(0x1000, b"\0")


def linux_job(tmp_path: Path, base: int, path: str = "/root/sample", pid: int = 77, kind: int = 2):
    dumps = tmp_path / "procdumps"
    sidecar(dumps, pid, core([(base, 4, elf_page(kind)), (base + 0x1000, 5, CODE),
                              # a library's code, far above: not the program's
                              (0x7F0000000000, 5, CODE)]))
    trace = tmp_path / "trace.log"
    trace.write_text("\n".join(json.dumps(r) for r in (
        {"Plugin": "syscall", "Method": "execve"},
        {"Plugin": "libmon", "Event": "executable", "PID": 1, "Path": "/usr/bin/bash", "Base": "0x5000000"},
        {"Plugin": "libmon", "Event": "executable", "PID": pid, "Path": path, "Base": hex(base)})) + "\n{not json\n")
    sample = tmp_path / "sample"
    sample.write_bytes(b"not a program the parsers read")
    return dumps, trace, sample


def test_unpacked_code_in_a_core_becomes_lines_that_wait_for_it(tmp_path):
    dumps, trace, sample = linux_job(tmp_path, 0x400000)
    lines, report = hints.hints("core", dumps, trace, sample, "/root/sample", LIST, sh.static_hooks(LIST), {},
                                signatures(tmp_path), tmp_path / "none")
    # by offset from the executable's base as libmon said it, with the bytes to wait for
    assert lines == ["/root/sample,connect,1040,when:" + BODY[:16].hex() + ",log,Fd:int,SockAddr:lpsockaddr,AddrLen:int"]
    assert report[0]["pid"] == 77 and report[0]["hooked"] == 1 and report[0]["found"] == {"flirt": 1}


def test_code_unpacked_below_the_packed_file_is_found_and_counted_backwards(tmp_path):
    """UPX: the packed file is loaded high (its AT_PHDR page is the base
    libmon reports), unmaps itself and writes the program at 0x400000, in
    memory no file backs (job ac66493d, 2026-11-15). The offset wraps: the
    tracer adds it to the base in 64 bits."""
    base = 0x3D92000
    dumps = tmp_path / "procdumps"
    sidecar(dumps, 77, core([(0x400000, 5, CODE), (0x401000, 4, b"rodata".ljust(0x1000, b"\0")),
                             # a library's code below LOW_MEMORY, in a 32-bit process: its own file
                             (0x8000000, 5, CODE), (0x7FFE00000000, 5, CODE)],
                            files=[(0x8000000, 0x8001000, "/usr/lib/libc.so.6")]))
    trace = tmp_path / "trace.log"
    trace.write_text(json.dumps({"Plugin": "libmon", "Event": "executable", "PID": 77,
                                 "Path": "/root/sample", "Base": hex(base)}) + "\n")
    sample = tmp_path / "sample"
    sample.write_bytes(b"packed")
    lines, report = hints.hints("core", dumps, trace, sample, "/root/sample", LIST, sh.static_hooks(LIST), {},
                                signatures(tmp_path), tmp_path / "none")
    offset = (0x400040 - base) & ((1 << 64) - 1)
    assert lines == [f"/root/sample,connect,{offset:x},when:{BODY[:16].hex()},log,Fd:int,SockAddr:lpsockaddr,AddrLen:int"]
    assert (base + offset) & ((1 << 64) - 1) == 0x400040
    # and the line is one the second run's list takes
    assert sh.hint_lines(lines[0]) == lines


def test_the_samples_dumps_are_read_however_many_others_are_newer(tmp_path):
    """procdump2 dumps every process that exits: a hundred of the guest's
    services came after the sample's one dump, and a cap on all of them
    read none of the sample's (job ac66493d)."""
    dumps, trace, sample = linux_job(tmp_path, 0x400000)
    for n in range(1, hints.MAX_DUMPS + 5):
        sidecar(dumps, 1000 + n, b"not read", n=n)
    lines, report = hints.hints("core", dumps, trace, sample, "/root/sample", LIST, sh.static_hooks(LIST), {},
                                signatures(tmp_path), tmp_path / "none")
    assert len(lines) == 1 and [entry["pid"] for entry in report] == [77]


def test_a_function_the_list_has_already_is_no_hint(tmp_path):
    """An unpacked sample: the file gave the same function at the same place."""
    dumps, trace, sample = linux_job(tmp_path, 0x400000)
    have = LIST + "/root/sample,connect,1040,log,Fd:int\n"
    lines, report = hints.hints("core", dumps, trace, sample, "/root/sample", have, sh.static_hooks(have), {},
                                signatures(tmp_path), tmp_path / "none")
    assert lines == [] and report[0]["hooked"] == 0


def test_only_the_samples_processes_are_read_and_a_memfd_program_is_one(tmp_path):
    dumps, trace, sample = linux_job(tmp_path, 0x400000, path="/usr/bin/curl")
    args = (LIST, sh.static_hooks(LIST), {}, signatures(tmp_path), tmp_path / "none")
    assert hints.hints("core", dumps, trace, sample, "/root/sample", *args) == ([], [])

    dumps, trace, sample = linux_job(tmp_path, 0x7F1200000000, path="/memfd:x (deleted)", kind=3)
    lines, _ = hints.hints("core", dumps, trace, sample, "/root/sample", *args)
    # named as libmon names it, which is what the second run's process is matched by
    assert [line.split(",")[:3] for line in lines] == [["/memfd:x (deleted)", "connect", "1040"]]
    assert hints.is_module("/tmp/root/sample", "/root/sample") == "/root/sample"
    assert hints.is_module("/notroot/sample2", "/root/sample") is None


def test_a_dump_that_is_not_finished_or_not_a_core_gives_nothing(tmp_path):
    dumps, trace, sample = linux_job(tmp_path, 0x400000)
    args = (trace, sample, "/root/sample", LIST, sh.static_hooks(LIST), {}, signatures(tmp_path), tmp_path / "none")
    meta = dumps / "procdump.0.metadata"
    meta.write_text(meta.read_text().replace("Success", "Fail"))
    assert hints.hints("core", dumps, *args) == ([], [])
    sidecar(dumps, 77, b"MDMP" + bytes(200))
    assert hints.hints("core", dumps, *args)[0] == []
    sidecar(dumps, 77, b"")
    assert hints.hints("core", dumps, *args)[0] == []
    # a compression that is not read is said, not guessed at
    sidecar(dumps, 77, b"x", Compression="zstd")
    assert hints.hints("core", dumps, *args)[1][0]["skipped"] == "zstd is not read"


def test_go_functions_are_found_where_a_moved_program_was_linked(tmp_path, monkeypatch):
    """Go's table has the linker's addresses: a PIE's memory is elsewhere."""
    seen = []

    def table(image, data):
        seen.append(image.base)
        if image.base == 0:
            image.go_table, image.go_version = "1.20", "go1.21.0"
            return [sh.Located("net.Dial", 0x1040, "gopclntab")]
        return []
    monkeypatch.setattr(sh, "from_gopclntab", table)
    monkeypatch.setattr(sh, "toolchain", lambda data: "go")
    image = sh.Image("elf", 64, base=0x555555554000, code=[(0x555555555000, 0, CODE)], moved=0x555555554000)
    located = hints.locate(image, CODE, tmp_path / "none", tmp_path / "none")
    assert seen == [0x555555554000, 0] and image.go_table == "1.20"
    assert located == [sh.Located("net.Dial", 0x555555555040, "gopclntab")]


def test_a_go_set_says_the_release_when_the_table_is_not_found_where_linked(tmp_path, monkeypatch):
    """A moved Go program whose table is unreadable either way -- garble --
    keeps the release its signature set said, which decides the convention."""
    def named_by_set(image, data, flirt_dir, yara_dir):
        image.go_set, image.go_version = "go-1.26.11-amd64", "go1.26.11"
        return [sh.Located("os.Rename", 0x400040, "flirt:go-1.26.11-amd64")]
    monkeypatch.setattr(sh, "locate_in", named_by_set)
    monkeypatch.setattr(sh, "toolchain", lambda data: "go")
    image = sh.Image("elf", 64, base=0x3D92000, code=[(0x400000, 0, CODE)], moved=0x3992000)
    located = hints.locate(image, CODE, tmp_path / "none", tmp_path / "none")
    assert image.go_version == "go1.26.11" and sh.go_abi(image) == "goabi"
    go = {"os.Rename": "goabi,log,From:buffer[FromLen],FromLen:ulong"}
    line, = sh.sample_lines(located, {}, "/s", image.base, go, sh.go_abi(image), hints.when(image, CODE))
    assert ",goabi,log,From:buffer[FromLen]" in line


# --- Windows ----------------------------------------------------------------

def pe_page(base: int, stamp: int = 0x12345678, dll: bool = False) -> bytes:
    page = bytearray(0x1000)
    page[0:2] = b"MZ"
    struct.pack_into("<I", page, 0x3C, 0x40)
    page[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", page, 0x44, 0x8664, 1, stamp, 0, 0, 240, 0x2022 if dll else 0x22)
    opt = 0x58
    struct.pack_into("<H", page, opt, 0x20B)
    struct.pack_into("<Q", page, opt + 24, base)
    struct.pack_into("<I", page, opt + 56, 0x3000)
    struct.pack_into("<I", page, opt + 108, 16)
    struct.pack_into("<II", page, opt + 112 + 5 * 8, 0x2000, 12)          # the relocation directory
    section = opt + 240
    page[section:section + 5] = b".text"
    struct.pack_into("<III", page, section + 8, 0x1000, 0x1000, 0x1000)
    struct.pack_into("<I", page, section + 36, 0x60000020)
    return bytes(page)


def minidump(ranges: list) -> bytes:
    """[(start, bytes)] as procdump2 writes a process: one stream that is
    looked at, the memory list, and the memory after it in that order."""
    table = 44 + 4
    data_at = table + 16 * len(ranges)
    out = bytearray(b"MDMP" + struct.pack("<IIIIIQ", 0x61B1A793, 1, 32, 0, 0, 0))
    out += struct.pack("<III", 5, 4 + 16 * len(ranges), 44)
    out += struct.pack("<I", len(ranges))
    offset = data_at
    for start, data in ranges:
        out += struct.pack("<QII", start, len(data), offset & 0xFFFFFFFF)
        offset += len(data)
    for _, data in ranges:
        out += data
    return bytes(out)


def windows_job(tmp_path: Path, base: int = 0x7FF600000000):
    # The loader rewrites eight bytes of the function, from its fifth on
    relocations = struct.pack("<IIHH", 0x1000, 12, (10 << 12) | 0x44, 0).ljust(0x1000, b"\0")
    image = pe_page(base) + CODE + relocations
    dumps = tmp_path / "procdumps"
    sidecar(dumps, 4321, minidump([(0x10000, bytes(0x4000)),
                                   # a DLL built the same second, and the right size: not the program
                                   (0x7FF500000000, pe_page(0x7FF500000000, dll=True) + CODE + relocations),
                                   (base, image), (0x7FF900000000, bytes(0x1000))]))
    sample = tmp_path / "s.exe"
    sample.write_bytes(pe_page(0x140000000) + b"packed")
    return dumps, sample


def test_the_image_with_the_samples_header_is_read_out_of_a_minidump(tmp_path):
    dumps, sample = windows_job(tmp_path)
    lines, report = hints.hints("minidump", dumps, tmp_path / "trace.log", sample, "C:\\Users\\u\\Desktop\\s.exe",
                                LIST, sh.static_hooks(LIST), {}, signatures(tmp_path), tmp_path / "none")
    # the VAD's name for the file, an RVA, and `??` where the loader wrote
    waits = BODY[:4].hex() + "??" * 8 + BODY[12:16].hex()
    assert lines == [f"Users\\u\\Desktop\\s.exe,connect,1040,when:{waits},log,Fd:int,SockAddr:lpsockaddr,AddrLen:int"]
    assert report[0]["base"] == 0x7FF600000000 and report[0]["pid"] == 4321


def windows_trace(tmp_path, base, pid=4321):
    """apimon's word for where each process has the sample's image, and the
    process names that say which processes are the sample."""
    module = "\\Users\\u\\Desktop\\s.exe"
    records = [
        {"Plugin": "syscall", "PID": pid, "ProcessName": "\\Device\\HarddiskVolume2" + module, "Method": "NtClose"},
        {"Plugin": "apimon", "Event": "dll_discovered", "DllName": module, "DllBase": hex(base), "PID": pid},
        # explorer maps the file for its icon: not the sample
        {"Plugin": "syscall", "PID": 2624, "ProcessName": "\\Device\\HarddiskVolume2\\Windows\\explorer.exe"},
        {"Plugin": "apimon", "Event": "dll_discovered", "DllName": module, "DllBase": "0x8080000", "PID": 2624},
    ]
    trace = tmp_path / "trace.log"
    trace.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    return trace


def test_the_samples_image_is_found_by_where_apimon_saw_it(tmp_path):
    """A packer that wipes its header, or writes the payload's over it, leaves
    no header to match: the image is the range at the base apimon reported,
    and the sample's own layout stands in for a wiped header."""
    base = 0x7FF600000000
    dumps, sample = windows_job(tmp_path, base)
    trace = windows_trace(tmp_path, base)
    assert hints.windows_images(trace, "Users\\u\\Desktop\\s.exe") == {4321: base}

    # the header wiped in memory
    raw = gzip.decompress((dumps / "procdump.0").read_bytes())
    at = raw.index(pe_page(base))
    (dumps / "procdump.0").write_bytes(gzip.compress(raw[:at] + bytes(0x1000) + raw[at + 0x1000:]))
    lines, report = hints.hints("minidump", dumps, trace, sample, "C:\\Users\\u\\Desktop\\s.exe",
                                LIST, sh.static_hooks(LIST), {}, signatures(tmp_path), tmp_path / "none")
    assert [line.split(",")[:3] for line in lines] == [["Users\\u\\Desktop\\s.exe", "connect", "1040"]]
    assert report[0]["base"] == base

    # a dump of another process, or one without that range, is said and not guessed at
    lines, report = hints.hints("minidump", dumps, windows_trace(tmp_path, 0x7FF700000000), sample,
                                "C:\\Users\\u\\Desktop\\s.exe", LIST, sh.static_hooks(LIST), {},
                                signatures(tmp_path), tmp_path / "none")
    assert lines == [] and report[0]["skipped"] == "the image is not in the dump"


def test_a_dump_without_the_samples_image_and_a_sample_that_is_no_program(tmp_path):
    dumps, sample = windows_job(tmp_path)
    args = (LIST, sh.static_hooks(LIST), {}, signatures(tmp_path), tmp_path / "none")
    other = tmp_path / "other.exe"
    other.write_bytes(pe_page(0x140000000, stamp=0x5555))
    assert hints.hints("minidump", dumps, tmp_path / "t", other, "C:\\other.exe", *args) == ([], [])
    script = tmp_path / "s.ps1"
    script.write_text("Write-Host hi")
    assert hints.hints("minidump", dumps, tmp_path / "t", script, "C:\\s.ps1", *args) == ([], [])


def test_an_address_of_the_image_in_its_code_is_left_out_of_the_marker():
    """32-bit Go: `mov ecx, [tls_g]` with the slot's absolute address, at
    the start of every function. A packer leaves no relocation directory to
    say so, and the image is elsewhere in the next run."""
    base = 0xA70000
    code = bytes.fromhex("8b0dc0b8e200" "648b09" "8b09" "3b6108" "0f86") + bytes(48)
    image = sh.Image("pe", 32, base=base, code=[(base + 0x1000, 0, code)], extent=0x400000)
    assert hints.when(image, code)(base + 0x1000) == "when:8b0d????????648b098b093b61080f86"
    # the same bytes in the next run, at 0x1D0000, match it
    pattern = hints.when(image, code)(base + 0x1000).removeprefix("when:")
    moved = (0x1D0000 + 0x3BB8C0).to_bytes(4, "little")
    there = bytes.fromhex("8b0d") + moved + code[6:16]
    assert all(p == "??" or int(p, 16) == b for p, b in zip((pattern[i:i + 2] for i in range(0, 32, 2)), there))
    # a value outside the image is the code's own, kept
    image.extent = 0x100000
    assert hints.when(image, code)(base + 0x1000) == "when:8b0dc0b8e200648b098b093b61080f86"


def test_code_that_is_the_same_nowhere_gets_no_marker():
    image = sh.Image("pe", 64, base=0x1000, code=[(0x2000, 0, bytes(64) + BODY)],
                     relocated=set(range(0x1040 + 2, 0x1040 + 16)))
    marker = hints.when(image, bytes(64) + BODY)
    assert marker(0x2000) == ""         # zeros: nothing to tell it by
    assert marker(0x2040) == ""         # two bytes the loader leaves alone
    assert marker(0x9000) == ""         # not in the code at all


def test_the_main_program_writes_hints_only_when_there_are_some(tmp_path):
    dumps, trace, sample = linux_job(tmp_path, 0x400000)
    job_list = tmp_path / "hooks.txt"
    job_list.write_text(LIST)
    argv = ["--procdumps", str(dumps), "--trace-log", str(trace), "--sample", str(sample),
            "--guest-path", "/root/sample", "--list", str(job_list), "--how", "core",
            "--out", str(tmp_path / "hints.txt"), "--json", str(tmp_path / "hints.json"),
            "--flirt", str(signatures(tmp_path)), "--code-signatures", str(tmp_path / "none"), "--max-mib", "0"]
    assert hints.main(argv) == 0
    line = (tmp_path / "hints.txt").read_text().strip()
    assert json.loads((tmp_path / "hints.json").read_text())["hooked"] == 1

    # the second run's list: the static one, then what the memory showed
    out = tmp_path / "second.txt"
    assert sh.main([str(sample), "--guest-path", "/root/sample", "--static", str(job_list), "--out", str(out),
                    "--hints", str(tmp_path / "hints.txt"), "--max-mib", "0"]) == 0
    assert out.read_text().startswith(LIST) and out.read_text().rstrip().endswith(line)

    (tmp_path / "hints.txt").unlink()
    job_list.write_text(LIST + line.replace(",when:" + BODY[:16].hex(), "") + "\n")
    assert hints.main(argv) == 0 and not (tmp_path / "hints.txt").exists()


def test_every_guest_with_process_dumps_names_a_format_this_reads():
    assert set(G.PROCESS_DUMPS.values()) <= {"core", "minidump"}
    assert G.TargetOs.ANDROID not in G.PROCESS_DUMPS


# --- the two runs -------------------------------------------------------------

@dataclass
class Lease(stages.FakeLease):
    second_pass: bool = True


def two_run_runner(found: bool = True, second_clone_fails: bool = False):
    """A host whose clone exists between `xl restore` and `xl destroy`, and
    whose locators write what the real ones would."""
    r = FakeRunner()
    state = {"up": False, "clones": 0, "samplehooks": [], "stagehints": 0}
    clone = "ubuntu_sandbox-3-clone"

    def answer(rc=0, stdout=""):
        return lambda argv: Completed(argv=tuple(argv), returncode=rc, stdout=stdout, stderr="", duration=0.0)

    def restore(argv):
        state["clones"] += 1
        if second_clone_fails and state["clones"] == 2:
            return answer(1)(argv)
        state["up"] = True
        return answer()(argv)

    def destroy(argv):
        state["up"] = False
        return answer()(argv)

    def samplehooks(argv):
        state["samplehooks"].append(argv)
        Path(argv[argv.index("--out") + 1]).write_text(LIST)
        return answer()(argv)

    def stagehints(argv):
        state["stagehints"] += 1
        directory = Path(argv[argv.index("--procdumps") + 1]).parent
        # what the first run left is still there to be read
        assert (directory / "trace.log").is_file()
        (directory / "first-run-marker").write_text("1")
        if found:
            Path(argv[argv.index("--out") + 1]).write_text("/s,connect,1040,when:5548,log\n")
        Path(argv[argv.index("--json") + 1]).write_text(json.dumps({"hooked": int(found)}))
        return answer()(argv)

    r.script(("lvdisplay", "/dev/vg-root/ubuntu_sandbox"), rc=0)
    r.hook(("lvdisplay", f"/dev/vg-root/{clone}"), lambda argv: answer(0 if state["up"] else 1)(argv))
    r.hook(("xl", "domid", clone), lambda argv: answer(0, "42\n")(argv) if state["up"] else answer(1)(argv))
    r.hook(("xl", "restore"), restore)
    r.hook(("xl", "destroy"), destroy)
    r.hook((sys.executable, "-m", "sandboxd.samplehooks"), samplehooks)
    r.hook((sys.executable, "-m", "sandboxd.stagehints"), stagehints)
    r.hook((sys.executable, "-m", "sandboxd.postprocessing"), stages.inline_postprocess)
    return r, state


PLUGINS = ["syscalls", "libmon", "procdump2"]


def test_a_job_that_asks_runs_twice_and_the_second_run_is_the_result(tmp_path):
    r, state = two_run_runner()
    outcome, api = stages.run(tmp_path, runner=r, lease=Lease(plugins=PLUGINS), keep_results=True)

    assert outcome.state == "completed" and state["clones"] == 2 and state["stagehints"] == 1
    # to the platform, one execution: its state machine goes forwards only
    assert stages.states_of(api) == ["preparing", "executing", "collecting", "cleaning", "completed"]
    first, second = state["samplehooks"]
    assert "--hints" not in first and second[second.index("--hints") + 1].endswith("hints.txt")
    # the first run's files are not the result's
    job_dir = tmp_path / "results" / Lease().job_id
    assert not (job_dir / "first-run-marker").exists()
    assert "second pass: this is the second run, with 1 function found" in outcome.manifest["notes"]
    assert outcome.cleanup_status == "clean"


def test_memory_with_nothing_to_add_is_one_run(tmp_path):
    r, state = two_run_runner(found=False)
    outcome, _ = stages.run(tmp_path, runner=r, lease=Lease(plugins=PLUGINS), keep_results=True)

    assert outcome.state == "completed" and state["clones"] == 1 and state["stagehints"] == 1
    assert (tmp_path / "results" / Lease().job_id / "first-run-marker").exists()
    assert "second pass: not made, the first run's memory showed no function" in outcome.manifest["notes"]


def test_a_second_run_that_fails_leaves_the_first_as_the_result(tmp_path):
    r, state = two_run_runner(second_clone_fails=True)
    outcome, api = stages.run(tmp_path, runner=r, lease=Lease(plugins=PLUGINS), keep_results=True)

    assert outcome.state == "completed" and state["clones"] == 2
    assert (tmp_path / "results" / Lease().job_id / "first-run-marker").exists()
    assert "the second run failed" in outcome.manifest["notes"]
    assert "this is the first run" in outcome.manifest["notes"]
    assert stages.states_of(api)[-1] == "completed"


def test_a_job_that_does_not_ask_leaves_the_lines_for_a_later_one(tmp_path):
    """One run, and `hints.txt` among its artifacts: what the job page offers
    "Run again" from."""
    r, state = two_run_runner()
    outcome, _ = stages.run(tmp_path / "a", runner=r, lease=stages.FakeLease(plugins=PLUGINS))
    assert outcome.state == "completed" and state["clones"] == 1 and state["stagehints"] == 1
    assert "hints.txt" in outcome.artifacts
    assert "second run available: 1 function found" in outcome.manifest["notes"]

    # nothing found, nothing left and nothing said: most jobs
    r, state = two_run_runner(found=False)
    outcome, _ = stages.run(tmp_path / "c", runner=r, lease=stages.FakeLease(plugins=PLUGINS))
    assert "hints.txt" not in outcome.artifacts and "second" not in outcome.manifest.get("notes", "")

    # asked for, without procdump2: nothing to read, and the manifest says so
    r, state = two_run_runner()
    outcome, _ = stages.run(tmp_path / "b", runner=r, lease=Lease(plugins=["syscalls", "libmon"]))
    assert state["clones"] == 1 and state["stagehints"] == 0
    assert "second pass: not made, it needs" in outcome.manifest["notes"]


@dataclass
class Again(stages.FakeLease):
    second_run_of: str | None = "22222222-2222-2222-2222-222222222222"
    hints_url: str | None = "https://store/results/2222/hints.txt"


class ApiWithHints(stages.FakeApi):
    hints = "/s,connect,1040,when:5548,log\nnot,a,hint\n"

    def fetch_hints(self, url, dest, *, limit=1 << 20, timeout=None):
        assert url == Again().hints_url
        if self.hints is None:
            raise OSError("gone")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(self.hints)
        return len(self.hints)


def test_a_job_made_from_a_finished_one_is_its_second_run(tmp_path):
    r, state = two_run_runner()
    outcome, _ = stages.run(tmp_path, runner=r, api=ApiWithHints(), lease=Again(plugins=PLUGINS))

    # one run, with the earlier job's lines, and its own memory is not read again
    assert outcome.state == "completed" and state["clones"] == 1 and state["stagehints"] == 0
    only, = state["samplehooks"]
    assert only[only.index("--hints") + 1].endswith("hints.txt")
    assert f"second run of {Again().second_run_of}, with 1 function" in outcome.manifest["notes"]
    assert "hints.txt" not in outcome.artifacts


def test_hints_that_cannot_be_had_make_it_a_first_run(tmp_path):
    api = ApiWithHints()
    api.hints = None
    r, state = two_run_runner()
    outcome, _ = stages.run(tmp_path, runner=r, api=api, lease=Again(plugins=PLUGINS))
    assert outcome.state == "completed" and "--hints" not in state["samplehooks"][0]
    assert "its hints could not be read" in outcome.manifest["notes"]


def test_only_a_hint_is_taken_from_a_hints_file(tmp_path):
    """What comes back from the store goes into the list DRAKVUF starts on."""
    good = "Users\\u\\s.exe,connect,1040,when:5548??ec,log,Fd:int"
    text = "\n".join([good, "/s,connect,log,Fd:int", "/s,f,10,log", "/s,f,zz,when:55,log", "/s,f,10,when:5,log",
                      "# /s,f,10,when:55,log", "/s,f,10,when:55,log\x00", ""])
    assert sh.hint_lines(text) == [good]
    out = tmp_path / "list"
    sh.write_list(LIST, [], out, text)
    assert out.read_text().rstrip().endswith(good) and "zz" not in out.read_text()


def test_a_lease_asks_for_a_second_pass_only_with_true():
    from sandboxd import api as A
    fields = {f.name: f for f in A.Lease.__dataclass_fields__.values()}
    assert fields["second_pass"].default is False
