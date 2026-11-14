"""trace_split's first pass on worker processes (postprocessing/linescan.py):
the same lines, in the same order, as one process reading the file."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd.guests import TargetOs  # noqa: E402
from sandboxd.postprocessing import linescan  # noqa: E402
from sandboxd.postprocessing.plugins.cape_plugin.trace_split import read_prelude  # noqa: E402
from sandboxd.tests.test_cape_noise import handed_off  # noqa: E402
from sandboxd.tests.test_cape_split import rec  # noqa: E402


def test_stretches_end_at_line_ends_and_cover_the_file(tmp_path):
    path = tmp_path / "t"
    path.write_bytes(b"".join(b"line %d %s\n" % (i, b"x" * (i % 37)) for i in range(500)) + b"no newline at the end")
    found = list(linescan.stretches(path, 256))
    assert found[0][0] == 0 and found[-1][1] == path.stat().st_size
    assert all(a[1] == b[0] for a, b in zip(found, found[1:]))
    data = path.read_bytes()
    assert all(data[end - 1:end] == b"\n" for _, end in found[:-1])


def test_workers_return_what_one_reader_does_in_order(tmp_path, monkeypatch):
    path = tmp_path / "t"
    rows = [b'{"Plugin":"%s","n":%d,"v":"a\\rb"}\n' % (p, i)
            for i, p in enumerate([b"procmon", b"syscall", b"sysret", b"apimon", b"inject"] * 400)]
    rows[7] = b'{"Plugin":"regmon","Value":"cut by a raw\rreturn, procmon"}\n'
    path.write_bytes(b"".join(rows))
    wanted = [r for r in rows if b"procmon" in r or b"inject" in r]

    monkeypatch.setattr(linescan, "MIN_PARALLEL_BYTES", 0)
    for workers in (1, 3):
        kept, flags = [], []
        for part, flag in linescan.matching(path, (b"procmon", b"inject"), rb'"Plugin":\s*"sysret"',
                                            workers=workers, chunk=4096):
            kept += linescan.lines(part)
            flags.append(flag)
        assert kept == wanted and all(flags)


def test_the_prelude_is_the_same_on_workers(tmp_path, monkeypatch):
    """The tree, the injection, the hand-off to the shell: whatever one
    process finds, over stretches small enough to cut the trace many times."""
    (tmp_path / "trace.log").write_text("".join(
        json.dumps(r) + "\n" for r in (*handed_off(), *(rec("syscall", 0x100 + i, 50, method="NtClose", Handle="0x4")
                                                         for i in range(300)))))
    alone = read_prelude(tmp_path / "trace.log", TargetOs.WINDOWS, workers=1)
    monkeypatch.setattr(linescan, "CHUNK", 1024)
    monkeypatch.setattr(linescan, "MIN_PARALLEL_BYTES", 0)
    spread = read_prelude(tmp_path / "trace.log", TargetOs.WINDOWS, workers=3)

    def facts(p):
        return (sorted((n.pid, n.ppid, n.procname) for n in p.tree.processes), p.injected, p.has_sysret,
                p.transfers, p.started_for)
    assert facts(alone) == facts(spread) and alone.started_for


def test_a_worker_loads_this_module_and_no_plugin():
    """What keeps a worker at 10 MiB: `import sandboxd.postprocessing.linescan`
    must not bring the plugins' package (capa, the signatures' loader) with it."""
    import subprocess
    code = ("import sys, sandboxd.postprocessing.linescan; "
            "print(sorted(m for m in sys.modules if m.startswith('sandboxd.') or m in ('capa', 'orjson')))")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    assert out.strip() == "['sandboxd.postprocessing', 'sandboxd.postprocessing.linescan']"
