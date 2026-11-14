"""scripts/dotnet-index.py: the precompiled methods of .NET assemblies.

The table format is checked against real assemblies when a directory of them
is given (`DOTNET_R2R_DIR`, e.g. the `lib/net8.0` of the NuGet package
Microsoft.NETCore.App.Runtime.win-x64): they are Microsoft's and too large to
keep in the tree. Without it, the parts that read no assembly are tested.
"""
import importlib.util
import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("dotnet_index", ROOT / "scripts" / "dotnet-index.py")
di = importlib.util.module_from_spec(spec)
spec.loader.exec_module(di)


def test_the_native_formats_numbers():
    # one to five bytes, the low bits of the first saying how many
    assert di.decode_unsigned(bytes([0x54]), 0) == (0x2A, 1)
    assert di.decode_unsigned(bytes([0x01 | 0x34 << 2 & 0xFF, 0x12 << 2 | 0x34 >> 6]), 0) == (0x1234, 2)
    assert di.decode_unsigned(bytes([0x0F, 0x78, 0x56, 0x34, 0x12]), 0) == (0x12345678, 5)


@pytest.mark.parametrize("blob,this,kinds,names", [
    # instance string M(string)
    (bytes([0x20, 0x01, 0x0E, 0x0E]), True, ["clrstring"], ["string", "string"]),
    # static Assembly Load(byte[], byte[])
    (bytes([0x00, 0x02, 0x12, 0x09, 0x1D, 0x05, 0x1D, 0x05]), False, ["clrbytes", "clrbytes"], ["class", "byte[]", "byte[]"]),
    # static void M<T>(int, ref long, List<string>, valuetype)
    (bytes([0x10, 0x01, 0x04, 0x01, 0x08, 0x10, 0x0A, 0x15, 0x12, 0x05, 0x01, 0x0E, 0x11, 0x09]), False,
     ["dword", "lpvoid", "lpvoid", "lpvoid"], ["void", "int", "long&", "generic", "valuetype"]),
])
def test_a_methods_signature_says_what_its_arguments_are(blob, this, kinds, names):
    assert di.read_signature(blob)[:3] == (this, kinds, names)


def test_a_hook_line_types_arguments_only_where_the_signature_places_them():
    entry = {"module": r"dotnet\8.0.11\X.dll", "rva": 0xA220, "bits": 64, "this": True,
             "args": ["clrstring"], "returns": "string", "signature": "(string)"}
    assert di.hook_line("N.T::M", entry) == r"dotnet\8.0.11\X.dll,N.T::M,a220,clrcall,log,This:lpvoid,Arg1:clrstring"
    # a struct returned by value is a hidden argument: the call, bare
    assert di.hook_line("N.T::M", dict(entry, returns="valuetype")) == r"dotnet\8.0.11\X.dll,N.T::M,a220,log"
    # x86 pushes a long as two words and keeps a double out of the registers
    wide = dict(entry, bits=32, args=["ulong"], signature="(long)")
    assert di.hook_line("N.T::M", wide).endswith(",a220,log")
    assert di.hook_line("N.T::M", dict(wide, bits=64)).endswith(",clrcall,log,This:lpvoid,Arg1:ulong")
    # a signature that was not read
    assert di.hook_line("N.T::M", dict(entry, args=None, signature=None)).endswith(",a220,log")


def test_the_rules_methods_are_the_ones_spelled_as_dotnet_spells_them(tmp_path):
    (tmp_path / "a.yml").write_text(
        "features:\n  - or:\n    - api: System.Net.WebClient::DownloadString\n"
        "    - api: kernel32.CreateFileW\n    - property/read: System.Environment::MachineName\n")
    assert di.capa_methods(tmp_path) == {"System.Net.WebClient::DownloadString", "System.Environment::MachineName"}


def test_real_assemblies_index_to_function_starts(tmp_path):
    where = os.environ.get("DOTNET_R2R_DIR")
    if not where:
        pytest.skip("DOTNET_R2R_DIR is not set: the table reader was not run on a real assembly")
    import pefile

    out, hooks = tmp_path / "index.json", tmp_path / "hooks.txt"
    assert di.main([where, "--root", where, "-o", str(out), "--hooks", str(hooks)]) == 0
    index = json.loads(out.read_text())["methods"]
    assert any(e["args"] == ["clrstring"] for e in index["System.Convert::FromBase64String"])
    for module in {e["module"] for es in index.values() for e in es}:
        pe = pefile.PE(str(Path(where) / module), fast_load=True)
        rvas = [e["rva"] for es in index.values() for e in es if e["module"] == module]
        code = [(s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize) for s in pe.sections
                if s.Characteristics & 0x20000000]
        assert all(any(a <= r < b for a, b in code) for r in rvas) and len(set(rvas)) == len(rvas)
    # and every line is one DRAKVUF's loader takes: a bad one stops apimon
    for line in hooks.read_text().splitlines():
        if line and not line.startswith("#"):
            fields = line.split(",")
            assert int(fields[2], 16) > 0 and "log" in fields[3:5]


def test_the_jit_compilers_hook_line_comes_from_its_symbol_profile(tmp_path):
    profile = tmp_path / "clrjit-core.json"
    # the name as it is in .NET 8.0.11's clrjit.pdb (fetched 2026-11-14)
    name = "?compileMethod@CILJit@@EEAA?AW4CorJitResult@@PEAVICorJitInfo@@PEAUCORINFO_METHOD_INFO@@IPEAPEAEPEAI@Z"
    profile.write_text(json.dumps({"symbols": {name: {"address": 0x7A5C0}, "?other@CILJit@@X": {"address": 1}}}))
    assert di.jit_line(r"dotnet\8.0.11\clrjit.dll", profile) == (
        r"dotnet\8.0.11\clrjit.dll,CILJit::compileMethod,7a5c0,log,This:lpvoid,Comp:lpvoid,"
        "Info:pcorinfo_method_info,Flags:dword,NativeEntry:lpvoid*,NativeSize:pulong")
    profile.write_text(json.dumps({"symbols": {}}))
    with pytest.raises(di.Unreadable):
        di.jit_line("clrjit.dll", profile)


def test_the_newest_runtime_directory_is_the_one_profiled(tmp_path):
    spec = importlib.util.spec_from_file_location("wsp", ROOT / "scripts" / "windows-symbol-profiles.py")
    wsp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wsp)
    for version in ("8.0.2", "8.0.11", "6.0.36"):
        (tmp_path / "dotnet" / version).mkdir(parents=True)
        (tmp_path / "dotnet" / version / "clrjit.dll").write_bytes(b"MZ")
    assert wsp.locate(tmp_path, "dotnet/*/clrjit.dll") == tmp_path / "dotnet" / "8.0.11" / "clrjit.dll"
    assert {name for _, name, _ in wsp.JIT} == {"clrjit.json", "clrjit32.json", "clrjit-core.json", "clrjit-core32.json"}


def test_a_compiled_method_is_named_by_its_il_body(tmp_path, monkeypatch):
    from sandboxd.postprocessing import clrjit

    bodies = {(7, "02280a00000a2a"): ["Stealer.Program::Main"],
              (1, "2a"): ["Stealer.A::.ctor", "Stealer.B::Dispose"]}
    monkeypatch.setattr(clrjit, "method_bodies", lambda path: bodies)
    timeline = clrjit.Timeline(tmp_path / "s.exe")

    def call(info, api=clrjit.JIT_API):
        return {"api": api, "ts": 1.5, "tid": 7, "arguments": [
            {"name": "Info", "value": info}, {"name": "NativeEntry", "value": "0x7ff0"},
            {"name": "NativeSize", "value": "0x40"}]}

    timeline.add(4, call("0x1f0:{ftn=0x1,scope=0x2,il=0x20001050,size=7,code=02280A00000A2A}"))
    timeline.add(4, call("0x1f0:{ftn=0x1,scope=0x2,il=0x20001060,size=1,code=2a}"))
    timeline.add(4, call("0x1f0:{ftn=0x1,scope=0x2,il=0x7ffa0000,size=9,code=0011223344}"))   # the framework's
    timeline.add(4, call("whatever", api="kernel32.CreateFileW"))
    result = timeline.result()
    assert (result["compiled"], result["named"]) == (3, 2)
    first, second, third = result["methods"]
    assert first["method"] == "Stealer.Program::Main" and first["native"] == "0x7ff0" and first["pid"] == 4
    assert second["method"] is None and second["candidates"] == ["Stealer.A::.ctor", "Stealer.B::Dispose"]
    assert third["method"] is None and third["candidates"] is None
    assert clrjit.Timeline(None).result() is None


def test_a_real_assemblys_method_bodies_are_read():
    where = os.environ.get("DOTNET_R2R_DIR")
    if not where:
        pytest.skip("DOTNET_R2R_DIR is not set: no managed assembly to read method bodies from")
    from sandboxd.postprocessing import clrjit

    bodies = clrjit.method_bodies(Path(where) / "System.Net.WebClient.dll")
    names = [n for ns in bodies.values() for n in ns]
    assert "System.Net.WebClient::DownloadString" in names and len(names) > 300
    # a body is IL: it ends in ret, throw, a branch or a tail of one, never in zero padding only
    assert all(size > 0 and len(prefix) == 2 * min(size, clrjit.PREFIX_BYTES) for size, prefix in bodies)
    assert clrjit.method_bodies(Path(__file__)) == {}
