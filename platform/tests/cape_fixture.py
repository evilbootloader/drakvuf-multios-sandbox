"""A CAPE report and calls log with every section the job page renders.

The shapes are those `sandboxd/postprocessing/plugins/cape_analysis.py`
writes (checked against its output over `samples/trace-*.log`, 2026-11-11),
filled the way a Windows dropper's run fills them -- and with the guest's
own processes alongside, whose dumps, drops, endpoints and events the page
must not show. `HOSTILE` lands in every kind of field the sample controls.
"""

from __future__ import annotations

import gzip
import json

HOSTILE = '"><script>alert(1)</script><img src=x onerror=alert(2)>'

T0 = 1789666600.0

# seqid: (pid, ppid, parent seqid, image, command line, started at +s)
SAMPLE = {
    10: (4100, 2200, None, "\\Device\\HarddiskVolume2\\Users\\u\\Desktop\\invoice.exe",
         '"C:\\Users\\u\\Desktop\\invoice.exe" /silent ' + HOSTILE, 0.5),
    11: (4188, 4100, 10, "\\Device\\HarddiskVolume2\\Windows\\System32\\cmd.exe",
         'cmd.exe /c schtasks /create /tn updater /tr "C:\\Users\\u\\AppData\\Roaming\\upd.exe"', 3.25),
    12: (4232, 4188, 11, "\\Device\\HarddiskVolume2\\Windows\\System32\\schtasks.exe",
         "schtasks /create /tn updater /tr C:\\Users\\u\\AppData\\Roaming\\upd.exe", 3.5),
    # explorer, taken over by a remote thread at +6.0 s
    13: (2300, 2200, None, "\\Device\\HarddiskVolume2\\Windows\\explorer.exe",
         "C:\\Windows\\explorer.exe", 0.0),
}
# The guest's own: in the trace, never on the page
GUEST = {20: (900, 4, None, "\\Device\\HarddiskVolume2\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs", 0.0)}


def _process(seqid, pid, ppid, parent, image, cmdline, started, calls):
    name = image.rsplit("\\", 1)[-1]
    return {
        "process_id": pid, "process_name": name, "parent_id": ppid, "module_path": image,
        "first_seen": "2026-09-18 10:00:00,000", "threads": [str(pid + 4), str(pid + 8)],
        "environ": {"CommandLine": cmdline},
        "file_activities": {"read_files": [], "write_files": [], "delete_files": []},
        "seqid": seqid, "parent_seqid": parent, "started_ts": T0 + started if started else None,
        "exited_ts": T0 + 9.75 if seqid == 12 else None,
        "exit_code": 0 if seqid == 12 else None, "exit_code_str": "STATUS_SUCCESS" if seqid == 12 else None,
        "killed_by": None, "call_count": calls,
    }


def _tree(seqid, everything):
    pid, ppid, parent, image, cmdline, started = everything[seqid]
    node = {"name": image.rsplit("\\", 1)[-1], "pid": pid, "parent_id": ppid, "module_path": image,
            "threads": [], "environ": {"CommandLine": cmdline}, "first_seen": "", "seqid": seqid,
            "parent_seqid": parent, "children": []}
    node["children"] = [_tree(s, everything) for s, v in everything.items() if v[2] == seqid]
    return node


def calls_for(seqid: int, n: int) -> list[dict]:
    pid = SAMPLE.get(seqid, GUEST.get(seqid))[0]
    apis = [("NtCreateFile", "filesystem", [("FileName", "C:\\Users\\u\\AppData\\Roaming\\upd.exe"),
                                            ("DesiredAccess", "0x40100080")]),
            ("RegSetValueExW", "registry", [("FullName", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd"),
                                            ("Buffer", "C:\\Users\\u\\AppData\\Roaming\\upd.exe")]),
            ("connect", "network", [("s", "0x1a4"), ("name", "203.0.113.7:443"), ("ip", "203.0.113.7"), ("port", "443")]),
            ("CryptEncrypt", "crypto", [("hKey", "0x5550"), ("pbData", "beacon \x00\x01\x02\x03\xff id=" + HOSTILE)]),
            ("NtClose", "system", [("Handle", "0x1a4")])]
    out = []
    for i in range(n):
        api, category, args = apis[i % len(apis)]
        out.append({"ts": f"{T0 + 1 + i * 0.01:.6f}", "tid": str(pid + 4 + 4 * (i % 2)), "api": api,
                    "kernel": api.startswith("Nt"), "category": category,
                    "status": False if i % 17 == 3 else True, "return": "0x0",
                    "caller": "0x402005", "repeated": 2 if i == 7 else 0, "plugin": "apimon",
                    "sources": ["apimon"],
                    "arguments": [{"name": k, "value": v} for k, v in args]
                    + [{"name": "Index", "value": hex(i)}]})
    return out


def calls_log(counts: dict[int, int], chunk: int = 200) -> tuple[bytes, bytes]:
    """(calls_index.json, calls.jsonl.gz) for the given calls per seqid, in
    the format cape_analysis._CallsLog writes."""
    log, offset, processes = bytearray(), 0, {}
    for seqid, n in counts.items():
        rows = calls_for(seqid, n)
        chunks, cats, apis = [], {}, {}
        for start in range(0, n, chunk):
            part = rows[start:start + chunk]
            member = gzip.compress(b"\n".join(json.dumps(r).encode() for r in part) + b"\n")
            cc = {}
            for r in part:
                cc[r["category"]] = cc.get(r["category"], 0) + 1
                cats[r["category"]] = cats.get(r["category"], 0) + 1
                apis[r["api"]] = apis.get(r["api"], 0) + 1
            chunks.append([offset, len(member), start, cc])
            log += member
            offset += len(member)
        processes[str(seqid)] = {"pid": SAMPLE.get(seqid, GUEST.get(seqid))[0], "count": n,
                                 "threads": sorted({r["tid"] for r in rows}), "categories": cats,
                                 "apis": apis, "chunks": chunks}
    index = {"version": 1, "chunk": chunk, "log": "calls.jsonl.gz", "processes": processes}
    return json.dumps(index).encode(), bytes(log)


CALL_COUNTS = {10: 450, 11: 40, 12: 12, 13: 6}


def document(scope_all: bool = False) -> dict:
    everything = {**SAMPLE, **(GUEST if scope_all else {})}
    processes = [_process(s, *v, CALL_COUNTS.get(s, 3)) for s, v in everything.items()]
    sample_pids = [v[0] for v in SAMPLE.values()]
    guest_pid = GUEST[20][0]
    sig_data = [{"type": "call", "pid": 4100, "cid": 1}, {"type": "call", "pid": 4100, "cid": 403},
                {"regkey": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd"},
                {"process": {"process_name": "invoice.exe", "process_id": 4100},
                 "signs": [{"type": "file", "value": "C:\\Users\\u\\AppData\\Roaming\\upd.exe"},
                           {"type": "cmdline", "value": HOSTILE}]}]
    return {
        "info": {"id": "job", "started": "2026-09-18 10:00:00", "ended": "2026-09-18 10:02:00",
                 "duration": 120, "started_ts": T0, "machine": {"name": "windows", "platform": "windows"}},
        "target": {"category": "file", "file": {
            "name": "invoice.exe", "path": "/srv/job/invoice.exe", "size": 284672, "type": "PE32+ executable (GUI) x86-64, for MS Windows",
            "md5": "0" * 32, "sha1": "1" * 40, "sha256": "2" * 64, "sha512": "3" * 128, "crc32": "DEADBEEF",
            "yara": [{"name": "UPX_Packed", "namespace": "packers", "meta": {}, "strings": ["$upx0"]}], "cape_yara": [],
            "pe": {"imagebase": "0x140000000", "entrypoint": "0x140012340", "machine_type": "IMAGE_FILE_MACHINE_AMD64",
                   "timestamp": "2026-08-30 22:14:01", "imphash": "f" * 32, "pdbpath": "C:\\build\\" + HOSTILE + ".pdb",
                   "sections": [{"name": "UPX0", "virtual_address": "0x00001000", "virtual_size": "0x00034000",
                                 "size_of_data": "0x00000000", "characteristics": "MEM_EXECUTE|MEM_READ|MEM_WRITE", "entropy": "0.00"},
                                {"name": "UPX1", "virtual_address": "0x00035000", "virtual_size": "0x00012000",
                                 "size_of_data": "0x00011e00", "characteristics": "MEM_EXECUTE|MEM_READ|MEM_WRITE", "entropy": "7.91"},
                                {"name": ".rsrc", "virtual_address": "0x00047000", "virtual_size": "0x00002000",
                                 "size_of_data": "0x00001a00", "characteristics": "MEM_READ", "entropy": "4.12"}],
                   "imports": {"KERNEL32": {"dll": "KERNEL32.dll", "imports": [
                       {"address": "0x140050000", "name": "LoadLibraryA"}, {"address": "0x140050008", "name": "GetProcAddress"},
                       {"address": "0x140050010", "name": "VirtualProtect"}]},
                               "ADVAPI32": {"dll": "ADVAPI32.dll", "imports": [{"address": "0x140050100", "name": "RegSetValueExW"}]}},
                   "exports": [], "versioninfo": [{"name": "CompanyName", "value": "Totally Legit " + HOSTILE},
                                                  {"name": "FileVersion", "value": "1.0.0.4"}],
                   "overlay": {"offset": "0x00045600", "size": "0x00000200"}}}},
        "trace_split": {"processes": len(everything), "sample_processes": len(SAMPLE),
                        "records": {"syscall": 2274487, "apimon": 5042, "regmon": 184268, "filetracer": 64480},
                        "merged": {"filetracer": 812}, "syscalls_paired": 2200000, "syscalls_unpaired": 1316,
                        "kernel_syscalls_dropped": 623, "nodes_added": 1, "bad_utf8": 2, "bad_json": 0,
                        "followed": [{"pid": 4100, "target_pid": 2300, "time": T0 + 6.0,
                                      "how": "memdump CreateRemoteThread heuristic"}],
                        "roots": [10], "sample": sorted(SAMPLE)},
        "behavior": {
            "processes": processes,
            "processtree": [_tree(10, everything), _tree(13, everything)],
            "summary": {
                "files": ["C:\\Users\\u\\AppData\\Roaming\\upd.exe", "C:\\Users\\u\\Desktop\\invoice.exe"],
                "read_files": ["C:\\Users\\u\\Desktop\\invoice.exe"] + [f"C:\\Windows\\System32\\file{i:03}.dll" for i in range(130)],
                "write_files": ["C:\\Users\\u\\AppData\\Roaming\\upd.exe", "C:\\Users\\u\\AppData\\Roaming\\" + HOSTILE],
                "delete_files": ["C:\\Users\\u\\Desktop\\invoice.exe"],
                "keys": [], "read_keys": ["HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid"],
                # not autostart first: the reader orders them
                "write_keys": ["HKEY_CURRENT_USER\\Software\\upd\\cfg",
                               "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd"],
                "delete_keys": [], "executed_commands": [SAMPLE[11][4], SAMPLE[12][4]],
                "resolved_apis": ["kernel32.dll.VirtualAllocEx", "ntdll.dll.NtUnmapViewOfSection"],
                "mutexes": ["Global\\upd-" + HOSTILE], "created_services": [], "started_services": [],
                # Each process's own (sandboxd's Summary.by_process): explorer
                # has nothing, the guest's svchost a file
                "by_process": {
                    "10": {"write_files": ["C:\\Users\\u\\AppData\\Roaming\\upd.exe",
                                           "C:\\Users\\u\\AppData\\Roaming\\" + HOSTILE],
                           "delete_files": ["C:\\Users\\u\\Desktop\\invoice.exe"],
                           "read_files": ["C:\\Users\\u\\Desktop\\invoice.exe"]
                           + [f"C:\\Windows\\System32\\file{i:03}.dll" for i in range(130)],
                           "read_keys": ["HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid"],
                           "write_keys": ["HKEY_CURRENT_USER\\Software\\upd\\cfg",
                                          "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd"],
                           "executed_commands": [SAMPLE[11][4]],
                           "resolved_apis": ["kernel32.dll.VirtualAllocEx", "ntdll.dll.NtUnmapViewOfSection"],
                           "mutexes": ["Global\\upd-" + HOSTILE]},
                    "11": {"executed_commands": [SAMPLE[12][4]]},
                    "12": {"write_keys": ["HKEY_CURRENT_USER\\Software\\upd\\cfg"]},
                    "20": {"write_files": ["C:\\Windows\\Prefetch\\GUEST-ONLY.pf"]},
                }},
            "enhanced": [
                {"event": "write", "object": "file", "timestamp": f"{T0 + 2.1:.6f}", "eid": 1,
                 "data": {"file": "C:\\Users\\u\\AppData\\Roaming\\upd.exe"}, "pid": 4100, "seqid": 10},
                {"event": "write", "object": "registry", "timestamp": f"{T0 + 2.4:.6f}", "eid": 2,
                 "data": {"regkey": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd",
                          "content": "C:\\Users\\u\\AppData\\Roaming\\upd.exe"}, "pid": 4100, "seqid": 10},
                {"event": "execute", "object": "file", "timestamp": f"{T0 + 3.25:.6f}", "eid": 3,
                 "data": {"file": SAMPLE[11][4]}, "pid": 4100, "seqid": 10},
                {"event": "load", "object": "library", "timestamp": 0, "eid": 4,
                 "data": {"file": HOSTILE + ".dll", "pathtofile": "C:\\Users\\u\\" + HOSTILE + ".dll",
                          "moduleaddress": "0x180000000"}, "pid": 4100, "seqid": 10},
                {"event": "move", "object": "file", "timestamp": f"{T0 + 5.0:.6f}", "eid": 5,
                 "data": {"from": "C:\\Users\\u\\Desktop\\invoice.exe", "to": "C:\\Users\\u\\AppData\\Local\\Temp\\x.tmp"},
                 "pid": 4100, "seqid": 10},
                # the guest's: not shown
                {"event": "write", "object": "file", "timestamp": f"{T0 + 1.0:.6f}", "eid": 6,
                 "data": {"file": "C:\\Windows\\Prefetch\\GUEST-ONLY.pf"}, "pid": guest_pid, "seqid": 20},
            ],
            "anomaly": [{"name": "invoice.exe", "pid": 4100, "category": "anti-vm", "funcname": "cpuid",
                         "message": "CPUID leaf 0x40000000: asks which hypervisor it runs under"},
                        {"name": "kernel", "pid": 4, "category": "rootkit", "funcname": "DriverCRC",
                         "message": "Modified (\\SystemRoot\\System32\\drivers\\evil.sys)"},
                        {"name": "svchost.exe", "pid": guest_pid, "category": "anti-debug", "funcname": "GUEST-ONLY",
                         "message": "the guest's"}],
            "encryptedbuffers": [
                {"process_name": "invoice.exe", "pid": 4100, "api_call": "CryptEncrypt", "direction": "encrypt",
                 "buffer": "beacon \x00\x01\x02\x03\xff id=" + HOSTILE, "buffer_size": 72, "crypt_key": "0x5550",
                 "algorithm": "AES_256", "key": "00112233445566778899aabbccddeeff"},
                {"process_name": "svchost.exe", "pid": guest_pid, "api_call": "SslEncryptPacket", "direction": "encrypt",
                 "buffer": "GUEST-ONLY", "buffer_size": 10}],
            "network_map": {
                "endpoint_map": [
                    {"ip_port": "203.0.113.7:443", "ip": "203.0.113.7", "port": 443,
                     "pinfo": [{"process_id": 4100, "process_name": "invoice.exe", "events": ["connect", "send"],
                                "sources": ["apimon", "socketmon"]}]},
                    {"ip_port": "192.0.2.99:80", "ip": "192.0.2.99", "port": 80,
                     "pinfo": [{"process_id": guest_pid, "process_name": "svchost.exe", "events": ["connect"],
                                "sources": ["socketmon"]}]}],
                "listeners": [{"ip_port": "0.0.0.0:4444", "ip": "0.0.0.0", "port": 4444,
                               "pinfo": [{"process_id": 4100, "process_name": "invoice.exe", "events": ["bind", "listen"],
                                          "sources": ["socketmon"]}]}],
                "unix_sockets": [],
                "http_host_map": [{"host": "c2.example", "pinfo": [{"process_id": 4100}]}],
                "dns_intents": [{"domain": "c2.example", "intents": [
                    {"process": {"process_id": 4100, "process_name": "invoice.exe"}, "api": "getaddrinfo",
                     "sources": ["apimon"], "answers": ["203.0.113.7"]}]},
                                {"domain": "guest-only.example", "intents": [
                    {"process": {"process_id": guest_pid, "process_name": "svchost.exe"}, "api": "DnsQuery_W",
                     "sources": ["apimon"], "answers": []}]}],
                "dns_answers": [{"domain": "c2.example", "answers": ["203.0.113.7"]}],
                "http_requests": [{"url": "https://c2.example/gate.php?id=" + HOSTILE, "host": "c2.example", "method": "POST",
                                   "user_agent": "Mozilla/5.0 " + HOSTILE, "process_id": 4100,
                                   "process_name": "invoice.exe", "api": "HttpSendRequestW", "source": "apimon"}],
                "user_agents": [{"user_agent": "Mozilla/5.0 " + HOSTILE, "pinfo": [{"process_id": 4100}]}],
                "filtered": {"multicast": 3}},
        },
        "network": {
            "hosts": [{"ip": "203.0.113.7", "hostname": "c2.example", "ports": [443]},
                      {"ip": "192.0.2.99", "hostname": "", "ports": [80]}],
            "tcp": [{"src": "10.0.0.5", "sport": 49152, "dst": "203.0.113.7", "dport": 443, "time": T0 + 4,
                     "process_id": 4100, "process_name": "invoice.exe", "source": "behavior"},
                    {"src": "10.0.0.5", "sport": 49170, "dst": "192.0.2.99", "dport": 80, "time": T0 + 5,
                     "process_id": None, "process_name": None, "source": "pcap"}],
            "udp": [], "dns": [], "http": []},
        "dropped": [
            {"name": ["upd.exe"], "path": "/srv/job/extracted/file.000001.mm", "size": 284672, "type": "PE32+ executable",
             "md5": "4" * 32, "sha1": "5" * 40, "sha256": "6" * 64, "sha512": "", "crc32": "CAFEBABE",
             "yara": [], "cape_yara": [], "guest_paths": ["C:\\Users\\u\\AppData\\Roaming\\upd.exe"], "pid": 4100,
             "process_name": "invoice.exe", "process_path": "", "reason": ""},
            {"name": ["GUEST-ONLY.pf"], "path": "/srv/job/extracted/file.000002.mm", "size": 10, "type": "data",
             "md5": "", "sha1": "", "sha256": "7" * 64, "guest_paths": ["C:\\Windows\\Prefetch\\GUEST-ONLY.pf"],
             "pid": guest_pid, "process_name": "svchost.exe"}],
        "procdump": [{"name": ["procdump.0"], "path": "/srv/job/procdumps/procdump.0", "size": 1048576, "type": "data",
                      "sha256": "8" * 64, "pid": 4100, "process_name": "invoice.exe", "target_pid": 4100,
                      "dump_size": "0x100000", "compression": "none", "status": "Success", "yara": [], "cape_yara": []}],
        "procmemory": [{"pid": 4100, "name": "invoice.exe", "proc_path": "", "yara": [], "cape_yara": [],
                        "address_space": [{"start": "0x7ff000", "end": "0x800000", "size": "0x1000",
                                           "path": "/srv/job/dumps/7ff000_aa", "sha256": "9" * 64, "type": "data",
                                           "method": "NtWriteVirtualMemory", "reason": "Remote process memory write",
                                           "target_pid": 2300}]},
                       {"pid": guest_pid, "name": "svchost.exe", "address_space": [
                           {"start": "0x1", "end": "0x2", "size": "0x1", "path": "/x/GUEST-ONLY", "sha256": "a" * 64}]}],
        "falco": {"alerts": [], "coverage": {}},
        "capa_summary": {"ATTCK": {"PERSISTENCE": ["Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder:: T1547.001"],
                                   "DEFENSE EVASION": ["Process Injection:: T1055"]},
                         "MBC": {"PROCESS": ["Create Process:: [C0017]"]},
                         "CAPABILITY": {"persistence/registry/run": ["persist via Run registry key"],
                                        "host-interaction/process/inject": ["inject thread (2 matches)"]}},
        "signatures": [
            {"name": "persistence_autorun", "description": "Installs itself for autorun at Windows startup",
             "categories": ["persistence"], "severity": 3, "confidence": 60, "weight": 1, "references": [],
             "families": [], "data": sig_data, "alert": False},
            {"name": "injection_createremotethread", "description": "Creates a thread in another process " + HOSTILE,
             "categories": ["injection"], "severity": 2, "confidence": 50, "weight": 1, "references": [],
             "families": ["Dropper"], "data": [{"type": "call", "pid": 4100, "cid": 2}], "alert": False},
            {"name": "guest_only_signature", "description": "matched the guest only", "categories": [],
             "severity": 1, "data": [{"type": "call", "pid": guest_pid, "cid": 0}]},
        ],
        "ttps": [{"signature": "persistence_autorun", "ttps": ["T1547.001"], "mbcs": []},
                 {"signature": "injection_createremotethread", "ttps": ["T1055"], "mbcs": []}],
        "malscore": 7.5, "malstatus": "Malicious",
    }
