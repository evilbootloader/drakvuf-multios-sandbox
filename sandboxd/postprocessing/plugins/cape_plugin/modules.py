"""The rest of what the old postprocessing chain produced, as CAPE processing
modules: each a `Processing` with a `key`, run by `RunProcessing` after
`BehaviorAnalysis` and before the signatures, so signatures and extractors
find `results["dropped"]`, `["procdump"]`, `["network"]`... where CAPE's
own keep them, in CAPE's shapes.

| module     | key        | was                                              |
|------------|------------|--------------------------------------------------|
| Dropped    | dropped    | process_extracted + yara_analysis (extracted/)   |
| ProcDump   | procdump   | (new: procdump2's dumps) + yara                  |
| MemDumps   | procmemory | process_dumps + yara_analysis (dumps/)           |
| Network    | network    | get_socket_info, get_http_info's URLs            |
| Falco      | falco      | falco_analysis + get_falco_info (Linux)          |
| TlsKeys    | tlskeys    | generate_wireshark_key_file                      |

What they read of the trace beyond the calls is `aux/<plugin>.log`, the
records `trace_split` sets aside in its one pass (fileextractor, memdump,
tlsmon, socketmon...). Nothing here reads a per-plugin log of the job
directory: there is no split any more.

**Whose files.** CAPE's monitor only sees the sample's processes, so its
`dropped` is the sample's by construction. DRAKVUF extracts every file any
process closes; with `scope == "sample"` an entry is kept only when a sample
process produced it.
"""
from __future__ import annotations

import gzip
import hashlib
import ipaddress
import importlib
import json
import logging
import os
import posixpath
import tempfile
import time
import zlib
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path, PureWindowsPath
from typing import Dict, Iterator, List, Optional
from urllib.parse import urlparse

import orjson

from ....guests import TargetOs
from .abstracts import Processing
from .filetype import sniff
from .pcap import read_pcap

log = logging.getLogger(__name__)

try:
    import magic
except ImportError:  # pragma: no cover
    magic = None
try:
    import yara_x
except ImportError:  # pragma: no cover
    yara_x = None


# -- shared -------------------------------------------------------------------

def aux_records(aux_path, plugin: str) -> Iterator[dict]:
    path = Path(aux_path) / f"{plugin}.log" if aux_path else None
    if path is None or not path.exists():
        return
    with path.open("rb") as f:
        for line in f:
            try:
                rec = orjson.loads(line)
            except orjson.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                yield rec


@lru_cache(maxsize=2)
def _yara_rules(rules_dir: str):
    """Every .yar/.yara under `rules_dir`, compiled once per process (the
    old yara_analysis's compilation, sources added one by one so `origin`
    names the file in an error)."""
    root = Path(rules_dir)
    compiler = yara_x.Compiler()
    compiler.add_include_dir(str(root))
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() in (".yar", ".yara"):
            compiler.add_source(path.read_text(encoding="utf-8"), origin=str(path))
    return compiler.build()


class FileInfo:
    """CAPE's `File.get_all()` (lib/cuckoo/common/objects.py) for one file:
    the hashes, the type, the YARA hits in CAPE's `{name, meta, strings,
    addresses}` form. No ssdeep/tlsh: neither library is in the venv.

    Two rule sets, as in CAPE: `yara` is the general one (sandboxd's
    `yara.rules_directory`), `cape_yara` CAPE's own family rules -- the
    community checkout's data/yara/CAPE, 487 files that all compile under
    yara-x (2026-11-12) -- which is what CAPE names a family from."""

    def __init__(self, yara_rules_dir: Optional[str], cape_rules_dir: Optional[str] = None):
        self.scanner = self._scanner(yara_rules_dir)
        self.cape_scanner = self._scanner(cape_rules_dir)

    @staticmethod
    def _scanner(rules_dir: Optional[str]):
        if yara_x is None or not rules_dir or not Path(rules_dir).is_dir():
            return None
        try:
            scanner = yara_x.Scanner(_yara_rules(str(rules_dir)))
            scanner.set_timeout(60)
            return scanner
        except Exception as e:  # noqa: BLE001 - a bad rule must not cost the file list
            log.error("YARA rules at %s did not compile: %s", rules_dir, e)
            return None

    def yara(self, path: Path) -> List[dict]:
        return self._hits(self.scanner, path)

    def cape_yara(self, path: Path) -> List[dict]:
        """The hits of CAPE's rules that name a payload (`cape_type` in the
        rule's meta, which is how CAPE itself reads a family out of one).
        The checkout also holds indicator rules without it -- deprecated/'s
        embedded_pe, embedded_win_api and shellcode_get_eip matched the dump
        of PING.EXE (2026-11-12) -- and `procmem_yara` (severity 3) fires on
        any hit listed."""
        return [hit for hit in self._hits(self.cape_scanner, path) if hit["meta"].get("cape_type")]

    @staticmethod
    def _hits(scanner, path: Path) -> List[dict]:
        if scanner is None:
            return []
        try:
            scan = scanner.scan_file(str(path))
        except Exception as e:  # noqa: BLE001 - ScanError, TimeoutError, OSError
            log.warning("YARA scan of %s failed: %s", path.name, e)
            return []
        hits = []
        for rule in scan.matching_rules:
            strings, addresses = [], {}
            for pattern in rule.patterns:
                for match in pattern.matches:
                    strings.append(pattern.identifier)
                    addresses.setdefault(pattern.identifier, match.offset)
            hits.append({"name": rule.identifier, "meta": dict(rule.metadata),
                         "strings": sorted(set(strings)), "addresses": addresses,
                         "namespace": rule.namespace})
        return hits

    def describe(self, path: Path) -> dict:
        digests = {n: hashlib.new(n) for n in ("md5", "sha1", "sha256", "sha512", "sha3_384")}
        crc, size = 0, 0
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                size += len(chunk)
                crc = zlib.crc32(chunk, crc)
                for d in digests.values():
                    d.update(chunk)
        file_type = ""
        if magic is not None:
            try:
                file_type = magic.from_file(str(path))
            except Exception:  # noqa: BLE001
                file_type = ""
        # No libmagic (Dom0), or none that answered: the file's own bytes
        file_type = file_type or sniff(path)
        return {
            "name": path.name, "path": str(path), "guest_paths": "", "size": size,
            "crc32": f"{crc & 0xFFFFFFFF:08X}",
            **{n: d.hexdigest() for n, d in digests.items()},
            "type": file_type, "yara": self.yara(path), "cape_yara": self.cape_yara(path),
        }


class _Module(Processing):
    """Base of the modules here: the options every one of them reads."""

    def _in_scope(self, pid) -> bool:
        pids = getattr(self.options, "sample_pids", None)
        return getattr(self.options, "scope", "sample") == "all" or pids is None or pid in pids

    def _sample_only(self, pid) -> bool:
        """The sample's, whatever `scope` says: what the dumps and the
        dropped files list. Every process's are in the aux logs, the guest's
        services' included, and the report -- and the page that renders it
        -- is the malware's, not the guest's (operator, 2026-11-11)."""
        pids = getattr(self.options, "sample_pids", None)
        return pids is None or pid in pids

    def _files(self) -> FileInfo:
        return FileInfo(getattr(self.options, "yara_rules", None),
                        getattr(self.options, "cape_yara_rules", None))

    def _process_name(self, path: str) -> str:
        if self.platform == TargetOs.WINDOWS:
            return PureWindowsPath(path or "").name
        return posixpath.basename(path or "")


# -- dropped ------------------------------------------------------------------

class Dropped(_Module):
    """Files fileextractor wrote to `extracted/`, as CAPE's `dropped`.

    The directory is the ground truth (process_extracted's rule): Windows
    files are `file.NNNNNN.mm` with a `.metadata` sidecar naming the guest
    path and the process; Linux files are named in the fileextractor record's
    `DumpFile`. One entry per content (sha256), its guest paths and PIDs
    merged, as CAPE merges a file dropped twice."""

    key = "dropped"
    order = 2

    def _sources(self, directory: Path) -> Iterator[dict]:
        if self.platform == TargetOs.WINDOWS:
            for sidecar in sorted(directory.glob("file.*.metadata")):
                try:
                    meta = json.loads(sidecar.read_text(errors="replace"))
                except ValueError:
                    continue
                data = sidecar.with_suffix(".mm")
                if data.exists():
                    yield {"file": data, "guest_path": meta.get("FileName") or "",
                           "pid": meta.get("PID"), "process_path": meta.get("ProcessName") or "",
                           "reason": ""}
            return
        seen = set()
        for rec in aux_records(self.aux_path, "fileextractor"):
            dump = rec.get("DumpFile")
            if not isinstance(dump, str):
                continue
            data = directory / posixpath.basename(dump)
            if data in seen or not data.exists():
                continue
            seen.add(data)
            yield {"file": data, "guest_path": rec.get("FileName") or "", "pid": rec.get("PID"),
                   "process_path": rec.get("ProcessName") or "", "reason": rec.get("Reason") or ""}

    def run(self):
        directory = Path(self.dropped_path)
        if not directory.is_dir():
            return []
        info = self._files()
        by_hash: Dict[str, dict] = {}
        for src in self._sources(directory):
            if not self._sample_only(src["pid"]):
                continue
            entry = info.describe(src["file"])
            known = by_hash.get(entry["sha256"])
            if known is None:
                guest = src["guest_path"]
                entry.update({
                    "name": [self._process_name(guest) or entry["name"]],
                    "guest_paths": [guest] if guest else [],
                    "pid": src["pid"],
                    "process_path": src["process_path"],
                    "process_name": self._process_name(src["process_path"]),
                    "reason": src["reason"],
                })
                by_hash[entry["sha256"]] = entry
                continue
            if src["guest_path"] and src["guest_path"] not in known["guest_paths"]:
                known["guest_paths"].append(src["guest_path"])
                name = self._process_name(src["guest_path"])
                if name and name not in known["name"]:
                    known["name"].append(name)
            pids = str(known["pid"]).split(",")
            if str(src["pid"]) not in pids:
                known["pid"] = ",".join(pids + [str(src["pid"])])
        return list(by_hash.values())


# -- procdump -----------------------------------------------------------------

class ProcDump(_Module):
    """procdump2's process dumps (`procdumps/`, one data file and a
    `.metadata` sidecar each), as CAPE's `procdump`. A compressed dump
    (`--compress-procdumps`, which sandboxd always passes: gzip, by the
    sidecar's `Compression` and the file's own 1f 8b) is hashed and listed
    as it is on disk, and scanned as what it holds: inflated in a stream
    into a temporary file that is removed again -- a 5 MB dump of a Windows
    process is 50 MB inflated, and the postprocessing child has a memory
    limit -- and YARA reads that file. Until 2026-11-12 it was not scanned
    at all, and the Mirai bot's own dump had no hit."""

    key = "procdump"
    order = 2
    # Inflated bytes scanned of one dump; what is past it is not scanned,
    # and the entry says so (`scan_truncated`). procdump2 writes a process's
    # committed memory, tens of MB; this is the bound on a file that is not
    # what its sidecar says.
    MAX_SCAN_BYTES = 1 << 30

    def _scan_compressed(self, info: FileInfo, data: Path) -> dict:
        """`yara`, `cape_yara` and the size scanned of a gzip dump's content."""
        out = {"yara": [], "cape_yara": []}
        if info.scanner is None and info.cape_scanner is None:
            return out
        try:
            with tempfile.NamedTemporaryFile(prefix="procdump-", suffix=".bin") as plain:
                size = 0
                with gzip.open(data, "rb") as packed:
                    while size < self.MAX_SCAN_BYTES:
                        chunk = packed.read(min(1 << 20, self.MAX_SCAN_BYTES - size))
                        if not chunk:
                            break
                        plain.write(chunk)
                        size += len(chunk)
                    else:
                        out["scan_truncated"] = bool(packed.read(1))
                plain.flush()
                out.update({"yara": info.yara(Path(plain.name)), "cape_yara": info.cape_yara(Path(plain.name)),
                            "scanned_size": size})
        except (OSError, EOFError, zlib.error) as e:
            # Not gzip after all, or cut short: listed, not scanned
            log.warning("process dump %s could not be inflated for YARA: %s", data.name, e)
            out["scan_error"] = f"{type(e).__name__}: {e}"
        return out

    def run(self):
        directory = Path(self.procdump_path)
        if not directory.is_dir():
            return []
        info = self._files()
        out = []
        for sidecar in sorted(directory.glob("*.metadata")):
            try:
                meta = json.loads(sidecar.read_text(errors="replace"))
            except ValueError:
                continue
            # The name alone, as Dropped and MemDumps take theirs: procdump2
            # writes "procdump.N", and a sidecar saying anything else must
            # not name a file outside this directory.
            data = directory / posixpath.basename(str(meta.get("DataFileName") or sidecar.stem))
            if not data.exists() or not self._sample_only(meta.get("PID")):
                continue
            compressed = str(meta.get("Compression") or "none").lower() not in ("none", "")
            entry = info.describe(data) if not compressed else {
                **FileInfo(None).describe(data), **self._scan_compressed(info, data)}
            entry.update({
                "name": [data.name],
                "pid": meta.get("PID"),
                "process_path": meta.get("ProcessName") or "",
                "process_name": self._process_name(meta.get("ProcessName") or ""),
                "module_path": meta.get("ProcessName") or "",
                "target_pid": meta.get("TargetPID"),
                "target_process": meta.get("TargetName") or "",
                "dump_size": meta.get("DumpSize"),
                "compression": meta.get("Compression"),
                "status": meta.get("Status"),
            })
            out.append(entry)
        return out


class MemDumps(_Module):
    """memdump's region dumps (`dumps/`), as CAPE's `procmemory`: one entry
    per process, its dumped regions as `address_space`, YARA hits collected
    over them. From process_dumps: a dump is listed when its file exists and
    its process is not System; no size cap, because nothing is zipped here."""

    key = "procmemory"
    order = 2

    def run(self):
        directory = Path(self.pmemory_path)
        if not directory.is_dir():
            return []
        info = self._files()
        by_pid: Dict[int, dict] = {}
        seen = set()
        for rec in aux_records(self.aux_path, "memdump"):
            name, pid = rec.get("DumpFilename"), rec.get("DumpPID", rec.get("PID"))
            if not isinstance(name, str) or pid in (None, 4) or not self._sample_only(rec.get("PID")):
                continue
            data = directory / posixpath.basename(name)
            if data in seen or not data.exists():
                continue
            seen.add(data)
            described = info.describe(data)
            proc = by_pid.setdefault(pid, {
                "pid": pid, "name": self._process_name(rec.get("ProcessName") or ""),
                "proc_path": rec.get("ProcessName") or "", "yara": [], "cape_yara": [],
                "address_space": [],
            })
            for kind in ("yara", "cape_yara"):
                for hit in described[kind]:
                    if hit["name"] not in {h["name"] for h in proc[kind]}:
                        proc[kind].append(hit)
            start = int(str(rec.get("DumpAddr") or "0"), 16)
            size = int(str(rec.get("DumpSize") or "0"), 16)
            proc["address_space"].append({
                "start": hex(start), "end": hex(start + size), "size": hex(size),
                "path": str(data), "sha256": described["sha256"], "type": described["type"],
                "method": rec.get("Method"), "reason": rec.get("DumpReason"),
                "target_pid": rec.get("TargetPID"),
            })
        return list(by_pid.values())


# -- network ------------------------------------------------------------------

class Network(_Module):
    """What the guest's own instrumentation saw of the network, in the keys
    of CAPE's `network`: `tcp`/`udp` connections, `hosts`, `domains`, `dns`,
    `http`. CAPE fills these from the pcap (dpkt, not installed here); this
    fills them from socketmon / unixsocketmon and from the behaviour's
    `network_map`, and so also knows the process, which a pcap does not.
    Every entry carries `source: "behavior"`, CAPE's own mark for that."""

    key = "network"
    order = 3      # after BehaviorAnalysis: it reads results["behavior"]

    @staticmethod
    def _owner(rec) -> Optional[int]:
        """The process a socket record is of: socketmon's `OwnerPID` where it
        has one -- a kernel-side send runs in whatever process was current
        (NetBIOS from System, printed with a console host's PID) -- else the
        record's own."""
        owner = rec.get("OwnerPID")
        return owner if isinstance(owner, int) and not isinstance(owner, bool) else rec.get("PID")

    def run(self):
        tcp, udp, seen = [], [], set()
        hosts: Dict[str, set] = defaultdict(set)
        # Addresses and names only the guest's other processes used: what
        # the wire has of them is not the sample's (_drop_background)
        others, other_names, own = set(), set(), set()
        for plugin in ("socketmon", "unixsocketmon"):
            for rec in aux_records(self.aux_path, plugin):
                ip, proto = rec.get("RemoteIp"), str(rec.get("Protocol") or "")
                owner = self._owner(rec)
                # The guest's own addresses are every flow's other end
                own.add(rec.get("LocalIp"))
                if rec.get("DnsName") and not self._in_scope(owner):
                    other_names.add(str(rec["DnsName"]).lower().rstrip("."))
                # socketmon prints "(null)" where it resolved no peer
                if not ip or ip == "(null)":
                    continue
                if str(rec.get("Type") or "AF_INET").startswith("AF_LOCAL"):
                    continue
                if not self._in_scope(owner):
                    others.add(ip)
                    continue
                entry = {
                    "src": rec.get("LocalIp") or "", "sport": rec.get("LocalPort") or 0,
                    "dst": ip, "dport": rec.get("RemotePort") or 0,
                    "time": float(rec.get("TimeStamp") or 0),
                    "process_id": owner,
                    "process_name": self._process_name(rec.get("ProcessName") or "") if owner == rec.get("PID") else "",
                    "source": "behavior",
                }
                key = (proto[:3].upper(), entry["src"], entry["sport"], ip, entry["dport"], entry["process_id"])
                if key in seen:
                    continue
                seen.add(key)
                (udp if proto.upper().startswith("UDP") else tcp).append(entry)
                hosts[ip].add(entry["dport"])

        nmap = (self.results.get("behavior") or {}).get("network_map") or {}
        dns, domains = [], []
        asked = set()
        # What the resolver answered, as the process saw it (getaddrinfo's
        # and DnsQuery's results, NetworkMap's dns_answers)
        answered = {item["domain"].lower(): item.get("answers") or [] for item in nmap.get("dns_answers", [])}

        def add_dns(name, ts, pid, process_name):
            # A name, not an address handed to a resolver API (`ping 127.0.0.1`).
            try:
                ipaddress.ip_address(name)
                return
            except ValueError:
                pass
            if not name or name.lower() in asked:
                return
            asked.add(name.lower())
            addresses = answered.get(name.lower(), [])
            answers = [{"type": "AAAA" if ":" in a else "A", "data": a} for a in addresses]
            dns.append({"request": name, "type": "A", "answers": answers, "first_seen": ts,
                        "process_id": pid, "process_name": process_name, "source": "behavior"})
            domains.append({"domain": name, "ip": addresses[0] if addresses else ""})

        # socketmon's DnsQuery_* records (Windows): the name asked of the
        # resolver, by the process that asked.
        for rec in aux_records(self.aux_path, "socketmon"):
            if rec.get("DnsName") and self._in_scope(self._owner(rec)):
                add_dns(str(rec["DnsName"]), float(rec.get("TimeStamp") or 0), rec.get("PID"),
                        self._process_name(rec.get("ProcessName") or ""))
        # Resolver API calls (getaddrinfo, gethostbyname, DnsQuery_A...).
        for item in nmap.get("dns_intents", []):
            first = (item.get("intents") or [{}])[0]
            add_dns(item["domain"], first.get("ts_epoch"),
                    (first.get("process") or {}).get("process_id"),
                    (first.get("process") or {}).get("process_name"))
        http = [{"uri": r.get("url"), "host": r.get("host") or "", "method": r.get("method") or "",
                 "port": 0, "path": "", "data": "", "body": "", "user-agent": r.get("user_agent") or "",
                 "version": "", "count": 1,
                 "process_id": r.get("process_id"), "process_name": r.get("process_name"),
                 "source": "behavior"}
                for r in nmap.get("http_requests", [])]
        # Endpoints an API call named that the kernel's plugins did not
        # report -- a connect that failed or was blocked, a sendto:
        # NetworkMap has them from apimon, libmon and the syscall plugin
        for item in nmap.get("endpoint_map", []):
            if item.get("ip") and any(self._in_scope(p.get("process_id")) for p in item.get("pinfo", [])):
                hosts[item["ip"]].add(item.get("port") or 0)
        for request in http:
            parsed = urlparse(request["uri"] or "")
            request["path"] = parsed.path or "/"
            request["port"] = parsed.port or (443 if parsed.scheme == "https" else 80)

        # The wire: every packet the clone's interface carried, whoever sent
        # it. Its entries come first; what the guest's instrumentation saw is
        # added where the wire does not already have it, and keeps its
        # process -- which a pcap cannot know.
        net = read_pcap(Path(self.pcap_path))
        if not net:
            net = {"hosts": [], "domains": [], "tcp": [], "udp": [], "icmp": [], "dns": [],
                   "http": [], "tls": [], "smtp": [], "irc": [], "dead_hosts": []}
        self._drop_background(net, others - set(hosts) - own, other_names - asked)
        wire_dns = {d["request"].lower(): d for d in net["dns"]}
        for entry in dns:
            seen = wire_dns.get(entry["request"].lower())
            if seen is None:
                net["dns"].append(entry)
            else:
                seen.setdefault("process_id", entry["process_id"])
                seen.setdefault("process_name", entry["process_name"])
        known = {d["domain"].lower() for d in net["domains"]}
        net["domains"] += [d for d in domains if d["domain"].lower() not in known]
        wire_hosts = {h["ip"]: h for h in net["hosts"]}
        # A host's name: the one the guest's resolver gave for its address
        names = {a: domain for domain, addresses in answered.items() for a in addresses}
        for ip, ports in sorted(hosts.items()):
            if ip in wire_hosts:
                wire_hosts[ip]["ports"] = sorted(set(wire_hosts[ip]["ports"]) | {p for p in ports if p})
                if not wire_hosts[ip].get("hostname"):
                    wire_hosts[ip]["hostname"] = names.get(ip, "")
            else:
                net["hosts"].append({"ip": ip, "country_name": "", "hostname": names.get(ip, ""),
                                     "inaddrarpa": "", "ports": sorted(p for p in ports if p)})
        # A connection the wire has too is one connection: it gets the
        # process, which the pcap cannot know, and is not listed twice.
        for kind, mine in (("tcp", tcp), ("udp", udp)):
            wire = defaultdict(list)
            for flow in net[kind]:
                wire[(flow.get("dst"), flow.get("dport"))].append(flow)
            for entry in mine:
                same = wire.get((entry["dst"], entry["dport"]))
                if not same:
                    net[kind].append(entry)
                    continue
                for flow in same:
                    flow.setdefault("process_id", entry["process_id"])
                    flow.setdefault("process_name", entry["process_name"])
        wire_uris = {r["uri"] for r in net["http"]}
        net["http"] += [r for r in http if r["uri"] not in wire_uris]
        return net


    def _drop_background(self, net: dict, addresses: set, names: set) -> None:
        """Take out of the wire's entries the ones the guest's other
        processes made: the pcap is the clone's whole interface, and a
        browser's, an updater's and the resolver's own traffic were listed
        as the sample's (three Windows jobs of 2026-11-12 had 18 hosts and
        11 HTTP requests each, none a sample process's). `addresses` are
        peers a socket plugin saw only processes outside the sample talk
        to, `names` ones only they asked the resolver for. What no plugin
        attributed to anyone stays: a flow the instrumentation missed is
        still on the wire. How many went is `background`."""
        if getattr(self.options, "scope", "sample") != "sample" or not (addresses or names):
            return
        dropped = Counter()

        def keep(kind, entries, background):
            kept = [e for e in entries if not background(e)]
            if len(kept) != len(entries):
                dropped[kind] = len(entries) - len(kept)
            net[kind] = kept

        def name_of(value):
            return str(value or "").lower().rstrip(".")

        def resolved_elsewhere(entry):
            answers = [a.get("data") for a in entry.get("answers") or () if a.get("type") in ("A", "AAAA")]
            return name_of(entry.get("request")) in names or (answers and all(a in addresses for a in answers))

        keep("hosts", net.get("hosts", []), lambda e: e.get("ip") in addresses)
        for kind in ("tcp", "udp"):
            keep(kind, net.get(kind, []), lambda e: e.get("dst") in addresses or e.get("src") in addresses)
        keep("http", net.get("http", []), lambda e: e.get("dst") in addresses)
        keep("tls", net.get("tls", []), lambda e: e.get("dst") in addresses)
        keep("dns", net.get("dns", []), resolved_elsewhere)
        keep("domains", net.get("domains", []),
             lambda e: name_of(e.get("domain")) in names or e.get("ip") in addresses)
        if dropped:
            net["background"] = dict(dropped)


# -- tls keys -------------------------------------------------------------------

class TlsKeys(_Module):
    """tlsmon's session keys as `wireshark_key_file.txt`, beside the pcap.

    **The whole guest's**, where the rest of the report is the sample's:
    tlsmon hooks lsass.exe, which derives every process's Schannel keys, so
    a record's PID is lsass's (828 in three jobs of 2026-11-12) and it has
    no field naming the client -- `client_random` and `master_key` are all
    it carries. `keys` therefore counts every TLS session of the guest. The
    key file is for decrypting the capture, which is the whole guest's too."""

    key = "tlskeys"
    order = 2

    def run(self):
        lines = []
        for rec in aux_records(self.aux_path, "tlsmon"):
            if rec.get("client_random") and rec.get("master_key"):
                lines.append(f"CLIENT_RANDOM {rec['client_random']} {rec['master_key']}\n")
        if lines:
            Path(self.analysis_path, "wireshark_key_file.txt").write_text("".join(lines))
        return {"keys": len(lines)}


# -- falco ----------------------------------------------------------------------

class Falco(_Module):
    """Falco's rules over the Linux trace: falco_analysis and get_falco_info
    in one, with the engine reading trace.log itself (`_TraceLog`) instead
    of the per-plugin logs. Returns `{alerts, coverage}`; the alerts are
    aggregated per (rule, process) as the report had them."""

    key = "falco"
    order = 2

    def run(self):
        # Imported here: the falco package is Linux-only work and pulls in
        # the rule compiler; a Windows job should not pay for it.
        # The module: `plugins/__init__` binds the plugin function to its name.
        fa = importlib.import_module("..falco_analysis", __package__)
        from ...falco import events as falco_events
        from ...falco.engine import Engine
        from ...falco.fields import FieldTable
        from ...falco.rules import RuleSet

        config = getattr(self.options, "falco", None)
        profile = fa.FALCO_PROFILES.get(self.platform)
        if config is None or not config.enabled or profile is None:
            return {}
        started = time.monotonic()
        ruleset = RuleSet()
        for path in config.rules_files:
            ruleset.load_file(path)
        if config.local_rules_directory.is_dir():
            for path in sorted(config.local_rules_directory.glob("*.yaml")):
                ruleset.load_file(path)
        fa._lab_network_overrides(ruleset, getattr(self.options, "vlan", None))
        tables = {src: FieldTable(src, profile.users, config.procmon_env_filter)
                  for src in profile.sources}
        ruleset.compile(tables)
        engine = Engine(ruleset, tables, config.max_alerts)

        scope = None
        if getattr(self.options, "scope", "sample") == "sample":
            scope = set(getattr(self.options, "sample_pids", None) or ())

        class _TraceLog(falco_events.Trace):
            """falco's Trace over one trace.log: the same records in the same
            order as its merge of per-plugin logs -- each kept by that log's
            own filter, ordered by (EventUID, kind) through the same window."""

            def __init__(trace, analysis_dir, present, *args, **kwargs):
                super().__init__(analysis_dir, *args, **kwargs)
                trace.sysret = trace.stats.sysret = "sysret" in present
                trace.stats.procmon = "procmon" in present
                trace.stats.libmon = "libmon" in present
                trace.socket_endpoints = "unixsocketmon" in present

            def _records(trace):
                keep = {kind: (rank, fn, fixed) for rank, (kind, _, fn, fixed)
                        in enumerate(trace._sources())}

                def stream():
                    with (trace.dir / "trace.log").open("rb") as f:
                        for line in f:
                            try:
                                rec = orjson.loads(line)
                            except orjson.JSONDecodeError:
                                continue
                            if not isinstance(rec, dict):
                                continue
                            entry = keep.get(rec.get("Plugin"))
                            if entry is None or not entry[1](rec):
                                continue
                            rank, _, fixed = entry
                            uid = fixed if fixed is not None else falco_events._event_uid(rec)
                            yield (uid, rank, rec["Plugin"], rec)

                return falco_events._windowed(stream(), trace.config.reorder_window)

        present = set(getattr(self.options, "trace_plugins", None) or ())
        trace = _TraceLog(
            Path(self.analysis_path), present,
            falco_events.TraceConfig(env_filter=frozenset(config.procmon_env_filter),
                                     users=profile.users),
            syscall_types=engine.event_types("syscall"),
            libmon_types=engine.event_types("libmon") if "libmon" in tables else set(),
            scope=scope,
        )
        result = engine.run(trace)

        grouped: Dict[tuple, dict] = {}
        for alert in result.alerts:
            key = (alert.get("rule"), alert.get("pid"))
            entry = grouped.get(key)
            if entry is None:
                grouped[key] = {**alert, "count": 1, "first_seen": alert.get("time")}
            else:
                entry["count"] += 1
        return {
            "alerts": list(grouped.values()),
            "coverage": {
                "scope_pids": sorted(scope) if scope is not None else None,
                "seconds": round(time.monotonic() - started, 3),
                "records": trace.stats.records, "events": trace.stats.events,
                "alerts_written": len(result.alerts), "alerts_dropped": result.dropped_alerts,
                "rules_matched": {name: o.matched for name, o in result.outcomes.items() if o.matched},
                # What each rule came to (falco_analysis's falco-rules.json):
                # a rule that could not be evaluated is not one that found
                # nothing. `ok` rules that neither matched nor were left
                # undetermined are only counted.
                "rules_by_status": dict(Counter(rule.status for rule in ruleset.rules.values())),
                "rules": [
                    {"rule": rule.name, "status": rule.status, "reason": rule.reason,
                     "matched": outcome.matched if outcome else 0,
                     "undetermined": outcome.undetermined if outcome else 0,
                     "missing": dict(outcome.missing.most_common(8)) if outcome else {}}
                    for rule, outcome in ((rule, result.outcomes.get(rule.name))
                                          for rule in ruleset.rules.values())
                    if rule.status != "ok" or (outcome and (outcome.matched or outcome.undetermined))],
                "warnings": ruleset.warnings,
            },
        }


MODULES = (Dropped, ProcDump, MemDumps, Network, TlsKeys, Falco)