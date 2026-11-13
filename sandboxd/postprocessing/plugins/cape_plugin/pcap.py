"""capture.pcap, read with the standard library, in the shapes of CAPE's
`network` processing module.

CAPE's own reader (modules/processing/network.py) is dpkt, dnspython and a
good part of CAPE; none of the three is in the venv. What signatures and the
report read from it is small -- who was talked to, what was asked of DNS and
answered, which HTTP requests were made, which TLS names were asked for --
and a classic pcap of Ethernet frames, which is what `argv_tcpdump` writes
(tcpdump -w on the clone's VLAN sub-interface: linktype 1, no 802.1Q tag),
needs only `struct` to give it up.

Nothing here resolves, looks up or connects to anything: CAPE's reader can
do reverse DNS and GeoIP, and a sandbox's Dom0 must not ask the internet
about a sample's peers.
"""
from __future__ import annotations

import hashlib
import ipaddress
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"}
_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ",
                 b"CONNECT ")
MAX_PACKETS = 2_000_000


def _dns_name(data: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
    """The name at `offset` (compression followed), and the offset after it."""
    labels, end = [], None
    while offset < len(data) and depth < 16:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if end is None:
                end = offset + 2
            offset, depth = pointer, depth + 1
            continue
        labels.append(data[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    return ".".join(labels), end if end is not None else offset


def _parse_dns(data: bytes) -> Optional[dict]:
    if len(data) < 12:
        return None
    ident, flags, qd, an = struct.unpack_from("!HHHH", data, 0)
    if qd == 0 or qd > 8:
        return None
    offset, questions = 12, []
    try:
        for _ in range(qd):
            name, offset = _dns_name(data, offset)
            qtype, _ = struct.unpack_from("!HH", data, offset)
            offset += 4
            questions.append((name, _DNS_TYPES.get(qtype, str(qtype))))
        answers = []
        for _ in range(an if flags & 0x8000 else 0):
            _, offset = _dns_name(data, offset)
            rtype, _, _, rdlen = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            rdata = data[offset:offset + rdlen]
            if rtype == 1 and rdlen == 4:
                value = str(ipaddress.IPv4Address(rdata))
            elif rtype == 28 and rdlen == 16:
                value = str(ipaddress.IPv6Address(rdata))
            elif rtype in (2, 5, 12):
                value, _ = _dns_name(data, offset)
            else:
                value = rdata.hex()
            answers.append({"type": _DNS_TYPES.get(rtype, str(rtype)), "data": value})
            offset += rdlen
    except (struct.error, IndexError):
        return None
    return {"id": ident, "response": bool(flags & 0x8000), "rcode": flags & 0xF,
            "questions": questions, "answers": answers}


def _tls_sni(payload: bytes) -> Optional[str]:
    """The server_name of a TLS ClientHello that starts this segment."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        pos = 5 + 4 + 2 + 32
        pos += 1 + payload[pos]                                   # session id
        pos += 2 + struct.unpack_from("!H", payload, pos)[0]      # cipher suites
        pos += 1 + payload[pos]                                   # compression
        end = pos + 2 + struct.unpack_from("!H", payload, pos)[0]
        pos += 2
        while pos + 4 <= min(end, len(payload)):
            ext, length = struct.unpack_from("!HH", payload, pos)
            pos += 4
            if ext == 0 and length >= 5:
                name_len = struct.unpack_from("!H", payload, pos + 3)[0]
                return payload[pos + 5:pos + 5 + name_len].decode("ascii", "replace")
            pos += length
    except (struct.error, IndexError):
        pass
    return None


def _parse_http(payload: bytes, dst: str, dport: int) -> Optional[dict]:
    if not payload.startswith(_HTTP_METHODS):
        return None
    head, _, body = payload.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    try:
        method, path, version = lines[0].decode("latin-1").split(" ", 2)
    except ValueError:
        return None
    headers = {}
    for line in lines[1:]:
        key, sep, value = line.decode("latin-1").partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    host = headers.get("host", dst)
    # `dst`: the server's address, which the Host header need not be -- and
    # what says whose request this was (modules.Network)
    return {"count": 1, "host": host, "dst": dst, "port": dport, "method": method, "path": path,
            "uri": f"http://{host}{path}" if path.startswith("/") else path,
            "version": version.replace("HTTP/", ""), "user-agent": headers.get("user-agent", ""),
            "data": head.decode("latin-1") + "\r\n\r\n", "body": body[:4096].decode("latin-1")}


def read_pcap(path: Path) -> dict:
    """CAPE's `network` keys from a pcap: {} when there is none or it is not
    a classic Ethernet pcap."""
    if not path.is_file() or path.stat().st_size < 24:
        return {}
    sha = hashlib.sha256()
    tcp: Dict[tuple, dict] = {}
    udp: Dict[tuple, dict] = {}
    icmp: List[dict] = []
    http: Dict[tuple, dict] = {}
    queries: Dict[tuple, dict] = {}
    by_id: Dict[tuple, dict] = {}
    hosts: Dict[str, set] = {}
    sni: Dict[str, str] = {}
    locals_: set = set()

    with path.open("rb") as f:
        header = f.read(24)
        sha.update(header)
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            return {}
        nanos = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        if struct.unpack_from(endian + "I", header, 20)[0] != 1:
            return {}
        first_ts = None
        for _ in range(MAX_PACKETS):
            rec = f.read(16)
            if len(rec) < 16:
                break
            sec, frac, caplen, _ = struct.unpack(endian + "IIII", rec)
            frame = f.read(caplen)
            sha.update(rec)
            sha.update(frame)
            if len(frame) < caplen:
                break
            ts = sec + frac / (1e9 if nanos else 1e6)
            if first_ts is None:
                first_ts = ts
            ethertype = struct.unpack_from("!H", frame, 12)[0] if len(frame) >= 14 else 0
            offset = 14
            if ethertype == 0x8100 and len(frame) >= 18:
                ethertype = struct.unpack_from("!H", frame, 16)[0]
                offset = 18
            try:
                if ethertype == 0x0800:
                    ihl = (frame[offset] & 0x0F) * 4
                    total = struct.unpack_from("!H", frame, offset + 2)[0]
                    proto = frame[offset + 9]
                    src = str(ipaddress.IPv4Address(frame[offset + 12:offset + 16]))
                    dst = str(ipaddress.IPv4Address(frame[offset + 16:offset + 20]))
                    l4 = frame[offset + ihl:offset + total]
                elif ethertype == 0x86DD:
                    proto = frame[offset + 6]
                    src = str(ipaddress.IPv6Address(frame[offset + 8:offset + 24]))
                    dst = str(ipaddress.IPv6Address(frame[offset + 24:offset + 40]))
                    l4 = frame[offset + 40:]
                else:
                    continue
                if proto == 6 and len(l4) >= 20:
                    sport, dport = struct.unpack_from("!HH", l4, 0)
                    flags = l4[13]
                    payload = l4[(l4[12] >> 4) * 4:]
                    if flags & 0x02 and not flags & 0x10:     # SYN: the connection
                        locals_.add(src)
                        tcp.setdefault((src, sport, dst, dport), {
                            "src": src, "sport": sport, "dst": dst, "dport": dport,
                            "offset": 0, "time": round(ts - first_ts, 6)})
                        hosts.setdefault(dst, set()).add(dport)
                    if payload:
                        request = _parse_http(payload, dst, dport)
                        if request:
                            known = http.get((request["host"], request["path"], request["method"]))
                            if known:
                                known["count"] += 1
                            else:
                                http[(request["host"], request["path"], request["method"])] = request
                        name = _tls_sni(payload)
                        if name:
                            sni[dst] = name
                elif proto == 17 and len(l4) >= 8:
                    sport, dport = struct.unpack_from("!HH", l4, 0)
                    payload = l4[8:]
                    udp.setdefault((src, sport, dst, dport), {
                        "src": src, "sport": sport, "dst": dst, "dport": dport,
                        "offset": 0, "time": round(ts - first_ts, 6)})
                    if 53 in (sport, dport) or 5355 in (sport, dport):
                        message = _parse_dns(payload)
                        if message is None:
                            continue
                        for name, qtype in message["questions"]:
                            key = (name.lower(), qtype)
                            if not message["response"]:
                                locals_.add(src)
                                entry = queries.setdefault(key, {
                                    "request": name, "type": qtype, "answers": [],
                                    "first_seen": ts})
                                by_id[(message["id"], name.lower())] = entry
                            else:
                                entry = by_id.get((message["id"], name.lower())) or \
                                    queries.setdefault(key, {"request": name, "type": qtype,
                                                             "answers": [], "first_seen": ts})
                                if message["rcode"] == 3 and not entry["answers"]:
                                    entry["answers"].append({"type": "NXDOMAIN", "data": ""})
                                for answer in message["answers"]:
                                    if answer not in entry["answers"]:
                                        entry["answers"].append(answer)
                elif proto in (1, 58) and len(l4) >= 4:
                    # ICMPv6's housekeeping is every IPv6 interface's, not a
                    # ping: multicast listener reports (130-132, 143) and
                    # neighbour discovery (133-137). A router solicitation to
                    # ff02::2 made network_icmp (severity 3) fire on every
                    # Linux job.
                    if proto == 58 and (130 <= l4[0] <= 137 or l4[0] == 143):
                        continue
                    icmp.append({"src": src, "dst": dst, "type": l4[0], "data": l4[4:68].hex()})
            except (struct.error, IndexError, ValueError):
                continue

    # The guest is whoever opened connections or asked DNS; a host is what it
    # sent to, broadcast and multicast aside. A capture in which it did
    # neither names no hosts rather than guessing which side was the guest.
    for flow in udp.values():
        try:
            address = ipaddress.ip_address(flow["dst"])
        except ValueError:
            continue
        if flow["src"] in locals_ and not (address.is_multicast or address.is_unspecified
                                           or flow["dst"] == "255.255.255.255"):
            hosts.setdefault(flow["dst"], set()).add(flow["dport"])

    names: Dict[str, str] = {}
    domains = []
    for entry in queries.values():
        ips = [a["data"] for a in entry["answers"] if a["type"] in ("A", "AAAA")]
        for ip in ips:
            names.setdefault(ip, entry["request"])
        if entry["type"] in ("A", "AAAA"):
            domains.append({"domain": entry["request"], "ip": ips[0] if ips else ""})
    for ip, name in sni.items():
        names.setdefault(ip, name)
    return {
        "pcap_sha256": sha.hexdigest(),
        "hosts": [{"ip": ip, "country_name": "", "hostname": names.get(ip, ""), "inaddrarpa": "",
                   "ports": sorted(ports)} for ip, ports in sorted(hosts.items())],
        "domains": domains,
        "tcp": list(tcp.values()), "udp": list(udp.values()), "icmp": icmp[:1000],
        "dns": list(queries.values()), "http": list(http.values()),
        "tls": [{"dst": ip, "sni": name} for ip, name in sorted(sni.items())],
        "smtp": [], "irc": [], "dead_hosts": [],
    }
