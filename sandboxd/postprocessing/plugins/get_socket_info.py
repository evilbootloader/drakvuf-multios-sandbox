"""Connections and DNS the guest made, per guest OS.

Windows reads `socketmon.log`: TCP connections, UDP sends and DnsQueryEx
calls, as it always has. Linux reads `unixsocketmon.log`, from our DRAKVUF
fork's unixsocketmon, which records every send (`sock_sendmsg`) and connect
with the socket's family, protocol and both ends -- an IP address and port,
or a Unix socket's path. The two live in SOCKET_SOURCES, not in a branch.

Linux IP connections are reported for every process, as socketmon's are on
Windows. Unix sockets only for the sample's processes: an idle Ubuntu desktop
sends thousands of D-Bus messages a minute, and none of them are the sample's.
"""
from collections import defaultdict
from typing import Callable, Dict, Optional, Tuple

from ...guests import TargetOs
from ..falco.events import sample_scope
from .parse_utils import parse_log
from .plugin_base import PostprocessContext


def _seqids(process) -> list:
    # A record from a process the tree never saw is still a connection
    return [process.seqid] if process is not None else []


# --- Windows: socketmon ------------------------------------------------------

def _windows(context: PostprocessContext) -> dict:
    process_tree = context.process_tree

    def filter_socketmon(data: dict) -> Optional[dict]:
        event_uid = int(data["EventUID"], 16)
        pid = data["PID"]
        process = process_tree.get_process_for_evtid(pid, event_uid)

        if data.get("Method") in [
            "UdpSendMessages",
            "TcpCreateAndConnectTcbComplete",
            "TcpCreateAndConnectTcbRateLimitComplete",
        ]:
            return {
                "process": process,
                "method": "connection",
                "Protocol": data["Protocol"],
                "LocalIp": data["LocalIp"],
                "LocalPort": data["LocalPort"],
                "RemoteIp": data["RemoteIp"],
                "RemotePort": data["RemotePort"],
            }
        elif data.get("Method") == "DnsQueryEx":
            return {
                "process": process,
                "method": "dns-query",
                "DnsName": data["DnsName"],
            }
        else:
            return None

    socketmon_log = parse_log(context.analysis_dir / "socketmon.log", filter_socketmon)
    connections = defaultdict(set)
    dns_queries = defaultdict(set)

    for data in socketmon_log:
        if data["method"] == "connection":
            key = (
                data["Protocol"],
                data["LocalIp"],
                data["LocalPort"],
                data["RemoteIp"],
                data["RemotePort"],
            )
            connections[key].update(_seqids(data["process"]))
        elif data["method"] == "dns-query":
            dns_queries[data["DnsName"]].update(_seqids(data["process"]))

    return {
        "connections": [
            {
                "protocol": protocol,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "process_seqids": list(processes),
            }
            for (
                protocol,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
            ), processes in connections.items()
        ],
        "dns_queries": [
            {"domain": domain, "process_seqids": list(processes)}
            for domain, processes in dns_queries.items()
        ],
    }


# --- Linux: unixsocketmon ----------------------------------------------------

def _linux(context: PostprocessContext) -> dict:
    process_tree = context.process_tree
    scope = sample_scope(context.analysis_dir)
    # (protocol, remote ip, remote port, seqid) -> the local ends seen
    ip: Dict[Tuple, set] = defaultdict(set)
    unix: Dict[Tuple[str, str], dict] = {}

    def keep(data: dict) -> Optional[dict]:
        return data if data.get("Type") in ("AF_INET", "AF_INET6", "AF_LOCAL") else None

    for data in parse_log(context.analysis_dir / "unixsocketmon.log", keep):
        process = process_tree.get_process_for_evtid(data["PID"], int(data["EventUID"], 16))
        seqid = process.seqid if process is not None else None
        if data["Type"] != "AF_LOCAL":
            if not data.get("RemoteIp"):
                continue
            key = (str(data.get("Protocol", "")).lower(), data["RemoteIp"], data.get("RemotePort"), seqid)
            # A connect is recorded before the socket is bound, with no local end yet
            ip[key].add((data.get("LocalIp"), data.get("LocalPort")) if data.get("LocalPort") else None)
        elif data["PID"] in scope:
            key = (data.get("LocalPath", ""), data.get("RemotePath", ""))
            entry = unix.setdefault(key, {"path": key[0], "peer_path": key[1], "messages": 0,
                                          "bytes": 0, "process_seqids": set()})
            if data.get("Method") != "connect":
                entry["messages"] += 1
                entry["bytes"] += int(data.get("Size") or 0)
            if seqid is not None:
                entry["process_seqids"].add(seqid)

    connections: Dict[Tuple, set] = defaultdict(set)
    for (protocol, rip, rport, seqid), local_ends in ip.items():
        bound = [end for end in local_ends if end is not None] or [("", None)]
        for lip, lport in bound:
            connections[(protocol, lip or "", lport, rip, rport)].update(
                [seqid] if seqid is not None else [])
    return {
        "connections": [
            {"protocol": p, "local_ip": lip, "local_port": lport, "remote_ip": rip,
             "remote_port": rport, "process_seqids": sorted(s)}
            for (p, lip, lport, rip, rport), s in connections.items()
        ],
        "unix_sockets": [
            {**e, "process_seqids": sorted(e["process_seqids"])}
            for e in sorted(unix.values(), key=lambda e: -e["messages"])
        ],
    }


SOCKET_SOURCES: Dict[TargetOs, Tuple[str, Callable[[PostprocessContext], dict]]] = {
    TargetOs.WINDOWS: ("socketmon.log", _windows),
    TargetOs.UBUNTU: ("unixsocketmon.log", _linux),
    TargetOs.ANDROID: ("unixsocketmon.log", _linux),
}


def get_socket_info(context: PostprocessContext) -> None:
    log_name, read = SOCKET_SOURCES[context.target_os]
    if not (context.analysis_dir / log_name).exists():
        # The plugin is selectable; a job that did not run it has nothing here
        return
    context.update_report(read(context))