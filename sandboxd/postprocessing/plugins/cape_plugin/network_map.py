"""NetworkMap: which process talked to what, from every source in the trace
that has network data -- the kernel's view (socketmon on Windows,
unixsocketmon on Linux), the APIs a process called (apimon, libmon:
Winsock, WinINet, WinHTTP, URL monikers, the resolver, SSPI, libc, curl,
OpenSSL), and the syscall plugin where its records carry anything decoded.

Upstream's NetworkMap (CAPEv2 behavior.py) reads capemon's calls only; the
keys it returns are kept, with what DRAKVUF adds beside them, so the
`Network` module (modules.py) and anything written against upstream's map
read it unchanged.

A connection socketmon or unixsocketmon recorded is the kernel's word for
it: the syscall plugin's record of the same thing adds nothing and is not
counted (`_Endpoints`). An API call adds what the kernel cannot know -- the
name asked of the resolver, the URL, the user agent -- and is counted
beside it.
"""
import fnmatch
import ipaddress
import re
from collections import defaultdict
from typing import Dict, Optional, Tuple

from .api_tables import canonical
from .pcap import _parse_dns
from .network_utils import (
    _extract_first_url,
    _get_call_ret_handle,
    _host_from_url,
    _norm_domain,
    _parse_handle,
    _safe_int,
    _winhttp_get_proc_state,
    winhttp_finalize_sessions,
    winhttp_update_from_call,
)

# ---------------------------------------------------------------------------
# What each call's arguments mean for the network, by api_tables.canonical
# name. The argument names are the hook lists' -- hooks.txt (Windows),
# so-hooks-linux.txt (Linux), the syscall plugin's tables -- lowercased, the
# first one a call has wins.

# A socket address, and what the call did with it. DRAKVUF prints one
# decoded where the hook types it lpsockaddr ("203.0.113.7:443",
# "[2001:db8::1]:443", a unix socket's path); a bare pointer names nothing.
SOCKADDR_ARGUMENTS: Dict[str, Tuple[Tuple[str, ...], str]] = {
    "connect": (("name", "sockaddr", "addr"), "connect"),
    "WSAConnect": (("name",), "connect"),
    "WSAConnectByName": (("remoteaddress",), "connect"),
    "WSAConnectByList": (("remoteaddress",), "connect"),
    "sendto": (("to", "destaddr", "dest_addr"), "send"),
    "WSASendTo": (("lpto",), "send"),
    "recvfrom": (("from", "srcaddr", "src_addr"), "recv"),
    "WSARecvFrom": (("lpfrom",), "recv"),
    "accept": (("addr", "sockaddr"), "accept"),
    "accept4": (("sockaddr", "addr"), "accept"),
    # AcceptEx completes later, its addresses in its buffer: the program
    # asks this where they are once it has (printers' ppsockaddr)
    "GetAcceptExSockaddrs": (("remotesockaddr",), "accept"),
    "getpeername": (("name", "sockaddr", "addr"), "peer"),
    "bind": (("name", "sockaddr", "addr"), "bind"),
    "getsockname": (("name", "sockaddr", "addr"), "local"),
    "getnameinfo": (("psockaddr", "sockaddr"), "lookup"),
}

# The events an address is the far end of; the rest are the process's own.
REMOTE_EVENTS = frozenset(("connect", "send", "recv", "accept", "peer"))
LOCAL_EVENTS = frozenset(("bind", "listen", "local"))

# Bytes the process sent (or received), where an HTTP request is visible.
PAYLOAD_ARGUMENTS: Dict[str, Tuple[str, ...]] = {
    "send": ("buf",), "sendto": ("buf",), "WSASend": ("lpbuffers",), "WSASendTo": ("lpbuffers",),
    "SSL_write": ("buf",), "SSL_write_ex": ("buf",),
    "InternetWriteFile": ("lpbuffer",), "WinHttpWriteData": ("lpbuffer",),
}

# The name asked of the resolver.
DNS_ARGUMENTS: Dict[str, Tuple[str, ...]] = {
    "getaddrinfo": ("pnodename", "node"), "GetAddrInfo": ("pnodename",),
    "GetAddrInfoEx": ("pname",), "gethostbyname": ("name",),
    "DnsQuery_A": ("pszname", "name"), "DnsQuery_W": ("pszname", "name"),
    "DnsQuery_UTF8": ("pszname", "name"), "DnsQueryEx": ("name", "queryname"),
    "WSAConnectByName": ("nodename",),
}

# The resolver's answer, read at the return (printers' ppaddrinfo,
# ppaddrinfoex, ppdns_record): the addresses, comma-separated.
ANSWER_ARGUMENTS: Dict[str, Tuple[str, ...]] = {
    "getaddrinfo": ("ppresult", "result"), "GetAddrInfo": ("ppresult",), "GetAddrInfoEx": ("ppresult",),
    "DnsQuery_A": ("ppqueryresults",), "DnsQuery_W": ("ppqueryresults",),
    "DnsQuery_UTF8": ("ppqueryresults",),
}

# A whole URL.
URL_ARGUMENTS: Dict[str, Tuple[str, ...]] = {
    "URLDownloadToFile": ("szurl",),
    "URLDownloadToCacheFile": ("szurl",), "InternetCrackUrl": ("lpszurl",),
    "WinHttpGetProxyForUrl": ("lpcwszurl",), "URLOpenStream": ("param1",),
    "URLOpenBlockingStream": ("param1",), "CryptRetrieveObjectByUrl": ("pszurl",),
}

# The server a TLS handshake is for (SChannel's target name is the SNI).
TLS_NAME_ARGUMENTS: Dict[str, Tuple[str, ...]] = {
    "InitializeSecurityContext": ("psztargetname",),
}

# curl_easy_setopt's options worth a name (curl/curl.h).
CURLOPT_URL, CURLOPT_POSTFIELDS, CURLOPT_REFERER, CURLOPT_USERAGENT = 10002, 10015, 10016, 10018
CURLOPT_CUSTOMREQUEST, CURLOPT_POST = 10036, 47

# INTERNET_FLAG_SECURE (WinINet) and WINHTTP_FLAG_SECURE: the same bit.
FLAG_SECURE = 0x00800000

# socketmon's and unixsocketmon's methods, by what happened.
KERNEL_EVENTS = {
    "TcpCreateAndConnectTcbComplete": "connect",
    "TcpCreateAndConnectTcbRateLimitComplete": "connect",
    "UdpSendMessages": "send",
    # socketmon's AFD requests (afd_ioctl_cb)
    "AfdConnect": "connect",
    "AfdBind": "bind",
    "AfdListen": "listen",
    "AfdSend": "send",
    # unixsocketmon
    "connect": "connect",
    "sock_sendmsg": "send",
    "bind": "bind",
    "listen": "listen",
    "accept": "accept",
    "sock_recvmsg": "recv",
}
KERNEL_PLUGINS = ("socketmon", "unixsocketmon")

# CLSIDs of out-of-process COM servers a sample can drive the network through.
OOP_CLSIDS = {
    "3050f4d8-98b5-11cf-bb82-00aa00bdce0b": "mshta.exe",
    "0002df01-0000-0000-c000-000000000046": "iexplore.exe",
    "9ba05972-f6a8-11cf-a442-00a0c90a8f39": "explorer.exe",
    "c08afd90-f2a1-11d1-8455-00a0c91f3880": "explorer.exe",
    "25336920-03f9-11cf-8fd0-00aa00686f13": "mshta.exe",
}
CLSCTX_LOCAL_SERVER = 0x4

_ENDPOINT = re.compile(
    r"\A(?:\[(?P<v6>[0-9A-Fa-f:.]+)\]|(?P<v4>\d{1,3}(?:\.\d{1,3}){3})):(?P<port>\d{1,5})\Z")
_ADDRESS = re.compile(r"\A0x[0-9a-fA-F]+\Z")
_HTTP_METHODS = ("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT")


# What the map leaves out unless told otherwise (CapeConfigSection's
# network_exclude_*): what the guest's own libraries reach from inside the
# sample's process -- proxy discovery, connectivity probes, the certificate
# checks behind any signed binary's verification -- and addresses no
# conversation has. Loopback is kept: a local proxy (Tor's 127.0.0.1:9050)
# is the sample's traffic.
DEFAULT_EXCLUDE_DOMAINS = (
    "localhost", "local", "in-addr.arpa", "ip6.arpa", "wpad", "wpad.*",
    "msftconnecttest.com", "msftncsi.com", "ctldl.windowsupdate.com", "crl.microsoft.com",
    "ocsp.digicert.com", "crl3.digicert.com", "crl4.digicert.com",
    "connectivity-check.ubuntu.com", "ntp.ubuntu.com", "motd.ubuntu.com",
)
DEFAULT_EXCLUDE_NETWORKS = (
    "0.0.0.0/32", "255.255.255.255/32", "224.0.0.0/4", "169.254.0.0/16",
    "::/128", "ff00::/8", "fe80::/10",
)


class NetworkFilter:
    """Which domains and addresses the map records. A domain pattern is a
    glob over the lowercased name that also covers every name under it
    ("windowsupdate.com" is "ctldl.windowsupdate.com" too); a network is a
    CIDR. An include wins over an exclude. What is left out is counted."""

    def __init__(self, exclude_domains=DEFAULT_EXCLUDE_DOMAINS, exclude_networks=DEFAULT_EXCLUDE_NETWORKS,
                 include_domains=(), include_networks=()):
        self.exclude_domains = [d.lower().lstrip("*.") if d.startswith("*.") else d.lower()
                                for d in exclude_domains]
        self.include_domains = [d.lower() for d in include_domains]
        self.exclude_networks = [ipaddress.ip_network(n, strict=False) for n in exclude_networks]
        self.include_networks = [ipaddress.ip_network(n, strict=False) for n in include_networks]
        self.filtered = defaultdict(int)

    @staticmethod
    def _domain_in(name, patterns):
        return any(fnmatch.fnmatchcase(name, p) or fnmatch.fnmatchcase(name, "*." + p) for p in patterns)

    @staticmethod
    def _address_in(address, networks):
        return any(address.version == n.version and address in n for n in networks)

    def keeps(self, value, what) -> bool:
        """Whether the map records `value`, a domain or an address (an
        address literal where a name could be is judged as an address)."""
        if not value:
            return False
        value = str(value).strip().strip("[]").lower()
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            address = None
        if address is not None:
            kept = (self._address_in(address, self.include_networks)
                    or not self._address_in(address, self.exclude_networks))
        else:
            kept = (self._domain_in(value, self.include_domains)
                    or not self._domain_in(value, self.exclude_domains))
        if not kept:
            self.filtered[what] += 1
        return kept


def parse_endpoint(value) -> Optional[Tuple[str, str, Optional[int]]]:
    """A decoded socket address: ("inet", ip, port), ("unix", path, None),
    or None for anything else -- a bare pointer, an empty string."""
    if not isinstance(value, str) or not value or _ADDRESS.match(value):
        return None
    m = _ENDPOINT.match(value)
    if m:
        return "inet", m.group("v6") or m.group("v4"), int(m.group("port"))
    if value.startswith(("/", "@")):
        return "unix", value, None
    return None


def _args(call) -> Dict[str, object]:
    return {a["name"].lower(): a.get("value") for a in call.get("arguments", []) if "name" in a}


def _first(args, names):
    for n in names:
        v = args.get(n)
        if isinstance(v, str) and v.strip() and not _ADDRESS.match(v):
            return v
    return None


def _timestamp(call) -> Optional[float]:
    try:
        return float(call.get("timestamp"))
    except (TypeError, ValueError):
        return None


def parse_http_request(text) -> Optional[Dict[str, str]]:
    """The request line and the headers that say who and where, of a buffer
    that starts with an HTTP request; None for anything else."""
    if not isinstance(text, str):
        return None
    lines = text.replace("\r\n", "\n").split("\n")
    parts = lines[0].strip().split()
    if len(parts) < 3 or parts[0].upper() not in _HTTP_METHODS or not parts[2].upper().startswith("HTTP/"):
        return None
    out = {"method": parts[0].upper(), "target": parts[1], "host": "", "user_agent": ""}
    for line in lines[1:64]:
        if not line.strip():
            break
        name, _, value = line.partition(":")
        name = name.strip().lower()
        if name == "host":
            out["host"] = value.strip()
        elif name == "user-agent":
            out["user_agent"] = value.strip()
    return out


def parse_headers(text) -> Dict[str, str]:
    """The headers WinINet/WinHTTP were given to add, by lowercased name."""
    out = {}
    if isinstance(text, str):
        for line in text.replace("\r\n", "\n").split("\n"):
            name, sep, value = line.partition(":")
            if sep and name.strip():
                out[name.strip().lower()] = value.strip()
    return out


class _Endpoints:
    """Addresses by (kind, address, port), each with the processes that used
    it, how, and according to which plugin. A syscall-plugin record of what
    socketmon or unixsocketmon already recorded -- the same process, address
    and event -- is dropped when the map is built."""

    def __init__(self):
        self.entries = defaultdict(dict)    # key -> pid -> pinfo
        self.syscall = []                   # (key, pinfo, event): decided in build()

    def add(self, key, process, event, source, ts):
        if source == "syscall":
            self.syscall.append((key, process, event, ts))
            return
        self._add(key, process, event, source, ts)

    def _add(self, key, process, event, source, ts):
        pid = process.get("process_id")
        entry = self.entries[key].get(pid)
        if entry is None:
            entry = self.entries[key][pid] = {
                "process_id": pid, "process_name": process.get("process_name", ""),
                "events": [], "sources": [], "first_seen": ts,
            }
        if event not in entry["events"]:
            entry["events"].append(event)
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if ts is not None and (entry["first_seen"] is None or ts < entry["first_seen"]):
            entry["first_seen"] = ts

    def build(self):
        for key, process, event, ts in self.syscall:
            entry = self.entries.get(key, {}).get(process.get("process_id"))
            if entry and event in entry["events"] and set(entry["sources"]) & set(KERNEL_PLUGINS):
                continue
            self._add(key, process, event, "syscall", ts)
        return self.entries


class NetworkMap:
    """Mappings between processes and network activity, for the `Network`
    module and the signatures: endpoints, HTTP hosts and requests, DNS
    intents, TLS server names, user agents, unix sockets, COM servers."""

    key = "network_map"

    def __init__(self, options=None):
        # CapeOptions.network_filter: CapeConfigSection's network_* lists
        self.filter = NetworkFilter(**(getattr(options, "network_filter", None) or {}))
        self.endpoints = _Endpoints()
        self.http_host_map = defaultdict(list)
        self.http_requests = []
        self.dns_intents = defaultdict(list)
        self.dns_answers = defaultdict(list)    # domain -> addresses the resolver gave
        self.user_agents = defaultdict(list)
        self.com_activations = []
        self._winhttp_state = {"processes": {}}
        # Per process: WinINet/WinHTTP handle -> what it was opened on; curl
        # easy handle -> its options.
        self._handles = defaultdict(dict)
        self._curl = defaultdict(lambda: defaultdict(dict))
        self._seen_requests = set()

    # -- recording ----------------------------------------------------------

    @staticmethod
    def _pinfo(process):
        return {"process_id": process.get("process_id"), "process_name": process.get("process_name", "")}

    def _host(self, host, process, source):
        host = _norm_domain(host)
        if not host or not self.filter.keeps(_bare_host(host), "hosts"):
            return
        pinfo = dict(self._pinfo(process), source=source)
        if pinfo not in self.http_host_map[host]:
            self.http_host_map[host].append(pinfo)

    def _dns(self, domain, process, call, source, answers=()):
        domain = _norm_domain(domain)
        if not domain:
            return
        try:
            ipaddress.ip_address(domain)
            return     # an address literal asks nothing of DNS
        except ValueError:
            pass
        if not self.filter.keeps(domain, "dns"):
            return
        for address in answers:
            if address not in self.dns_answers[domain]:
                self.dns_answers[domain].append(address)
        pid = process.get("process_id")
        api = call.get("api") or call.get("syscall") or ""
        for intent in self.dns_intents[domain]:
            if intent["process"]["process_id"] == pid:
                intent["sources"] = sorted(set(intent["sources"]) | {source})
                if api not in intent["apis"]:
                    intent["apis"].append(api)
                intent["answers"] += [a for a in answers if a not in intent["answers"]]
                return
        self.dns_intents[domain].append({
            "process": self._pinfo(process), "ts_epoch": _timestamp(call),
            "api": api, "apis": [api], "sources": [source], "answers": list(answers)})

    def _user_agent(self, agent, process, source):
        if isinstance(agent, str) and agent.strip():
            pinfo = dict(self._pinfo(process), source=source)
            if pinfo not in self.user_agents[agent.strip()]:
                self.user_agents[agent.strip()].append(pinfo)

    def _request(self, process, call, source, url, method="", user_agent="", host=""):
        url = (url or "").strip()
        if not url:
            return
        if "://" not in url and host:
            url = f"http://{host}{url if url.startswith('/') else '/' + url}"
        host = host or _host_from_url(url) or ""
        if host and not self.filter.keeps(_bare_host(host), "requests"):
            return
        key = (process.get("process_id"), url, method)
        if key in self._seen_requests:
            return
        self._seen_requests.add(key)
        if host:
            self._host(host, process, source)
        if user_agent:
            self._user_agent(user_agent, process, source)
        self.http_requests.append({
            "url": url, "host": host, "method": method, "user_agent": user_agent,
            "process_id": process.get("process_id"), "process_name": process.get("process_name"),
            "time": call.get("timestamp"), "api": call.get("api") or call.get("syscall") or "",
            "source": source})

    def _payload(self, text, process, call, source):
        request = parse_http_request(text)
        if request:
            self._request(process, call, source, request["target"], request["method"],
                          request["user_agent"], request["host"])

    def _endpoint(self, value, event, process, call, source):
        parsed = parse_endpoint(value)
        if parsed and (parsed[0] == "unix" or event in LOCAL_EVENTS or self.filter.keeps(parsed[1], "endpoints")):
            self.endpoints.add(parsed, process, event, source, _timestamp(call))

    # -- per source -----------------------------------------------------------

    def event_apicall(self, call, process):
        plugin = call.get("plugin") or ""
        if plugin in KERNEL_PLUGINS and "api" not in call:
            self._kernel(call, process, plugin)
            return
        if plugin not in ("apimon", "libmon", "syscall", "socketmon"):
            return
        name = canonical(call.get("api") or call.get("syscall") or "")
        if not name:
            return
        args = _args(call)
        source = plugin

        sock = SOCKADDR_ARGUMENTS.get(name)
        if sock:
            self._endpoint(_first(args, sock[0]), sock[1], process, call, source)
            if name == "getnameinfo":
                # libmon prints the result buffer at the return: the name
                # the address resolved to
                host = _first(args, ("host", "pnodebuffer"))
                if host:
                    self._host(host, process, source)

        payload = PAYLOAD_ARGUMENTS.get(name)
        if payload:
            self._payload(_first(args, payload), process, call, source)

        dns = DNS_ARGUMENTS.get(name)
        if dns:
            answers = ANSWER_ARGUMENTS.get(name)
            self._dns(_first(args, dns), process, call, source,
                      _addresses(_first(args, answers)) if answers else [])

        url = URL_ARGUMENTS.get(name)
        if url:
            self._request(process, call, source, _first(args, url))

        tls = TLS_NAME_ARGUMENTS.get(name)
        if tls:
            server = _first(args, tls)
            if server:
                # SChannel's is the host; Kerberos' an SPN, HTTP/host@REALM
                self._host(server.split("/")[-1].split("@")[0], process, source)

        if plugin == "apimon":
            self._wininet(name, args, call, process, source)
            self._winhttp(name, args, call, process, source)
            self._com(name, args, process)
        if plugin == "libmon":
            self._libcurl(name, args, call, process, source)

    def _kernel(self, call, process, plugin):
        """socketmon's and unixsocketmon's records: the endpoint, from the
        kernel's socket -- the far end, or for a bind or listen the
        process's own -- and unixsocketmon's also the bytes sent."""
        event = KERNEL_EVENTS.get(call.get("syscall") or "", "connect")
        side = "local" if event in LOCAL_EVENTS else "remote"
        ts = _timestamp(call)
        ip, port = call.get(f"{side}ip"), _safe_int(call.get(f"{side}port"))
        # A bind's 0.0.0.0 is any address, not one no conversation has: the
        # filter is for far ends
        if ip and port is not None and (side == "local" or self.filter.keeps(ip, "endpoints")):
            self.endpoints.add(("inet", str(ip), port), process, event, plugin, ts)
        path = call.get(f"{side}path")
        if path:
            self.endpoints.add(("unix", str(path), None), process, event, plugin, ts)
        # The process's requests are in what it sends; what it receives is
        # another's (a sample serving gets the requests made of it)
        if event == "send" and call.get("value"):
            self._payload(call["value"], process, call, plugin)
            # A name asked of a resolver over the process's own socket, no
            # resolver API in between: a static program's DNS (a bot's
            # `lkol.dyn` to eight servers, 2026-11-12)
            if port == 53:
                self._dns_query(call["value"], process, call, plugin)

    def _dns_query(self, value, process, call, source):
        """The names in a DNS query unixsocketmon printed as hex."""
        try:
            message = _parse_dns(bytes.fromhex(str(value)))
        except ValueError:
            return
        if not message or message["response"]:
            return
        for name, _qtype in message["questions"]:
            if name:
                self._dns(name, process, call, source)

    def _wininet(self, name, args, call, process, source):
        """InternetOpen -> InternetConnect -> HttpOpenRequest -> HttpSendRequest,
        followed by handle: the request's URL is the connection's server and
        the request's path, its user agent the session's."""
        handles = self._handles[process.get("process_id")]
        ret = _get_call_ret_handle(call)
        if name == "InternetOpen" and ret:
            agent = _first(args, ("lpszagent",))
            handles[ret] = {"agent": agent or ""}
            self._user_agent(agent, process, source)
        elif name == "InternetConnect" and ret:
            session = handles.get(_parse_handle(args.get("hinternet")), {})
            server = _first(args, ("lpszservername",)) or ""
            port = _safe_int(args.get("nserverport")) or 0
            handles[ret] = {"agent": session.get("agent", ""), "server": server, "port": port}
            self._host(server, process, source)
        elif name == "HttpOpenRequest" and ret:
            conn = handles.get(_parse_handle(args.get("hconnect")), {})
            secure = bool((_safe_int(args.get("dwflags")) or 0) & FLAG_SECURE) or conn.get("port") == 443
            handles[ret] = dict(conn, verb=(_first(args, ("lpszverb",)) or "GET").upper(),
                                path=_first(args, ("lpszobjectname",)) or "/", secure=secure)
        elif name == "HttpSendRequest":
            request = handles.get(_parse_handle(args.get("hrequest")))
            if request and request.get("server"):
                headers = parse_headers(_first(args, ("lpszheaders",)))
                self._request(process, call, source, _url(request), request.get("verb", "GET"),
                              headers.get("user-agent") or request.get("agent", ""))
        elif name == "InternetOpenUrl":
            session = handles.get(_parse_handle(args.get("hinternet")), {})
            headers = parse_headers(_first(args, ("lpszheaders",)))
            self._request(process, call, source, _first(args, ("lpszurl",)), "GET",
                          headers.get("user-agent") or session.get("agent", ""))

    def _winhttp(self, name, args, call, process, source):
        """The same chain in WinHTTP (WinHttpOpen -> Connect -> OpenRequest
        -> SendRequest), and upstream's per-session record of it."""
        if not name.startswith("WinHttp"):
            return
        ret = _get_call_ret_handle(call)
        pstate = _winhttp_get_proc_state(self._winhttp_state, process)
        winhttp_update_from_call(pstate, name.lower(), args, ret)
        handles = self._handles[process.get("process_id")]
        if name == "WinHttpOpen" and ret:
            agent = _first(args, ("pszagentw", "pwszuseragent", "useragent"))
            handles[ret] = {"agent": agent or ""}
            self._user_agent(agent, process, source)
        elif name == "WinHttpConnect" and ret:
            session = handles.get(_parse_handle(args.get("hsession")), {})
            server = _first(args, ("pswzservername", "servername")) or ""
            handles[ret] = {"agent": session.get("agent", ""), "server": server,
                            "port": _safe_int(args.get("nserverport")) or 0}
            self._host(server, process, source)
        elif name == "WinHttpOpenRequest" and ret:
            conn = handles.get(_parse_handle(args.get("hconnect")), {})
            secure = bool((_safe_int(args.get("dwflags")) or 0) & FLAG_SECURE) or conn.get("port") == 443
            handles[ret] = dict(conn, verb=(_first(args, ("pwszverb", "verb")) or "GET").upper(),
                                path=_first(args, ("pwszobjectname", "objectname")) or "/", secure=secure)
        elif name == "WinHttpSendRequest":
            request = handles.get(_parse_handle(args.get("hrequest")))
            if request and request.get("server"):
                headers = parse_headers(_first(args, ("lpszheaders", "headers")))
                self._request(process, call, source, _url(request), request.get("verb", "GET"),
                              headers.get("user-agent") or request.get("agent", ""))

    def _libcurl(self, name, args, call, process, source):
        """curl_easy_setopt's URL, user agent and method, by easy handle;
        the request once the handle is performed or handed to a multi."""
        handles = self._curl[process.get("process_id")]
        if name == "curl_easy_setopt":
            handle = _parse_handle(args.get("handle"))
            option = _safe_int(args.get("option"))
            value = _first(args, ("value",))
            if handle and option is not None and value is not None:
                handles[handle][option] = value
                if option == CURLOPT_USERAGENT:
                    self._user_agent(value, process, source)
        elif name in ("curl_easy_perform", "curl_multi_add_handle"):
            options = handles.get(_parse_handle(args.get("handle")), {})
            if options.get(CURLOPT_URL):
                method = options.get(CURLOPT_CUSTOMREQUEST) or ("POST" if CURLOPT_POSTFIELDS in options else "GET")
                self._request(process, call, source, options[CURLOPT_URL], method.upper(),
                              options.get(CURLOPT_USERAGENT, ""))

    def _com(self, name, args, process):
        """An out-of-process COM server activated: a network request it makes
        is the sample's, from another process (ProcessTree's COM parents)."""
        if name not in ("CoCreateInstance", "CoCreateInstanceEx"):
            return
        clsid = str(args.get("rclsid") or args.get("clsid") or "").strip('"{} ').lower()
        context = _safe_int(args.get("dwclscontext") if "dwclscontext" in args else args.get("dwclsctx")) or 0
        if clsid and (context & CLSCTX_LOCAL_SERVER or clsid in OOP_CLSIDS):
            self.com_activations.append({
                "clsid": clsid, "progid": "",
                "activator_pid": process.get("process_id"),
                "activator_name": process.get("process_name", ""),
                "target_binary": OOP_CLSIDS.get(clsid, ""),
            })

    # -- result ---------------------------------------------------------------

    def run(self):
        for intents in self.dns_intents.values():
            intents.sort(key=lambda x: (x["ts_epoch"] is None, x["ts_epoch"] or 0.0))

        endpoint_map, listeners, unix_sockets = [], [], []
        for (kind, address, port), by_pid in sorted(self.endpoints.build().items(),
                                                    key=lambda kv: (kv[0][0], kv[0][1], kv[0][2] or 0)):
            pinfo = list(by_pid.values())
            if kind == "unix":
                unix_sockets.append({"path": address, "pinfo": pinfo})
                continue
            ip_port = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
            remote = [p for p in pinfo if set(p["events"]) & REMOTE_EVENTS]
            local = [p for p in pinfo if set(p["events"]) & LOCAL_EVENTS]
            if remote:
                endpoint_map.append({"ip_port": ip_port, "ip": address, "port": port, "pinfo": remote})
            if local:
                listeners.append({"ip_port": ip_port, "ip": address, "port": port, "pinfo": local})

        return {
            "endpoint_map": endpoint_map,
            "listeners": listeners,
            "unix_sockets": unix_sockets,
            "http_host_map": [{"host": k, "pinfo": v} for k, v in self.http_host_map.items()],
            "dns_intents": [{"domain": k, "intents": v} for k, v in self.dns_intents.items()],
            "dns_answers": [{"domain": k, "answers": v} for k, v in self.dns_answers.items() if v],
            "http_requests": self.http_requests,
            "user_agents": [{"user_agent": k, "pinfo": v} for k, v in self.user_agents.items()],
            "winhttp_sessions": winhttp_finalize_sessions(self._winhttp_state),
            "com_activations": self.com_activations,
            # What NetworkFilter left out, by kind: none of it silently
            "filtered": dict(self.filter.filtered),
        }


def _addresses(text) -> list:
    """A resolver answer's addresses ("203.0.113.7,2001:db8::1"), each a
    valid address; none for an answer not read (a bare pointer)."""
    out = []
    if isinstance(text, str):
        for item in text.split(","):
            try:
                out.append(str(ipaddress.ip_address(item.strip())))
            except ValueError:
                continue
    return out


def _bare_host(host: str) -> str:
    """A host without the port a Host header or URL netloc may carry
    ("example.com:8080"); an IPv6 literal, all colons, as it is."""
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def _url(request) -> str:
    """A WinINet/WinHTTP request's URL from its connection and path."""
    scheme = "https" if request.get("secure") else "http"
    port = request.get("port") or 0
    default = 443 if request.get("secure") else 80
    netloc = request["server"] if port in (0, default) else f"{request['server']}:{port}"
    path = request.get("path") or "/"
    if _extract_first_url(path):
        return path
    return f"{scheme}://{netloc}{path if path.startswith('/') else '/' + path}"
