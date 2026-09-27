"""Reconstruct HTTP requests the sample made, per guest OS.

Windows reads `apimon.log` and replays the WinINet/WinHTTP handle chain:
`InternetOpen` -> `InternetConnect` -> `HttpOpenRequest`, each returning a
handle the next call takes as an argument, so a request is assembled by
following handles rather than by reading any single call.

Linux reads `libmon.log`, which is the same record shape from the Linux
counterpart plugin (`src/plugins/libmon` in the DRAKVUF fork): `Event`,
`Method`, `Arguments`, `ReturnValue`, with apimon's argument printers. libcurl
has a handle chain of the same shape -- `curl_easy_init` returns a handle,
`curl_easy_setopt` accumulates options onto it, `curl_easy_perform` runs it --
so the two are one algorithm with two vocabularies, and the vocabularies live
in the per-OS table below rather than in a branch.

**There is no capa-rules-derived vocabulary for this.** capa's rule set at
v9.4.0 contains no curl, OpenSSL or gnutls `api:` feature at all -- every HTTP
API it knows is winhttp/wininet/httpapi or .NET. The Linux hooks are therefore
hand-authored in `sandboxd/data/so-hooks-linux.txt`, and this table has to
agree with that file: a method named here that is not hooked there is never
seen, and the reverse is merely unused.
"""

from collections import defaultdict
from typing import Any, Callable, Dict, Optional, Tuple

from ...guests import TargetOs
from .parse_utils import parse_apimon_arguments, parse_log, trim_method_name
from .plugin_base import PostprocessContext

# --- Windows: WinINet and WinHTTP ------------------------------------------

_WINHTTP_METHODS = frozenset({
    "WinHttpOpen", "WinHttpConnect", "WinHttpGetProxyForUrl",
    "WinHttpOpenRequest", "WinHttpSendRequest", "WinHttpReceiveResponse",
    "WinHttpSetOption", "WinHttpQueryHeaders", "WinHttpCrackUrl",
    "WinHttpCreateUrl", "WinHttpAddRequestHeaders",
    "WinHttpWebSocketCompleteUpgrade", "WinHttpSetCredentials",
})

_WININET_METHODS = frozenset({
    "InternetOpen", "InternetOpenUrl", "InternetConnect", "InternetCreateUrl",
    "InternetSetOption", "InternetCrackUrl", "HttpOpenRequest",
    "HttpAddRequestHeaders", "InternetReadFile", "InternetWriteFile",
})

# --- Linux: libcurl and OpenSSL --------------------------------------------

_CURL_METHODS = frozenset({
    "curl_easy_init", "curl_easy_setopt", "curl_easy_perform",
    "curl_easy_cleanup", "curl_easy_getinfo",
})

_OPENSSL_METHODS = frozenset({
    "SSL_write", "SSL_read", "SSL_set_fd", "SSL_connect",
})

# CURLoption values libcurl fixes and never renumbers -- that ABI guarantee
# is what makes reading them by number safe. Only the options carrying request
# identity are listed; anything else is reported as a raw (option, value) pair
# rather than guessed at.
#
# **Every value below was read out of `include/curl/curl.h` at tag
# `curl-8_5_0`, not recalled.** Three of them were wrong when written from
# memory -- CURLOPT_FOLLOWLOCATION is 52 and 80 is CURLOPT_HTTPGET, and
# USERNAME/PASSWORD were each one low -- which does not fail loudly: a wrong
# number silently files a URL under the wrong key, or drops it into the
# untyped `options` list where nothing looks for it. Check the header before
# adding a row.
#
# The number is `CURLOPTTYPE_* base + ordinal`: OBJECTPOINT (and its
# STRINGPOINT/SLISTPOINT aliases) = 10000, LONG = 0.
CURL_OPTIONS: Dict[int, str] = {
    10002: "url",            # CURLOPT_URL            (STRINGPOINT   2)
    10004: "proxy",          # CURLOPT_PROXY          (STRINGPOINT   4)
    10015: "postfields",     # CURLOPT_POSTFIELDS     (OBJECTPOINT  15)
    10016: "referer",        # CURLOPT_REFERER        (STRINGPOINT  16)
    10018: "user_agent",     # CURLOPT_USERAGENT      (STRINGPOINT  18)
    10023: "extra_headers",  # CURLOPT_HTTPHEADER     (SLISTPOINT   23)
    10036: "verb",           # CURLOPT_CUSTOMREQUEST  (STRINGPOINT  36)
    10173: "username",       # CURLOPT_USERNAME       (STRINGPOINT 173)
    10174: "password",       # CURLOPT_PASSWORD       (STRINGPOINT 174)
    3: "port",               # CURLOPT_PORT           (LONG          3)
    52: "follow_location",   # CURLOPT_FOLLOWLOCATION (LONG         52)
}


def _text(value: Any) -> Optional[str]:
    """An argument, kept only if it arrived as text.

    **Whether a field here is text is decided by the hook list, not by this
    file.** A string printer always emits `Name=0xADDR:"..."`, quotes included
    even for an empty read, and `parse_apimon_arguments` returns a `str`. Every
    other type token reaches the base `ArgumentPrinter`, which prints
    `Name=0x<hex>` with no quoted half (`printers.cpp::ArgumentPrinter::print`)
    -- so a string position typed `lpvoid` arrives as an **int**.

    **An int in a text field degrades the WHOLE report**, not the field.
    `platform/sandbox_platform/report.py` types these `str | None` and
    `extra_headers` as `list[str]`, and `parse` turns a single `ValidationError`
    into `Loaded(error=...)`: every report-driven tab renders "report.json did
    not validate" instead of the run. The generated
    `winhttp.dll,WinHttpAddRequestHeaders` line typed its header argument
    `lpvoid` and did exactly that. That line is now curated with `lpcwstr`, and
    this is what stops the next regeneration reintroducing it -- the generator
    keeps emitting lines as capa-rules grows, and `existing_hooks` protects only
    the exact `(dll, function)` pairs already curated.

    Dropped rather than rendered as a number: `0x7ffc1234` is not the header the
    sample sent, and the `if v` filter in `get_http_info` removes a None.
    """
    return value if isinstance(value, str) else None


def _api_type_windows(method: str) -> Optional[str]:
    if method in _WINHTTP_METHODS:
        return "winhttp"
    if method in _WININET_METHODS:
        return "wininet"
    return None


def _api_type_linux(method: str) -> Optional[str]:
    if method in _CURL_METHODS:
        return "curl"
    if method in _OPENSSL_METHODS:
        return "openssl"
    return None


def _windows_handlers() -> Dict[str, Callable]:
    """WinINet and WinHTTP share a shape; the two families differ only in the
    handle kinds they thread together, so each handler is registered twice
    with the names of its family.

    Every handler checks its own arity first. The hook list decides how many
    arguments a record carries, and the generator's last two rungs emit a line
    with NO argument types at all (`capa-hint`, `phnt`) -- so a future
    regeneration can hand one of these methods an empty `Arguments` list. The
    handlers run outside `parse_log`'s per-line `try`, so one IndexError here
    loses every request in the run rather than one record.
    """

    def open_session(state, data, arguments, kind):
        if len(arguments) < 4:
            return
        state.handles[(data["seqid"], data["retval"], f"{kind}_open")] = {
            "user_agent": _text(arguments[0]),
            "proxy": _text(arguments[2]),
            "proxy_bypass": _text(arguments[3]),
        }

    def connect(state, data, arguments, kind):
        # WinHttpConnect takes the port at 2 and stops; InternetConnect carries
        # credentials and the service through 5.
        if len(arguments) < (6 if kind == "internet" else 3):
            return
        session = state.handles.get(
            (data["seqid"], arguments[0], f"{kind}_open"), {})
        # `internet_port` and `dword` both reach the base printer, so this is
        # an int under every hook list that types it at all -- but `&` on a str
        # raises, and that would cost the whole run rather than this port.
        port = arguments[2]
        server_port = port & 0xFFFF if isinstance(port, int) else None
        entry = {"server_name": _text(arguments[1]), "session": session,
                 **({"server_port": server_port} if server_port else {})}
        if kind == "internet":
            entry.update({"username": _text(arguments[3]),
                          "password": _text(arguments[4]),
                          # `service` is `int | str | None` in the report
                          # model -- a service id is a number, so it is not
                          # text and is passed through as it arrived.
                          "service": arguments[5]})
        state.handles[(data["seqid"], data["retval"], f"{kind}_connect")] = entry

    def open_request(state, data, arguments, kind):
        if len(arguments) < 7:
            return
        connection = state.handles.get(
            (data["seqid"], arguments[0], f"{kind}_connect"), {})
        handle = (data["seqid"], data["retval"], f"{kind}_request")
        request = {
            "verb": _text(arguments[1]),
            "path": _text(arguments[2]),
            "version": _text(arguments[3]),
            "referer": _text(arguments[4]),
            # `flags` is `int | str | None`: a flag word is a number.
            "flags": arguments[6],
            "connection": connection,
            "extra_headers": [],
        }
        state.request_handles[handle] = state.handles[handle] = request

    def add_headers(state, data, arguments, kind):
        if len(arguments) < 2:
            return
        request = state.handles.get((data["seqid"], arguments[0],
                                     f"{kind}_request"))
        if request is None:
            return
        header = _text(arguments[1])
        if header is not None:
            request.setdefault("extra_headers", []).append(header)
        else:
            # Only the address, so the headers are recorded as present and
            # their contents are not invented -- the same thing `easy_setopt`
            # does with a `curl_slist` it cannot walk.
            request["extra_headers_ptr"] = arguments[1]

    def crack_url(state, data, arguments, index):
        if len(arguments) <= index:
            return
        url = arguments[index]
        if isinstance(url, str):
            state.cracked_urls[url].add(data["seqid"])

    return {
        "InternetOpen": lambda s, d, a: open_session(s, d, a, "internet"),
        "InternetConnect": lambda s, d, a: connect(s, d, a, "internet"),
        "HttpOpenRequest": lambda s, d, a: open_request(s, d, a, "internet"),
        "HttpAddRequestHeaders": lambda s, d, a: add_headers(s, d, a, "internet"),
        "InternetCrackUrl": lambda s, d, a: crack_url(s, d, a, 0),
        "InternetCreateUrl": lambda s, d, a: crack_url(s, d, a, 3),
        "WinHttpOpen": lambda s, d, a: open_session(s, d, a, "winhttp"),
        "WinHttpConnect": lambda s, d, a: connect(s, d, a, "winhttp"),
        "WinHttpOpenRequest": lambda s, d, a: open_request(s, d, a, "winhttp"),
        "WinHttpAddRequestHeaders": lambda s, d, a: add_headers(s, d, a, "winhttp"),
    }


def _linux_handlers() -> Dict[str, Callable]:
    """libcurl's chain, which carries the same information in a different
    order: where WinINet fixes the verb and path when the request handle is
    opened, curl accumulates them onto one handle as options, and the request
    exists only when `curl_easy_perform` runs it.

    A handle is therefore accumulated on `setopt` and SNAPSHOTTED on
    `perform`: curl handles are routinely reused for a second request with a
    different URL, and reporting the live dict would show every request with
    the last URL set on it.
    """

    def easy_init(state, data, arguments):
        state.handles[(data["seqid"], data["retval"], "curl")] = {
            "extra_headers": []}

    def easy_setopt(state, data, arguments):
        if len(arguments) < 3:
            return
        handle = (data["seqid"], arguments[0], "curl")
        # An option set on a handle whose init was never seen still belongs to
        # a real request -- the hook may have landed after `curl_easy_init`
        # ran. Create the handle rather than dropping the option.
        request = state.handles.setdefault(handle, {"extra_headers": []})
        name = CURL_OPTIONS.get(arguments[1])
        value = arguments[2]
        if name is None:
            request.setdefault("options", []).append(
                {"option": arguments[1], "value": value})
        elif name == "extra_headers":
            # A curl_slist pointer. Only its address is available without
            # walking guest memory, so the presence of headers is recorded
            # and their contents are not invented.
            request["extra_headers_ptr"] = value
        else:
            request[name] = value

    def easy_perform(state, data, arguments):
        if not arguments:
            return
        handle = (state_seqid := data["seqid"], arguments[0], "curl")
        request = state.handles.get(handle)
        if request is None:
            return
        snapshot = {k: v for k, v in request.items()}
        snapshot["connection"] = {}
        # `perform` is the moment a request happens, so each one is its own
        # entry even when the handle is reused.
        state.request_handles[(state_seqid, arguments[0], "curl",
                               len(state.request_handles))] = snapshot
        url = snapshot.get("url")
        if isinstance(url, str):
            state.cracked_urls[url].add(state_seqid)

    def ssl_write(state, data, arguments):
        """A TLS payload that begins with a request line is an HTTP request
        the sample made without libcurl. Only the request line is read: the
        body may be arbitrary bytes and is not evidence of a URL."""
        if len(arguments) < 2 or not isinstance(arguments[1], str):
            return
        first, _, _ = arguments[1].partition("\r\n")
        parts = first.split(" ")
        if len(parts) == 3 and parts[2].startswith("HTTP/"):
            state.request_handles[
                (data["seqid"], data["retval"], "openssl",
                 len(state.request_handles))
            ] = {"verb": parts[0], "path": parts[1], "version": parts[2],
                 "connection": {}, "extra_headers": [], "over_tls": True}

    return {
        "curl_easy_init": easy_init,
        "curl_easy_setopt": easy_setopt,
        "curl_easy_perform": easy_perform,
        "SSL_write": ssl_write,
    }


class _State:
    def __init__(self) -> None:
        self.handles: Dict[Tuple, Dict[str, Any]] = defaultdict(dict)
        self.request_handles: Dict[Tuple, Dict[str, Any]] = {}
        self.cracked_urls: Dict[str, set] = defaultdict(set)


# Which log carries library calls, which names are HTTP, and how to replay
# them -- per guest OS. The rule CLAUDE.md states for a new guest applies
# here: add a row, never a branch.
HTTP_SOURCES: Dict[TargetOs, Tuple[str, Callable, Callable]] = {
    TargetOs.WINDOWS: ("apimon.log", _api_type_windows, _windows_handlers),
    TargetOs.UBUNTU: ("libmon.log", _api_type_linux, _linux_handlers),
    TargetOs.ANDROID: ("libmon.log", _api_type_linux, _linux_handlers),
}


def get_http_info(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    process_tree = context.process_tree
    log_name, api_type_of, handlers_of = HTTP_SOURCES[context.target_os]

    log_path = analysis_dir / log_name
    if not log_path.exists():
        # Not an error: the plugin that writes it is selectable, so a job that
        # did not run apimon/libmon simply has no HTTP evidence. Reported as
        # an empty list rather than a missing key, so a consumer can tell
        # "nothing was seen" from "this run did not look".
        context.update_report({"http_requests": [], "cracked_urls": []})
        return

    def filter_http(data: dict) -> Optional[dict]:
        if data.get("Event") != "api_called":
            return None
        method = trim_method_name(data.get("Method", ""))
        api_type = api_type_of(method)
        if not api_type:
            return None
        pid = data["PID"]
        process = process_tree.get_process_for_evtid(
            pid, int(data["EventUID"], 16))
        return {
            "process": process,
            # **None when the tree does not know the PID.** Reading
            # `.seqid` unguarded is what this used to do, and an API call
            # from a process procmon never saw crashed the whole plugin --
            # losing every request in the run, not just that one.
            "seqid": process.seqid if process is not None else None,
            "api_type": api_type,
            "method": method,
            "arguments": parse_apimon_arguments(data.get("Arguments", [])),
            "retval": int(data["ReturnValue"], 16)
            if data.get("ReturnValue") else None,
        }

    state = _State()
    handlers = handlers_of()
    for data in parse_log(log_path, filter_http):
        handler = handlers.get(data["method"])
        if handler is not None:
            handler(state, data, data["arguments"])

    requests = []
    for handle, request in state.request_handles.items():
        request_data = {k: v for k, v in request.items()
                        if k != "connection" and v}
        connection = request.get("connection", {})
        session = connection.get("session", {})
        request_data.update(
            {k: v for k, v in connection.items() if k != "session" and v})
        request_data.update({k: v for k, v in session.items() if v})
        request_data["process_seqid"] = handle[0]
        requests.append(request_data)

    context.update_report(
        {
            "http_requests": requests,
            "cracked_urls": [
                {"url": url, "process_seqids": sorted(
                    s for s in seqids if s is not None)}
                for url, seqids in state.cracked_urls.items()
            ],
        }
    )