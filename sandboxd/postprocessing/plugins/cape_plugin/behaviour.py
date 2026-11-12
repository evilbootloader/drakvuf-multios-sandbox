import datetime
import json
import logging
import mmap
import os
import re
import struct
import time
from collections import Counter, defaultdict, deque
from contextlib import suppress
from dataclasses import dataclass
from typing import Optional, Set

import orjson

from ....guests import TargetOs
from ...drakvuf_records import DRAKVUF_ADDRESSED_STRING, unescape_drakvuf, unescape_glib
from .abstracts import Processing
from .capa_integration import HAVE_FLARE_CAPA, flare_capa_details
from .api_kernel import KEY_OPEN_SERVICES, OBJECT_NAME_KEYS, registry_data, registry_full_name
from .api_tables import canonical, cape_aliases, returned_as_argument, settle_outputs
from .flags import CREATE_OPTIONS, DESIRED_ACCESS, flags_to_int, symbolic_to_hex
from .api_tables import category as api_category
from .network_map import SOCKADDR_ARGUMENTS, NetworkMap, parse_endpoint
from .syscall_origin import ORIGIN_API
from .syscall_origin import classify as syscall_origin

log = logging.getLogger(__name__)


@dataclass
class CapeOptions:
    """What CAPE reads from processing.conf's `[behavior]` section, plus the
    instance switches `BehaviorAnalysis` looks up by key."""
    analysis_call_limit: int = 0       # calls per process; 0 is no limit
    ram_boost: bool = False            # needs the BSON-era api_call_cache
    ram_mmap: bool = False
    replace_patterns: bool = False     # KNOWN GAP: CAPE's data/safelist is not vendored
    file_activities: bool = True
    capa: bool = True
    capa_rules: Optional[str] = None
    # The PIDs capa looks at (the sample's processes); None is every process.
    capa_pids: Optional[Set[int]] = None
    # For cape_plugin/modules.py: which processes' files, dumps and
    # connections are the sample's; the YARA rules; Falco's config section,
    # the clone's VLAN and the plugins the trace has records of.
    scope: str = "sample"
    sample_pids: Optional[Set[int]] = None
    yara_rules: Optional[str] = None
    falco: Optional[object] = None
    vlan: Optional[int] = None
    trace_plugins: Optional[Set[str]] = None
    # NetworkMap's NetworkFilter arguments (CapeConfigSection's network_*)
    network_filter: Optional[dict] = None


# -- from CAPEv2 lib/cuckoo/common/{path_utils,utils,replace_patterns_utils}.py
# (c7f57d04), the parts behaviour needs without CAPE's config and data/ tree.

def path_exists(path) -> bool:
    return os.path.exists(path)


def bytes2str(convert):
    if isinstance(convert, (bytes, bytearray)):
        try:
            return bytes(convert).decode()
        except UnicodeDecodeError:
            return "".join(chr(c) for c in convert)
    return convert


def default_converter(v):
    if isinstance(v, int):
        return v & 0xFFFFFFFFFFFFFFFF if v & 0xFFFFFFFF00000000 else v & 0xFFFFFFFF
    return v


def logtime(dt):
    t = time.strftime("%Y-%m-%d %H:%M:%S", dt.timetuple())
    return f"{t},{dt.microsecond // 1000:03d}"


def _clean_path(string, replace_patterns=False):
    # Upstream normalises sandbox usernames and paths from data/safelist; with
    # replace_patterns off -- the only setting here -- it is the identity.
    return string


# KNOWN GAP: CAPE's denylists (data/safelist/replacepatterns.py) are not
# vendored. check_deny_pattern runs only with replace_patterns on, which
# CapeOptions keeps off; these empty stand-ins let nothing through unchanged.
FILES_DENYLIST = ()
FILES_ENDING_DENYLIST = ()
SERVICES_DENYLIST = ()
REGISTRY_TRANSLATION = {}


def _is_regkey_ok(pattern):
    return True


def _is_mutex_ok(pattern):
    return True


def check_deny_pattern(container: list, pattern: str):
    if not pattern:
        return
    if any(deny_file in pattern for deny_file in FILES_DENYLIST):
        return
    if pattern.endswith(FILES_ENDING_DENYLIST):
        return
    if not _is_regkey_ok(pattern):
        return
    if pattern in SERVICES_DENYLIST:
        return
    if not _is_mutex_ok(pattern):
        return

    pattern = _clean_path(pattern, True)

    for key in REGISTRY_TRANSLATION.keys():
        if pattern.startswith(key):
            pattern = pattern.replace(key, REGISTRY_TRANSLATION[key])

    container.append(pattern)

# Keys every DRAKVUF record carries that describe the event rather than the
# call: never arguments. `Ret`/`Info` are sysret's, merged in by trace_split.
_COMMON_KEYS = frozenset((
    "Plugin", "TimeStamp", "PID", "PPID", "TID", "UserId", "UserName", "ProcessName",
    "Method", "EventUID", "ThreadName", "Module", "vCPU", "VCPU", "CR3", "Syscall",
    "NArgs", "PreviousMode", "FromModule", "FromParentModule", "Ret", "Info",
    "Event", "Caller", "ParentCaller", "ReturnValue", "Arguments", "Library", "CLSID", "Outputs",
    "Resolved", "Kernel",
    # Where a Windows syscall was made from (syscall_origin)
    "Bitness", "FromModuleCopy", "FromParentModuleCopy", "StubSyscall", "ParentCallTarget",
    "ParentCallTargetModule",
))


# The argument capemon logs a registry value's data under, per API
# (`api_tables.canonical` names: no A/W).
_REGMON_DATA_ARGUMENT = {
    "NtSetValueKey": "Buffer",
    "RegSetValueEx": "Buffer",
    "RegSetValue": "Buffer",
    "RegSetKeyValue": "Buffer",
    "SHSetValue": "Buffer",
    "NtQueryValueKey": "Information",
    "NtQueryMultipleValueKey": "Information",
    "NtEnumerateValueKey": "Information",
    "RegQueryValueEx": "Data",
    "RegQueryValue": "Data",
    "RegGetValue": "Data",
}

# Where an API names the registry key it works under, the sub-key and the
# value, in Microsoft's prototypes (hooks.txt) and the Nt* services'.
_REGISTRY_HANDLE_ARGUMENTS = ("hKey", "KeyHandle", "hkey", "hKeyRoot")
_REGISTRY_SUBKEY_ARGUMENTS = ("lpSubKey", "pszSubKey", "lpszSubKey", "SubKey")
_REGISTRY_VALUE_ARGUMENTS = ("lpValueName", "ValueName", "lpValue", "pszValue")
_REGISTRY_TYPE_ARGUMENTS = ("dwType", "Type")

# The registry APIs and services that operate on a VALUE, whose `FullName`
# ends in the value's name (`(Default)` for the unnamed one), as capemon's.
_REGISTRY_VALUE_APIS = frozenset((
    "NtSetValueKey", "NtQueryValueKey", "NtDeleteValueKey", "NtQueryMultipleValueKey",
    "RegSetValueEx", "RegSetValue", "RegSetKeyValue", "RegQueryValueEx", "RegQueryValue",
    "RegGetValue", "RegDeleteValue", "RegDeleteKeyValue", "SHSetValue", "SHGetValue",
    "SHRegGetValue", "SHDeleteValue",
))

# capemon's argument for the name of the object a service creates or opens.
_NAMED_OBJECT_ARGUMENT = {
    "NtCreateMutant": "MutexName", "NtOpenMutant": "MutexName",
    "CreateMutex": "MutexName", "CreateMutexEx": "MutexName", "OpenMutex": "MutexName",
    "NtCreateEvent": "EventName", "NtOpenEvent": "EventName",
    "CreateEvent": "EventName", "CreateEventEx": "EventName", "OpenEvent": "EventName",
}

# Where capemon logs a CLIENT_ID's process and thread: the names signatures
# read (ProcessIdentifier on NtOpenProcess, ProcessId elsewhere).
_CLIENT_ID_ARGUMENTS = {
    "NtOpenProcess": ("ProcessIdentifier", "ProcessId"),
    "NtOpenThread": ("ThreadId", "ProcessId"),
    "RtlCreateUserThread": ("ThreadId", "ProcessId"),
}
_CLIENT_ID = re.compile(r"\A\d+:\d+\Z")
_CONTEXT = re.compile(r"\A(?:[A-Za-z0-9]+=0x[0-9a-fA-F]+;)*[A-Za-z0-9]+=0x[0-9a-fA-F]+\Z")

# The APIs capemon logs `HandleName` for: the path of the file a handle is
# open on (hook_file.c), which apimon and filetracer resolve as `FileName`.
_HANDLE_NAME_APIS = frozenset(("NtReadFile", "NtWriteFile", "NtQueryInformationFile",
                               "NtSetInformationFile", "NtDeviceIoControlFile"))

# The APIs given a service handle, which capemon logs `ServiceName` for (the
# name it tracked the handle to); DRAKVUF prints the handle alone. And the
# ones that return such a handle, with the name.
_SERVICE_HANDLE_APIS = frozenset(("StartService", "ControlService", "ControlServiceEx",
                                  "DeleteService", "ChangeServiceConfig", "ChangeServiceConfig2"))
_SERVICE_OPEN_APIS = frozenset(("OpenService", "CreateService"))

# The APIs that create a process, whose `CommandLine` signatures read
# without asking whether it is there (capemon always logs it).
_PROCESS_CREATION_APIS = frozenset(("NtCreateUserProcess", "CreateProcessInternal",
                                    "CreateProcess", "CreateProcessAsUser",
                                    "CreateProcessWithLogon", "CreateProcessWithToken",
                                    "RtlCreateUserProcess"))


# A bare address: a pointer DRAKVUF printed without following it.
_ADDRESS = re.compile(r"\A0x[0-9a-fA-F]+\Z")


def _created_ids(rec):
    """capemon's `ProcessId` and `ThreadId` for what a creation made (procmon's
    NewPid/NewTid), in decimal as capemon logs them (format `i`): CAPE's
    get_name_from_pid takes a pid that is all digits, and a hex string is
    not."""
    out = []
    for name, key in (("ProcessId", "NewPid"), ("ThreadId", "NewTid")):
        value = rec.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            out.append({"name": name, "value": str(value)})
    return out


# A path in the NT object namespace that names a drive: `\??\C:\x` (and the
# Win32 `\\?\C:\x`). capemon logs it as `C:\x`.
_NT_DOS_PREFIX = re.compile(r"\A(?:\\\?\?\\|\\\\\?\\)(?=[A-Za-z]:)")

# The arguments capemon logs a file's path under.
_PATH_ARGUMENTS = ("FileName", "HandleName", "ExistingFileName", "NewFileName", "FilePath",
                   "DirectoryName", "PathName", "ApplicationName")


_REPEATED_SEPARATORS = re.compile(r"\\{2,}")


def resolved_path(path: str) -> str:
    """A Windows path as Windows resolves it: a run of separators is one,
    as path normalization makes it (`C:\\x\\\\y.dll` opens `C:\\x\\y.dll`;
    a caller joining a directory and a name produces such runs). Not the
    leading two of a UNC path, and not a `\\\\?\\` path, which Windows takes
    verbatim."""
    if path.startswith("\\\\?\\"):
        return path
    if path.startswith("\\\\"):
        return "\\\\" + _REPEATED_SEPARATORS.sub(r"\\", path[2:].lstrip("\\"))
    return _REPEATED_SEPARATORS.sub(r"\\", path)


def _address(value):
    """A call's caller/parentcaller as CAPE reports it: hex, and
    "0x00000000" when there is none."""
    return value if isinstance(value, str) and value.startswith("0x") else "0x00000000"


def _cape_value(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return hex(value)
    return str(value)


def _epoch_datetime(ts):
    try:
        return datetime.datetime.fromtimestamp(float(ts or 0), tz=datetime.timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc)


def _parse_int(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        with suppress(ValueError):
            return int(value, 0)
    return None


def _syscall_ok(ret, linux):
    """NT_SUCCESS on Windows; on Linux, not one of the -4095..-1 the kernel
    returns as -errno. None when the call never returned (unpaired)."""
    value = _parse_int(ret)
    if value is None:
        return None
    if linux:
        value &= 0xFFFFFFFFFFFFFFFF
        return not (value >= 0xFFFFFFFFFFFFF001)
    return (value & 0xFFFFFFFF) < 0x80000000


class JsonParser:
    """Reads one `trace_split` per-process log, the JSON-lines counterpart of
    CAPE's BsonParser: each record becomes one call on the ParseProcessLog it
    reads for, through that log's `log_*` methods."""

    def __init__(self, fd, task_id=None):
        self.fd = fd
        self.pid = None
        self.task_id = task_id

    def close(self):
        pass

    def get_api_arguments(self, arguments):
        """apimon/libmon's `name=value` strings as CAPE `{name, value}`.

        Three forms reach here, and they are told apart by the address:

        * `name=0xADDR:"text"`, a string argument, from DRAKVUF's string
          printers with DRAKVUF's own escaping (`drakvuf_records.py`): the
          value is the unescaped text, as CAPE's monitor reports a string;
        * `name=0x...`, a number, kept as printed;
        * `name=text`, a value apimon RESOLVED and appended after the
          argument it came from (apimon.cpp, 2026-11-10): `FileName=` after
          an ObjectAttributes or a FileHandle, `Key=` after a Reg* hKey,
          `CommandLine=` after NtCreateUserProcess's ProcessParameters,
          `FilePath=`/`Parameters=`/`Show=` after ShellExecuteExW's
          pExecInfo. It is the text itself, neither quoted nor escaped --
          a command line that starts and ends with a quote is still just
          the command line -- so it is kept as it is. Its name can be one
          the API already has (NtWriteFile's own `Key` parameter): the
          first of a name wins wherever one is looked up, and both stay.
        """
        result = []
        for arg in arguments or ():
            name, sep, value = str(arg).partition("=")
            if not sep:
                result.append({"name": name, "value": ""})
                continue
            m = DRAKVUF_ADDRESSED_STRING.match(value)
            if m:
                value = unescape_drakvuf(m.group(1))
            result.append({"name": name, "value": value})
        return result

    def read_next_message(self, platform):
        """Hand the next record that is a call to the log; True, or False at EOF."""
        while True:
            try:
                data = self.fd.readline()
            except EOFError:
                return False
            if not data:
                return False

            try:
                dec = orjson.loads(data)
            except orjson.JSONDecodeError as e:
                log.warning("JsonParser decoding problem %s on data[:50] %s", e, data[:50])
                continue

            if self.handle_message(dec, platform):
                return True

    def handle_message(self, dec, platform):
        """Hand one decoded record to the log, as the call (or process
        header) it is; False for a record that is not one."""
        before = self.fd.lastcall
        handled = self._dispatch(dec, platform)
        call = self.fd.lastcall
        if handled and call is not None and call is not before:
            self.fd.finish_call(call)
        return handled

    def _dispatch(self, dec, platform):
        mtype = dec.get("Plugin", "none")
        index = dec.get("EventUID", -1)
        tid = dec.get("TID", -1)
        time = dec.get("TimeStamp", 0)
        pid = dec.get("PID", -1)
        ppid = dec.get("PPID", -1)

        context = [index, 1, 0, tid, time, pid, ppid, mtype]

        if mtype == "__process__":
            # trace_split's header, in place of CAPE's __process__ message.
            self.fd.log_process(context, _epoch_datetime(time), pid, ppid,
                                dec.get("ModulePath", ""), dec.get("ProcessName", ""))
            self.fd.log_environ(context, {"CommandLine": dec.get("CommandLine", "")})
            self.fd.log_identity(dec)
            return True

        elif mtype == "syscall":
            self.fd.log_syscall(context, dec)
    
        elif mtype == "apimon":
            if dec.get("Event") == "api_called":
                apiname, retval, caller, parentcaller = dec["Method"], dec.get("ReturnValue", None), dec.get("Caller", None), dec.get("ParentCaller", None)
                arguments = self.get_api_arguments(dec.get("Arguments", []))
                context[2] = retval
                # `Kernel`: the kernel-side records of this same call, from
                # trace_split._CallMerger.
                self.fd.log_api(context, apiname, caller, parentcaller, arguments, dec.get("Kernel"))

            elif dec.get("Event") in ("dll_loaded", "dll_discovered"):
                # dll_discovered: a module apimon found mapped, hooked or
                # not; dll_loaded: one whose hooks it placed. Either way
                # the process has that DLL at that base, which is what
                # CAPE's DllLoadNotification tells its consumers.
                apiname = "DllLoadNotification"
                arguments = [
                    {"name": "Event", "value": "load"},
                    {"name": "DllName", "value": dec.get("DllName", "")},
                    {"name": "DllBase", "value": dec.get("DllBase", "")},
                ]
                self.fd.log_api(context, apiname, None, None, arguments)
            else:
                return False

        elif mtype == "libmon":
            if dec.get("Event") != "api_called":
                return False
            apiname, retval, caller, parentcaller = dec["Method"], dec.get("ReturnValue"), dec.get("Caller", None), dec.get("ParentCaller", None)
            arguments = self.get_api_arguments(dec.get("Arguments", []))
            context[2] = retval
            self.fd.log_api(context, apiname, caller, parentcaller, arguments, dec.get("Kernel"))

        elif mtype == "regmon":
            apiname, key, valuename, value = dec["Method"], dec.get("Key"), dec.get("ValueName"), dec.get("Value")
            self.fd.log_regmon(context, apiname, key, valuename, value)

        elif mtype == "filetracer":
            apiname, operation, filehandle, filename = dec["Method"], dec.get("Operation", ""), dec.get("FileHandle", ""), dec.get("FileName")
            # Linux filetracer hooks the syscall entry: Method is always
            # do_syscall_64 and the call is in `Syscall`, by name.
            if isinstance(dec.get("Syscall"), str):
                apiname = dec["Syscall"]
            self.fd.log_filetracer(context, apiname, operation, filehandle, filename, dec)

        elif mtype == "socketmon" and dec.get("DnsName") is not None:
            # socketmon's hook on dnsapi's DnsQuery_* family: the call
            # capemon logs as DnsQuery_A / DnsQuery_W, with the name as `Name`.
            method = str(dec.get("Method") or "DnsQuery_W")
            apiname = "DnsQuery_A" if method.endswith(("_A", "A")) else "DnsQuery_W"
            self.fd.log_api(context, apiname, None, None, [{"name": "Name", "value": dec["DnsName"]}])

        elif mtype == "socketmon":
            apiname, protocol, remoteip, remoteport, localip, localport = dec["Method"], dec.get("Protocol"), dec.get("RemoteIp"), dec.get("RemotePort"), dec.get("LocalIp"), dec.get("LocalPort")
            self.fd.log_socketmon(context, apiname, protocol, remoteip, remoteport, localip, localport,
                                  dec.get("Value"))

        elif mtype == "unixsocketmon":
            sockettype = str(dec.get("Type", ""))
            if sockettype.startswith("AF_INET"):
                data = [dec.get("Protocol"), dec.get("RemoteIp"), dec.get("RemotePort"),
                        dec.get("LocalIp"), dec.get("LocalPort"), dec.get("Value")]
            elif sockettype.startswith("AF_LOCAL"):
                data = [dec.get("RemotePath", ""), dec.get("LocalPath", ""), dec.get("Value")]
            else:
                return False
            # The rest of the record, for signatures: the send's size, a
            # listen's backlog, whether the socket was connected.
            data.append({"sockettype": sockettype, "size": dec.get("Size"),
                         "backlog": dec.get("Backlog"), "connected": dec.get("Connected")})
            self.fd.log_unixsocketmon(context, dec["Method"], sockettype, data)

        elif mtype == "procmon":
            # The tree was built from these before the split
            # (trace_split.read_prelude); here they are calls like any
            # other, so a signature can see NtCreateUserProcess or
            # kernel_clone with its arguments.
            self.fd.log_procmon(context, dec)

        elif mtype == "cpuidmon":
            leaf, subleaf, rax, rbx, rcx, rdx = dec.get("Leaf"), dec.get("Subleaf"), dec.get("RAX"), dec.get("RBX"), dec.get("RCX"), dec.get("RDX")
            self.fd.log_cpuidmon(context, leaf, subleaf, rax, rbx, rcx, rdx)

        elif mtype in ("ptracemon", "debugmon", "ebpfmon"):
            # A process's own detections, for the Anomaly module
            self.fd.log_event(context, dec)

        else:
            return False

        return True


class ParseProcessLog(list):
    """Parses process log file."""

    def __init__(self, log_path, options, platform):
        """@param log_path: log file path."""
        self._log_path = log_path
        self.fd = None
        self.reporting_mode = False
        self.process_id = None
        self.process_name = None
        self.parent_id = None
        self.module_path = None
        # Using an empty initializer here allows the assignment of current_log.threads in the Processes run()
        # method to get a reference to the threads list we eventually build up by fully parsing a log
        # via the behavior analysis that happens later.  By the time the results dict is used later
        # to extract this information, it will finally have valid info.
        self.threads = []
        self.first_seen = None
        # trace_split's identity of the process (log_identity)
        self.identity = {}
        self.calls = self
        self.lastcall = None
        # Calls one record makes beside `lastcall`, taken after it (log_syscall)
        self.queued = deque()
        self.environdict = {}
        self.api_count = 0
        self.call_id = 0
        self.conversion_cache = {}
        self.options = options
        self.options.ram_mmap = False # self.options.ram_mmap if self.options.ram_mmap else False
        # Limit of API calls per process
        self.api_limit = self.options.analysis_call_limit
        self.platform = platform
        # service handle -> service name, from OpenService/CreateService
        # (_cape_names): this process's, in call order
        self._service_handles = {}

        if path_exists(log_path) and os.stat(log_path).st_size > 0:
            self.parse_first_and_reset()

    def close(self):
        if hasattr(self, "mv") and self.mv:
            self.mv.release()
            self.mv = None
        if hasattr(self, "mm") and self.mm:
            self.mm.close()
            self.mm = None
        if self.fd:
            self.fd.close()
            self.fd = None

    def parse_first_and_reset(self):
        """Open file and init Bson Parser. Read till first process"""
        if not self._log_path.endswith(".log"):
            return

        self.fd = open(self._log_path, "rb")

        self.use_mmap = False
        self.mm = None
        self.mv = None
        self.mm_pos = 0

        """
        if self.options.ram_mmap:
            try:
                self.mm = mmap.mmap(self.fd.fileno(), 0, access=mmap.ACCESS_READ)
                self.mv = memoryview(self.mm)
                self.use_mmap = True
            except (ValueError, OSError) as e:
                log.debug("mmap failed, falling back to standard file reading: %s", e)
        """
        
        self.parser = JsonParser(self)

        # Get the process information from file
        # Note that we have to read in all messages until we
        # get all the information we need, so the invariant below
        # should involve the last process-related bit of
        # information logged
        # Environment info will be filled in as the log is read
        # and will be stored by reference into the results dict.
        # trace_split writes the __process__ header first, so this reads one
        # line; a log without one is read to EOF and left unnamed (skipped).
        while self.process_id is None:
            if not self.parser.read_next_message(self.platform):
                break
        self.lastcall = None

        if self.use_mmap:
            self.mm_pos = 0
        elif self.fd:
            self.fd.seek(0)

    def read(self, length):
        """Read data from log file

        @param length: Length in byte to read
        """
        if not length or length < 0:
            return b""

        if self.use_mmap:
            if self.mm_pos + length > len(self.mm):
                raise EOFError()
            buf = self.mv[self.mm_pos : self.mm_pos + length]
            self.mm_pos += length
            return buf

        buf = self.fd.read(length)
        if not buf or len(buf) != length:
            raise EOFError()
        return buf


    def readline(self, length=-1):
        """Read one line from the log file; EOFError at its end.

        @param length: ignored except under mmap, which is never on
        """

        if self.use_mmap:
            if self.mm_pos + length > len(self.mm):
                raise EOFError()
            buf = self.mv[self.mm_pos : self.mm_pos + length]
            self.mm_pos += length
            return buf

        buf = self.fd.readline()
        if not buf:
            raise EOFError()
        return buf

    def __iter__(self):
        # import inspect
        # log.debug("iter called by: %s", inspect.stack()[1])
        # import code; code.interact(local=dict(locals(), **globals()))
        return self

    def __repr__(self):
        return f"<ParseProcessLog log-path: {self._log_path}>"

    def __nonzero__(self):
        return self.wait_for_lastcall()

    def reset(self):
        """Reset fd"""
        if self.use_mmap:
            self.mm_pos = 0
        elif self.fd:
            self.fd.seek(0)
        self.api_count = 0
        self.lastcall = None
        self.queued.clear()
        self.call_id = 0
        self.api_pointer = 0
        self._service_handles = {}

    def compare_calls(self, a, b):
        """Compare two calls for equality. Same implementation as before netlog.
        @param a: call a
        @param b: call b
        @return: True if a == b else False
        """
        return (
            (a.get("api") or a.get("syscall")) == (b.get("api") or b.get("syscall")) and a["return"] == b["return"] and a["arguments"] == b["arguments"]
        )

    def wait_for_lastcall(self):
        """If there is no lastcall, iterate through messages till a call is found or EOF.
        To get the next call, set self.lastcall to None before calling this function

        @return: True if there is a call, False on EOF
        """
        while not self.lastcall:
            if self.queued:
                self.lastcall = self.queued.popleft()
                break
            try:
                if not self.parser.read_next_message(self.platform):
                    return False
            except EOFError:
                return False

        return True

    def cacheless_next(self):
        if not self.fd:
            raise StopIteration()

        if not self.wait_for_lastcall():
            self.reset()
            raise StopIteration()

        self.api_count += 1
        if self.api_limit and self.api_count > self.api_limit:
            self.reset()
            raise StopIteration()

        nextcall, self.lastcall = self.lastcall, None

        self.wait_for_lastcall()
        while self.lastcall and self.compare_calls(nextcall, self.lastcall):
            nextcall["repeated"] += self.lastcall["repeated"] + 1
            self.lastcall = None
            self.wait_for_lastcall()

        nextcall["id"] = self.call_id
        self.call_id += 1

        return nextcall

    def __next__(self):
        """Just accessing the cache"""

        if not self.options.ram_boost:
            return self.cacheless_next()
        res = self.api_call_cache[self.api_pointer]
        if res is None:
            self.reset()
            raise StopIteration()
        self.api_pointer += 1
        return res

    def call_from_line(self, line):
        """The call one line of this log is, parsed as iteration parses it
        (minus the merging of repeats), or None for the header and records
        that are no call. For readers that seek by offset -- the capa pass
        reads one thread's calls at a time. Not while iterating `calls`: it
        shares `lastcall` with the iterator."""
        try:
            dec = orjson.loads(line)
        except orjson.JSONDecodeError:
            return None
        if not isinstance(dec, dict) or dec.get("Plugin") == "__process__":
            return None
        self.lastcall = None
        self.parser.handle_message(dec, self.platform)
        call, self.lastcall = self.lastcall, None
        # The line's own call only: what log_syscall queued beside it is not the line's
        self.queued.clear()
        return call

    def log_process(self, context, timestring, pid, ppid, modulepath, procname):
        """log process information parsed from data file

        @param context: ignored
        @param timestring: Process first seen time
        @param pid: PID
        @param ppid: Parent PID
        @param modulepath: ignored
        @param procname: Process name
        """
        self.process_id, self.parent_id, self.process_name = pid, ppid, procname
        self.module_path = modulepath
        self.first_seen = timestring

    def log_identity(self, header):
        """What trace_split's header says beyond CAPE's __process__ message:
        the process's seqid and its parent's (the tree's identity, which a
        reused PID cannot confuse), its start as a number, and how it ended.
        Additions to CAPE's process, for the platform's report."""
        def number(key):
            value = header.get(key)
            return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None
        self.identity = {
            "seqid": number("Seqid"),
            "parent_seqid": number("ParentSeqid"),
            "started_ts": number("TimeStamp"),
            "exited_ts": number("ExitTimeStamp"),
            "exit_code": number("ExitCode"),
            "exit_code_str": header.get("ExitCodeStr") if isinstance(header.get("ExitCodeStr"), str) else None,
            "killed_by": number("KilledBy"),
        }

    def log_thread(self, context, pid):
        pass

    def log_environ(self, context, environdict):
        """log user/process environment information for later use in behavioral signatures

        @param context: ignored
        @param environdict: dict of the various collected information, which will expand over time
        """
        environdict = bytes2str(environdict)
        if self.options.replace_patterns:
            for key in ("UserName", "ComputerName", "TempPath", "CommandLine"):
                environdict[key] = _clean_path(environdict[key], self.options.replace_patterns)
        self.environdict.update(environdict)

    def log_anomaly(self, subcategory, tid, funcname, msg):
        """log an anomaly parsed from data file

        @param subcategory:
        @param tid: Thread ID
        @param funcname:
        @param msg:
        """
        self.lastcall = {
            "thread_id": tid,
            "category": "anomaly",
            "api": "",
            "subcategory": subcategory,
            "funcname": funcname,
            "msg": msg,
        }

    def log_api(self, context, apiname, caller, parentcaller, arguments, kernel=None):
        """log an api call from data file
        @param context: containing additional api info
        @param apiname: name of the api
        @param caller: return address (apimon) or calling module (libmon)
        @param arguments: arguments to the api call
        @param kernel: the kernel-side records of the same call, or None
        """
        index, repeated, returnval, tid, time, pid, ppid, mtype = context

        self.lastcall = self._parse_api(
            [time, tid, caller, parentcaller, mtype, apiname, returnval] + arguments, kernel
        )

    def log_syscall(self, context, dec):
        """log a syscall, merged with its sysret by trace_split (`Ret`, `Info`).
        A syscall made where the system makes none (syscall_origin) is
        followed by the call capemon logs for one on Windows: an API call,
        which is what signatures read -- the syscall itself is the kernel's
        side."""
        index, repeated, returnval, tid, time, pid, ppid, mtype = context
        self.lastcall = self._parse_syscall(time, tid, mtype, dec)
        origin = syscall_origin(dec, linux=self.platform != TargetOs.WINDOWS)
        if origin is not None:
            call = self._origin_call(time, tid, dec, origin)
            self.finish_call(call)
            self.queued.append(call)

    def _origin_call(self, timestamp, thread_id, dec, origin):
        """capemon's call for a syscall made outside ntdll: `Return Address`
        and `Module` its frame 0, `caller` the sample's code that made it --
        what CAPE's direct_syscall_evasion and unbacked_syscall_execution
        read -- and the technique, the service and what gave it away."""
        arguments = [
            {"name": "Return Address", "value": origin.address},
            {"name": "Module", "value": origin.module},
            {"name": "Service", "value": dec.get("Method", "")},
            {"name": "Technique", "value": origin.technique},
            {"name": "Evidence", "value": origin.evidence},
        ]
        call = self._call(timestamp, thread_id, "syscall", ORIGIN_API, dec.get("Ret"), arguments)
        call["caller"] = _address(origin.caller)
        call["parentcaller"] = _address(origin.parentcaller)
        return call

    def log_procmon(self, context, dec):
        """log a procmon event (process creation, exit, open, ...) as a call."""
        index, repeated, returnval, tid, time, pid, ppid, mtype = context
        self.lastcall = self._parse_procmon(time, tid, mtype, dec)

    def log_event(self, context, dec):
        """log a kernel-side detection (ptracemon, debugmon, ebpfmon) as a call."""
        index, repeated, returnval, tid, time, pid, ppid, mtype = context
        self.lastcall = self._parse_event(time, tid, mtype, dec)

    def log_cpuidmon(self, context, leaf, subleaf, rax, rbx, rcx, rdx):
        """log a cpuid instruction from data file
        @param context: containing additional syscall info
        @param leaf: requested leaf (EAX)
        @param subleaf: requested subleaf (ECX)
        @param rax: result part 1
        @param rbx: result part 2
        @param rcx: result part 3
        @param rdx: result part 4
        """

        index, repeated, returnval, tid, time, pid, ppid, mtype = context

        arguments = [leaf, subleaf, rax, rbx, rcx, rdx]

        self.lastcall = self._parse_cpuidmon(
            [time, tid, mtype, "cpuid"] + arguments
        )

    def log_regmon(self, context, apiname, key, valuename, value):
        """log an api call from data file
        @param context: containing additional api info
        @param apiname: name of the api
        @param key: Registry Key
        @param valuename: Value Name of the registry key
        @param value: value inside Value Name
        """

        index, repeated, returnval, tid, time, pid, ppid, mtype = context

        self.lastcall = self._parse_regmon(
            [time, tid, mtype, apiname, key, valuename, value]
        )

    def log_filetracer(self, context, apiname, operation, filehandle, filename, dec=None):
        """log an api call from data file
        @param context: containing additional api info
        @param apiname: name of the api
        @param operation: operation, can be None
        @param filehandle: handle to the file, can be none
        @param filename: accessed file name
        @param dec: the whole record, for the rest of its parameters
        """

        index, repeated, returnval, tid, time, pid, ppid, mtype = context

        self.lastcall = self._parse_filetracer(
            [time, tid, mtype, apiname, operation, filehandle, filename, dec or {}]
        )

    def log_socketmon(self, context, apiname, protocol, remoteip, remoteport, localip, localport, value=None):
        """log an api call from data file
        @param context: containing additional api info
        @param apiname: name of the api
        @param protocol: IP protocol
        @param remoteip: Remote IP
        @param remoteport: Remote Port
        @param localip: Local IP
        @param localport: Local Port
        @param value: the bytes sent, for an AFD send (AfdSend)
        """

        index, repeated, returnval, tid, time, pid, ppid, mtype = context

        self.lastcall = self._parse_socketmon(
            [time, tid, mtype, apiname,  protocol, remoteip, remoteport, localip, localport, value]
        )


    def log_unixsocketmon(self, context, apiname, sockettype, data):

        index, repeated, returnval, tid, time, pid, ppid, mtype = context

        self.lastcall = self._parse_unixsocketmon(
            [time, tid, mtype, apiname, sockettype] + data
        )

    def log_error(self, emsg):
        """Log an error"""
        log.warning("ParseProcessLog error condition on log %s: %s", self._log_path, emsg)

    def begin_reporting(self):
        self.reporting_mode = True
        if self.options.ram_boost:
            idx = 0
            ent = self.api_call_cache[idx]
            while ent:
                # remove the values we don't want to encode in reports
                for arg in ent["arguments"]:
                    with suppress(KeyError):
                        if "raw_value" in arg:
                            del arg["raw_value"]
                        elif "raw_value_string" in arg:
                            del arg["raw_value_string"]
                idx += 1
                ent = self.api_call_cache[idx]

    def _call(self, timestamp, thread_id, plugin, api_name, return_value, arguments, status=True):
        """A call in CAPE's shape, with every key CAPE's consumers index
        unconditionally: `category` (per API, categories.py), `status`,
        `return`, `arguments` as `{name, value}`, `repeated` (cacheless_next
        adds to it). `status` is True where DRAKVUF reports no outcome --
        apimon, libmon, regmon -- since the call was made; syscalls and
        filetracer carry a real one."""
        thread_id = str(thread_id)
        # apimon's dll events carry no TID (-1 here): not a thread.
        if thread_id not in self.threads and thread_id.isdigit():
            self.threads.append(thread_id)
        linux = self.platform != TargetOs.WINDOWS
        # capemon logs every value as text, and signatures rely on it
        # (`int(value, 16)`, `value.lower()`, `"x" in value`): numbers as
        # hex, nothing as the empty string.
        for arg in arguments:
            value = arg.get("value")
            if not isinstance(value, str):
                arg["value"] = _cape_value(value)
        return {
            "timestamp": timestamp,
            "thread_id": thread_id,
            # Both always present and hex, as in a CAPE report; apimon's
            # Caller replaces `caller` where there is one.
            "caller": "0x00000000",
            "parentcaller": "0x00000000",
            "plugin": plugin,
            "category": api_category(api_name, plugin, linux),
            "api": api_name,
            "status": status,
            "return": return_value,
            "arguments": arguments,
            "repeated": 0,
        }

    @staticmethod
    def _record_arguments(dec, typed=False):
        """Every parameter of a raw record, as CAPE arguments. `Type` is a
        parameter on Windows (NtSetValueKey's value type, in hex) and the
        syscall's ABI on Linux (`x64`), which is not one -- unless the record
        is `typed`: ptracemon's request, ebpfmon's program type."""
        return [{"name": k, "value": v} for k, v in dec.items()
                if k not in _COMMON_KEYS
                and (typed or not (k == "Type" and isinstance(v, str) and not v.startswith("0x")))]

    def _parse_api(self, row, kernel=None):
        """Parse log row.
        @param row: row data.
        @param kernel: the kernel-side records of the same call
                       (trace_split._CallMerger), folded into it.
        @return: parsed information dict.
        """
        arguments = []

        try:
            timestamp = row[0]  # Timestamp of current API call invocation.
            thread_id = row[1]  # Thread ID.
            caller = row[2]  # non-system DLL return address
            parentcaller = row[3]
            mtype = row[4]  # plugin
            api_name = row[5]  # Name of the Windows API.
            return_value = row[6]  # Value returned by the function.
        except IndexError as e:
            log.debug("Unable to parse process log row: %s", e)
            return None

        # ntdll exports every service twice, `Nt` and `Zw`, at one address,
        # and a hook list line can name either (ZwOpenKeyEx,
        # ZwSetInformationFile). capemon and every signature say `Nt`.
        if mtype == "apimon" and api_name.startswith("Zw") and api_name[2:3].isupper():
            api_name = "Nt" + api_name[2:]

        # Now walk through the remaining columns, which will contain API arguments.

        for arg in row[7:]:
            if not isinstance(arg, dict):
                continue

            name = arg.get("name")
            if name:
                arguments.append({
                    "name": name,
                    "value": arg.get("value"),
                })

            """ CHECK
            arg_value_raw = arg_value
            if isinstance(arg_value, bytes):
                arg_value = bytes2str(arg_value)

            if arg_value and isinstance(arg_value, list) and len(arg_value) >= 1 and isinstance(arg_value[0], bytes):
                arg_value = " ".join(bytes2str(arg_value))

            try:
                argument["value"] = convert_to_printable(arg_value, self.conversion_cache)
            except Exception:
                log.exception(arg_value)
                continue
            if not self.reporting_mode:
                if isinstance(arg_value_raw, bytes):
                    argument["raw_value"] = bytes.hex(arg_value_raw)
                elif isinstance(arg_value_raw, int) and arg_value_raw > 0x7FFFFFFFFFFFFFFF:
                    # Mongo can't support ints larger than this.
                    argument["raw_value_string"] = str(arg_value_raw)
                else:
                    argument["raw_value"] = arg_value
            pretty = pretty_print_arg(category, api_name, arg_name, argument["value"])
            if pretty:
                argument["pretty_value"] = pretty

            
            """

        arguments = returned_as_argument(api_name, arguments, return_value)

        thread_id = str(thread_id)
        # apimon's dll events carry no TID (-1 here): not a thread.
        if thread_id not in self.threads and thread_id.isdigit():
            self.threads.append(thread_id)
        linux = self.platform != TargetOs.WINDOWS

        call = {
            "timestamp": timestamp,
            "thread_id": thread_id,
            # Both always present and hex, as in a CAPE report: apimon's and
            # libmon's Caller. DRAKVUF prints no ParentCaller since
            # 2026-11-11 -- no CAPE signature reads it -- so parentcaller is
            # CAPE's "none".
            "caller": _address(caller),
            "parentcaller": _address(parentcaller),
            "plugin": mtype,
            "category": api_category(api_name, mtype, linux),
            "api": api_name,
            "status": True,
            "return": return_value,
            "arguments": cape_aliases(api_name, settle_outputs(api_name, mtype, arguments)),
            "repeated": 0,
        }

        """ CHECK
        if isinstance(return_value, int):
            call["return"] = f"0x{default_converter(return_value):08x}"
        else:
            call["return"] = convert_to_printable(str(return_value), self.conversion_cache)

        prettyret = pretty_print_retval(call["status"], call["return"])
        if prettyret:
            call["pretty_return"] = prettyret
        """

        if (
            api_name == "DllLoadNotification"
            and len(arguments) == 3
            and arguments[-1].get("name", "") == "DllBase"
            and arguments[0].get("value", "") == "load"
            and "DllBase" not in self.environdict
        ):
            self.environdict.setdefault("DllBase", arguments[-1]["value"])

        # What the kernel saw of this same call: the key and the data behind
        # a registry handle, the file behind a file handle, the process a
        # creation made. finish_call then derives capemon's names from it.
        for record in kernel or ():
            self._fold_resolved(call, record)

        return call

    def finish_call(self, call):
        """What every call gets once parsed, whichever plugin it came from:
        its values as text (capemon logs every value as text, and signatures
        rely on it: `int(value, 16)`, `value.lower()`, `"x" in value`), the
        names capemon computes (`_cape_names`), and `raw_value`."""
        for arg in call["arguments"]:
            if not isinstance(arg.get("value"), str):
                arg["value"] = _cape_value(arg.get("value"))
        self._cape_names(call)
        self._raw_values(call)

    @staticmethod
    def _raw_values(call):
        """`raw_value` beside each `value`, which is what a signature's
        `get_raw_argument` reads (`int(raw, 16)` on an information class or
        a set of flags). CAPE keeps the value before its pretty-printing
        there; DRAKVUF's are never pretty-printed, so it is the value."""
        for arg in call["arguments"]:
            arg.setdefault("raw_value", arg["value"])

    def _cape_names(self, call):
        """The arguments capemon logs that no parameter holds, from what the
        call now has -- its own arguments, what apimon resolved and appended
        (`Key=`, `FileName=`), and the kernel-side records folded into it.

        * `FullName`, a registry call's key path with, for a value, its
          name: the first thing every registry signature reads, and reads
          without asking whether it is there. Always present on a registry
          call, empty when nothing could be resolved.
        * the value's data, under capemon's name for it (`Buffer`), from
          regmon -- over what the API's own data pointer printed, which is
          an address or the first characters of a wide string read as ANSI.
        * `HandleName`, the path of the file a handle is open on.
        * `CommandLine` on a process creation: always present.
        """
        name = canonical(call.get("api") or call.get("syscall") or "")
        arguments = call["arguments"]
        by_name = {}
        for arg in arguments:
            by_name.setdefault(arg["name"], arg)

        def text(*names):
            """The first of `names` the call has as text; a bare address is
            a pointer DRAKVUF did not follow, not a name."""
            for n in names:
                arg = by_name.get(n)
                if arg is not None and isinstance(arg["value"], str) and not _ADDRESS.match(arg["value"]):
                    return arg["value"]
            return None

        def put(n, value, replace=False):
            arg = by_name.get(n)
            if arg is None:
                arg = by_name[n] = {"name": n, "value": value}
                arguments.append(arg)
            elif replace:
                arg["value"] = value

        if self.platform == TargetOs.WINDOWS and call["category"] == "registry":
            # The key the kernel resolved for this call, else what apimon
            # read out of the ObjectAttributes of an Nt* key service: as
            # `Key` (handle_key below) since 2026-11-11, as a `FileName`
            # in \REGISTRY before.
            key = call.get("key")
            if not key:
                resolved = text("FileName")
                if resolved and resolved.upper().startswith("\\REGISTRY"):
                    key = resolved
            handle_key = text("Key")
            if handle_key and not handle_key.startswith("\\"):
                handle_key = None
            root = by_name.get(next((n for n in _REGISTRY_HANDLE_ARGUMENTS if n in by_name), ""))
            # A value's name: regmon's, else the API's own argument (`""` is
            # a NULL name, the default value). A value API with no such
            # argument at all (RegSetValue, RegQueryValue) works on the
            # default value; one whose argument is a pointer nothing
            # followed names a value nobody knows, so only the key is given.
            is_value = name in _REGISTRY_VALUE_APIS
            value_name = call.get("valuename")
            if value_name is None:
                value_name = text(*_REGISTRY_VALUE_ARGUMENTS)
            if is_value and value_name is None and any(n in by_name for n in _REGISTRY_VALUE_ARGUMENTS):
                is_value = False
            full = registry_full_name(
                key=key, handle_key=handle_key, root=root["value"] if root else None,
                subkey=text(*_REGISTRY_SUBKEY_ARGUMENTS), value_name=value_name, is_value=is_value)
            put("FullName", full, replace=bool(full))

            data_name = _REGMON_DATA_ARGUMENT.get(name)
            if data_name and call.get("value") is not None:
                reg_type = by_name.get(next((n for n in _REGISTRY_TYPE_ARGUMENTS if n in by_name), ""))
                put(data_name, registry_data(call["value"], reg_type["value"] if reg_type else None),
                    replace=True)

        if name in _HANDLE_NAME_APIS:
            filename = call.get("filename") or text("FileName")
            if filename:
                put("HandleName", filename)

        # A path as capemon logs it: `C:\x`, not the NT `\??\C:\x` that
        # filetracer and apimon resolve. The NT path stays under its own
        # name where one was given (`filename` on the call).
        for n in _PATH_ARGUMENTS:
            arg = by_name.get(n)
            if arg is not None and isinstance(arg["value"], str):
                arg["value"] = _NT_DOS_PREFIX.sub("", arg["value"])

        if name in _PROCESS_CREATION_APIS:
            put("CommandLine", "")

        # What an OBJECT_ATTRIBUTES names, where capemon logs it in place of
        # the argument (NtCreateSection, NtOpenDirectoryObject, NtOpenKey...;
        # signatures read `ObjectAttributes` as the name): DRAKVUF's
        # `ObjectName`, and a key service's `Key`, the key it opens.
        named = text("ObjectName") or (text("Key") if name in KEY_OPEN_SERVICES else None)
        if named and "ObjectAttributes" in by_name:
            put("ObjectAttributes", named, replace=True)

        # capemon's name for the object a mutant or event service named.
        # DRAKVUF names it so itself since 2026-11-11; a trace from before
        # has it as `FileName` (or, older still, the ObjectAttributes
        # argument itself), whatever the object.
        object_name = _NAMED_OBJECT_ARGUMENT.get(name)
        if object_name:
            found = text("FileName", "ObjectAttributes", "lpName", "Name")
            if found:
                put(object_name, found)

        # A CLIENT_ID DRAKVUF decoded ("pid:tid", printers' pclient_id), as
        # capemon names its halves: in decimal, as it logs them.
        ids = _CLIENT_ID_ARGUMENTS.get(name)
        client = text("ClientId")
        if ids and client and _CLIENT_ID.match(client):
            pid, tid = client.split(":")
            for n in ids:
                put(n, tid if n == "ThreadId" else pid)

        # A thread CONTEXT DRAKVUF decoded (printers' pcontext,
        # "Dr0=0x0;...;Rip=0x..."): each register as an argument, as capemon
        # logs the debug registers a hardware-breakpoint signature reads.
        if name in ("NtSetContextThread", "SetThreadContext"):
            context = text("Context", "lpContext")
            if context and _CONTEXT.match(context):
                for field in context.split(";"):
                    register, _, value = field.partition("=")
                    put(register, value)

        # NtDelayExecution's interval (printers' plarge_integer): negative is
        # relative, in 100 ns units, which capemon logs as Milliseconds;
        # positive is an absolute time, no duration.
        if name == "NtDelayExecution":
            interval = _parse_int(text("DelayInterval"))
            if interval is not None and interval <= 0:
                put("Milliseconds", str(-interval // 10000))

        # capemon's ip and port beside a socket address (connect, bind,
        # sendto, WSAConnect...): network signatures read those, and DRAKVUF
        # prints the address whole ("203.0.113.7:443", printers' sockaddr).
        sock = SOCKADDR_ARGUMENTS.get(name)
        if sock:
            lower = {n.lower(): a for n, a in by_name.items()}
            for n in sock[0]:
                parsed = parse_endpoint(lower[n]["value"]) if n in lower else None
                if parsed and parsed[0] == "inet":
                    put("ip", parsed[1])
                    put("port", str(parsed[2]))
                    break

        # capemon's ServiceName on a call given a service handle: the name
        # the handle was returned for, earlier in this process
        if name in _SERVICE_OPEN_APIS:
            handle = _parse_int(call.get("return"))
            service = text("ServiceName", "lpServiceName")
            if handle and service:
                self._service_handles[handle] = service
        elif name in _SERVICE_HANDLE_APIS:
            arg = by_name.get("ServiceHandle") or by_name.get("hService")
            service = self._service_handles.get(_parse_int(arg["value"])) if arg else None
            if service:
                put("ServiceName", service)

        if name == "ShellExecuteEx":
            # apimon prints the SHELLEXECUTEINFO's nShow in decimal
            # (apimon.cpp, ShellExecuteExW_hook); every other number of a
            # record is hex, and signatures read it as one.
            show = by_name.get("Show")
            if show is not None and str(show["value"]).lstrip("-").isdigit():
                show["value"] = hex(int(show["value"]) & 0xFFFFFFFF)

    def _parse_syscall(self, timestamp, thread_id, mtype, dec):
        return_value = dec.get("Ret")
        syscall_name = dec.get("Method", "")
        arguments = settle_outputs(syscall_name, mtype, self._record_arguments(dec),
                                   returned=dec.get("Outputs") or ())

        arguments = returned_as_argument(syscall_name, arguments, return_value)

        thread_id = str(thread_id)
        # apimon's dll events carry no TID (-1 here): not a thread.
        if thread_id not in self.threads and thread_id.isdigit():
            self.threads.append(thread_id)
        linux = self.platform != TargetOs.WINDOWS

        # Linux: a -errno return is the failure. A call that never returned
        # (exit, a successful execve) counts as done. Windows keeps True:
        # what signatures read there is apimon's status.
        status = _syscall_ok(return_value, True) if linux else True
        call = {
            "timestamp": timestamp,
            "thread_id": thread_id,
            "plugin": mtype,
            "category": api_category(syscall_name, mtype, linux),
            "syscall": syscall_name,
            "status": True if status is None else status,
            "return": return_value,
            "arguments": cape_aliases(syscall_name, settle_outputs(syscall_name, mtype, arguments)),
            "repeated": 0,
        }

        if dec.get("Info"):
            call["pretty_return"] = dec["Info"]
        call["module"] = dec.get("FromModule")
        # apimon's record of the same call (trace_split._CallMerger).
        if isinstance(dec.get("Caller"), str):
            call["caller"] = dec["Caller"]
        for resolved in dec.get("Resolved") or ():
            self._fold_resolved(call, resolved)
        return call

    def _fold_resolved(self, call, rec):
        """Fold filetracer's / regmon's / procmon's record of the same
        system call into it: their resolved values as further arguments
        (never over one the syscall already has), and the keys Summary reads
        from those plugins' own calls."""
        plugin = rec.get("Plugin")
        sources = call.setdefault("sources", [call["plugin"]])
        if plugin not in sources:
            sources.append(plugin)
        have = {a["name"] for a in call["arguments"]}

        def add(name, value):
            if name not in have and value is not None:
                have.add(name)
                call["arguments"].append({"name": name, "value": _cape_value(value)})

        if plugin == "filetracer":
            filename = rec.get("FileName")
            # The service filetracer saw: Summary's file classification is by
            # service (NtCreateFile's access mask, NtSetInformationFile's
            # class), whatever API the call was made through. Linux
            # filetracer names it in `Syscall`; its Method is do_syscall_64.
            service = rec.get("Syscall") if isinstance(rec.get("Syscall"), str) else rec.get("Method")
            # `information`: NtCreateFile's IoStatusBlock.Information
            # (FILE_CREATED...), which the syscall's own IoStatusBlock
            # argument, a pointer, would hide among the arguments
            call.update({"operation": rec.get("Operation", ""), "service": service,
                         "filehandle": rec.get("FileHandle", ""), "filename": filename,
                         "information": rec.get("IoStatusBlock")})
            for arg in symbolic_to_hex(self._record_arguments(rec)):
                if arg["name"] not in ("FileHandle", "ObjectAttributes", "Syscall"):
                    add(arg["name"], arg["value"])
            add("HandleName", filename)
            add("FileName", filename)
        elif plugin == "regmon":
            # `FullName` and the data are derived from these in _cape_names,
            # once every record of the call is in.
            key, valuename, value = rec.get("Key"), rec.get("ValueName"), rec.get("Value")
            call.update({"key": key, "valuename": valuename, "value": value})
            add("Key", key)
        elif plugin == "procmon":
            for arg in self._record_arguments(rec):
                value = arg["value"]
                if (arg["name"] == "CommandLine" and isinstance(value, str)
                        and self.platform == TargetOs.WINDOWS):
                    # Windows procmon g_strescape's it (drakvuf_records.unescape_glib).
                    value = unescape_glib(value)
                add(arg["name"], value)
            for arg in _created_ids(rec):
                add(arg["name"], arg["value"])
        elif plugin == "syscall":
            # trace_split._kernel_view: a name the syscall plugin resolved,
            # and the outputs a DRAKVUF that prints them at return put on
            # the sysret. An output is the value after the call, so it
            # replaces what the API printed for that argument at entry --
            # the address of the caller's variable.
            for name in OBJECT_NAME_KEYS:
                add(name, rec.get(name))
            # A key service's `Key` is the key it opened, sub-key included,
            # as regmon's: _cape_names must not append the API's sub-key to
            # it, as it does to the parent key apimon resolved for `hKey`.
            if isinstance(rec.get("Key"), str) and not call.get("key"):
                call["key"] = rec["Key"]
            for name in rec.get("Outputs") or ():
                value = _cape_value(rec.get(name))
                for arg in call["arguments"]:
                    if arg["name"] == name:
                        arg["value"] = value
                        break
                else:
                    add(name, value)
        else:
            for arg in self._record_arguments(rec):
                add(arg["name"], arg["value"])

    def _parse_procmon(self, timestamp, thread_id, mtype, dec):
        """procmon's record of a process or thread service (NtCreateUserProcess,
        NtOpenProcess, NtTerminateProcess... / kernel_clone,
        do_execveat_common, do_exit on Linux): a kernel-side record like
        regmon's and filetracer's, so a `syscall` call."""
        syscall_name = dec.get("Method", "")
        status = dec.get("Status")
        ok = (_parse_int(status) & 0xFFFFFFFF) < 0x80000000 if _parse_int(status) is not None else True
        arguments = self._record_arguments(dec)
        for arg in arguments:
            if (arg["name"] == "CommandLine" and isinstance(arg["value"], str)
                    and self.platform == TargetOs.WINDOWS):
                # Windows procmon g_strescape's it (drakvuf_records.unescape_glib);
                # Linux procmon prints it through the JSON escaper, which the
                # decode has already undone.
                arg["value"] = unescape_glib(arg["value"])
        arguments.extend(_created_ids(dec))

        thread_id = str(thread_id)
        if thread_id not in self.threads and thread_id.isdigit():
            self.threads.append(thread_id)
        linux = self.platform != TargetOs.WINDOWS

        return {
            "timestamp": timestamp,
            "thread_id": thread_id,
            "plugin": mtype,
            "category": api_category(syscall_name, mtype, linux),
            "syscall": syscall_name,
            "status": ok,
            "return": status,
            "arguments": cape_aliases(syscall_name, settle_outputs(syscall_name, mtype, arguments)),
            "repeated": 0,
        }

    def _parse_event(self, timestamp, thread_id, mtype, dec):
        """A record a plugin prints of something the process did -- ptracemon's
        ptrace, debugmon's debug exception, ebpfmon's bpf: a `syscall` call
        named after the record's Method, its keys the arguments."""
        name = dec.get("Method") or mtype
        thread_id = str(thread_id)
        if thread_id not in self.threads and thread_id.isdigit():
            self.threads.append(thread_id)
        return {
            "timestamp": timestamp,
            "thread_id": thread_id,
            "plugin": mtype,
            "category": api_category(name, mtype, self.platform != TargetOs.WINDOWS),
            "syscall": name,
            "status": True,
            "return": None,
            "arguments": self._record_arguments(dec, typed=True),
            "repeated": 0,
        }

    def _parse_cpuidmon(self, row):
        """Parse log row.
        @param row: row data.
        @return: parsed information dict.
        """
        try:
            timestamp = row[0]  # Timestamp of current API call invocation.
            thread_id = row[1]  # Thread ID.
            mtype = row[2]  # mtype
            syscall_name = row[3]  # syscall name
        except IndexError as e:
            log.debug("Unable to parse process log row: %s", e)
            return None

        names = ("Leaf", "Subleaf", "RAX", "RBX", "RCX", "RDX")
        arguments = [{"name": n, "value": v} for n, v in zip(names, row[4:])]
        
        thread_id = str(thread_id)
        # apimon's dll events carry no TID (-1 here): not a thread.
        if thread_id not in self.threads and thread_id.isdigit():
            self.threads.append(thread_id)
        linux = self.platform != TargetOs.WINDOWS

        call = {
            "timestamp": timestamp,
            "thread_id": thread_id,
            "plugin": mtype,
            "category": api_category(syscall_name, mtype, linux),
            "syscall": syscall_name,
            "status": True,
            "return": None,
            "arguments": cape_aliases(syscall_name, settle_outputs(syscall_name, mtype, arguments)),
            "repeated": 0,
        }

        return call

    def _parse_regmon(self, row):
        """Parse log row.
        @param row: row data.
        @return: parsed information dict.
        """

        try:
            timestamp = row[0]  # Timestamp of current API call invocation.
            thread_id = row[1]  # Thread ID.
            mtype = row[2]  # mtype
            syscall_name = row[3]  # api name
            key = row[4]
            valuename = row[5]
            value = row[6]
        except IndexError as e:
            log.debug("Unable to parse process log row: %s", e)
            return None

        arguments = [{"name": "Key", "value": key}, {"name": "ValueName", "value": valuename},
                     {"name": "Value", "value": value}]
        # What capemon logs for the same call, which regmon has already
        # resolved: the key's full path (with the value's name, for a value
        # operation), and the data under the name CAPE's API gives it.
        full = f"{key}\\{valuename}" if key and valuename else key
        arguments.append({"name": "FullName", "value": full})
        data_name = _REGMON_DATA_ARGUMENT.get(syscall_name)
        if data_name and value is not None:
            arguments.append({"name": data_name, "value": value})
        # call = self._call(timestamp, thread_id, mtype, api_name, None, arguments)

        thread_id = str(thread_id)
        # apimon's dll events carry no TID (-1 here): not a thread.
        if thread_id not in self.threads and thread_id.isdigit():
            self.threads.append(thread_id)
        linux = self.platform != TargetOs.WINDOWS

        call = {
            "timestamp": timestamp,
            "thread_id": thread_id,
            "plugin": mtype,
            "category": api_category(syscall_name, mtype, linux),
            "syscall": syscall_name,
            "status": True,
            "return": None,
            "arguments": cape_aliases(syscall_name, settle_outputs(syscall_name, mtype, arguments)),
            "repeated": 0,
        }

        # Read by Summary's registry handlers.
        call.update({"key": key, "valuename": valuename, "value": value})
        return call

    def _parse_filetracer(self, row):
        """Parse log row.
        @param row: row data.
        @return: parsed information dict.
        """

        try:
            timestamp = row[0]  # Timestamp of current API call invocation.
            thread_id = row[1]  # Thread ID.
            mtype = row[2]  # mtype
            syscall_name = row[3]  # api name
            operation = row[4]
            filehandle = row[5]
            filename = row[6]
            dec = row[7]
        except IndexError as e:
            log.debug("Unable to parse process log row: %s", e)
            return None

        status = dec.get("Status")
        ok = (_parse_int(status) & 0xFFFFFFFF) < 0x80000000 if _parse_int(status) is not None else True
        arguments = symbolic_to_hex(self._record_arguments(dec))
        if filename:
            # capemon's name for the path behind a handle (NtReadFile,
            # NtWriteFile, NtSetInformationFile...), which filetracer resolved.
            arguments.append({"name": "HandleName", "value": filename})
        #call = self._call(timestamp, thread_id, mtype, api_name, status,
        #                  cape_aliases(api_name, arguments), status=ok)

        thread_id = str(thread_id)
        # apimon's dll events carry no TID (-1 here): not a thread.
        if thread_id not in self.threads and thread_id.isdigit():
            self.threads.append(thread_id)
        linux = self.platform != TargetOs.WINDOWS

        call = {
            "timestamp": timestamp,
            "thread_id": thread_id,
            "plugin": mtype,
            "category": api_category(syscall_name, mtype, linux),
            "syscall": syscall_name,
            "status": ok,
            "return": status,
            "arguments": cape_aliases(syscall_name, settle_outputs(syscall_name, mtype, arguments)),
            "repeated": 0,
        }

        call.update({"operation": operation, "filehandle": filehandle, "filename": filename,
                     "information": dec.get("IoStatusBlock")})
        return call

    def _parse_socketmon(self, row):
        """Parse log row.
        @param row: row data.
        @return: parsed information dict.
        """
        
        try:
            timestamp = row[0]  # Timestamp of current API call invocation.
            thread_id = row[1]  # Thread ID.
            mtype = row[2]  # mtype
            syscall_name = row[3]  # api name
            protocol = row[4]
            remoteip = row[5]
            remoteport = row[6]
            localip = row[7]
            localport = row[8]
        except IndexError as e:
            log.debug("Unable to parse process log row: %s", e)
            return None

        fields = {"protocol": protocol, "remoteip": remoteip, "remoteport": remoteport,
                  "localip": localip, "localport": localport}
        # An AFD send's bytes (socketmon's AfdSend), as unixsocketmon's sends
        if len(row) > 9 and row[9] is not None:
            fields["value"] = row[9]
        #call = self._call(timestamp, thread_id, mtype, api_name, None,
        #                  [{"name": k, "value": v} for k, v in fields.items()])

        thread_id = str(thread_id)
        # apimon's dll events carry no TID (-1 here): not a thread.
        if thread_id not in self.threads and thread_id.isdigit():
            self.threads.append(thread_id)
        linux = self.platform != TargetOs.WINDOWS

        call = {
            "timestamp": timestamp,
            "thread_id": thread_id,
            "plugin": mtype,
            "category": api_category(syscall_name, mtype, linux),
            "syscall": syscall_name,
            # socketmon reports a connection or a send that happened; it has
            # no outcome to report.
            "status": True,
            "return": None,
            "arguments": cape_aliases(syscall_name, settle_outputs(syscall_name, mtype, [{"name": k, "value": v} for k, v in fields.items()])),
            "repeated": 0,
        }
        # NetworkMap reads these straight off the call (args_map = call).
        call.update(fields)
        return call

    def _parse_unixsocketmon(self, row):
        """Parse log row.
        @param row: row data.
        @return: parsed information dict.
        """

        try:
            timestamp = row[0]  # Timestamp of current API call invocation.
            thread_id = row[1]  # Thread ID.
            mtype = row[2]  # mtype
            syscall_name = row[3]  # api name
            sockettype = row[4]  # api name
        except IndexError as e:
            log.debug("Unable to parse process log row: %s", e)
            return None

        if sockettype.startswith("AF_INET"):

            try:
                fields = {"protocol": row[5], "remoteip": row[6], "remoteport": row[7],
                          "localip": row[8], "localport": row[9], "value": row[10]}
            except IndexError as e:
                log.debug("Unable to parse process log row: %s", e)
                return None

        elif sockettype.startswith("AF_LOCAL"):

            try:
                fields = {"remotepath": row[5], "localpath": row[6], "value": row[7]}
            except IndexError as e:
                log.debug("Unable to parse process log row: %s", e)
                return None
        else:
            return None

       # call = self._call(timestamp, thread_id, mtype, api_name, None,
       #                   [{"name": k, "value": v} for k, v in fields.items()])


        thread_id = str(thread_id)
        # apimon's dll events carry no TID (-1 here): not a thread.
        if thread_id not in self.threads and thread_id.isdigit():
            self.threads.append(thread_id)
        linux = self.platform != TargetOs.WINDOWS

        call = {
            "timestamp": timestamp,
            "thread_id": thread_id,
            "plugin": mtype,
            "category": api_category(syscall_name, mtype, linux),
            "syscall": syscall_name,
            "status": True,
            "return": None,
            "arguments": cape_aliases(syscall_name, settle_outputs(syscall_name, mtype, [{"name": k, "value": v} for k, v in fields.items()])),
            "repeated": 0,
        }

        call.update(fields)
        # log_unixsocketmon's last element: sockettype, size, backlog, connected.
        if isinstance(row[-1], dict):
            call.update({k: v for k, v in row[-1].items() if v is not None})
        return call


class Processes:
    """Processes analyzer."""

    def __init__(self, logs_path, task, options, platform):
        """@param logs_path: trace_split's per-process logs, CAPE's `logs/`."""
        self.task = task
        self._logs_path = logs_path
        self.options = options
        self.platform = platform

    def run(self):
        """Run analysis.
        @return: processes infomartion list.
        """
        results = []

        if not path_exists(self._logs_path):
            log.warning('Analysis results folder does not exist at path "%s"', self._logs_path)
            return results

        # `<seqid>.log`, in seqid order: the order processes were created in,
        # which is what breaks a tie in first_seen below.
        names = [n for n in os.listdir(self._logs_path) if n.endswith(".log")]
        names.sort(key=lambda n: (len(n), n))

        for file_name in names:
            # Invoke parsing of current log file (if ram_boost is enabled, otherwise parsing is done on-demand)
            current_log = ParseProcessLog(os.path.join(self._logs_path, file_name), self.options, self.platform)
            if current_log.process_id is None:
                continue

            # If the current log actually contains any data, add its data to the results list.
            results.append(
                {
                    "process_id": current_log.process_id,
                    "process_name": bytes2str(current_log.process_name),
                    "parent_id": current_log.parent_id,
                    "module_path": _clean_path(bytes2str(current_log.module_path), self.options.replace_patterns),
                    "first_seen": logtime(current_log.first_seen),
                    "calls": current_log.calls,
                    "threads": current_log.threads,
                    "environ": current_log.environdict,
                    "file_activities": {"read_files": [], "write_files": [], "delete_files": []},
                    # trace_split's seqid, parent seqid, times and exit:
                    # beyond CAPE's process, for the platform's report
                    **current_log.identity,
                }
            )

        # Sort the items in the results list chronologically. In this way we
        # can have a sequential order of spawned processes.
        results.sort(key=lambda process: process["first_seen"])

        return results


class _UniqueList:
    """Insertion-ordered collection whose membership test is O(1).

    ``Summary`` guards almost every append with ``value not in self.<list>``, once per
    matching API call. Against a plain list that is a linear scan of a structure that
    reaches thousands of entries on a normal sample. Only the operations ``Summary`` and
    ``check_deny_pattern`` actually use are implemented, so an accidental slice or index
    fails loudly instead of silently reintroducing a scan.
    """

    __slots__ = ("_items", "_seen")

    def __init__(self):
        self._items = []
        self._seen = set()

    def append(self, value):
        if value not in self._seen:
            self._seen.add(value)
            self._items.append(value)

    def mark_seen(self, value):
        """Record a raw value as seen without appending it to the backing list."""
        self._seen.add(value)

    def __contains__(self, value):
        return value in self._seen

    def __iter__(self):
        return iter(self._items)

    def __len__(self):
        return len(self._items)

    def __eq__(self, other):
        if isinstance(other, _UniqueList):
            return self._items == other._items
        return self._items == other

    def __repr__(self):
        return repr(self._items)

    def as_list(self):
        """The backing list, for serialisation at the reporting boundary."""
        return self._items

class Summary:
    """Generates summary information."""

    key = "summary"

    def __init__(self, options):
        self.keys = _UniqueList()
        self.read_keys = _UniqueList()
        self.write_keys = _UniqueList()
        self.delete_keys = _UniqueList()
        self.mutexes = _UniqueList()
        self.files = _UniqueList()
        self.read_files = _UniqueList()
        self.write_files = _UniqueList()
        self.delete_files = _UniqueList()
        self.started_services = _UniqueList()
        self.created_services = _UniqueList()
        self.executed_commands = _UniqueList()
        self.resolved_apis = _UniqueList()
        self.options = options
        # The lists again, per process: what the platform's Summary shows,
        # one section per process of the sample. seqid (as text, a JSON key)
        # -> list name -> items, each process's own in the order it made
        # them. `files` and `keys` -- every file and key touched -- are the
        # read/write/delete lists over again, so not kept twice.
        self.by_process = {}
        self._attributed = set()
        self._process = None
        self._list_names = {id(getattr(self, n)): n for n in (
            "read_files", "write_files", "delete_files", "read_keys", "write_keys", "delete_keys",
            "executed_commands", "resolved_apis", "mutexes", "created_services", "started_services")}
        # process_id -> {DLL base: DLL file name}, from DllLoadNotification:
        # what turns GetProcAddress's module handle into `kernel32RegOpenKeyExA.dll`.
        # On Linux {dlopen's handle: library file name}, for dlsym.
        self._modules = {}

        self.dispatch = {
            "SHGetFileInfoW": self._handle_SHGetFileInfoW,
            "ShellExecuteExW": self._handle_ShellExecuteExW,
            "NtDeleteFile": self._handle_DeleteFile,
            "LdrGetProcedureAddress": self._handle_LdrGetProcedureAddress,
            "GetProcAddress": self._handle_LdrGetProcedureAddress,
            "DllLoadNotification": self._handle_DllLoadNotification,
            "MoveFileWithProgressW": self._handle_MoveFile,
            "MoveFileWithProgressTransactedW": self._handle_MoveFile,
            "CreateProcessInternalW": self._handle_CreateProcess,
            "NtCreateUserProcess": self._handle_CreateProcess,
            "CreateProcessWithTokenW": self._handle_CreateProcess,
            "CreateProcessWithLogonW": self._handle_CreateProcess,
            "dlopen": self._handle_dlopen,
            "dlmopen": self._handle_dlopen,
            "dlsym": self._handle_dlsym,
            "dlvsym": self._handle_dlsym,
        }

    def get_argument(self, call, argname, strip=False):
        return next(
            (arg["value"].strip() if strip else arg["value"] for arg in call["arguments"] if arg["name"] == argname),
            None,
        )

    def get_raw_argument(self, call, argname):
        return next(
            (arg["raw_value"] for arg in call["arguments"] if arg["name"] == argname),
            None,
        )

    def _add(self, target, value):
        """`value` into one of the lists once, and into the current
        process's copy of it once -- a file two processes wrote is each
        one's."""
        if value not in target:
            self._filtering_helper(target, value)
        name = self._list_names.get(id(target))
        if name and self._process is not None and value:
            seqid = self._process.get("seqid")
            key = str(seqid) if seqid is not None else f"pid:{self._process.get('process_id')}"
            if (key, name, value) not in self._attributed:
                self._attributed.add((key, name, value))
                self.by_process.setdefault(key, {}).setdefault(name, []).append(value)

    def _filtering_helper(self, source_list, pattern):
        if not pattern:
            return
        if self.options.replace_patterns:
            check_deny_pattern(source_list, pattern)
            if isinstance(source_list, _UniqueList):
                source_list.mark_seen(pattern)
        else:
            source_list.append(pattern)

    def _add_file_activity(self, process, key, filename):
        if not filename:
            return
        if self.options.file_activities:
            process["file_activities"][key].append(filename)

    # Registry operations, by the canonical name of the API or service, into
    # the lists after `keys` (which every one goes into). NtCreateKey and
    # RegCreateKeyEx are writes, as the port had them: CAPE counts a create
    # only when the disposition says the key was new, and that disposition
    # is an output DRAKVUF does not print.
    _REGISTRY_KINDS = {
        **dict.fromkeys(("NtSetValueKey", "RegSetValueEx", "RegSetValue", "RegSetKeyValue",
                         "SHSetValue", "NtCreateKey", "NtCreateKeyTransacted", "RegCreateKeyEx",
                         "RegCreateKey", "RegCreateKeyTransacted"), "write_keys"),
        **dict.fromkeys(("NtQueryValueKey", "NtQueryMultipleValueKey", "RegQueryValueEx",
                         "RegQueryValue", "RegGetValue", "SHGetValue", "SHRegGetValue",
                         "RegQueryMultipleValues"), "read_keys"),
        **dict.fromkeys(("NtDeleteKey", "NtDeleteValueKey", "RegDeleteKey", "RegDeleteKeyEx",
                         "RegDeleteValue", "RegDeleteKeyValue", "RegDeleteTree", "SHDeleteKey",
                         "SHDeleteValue"), "delete_keys"),
    }

    def _handle_registry(self, call, process):
        """CAPE's registry lists, by `FullName` as upstream's Summary reads
        them: the key path in capemon's form (HKEY_LOCAL_MACHINE\\...) and,
        for a value, its name. A name that is not a full path -- a sub-key
        alone, where no handle could be resolved -- is left out: the
        kernel-side record of the same operation has the full one."""
        name = self.get_argument(call, "FullName")
        if not name or not name.startswith(("HKEY_", "\\")):
            return
        self._add(self.keys, name)
        kind = self._REGISTRY_KINDS.get(canonical(call.get("api") or call.get("syscall") or ""))
        if kind:
            self._add(getattr(self, kind), name)
        if kind == "write_keys":
            # A service installed by writing its key, not through
            # CreateService (which services.exe, not the sample, turns into
            # these writes)
            m = self._SERVICE_IMAGE_PATH.search(name)
            if m:
                self._add_service(self.created_services, m.group(1))

    # A service's binary, which the service control manager starts
    _SERVICE_IMAGE_PATH = re.compile(
        r"\\SYSTEM\\(?:CurrentControlSet|ControlSet\d{3})\\Services\\([^\\]+)\\ImagePath\Z", re.I)

    def _add_service(self, target, name):
        name = (name or "").strip().strip('"')
        if name and not name.startswith("0x"):
            self._add(target, name)

    def _arg(self, call, *names, strip=False):
        """The first of `names` the call has. capemon's name comes first: the
        hook list names arguments as capemon logs them (since 2026-11-11);
        the prototype's name after it, for traces recorded before."""
        for name in names:
            value = self.get_argument(call, name, strip=strip)
            if value is not None:
                return value
        return None

    # CHECK
    def _handle_SHGetFileInfoW(self, call, process):
        filename = self._arg(call, "Path", "pszPath")
        if filename and (len(filename) < 2 or filename[1] != ":"):
            filename = None
        if filename:
            self._add(self.files, filename)

    # CHECK, we need to read SHELLEXECUTEINFOW Struct
    def _handle_ShellExecuteExW(self, call, process):
        filename = self.get_argument(call, "FilePath")
        if not filename or len(filename) < 2 or filename[1] != ":":
            filename = None
        if filename:
            self._add(self.files, filename)
        path = self.get_argument(call, "FilePath", strip=True)
        params = self.get_argument(call, "Parameters", strip=True)
        cmdline = f"{path} {params}" if path else None
        if cmdline:
            self._add(self.executed_commands, cmdline)

    # NtSetInformationFile has no API handler: a delete or rename through it
    # is filetracer's record (_handle_filetracer), whose file name the
    # kernel resolved; apimon prints the handle and a buffer pointer.

    # Check, we need to read ObjectAttributes
    def _handle_DeleteFile(self, call, process):
        filename = self.get_argument(call, "FileName")
        if not filename:
            filename = self.get_argument(call, "DirectoryName")
        if filename:
            self._add(self.files, filename)
            if filename not in self.delete_files:
                self._add_file_activity(process, "delete_files", filename)
            self._add(self.delete_files, filename)

    def _handle_StartService(self, call, process):
        # ServiceName: what the handle was opened for (_cape_names)
        servicename = self._arg(call, "ServiceName", strip=True)
        if not servicename:
            servicename = (self._arg(call, "Arguments", "lpServiceArgVectors", strip=True) or "").split(" ")[0]
        self._add_service(self.started_services, servicename)

    def _handle_CreateService(self, call, process):
        # A null handle is a service not created
        if call.get("return") is not None and not _parse_int(call.get("return")):
            return
        self._add_service(self.created_services, self._arg(call, "ServiceName", "lpServiceName", strip=True))

    # -- services from the commands that manage them (both systems) ----------
    # The process that runs one is the sample's; the service manager that acts
    # on it (services.exe, systemd) is not, and on Linux nothing else in the
    # trace says a service was started.

    _SYSTEMCTL_START = frozenset(("start", "restart", "try-restart", "reload-or-restart",
                                  "try-reload-or-restart"))
    _SERVICE_START = frozenset(("start", "restart"))
    _COMMAND_TOKEN = re.compile(r'"([^"]*)"|(\S+)')

    def _service_commands(self, cmdline):
        """Services a command line creates or starts: `sc create|start`,
        `net start` (Windows); `systemctl start|restart`, `systemctl enable
        --now`, `service <name> start`, `/etc/init.d/<name> start`,
        `invoke-rc.d <name> start` (Linux)."""
        # (quoted, bare) per token: a quoted path or service name is one
        tokens = [t for t in (q or a for q, a in self._COMMAND_TOKEN.findall(cmdline)) if t]
        if not tokens:
            return
        prog_path = tokens[0].replace("\\", "/")
        prog = prog_path.rsplit("/", 1)[-1].lower()
        if prog.endswith(".exe"):
            prog = prog[:-4]
        args = tokens[1:]
        lowered = [a.lower() for a in args]
        if prog == "sc":
            if lowered and lowered[0].startswith("\\\\"):
                args, lowered = args[1:], lowered[1:]
            if len(args) >= 2 and lowered[0] == "create":
                self._add_service(self.created_services, args[1])
            elif len(args) >= 2 and lowered[0] == "start":
                self._add_service(self.started_services, args[1])
        elif prog in ("net", "net1"):
            if len(args) >= 2 and lowered[0] == "start":
                self._add_service(self.started_services, " ".join(args[1:]))
        elif prog == "systemctl":
            words = [a for a in args if not a.startswith("-")]
            if not words:
                return
            verb = words[0].lower()
            if verb in self._SYSTEMCTL_START or (verb == "enable" and "--now" in lowered):
                for unit in words[1:]:
                    self._add_service(self.started_services, self._unit_name(unit))
        elif prog == "service":
            if len(args) >= 2 and lowered[1] in self._SERVICE_START:
                self._add_service(self.started_services, args[0])
        elif prog == "invoke-rc.d":
            words = [a for a in args if not a.startswith("-")]
            if len(words) >= 2 and words[1].lower() in self._SERVICE_START:
                self._add_service(self.started_services, words[0])
        elif prog_path.startswith("/etc/init.d/"):
            if lowered and lowered[0] in self._SERVICE_START:
                self._add_service(self.started_services, prog)

    @staticmethod
    def _unit_name(unit):
        return unit[:-len(".service")] if unit.endswith(".service") else unit

    # A unit file or init script written where the service manager looks for
    # them (a `.wants/` link is `systemctl enable` of a service that exists)
    _LINUX_SERVICE_FILE = re.compile(
        r"\A(?:/etc/systemd/(?:system|user)|/(?:usr/)?lib/systemd/(?:system|user)|/run/systemd/system"
        r"|/home/[^/]+/\.config/systemd/user|/root/\.config/systemd/user)/([^/]+)\.service\Z"
        r"|\A/etc/init\.d/([^/]+)\Z")

    def _handle_CreateProcess(self, call, process):
        cmdline = self._arg(call, "CommandLine", "lpCommandLine", strip=True)
        appname = self._arg(call, "ApplicationName", "lpApplicationName", strip=True)
        if appname and cmdline:
            base = appname.rsplit("\\", 1)[-1].rsplit(".", 1)[0]
            firstarg = ""
            if cmdline[0] == '"':
                firstarg = cmdline[1:].split('"', 1)[0]
            else:
                firstarg = cmdline.split(" ", 1)[0]
            if base not in firstarg:
                cmdline = f"{appname} {cmdline}"
        if cmdline:
            self._add(self.executed_commands, cmdline)

    # -- from get_modified_files_info.py, the classification the old chain
    # used for report.json's modified/read/deleted files ---------------------

    _WIN_FILE_ACCESS_WRITE = ("GENERIC_WRITE", "FILE_WRITE_DATA", "FILE_APPEND_DATA", "DELETE")
    _WIN_FILE_ACCESS_READ = ("GENERIC_READ", "FILE_READ_DATA")
    _LINUX_FILE_WRITE = frozenset((
        "write", "pwrite64", "writev", "pwritev", "pwritev2", "ftruncate", "truncate",
        "fallocate", "rename", "renameat", "renameat2", "mkdir", "mkdirat", "symlink",
        "symlinkat", "creat", "chmod", "fchmodat", "chown", "fchownat"))
    _LINUX_FILE_READ = frozenset(("read", "pread64", "readv", "preadv", "preadv2"))
    _LINUX_FILE_OPEN = frozenset(("open", "openat", "openat2"))
    _LINUX_FILE_DELETE = frozenset(("unlink", "unlinkat", "rmdir"))
    # Pseudo-filesystems and caches every process touches; not behaviour.
    _LINUX_EXCLUDED = ("/proc", "/sys", "/dev", "/run", "/var/cache", "/var/log")

    _LINUX_FILE_RENAME = frozenset(("rename", "renameat", "renameat2"))
    _LINUX_FILE_LINK = frozenset(("link", "linkat"))

    @staticmethod
    def _dos_name(path):
        """`\\??\\C:\\x` is the NT name of `C:\\x`, which is how CAPE reports it."""
        return path[4:] if path.startswith("\\??\\") else path

    def _deletes(self, call):
        return _file_deleted(call)

    def _linux_files(self, call, filename, api):
        """[(path, kinds)] of a Linux filetracer record. A rename's FileName
        is the new name and `old_name` the old one; a link's FileName is the
        file linked to and `link_name` the new name."""
        if api in self._LINUX_FILE_RENAME:
            out = [(filename, ("write_files",))]
            old = self.get_argument(call, "old_name")
            if isinstance(old, str) and old:
                out.append((old, ("delete_files",)))
            return out
        if api in self._LINUX_FILE_LINK:
            new = self.get_argument(call, "link_name")
            return [(new, ("write_files",))] if isinstance(new, str) and new else []
        if api in self._LINUX_FILE_DELETE:
            kinds = ("delete_files",)
        elif api in self._LINUX_FILE_WRITE:
            kinds = ("write_files",)
        elif api in self._LINUX_FILE_READ:
            kinds = ("read_files",)
        elif api in self._LINUX_FILE_OPEN:
            flags = _parse_int(self.get_argument(call, "flags")) or 0
            kinds = ("write_files",) if flags & (os.O_CREAT | os.O_TRUNC) else ()
        else:
            return []
        return [(filename, kinds)]

    def _note_file(self, process, filename, kinds):
        self._add(self.files, filename)
        for kind in kinds:
            target = getattr(self, kind)
            if filename not in target:
                self._add_file_activity(process, kind, filename)
            self._add(target, filename)

    def _handle_filetracer(self, call, process):
        """A file the kernel saw opened, read, written or deleted, classified
        by the service (filetracer's own record, or the syscall it was folded
        into): what CAPE's read/write/delete file lists hold."""
        filename = call.get("filename")
        api = call.get("service") or call.get("syscall") or call.get("api")
        if call.get("operation") == "FileRenameInformation":
            # Windows: no FileName, the two ends. CAPE's MoveFile: the old
            # name deleted, the new one written.
            for name, kind in (("FileSrc", "delete_files"), ("FileDst", "write_files")):
                path = self.get_argument(call, name)
                if isinstance(path, str) and path:
                    self._note_file(process, self._dos_name(path), (kind,))
            return
        if not isinstance(filename, str) or not filename:
            return
        if filename.startswith("/"):
            for path, kinds in self._linux_files(call, filename, api):
                if "write_files" in kinds:
                    m = self._LINUX_SERVICE_FILE.match(path)
                    if m:
                        self._add_service(self.created_services, m.group(1) or m.group(2))
                if not path.startswith(self._LINUX_EXCLUDED):
                    self._note_file(process, path, kinds)
            return
        else:
            filename = self._dos_name(filename)
            if api == "NtWriteFile":
                kinds = ("write_files",)
            elif api == "NtReadFile":
                kinds = ("read_files",)
            elif api == "NtSetInformationFile":
                if not self._deletes(call):
                    return
                kinds = ("delete_files",)
            elif api in ("NtCreateFile", "NtOpenFile"):
                # Hex from the syscall or from flags.symbolic_to_hex; the
                # names themselves from a filetracer value nothing converted.
                raw = str(self.get_argument(call, "DesiredAccess") or "")
                access = _parse_int(raw)
                if access is None:
                    access = flags_to_int(raw, DESIRED_ACCESS) or 0
                kinds = tuple(k for k, names in (("write_files", self._WIN_FILE_ACCESS_WRITE),
                                                 ("read_files", self._WIN_FILE_ACCESS_READ))
                              if any(access & DESIRED_ACCESS[n] for n in names))
                # filetracer prints every object NtCreateFile opens; a file
                # has a drive (or is a UNC or device path under \Device).
                if len(filename) < 3 or filename[1] != ":":
                    return
            else:
                return
        self._note_file(process, filename, kinds)

    def _handle_procmon(self, call, process):
        """A process procmon saw created (Windows) or exec'd (Linux): CAPE's
        executed_commands, which capemon takes from CreateProcessInternalW."""
        # `status` None: the syscall never returned in the trace; procmon,
        # which reports only what happened, saw the process all the same.
        name = call.get("syscall") or call.get("api")
        if name not in ("NtCreateUserProcess", "do_execveat_common") or call["status"] is False:
            return
        # Already unescaped where the procmon record was parsed or folded
        # (drakvuf_records.unescape_glib).
        cmdline = self.get_argument(call, "CommandLine")
        cmdline = (cmdline or self.get_argument(call, "ImagePathName") or "").strip()
        if cmdline:
            self._add(self.executed_commands, cmdline)
            self._service_commands(cmdline)

    def _handle_mutex(self, call, process):
        """The mutex's name: capemon's `MutexName` (ParseProcessLog._cape_names
        derives it from lpName, or from the object name apimon and the
        syscall plugin resolve out of ObjectAttributes); failing that, the
        last argument of a hook-list line that names no arguments."""
        name = self.get_argument(call, "MutexName") or self.get_argument(call, "lpName")
        if name is None and call["plugin"] == "apimon" and call["arguments"]:
            name = call["arguments"][-1].get("value")
        if isinstance(name, str) and name and not name.startswith("0x"):
            self._add(self.mutexes, name)

    def _handle_DllLoadNotification(self, call, process):
        base = _parse_int(self.get_argument(call, "DllBase"))
        name = self.get_argument(call, "DllName")
        if base is not None and name:
            dll = str(name).replace("/", "\\").rsplit("\\", 1)[-1].lower()
            self._modules.setdefault(process["process_id"], {})[base] = dll

    def _handle_LdrGetProcedureAddress(self, call, process):
        """CAPE's resolved_apis entry, `dll.function`. capemon logs the
        module's name; DRAKVUF logs its handle, which is its base address,
        resolved through the DLLs this process was seen to load. A function
        asked for by ordinal (a number, not a string) or whose module was
        never seen is not recorded: `0x7ff...` is not a resolved API."""
        if not call["status"]:
            return
        funcname = (self.get_argument(call, "FunctionName") or self.get_argument(call, "lpProcName")
                    or self.get_argument(call, "ProcedureName"))
        if funcname is None and call["api"] == "GetProcAddress" and len(call["arguments"]) > 1:
            # A hook list line without argument names prints Arg0, Arg1.
            funcname = call["arguments"][1].get("value")
        if not isinstance(funcname, str) or not funcname or funcname.startswith("0x"):
            return
        dllname = self.get_argument(call, "ModuleName")
        if not dllname:
            handle = (self.get_argument(call, "ModuleHandle") or self.get_argument(call, "hModule")
                      or self.get_argument(call, "DllHandle"))
            if handle is None and call["arguments"]:
                handle = call["arguments"][0].get("value")
            dllname = self._modules.get(process["process_id"], {}).get(_parse_int(handle))
        if not dllname:
            return
        combined = f"{str(dllname).lower()}.{funcname}"
        self._add(self.resolved_apis, combined)

    # dlsym's pseudo-handles: the global scope, and the libraries after the caller's
    _DLSYM_SCOPES = {0: "RTLD_DEFAULT", 0xFFFFFFFFFFFFFFFF: "RTLD_NEXT", -1: "RTLD_NEXT"}

    def _handle_dlopen(self, call, process):
        """The handle dlopen returned, for the library's file name (Linux's
        DllLoadNotification for dlsym). NULL is the program itself."""
        handle = _parse_int(call.get("return"))
        path = self._arg(call, "Path", "filename")
        if handle and isinstance(path, str) and path and not path.startswith("0x"):
            self._modules.setdefault(process["process_id"], {})[handle] = path.rsplit("/", 1)[-1]

    def _handle_dlsym(self, call, process):
        """CAPE's resolved_apis on Linux: `libname.symbol`, the library by the
        handle dlopen returned; RTLD_DEFAULT and RTLD_NEXT by name."""
        ret = call.get("return")
        if ret is not None and not _parse_int(ret):
            return      # NULL: not found
        symbol = self._arg(call, "Symbol", "symbol")
        if not isinstance(symbol, str) or not symbol or symbol.startswith("0x"):
            return
        handle = _parse_int(self._arg(call, "Handle", "handle"))
        library = self._DLSYM_SCOPES.get(handle) or self._modules.get(process["process_id"], {}).get(handle)
        if not library:
            return
        combined = f"{library}.{symbol}"
        self._add(self.resolved_apis, combined)

    # Check, need to read ObjectAttributes
    def _handle_NtCreateProcess(self, call, process):
        cmdline = self.get_argument(call, "FileName")
        if cmdline:
            self._add(self.executed_commands, cmdline)

    def _handle_MoveFile(self, call, process):
        origname = self._arg(call, "ExistingFileName", "lpExistingFileName")
        newname = self._arg(call, "NewFileName", "lpNewFileName")
        if origname:
            self._add(self.files, origname)
            if origname not in self.delete_files:
                self._add_file_activity(process, "delete_files", origname)
            self._add(self.delete_files, origname)
        if newname:
            self._add(self.files, newname)
            if newname not in self.write_files:
                self._add_file_activity(process, "write_files", newname)
            self._add(self.write_files, newname)

    def event_apicall(self, call, process):
        """Generate processes list from streamed calls/processes.
        @return: None.
        """
        # Whose: every list addition below is this process's too (_add)
        self._process = process
        if "api" not in call:
            # The kernel's side (`syscall` calls: the syscall plugin, regmon,
            # filetracer, procmon): every file, key and process this process
            # touched, whichever API -- hooked or not -- it went through. The
            # file and process lists come from here alone, so that an API
            # call carrying a copy of the same record does not count twice.
            name = call.get("syscall")
            if not name:
                return
            sources = call.get("sources") or (call["plugin"],)
            if "filetracer" in sources:
                self._handle_filetracer(call, process)
            if "procmon" in sources:
                self._handle_procmon(call, process)
            if call.get("category") == "registry":
                self._handle_registry(call, process)
            if canonical(name) in ("NtCreateMutant", "NtOpenMutant"):
                self._handle_mutex(call, process)
            return

        api = call["api"]
        if not api:
            return
        # Registry names from the API as well: apimon resolves the handle the
        # API was given (`Key=`), which on a WOW64 process is the path before
        # the kernel redirects it -- the one the program asked for.
        if call.get("category") == "registry":
            self._handle_registry(call, process)
            return
        if api in ("NtCreateMutant", "NtOpenMutant") or api.startswith(("CreateMutex", "OpenMutex")):
            self._handle_mutex(call, process)
            return
        handler = self.dispatch.get(api)
        if handler:
            handler(call, process)
            return

        if api.startswith("DeleteFile") or api.startswith("RemoveDirectory"):
            self._handle_DeleteFile(call, process)
        elif api.startswith("StartService"):
            self._handle_StartService(call, process)
        elif api.startswith("CreateService"):
            self._handle_CreateService(call, process)
        elif api.startswith("NtCreateProcess"):
            self._handle_NtCreateProcess(call, process)

        # Check
        """
        elif call["plugin"] == "filetracer":
            filename = self.get_argument(call, "filename")
            if not filename:
                filename = self.get_argument(call, "DirectoryName")
            srcfilename = self.get_argument(call, "ExistingFileName")
            dstfilename = self.get_argument(call, "NewFileName")
            accessval = self.get_argument(call, "DesiredAccess")
            access = int(accessval, 16) if accessval else None
            if filename:
                if (
                    access
                    and (access & 0x80000000 or access & 0x10000000 or access & 0x02000000 or access & 0x1)
                    and filename not in self.read_files
                ):
                    self._filtering_helper(self.read_files, srcfilename or filename)
                    self._add_file_activity(process, "read_files", srcfilename or filename)
                if (
                    access
                    and (access & 0x40000000 or access & 0x10000000 or access & 0x02000000 or access & 0x6)
                    and filename not in self.write_files
                ):
                    self._filtering_helper(self.write_files, srcfilename or filename)
                    self._add_file_activity(process, "write_files", srcfilename or filename)
                if filename not in self.files:
                    self._filtering_helper(self.files, filename)
            if srcfilename:
                if srcfilename not in self.read_files:
                    self._filtering_helper(self.read_files, srcfilename)
                    self._add_file_activity(process, "read_files", srcfilename)
                if srcfilename not in self.files:
                    self._filtering_helper(self.files, srcfilename)
            if dstfilename:
                if dstfilename not in self.write_files:
                    self._filtering_helper(self.write_files, dstfilename)
                    self._add_file_activity(process, "write_files", dstfilename)
                if dstfilename not in self.files:
                    self._filtering_helper(self.files, dstfilename)
        """
    def run(self):
        """Get registry keys, mutexes and files.
        @return: Summary of keys, read keys, written keys, mutexes and files.
        """
        # Unwrap to plain lists: everything downstream (json, orjson, bson, the web UI)
        # expects a list, and nothing after this point needs the membership index.
        return {
            "files": self.files.as_list(),
            "read_files": self.read_files.as_list(),
            "write_files": self.write_files.as_list(),
            "delete_files": self.delete_files.as_list(),
            "keys": self.keys.as_list(),
            "read_keys": self.read_keys.as_list(),
            "write_keys": self.write_keys.as_list(),
            "delete_keys": self.delete_keys.as_list(),
            "executed_commands": self.executed_commands.as_list(),
            "resolved_apis": self.resolved_apis.as_list(),
            "mutexes": self.mutexes.as_list(),
            "created_services": self.created_services.as_list(),
            "started_services": self.started_services.as_list(),
            "by_process": self.by_process,
        }


class Enhanced:
    """Generates a more extensive high-level representation than Summary."""

    key = "enhanced"

    def __init__(self, details=False):
        """
        @param details: Also add some (not so relevant) Details to the log
        """
        self.eid = 0
        self.details = details
        self.modules = {}
        self.procedures = {}
        self.events = []
        # What the kernel saw a process do (_kernel_events), once per
        # process and object: [(key, event)], and the keys of the API events,
        # which say the same where both exist (run())
        self._kernel = []
        self._kernel_keys = set()
        self._api_keys = set()
        self.gendat = [
            {
                "event": "move",
                "object": "file",
                "apis": [
                    "MoveFileWithProgressW",
                    "MoveFileWithProgressTransactedW",
                ],
                "args": [("from", "ExistingFileName"), ("to", "NewFileName")],
            },
            {
                "event": "copy",
                "object": "file",
                "apis": ["CopyFileA", "CopyFileW", "CopyFileExW", "CopyFileExA"],
                "args": [("from", "ExistingFileName"), ("to", "NewFileName")],
            },
            {
                "event": "delete",
                "object": "file",
                "apis": ["DeleteFileA", "DeleteFileW", "NtDeleteFile"],
                "args": [("file", "FileName")],
            },
            {
                "event": "delete",
                "object": "dir",
                "apis": ["RemoveDirectoryA", "RemoveDirectoryW"],
                "args": [("file", "DirectoryName")],
            },
            {
                "event": "create",
                "object": "dir",
                "apis": ["CreateDirectoryW", "CreateDirectoryExW"],
                "args": [("file", "DirectoryName")],
            },
            {
                "event": "write",
                "object": "file",
                "apis": ["URLDownloadToFileW", "URLDownloadToFileA"],
                "args": [("file", "FileName")],
            },
            {
                "event": "read",
                "object": "file",
                "apis": [
                    "NtReadFile",
                ],
                "args": [("file", "HandleName")],
            },
            {
                "event": "write",
                "object": "file",
                "apis": [
                    "NtWriteFile",
                ],
                "args": [("file", "HandleName")],
            },
            {
                "event": "execute",
                "object": "file",
                "apis": [
                    "CreateProcessAsUserA",
                    "CreateProcessAsUserW",
                    "CreateProcessA",
                    "CreateProcessW",
                    "NtCreateProcess",
                    "NtCreateProcessEx",
                ],
                "args": [("file", "FileName")],
            },
            {
                "event": "execute",
                "object": "file",
                "apis": [
                    "CreateProcessInternalW",
                    "CreateProcessWithLogonW",
                    "CreateProcessWithTokenW",
                ],
                "args": [("file", "CommandLine")],
            },
            {
                "event": "execute",
                "object": "file",
                "apis": [
                    "ShellExecuteExA",
                    "ShellExecuteExW",
                ],
                "args": [("file", "FilePath")],
            },
            {
                "event": "load",
                "object": "library",
                "apis": ["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "LdrLoadDll", "LdrGetDllHandle"],
                "args": [("file", "FileName"), ("pathtofile", "PathToFile"), ("moduleaddress", "BaseAddress")],
            },
            {
                "event": "findwindow",
                "object": "windowname",
                "apis": ["FindWindowA", "FindWindowW", "FindWindowExA", "FindWindowExW"],
                "args": [("classname", "ClassName"), ("windowname", "WindowName")],
            },
            {
                "event": "write",
                "object": "registry",
                "apis": [
                    "RegSetValueExA",
                    "RegSetValueExW",
                    "NtSetValueKey",
                    "RegSetValueA",
                    "RegSetValueW",
                ],
                "args": [("regkey", "FullName"), ("content", "Buffer")],
            },
            {
                "event": "write",
                "object": "registry",
                "apis": ["RegCreateKeyExA", "RegCreateKeyExW"],
                "args": [("regkey", "FullName")],
            },
            {
                "event": "read",
                "object": "registry",
                "apis": [
                    "RegQueryValueExA",
                    "RegQueryValueExW",
                ],
                "args": [("regkey", "FullName"), ("content", "Data")],
            },
            {
                "event": "read",
                "object": "registry",
                "apis": ["NtQueryValueKey"],
                "args": [("regkey", "FullName"), ("content", "Information")],
            },
            {
                "event": "delete",
                "object": "registry",
                "apis": ["RegDeleteKeyA", "RegDeleteKeyW", "RegDeleteValueA", "RegDeleteValueW", "NtDeleteValueKey"],
                "args": [("regkey", "FullName")],
            },
            {
                "event": "create",
                "object": "windowshook",
                "apis": ["SetWindowsHookExA"],
                "args": [("id", "HookIdentifier"), ("moduleaddress", "ModuleAddress"), ("procedureaddress", "ProcedureAddress")],
            },
            {
                "event": "start",
                "object": "service",
                "apis": ["StartServiceA", "StartServiceW"],
                "args": [("service", "ServiceName")],
            },
            {
                "event": "modify",
                "object": "service",
                "apis": ["ControlService"],
                "args": [("service", "ServiceName"), ("controlcode", "ControlCode")],
            },
            {"event": "delete", "object": "service", "apis": ["DeleteService"], "args": [("service", "ServiceName")]},
            # Linux, libmon's
            {"event": "load", "object": "library", "apis": ["dlopen", "dlmopen"], "args": [("file", "Path")]},
            {"event": "execute", "object": "file", "apis": ["system", "popen"], "args": [("file", "Command")]},
            {"event": "execute", "object": "file", "apis": ["execve", "posix_spawn"], "args": [("file", "Path")]},
            {"event": "execute", "object": "file", "apis": ["execvp"], "args": [("file", "File")]},
        ]
        self.api_map = {}
        for item in self.gendat:
            for api in item["apis"]:
                self.api_map[api] = item

    def _add_procedure(self, mbase, name, base):
        """
        Add a procedure address
        """
        self.procedures[base] = f"{self._get_loaded_module(mbase)}:{name}"

    def _add_loaded_module(self, name, base):
        """
        Add a loaded module to the internal database
        """
        self.modules[base] = resolved_path(name) if isinstance(name, str) else name

    def _get_loaded_module(self, base):
        """
        Get the name of a loaded module from the internal db
        """
        return self.modules.get(base, "")

    def _process_call(self, call):
        """Gets files calls
        @return: information list
        """

        def _load_args(call):
            """
            Load arguments from call
            """
            return {argument["name"]: argument["value"] for argument in call["arguments"]}

        def _get_service_action(control_code):
            """@see: http://msdn.microsoft.com/en-us/library/windows/desktop/ms682108%28v=vs.85%29.aspx"""
            codes = {1: "stop", 2: "pause", 3: "continue", 4: "info"}
            # Hex text, as every number of a call is: int() of it raised
            control_code = _parse_int(control_code)
            if control_code is None:
                return None
            default = "user" if control_code >= 128 else "notify"
            return codes.get(control_code, default)

        event = None
        item = self.api_map.get(call["api"])
        if item:
            args = _load_args(call)
            if call["api"] in ("RegCreateKeyExA", "RegCreateKeyExW"):
                disposition = args.get("Disposition")
                if disposition is not None and _parse_int(disposition) != 1:
                    return None
            self.eid += 1

            event = {
                "event": item["event"],
                "object": item["object"],
                "timestamp": call["timestamp"],
                "eid": self.eid,
                "data": {},
            }

            for logname, dataname in item["args"]:
                event["data"][logname] = args.get(dataname)

            # The file Windows opens, not the string it was given: the
            # call's own argument keeps it as passed.
            if item["object"] in ("file", "dir", "library"):
                for logname in ("file", "from", "to"):
                    if isinstance(event["data"].get(logname), str):
                        event["data"][logname] = resolved_path(event["data"][logname])
            # LoadLibrary and dlopen return the module they loaded; capemon
            # hooks only LdrLoadDll, which writes it to an argument.
            if item["object"] == "library" and call["api"].startswith(("LoadLibrary", "dlopen", "dlmopen")):
                event["data"]["moduleaddress"] = event["data"].get("moduleaddress") or call.get("return")

        # Not sure I really want this, way too noisy anyway and doesn't bring much value.
        # if self.details:
        #    gendata += [{"event" : "get",
        #           "object" : "procedure",
        #           "apis" : ["LdrGetProcedureAddress"],
        #           "args": [("name", "FunctionName"), ("ordinal", "Ordinal")]
        #          },]

        args = _load_args(call)

        if event:
            if call["api"] == "LdrGetDllHandle" and call["status"]:
                self._add_loaded_module(args.get("FileName", ""), args.get("ModuleHandle", ""))

            elif call["api"] in ("LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW") and call["status"]:
                self._add_loaded_module(args.get("FileName", ""), event["data"].get("moduleaddress") or "")

            elif call["api"] == "LdrLoadDll" and call["status"]:
                self._add_loaded_module(args.get("FileName", ""), args.get("BaseAddress", ""))

            elif call["api"] == "LdrGetProcedureAddress" and call["status"]:
                self._add_procedure(args.get("ModuleHandle", ""), args.get("FunctionName", ""), args.get("FunctionAddress", ""))
                event["data"]["module"] = self._get_loaded_module(args.get("ModuleHandle", ""))

            elif call["api"] == "SetWindowsHookExA":
                event["data"]["module"] = self._get_loaded_module(args.get("ModuleAddress", ""))

            elif call["api"] == "ControlService":
                event["data"]["action"] = _get_service_action(args.get("ControlCode") or args.get("dwControl"))

            return event

        return event

    # -- what the kernel saw (filetracer, regmon, procmon) and apimon's
    # DllLoadNotification: the events no call of the hooked set gives --------

    _LINUX_FILE_EVENTS = {
        **dict.fromkeys(("write", "pwrite64", "writev", "pwritev", "pwritev2", "ftruncate", "truncate",
                         "fallocate"), ("write", "file")),
        **dict.fromkeys(("read", "pread64", "readv", "preadv", "preadv2"), ("read", "file")),
        **dict.fromkeys(("unlink", "unlinkat"), ("delete", "file")),
        "rmdir": ("delete", "dir"),
        **dict.fromkeys(("mkdir", "mkdirat"), ("create", "dir")),
    }
    _LINUX_RENAMES = frozenset(("rename", "renameat", "renameat2"))
    _FILE_CREATED = 2       # IO_STATUS_BLOCK.Information of an NtCreateFile that created
    _WINDOWS_DIR = re.compile(
        r"\A(?:\\\?\?\\)?(?:(?:[a-z]:|\\device\\harddiskvolume\d+)?\\windows|\\systemroot)\\", re.I)
    _REGISTRY_EVENTS = {"NtSetValueKey": "write", "NtDeleteValueKey": "delete", "NtDeleteKey": "delete",
                        "NtQueryValueKey": "read"}

    def _kernel_events(self, call):
        """[(event, object, data)] of a call's kernel-side records -- the
        call itself, or the API call they were folded into."""
        if call.get("api") == "DllLoadNotification":
            dll, base = _call_argument(call, "DllName"), _call_argument(call, "DllBase")
            if not isinstance(dll, str) or not dll:
                return []
            self._add_loaded_module(dll, base)
            # apimon reports every module it finds mapped: the system's
            # would be dozens per process that CAPE's timeline never shows
            # (capemon's LdrLoadDll is a dynamic load). A module from
            # anywhere else -- the sample's, one it dropped, a side-loaded
            # copy of a system name -- is what the timeline is for.
            if self._WINDOWS_DIR.match(dll):
                return []
            path = resolved_path(dll)
            name = path.replace("/", "\\").rsplit("\\", 1)[-1]
            return [("load", "library", {"file": name, "pathtofile": path, "moduleaddress": base})]

        sources = call.get("sources") or (call.get("plugin"),)
        out = []
        if "filetracer" in sources:
            out.extend(self._file_events(call))
        name = canonical(call.get("syscall") or call.get("api") or "")
        if "procmon" in sources and name in ("NtCreateUserProcess", "do_execveat_common") \
                and call.get("status") is not False:
            command = _call_argument(call, "CommandLine") or _call_argument(call, "ImagePathName")
            if isinstance(command, str) and command.strip():
                out.append(("execute", "file", {"file": command.strip()}))
        if "regmon" in sources and name in self._REGISTRY_EVENTS:
            full = _call_argument(call, "FullName")
            if isinstance(full, str) and full.startswith(("HKEY_", "\\")):
                data = {"regkey": full}
                content = _REGMON_DATA_ARGUMENT.get(name)
                if content and self._REGISTRY_EVENTS[name] != "delete":
                    data["content"] = _call_argument(call, content)
                out.append((self._REGISTRY_EVENTS[name], "registry", data))
        return out

    def _file_events(self, call):
        service = call.get("service") or call.get("syscall") or call.get("api")
        if call.get("operation") == "FileRenameInformation":
            src, dst = _call_argument(call, "FileSrc"), _call_argument(call, "FileDst")
            if src and dst:
                return [("move", "file", {"from": Summary._dos_name(src), "to": Summary._dos_name(dst)})]
            return []
        filename = call.get("filename")
        if not isinstance(filename, str) or not filename:
            return []
        if filename.startswith("/"):
            if filename.startswith(Summary._LINUX_EXCLUDED):
                return []
            if service in self._LINUX_RENAMES:
                old = _call_argument(call, "old_name")
                return [("move", "file", {"from": old, "to": filename})] if old else []
            found = self._LINUX_FILE_EVENTS.get(service)
            return [(found[0], found[1], {"file": filename})] if found else []
        filename = Summary._dos_name(filename)
        if service == "NtWriteFile":
            return [("write", "file", {"file": filename})]
        if service == "NtReadFile":
            return [("read", "file", {"file": filename})]
        if service == "NtSetInformationFile" and _file_deleted(call):
            return [("delete", "file", {"file": filename})]
        if service == "NtCreateFile" and _parse_int(call.get("information")) == self._FILE_CREATED:
            options = _parse_int(_call_argument(call, "CreateOptions")) or 0
            if options & CREATE_OPTIONS["FILE_DIRECTORY_FILE"]:
                return [("create", "dir", {"file": filename})]
        return []

    @staticmethod
    def _event_key(process, event):
        """What an event is about, in this process: the same for an API
        event and the kernel's record of the same operation."""
        data = event["data"]
        if event["object"] == "library":
            target = str(data.get("file") or "").replace("/", "\\").rsplit("\\", 1)[-1]
        elif event["event"] in ("move", "copy"):
            target = f"{data.get('from')}>{data.get('to')}"
        else:
            target = str(data.get("file") or data.get("regkey") or data.get("service") or "")
        return process["process_id"], event["event"], event["object"], target.lower()

    def event_apicall(self, call, process):
        """Generate processes list from streamed calls/processes.
        @return: None.
        """
        # Which process, beyond CAPE's event shape: the platform's timeline
        # and each process's own activity are read by it
        who = {"pid": process["process_id"], "seqid": process.get("seqid")}
        event = self._process_call(call) if call.get("api") else None
        if event:
            event.update(who)
            self.events.append(event)
            self._api_keys.add(self._event_key(process, event))
            return
        for kind, obj, data in self._kernel_events(call):
            event = {"event": kind, "object": obj, "timestamp": call["timestamp"], "eid": 0, "data": data,
                     **who}
            key = self._event_key(process, event)
            if key not in self._kernel_keys:
                self._kernel_keys.add(key)
                self._kernel.append((key, event))

    def run(self):
        """The API events, and the kernel's where no API event says the
        same, in time order.
        @return: Summary of keys, mutexes and files.
        """
        events = self.events + [event for key, event in self._kernel if key not in self._api_keys]
        events.sort(key=lambda e: _timestamp_key(e["timestamp"]))
        for eid, event in enumerate(events, 1):
            event["eid"] = eid
        return events


class Anomaly:
    """Anomaly detected during analysis.
    For example: a malware tried to remove Cuckoo's hooks.

    capemon reports its own as calls of category `anomaly`; DRAKVUF has none
    of those, and its detection plugins say what the process did instead:
    cpuidmon a CPUID that asks for the hypervisor (both systems), debugmon a
    debug exception the process raised, ptracemon a ptrace (Linux), ebpfmon
    an eBPF program loaded (Linux), rootkitmon a kernel structure changed
    (Windows; the kernel's, no process's: read from its aux log). Each
    distinct finding once per process, in CAPE's shape.
    """

    key = "anomaly"

    # CPUID leaves where a hypervisor names itself (0x40000000: "KVMKVMKVM",
    # "XenVMMXenVMM", "Microsoft Hv"...): only a check for one asks
    HYPERVISOR_LEAVES = range(0x40000000, 0x40000100)
    # debugmon's kinds a process raises; the rest (external interrupts,
    # NMIs) are the hardware's
    DEBUG_KINDS = ("software interrupt", "software exception", "ICEBP", "hardware exception")
    # ptrace requests that act on another process
    PTRACE_ATTACH = ("PTRACE_ATTACH", "PTRACE_SEIZE")
    PTRACE_WRITE = ("PTRACE_POKETEXT", "PTRACE_POKEDATA", "PTRACE_POKEUSER", "PTRACE_SETREGS",
                    "PTRACE_SETFPREGS", "PTRACE_SETREGSET")

    def __init__(self, aux_path=None):
        self.anomalies = []
        self.aux_path = aux_path
        self._seen = set()

    def _add(self, name, pid, category, funcname, message, key=None):
        seen = (pid, category, funcname, key if key is not None else message)
        if seen in self._seen:
            return
        self._seen.add(seen)
        self.anomalies.append({"name": name, "pid": pid, "category": category,
                               "funcname": funcname, "message": message})

    def event_apicall(self, call, process):
        """Process API calls.
        @param call: API call object
        @param process: process object
        """
        name, pid = process["process_name"], process["process_id"]
        if call["category"] == "anomaly":
            category, funcname, message = None, None, None
            for row in call["arguments"]:
                if row["name"] == "Subcategory":
                    category = row["value"]
                elif row["name"] == "FunctionName":
                    funcname = row["value"]
                elif row["name"] == "Message":
                    message = row["value"]
            self.anomalies.append({"name": name, "pid": pid, "category": category,
                                   "funcname": funcname, "message": message})
            return

        plugin = call.get("plugin")
        if plugin not in ("cpuidmon", "debugmon", "ptracemon", "ebpfmon"):
            return
        args = {a["name"]: a["value"] for a in call["arguments"]}

        if plugin == "cpuidmon":
            leaf = _parse_int(args.get("Leaf"))
            if leaf is not None and leaf in self.HYPERVISOR_LEAVES:
                self._add(name, pid, "anti-vm", "cpuid",
                          f"CPUID leaf {leaf:#x}: asks which hypervisor it runs under", key=leaf)
        elif plugin == "debugmon":
            kind = args.get("DebugTypeStr")
            if kind in self.DEBUG_KINDS:
                self._add(name, pid, "anti-debug", kind,
                          f"raised a {kind} (at {args.get('RIP')}): a debugger's, or a check for one",
                          key=kind)
        elif plugin == "ptracemon":
            # the PID arrives as CAPE prints a number: in hex
            request, target = args.get("Type"), _parse_int(args.get("TargetPID"))
            target_name = args.get("TargetProcessName") or ""
            if request == "PTRACE_TRACEME":
                self._add(name, pid, "anti-debug", "ptrace",
                          "PTRACE_TRACEME: traces itself, so no debugger can attach", key=request)
            elif request in self.PTRACE_ATTACH and target != _parse_int(pid):
                self._add(name, pid, "injection", "ptrace",
                          f"{request} {target_name} ({target}): takes control of another process",
                          key=(request, target))
            elif request in self.PTRACE_WRITE and target != _parse_int(pid):
                self._add(name, pid, "injection", "ptrace",
                          f"{request} {target_name} ({target}): writes into another process",
                          key=(request, target))
        elif plugin == "ebpfmon":
            if args.get("Value") == "BPF_PROG_LOAD":
                program = args.get("Type") or "unknown type"
                self._add(name, pid, "kernel", "bpf", f"loads an eBPF program ({program}) into the kernel",
                          key=program)

    def run(self):
        """Fetch all anomalies, the kernel's (rootkitmon) after the processes'."""
        from .modules import aux_records   # modules imports this module

        for rec in aux_records(self.aux_path, "rootkitmon"):
            what = " ".join(str(rec[k]) for k in ("Action", "Name") if rec.get(k))
            if rec.get("Module"):
                what += f" ({rec['Module']})"
            self._add("kernel", 4, "rootkit", rec.get("Type"), what or rec.get("Type"))
        return self.anomalies

class ProcessTree:
    """Generates process tree."""

    key = "processtree"

    def __init__(self):
        self.processes = []
        self.seen = set()

    def event_process(self, process):
        """Every process the behaviour has, whether it made a call or not:
        upstream added a node at a process's first call, so one that made
        none -- a child that exec'd at once, one outside the hooked set --
        left its children without a parent."""
        # id(): one node per process instance, a reused PID included
        if id(process) in self.seen:
            return
        self.seen.add(id(process))
        self.processes.append(
            {
                "name": process["process_name"],
                "pid": process["process_id"],
                "parent_id": process["parent_id"],
                "module_path": process["module_path"],
                "threads": process["threads"],
                "environ": process["environ"],
                "first_seen": process.get("first_seen"),
                "seqid": process.get("seqid"),
                "parent_seqid": process.get("parent_seqid"),
            }
        )

    def event_apicall(self, call, process):
        self.event_process(process)

    def run(self):
        # Index processes by PID.
        # This implementation uses an iterative approach to build the tree and detects cycles
        # to prevent infinite recursion or excessive depth that causes JSON serialization issues.
        # A PID can have had several processes (reuse): a child's parent is
        # the latest one with that PID started before the child, or the
        # earliest when none was (a parent the trace saw only later).
        by_pid = defaultdict(list)
        for p in self.processes:
            by_pid[p["pid"]].append(p)
        for instances in by_pid.values():
            instances.sort(key=lambda p: _start_key(p.get("first_seen")))

        # trace_split's own parent link, where the process has one: exact,
        # whatever PIDs were reused. By PID and start time otherwise.
        by_seqid = {p["seqid"]: p for p in self.processes if p.get("seqid") is not None}

        def parent_of(p):
            if p.get("parent_seqid") in by_seqid:
                return by_seqid[p["parent_seqid"]]
            candidates = by_pid.get(p.get("parent_id"))
            if not candidates:
                return None
            started = _start_key(p.get("first_seen"))
            before = [c for c in candidates if _start_key(c.get("first_seen")) <= started and c is not p]
            return before[-1] if before else candidates[0]

        parents = {id(p): parent_of(p) for p in self.processes}
        roots = []

        # Initialize children list for all processes
        for p in self.processes:
            p["children"] = []

        # Each process level adds two container levels (dict + children list) in JSON/BSON.
        # Capping tree depth at 64 (~132 container levels) stays well below both MongoDB's
        # BSON nesting limit (code 15 Overflow at 200) and orjson's 254-level recursion limit.
        max_depth = 64
        detached_roots = set()

        for p in self.processes:
            parent_pid = p.get("parent_id")
            parent = parents[id(p)]

            # Check if parent exists and is not self (self-parenting treated as root)
            if parent is not None and parent is not p:

                # Cycle Detection & Depth Bounding: Traverse ancestry to ensure 'p' is not
                # an ancestor of 'parent' and that attaching 'p' does not exceed max_depth.
                curr = parent
                is_cycle = False
                depth = 1

                while depth <= max_depth:
                    if curr is p:
                        is_cycle = True
                        break
                    if id(curr) in detached_roots:
                        break

                    # Move up to the next parent
                    up = parents.get(id(curr))
                    if up is not None and up is not curr:
                        curr = up
                        depth += 1
                    else:
                        # Reached a root or unknown parent
                        break

                sub_depth = 0
                if not is_cycle and depth <= max_depth and p["children"]:
                    stack = [(p, 0)]
                    while stack:
                        node, d = stack.pop()
                        if d > sub_depth:
                            sub_depth = d
                        for child in node["children"]:
                            stack.append((child, d + 1))

                if not is_cycle and depth + sub_depth <= max_depth:
                    parent["children"].append(p)
                else:
                    # Cycle detected or depth limit hit, treat as root to avoid breaking JSON
                    log.warning(
                        "Cycle or deep nesting detected for process %s (parent %s). treating as root.", p["pid"], parent_pid
                    )
                    detached_roots.add(id(p))
                    roots.append(p)
            else:
                roots.append(p)

        return roots


class EncryptedBuffers:
    """The data a process enciphered: CAPE's SslEncryptPacket, CryptEncrypt
    and CryptEncryptMessage buffers, and every other crypto API the hook
    lists print a plaintext for, on both systems -- BCrypt, DPAPI, SSPI's
    EncryptMessage, OpenSSL (SSL_write, EVP_EncryptUpdate) and GnuTLS. The
    decrypting side as well (`direction`): what a C2 answer said is the
    other half of the conversation. A key's algorithm, and its bytes where
    the process handed them over in the clear, from the call that made the
    handle (`algorithm`, `key`)."""

    key = "encryptedbuffers"

    # canonical API -> (the plaintext's argument names, its size's, direction)
    _PLAINTEXT = {
        "SslEncryptPacket": (("Buffer", "pbInput"), ("BufferSize", "cbInput"), "encrypt"),
        "SslDecryptPacket": (("pbOutput",), (), "decrypt"),
        "CryptEncrypt": (("Buffer", "pbData"), (), "encrypt"),
        "CryptDecrypt": (("Buffer", "pbData"), (), "decrypt"),
        "CryptEncryptMessage": (("Buffer", "pbToBeEncrypted"), ("cbToBeEncrypted",), "encrypt"),
        "CryptDecryptMessage": (("pbDecrypted",), (), "decrypt"),
        "BCryptEncrypt": (("pbInput",), ("cbInput",), "encrypt"),
        "BCryptDecrypt": (("pbOutput",), (), "decrypt"),
        "CryptProtectData": (("pDataIn",), (), "encrypt"),
        "CryptUnprotectData": (("pDataOut",), (), "decrypt"),
        "EncryptMessage": (("pMessage",), (), "encrypt"),
        "DecryptMessage": (("pMessage",), (), "decrypt"),
        "SSL_write": (("Buf",), ("Num",), "encrypt"),
        "SSL_write_ex": (("Buf",), ("Num",), "encrypt"),
        "SSL_read": (("Buf",), (), "decrypt"),
        "SSL_read_ex": (("Buf",), (), "decrypt"),
        "EVP_EncryptUpdate": (("In",), ("InLen",), "encrypt"),
        "EVP_DecryptUpdate": (("Out",), (), "decrypt"),
        "gnutls_record_send": (("Data",), ("Size",), "encrypt"),
        "gnutls_record_recv": (("Data",), (), "decrypt"),
    }
    # The symmetric and key-exchange ALG_IDs (wincrypt.h)
    _ALG_IDS = {
        0x6601: "DES", 0x6602: "RC2", 0x6603: "3DES", 0x6604: "DESX", 0x6609: "3DES_112",
        0x660E: "AES_128", 0x660F: "AES_192", 0x6610: "AES_256", 0x6611: "AES",
        0x6801: "RC4", 0x6802: "SEAL", 0xA400: "RSA_KEYX", 0x2400: "RSA_SIGN",
        0xAA01: "DH_SF", 0xAA02: "DH_EPHEM",
    }
    _PLAINTEXTKEYBLOB = 0x8
    _KEY_DATA_BLOB_MAGIC = 0x4D42444B       # BCRYPT_KEY_DATA_BLOB_MAGIC, "KDBM"

    def __init__(self):
        self.bufs = []
        # (api_call, buffer) pairs already recorded. The guard below used to be
        # `buf not in self.bufs`, comparing a str against a list of dicts: always true,
        # so nothing was ever deduplicated and every check walked the whole list.
        self.seen = set()
        # pid -> {key handle: {"algorithm": ..., "key": hex}}, and
        # pid -> {BCrypt algorithm handle: its name}
        self._keys = defaultdict(dict)
        self._algorithms = defaultdict(dict)

    def get_argument(self, call, argname, strip=False):
        return next(
            (arg["value"].strip() if strip else arg["value"] for arg in call["arguments"] if arg["name"] == argname),
            None,
        )

    def get_raw_argument(self, call, argname):
        return next(
            (arg["raw_value"] for arg in call["arguments"] if arg["name"] == argname),
            None,
        )

    def _arg(self, call, names):
        for name in names:
            value = self.get_argument(call, name)
            if value is not None:
                return value
        return None

    def _record(self, api_call, buf, entry):
        key = (api_call, buf)
        if key in self.seen:
            return
        self.seen.add(key)
        self.bufs.append(entry)

    @staticmethod
    def _bytes(value):
        """A buffer argument's bytes: the parser decodes DRAKVUF's \\xHH
        escapes to one character per byte."""
        try:
            return value.encode("latin-1")
        except (AttributeError, UnicodeEncodeError):
            return None

    def _note_key(self, call, pid, name):
        """A key handle a call returned, with what it is."""
        if name in ("CryptGenKey", "CryptDeriveKey", "CryptImportKey"):
            handle = _parse_int(self.get_argument(call, "phKey"))
            if not handle:
                return
            info = {}
            if name == "CryptImportKey":
                blob = self._bytes(self._arg(call, ("KeyBlob", "pbData")))
                if blob and len(blob) >= 8:
                    b_type, alg = blob[0], struct.unpack_from("<I", blob, 4)[0]
                    info["algorithm"] = self._ALG_IDS.get(alg, hex(alg))
                    if b_type == self._PLAINTEXTKEYBLOB and len(blob) >= 12:
                        size = struct.unpack_from("<I", blob, 8)[0]
                        info["key"] = blob[12:12 + size].hex()
            else:
                alg = _parse_int(self.get_argument(call, "Algid"))
                if alg is not None:
                    info["algorithm"] = self._ALG_IDS.get(alg, hex(alg))
            self._keys[pid][handle] = info
        elif name == "BCryptOpenAlgorithmProvider":
            handle = _parse_int(self.get_argument(call, "phAlgorithm"))
            algorithm = self.get_argument(call, "pszAlgId")
            if handle and algorithm:
                self._algorithms[pid][handle] = algorithm
        elif name in ("BCryptGenerateSymmetricKey", "BCryptImportKey"):
            handle = _parse_int(self.get_argument(call, "phKey"))
            if not handle:
                return
            info = {}
            algorithm = self._algorithms[pid].get(_parse_int(self.get_argument(call, "hAlgorithm")))
            if algorithm:
                info["algorithm"] = algorithm
            if name == "BCryptGenerateSymmetricKey":
                secret = self._bytes(self.get_argument(call, "pbSecret"))
                if secret:
                    info["key"] = secret.hex()
            elif self.get_argument(call, "pszBlobType") == "KeyDataBlob":
                blob = self._bytes(self.get_argument(call, "pbInput"))
                if blob and len(blob) >= 12 and struct.unpack_from("<I", blob, 0)[0] == self._KEY_DATA_BLOB_MAGIC:
                    size = struct.unpack_from("<I", blob, 8)[0]
                    info["key"] = blob[12:12 + size].hex()
            self._keys[pid][handle] = info

    def event_apicall(self, call, process):
        """Generate processes list from streamed calls/processes.
        @return: None.
        """

        if (not call.get("api")):
            return

        name = canonical(call["api"])
        pid = process["process_id"]
        self._note_key(call, pid, name)
        spec = self._PLAINTEXT.get(name)
        if spec is None:
            return
        names, size_names, direction = spec
        buf = self._arg(call, names)
        # Nothing read: DRAKVUF printed the pointer alone
        if not isinstance(buf, str) or not buf or _ADDRESS.match(buf):
            return
        size = _parse_int(self._arg(call, size_names)) if size_names else None
        entry = {
            "process_name": process["process_name"],
            "pid": pid,
            "api_call": name,
            "direction": direction,
            "buffer": buf,
            "buffer_size": size if size is not None else len(buf),
        }
        handle = self._arg(call, ("CryptKey", "hKey"))
        if handle is not None:
            entry["crypt_key"] = handle
            entry.update(self._keys[pid].get(_parse_int(handle), {}))
        self._record(name, buf, entry)

    def run(self):
        """Get registry keys, mutexes and files.
        @return: Summary of keys, read keys, written keys, mutexes and files.
        """
        return self.bufs


def _timestamp_key(timestamp):
    """A call's TimeStamp (DRAKVUF's `sec.usec`) as a number to order by;
    unknown last."""
    try:
        return float(timestamp)
    except (TypeError, ValueError):
        return float("inf")


def _call_argument(call, name):
    return next((a["value"] for a in call["arguments"] if a["name"] == name), None)


def _file_deleted(call):
    """Whether filetracer's NtSetInformationFile record deletes its file:
    the disposition classes, by their flag (a record from before filetracer
    printed DeleteFile counts as one)."""
    operation = call.get("operation")
    if operation == "FileDispositionInformation":
        return _parse_int(_call_argument(call, "DeleteFile")) != 0
    if operation == "FileDispositionInformationEx":
        # What DeleteFileW sends since Windows 10 RS1. Flags by name, as
        # filetracer prints them (FILE_DISPOSITION_DELETE | ...)
        flags = _call_argument(call, "Flags")
        return "FILE_DISPOSITION_DELETE" in re.split(r"[|\s]+", str(flags or ""))
    return False


def _start_key(first_seen):
    """A process's start as a number to order instances of one PID by;
    unknown sorts first. `first_seen` is as Processes prints it (logtime:
    `2026-11-11 10:00:01,016`) -- float() of that failed on every process,
    which made every instance of a reused PID equally early."""
    if isinstance(first_seen, (int, float)):
        return float(first_seen)
    try:
        return datetime.datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S,%f").timestamp()
    except (TypeError, ValueError):
        return float("-inf")


_COM_HOST_PARENTS = {"svchost.exe", "dllhost.exe"}



def _enrich_tree_com_parents(tree_nodes, com_activations):
    """Walk the processtree and annotate nodes whose binary matches a COM activation record."""
    # Build lookup: target_binary_lower -> list of activations
    binary_map = {}
    for act in com_activations:
        binary = (act.get("target_binary") or "").lower()
        if not binary:
            # Fall back to ProgID heuristic
            progid = (act.get("progid") or "").lower()
            _progid_to_binary = {
                "htafile": "mshta.exe",
                "internetexplorer.application": "iexplore.exe",
                "shell.application": "explorer.exe",
            }
            binary = _progid_to_binary.get(progid, "")
        if binary:
            binary_map.setdefault(binary, []).append(act)

    def _walk(nodes, parent_name=None):
        for node in nodes:
            path = node.get("module_path") or node.get("name") or ""
            name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
            if name in binary_map and (parent_name is None or parent_name in _COM_HOST_PARENTS):
                act = next(
                    (
                        a
                        for a in binary_map[name]
                        if a.get("activator_pid") != node.get("pid")
                        and a.get("activator_pid") != node.get("parent_id")
                    ),
                    None,
                )
                if act:
                    node["com_logical_parent_pid"] = act["activator_pid"]
                    node["com_logical_parent_name"] = act["activator_name"]
                    node["com_progid"] = act.get("progid", "")
                    node["com_clsid"] = act.get("clsid", "")
            _walk(node.get("children") or [], parent_name=name)

    _walk(tree_nodes)


class BehaviorAnalysis(Processing):
    """Behavior Analyzer."""

    key = "behavior"

    def run(self):
        """Run analysis.
        @return: results dict.
        """

        behavior = {"processes": []}
        logs_path = getattr(self, "logs_path", None)
        if not logs_path or not path_exists(logs_path) or not os.listdir(logs_path):
            # No CAPE_REPORT/report.json fallback as upstream has: the
            # report.json beside a sandboxd job is sandboxd's, another schema.
            log.warning('No per-process logs at "%s"', logs_path)
            return behavior

        behavior = {"processes": Processes(logs_path, self.task, self.options, self.platform).run()}

        instances = [
            Anomaly(getattr(self, "aux_path", None)),
            ProcessTree(),
            Summary(self.options),
            Enhanced(),
            EncryptedBuffers(),
            NetworkMap(self.options),
        ]
        enabled_instances = [instance for instance in instances if getattr(self.options, instance.key, True)]

        # One traceback per partial behaviour and exception type, then a
        # count: a handler that cannot read DRAKVUF's version of some call
        # fails on every such call, and upstream's per-call log.exception
        # turned that into one traceback per call.
        failures = Counter()
        if enabled_instances:
            # Iterate calls and tell interested signatures about them
            for process in behavior["processes"]:
                # Every process, calls or none (ProcessTree's nodes)
                for instance in enabled_instances:
                    if hasattr(instance, "event_process"):
                        instance.event_process(process)
                for call in process["calls"]:
                    for instance in enabled_instances:
                        try:
                            instance.event_apicall(call, process)
                        except Exception as e:
                            key = (instance.key, type(e).__name__)
                            if not failures[key]:
                                log.exception('Failure in partial behavior "%s"', instance.key)
                            failures[key] += 1
                # Reset the iterator so reporting modules can read the calls again
                with suppress(AttributeError):
                    process["calls"].reset()
        for (key, exc), count in failures.items():
            log.warning('Partial behavior "%s" raised %s on %d calls', key, exc, count)

        for instance in instances:
            try:
                behavior[instance.key] = instance.run()
            except Exception as e:
                log.exception('Failed to run partial behavior class "%s" due to "%s"', instance.key, e)

        # Enrich processtree nodes with COM logical parent relationships
        com_acts = (behavior.get("network_map") or {}).get("com_activations") or []
        if com_acts and behavior.get("processtree"):
            _enrich_tree_com_parents(behavior["processtree"], com_acts)

        # https://github.com/mandiant/capa/issues/2620
        # Upstream runs this for PE files only; the CAPE extractor takes an
        # ELF as well (capa_integration.capa_report says how), and the
        # calls here include the syscalls.
        if HAVE_FLARE_CAPA and getattr(self.options, "capa", False):
            try:
                self.results["capa_summary"] = flare_capa_details(
                    results={"behavior": behavior, **self.results},
                    rules_path=self.options.capa_rules,
                    pids=self.options.capa_pids,
                )
            except Exception as e:
                log.exception("Can't generate CAPA summary: %s", e)
        return behavior
