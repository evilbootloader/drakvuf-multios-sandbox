"""Registry writes, from regmon.log. Not an upstream plugin.

drakvuf-sandbox shows regmon only in its raw log viewer. Here the writes are
summarised into the report the way filetracer's are: what was set, created and
deleted, by which process. Reads are left out -- on a 184k-line regmon.log
(trace-windows.log, 2026-09-19) 181k were NtQueryKey / NtOpenKeyEx /
NtQueryValueKey, and the 1.2k writes are the part that says what the sample
changed.
"""

from collections import defaultdict
from typing import Optional

from .parse_utils import parse_log
from .plugin_base import PostprocessContext

# Value data is a hex dump for binary values and can run to kilobytes; the
# report keeps the start. The platform cuts every string again on its side.
MAX_VALUE_CHARS = 512

# Key paths under which a write is the classic way to survive a reboot or a
# logon. Matched case-insensitively as substrings of the full \REGISTRY\...
# path. An observation to flag, not a classification: the guest's own
# services write here too.
AUTOSTART_MARKERS = (
    "\\CURRENTVERSION\\RUN",             # Run, RunOnce, RunOnceEx, RunServices
    "\\CURRENTVERSION\\POLICIES\\EXPLORER\\RUN",
    "\\CURRENTVERSION\\WINLOGON",        # Shell, Userinit, Notify
    "\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS",
    "\\CURRENTVERSION\\EXPLORER\\USER SHELL FOLDERS",
    "\\SESSION MANAGER\\APPINIT_DLLS",
    "\\WINDOWS\\APPINIT_DLLS",
    "\\CURRENTCONTROLSET\\SERVICES\\",
    "\\CURRENTVERSION\\IMAGE FILE EXECUTION OPTIONS\\",
    "\\CLASSES\\EXEFILE\\SHELL\\OPEN\\COMMAND",
    "\\CURRENTVERSION\\SHELLSERVICEOBJECTDELAYLOAD",
    "\\CURRENTVERSION\\EXPLORER\\BROWSER HELPER OBJECTS",
    "\\ENVIRONMENT\\",
)


# Markers that mean something only when a VALUE is written there. NtCreateKey
# is open-or-create, and every service opens its own Services\<name>\...
# key: on a Notepad run, svchost creating Tcpip\Parameters was the one
# "autostart" hit (2026-09-19), which is noise, not a finding.
VALUE_ONLY_MARKERS = ("\\CURRENTCONTROLSET\\SERVICES\\",)


def is_autostart(key: str, created: bool = False) -> bool:
    upper = key.upper()
    return any(marker in upper for marker in AUTOSTART_MARKERS
               if not (created and marker in VALUE_ONLY_MARKERS))


def get_registry_info(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    process_tree = context.process_tree

    def filter_writes(data: dict) -> Optional[dict]:
        method = data.get("Method")
        if method not in ("NtSetValueKey", "NtCreateKey", "NtDeleteKey",
                          "NtDeleteValueKey"):
            return None
        key = data.get("Key")
        if not key:
            return None
        event_uid = int(data["EventUID"], 16)
        process = process_tree.get_process_for_evtid(data["PID"], event_uid)
        value = data.get("Value")
        if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
            value = value[:MAX_VALUE_CHARS] + "…"
        return {
            "method": method,
            "key": key,
            "value_name": data.get("ValueName"),
            "value": value,
            # None when the tree does not know the PID: kept, and shown as
            # unattributed, rather than dropped.
            "seqid": process.seqid if process is not None else None,
        }

    # Grouped per (key, value name): a value set ten times is one row with
    # the last data seen, and the processes that touched it.
    set_values: dict = {}
    created_keys = defaultdict(set)
    deleted_keys = defaultdict(set)
    deleted_values = defaultdict(set)

    for entry in parse_log(analysis_dir / "regmon.log", filter_writes):
        key, name, seqid = entry["key"], entry["value_name"], entry["seqid"]
        if entry["method"] == "NtSetValueKey":
            row = set_values.setdefault((key, name), {"value": None, "seqids": set()})
            row["value"] = entry["value"]
            row["seqids"].add(seqid)
        elif entry["method"] == "NtCreateKey":
            created_keys[key].add(seqid)
        elif entry["method"] == "NtDeleteKey":
            deleted_keys[key].add(seqid)
        elif entry["method"] == "NtDeleteValueKey":
            deleted_values[(key, name)].add(seqid)

    def seqids(values: set) -> list:
        # None sorts last: the unattributed reference after the known ones.
        return sorted(values, key=lambda s: (s is None, s if s is not None else 0))

    context.update_report({
        "registry_set_values": [
            {"key": key, "value_name": name, "value": row["value"],
             "autostart": is_autostart(key),
             "process_seqids": seqids(row["seqids"])}
            for (key, name), row in sorted(set_values.items(),
                                           key=lambda kv: (kv[0][0], kv[0][1] or ""))
        ],
        "registry_created_keys": [
            {"key": key, "autostart": is_autostart(key, created=True),
             "process_seqids": seqids(procs)}
            for key, procs in sorted(created_keys.items())
        ],
        "registry_deleted_keys": [
            {"key": key, "process_seqids": seqids(procs)}
            for key, procs in sorted(deleted_keys.items())
        ],
        "registry_deleted_values": [
            {"key": key, "value_name": name, "process_seqids": seqids(procs)}
            for (key, name), procs in sorted(deleted_values.items(),
                                             key=lambda kv: (kv[0][0], kv[0][1] or ""))
        ],
    })
