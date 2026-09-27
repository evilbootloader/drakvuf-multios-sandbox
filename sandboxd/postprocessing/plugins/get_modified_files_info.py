import pathlib
from collections import defaultdict
from typing import Optional
import os

from .parse_utils import parse_log
from .plugin_base import PostprocessContext
from ...guests import TargetOs

def get_modified_files_info(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    process_tree = context.process_tree

    def filter_files_windows(data: dict) -> Optional[dict]:
        method_name = data.get("Method")

        if method_name == "NtSetInformationFile":
            if data.get("Operation") != "FileDispositionInformation":
                return None
            method = "delete"

        elif method_name in ("NtCreateFile", "NtOpenFile"):
            desired_access_raw = data.get("DesiredAccess", "")

            if not isinstance(desired_access_raw, str):
                return None

            desired_access = {
                access.strip()
                for access in desired_access_raw.split(" | ")
            }

            write_access = {
                "GENERIC_WRITE",
                "GENERIC_ALL",
                "FILE_WRITE_DATA",
                "FILE_APPEND_DATA",
                "FILE_WRITE_ATTRIBUTES",
                "FILE_WRITE_EA",
                "DELETE",
            }

            read_access = {
                "GENERIC_READ",
                "GENERIC_ALL",
                "FILE_READ_DATA",
            }

            if desired_access.intersection(write_access):
                method = "write"
            elif desired_access.intersection(read_access):
                method = "read"
            else:
                return None

        elif method_name == "NtWriteFile":
            method = "write"

        elif method_name == "NtReadFile":
            method = "read"

        else:
            return None

        filename = data.get("FileName")

        if not filename or not isinstance(filename, str):
            return None

        filename_lower = filename.lower()

        # Only normal NT drive paths such as:
        # \??\C:\Windows\...
        nt_prefix = "\\??\\"

        if not filename_lower.startswith(nt_prefix):
            return None

        windows_path_str = filename[len(nt_prefix):]
        path = pathlib.PureWindowsPath(windows_path_str)

        if not path.drive:
            return None

        normalized = str(path)
        normalized_lower = normalized.lower()

        # Very noisy OS/cache paths
        excluded_paths = (
            "\\windows\\prefetch",
        )

        if any(
            excluded in normalized_lower
            for excluded in excluded_paths
        ):
            return None

        excluded_files = {
            "pagefile.sys",
            "swapfile.sys",
            "hiberfil.sys",
            "memory.dmp",
        }

        if path.name.lower() in excluded_files:
            return None

        try:
            event_uid = int(data["EventUID"], 16)
            pid = data["PID"]
        except (KeyError, TypeError, ValueError):
            return None

        process = process_tree.get_process_for_evtid(
            pid,
            event_uid,
        )

        return {
            "process": process,
            "handle": data.get("FileHandle"),
            "file_name": data["FileName"],
            "method": method,
        }

    def filter_modified_files_linux(data: dict) -> Optional[dict]:
        """
        Filter DRAKVUF filetracer Linux events and return filesystem
        operations that may modify persistent or otherwise interesting files.

        Filters:
        - read-only opens
        - virtual filesystems (/proc, /sys, /dev, /run)
        - common high-volume OS/cache/log paths

        Keeps potentially interesting malware locations such as:
        /etc
        /usr
        /var/lib
        /var/spool
        /tmp
        /home
        /root
        /opt
        """

        syscall = data.get("Syscall")

        # ------------------------------------------------------------
        # Paths to completely ignore
        # ------------------------------------------------------------

        excluded_paths = (
            # Virtual / pseudo filesystems
            "/proc",
            "/sys",
            "/dev",
            "/run",

            # High-volume caches
            "/var/cache",

            # Logs are usually very noisy and generally don't represent
            # meaningful filesystem modification by the analysed sample.
            "/var/log",

            # Temporary system state
            "/var/tmp/systemd-private",
        )

        # ------------------------------------------------------------
        # Determine operation type
        # ------------------------------------------------------------

        if syscall in (
            "unlink",
            "unlinkat",
            "rmdir",
        ):
            method = "delete"

        elif syscall in (
            "open",
            "openat",
        ):
            try:
                flags = int(data.get("flags", 0))
            except (TypeError, ValueError):
                return None

            # O_RDONLY == 0, therefore use O_ACCMODE.
            access_mode = flags & os.O_ACCMODE

            writable = access_mode in (
                os.O_WRONLY,
                os.O_RDWR,
            )

            modifies = (
                writable
                or bool(flags & os.O_CREAT)
                or bool(flags & os.O_TRUNC)
            )

            if hasattr(os, "O_TMPFILE"):
                modifies = modifies or bool(flags & os.O_TMPFILE)

            if not modifies:
                return None

            method = "open"

        elif syscall in (
            "write",
            "pwrite64",
            "ftruncate",
        ):
            method = "write"

        elif syscall in (
            "rename",
            "renameat",
        ):
            method = "write"

        elif syscall in (
            "mkdir",
            "symlink",
        ):
            method = "write"

        else:
            return None

        # ------------------------------------------------------------
        # Get filename
        # ------------------------------------------------------------

        filename = data.get("FileName")

        if not filename:
            return None

        if not filename.startswith("/"):
            return None

        path = pathlib.PurePosixPath(filename)
        path_str = str(path)

        # ------------------------------------------------------------
        # Ignore noisy paths
        # ------------------------------------------------------------

        if any(
            path_str == prefix or path_str.startswith(prefix + "/")
            for prefix in excluded_paths
        ):
            return None

        # ------------------------------------------------------------
        # Ignore some known high-frequency individual files
        # ------------------------------------------------------------

        excluded_files = {
            "/etc/ld.so.cache",
        }

        if path_str in excluded_files:
            return None

        try:
            event_uid = int(data["EventUID"], 16)
            pid = data["PID"]
        except (KeyError, TypeError, ValueError):
            return None

        process = process_tree.get_process_for_evtid(
            pid,
            event_uid,
        )
        # ------------------------------------------------------------
        # Normalize event
        # ------------------------------------------------------------

        return {
            "process": process,
            #"handle": data["FileHandle"],
            "file_name": data["FileName"],
            "method": method,
        }

    if context.target_os == TargetOs.WINDOWS:
        modified_files_log = parse_log(
            analysis_dir / "filetracer.log", filter_modified_files_windows
        )
    else:
        modified_files_log = parse_log(
            analysis_dir / "filetracer.log", filter_modified_files_linux
        )

    opened_files = {}
    modified_files = defaultdict(set)
    deleted_files = defaultdict(set)
    read_files = defaultdict(set)

    for data in modified_files_log:
        seqid = data["process"].seqid
        key = (seqid, data["handle"])
        if data["method"] == "open":
            opened_files[key] = data["file_name"]
        elif key in opened_files:
            filename = opened_files[key]
            if filename.lower().startswith("\\??\\c:\\windows\\prefetch"):
                continue
            if filename.startswith("\\??\\"):
                filename = filename[len("\\??\\") :]
            if data["method"] == "delete":
                deleted_files[filename].add(seqid)
            elif data["method"] == "write":
                modified_files[filename].add(seqid)
            elif data["method"] == "read":
                read_files[filename].add(seqid)

    context.update_report(
        {
            "modified_files": [
                {
                    "filename": filename,
                    "process_seqids": sorted(list(modified_files[filename])),
                }
                for filename in sorted(modified_files.keys())
            ],
            "deleted_files": [
                {
                    "filename": filename,
                    "process_seqids": sorted(list(deleted_files[filename])),
                }
                for filename in sorted(deleted_files.keys())
            ],
        }
    )
