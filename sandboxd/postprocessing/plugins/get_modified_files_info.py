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

    def filter_modified_files_windows(data: dict) -> Optional[dict]:
        method_name = data.get("Method")
        if method_name == "NtSetInformationFile":
            if data.get("Operation") != "FileDispositionInformation":
                return None
            method = "delete"

        elif method_name in ("NtCreateFile", "NtOpenFile"):
            desired_access_raw = data.get("DesiredAccess", "")

            if not isinstance(desired_access_raw, str):
                return None

            desired_access = [
                access.strip()
                for access in desired_access_raw.split(" | ")
            ]

            if not any(
                access
                in ["GENERIC_WRITE", "FILE_WRITE_DATA", "FILE_APPEND_DATA", "DELETE", "FILE_READ_DATA", "GENERIC_READ"] 
                for access in list(desired_access)
            ):
                return None

            filename = data.get("FileName").lower()

            if not filename.startswith("\\??\\"):
                return None

            path = pathlib.PureWindowsPath(filename[len("\\??\\") :])
            if not path.drive:
                return None

            method = "open"

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

        try:
            event_uid = int(data["EventUID"], 16)
            pid = data["PID"]
        except (KeyError, TypeError, ValueError):
            return None

        process = process_tree.get_process_for_evtid(pid, event_uid)
        return {
            "process": process,
            "handle": data.get("FileHandle"),
            "file_name": data.get("FileName"),
            "method": method,
        }

    def filter_modified_files_linux(data: dict) -> Optional[dict]:
        """Parse Linux filetracer operations, including those without FileName.

        Linux write/read syscalls may contain only FileHandle. Preserve these
        events so they can be joined to fileextractor by (PID, EventUID).
        Resolve/filter paths later, after the extractor has been consulted.
        """
        syscall = data.get("Syscall")
        changes_on_open = False

        if syscall in ("unlink", "unlinkat", "rmdir"):
            method = "delete"
        elif syscall in ("open", "openat", "openat2", "creat"):
            method = "open"
            try:
                flags = int(data.get("flags", 0))
            except (TypeError, ValueError):
                flags = 0
            changes_on_open = bool(flags & (os.O_CREAT | os.O_TRUNC))
            if hasattr(os, "O_TMPFILE"):
                changes_on_open |= (flags & os.O_TMPFILE) == os.O_TMPFILE
            if syscall == "creat":
                changes_on_open = True
        elif syscall in ("write", "pwrite64", "writev", "pwritev", "pwritev2",
                         "ftruncate", "truncate", "fallocate", "rename", "renameat",
                         "renameat2", "mkdir", "mkdirat", "symlink", "symlinkat"):
            method = "write"
        elif syscall in ("read", "pread64", "readv", "preadv", "preadv2"):
            method = "read"
        elif syscall == "close":
            method = "close"
        else:
            return None

        try:
            event_uid = int(data["EventUID"], 16)
            pid = int(data["PID"])
        except (KeyError, TypeError, ValueError):
            return None

        filename = data.get("FileName")
        if not isinstance(filename, str) or not filename.startswith("/"):
            filename = None

        return {
            "process": process_tree.get_process_for_evtid(pid, event_uid),
            "pid": pid,
            "event_uid": event_uid,
            "file_name": filename,
            "handle": data.get("FileHandle"),
            "method": method,
            "changes_on_open": changes_on_open,
        }

    def find_extracted_files(data: dict) -> Optional[dict]:
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
            "pid": int(pid),
            "event_uid": event_uid,
            "file_name": data.get("FileName"),
            "seq_num": data.get("SeqNum"),
            "timestamp": data.get("TimeStamp"),
            "dump_file": data.get("DumpFile"),
        }

    if context.target_os == TargetOs.WINDOWS:
        modified_files_log = parse_log(
            analysis_dir / "filetracer.log", filter_modified_files_windows
        )
    else:
        modified_files_log = parse_log(
            analysis_dir / "filetracer.log", filter_modified_files_linux
        )

    extracted_files_log = parse_log(
            analysis_dir / "fileextractor.log", find_extracted_files
        )

    opened_files = {}
    modified_files = defaultdict(set)
    deleted_files = defaultdict(set)
    read_files = defaultdict(set)
    extracted_files = defaultdict(list)

    if context.target_os == TargetOs.WINDOWS:

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

        def normalize_filename(filename):
            if filename.startswith("\\??"):
                filename = filename[len("\\??"):]
            if filename.lower().startswith("c:"):
                filename = filename[len("c:"):]
            if filename.lower().startswith("\\\\device\\\\harddiskvolume2\\"):
                filename = filename[len("\\\\Device\\\\HarddiskVolume2\\"):]
            return filename.casefold()

        for data in extracted_files_log:
            if data["process"] is None or not data["file_name"]:
                continue

            key = (
                normalize_filename(data["file_name"]),
                data["process"].seqid,
            )
            extracted_files[key].append(int(data["seq_num"]))

        def build_report(files):
            return [
                {
                    "filename": filename,
                    "extracted": sorted(
                        seq_num
                        for seqid in files[filename]
                        for seq_num in extracted_files.get(
                            (normalize_filename(filename), seqid), [])
                        if seq_num is not None
                    ),
                    "process_seqids": sorted(files[filename]),
                }
                for filename in sorted(files)
            ]

        context.update_report({
            "modified_files": build_report(modified_files),
            "deleted_files": build_report(deleted_files),
            "read_files": build_report(read_files),
        })
    
    else:
        # (PID, EventUID) identifies the SAME syscall in both plugins.
        # Timestamps alone are not reliable matching keys, and Linux
        # fileextractor logs use DumpFile rather than SeqNum.
        extractor_by_event = defaultdict(list)
        for data in extracted_files_log:
            dump_file = data.get("dump_file")
            if not isinstance(dump_file, str) or not dump_file:
                continue

            seq_num = data.get("seq_num")
            if seq_num is None:
                stem = pathlib.PurePosixPath(dump_file).name.split("_", 1)[0]
                if len(stem) != 8 or not stem.isdigit():
                    continue
                seq_num = stem

            extractor_by_event[(data["pid"], data["event_uid"])].append(
                (int(seq_num), data.get("file_name"))
            )

        excluded_paths = (
            "/proc", "/sys", "/dev", "/run", "/var/cache", "/var/log",
            "/var/tmp/systemd-private",
        )
        excluded_files = {"/etc/ld.so.cache"}

        def valid_linux_path(filename):
            if not isinstance(filename, str) or not filename.startswith("/"):
                return None
            filename = str(pathlib.PurePosixPath(filename))
            if filename in excluded_files or any(
                filename == prefix or filename.startswith(prefix + "/")
                for prefix in excluded_paths
            ):
                return None
            return filename

        extracted_by_filename = defaultdict(set)
        for data in modified_files_log:
            process = data["process"]
            if process is None:
                continue
            seqid = process.seqid
            handle = data["handle"]
            handle_key = (seqid, handle) if handle is not None else None
            event_key = (data["pid"], data["event_uid"])
            extracted = extractor_by_event.get(event_key, [])
            method = data["method"]

            # Some Linux builds expose a handle on open, others only a path.
            if method == "open":
                filename = valid_linux_path(data["file_name"])
                if handle_key is not None and filename:
                    opened_files[handle_key] = filename
                if filename and data["changes_on_open"]:
                    modified_files[filename].add(seqid)
                continue

            if method == "close":
                if handle_key is not None:
                    opened_files.pop(handle_key, None)
                continue

            # Prefer filetracer's path; use fileextractor's path when the
            # syscall has only a file descriptor. unknown_fd_N is NOT a path.
            filename = valid_linux_path(data["file_name"])
            if filename is None:
                for _, extracted_name in extracted:
                    filename = valid_linux_path(extracted_name)
                    if filename:
                        break
            if filename is None and handle_key is not None:
                filename = valid_linux_path(opened_files.get(handle_key))
            if filename is None:
                continue

            if method == "delete":
                deleted_files[filename].add(seqid)
            elif method == "write":
                modified_files[filename].add(seqid)
            elif method == "read":
                read_files[filename].add(seqid)

            if extracted:
                extracted_by_filename[filename].update(
                    int(seq_num) for seq_num, _ in extracted
                )

        def build_report(files):
            return [
                {
                    "filename": filename,
                    "extracted": sorted(extracted_by_filename.get(filename, ())),
                    "process_seqids": sorted(files[filename]),
                }
                for filename in sorted(files)
            ]

        context.update_report({
            "modified_files": build_report(modified_files),
            "deleted_files": build_report(deleted_files),
            "read_files": build_report(read_files),
        })
