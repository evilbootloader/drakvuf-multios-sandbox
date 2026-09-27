"""Pack what `fileextractor` recovered, and attribute each file to a process.

The counterpart of `process_dumps` for DRAKVUF's `-D` directory: same shape
(parse the log, attribute by PID and event, filter by size, pack into a zip
beside the directory, remove the directory), and `stages._collect` reads the
EXTRACTED_DIR/EXTRACTED_ZIP pair exactly as it reads the dumps one.

**It is not a copy of `process_dumps`, because fileextractor is not memdump.**
Three differences, each of which silently loses evidence if ignored:

- **Linux writes no `.metadata` sidecar.** Only `win.cpp::save_file_metadata`
  does. `process_dumps` skips any dump whose sidecar is missing, so copying
  that guard would drop every extracted file on Ubuntu and Android -- the
  whole point of the plugin, on two of the three guests.

- **The on-disk name is per-OS.** Linux writes `%08d_<sanitized name>` and
  puts the full path in `DumpFile`; Windows writes `file.%06d.mm` beside
  `file.%06d.metadata` and puts only `SeqNum` in the log. Hence the per-OS
  table below rather than a branch, as `process_tree.METHOD_PARSERS` does it.

- **The directory is the ground truth, not the log.** A file DRAKVUF wrote but
  did not log -- a truncated run, a record lost to a parse error -- is still a
  file the sample wrote. Everything present is packed; the log supplies
  attribution where it can, and a file it cannot explain is kept with
  `process: null` rather than dropped, the same rule `process_dumps` follows
  for a dump whose PID the process tree never saw.
"""

import logging
import shutil
import zipfile
from collections import defaultdict
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Callable, Dict, Optional

from ...guests import TargetOs
from ..paths import EXTRACTED_DIR, EXTRACTED_ZIP
from .parse_utils import parse_log
from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)

# Records fileextractor emits that are not an extraction. `_fail` and `_skip`
# name a file that was NOT written, so treating them as extractions would
# invent artifacts; they are counted for the report instead. `_close` repeats
# an extraction already reported, with the process attached.
FAILURE_PLUGINS = ("fileextractor_fail", "fileextractor_skip")


def _linux_disk_name(data: Dict[str, Any]) -> Optional[str]:
    """`DumpFile` is an absolute Dom0 path; only the basename is portable.

    The job directory moves between Dom0 and the platform, so a path recorded
    at trace time does not resolve at postprocessing time on another host.
    """
    dump_file = data.get("DumpFile")
    if not dump_file:
        return None
    return PurePosixPath(dump_file).name


def _windows_disk_name(data: Dict[str, Any]) -> Optional[str]:
    """`file.%06d.mm`, rebuilt from SeqNum -- win.cpp::get_data_filename.

    The Windows record carries no path at all, so this is the only link
    between a log line and a file on disk.
    """
    seq = data.get("SeqNum")
    if seq is None:
        return None
    return f"file.{int(seq):06d}.mm"


def _windows_sidecar(name: str) -> Optional[str]:
    """`file.000007.mm` -> `file.000007.metadata`.

    **The extension is REPLACED, not appended.** Both names come from
    `win.cpp::get_filename(folder, idx, ext)`, which builds
    `file.<idx>.<ext>` -- so the sidecar is `.metadata` where the data file
    is `.mm`, and looking for `file.000007.mm.metadata` finds nothing.
    """
    stem, _, ext = name.rpartition(".")
    return f"{stem}.metadata" if ext == "mm" else None


def _linux_sidecar(name: str) -> Optional[str]:
    """None, always: `linux.cpp` has no `save_file_metadata`.

    Load-bearing rather than merely true. `process_extracted` derives the set of
    files to skip from this table, so returning None is what keeps a file the
    sample chose to call `*.metadata` in the evidence.
    """
    return None


# Which field names the file on disk, per guest OS. A per-OS table rather than
# a branch in the parser: a guest this does not know fails on the lookup
# instead of silently attributing nothing.
DISK_NAME: Dict[TargetOs, Callable[[Dict[str, Any]], Optional[str]]] = {
    TargetOs.WINDOWS: _windows_disk_name,
    TargetOs.UBUNTU: _linux_disk_name,
    TargetOs.ANDROID: _linux_disk_name,
}

# How a data file's metadata sidecar is named, per guest OS -- None where the
# guest writes none at all, which is every Linux guest.
SIDECAR_NAME: Dict[TargetOs, Callable[[str], Optional[str]]] = {
    TargetOs.WINDOWS: _windows_sidecar,
    TargetOs.UBUNTU: _linux_sidecar,
    TargetOs.ANDROID: _linux_sidecar,
}


def process_extracted(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    process_tree = context.process_tree
    config = context.config.extracted
    disk_name = DISK_NAME[context.target_os]
    sidecar_name = SIDECAR_NAME[context.target_os]

    extracted_path = analysis_dir / EXTRACTED_DIR
    target_zip = analysis_dir / EXTRACTED_ZIP

    failures: list[Dict[str, Any]] = []

    def parse_extraction(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        plugin = data.get("Plugin")
        if plugin in FAILURE_PLUGINS:
            failures.append(
                {
                    "filename": data.get("FileName"),
                    "reason": data.get("Message"),
                    "pid": data.get("PID"),
                }
            )
            return None
        name = disk_name(data)
        if name is None:
            return None
        pid = data.get("PID")
        # `process` is None when the tree does not know the PID -- or when the
        # record carries no PID at all, which the Linux `fileextractor` line
        # does not always. The file is kept either way; attribution is a
        # property of the evidence, not a condition for keeping it.
        process = None
        if pid is not None and "EventUID" in data:
            process = process_tree.get_process_for_evtid(
                pid, int(data["EventUID"], 16)
            )
            if process is None:
                logger.warning(
                    "extracted file from PID %s, which the process tree does "
                    "not know", pid
                )
        # The guest's own path for the file, with the name the SAMPLE chose --
        # never spliced into a shell, only reported. Windows paths keep their
        # separators, so the basename is taken with the matching flavour.
        guest_path = data.get("FileName")
        return {
            "disk_name": name,
            "guest_path": guest_path,
            "pid": pid,
            "process": process,
            "reason": data.get("Reason"),
            "size": data.get("Size"),
            "sha256": data.get("FileHash"),
        }

    log_path = analysis_dir / "fileextractor.log"
    by_disk_name: Dict[str, Dict[str, Any]] = {}
    if log_path.exists():
        for entry in parse_log(log_path, parse_extraction):
            # A later record for the same file wins: `fileextractor_close`
            # repeats the extraction once the handle is closed, by which point
            # the size is final and the process is attached.
            by_disk_name[entry["disk_name"]] = entry
    else:
        logger.warning(
            "%s does not exist; extracted files are packed unattributed",
            log_path.name,
        )

    on_disk = sorted(p for p in extracted_path.rglob("*") if p.is_file())
    if not on_disk:
        logger.info("no extracted files to pack")

    # A metadata sidecar is packed with its data file (below) and is not itself
    # a file the sample wrote, so it does not become a report entry.
    #
    # **Recognised through the per-OS table, never by the `.metadata` suffix.**
    # Only Windows writes a sidecar, and only `win.cpp::get_filename` names it.
    # On Linux everything after `%08d_` is the name the SAMPLE chose --
    # `linux.cpp::sanitize_filename` replaces separators and non-printables and
    # nothing else -- so a sample that writes `/tmp/payload.metadata` lands on
    # disk as `00000001_payload.metadata`. A suffix test dropped that file from
    # the zip AND from the report, logging nothing, and the `rmtree` below then
    # deleted it: a sample could erase one of its own dropped files from the
    # evidence by choosing its name. `_linux_sidecar` returns None, so on Linux
    # and Android this set is empty and nothing is skipped.
    #
    # A sidecar whose data file is absent is NOT skipped: the directory is the
    # ground truth (module docstring), so an orphan is kept unattributed rather
    # than dropped.
    present = {p.relative_to(extracted_path).as_posix() for p in on_disk}
    sidecars = {side for name in present
                if (side := sidecar_name(name)) and side in present}

    files: list[Dict[str, Any]] = []
    skipped_large = 0
    current_size = 0
    for path in on_disk:
        rel = path.relative_to(extracted_path).as_posix()
        if rel in sidecars:
            continue
        size = path.stat().st_size
        if size > config.max_single_extracted_size:
            logger.warning(
                "extracted file %s is %d bytes, over the single-file limit",
                rel, size,
            )
            skipped_large += 1
            continue
        if current_size + size > config.max_total_extracted_size:
            logger.warning(
                "extracted files exceed the total size limit; %d not packed",
                len(on_disk) - len(files),
            )
            break
        current_size += size
        entry = by_disk_name.get(path.name, {})
        if not entry:
            logger.warning(
                "extracted file %s has no fileextractor record; kept "
                "unattributed", rel
            )
        guest_path = entry.get("guest_path")
        files.append(
            {
                "name": rel,
                "guest_path": guest_path,
                "guest_basename": _basename(guest_path, context.target_os),
                "size": size,
                "pid": entry.get("pid"),
                "process": entry.get("process"),
                "reason": entry.get("reason"),
                "sha256": entry.get("sha256"),
            }
        )

    per_process = defaultdict(list)
    with zipfile.ZipFile(target_zip, "w", zipfile.ZIP_DEFLATED) as zipf:
        for entry in files:
            member = f"{EXTRACTED_DIR}/{entry['name']}"
            zipf.write(extracted_path / entry["name"], member)
            # seqid None groups the files whose process the tree never saw.
            process = entry["process"]
            per_process[process.seqid if process else None].append(entry)
            side = sidecar_name(entry["name"])
            if side and (extracted_path / side).exists():
                zipf.write(extracted_path / side, f"{EXTRACTED_DIR}/{side}")
        # No files, force empty directory -- the same shape process_dumps
        # gives an empty dumps.zip, so a consumer never has to special-case a
        # zip with no members.
        if not files:
            zipf.writestr(zipfile.ZipInfo(f"{EXTRACTED_DIR}/"), "")

    shutil.rmtree(extracted_path)

    context.update_metadata(
        {
            "extracted_metadata": [
                {"filename": f"{EXTRACTED_DIR}/{e['name']}",
                 "guest_path": e["guest_path"]}
                for e in files
            ]
        }
    )
    context.update_report(
        {
            "extracted_files": [
                {
                    "process_seqid": seqid,
                    "files": [
                        {k: v for k, v in entry.items() if k != "process"}
                        for entry in per_process[seqid]
                    ],
                }
                # Known processes in seqid order, the unattributed group last.
                for seqid in sorted(
                    per_process.keys(),
                    key=lambda s: (s is None, s or 0),
                )
            ],
            "extraction_failures": failures,
            **({"extracted_skipped_oversize": skipped_large}
               if skipped_large else {}),
        }
    )


def _basename(guest_path: Optional[str], os_: TargetOs) -> Optional[str]:
    """The sample's own name for the file, separators taken per guest.

    `PurePosixPath` on `C:\\Users\\x\\a.exe` returns the whole string, so the
    flavour has to follow the guest rather than the host this runs on.
    """
    if not guest_path:
        return None
    flavour = PureWindowsPath if os_ is TargetOs.WINDOWS else PurePosixPath
    return flavour(guest_path).name