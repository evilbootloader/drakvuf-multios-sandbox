
from .parse_utils import parse_log
from .plugin_base import PostprocessContext


def get_yara_info(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    process_tree = context.process_tree

    def get_process_seqids(data: dict) -> list:
        raw_pid = data.get("PID")
        occurrences = (
            raw_pid if isinstance(raw_pid, list) else [raw_pid]
        )

        seqids = []

        for occurrence in occurrences:
            if isinstance(occurrence, dict):
                pid = occurrence.get("pid", occurrence.get("PID"))
                ppid = occurrence.get(
                    "ppid", occurrence.get("PPID", data.get("PPID"))
                )
            else:
                pid = occurrence
                ppid = data.get("PPID")

            if pid is None or ppid is None:
                continue

            try:
                process = process_tree.get_process_by_pid_ppid(
                    int(pid), int(ppid)
                )
            except (TypeError, ValueError):
                continue

            if process and process.seqid not in seqids:
                seqids.append(process.seqid)

        return seqids

    def filter_yara(data: dict) -> dict:
        return {
            "filename": data["filename"],
            "process_seqids": get_process_seqids(data),
            "matches": data.get("matches") or [],
        }

    yara_log = parse_log(analysis_dir / "yara.json", filter_yara)

    results = []

    for entry in yara_log:
        for match in entry["matches"]:
            results.append({
                "filename": entry["filename"],
                "identifier": match["identifier"],
                "namespace": match["namespace"],
                "process_seqids": entry["process_seqids"],
                "metadata": match.get("metadata", {}),
            })

    context.update_report({"yara": results})
