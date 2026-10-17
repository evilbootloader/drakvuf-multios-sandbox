
from collections import defaultdict, deque
import logging

import orjson
import yara_x

log = logging.getLogger(__name__)


def yara_analysis(context: PostprocessContext):
    analysis_dir = context.analysis_dir
    staging_dir = analysis_dir.parent.parent / "staging" / analysis_dir.name
    rules_dir = context.config.yara.rules_directory

    compiler = yara_x.Compiler()
    compiler.add_include_dir(str(rules_dir))

    for path in sorted(rules_dir.rglob("*")):
        if path.is_file() and path.suffix.lower() in (".yar", ".yara"):
            compiler.add_source(
                path.read_text(encoding="utf-8"),
                origin=str(path),
            )

    rules = compiler.build()
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(60)

    def load_logs(filename, key):
        entries = defaultdict(deque)

        with (analysis_dir / filename).open("rb") as f:
            for line in f:
                if not line.strip():
                    continue
                entry = orjson.loads(line)
                if entry.get(key):
                    entries[entry[key]].append(entry)

        return entries

    fileextractor_logs = load_logs("fileextractor.log", "DumpFile")
    memdump_logs = load_logs("memdump.log", "DumpFilename")

    results = []

    sources = (
        (analysis_dir / "extracted", fileextractor_logs, lambda p: str(p)),
        (analysis_dir / "dumps", memdump_logs, lambda p: p.name),
        (staging_dir, None, None),
    )

    for directory, logs, key_fn in sources:
        for path in sorted(directory.rglob("*")):
            if not path.is_file():
                continue

            log_entry = None
            if logs is not None:
                entries = logs.get(key_fn(path))
                log_entry = entries.popleft() if entries else None

            try:
                scan = scanner.scan_file(str(path))
            except (yara_x.ScanError, yara_x.TimeoutError, OSError) as exc:
                log.warning("YARA scan failed for %s: %s", path, exc)
                continue

            filename = (
                f"staging/{path.relative_to(staging_dir)}"
                if directory == staging_dir
                else str(path.relative_to(analysis_dir))
            )

            results.append({
                "filename": filename,
                "PID": log_entry.get("PID") if log_entry else None,
                "PPID": log_entry.get("PPID") if log_entry else None,
                "matches": [
                    {
                        "identifier": rule.identifier,
                        "namespace": rule.namespace,
                        "metadata": dict(rule.metadata),
                    }
                    for rule in scan.matching_rules
                ],
            })

    with (analysis_dir / "yara.json").open("wb") as f:
        for result in results:
            f.write(orjson.dumps(result))
            f.write(b"\n")
