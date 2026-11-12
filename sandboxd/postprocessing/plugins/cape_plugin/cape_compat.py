"""What CAPE's abstracts.py and plugins.py take from the rest of CAPE
(`lib.cuckoo.common.*`), in the form a sandboxd job can give it: no CAPE
install, no config files, no database.

`CUCKOO_ROOT` is a checkout of CAPESandbox/community -- the tree the
signatures come from, which also carries the data files they open through
that name (`data/mitre/TTPs.json`, `data/malicioustlds.txt`). It is set by
`signatures.load_signatures`; until then it names a directory that does not
exist, and everything that reads it finds nothing.
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from pathlib import Path

# sandboxd/data/cape-community: where the community tree is expected, beside
# capa-rules and falco-rules.
DEFAULT_COMMUNITY = Path(__file__).resolve().parents[3] / "data" / "cape-community"

CUCKOO_ROOT = str(DEFAULT_COMMUNITY)
# What a signature's `minimum`/`maximum` is compared against, and the report
# version capa's CAPE extractor was tested with.
CUCKOO_VERSION = "2.5-CAPE"


def set_root(path) -> None:
    global CUCKOO_ROOT
    CUCKOO_ROOT = str(path)
    _ttp_map.clear()


class CuckooOperationalError(Exception):
    pass


class CuckooReportError(Exception):
    pass


def path_exists(path) -> bool:
    return os.path.exists(path)


def create_folder(root=".", folder=None):
    os.makedirs(os.path.join(root, folder) if folder else root, exist_ok=True)


def add_family_detection(results: dict, family: str, detected_by: str, detected_on: str):
    # lib/cuckoo/common/utils.py, without its family-name normalisation table.
    results.setdefault("detections", [])
    detection = {detected_by: detected_on}
    for block in results["detections"]:
        if family == block.get("family", ""):
            if detection not in block["details"]:
                block["details"].append(detection)
            break
    else:
        results["detections"].append({"family": family, "details": [detection]})


_ttp_map: dict = {}


def _ttps() -> dict:
    if not _ttp_map:
        path = os.path.join(CUCKOO_ROOT, "data", "mitre", "TTPs.json")
        try:
            with open(path) as f:
                _ttp_map.update(json.load(f))
        except (OSError, ValueError):
            pass
    return _ttp_map


def mapTTP(oldTTPs: list, mbcs: dict):
    """lib/cuckoo/common/mapTTPs.py: signatures' TTPs grouped per signature,
    old ATT&CK ids translated through the community tree's TTPs.json. Upstream
    drops an id that file does not list; without the file every id would go,
    so here an unlisted id is kept as it is."""
    table = _ttps()
    grouped = defaultdict(list)
    for item in oldTTPs:
        ttp = item["ttp"]
        if "." in ttp and table:
            continue
        grouped[item["signature"]].append(table.get(ttp, ttp))
    return [
        {"signature": signature, "ttps": list(dict.fromkeys(ttps)), "mbcs": mbcs.get(signature, [])}
        for signature, ttps in grouped.items()
    ]
