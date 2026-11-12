"""`python -m sandboxd.postprocessing.plugins.cape_plugin <dir> --os windows`

CAPE's processing over `<dir>/trace.log`, outside the postprocessing chain
and whatever `SANDBOXD_POSTPROCESS_CAPE` says: writes `<dir>/cape_results.json`
and prints what it found.
"""
from __future__ import annotations

import argparse
import logging
import resource
import sys
from pathlib import Path

from ....guests import TargetOs
from ..cape_analysis import CAPE_RESULTS, run_cape
from ..plugin_base import CapeConfigSection, PostprocessContext, load_postprocessing_config


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m sandboxd.postprocessing.plugins.cape_plugin")
    p.add_argument("analysis_dir", type=Path, help="a directory holding trace.log")
    p.add_argument("--os", required=True, dest="os_name", choices=[o.value for o in TargetOs])
    p.add_argument("--scope", choices=["sample", "all"], default="sample")
    p.add_argument("--kernel-syscalls", action="store_true")
    p.add_argument("--call-limit", type=int, default=0)
    p.add_argument("--no-capa", action="store_true")
    p.add_argument("--compress-trace", action="store_true",
                   help="replace trace.log with trace.log.gz afterwards, as the chain does")
    p.add_argument("--community", type=Path, help="CAPESandbox/community checkout (signatures)")
    p.add_argument("--sample", type=Path, help="the sample file, for its hashes")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    config = load_postprocessing_config()
    cfg = CapeConfigSection(**{**config.cape.model_dump(), "enabled": True, "scope": args.scope,
                               "kernel_syscalls": args.kernel_syscalls,
                               "call_limit": args.call_limit, "capa": not args.no_capa,
                               "compress_trace": args.compress_trace,
                               **({"community": args.community} if args.community else {})})
    context = PostprocessContext(args.analysis_dir, config, TargetOs(args.os_name))
    results = run_cape(context, cfg, args.sample)

    behavior = results.get("behavior", {})
    print(f"{len(behavior.get('processes', []))} processes -> {args.analysis_dir / CAPE_RESULTS}")
    summary = behavior.get("summary") or {}
    print("summary:", {k: len(v) for k, v in summary.items()})
    capa = results.get("capa_summary") or {}
    print("capa:", sum(len(v) for v in capa.get("CAPABILITY", {}).values()), "capabilities,",
          sum(len(v) for v in capa.get("ATTCK", {}).values()), "ATT&CK techniques")
    sigs = results.get("signatures") or []
    print(f"signatures: {len(sigs)} matched, malscore {results.get('malscore')} "
          f"({results.get('malstatus')})")
    for sig in sorted(sigs, key=lambda m: -m["severity"])[:15]:
        print(f"   [{sig['severity']}] {sig['name']}: {sig['description']}")
    print("peak RSS:", resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024, "MiB")
    return 0


if __name__ == "__main__":
    sys.exit(main())