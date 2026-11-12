"""`python -m sandboxd.postprocessing <job_dir> --os <os> --max-mib M [--vlan N]`

The postprocessing child; child.py says why it is a child. This file does
three things in a fixed order, and the order is the point:

1. parse the arguments and set `RLIMIT_DATA` -- BEFORE importing a plugin, so
   the limit covers capa's and vivisect's own imports too;
2. configure logging to stderr, which the daemon captures and re-logs;
3. import and run the plugins, and exit 0 when every plugin that had its
   inputs ran to the end, `child.EXIT_PLUGIN_FAILED` when any raised, naming
   them on the last line of stdout.

`RLIMIT_DATA` rather than `RLIMIT_AS`: since Linux 4.7 it counts the heap and
private anonymous mappings -- what Python's allocator and glibc's malloc use
-- and not the shared libraries and file mappings that make a Python process's
address space two to three times its resident size (the killed daemon had
15.6 GB of address space for 6.7 GiB resident). When the limit is hit, `mmap`
and `brk` fail with ENOMEM and Python raises `MemoryError` in whatever plugin
was allocating, which `postprocess.run_postprocessing` catches per plugin.
"""

from __future__ import annotations

import argparse
import logging
import os
import resource
import sys
from pathlib import Path


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m sandboxd.postprocessing")
    p.add_argument("analysis_dir", type=Path)
    p.add_argument("--os", required=True, dest="os_name",
                   help="the guest OS, as sandboxd.guests.TargetOs names it")
    p.add_argument("--vlan", type=int, default=None,
                   help="the clone's VLAN; names its /24 for the Falco rules")
    p.add_argument("--sample", type=Path, default=None,
                   help="the staged sample; CAPE's `target` is read from it")
    p.add_argument("--max-mib", type=int, required=True,
                   help="RLIMIT_DATA in MiB; 0 sets no limit")
    return p.parse_args(argv)


def apply_memory_limit(max_mib: int) -> None:
    """Soft and hard `RLIMIT_DATA` at `max_mib`. Irreversible for this process."""
    limit = max_mib * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_DATA, (limit, limit))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.max_mib > 0:
        apply_memory_limit(args.max_mib)
    logging.basicConfig(
        level=os.environ.get("SANDBOXD_LOG_LEVEL", "INFO").upper(),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # Only now: everything above ran under the limit, and these imports are
    # what pull in capa and vivisect.
    from ..guests import TargetOs
    from .child import EXIT_PLUGIN_FAILED, FAILED_PREFIX, PEAK_PREFIX
    from .plugins.plugin_base import load_postprocessing_config
    from .postprocess import postprocess_analysis_dir

    failed = postprocess_analysis_dir(
        args.analysis_dir, load_postprocessing_config(),
        TargetOs(args.os_name), args.vlan, sample=args.sample)
    # The pass's high-water mark, for the daemon's log: the number that
    # sizes SANDBOXD_POSTPROCESS_MAX_MIB on a real trace, read where the
    # limit applies rather than guessed from the parent.
    print(PEAK_PREFIX, resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
          flush=True)
    if failed:
        print(FAILED_PREFIX, " ".join(failed), flush=True)
        return EXIT_PLUGIN_FAILED
    return 0


if __name__ == "__main__":
    sys.exit(main())