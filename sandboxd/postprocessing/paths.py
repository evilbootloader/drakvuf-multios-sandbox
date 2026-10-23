"""Names inside a job directory that more than one module must agree on.

The equivalent of upstream drakvuf-sandbox's `drakrun/lib/paths.py`. The
values are upstream's, unchanged: `process_dumps` packs DUMPS_DIR into
DUMPS_ZIP with DUMPS_DIR as the member prefix, and `capa_processor` unpacks it
expecting that prefix, so the two are one contract rather than two literals.

`sandboxd.guests.argv_trace` and `sandboxd.stages` import these too -- the
directories DRAKVUF is told to write are the directories the plugins read, and
on 2026-09-18 they disagreed (`--memdump-dir` pointed at `memdumps/`,
`process_dumps` read `dumps/`) and every memory dump would have been lost.
This module has no imports so that importing it costs nothing.

The layout these describe is docs/architecture/result-schema.md 4.1.
"""

# The memdump plugin's output directory: `--memdump-dir`, as upstream passes
# it (drakrun/analyzer/analyzer.py:90). Packed by process_dumps into DUMPS_ZIP
# and then removed, so a job that ran process_dumps uploads the zip and a job
# that did not uploads the directory.
DUMPS_DIR = "dumps"
DUMPS_ZIP = "dumps.zip"

# The ipt plugin's output directory: `--ipt-dir`, which `argv_trace` passes
# only when `ipt` is among the job's plugins, and `stages._trace` creates on
# the same condition. Packed by compress_ipt into IPT_ZIP with IPT_DIR as the
# member prefix (the same shape as DUMPS_ZIP) and then removed. Same names as
# upstream.
IPT_DIR = "ipt"
IPT_ZIP = "ipt.zip"

# procdump2's output directory: `--procdump-dir`, which `argv_trace` passes
# only when `procdump2` is among the job's plugins, and `stages._trace`
# creates on the same condition. Not packed: DRAKVUF already gzips each dump
# (`--compress-procdumps`), so `stages._collect` uploads them as they are.
PROCDUMPS_DIR = "procdumps"

# fileextractor's output directory: DRAKVUF's `-D`. Upstream never passes -D
# and has no plugin for it; the name is result-schema.md's, chosen there
# because these are the files the SAMPLE wrote, with names the sample chose.
# Packed by process_extracted into EXTRACTED_ZIP with EXTRACTED_DIR as the
# member prefix -- the same contract DUMPS_DIR/DUMPS_ZIP have, and the same
# pairing `stages._collect` reads to decide whether to upload the directory
# or the archive.
EXTRACTED_DIR = "extracted"
EXTRACTED_ZIP = "extracted.zip"

# DRAKVUF's stdout, as `stages._trace` writes it. **Must equal
# `sandboxd.stages.TRACE_LOG`** -- it is restated here rather than imported
# because stages.py imports this package, and sandboxd/tests/test_postprocessing.py
# asserts the two agree. Upstream calls the same file drakmon.log; the port
# first read drakvuf.log, which nothing wrote, and the whole chain was a
# no-op until 2026-09-18. split_drakvuf_log replaces it with one
# `<plugin>.log` per DRAKVUF plugin plus parse_errors.log and removes it, so
# the raw stream is never uploaded -- the per-plugin logs are.
TRACE_LOG = "trace.log"
