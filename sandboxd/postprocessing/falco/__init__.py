"""Falco rules evaluated over a finished Linux trace.

Falco itself reads libscap events from a kernel driver; it cannot read what
DRAKVUF writes, and a converter to its capture format would still lack what
DRAKVUF does not record. So this is an evaluator of Falco's rule language over
DRAKVUF's own records: `rules` loads the YAML, `condition` parses and compiles
conditions, `events` turns procmon, syscall, sysret, filetracer and libmon
records into Falco-shaped events, `fields` extracts Falco's fields from them
and `engine` runs the rules. docs/architecture/falco-rules.md has the field
coverage and the three-valued logic that keeps missing data from raising an
alert.

Imported by `plugins/falco_analysis.py` only, and imports nothing heavy, so
the rest of the postprocessing package does not pay for it.
"""