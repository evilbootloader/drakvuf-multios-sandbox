"""Derived data from a finished trace: the drakvuf-sandbox postprocessing
plugins, ported 2026-09-15. Windows traces only, for now.

Deliberately empty. `stages.py` imports `.postprocess` directly, and
`guests.py` imports `.paths` for the directory names it hands DRAKVUF --
re-exporting `postprocess_analysis_dir` here would make that second import
pull in capa and vivisect for the sake of three strings.
"""