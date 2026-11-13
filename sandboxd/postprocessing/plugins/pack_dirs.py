import logging
import zipfile
from pathlib import Path

from ..paths import DUMPS_DIR, DUMPS_ZIP, EXTRACTED_DIR, EXTRACTED_ZIP
from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)


def _pack(analysis_dir: Path, directory: str, archive: str, limit: int) -> None:
    """Pack `directory` into `archive` beside it and remove what was packed.

    The shape compress_ipt gives ipt.zip: members carry the directory's own
    layout (`extracted/<file>`), which is the name each file uploaded under
    before 2026-11-13, when these two directories went to the platform a
    file at a time -- 481 memory dumps and 266 extracted files for one
    120 s Steam installer, against a manifest of 1024 names.

    **Everything in the directory is packed, sidecars included.** The
    directory is the ground truth: which file is whose is in
    cape_results.json (`dropped`, `procmemory`), written by cape_analysis
    before this runs, from these same files -- so this must stay after it in
    POSTPROCESS_PLUGINS.

    `limit` bounds the members' total size, because the platform's download
    path refuses an entry over 4 GiB minus 16 bytes (packaging.py,
    _MAX_ENTRY). What does not fit is left in the directory, which
    `stages._collect` does not upload beside its archive: it stays on Dom0
    and is logged here, the first files in name order having been packed.

    An empty directory makes no archive -- `stages._trace` creates both
    directories for every job, and an empty zip in every manifest would say
    something was recovered when nothing was.
    """
    source = analysis_dir / directory
    target = analysis_dir / archive
    files = sorted(p for p in source.rglob("*") if p.is_file())
    if not files:
        logger.info("%s is empty; no %s", directory, archive)
        return

    packed = []
    total = 0
    # The files go only once the zip is whole, and a zip that is not whole
    # goes too: `stages._collect` skips the directory whenever the archive
    # is beside it, so a partial one would hide the raw files from the
    # upload while carrying only some of them.
    try:
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zipf:
            for path in files:
                size = path.stat().st_size
                if total + size > limit:
                    continue
                total += size
                zipf.write(path, path.relative_to(analysis_dir).as_posix())
                packed.append(path)
    except BaseException:
        target.unlink(missing_ok=True)
        raise

    for path in packed:
        path.unlink()
    left = len(files) - len(packed)
    if left:
        logger.warning(
            "%s: %d of %d files did not fit under %d bytes and are not in %s",
            directory, left, len(files), limit, archive,
        )
        return
    # Deepest first; the directory itself last.
    for sub in sorted((p for p in source.rglob("*") if p.is_dir()), reverse=True):
        sub.rmdir()
    source.rmdir()


def compress_extracted(context: PostprocessContext) -> None:
    """fileextractor's `-D` directory, as extracted.zip."""
    _pack(context.analysis_dir, EXTRACTED_DIR, EXTRACTED_ZIP,
          context.config.extracted.max_total_extracted_size)


def compress_dumps(context: PostprocessContext) -> None:
    """memdump's `--memdump-dir`, as dumps.zip."""
    _pack(context.analysis_dir, DUMPS_DIR, DUMPS_ZIP,
          context.config.memdump.max_total_packed_size)
