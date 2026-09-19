import shutil
import zipfile

from ..paths import IPT_DIR, IPT_ZIP
from .plugin_base import PostprocessContext


def compress_ipt(context: PostprocessContext) -> None:
    """Pack the ipt plugin's output directory into IPT_ZIP and remove it.

    Intel PT traces are large and compress well, and the zip carries the
    directory's own layout (`ipt/<file>`), the shape process_dumps gives
    dumps.zip. Runs only when IPT_DIR exists, which `stages._trace` creates
    and `guests.argv_trace` names with `--ipt-dir` only for a job that
    selected the `ipt` plugin -- so a job without it has no `ipt.zip` rather
    than an empty one.

    The port shipped this importing IPT_DIR and IPT_ZIP from drakrun, which
    does not exist here, and unregistered; with that it raised NameError on
    the first call. Upstream also `rglob`bed directories into `zipf.write`
    and then `unlink`ed them, which fails on the first subdirectory, and
    never closed the zip.
    """
    analysis_dir = context.analysis_dir
    ipt_path = analysis_dir / IPT_DIR
    target = analysis_dir / IPT_ZIP

    # The directory goes only once the zip is whole, and a zip that is not
    # whole goes too: `stages._collect` skips IPT_DIR whenever IPT_ZIP is
    # beside it, so a partial zip left behind would hide the raw traces from
    # the upload while carrying only some of them.
    try:
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zipf:
            for ipt_file in sorted(p for p in ipt_path.rglob("*") if p.is_file()):
                zipf.write(ipt_file, ipt_file.relative_to(analysis_dir).as_posix())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    shutil.rmtree(ipt_path)
