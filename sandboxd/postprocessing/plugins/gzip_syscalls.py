import gzip
import shutil

from .plugin_base import PostprocessContext


#: The logs replaced by a `.log.gz`. A gzipped log leaves the platform's log
#: viewer (it reads `.log` files by byte range from `log_index`) and is
#: offered as a download instead -- the trade the operator took for
#: `apimon.log` on 2026-11-03, when a 20-minute Windows trace left 3.9 GB of
#: it, uploaded raw: half the job's 8 GiB result budget on its own, and over
#: the per-artifact cap of that morning. Each gzips roughly twenty to one.
#: **This plugin must stay after every reader of these logs** in
#: POSTPROCESS_PLUGINS; get_http_info reads apimon.log.
GZIPPED_LOGS = ("syscall", "sysret", "apimon")


def gzip_syscalls(context: PostprocessContext) -> None:
    """
    Compress syscall.log, sysret.log and apimon.log with gzip if the
    gzip_syscalls configuration option is True. This disables the preview of
    these logs in the web UI, which offers them as downloads instead.
    """
    analysis_dir = context.analysis_dir
    # The context's config, not a fresh load: upstream re-read its own config
    # file here, and the port kept the call against a config that has no
    # `drakrun` section, so this raised on every run.
    if not context.config.gzip_syscalls:
        return

    for name in GZIPPED_LOGS:
        log_path = analysis_dir / f"{name}.log"
        log_path_gz = analysis_dir / f"{name}.log.gz"
        # sysret.log is absent whenever the trace ran with sysret disabled;
        # upstream unlinked outside this test and raised FileNotFoundError.
        if not log_path.exists():
            continue
        with log_path.open("rb") as f_in:
            with gzip.open(log_path_gz, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        log_path.unlink()