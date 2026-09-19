import gzip
import shutil

from .plugin_base import PostprocessContext


def gzip_syscalls(context: PostprocessContext) -> None:
    """
    Compress syscall.log using gzip if gzip_syscalls configuration option is True.
    This will disable preview of these logs in web.
    """
    analysis_dir = context.analysis_dir
    # The context's config, not a fresh load: upstream re-read its own config
    # file here, and the port kept the call against a config that has no
    # `drakrun` section, so this raised on every run.
    if not context.config.gzip_syscalls:
        return

    for name in ["syscall", "sysret"]:
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