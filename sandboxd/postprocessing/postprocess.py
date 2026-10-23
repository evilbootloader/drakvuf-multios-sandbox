import logging
import pathlib
from typing import Optional

from .plugins import POSTPROCESS_PLUGINS
from .plugins.plugin_base import PostprocessContext, PostprocessPlugin, PostprocessingConfig
from ..guests import TargetOs

logger = logging.getLogger(__name__)


def check_plugin_requirements(
    analysis_dir: pathlib.Path, plugin: PostprocessPlugin
) -> bool:
    plugin_name = plugin.function.__name__
    for required_path in plugin.requires:
        if not (analysis_dir / required_path).exists():
            logger.warning(
                f"{plugin_name} won't be run because {required_path} does not exist"
            )
            return False
    for generated_path in plugin.generates:
        if (analysis_dir / generated_path).exists():
            logger.warning(
                f"{plugin_name} won't be run because {generated_path} already exists"
            )
            return False
    return True


def run_postprocessing(context: PostprocessContext):
    for plugin in POSTPROCESS_PLUGINS:
        plugin_name = plugin.function.__name__
        if not check_plugin_requirements(context.analysis_dir, plugin):
            continue
        try:
            plugin.function(context)
        except Exception:
            logger.exception(f"{plugin_name} failed with uncaught exception")


def postprocess_analysis_dir(
    analysis_dir: pathlib.Path, config: PostprocessingConfig, os_: TargetOs,
    vlan: Optional[int] = None) -> None:
    """Run every plugin whose inputs exist. Never raises.

    Called from `Analysis.run` between the trace and `_collect`, inside the
    try that turns any exception into a `failed` outcome. Postprocessing is
    derived data; a fault in it must not discard a completed trace, so what
    `run_postprocessing`'s per-plugin handler does not catch is caught here.
    """
    context = PostprocessContext(
        analysis_dir=analysis_dir,
        config=config,
        target_os=os_,
        vlan=vlan,
    )
    try:
        run_postprocessing(context)
    except Exception:  # noqa: BLE001 - the trace is the result, not this
        logger.exception("postprocessing of %s aborted", analysis_dir)