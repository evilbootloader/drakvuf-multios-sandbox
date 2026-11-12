"""CAPE's processing architecture over DRAKVUF's trace.log.

CAPE finds its processing modules by importing every module of
`modules/processing` and registering each `Processing` subclass
(`plugins.import_package` / `load_plugins`). The modules here are few and
known, so they are registered by name instead; `RunProcessing` then runs
them by `order`, exactly as CAPE does.
"""
from .behaviour import BehaviorAnalysis, CapeOptions
from .modules import MODULES
from .plugins import RunProcessing, RunSignatures, register_plugin
from .signatures import load_signatures
from .trace_split import split_by_process

register_plugin("processing", BehaviorAnalysis)
for _module in MODULES:
    register_plugin("processing", _module)

__all__ = ["BehaviorAnalysis", "CapeOptions", "RunProcessing", "RunSignatures", "load_signatures",
           "split_by_process"]