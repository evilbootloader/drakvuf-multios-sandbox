"""CAPE community signatures, loaded as CAPE loads them.

A signature module is written against CAPE's layout:

    from lib.cuckoo.common.abstracts import Signature
    from modules.signatures.utils import re
    from data.cryptopools import pool_domains

so those names are made to resolve: `lib.cuckoo.common.abstracts` IS this
package's abstracts.py (one `Signature` class, or `issubclass` would not
find them), `modules.signatures` and `data` are the community checkout's own
directories, and the few other `lib.cuckoo.common` modules signatures import
are the stand-ins in `cape_compat`. Every `Signature` subclass in
`modules/signatures/{all,windows,linux,custom}` is then registered, for
`RunSignatures` to filter by platform as CAPE does (by module path).

A module that fails to import -- it wants a CAPE helper nobody ported, or a
library the venv lacks -- is skipped and counted; one signature must not
take the other five hundred with it.
"""
from __future__ import annotations

import importlib
import inspect
import logging
import sys
import types
from pathlib import Path
from typing import Dict, Optional

from . import abstracts, cape_compat
from .plugins import list_plugins, register_plugin

log = logging.getLogger(__name__)

GROUPS = ("all", "windows", "linux", "custom")

# Modules never imported, whatever the venv holds. network_questionable_host
# queries DNS blocklists for every address the sample contacted -- live, from
# Dom0 -- as soon as dnspython is importable; today it fails to import, and
# that must not be what keeps it quiet.
NEVER_LOAD = frozenset(("network_questionable_host",))
_loaded_from: Optional[Path] = None


def _package(name: str, path: Optional[Path] = None, **attrs) -> types.ModuleType:
    mod = sys.modules.get(name)
    if mod is None:
        mod = types.ModuleType(name)
        sys.modules[name] = mod
        parent, _, child = name.rpartition(".")
        if parent:
            setattr(sys.modules[parent], child, mod)
    mod.__path__ = [str(path)] if path is not None else []
    for key, value in attrs.items():
        setattr(mod, key, value)
    return mod


def _install_cape_names(root: Path) -> None:
    cape_compat.set_root(root)
    _package("lib")
    _package("lib.cuckoo")
    _package("lib.cuckoo.common")
    sys.modules["lib.cuckoo.common.abstracts"] = abstracts
    sys.modules["lib.cuckoo.common"].abstracts = abstracts
    _package("lib.cuckoo.common.constants", CUCKOO_ROOT=str(root),
             CUCKOO_VERSION=cape_compat.CUCKOO_VERSION)
    _package("lib.cuckoo.common.utils",
             add_family_detection=cape_compat.add_family_detection,
             convert_to_printable=lambda s, cache=None: s if isinstance(s, str) else str(s),
             bytes2str=lambda b: b.decode(errors="replace") if isinstance(b, bytes) else b)
    _package("modules")
    _package("modules.signatures", root / "modules" / "signatures")
    # The community tree's data/ (cryptopools.py, malpedia.py); CAPE's own
    # data/safelist is not in it, so the passlist signatures consult is empty.
    _package("data", root / "data")
    _package("data.safelist")
    _package("data.safelist.domains", domain_passlist=[], domain_passlist_re=[])


def load_signatures(root=None) -> Dict[str, int]:
    """Register every signature under `<root>/modules/signatures`; returns
    {"signatures", "modules", "failed"}. Once per process and root."""
    global _loaded_from
    root = Path(root or cape_compat.DEFAULT_COMMUNITY)
    sig_dir = root / "modules" / "signatures"
    stats = {"signatures": len(list_plugins("signatures") or ()), "modules": 0, "failed": 0}
    if _loaded_from == root:
        return stats
    if not sig_dir.is_dir():
        log.warning("no CAPE signatures at %s (CAPESandbox/community checkout expected)", sig_dir)
        return stats
    _install_cape_names(root)
    for group in GROUPS:
        for path in sorted((sig_dir / group).glob("*.py")):
            if path.name == "__init__.py" or path.stem in NEVER_LOAD:
                continue
            name = f"modules.signatures.{group}.{path.stem}"
            try:
                module = importlib.import_module(name)
            except Exception as e:  # noqa: BLE001 - see the module docstring
                stats["failed"] += 1
                log.debug("signature module %s not loaded: %s", name, e)
                continue
            stats["modules"] += 1
            for _, value in inspect.getmembers(module, inspect.isclass):
                if (issubclass(value, abstracts.Signature) and value is not abstracts.Signature
                        and value.__module__ == name):
                    register_plugin("signatures", value)
    _loaded_from = root
    stats["signatures"] = len(list_plugins("signatures") or ())
    log.info("CAPE signatures: %d from %d modules, %d modules failed to import",
             stats["signatures"], stats["modules"], stats["failed"])
    return stats
