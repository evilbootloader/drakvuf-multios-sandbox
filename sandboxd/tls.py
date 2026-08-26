"""TLS for the worker channel. Imported from the platform, never reimplemented.

Issue #41 (DRAFT-060).

`platform/client_tls.py` builds the SSL context that `fake_worker.py` and
`submit.py` already use, and it exists because of a trap that cost an hour on
2026-08-23: httpx 0.28's `create_ssl_context` returns early on a string
`verify` and never reaches its `cert` branch, so a client certificate passed
alongside a CA path is **dropped with no error**. Under TLS 1.3 the server
completes the handshake before it validates the client certificate, so the
symptom is not a handshake failure -- it is an unexplained EOF while reading
the first response, with nothing in the server's log, because the request never
reached the application.

Its own docstring says it is "a security parameter that fails open and fails
quietly, which is the worst combination to duplicate". A copy here would be a
second definition of that, free to drift, on the one component that presents
Dom0's identity.

So this module resolves the real file rather than restating it. Dom0 runs a
full checkout of this repository -- that is how issue #4 arranged every
repository-owned asset -- so `platform/client_tls.py` is present beside
`sandboxd/`.

**The import failing is fatal, deliberately.** Falling back to a context
without the client certificate is exactly the fail-open the original warns
about: the connection would go out anonymous and be refused in a way that looks
like a network fault.
"""

from __future__ import annotations

import sys
from pathlib import Path

_PLATFORM = Path(__file__).resolve().parents[1] / "platform"

if str(_PLATFORM) not in sys.path:
    sys.path.insert(0, str(_PLATFORM))

try:
    from client_tls import ssl_context  # noqa: F401
except ImportError as exc:  # pragma: no cover - a broken checkout
    raise ImportError(
        f"cannot import client_tls from {_PLATFORM}. sandboxd shares the "
        f"platform's TLS context rather than carrying its own copy -- see this "
        f"module's docstring. A checkout missing platform/ cannot present "
        f"Dom0's client certificate, and proceeding without one fails open."
    ) from exc

__all__ = ["ssl_context"]