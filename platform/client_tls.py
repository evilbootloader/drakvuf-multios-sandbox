"""SSL contexts for the platform's command-line clients.

Issue #36 (DRAFT-043). Shared by `fake_worker.py` and `submit.py` so that the
httpx behaviour documented below is handled once rather than rediscovered per
script -- it is a security parameter that fails open and fails quietly, which
is the worst combination to duplicate.
"""

from __future__ import annotations

import ssl


def ssl_context(cacert: str | None,
                client_cert: tuple[str, str] | None = None) -> ssl.SSLContext:
    """Trust anchor, and optionally an identity to present.

    Built here rather than handed to httpx as `verify=<path>` plus
    `cert=<pair>`, because httpx 0.28's `create_ssl_context` returns early on a
    string `verify` and never reaches its `cert` branch:

        elif isinstance(verify, str):
            return ssl.create_default_context(cafile=verify)   # returns here
        ...
        if cert:                                              # unreachable
            ctx.load_cert_chain(*cert)

    The client certificate is dropped with no error and the connection goes
    out anonymous. **Under TLS 1.3 the server completes the handshake before
    it validates the client certificate**, so the symptom is not a handshake
    failure: it is an unexplained EOF while reading the first response, with
    nothing at all in the server's log because the request never reached the
    application. Cost an hour on 2026-08-23; see `d1640b8`.

    Passing `client_cert=None` is meaningful, not merely a default -- it is how
    object-store traffic avoids presenting the worker's identity to a server
    that never asked for it.
    """
    ctx = (ssl.create_default_context(cafile=cacert) if cacert
           else ssl.create_default_context())
    if client_cert:
        ctx.load_cert_chain(*client_cert)
    return ctx