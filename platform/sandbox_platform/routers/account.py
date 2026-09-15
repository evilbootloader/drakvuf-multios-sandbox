"""The caller's own account: what they may still spend.

Issue #40 (DRAFT-047) decision 8.

Separate from `routers/jobs.py` because it is about the tenant rather than
about any job, and because it is the one route the UI calls on every page
load -- keeping it here means a change to the balance cannot disturb
submission.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Response

from .. import auth
from ..csrf import require_csrf_header
from ..db import connection

log = logging.getLogger(__name__)

# The identity dependency is attached to the ROUTER, not to routes, so a
# route added later cannot forget it. `caller_identity` since the cut-over --
# see the longer note in `routers/jobs.py`, which this mirrors: the old gate
# could only read a Cloudflare header, so it refused every session this
# platform issued.
# `require_csrf_header` alongside the identity dependency (review finding M-7).
# `/balance` is a POST -- chosen for cache behaviour rather than because it
# mutates, see below -- and `balance.js` was sending it with only an `Accept`
# header, which is a CORS-simple request a cross-site page could issue. The
# effect was small (it creates a tenant row on first contact) but the property
# is one this application should hold uniformly rather than per call.
# CSRF before identity, for the reason `routers/jobs.py` spells out: whichever
# runs first decides what a refused request is told, and identity-first lets a
# cross-site page read 401-vs-403 as "is this visitor signed in".
router = APIRouter(prefix="/api/v1/account", tags=["account"],
                   dependencies=[Depends(require_csrf_header),
                                 Depends(auth.caller_identity)])


# POST, and not because the balance is a mutation the caller asked for -- it is
# a read that happens to create the tenant row on first contact. The method is
# chosen for what sits in front of this listener.
#
# A GET is cacheable by intermediaries, and Cloudflare is one. A cache rule
# that ever matched /api/v1/account/* would serve one tenant's balance to
# another: a cross-tenant leak in the subsystem whose entire purpose is
# per-user isolation, prevented only by a CDN's default configuration. POST is
# cached by default nowhere, and it stops HTTP clients, monitors and proxies
# treating the row creation as a free retry.
#
# no-store on top of that, because the balance is per-user data crossing a
# shared CDN and the method alone is an argument rather than an instruction.
@router.post("/balance")
def get_balance(response: Response, owner: auth.RequiredIdentity) -> int:
    """This caller's remaining analysis seconds, creating their tenant row if
    this is the first time the platform has seen them.

    **The upsert is not an optimisation.** A SELECT-then-INSERT returns no row
    on the first call -- there is nothing to select yet -- so the branch meant
    to handle a new tenant is the one that crashes. It also races the identical
    block in `create_job`, and the UI guarantees that race: the page asks for a
    balance on load while a headless client submits without ever asking.

    `DO UPDATE` rather than `DO NOTHING` because `DO NOTHING` returns no row on
    conflict, and the balance is wanted in both cases.

    The number comes back from the ROW, never from a literal here. 3600 is
    declared once, as the column default in migration 0008; a copy in this
    module would disagree with the database the first time it changes.
    """
    response.headers["Cache-Control"] = "no-store"
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO tenants (owner) VALUES (%s)
            ON CONFLICT (owner) DO UPDATE SET owner = EXCLUDED.owner
            RETURNING balance_seconds
            """,
            (owner,),
        )
        return cur.fetchone()[0]