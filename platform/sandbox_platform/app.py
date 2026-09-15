"""The platform API.

Issue #36 (DRAFT-043). Design record: docs/architecture/platform.md.

This service is the **only** component holding database and object-store
credentials. That concentration is deliberate and is what buys the narrow
blast radius on Dom0 -- a sample that escapes there holds one scoped token
and reaches the jobs it is currently running, not the job history and not the
bucket. It also makes this the highest-value target on the platform, which is
an argument against adding capability here casually.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
from fastapi.responses import RedirectResponse

from . import credentials, events, maintenance, telegram, throttle
from .db import close_pool, connection, open_pool
from .routers import console as console_router
from .routers import auth as auth_router
from .routers import jobs, worker, account
from .ui import (
    public_router as ui_router_public,
    router as ui_router,
    static as ui_static,
)

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Own the connection pool for the lifetime of the application.

    Created here rather than at import for two reasons: importing this module
    -- which the tests and the OpenAPI generator both do -- must not require a
    reachable database, and a pool closed on shutdown cannot be reopened, so
    a module-level one would make the app startable exactly once per process.
    """
    open_pool()
    # The event listener holds its own connection, outside the pool: LISTEN
    # occupies one for its whole lifetime, so borrowing a pool slot would
    # never give it back. See events.py.
    events.start()
    # Nothing else triggers the lease TTL or expires abandoned submissions.
    # Both were implemented and never invoked until this call existed --
    # see maintenance.py.
    maintenance.start()
    # Outbound long-polling for signup and reset codes. A no-op
    # without TELEGRAM_BOT_TOKEN, and deliberately NOT a webhook --
    # that would be an inbound endpoint this architecture has none of.
    telegram.start()
    try:
        yield
    finally:
        await telegram.stop()
        await maintenance.stop()
        await events.stop()
        close_pool()


app = FastAPI(
    title="DRAKVUF multiOS sandbox platform",
    version="0.1.0",
    summary="Job submission, admission and the Dom0 worker channel.",
    lifespan=lifespan,
)

# **Throttling refusals are mapped in ONE place, and identically.**
#
# `RateLimited` and `AccountLocked` must be indistinguishable in the response:
# a caller who can tell them apart has learned the account exists, which hands
# back the enumeration signal `credentials.verify_password` pays a full argon2
# hash to withhold. One handler on the base class is what makes that structural
# rather than a convention two routes have to keep.
@app.exception_handler(throttle.Throttled)
def _throttled(request, exc: throttle.Throttled):
    return JSONResponse(
        {"detail": "too many attempts"},
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        headers={"Retry-After": str(exc.retry_after)},
    )


# **Only the deployment-level failures become 503.** The first version of this
# handler caught `CredentialsError` wholesale, which swept up `InvalidCredentials`
# and `InvalidToken` as well -- so a user typing the wrong second-factor code was
# told the service was unavailable, and any monitoring watching for 503s would
# have alerted on people mistyping. Caught by
# `test_confirming_with_a_wrong_code_is_refused`.
#
# 503 rather than 500 for the two that remain: the request was fine and the
# DEPLOYMENT is not, and at 3am those need to look different.
# `HashCapacityExceeded` means the concurrent-hash cap refused rather than
# queued -- see `credentials._hash_slot`, where waiting would park threadpool
# threads and take the rest of the API with it.
@app.exception_handler(credentials.CredentialsUnconfigured)
def _credentials_unconfigured(request, exc):
    log.error("credentials are misconfigured: %s", exc)
    return JSONResponse(
        {"detail": "authentication is not configured"},
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        headers={"Retry-After": "5"},
    )


@app.exception_handler(credentials.HashCapacityExceeded)
def _hash_capacity(request, exc):
    return JSONResponse(
        {"detail": "temporarily unable to authenticate"},
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        headers={"Retry-After": "5"},
    )


# A wrong password, a bad token, a wrong or spent second-factor code: all things
# the CALLER got wrong, and all answered the same way so none of them says which.
@app.exception_handler(credentials.InvalidCredentials)
@app.exception_handler(credentials.InvalidToken)
@app.exception_handler(credentials.TotpReplayed)
def _invalid_credentials(request, exc):
    return JSONResponse(
        {"detail": "invalid credentials"},
        status_code=status.HTTP_401_UNAUTHORIZED,
    )


app.include_router(jobs.router)
app.include_router(worker.router)
app.include_router(account.router)
# Login, refresh and logout. The one router with no identity
# dependency -- these routes exist to create the session the others
# assume (DRAFT-061 decision 3).
app.include_router(auth_router.router)
# Two ends of a live console session, on two routers because they authenticate
# differently -- Access for the browser, the worker token over the LAN for
# Dom0. Both are no-ops unless CONSOLE_ENABLED is set (DRAFT-056).
app.include_router(console_router.browser_router)
app.include_router(console_router.worker_router)

# The operator UI (#38). Mounted under /ui, behind the same identity dependency
# as the JSON routes. Deliberately NOT at "/" -- the object store is
# path-routed at /analysis on this same hostname (#37), so the root namespace
# is shared and a catch-all here would be a collision waiting to happen.
app.include_router(ui_router)
# The sign-in page, and nothing else that could ever need an identity. A
# SEPARATE router because route-level `dependencies=[]` does not remove a
# router's -- so the page you reach when you have no session cannot live on the
# router that demands one. Included after it, which does not matter for routing
# (the paths are disjoint) and reads in the order someone meets them.
app.include_router(ui_router_public)
app.mount("/ui/static", ui_static, name="ui-static")


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    """Send the bare hostname to the UI.

    Without this `/` is a 404: cloudflared routes everything except
    `/analysis*` here, and the API has no root of its own — so someone typing
    the hostname gets an error page from a service that is working perfectly.

    **302, not 308.** A permanent redirect is cached hard by browsers and
    would make `/` difficult to reclaim later — for a landing page, a public
    report index, or anything else. This costs one redirect per visit and
    keeps the decision reversible.

    Deliberately not carrying the Access dependency the routers do. Cloudflare
    intercepts before this is reached on the browser path, so an
    unauthenticated visitor sees the login page rather than this route at all;
    adding auth here would only affect the LAN path, where it would turn a
    helpful redirect into a 401.
    """
    return RedirectResponse("/ui", status_code=302)


@app.get("/healthz", tags=["ops"])
def healthz() -> dict[str, str]:
    """Liveness, and the one endpoint that is deliberately unauthenticated.

    It reports that the process is up and can reach its database. It reveals
    nothing else -- no version detail, no counts, no configuration -- because
    the reverse proxy exposes it and an unauthenticated endpoint should carry
    the least information that still answers the question.
    """
    with connection() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok"}