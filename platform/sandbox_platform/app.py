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

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from . import events, maintenance
from .db import close_pool, connection, open_pool
from .routers import jobs, worker
from .ui import router as ui_router, static as ui_static


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
    try:
        yield
    finally:
        await maintenance.stop()
        await events.stop()
        close_pool()


app = FastAPI(
    title="DRAKVUF multiOS sandbox platform",
    version="0.1.0",
    summary="Job submission, admission and the Dom0 worker channel.",
    lifespan=lifespan,
)

app.include_router(jobs.router)
app.include_router(worker.router)

# The operator UI (#38). Mounted under /ui, behind the same Access dependency
# as the JSON routes. Deliberately NOT at "/" -- the object store is
# path-routed at /analysis on this same hostname (#37), so the root namespace
# is shared and a catch-all here would be a collision waiting to happen.
app.include_router(ui_router)
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