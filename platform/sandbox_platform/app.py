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

from .db import close_pool, connection, open_pool
from .routers import worker


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Own the connection pool for the lifetime of the application.

    Created here rather than at import for two reasons: importing this module
    -- which the tests and the OpenAPI generator both do -- must not require a
    reachable database, and a pool closed on shutdown cannot be reopened, so
    a module-level one would make the app startable exactly once per process.
    """
    open_pool()
    try:
        yield
    finally:
        close_pool()


app = FastAPI(
    title="DRAKVUF multiOS sandbox platform",
    version="0.1.0",
    summary="Job submission, admission and the Dom0 worker channel.",
    lifespan=lifespan,
)

app.include_router(worker.router)


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