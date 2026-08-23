"""Database connection pool.

Issue #36 (DRAFT-043).

A pool rather than a connection per request: Postgres forks a backend per
connection, so opening one per HTTP call turns a millisecond query into tens
of milliseconds. Ten connections is generous for one analysis host and one
operator.

**The pool is owned by the application lifespan, not by module import.**
`psycopg_pool` cannot reopen a closed pool, so a module-level singleton that
lifespan closes on shutdown can only ever be started once per process. That
shows up first in tests -- where each TestClient runs lifespan and the second
one finds a corpse -- but it is a real constraint either way: an app that
cannot be restarted in-process cannot be exercised twice.

**The SSE listener will not use this pool.** `LISTEN` occupies a connection
for its entire lifetime, so a listener borrowed from here would hold a slot
open indefinitely and, with a few browser tabs, exhaust it. It gets its own
dedicated connection.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
from psycopg_pool import ConnectionPool

from .config import settings

_pool: ConnectionPool | None = None


def open_pool() -> None:
    """Create the pool. Idempotent, and safe after a previous close."""
    global _pool
    if _pool is None or _pool.closed:
        _pool = ConnectionPool(
            conninfo=settings.database_url,
            min_size=settings.pool_min,
            max_size=settings.pool_max,
            # Fail fast rather than hanging a request forever on an exhausted
            # pool: a 500 naming the problem is more use than a browser tab
            # that spins.
            timeout=10.0,
            open=False,
        )
        _pool.open(wait=True, timeout=10.0)


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


def get_pool() -> ConnectionPool:
    if _pool is None:
        raise RuntimeError("connection pool is not open")
    return _pool


@contextmanager
def connection() -> Iterator[psycopg.Connection]:
    """A pooled connection, committed on success and rolled back on error.

    psycopg's own context manager handles the transaction boundary, which is
    what the data-access layer in jobs.py expects -- it issues statements and
    leaves commits to its caller.
    """
    with get_pool().connection() as conn:
        yield conn