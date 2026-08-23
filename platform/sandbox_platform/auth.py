"""Authentication for the worker channel.

Issue #36 (DRAFT-043).

Dom0 holds exactly one credential: a bearer token valid only for
`/api/v1/worker/*`. In deployment it sits behind mTLS as well, and the two
answer different questions -- the client certificate says *which host*, the
token says *what it may do*. mTLS is terminated by the reverse proxy, so it
does not appear here; this module is the second half.

The token is not enough on its own for job-scoped routes. Every
`/worker/jobs/{id}/...` route additionally requires that the job's
`lease_owner` matches the caller, so a compromised Dom0 reaches the jobs it
is currently running and nothing else. That check is `leased_job` below, and
it is a dependency rather than a line in each handler for the same reason the
token is attached to the router rather than to routes: something added later
cannot forget it.
"""

from __future__ import annotations

import secrets
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Path, status
from psycopg.rows import dict_row

from .config import settings
from .db import connection
from .enums import LEASED_STATES

# Every value below reaches SQL as a bound parameter -- `%s` with the values
# passed separately, never `%`-formatting, an f-string or concatenation.
# psycopg sends statement and parameters over the extended query protocol, so
# a value is never parsed as SQL. The one-character difference between
# `execute(q, (v,))` and `execute(q % v)` is the whole of the defence.
_SELECT_JOB = """
    SELECT id, state, lease_owner, cancel_requested, target_os,
           submitted_filename, sha256
      FROM jobs
     WHERE id = %s
"""


def require_worker_token(
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    """Authenticate a worker. Attached to the worker router as a whole.

    `secrets.compare_digest` rather than `==`: a naive comparison returns as
    soon as two bytes differ, which leaks the token prefix by prefix to
    anyone who can time the response. Cheap to get right, tedious to retrofit.
    """
    if not settings.worker_token:
        # Refusing beats defaulting to an empty token that every caller
        # matches. A misconfigured deployment must not be an open one.
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "worker channel is not configured (WORKER_TOKEN unset)",
        )

    scheme, _, presented = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not presented:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "worker token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not secrets.compare_digest(presented, settings.worker_token):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid worker token")
    return presented


WorkerAuth = Annotated[str, Depends(require_worker_token)]


def leased_job(
    job_id: Annotated[UUID, Path()],
    worker_id: Annotated[str | None, Header(alias="X-Worker-Id")] = None,
) -> dict:
    """Resolve a job the calling worker currently holds a lease on.

    Three distinct failures, kept distinct because they mean different things
    to the caller:

      404  no such job -- and deliberately also what a job belonging to
           ANOTHER worker returns, so the channel cannot be used to probe
           which job ids exist.
      409  the job is this worker's but is no longer running: its lease was
           reaped, or it already reached a terminal state. Stop reporting.
      400  no X-Worker-Id header, which is a client bug rather than a
           permission problem.
    """
    if not worker_id:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "X-Worker-Id header required"
        )

    with connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(_SELECT_JOB, (job_id,))
        job = cur.fetchone()

    # Indistinguishable from "no such job" on purpose: a worker that guesses
    # an id must not learn whether it exists.
    if job is None or job["lease_owner"] != worker_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such job for this worker")

    # LEASED_STATES, not RUNNING_STATES: `cleaning` is still the worker's --
    # it is the one running cleanup.sh, and it has yet to report where the
    # job ended up.
    if job["state"] not in LEASED_STATES:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"job is {job['state']}; the worker no longer owns it",
        )
    return job


LeasedJob = Annotated[dict, Depends(leased_job)]
