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

import logging
import secrets
import threading
import time
from typing import Annotated
from uuid import UUID

import httpx
import jwt
from fastapi import Depends, Header, HTTPException, Path, status
from psycopg.rows import dict_row

from .config import settings
from .db import connection
from .enums import LEASED_STATES

log = logging.getLogger(__name__)

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


# --- browser identity -----------------------------------------------------
#
# Cloudflare Access authenticates the human at its edge and forwards a signed
# JWT in `Cf-Access-Jwt-Assertion`. Verifying it here is what gives the browser
# routes an identity; before this, anything that reached the API could read,
# cancel and stream every job.
#
# **Verifying the signature is the whole point.** The header is attacker-
# controlled on any path that does not traverse Cloudflare, so trusting its
# claims -- or trusting the plainer `Cf-Access-Authenticated-User-Email`
# header, which carries no signature at all -- would be authentication by
# assertion. That is why this fetches Cloudflare's public keys rather than
# decoding with `verify_signature=False`.

_JWKS_TTL = 3600.0

# The shortest gap between two refetches triggered by an unknown `kid`.
#
# **This is what stops an unauthenticated caller driving one outbound HTTPS
# request per request.** An unknown kid means one of two things -- Cloudflare
# rotated a key, or the token is forged -- and only the attacker can produce
# them at will. Without a floor here, a stream of forged tokens carrying random
# kids fetched the JWKS every time, each fetch serialized on `_jwks_lock` and
# each able to block for the full 10s timeout, so a handful of them stalled
# Access verification for every real user. Each one also overwrote the cache
# and reset its TTL.
#
# A rotation still recovers by itself, one minute later at worst, which is the
# trade this makes: a bounded delay on a rare legitimate event, in exchange for
# the forged path costing nothing to serve.
_JWKS_MIN_REFETCH = 60.0

_jwks_lock = threading.Lock()
_jwks: tuple[float, dict] | None = None      # (fetched_at, keys by kid)
_jwks_attempted = 0.0                        # last fetch, successful or not


def _signing_key(token: str):
    """Cloudflare's public key for this token's `kid`, cached for an hour.

    Refetched on an unknown `kid` so that a key rotation recovers by itself
    rather than at the next restart -- but at most once per `_JWKS_MIN_REFETCH`,
    because an unknown kid is also what a forged token looks like and that path
    must not become a way to make the API hammer Cloudflare.
    """
    global _jwks, _jwks_attempted
    kid = jwt.get_unverified_header(token).get("kid")

    with _jwks_lock:
        now = time.monotonic()
        fresh = _jwks is not None and now - _jwks[0] < _JWKS_TTL
        if fresh and kid in _jwks[1]:
            return _jwks[1][kid]

        # A fresh cache that does not hold this kid is the suspicious case, and
        # the only one that is rate-limited. An absent or expired cache must
        # always fetch: that is the TTL doing its job, not an attacker.
        if fresh and now - _jwks_attempted < _JWKS_MIN_REFETCH:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "unknown signing key"
            )

        # Recorded BEFORE the request, so a fetch that fails still counts
        # against the interval -- otherwise an unreachable Cloudflare turns
        # every forged token back into an outbound attempt.
        _jwks_attempted = now
        url = f"{settings.access_team_domain}/cdn-cgi/access/certs"
        keys = {
            k["kid"]: jwt.PyJWK(k).key
            for k in httpx.get(url, timeout=10.0).raise_for_status().json()["keys"]
        }
        _jwks = (time.monotonic(), keys)

    if kid not in keys:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown signing key")
    return keys[kid]


def access_identity(
    cf_access_jwt_assertion: Annotated[str | None, Header()] = None,
) -> str | None:
    """The authenticated submitter's email, or None where Access is not in play.

    Attached to the jobs router as a whole rather than to individual routes,
    for the same reason the worker token is: something added later cannot
    forget it.

    `require_access_jwt` is set **per listener** in the systemd unit. The
    browser listener sits behind Access and requires a token; the mTLS
    listener is already gated by a client certificate at the TLS layer, and
    demanding a browser session there would lock out Dom0 and the
    command-line tools. Two front doors, two proofs of identity.
    """
    if not settings.require_access_jwt:
        return None

    if not cf_access_jwt_assertion:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "access token required"
        )

    if not settings.access_team_domain or not settings.access_aud:
        # Refuse rather than fall through. A missing AUD would otherwise mean
        # accepting a valid token issued for ANY application in the account.
        log.error("REQUIRE_ACCESS_JWT is set but ACCESS_TEAM_DOMAIN/ACCESS_AUD "
                  "are not; refusing rather than accepting unverified tokens")
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "access verification misconfigured"
        )

    try:
        claims = jwt.decode(
            cf_access_jwt_assertion,
            key=_signing_key(cf_access_jwt_assertion),
            algorithms=["RS256"],
            audience=settings.access_aud,
            issuer=settings.access_team_domain,
        )
    except HTTPException:
        raise
    except Exception as exc:
        # The reason is logged and NOT returned: which check failed is a hint
        # to whoever is probing.
        log.warning("Access JWT rejected: %s", exc)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "invalid access token"
        ) from exc

    # Service tokens authenticate a machine and carry `common_name` instead of
    # an email. Accepted, and recorded as what they are.
    return claims.get("email") or f"service:{claims.get('common_name', 'unknown')}"


Identity = Annotated[str | None, Depends(access_identity)]
