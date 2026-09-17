"""Authentication: the worker channel, and browser identity.

Issue #36 (DRAFT-043), extended by #40 (DRAFT-047) and DRAFT-061.

Two unrelated halves, kept in one module because they are the two answers to
"who is calling". The worker channel is a shared bearer token plus a lease
check; browser identity is a verified Access JWT resolved to a tenant id --
`access_identity` -> `resolve_tenant` -> `Identity`, where only the first sees
an email and only the second touches the database.

Dom0 holds exactly one credential: a bearer token valid only for
`/api/v1/worker/*`. In deployment it sits behind mTLS as well. mTLS is
terminated by the listener and the certificate is never read by this
application, so it is a transport gate rather than an identity source; this
module is the second half.

Every `/worker/jobs/{id}/...` route additionally requires that the job's
`lease_owner` matches the caller, which is `leased_job` below -- a dependency
rather than a line in each handler, for the same reason the token is attached
to the router rather than to routes: something added later cannot forget it.

**CLOSED, DRAFT-061: the credential now names the worker.** This block used to
record a KNOWN GAP -- the caller's identity was an `X-Worker-Id` header,
`lease_owner` was set from a body field, and `WORKER_TOKEN` was one shared
string, so any token holder could present any worker id. `POST /worker/reconcile`
and `/worker/register` took a `worker_id` with no lease gate at all, and
`reconcile` writes.

`authenticated_worker` looks the worker up by its own token's hash, so the id is
derived from the credential rather than declared beside it and the two cannot
disagree. `leased_job` is therefore authorization now, not merely scoping.

What has NOT changed: `docs/architecture/platform.md` still records that a
compromised Dom0 "owns the platform outright", because it is the hypervisor
holding the platform's disks. Per-worker credentials bound what ONE worker's
token reaches; they do not bound what the host running the platform reaches.
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
from fastapi import Cookie, Depends, Header, HTTPException, Path, status
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
           submitted_filename, sha256, key_prefix
      FROM jobs
     WHERE id = %s
"""


def authenticated_worker(
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    """The worker id this credential belongs to. Attached to the whole router.

    **The token names the worker.** Until DRAFT-061 the channel authenticated
    with one shared `WORKER_TOKEN` and read the caller's identity from an
    `X-Worker-Id` header -- two values with nothing binding them, so any token
    holder could present any worker id, drive another worker's job through
    `reconcile`, or attach to a running clone's console. That was KNOWN GAP
    (DRAFT-043/046), and this is the fix: the id is looked up FROM the
    credential, so "present someone else's id" is no longer expressible. The
    header is gone rather than merely ignored.

    **404-shaped refusals, not 403.** Every failure here answers the same way,
    because the alternative tells a caller holding a guessed token whether it
    was a real one that lacked permission or nothing at all.

    Looked up by hash on every request. That is one indexed lookup against a
    table with one row per analysis host -- the `UNIQUE` on `token_hash`
    provides the index -- and it is what makes revoking a worker immediate
    rather than something that waits for a restart.
    """
    scheme, _, presented = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not presented:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "worker credential required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    from .credentials import hash_refresh_token

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT worker_id FROM workers WHERE token_hash = %s",
            (hash_refresh_token(presented),),
        )
        row = cur.fetchone()

    if row is None:
        # A hash lookup is already constant-time in the sense that matters --
        # the comparison happens in the index, not byte by byte in Python --
        # so `secrets.compare_digest` has nothing left to protect here.
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "invalid worker credential"
        )
    return row[0]


WorkerAuth = Annotated[str, Depends(authenticated_worker)]


def leased_job(
    job_id: Annotated[UUID, Path()],
    worker_id: WorkerAuth = None,
) -> dict:
    """Resolve a job the calling worker currently holds a lease on.

    **`worker_id` now comes from the CREDENTIAL**, not from a header the caller
    chose -- which is what turns this from scoping into authorization. Before,
    `lease_owner == worker_id` compared a database value against an unbound
    claim, so it stopped an honest worker touching another's job by mistake and
    stopped nothing else.

    Two distinct failures, kept distinct because they mean different things:

      404  no such job -- and deliberately also what a job belonging to
           ANOTHER worker returns, so the channel cannot be used to probe
           which job ids exist.
      409  the job is this worker's but is no longer running: its lease was
           reaped, or it already reached a terminal state. Stop reporting.

    The 400 that used to mean "no X-Worker-Id header" is gone with the header:
    a caller that reaches here has authenticated, so there is no longer a
    client-bug case to distinguish.
    """
    with connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(_SELECT_JOB, (job_id,))
        job = cur.fetchone()

    # Indistinguishable from "no such job" on purpose: a worker that guesses
    # an id must not learn whether it exists.
    if job is None or job["lease_owner"] != worker_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such job for this worker")

    # LEASED_STATES, not RUNNING_STATES: `cleaning` is still the worker's --
    # it is the one running the cleanup stage, and it has yet to report where the
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


# What the identity provider says, before this platform has resolved it to
# anything of its own: an email, `service:<common_name>`, or None.
AccessIdentity = Annotated[str | None, Depends(access_identity)]


# RFC 5321's maximum address length, in octets. Numerically equal to
# `objects.MAX_OWNER` and NOT the same fact any more: that one bounds the owner
# segment of an S3 key, which since 0009 holds a uuid and can never approach it.
# The two agreed while the key was built from the address; they are now separate
# constants that happen to share a value, and coupling them again would tie a
# storage bound to a key budget that no longer depends on it.
#
# **This is the ONLY bound on what `resolve_tenant` stores**, which it was not
# before. It used to write `identities.email`, declared `varchar(254)`, so the
# column was a backstop even if this check were removed -- a weaker one, since it
# counts CHARACTERS and UTF-8 octets are never fewer, but a real one. It now
# writes `access_subject`, which is `text` and deliberately so: that column has
# to be able to hold a provider `sub` claim later, and those are not addresses.
# Nothing downstream will refuse an over-long value, so this check is load-
# bearing rather than belt-and-braces.
MAX_EMAIL_OCTETS = 254


# The shape `access_identity` gives a service token, reserved so that nothing a
# caller supplies can be spelled like one.
_RESERVED_IDENTITY_PREFIX = "service:"


def address_admissible(value: str) -> bool:
    """Whether `value` may be STORED as a login address.

    One predicate rather than two, because `create_user.py` and the signup route
    both decide this and an operator-made account that could not have been made
    through the route is a difference nobody documents and everybody is
    surprised by.

    **Not a validity check, and deliberately not RFC 5322.** Parsing addresses
    properly admits things no deployment wants and rejects things real users
    have; what this refuses is a value that would be *misread* once stored:

      no `@`             `service:submit-cli`, or any bare word, which would sit
                         in the Owner column of the jobs list looking like
                         infrastructure or another user's account.
      a `service:` prefix
                         checked separately because `service:a@b` HAS an `@`.
                         `access_identity` spells service tokens that way, so
                         this is the one string family a stored address must
                         never be confused with.

    **This is no longer what stops the pre-hijacking attack** -- `resolve_tenant`
    resolving on `access_subject` is, and it holds even if every check here is
    removed. What remains is display integrity: `owner_email` is rendered by
    `_jobs_table.html` and `_job_status.html`, and a published job whose owner
    reads `service:submit-cli` is impersonation in the UI. Jinja autoescapes, so
    it is never more than that.
    """
    value = value.strip()
    if "@" not in value:
        return False
    return not value.lower().startswith(_RESERVED_IDENTITY_PREFIX)


def resolve_tenant(access: AccessIdentity = None) -> str | None:
    """The tenant id for an authenticated caller, or None where there is none.

    **A separate dependency rather than the tail of `access_identity`**, for
    three reasons that are all about keeping verification and resolution apart.

    `access_identity` answers "who does the identity provider say this is", and
    is the half DRAFT-061 replaces once this platform issues its own tokens;
    this answers "which tenant is that" and survives that change untouched.
    `tests/test_access_jwt.py` calls the verifier directly nine times to forge
    tokens against it, and none of those tests wants a database. And
    `tests/conftest.py` overrides `access_identity` for some ninety tests that
    merely need a submitter to exist -- if resolution lived inside it, the
    override would bypass resolution and hand an email to a `uuid` column.

    **None in, None out, and no row created.** None means the request arrived
    on the certificate-gated listener, where the caller is Dom0 or a
    command-line tool rather than a person. Minting an identity for it would
    put infrastructure in the tenant table and give `visible_to` something to
    scope against that is not a tenant.

    **A service token resolves through the same column**, which holds
    `service:<common_name>` for one. That is not an address, which is the cost
    of keeping `submit.py` working across this change -- `required_identity`
    below has always expected service tokens to be able to submit. Revisit at
    the cut-over, when Access goes away and those callers need a credential of
    ours instead.

    **`access_subject`, never `email`, and that is a security boundary rather
    than a column preference.** While this resolved on `lower(email)`, one
    user-writable column was the join key for two independent issuers.
    `/auth/signup` takes an address on trust -- a Telegram code proves control
    of a Telegram account, never of an address -- so claiming an address no
    identity held yet meant the next Access assertion for it landed on the
    CLAIMANT's row, with their password on it: that tenant's jobs, prepaid
    balance and object prefix, taken with one request. `service:<common_name>`
    was claimable the same way and needed no victim address at all. Since no
    route a stranger can reach writes `access_subject`, the two keyspaces cannot
    collide however the address column is filled.

    **So one person can end up with two identities**, if they sign up here and
    also arrive through Access with the same address. That is the deliberate
    cost: this platform cannot know the two are the same human -- believing it
    could is the hole above -- so it declines to guess. Merging them is an
    operator action against evidence, not an inference from a matching string.

    Read first, write only on a miss: this hangs off whole routers, so the
    upsert alone would rewrite the row on every browser request -- `ON CONFLICT
    DO UPDATE` performs an update even when the values are identical, and the
    balance endpoint fires on every page load. Both statements match on
    `lower(access_subject)` because that is what the unique index is on.
    `access_subject = lower(%s)` reads as equivalent and is not: the index
    expression is `lower(access_subject)`, so a predicate on the bare column
    cannot use it and sequentially scans instead.
    """
    if access is None:
        return None            # the cert-gated listener -- mint nothing

    # RFC 5321's maximum address, in OCTETS -- which is what the RFC counts and
    # what the message below has to say, because a 111-character address of
    # multi-byte codepoints is 206 bytes and a reader told "254 characters"
    # would not understand why it was refused. `jobs.py`'s `_MAX_SAMPLE_NAME`
    # carries the same warning against the same mistake.
    #
    # **Why bound it at all, now that an over-long address cannot reach a key.**
    # It used to be `owner_prefix`'s problem: the prefix was built from the
    # address, so 255 bytes minted a key S3 could not store. Since 0009 the
    # prefix holds a uuid and that failure is gone. What remains is weaker and
    # still real -- this value is STORED and DISPLAYED, and it arrives from
    # whatever identity provider the deployment is wired to, so without a bound
    # an IdP could hand over a megabyte and the jobs list would render it.
    #
    # 403 rather than 400 or 413: the caller authenticated perfectly well, and
    # what is refused is a fact about their IDENTITY rather than about this
    # request -- the same distinction `required_identity` below draws, and the
    # reason it uses 403 too. 413 would be wrong twice over: the request body is
    # not oversized, and the caller cannot shorten a claim their IdP issued.
    if len(access.encode("utf-8")) > MAX_EMAIL_OCTETS:
        # Logged, NOT returned, for the reason `access_identity` gives above:
        # the value is attacker-influenceable and echoing a multi-kilobyte
        # string back into an error body amplifies it for nothing. The caller
        # already knows their own address; what they do not know is the limit.
        log.warning("identity refused: %d octets, over the %d-octet limit",
                    len(access.encode("utf-8")), MAX_EMAIL_OCTETS)
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"identity is too long; maximum {MAX_EMAIL_OCTETS} octets "
            f"(RFC 5321)",
        )

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM identities"
            " WHERE lower(access_subject) = lower(%s)",
            (access,),
        )
        # The ROW, not its first column. `fetchone()` returns None on a miss,
        # and subscripting that raises `TypeError` before any check on the
        # value can run -- which made the first request from every new identity
        # a 500 rather than the signup it was meant to be.
        row = cur.fetchone()
        if row is not None:
            return str(row[0])

        # **`email` is deliberately left NULL.** Writing the address here as
        # well would put a provider-asserted value back into the login keyspace
        # -- re-coupling the two columns this split exists to separate -- and
        # would collide outright with a signup that already holds it, turning
        # every subsequent request from this caller into a 500. The address is
        # still shown: the jobs list reads `COALESCE(email, access_subject)`.
        cur.execute(
            """
            INSERT INTO identities (access_subject) VALUES (lower(%s))
            ON CONFLICT (lower(access_subject))
                DO UPDATE SET access_subject = identities.access_subject
            RETURNING id
            """,
            (access,),
        )
        # `DO UPDATE` rather than `DO NOTHING` so RETURNING fires on the
        # conflict path too -- the same reason `create_job`'s `tenants` upsert
        # is written that way. Assigning the column to itself is the no-op that
        # turns it into a lookup: `EXCLUDED.access_subject` would overwrite the
        # stored value with whatever case this caller happened to use.
        #
        # Reachable even after the SELECT above missed, because two concurrent
        # first requests from one identity both miss and only one inserts.
        return str(cur.fetchone()[0])


class _Everything:
    """Infrastructure: a caller that is not a tenant and sees every job.

    A distinct TYPE rather than `None`, and that is the whole of the fix. While
    this was `None`, "no identity" and "see everything" were the same value --
    so every path that could fail to produce an identity quietly produced the
    most privileged one instead, and `visible_to` had no way to tell a
    deliberate infrastructure caller from a bug.

    There is exactly one instance, `EVERYTHING`, and reaching it takes either
    `INFRASTRUCTURE_LISTENER` being set or a caller passing it by name.
    """

    __slots__ = ()

    def __repr__(self) -> str:          # pragma: no cover - debugging aid
        return "EVERYTHING"


EVERYTHING = _Everything()


#: What a resolved caller can be, for the helpers that take one as an ordinary
#: argument rather than through `Depends`.
#:
#: `Identity` below is the FastAPI-facing annotation; this is the plain type.
#: It exists because `str | None` was on six such signatures -- `visible_to`,
#: `_visible_or_404`, `_detail`, `_for_download`, `_publisher`, `_job_row` --
#: and every one of them became wrong the moment `EVERYTHING` was introduced as
#: a third possible value. They kept working, because `from __future__ import
#: annotations` means nothing evaluates them, which is exactly why a wrong
#: annotation here survives: it misleads a reader and a type checker and
#: nothing else. Naming the union once means the next value added to it reaches
#: all six.
Caller = str | _Everything | None


def session_identity(
    sandbox_access: Annotated[str | None, Cookie()] = None,
) -> str | None:
    """The tenant id from a session this platform issued, or None.

    The cookie's `sub` IS the tenant id -- `mint_access_token` puts it there --
    so unlike the Access path there is nothing to resolve and no database round
    trip on the read path.

    **An invalid or expired cookie is None, not a refusal.** A stale cookie is
    the ordinary state of a browser tab left open overnight, and turning it into
    a hard error would mean the UI could not fall back to asking for a login. It
    is safe to be permissive here only because `caller_identity` below refuses
    when NOTHING produced an identity -- which is the half that used to be
    missing.
    """
    if not sandbox_access:
        return None
    from . import credentials

    try:
        return credentials.decode_access_token(sandbox_access)["sub"]
    except credentials.CredentialsError as exc:
        log.debug("ignoring an unusable session cookie: %s", exc)
        return None


def caller_identity(
    session: Annotated[str | None, Depends(session_identity)] = None,
    access: AccessIdentity = None,
) -> "str | _Everything":
    """Who is calling, from whichever credential they hold.

    **Two issuers, one answer.** A session this platform minted takes
    precedence over a Cloudflare Access assertion, so during the cut-over both
    work and a user who has logged in with our own credentials is not sent back
    through the edge. Removing Access later removes a branch here and nothing
    else.

    **Never None.** That is the point of this function. Before DRAFT-061 an
    absent identity flowed into `visible_to`, which read it as "arrived over the
    certificate-gated listener" and scoped nothing -- correct while Access
    guaranteed authentication at the edge, and a full cross-tenant read the
    moment that stopped being true. Now an unauthenticated caller is refused
    here unless the listener is explicitly marked as infrastructure.
    """
    if session is not None:
        return session
    if access is not None:
        return resolve_tenant(access)
    if settings.infrastructure_listener:
        return EVERYTHING
    raise HTTPException(
        status_code=status.HTTP_303_SEE_OTHER,
        headers={"Location": "/ui/login"},
    )


def session_is_ours(
    sandbox_access: Annotated[str | None, Cookie()] = None,
) -> bool:
    """Whether this request's identity came from a session THIS platform issued.

    **The UI needs it because sign-out is only honourable for our own
    sessions.** While an external provider is in front, every request carries
    its assertion and is re-authenticated regardless of what we do with our
    cookies -- so `POST /auth/logout` returns 204, clears cookies that were
    doing nothing, and leaves the caller fully signed in. Offering the control
    anyway is what produced the reported symptom: the UI navigates to
    `/ui/login`, the user believes they are out, and the next link they click
    shows them signed in again.

    A control that cannot do what it says must not be offered. `base.html`
    renders the button only when this is true, which is also why it will simply
    always be true after the cut-over -- there will be no other issuer.

    Deliberately NOT derived from `caller_identity`: this has to answer for a
    caller that has no identity at all, and it must not raise.
    """
    if not sandbox_access:
        return False
    from . import credentials

    try:
        credentials.decode_access_token(sandbox_access)
    except credentials.CredentialsError:
        return False
    return True


# The tenant id -- what every read predicate and every owned row uses.
#
# Re-pointed twice: to `resolve_tenant` by 0009, and to `caller_identity` when
# this platform began issuing its own sessions. The NAME has not changed either
# time, which is why none of its consumers moved.
Identity = Annotated["str | _Everything", Depends(caller_identity)]


def required_identity(identity: Identity = None) -> str:
    """The caller's identity, refusing the callers that do not have one.

    **Reads may be ownerless; writes may not.** `None` is a meaningful answer
    on the read side -- `visible_to` treats it as "arrived over the
    certificate-gated listener" and scopes nothing, which is what lets Dom0
    and the command-line tools see every job. It cannot mean anything on the
    write side since migration 0008: `jobs.owner` is NOT NULL and
    `tenants.owner` is a primary key, so a None here reaches the database as a
    constraint violation and surfaces as a 500 naming a column.

    So this exists to turn that into one refusal, stated once, where a reader
    looking for the rule will find it. Attach it to routes that create an
    owned row -- `create_job` and the balance endpoint -- and leave every read
    route on the optional `Identity`.

    403 rather than 401: the caller authenticated fine, with a client
    certificate. What it lacks is an identity work can be attributed to.

    **Expected to stop firing rather than be removed.** The only callers it
    refuses today are the command-line tools on the mTLS listener; once those
    route through the tunnel they carry an Access service token, which
    `access_identity` reports as `service:<common_name>` and `resolve_tenant`
    gives an identity row like any other.

    **What this receives is a tenant id, not an address** -- since 0009 the
    chain is `access_identity` -> `resolve_tenant` -> here, and only the first
    of those ever sees an email.
    """
    # `EVERYTHING` as well as None: infrastructure is not a person either, and
    # it is now the value the mTLS listener produces. Letting it through would
    # put the sentinel itself into `jobs.owner` -- psycopg refuses to adapt it,
    # so the failure would be a 500 about a placeholder rather than a refusal
    # about an identity.
    if identity is None or identity is EVERYTHING:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "this route records an owner and the caller has no identity; "
            "sign in rather than calling from an infrastructure listener",
        )
    return identity


RequiredIdentity = Annotated[str, Depends(required_identity)]


# --- browser scope --------------------------------------------------------
#
# Issue #40 (DRAFT-047), decision 4: a user reads their own jobs plus published
# ones, and nothing else.
#
# **One predicate, used by every browser read**, so the rule exists once and is
# greppable. Before this, `owner` was written on every submission and enforced
# nowhere -- which is the worse of the two states to sit in, because the column
# looks populated.
#
# **This is the browser channel only.** The worker channel is scoped by
# `lease_owner` (see `leased_job` above) and must never be scoped by `owner`:
# Dom0 is infrastructure, not a tenant, and it has to be able to run anyone's
# job. A future change that "unifies" the two breaks the pipeline for every job
# not owned by whoever Dom0's certificate names.
#
# **Read scope only -- NOT an authorization predicate for writes.** The third
# arm makes this reflexive: once a job is public, every authenticated caller is
# inside the predicate. A mutating route gated on it would therefore hand
# control of the mutation to everyone the previous mutation admitted --
# publication would pass from the owner to anyone who could read it, and B
# could unpublish A's analysis.
#
# `routers.jobs._owned_or_404` is the write-side gate, deliberately a narrower
# predicate. A new mutating route wants that one.
# `tests/test_tenancy.py::test_b_cannot_unpublish_as_published_job` is what
# holds the two apart; it is the only test that fails if they are merged.


def visible_to(identity: Caller) -> tuple[str, list]:
    """SQL fragment and bound params restricting a read to what a caller may see.

    Returns a fragment rather than a finished statement so the caller can
    compose it, and its values separately so they stay bound parameters -- the
    same shape `routers.jobs._filters` uses, and for the same reason.

    Three arms, and each is load-bearing:

    `owner = %s`
        The caller's own submissions.

    `owner IS NULL`
        **Unreachable since migration 0008, and kept deliberately.** It used to
        admit jobs submitted over the mTLS listener, where the identity chain
        returns None and there was no person to record. 0008 made `jobs.owner`
        NOT NULL for traceability and `required_identity` refuses those callers
        before a row exists, so no matching row can be created.

        Left in place because it costs one always-false comparison and removing
        it is a change to a security predicate. **What to know if you touch
        it:** this arm is a shared pool visible to every authenticated user,
        and the only thing keeping it empty is the NOT NULL constraint. Drop
        that constraint and cross-tenant reads come back silently, here.

    `visibility = 'public'`
        Published by the owner through `POST /jobs/{id}/publish` (decisions
        5/6), live since 2026-09-06. It was written here before anything set
        the column, which is what let publishing land as a pure addition rather
        than a change to every read path.

        NOT NULL with a CHECK since migration 0007, so this arm is a plain
        two-valued comparison and there is no NULL case to reason about. The
        value is a literal rather than a bound parameter because it is a
        fragment of a WHERE clause; `enums.Visibility` is the other half of the
        pair and carries the same warning against drift.

    **`EVERYTHING` is not scoped at all**, and it is the only value that is.
    It means infrastructure -- a caller that is not a tenant and has to be able
    to see every job, which Dom0's console end genuinely does.

    This used to be what `None` meant, inferred from Cloudflare Access being
    unset on the mTLS listener. The inference was correct and invisible: one
    configuration mistake, or any later path that failed to produce an identity,
    silently produced the most privileged answer instead. `EVERYTHING` has to be
    passed by name, and `caller_identity` will only produce it where
    `INFRASTRUCTURE_LISTENER` says so.

    """
    if identity is EVERYTHING:
        return "TRUE", []

    # **None is a bug, and is refused as one.** It used to mean "see
    # everything", on the reasoning that only the certificate-gated listener
    # could produce it -- true while Cloudflare Access authenticated the browser
    # at the edge, and a full cross-tenant read the instant that stopped being
    # so. The unscoped answer now requires `EVERYTHING`, which a caller has to
    # ask for by name.
    #
    # ValueError rather than a quiet fallback: a read predicate that cannot tell
    # what it is scoping to must not guess, and the guess it used to make was
    # the most permissive one available.
    if not isinstance(identity, str) or not identity:
        raise ValueError(
            f"visible_to needs a tenant id or EVERYTHING, got {identity!r}"
        )
    return "(jobs.owner = %s OR jobs.owner IS NULL OR jobs.visibility = 'public')", [identity]
