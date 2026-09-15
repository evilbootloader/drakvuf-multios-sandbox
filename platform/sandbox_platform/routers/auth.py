"""Login, refresh and logout for credentials this platform issues.

DRAFT-061 decision 3.

**The only router not behind `Depends(auth.access_identity)`.** Every other
route may assume a session; these three exist to create one, so requiring one
would be circular.

**Nothing consumes these cookies yet.** `auth.access_identity` still reads
Cloudflare's header, so this router issues sessions no route accepts -- which is
deliberate: the verifier swap is the cut-over, kept separate so both credentials
work at once and a rollback stays a config change rather than a data decision.
"""

from __future__ import annotations

import logging

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
import psycopg
from psycopg.rows import dict_row
from pydantic import BaseModel, Field, field_validator

from .. import auth, credentials, sessions, telegram, throttle
from ..config import settings
from ..csrf import require_csrf_header
from ..db import connection

log = logging.getLogger(__name__)


# The CSRF rule moved to `sandbox_platform/csrf.py` (review finding M-7). It was
# defined here and attached to this router alone, while every other mutating
# route in the application relied on `SameSite=Lax` for our own session and on
# Cloudflare's cookie policy for the Access assertion -- which is not ours to
# set. That module carries the full argument, including why presence alone is
# sufficient and the two places it deliberately does not reach.
#
# It still works because the application has NO HTML form POSTs: `submit.html`'s
# form has no method or action and is driven by `submit.js` through `fetch`,
# `jobs.html`'s is a GET filter, and `_job_status.html`'s is a native
# `method="dialog"`. Every mutation is a same-origin fetch that can set a
# header. **If an ordinary `<form method="post">` is ever added, this stops being
# sufficient** and a token is needed instead.


router = APIRouter(
    prefix="/api/v1/auth",
    tags=["auth"],
    dependencies=[Depends(require_csrf_header)],
)


# Cookies rather than an Authorization header, because the UI is server-rendered
# and a page navigation cannot carry one. Both are HttpOnly: a token readable by
# script is a token an XSS gets, and `test_ui_browser.py` exists because hostile
# filenames reach these pages.
_ACCESS_COOKIE = "sandbox_access"
_REFRESH_COOKIE = "sandbox_refresh"

# **The refresh cookie is scoped to the one route that spends it.** The browser
# then never sends it anywhere else, so its exposure is a single endpoint rather
# than every request in the application -- a free reduction, since nothing else
# has any use for it.
_REFRESH_PATH = "/api/v1/auth/refresh"


class LoginRequest(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=1024)
    # Absent on the first attempt: the client cannot know whether this account
    # has a second factor until the password is right, and telling it sooner
    # would disclose that to someone who does not have the password.
    #
    # **Sized for a RECOVERY code, not a TOTP one.** Both arrive in this field,
    # and a recovery code is `xxxx-xxxx-xxxx` -- so a bound of 16 fitted the
    # six digits and rejected the fallback the moment it carried any incidental
    # whitespace, as a value pasted off paper does. The refusal was a 422 from
    # validation, before the route ran at all, so it neither logged nor counted.
    totp: str | None = Field(default=None, max_length=64)


def _client_ip(request: Request) -> str | None:
    """The caller's address, from a source the caller cannot choose.

    **Never from the request body.** A field the client fills in defeats the
    limiter outright: send a different value each time and no bucket ever
    reaches its second attempt.

    Behind cloudflared the socket peer is always the tunnel, so every user would
    share one bucket; `TRUSTED_CLIENT_IP_HEADER` names the header the proxy sets
    instead. Unset means fall back to the peer, which is right in development
    and for a directly-reachable deployment.
    """
    header = settings.trusted_client_ip_header
    if header:
        # Only the first value: `X-Forwarded-For` accumulates a list, and
        # everything after the proxy's own entry was supplied by whoever came
        # before it.
        raw = request.headers.get(header, "")
        return raw.split(",")[0].strip() or None
    return request.client.host if request.client else None


def _set_session_cookies(response: Response, access: str, refresh: str) -> None:
    """Both cookies, with the flags that make them a session rather than a leak."""
    response.set_cookie(
        _ACCESS_COOKIE,
        access,
        max_age=settings.access_token_ttl_minutes * 60,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        _REFRESH_COOKIE,
        refresh,
        max_age=settings.refresh_token_ttl_days * 86400,
        httponly=True,
        secure=True,
        # Strict rather than Lax: nothing should ever spend a refresh token as a
        # side effect of following a link from elsewhere.
        samesite="strict",
        path=_REFRESH_PATH,
    )


@router.post("/login", status_code=status.HTTP_204_NO_CONTENT)
def login(payload: LoginRequest, request: Request, response: Response) -> None:
    """Exchange an address and password for a session.

    **The order of what follows is most of the security here**, and two parts of
    it are load-bearing:

    The rate limit runs BEFORE any hashing. Reversed, the limiter would count
    attempts after paying 64 MiB and ~100ms for each, which records a flood
    rather than preventing one.

    `verify_password` runs on every path, including the one where the address
    matches no identity -- it is passed `None` and verifies against a dummy hash
    of the same cost. Returning early there is what makes a login route answer
    "no such user" in microseconds and "wrong password" in ~100ms, which
    identifies every registered address regardless of how identical the error
    text is.
    """
    ip = _client_ip(request)

    # **Every refusal is raised AFTER the connection block closes.**
    #
    # `db.connection` is "committed on success and rolled back on error", so an
    # HTTPException raised while it is open discards everything the block did --
    # including the increment that was meant to count the very attempt being
    # refused. Left that way, failed logins roll back and only SUCCESSFUL ones
    # persist a count: the rate limit and the lockout both sit permanently at
    # zero while looking implemented. Measured, not reasoned about -- the
    # `rate_limit` table came back empty after six failed attempts.
    #
    # So the block records what happened and sets a verdict; the raising is
    # below. `refresh` has the same shape for the same reason.
    throttled = False
    failed = False
    mfa_required = False
    used_recovery = False
    owner = None
    stored = None
    row = None
    # Stays None on every refused path, and that is load-bearing rather than
    # tidiness -- see the success block below.
    refresh = None

    with connection() as conn:
        try:
            for bucket in throttle.login_buckets(ip, payload.email):
                throttle.enforce_limit(conn, bucket)
        except throttle.Throttled:
            throttled = True

        if not throttled:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT i.id AS owner, c.hashed_password, c.totp_secret,
                           c.totp_confirmed_at, c.totp_last_step
                      FROM identities i
                      LEFT JOIN tenant_credentials c ON c.owner = i.id
                     WHERE lower(i.email) = lower(%s)
                    """,
                    (payload.email,),
                )
                row = cur.fetchone()

            # A LEFT JOIN, so "no such identity" and "identity with no password
            # set" arrive the same way: both leave `stored` None and take the
            # dummy-hash path, rather than being two branches with two timings.
            owner = str(row["owner"]) if row else None
            stored = row["hashed_password"] if row else None

            try:
                if owner is not None:
                    throttle.assert_not_locked(conn, owner)
            except throttle.Throttled:
                throttled = True

        if not throttled:
            if credentials.verify_password(stored, payload.password):
                # **The second factor is checked only AFTER the password.**
                # Whether an account has one is disclosed by the refusal below,
                # so the refusal must be unreachable without the password --
                # otherwise it becomes a free oracle for which accounts are
                # worth attacking.
                if row and row["totp_confirmed_at"] is not None:
                    if not payload.totp:
                        mfa_required = True
                    else:
                        try:
                            step = credentials.verify_totp(
                                row["totp_secret"], payload.totp,
                                row["totp_last_step"],
                            )
                            conn.execute(
                                "UPDATE tenant_credentials SET totp_last_step"
                                " = %s WHERE owner = %s", (step, owner),
                            )
                        except credentials.InvalidCredentials:
                            # **A recovery code is offered in the same field.**
                            # One box on the form, and no shape-sniffing to
                            # decide which kind was typed -- whichever verifies
                            # is what it was. Tried second so a valid
                            # authenticator code never touches the codes table.
                            if _spend_recovery_code(conn, owner, payload.totp):
                                used_recovery = True
                            else:
                                throttle.record_failure(conn, owner)
                                failed = True
                        except credentials.TotpReplayed:
                            # Correct but spent. Not counted as a failed
                            # attempt: the code verified, so this is a replay
                            # rather than a guess, and counting it would let an
                            # attacker lock out a user by replaying one code.
                            mfa_required = True

                # **Everything below runs only on the FULLY-successful path**,
                # and the indentation is the whole fix.
                #
                # It used to run whenever the PASSWORD verified, second factor
                # or not -- so a login refused for a missing or wrong code
                # still committed a `refresh_tokens` row, because the refusal
                # is raised after this block closes and the block commits on
                # the way out. Not a bypass: the plaintext was discarded and no
                # cookie was set. What it left behind was a live, unrevoked
                # token, valid for REFRESH_TOKEN_TTL_DAYS, mintable by anyone
                # holding a password but not the factor -- and one extra per
                # ordinary MFA login, since the first attempt carries no code.
                # Measured: five refused logins, five rows.
                if not (mfa_required or failed):
                    throttle.record_success(conn, owner)
                    # Rehashed HERE: this is the only moment the plaintext
                    # exists. Deferring it to "next login" means storing a flag
                    # and waiting for a login that may never come, while the
                    # account keeps the old cost. Also on the successful path
                    # only -- rewriting the hash for a caller who cannot finish
                    # authenticating is a write on behalf of someone who has
                    # not yet proved they are the account holder.
                    if credentials.needs_rehash(stored):
                        conn.execute(
                            "UPDATE tenant_credentials SET hashed_password = %s"
                            " WHERE owner = %s",
                            (credentials.hash_password(payload.password), owner),
                        )
                    refresh = sessions.issue_refresh_token(conn, owner)
            else:
                throttle.record_failure(conn, owner)
                failed = True

    # Raised by the app-level handler as a 429, identically for a rate limit and
    # a lockout -- see `app._throttled`. Telling them apart would say the
    # account exists.
    if throttled:
        raise throttle.RateLimited("too many attempts")
    if failed:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "invalid email or password"
        )
    if mfa_required:
        # A DIFFERENT refusal from a wrong password, and deliberately so: the
        # caller has already proved the password, so telling them a code is
        # wanted discloses nothing they could not learn by guessing once more.
        # Without it the UI has no way to know it should ask.
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "a second-factor code is required"
        )

    _set_session_cookies(response, credentials.mint_access_token(owner), refresh)

    if used_recovery:
        # Logged, because spending one is worth noticing: it means an
        # authenticator is gone, or someone else is using the codes.
        log.warning("recovery code spent for %s", owner)


@router.post("/refresh", status_code=status.HTTP_204_NO_CONTENT)
def refresh(request: Request, response: Response) -> None:
    """Spend a refresh token for a new pair.

    Rotation on every use is what makes a stolen token detectable at all: the
    honest client always moves on to the successor, so a second presentation of
    a spent token means two parties hold it.
    """
    presented = request.cookies.get(_REFRESH_COOKIE)
    if not presented:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no session")

    # **The refusal is raised AFTER the connection block, not inside it.**
    #
    # `db.connection` is "committed on success and rolled back on error", so an
    # HTTPException raised while it is open discards everything the block did --
    # including the revocation of a chain we have just detected as stolen. The
    # replay would be declined and the successor would keep working, which is
    # the one outcome this whole mechanism exists to prevent. Caught by
    # `test_replaying_a_spent_token_revokes_the_whole_chain`, which is why the
    # test asserts on the SUCCESSOR rather than on the replayed token.
    refused = False
    with connection() as conn:
        try:
            new_refresh, owner = sessions.rotate_refresh_token(conn, presented)
        except sessions.TokenReused as exc:
            sessions.revoke_chain(conn, int(str(exc)))
            log.warning("refresh token replay; chain revoked")
            refused = True
        except sessions.UnknownRefreshToken:
            refused = True

    if refused:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session ended")

    _set_session_cookies(
        response, credentials.mint_access_token(owner), new_refresh
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response) -> None:
    """End this session everywhere, and clear both cookies.

    Deliberately not an error when there is no session: logout is idempotent,
    and a caller who has already lost their cookie has got what they asked for.

    Revokes every token for the owner rather than only the presented one --
    "log out" that leaves other sessions running is not what anyone means by it,
    and the common reason for pressing it is suspecting one of them.

    **The owner is found from the ACCESS cookie when the refresh cookie is not
    sent, and a browser never sends it here.** `_REFRESH_PATH` scopes the
    refresh cookie to `/api/v1/auth/refresh`, and `/api/v1/auth/logout` is not
    a prefix match -- so from a real browser the revoking half of this route was
    unreachable, and only the two `delete_cookie` calls ever ran. The tests
    passed because a test client is handed the cookie explicitly. Found when
    `base.html` gained a sign-out control that had to actually end the session.

    Trusting the access cookie to identify whom to revoke costs nothing: it is
    a bearer credential for this owner, so anyone holding it can already act as
    them for its whole TTL, and all it buys here is ending those sessions.
    """
    owner = None

    presented = request.cookies.get(_REFRESH_COOKIE)
    if presented:
        with connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT owner FROM refresh_tokens WHERE token_hash = %s",
                (credentials.hash_refresh_token(presented),),
            )
            row = cur.fetchone()
            if row is not None:
                owner = str(row["owner"])

    if owner is None:
        access = request.cookies.get(_ACCESS_COOKIE)
        if access:
            try:
                owner = credentials.decode_access_token(access)["sub"]
            except credentials.InvalidToken:
                # Expired or forged. Not an error: the cookies are cleared
                # below either way, which is the part the caller asked for.
                # `CredentialsUnconfigured` is deliberately NOT caught -- that
                # is the deployment being broken, and it is mapped to a 503
                # everywhere else in this module.
                owner = None

    if owner is not None:
        with connection() as conn:
            sessions.revoke_all_for_owner(conn, owner)

    # Cleared with the SAME path and flags they were set with -- a browser
    # matches those when deciding which cookie to remove, so a mismatch leaves
    # the original in place and the session appears to survive logout.
    response.delete_cookie(_ACCESS_COOKIE, path="/", httponly=True, secure=True,
                           samesite="lax")
    response.delete_cookie(_REFRESH_COOKIE, path=_REFRESH_PATH, httponly=True,
                           secure=True, samesite="strict")

# --- signup and password reset (DRAFT-061 decisions 1 and 2) ----------------
#
# **Both are gated on Telegram, and neither can be reached without it.** That is
# what makes signup self-service without making it an abuse vector: the
# `tenants` row carries an opening grant of prepaid analysis seconds, so an
# ungated signup route is free malware-analysis compute for anyone who can make
# an email address.
#
# The flow is Telegram-first because a bot cannot message a user who has not
# started it. `/start` creates an identity with a Telegram id and nothing else;
# these routes are where an address, a password and a balance get attached. See
# `telegram.py` for why that order is forced rather than chosen.


class SignupRequest(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=12, max_length=1024)
    code: str = Field(max_length=64)

    # **On this model and on NO other, which is the part worth being careful
    # about.** The same rule on `LoginRequest` or `ResetRequest` would refuse a
    # malformed address with a 422 raised by validation, before the route body
    # runs -- so the attempt would neither be logged nor counted against the
    # rate limiter, which is exactly the trap the `totp` field above records
    # having already fallen into once. Signup is the only route here that
    # STORES an address, so it is the only one that gets to be fussy about it.
    @field_validator("email")
    @classmethod
    def _storable_address(cls, value: str) -> str:
        if not auth.address_admissible(value):
            raise ValueError("that is not an email address")
        return value


class ResetRequest(BaseModel):
    email: str = Field(max_length=254)


class ResetConfirm(BaseModel):
    code: str = Field(max_length=64)
    password: str = Field(min_length=12, max_length=1024)


@router.post("/signup", status_code=status.HTTP_204_NO_CONTENT)
def signup(payload: SignupRequest, request: Request) -> None:
    """Attach an address, a password and a balance to a Telegram-verified id.

    Rate limited on the same buckets as login, because it is a public route that
    runs argon2 -- and an unlimited one would be a cheaper way to exhaust the
    hashing slots than login, since it needs no existing account.

    **The grant is what the gate protects.** `tenants.balance_seconds` defaults
    to an hour of analysis, so this route is the one place where a stranger
    acquires something worth having.
    """
    # Checked before anything else, including the rate limit: a closed
    # registration is a fact about the deployment rather than about this
    # caller, so there is nothing to count and nothing to hash.
    if not settings.registration_open:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "registration is closed on this deployment",
        )

    ip = _client_ip(request)
    throttled = False
    conflict = False
    bad_code = False

    with connection() as conn:
        try:
            for bucket in throttle.login_buckets(ip, payload.email):
                throttle.enforce_limit(conn, bucket)
        except throttle.Throttled:
            throttled = True

        if not throttled:
            owner = telegram.redeem_code(conn, payload.code, "telegram_linking")
            if owner is None:
                bad_code = True
            else:
              # A SAVEPOINT, because claiming the address can raise
              # `UniqueViolation` -- `WHERE email IS NULL` guards against this
              # identity having signed up already, but not against ANOTHER
              # identity holding the address. psycopg aborts the whole
              # transaction on that error, so without a nested transaction the
              # rate-limit increments above would be lost with it and the route
              # would 500 instead of refusing.
              try:
                with conn.transaction(), conn.cursor() as cur:
                      # Claiming the address and creating the credentials in one
                      # statement each, on a connection that commits together: a
                      # half-finished signup would leave an identity holding an
                      # address with no way to log in, and no way to retry either
                      # because the address is taken.
                      cur.execute(
                          """
                          UPDATE identities SET email = lower(%s)
                           WHERE id = %s AND email IS NULL
                          RETURNING id
                          """,
                          (payload.email, owner),
                      )
                      if cur.fetchone() is None:
                          # Either this identity already signed up, or the UNIQUE
                          # index rejected the address. Both are "cannot use this
                          # code with this address"; neither says which.
                          conflict = True
                      else:
                          cur.execute(
                              "INSERT INTO tenant_credentials (owner,"
                              " hashed_password) VALUES (%s, %s)",
                              (owner, credentials.hash_password(payload.password)),
                          )
                          # The opening grant. `ON CONFLICT DO NOTHING` because
                          # `create_job` and the balance endpoint both create this
                          # row on first contact too, and signup must not fail if
                          # one of them got there first.
                          cur.execute(
                              "INSERT INTO tenants (owner) VALUES (%s)"
                              " ON CONFLICT DO NOTHING",
                              (owner,),
                          )
              except psycopg.errors.UniqueViolation:
                # The address belongs to someone else. Indistinguishable from a
                # bad code below, so signup cannot be used to test whether an
                # address is registered.
                conflict = True

    if throttled:
        raise throttle.RateLimited("too many attempts")
    if bad_code or conflict:
        # One refusal for both, so a caller cannot use signup to test whether an
        # address is already registered.
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "that code is not valid, or has already been used",
        )


def _deliver_reset_code(chat_id: int, text: str) -> None:
    """The outbound half of a reset, run after the response has been written.

    **Not called inline, and the reason is a measured resource bound.**
    `telegram.send_message` is a synchronous `httpx.post` with a 30s timeout.
    Called from inside a `with connection()` block it holds a pooled connection
    for the whole round trip, and the pool is `DB_POOL_MAX=10` with a 10s
    acquire timeout -- so eleven concurrent resets against a slow
    `api.telegram.org` exhaust it and every other route in the process starts
    failing in `db.get_pool()`. Reset is public and unauthenticated, so nothing
    but the rate limiter stands in front of that.

    `CredentialsUnconfigured` is caught here and nowhere else. `send_message`
    re-raises it so `telegram.poll_once` can say "never configured" rather than
    "Telegram is down", but on this path there is no caller left to tell: the
    204 has already gone out. A log line is the whole of what can be done, and
    it is what an operator needs -- the code exists and will never arrive.
    """
    try:
        telegram.send_message(chat_id, text)
    except credentials.CredentialsUnconfigured:
        log.error("a reset code was minted but TELEGRAM_BOT_TOKEN is unset")


@router.post("/reset/request", status_code=status.HTTP_204_NO_CONTENT)
def request_reset(payload: ResetRequest, request: Request,
                  background: BackgroundTasks) -> None:
    """Send a reset code to the Telegram account linked to this address.

    **Always 204, whether or not the address exists.** The response cannot
    depend on it: a route that says "no such account" is an enumeration oracle
    that needs no password guessing at all, and it would undo what the login
    path pays a full argon2 hash to withhold.

    **The body is not the only channel, which is why delivery is deferred.**
    The Telegram round trip happens only when the address resolves, so calling
    it inline made existence readable off response latency without reading the
    response at all -- microseconds for an unknown address against a network
    round trip for a known one. Handing it to `BackgroundTasks` moves it past
    the point where the response body is written, so both paths return after
    the same work. No artificial delay: a sleep long enough to cover a 30s
    timeout would be a self-inflicted denial of service on a public route, and
    one shorter than the real call would not equalise anything.

    **The residual, stated rather than claimed away:** the ASGI request cycle
    is not complete until the background task finishes, so a caller who keeps
    the connection alive and pipelines a second request can still time the
    difference. That is a much narrower oracle than the first one -- it needs
    connection reuse and a second request -- and closing it entirely means
    delivery by a separate worker, which is machinery this has not earned.

    Delivery failures are swallowed by `telegram.send_message` for the same
    reason the status is fixed -- the user retries, and the response says
    nothing either way.
    """
    ip = _client_ip(request)
    throttled = False
    # Filled in inside the block and spent after it, so the code is COMMITTED
    # before it is delivered. The other order is worse than the bug it would
    # fix: a rolled-back transaction with a delivered code is a user reading a
    # code out of Telegram that this platform has no record of.
    chat_id = None
    code = None

    with connection() as conn:
        try:
            for bucket in throttle.login_buckets(ip, payload.email):
                throttle.enforce_limit(conn, bucket)
        except throttle.Throttled:
            throttled = True

        if not throttled:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT id, telegram_user_id FROM identities
                     WHERE lower(email) = lower(%s)
                       AND telegram_user_id IS NOT NULL
                    """,
                    (payload.email,),
                )
                row = cur.fetchone()

            if row is not None:
                chat_id = row["telegram_user_id"]
                code = telegram.mint_code(conn, str(row["id"]), "password_reset")

    if throttled:
        raise throttle.RateLimited("too many attempts")

    if code is not None:
        background.add_task(
            _deliver_reset_code,
            chat_id,
            f"Your sandbox password reset code:\n\n{code}\n\n"
            "If you did not ask for this, ignore it -- nothing has changed.",
        )


@router.post("/reset/confirm", status_code=status.HTTP_204_NO_CONTENT)
def confirm_reset(payload: ResetConfirm, request: Request) -> None:
    """Set a new password from a reset code, and end every existing session.

    **Revoking sessions is the point, not a courtesy.** The usual reason for
    resetting a password is believing someone else has it; leaving their
    sessions running means the reset changed nothing for the person it was for.
    """
    ip = _client_ip(request)
    throttled = False
    owner = None

    with connection() as conn:
        try:
            # Keyed on the code rather than an address -- this route is given no
            # address, and a bucket per code is what stops it being used to
            # brute-force one.
            throttle.enforce_limit(conn, f"reset:{ip or 'unknown'}")
        except throttle.Throttled:
            throttled = True

        if not throttled:
            owner = telegram.redeem_code(conn, payload.code, "password_reset")
            if owner is not None:
                conn.execute(
                    """
                    UPDATE tenant_credentials
                       SET hashed_password = %s,
                           password_changed_at = now(),
                           failed_attempts = 0,
                           last_failed_at = NULL,
                           locked_until = NULL
                     WHERE owner = %s
                    """,
                    (credentials.hash_password(payload.password), owner),
                )
                sessions.revoke_all_for_owner(conn, owner)

    if throttled:
        raise throttle.RateLimited("too many attempts")
    if owner is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "that code is not valid, or has already been used",
        )


# --- the second factor (DRAFT-061 decision 3) -------------------------------


class TotpConfirm(BaseModel):
    code: str = Field(max_length=16)


class TotpDisable(BaseModel):
    password: str = Field(max_length=1024)


def _session_owner(request: Request) -> str:
    """The tenant id from the access cookie, or 401.

    **Local to this router, and NOT the cut-over.** `auth.access_identity` still
    reads Cloudflare's header and every other route still goes through it; this
    only lets the enrolment routes below know who is asking, which they cannot
    do any other way. Swapping the application-wide verifier is a separate step,
    kept separate so both credentials work at once and a rollback stays a config
    change.
    """
    token = request.cookies.get(_ACCESS_COOKIE)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no session")
    try:
        return credentials.decode_access_token(token)["sub"]
    except credentials.InvalidToken as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no session") from exc


@router.get("/totp/status")
def totp_status(request: Request) -> dict:
    """Whether the factor is on, and whether an enrolment is part-finished.

    **Read-only, and that is the entire reason it exists.** The account page
    used to answer "is MFA on?" by POSTing to `/totp/enrol` and reading the 409
    -- which meant every page load, every reload and every second tab minted a
    fresh secret and wrote it over the unconfirmed one. Someone who added the
    key to their authenticator and then reloaded was confirming against a
    secret the server had already replaced, and every code was wrong with
    nothing on the page to explain it. A probe that mutates is not a probe.

    **No secret in the answer**, confirmed or otherwise. This is a GET, it is
    reachable with nothing but a session cookie, and an enrolment secret is a
    credential -- `enrol_totp` is the only route that hands one out, once, in
    response to a deliberate POST.

    `credentialed` distinguishes an account with no `tenant_credentials` row at
    all. Such an identity cannot enrol -- there is no row to attach a secret to
    -- and saying so here lets the page offer something other than a button
    that can only fail.
    """
    owner = _session_owner(request)

    with connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT totp_secret IS NOT NULL AS started,"
            "       totp_confirmed_at IS NOT NULL AS enabled"
            "  FROM tenant_credentials WHERE owner = %s",
            (owner,),
        )
        row = cur.fetchone()

    if row is None:
        return {"credentialed": False, "enabled": False, "enrolling": False}
    return {
        "credentialed": True,
        "enabled": row["enabled"],
        # A confirmed secret is not an enrolment in progress. Reporting both at
        # once would have the page offering to finish something already done.
        "enrolling": row["started"] and not row["enabled"],
    }


@router.post("/totp/enrol")
def enrol_totp(request: Request) -> dict:
    """Begin enrolment: a new secret and the URI an authenticator scans.

    **Called on a deliberate press, never on page load.** It replaces whatever
    unconfirmed secret is there, so anything that calls it speculatively
    invalidates an enrolment someone may be halfway through -- see
    `totp_status`, which is what a page asks instead.

    **The secret is stored but not yet active** -- `totp_confirmed_at` stays
    NULL until a code proves the authenticator agrees. Treating a generated
    secret as live is how people lock themselves out between scanning the code
    and it working.

    Re-enrolling replaces an unconfirmed secret, which is what makes a failed
    attempt recoverable by simply starting again. It refuses once confirmed, so
    a stolen SESSION cannot silently swap the second factor for one the attacker
    holds -- disabling it first requires the password.
    """
    owner = _session_owner(request)
    secret = credentials.new_totp_secret()

    # Two refusals, raised after the block for the reason `login` documents at
    # length. Nothing here writes on a refused path today, so the rollback
    # costs nothing yet -- but the shape is the module's, and a later increment
    # added above would be silently discarded by an inline raise.
    already_enabled = False
    no_credentials = False
    row = None

    with connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            UPDATE tenant_credentials
               SET totp_secret = %s, totp_last_step = NULL
             WHERE owner = %s AND totp_confirmed_at IS NULL
            RETURNING owner
            """,
            (secret, owner),
        )
        if cur.fetchone() is None:
            # **Zero rows means one of two opposite things.** The UPDATE
            # matches on `totp_confirmed_at IS NULL`, so it also misses when
            # there is no `tenant_credentials` row at all -- and an identity
            # with no password set was being told "the second factor is already
            # enabled; disable it first", which is as wrong as an answer can
            # be. A second read decides which; the UPDATE above is still the
            # authority on the race, since this one only explains a miss.
            cur.execute(
                "SELECT 1 FROM tenant_credentials WHERE owner = %s", (owner,)
            )
            already_enabled = cur.fetchone() is not None
            no_credentials = not already_enabled
        else:
            cur.execute("SELECT email FROM identities WHERE id = %s", (owner,))
            row = cur.fetchone()

    if already_enabled:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "the second factor is already enabled; disable it first",
        )
    if no_credentials:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "this account has no password set, so there is nothing to add a "
            "second factor to",
        )

    return {"secret": secret,
            "uri": credentials.totp_uri(secret, row["email"] or owner)}


def _issue_recovery_codes(conn, owner: str) -> list[str]:
    """Replace this account's recovery codes and return the new set.

    **Returned exactly once.** Only hashes are stored, so there is no route that
    can show them again -- which is the property that makes them worth having,
    and also why regenerating is the answer to "I lost them" rather than a
    second look.

    The whole set is replaced rather than topped up: leaving old codes live
    alongside new ones means a set someone believes they have replaced is still
    spendable.
    """
    codes, hashes = credentials.new_recovery_codes()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM mfa_recovery_codes WHERE owner = %s", (owner,))
        cur.executemany(
            "INSERT INTO mfa_recovery_codes (code_hash, owner) VALUES (%s, %s)",
            [(h, owner) for h in hashes],
        )
    return codes


def _spend_recovery_code(conn, owner: str, code: str) -> bool:
    """Spend one code if it is live. True if it was.

    **One UPDATE, not a SELECT then an UPDATE.** Single-use has to be atomic, or
    two requests presenting the same code both read it as unused and both
    succeed -- which for a login is two sessions from one credential.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE mfa_recovery_codes SET used_at = now()
             WHERE code_hash = %s AND owner = %s AND used_at IS NULL
            RETURNING code_hash
            """,
            (credentials.hash_recovery_code(code), owner),
        )
        return cur.fetchone() is not None


@router.post("/totp/confirm")
def confirm_totp(payload: TotpConfirm, request: Request) -> dict:
    """Finish enrolment, and hand back the recovery codes.

    **The codes are part of enabling it, not an afterthought.** Issued in the
    same call that turns the factor on, because a user who is asked to save them
    later mostly does not -- and an authenticator lost before that step is an
    account only an operator can recover.
    """
    owner = _session_owner(request)

    with connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT totp_secret, totp_confirmed_at, totp_last_step"
                " FROM tenant_credentials WHERE owner = %s",
                (owner,),
            )
            row = cur.fetchone()

        if row is None or not row["totp_secret"]:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                "no enrolment in progress")
        if row["totp_confirmed_at"] is not None:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "the second factor is already enabled")

        step = credentials.verify_totp(row["totp_secret"], payload.code,
                                       row["totp_last_step"])
        conn.execute(
            "UPDATE tenant_credentials SET totp_confirmed_at = now(),"
            " totp_last_step = %s WHERE owner = %s",
            (step, owner),
        )
        codes = _issue_recovery_codes(conn, owner)

    return {"recovery_codes": codes}


# --- re-proving the password inside an existing session ---------------------
#
# **The two routes below are password guesses, and they were not counted.**
# Both verify a password and neither touched the limiter, so the password was
# guessable at full speed by whoever held a session cookie -- which, per their
# own docstrings, is precisely the attacker they exist to defend against. A
# success there removes the second factor outright, or hands back ten codes
# that bypass it.
#
# There is a second, quieter reason. `credentials._hash_slot` bounds concurrent
# argon2 to MAX_CONCURRENT_HASHES (4), and refuses rather than queues. An
# authenticated caller looping on an unlimited hashing route holds all four and
# turns LOGIN into a 503 for everyone -- so an unthrottled route here is an
# availability hole for the whole authentication surface, not only its own.


def _password_bucket(owner: str) -> str:
    """The rate-limit bucket for re-proving a password inside a session.

    **Not `throttle.login_buckets`**, which is the login shape: it keys on a
    submitted address, and these routes are given none -- the owner comes from
    the access cookie. Its per-address bucket exists to make a nonexistent
    account accumulate a counter like a real one, which is an enumeration
    concern that cannot arise here, since reaching these routes already
    required a valid session for a real identity.

    ONE bucket shared by both routes rather than one each. An attacker able to
    alternate between two counters gets twice the guesses at the same password
    for the same work.
    """
    return f"totp:{owner}"


def _verify_password_for_session(conn, owner: str,
                                 password: str) -> tuple[str, dict | None]:
    """Re-prove the password of an established session. Returns a verdict.

    `("throttled" | "failed" | "ok", credentials row or None)`.

    **It returns rather than raises, and that is the point of it existing.**
    `db.connection` is committed on success and rolled back on error, so an
    HTTPException raised while the block is open discards everything the block
    did -- including the increment meant to count the very attempt being
    refused. `login` documents that measurement at length: the `rate_limit`
    table came back empty after six failed attempts. This is the same trap one
    level down, and handing back a verdict is what stops a caller reaching for
    an inline `raise`. `_raise_password_verdict` is the other half.

    The limiter runs BEFORE `verify_password`, for the reason `login` gives:
    counting after paying 64 MiB and ~100ms per attempt records a flood instead
    of preventing one, and it is also what keeps this route off the four
    argon2 slots once it is being abused.

    The per-account lockout is the SAME one login uses, deliberately. A
    password being guessed through a stolen cookie is the account under attack,
    and it should stop answering to login as well.
    """
    try:
        throttle.enforce_limit(conn, _password_bucket(owner))
        throttle.assert_not_locked(conn, owner)
    except throttle.Throttled:
        return "throttled", None

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT hashed_password, totp_confirmed_at"
            "  FROM tenant_credentials WHERE owner = %s",
            (owner,),
        )
        row = cur.fetchone()

    # No credentials row is treated exactly like a wrong password. There is no
    # enumeration to protect against here, but there is also nothing this
    # caller could do about it, and one refusal is one thing for the UI to say.
    if row is None or not credentials.verify_password(
            row["hashed_password"], password):
        throttle.record_failure(conn, owner)
        return "failed", row

    throttle.record_success(conn, owner)
    return "ok", row


def _raise_password_verdict(verdict: str) -> None:
    """Turn a verdict into its refusal. **Call AFTER the connection block.**

    Split out so the two call sites cannot disagree, and so the raising is
    visibly outside the `with` in both of them.

    `RateLimited` for a lockout as well as a window overflow: `app._throttled`
    maps every `Throttled` to the same 429, because telling them apart says the
    account exists. Here the caller already knows it does, but keeping one
    refusal keeps one code path.
    """
    if verdict == "throttled":
        raise throttle.RateLimited("too many attempts")
    if verdict == "failed":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "incorrect password")


@router.post("/totp/disable", status_code=status.HTTP_204_NO_CONTENT)
def disable_totp(payload: TotpDisable, request: Request) -> None:
    """Turn the second factor off. **Requires the password, not just a session.**

    A session alone is exactly what an attacker who stole a cookie has; letting
    that remove the second factor would make the factor worth nothing against
    the attack it exists for. Re-entering the password is a small cost on a rare
    action.

    Counted and rate limited like a login, because that is what it is -- see
    `_verify_password_for_session`.
    """
    owner = _session_owner(request)

    with connection() as conn:
        verdict, _ = _verify_password_for_session(conn, owner, payload.password)

        if verdict == "ok":
            conn.execute(
                "UPDATE tenant_credentials SET totp_secret = NULL,"
                " totp_confirmed_at = NULL, totp_last_step = NULL"
                " WHERE owner = %s",
                (owner,),
            )
            # The codes go with it. Left behind, they would be live credentials
            # for a second factor that no longer exists -- and would silently
            # come back into force if the factor were ever re-enabled.
            conn.execute("DELETE FROM mfa_recovery_codes WHERE owner = %s",
                         (owner,))

    _raise_password_verdict(verdict)


class RecoveryRegenerate(BaseModel):
    password: str = Field(max_length=1024)


@router.post("/totp/recovery")
def regenerate_recovery_codes(payload: RecoveryRegenerate,
                              request: Request) -> dict:
    """Replace the recovery codes and return the new set.

    **Requires the password, like disabling does**, and for the same reason: a
    session alone is what someone holding a stolen cookie has, and this route
    hands back ten credentials that each bypass the second factor. Issuing them
    to a session would make the factor worth nothing against exactly the attack
    it exists for.

    This is also the answer to "I lost the list" -- there is no route that shows
    the old ones, because only their hashes were ever stored.

    Counted and rate limited like a login, because that is what it is -- see
    `_verify_password_for_session`.
    """
    owner = _session_owner(request)
    not_enabled = False
    codes = None

    with connection() as conn:
        verdict, row = _verify_password_for_session(conn, owner,
                                                    payload.password)

        if verdict == "ok":
            if row["totp_confirmed_at"] is None:
                not_enabled = True
            else:
                codes = _issue_recovery_codes(conn, owner)

    _raise_password_verdict(verdict)
    # Out here with the others. It arrives AFTER a successful verify, so
    # `record_success` has already cleared the failure state on the row -- an
    # inline raise would roll that write back and leave a caller who typed
    # their password correctly still carrying a failure count.
    if not_enabled:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "the second factor is not enabled; there is nothing to recover",
        )

    return {"recovery_codes": codes}


@router.get("/totp/recovery/remaining")
def remaining_recovery_codes(request: Request) -> dict:
    """How many codes are still live.

    A COUNT and nothing else -- the codes themselves are unreadable. It exists
    so the account page can say "2 remaining" rather than leaving someone to
    discover it at the moment they need one.
    """
    owner = _session_owner(request)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM mfa_recovery_codes"
            " WHERE owner = %s AND used_at IS NULL",
            (owner,),
        )
        return {"remaining": cur.fetchone()[0]}
