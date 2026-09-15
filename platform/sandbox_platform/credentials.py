"""Credentials this platform issues and checks itself.

DRAFT-061 decision 3. Until now the platform verified someone else's identity
assertion -- `auth.access_identity` checks a Cloudflare JWT against Cloudflare's
keys -- and issued nothing. This module is the other half, and it is
security-critical surface the project did not previously carry.

**No FastAPI import, deliberately**, for the reason `objects.py` gives about
itself: this is a library of cryptographic operations, and raising HTTPException
here would make every test of it need a request. It raises its own exceptions
and the route layer maps them to statuses.

**Issuance is kept separable from verification of OTHER issuers.** DRAFT-061
notes that a future SSO integration plugs into the verification path, so
`auth.access_identity` stays where it is and this module never touches it. The
only thing both produce is a tenant id, and `auth.resolve_tenant` is where they
meet.

Three kinds of secret live here and they are not interchangeable:

    password        low entropy, chosen by a human      -> argon2id, slow
    refresh token   256 bits from `secrets`             -> sha256, fast
    access token    a signed assertion, not a secret    -> HMAC, stateless
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .config import settings


class CredentialsError(Exception):
    """Base for everything this module raises, so a caller can catch one thing."""


class CredentialsUnconfigured(CredentialsError):
    """A secret this module needs is unset. Maps to 503, never to 500.

    The deployment is misconfigured rather than the request being wrong, and the
    distinction matters to whoever is reading the logs at the time.
    """


class HashCapacityExceeded(CredentialsError):
    """Too many hashes already in flight. Maps to 503 with a Retry-After."""


class InvalidCredentials(CredentialsError):
    """Wrong password, or no such account. Deliberately one exception for both."""


class InvalidToken(CredentialsError):
    """A token that does not verify: forged, expired, or for someone else."""


# Built ONCE, at import. `PasswordHasher.from_parameters` rather than
# `PasswordHasher(params)` -- the constructor takes `time_cost` first and
# positional `Parameters` raises `TypeError: 'time_cost' must be a int`.
_HASHER = PasswordHasher.from_parameters(settings.argon2_params)

# **Try-acquire, never block.** Handlers here are sync, so FastAPI runs them in
# anyio's threadpool; a semaphore that WAITED would park threads from that pool
# for the duration of a login flood and take job submission and the UI down with
# it. Refusing logins under load is a much smaller failure than refusing
# everything, so this converts saturation into a fast 503 on one route.
#
# What it bounds is concurrent MEMORY: each hash holds `argon2_params.memory_cost`
# for as long as it runs, so the product of these two is the real figure --
# 4 x 64 MiB today. `rate_limit` in migration 0009 bounds attempts over time and
# cannot bound this: requests arriving in the same millisecond all allocate
# before any window has closed.
_HASH_SLOTS = threading.Semaphore(settings.max_concurrent_hashes)

# A real argon2id hash of a value nobody knows, verified against when the
# account does not exist. Without it `verify_password` would return early on an
# unknown address and answer in microseconds where a known one takes ~100ms,
# which turns the login route into an account enumeration oracle.
#
# Computed at import so the cost is paid once rather than per miss -- and so the
# miss path and the hit path do the same work.
_DUMMY_HASH = _HASHER.hash(secrets.token_hex(32))

# Every token this platform mints carries both, and every token it accepts is
# checked against both. `auth.access_identity` records why the audience matters
# for Cloudflare -- a missing AUD there would mean "accepting a valid token
# issued for ANY application in the account" -- and the same reasoning applies to
# tokens we sign ourselves the moment this key signs anything else.
_ALGORITHM = "HS256"

# A key id in the header from the first token, though there is only one key.
# Rotation without it means every token issued before the change is unverifiable
# the instant the key is replaced; with it, a verifier can hold both keys and
# retire the old one when the last token carrying it has expired. `_signing_key`
# in auth.py is the same mechanism seen from the verifying side.
_KID = "v1"


def _require_signing_key() -> str:
    """The signing key, or a refusal.

    **An empty key is not an invalid one**, which is the whole reason this
    exists. `jwt.encode(payload, "")` succeeds and `jwt.decode(token, "")`
    verifies it, so an unset JWT_SIGNING_KEY does not fail -- it silently lets
    anyone who guesses that it is unset mint any `sub` they like. Measured, not
    assumed.

    Called by BOTH `mint_access_token` and `decode_access_token`. Guarding only
    the minting side would leave a service that refuses to issue tokens and
    cheerfully accepts forged ones, which is the worse half to lose.

    Refusing beats defaulting: a misconfigured deployment must not be an open
    one. `auth.authenticated_worker` makes the same argument for the worker
    channel, where an unknown credential is refused rather than waved through.
    """
    if not settings.jwt_signing_key:
        raise CredentialsUnconfigured(
            "JWT_SIGNING_KEY is unset; refusing to sign or verify with an "
            "empty key"
        )
    return settings.jwt_signing_key


def _require_issuer_and_audience() -> tuple[str, str]:
    """The issuer and audience, or a refusal. Called by both sides, like the key.

    **An empty audience is not a permissive one -- it is a silent outage**, and
    that is the opposite failure from the signing key above, which is why this
    check is separate rather than folded in. `jwt.encode` writes `aud: ""`
    happily; `jwt.decode` then raises `MissingRequiredClaimError: Token is
    missing the "aud" claim`, because PyJWT treats a falsy `aud` as absent.
    Measured, not assumed.

    So an unset `JWT_AUDIENCE` produces a deployment where login returns 204,
    sets its cookies, and every subsequent request is anonymous -- the token was
    minted and is unverifiable. Nothing logs a reason, because from the reading
    side it is simply an invalid token. Refusing to MINT is what turns that into
    one legible 503 at the first login instead.

    Both values default to empty (`config.Settings`), so this fires on a
    deployment that set the signing key and stopped -- which is the likely
    mistake, the key being the one that sounds security-critical.
    """
    if not settings.jwt_issuer or not settings.jwt_audience:
        raise CredentialsUnconfigured(
            "JWT_ISSUER and JWT_AUDIENCE must both be set; an empty audience "
            "mints tokens that can never be verified"
        )
    return settings.jwt_issuer, settings.jwt_audience


# --- passwords --------------------------------------------------------------


def hash_password(password: str) -> str:
    """An argon2id hash of `password`, at the configured cost.

    The cost parameters are encoded into the returned string, so raising them
    later is a rehash-on-next-login rather than a migration -- see
    `needs_rehash`.
    """
    with _hash_slot():
        return _HASHER.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    """Whether `password` matches, in the same time whether the account exists.

    **`None` means no such account, and is handled rather than short-circuited.**
    That is the point of the signature: the caller looks up the credentials row,
    passes whatever it found, and this does the same amount of work either way.
    An early `return False` on a miss is what makes a login route answer "no
    such user" in microseconds and "wrong password" in ~100ms, which is an
    enumeration oracle that no amount of identical error text hides.

    Returns a bool rather than raising, because "wrong password" is an expected
    outcome of a working system and the caller has to count it against a lockout
    either way.
    """
    with _hash_slot():
        try:
            _HASHER.verify(stored_hash if stored_hash is not None else _DUMMY_HASH,
                           password)
        except VerifyMismatchError:
            return False
        except InvalidHashError:
            # A stored hash that argon2 cannot parse is a CORRUPT ROW, not a
            # wrong password. Returning False here would let a damaged record
            # present as an ordinary failed login and never be noticed.
            raise
        except VerificationError:
            return False

    # A miss against the dummy that somehow verified would mean the caller had
    # guessed 32 bytes of `secrets` output; treat it as the failure it is.
    return stored_hash is not None


def needs_rehash(stored_hash: str) -> bool:
    """Whether this hash was made at a cost below the current setting.

    Call it after a SUCCESSFUL verify and rehash immediately -- that is the one
    moment the plaintext is in hand. Deferring it to "next login" means storing
    a flag and waiting for a login that may never come, while the account stays
    at the old cost.
    """
    return _HASHER.check_needs_rehash(stored_hash)


class _hash_slot:
    """Hold one of the concurrent-hash slots, or refuse at once.

    A context manager rather than a decorator so the acquire and release bracket
    exactly the argon2 call and nothing else -- holding a slot across a database
    round trip would make the cap bound the wrong thing.
    """

    def __enter__(self) -> None:
        if not _HASH_SLOTS.acquire(blocking=False):
            raise HashCapacityExceeded(
                f"all {settings.max_concurrent_hashes} hashing slots are in use"
            )

    def __exit__(self, *exc) -> None:
        _HASH_SLOTS.release()


# --- access tokens ----------------------------------------------------------


def mint_access_token(subject: str) -> str:
    """A short-lived signed assertion that `subject` is the caller.

    `subject` is a TENANT ID -- what `auth.resolve_tenant` returns -- and never
    an address. Since migration 0009 the address is an attribute of an identity
    rather than a key, and putting one in a token would mean a credential that
    stops being valid when someone changes their email, plus a copy of personal
    data in every request log that captures an Authorization header.

    Not revocable, by design: verification is a signature check with no database
    round trip, which is what makes it cheap enough to do on every request. The
    revocable half is the refresh token, and the access token's short TTL is the
    window a stolen one stays useful.
    """
    now = datetime.now(UTC)
    issuer, audience = _require_issuer_and_audience()
    return jwt.encode(
        {
            "sub": subject,
            "iss": issuer,
            "aud": audience,
            "iat": now,
            "exp": now + timedelta(minutes=settings.access_token_ttl_minutes),
        },
        _require_signing_key(),
        algorithm=_ALGORITHM,
        headers={"kid": _KID},
    )


def decode_access_token(token: str) -> dict:
    """The claims of a token this platform signed, or `InvalidToken`.

    **`algorithms` is pinned to a list**, which is the difference between a
    verifier and a formality: without it a token whose header says `alg: none`
    is accepted unverified, and one saying `alg: HS256` against an RSA public
    key turns a public value into a signing key. `auth.access_identity` pins it
    for the same reason.

    Issuer and audience are checked here rather than by the caller, so a route
    cannot forget. What that buys: the moment this key signs anything else --
    another service, a different token type -- those tokens do not silently
    become valid sessions here.

    The reason a token failed is logged by the caller and NOT returned, matching
    `access_identity`: which check failed is a hint to whoever is probing.
    """
    try:
        issuer, audience = _require_issuer_and_audience()
        return jwt.decode(
            token,
            _require_signing_key(),
            algorithms=[_ALGORITHM],
            issuer=issuer,
            audience=audience,
        )
    except CredentialsUnconfigured:
        raise
    except Exception as exc:
        raise InvalidToken(str(exc)) from exc


# --- refresh tokens ---------------------------------------------------------


def new_refresh_token() -> tuple[str, str]:
    """A fresh refresh token: `(give this out, store this)`.

    **Opaque random bytes rather than a JWT**, and that is a deliberate
    narrowing. A refresh token is looked up in the database on every use, so a
    signature would buy nothing -- and if both token types were JWTs under one
    key, a refresh token presented as an access token would verify, leaving a
    `typ` claim check as the only thing standing between the two. Different
    SHAPES cannot be confused; a claim someone forgets to check can be.

    Returned as a pair because the plaintext exists exactly once, here. Nothing
    stores it, and the only copy goes to the client.
    """
    token = secrets.token_urlsafe(32)
    return token, hash_refresh_token(token)


def hash_refresh_token(token: str) -> str:
    """The stored form of a refresh token.

    **sha256, not argon2, and that is not a shortcut.** A slow hash exists to
    make guessing a LOW-ENTROPY secret expensive; `secrets.token_urlsafe(32)` is
    256 bits of entropy, so there is nothing to guess and the cost would buy
    nothing. Using argon2 here would mean 64 MiB and ~100ms on every refresh --
    a real availability cost for no security gain.

    Hashed at all for the same reason a password is: the value is a bearer
    credential, so a database disclosure -- a dump, a backup, a read-only
    injection -- would otherwise hand over every live session.
    """
    return hashlib.sha256(token.encode()).hexdigest()

# --- the second factor ------------------------------------------------------
#
# TOTP rather than a code over Telegram, although signup already proves a
# Telegram account. A messaging channel is a delivery mechanism someone else can
# take over, and it puts an outbound network call on the login path; TOTP needs
# no provider, no per-message cost and nothing reachable. The Telegram link is a
# signup gate, not an authentication factor.


class TotpReplayed(CredentialsError):
    """A correct code, already spent.

    Correct and refused, which is the distinction worth keeping: the code
    verified, so this is not a wrong-code failure and should not be counted as
    one against a lockout.
    """


def new_totp_secret() -> str:
    """A fresh base32 secret, not yet enrolled.

    Generated here rather than in the route so the only place a secret comes
    into existence is this module, alongside everything else that mints a
    credential.
    """
    import pyotp

    return pyotp.random_base32()


def totp_uri(secret: str, label: str) -> str:
    """The `otpauth://` URI an authenticator app scans.

    The issuer is what the app shows in its list, so it has to be recognisable:
    a row reading "sandbox" tells nobody which of their accounts it protects.
    """
    import pyotp

    return pyotp.TOTP(secret).provisioning_uri(
        name=label, issuer_name="DRAKVUF Sandbox"
    )


def verify_totp(secret: str, code: str, last_step: int | None) -> int:
    """The time-step a valid code belongs to, or raise.

    **`valid_window=1` accepts the neighbouring steps**, which is clock skew
    tolerance rather than looseness: a phone a few seconds out would otherwise
    fail every time, and users respond to that by disabling the second factor.
    It widens the window to ~90 seconds, and the replay check below is what
    stops that being three chances at the same code.

    `last_step` is the highest step already accepted for this account. Refusing
    anything at or below it is what makes a code single-use -- TOTP has no such
    property on its own, so a code observed in transit stays spendable for the
    rest of its window without this.
    """
    import pyotp

    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        raise InvalidCredentials("incorrect code")

    # Recomputed rather than returned by `verify`, which only answers yes or no.
    # The candidate steps are the same ones `valid_window` admitted.
    import time as _time

    now_step = int(_time.time()) // totp.interval
    for step in (now_step, now_step - 1, now_step + 1):
        if totp.verify(code, for_time=step * totp.interval, valid_window=0):
            if last_step is not None and step <= last_step:
                raise TotpReplayed("that code has already been used")
            return step

    raise InvalidCredentials("incorrect code")


# How many are issued at once. Ten is enough that spending one is unremarkable
# and running out is a deliberate act, and few enough that a user will actually
# store them somewhere rather than skipping the step.
RECOVERY_CODE_COUNT = 10


def new_recovery_codes() -> tuple[list[str], list[str]]:
    """A fresh set: `(show these once, store these)`.

    Grouped with hyphens because these are transcribed by a human under some
    pressure -- from a printout, at the moment their phone is gone -- and an
    unbroken string of characters is where that goes wrong.

    **Hashed with sha256, not argon2**, for the reason `hash_refresh_token`
    gives: 80 bits of `secrets` output has nothing to brute-force, and a slow
    hash would only add latency to a login someone is already having a bad day
    during.
    """
    codes = [
        "-".join(secrets.token_hex(2) for _ in range(3))
        for _ in range(RECOVERY_CODE_COUNT)
    ]
    return codes, [hash_recovery_code(c) for c in codes]


def hash_recovery_code(code: str) -> str:
    """The stored form. Case and surrounding space are normalised away.

    A code read off paper arrives with whatever spacing and capitalisation the
    reader gave it, and refusing a correct code because it was typed in capitals
    is the kind of failure that sends someone to an operator instead.
    """
    return hashlib.sha256(code.strip().lower().encode()).hexdigest()
