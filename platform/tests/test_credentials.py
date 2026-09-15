"""The credentials this platform issues itself (DRAFT-061 decision 3).

**No database in this module, by design.** `sandbox_platform.credentials` is
pure -- hashing, signing, random generation -- and keeping its tests free of a
connection is what makes that worth having. The transactional half lives in
`test_sessions.py`.

Modelled on `test_access_jwt.py`, which forges tokens against the real verifier
rather than mocking it. The same approach applies here and matters more: this is
the first code in the project that MINTS credentials, so a test that trusts the
minting side to describe itself proves nothing.
"""

from __future__ import annotations

import dataclasses
import time

import jwt
import pytest
from argon2.exceptions import InvalidHashError

from sandbox_platform import credentials
from sandbox_platform.config import settings

KEY = "test-signing-key"
ISS = "sandbox.evilbootloader.com"
AUD = "sandbox-platform"


def configure(monkeypatch, **overrides):
    """Swap credentials.py's settings for a copy with these fields changed.

    `Settings` is frozen, so the field cannot be patched on the instance --
    `test_access_jwt.configure` solves it the same way and this mirrors it
    deliberately rather than inventing a second idiom for one problem.
    """
    monkeypatch.setattr(credentials, "settings",
                        dataclasses.replace(settings, **overrides))


@pytest.fixture(autouse=True)
def signing_key(monkeypatch):
    """A usable key for every test here, since `config` read the environment at
    import and the deployment's key is not in it."""
    configure(monkeypatch, jwt_signing_key=KEY, jwt_issuer=ISS, jwt_audience=AUD)


# --- passwords --------------------------------------------------------------


def test_a_password_verifies_against_its_own_hash():
    stored = credentials.hash_password("correct horse battery staple")
    assert credentials.verify_password(stored, "correct horse battery staple")


def test_a_wrong_password_does_not():
    stored = credentials.hash_password("correct horse battery staple")
    assert not credentials.verify_password(stored, "Correct horse battery staple")


def test_the_same_password_hashes_differently_every_time():
    """Salting, observed rather than assumed.

    Two identical passwords sharing a hash would mean a stolen database tells an
    attacker which accounts to attack once and reuse everywhere.
    """
    a = credentials.hash_password("same")
    b = credentials.hash_password("same")
    assert a != b
    assert credentials.verify_password(a, "same")
    assert credentials.verify_password(b, "same")


def test_an_unknown_account_is_refused_without_short_circuiting():
    """`None` means no such account, and must still do the work.

    The return value is the easy half. What this actually guards is in the next
    test -- that the miss costs the same as a hit.
    """
    assert not credentials.verify_password(None, "anything at all")


def test_an_unknown_account_costs_the_same_as_a_wrong_password():
    """**The account enumeration oracle**, and the reason `_DUMMY_HASH` exists.

    An early `return False` for a missing account answers in microseconds while
    a real one takes ~100ms of argon2. That difference is measurable over a
    network and identifies which addresses are registered, no matter how
    identical the error text is.

    The bound is deliberately loose -- a factor of three, against a ~100ms
    operation -- because this asserts "the same order of magnitude" and must not
    fail on a loaded CI box. A short-circuit would be a factor of a thousand.
    """
    stored = credentials.hash_password("a real password")

    t0 = time.perf_counter()
    credentials.verify_password(stored, "wrong")
    known = time.perf_counter() - t0

    t0 = time.perf_counter()
    credentials.verify_password(None, "wrong")
    unknown = time.perf_counter() - t0

    assert unknown > known / 3, (
        f"miss took {unknown:.4f}s against {known:.4f}s for a hit -- "
        "the unknown-account path is short-circuiting"
    )


def test_a_corrupt_stored_hash_is_not_reported_as_a_wrong_password():
    """A damaged row must be loud.

    Returning False here would let a corrupted record present as an ordinary
    failed login, and the account would simply stop working with nothing to say
    why.
    """
    with pytest.raises(InvalidHashError):
        credentials.verify_password("not-an-argon2-hash", "anything")


def test_a_hash_at_the_current_cost_does_not_need_rehashing():
    assert not credentials.needs_rehash(credentials.hash_password("x"))


def test_a_hash_made_at_a_lower_cost_does():
    """What makes a parameter raise reach existing accounts.

    Without this check a raised cost protects only accounts created afterwards,
    and the oldest passwords -- the ones most likely to be weak and reused --
    keep the weakest hashes indefinitely.
    """
    from argon2 import PasswordHasher

    weaker = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    assert credentials.needs_rehash(weaker.hash("x"))


def test_hashing_refuses_rather_than_queueing_when_saturated(monkeypatch):
    """**Refusing beats waiting**, and the reason is availability.

    Handlers run in anyio's threadpool. A semaphore that BLOCKED would park
    those threads for the duration of a login flood, so job submission and the
    UI would stop responding too -- converting a bounded memory problem into an
    unbounded one. Refusing keeps the failure on the route that caused it.
    """
    import threading

    monkeypatch.setattr(credentials, "_HASH_SLOTS", threading.Semaphore(0))
    with pytest.raises(credentials.HashCapacityExceeded):
        credentials.hash_password("anything")


# --- access tokens ----------------------------------------------------------


def test_a_minted_token_decodes_to_its_subject():
    token = credentials.mint_access_token("a-tenant-id")
    assert credentials.decode_access_token(token)["sub"] == "a-tenant-id"


def test_a_token_signed_with_another_key_is_refused():
    forged = jwt.encode(
        {"sub": "someone-else", "iss": ISS, "aud": AUD},
        "not-the-signing-key",
        algorithm="HS256",
    )
    with pytest.raises(credentials.InvalidToken):
        credentials.decode_access_token(forged)


def test_an_expired_token_is_refused(monkeypatch):
    configure(monkeypatch, jwt_signing_key=KEY, jwt_issuer=ISS,
              jwt_audience=AUD, access_token_ttl_minutes=-1)
    with pytest.raises(credentials.InvalidToken):
        credentials.decode_access_token(credentials.mint_access_token("x"))


def test_a_token_for_another_audience_is_refused():
    """Why `aud` is checked at all.

    The moment this signing key is used for anything else -- another service, a
    second token type -- tokens meant for that thing would otherwise be valid
    sessions here. `auth.access_identity` records the same reasoning for
    Cloudflare, where a missing AUD means accepting a token issued for any
    application in the account.
    """
    other = jwt.encode(
        {"sub": "x", "iss": ISS, "aud": "some-other-service"},
        KEY,
        algorithm="HS256",
    )
    with pytest.raises(credentials.InvalidToken):
        credentials.decode_access_token(other)


def test_a_token_from_another_issuer_is_refused():
    other = jwt.encode(
        {"sub": "x", "iss": "https://not-us.example", "aud": AUD},
        KEY,
        algorithm="HS256",
    )
    with pytest.raises(credentials.InvalidToken):
        credentials.decode_access_token(other)


def test_an_unsigned_token_is_refused():
    """`alg: none`, the oldest JWT attack there is.

    **Not the `algorithms=` pin that refuses this**, which is worth recording
    because it is the obvious assumption and it is wrong. Measured: adding
    `"none"` to the allowed list still refuses, because PyJWT raises
    `InvalidKeyError: When alg = "none", key value must be None` whenever a key
    is supplied. The library closes this one regardless of what we pass.

    Kept anyway -- it pins the OUTCOME rather than the mechanism, so it holds if
    a future library version ever makes the allowed list the only guard.
    `test_a_token_signed_with_another_algorithm_is_refused` is what actually
    exercises the pin.
    """
    unsigned = jwt.encode(
        {"sub": "admin", "iss": ISS, "aud": AUD},
        key="",
        algorithm="none",
    )
    with pytest.raises(credentials.InvalidToken):
        credentials.decode_access_token(unsigned)


def test_a_token_signed_with_another_algorithm_is_refused():
    """**This is the test that the `algorithms=` pin is load-bearing.**

    Written after mutation testing showed the `alg: none` case above survives
    widening the allowed list -- so that test, on its own, would have let the
    pin be deleted silently.

    A token is HS512 here, signed with the real key: everything about it is
    valid except the algorithm. Accepting it would mean the header chooses how
    the signature is checked, which is the door every algorithm-confusion attack
    walks through -- including the RS256-to-HS256 swap that turns a published
    public key into a signing key.
    """
    other_alg = jwt.encode(
        {"sub": "x", "iss": ISS, "aud": AUD}, KEY, algorithm="HS512"
    )
    with pytest.raises(credentials.InvalidToken):
        credentials.decode_access_token(other_alg)


def test_tokens_carry_a_key_id():
    """Present from the first token, with one key in existence.

    Rotation without a `kid` invalidates every token in circulation the instant
    the key changes; with one, a verifier can hold both and retire the old key
    when the last token carrying it expires.
    """
    header = jwt.get_unverified_header(credentials.mint_access_token("x"))
    assert header["kid"] == credentials._KID


def test_minting_refuses_when_the_signing_key_is_unset(monkeypatch):
    """**An empty key is a VALID HMAC key**, which is what makes this necessary.

    `jwt.encode(payload, "")` succeeds and `jwt.decode(token, "")` verifies it,
    so an unset JWT_SIGNING_KEY does not fail -- it lets anyone who guesses that
    it is unset mint any subject they like.
    """
    configure(monkeypatch, jwt_signing_key="")
    with pytest.raises(credentials.CredentialsUnconfigured):
        credentials.mint_access_token("x")


def test_verifying_refuses_when_the_signing_key_is_unset(monkeypatch):
    """The half that is easy to forget.

    Guarding only minting leaves a service that will not issue tokens and
    happily accepts forged ones -- which is the worse of the two to lose.
    """
    token = credentials.mint_access_token("x")
    configure(monkeypatch, jwt_signing_key="")
    with pytest.raises(credentials.CredentialsUnconfigured):
        credentials.decode_access_token(token)


# --- refresh tokens ---------------------------------------------------------


def test_a_refresh_token_is_opaque_and_not_a_jwt():
    """**Different shapes cannot be confused.**

    If refresh and access tokens were both JWTs under one key, a refresh token
    presented as an access token would verify, and only a `typ` claim check --
    something a route can forget -- would stand between them. This is that class
    of bug removed structurally rather than guarded against.
    """
    token, _ = credentials.new_refresh_token()
    with pytest.raises(credentials.InvalidToken):
        credentials.decode_access_token(token)


def test_a_refresh_token_is_stored_only_as_a_hash():
    token, stored = credentials.new_refresh_token()
    assert token not in stored
    assert stored == credentials.hash_refresh_token(token)
    assert len(stored) == 64          # sha256, hex


def test_refresh_tokens_do_not_repeat():
    assert len({credentials.new_refresh_token()[0] for _ in range(50)}) == 50