"""Signup and password reset through Telegram (DRAFT-061 decisions 1 and 2).

**No network.** `httpx` is patched at the two call sites, so what is under test
is the platform's half: which rows get created, what a code can and cannot be
redeemed for, and what each route discloses. The Bot API's own behaviour is not
this suite's to assert.
"""

from __future__ import annotations

import dataclasses
import uuid

import pytest
from conftest import identity_id

from sandbox_platform import credentials, telegram, throttle
from sandbox_platform.config import settings
from sandbox_platform.routers import auth as auth_router

CSRF = {"X-Sandbox-Request": "1"}
PASSWORD = "a sufficiently long password"


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    for module in (credentials, throttle, telegram):
        monkeypatch.setattr(
            module, "settings",
            dataclasses.replace(
                settings,
                jwt_signing_key="test-key",
                jwt_issuer="sandbox.evilbootloader.com",
                jwt_audience="sandbox-platform",
                telegram_bot_token="test-bot-token",
                attempts_per_window=50,
                registration_open=True,
            ),
        )
    monkeypatch.setattr(
        auth_router, "settings",
        dataclasses.replace(settings,
                            trusted_client_ip_header="X-Test-Client-IP",
                            registration_open=True),
    )


@pytest.fixture
def sent(monkeypatch):
    """Capture what would have been delivered, instead of delivering it."""
    outbox: list[tuple[int, str]] = []
    monkeypatch.setattr(telegram, "send_message",
                        lambda chat_id, text: outbox.append((chat_id, text)))
    return outbox


def _tg_id():
    return int(uuid.uuid4().int % 10**9)


def _addr():
    return f"signup-{uuid.uuid4().hex[:12]}@example.test"


def _post(client, path, body, ip="203.0.113.10"):
    return client.post(f"/api/v1/auth/{path}",
                       headers={**CSRF, "X-Test-Client-IP": ip}, json=body)


# --- /start -----------------------------------------------------------------


def test_start_creates_an_identity_that_cannot_log_in(conn, sent):
    """**The gate is that this identity is worthless until signup.**

    No address, no password, and crucially no `tenants` row -- so the opening
    grant of analysis seconds has not been handed out. Pressing /start must not
    be a way to acquire anything.
    """
    tg = _tg_id()
    telegram.handle_update(conn, {"message": {"from": {"id": tg},
                                              "text": "/start"}})

    with conn.cursor() as cur:
        cur.execute(
            "SELECT i.email, c.owner, t.owner FROM identities i"
            "  LEFT JOIN tenant_credentials c ON c.owner = i.id"
            "  LEFT JOIN tenants t ON t.owner = i.id"
            " WHERE i.telegram_user_id = %s",
            (tg,),
        )
        email, creds, tenant = cur.fetchone()

    assert email is None
    assert creds is None
    assert tenant is None, "the grant was handed out before signup"


def test_start_replies_with_a_code(conn, sent):
    tg = _tg_id()
    telegram.handle_update(conn, {"message": {"from": {"id": tg},
                                              "text": "/start"}})
    assert len(sent) == 1
    chat_id, text = sent[0]
    assert chat_id == tg
    assert "signup code" in text


def test_pressing_start_twice_does_not_make_a_second_account(conn, sent):
    """The obvious thing to do when a code expires is press it again.

    `identities.telegram_user_id UNIQUE` is what makes that safe; without the
    upsert it would be an integrity error on the second press.
    """
    tg = _tg_id()
    for _ in range(2):
        telegram.handle_update(conn, {"message": {"from": {"id": tg},
                                                  "text": "/start"}})

    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM identities WHERE telegram_user_id = %s",
                    (tg,))
        assert cur.fetchone()[0] == 1
    assert len(sent) == 2, "the second press should still yield a code"


def test_anything_that_is_not_start_is_ignored(conn, sent):
    """A bot that answers arbitrary text is a bot that can be made to send
    messages. This one exists to deliver codes to people who asked."""
    telegram.handle_update(conn, {"message": {"from": {"id": _tg_id()},
                                              "text": "hello?"}})
    assert sent == []


# --- codes ------------------------------------------------------------------


def test_a_code_is_stored_only_as_a_hash(conn):
    owner = identity_id(conn.cursor(), _addr())
    code = telegram.mint_code(conn, owner, "telegram_linking")

    with conn.cursor() as cur:
        cur.execute("SELECT token_hash FROM verification_tokens WHERE owner = %s",
                    (owner,))
        assert cur.fetchone()[0] != code


def test_a_code_can_be_redeemed_once(conn):
    owner = identity_id(conn.cursor(), _addr())
    code = telegram.mint_code(conn, owner, "telegram_linking")

    assert telegram.redeem_code(conn, code, "telegram_linking") == owner
    assert telegram.redeem_code(conn, code, "telegram_linking") is None


def test_a_linking_code_cannot_be_redeemed_as_a_password_reset(conn):
    """**Purposes are not interchangeable.**

    A code minted to prove someone owns a Telegram account must not also set a
    password. Matching on purpose as well as the hash is what keeps them apart,
    and the CHECK in 0009 keeps the set of purposes closed.
    """
    owner = identity_id(conn.cursor(), _addr())
    code = telegram.mint_code(conn, owner, "telegram_linking")

    assert telegram.redeem_code(conn, code, "password_reset") is None
    assert telegram.redeem_code(conn, code, "telegram_linking") == owner


def test_an_expired_code_is_refused(conn):
    owner = identity_id(conn.cursor(), _addr())
    code = telegram.mint_code(conn, owner, "telegram_linking")
    conn.execute("UPDATE verification_tokens SET expires_at = now() -"
                 " interval '1 second' WHERE owner = %s", (owner,))

    assert telegram.redeem_code(conn, code, "telegram_linking") is None


# --- signup -----------------------------------------------------------------


def _start(client, conn, sent):
    """Press /start and return (telegram id, code)."""
    tg = _tg_id()
    telegram.handle_update(conn, {"message": {"from": {"id": tg},
                                              "text": "/start"}})
    return tg, sent[-1][1].split("\n")[2].strip()


def test_signup_with_a_valid_code_creates_an_account_that_can_log_in(
        client, conn, sent):
    _, code = _start(client, conn, sent)
    email = _addr()

    r = _post(client, "signup", {"email": email, "password": PASSWORD,
                                 "code": code})
    assert r.status_code == 204, r.text

    login = _post(client, "login", {"email": email, "password": PASSWORD})
    assert login.status_code == 204, login.text
    assert "sandbox_access" in login.cookies


def test_signup_grants_the_opening_balance(client, conn, sent):
    _, code = _start(client, conn, sent)
    email = _addr()
    _post(client, "signup", {"email": email, "password": PASSWORD, "code": code})

    with conn.cursor() as cur:
        cur.execute(
            "SELECT t.balance_seconds FROM tenants t JOIN identities i"
            " ON i.id = t.owner WHERE lower(i.email) = %s", (email,))
        row = cur.fetchone()

    assert row is not None, "no tenant row: the grant never happened"
    assert row[0] > 0


def test_signup_without_a_code_is_refused(client, conn):
    """**The whole gate.** Without this, signup is an hour of free
    malware-analysis compute for anyone who can make an email address."""
    r = _post(client, "signup", {"email": _addr(), "password": PASSWORD,
                                 "code": "not-a-real-code"})
    assert r.status_code == 400, r.text


def test_a_code_cannot_be_used_twice(client, conn, sent):
    _, code = _start(client, conn, sent)
    first = _post(client, "signup", {"email": _addr(), "password": PASSWORD,
                                     "code": code})
    second = _post(client, "signup", {"email": _addr(), "password": PASSWORD,
                                      "code": code})

    assert first.status_code == 204
    assert second.status_code == 400, "one code, two accounts"


def test_an_address_already_in_use_is_refused_like_a_bad_code(
        client, conn, sent):
    """One refusal for both, so signup cannot be used to test whether an
    address is registered."""
    _, first_code = _start(client, conn, sent)
    email = _addr()
    _post(client, "signup", {"email": email, "password": PASSWORD,
                             "code": first_code})

    _, second_code = _start(client, conn, sent)
    taken = _post(client, "signup", {"email": email, "password": PASSWORD,
                                     "code": second_code})
    bad = _post(client, "signup", {"email": _addr(), "password": PASSWORD,
                                   "code": "nonsense"})

    assert taken.status_code == bad.status_code == 400
    assert taken.json() == bad.json()


def test_a_short_password_is_refused(client, conn, sent):
    _, code = _start(client, conn, sent)
    r = _post(client, "signup", {"email": _addr(), "password": "short",
                                 "code": code})
    assert r.status_code == 422


# --- password reset ---------------------------------------------------------


def _signed_up(client, conn, sent):
    tg, code = _start(client, conn, sent)
    email = _addr()
    _post(client, "signup", {"email": email, "password": PASSWORD, "code": code})
    return tg, email


def test_a_reset_code_is_delivered_to_the_linked_account(client, conn, sent):
    tg, email = _signed_up(client, conn, sent)
    sent.clear()

    r = _post(client, "reset/request", {"email": email})

    assert r.status_code == 204
    assert len(sent) == 1
    assert sent[0][0] == tg, "delivered to a different Telegram account"


def test_requesting_a_reset_for_an_unknown_address_says_nothing(
        client, conn, sent):
    """**Always 204.** A route that says "no such account" is an enumeration
    oracle needing no password guessing at all, and would undo what the login
    path pays a full argon2 hash to withhold."""
    known = _signed_up(client, conn, sent)[1]
    sent.clear()

    hit = _post(client, "reset/request", {"email": known})
    miss = _post(client, "reset/request", {"email": _addr()})

    assert hit.status_code == miss.status_code == 204
    assert hit.content == miss.content
    assert len(sent) == 1, "a message went out for an address with no account"


def test_a_reset_code_changes_the_password(client, conn, sent):
    _, email = _signed_up(client, conn, sent)
    sent.clear()
    _post(client, "reset/request", {"email": email})
    code = sent[-1][1].split("\n")[2].strip()

    new = "an entirely different password"
    r = _post(client, "reset/confirm", {"code": code, "password": new})
    assert r.status_code == 204, r.text

    assert _post(client, "login", {"email": email,
                                   "password": new}).status_code == 204
    assert _post(client, "login", {"email": email,
                                   "password": PASSWORD}).status_code == 401


def test_a_reset_ends_every_existing_session(client, conn, sent):
    """**The point of the reset, not a courtesy.**

    The usual reason for resetting is believing someone else has the password.
    Leaving their sessions running means the reset changed nothing for the
    person who asked for it.
    """
    _, email = _signed_up(client, conn, sent)
    refresh = _post(client, "login", {"email": email,
                                      "password": PASSWORD}).cookies["sandbox_refresh"]
    sent.clear()
    _post(client, "reset/request", {"email": email})
    code = sent[-1][1].split("\n")[2].strip()

    _post(client, "reset/confirm", {"code": code, "password": "brand new one here"})

    r = client.post("/api/v1/auth/refresh", headers=CSRF,
                    cookies={"sandbox_refresh": refresh})
    assert r.status_code == 401, "a session survived the password reset"


def test_a_reset_clears_a_lockout(client, conn, sent):
    """Someone locked out is exactly who needs to reset, so a reset that leaves
    the lockout in place has helped nobody."""
    _, email = _signed_up(client, conn, sent)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE tenant_credentials SET locked_until = now() +"
            " interval '1 hour', failed_attempts = 9"
            " WHERE owner = (SELECT id FROM identities WHERE lower(email) = %s)",
            (email,),
        )
    sent.clear()
    _post(client, "reset/request", {"email": email})
    code = sent[-1][1].split("\n")[2].strip()

    new = "yet another long password"
    _post(client, "reset/confirm", {"code": code, "password": new})

    assert _post(client, "login", {"email": email,
                                   "password": new}).status_code == 204


def test_confirming_with_a_bad_code_is_refused(client, conn):
    r = _post(client, "reset/confirm", {"code": "nope", "password": PASSWORD})
    assert r.status_code == 400


# --- the poller -------------------------------------------------------------


def test_the_offset_advances_past_handled_updates(client, monkeypatch, conn, sent):
    """**The offset is how Telegram acknowledges a batch.**

    Without advancing it the same updates arrive forever, so every /start is
    answered again on every poll -- a loop that looks like it is working and is
    re-delivering one message indefinitely.
    """
    import httpx

    updates = {"result": [{"update_id": 41, "message": {"from": {"id": _tg_id()},
                                                        "text": "/start"}},
                          {"update_id": 42, "message": {"from": {"id": _tg_id()},
                                                        "text": "/start"}}]}
    monkeypatch.setattr(
        httpx, "get",
        lambda *a, **k: httpx.Response(200, json=updates,
                                       request=httpx.Request("GET", "http://x")),
    )
    offset, handled = telegram.poll_once(0)

    assert handled == 2
    assert offset == 43


def test_one_bad_update_does_not_wedge_the_batch(client, monkeypatch, conn, sent):
    """A malformed update must not be redelivered forever.

    If the offset stopped advancing on a failure, the channel would wedge on a
    single bad message and no signup code would ever be delivered again.
    """
    import httpx

    updates = {"result": [{"update_id": 7},                      # no message
                          {"update_id": 8, "message": {"from": {"id": _tg_id()},
                                                       "text": "/start"}}]}
    monkeypatch.setattr(
        httpx, "get",
        lambda *a, **k: httpx.Response(200, json=updates,
                                       request=httpx.Request("GET", "http://x")),
    )
    offset, _ = telegram.poll_once(0)

    assert offset == 9
    assert len(sent) == 1


def test_polling_without_a_token_refuses_rather_than_calling_out(monkeypatch):
    """Empty is not a usable token -- the Bot API would answer 401 to every
    call, so the failure would read as "Telegram is down" rather than "this was
    never configured"."""
    monkeypatch.setattr(telegram, "settings",
                        dataclasses.replace(settings, telegram_bot_token=""))
    with pytest.raises(credentials.CredentialsUnconfigured):
        telegram.poll_once(0)

# --- the registration flag --------------------------------------------------


def _closed(monkeypatch):
    """Close registration in both places that read the flag."""
    for module in (auth_router, telegram):
        monkeypatch.setattr(
            module, "settings",
            dataclasses.replace(getattr(module, "settings"),
                                registration_open=False),
        )


def test_signup_is_refused_when_registration_is_closed(client, conn, sent,
                                                       monkeypatch):
    """**Off by default**, like `console_enabled`, because a flag that opens a
    capability must not be opened by forgetting to set it.

    What it gates is the opening grant: `tenants` defaults to an hour of
    prepaid analysis seconds, so an open route is free compute for anyone with
    an email address and a Telegram account.
    """
    _, code = _start(client, conn, sent)
    _closed(monkeypatch)

    r = _post(client, "signup", {"email": _addr(), "password": PASSWORD,
                                 "code": code})

    assert r.status_code == 403, r.text
    assert "closed" in r.json()["detail"]


def test_start_creates_nothing_when_registration_is_closed(conn, sent,
                                                           monkeypatch):
    """Minting a code nobody can redeem would be a row per Telegram account
    that ever messages the bot, growing a table for a route that refuses."""
    _closed(monkeypatch)
    tg = _tg_id()

    telegram.handle_update(conn, {"message": {"from": {"id": tg},
                                              "text": "/start"}})

    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM identities WHERE telegram_user_id = %s",
                    (tg,))
        assert cur.fetchone()[0] == 0
    assert len(sent) == 1
    assert "closed" in sent[0][1], "the sender was not told why"


def test_a_closed_deployment_still_resets_passwords(client, conn, sent,
                                                    monkeypatch):
    """Closing registration must not strand the accounts that already exist --
    `create_user.py` makes them, and reset is how they recover."""
    _, email = _signed_up(client, conn, sent)
    _closed(monkeypatch)
    sent.clear()

    assert _post(client, "reset/request", {"email": email}).status_code == 204
    assert len(sent) == 1, "reset stopped working on a closed deployment"


# --- the address is claimed, never proved (DRAFT-061, security review) -------
#
# **Signup takes an address entirely on trust.** A Telegram code proves control
# of a Telegram account and says nothing whatever about an address, and there is
# no confirmation loop anywhere in this platform -- nothing is ever sent to
# `identities.email`. That is a deliberate design and it is safe only because of
# what these tests pin: a claimed address must not be a way to become someone
# else.
#
# The hole this closes, found in review before it shipped: while
# `resolve_tenant` resolved on `lower(email)`, claiming an address no identity
# held yet meant the next Cloudflare Access assertion for it landed on the
# CLAIMANT's row -- with the claimant's password on it. One request, and that
# tenant's jobs, prepaid balance and object prefix changed hands.


def test_a_claimed_address_does_not_capture_an_access_identity(
        client, conn, sent):
    """**The pre-hijacking case, and the reason `access_subject` exists.**

    The attacker signs up naming an address they do not hold. When the real
    holder arrives through Access, they must land on their OWN identity -- not
    on the row carrying the attacker's password.
    """
    _, code = _start(client, conn, sent)
    victim = _addr()

    assert _post(client, "signup", {"email": victim, "password": PASSWORD,
                                    "code": code}).status_code == 204

    claimed = conn.execute(
        "SELECT id FROM identities WHERE lower(email) = lower(%s)", (victim,)
    ).fetchone()[0]

    from sandbox_platform import auth
    resolved = auth.resolve_tenant(victim)

    assert resolved != str(claimed), (
        "an Access assertion resolved to a self-claimed address: whoever "
        "signed up with it holds that tenant's jobs and balance"
    )
    # And the identity it DID reach is one no password can open, because signup
    # never wrote `access_subject` and login never reads it.
    assert _post(client, "login", {"email": victim,
                                   "password": PASSWORD}).status_code == 204, \
        "the attacker's own account stopped working, which is not the fix"
    owner_of_session = conn.execute(
        "SELECT owner FROM tenant_credentials WHERE owner = %s", (resolved,)
    ).fetchone()
    assert owner_of_session is None, (
        "the identity an Access caller resolved to carries a password someone "
        "else chose"
    )


def test_signup_cannot_claim_a_service_token_identity(client, conn, sent):
    """`access_identity` spells a service token `service:<common_name>`.

    That is not an address, so it needs no victim address to guess -- it was the
    cheaper half of the same attack. Refused at the boundary now, which is why
    this asserts a 422 rather than merely a failure to capture anything.
    """
    _, code = _start(client, conn, sent)

    r = _post(client, "signup", {"email": "service:submit-cli",
                                 "password": PASSWORD, "code": code})
    assert r.status_code == 422, r.text
    assert conn.execute(
        "SELECT count(*) FROM identities WHERE email = %s",
        ("service:submit-cli",)).fetchone()[0] == 0


def test_signup_refuses_an_address_that_is_not_one(client, conn, sent):
    """Display integrity rather than the join key, now that the two are split.

    `owner_email` is rendered in the jobs list, so a bare word would sit in the
    Owner column looking like infrastructure or another account.
    """
    _, code = _start(client, conn, sent)

    r = _post(client, "signup", {"email": "administrator",
                                 "password": PASSWORD, "code": code})
    assert r.status_code == 422, r.text


def test_an_access_identity_is_not_claimable_afterwards(client, conn, sent):
    """The other ordering: the provider got there first.

    Resolution creates the row with `access_subject` set and `email` NULL, so
    the address is still free in the LOGIN keyspace -- someone may sign up with
    it and get their own separate account. What they must not get is the
    identity that already holds the Access caller's jobs.
    """
    from sandbox_platform import auth

    existing = _addr()
    theirs = auth.resolve_tenant(existing)

    _, code = _start(client, conn, sent)
    assert _post(client, "signup", {"email": existing, "password": PASSWORD,
                                    "code": code}).status_code == 204

    assert auth.resolve_tenant(existing) == theirs, \
        "a signup moved an established Access identity"
    signed_up = conn.execute(
        "SELECT id FROM identities WHERE lower(email) = lower(%s)", (existing,)
    ).fetchone()[0]
    assert str(signed_up) != theirs
