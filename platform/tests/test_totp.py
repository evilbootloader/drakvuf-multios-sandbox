"""The second factor (DRAFT-061 decision 3).

Enrolment, and the three things that make a second factor worth having: that a
generated secret is not yet live, that a code cannot be spent twice, and that a
stolen session alone cannot remove it.
"""

from __future__ import annotations

import dataclasses
import uuid

import pyotp
import pytest
from conftest import credentialed_identity_id

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
                attempts_per_window=50,
            ),
        )
    monkeypatch.setattr(
        auth_router, "settings",
        dataclasses.replace(settings, trusted_client_ip_header="X-Test-Client-IP"),
    )


@pytest.fixture
def account(conn):
    """An identity with a password. Returns (email, owner)."""
    email = f"totp-{uuid.uuid4().hex[:12]}@example.test"
    with conn.cursor() as cur:
        owner = credentialed_identity_id(cur, email)
        cur.execute(
            "INSERT INTO tenant_credentials (owner, hashed_password)"
            " VALUES (%s, %s)",
            (owner, credentials.hash_password(PASSWORD)),
        )
    return email, owner


def _post(client, path, body=None, **kw):
    return client.post(f"/api/v1/auth/{path}",
                       headers={**CSRF, "X-Test-Client-IP": "203.0.113.20"},
                       json=body, **kw)


def _get(client, path, **kw):
    return client.get(f"/api/v1/auth/{path}",
                      headers={**CSRF, "X-Test-Client-IP": "203.0.113.20"}, **kw)


def _refresh_rows(conn, owner):
    """How many refresh tokens exist for this account, spent or not.

    Counted rather than asserted absent: the account has logged in legitimately
    by the time most of these tests run, so what matters is the DELTA across a
    refused attempt.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM refresh_tokens WHERE owner = %s",
                    (owner,))
        return cur.fetchone()[0]


def _login(client, email, password=PASSWORD, totp=None):
    body = {"email": email, "password": password}
    if totp is not None:
        body["totp"] = totp
    return _post(client, "login", body)


def _session(client, email):
    """Log in and return the cookies a session needs."""
    r = _login(client, email)
    assert r.status_code == 204, r.text
    return {"sandbox_access": r.cookies["sandbox_access"]}


# --- enrolment --------------------------------------------------------------


def test_enrolling_returns_a_secret_and_a_scannable_uri(client, conn, account):
    email, _ = account
    r = _post(client, "totp/enrol", cookies=_session(client, email))

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["secret"]
    assert body["uri"].startswith("otpauth://totp/")
    # The issuer is what an authenticator app shows in its list, so it has to
    # name something recognisable.
    assert "DRAKVUF" in body["uri"]


def test_a_generated_secret_is_not_yet_active(client, conn, account):
    """**Enrolment is not finished when the secret exists.**

    Treating a generated secret as live is how people lock themselves out
    between scanning the QR code and their authenticator working -- so login
    must not start demanding codes until one has been proved.
    """
    email, owner = account
    _post(client, "totp/enrol", cookies=_session(client, email))

    with conn.cursor() as cur:
        cur.execute("SELECT totp_confirmed_at FROM tenant_credentials"
                    " WHERE owner = %s", (owner,))
        assert cur.fetchone()[0] is None

    assert _login(client, email).status_code == 204, "login started demanding a code"


def test_confirming_with_a_correct_code_activates_it(client, conn, account):
    email, owner = account
    secret = _post(client, "totp/enrol",
                   cookies=_session(client, email)).json()["secret"]

    r = _post(client, "totp/confirm", {"code": pyotp.TOTP(secret).now()},
              cookies=_session(client, email))
    assert r.status_code == 200, r.text
    # The recovery codes arrive with the confirmation, not as a later step a
    # user can skip.
    assert len(r.json()["recovery_codes"]) == credentials.RECOVERY_CODE_COUNT

    with conn.cursor() as cur:
        cur.execute("SELECT totp_confirmed_at FROM tenant_credentials"
                    " WHERE owner = %s", (owner,))
        assert cur.fetchone()[0] is not None


def test_confirming_with_a_wrong_code_is_refused(client, conn, account):
    email, _ = account
    _post(client, "totp/enrol", cookies=_session(client, email))

    r = _post(client, "totp/confirm", {"code": "000000"},
              cookies=_session(client, email))
    assert r.status_code == 401


def test_re_enrolling_before_confirmation_replaces_the_secret(client, conn,
                                                              account):
    """A failed enrolment has to be recoverable by starting again."""
    email, _ = account
    first = _post(client, "totp/enrol",
                  cookies=_session(client, email)).json()["secret"]
    second = _post(client, "totp/enrol",
                   cookies=_session(client, email)).json()["secret"]
    assert first != second


def test_enrolling_again_once_confirmed_is_refused(client, conn, account):
    """**A stolen session must not be able to swap the second factor.**

    Silently replacing a confirmed secret would let whoever holds a cookie
    substitute an authenticator they control, which is the attack the factor
    exists to stop. Disabling it first needs the password.
    """
    email, _ = account
    session = _session(client, email)
    secret = _post(client, "totp/enrol", cookies=session).json()["secret"]
    _post(client, "totp/confirm", {"code": pyotp.TOTP(secret).now()},
          cookies=session)

    r = _post(client, "totp/enrol", cookies=session)
    assert r.status_code == 409


def test_enrolment_requires_a_session(client, conn):
    assert _post(client, "totp/enrol").status_code == 401


# --- login with a second factor ---------------------------------------------


def _enrolled(client, conn, account):
    email, owner = account
    session = _session(client, email)
    secret = _post(client, "totp/enrol", cookies=session).json()["secret"]
    _post(client, "totp/confirm", {"code": pyotp.TOTP(secret).now()},
          cookies=session)
    return email, owner, secret


def test_login_without_a_code_is_refused_once_enrolled(client, conn, account):
    email, _, _ = _enrolled(client, conn, account)
    r = _login(client, email)

    assert r.status_code == 401
    assert "second-factor" in r.json()["detail"]
    assert not r.cookies, "a session was issued without the second factor"


def _fresh_step(conn, owner):
    """Forget the last accepted step, so the CURRENT code counts as unused.

    Enrolment consumes the step it was confirmed on, so a login in the same
    30 seconds presents an already-spent code. Waiting for the next step would
    make these tests take half a minute each and fail on a boundary; clearing
    the marker tests the login path without racing the clock. The replay guard
    itself is tested separately, where the spent code is the point.
    """
    conn.execute("UPDATE tenant_credentials SET totp_last_step = NULL"
                 " WHERE owner = %s", (owner,))


def test_login_with_a_correct_code_succeeds(client, conn, account):
    email, owner, secret = _enrolled(client, conn, account)
    _fresh_step(conn, owner)

    r = _login(client, email, totp=pyotp.TOTP(secret).now())
    assert r.status_code == 204, r.text
    assert "sandbox_access" in r.cookies


def test_the_code_the_account_was_enrolled_with_cannot_be_reused(
        client, conn, account):
    """**TOTP has no replay protection of its own.**

    A code stays valid for its whole 30-second step, so anyone who observes one
    -- a compromised proxy, a phishing page relaying it -- can spend it again
    inside that window. `totp_last_step` is what makes it single-use.

    Enrolment consumed the current step, so presenting the same code to login
    must be refused rather than accepted as a second use.
    """
    email, _, secret = _enrolled(client, conn, account)
    used = pyotp.TOTP(secret).now()

    r = _login(client, email, totp=used)
    assert r.status_code == 401, "a spent code was accepted at login"
    assert not r.cookies


def test_a_wrong_code_does_not_grant_a_session(client, conn, account):
    email, _, _ = _enrolled(client, conn, account)
    r = _login(client, email, totp="000000")

    assert r.status_code == 401
    assert not r.cookies


def test_a_refused_second_factor_mints_no_refresh_token(client, conn, account):
    """**A refusal must leave nothing behind that a session could be built on.**

    The refusal is raised AFTER the connection block closes -- that is what
    makes the throttle counters durable, and it is deliberate -- so everything
    the block did commits alongside them. `issue_refresh_token` used to be one
    of those things, and it ran whenever the PASSWORD verified, second factor
    or not.

    Never a bypass: the plaintext was discarded and no cookie was set. What it
    left was a `refresh_tokens` row with `revoked_at IS NULL`, live for
    REFRESH_TOKEN_TTL_DAYS, mintable by anyone holding a password but not the
    factor -- and one spare on every ordinary MFA login, since the first
    attempt never carries a code. Only a count of the table shows it, which is
    why this test is a delta and not an assertion about the response.
    """
    email, owner, _ = _enrolled(client, conn, account)
    before = _refresh_rows(conn, owner)

    no_code = _login(client, email)
    wrong_code = _login(client, email, totp="000000")

    assert no_code.status_code == wrong_code.status_code == 401
    assert not no_code.cookies and not wrong_code.cookies
    assert _refresh_rows(conn, owner) == before, (
        "a refused login minted a live refresh token")


def test_a_refused_second_factor_does_not_rehash_the_password(
        client, conn, account):
    """The other half of the same block, and the same reasoning.

    Rewriting the stored hash is a write made on behalf of someone who has not
    finished proving they are the account holder. It is harmless in isolation
    -- the plaintext already verified -- but it belongs with the success, not
    beside it.
    """
    email, owner, _ = _enrolled(client, conn, account)
    with conn.cursor() as cur:
        cur.execute("SELECT hashed_password FROM tenant_credentials"
                    " WHERE owner = %s", (owner,))
        before = cur.fetchone()[0]

    _login(client, email)

    with conn.cursor() as cur:
        cur.execute("SELECT hashed_password FROM tenant_credentials"
                    " WHERE owner = %s", (owner,))
        assert cur.fetchone()[0] == before


def test_a_wrong_password_is_refused_before_the_factor_is_mentioned(
        client, conn, account):
    """**Whether an account has a second factor is disclosed by the refusal**,
    so that refusal has to be unreachable without the password -- otherwise it
    is a free oracle for which accounts are worth attacking.
    """
    email, _, _ = _enrolled(client, conn, account)
    r = _login(client, email, password="wrong")

    assert r.status_code == 401
    assert "second-factor" not in r.json()["detail"]


# --- disabling --------------------------------------------------------------


def test_disabling_requires_the_password(client, conn, account):
    """A session alone is what an attacker who stole a cookie has.

    Letting that remove the second factor makes the factor worth nothing
    against the exact attack it exists for.
    """
    email, owner, secret = _enrolled(client, conn, account)
    _fresh_step(conn, owner)

    got = _login(client, email, totp=pyotp.TOTP(secret).now())
    assert got.status_code == 204, got.text
    session = {"sandbox_access": got.cookies["sandbox_access"]}

    r = _post(client, "totp/disable", {"password": "wrong"}, cookies=session)
    assert r.status_code == 401, "a session alone removed the second factor"


def test_disabling_with_the_password_turns_it_off(client, conn, account):
    email, owner, secret = _enrolled(client, conn, account)
    _fresh_step(conn, owner)

    r = _login(client, email, totp=pyotp.TOTP(secret).now())
    assert r.status_code == 204, r.text
    session = {"sandbox_access": r.cookies["sandbox_access"]}

    off = _post(client, "totp/disable", {"password": PASSWORD}, cookies=session)
    assert off.status_code == 204, off.text

    with conn.cursor() as cur:
        cur.execute("SELECT totp_secret, totp_confirmed_at, totp_last_step"
                    " FROM tenant_credentials WHERE owner = %s", (owner,))
        assert cur.fetchone() == (None, None, None)

    assert _login(client, email).status_code == 204, "still demanding a code"


def _mfa_session(client, conn, account):
    """An enrolled account and a live session for it. `(email, owner, session)`."""
    email, owner, secret = _enrolled(client, conn, account)
    _fresh_step(conn, owner)
    r = _login(client, email, totp=pyotp.TOTP(secret).now())
    assert r.status_code == 204, r.text
    return email, owner, {"sandbox_access": r.cookies["sandbox_access"]}


def test_guessing_the_password_at_disable_is_eventually_refused(
        client, conn, account, monkeypatch):
    """**A stolen session must not be a free password oracle.**

    This route and `/totp/recovery` are gated on a session cookie and then ask
    for the password -- and a session cookie is exactly what the attacker they
    defend against already holds. Neither counted an attempt, so the password
    was guessable at full speed, and a success removes the second factor or
    hands back ten codes that bypass it.

    Separately, every attempt takes one of MAX_CONCURRENT_HASHES (4) argon2
    slots, which `credentials._hash_slot` refuses rather than queues -- so an
    unlimited route here turns LOGIN into a 503 for everybody.

    The limit is tightened after the setup logins so the 429 provably comes
    from the window limiter rather than from the account lockout, which is
    pinned separately below.
    """
    email, owner, session = _mfa_session(client, conn, account)
    monkeypatch.setattr(
        throttle, "settings",
        dataclasses.replace(settings, attempts_per_window=3,
                            lockout_threshold=50),
    )

    seen = [_post(client, "totp/disable", {"password": "wrong"},
                  cookies=session).status_code for _ in range(5)]

    assert 429 in seen, f"unlimited password guesses from a session: {seen}"
    # Even the correct password, because `enforce_limit` runs before any
    # hashing -- the same shape as login, and the reason it is that way there.
    assert _post(client, "totp/disable", {"password": PASSWORD},
                 cookies=session).status_code == 429


def test_guessing_the_password_at_recovery_shares_that_limit(
        client, conn, account, monkeypatch):
    """**One bucket for both routes, not one each.**

    A caller who can alternate between two counters gets twice the guesses at
    the same password for the same work, which is most of a limiter undone by
    arithmetic.
    """
    email, owner, session = _mfa_session(client, conn, account)
    monkeypatch.setattr(
        throttle, "settings",
        dataclasses.replace(settings, attempts_per_window=3,
                            lockout_threshold=50),
    )

    for _ in range(4):
        _post(client, "totp/disable", {"password": "wrong"}, cookies=session)

    r = _post(client, "totp/recovery", {"password": "wrong"}, cookies=session)
    assert r.status_code == 429, "the two routes kept separate counters"


def test_a_wrong_password_at_disable_counts_against_the_account(
        client, conn, account):
    """The lockout is the SAME one login uses, deliberately.

    A password being guessed through a stolen cookie is that account under
    attack. Counting it only against its own route would leave login answering
    at full speed to the attacker who had just been slowed down here.
    """
    email, owner, session = _mfa_session(client, conn, account)

    _post(client, "totp/disable", {"password": "wrong"}, cookies=session)

    with conn.cursor() as cur:
        cur.execute("SELECT failed_attempts FROM tenant_credentials"
                    " WHERE owner = %s", (owner,))
        assert cur.fetchone()[0] >= 1


def test_the_counters_survive_the_refusal_they_counted(client, conn, account):
    """**The trap this module documents at the top of `login`.**

    `db.connection` rolls back on exception, so a refusal raised while the
    block is open discards the increment meant to count the attempt being
    refused -- leaving a limiter that sits permanently at zero while looking
    implemented. It was measured once already on login: the `rate_limit` table
    came back empty after six failed attempts.

    So this asserts on the TABLE after a 401, not on the 401.
    """
    email, owner, session = _mfa_session(client, conn, account)

    r = _post(client, "totp/disable", {"password": "wrong"}, cookies=session)
    assert r.status_code == 401

    with conn.cursor() as cur:
        cur.execute("SELECT coalesce(sum(count), 0) FROM rate_limit"
                    " WHERE bucket_key = %s", (f"totp:{owner}",))
        assert cur.fetchone()[0] >= 1, (
            "the refusal rolled back the increment that counted it")


# --- what the account page is allowed to ask --------------------------------


def test_reading_the_status_does_not_disturb_an_enrolment(client, conn,
                                                           account):
    """**The probe that used to be a POST.**

    The account page answered "is MFA on?" by POSTing `/totp/enrol` and reading
    the 409. When MFA was off that call ran `UPDATE tenant_credentials SET
    totp_secret = ...`, so every page load, every reload and every second tab
    replaced an unconfirmed secret. Somebody who had already added the key to
    their authenticator was then confirming against a secret the server had
    thrown away, and every code was wrong with nothing on the page to say why.
    """
    email, owner = account
    session = _session(client, email)
    secret = _post(client, "totp/enrol", cookies=session).json()["secret"]

    r = _get(client, "totp/status", cookies=session)

    assert r.status_code == 200, r.text
    assert r.json() == {"credentialed": True, "enabled": False,
                        "enrolling": True}
    with conn.cursor() as cur:
        cur.execute("SELECT totp_secret FROM tenant_credentials"
                    " WHERE owner = %s", (owner,))
        assert cur.fetchone()[0] == secret, "reading the status rotated it"

    # And the authenticator that scanned it still finishes enrolment.
    assert _post(client, "totp/confirm", {"code": pyotp.TOTP(secret).now()},
                 cookies=session).status_code == 200


def test_the_status_never_carries_a_secret(client, conn, account):
    """A GET reachable with nothing but a session cookie.

    An enrolment secret is a credential; `/totp/enrol` is the only route that
    hands one out, once, in answer to a deliberate POST.
    """
    email, _ = account
    session = _session(client, email)
    secret = _post(client, "totp/enrol", cookies=session).json()["secret"]

    body = _get(client, "totp/status", cookies=session)

    assert secret not in body.text, "the status route disclosed the secret"


def test_the_status_reports_the_factor_as_on_once_confirmed(client, conn,
                                                             account):
    email, owner, session = _mfa_session(client, conn, account)
    assert _get(client, "totp/status", cookies=session).json() == {
        "credentialed": True, "enabled": True, "enrolling": False}


def test_the_status_requires_a_session(client, conn):
    assert _get(client, "totp/status").status_code == 401


def test_enrolling_with_no_password_set_says_so_rather_than_the_opposite(
        client, conn):
    """**The refusal used to be the exact opposite of the truth.**

    `enrol_totp`'s UPDATE matches on `totp_confirmed_at IS NULL`, so it also
    misses when there is no `tenant_credentials` row at all -- and an identity
    that has never had a password was told "the second factor is already
    enabled; disable it first".

    The session is minted directly rather than logged into, because an account
    with no credentials row is exactly one that cannot log in.
    """
    email = f"nocreds-{uuid.uuid4().hex[:12]}@example.test"
    with conn.cursor() as cur:
        owner = credentialed_identity_id(cur, email)
    session = {"sandbox_access": credentials.mint_access_token(owner)}

    r = _post(client, "totp/enrol", cookies=session)

    assert r.status_code == 409
    assert "already enabled" not in r.json()["detail"], r.json()
    assert "no password" in r.json()["detail"], r.json()

    assert _get(client, "totp/status", cookies=session).json() == {
        "credentialed": False, "enabled": False, "enrolling": False}

# --- recovery codes ---------------------------------------------------------


def _enrolled_with_codes(client, conn, account):
    """Enrol, and return (email, owner, secret, recovery codes)."""
    email, owner = account
    session = _session(client, email)
    secret = _post(client, "totp/enrol", cookies=session).json()["secret"]
    r = _post(client, "totp/confirm", {"code": pyotp.TOTP(secret).now()},
              cookies=session)
    return email, owner, secret, r.json()["recovery_codes"]


def test_codes_are_issued_when_the_factor_is_enabled(client, conn, account):
    """**Part of enabling it, not a later step.**

    A user asked to save them afterwards mostly does not, and an authenticator
    lost before that point is an account only an operator can recover.
    """
    _, _, _, codes = _enrolled_with_codes(client, conn, account)

    assert len(codes) == credentials.RECOVERY_CODE_COUNT
    assert len(set(codes)) == len(codes)


def test_codes_are_stored_only_as_hashes(client, conn, account):
    _, owner, _, codes = _enrolled_with_codes(client, conn, account)

    with conn.cursor() as cur:
        cur.execute("SELECT code_hash FROM mfa_recovery_codes WHERE owner = %s",
                    (owner,))
        stored = {r[0] for r in cur.fetchall()}

    assert not (set(codes) & stored), "a plaintext code reached the table"
    assert credentials.hash_recovery_code(codes[0]) in stored


def test_a_recovery_code_logs_in_when_the_authenticator_is_gone(
        client, conn, account):
    """The whole point: a lost phone is recoverable without an operator."""
    email, _, _, codes = _enrolled_with_codes(client, conn, account)

    r = _login(client, email, totp=codes[0])

    assert r.status_code == 204, r.text
    assert "sandbox_access" in r.cookies


def test_a_recovery_code_works_only_once(client, conn, account):
    email, _, _, codes = _enrolled_with_codes(client, conn, account)
    assert _login(client, email, totp=codes[0]).status_code == 204

    again = _login(client, email, totp=codes[0])
    assert again.status_code == 401, "a spent recovery code was accepted twice"
    assert not again.cookies


def test_spending_one_leaves_the_others_usable(client, conn, account):
    email, _, _, codes = _enrolled_with_codes(client, conn, account)
    _login(client, email, totp=codes[0])

    assert _login(client, email, totp=codes[1]).status_code == 204


def test_codes_are_normalised_for_case_and_spacing(client, conn, account):
    """They are read off paper at the worst possible moment.

    Refusing a correct code because it was typed in capitals is what sends
    someone to an operator instead.
    """
    email, _, _, codes = _enrolled_with_codes(client, conn, account)

    r = _login(client, email, totp=f"  {codes[0].upper()}  ")
    assert r.status_code == 204, r.text


def test_another_account_s_code_does_not_work(client, conn, account):
    """Scoped to the owner as well as the hash. The PRIMARY KEY makes a
    collision unpresentable, but the query must not rely on that alone."""
    email_a, _, _, codes_a = _enrolled_with_codes(client, conn, account)

    other_email = f"totp-{uuid.uuid4().hex[:12]}@example.test"
    with conn.cursor() as cur:
        other = credentialed_identity_id(cur, other_email)
        cur.execute("INSERT INTO tenant_credentials (owner, hashed_password)"
                    " VALUES (%s, %s)",
                    (other, credentials.hash_password(PASSWORD)))
    session = _session(client, other_email)
    secret = _post(client, "totp/enrol", cookies=session).json()["secret"]
    _post(client, "totp/confirm", {"code": pyotp.TOTP(secret).now()},
          cookies=session)

    r = _login(client, other_email, totp=codes_a[0])
    assert r.status_code == 401


def test_a_wrong_code_is_still_a_failed_attempt(client, conn, account):
    """Falling back to the codes table must not turn a guess into a free one --
    a wrong value is neither a TOTP code nor a recovery code, and counts."""
    email, owner, _, _ = _enrolled_with_codes(client, conn, account)

    _login(client, email, totp="definitely-not-a-code")

    with conn.cursor() as cur:
        cur.execute("SELECT failed_attempts FROM tenant_credentials"
                    " WHERE owner = %s", (owner,))
        assert cur.fetchone()[0] >= 1


def test_remaining_counts_down_as_they_are_spent(client, conn, account):
    email, owner, secret, codes = _enrolled_with_codes(client, conn, account)
    _fresh_step(conn, owner)
    session = {"sandbox_access": _login(
        client, email, totp=pyotp.TOTP(secret).now()).cookies["sandbox_access"]}

    before = client.get("/api/v1/auth/totp/recovery/remaining",
                        headers=CSRF, cookies=session).json()["remaining"]
    _login(client, email, totp=codes[0])
    after = client.get("/api/v1/auth/totp/recovery/remaining",
                       headers=CSRF, cookies=session).json()["remaining"]

    assert before == credentials.RECOVERY_CODE_COUNT
    assert after == before - 1


def test_regenerating_replaces_the_whole_set(client, conn, account):
    """**Replaced, not topped up.** Leaving the old ones live means a set
    someone believes they have replaced is still spendable."""
    email, owner, secret, old = _enrolled_with_codes(client, conn, account)
    _fresh_step(conn, owner)
    session = {"sandbox_access": _login(
        client, email, totp=pyotp.TOTP(secret).now()).cookies["sandbox_access"]}

    new = _post(client, "totp/recovery", {"password": PASSWORD},
                cookies=session).json()["recovery_codes"]

    assert not (set(old) & set(new))
    assert _login(client, email, totp=old[0]).status_code == 401
    assert _login(client, email, totp=new[0]).status_code == 204


def test_regenerating_requires_the_password(client, conn, account):
    """It hands back ten credentials that each bypass the second factor, so a
    session alone must not be enough -- that is what a stolen cookie is."""
    email, owner, secret, _ = _enrolled_with_codes(client, conn, account)
    _fresh_step(conn, owner)
    session = {"sandbox_access": _login(
        client, email, totp=pyotp.TOTP(secret).now()).cookies["sandbox_access"]}

    r = _post(client, "totp/recovery", {"password": "wrong"}, cookies=session)
    assert r.status_code == 401


def test_disabling_the_factor_destroys_the_codes(client, conn, account):
    """Left behind they would be live credentials for a factor that no longer
    exists -- and would come back into force if it were re-enabled."""
    email, owner, secret, _ = _enrolled_with_codes(client, conn, account)
    _fresh_step(conn, owner)
    session = {"sandbox_access": _login(
        client, email, totp=pyotp.TOTP(secret).now()).cookies["sandbox_access"]}

    _post(client, "totp/disable", {"password": PASSWORD}, cookies=session)

    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM mfa_recovery_codes WHERE owner = %s",
                    (owner,))
        assert cur.fetchone()[0] == 0
