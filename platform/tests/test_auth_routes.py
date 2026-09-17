"""Login, refresh and logout (DRAFT-061 decision 3).

The properties worth testing here are mostly about what a caller CANNOT learn.
Several of these would pass against an implementation that leaks the thing they
exist to hide, so each says what it would look like if it were broken.
"""

from __future__ import annotations

import dataclasses

import pytest
from conftest import credentialed_identity_id

from sandbox_platform import credentials, throttle
from sandbox_platform.config import settings

PASSWORD = "correct horse battery staple"
CSRF = {"X-Sandbox-Request": "1"}


@pytest.fixture(autouse=True)
def signing_key(monkeypatch):
    """A usable key, and limits loose enough not to fire in unrelated tests."""
    for module in (credentials, throttle):
        monkeypatch.setattr(
            module, "settings",
            dataclasses.replace(
                settings,
                jwt_signing_key="test-key",
                jwt_issuer="sandbox.evilbootloader.com",
                jwt_audience="sandbox-platform",
                attempts_per_window=50,
                lockout_threshold=50,
            ),
        )


@pytest.fixture
def account(conn):
    """An identity with a password set. Returns (email, owner)."""
    import uuid

    email = f"login-{uuid.uuid4().hex[:12]}@example.test"
    with conn.cursor() as cur:
        owner = credentialed_identity_id(cur, email)
        cur.execute(
            "INSERT INTO tenant_credentials (owner, hashed_password)"
            " VALUES (%s, %s)",
            (owner, credentials.hash_password(PASSWORD)),
        )
    return email, owner


def _set_cookie(response, name):
    """The Set-Cookie header for one cookie.

    `headers.items()` collapses repeated headers into a single comma-joined
    value, which silently returns nothing for the second cookie -- `get_list` is
    the one that preserves them.
    """
    for raw in response.headers.get_list("set-cookie"):
        if raw.startswith(f"{name}="):
            return raw
    raise AssertionError(f"no Set-Cookie for {name}: "
                         f"{response.headers.get_list('set-cookie')}")


def _login(client, email, password, **kw):
    return client.post("/api/v1/auth/login", headers=CSRF,
                       json={"email": email, "password": password}, **kw)


# --- the happy path ---------------------------------------------------------


def test_a_correct_password_sets_both_cookies(client, conn, account):
    email, _ = account
    r = _login(client, email, PASSWORD)

    assert r.status_code == 204, r.text
    assert "sandbox_access" in r.cookies
    assert "sandbox_refresh" in r.cookies


def test_the_access_cookie_carries_a_token_for_the_tenant(client, conn, account):
    email, owner = account
    r = _login(client, email, PASSWORD)

    claims = credentials.decode_access_token(r.cookies["sandbox_access"])
    assert claims["sub"] == owner


def test_the_refresh_cookie_is_scoped_to_the_refresh_route(client, conn, account):
    """**Path scoping is why the refresh token is not sent on every request.**

    Without it the browser attaches a long-lived credential to every page load,
    every poll and every artifact download -- multiplying the places a leak can
    happen, for no gain, since only one route can spend it.
    """
    email, _ = account
    r = _login(client, email, PASSWORD)

    raw = _set_cookie(r, "sandbox_refresh")
    assert "Path=/api/v1/auth/refresh" in raw, raw
    assert "HttpOnly" in raw, raw
    assert "samesite=strict" in raw.lower(), raw


def test_both_cookies_are_httponly(client, conn, account):
    """A token readable by script is a token an XSS takes.

    `test_ui_browser.py` exists because hostile filenames reach these pages, so
    this is not a hypothetical threat model for this application.
    """
    email, _ = account
    r = _login(client, email, PASSWORD)

    for name in ("sandbox_access", "sandbox_refresh"):
        raw = _set_cookie(r, name)
        assert "HttpOnly" in raw, raw
        assert "Secure" in raw, raw


# --- what a caller must not learn -------------------------------------------


def test_a_wrong_password_and_an_unknown_address_are_indistinguishable(
        client, conn, account):
    """**Byte-identical, not merely similar.**

    Status, body and the presence of cookies all have to match. This is the
    enumeration hole that `verify_password(None, ...)` pays a full argon2 hash
    to close, and a route that returns early on a missing account undoes it for
    free.
    """
    email, _ = account
    wrong = _login(client, email, "not the password")
    unknown = _login(client, "nobody-at-all@example.test", "not the password")

    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()
    assert not wrong.cookies and not unknown.cookies


def test_an_identity_with_no_password_looks_like_no_account(client, conn):
    """An identity created by `resolve_tenant` has no credentials row.

    The LEFT JOIN is what makes this arrive the same way as an unknown address
    -- an inner join would return no row for one case and a row for the other,
    which is a different code path and therefore a different answer.
    """
    import uuid

    email = f"nopass-{uuid.uuid4().hex[:12]}@example.test"
    with conn.cursor() as cur:
        credentialed_identity_id(cur, email)

    r = _login(client, email, "anything")
    unknown = _login(client, "nobody-here@example.test", "anything")

    assert r.status_code == unknown.status_code == 401
    assert r.json() == unknown.json()


# --- CSRF -------------------------------------------------------------------


@pytest.mark.parametrize("route", [
    ("/api/v1/auth/login"),
    ("/api/v1/auth/refresh"),
    ("/api/v1/auth/logout"),
    # Since M-7 the rule reaches past `/auth`. These two were relying on
    # `SameSite=Lax` for our own session and on Cloudflare's cookie policy for
    # the Access assertion -- a policy this project does not set.
    ("/api/v1/account/balance"),
    ("/api/v1/jobs"),
])
def test_every_unsafe_route_requires_the_header(conn, route):
    """**The whole CSRF defence**, and it is complete only because this
    application has no HTML form POSTs -- a cross-site form cannot set a header,
    and a cross-site fetch that tries is stopped by the missing CORS middleware.

    Parametrised across all three routers so a route added without the
    router-level dependency fails here rather than in production.

    **A client WITHOUT the fixture's default header**, and constructing it is
    the point. `conftest.client` sets `X-Sandbox-Request` on every request so
    that the ~68 tests about admission, tenancy and rendering stay about those
    things. A test that is actually about CSRF has to build the absence itself,
    which also makes it a real assertion rather than a tripwire that would break
    in company with everything else.
    """
    from fastapi.testclient import TestClient

    from sandbox_platform.app import app

    with TestClient(app) as bare:
        r = bare.post(route, json={"email": "a@b.c", "password": "x"})

    assert r.status_code == 403, r.text
    assert "X-Sandbox-Request" in r.json()["detail"]


def test_a_safe_method_needs_no_header(conn):
    """**Artifact downloads are GET links a person clicks**, and a click cannot
    set a header.

    `routers/jobs.py::_detail` hands `/api/v1/jobs/{id}/artifact.zip` to the
    browser as an ordinary `href`. Attaching the CSRF dependency to the whole
    jobs router would have refused every one of them -- while looking, in the
    diff, exactly like tightening security. `csrf.py` exempts safe methods for
    this reason and this test is what holds it.

    Not 200: with no credential this is a 401, which is the identity dependency
    doing its own job. What matters is that it is not the CSRF refusal.

    **No `client` fixture here, deliberately.** Nesting a second `TestClient`
    inside it runs lifespan twice, and the inner one's exit calls `close_pool()`
    on the pool the outer fixture is still holding -- every later request in the
    test then fails with "connection pool is not open".
    """
    from fastapi.testclient import TestClient

    from sandbox_platform.app import app

    with TestClient(app) as bare:
        assert bare.get("/api/v1/jobs").status_code != 403


# --- refresh ----------------------------------------------------------------


def test_refreshing_rotates_both_cookies(client, conn, account):
    email, _ = account
    first = _login(client, email, PASSWORD)
    before = first.cookies["sandbox_refresh"]

    r = client.post("/api/v1/auth/refresh", headers=CSRF,
                    cookies={"sandbox_refresh": before})

    assert r.status_code == 204, r.text
    assert r.cookies["sandbox_refresh"] != before


def test_a_spent_refresh_token_is_refused(client, conn, account):
    email, _ = account
    before = _login(client, email, PASSWORD).cookies["sandbox_refresh"]
    client.post("/api/v1/auth/refresh", headers=CSRF,
                cookies={"sandbox_refresh": before})

    again = client.post("/api/v1/auth/refresh", headers=CSRF,
                        cookies={"sandbox_refresh": before})
    assert again.status_code == 401


def test_replaying_a_spent_token_revokes_the_whole_chain(client, conn, account):
    """Detection that does not revoke has noticed a theft and done nothing.

    After a replay the successor -- the token the honest client is holding --
    must stop working too, because there is no way to tell which of the two
    parties is the attacker.
    """
    email, _ = account
    first = _login(client, email, PASSWORD).cookies["sandbox_refresh"]
    second = client.post("/api/v1/auth/refresh", headers=CSRF,
                         cookies={"sandbox_refresh": first}
                         ).cookies["sandbox_refresh"]

    # The replay.
    client.post("/api/v1/auth/refresh", headers=CSRF,
                cookies={"sandbox_refresh": first})

    r = client.post("/api/v1/auth/refresh", headers=CSRF,
                    cookies={"sandbox_refresh": second})
    assert r.status_code == 401, "the successor survived a detected replay"


def test_refreshing_without_a_cookie_is_refused(client):
    r = client.post("/api/v1/auth/refresh", headers=CSRF)
    assert r.status_code == 401


# --- logout -----------------------------------------------------------------


def test_logout_ends_every_session_for_the_owner(client, conn, account):
    """"Log out" that leaves other sessions running is not what anyone means.

    The usual reason for pressing it is suspecting one of them.
    """
    email, _ = account
    one = _login(client, email, PASSWORD).cookies["sandbox_refresh"]
    two = _login(client, email, PASSWORD).cookies["sandbox_refresh"]

    client.post("/api/v1/auth/logout", headers=CSRF,
                cookies={"sandbox_refresh": one})

    for token in (one, two):
        r = client.post("/api/v1/auth/refresh", headers=CSRF,
                        cookies={"sandbox_refresh": token})
        assert r.status_code == 401


def test_logout_revokes_when_only_the_access_cookie_is_sent(client, conn,
                                                            account):
    """**The shape a real browser sends, and the one that did not work.**

    `sandbox_refresh` is scoped to `Path=/api/v1/auth/refresh`, which is the
    property the test above this one pins -- so a browser never attaches it to
    `/api/v1/auth/logout`. The revoking half of logout was therefore unreachable
    from a browser, and only the two `delete_cookie` calls ever ran: the tab
    looked signed out and every refresh token stayed live for
    REFRESH_TOKEN_TTL_DAYS. The other logout tests pass because a test client is
    handed the cookie explicitly, which no browser does.

    Found when the masthead gained a sign-out control that had to actually end
    the session.
    """
    email, _ = account
    r = _login(client, email, PASSWORD)
    access, refresh = r.cookies["sandbox_access"], r.cookies["sandbox_refresh"]

    out = client.post("/api/v1/auth/logout", headers=CSRF,
                      cookies={"sandbox_access": access})
    assert out.status_code == 204, out.text

    spend = client.post("/api/v1/auth/refresh", headers=CSRF,
                        cookies={"sandbox_refresh": refresh})
    assert spend.status_code == 401, "the session survived sign-out"


def test_logout_with_an_unusable_access_cookie_is_still_not_an_error(client):
    """A cookie that no longer verifies is the ordinary way to arrive here --
    it expired, which is often why someone is pressing sign out. The cookies are
    cleared either way, which is the part the caller asked for."""
    r = client.post("/api/v1/auth/logout", headers=CSRF,
                    cookies={"sandbox_access": "not.a.token"})
    assert r.status_code == 204, r.text


def test_logout_without_a_session_is_not_an_error(client):
    """Idempotent: a caller who already lost their cookie got what they asked
    for, and a 4xx here would make the UI show an error for a successful
    outcome."""
    assert client.post("/api/v1/auth/logout", headers=CSRF).status_code == 204

def test_the_masthead_offers_a_way_out(client, conn, account):
    """**The route had no caller in the UI at all.**

    `POST /api/v1/auth/logout` was implemented and tested while the masthead
    offered Submit, History, Account, a balance and a theme toggle -- and no
    way to sign out. Asserted on the rendered page rather than left to a
    reviewer noticing, because "implemented and unreachable" is the state it
    was already in once.

    **Signed in with OUR OWN session, which is now the condition.** The default
    `client` carries an Access identity, and the control is deliberately hidden
    there: we cannot end a Cloudflare session, so offering to would produce the
    "signed out but still signed in" state that
    `test_cutover.py::test_sign_out_is_not_offered_while_an_external_provider_owns_the_session`
    describes.
    """
    email, _ = account
    cookies = {"sandbox_access": _login(client, email,
                                        PASSWORD).cookies["sandbox_access"]}

    body = client.get("/ui/account", cookies=cookies).text
    assert 'id="sign-out"' in body
    assert "signout.js" in body, "the control is there with nothing driving it"


def test_the_sign_in_page_offers_no_way_out(client):
    """`base.html` is shared by every page, `/ui/login` included.

    A sign-out control on the sign-in page is either a no-op or a reload, and
    reads as broken either way.
    """
    body = client.get("/ui/login").text
    assert 'id="sign-out"' not in body
    assert "signout.js" not in body


# --- the session actually works ---------------------------------------------


def test_a_session_reaches_the_rest_of_the_api(conn, account):
    """**DRAFT-061 acceptance criterion 5**, end to end.

    Every increment before this one issued sessions nothing accepted --
    `access_identity` read Cloudflare's header and no other route looked at the
    cookie. This is the test that says the swap happened: log in, and the
    balance endpoint answers.

    **An https client, deliberately.** The session cookies are `Secure`, and
    httpx honours that -- over `http://testserver` the cookie jar silently
    keeps them and every follow-up request is anonymous. That failure looks
    exactly like a broken verifier, and cost a debugging round here.
    """
    from fastapi.testclient import TestClient

    from sandbox_platform import auth
    from sandbox_platform.app import app

    email, _ = account
    # `headers=CSRF` on the client rather than per call: `/account/balance` is a
    # POST and the account router now requires the header too (finding M-7), so
    # every unsafe call below needs it. The GET does not, which is what keeps
    # artifact download links working -- see `sandbox_platform/csrf.py`.
    with TestClient(app, base_url="https://testserver",
                    headers=CSRF) as https:
        assert https.post("/api/v1/account/balance", follow_redirects=False).status_code == 303 # Redirected to login

        assert https.post("/api/v1/auth/login",
                          json={"email": email,
                                "password": PASSWORD}).status_code == 204

        balance = https.post("/api/v1/account/balance")
        assert balance.status_code == 200, balance.text
        assert balance.json() > 0

        assert https.get("/api/v1/jobs").status_code == 200

        https.post("/api/v1/auth/logout")
        assert https.post("/api/v1/account/balance", follow_redirects=False).status_code == 303


def test_an_unauthenticated_read_is_refused_rather_than_unscoped(client,
                                                                 no_identity):
    """**The hole DRAFT-061 closed.**

    `visible_to(None)` used to return `TRUE` and scope nothing, on the
    reasoning that only the certificate-gated listener could produce a None.
    That was correct while Cloudflare Access authenticated every browser
    request at the edge -- and a full cross-tenant read the moment it stopped.

    An anonymous caller is now refused before any predicate is built.
    """
    assert client.get("/api/v1/jobs", follow_redirects=False).status_code == 303


def test_the_unscoped_read_now_requires_asking_for_it(conn):
    """`EVERYTHING` is a value a caller passes by name, not an absence.

    Passing None is a programming error and is refused as one, so a future path
    that fails to produce an identity cannot silently produce the most
    privileged answer instead.
    """
    import pytest as _pytest

    from sandbox_platform import auth

    sql, params = auth.visible_to(auth.EVERYTHING)
    assert sql == "TRUE" and params == []

    with _pytest.raises(ValueError):
        auth.visible_to(None)
