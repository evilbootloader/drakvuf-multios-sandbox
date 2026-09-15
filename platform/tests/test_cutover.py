"""The platform authenticating on its own, with no Cloudflare Access at all.

DRAFT-061's cut-over. Every test here runs on a client that has **no Access
override and no Access header** -- `no_identity` -- which is precisely the
deployment after the Access policy is removed. That is the whole point: the rest
of the suite overrides `auth.access_identity`, so it would pass just as happily
against a platform that still could not authenticate anybody by itself.

What these pin is one property in two halves, and the second half is the one
worth being careful about:

    a session this platform issued is sufficient
    nothing at all is refused

The first half was unreachable before this change. `access_identity` raises when
`REQUIRE_ACCESS_JWT` is set and no Cloudflare header is present, and it was the
gate on the jobs, account and UI routers -- so a caller holding a perfectly good
session cookie was turned away by the Cloudflare verifier before
`caller_identity` ever looked at it. The session machinery existed and no route
could be reached with it.
"""

from __future__ import annotations

import dataclasses
import uuid

import pytest
from conftest import credentialed_identity_id

from sandbox_platform import auth, credentials, telegram, throttle
from sandbox_platform.config import settings
from sandbox_platform.routers import auth as auth_router
from sandbox_platform.routers import console as console_router
from sandbox_platform.routers import jobs as jobs_router

CSRF = {"X-Sandbox-Request": "1"}
PASSWORD = "a sufficiently long password"


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    """A deployment that can mint and verify its own sessions.

    `jwt_issuer` and `jwt_audience` are set explicitly and both matter: an empty
    audience mints tokens that can never be verified, which
    `credentials._require_issuer_and_audience` now refuses rather than allowing
    a deployment where login succeeds and every subsequent request is anonymous.
    """
    for module in (credentials, throttle, telegram, auth):
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
    """An identity with a password and nothing else. Returns (email, owner)."""
    email = f"cutover-{uuid.uuid4().hex[:12]}@example.test"
    with conn.cursor() as cur:
        owner = credentialed_identity_id(cur, email)
        cur.execute(
            "INSERT INTO tenant_credentials (owner, hashed_password)"
            " VALUES (%s, %s)",
            (owner, credentials.hash_password(PASSWORD)),
        )
    return email, owner


def _sign_in(client, email):
    """The cookies a real browser would be holding after signing in."""
    r = client.post(
        "/api/v1/auth/login",
        headers={**CSRF, "X-Test-Client-IP": "203.0.113.30"},
        json={"email": email, "password": PASSWORD},
    )
    assert r.status_code == 204, r.text
    return {"sandbox_access": r.cookies["sandbox_access"]}


# --- the page you reach with nothing -----------------------------------------


def test_the_sign_in_page_is_reachable_with_no_credential(client, no_identity):
    """**The chicken-and-egg case, and it was broken.**

    `/ui/login` carried `dependencies=[]` and a comment claiming that put it
    outside the router's gate. FastAPI does not compose them that way -- router
    dependencies always run -- so the page someone reaches when they have no
    session sat behind the gate demanding one. It is on its own router now.
    """
    r = client.get("/ui/login")
    assert r.status_code == 200, r.text
    assert "login.js" in r.text, "the page rendered without the script that works it"


def test_the_sign_in_page_is_reachable_while_access_is_still_enforced(
        client, no_identity, monkeypatch):
    """**The transition state, which is where this actually bit.**

    With `REQUIRE_ACCESS_JWT=1` -- what the deployment runs today --
    `access_identity` REFUSES a request carrying no Cloudflare header rather
    than returning None. While `/ui/login` sat on the gated router that refusal
    reached it, so during the one period when both credentials are meant to work
    there was no way to obtain the new one. The page has to be reachable in both
    states, not only after the flag is flipped.
    """
    from sandbox_platform import ui as ui_module

    monkeypatch.setattr(ui_module.auth, "settings", dataclasses.replace(
        settings, require_access_jwt=True,
        access_team_domain="https://example.cloudflareaccess.com",
        access_aud="deadbeef"))

    assert client.get("/ui/login").status_code == 200
    # And the gated half is still gated, which is the half that matters.
    assert client.get("/ui/jobs").status_code == 401


# --- a session is sufficient --------------------------------------------------


def test_a_session_alone_reaches_the_json_api(client, no_identity, account):
    email, _ = account
    cookies = _sign_in(client, email)

    r = client.get("/api/v1/jobs", cookies=cookies)
    assert r.status_code == 200, r.text


def test_a_session_alone_reaches_the_ui(client, no_identity, account):
    email, _ = account
    cookies = _sign_in(client, email)

    r = client.get("/ui/jobs", cookies=cookies)
    assert r.status_code == 200, r.text


def test_a_session_alone_reaches_the_balance(client, no_identity, account):
    """The account router was gated the same way and is what every page load
    hits, so a cut-over that missed it would break the UI on every render."""
    email, _ = account
    cookies = _sign_in(client, email)

    r = client.post("/api/v1/account/balance", cookies=cookies)
    assert r.status_code == 200, r.text


def test_a_session_is_scoped_to_its_own_tenant(client, conn, no_identity,
                                               account):
    """Sufficient to get IN is not the same as scoped correctly once in.

    The session's `sub` is the tenant id, so a job belonging to someone else
    must not appear -- the same predicate `visible_to` applies to an Access
    caller, reached through a different credential.
    """
    email, owner = account
    stranger = credentialed_identity_id(conn.cursor(), f"other-{uuid.uuid4().hex[:8]}@example.test")
    conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, owner)"
        " VALUES ('ubuntu', 'theirs.bin', 'completed', %s)", (stranger,))
    conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, owner)"
        " VALUES ('ubuntu', 'mine.bin', 'completed', %s)", (owner,))

    cookies = _sign_in(client, email)
    names = [j["submitted_filename"]
             for j in client.get("/api/v1/jobs", cookies=cookies).json()]

    assert "mine.bin" in names
    assert "theirs.bin" not in names, "a session read another tenant's private job"


# --- nothing at all is refused -----------------------------------------------


@pytest.mark.parametrize("path", ["/api/v1/jobs", "/ui/jobs", "/ui/account"])
def test_an_anonymous_caller_is_refused(client, no_identity, path):
    """**The half that must not regress while making the other half work.**

    Removing Cloudflare from in front of these routes is only safe because
    `caller_identity` refuses when neither credential produced an identity. A
    cut-over that made sessions work and left this open would have replaced an
    edge that authenticated with nothing at all.
    """
    assert client.get(path).status_code == 401


def test_an_anonymous_caller_cannot_post_a_balance(client, no_identity):
    assert client.post("/api/v1/account/balance").status_code == 401


def test_a_forged_session_cookie_is_refused(client, no_identity):
    """Not signed by this platform, so it is not a session.

    `session_identity` swallows the verification error and returns None -- a
    stale cookie is the ordinary state of a tab left open overnight -- which is
    safe only because `caller_identity` then refuses. This is that pairing.
    """
    r = client.get("/api/v1/jobs",
                   cookies={"sandbox_access": "not.a.token"})
    assert r.status_code == 401


def test_a_session_signed_with_another_key_is_refused(client, no_identity,
                                                      account, monkeypatch):
    """A valid JWT in every respect except whose key signed it."""
    email, _ = account
    cookies = _sign_in(client, email)
    assert client.get("/api/v1/jobs", cookies=cookies).status_code == 200

    monkeypatch.setattr(
        credentials, "settings",
        dataclasses.replace(settings, jwt_signing_key="a-different-key",
                            jwt_issuer="sandbox.evilbootloader.com",
                            jwt_audience="sandbox-platform"),
    )
    assert client.get("/api/v1/jobs", cookies=cookies).status_code == 401


# --- the console, which read only the Cloudflare header ----------------------


def test_a_session_opens_a_console_on_its_own_job(client, conn, monkeypatch,
                                                  no_identity, account):
    """This end never looked at a cookie, so Access removal would have killed it
    -- and killed it as a `ValueError` inside a socket handler, because
    `visible_to(None)` is refused rather than read as "see everything"."""
    for module in (console_router, jobs_router):
        monkeypatch.setattr(module, "settings", dataclasses.replace(
            module.settings, console_enabled=True))

    email, owner = account
    job_id = conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, owner)"
        " VALUES ('ubuntu', 'live.bin', 'executing', %s) RETURNING id",
        (owner,)).fetchone()[0]

    cookies = _sign_in(client, email)
    # Origin as well as the cookie. A real browser sends both, and the console
    # handshake is refused without one -- the Same-Origin Policy does not cover
    # WebSockets, so `Origin` is the only thing distinguishing this tab from a
    # page on another origin holding the same valid session. Same-origin with
    # TestClient's own base_url, which is what an unset CONSOLE_ALLOWED_ORIGINS
    # requires.
    with client.websocket_connect(f"/api/v1/jobs/{job_id}/console",
                                  cookies=cookies,
                                  headers={"origin": "http://testserver"}) as ws:
        assert ws is not None


def test_an_anonymous_caller_cannot_open_a_console(client, conn, monkeypatch,
                                                   no_identity, account):
    """Closed with a reason, not dropped: the far end is an interactive channel
    into a live malware VM, and a socket that dies silently is one nobody
    notices is open to the wrong person."""
    from starlette.websockets import WebSocketDisconnect

    for module in (console_router, jobs_router):
        monkeypatch.setattr(module, "settings", dataclasses.replace(
            module.settings, console_enabled=True))

    _, owner = account
    job_id = conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, owner)"
        " VALUES ('ubuntu', 'live.bin', 'executing', %s) RETURNING id",
        (owner,)).fetchone()[0]

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/api/v1/jobs/{job_id}/console") as ws:
            ws.receive_text()


# --- the misconfiguration that fails silently --------------------------------


def test_an_unset_audience_refuses_rather_than_minting_dead_tokens(monkeypatch):
    """**503, not a working login followed by anonymous requests.**

    `jwt.encode` writes `aud: ""` without complaint and `jwt.decode` then reports
    the claim as MISSING, so an unset `JWT_AUDIENCE` produced a deployment where
    signing in appeared to work and nothing after it did -- with no log line
    saying why, because from the reading side it is just an invalid token.
    """
    monkeypatch.setattr(
        credentials, "settings",
        dataclasses.replace(settings, jwt_signing_key="test-key",
                            jwt_issuer="sandbox.evilbootloader.com",
                            jwt_audience=""),
    )
    with pytest.raises(credentials.CredentialsUnconfigured):
        credentials.mint_access_token("some-tenant-id")
    with pytest.raises(credentials.CredentialsUnconfigured):
        credentials.decode_access_token("anything")
