"""Cloudflare Access identity on the browser routes.

Issue #36 / #47. Before this, anything that reached the API could read,
cancel and stream every job -- Access at the edge was the only gate and the
API had no way to know who was calling.

The property under test is that the signature is **verified**, not merely
decoded. `Cf-Access-Jwt-Assertion` is attacker-controlled on any path that
does not traverse Cloudflare, so a check that trusts its claims is
authentication by assertion. Each test below forges a token that would pass
such a check.
"""

from __future__ import annotations

import dataclasses
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sandbox_platform import auth
from sandbox_platform.config import settings

TEAM = "https://testteam.cloudflareaccess.com"
AUD = "0123456789abcdef"
KID = "test-key-1"


def configure(monkeypatch, **overrides):
    """Swap auth.py's settings for a copy with these fields changed."""
    monkeypatch.setattr(auth, "settings",
                        dataclasses.replace(settings, **overrides))


@pytest.fixture
def issuer(monkeypatch):
    """A local RSA key standing in for Cloudflare's, served to the verifier.

    Patching `_signing_key` rather than the HTTP fetch keeps the test about
    signature verification instead of about httpx.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Settings is frozen, so replace the object auth.py resolved rather than
    # mutating it -- which is also closer to how deployment differs: two
    # listeners, two environments, one immutable snapshot each.
    configure(monkeypatch, require_access_jwt=True,
              access_team_domain=TEAM, access_aud=AUD)
    monkeypatch.setattr(auth, "_signing_key", lambda _t: key.public_key())

    def mint(private_key=key, **overrides):
        claims = {
            "aud": AUD, "iss": TEAM, "email": "analyst@example.test",
            "exp": int(time.time()) + 600, "iat": int(time.time()),
        }
        claims.update(overrides)
        pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return jwt.encode(claims, pem, algorithm="RS256",
                          headers={"kid": KID})

    mint.key = key
    return mint


# --- the happy path --------------------------------------------------------

def test_a_valid_token_yields_the_email(issuer):
    assert auth.access_identity(issuer()) == "analyst@example.test"


def test_a_service_token_is_recorded_as_a_machine(issuer):
    """Service tokens carry `common_name`, not an email. Accepted, and stored
    as what they are rather than silently becoming an empty owner."""
    token = issuer(email=None, common_name="dom0-batch")
    assert auth.access_identity(token) == "service:dom0-batch"


# --- forgery ---------------------------------------------------------------

def test_a_token_signed_by_a_different_key_is_refused(issuer):
    """The whole point. This token is well-formed, unexpired, has the right
    audience and issuer -- and is signed by someone else."""
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = issuer(private_key=attacker)

    with pytest.raises(Exception) as exc:
        auth.access_identity(forged)
    assert exc.value.status_code == 401


def test_an_unsigned_token_is_refused(issuer):
    """`alg: none` is the classic JWT bypass. PyJWT is told RS256 only, and
    this asserts that rather than trusting the default."""
    unsigned = jwt.encode(
        {"aud": AUD, "iss": TEAM, "email": "attacker@example.test",
         "exp": int(time.time()) + 600},
        key="", algorithm="none",
    )
    with pytest.raises(Exception) as exc:
        auth.access_identity(unsigned)
    assert exc.value.status_code == 401


def test_a_token_for_another_application_is_refused(issuer):
    """Without the `aud` check, a valid token for ANY Access application in
    the account would authenticate here -- including one protecting something
    unrelated with a much looser policy."""
    with pytest.raises(Exception) as exc:
        auth.access_identity(issuer(aud="some-other-application"))
    assert exc.value.status_code == 401


def test_an_expired_token_is_refused(issuer):
    with pytest.raises(Exception) as exc:
        auth.access_identity(issuer(exp=int(time.time()) - 60))
    assert exc.value.status_code == 401


# --- configuration ---------------------------------------------------------

def test_no_token_is_refused_when_required(issuer):
    with pytest.raises(Exception) as exc:
        auth.access_identity(None)
    assert exc.value.status_code == 401


def test_identity_is_none_when_not_required(monkeypatch):
    """The mTLS listener does not set REQUIRE_ACCESS_JWT: a client
    certificate already gated it at the TLS layer, and demanding a browser
    session there would lock out Dom0 and the command-line tools."""
    configure(monkeypatch, require_access_jwt=False)
    assert auth.access_identity(None) is None


def test_misconfiguration_refuses_rather_than_falls_through(monkeypatch, issuer):
    """Requiring a token with no AUD configured must not degrade into
    accepting tokens unverified. It fails closed, loudly."""
    configure(monkeypatch, require_access_jwt=True,
              access_team_domain=TEAM, access_aud="")

    with pytest.raises(Exception) as exc:
        auth.access_identity(issuer())
    assert exc.value.status_code == 500