"""The certificates issued by tls/issue-cert.sh actually enforce what they claim.

Issue #46 (DRAFT-046).

**The negative cases are the point.** A server that accepts any certificate
passes every positive test, so "the client connected" proves nothing on its
own. Each check here has a matching failure that must occur.

Self-contained: a throwaway CA is built per test session in a temporary
directory, so nothing here touches the real CA -- which by design is not on
any machine that runs tests.
"""

from __future__ import annotations

import socket
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ISSUE = REPO_ROOT / "tls" / "issue-cert.sh"


def _issue(ca_dir: Path, *args: str) -> None:
    subprocess.run(
        [str(ISSUE), *args],
        env={"PATH": "/usr/bin:/bin", "CA_DIR": str(ca_dir), "CA_ALLOW_HERE": "1"},
        check=True,
        capture_output=True,
    )


@pytest.fixture(scope="session")
def ca(tmp_path_factory) -> Path:
    """A CA with a server certificate and a client certificate."""
    d = tmp_path_factory.mktemp("ca")
    _issue(d, "init")
    _issue(d, "server", "api", "127.0.0.1", "platform.lan")
    _issue(d, "client", "dom0-lab")
    return d


@pytest.fixture(scope="session")
def foreign_ca(tmp_path_factory) -> Path:
    """A second, unrelated CA.

    Without this, the 'no client certificate' test passes against a server
    that accepts *any* certificate -- which is the failure mode that matters,
    because it looks exactly like working mTLS.
    """
    d = tmp_path_factory.mktemp("foreign-ca")
    _issue(d, "init")
    _issue(d, "client", "impostor")
    return d


@pytest.fixture
def mtls_server(ca):
    """A TLS listener that requires a client certificate from `ca`."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2      # decision 8, pinned
    ctx.load_cert_chain(ca / "api.crt", ca / "api.key")
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(ca / "ca.crt")

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                raw, _ = sock.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(raw, server_side=True) as tls:
                    tls.send(b"ok")
            except (ssl.SSLError, OSError):
                pass          # a refused handshake is the expected result here

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield port
    stop.set()
    sock.close()


def _client_ctx(ca_cert: Path, cert: Path | None = None, key: Path | None = None):
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if cert:
        ctx.load_cert_chain(cert, key)
    return ctx


def _connect(port: int, ctx: ssl.SSLContext, server_hostname="127.0.0.1"):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_hostname) as tls:
            return tls.recv(2), tls.version(), tls.cipher()


# --- positive -------------------------------------------------------------

def test_a_valid_client_certificate_connects(ca, mtls_server):
    data, _, _ = _connect(
        mtls_server, _client_ctx(ca / "ca.crt", ca / "dom0-lab.crt", ca / "dom0-lab.key")
    )
    assert data == b"ok"


def test_the_certificate_covers_the_ip_with_hostname_checking_on(ca, mtls_server):
    """SAN, not CN. A certificate carrying the address only in the common name
    fails here, with an error that does not say why."""
    ctx = _client_ctx(ca / "ca.crt", ca / "dom0-lab.crt", ca / "dom0-lab.key")
    assert ctx.check_hostname is True
    _connect(mtls_server, ctx, server_hostname="127.0.0.1")


def test_the_key_exchange_is_ephemeral(ca, mtls_server):
    """Forward secrecy, without a dhparam file.

    TLS 1.3 removed static RSA key exchange from the protocol, so this is a
    property of the version rather than of configuration. Asserted because
    "we get forward secrecy for free" is exactly the sort of claim that stops
    being true quietly.
    """
    _, version, cipher = _connect(
        mtls_server, _client_ctx(ca / "ca.crt", ca / "dom0-lab.crt", ca / "dom0-lab.key")
    )
    assert version in ("TLSv1.2", "TLSv1.3")
    if version == "TLSv1.3":
        assert cipher[0].startswith("TLS_")     # 1.3 suites are ephemeral by definition
    else:
        assert "ECDHE" in cipher[0], cipher


# --- negative: the ones that prove it is doing anything -------------------

def test_no_client_certificate_is_refused(ca, mtls_server):
    """Refused at the TLS layer, before any application code runs."""
    with pytest.raises(ssl.SSLError):
        _connect(mtls_server, _client_ctx(ca / "ca.crt"))


def test_a_certificate_from_another_ca_is_refused(ca, foreign_ca, mtls_server):
    """The check that gives the previous test its meaning."""
    ctx = _client_ctx(
        ca / "ca.crt", foreign_ca / "impostor.crt", foreign_ca / "impostor.key"
    )
    with pytest.raises(ssl.SSLError):
        _connect(mtls_server, ctx)


def test_a_client_not_trusting_the_ca_is_refused(ca, foreign_ca, mtls_server):
    """The other direction: the client must verify the server too."""
    ctx = _client_ctx(
        foreign_ca / "ca.crt", ca / "dom0-lab.crt", ca / "dom0-lab.key"
    )
    with pytest.raises(ssl.SSLCertVerificationError):
        _connect(mtls_server, ctx)


# --- certificate shape ----------------------------------------------------

def _text(path: Path) -> str:
    return subprocess.run(
        ["openssl", "x509", "-in", str(path), "-noout", "-text"],
        check=True, capture_output=True, text=True,
    ).stdout


def test_server_and_client_certificates_have_disjoint_key_usage(ca):
    """A certificate valid for both roles could authenticate *to* the service
    it also identifies, which defeats having two kinds."""
    server, client = _text(ca / "api.crt"), _text(ca / "dom0-lab.crt")
    assert "TLS Web Server Authentication" in server
    assert "TLS Web Client Authentication" not in server
    assert "TLS Web Client Authentication" in client
    assert "TLS Web Server Authentication" not in client


def test_the_ca_cannot_sign_another_ca(ca):
    """pathlen:0 -- nothing here needs a chain, and forbidding one removes a
    class of mistake rather than documenting it."""
    assert "CA:TRUE, pathlen:0" in _text(ca / "ca.crt")


def test_leaf_certificates_are_not_cas(ca):
    for leaf in ("api.crt", "dom0-lab.crt"):
        assert "CA:FALSE" in _text(ca / leaf), leaf


def test_private_keys_are_not_world_readable(ca):
    """A readable key in a container running a web service makes everything
    above it ornamental."""
    for key in ca.glob("*.key"):
        assert oct(key.stat().st_mode)[-3:] == "600", key