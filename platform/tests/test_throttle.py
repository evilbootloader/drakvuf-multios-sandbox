"""Attempt counting, and the two ways it is easy to build one that never fires.

Both failures this module guards against LOOK implemented from the outside: the
code is present, the columns fill in, and nothing errors. What is missing is
that the counts survive the refusal they were meant to count.
"""

from __future__ import annotations

import dataclasses
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from conftest import credentialed_identity_id

from sandbox_platform import credentials, throttle
from sandbox_platform.routers import auth as auth_router
from sandbox_platform.config import settings

CSRF = {"X-Sandbox-Request": "1"}
PASSWORD = "correct horse battery staple"


@pytest.fixture(autouse=True)
def tight_limits(monkeypatch):
    """Small thresholds so a test is three requests rather than fifty."""
    # The router reads `trusted_client_ip_header`, and setting it lets each
    # test give itself a distinct address. Without that every request from
    # TestClient reports a peer of `testclient`, so the shared IP bucket fires
    # first and hides whatever the test was actually about.
    monkeypatch.setattr(
        auth_router, "settings",
        dataclasses.replace(settings, trusted_client_ip_header="X-Test-Client-IP"),
    )
    for module in (credentials, throttle):
        monkeypatch.setattr(
            module, "settings",
            dataclasses.replace(
                settings,
                jwt_signing_key="test-key",
                jwt_issuer="sandbox.evilbootloader.com",
                jwt_audience="sandbox-platform",
                attempts_per_window=3,
                lockout_threshold=3,
                lockout_duration_minutes=5,
                decay_window_minutes=5,
            ),
        )


def _addr():
    return f"throttle-{uuid.uuid4().hex[:12]}@example.test"


def _login(client, email, password="wrong", ip="198.51.100.1"):
    """One attempt, from a caller-chosen address.

    `ip` defaults to a single value so most tests share a bucket deliberately;
    a test isolating the per-ADDRESS bucket passes a distinct one.
    """
    return client.post("/api/v1/auth/login",
                       headers={**CSRF, "X-Test-Client-IP": ip},
                       json={"email": email, "password": password})


# --- the counter has to survive the refusal ---------------------------------


def test_failed_logins_are_counted(client, conn):
    """**The bug this exists to prevent:** counts rolled back by their own 401.

    `db.connection` commits on success and rolls back on error, so a refusal
    raised inside the block discards the increment that was meant to count it.
    The symptom is a limiter that never fires while looking entirely
    implemented -- measured once as an empty `rate_limit` table after six failed
    attempts.
    """
    email = _addr()
    for _ in range(3):
        _login(client, email)

    with conn.cursor() as cur:
        cur.execute("SELECT count FROM rate_limit WHERE bucket_key = %s",
                    (f"email:{email}",))
        row = cur.fetchone()

    assert row is not None, "no bucket at all -- the increments were rolled back"
    assert row[0] == 3


def test_the_limit_fires_after_the_configured_attempts(client, conn):
    email = _addr()
    codes = [_login(client, email).status_code for _ in range(6)]
    assert codes == [401, 401, 401, 429, 429, 429], codes


def test_a_rate_limited_response_carries_retry_after(client, conn):
    email = _addr()
    for _ in range(4):
        last = _login(client, email)
    assert last.status_code == 429
    assert "retry-after" in {k.lower() for k in last.headers}


# --- what the two buckets are for -------------------------------------------


def test_an_address_that_does_not_exist_is_counted_too(client, conn):
    """**This is what closes the enumeration divergence.**

    Counting only real accounts leaves a tell that no amount of identical error
    text hides: guesses at a real address eventually lock and return 429, while
    guesses at a fake one return 401 forever. An attacker does not read the
    body -- they watch which addresses change behaviour.

    Bucketing on the submitted address means both reach the limit at the same
    point, so the two stay identical over time as well as per request.
    """
    real, fake = _addr(), _addr()
    with conn.cursor() as cur:
        owner = credentialed_identity_id(cur, real)
        cur.execute(
            "INSERT INTO tenant_credentials (owner, hashed_password)"
            " VALUES (%s, %s)",
            (owner, credentials.hash_password(PASSWORD)),
        )

    # A separate address per sequence, so the shared IP bucket cannot fire
    # first and make both look identical for the wrong reason.
    real_codes = [_login(client, real, ip="203.0.113.1").status_code
                  for _ in range(5)]
    fake_codes = [_login(client, fake, ip="203.0.113.2").status_code
                  for _ in range(5)]

    assert real_codes == fake_codes, (real_codes, fake_codes)
    assert real_codes == [401, 401, 401, 429, 429], real_codes


def test_one_address_being_limited_does_not_lock_out_another(client, conn):
    """The address bucket must be per address, or one attacker denies service
    to every user at once."""
    victim, attacker = _addr(), _addr()
    for _ in range(5):
        _login(client, attacker, ip="203.0.113.3")

    # From a different address, so this proves the ADDRESS bucket is per
    # address rather than proving the IP bucket is per IP.
    assert _login(client, victim, ip="203.0.113.4").status_code == 401


# --- lockout ----------------------------------------------------------------


def test_a_failed_attempt_increments_the_account_counter(client, conn):
    email = _addr()
    with conn.cursor() as cur:
        owner = credentialed_identity_id(cur, email)
        cur.execute(
            "INSERT INTO tenant_credentials (owner, hashed_password)"
            " VALUES (%s, %s)",
            (owner, credentials.hash_password(PASSWORD)),
        )

    _login(client, email)

    with conn.cursor() as cur:
        cur.execute("SELECT failed_attempts FROM tenant_credentials"
                    " WHERE owner = %s", (owner,))
        assert cur.fetchone()[0] == 1


def test_a_successful_login_clears_the_counter_and_any_lockout(conn):
    """Proving the password is the only thing that should lift a lockout.

    Driven directly rather than through the route, because the route would hit
    the rate limit first -- the two mechanisms overlap at these thresholds and
    this test is about the account one.
    """
    email = _addr()
    with conn.cursor() as cur:
        owner = credentialed_identity_id(cur, email)
        cur.execute(
            "INSERT INTO tenant_credentials (owner, hashed_password,"
            " failed_attempts, locked_until)"
            " VALUES (%s, 'x', 4, now() + interval '5 minutes')",
            (owner,),
        )

    throttle.record_success(conn, owner)

    with conn.cursor() as cur:
        cur.execute("SELECT failed_attempts, locked_until, last_failed_at"
                    " FROM tenant_credentials WHERE owner = %s", (owner,))
        assert cur.fetchone() == (0, None, None)


def test_the_counter_decays(conn):
    """Without decay a counter only rises, and an account locks on its fifth
    lifetime typo rather than its fifth in five minutes."""
    email = _addr()
    with conn.cursor() as cur:
        owner = credentialed_identity_id(cur, email)
        cur.execute(
            "INSERT INTO tenant_credentials (owner, hashed_password,"
            " failed_attempts, last_failed_at)"
            " VALUES (%s, 'x', 2, now() - interval '1 hour')",
            (owner,),
        )

    throttle.record_failure(conn, owner)

    with conn.cursor() as cur:
        cur.execute("SELECT failed_attempts FROM tenant_credentials"
                    " WHERE owner = %s", (owner,))
        assert cur.fetchone()[0] == 1, "stale failures were not decayed"


def test_a_locked_account_is_refused(conn):
    email = _addr()
    with conn.cursor() as cur:
        owner = credentialed_identity_id(cur, email)
        cur.execute(
            "INSERT INTO tenant_credentials (owner, hashed_password, locked_until)"
            " VALUES (%s, 'x', now() + interval '5 minutes')",
            (owner,),
        )

    with pytest.raises(throttle.AccountLocked):
        throttle.assert_not_locked(conn, owner)


def test_a_lockout_that_has_passed_clears_itself(conn):
    """`locked_until` is a timestamp rather than a flag precisely so that
    nothing has to run to unlock an account."""
    email = _addr()
    with conn.cursor() as cur:
        owner = credentialed_identity_id(cur, email)
        cur.execute(
            "INSERT INTO tenant_credentials (owner, hashed_password, locked_until)"
            " VALUES (%s, 'x', now() - interval '1 second')",
            (owner,),
        )

    throttle.assert_not_locked(conn, owner)


def test_an_identity_with_no_credentials_row_is_not_locked(conn):
    """Raising here would distinguish "no such account" from "account exists",
    which is the tell the dummy-hash path pays argon2 to withhold."""
    with conn.cursor() as cur:
        owner = credentialed_identity_id(cur, _addr())

    throttle.assert_not_locked(conn, owner)


def test_recording_a_failure_for_an_unknown_address_does_nothing(conn):
    """`owner` is None when the address resolved to no identity.

    A no-op rather than an error: there is no row to count against, and creating
    one would invent an account. The per-address rate-limit bucket is what
    covers that case.
    """
    throttle.record_failure(conn, None)


# --- housekeeping -----------------------------------------------------------


def test_closed_windows_are_swept(conn):
    """One row per bucket per window, and a stuffing run mints one per address
    it tries -- so nothing reaping them is unbounded growth."""
    conn.execute(
        "INSERT INTO rate_limit (window_start, bucket_key, count)"
        " VALUES (now() - interval '1 day', 'email:ancient@example.test', 9)"
    )

    assert throttle.sweep_expired_windows(conn) >= 1

    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM rate_limit"
                    " WHERE bucket_key = 'email:ancient@example.test'")
        assert cur.fetchone()[0] == 0


# --- where a window begins --------------------------------------------------


def _window_at(monkeypatch, moment: datetime, minutes: int) -> datetime:
    """What `_current_window()` answers at `moment`, for this window length.

    The clock is frozen by substituting the `datetime` the module resolved,
    rather than by sleeping to a boundary: the defect under test is at the top
    of the hour, and a test that waited for one would take an hour to fail.
    A subclass so `fromtimestamp` still works -- `_current_window` uses both.
    """
    class _Frozen(datetime):
        @classmethod
        def now(cls, tz=None):
            return moment

    monkeypatch.setattr(throttle, "datetime", _Frozen)
    monkeypatch.setattr(
        throttle, "settings",
        dataclasses.replace(settings, window_length_minutes=minutes),
    )
    return throttle._current_window()


def test_windows_are_one_length_apart_across_an_hour_boundary(monkeypatch):
    """**The free counter reset, once an hour, on a schedule.**

    `floored.minute % minutes` truncates within the HOUR, so the count restarts
    at every `:00` and the last window of each hour is short. Measured at
    length 7: `:55 -> 10:49`, `:56 -> 10:56`, `:59 -> 10:56`, `:00 -> 11:00` --
    a four-minute window, so an attacker who has spent their attempts by 10:58
    is counting again at 11:00 rather than at 11:03.

    Asserted as the gap between consecutive distinct window starts rather than
    against a table of expected values, because the property is exactly that
    there is no boundary anywhere for the truncation to restart against.
    """
    minutes = 7
    base = datetime(2026, 9, 14, 10, 0, tzinfo=UTC)

    starts = sorted({
        _window_at(monkeypatch, base + timedelta(minutes=m), minutes)
        for m in range(0, 180)
    })
    gaps = {later - earlier for earlier, later in zip(starts, starts[1:])}

    assert gaps == {timedelta(minutes=minutes)}, gaps


def test_a_moment_falls_inside_the_window_it_is_given(monkeypatch):
    """The other half of the invariant: no gap, no overlap, seconds included."""
    minutes = 7
    length = timedelta(minutes=minutes)
    base = datetime(2026, 9, 14, 10, 30, tzinfo=UTC)

    for seconds in range(0, 3600, 17):
        at = base + timedelta(seconds=seconds)
        start = _window_at(monkeypatch, at, minutes)
        assert start <= at < start + length, (at, start)


def test_the_deployed_default_is_unchanged(monkeypatch):
    """5 divides 60, so epoch truncation and the hour truncation it replaces
    agree exactly -- which is why this defect was invisible on the deployment
    and why fixing it moves nothing there.

    Every length anyone had tried (1, 5, 10, 15, 30) divides an hour. 7, 8, 45
    and 90 do not, and nothing in `config.py` refuses them.
    """
    base = datetime(2026, 9, 14, 10, 0, tzinfo=UTC)

    for m in range(0, 65):
        at = base + timedelta(minutes=m, seconds=37)
        floored = at.replace(second=0, microsecond=0)
        hour_truncated = floored - timedelta(minutes=floored.minute % 5)
        assert _window_at(monkeypatch, at, 5) == hour_truncated, at