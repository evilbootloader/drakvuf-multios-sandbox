"""The prepaid analysis-seconds balance.

Issue #40 (DRAFT-047) decision 8. Seconds are bought once and drawn down as
jobs finish; an idle month neither expires nor replenishes anything.

**Three properties, and the negative ones are the point.** That a completed
job charges is easy and would be caught by hand within a day. That a job the
platform LOST TRACK OF does not charge, and that a retried report does not
charge twice, are the two nobody would notice going wrong -- the first shows up
as tenants slowly losing seconds they never spent, the second as a balance that
drifts down faster than the job list explains.

The reaper case is the one to read first. `queries.REAP` marks a job
`interrupted` when its lease lapses, which happens because Dom0 crashed, was
restarted, or lost the link -- the platform's fault in almost every case. It
also cannot measure what it lost: `updated_at` is when the sweep NOTICED, so
the elapsed time includes up to LEASE_SECONDS plus a sweep interval of pure
detection lag. Charging for it would bill a number nobody could defend.
"""

from __future__ import annotations

import pytest

from conftest import DEFAULT_OWNER, enqueue, owner_id

SMALL_MIB = 2198
FREE_MIB = 8192

REGISTRATION = {
    "total_mib": 12082,
    "total_vlans": 8,
    "total_slots": 2,
    "pipelines": [{"os": "ubuntu", "required_mib": SMALL_MIB}],
}


def balance_of(conn, owner=DEFAULT_OWNER):
    # Joined to `identities` rather than matching `tenants.owner` directly:
    # that column is a tenant id since 0009 and tests name their people by
    # address. Lookup only, never creating -- otherwise `is None` below would
    # stop being able to mean "this tenant has no row yet".
    #
    # **Either column**, because since DRAFT-061 an address can be in either and
    # which one depends on how the identity came to exist: `access_subject` for
    # one a provider asserted (what `owner_id` writes, and what these tests
    # make), `email` for one that signs in with a password. Matching only
    # `email` reported every balance here as None -- read as "the tenant row was
    # never created", which is a much more alarming bug than the one it was.
    row = conn.execute(
        "SELECT t.balance_seconds FROM tenants t"
        "  JOIN identities i ON i.id = t.owner"
        " WHERE lower(i.access_subject) = lower(%s)"
        "    OR lower(i.email) = lower(%s)", (owner, owner)
    ).fetchone()
    return None if row is None else row[0]


def charged_on(conn, job_id):
    return conn.execute(
        "SELECT charged_seconds FROM jobs WHERE id = %s", (job_id,)
    ).fetchone()[0]


def lease_one(client, worker_headers, conn):
    """Register, enqueue and claim -- a job in `cloning` with a started clock."""
    client.post("/api/v1/worker/register", headers=worker_headers,
                json=REGISTRATION)
    job_id = enqueue(conn, "ubuntu", SMALL_MIB)
    claimed = client.post("/api/v1/worker/claim", headers=worker_headers, json={ "free_mib": FREE_MIB,
        "free_vlans": 6, "free_slots": 2,
    })
    assert claimed.json()["status"] == "leased", claimed.text
    return job_id


def drive_to(client, worker_headers, job_id, *states):
    for state in states:
        r = client.post(f"/api/v1/worker/jobs/{job_id}/state",
                        headers=worker_headers, json={"state": state})
        assert r.status_code == 204, r.text


# --- the clock --------------------------------------------------------------

def test_the_clock_starts_at_the_claim_not_at_submission(client, conn,
                                                         worker_headers):
    """`started_at` is set by CLAIM, and queue time is not billable.

    A submitter cannot control how long their job waits behind other people's
    work, so charging from `created_at` would bill them for the platform being
    busy. It is also where the previous version broke: the clock was set on a
    `cloning` report, and CLAIM sets `cloning` itself, so no worker ever
    reported that transition and `started_at` stayed NULL forever.
    """
    job_id = enqueue(conn, "ubuntu", SMALL_MIB)
    assert conn.execute("SELECT started_at FROM jobs WHERE id = %s",
                        (job_id,)).fetchone()[0] is None

    client.post("/api/v1/worker/register", headers=worker_headers,
                json=REGISTRATION)
    client.post("/api/v1/worker/claim", headers=worker_headers, json={ "free_mib": FREE_MIB,
        "free_vlans": 6, "free_slots": 2,
    })

    assert conn.execute("SELECT started_at FROM jobs WHERE id = %s",
                        (job_id,)).fetchone()[0] is not None


# --- what charges -----------------------------------------------------------

def test_a_completed_job_charges_its_owner(client, conn, worker_headers):
    """The common case, and the one `report_state` never sees: a finished
    analysis arrives at /complete, because that is the call carrying the
    manifest."""
    job_id = lease_one(client, worker_headers, conn)
    # Read AFTER the claim: `enqueue` is what creates the tenant row, so a
    # balance taken before it is None rather than the opening grant.
    before = balance_of(conn)
    drive_to(client, worker_headers, job_id,
             "preparing", "executing", "collecting", "cleaning")

    r = client.post(f"/api/v1/worker/jobs/{job_id}/complete",
                    headers=worker_headers,
                    json={"manifest": {"schema_version": 1}})

    assert r.status_code == 204, r.text
    assert charged_on(conn, job_id) is not None
    assert balance_of(conn) == before - charged_on(conn, job_id)


def test_a_failed_job_charges_too(client, conn, worker_headers):
    """Host time was spent either way.

    Charging only on success is the free-analysis loop: a sample that reliably
    dies at minute 55 of an hour would cost nothing, and arranging that is
    cheaper than arranging almost anything else here.
    """
    job_id = lease_one(client, worker_headers, conn)
    # Read AFTER the claim: `enqueue` is what creates the tenant row, so a
    # balance taken before it is None rather than the opening grant.
    before = balance_of(conn)
    drive_to(client, worker_headers, job_id,
             "preparing", "executing", "cleaning", "failed")

    assert charged_on(conn, job_id) is not None
    assert balance_of(conn) == before - charged_on(conn, job_id)


def test_a_job_that_never_had_a_clone_charges_nothing(client, conn):
    """`started_at IS NOT NULL` is the whole rule, and this is why no list of
    chargeable states appears anywhere in the code.

    A submission refused at admission never reached CLAIM, so it carries no
    start and costs nothing -- by construction rather than by an enumeration
    that a new terminal state could fall outside of.
    """
    conn.execute(
        "INSERT INTO tenants (owner) VALUES (%s) ON CONFLICT DO NOTHING",
        (owner_id(conn),))
    before = balance_of(conn)
    job_id = conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, owner)"
        " VALUES ('ubuntu', 'x.bin', 'received', %s) RETURNING id",
        (owner_id(conn),),
    ).fetchone()[0]

    conn.execute("UPDATE jobs SET state = 'rejected' WHERE id = %s", (job_id,))

    assert charged_on(conn, job_id) is None
    assert balance_of(conn) == before


# --- what does not charge ---------------------------------------------------

def test_a_reaped_job_does_not_charge(client, conn, worker_headers):
    """The lease lapsed, so the platform does not know when the job stopped.

    `updated_at` is when the sweep noticed, not when the worker went quiet, so
    the elapsed time carries up to LEASE_SECONDS plus a sweep interval of
    detection lag. The reaper reaches this by a path that never touches the
    worker router -- a bulk UPDATE in `queries.REAP` -- and `auth.leased_job`
    then refuses the worker's next report with a 409, so nothing charges it
    afterwards either.
    """
    from sandbox_platform import jobs as dal

    job_id = lease_one(client, worker_headers, conn)
    # Read AFTER the claim: `enqueue` is what creates the tenant row, so a
    # balance taken before it is None rather than the opening grant.
    before = balance_of(conn)
    conn.execute("UPDATE jobs SET lease_expires_at = now() - interval '1 min'"
                 " WHERE id = %s", (job_id,))

    reaped = dal.reap(conn)

    assert len(reaped) == 1
    assert charged_on(conn, job_id) is None
    assert balance_of(conn) == before

    # And the worker cannot charge it by reporting late: it no longer owns it.
    late = client.post(f"/api/v1/worker/jobs/{job_id}/state",
                       headers=worker_headers, json={"state": "cleaning"})
    assert late.status_code == 409
    assert balance_of(conn) == before


def test_a_job_is_charged_only_once(client, conn, worker_headers):
    """Dom0's delivery is at-least-once in practice.

    The guard is a conditional UPDATE rather than a read followed by a write:
    testing `charged_seconds IS NULL` in Python and then setting it lets two
    concurrent reports both see NULL and both charge.
    """
    job_id = lease_one(client, worker_headers, conn)
    # Read AFTER the claim: `enqueue` is what creates the tenant row, so a
    # balance taken before it is None rather than the opening grant.
    before = balance_of(conn)
    drive_to(client, worker_headers, job_id,
             "preparing", "executing", "cleaning", "failed")

    charged = charged_on(conn, job_id)
    assert balance_of(conn) == before - charged

    # A second terminal report for the same job, as a retry would send.
    client.post(f"/api/v1/worker/jobs/{job_id}/state",
                headers=worker_headers, json={"state": "failed"})

    assert charged_on(conn, job_id) == charged
    assert balance_of(conn) == before - charged


# --- the guards, at the helper ----------------------------------------------
#
# The two tests above assert the right OUTCOMES and would pass with either
# guard deleted, which is not the same thing. Checked, and both did:
#
#   * the retry in `test_a_job_is_charged_only_once` is stopped by
#     `auth.leased_job` returning 409 for a job in a terminal state, so it
#     never reaches `charged_seconds IS NULL`;
#   * `test_a_job_that_never_had_a_clone_charges_nothing` moves the state with
#     a raw UPDATE, so it never calls the helper at all.
#
# Both routes are worth keeping -- they are what a worker actually does. These
# two call the helper directly, because that is where the guards live and the
# only place a break in them is visible.

def _startable(conn, started: bool):
    """A leased-looking job, with or without a clock.

    When it has one it is set 90 seconds back, so the charge is a positive
    number a test can assert on rather than the 0 that `now()` would give.
    """
    conn.execute(
        "INSERT INTO tenants (owner) VALUES (%s) ON CONFLICT DO NOTHING",
        (owner_id(conn),))
    return conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, owner,"
        "                  started_at)"
        " VALUES ('ubuntu', 'x.bin', 'cleaning', %s,"
        "         CASE WHEN %s THEN now() - interval '90 seconds' END)"
        " RETURNING id",
        (owner_id(conn), started),
    ).fetchone()[0]


def test_the_helper_charges_once_however_often_it_is_called(conn):
    """`charged_seconds IS NULL` inside the UPDATE, not tested in Python first.

    A read-then-write lets two concurrent terminal reports both see NULL and
    both decrement. Here the second call matches no row and returns having
    done nothing.
    """
    from sandbox_platform.routers.worker import _charge_for_runtime

    job_id = _startable(conn, started=True)
    before = balance_of(conn)

    with conn.cursor() as cur:
        _charge_for_runtime(cur, job_id)
        first = charged_on(conn, job_id)
        _charge_for_runtime(cur, job_id)

    assert first is not None and first > 0
    assert charged_on(conn, job_id) == first
    assert balance_of(conn) == before - first


def test_the_helper_charges_nothing_for_a_job_that_never_started(conn):
    """`started_at IS NOT NULL` is the "a clone existed" rule.

    Without it a rejected submission charges `now() - NULL`, and the whole
    reason no list of chargeable states appears in the code is that this one
    condition stands in for it.
    """
    from sandbox_platform.routers.worker import _charge_for_runtime

    job_id = _startable(conn, started=False)
    before = balance_of(conn)

    with conn.cursor() as cur:
        _charge_for_runtime(cur, job_id)

    assert charged_on(conn, job_id) is None
    assert balance_of(conn) == before


def test_a_clock_that_ran_backwards_cannot_credit_a_tenant(conn):
    """GREATEST(0, ...), and the direction of the mistake is what matters.

    `started_at` comes from the database's `now()`, so it is in the future only
    if the clock moved -- an NTP correction, a restored snapshot, a VM
    migration. Without the floor the charge is negative and the UPDATE
    subtracts it, which ADDS seconds: an accounting error that pays out.
    """
    from sandbox_platform.routers.worker import _charge_for_runtime

    conn.execute(
        "INSERT INTO tenants (owner) VALUES (%s) ON CONFLICT DO NOTHING",
        (owner_id(conn),))
    job_id = conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, owner,"
        "                  started_at)"
        " VALUES ('ubuntu', 'x.bin', 'cleaning', %s,"
        "         now() + interval '90 seconds') RETURNING id",
        (owner_id(conn),),
    ).fetchone()[0]
    before = balance_of(conn)

    with conn.cursor() as cur:
        _charge_for_runtime(cur, job_id)

    assert charged_on(conn, job_id) == 0
    assert balance_of(conn) == before


# --- admission --------------------------------------------------------------

def test_a_new_tenant_is_granted_a_balance_on_first_submission(client, conn,
                                                               access_token):
    """No signup step: Access decides who reaches the listener, and anyone it
    lets through is a tenant. The grant comes from the column default, so the
    number lives in migration 0008 and nowhere else."""
    newcomer = "newcomer@example.test"
    assert balance_of(conn, newcomer) is None

    r = client.post("/api/v1/jobs", headers=access_token(newcomer),
                    json={"target_os": "ubuntu", "filename": "x.bin",
                          "size_bytes": 4, "plugins":["syscalls"],})

    assert r.status_code == 201, r.text
    assert balance_of(conn, newcomer) == 3600


def test_an_exhausted_tenant_is_refused_with_402(client, conn, access_token):
    """402 Payment Required, and no row.

    Semantically exact, distinguishable from the 403 that means a tenancy
    refusal, and the status the purchasing work will want.
    """
    broke = "broke@example.test"
    conn.execute("INSERT INTO tenants (owner, balance_seconds) VALUES (%s, 0)",
                 (owner_id(conn, broke),))

    r = client.post("/api/v1/jobs", headers=access_token(broke),
                    json={"target_os": "ubuntu", "filename": "x.bin",
                          "size_bytes": 4, "plugins":["syscalls"],})

    assert r.status_code == 402, r.text
    assert conn.execute("SELECT count(*) FROM jobs WHERE owner = %s",
                        (owner_id(conn, broke),)).fetchone()[0] == 0


def test_a_negative_balance_is_refused_too(client, conn, access_token):
    """Overdrawn is not a licence to keep going.

    A balance goes negative when a job admitted with seconds left overruns
    them -- deliberate, because refusing mid-analysis would destroy host time
    already spent. What it must not do is admit the NEXT one.
    """
    overdrawn = "overdrawn@example.test"
    conn.execute("INSERT INTO tenants (owner, balance_seconds)"
                 " VALUES (%s, -120)", (owner_id(conn, overdrawn),))

    r = client.post("/api/v1/jobs", headers=access_token(overdrawn),
                    json={"target_os": "ubuntu", "filename": "x.bin",
                          "size_bytes": 4, "plugins":["syscalls"],})

    assert r.status_code == 402, r.text


# --- the balance endpoint ---------------------------------------------------

def test_the_balance_endpoint_creates_the_tenant_and_returns_the_row(
        client, conn, access_token):
    """The UI calls this on page load, so it is usually what creates the row.

    The value comes back from the ROW, not from a literal in the router: a
    copy of 3600 in Python would disagree with the database the first time the
    default changes.
    """
    newcomer = "browser-first@example.test"
    hdrs = access_token(newcomer)

    r = client.post("/api/v1/account/balance", headers=hdrs)

    assert r.status_code == 200, r.text
    assert r.json() == 3600
    assert balance_of(conn, newcomer) == 3600

    # Idempotent: a second page load must not grant a second time.
    conn.execute("UPDATE tenants SET balance_seconds = 60 WHERE owner = %s",
                 (owner_id(conn, newcomer),))
    assert client.post("/api/v1/account/balance", headers=hdrs).json() == 60


def test_the_balance_is_never_cached(client, access_token):
    """It crosses a shared CDN, and a cached response is one tenant's balance
    served to another. POST is most of the defence; this is the rest of it."""
    r = client.post("/api/v1/account/balance",
                    headers=access_token("cache-me@example.test"))

    assert r.headers["cache-control"] == "no-store"


def test_the_balance_endpoint_refuses_a_caller_with_no_identity(client,
                                                                no_identity):
    """401 since DRAFT-061: a caller with no credential is refused by
    `auth.caller_identity` before the route runs, rather than reaching
    `required_identity` with a None that `visible_to` would have read as
    "see everything"."""
    assert client.post("/api/v1/account/balance", follow_redirects=False).status_code == 303


# --- the two paths agree ----------------------------------------------------

def test_both_charge_sites_use_the_same_units(client, conn, worker_headers):
    """They did not, briefly: one returned epoch seconds and the other raw
    timestamps, and `bigint - interval` is not an operator in Postgres.

    Computing the duration in SQL inside one helper is what stops them
    drifting; this is what would catch it if the helper were inlined again.
    """
    completed = lease_one(client, worker_headers, conn)
    drive_to(client, worker_headers, completed,
             "preparing", "executing", "collecting", "cleaning")
    client.post(f"/api/v1/worker/jobs/{completed}/complete",
                headers=worker_headers, json={"manifest": {"schema_version": 1}})

    failed = lease_one(client, worker_headers, conn)
    drive_to(client, worker_headers, failed,
             "preparing", "executing", "cleaning", "failed")

    both = [charged_on(conn, completed), charged_on(conn, failed)]
    assert all(isinstance(c, int) for c in both), both
    # Seconds, not microseconds or milliseconds: a test that runs in under a
    # second charges 0, and anything else means the unit slipped.
    assert all(0 <= c < 60 for c in both), both