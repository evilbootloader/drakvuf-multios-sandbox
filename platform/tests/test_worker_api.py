"""The worker channel over HTTP.

Issue #36 (DRAFT-043).

The numbers are the real ones: 6294 MiB is a Windows clone
(misc/windows.cfg's memory = 6144 plus a per-host domain overhead), 2198 is
Ubuntu and Android, and 5082 is what was free on Dom0 during the 2026-08-20
starvation measurement.
"""

from __future__ import annotations

import uuid

import pytest

from conftest import WORKER_TOKEN, count_in_state, enqueue, state_of

WINDOWS_MIB = 6294
SMALL_MIB = 2198
FREE_MIB = 5082

REGISTRATION = {
    "total_mib": 12082,
    "total_vlans": 8,
    "total_slots": 2,
    "pipelines": [
        {"os": "ubuntu", "required_mib": SMALL_MIB},
        {"os": "android", "required_mib": SMALL_MIB},
        {"os": "windows", "required_mib": WINDOWS_MIB},
    ],
}


def claim(client, headers, free_mib=FREE_MIB):
    return client.post(
        "/api/v1/worker/claim",
        headers=headers,
        json={
            "free_mib": free_mib,
            "free_vlans": 6,
            "free_slots": 2,
        },
    )


# --- authentication -------------------------------------------------------

def test_worker_routes_require_a_token(client):
    r = client.post("/api/v1/worker/reconcile",
                    json={"live_job_ids": []})
    assert r.status_code == 401


def test_a_wrong_token_is_refused_the_same_way_as_a_missing_one(client):
    """**401 for both, deliberately.**

    It used to be 403 for a wrong token and 401 for none, which told a caller
    holding a guessed value whether it was a real credential that lacked
    permission or nothing at all. With per-worker tokens that distinction
    would leak which tokens exist, so both answer the same.
    """
    missing = client.post("/api/v1/worker/reconcile", json={"live_job_ids": []})
    wrong = client.post("/api/v1/worker/reconcile",
                        headers={"Authorization": "Bearer nope"},
                        json={"live_job_ids": []})

    assert missing.status_code == wrong.status_code == 401


def test_every_worker_route_is_authenticated(client):
    """Attached to the router, so this holds for routes added later too.

    The check that matters is not "these six are protected" but "nothing
    under this prefix is reachable unauthenticated" -- which is why the
    dependency is on the router rather than repeated per handler.
    """
    from sandbox_platform.routers.worker import router

    for route in router.routes:
        r = client.request(sorted(route.methods)[0],
                           route.path.replace("{job_id}", str(uuid.uuid4())),
                           json={})
        assert r.status_code in (401, 403), f"{route.path} answered {r.status_code}"


def test_healthz_is_deliberately_open(client):
    assert client.get("/healthz").status_code == 200


# --- the enum boundary ----------------------------------------------------

@pytest.mark.parametrize("bad", ["linux", "Windows", "../ubuntu", "", 7, None])
def test_target_os_is_closed_at_the_boundary(client, worker_headers, bad):
    """Issue #3: the OS token is the only untrusted routing input, validated
    against a closed set at one place. A 422 means the handler never ran."""
    body = dict(REGISTRATION)
    body["pipelines"] = [{"os": bad, "required_mib": 2048}]
    r = client.post("/api/v1/worker/register", headers=worker_headers, json=body)
    assert r.status_code == 422


# --- registration and claiming --------------------------------------------

def test_register_then_claim_idle(client, worker_headers):
    assert client.post("/api/v1/worker/register",
                       headers=worker_headers, json=REGISTRATION).status_code == 204
    assert claim(client, worker_headers).json() == {"status": "idle"}


def test_head_of_line_reservation_over_http(client, worker_headers, conn):
    """DRAFT-042's test 1, through the HTTP layer.

    The API must report `reserved` and hand out nothing -- not the twelve
    smaller jobs sitting behind the Windows one.
    """
    client.post("/api/v1/worker/register", headers=worker_headers, json=REGISTRATION)
    big = enqueue(conn, "windows", WINDOWS_MIB)
    for _ in range(12):
        enqueue(conn, "ubuntu", SMALL_MIB)

    body = claim(client, worker_headers, free_mib=FREE_MIB).json()

    assert body["status"] == "reserved"
    assert body["blocking_job_id"] == str(big)
    assert body["need_mib"] == WINDOWS_MIB
    assert count_in_state(conn, "queued") == 13


def test_the_head_is_leased_once_it_fits(client, worker_headers, conn):
    client.post("/api/v1/worker/register", headers=worker_headers, json=REGISTRATION)
    big = enqueue(conn, "windows", WINDOWS_MIB)
    for _ in range(12):
        enqueue(conn, "ubuntu", SMALL_MIB)

    body = claim(client, worker_headers, free_mib=WINDOWS_MIB).json()

    assert body["status"] == "leased"
    assert body["job_id"] == str(big)
    assert body["target_os"] == "windows"
    assert body["attempt"] == 1


# --- lease scoping --------------------------------------------------------

def test_a_worker_cannot_touch_another_workers_job(client, worker_headers,
                                                   other_worker_headers, conn):
    """**Impersonation now requires a second credential, which is the point.**

    This test used to change an `X-Worker-Id` header while keeping the shared
    token -- and it passed, because `lease_owner` was compared against whatever
    the caller typed. That comparison was scoping, not authorization: it stopped
    an honest worker making a mistake and stopped nothing else. Since DRAFT-061
    the id comes from the credential, so the only way to be another worker is to
    hold its token.
    """
    enqueue(conn, "ubuntu", SMALL_MIB)
    job_id = claim(client, worker_headers, free_mib=FREE_MIB).json()["job_id"]

    r = client.post(f"/api/v1/worker/jobs/{job_id}/heartbeat",
                    headers=other_worker_headers)

    # 404, not 403: a worker guessing ids must not learn which exist.
    assert r.status_code == 404


def test_an_unknown_job_is_indistinguishable_from_someone_elses(client, worker_headers):
    r = client.post(f"/api/v1/worker/jobs/{uuid.uuid4()}/heartbeat",
                    headers=worker_headers)
    assert r.status_code == 404


def test_an_unprovisioned_credential_is_refused(client, conn):
    """The successor to "the X-Worker-Id header is required".

    There is no id header to omit any more. What can go wrong instead is a
    token that names no worker -- one that was never issued, or was rotated
    away -- and that is a 401 rather than the 400 a missing header used to be:
    it is a credential problem, not a client bug.
    """
    enqueue(conn, "ubuntu", SMALL_MIB)
    r = client.post(f"/api/v1/worker/jobs/{uuid.uuid4()}/heartbeat",
                    headers={"Authorization": "Bearer never-issued"})
    assert r.status_code == 401


# --- state transitions ----------------------------------------------------

def test_the_happy_path_transitions(client, worker_headers, conn):
    enqueue(conn, "ubuntu", SMALL_MIB)
    job_id = claim(client, worker_headers, free_mib=FREE_MIB).json()["job_id"]

    for nxt in ("preparing", "executing", "collecting", "cleaning"):
        r = client.post(f"/api/v1/worker/jobs/{job_id}/state",
                        headers=worker_headers, json={"state": nxt})
        assert r.status_code == 204, (nxt, r.text)
        assert state_of(conn, uuid.UUID(job_id)) == nxt


def test_an_illegal_transition_is_refused(client, worker_headers, conn):
    """A worker that has lost track of itself must not rewrite history.

    Accepting this would make the state column a record of what was claimed
    rather than of what happened.
    """
    enqueue(conn, "ubuntu", SMALL_MIB)
    job_id = claim(client, worker_headers, free_mib=FREE_MIB).json()["job_id"]

    r = client.post(f"/api/v1/worker/jobs/{job_id}/state",
                    headers=worker_headers, json={"state": "completed"})

    assert r.status_code == 409
    assert "illegal transition" in r.json()["detail"]
    assert state_of(conn, uuid.UUID(job_id)) == "cloning"


def test_completed_is_reachable_only_through_cleaning(client, worker_headers, conn):
    """A job that has not torn its clone down has not finished."""
    enqueue(conn, "ubuntu", SMALL_MIB)
    job_id = claim(client, worker_headers, free_mib=FREE_MIB).json()["job_id"]

    # A VALID manifest, so 409 is the state rule talking and not the body
    # validator. `{}` used to serve here, and under DRAFT-018's model it is
    # rejected for a missing schema_version before the handler runs -- which
    # would have made this test pass for the wrong reason if it had asserted
    # only "not 204".
    early = client.post(f"/api/v1/worker/jobs/{job_id}/complete",
                        headers=worker_headers,
                        json={"manifest": {"schema_version": 1}})
    assert early.status_code == 409

    for nxt in ("preparing", "executing", "collecting", "cleaning"):
        client.post(f"/api/v1/worker/jobs/{job_id}/state",
                    headers=worker_headers, json={"state": nxt})

    ok = client.post(f"/api/v1/worker/jobs/{job_id}/complete",
                     headers=worker_headers,
                     json={"manifest": {
                         "schema_version": 1,
                         "artifacts": [{"name": "capture.pcap",
                                        "size_bytes": 0,
                                        "sha256": "e3b0c442" + "98fc1c14"
                                                  + "9afbf4c8" + "996fb924"
                                                  + "27ae41e4" + "649b934c"
                                                  + "a495991b" + "7852b855"}],
                     }})
    assert ok.status_code == 204
    assert state_of(conn, uuid.UUID(job_id)) == "completed"


def test_a_state_report_does_not_erase_earlier_diagnostics(client, worker_headers, conn):
    """A worker sends what it learned, not the whole row."""
    enqueue(conn, "ubuntu", SMALL_MIB)
    job_id = claim(client, worker_headers, free_mib=FREE_MIB).json()["job_id"]

    client.post(f"/api/v1/worker/jobs/{job_id}/state", headers=worker_headers,
                json={"state": "preparing", "clone_domain": "ubuntu_sandbox-1-clone",
                      "vlan": 1})
    client.post(f"/api/v1/worker/jobs/{job_id}/state", headers=worker_headers,
                json={"state": "executing"})

    with conn.cursor() as cur:
        cur.execute("SELECT clone_domain, vlan FROM jobs WHERE id = %s", (job_id,))
        assert cur.fetchone() == ("ubuntu_sandbox-1-clone", 1)


# --- cancellation ---------------------------------------------------------

def test_cancellation_arrives_in_the_heartbeat_response(client, worker_headers, conn):
    """The ONLY channel: Dom0 has no inbound listener, so there is nowhere to
    push to."""
    from sandbox_platform import jobs as dal

    enqueue(conn, "ubuntu", SMALL_MIB)
    job_id = claim(client, worker_headers, free_mib=FREE_MIB).json()["job_id"]

    before = client.post(f"/api/v1/worker/jobs/{job_id}/heartbeat",
                         headers=worker_headers).json()
    assert before["cancel_requested"] is False

    assert dal.cancel(conn, uuid.UUID(job_id)) == "cancel_requested"

    after = client.post(f"/api/v1/worker/jobs/{job_id}/heartbeat",
                        headers=worker_headers).json()
    assert after["cancel_requested"] is True
    # The state is untouched: the clone is still running until the worker
    # tears it down.
    assert state_of(conn, uuid.UUID(job_id)) == "cloning"


def test_heartbeat_extends_the_lease(client, worker_headers, conn):
    enqueue(conn, "ubuntu", SMALL_MIB)
    lease = claim(client, worker_headers, free_mib=FREE_MIB).json()
    beat = client.post(f"/api/v1/worker/jobs/{lease['job_id']}/heartbeat",
                       headers=worker_headers).json()
    assert beat["lease_expires_at"] >= lease["lease_expires_at"]


# --- recovery -------------------------------------------------------------

def test_reconcile_interrupts_only_unlisted_jobs(client, worker_headers, conn):
    for _ in range(2):
        enqueue(conn, "ubuntu", SMALL_MIB)
    a = claim(client, worker_headers, free_mib=FREE_MIB).json()["job_id"]
    b = claim(client, worker_headers, free_mib=FREE_MIB).json()["job_id"]

    r = client.post("/api/v1/worker/reconcile", headers=worker_headers,
                    json={"live_job_ids": [a]})

    assert r.json()["interrupted"] == [b]
    assert state_of(conn, uuid.UUID(a)) == "cloning"
    assert state_of(conn, uuid.UUID(b)) == "interrupted"


# --- artifact upload tickets ----------------------------------------------
#
# Issue #37. This route shipped with #36 and had no test at all, so neither
# the URLs it minted nor the traversal check it carried were ever exercised.

def leased_and_cleaning(client, headers, conn) -> str:
    """A job held by this worker and far enough along to have results."""
    enqueue(conn, "ubuntu", SMALL_MIB)
    job_id = claim(client, headers, free_mib=FREE_MIB).json()["job_id"]
    for nxt in ("preparing", "executing", "collecting", "cleaning"):
        client.post(f"/api/v1/worker/jobs/{job_id}/state",
                    headers=headers, json={"state": nxt})
    return job_id


def test_an_artifact_ticket_uploads_and_the_bytes_come_back(
        client, worker_headers, conn, read_object):
    """The whole loop against a real MinIO, including an EMPTY artifact.

    `capture.pcap` with no bytes is a real result -- it means the clone
    generated no traffic. The sample policy's range starts at 1, so reusing it
    here would have refused a legitimate result on the first run.

    Read back with credentials rather than through the ticket: a POST ticket is
    a write capability and cannot verify its own effect.
    """
    import httpx

    job_id = leased_and_cleaning(client, worker_headers, conn)
    bodies = {"trace.log": b"syscall trace\n", "capture.pcap": b"",
              "memdump/0x7ffd_rwx.bin": b"\x90" * 4096}

    tickets = client.post(
        f"/api/v1/worker/jobs/{job_id}/artifacts", headers=worker_headers,
        json={"artifacts": {n: len(b) for n, b in bodies.items()}},
    ).json()

    for name, body in bodies.items():
        up = httpx.post(tickets[name]["url"], data=tickets[name]["fields"],
                        files={"file": (name, body)})
        assert up.status_code in (200, 201, 204), (name, up.text[:400])

    for name, body in bodies.items():
        assert read_object(f"results/{job_id}/{name}") == body, name


def test_the_declared_size_binds_the_artifact_policy(
        client, worker_headers, conn):
    """A worker held to what it said, exactly as a browser is.

    Without this the ticket is an unbounded write primitive -- which is what
    the presigned PUT it replaced actually was.
    """
    import httpx

    job_id = leased_and_cleaning(client, worker_headers, conn)
    ticket = client.post(
        f"/api/v1/worker/jobs/{job_id}/artifacts", headers=worker_headers,
        json={"artifacts": {"trace.log": 10}},
    ).json()["trace.log"]

    over = httpx.post(ticket["url"], data=ticket["fields"],
                      files={"file": ("trace.log", b"x" * 2000)})

    assert over.status_code == 400
    assert "EntityTooLarge" in over.text


def test_an_oversized_declaration_never_gets_a_ticket(
        client, worker_headers, conn):
    """Refused before signing, so the transfer never starts."""
    from sandbox_platform.config import settings

    job_id = leased_and_cleaning(client, worker_headers, conn)
    r = client.post(
        f"/api/v1/worker/jobs/{job_id}/artifacts", headers=worker_headers,
        json={"artifacts": {"memdump/huge.bin": settings.max_artifact_bytes + 1}},
    )
    assert r.status_code == 413


@pytest.mark.parametrize("name", [
    "../../etc/passwd",          # the obvious one
    "/etc/passwd",               # absolute
    "memdump/../../../escape",   # traversal below a legitimate prefix
    "a//b",                      # empty component
    "trace.log/",                # trailing separator
    ".",                         # the prefix itself
    "..",
    "..\\..\\windows",           # backslash, ambiguous to a Windows reader
    "trace\x00.log",             # NUL: a truncation point in any C layer
    "trace\n.log",               # control character
    "",                          # empty
])
def test_an_artifact_name_cannot_leave_the_job_prefix(
        client, worker_headers, conn, name):
    """`extracted/` names come from what the SAMPLE dropped, so these are
    untrusted on the same footing as a submitted filename."""
    job_id = leased_and_cleaning(client, worker_headers, conn)
    r = client.post(
        f"/api/v1/worker/jobs/{job_id}/artifacts", headers=worker_headers,
        json={"artifacts": {name: 10}},
    )
    assert r.status_code == 422, (name, r.text[:200])


@pytest.mark.parametrize("name", [
    "50%off.exe",                 # percent-encoding is NOT traversal here
    "..%2f..%2fetc%2fpasswd",     # nor is it when it looks like traversal
    "extracted/a b c.dll",
    "extracted/dropped‮gnp.exe",
    "memdump/0x7ffd_rwx.bin",
    # XSS shapes, admitted on purpose -- escaping is the UI's job (DRAFT-045),
    # and these names come from files the sample dropped. The unclosed one has
    # no slash and so would pass even the stricter SAMPLE rule; the closed one
    # is admissible here and refused there, which is the intended difference
    # between the two validators.
    "extracted/<script>alert(1)",
    "extracted/<script>alert(1)</script>.dll",
])
def test_a_hostile_but_contained_artifact_name_is_admitted(
        client, worker_headers, conn, name):
    """Refuse structure, not characters.

    An S3 key is an opaque byte string that nothing resolves as a path, so
    `%2f` is a literal name and not a separator -- and a dropped file really
    can be called `50%off.exe`. Sanitising these would store the wrong
    evidence under a plausible name.
    """
    job_id = leased_and_cleaning(client, worker_headers, conn)
    r = client.post(
        f"/api/v1/worker/jobs/{job_id}/artifacts", headers=worker_headers,
        json={"artifacts": {name: 10}},
    )
    assert r.status_code == 200, (name, r.text[:200])
    assert r.json()[name]["fields"]["key"] == f"results/{job_id}/{name}"


def test_a_job_cannot_exceed_its_result_budget(client, worker_headers, conn):
    """One job cannot fill the store, and the bucket quota is not what stops it.

    Measured 2026-08-24: MinIO accepted 3 MiB into a 1 MiB quota and only
    refused ~45s later, because quotas are enforced against usage statistics a
    background scanner refreshes rather than at write time. `memdump` produces
    many small files and a worker may ask for tickets repeatedly, so without
    this a job's total was bounded by nothing prompt.

    Refused when the TICKET is minted -- the capability never exists, so the
    bytes never travel.
    """
    from sandbox_platform.config import settings

    job_id = leased_and_cleaning(client, worker_headers, conn)
    half = settings.max_job_result_bytes // 2

    first = client.post(
        f"/api/v1/worker/jobs/{job_id}/artifacts", headers=worker_headers,
        json={"artifacts": {"memdump/a.bin": half}})
    assert first.status_code == 200

    # Same size again: fits on its own, does not fit on top of the first.
    # The per-artifact cap cannot catch this, which is the whole point.
    second = client.post(
        f"/api/v1/worker/jobs/{job_id}/artifacts", headers=worker_headers,
        json={"artifacts": {"memdump/b.bin": half + 1}})
    assert second.status_code == 413

    assert conn.execute(
        "SELECT results_bytes FROM jobs WHERE id = %s", (job_id,)
    ).fetchone()[0] == half, "a refused request must not be charged"


def test_one_oversized_name_costs_the_job_nothing(client, worker_headers, conn):
    """A 413 must not spend the budget it refused to serve.

    The per-artifact ceiling used to be checked in the ticket-minting loop,
    AFTER the budget UPDATE had committed -- so a request naming one oversized
    file was charged for every name in it and then refused with no ticket
    minted. Reproduced before the fix: results_bytes 0 -> 2147483659 across a
    request that answered 413, out of a 4 GiB budget. Half a job's allowance
    gone, and nothing reclaims it: the budget is never reset, because a job_id
    is analysed once.

    `_collect` asks for tickets 64 names at a time and `memdump` routinely
    produces more than 64 files, so this is reachable by an ordinary run with
    one large region in a late batch -- not only by a hostile worker.

    Both halves are the regression: the row is untouched, and the job is still
    usable afterwards rather than poisoned for the rest of its collection.
    """
    from sandbox_platform.config import settings

    job_id = leased_and_cleaning(client, worker_headers, conn)

    def results_bytes():
        return conn.execute(
            "SELECT results_bytes FROM jobs WHERE id = %s", (job_id,)
        ).fetchone()[0]

    before = results_bytes()

    refused = client.post(
        f"/api/v1/worker/jobs/{job_id}/artifacts", headers=worker_headers,
        json={"artifacts": {
            "trace.log": 1000,
            "memdump/big.bin": settings.max_artifact_bytes + 1,
            "capture.pcap": 10,
        }})

    assert refused.status_code == 413
    # Named, so the worker learns WHICH file to stop offering. A bare "too
    # large" would leave it retrying the whole batch.
    assert "memdump/big.bin" in refused.json()["detail"]
    assert results_bytes() == before, "a refused request must not be charged"

    # The second half: the job still has its whole budget, so the artifacts
    # that would have fitted still do.
    ok = client.post(
        f"/api/v1/worker/jobs/{job_id}/artifacts", headers=worker_headers,
        json={"artifacts": {"trace.log": 1000, "capture.pcap": 10}})
    assert ok.status_code == 200, ok.text[:200]
    assert sorted(ok.json()) == ["capture.pcap", "trace.log"]
    assert results_bytes() == before + 1010


def test_the_budget_is_charged_across_requests(client, worker_headers, conn):
    """Accumulated, not per-call: max_length bounds names per request only."""
    job_id = leased_and_cleaning(client, worker_headers, conn)

    for _ in range(3):
        client.post(f"/api/v1/worker/jobs/{job_id}/artifacts",
                    headers=worker_headers,
                    json={"artifacts": {"extracted/x.bin": 1000}})

    assert conn.execute(
        "SELECT results_bytes FROM jobs WHERE id = %s", (job_id,)
    ).fetchone()[0] == 3000


def test_a_job_is_claimed_only_once(client, worker_headers, conn):
    """The budget needs no reset, and this is why.

    Nothing returns a claimed job to 'queued': `reap` marks an expired lease
    'interrupted' and leaves it for sandboxd's reconciliation to judge. A retry
    is a new job with a new id and its own results/<job_id>/ prefix.

    An earlier version of the budget reset `results_bytes` on re-claim and had
    a test that forced a job back to 'queued' by hand to prove it. That state
    is unreachable, so the test asserted behaviour production never produces --
    both are gone, and this stands in their place.
    """
    enqueue(conn, "ubuntu", SMALL_MIB)
    first = claim(client, worker_headers, free_mib=FREE_MIB).json()
    assert first["status"] == "leased"
    assert first["attempt"] == 1

    # Expire the lease and sweep it, the only route out of an in-flight state.
    conn.execute("UPDATE jobs SET lease_expires_at = now() - interval '1s'"
                 " WHERE id = %s", (first["job_id"],))
    from sandbox_platform import maintenance
    maintenance.sweep()

    assert state_of(conn, uuid.UUID(first["job_id"])) == "interrupted"
    assert claim(client, worker_headers, free_mib=FREE_MIB).json()["status"] \
        != "leased", "an interrupted job must not be handed out again"


# --- retention meets the queue --------------------------------------------

def test_a_sample_removed_before_the_claim_says_so_precisely(
        client, worker_headers, conn, remove_object):
    """A job queued past the retention window loses its sample.

    Issue #37. Both this and a post-admission swap make the ETag check fail,
    and until retention landed they shared one `failure_reason`. Reporting an
    expired sample as "changed after admission" sends whoever reads it hunting
    for a tamper that never happened -- so the two are kept apart.

    The job still fails CLOSED, which is the part that must not regress: a
    sample that cannot be verified is never handed to a worker.
    """
    job_id = enqueue(conn, "ubuntu", SMALL_MIB)
    remove_object(f"samples/{job_id}/ubuntu-{SMALL_MIB}.bin")

    claim_r = claim(client, worker_headers, free_mib=FREE_MIB).json()

    assert claim_r["status"] != "leased"
    assert state_of(conn, job_id) == "failed"
    reason = conn.execute(
        "SELECT failure_reason FROM jobs WHERE id = %s", (job_id,)
    ).fetchone()[0]
    assert reason == "sample_expired_or_removed"


# --- input hostility ------------------------------------------------------

@pytest.mark.parametrize("name", [
    '"; rm -rf ~ #', "$(whoami).sh", "`id`.bin", "'; DROP TABLE jobs; --",
    "<img src=x onerror=alert(1)>.exe", "a b\tc.exe", "‮exe.txt",
    "<script>alert(1)", "<!--",   # unclosed: no slash, so admissible
])
def test_hostile_filenames_survive_the_http_layer(client, worker_headers, conn, name):
    """Byte-exact from the database, through JSON, to the worker.

    The name must reach the guest unchanged -- DRAFT-030's reason for
    abandoning hash-named guest files. Serialisation must not normalise it.

    `/`-free since 2026-08-24: submission refuses separators, so a name
    carrying one can no longer reach this table through the API and testing it
    here would assert something about a state production cannot produce. The
    tab and the RTL override stay -- both are admissible and both are exactly
    what a careless downstream parser mishandles.
    """
    enqueue(conn, "windows", WINDOWS_MIB, filename=name)
    body = claim(client, worker_headers, free_mib=WINDOWS_MIB).json()
    assert body["submitted_filename"] == name