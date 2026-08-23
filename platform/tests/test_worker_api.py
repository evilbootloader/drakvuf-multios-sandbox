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
    "worker_id": "test-worker",
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
            "worker_id": headers["X-Worker-Id"],
            "free_mib": free_mib,
            "free_vlans": 6,
            "free_slots": 2,
        },
    )


# --- authentication -------------------------------------------------------

def test_worker_routes_require_a_token(client):
    r = client.post("/api/v1/worker/reconcile",
                    json={"worker_id": "w", "live_job_ids": []})
    assert r.status_code == 401


def test_a_wrong_token_is_forbidden(client):
    r = client.post("/api/v1/worker/reconcile",
                    headers={"Authorization": "Bearer nope"},
                    json={"worker_id": "w", "live_job_ids": []})
    assert r.status_code == 403


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

def test_a_worker_cannot_touch_another_workers_job(client, worker_headers, conn):
    enqueue(conn, "ubuntu", SMALL_MIB)
    job_id = claim(client, worker_headers, free_mib=FREE_MIB).json()["job_id"]

    intruder = dict(worker_headers, **{"X-Worker-Id": "someone-else"})
    r = client.post(f"/api/v1/worker/jobs/{job_id}/heartbeat", headers=intruder)

    # 404, not 403: a worker guessing ids must not learn which exist.
    assert r.status_code == 404


def test_an_unknown_job_is_indistinguishable_from_someone_elses(client, worker_headers):
    r = client.post(f"/api/v1/worker/jobs/{uuid.uuid4()}/heartbeat",
                    headers=worker_headers)
    assert r.status_code == 404


def test_worker_id_header_is_required(client, conn):
    enqueue(conn, "ubuntu", SMALL_MIB)
    r = client.post(f"/api/v1/worker/jobs/{uuid.uuid4()}/heartbeat",
                    headers={"Authorization": f"Bearer {WORKER_TOKEN}"})
    assert r.status_code == 400


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

    early = client.post(f"/api/v1/worker/jobs/{job_id}/complete",
                        headers=worker_headers, json={"manifest": {}})
    assert early.status_code == 409

    for nxt in ("preparing", "executing", "collecting", "cleaning"):
        client.post(f"/api/v1/worker/jobs/{job_id}/state",
                    headers=worker_headers, json={"state": nxt})

    ok = client.post(f"/api/v1/worker/jobs/{job_id}/complete",
                     headers=worker_headers,
                     json={"manifest": {"artifacts": ["capture.pcap"]}})
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
                    json={"worker_id": "test-worker", "live_job_ids": [a]})

    assert r.json()["interrupted"] == [b]
    assert state_of(conn, uuid.UUID(a)) == "cloning"
    assert state_of(conn, uuid.UUID(b)) == "interrupted"


# --- input hostility ------------------------------------------------------

@pytest.mark.parametrize("name", [
    '"; rm -rf / #', "$(whoami).sh", "`id`.bin", "'; DROP TABLE jobs; --",
    "<script>alert(1)</script>.exe", "a b\tc.exe", "‮exe.txt",
])
def test_hostile_filenames_survive_the_http_layer(client, worker_headers, conn, name):
    """Byte-exact from the database, through JSON, to the worker.

    The name must reach the guest unchanged -- DRAFT-030's reason for
    abandoning hash-named guest files. Serialisation must not normalise it.
    """
    enqueue(conn, "windows", WINDOWS_MIB, filename=name)
    body = claim(client, worker_headers, free_mib=WINDOWS_MIB).json()
    assert body["submitted_filename"] == name