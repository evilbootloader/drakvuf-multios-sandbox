"""Per-user isolation on the browser channel.

Issue #40 (DRAFT-047), decision 4: a user reads their own jobs plus published
ones, and nothing else.

**The negative cases are the issue.** `owner` has been written on every
submission since #36 and enforced nowhere, which is the worse of the two
states to sit in: the column looks populated, so the isolation looks present.
A tenancy check never exercised against a second user is a check nobody has
tested, so every test here is two users and one job.

Real signed Access tokens throughout, via the `access_token` fixture -- two
identities that differ only in their `email` claim, which is exactly what
distinguishes two real users at the edge.

What is deliberately NOT here, because it is not built yet:

  * **Publishing** (decisions 5/6). `test_a_public_job_is_readable_by_anyone`
    sets `visibility` directly, which tests the predicate's third arm; the
    `POST /publish` route that would set it is a later change, and
    owner-only-may-publish belongs with it.
  * **Loopback binding** (decision 3) and the **runtime quota** (decision 8).
  * **Forged and absent tokens** -- covered in `test_access_jwt.py`, which
    owns verification. This module assumes a verified identity and asks what
    it may reach.
"""

from __future__ import annotations

import io
import json
import zipfile

import dataclasses
import pytest
from starlette.websockets import WebSocketDisconnect

from conftest import enqueue

A = "analyst-a@example.test"
B = "analyst-b@example.test"


@pytest.fixture
def as_a(access_token):
    return access_token(A)


@pytest.fixture
def as_b(access_token):
    return access_token(B)


def submit(client, headers, filename="sample.bin"):
    """Create a job as whoever `headers` authenticates, and return its id."""
    r = client.post(
        "/api/v1/jobs",
        json={"target_os": "ubuntu", "filename": filename, "size_bytes": 4},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    return r.json()["job_id"]


def completed_with_artifacts(conn, put_object, owner, files):
    """A finished job owned by `owner`, with real objects behind its manifest."""
    job_id = conn.execute(
        """
        INSERT INTO jobs (target_os, submitted_filename, state, manifest, owner)
        VALUES ('ubuntu', 'x.bin', 'completed', %s, %s) RETURNING id
        """,
        (json.dumps({"artifacts": sorted(files)}), owner),
    ).fetchone()[0]
    for name, body in files.items():
        put_object(f"results/{job_id}/{name}", body)
    return job_id


# --- 1. reading someone else's job -----------------------------------------

def test_b_cannot_read_as_job(client, as_a, as_b):
    """Test 1. **404, not 403** -- a 403 confirms the id exists, which turns
    this route into an oracle for enumerating other people's job ids."""
    job_id = submit(client, as_a)

    assert client.get(f"/api/v1/jobs/{job_id}", headers=as_a).status_code == 200

    refused = client.get(f"/api/v1/jobs/{job_id}", headers=as_b)
    assert refused.status_code == 404


def test_the_refusal_is_indistinguishable_from_a_missing_job(client, as_a, as_b):
    """Same status AND same body. A refusal that differs in either is still an
    oracle -- 'no such job' versus 'not yours' answers the question the status
    code was chosen to withhold."""
    job_id = submit(client, as_a)
    absent = "00000000-0000-0000-0000-000000000000"

    theirs = client.get(f"/api/v1/jobs/{job_id}", headers=as_b)
    nothing = client.get(f"/api/v1/jobs/{absent}", headers=as_b)

    assert theirs.status_code == nothing.status_code == 404
    assert theirs.json() == nothing.json()


# --- 2. cancelling ----------------------------------------------------------

def test_b_cannot_cancel_as_job(client, conn, as_a, as_b):
    """Test 2. Cancellation is destructive and free to attempt, so an
    unscoped cancel is the cheapest way to ruin someone else's day."""
    job_id = submit(client, as_a)

    assert client.post(f"/api/v1/jobs/{job_id}/cancel",
                       headers=as_b).status_code == 404

    # And the job is untouched -- the refusal must be before the UPDATE, not a
    # cosmetic status on a cancellation that already happened.
    state = conn.execute("SELECT state, cancel_requested FROM jobs WHERE id = %s",
                         (job_id,)).fetchone()
    assert state[0] == "received"
    assert state[1] is False


def test_a_can_cancel_their_own_job(client, as_a):
    """The check must not have closed the route for its owner too."""
    job_id = submit(client, as_a)
    r = client.post(f"/api/v1/jobs/{job_id}/cancel", headers=as_a)
    assert r.status_code == 200
    assert r.json()["outcome"] in {"cancelled", "cancel_requested"}


# --- 3. event streams -------------------------------------------------------

def _completed_job_of(conn, owner):
    """A terminal job, so `events.stream` ends by itself.

    Terminal on purpose: the stream stays open until a job can no longer
    change, so if this check ever regresses these two tests must FAIL rather
    than hang. A hanging suite reads as infrastructure trouble and gets
    retried; a failing one gets read.
    """
    return conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, owner) "
        "VALUES ('ubuntu', 'x.bin', 'completed', %s) RETURNING id",
        (owner,),
    ).fetchone()[0]


def test_b_cannot_subscribe_to_as_events(client, conn, as_b):
    """Test 3. The stream carries every state transition, so an unscoped
    subscription is a live feed of another user's analysis."""
    job_id = _completed_job_of(conn, A)

    r = client.get(f"/api/v1/jobs/{job_id}/events", headers=as_b)
    assert r.status_code == 404


def test_the_event_refusal_is_a_status_not_an_empty_stream(client, conn, as_b):
    """**Checked before the StreamingResponse is constructed.** Refusing from
    inside the generator would arrive as a 200 with an empty body, which a
    client cannot tell from a job that simply is not changing."""
    job_id = _completed_job_of(conn, A)

    r = client.get(f"/api/v1/jobs/{job_id}/events", headers=as_b)

    assert r.status_code == 404
    assert "text/event-stream" not in r.headers.get("content-type", "")


def test_a_can_subscribe_to_their_own_events(client, conn, as_a):
    """The refusal must not have closed the stream for its owner."""
    job_id = _completed_job_of(conn, A)

    r = client.get(f"/api/v1/jobs/{job_id}/events", headers=as_a)

    assert r.status_code == 200
    assert "text/event-stream" in r.headers["content-type"]


# --- 4. listings ------------------------------------------------------------

def test_bs_listing_does_not_contain_as_jobs(client, as_a, as_b):
    """Test 4. The id is enough to reach everything else, so a listing that
    leaks ids undoes every other check here."""
    mine = submit(client, as_b, filename="mine.bin")
    theirs = submit(client, as_a, filename="theirs.bin")

    listed = {j["id"] for j in client.get("/api/v1/jobs", headers=as_b).json()}

    assert mine in listed
    assert theirs not in listed


def test_the_ui_history_is_scoped_too(client, as_a, as_b):
    """The UI reads through the same helpers, and is the surface a person
    actually uses. Scoping the JSON API alone would leave /ui wide open."""
    submit(client, as_a, filename="a-secret-sample.bin")

    body = client.get("/ui/jobs", headers=as_b).text

    assert "a-secret-sample.bin" not in body


def test_the_ui_job_page_is_scoped_too(client, as_a, as_b):
    job_id = submit(client, as_a)
    assert client.get(f"/ui/jobs/{job_id}", headers=as_b).status_code == 404


# --- 5. artifacts -----------------------------------------------------------

def test_b_cannot_download_as_artifacts(client, conn, put_object, as_a, as_b):
    """Test 5. **The check is before the object store is read**, not on the
    way out. DRAFT-047 states this as 'before the presigned URL is minted' --
    these routes wrap rather than presign, so the equivalent moment is before
    `objects.chunks` opens a read."""
    payload = b"MZ" + b"\x90" * 512
    job_id = completed_with_artifacts(
        conn, put_object, A, {"extracted/evil.exe": payload})

    every = client.get(f"/api/v1/jobs/{job_id}/artifacts.zip", headers=as_b)
    one = client.get(f"/api/v1/jobs/{job_id}/artifact.zip",
                     params={"name": "extracted/evil.exe"}, headers=as_b)

    assert every.status_code == 404
    assert one.status_code == 404
    # The bytes must not appear even wrapped: a 404 that still streamed the
    # archive would pass a status assertion and leak the sample.
    assert payload not in every.content
    assert payload not in one.content


def test_a_can_still_download_their_own(client, conn, put_object, as_a):
    payload = b"MZ" + b"\x90" * 512
    job_id = completed_with_artifacts(
        conn, put_object, A, {"extracted/evil.exe": payload})

    r = client.get(f"/api/v1/jobs/{job_id}/artifacts.zip", headers=as_a)

    assert r.status_code == 200
    archive = zipfile.ZipFile(io.BytesIO(r.content))
    archive.setpassword(b"infected")
    assert archive.read("extracted/evil.exe") == payload


# --- 6. published jobs ------------------------------------------------------

def test_a_public_job_is_readable_by_anyone_in_full(client, conn, put_object,
                                                    as_a, as_b):
    """Test 6, as far as it can be tested today.

    `visibility` is set directly here because nothing writes it yet -- the
    publish route is decisions 5/6 and has not landed. So this proves the
    predicate's third arm works, which is what makes that route a pure
    addition rather than a change to every read path.

    **In full, sample and `extracted/` included.** DRAFT-047 considered and
    rejected metadata-only publishing: for a malware lab the payload is
    frequently the point of sharing.
    """
    payload = b"MZ" + b"\x90" * 512
    job_id = completed_with_artifacts(
        conn, put_object, A, {"extracted/evil.exe": payload})
    conn.execute("UPDATE jobs SET visibility = 'public' WHERE id = %s", (job_id,))

    assert client.get(f"/api/v1/jobs/{job_id}", headers=as_b).status_code == 200

    r = client.get(f"/api/v1/jobs/{job_id}/artifact.zip",
                   params={"name": "extracted/evil.exe"}, headers=as_b)
    assert r.status_code == 200
    archive = zipfile.ZipFile(io.BytesIO(r.content))
    archive.setpassword(b"infected")
    assert archive.read("extracted/evil.exe") == payload


# --- ownerless jobs ---------------------------------------------------------
#
# The case DRAFT-047 does not mention, decided 2026-09-05: an unowned job is an
# infrastructure job, not a private one.

def test_an_mtls_submission_is_visible_to_authenticated_users(client, conn, as_b):
    """`submit.py` and the other command-line tools record no owner, because a
    client certificate identifies a machine rather than a person. Those jobs
    stay readable in the browser -- otherwise every CLI submission, and every
    job already in the table, vanishes from the UI on deploy.

    **The consequence, stated:** the ownerless set is a shared pool. It is not
    where one tenant's samples should land once there is more than one tenant.

    The row is inserted directly rather than submitted, because `as_b` puts
    this process on the browser listener for the duration of the test and an
    unauthenticated POST would simply 401. What is under test is how an
    ownerless ROW reads, not how one comes to exist.
    """
    job_id = conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, owner) "
        "VALUES ('ubuntu', 'cli.bin', 'received', NULL) RETURNING id"
    ).fetchone()[0]

    assert client.get(f"/api/v1/jobs/{job_id}", headers=as_b).status_code == 200


def test_the_mtls_listener_still_sees_everything(client, conn):
    """No token, no scope, and that is not the hole it looks like.

    `access_identity` returns None only where REQUIRE_ACCESS_JWT is unset,
    which the deployment sets per listener -- so None means 'arrived over the
    listener already gated by a client certificate', never 'arrived
    unauthenticated over the browser one'. Dom0 and the command-line tools
    must not be locked out of a job a browser user submitted.

    No `access_token` fixture here deliberately: this test needs the settings
    a deployment gives the mTLS listener, which are the defaults.
    """
    job_id = conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, owner) "
        "VALUES ('ubuntu', 'browser.bin', 'received', %s) RETURNING id",
        (A,),
    ).fetchone()[0]

    # No Cf-Access-Jwt-Assertion header at all, as on the mTLS listener.
    assert client.get(f"/api/v1/jobs/{job_id}").status_code == 200


# --- 11. the worker channel is unchanged ------------------------------------

def test_a_worker_runs_a_job_it_does_not_own(client, conn, worker_headers):
    """Test 11, and the regression that would break the pipeline for everyone.

    **Dom0 is infrastructure, not a tenant.** It must be able to run anyone's
    job, so `owner` must never scope the worker channel -- `lease_owner` does
    that, and has since #35. A change that 'unifies' the two authorization
    models breaks every job not owned by whoever Dom0's certificate names.

    This job is owned by a browser user the worker has never heard of.
    """
    client.post("/api/v1/worker/register", headers=worker_headers, json={
        "worker_id": worker_headers["X-Worker-Id"],
        "total_mib": 12082, "total_vlans": 8, "total_slots": 2,
        "pipelines": [{"os": "ubuntu", "required_mib": 2048}],
    })
    job_id = enqueue(conn, "ubuntu", 2048)
    conn.execute("UPDATE jobs SET owner = %s WHERE id = %s", (A, job_id))

    claimed = client.post("/api/v1/worker/claim", headers=worker_headers, json={
        "worker_id": worker_headers["X-Worker-Id"],
        "free_mib": 8192, "free_vlans": 6, "free_slots": 2,
    })

    assert claimed.status_code == 200
    body = claimed.json()
    assert body["status"] == "leased"
    assert body["job_id"] == str(job_id)


def test_a_worker_reports_progress_on_a_job_it_does_not_own(
        client, conn, worker_headers):
    """Claiming is not enough: every subsequent worker route resolves through
    `auth.leased_job`, and owner-scoping any of them would strand the job
    mid-run rather than refusing it up front."""
    client.post("/api/v1/worker/register", headers=worker_headers, json={
        "worker_id": worker_headers["X-Worker-Id"],
        "total_mib": 12082, "total_vlans": 8, "total_slots": 2,
        "pipelines": [{"os": "ubuntu", "required_mib": 2048}],
    })
    job_id = enqueue(conn, "ubuntu", 2048)
    conn.execute("UPDATE jobs SET owner = %s WHERE id = %s", (A, job_id))
    client.post("/api/v1/worker/claim", headers=worker_headers, json={
        "worker_id": worker_headers["X-Worker-Id"],
        "free_mib": 8192, "free_vlans": 6, "free_slots": 2,
    })

    r = client.post(f"/api/v1/worker/jobs/{job_id}/state",
                    headers=worker_headers, json={"state": "preparing"})

    assert r.status_code in (200, 204), r.text
    assert conn.execute("SELECT state FROM jobs WHERE id = %s",
                        (job_id,)).fetchone()[0] == "preparing"


# --- the live console -------------------------------------------------------

def test_b_cannot_request_a_console_on_as_job(client, monkeypatch, as_a, as_b):
    """A console session streams a live malware VM's framebuffer and accepts
    input into it, so it is the most consequential thing an unscoped job id
    reaches."""
    from sandbox_platform.routers import jobs as jobs_router

    monkeypatch.setattr(jobs_router, "settings", dataclasses.replace(
        jobs_router.settings, console_enabled=True))

    job_id = submit(client, as_a)

    r = client.post(f"/api/v1/jobs/{job_id}/console/request", headers=as_b)
    assert r.status_code == 404


def test_b_cannot_open_a_console_socket_on_as_job(client, conn, monkeypatch,
                                                  as_a, as_b):
    """The WebSocket end. It computes the identity itself -- `Depends` cannot
    raise usefully on a socket -- so it is the one browser route where the
    scope check is not a shared dependency, and therefore the one most worth
    asserting directly."""
    from sandbox_platform.routers import console as console_router

    monkeypatch.setattr(console_router, "settings", dataclasses.replace(
        console_router.settings, console_enabled=True))

    job_id = submit(client, as_a)
    conn.execute("UPDATE jobs SET state = 'executing' WHERE id = %s", (job_id,))

    # The REASON is asserted, not merely that something was raised: a bare
    # `pytest.raises(Exception)` passes when the socket is refused for any
    # reason at all -- including the console being disabled, or the job being
    # in the wrong state -- which would make this test green against an
    # unscoped build. Checked: it is.
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(
            f"/api/v1/jobs/{job_id}/console",
            headers=as_b,
        ) as ws:
            ws.receive_text()

    # Deliberately the same reason a missing id gets, for the same
    # non-enumeration reason the HTTP routes return 404 rather than 403.
    assert exc.value.reason == "no such job"


def test_a_can_open_a_console_socket_on_their_own_job(client, conn, monkeypatch,
                                                      as_a):
    """The owner reaches the same socket -- the check must refuse B without
    also closing the feature for the person the session is for."""
    from sandbox_platform.routers import console as console_router

    monkeypatch.setattr(console_router, "settings", dataclasses.replace(
        console_router.settings, console_enabled=True))

    job_id = submit(client, as_a)
    conn.execute("UPDATE jobs SET state = 'executing' WHERE id = %s", (job_id,))

    with client.websocket_connect(f"/api/v1/jobs/{job_id}/console",
                                  headers=as_a):
        pass