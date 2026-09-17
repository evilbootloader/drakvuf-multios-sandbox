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

Publishing (decisions 5/6) is section 7. The predicate's third arm and the
route that writes it are tested separately and on purpose: section 6 sets
`visibility` directly, so a failure there is the READ rule; section 7 goes
through `POST /publish`, so a failure there is the WRITE rule. Collapsing them
would leave either fault able to hide behind the other.

What is deliberately NOT here, because it is not built yet:

  * **Loopback binding** (decision 3) and the **runtime quota** (decision 8).
  * **Forged and absent tokens** -- covered in `test_access_jwt.py`, which
    owns verification. This module assumes a verified identity and asks what
    it may reach.
"""

from __future__ import annotations

import io
import json
import re
import zipfile

import dataclasses
import hashlib
from urllib.parse import unquote, urlsplit
from uuid import UUID, uuid4

import pytest
from starlette.websockets import WebSocketDisconnect

from conftest import enqueue, owner_id
from sandbox_platform import auth, objects

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
        json={"target_os": "ubuntu", "filename": filename, "size_bytes": 4, "plugins": ["syscalls"],},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    return r.json()["job_id"]


def completed_with_artifacts(conn, put_object, owner, files, key_prefix="",
                             job_id=None):
    """A finished job owned by `owner`, with real objects behind its manifest.

    `key_prefix` defaults to the pre-#40 flat layout, which is what every
    caller below wants: those tests are about who may read a job, and the flat
    layout is the one with real objects behind it in the deployment.

    Pass `objects.owner_prefix(job_id, owner)` to place the objects where a job
    submitted after migration 0008 actually puts them -- section 12 is what
    that is for. That needs the id BEFORE the row exists, because the prefix
    contains a shard derived from it, so a caller doing this generates the id
    and passes it in -- the same ordering `routers.jobs.create_job` now uses,
    and for the same reason.
    """
    job_id = conn.execute(
        """
        INSERT INTO jobs (id, target_os, submitted_filename, state, manifest,
                          owner, key_prefix)
        VALUES (%s, 'ubuntu', 'x.bin', 'completed', %s, %s, %s) RETURNING id
        """,
        (job_id or uuid4(), json.dumps({"artifacts": sorted(files)}),
         owner_id(conn, owner), key_prefix),
    ).fetchone()[0]
    for name, body in files.items():
        # **Built literally, NOT through objects.result_prefix.** Using the
        # builder here would place the object wherever the code currently
        # thinks it goes, so a builder that ignored `key_prefix` entirely would
        # write and read the same wrong key and every test would pass. Checked:
        # it does -- these tests were green against exactly that break until
        # this line stopped calling the code under test.
        put_object(f"{key_prefix}results/{job_id}/{name}", body)
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
        (owner_id(conn, owner),),
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
    """Test 6, against the READ rule alone.

    `visibility` is set directly rather than through `POST /publish`, so what
    this proves is the predicate's third arm and nothing else. Section 7 drives
    the route. Two tests rather than one because a broken predicate and a broken
    publish route would otherwise be able to hide behind each other.

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


# **Publishing the RESULT is not publishing the SUBMITTER.** Decision 6 shares
# an analysis, and nothing in it says who ran it. Both identifying fields are
# withheld from a reader who is not the owner -- the address because it names a
# person, and the tenant id because several public jobs carrying one id say
# "same submitter" just as plainly. Opacity is not anonymity.
#
# The owner's own view is the other half and needs its own test: a comparison
# that got the types wrong would redact the address from everyone, including
# the person whose address it is, and every stranger-side assertion would still
# pass.
#
# Three readers, three tests, because the rule answers differently for each: a
# stranger, the owner, and infrastructure -- which is not a tenant at all and is
# exempt. Only the stranger case fails against a redaction that is too WIDE, and
# it is the one case that passes against every version of this rule there is.

def test_a_stranger_reading_a_public_job_gets_neither_identifying_field(
        client, conn, put_object, as_a, as_b):
    job_id = completed_with_artifacts(conn, put_object, A, {})
    conn.execute("UPDATE jobs SET visibility = 'public' WHERE id = %s", (job_id,))

    body = client.get(f"/api/v1/jobs/{job_id}", headers=as_b).json()

    assert body["owner_email"] == "REDACTED"
    assert body["owner"] == "REDACTED"
    # Not merely absent from the two fields -- absent from the response.
    assert A not in json.dumps(body)

    # The listing is a separate code path and redacts separately.
    row = next(j for j in client.get("/api/v1/jobs", headers=as_b).json()
               if j["id"] == str(job_id))
    assert row["owner_email"] == "REDACTED"
    assert row["owner"] == "REDACTED"


def test_the_owner_of_a_public_job_still_sees_their_own_address(
        client, conn, put_object, as_a):
    """The redaction must be about the READER, not about the row.

    This is what fails if the comparison compares a tenant id to an address --
    which it did, twice, while the identity column was being changed. Nothing on
    the stranger side can catch it: over-redaction looks exactly like working
    redaction from the outside.
    """
    job_id = completed_with_artifacts(conn, put_object, A, {})
    conn.execute("UPDATE jobs SET visibility = 'public' WHERE id = %s", (job_id,))

    body = client.get(f"/api/v1/jobs/{job_id}", headers=as_a).json()

    assert body["owner_email"] == A
    assert body["owner"] != "REDACTED"

    row = next(j for j in client.get("/api/v1/jobs", headers=as_a).json()
               if j["id"] == str(job_id))
    assert row["owner_email"] == A


def test_infrastructure_reads_the_real_owner_and_a_tenant_still_does_not(
        client, conn, put_object, infrastructure):
    """`auth.EVERYTHING` is exempt from the redaction; a tenant is not.

    **The sentinel is not a string**, so `owner != identity` was true for it
    however the row read -- and infrastructure got `REDACTED` on exactly the
    PUBLIC jobs while reading the real owner on every private one it was handed.
    That is backwards from what `auth.visible_to` does for the same caller: it
    returns `TRUE` and scopes nothing, because Dom0 and the command-line tools
    are the things that RUN these jobs. Withholding the submitter from them
    protects nobody from anybody.

    Cosmetic rather than a leak, which is why it survived: every assertion in
    the two tests above passes against it.

    Both halves on ONE listener, deliberately. The `infrastructure` fixture is
    the mTLS configuration -- Access off, `INFRASTRUCTURE_LISTENER` set -- so a
    caller with no credential resolves to `EVERYTHING`, and overriding
    `access_identity` partway through turns the same client into an ordinary
    authenticated tenant without changing anything else. One row, one
    configuration, two readers: the difference asserted is the reader and
    nothing else. (`client` clears the override in its teardown.)
    """
    from sandbox_platform.app import app

    job_id = completed_with_artifacts(conn, put_object, A, {})
    conn.execute("UPDATE jobs SET visibility = 'public' WHERE id = %s", (job_id,))

    # No Cf-Access-Jwt-Assertion header at all, as on the mTLS listener.
    body = client.get(f"/api/v1/jobs/{job_id}").json()
    assert body["owner_email"] == A
    assert body["owner"] != "REDACTED"

    # The listing redacts on its own code path and has to be exempt on its own
    # too -- one helper now, and this is what holds the two answers together.
    row = next(j for j in client.get("/api/v1/jobs").json()
               if j["id"] == str(job_id))
    assert row["owner_email"] == A
    assert row["owner"] != "REDACTED"

    # Same listener, same row, an authenticated tenant who is not the owner:
    # still redacted. Without this half the test passes against a redaction
    # deleted outright.
    app.dependency_overrides[auth.access_identity] = lambda: B

    body = client.get(f"/api/v1/jobs/{job_id}").json()
    assert body["owner_email"] == "REDACTED"
    assert body["owner"] == "REDACTED"
    assert A not in json.dumps(body)

    row = next(j for j in client.get("/api/v1/jobs").json()
               if j["id"] == str(job_id))
    assert row["owner_email"] == "REDACTED"
    assert row["owner"] == "REDACTED"


# --- 7. publishing ----------------------------------------------------------
#
# Decisions 5/6: publication is the OWNER's, after the fact, and unpublishing
# restores the check.
#
# **The gate is `owner = %s`, NOT `auth.visible_to`**, and
# `test_b_cannot_unpublish_as_published_job` is the test that holds it there.
# `visible_to` admits public rows through its third arm, so a route gated on it
# would be reflexive: the instant A publishes, B is inside the gate and can
# revoke it. Every other test in this section passes against that mistake --
# only that one fails, which is why it is here rather than left implied by the
# others.
#
# Checked against a neutered gate -- `_owned_or_404`'s `AND owner = %s` removed,
# leaving it owner-blind. Exactly three of these fail, and they are the three
# that assert the gate: `test_b_cannot_publish_as_job`,
# `test_b_cannot_unpublish_as_published_job` and
# `test_an_ownerless_job_cannot_be_published_by_anyone`.
#
# The rest stay green, which is not a weakness in them -- they cover the other
# three rules, and each has its own way of being wrong. The state rule
# (`..._has_not_finished`, `..._failed_run_is_publishable`) breaks if the
# terminal check is dropped or narrowed to `completed`; idempotency breaks if a
# second publish is made a 409; and `test_the_mtls_listener_cannot_publish`
# guards `_publisher`, a different gate that fails open in a different way.

def visibility_of(conn, job_id) -> str:
    return conn.execute(
        "SELECT visibility FROM jobs WHERE id = %s", (job_id,)
    ).fetchone()[0]


def test_b_cannot_publish_as_job(client, conn, as_a, as_b):
    """Test 7. Publication is the owner's, and B is not the owner.

    404 with the same body a missing id gets, for the reason every read path
    here does it: this route takes a job id, so it is an enumeration oracle on
    exactly the same terms.
    """
    job_id = _completed_job_of(conn, A)

    refused = client.post(f"/api/v1/jobs/{job_id}/publish", headers=as_b)
    missing = client.post(
        "/api/v1/jobs/00000000-0000-0000-0000-000000000000/publish",
        headers=as_b)

    assert refused.status_code == missing.status_code == 404
    assert refused.json() == missing.json()
    assert visibility_of(conn, job_id) == "private"


def test_a_can_publish_their_own_and_b_then_reads_it_in_full(
        client, conn, put_object, as_a, as_b):
    """The route's positive case, end to end.

    **In full, sample and `extracted/` included** -- decision 6, which
    considered and rejected metadata-only publishing because for a malware lab
    the payload is frequently the point of sharing.

    The 404 before publication is asserted too: without it this would pass
    against a build where B could always read the job, and the publish call
    would be proving nothing.
    """
    payload = b"MZ" + b"\x90" * 512
    job_id = completed_with_artifacts(
        conn, put_object, A, {"extracted/evil.exe": payload})

    assert client.get(f"/api/v1/jobs/{job_id}", headers=as_b).status_code == 404

    published = client.post(f"/api/v1/jobs/{job_id}/publish", headers=as_a)
    assert published.status_code == 200
    assert published.json()["visibility"] == "public"

    assert client.get(f"/api/v1/jobs/{job_id}", headers=as_b).status_code == 200
    r = client.get(f"/api/v1/jobs/{job_id}/artifact.zip",
                   params={"name": "extracted/evil.exe"}, headers=as_b)
    assert r.status_code == 200
    archive = zipfile.ZipFile(io.BytesIO(r.content))
    archive.setpassword(b"infected")
    assert archive.read("extracted/evil.exe") == payload


def test_b_cannot_unpublish_as_published_job(client, conn, as_a, as_b):
    """**The test this section exists for.**

    Once A has published, B may read the job -- `visible_to`'s third arm says
    so, and the middle assertion checks that rather than assuming it. A route
    gated on that predicate would therefore let B revoke A's publication, and
    control of publication would pass from the owner to everyone the act of
    publishing had just admitted.
    """
    job_id = _completed_job_of(conn, A)
    assert client.post(f"/api/v1/jobs/{job_id}/publish",
                       headers=as_a).status_code == 200

    # B can read it now. That is the point: the gate must not widen with it.
    assert client.get(f"/api/v1/jobs/{job_id}", headers=as_b).status_code == 200

    assert client.post(f"/api/v1/jobs/{job_id}/unpublish",
                       headers=as_b).status_code == 404
    assert visibility_of(conn, job_id) == "public"


def test_unpublishing_restores_the_check(client, conn, as_a, as_b):
    """The second half of test 7.

    Reversible for the ACCESS CHECK and for nothing else. Anything downloadable
    while the job was public, somebody has -- which is why the warning belongs
    at the moment of publishing rather than here.
    """
    job_id = _completed_job_of(conn, A)
    client.post(f"/api/v1/jobs/{job_id}/publish", headers=as_a)
    assert client.get(f"/api/v1/jobs/{job_id}", headers=as_b).status_code == 200

    r = client.post(f"/api/v1/jobs/{job_id}/unpublish", headers=as_a)

    assert r.status_code == 200
    assert r.json()["visibility"] == "private"
    assert client.get(f"/api/v1/jobs/{job_id}", headers=as_b).status_code == 404


def test_a_job_that_has_not_finished_cannot_be_published(client, conn, as_a):
    """409, not 404: the caller owns it, so withholding its existence would be
    a lie rather than a defence.

    Publishing something nobody has seen the result of is the case decision 5
    exists to prevent -- the whole argument for publishing after the fact is
    that a result cannot be judged before it exists.
    """
    job_id = submit(client, as_a)

    r = client.post(f"/api/v1/jobs/{job_id}/publish", headers=as_a)

    assert r.status_code == 409
    assert visibility_of(conn, job_id) == "private"


def test_a_failed_run_is_publishable(client, conn, as_a):
    """Terminal, not `completed`.

    A sample that detected the sandbox and bailed is a finding, and frequently
    the one worth sharing. Restricting this to `completed` would make the rule
    about whether the pipeline succeeded rather than about whether there is a
    result to judge.
    """
    job_id = _completed_job_of(conn, A)
    conn.execute("UPDATE jobs SET state = 'failed' WHERE id = %s", (job_id,))

    assert client.post(f"/api/v1/jobs/{job_id}/publish",
                       headers=as_a).status_code == 200


def test_publishing_twice_is_not_an_error(client, conn, as_a):
    """Idempotent. Two tabs, or a retry after a dropped response, must not
    report a failure for a state the row is already in."""
    job_id = _completed_job_of(conn, A)

    first = client.post(f"/api/v1/jobs/{job_id}/publish", headers=as_a)
    second = client.post(f"/api/v1/jobs/{job_id}/publish", headers=as_a)

    assert first.status_code == second.status_code == 200
    assert visibility_of(conn, job_id) == "public"


def test_an_ownerless_job_cannot_exist_at_all(conn):
    """The database refuses the row, which is why nothing else here tests it.

    Two tests used to live at this spot: an ownerless job is readable by every
    authenticated user, and publishable by none of them. Both described the
    mTLS submission path, where a client certificate identified a machine and
    `owner` was left NULL.

    Migration 0008 ended that. `owner` is NOT NULL for traceability, and
    `auth.required_identity` refuses the callers who cannot supply one -- so
    the rows those tests built by hand can no longer be created by any route,
    and asserting on them would be asserting on a state the schema forbids.

    **This stands in their place deliberately rather than deleting the
    coverage.** `auth.visible_to` still carries an `owner IS NULL` arm, and
    that arm is a shared pool visible to every authenticated user. The only
    thing keeping it empty is the constraint below. If someone drops it, this
    test fails first and the docstring on that arm explains what comes back.
    """
    import psycopg

    with pytest.raises(psycopg.errors.NotNullViolation):
        conn.execute(
            "INSERT INTO jobs (target_os, submitted_filename, state, owner) "
            "VALUES ('ubuntu', 'cli.bin', 'completed', NULL)"
        )


def test_the_mtls_listener_cannot_publish(client, conn, infrastructure):
    """403, and it never reaches the database.

    The certificate-gated listener authenticates a MACHINE -- Dom0 and the
    command-line tools -- and publication is a judgement about a result. It also
    keeps Dom0's one credential from carrying an authority nothing uses:
    `submit.py` has no publish command.

    403 rather than the 404 everything else in this section returns, because it
    is a fact about the LISTENER and not about the job, so it discloses nothing
    about which ids exist.

    `infrastructure` rather than `access_token`, deliberately: this test needs
    the settings a deployment gives the mTLS listener -- Access off, and
    INFRASTRUCTURE_LISTENER set so an unauthenticated caller is EVERYTHING -- which the `client` fixture otherwise overrides away.
    """
    job_id = _completed_job_of(conn, A)

    r = client.post(f"/api/v1/jobs/{job_id}/publish")

    assert r.status_code == 403
    assert visibility_of(conn, job_id) == "private"


# --- the mTLS listener ------------------------------------------------------
#
# It reads everything and writes nothing owned. An "ownerless jobs" section
# lived here until 2026-09-07, when migration 0008 made `jobs.owner` NOT NULL
# and the shared pool it described stopped being reachable --
# `test_an_ownerless_job_cannot_exist_at_all` above is what it became.

def test_the_mtls_listener_still_sees_everything(client, conn,
                                                 infrastructure):
    """No token, no scope, and that is not the hole it looks like.

    `access_identity` returns None only where REQUIRE_ACCESS_JWT is unset,
    which the deployment sets per listener -- so None means 'arrived over the
    listener already gated by a client certificate', never 'arrived
    unauthenticated over the browser one'. Dom0 and the command-line tools
    must not be locked out of a job a browser user submitted.

    `infrastructure` rather than `access_token`, deliberately: this test needs
    the settings a deployment gives the mTLS listener -- Access off, and
    INFRASTRUCTURE_LISTENER set so an unauthenticated caller is EVERYTHING
    -- which the `client` fixture otherwise overrides away.
    """
    job_id = conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, owner) "
        "VALUES ('ubuntu', 'browser.bin', 'received', %s) RETURNING id",
        (owner_id(conn, A),),
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
        "total_mib": 12082, "total_vlans": 8, "total_slots": 2,
        "pipelines": [{"os": "ubuntu", "required_mib": 2048}],
    })
    job_id = enqueue(conn, "ubuntu", 2048)
    conn.execute("UPDATE jobs SET owner = %s WHERE id = %s",
                 (owner_id(conn, A), job_id))

    claimed = client.post("/api/v1/worker/claim", headers=worker_headers, json={
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
        "total_mib": 12082, "total_vlans": 8, "total_slots": 2,
        "pipelines": [{"os": "ubuntu", "required_mib": 2048}],
    })
    job_id = enqueue(conn, "ubuntu", 2048)
    conn.execute("UPDATE jobs SET owner = %s WHERE id = %s",
                 (owner_id(conn, A), job_id))
    client.post("/api/v1/worker/claim", headers=worker_headers, json={
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
        # Origin alongside the credential: a browser sends both, and the
        # handshake is refused without one. Same-origin here, so the only thing
        # under test stays the TENANCY check rather than the origin check.
        with client.websocket_connect(
            f"/api/v1/jobs/{job_id}/console",
            headers={**as_b, "origin": "http://testserver"},
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
                                  headers={**as_a,
                                           "origin": "http://testserver"}):
        pass

# --- 12. the per-user key prefix -------------------------------------------
#
# Issue #40 (DRAFT-047) decision 7. **The prefix is stored on the row, never
# derived from whoever is asking**, and these are the tests that hold it there.
#
# Three kinds of caller need the same key and only one of them holds the
# identity it was built from: the submitter at admission, Dom0 on the worker
# channel with no browser identity at all, and a second user reading a
# published job. Deriving from the caller gives a different answer to each --
# and it fails silently as a missing object, which is indistinguishable from
# retention expiry.
#
# Everything else in this suite runs through the EMPTY prefix, because the
# fixtures insert rows directly and the column defaults to it. That is worth
# having -- it is the layout with real objects behind it in the deployment --
# but it means nothing above this line exercises decision 7 at all.


def test_a_legacy_row_still_resolves_to_the_flat_layout(conn, put_object,
                                                        client, as_a):
    """The empty prefix must reproduce the pre-#40 key BYTE FOR BYTE.

    This is what makes migration 0008 safe against a populated bucket: every
    object already in the store is at `results/<job_id>/<name>`, and nothing
    moved them. A prefix that merely *looked* empty -- a stray separator
    producing `/results/…` or `//results/…` -- is a different S3 key and would
    strand every artifact the deployment has ever collected.
    """
    payload = b"MZ" + b"\x90" * 64
    job_id = completed_with_artifacts(
        conn, put_object, A, {"trace.log": payload})

    stored = conn.execute("SELECT key_prefix FROM jobs WHERE id = %s",
                          (job_id,)).fetchone()[0]
    assert stored == ""

    # Both arms of the builder, spelled out. The empty case is the regression
    # that would strand every object already in the deployment; the non-empty
    # case is the one a builder ignoring its argument still passes without.
    assert objects.result_prefix(job_id, "") == f"results/{job_id}/"
    assert objects.sample_key(job_id, "s.bin", "") == f"samples/{job_id}/s.bin"
    assert objects.result_prefix(job_id, "u/x/") == f"u/x/results/{job_id}/"
    assert (objects.sample_key(job_id, "s.bin", "u/x/")
            == f"u/x/samples/{job_id}/s.bin")

    r = client.get(f"/api/v1/jobs/{job_id}/artifact.zip",
                   params={"name": "trace.log"}, headers=as_a)
    assert r.status_code == 200
    archive = zipfile.ZipFile(io.BytesIO(r.content))
    archive.setpassword(b"infected")
    assert archive.read("trace.log") == payload


def test_a_published_job_under_a_prefix_is_readable_by_b_in_full(
        client, conn, put_object, as_a, as_b):
    """**The test decision 7 exists to be checked by.**

    A's objects live under A's prefix. B reads them after publication, so the
    key B's request resolves to must come from the ROW and not from B. Deriving
    it from the caller yields `u/analyst-b.../results/…`, where nothing was ever
    written, and the download 404s or streams an empty archive -- which looks
    exactly like the retention window having expired.

    Decision 6 x decision 7, and the only place in this suite where the prefix
    and the reader disagree.
    """
    payload = b"MZ" + b"\x90" * 512
    job_id = uuid4()
    prefix = objects.owner_prefix(job_id, A)
    completed_with_artifacts(
        conn, put_object, A, {"extracted/evil.exe": payload},
        key_prefix=prefix, job_id=job_id)

    # The premise: the objects really are somewhere B could not have guessed.
    # Spelled out rather than rebuilt through `owner_prefix`, so this pins the
    # layout instead of agreeing with whatever the function currently returns.
    assert prefix == f"u/analyst-a@example.test/{job_id.hex[:3]}/"
    assert client.get(f"/api/v1/jobs/{job_id}", headers=as_b).status_code == 404

    assert client.post(f"/api/v1/jobs/{job_id}/publish",
                       headers=as_a).status_code == 200

    r = client.get(f"/api/v1/jobs/{job_id}/artifact.zip",
                   params={"name": "extracted/evil.exe"}, headers=as_b)
    assert r.status_code == 200
    archive = zipfile.ZipFile(io.BytesIO(r.content))
    archive.setpassword(b"infected")
    assert archive.read("extracted/evil.exe") == payload

    # And the whole-run download, which builds the key by a different route.
    every = client.get(f"/api/v1/jobs/{job_id}/artifacts.zip", headers=as_b)
    assert every.status_code == 200
    assert zipfile.ZipFile(io.BytesIO(every.content)).namelist() == [
        "extracted/evil.exe"]


def test_a_worker_reaches_a_sample_under_someone_elses_prefix(
        client, conn, put_object, worker_headers):
    """The decision-7 twin of test 11.

    Dom0 has no browser identity -- `access_identity` returns None on the
    certificate-gated listener -- so there is nothing for it to derive a prefix
    from even in principle. The claim must carry the stored value through, or
    every owned job hands the worker a `sample_url` for an object that does not
    exist and the pipeline breaks for exactly the jobs decision 7 applies to.

    `conftest.enqueue` cannot be used: it writes the flat layout, which is the
    one case this change does not touch.
    """
    body = b"\x7fELF" + b"\x00" * 60
    job_id = uuid4()
    prefix = objects.owner_prefix(job_id, A)
    conn.execute(
        "INSERT INTO jobs (id, target_os, submitted_filename, required_mib,"
        "                  state, owner, key_prefix)"
        " VALUES (%s, 'ubuntu', 's.bin', 2048, 'queued', %s, %s)",
        (job_id, owner_id(conn, A), prefix),
    )

    # Literal, for the reason `completed_with_artifacts` gives: the fixture must
    # be able to disagree with the code, or it proves only self-consistency.
    key = f"{prefix}samples/{job_id}/s.bin"
    put_object(key, body)
    # A claim re-checks the sample against the ETag admission recorded, and a
    # queued job without one fails closed. For a single-part upload MinIO's
    # ETag is the MD5, so it can be computed here rather than read back.
    conn.execute("UPDATE jobs SET sample_etag = %s WHERE id = %s",
                 (hashlib.md5(body).hexdigest(), job_id))

    client.post("/api/v1/worker/register", headers=worker_headers, json={
        "total_mib": 12082, "total_vlans": 8, "total_slots": 2,
        "pipelines": [{"os": "ubuntu", "required_mib": 2048}],
    })
    claimed = client.post("/api/v1/worker/claim", headers=worker_headers, json={
        "free_mib": 8192, "free_vlans": 6, "free_slots": 2,
    })

    assert claimed.status_code == 200, claimed.text
    body_json = claimed.json()
    assert body_json["status"] == "leased"

    # The path, unquoted and compared whole. `@` arrives as %40 in a signed
    # URL, so a substring check against the raw key fails for a reason that has
    # nothing to do with what is under test -- and comparing the whole path
    # rules out the flat layout as well, which `in` would not.
    signed = unquote(urlsplit(body_json["sample_url"]).path)
    assert signed.endswith(key), signed


def test_the_longest_admissible_key_still_fits_s3(conn):
    """An S3 key caps at 1024 BYTES, and three constants share that budget.

    **The ARTIFACT path is the binding one, not the sample path.**
    `manifest.MAX_ARTIFACT_NAME` is 718 against `_MAX_SAMPLE_NAME`'s 512, so
    the sample key has 200-odd bytes of slack and would pass at any owner
    length -- certifying nothing. An earlier version of this test measured
    only that one, which is how `MAX_ARTIFACT_NAME` came to be 900 while the
    prefix it budgets for grew from 45 bytes to 261.

        u/ + 254 + / + 3 + /   =  261     owner prefix, worst case
        results/ + 36 + /      =   45     job segment
        MAX_ARTIFACT_NAME      =  718
                                 -----
                                  1024

    Equality rather than `<=`, deliberately: the three are one budget, so this
    fails in BOTH directions and raising any of them shows up as spending
    another's share.
    """
    from sandbox_platform.manifest import MAX_ARTIFACT_NAME
    from sandbox_platform.routers.jobs import _MAX_SAMPLE_NAME

    owner = ("a" * 189) + "@" + ("b" * 59) + ".test"      # 254 bytes, RFC max
    assert len(owner.encode()) == objects.MAX_OWNER

    job_id = UUID("00000000-0000-0000-0000-000000000000")
    prefix = objects.owner_prefix(job_id, owner)

    worst = objects.result_prefix(job_id, prefix) + "r" * MAX_ARTIFACT_NAME
    assert len(worst.encode()) == 1024        # exact, not <= -- see MAX_OWNER

    # The sample path is checked too, but it is not the binding one.
    assert len(objects.sample_key(
        job_id, "n" * _MAX_SAMPLE_NAME, prefix).encode()) <= 1024

    # The database agrees the prefix is well formed -- the CHECK in 0008 is
    # what stops a malformed one ever reaching a key.
    conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, key_prefix,"
        "                  owner)"
        " VALUES ('ubuntu', 'x.bin', 'received', %s, %s)",
        (prefix, owner_id(conn, owner)))


# --- 13. an identity provider's value cannot reach an object key ------------
#
# **This section was inverted by migration 0009, not merely updated.** It used
# to assert that admission REFUSED an address too long or too separator-laden
# to become a key prefix, because the prefix was built from the address itself
# and `owner_prefix` was where an identity provider's value became this
# platform's problem.
#
# Since 0009 the prefix is built from an opaque tenant id, so that class of
# failure is structurally gone: `resolve_tenant` has already replaced the
# address with a uuid before `create_job` runs, and a uuid is always 36 bytes
# and never contains `/`. The prefix went from a 261-byte worst case to a fixed
# 43.
#
# So the tests below now pin the PROPERTY that made the old guard unnecessary.
# That is worth more than deleting them: the failure mode they guard against is
# someone reintroducing an address-derived prefix, which would look like a
# readability improvement and would silently restore every problem 0009 removed.
#
# `owner_prefix`'s own guards stay, and the last test here is what stops them
# rotting -- they still bound any caller that passes something other than a
# tenant id, and `MAX_OWNER` still has to accommodate the address-based
# prefixes that pre-0009 rows really do carry.

def _long_email(nbytes: int) -> str:
    """An address of exactly `nbytes`, shaped like a real one."""
    local = "a" * (nbytes - len("@" + "b" * 59 + ".test"))
    email = f"{local}@{'b' * 59}.test"
    assert len(email.encode()) == nbytes
    return email


def test_an_oversized_identity_is_refused_before_it_is_stored(client, conn,
                                                              access_token):
    """Refused at the identity boundary, not at admission.

    **The reason changed with 0009 even though the outcome did not.** This used
    to be about the object key: the prefix was built from the address, so 255
    bytes minted a key S3 could not store. The prefix holds a uuid now and that
    failure is structurally gone -- `test_owner_prefix_still_refuses_what_it_...`
    below covers what is left of it.

    What justifies the bound today is weaker and still real: the address is
    STORED and DISPLAYED, and it comes from whatever identity provider the
    deployment is wired to, so an unbounded one would be rendered in the jobs
    list. `auth.MAX_EMAIL_OCTETS` is where that is decided.

    403 rather than 400: the caller authenticated fine and cannot shorten a
    claim their IdP issued, so this is a fact about their identity rather than
    about the request -- see `auth.required_identity` for the same reasoning.

    Octets, not characters. A 111-character address of multi-byte codepoints is
    206 bytes, and the second case is what stops the bound being reimplemented
    with `len()`.
    """
    address = _long_email(auth.MAX_EMAIL_OCTETS + 1)

    r = client.post("/api/v1/jobs", headers=access_token(address),
                    json={"target_os": "ubuntu", "filename": "s.bin",
                          "size_bytes": 4, "plugins": ["syscalls"],})

    assert r.status_code == 403, r.text
    assert str(auth.MAX_EMAIL_OCTETS) in r.json()["detail"]
    # The address itself is logged, never returned: it is attacker-influenceable
    # and the caller already knows it.
    assert "aaaa" not in r.json()["detail"]
    assert conn.execute("SELECT count(*) FROM jobs").fetchone()[0] == 0
    # Scoped to THIS address, not `count(*)`: `identities` is deliberately not
    # in the `conn` fixture's TRUNCATE, so the table carries rows from earlier
    # tests in the session and an empty-table assertion would be testing the
    # fixture rather than the refusal.
    assert conn.execute(
        "SELECT count(*) FROM identities WHERE email = %s", (address,)
    ).fetchone()[0] == 0


def test_the_longest_real_address_is_still_admitted(client, conn, access_token):
    """The bound must not have closed the door on RFC-legal addresses.

    254 octets is a valid address and has to work. Without this, `>=` for `>` --
    or a bound taken from the old key arithmetic, which would be 72 -- passes
    every other test here while locking out real users.
    """
    ok = access_token(_long_email(auth.MAX_EMAIL_OCTETS))

    r = client.post("/api/v1/jobs", headers=ok,
                    json={"target_os": "ubuntu", "filename": "s.bin",
                          "size_bytes": 4, "plugins": ["syscalls"],})

    assert r.status_code == 201, r.text


def test_the_bound_counts_octets_and_not_characters(client, conn, access_token):
    """111 characters, 206 octets: admitted.

    The mirror of the test above. A bound written as `len(address)` admits this
    and also admits a 254-character address that is 1016 octets -- which is the
    bug `jobs.py`'s `_MAX_SAMPLE_NAME` comment records having already shipped
    once, in the sample-name path, for exactly this reason.
    """
    multibyte = "\u00e9" * 130 + "@" + "b" * 10 + ".test"
    assert len(multibyte) < auth.MAX_EMAIL_OCTETS < len(multibyte.encode())

    r = client.post("/api/v1/jobs", headers=access_token(multibyte),
                    json={"target_os": "ubuntu", "filename": "s.bin",
                          "size_bytes": 4, "plugins": ["syscalls"],})

    assert r.status_code == 403, r.text


def test_an_identity_containing_a_separator_cannot_reach_an_object_key(
        client, conn, access_token):
    """A `/` in the claim no longer adds a path segment.

    This was a 400 before 0009 and is a 201 now, for the same reason as above:
    the character never reaches the prefix. The 0008 CHECK
    (`^u/[^/]+/[0-9a-f]{3}/$`) is asserted here as well, because it is the
    database's half of the same guarantee and it is what would fail loudly if
    an address ever found its way back into the value.
    """
    weird = access_token("a/b@example.test")

    r = client.post("/api/v1/jobs", headers=weird,
                    json={"target_os": "ubuntu", "filename": "s.bin",
                          "size_bytes": 4, "plugins": ["syscalls"],})

    assert r.status_code == 201, r.text
    prefix = conn.execute("SELECT key_prefix FROM jobs WHERE id = %s",
                          (r.json()["job_id"],)).fetchone()[0]
    assert "/" not in prefix.removeprefix("u/").removesuffix("/")[:-4]
    assert re.fullmatch(r"u/[^/]+/[0-9a-f]{3}/", prefix), prefix


@pytest.mark.parametrize("bad, reason", [
    (_long_email(objects.MAX_OWNER + 1), "over the"),
    ("a/b@example.test", "path separator"),
])
def test_owner_prefix_still_refuses_what_it_always_did(bad, reason):
    """The guards in `owner_prefix` are unreachable from a live identity, and
    kept.

    Tested directly rather than through the API, because no request can produce
    these arguments any more -- which is exactly why they need a test of their
    own. Two things still depend on them: `MAX_OWNER` has to keep bounding the
    address-derived prefixes that pre-0009 rows genuinely carry, and any future
    caller that passes something other than a tenant id gets a refusal rather
    than a key S3 cannot store.
    """
    with pytest.raises(ValueError, match=reason):
        objects.owner_prefix(uuid4(), bad)
