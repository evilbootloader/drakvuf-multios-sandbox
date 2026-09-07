"""The browser channel: submission, admission, and reading results.

Issue #36 (DRAFT-043), with the two-endpoint split from #39.
"""

from __future__ import annotations

import io
import json
import uuid
import zipfile

import pytest

from conftest import WORKER_TOKEN, enqueue, state_of

WINDOWS_MIB = 6294
SMALL_MIB = 2198

# Real headers, so libmagic sees what it would see in production.
ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
PE = b"MZ\x90\x00\x03" + b"\x00" * 60 + b"PE\x00\x00" + b"\x00" * 64
ZIP = b"PK\x03\x04" + b"\x00" * 60

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


@pytest.fixture
def registered(client, worker_headers):
    """A worker exists, so admission has capacity to check against."""
    client.post("/api/v1/worker/register", headers=worker_headers,
                json=REGISTRATION)
    return client


def submit(client, target_os="ubuntu", filename="sample.bin", size=len(ELF)):
    r = client.post("/api/v1/jobs", json={
        "target_os": target_os, "filename": filename, "size_bytes": size,
    })
    assert r.status_code == 201, r.text
    return r.json()


def upload_and_admit(client, put_object, body=ELF, **kw):
    # The key comes from the signed policy, not from a path built here -- see
    # the note in test_egress.admit. Owned submissions live under a prefix.
    created = submit(client, size=len(body), **kw)
    job_id = created["job_id"]
    put_object(created["upload_fields"]["key"], body)
    return job_id, client.post(f"/api/v1/jobs/{job_id}/uploaded").json()


# --- the enum boundary ----------------------------------------------------

@pytest.mark.parametrize("bad", ["linux", "Windows", "../ubuntu", "", 7, None])
def test_target_os_is_closed_at_submission(client, bad):
    """Issue #3: the one untrusted routing input, validated in one place."""
    r = client.post("/api/v1/jobs", json={
        "target_os": bad, "filename": "x.bin", "size_bytes": 10,
    })
    assert r.status_code == 422


# --- the two endpoints ----------------------------------------------------

def test_upload_url_is_signed_for_the_public_host(client):
    """The browser gets a URL for the tunnel hostname, not the LAN address.

    SigV4 covers the Host header, so this is not cosmetic: a URL signed for
    127.0.0.1 is rejected when presented to the tunnel and vice versa.
    """
    created = submit(client)
    assert created["upload_url"].startswith("http://localhost:9000")
    assert "127.0.0.1" not in created["upload_url"]


def test_the_worker_and_browser_get_different_hosts(client):
    from sandbox_platform import objects

    key = "samples/x/y.bin"
    assert "127.0.0.1" in objects.presigned_get(key, objects.Audience.WORKER)
    assert "localhost:9000" in objects.presigned_get(
        key, objects.Audience.BROWSER
    )


def test_the_declared_size_binds_the_upload_policy(client):
    """A client is held to the size it declared.

    Raised in review: "can they spoof size and upload a bigger sample?" They
    could, until 2026-08-23 -- the policy was signed with the configured cap
    alone, so declaring 100 bytes and uploading 500 KiB succeeded and the
    declared value protected nothing.

    The claim can only ever TIGHTEN the bound. A declaration above the cap is
    refused before a URL exists, so this cannot be used to raise the ceiling.
    """
    import httpx

    from sandbox_platform.config import settings

    created = submit(client, size=100)

    def upload(n: int) -> int:
        return httpx.post(created["upload_url"], data=created["upload_fields"],
                          files={"file": ("sample.bin", b"A" * n)}).status_code

    assert upload(100) == 204
    assert upload(100_000) == 400, "declared size must bound the upload"

    over = client.post("/api/v1/jobs", json={
        "target_os": "ubuntu", "filename": "big.bin",
        "size_bytes": settings.max_sample_bytes + 1,
    })
    assert over.status_code == 413


def test_the_signed_policy_cannot_be_edited_client_side(client):
    """Burp-style tampering: raise the range, drop the signature, redirect the
    key. The signature covers the policy and the policy pins the key."""
    import base64
    import json

    import httpx

    created = submit(client, size=100)
    fields = dict(created["upload_fields"])

    def post(f, n=100):
        return httpx.post(created["upload_url"], data=f,
                          files={"file": ("sample.bin", b"A" * n)}).status_code

    raised = dict(fields)
    policy = json.loads(base64.b64decode(fields["policy"]))
    policy["conditions"] = [
        ["content-length-range", 1, 10**9]
        if isinstance(c, list) and c[0] == "content-length-range" else c
        for c in policy["conditions"]
    ]
    raised["policy"] = base64.b64encode(json.dumps(policy).encode()).decode()
    assert post(raised, 100_000) == 403          # SignatureDoesNotMatch

    unsigned = dict(raised)
    unsigned.pop("x-amz-signature", None)
    assert post(unsigned, 100_000) == 403

    redirected = dict(fields)
    redirected["key"] = "samples/00000000-0000-0000-0000-000000000000/evil.bin"
    assert post(redirected) == 403               # AccessDenied


def test_a_same_size_swap_after_admission_fails_the_job(registered, worker_headers):
    """The sample a worker runs must be the one admission looked at.

    The browser's upload capability outlives admission, so an object can be
    replaced after it was hashed and queued. Same length on purpose: the
    declared-size bound cannot catch this, which is why the ETag check exists.

    Without it, Dom0 executes bytes that were never admitted while the trace,
    the verdict and the recorded SHA-256 all describe the file that was
    replaced -- a sandbox that can be made to analyse one thing and report
    another.
    """
    import httpx

    benign = b"\x7fELF" + b"\x00" * 60 + b"A" * 16
    evil = b"\x7fELF" + b"\x00" * 60 + b"B" * 16
    assert len(benign) == len(evil)

    created = submit(registered, size=len(benign))
    job_id = created["job_id"]
    httpx.post(created["upload_url"], data=created["upload_fields"],
               files={"file": ("sample.bin", benign)})
    assert registered.post(f"/api/v1/jobs/{job_id}/uploaded").json()["state"] == "queued"

    swap = httpx.post(created["upload_url"], data=created["upload_fields"],
                      files={"file": ("sample.bin", evil)})
    assert swap.status_code == 204, "the size bound cannot catch a same-size swap"

    claim = registered.post("/api/v1/worker/claim", headers=worker_headers, json={
        "worker_id": "test-worker", "free_mib": 5082,
        "free_vlans": 6, "free_slots": 2,
    }).json()

    assert claim["status"] != "leased", "a swapped sample must never be handed out"
    detail = registered.get(f"/api/v1/jobs/{job_id}").json()
    assert detail["state"] == "failed"
    assert detail["failure_reason"] == "sample_changed_after_admission"


def test_an_unswapped_sample_is_leased_with_a_url(registered, worker_headers):
    """The check must not reject the normal case."""
    import httpx

    body = b"\x7fELF" + b"\x00" * 60 + b"ok"
    created = submit(registered, size=len(body))
    httpx.post(created["upload_url"], data=created["upload_fields"],
               files={"file": ("sample.bin", body)})
    registered.post(f"/api/v1/jobs/{created['job_id']}/uploaded")

    claim = registered.post("/api/v1/worker/claim", headers=worker_headers, json={
        "worker_id": "test-worker", "free_mib": 5082,
        "free_vlans": 6, "free_slots": 2,
    }).json()

    assert claim["status"] == "leased"
    # Signed for the LAN endpoint, not the tunnel -- Dom0's audience.
    assert claim["sample_url"].startswith("http://127.0.0.1:9000")


def test_the_upload_policy_carries_a_size_cap(client):
    """A presigned PUT cannot constrain size; a POST policy can, and that is
    the whole reason uploads use POST."""
    import base64
    import json

    created = submit(client)
    policy = json.loads(base64.b64decode(created["upload_fields"]["policy"]))
    ranges = [c for c in policy["conditions"]
              if isinstance(c, list) and c[0] == "content-length-range"]
    assert ranges, policy["conditions"]


# --- admission ------------------------------------------------------------

def test_a_good_sample_reaches_queued(registered, put_object):
    job_id, detail = upload_and_admit(registered, put_object)
    assert detail["state"] == "queued"
    assert detail["sha256"] and len(detail["sha256"]) == 64
    assert detail["detected_type"]


def test_a_missing_object_is_unreadable(registered, put_object):
    """Nothing was uploaded; admission must not hang or 500."""
    created = submit(registered)
    detail = registered.post(f"/api/v1/jobs/{created['job_id']}/uploaded").json()
    assert detail["state"] == "rejected"
    assert detail["failure_reason"] == "unreadable"


def test_an_empty_object_is_unreadable(registered, put_object):
    created = submit(registered)
    # The signed key, so EMPTINESS is what this tests. A hand-built flat key
    # is simply absent now that submissions are owned, and "unreadable" is
    # also what absent produces -- the assertion would hold for the wrong
    # reason.
    put_object(created["upload_fields"]["key"], b"")
    detail = registered.post(f"/api/v1/jobs/{created['job_id']}/uploaded").json()
    assert detail["failure_reason"] == "unreadable"


def test_magic_may_reject_a_contradiction(registered, put_object):
    """An ELF submitted as Windows is refused..."""
    _, detail = upload_and_admit(registered, put_object, body=ELF,
                                 target_os="windows")
    assert detail["state"] == "rejected"
    assert detail["failure_reason"] == "unsupported_type"


def test_magic_never_reroutes(registered, put_object):
    """...and is NOT quietly rerouted to the OS its magic suggests.

    This is the half that matters. Magic reports; the submitter routes.
    """
    _, detail = upload_and_admit(registered, put_object, body=ELF,
                                 target_os="windows")
    assert detail["target_os"] == "windows"
    assert detail["state"] != "queued"


def test_ambiguity_resolves_in_the_submitters_favour(registered, put_object):
    """A ZIP submitted as Android is admitted: an APK is a ZIP, and detection
    that cannot tell must defer to the choice (issue #3)."""
    _, detail = upload_and_admit(registered, put_object, body=ZIP,
                                 target_os="android")
    assert detail["state"] == "queued"


def test_no_workers_is_distinct_from_no_capacity(client, put_object):
    """On a fresh install refusing every submission is CORRECT -- but the
    reason must be actionable, not 'submission failed'."""
    created = submit(client)
    put_object(created["upload_fields"]["key"], ELF)
    detail = client.post(f"/api/v1/jobs/{created['job_id']}/uploaded").json()
    assert detail["failure_reason"] == "no_workers"


def test_a_job_no_host_can_afford_is_rejected(client, worker_headers, put_object):
    small_host = dict(REGISTRATION, total_mib=4096)
    client.post("/api/v1/worker/register", headers=worker_headers,
                json=small_host)
    created = submit(client, target_os="windows")
    put_object(created["upload_fields"]["key"], PE)
    detail = client.post(f"/api/v1/jobs/{created['job_id']}/uploaded").json()
    assert detail["failure_reason"] == "no_capacity"


def test_oversized_is_refused_before_a_url_is_issued(client):
    from sandbox_platform.config import settings

    r = client.post("/api/v1/jobs", json={
        "target_os": "ubuntu", "filename": "big.bin",
        "size_bytes": settings.max_sample_bytes + 1,
    })
    assert r.status_code == 413


def test_admission_runs_once(registered, put_object):
    job_id, _ = upload_and_admit(registered, put_object)
    again = registered.post(f"/api/v1/jobs/{job_id}/uploaded")
    assert again.status_code == 409


# --- reading --------------------------------------------------------------

def test_a_held_job_says_something_is_ahead_without_naming_it(registered, put_object, conn):
    """The browser must not learn another submitter's job id or footprint.

    Those live on the worker channel, where Dom0 needs them for capacity
    accounting. Adding them here 'for symmetry' is the mistake this guards.
    """
    from conftest import enqueue

    enqueue(conn, "windows", WINDOWS_MIB)
    job_id, detail = upload_and_admit(registered, put_object)

    assert detail["state"] == "queued"
    assert detail["reserved_ahead"] is True
    assert "blocking_job_id" not in detail
    assert "need_mib" not in detail


def test_history_filters_and_paginates(registered, put_object):
    for _ in range(3):
        upload_and_admit(registered, put_object)
    rows = registered.get("/api/v1/jobs", params={"state": "queued"}).json()
    assert len(rows) == 3
    assert registered.get("/api/v1/jobs", params={"limit": 2}).json().__len__() == 2


def test_identical_bytes_under_two_names_are_two_jobs(registered, put_object):
    """DRAFT-030: the submitted name is part of what is analysed."""
    a, da = upload_and_admit(registered, put_object, filename="invoice.exe")
    b, db = upload_and_admit(registered, put_object, filename="setup.exe")
    assert a != b
    assert da["sha256"] == db["sha256"]


# --- cancellation ---------------------------------------------------------

def test_cancel_before_a_clone_exists(registered, put_object, conn):
    job_id, _ = upload_and_admit(registered, put_object)
    r = registered.post(f"/api/v1/jobs/{job_id}/cancel").json()
    assert r["outcome"] == "cancelled"
    assert state_of(conn, uuid.UUID(job_id)) == "cancelled"


def test_cancel_while_running_is_a_request(registered, worker_headers, put_object, conn):
    job_id, _ = upload_and_admit(registered, put_object)
    registered.post("/api/v1/worker/claim", headers=worker_headers, json={
        "worker_id": "test-worker", "free_mib": 5082,
        "free_vlans": 6, "free_slots": 2,
    })
    r = registered.post(f"/api/v1/jobs/{job_id}/cancel").json()
    assert r["outcome"] == "cancel_requested"
    assert state_of(conn, uuid.UUID(job_id)) == "cloning"


# --- input hostility ------------------------------------------------------

@pytest.mark.parametrize("name", [
    '"; rm -rf ~ #', "$(whoami).sh", "`id`.bin", "'; DROP TABLE jobs; --",
    "<img src=x onerror=alert(1)>.exe", "a b c.exe",
    # Unclosed tags, which carry no slash and are therefore admissible. A
    # different shape from the attribute payload above: an unterminated tag
    # swallows whatever markup follows it, which is how a name breaks out of a
    # template even where closing tags are filtered.
    "<script>alert(1)", '"><script>alert(1)', "<!--",
])
def test_hostile_filenames_round_trip_through_submission(registered, put_object, name):
    """Byte-exact from submission, through the object key, to the worker.

    **Every name here is deliberately ADMITTED.** They are legal filenames, and
    a sample really can be called any of them; refusing them would be
    sanitising, and a sanitised name analyses something the submitter did not
    send (DRAFT-030). The defence against the XSS ones is escaping on OUTPUT,
    which belongs to the web UI -- DRAFT-045 names it explicitly. This test
    pins the contract that UI has to work against: what comes out is what went
    in, byte for byte, however hostile.

    These are `/`-free by necessity. Two used to carry a slash (`rm -rf /`,
    `</script>`) and were changed on 2026-08-24 when submission started
    refusing separators; the hostility they exist to test is the
    metacharacters, not the slash, and the slash cases moved to
    `test_a_filename_that_cannot_be_a_path_component_is_refused` below.
    """
    job_id, detail = upload_and_admit(registered, put_object, filename=name)
    assert detail["submitted_filename"] == name
    assert detail["state"] == "queued"


@pytest.mark.parametrize("name", [
    "../../../etc/passwd",       # out of the bucket prefix entirely
    "../results/other/trace.log",  # into another job's results
    "a/b.exe",                   # any separator at all: the guest path moves
    "/absolute.exe",
    ".",
    "..",
    "sample\x00.exe",            # NUL: a truncation point in any C layer
    "sample\n.exe",              # forges a log line
    "a" * 513,                   # over the byte ceiling
    "é" * 300,              # 600 bytes: max_length in CHARS missed this
])
def test_a_filename_that_cannot_be_a_path_component_is_refused(client, name):
    """Refused at submission, before a row exists or a URL is signed.

    Mirrors `sample_name_admissible()` in `automation/dirwatch.c:250` on
    purpose -- the API is now the boundary that inotify watch used to be.

    Not a live escape today: MinIO refuses `..` components itself with
    XMinioInvalidObjectName (checked 2026-08-24). It is refused here because
    that is MinIO's behaviour and not S3's, because the name also becomes the
    guest staging path, and because a rejected key still leaves a `received`
    row behind that only the abandon sweep clears.
    """
    r = client.post("/api/v1/jobs", json={
        "target_os": "ubuntu", "filename": name, "size_bytes": 4,
    })
    assert r.status_code == 422, (name, r.text[:200])


def test_a_refused_filename_leaves_no_job_row(client, conn):
    """422 before the INSERT, not after.

    `create_job` writes the row and *then* mints the URL, so validation that
    ran later would leave a row nothing can ever upload to -- a free
    row-insertion primitive for anyone who can reach the API.
    """
    before = conn.execute("SELECT count(*) FROM jobs").fetchone()[0]

    client.post("/api/v1/jobs", json={
        "target_os": "ubuntu", "filename": "../../etc/passwd", "size_bytes": 4,
    })

    assert conn.execute("SELECT count(*) FROM jobs").fetchone()[0] == before


def test_the_browser_never_receives_a_credential(client):
    """Only capabilities: one key, short expiry, no access key in the clear
    beyond what SigV4 requires in the signature itself."""
    created = submit(client)
    from sandbox_platform.config import settings

    assert settings.s3_secret_key not in created["upload_url"]
    assert settings.s3_secret_key not in str(created["upload_fields"])


# --- retention -------------------------------------------------------------
#
# Issue #37. MinIO expires objects on a lifecycle rule; the job row is
# permanent. Everything below is about that asymmetry.

def _completed_with_artifacts(conn, age_days: int) -> uuid.UUID:
    """A finished job of a given age, with a manifest and no objects.

    No objects on purpose: what is under test is whether the API offers links,
    not whether the store can serve them.
    """
    return conn.execute(
        """
        INSERT INTO jobs (target_os, submitted_filename, state, manifest,
                          created_at, owner)
        VALUES ('ubuntu', 'x.bin', 'completed', '{"artifacts": ["trace.log"]}',
                now() - %s::interval, 'fixture-owner@example.test')
        RETURNING id
        """,
        (f"{age_days} days",),
    ).fetchone()[0]


def test_a_job_past_retention_offers_no_download_links(client, conn):
    """The link would 404: MinIO removed the object days ago."""
    job_id = _completed_with_artifacts(conn, age_days=45)

    detail = client.get(f"/api/v1/jobs/{job_id}").json()

    assert detail["artifacts_expired"] is True
    assert detail["artifacts"] == {}
    # The manifest survives, and that is the point -- a reader can still tell
    # "this run collected a trace, and it is gone" from "it collected nothing".
    assert detail["manifest"]["artifacts"] == ["trace.log"]


def test_a_job_inside_the_window_still_offers_links(client, conn):
    job_id = _completed_with_artifacts(conn, age_days=1)

    detail = client.get(f"/api/v1/jobs/{job_id}").json()

    assert detail["artifacts_expired"] is False
    assert "trace.log" in detail["artifacts"]


# --- wrapped downloads -----------------------------------------------------
#
# End to end: real objects in the bucket, through the route, decrypted with the
# stdlib. `test_packaging.py` covers the archive format on its own.

def _completed_with_objects(conn, put_object, files: dict[str, bytes]):
    names = json.dumps({"artifacts": sorted(files)})
    job_id = conn.execute(
        """
        INSERT INTO jobs (target_os, submitted_filename, state, manifest, owner)
        VALUES ('ubuntu', 'x.bin', 'completed', %s,
                'fixture-owner@example.test') RETURNING id
        """,
        (names,),
    ).fetchone()[0]
    for name, body in files.items():
        put_object(f"results/{job_id}/{name}", body)
    return job_id


def _unzip(payload: bytes) -> zipfile.ZipFile:
    archive = zipfile.ZipFile(io.BytesIO(payload))
    archive.setpassword(b"infected")
    return archive


def test_one_artifact_downloads_as_an_encrypted_zip(client, conn, put_object):
    """The claim the artifacts tab has made since #38, finally true."""
    payload = b"MZ" + b"\x90" * 2048
    job_id = _completed_with_objects(conn, put_object,
                                     {"extracted/evil.exe": payload})

    r = client.get(f"/api/v1/jobs/{job_id}/artifact.zip",
                   params={"name": "extracted/evil.exe"})

    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    # The executable's own bytes never appear on the wire, which is the whole
    # reason for wrapping: no scanner or browser in between can act on them.
    assert payload not in r.content
    assert _unzip(r.content).read("extracted/evil.exe") == payload


def test_every_artifact_downloads_in_one_archive(client, conn, put_object):
    files = {"trace.log": b"openat\n" * 100,
             "capture.pcap": b"\xd4\xc3\xb2\xa1" + b"\x00" * 500,
             "memdump/0x1000.dmp": b"\xde\xad\xbe\xef" * 64}
    job_id = _completed_with_objects(conn, put_object, files)

    r = client.get(f"/api/v1/jobs/{job_id}/artifacts.zip")

    assert r.status_code == 200
    archive = _unzip(r.content)
    assert set(archive.namelist()) == set(files)
    for name, body in files.items():
        assert archive.read(name) == body


def test_the_download_name_never_carries_the_artifacts_own_name(
        client, conn, put_object):
    """`reject_unsafe_name` admits quotes on purpose, and an artifact called
    `a".exe` would otherwise close the quoting in Content-Disposition."""
    job_id = _completed_with_objects(conn, put_object, {'a";x.exe': b"hi"})

    r = client.get(f"/api/v1/jobs/{job_id}/artifact.zip",
                   params={"name": 'a";x.exe'})

    # Both the quote and the semicolon are replaced, so neither can terminate
    # the quoted string or start a second header parameter.
    assert r.headers["content-disposition"] == 'attachment; filename="a__x.exe.zip"'
    # The real name survives where it matters, inside the archive.
    assert _unzip(r.content).read('a";x.exe') == b"hi"


def test_a_name_not_in_the_manifest_is_refused(client, conn, put_object):
    """**The name resolves against the manifest rather than building a key.**
    Otherwise this route is an arbitrary read over a bucket of live malware."""
    job_id = _completed_with_objects(conn, put_object, {"trace.log": b"ok"})
    put_object(f"results/{job_id}/secret.bin", b"not declared")

    for name in ("secret.bin", "../../samples/x", "trace.log/../secret.bin"):
        r = client.get(f"/api/v1/jobs/{job_id}/artifact.zip",
                       params={"name": name})
        assert r.status_code == 404, name


def test_an_expired_job_refuses_the_download_rather_than_404ing(client, conn):
    """410: the objects existed and the manifest still says what they were,
    which is a different thing to say than "no such job"."""
    job_id = _completed_with_artifacts(conn, age_days=45)

    assert client.get(f"/api/v1/jobs/{job_id}/artifacts.zip").status_code == 410
    assert client.get(f"/api/v1/jobs/{job_id}/artifact.zip",
                      params={"name": "trace.log"}).status_code == 410


def test_a_run_with_no_artifacts_has_nothing_to_download(client, conn):
    job_id = conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, manifest, owner) "
        "VALUES ('ubuntu', 'x.bin', 'completed', '{\"artifacts\": []}', "
        "        'fixture-owner@example.test') RETURNING id"
    ).fetchone()[0]

    assert client.get(f"/api/v1/jobs/{job_id}/artifacts.zip").status_code == 404


def test_download_links_point_at_the_wrapping_routes(client, conn):
    """**Not a presigned GET.** One of those hands over the stored object as it
    is, so an analyst clicking something from `extracted/` received a live
    executable while the tab said it arrived as a password-protected ZIP. The
    wrapping can only happen in this API, so the link has to come back here."""
    job_id = _completed_with_artifacts(conn, age_days=1)

    url = client.get(f"/api/v1/jobs/{job_id}").json()["artifacts"]["trace.log"]

    assert url == f"/api/v1/jobs/{job_id}/artifact.zip?name=trace.log"


def test_an_artifact_name_is_url_encoded_into_the_link(client, conn):
    """Names admit spaces, `&` and unicode by design -- `reject_unsafe_name`
    says so -- and an unencoded one would silently truncate at the `&`."""
    job_id = conn.execute(
        """
        INSERT INTO jobs (target_os, submitted_filename, state, manifest, owner)
        VALUES ('ubuntu', 'x.bin', 'completed',
                '{"artifacts": ["extracted/a b&c.exe"]}',
                'fixture-owner@example.test')
        RETURNING id
        """
    ).fetchone()[0]

    urls = client.get(f"/api/v1/jobs/{job_id}").json()["artifacts"]

    assert urls["extracted/a b&c.exe"].endswith(
        "artifact.zip?name=extracted%2Fa%20b%26c.exe")


def test_retention_disabled_never_expires_anything(client, conn, monkeypatch):
    """RETENTION_DAYS=0 means MinIO has no lifecycle rule, so nothing is
    removed and withholding links would be wrong."""
    import dataclasses

    from sandbox_platform.routers import jobs as jobs_router

    monkeypatch.setattr(jobs_router, "settings",
                        dataclasses.replace(jobs_router.settings,
                                            retention_days=0))
    job_id = _completed_with_artifacts(conn, age_days=3650)

    detail = client.get(f"/api/v1/jobs/{job_id}").json()

    assert detail["artifacts_expired"] is False
    assert "trace.log" in detail["artifacts"]


# --- the guest's filesystem, not just ours ---------------------------------
#
# The filename becomes $GUEST_STAGING_DIR/<name> inside the analysis guest, so
# what it must survive is the GUEST's filesystem. Validated per target_os,
# which arrives in the same request.

@pytest.mark.parametrize("name", [
    "payload:1.bin",              # ADS on NTFS; an ordinary name on ext4
    'quote".bin',
    "wild*card.exe", "who?.exe", "pipe|d.exe", "lt<gt>.exe",
    "back\\slash.exe",
    "CON", "con.txt", "NUL.exe", "COM1", "lpt9.dll",   # DOS device names
    "trailing.exe.", "trailing ",
])
def test_a_name_ntfs_refuses_is_refused_for_windows(client, name):
    """Refused at submission, because it could never be staged.

    `:` is the one that matters rather than the noisiest: on NTFS
    `sample.exe:payload` is not a file, it is an alternate data stream on
    `sample.exe`. `injector -m writefile` would create the stream and what
    the trace then executes is ambiguous -- a sample staged under one name and
    run from another, which is a place to hide a payload outright.

    The device names are the quiet ones: writing to `CON` writes to the
    console, so the sample never lands and it looks like a broken injector.
    """
    r = client.post("/api/v1/jobs", json={
        "target_os": "windows", "filename": name, "size_bytes": 4,
    })
    assert r.status_code == 422, (name, r.text[:200])


@pytest.mark.parametrize("target", ["ubuntu", "android"])
@pytest.mark.parametrize("name", [
    "payload:1.bin", 'quote".bin', "wild*card.exe", "back\\slash.exe",
    "CON", "trailing.exe.", "trailing ",
])
def test_the_same_names_are_legal_on_a_linux_guest(client, target, name):
    """Per-target, not a lowest common denominator.

    Every name above is a perfectly ordinary ext4 filename. Refusing them for
    an Ubuntu or Android sample would discard evidence -- the submitted name is
    part of what is being analysed (DRAFT-030) -- to satisfy a constraint that
    does not apply to that guest.
    """
    r = client.post("/api/v1/jobs", json={
        "target_os": target, "filename": name, "size_bytes": 4,
    })
    assert r.status_code == 201, (target, name, r.text[:200])


@pytest.mark.parametrize("name", ["sample.exe", "CONSOLE.exe", "COM10.dll",
                                  "not-con.exe", "a.CON"])
def test_windows_still_accepts_ordinary_names(client, name):
    """The rules must not over-refuse. `CONSOLE` merely starts with `CON`,
    `COM10` is not a device (only COM1-COM9 are), and `a.CON` has `CON` as an
    extension rather than as the stem."""
    r = client.post("/api/v1/jobs", json={
        "target_os": "windows", "filename": name, "size_bytes": 4,
    })
    assert r.status_code == 201, (name, r.text[:200])


# --- the SSE stream --------------------------------------------------------

def _stream_frames(client, job_id, limit=3):
    """Read up to `limit` data frames, then let the context close the stream."""
    frames = []
    with client.stream("GET", f"/api/v1/jobs/{job_id}/events") as r:
        assert r.status_code == 200
        for line in r.iter_lines():
            if line.startswith("data: "):
                frames.append(json.loads(line[6:]))
                if len(frames) >= limit:
                    break
    return frames


def test_the_stream_opens_with_the_current_state(client, conn):
    """Without this frame the stream loses a race it cannot win.

    NOTIFY only reaches subscribers that already exist, and submit.py
    subscribes AFTER /uploaded returns. A worker long-polling on /claim can
    take a job from queued to completed inside that gap -- a fake or fast
    worker walks the whole state machine at HTTP round-trip speed.

    Reproduced 2026-08-24 by inserting 3s between admission and subscription:
    the job reached `completed` and `--watch` then hung for its full budget.
    On the LAN the gap was sub-millisecond and the race was won by luck; the
    tunnel put Cloudflare, an Access check and a TLS handshake in it.
    """
    job_id = conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, owner) "
        "VALUES ('ubuntu', 'x.bin', 'completed',"
        "        'fixture-owner@example.test') RETURNING id"
    ).fetchone()[0]

    frames = _stream_frames(client, job_id)

    assert frames, "a subscriber that connects after the job finished got nothing"
    assert frames[0]["state"] == "completed"
    assert frames[0]["id"] == str(job_id)


def test_the_stream_ends_at_a_terminal_state(client, conn):
    """Rather than holding a connection open on a job that cannot change.

    submit.py relies on this: it returns when the stream closes, so a stream
    that never closes is a client that never exits.
    """
    job_id = conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, owner) "
        "VALUES ('ubuntu', 'x.bin', 'failed',"
        "        'fixture-owner@example.test') RETURNING id"
    ).fetchone()[0]

    with client.stream("GET", f"/api/v1/jobs/{job_id}/events") as r:
        lines = list(r.iter_lines())     # returns only because the server closes

    assert any('"failed"' in line for line in lines)


# Live delivery -- a snapshot followed by real NOTIFY frames -- is NOT tested
# here. TestClient is synchronous, so reading a stream that stays open needs a
# concurrent writer, and breaking out of iter_lines() mid-stream deadlocks it
# (observed 2026-08-24: the run hung until it was killed). That path is
# covered end to end by `submit.py --watch` against a running worker, which is
# step 23 of the deploy runbook.
