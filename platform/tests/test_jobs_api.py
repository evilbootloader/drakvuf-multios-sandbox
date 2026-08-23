"""The browser channel: submission, admission, and reading results.

Issue #36 (DRAFT-043), with the two-endpoint split from #39.
"""

from __future__ import annotations

import uuid

import pytest

from conftest import WORKER_TOKEN, state_of

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
    created = submit(client, size=len(body), **kw)
    job_id = created["job_id"]
    put_object(f"samples/{job_id}/{kw.get('filename', 'sample.bin')}", body)
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
    put_object(f"samples/{created['job_id']}/sample.bin", b"")
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
    put_object(f"samples/{created['job_id']}/sample.bin", ELF)
    detail = client.post(f"/api/v1/jobs/{created['job_id']}/uploaded").json()
    assert detail["failure_reason"] == "no_workers"


def test_a_job_no_host_can_afford_is_rejected(client, worker_headers, put_object):
    small_host = dict(REGISTRATION, total_mib=4096)
    client.post("/api/v1/worker/register", headers=worker_headers,
                json=small_host)
    created = submit(client, target_os="windows")
    put_object(f"samples/{created['job_id']}/sample.bin", PE)
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
    '"; rm -rf / #', "$(whoami).sh", "`id`.bin", "'; DROP TABLE jobs; --",
    "<script>alert(1)</script>.exe", "a b c.exe",
])
def test_hostile_filenames_round_trip_through_submission(registered, put_object, name):
    """Byte-exact from submission, through the object key, to the worker."""
    job_id, detail = upload_and_admit(registered, put_object, filename=name)
    assert detail["submitted_filename"] == name
    assert detail["state"] == "queued"


def test_the_browser_never_receives_a_credential(client):
    """Only capabilities: one key, short expiry, no access key in the clear
    beyond what SigV4 requires in the signature itself."""
    created = submit(client)
    from sandbox_platform.config import settings

    assert settings.s3_secret_key not in created["upload_url"]
    assert settings.s3_secret_key not in str(created["upload_fields"])
