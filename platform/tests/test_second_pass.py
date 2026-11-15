"""A job that asks to be run twice (migration 0015, 2026-11-14): the analysis
host reads the first run's memory and traces the sample again with hooks on
what it showed (`sandboxd/stagehints.py`). Here: the choice is stored, leased
and offered on the form; `sandboxd/tests/test_stagehints.py` has what the host
does with it.
"""

from __future__ import annotations

import pytest
from test_launch import ELF, REGISTRATION, create
from test_tenancy import as_a, as_b  # noqa: F401 - fixtures

from sandbox_platform import objects


def asked(conn, job_id) -> bool:
    return conn.execute("SELECT second_pass FROM jobs WHERE id = %s", (job_id,)).fetchone()[0]


def test_a_job_is_one_run_unless_it_asks(client, conn):
    r = create(client)
    assert r.status_code == 201, r.text
    assert asked(conn, r.json()["job_id"]) is False

    r = create(client, second_pass=True)
    assert r.status_code == 201, r.text
    assert asked(conn, r.json()["job_id"]) is True


@pytest.mark.parametrize("value", ["yes", "0", 1, None, [True]])
def test_only_a_boolean_asks(client, conn, value):
    """It can double the job's time: "0" is not read as yes, nor 1."""
    r = create(client, second_pass=value)
    assert r.status_code == 422, r.text
    assert conn.execute("SELECT count(*) FROM jobs").fetchone()[0] == 0


@pytest.mark.parametrize("wanted", [True, False])
def test_the_worker_is_leased_the_choice(client, worker_headers, put_object, wanted):
    client.post("/api/v1/worker/register", headers=worker_headers, json=REGISTRATION)
    created = create(client, second_pass=wanted).json()
    put_object(created["upload_fields"]["key"], ELF)
    client.post(f"/api/v1/jobs/{created['job_id']}/uploaded")

    lease = client.post("/api/v1/worker/claim", headers=worker_headers, json={
        "free_mib": 8192, "free_vlans": 6, "free_slots": 2}).json()

    assert lease["status"] == "leased" and lease["second_pass"] is wanted


def test_the_form_does_not_offer_it(client):
    """Whether a sample is worth a second run is read off its first: the
    option is in the first run's report (operator, 2026-11-14). The API
    field stays for a client that knows beforehand."""
    assert "second_pass" not in client.get("/").text


# --- "Run again", from a finished job ----------------------------------------

import hashlib  # noqa: E402

HINTS = b"/home/u/sample.bin,connect,1040,when:554889e5,log,Fd:int\n"


def finished(client, conn, put_object, worker_headers, *, hints=True, state="completed",
             headers=None, **options) -> dict:
    """A job that ran, as the worker leaves it: completed, its manifest
    listing what was uploaded, `hints.txt` among it when its memory showed
    something."""
    client.post("/api/v1/worker/register", headers=worker_headers, json=REGISTRATION)
    created = client.post("/api/v1/jobs", headers=headers or {}, json={
        "target_os": "ubuntu", "filename": "sample.bin", "size_bytes": len(ELF),
        "plugins": ["syscalls", "libmon", "procdump2"], "timeout": 90, "disable_sysret": False,
        **options}).json()
    put_object(created["upload_fields"]["key"], ELF)
    assert client.post(f"/api/v1/jobs/{created['job_id']}/uploaded", headers=headers or {}).json()["state"] == "queued"
    prefix = conn.execute("SELECT key_prefix FROM jobs WHERE id = %s", (created["job_id"],)).fetchone()[0]
    artifacts = [{"name": "trace.log.gz", "size_bytes": 1, "sha256": "0" * 64}]
    if hints:
        put_object(f"{prefix}results/{created['job_id']}/hints.txt", HINTS)
        artifacts.append({"name": "hints.txt", "size_bytes": len(HINTS),
                          "sha256": hashlib.sha256(HINTS).hexdigest()})
    from psycopg.types.json import Jsonb
    conn.execute("UPDATE jobs SET state = %s, manifest = %s WHERE id = %s",
                 (state, Jsonb({"schema_version": 1, "artifacts": artifacts, "documents": [],
                                "truncated": False}), created["job_id"]))
    return created


def test_a_finished_job_with_hints_spawns_its_second_run(client, conn, put_object, worker_headers):
    first = finished(client, conn, put_object, worker_headers, drop_location="temp", arguments="-x")
    assert client.get(f"/api/v1/jobs/{first['job_id']}").json()["second_run_available"] is True

    made = client.post(f"/api/v1/jobs/{first['job_id']}/second-run")
    assert made.status_code == 201, made.text
    second = made.json()
    assert second["job_id"] != first["job_id"] and second["state"] == "queued"

    # the first job's object, never a copy: the store's front refuses
    # CopyObject (garage/objects.conf), and nothing is written under the new id
    first_key = conn.execute("SELECT key_prefix FROM jobs WHERE id = %s", (first["job_id"],)).fetchone()[0] \
        + f"samples/{first['job_id']}/sample.bin"
    assert conn.execute("SELECT sample_key FROM jobs WHERE id = %s", (second["job_id"],)).fetchone()[0] == first_key
    assert objects.head(objects.sample_key(second["job_id"], "sample.bin", conn.execute(
        "SELECT key_prefix FROM jobs WHERE id = %s", (second["job_id"],)).fetchone()[0])) is None

    # the same sample, admitted again, and the same options
    row = conn.execute(
        "SELECT sha256, target_os, timeout, plugins::text[], drop_location, arguments, second_run_of::text,"
        "       second_pass FROM jobs WHERE id = %s", (second["job_id"],)).fetchone()
    assert row == (hashlib.sha256(ELF).hexdigest(), "ubuntu", 90, ["syscalls", "libmon", "procdump2"],
                   "temp", "-x", first["job_id"], False)
    detail = client.get(f"/api/v1/jobs/{second['job_id']}").json()
    assert detail["second_run_of"] == first["job_id"] and detail["second_run_available"] is False
    # the first job is as it was
    assert client.get(f"/api/v1/jobs/{first['job_id']}").json()["state"] == "completed"

    # and the host is leased the lines of the first run
    lease = client.post("/api/v1/worker/claim", headers=worker_headers, json={
        "free_mib": 8192, "free_vlans": 6, "free_slots": 2}).json()
    # the claim reads the first job's object, and finds it the one admitted
    assert lease["job_id"] == second["job_id"] and lease["second_run_of"] == first["job_id"]
    assert f"samples/{first['job_id']}/sample.bin" in lease["sample_url"]
    assert f"results/{first['job_id']}/hints.txt" in lease["hints_url"]
    import httpx
    assert httpx.get(lease["hints_url"]).content == HINTS


def test_a_second_run_of_a_second_run_runs_the_same_object(client, conn, put_object, worker_headers):
    first = finished(client, conn, put_object, worker_headers)
    second = client.post(f"/api/v1/jobs/{first['job_id']}/second-run").json()
    prefix = conn.execute("SELECT key_prefix FROM jobs WHERE id = %s", (second["job_id"],)).fetchone()[0]
    put_object(f"{prefix}results/{second['job_id']}/hints.txt", HINTS)
    from psycopg.types.json import Jsonb
    conn.execute("UPDATE jobs SET state = 'completed', manifest = %s WHERE id = %s",
                 (Jsonb({"schema_version": 1, "documents": [], "truncated": False,
                         "artifacts": [{"name": "hints.txt", "size_bytes": len(HINTS),
                                        "sha256": hashlib.sha256(HINTS).hexdigest()}]}), second["job_id"]))
    third = client.post(f"/api/v1/jobs/{second['job_id']}/second-run")
    assert third.status_code == 201, third.text
    keys = [conn.execute("SELECT sample_key FROM jobs WHERE id = %s", (j,)).fetchone()[0]
            for j in (second["job_id"], third.json()["job_id"])]
    assert keys[0] == keys[1] and f"samples/{first['job_id']}/" in keys[0]


def test_an_ordinary_lease_carries_no_hints(client, worker_headers, put_object):
    client.post("/api/v1/worker/register", headers=worker_headers, json=REGISTRATION)
    created = create(client).json()
    put_object(created["upload_fields"]["key"], ELF)
    client.post(f"/api/v1/jobs/{created['job_id']}/uploaded")
    lease = client.post("/api/v1/worker/claim", headers=worker_headers, json={
        "free_mib": 8192, "free_vlans": 6, "free_slots": 2}).json()
    assert lease["hints_url"] is None and lease["second_run_of"] is None


def test_nothing_to_run_again_with_is_refused(client, conn, put_object, worker_headers):
    """No lines, or a run that did not complete: a second run would add nothing."""
    plain = finished(client, conn, put_object, worker_headers, hints=False)
    assert client.get(f"/api/v1/jobs/{plain['job_id']}").json()["second_run_available"] is False
    assert client.post(f"/api/v1/jobs/{plain['job_id']}/second-run").status_code == 409

    failed = finished(client, conn, put_object, worker_headers, state="failed")
    assert client.post(f"/api/v1/jobs/{failed['job_id']}/second-run").status_code == 409
    assert conn.execute("SELECT count(*) FROM jobs").fetchone()[0] == 2


def test_only_the_owner_runs_a_job_again(client, conn, put_object, worker_headers, as_a, as_b):
    """404, as for a job that does not exist: it spends the owner's balance
    and copies their sample, published or not."""
    first = finished(client, conn, put_object, worker_headers, headers=as_a)
    conn.execute("UPDATE jobs SET visibility = 'public' WHERE id = %s", (first["job_id"],))
    refused = client.post(f"/api/v1/jobs/{first['job_id']}/second-run", headers=as_b)
    assert refused.status_code == 404
    assert conn.execute("SELECT count(*) FROM jobs").fetchone()[0] == 1
    assert client.post(f"/api/v1/jobs/{first['job_id']}/second-run", headers=as_a).status_code == 201


def test_no_balance_and_no_sample_are_said(client, conn, put_object, worker_headers):
    first = finished(client, conn, put_object, worker_headers)
    conn.execute("UPDATE tenants SET balance_seconds = 0")
    assert client.post(f"/api/v1/jobs/{first['job_id']}/second-run").status_code == 402
    conn.execute("UPDATE tenants SET balance_seconds = 3600")
    # retention took the sample: renamed on the row, so the key names nothing
    conn.execute("UPDATE jobs SET submitted_filename = 'gone.bin' WHERE id = %s", (first["job_id"],))
    assert client.post(f"/api/v1/jobs/{first['job_id']}/second-run").status_code == 410


def test_the_report_offers_it_beside_the_memory_and_the_dropped_files(client, conn, put_object, worker_headers):
    first = finished(client, conn, put_object, worker_headers)
    for tab in ("memory", "dropped"):
        page = client.get(f"/ui/jobs/{first['job_id']}?tab={tab}").text
        assert "data-second-run " in page and "hints.txt" in page, tab
    # not in the header, and not on a tab that is about something else
    assert "data-second-run " not in client.get(f"/ui/jobs/{first['job_id']}?tab=overview").text

    second = client.post(f"/api/v1/jobs/{first['job_id']}/second-run").json()
    page = client.get(f"/ui/jobs/{second['job_id']}?tab=memory").text
    assert "data-second-run " not in page
    assert f'href="/ui/jobs/{first["job_id"]}"' in page

    plain = finished(client, conn, put_object, worker_headers, hints=False)
    assert "data-second-run " not in client.get(f"/ui/jobs/{plain['job_id']}?tab=memory").text


def test_nothing_here_asks_the_store_to_copy():
    """The deployed store's front answers 403 to every request carrying
    x-amz-copy-source (garage/objects.conf, DECISION A2), and the test store
    has no front: a copy passes here and fails there, as second_run's did on
    2026-11-15."""
    from pathlib import Path
    import sandbox_platform
    root = Path(sandbox_platform.__file__).parent
    offenders = [str(p.relative_to(root)) for p in root.rglob("*.py")
                 if any(word in p.read_text() for word in ("copy_object", "CopySource", "upload_part_copy"))]
    assert offenders == []
