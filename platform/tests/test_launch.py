"""Where a sample is dropped and what it is passed (`launch.py`, 2026-11-01).

The API half: what is accepted, what is refused, what is stored and what the
worker is leased. The rendering half: the submit form offers each guest's own
locations with the analysis username in the path, and the job page shows what
was asked for -- escaped, because the command line is the submitter's text.

`sandboxd/tests/test_guests.py` pins that the host's copy of the location
table, and of the subfolder rule, agrees with this one.
"""

from __future__ import annotations

import uuid

import pytest
from conftest import owner_id
from markupsafe import escape

from sandbox_platform.config import settings

ELF = b"\x7fELF" + b"\x00" * 60

REGISTRATION = {
    "total_mib": 16384, "total_vlans": 8, "total_slots": 2,
    "pipelines": [{"os": "ubuntu", "required_mib": 2048},
                  {"os": "android", "required_mib": 2048},
                  {"os": "windows", "required_mib": 4096}],
}


def create(client, target_os="ubuntu", size=len(ELF), **launch):
    return client.post("/api/v1/jobs", json={
        "target_os": target_os, "filename": "sample.bin", "size_bytes": size,
        "plugins": ["syscalls"], "timeout": 180, "disable_sysret": True,
        **launch,
    })


def stored(conn, job_id) -> tuple:
    return conn.execute(
        "SELECT drop_location, drop_subdir, arguments FROM jobs WHERE id = %s",
        (job_id,)).fetchone()


# --- the API --------------------------------------------------------------

def test_a_job_that_chooses_nothing_stores_nothing(client, conn):
    """NULL is "the guest's default", which is what every older row means."""
    r = create(client)
    assert r.status_code == 201, r.text
    assert stored(conn, r.json()["job_id"]) == (None, None, None)


def test_empty_fields_are_stored_as_nothing_chosen(client, conn):
    r = create(client, drop_subdir="  ", arguments="   ")
    assert r.status_code == 201, r.text
    assert stored(conn, r.json()["job_id"]) == (None, None, None)


def test_a_choice_is_stored_with_its_subfolder_in_one_spelling(client, conn):
    r = create(client, "windows", drop_location="appdata",
               drop_subdir="Vendor\\App 2\\", arguments="  /S /D=C:\\x  ")
    assert r.status_code == 201, r.text
    job_id = r.json()["job_id"]
    assert stored(conn, job_id) == ("appdata", "Vendor/App 2", "/S /D=C:\\x")

    detail = client.get(f"/api/v1/jobs/{job_id}").json()
    assert (detail["drop_location"], detail["drop_subdir"], detail["arguments"]) \
        == ("appdata", "Vendor/App 2", "/S /D=C:\\x")


@pytest.mark.parametrize("target_os,launch", [
    ("ubuntu", {"drop_location": "appdata"}),        # a Windows folder
    ("android", {"drop_location": "desktop"}),       # one location only
    ("windows", {"drop_location": "C:\\Windows"}),   # a path is never a key
    ("ubuntu", {"drop_location": "../etc"}),
    ("ubuntu", {"drop_subdir": "../../etc"}),
    ("ubuntu", {"drop_subdir": "/etc"}),
    ("windows", {"drop_subdir": "C:\\Windows"}),
    ("windows", {"drop_subdir": 'x" & calc & "'}),
    ("windows", {"drop_subdir": "%APPDATA%"}),
    ("windows", {"drop_subdir": "CON"}),
    ("ubuntu", {"drop_subdir": "$(id)"}),
    ("ubuntu", {"drop_subdir": "x" * 129}),
    ("ubuntu", {"arguments": "'unclosed"}),          # cannot be split
    ("windows", {"arguments": "a\r\nb"}),            # ends a cmd.exe command
    ("ubuntu", {"arguments": "a\x00b"}),
    ("ubuntu", {"arguments": "x" * 1025}),
])
def test_what_no_guest_could_honour_is_refused_without_a_row(client, conn,
                                                           target_os, launch):
    before = conn.execute("SELECT count(*) FROM jobs").fetchone()[0]
    r = create(client, target_os, **launch)
    assert r.status_code == 422, r.text
    assert conn.execute("SELECT count(*) FROM jobs").fetchone()[0] == before


def test_windows_takes_a_command_line_a_shell_could_not_split(client, conn):
    """Windows programs split their own command line; an open quote is the
    submitter's business there, and reaches the sample as typed."""
    r = create(client, "windows", arguments='"C:\\a b')
    assert r.status_code == 201, r.text
    assert stored(conn, r.json()["job_id"])[2] == '"C:\\a b'


def test_the_worker_is_leased_what_was_asked_for(client, worker_headers,
                                                 put_object):
    client.post("/api/v1/worker/register", headers=worker_headers,
                json=REGISTRATION)
    created = create(client, drop_location="temp", drop_subdir="a/b",
                     arguments="--x 'y z'").json()
    put_object(created["upload_fields"]["key"], ELF)
    client.post(f"/api/v1/jobs/{created['job_id']}/uploaded")

    lease = client.post("/api/v1/worker/claim", headers=worker_headers, json={
        "free_mib": 8192, "free_vlans": 6, "free_slots": 2}).json()

    assert lease["status"] == "leased"
    assert (lease["drop_location"], lease["drop_subdir"], lease["arguments"]) \
        == ("temp", "a/b", "--x 'y z'")


# --- the form ---------------------------------------------------------------

def test_the_form_offers_the_first_guests_locations_with_the_username(client):
    page = client.get("/ui/submit").text
    user = settings.analysis_username

    assert 'name="drop_location"' in page
    assert 'name="drop_subdir"' in page
    assert 'name="arguments"' in page
    assert f"/home/{user}/Desktop" in page
    assert f"/home/{user}/Downloads" in page
    # Rendered in place on the page, so not marked for an out-of-band swap.
    assert 'hx-swap-oob' not in page


def test_switching_guest_swaps_the_locations_out_of_band(client):
    """The Execution block sits outside the plugin list's swap target, so the
    plugin route sends it again for htmx to place by id."""
    page = client.get("/ui/plugins/windows").text
    user = settings.analysis_username

    assert 'id="launch-options"' in page and 'hx-swap-oob="true"' in page
    assert str(escape(f"C:\\Users\\{user}\\AppData\\Roaming")) in page
    assert "C:\\ProgramData" in page
    assert "/home/" not in page


def test_android_offers_one_location_and_says_why(client):
    page = client.get("/ui/plugins/android").text
    assert page.count('<option value=') == 1
    assert "/data/local/tmp" in page
    assert "noexec" in page


# --- the report -------------------------------------------------------------

def _job(conn, **launch) -> uuid.UUID:
    cols = ", ".join(launch)
    marks = ", ".join(["%s"] * len(launch))
    return conn.execute(
        f"""
        INSERT INTO jobs (target_os, submitted_filename, state, owner
                          {', ' + cols if cols else ''})
        VALUES ('windows', 'setup.exe', 'completed', %s
                {', ' + marks if marks else ''})
        RETURNING id
        """,
        (owner_id(conn), *launch.values()),
    ).fetchone()[0]


def test_overview_shows_where_it_was_dropped_and_what_it_was_passed(client, conn):
    hostile = '<script>alert(1)</script> & "x"'
    job_id = _job(conn, drop_location="temp", drop_subdir="a/b",
                  arguments=hostile)
    page = client.get(f"/ui/jobs/{job_id}").text
    user = settings.analysis_username

    assert str(escape(f"C:\\Users\\{user}\\AppData\\Local\\Temp\\a\\b")) in page
    assert str(escape(hostile)) in page
    assert hostile not in page


def test_overview_shows_the_guests_default_when_nothing_was_chosen(client, conn):
    page = client.get(f"/ui/jobs/{_job(conn)}").text
    assert str(escape(f"C:\\Users\\{settings.analysis_username}\\Desktop")) in page
