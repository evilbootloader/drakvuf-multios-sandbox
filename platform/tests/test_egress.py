"""Per-job egress selection, end to end through the API. DRAFT-057.

The property under test throughout: **a submitter can never get more network
than a host declared, and never gets network they did not ask for.** Every test
here is one way of trying to break that.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sandbox_platform import egress
from sandbox_platform.enums import EgressMode

ELF = b"\x7fELF" + b"\x00" * 60

# The id MUST match `worker_headers`' X-Worker-Id: the claim body sets
# lease_owner, and job-scoped routes resolve the job by the HEADER. Use two
# different names and every claim succeeds while every later report 404s.
WORKER = "test-worker"

BASE = {"total_mib": 8192, "total_vlans": 4,
        "total_slots": 4,
        "pipelines": [{"os": "ubuntu", "required_mib": 2048}]}


def register(client, headers, exits):
    r = client.post("/api/v1/worker/register", headers=headers,
                    json={**BASE, "exits": exits})
    assert r.status_code == 204, r.text
    return client


def submit(client, **kw):
    body = {"target_os": "ubuntu", "filename": "sample.bin",
            "size_bytes": len(ELF), **kw, "plugins":["syscalls"],  "timeout":180, "disable_sysret": True}
    return client.post("/api/v1/jobs", json=body)


def admit(client, put_object, created):
    # The key comes from the SIGNED POLICY the API just handed back, not from a
    # path built here. Every submission is owned since migration 0008, so the
    # object lives under `u/<owner>/<shard>/` and a hand-built `samples/<id>/`
    # key misses it -- which surfaces as `unreadable`, a real rejection reason,
    # and looks like the thing under test failing.
    job_id = created["job_id"]
    put_object(created["upload_fields"]["key"], ELF)
    return client.post(f"/api/v1/jobs/{job_id}/uploaded").json()


SIMULATED = [{"name": "sim-local", "mode": "simulated", "country": None,
              "caveats": ["no-real-internet"]}]
TOR = [{"name": "tor-default", "mode": "tor", "country": None,
        "caveats": ["tcp-only", "smtp-blocked-upstream"]}]
DIRECT = [{"name": "host-uplink", "mode": "direct", "country": None,
           "caveats": ["egresses-via-host-uplink"]}]


# --- the default ----------------------------------------------------------

def test_saying_nothing_never_yields_internet_access(client, worker_headers):
    """The property that matters most about the default.

    A submitter who expresses no preference must not get a live way out, no
    matter what the hosts happen to offer. Here every live mode is available
    and the resolver still picks the responder.
    """
    register(client, worker_headers, SIMULATED + TOR + DIRECT)
    job = submit(client).json()
    detail = client.get(f"/api/v1/jobs/{job['job_id']}").json()
    assert detail["egress_mode"] == "simulated"
    assert detail["egress_exit"] == "sim-local"


def test_the_default_falls_back_to_offline_when_nothing_is_offered(
        client, worker_headers):
    """A deployment where Phase 3 has not shipped must still accept work.

    Hard-coding `simulated` as the default would refuse every submission on a
    host with no responder -- a fleet-wide outage caused by a default.
    """
    register(client, worker_headers, [])
    job = submit(client).json()
    detail = client.get(f"/api/v1/jobs/{job['job_id']}").json()
    assert detail["egress_mode"] == "offline"
    assert detail["egress_exit"] is None


def test_a_mode_without_an_exit_resolves_to_one(client, worker_headers):
    """"any exit that does this" is a legitimate request, not an error."""
    register(client, worker_headers, TOR)
    job = submit(client, egress_mode="tor").json()
    detail = client.get(f"/api/v1/jobs/{job['job_id']}").json()
    assert detail["egress_exit"] == "tor-default"


def test_resolution_is_deterministic(client, worker_headers):
    """Two identical submissions must get the same exit.

    Otherwise two reports of the same sample are not comparable, and the
    difference would be invisible.
    """
    register(client, worker_headers, [
        {"name": "tor-b", "mode": "tor"}, {"name": "tor-a", "mode": "tor"},
    ])
    first = submit(client, egress_mode="tor").json()["job_id"]
    second = submit(client, egress_mode="tor").json()["job_id"]
    got = {client.get(f"/api/v1/jobs/{j}").json()["egress_exit"]
           for j in (first, second)}
    assert got == {"tor-a"}


# --- the gate -------------------------------------------------------------

def test_an_undeclared_exit_is_rejected(client, worker_headers, put_object):
    """Refused, never downgraded.

    A submitter asked a specific question about where their sample's traffic
    goes. Running it somewhere else and reporting success answers a different
    question than the one the report will show.
    """
    register(client, worker_headers, SIMULATED)
    job = submit(client, egress_mode="tor", egress_exit="tor-default").json()
    detail = admit(client, put_object, job)
    assert detail["state"] == "rejected"
    assert detail["failure_reason"] == "no_egress"


def test_direct_is_unreachable_until_a_host_declares_it(
        client, worker_headers, put_object):
    """**The gate on the residential line.**

    There is no rule about `direct` anywhere in the API. It is refused purely
    because no host declared it, which is why the API cannot fall out of step
    with the host's actual posture.
    """
    register(client, worker_headers, SIMULATED)
    job = submit(client, egress_mode="direct",
                 egress_exit="host-uplink").json()
    detail = admit(client, put_object, job)
    assert detail["state"] == "rejected"
    assert detail["failure_reason"] == "no_egress"


def test_direct_works_once_the_host_opts_in(client, worker_headers, put_object):
    """The same submission, accepted, with the only difference being the host.

    Paired with the test above this pins the gate to one cause.
    """
    register(client, worker_headers, DIRECT)
    job = submit(client, egress_mode="direct",
                 egress_exit="host-uplink").json()
    detail = admit(client, put_object, job)
    assert detail["state"] == "queued"


def test_withdrawing_an_exit_removes_it(client, worker_headers, put_object):
    """Registration REPLACES a host's exits rather than merging them.

    The case this protects: an operator unsets SANDBOXD_ALLOW_DIRECT and
    restarts. `direct` must be gone immediately, not linger because nothing
    deleted the row.
    """
    register(client, worker_headers, DIRECT)
    register(client, worker_headers, SIMULATED)
    job = submit(client, egress_mode="direct",
                 egress_exit="host-uplink").json()
    detail = admit(client, put_object, job)
    assert detail["state"] == "rejected"
    assert detail["failure_reason"] == "no_egress"


def test_a_mode_cannot_be_paired_with_another_modes_exit(
        client, worker_headers, put_object):
    """Name and mode are checked TOGETHER.

    Matching the name alone would let a submitter pair a real exit with a
    different mode -- the exit would resolve on Dom0 and the mode printed on
    the report would be a lie about what happened.
    """
    register(client, worker_headers, TOR)
    job = submit(client, egress_mode="routed",
                 egress_exit="tor-default").json()
    detail = admit(client, put_object, job)
    assert detail["state"] == "rejected"
    assert detail["failure_reason"] == "no_egress"


# --- the boundary ---------------------------------------------------------

@pytest.mark.parametrize("bad", ["internet", "OFFLINE", "../tor", "", 7])
def test_the_mode_is_a_closed_set(client, bad):
    """The second untrusted routing input, refused at the type boundary."""
    assert submit(client, egress_mode=bad).status_code == 422


def test_offline_may_not_name_an_exit(client):
    """Incoherent no matter what any host offers, so it is a 422 not a reject.

    A row saying both would contradict itself.
    """
    r = submit(client, egress_mode="offline", egress_exit="tor-default")
    assert r.status_code == 422
    assert "cannot mean anything" in r.text


def test_offline_needs_no_host_at_all(client, put_object):
    """No worker is registered here.

    On Dom0 `offline` is the absence of a rule, so every host can always
    provide it -- and checking would create a way for the SAFEST mode to be
    refused, which is the wrong direction to fail in.
    """
    job = submit(client, egress_mode="offline").json()
    detail = admit(client, put_object, job)
    assert detail["failure_reason"] != "no_egress"


# --- what reaches the worker, and what comes back -------------------------

def test_the_lease_carries_the_choice(client, worker_headers, put_object, conn):
    # `conn` for its TRUNCATE, not for its connection: a claim takes the HEAD
    # of the queue, so without it this test can lease a job another test left
    # behind and assert against the wrong row.
    register(client, worker_headers, TOR)
    job = submit(client, egress_mode="tor").json()
    admit(client, put_object, job)

    claim = client.post("/api/v1/worker/claim", headers=worker_headers, json={ "free_mib": 8192, "free_vlans": 4,
        "free_slots": 4}).json()
    assert claim["status"] == "leased"
    assert claim["egress_mode"] == "tor"
    assert claim["egress_exit"] == "tor-default"


def test_the_host_records_what_it_actually_applied(
        client, worker_headers, put_object, conn):
    """Requested and applied are kept apart, because they can differ.

    DRAFT-057 makes recording the mode a correctness requirement: a report
    showing no network activity means nothing without knowing whether egress
    existed at all.
    """
    register(client, worker_headers, SIMULATED)
    job = submit(client, egress_mode="simulated").json()
    job_id = job["job_id"]
    admit(client, put_object, job)
    client.post("/api/v1/worker/claim", headers=worker_headers, json={ "free_mib": 8192, "free_vlans": 4,
        "free_slots": 4})

    # The host could not start its responder and fell back, honestly.
    r = client.post(f"/api/v1/worker/jobs/{job_id}/state",
                    headers=worker_headers,
                    json={"state": "preparing", "vlan": 3,
                          "egress": {"mode": "offline", "exit": "sim-local",
                                     "reason": "responder unavailable",
                                     "caveats": ["no-real-internet"]}})
    assert r.status_code == 204, r.text

    detail = client.get(f"/api/v1/jobs/{job_id}").json()
    assert detail["egress_mode"] == "simulated"          # what was asked
    assert detail["egress_applied"]["mode"] == "offline"  # what happened
    assert detail["egress_applied"]["reason"] == "responder unavailable"


def test_an_old_worker_registering_without_exits_offers_none(
        client, worker_headers, put_object):
    """The worker channel must tolerate the two sides deployed minutes apart.

    An old worker's silence means it offers nothing, which is the correct
    reading -- not an error, and not everything.
    """
    r = client.post("/api/v1/worker/register", headers=worker_headers,
                    json=BASE)
    assert r.status_code == 204
    job = submit(client, egress_mode="tor", egress_exit="tor-default").json()
    detail = admit(client, put_object, job)
    assert detail["failure_reason"] == "no_egress"


# --- the catalogue --------------------------------------------------------

def test_every_mode_has_a_description():
    """The form renders these; a missing one would be a blank radio button."""
    for mode in EgressMode:
        assert mode in egress.BY_MODE
        assert egress.BY_MODE[mode].describes


def test_only_the_truly_live_modes_are_marked_live():
    live = {m.mode for m in egress.MODES if m.live}
    assert live == {EgressMode.TOR, EgressMode.ROUTED, EgressMode.DIRECT}


def test_offers_sort_safest_first():
    offers = [egress.Offer("d", EgressMode.DIRECT),
              egress.Offer("t", EgressMode.TOR),
              egress.Offer("s", EgressMode.SIMULATED)]
    assert [o.mode for o in egress.sort_offers(offers)][0] is EgressMode.SIMULATED


def test_an_unknown_caveat_is_shown_rather_than_dropped():
    """Dropping it would hide a limitation the host explicitly reported."""
    assert egress.describe_caveat("some-new-block") == "some-new-block"


def test_every_caveat_sandboxd_can_send_has_prose_here():
    """A slug with no prose renders as the slug, which is ugly but honest.

    This test is about the ugliness. Both sides declare the same vocabulary in
    two files that nothing else makes agree, so a caveat added on the host
    reaches the page as `tls-untrusted-cert` rather than as a sentence a
    submitter can act on.
    """
    import re

    source = (Path(__file__).resolve().parents[2]
              / "sandboxd" / "egress.py").read_text()
    slugs = set(re.findall(r'^CAVEAT_\w+ = "([^"]+)"', source, re.MULTILINE))
    assert slugs, "no caveat constants found; did sandboxd/egress.py move?"

    missing = sorted(slugs - set(egress.CAVEATS))
    assert not missing, (
        f"sandboxd can send {missing} and this deployment has no prose for "
        f"them; they would reach the report as raw slugs")


def test_simulated_discloses_that_https_is_refused():
    """The caveat that stops an empty report reading as a quiet sample.

    FakeNet's certificate comes from an ephemeral CA the guest never trusted,
    so a sample that validates answers the handshake with
    SSLV3_ALERT_BAD_CERTIFICATE and its HTTPS never reaches a listener --
    observed on Dom0 2026-09-01. Installing the CA in the guest would fix the
    handshake and add an enumerable sandbox artefact, so the limitation is
    disclosed instead, and disclosure only works if the string is here.
    """
    prose = egress.describe_caveat("tls-untrusted-cert")
    assert prose != "tls-untrusted-cert", "no prose for the TLS caveat"
    assert "HTTPS" in prose