"""The worker channel: issue #41 (DRAFT-060).

Two kinds of test here, and the split is deliberate.

**Contract** — what the client sends is validated against the SERVER's own
pydantic models, imported from `sandbox_platform`. No Postgres, no MinIO, no
running API: if `RegisterRequest` or `ClaimRequest` changes shape, these fail
here rather than at 3am on Dom0 against a platform that was upgraded.

**Behaviour** — retry, backoff, cancellation and the credential split, driven
through `httpx.MockTransport`. Those are properties of this client, not of the
protocol, and a real server would not exercise the interesting cases (a
connection that drops, a 500 that clears).
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "platform"))

# The server models read config at import; give them something harmless. They
# never connect -- validation is local.
os.environ.setdefault("DATABASE_URL", "postgresql:///unused")
os.environ.setdefault("WORKER_TOKEN", "unused")

from sandboxd.api import (  # noqa: E402
    Idle, Lease, ProtocolError, Reserved, SampleMismatch, Ticket, WorkerAPI,
)

from sandbox_platform.routers.worker import (  # noqa: E402
    ArtifactRequest, ClaimRequest, CompleteRequest, ReconcileRequest,
    RegisterRequest, StateRequest,
)


def api(handler, *, store=None) -> WorkerAPI:
    t = httpx.MockTransport(handler)
    return WorkerAPI("https://platform:8443", "tok", "dom0-1",
                     transport=t, store_transport=httpx.MockTransport(store)
                     if store else None)


def ok(payload):
    return lambda request: httpx.Response(200, json=payload)


# --- contract: what we send is what the server accepts ---------------------

def test_the_registration_body_satisfies_the_server_model():
    """Validated against RegisterRequest itself, so a field rename on the
    platform breaks this test rather than the daemon."""
    body = api(ok({})).register_body(
        total_mib=16384, total_vlans=8, total_slots=4,
        pipelines={"ubuntu": 2198, "android": 2198, "windows": 6294},
    )

    parsed = RegisterRequest.model_validate(body)

    # No `worker_id` in the body since DRAFT-061: the platform derives it from
    # the credential, so sending one would be a claim with nothing behind it.
    assert not hasattr(parsed, "worker_id")
    assert {p.os.value: p.required_mib for p in parsed.pipelines} == {
        "ubuntu": 2198, "android": 2198, "windows": 6294}


def test_the_claim_body_satisfies_the_server_model():
    body = api(ok({})).claim_body(free_mib=8192, free_vlans=6, free_slots=3)
    assert ClaimRequest.model_validate(body).free_mib == 8192


def test_the_reconcile_body_satisfies_the_server_model():
    body = api(ok({})).reconcile_body([])
    assert ReconcileRequest.model_validate(body).live_job_ids == []


def test_no_request_body_carries_an_unbound_worker_id():
    """DRAFT-061 removed the field; sandboxd kept sending it for a while.

    **Asserted on the BODY, not on the parsed model**, and that distinction is
    the whole reason this test exists. `RegisterRequest`, `ClaimRequest` and
    `ReconcileRequest` do not set `extra="forbid"` (unlike `Manifest` and
    `ArtifactEntry`), so pydantic drops an unexpected `worker_id` without
    complaint -- every model-side assertion above passed while the client was
    still putting an identity claim on the wire that nothing bound to the
    credential carrying it.

    `self.worker_id` is deliberately still populated: `stages._start_console`
    passes it to the relay and the logs use it. What it may not do is travel
    as a field the platform could be tempted to trust.
    """
    client = api(ok({}))
    bodies = {
        "register": client.register_body(total_mib=1, total_vlans=1,
                                         total_slots=1, pipelines={}),
        "claim": client.claim_body(free_mib=1, free_vlans=1, free_slots=1),
        "reconcile": client.reconcile_body(["j1"]),
    }

    for name, body in bodies.items():
        assert "worker_id" not in body, (
            f"the {name} body still sends worker_id; the platform ignores it "
            f"only because that model does not forbid extras")

    assert client.worker_id == "dom0-1"


def test_a_state_report_satisfies_the_server_model():
    """Every field but `state` is optional server-side, which is what makes a
    later report unable to erase an earlier diagnostic."""
    sent = {}
    def handler(request):
        sent.update(__import__("json").loads(request.content))
        return httpx.Response(204)

    api(handler).report_state("job-1", "cloning", clone_domain="u-1-clone",
                              vlan=1, failure_reason=None)

    parsed = StateRequest.model_validate(sent)
    assert parsed.state.value == "cloning"
    assert parsed.clone_domain == "u-1-clone"
    # None is omitted, not sent: sending it would overwrite a real value.
    assert "failure_reason" not in sent


def test_the_manifest_satisfies_the_server_model():
    """DRAFT-018's shape. A worker still sending the old bare-name list would
    take a 422 from a real platform."""
    sent = {}
    def handler(request):
        sent.update(__import__("json").loads(request.content))
        return httpx.Response(204)

    manifest = {
        "schema_version": 1,
        "artifacts": [{"name": "trace.log", "size_bytes": 12,
                       "sha256": "a" * 64}],
    }
    api(handler).complete("job-1", manifest)

    assert CompleteRequest.model_validate(sent).manifest.schema_version == 1


def test_artifact_sizes_satisfy_the_server_model():
    sent = {}
    def handler(request):
        sent.update(__import__("json").loads(request.content))
        return httpx.Response(200, json={})

    api(handler).artifact_tickets("job-1", {"trace.log": 12, "capture.pcap": 0})

    parsed = ArtifactRequest.model_validate(sent)
    assert parsed.artifacts["capture.pcap"] == 0   # an empty pcap is a result


# --- claim: three outcomes, one of which is not a failure ------------------

def test_a_lease_carries_everything_the_run_needs():
    payload = {
        "status": "leased", "job_id": "11111111-1111-1111-1111-111111111111",
        "target_os": "ubuntu", "submitted_filename": "a b.exe",
        "required_mib": 2198, "attempt": 1, "sample_url": "https://s3/x",
        "sha256": "b" * 64, "lease_expires_at": "2026-08-26T10:00:00Z",
    }
    got = api(ok(payload)).claim(free_mib=8192, free_vlans=4, free_slots=2)

    assert isinstance(got, Lease)
    # The submitted name reaches us byte-exact, spaces included: DRAFT-030
    # keeps it that way because extension dispatch and argv[0] self-checks are
    # real evasion surface.
    assert got.submitted_filename == "a b.exe"


def _leased(**over) -> dict:
    payload = {
        "status": "leased", "job_id": "11111111-1111-1111-1111-111111111111",
        "target_os": "ubuntu", "submitted_filename": "a b.exe",
        "required_mib": 2198, "attempt": 1, "sample_url": "https://s3/x",
        "sha256": "b" * 64, "lease_expires_at": "2026-08-26T10:00:00Z",
    }
    payload.update(over)
    return payload


@pytest.mark.parametrize("name", [
    "/etc/cron.d/pwn",          # absolute: pathlib REPLACES the join
    "../../../../etc/passwd",   # relative: pathlib does not normalise it
    "..",
    ".",
    "sub/dir.bin",
    "back\\slash.bin",
    "nul\x00byte.bin",
    "bell\x07.bin",
])
def test_a_lease_naming_a_path_is_refused(name):
    """These become a filename under root on Dom0.

    `staging / job_id / name` is handed to `open(dest, "wb")` and its parent to
    `shutil.rmtree`, both as root. An absolute name replaces the join outright
    and a relative one is left unnormalised, so without this the platform is
    the only thing standing between a lease and a write into /etc.
    """
    with pytest.raises(ProtocolError, match="unusable lease"):
        api(ok(_leased(submitted_filename=name))).claim(
            free_mib=8192, free_vlans=4, free_slots=2)


@pytest.mark.parametrize("job_id", [
    "../../etc", "/etc/passwd", "not-a-uuid", "", "11111111-1111-1111-1111",
])
def test_a_lease_with_a_job_id_that_is_not_a_uuid_is_refused(job_id):
    """It becomes a directory name under both the results and staging roots."""
    with pytest.raises(ProtocolError, match="unusable lease"):
        api(ok(_leased(job_id=job_id))).claim(
            free_mib=8192, free_vlans=4, free_slots=2)


def test_shell_metacharacters_in_a_sample_name_still_pass():
    """**Deliberately admitted, and this is the rule the project already has.**

    A sample really can be called `a$(id).exe`, and byte-exact delivery of that
    name is part of what is being analysed -- extension dispatch and argv[0]
    self-checks are real evasion surface. What stops those characters hurting
    is the `sh -c '…' sh "$UNSAFE"` idiom in guests.py, not a name filter.
    Widening this check to reject them would break the pipeline's purpose while
    adding nothing, so a test pins the narrow scope.
    """
    hostile = 'a$(id)`whoami`;reboot &"\'.exe'
    got = api(ok(_leased(submitted_filename=hostile))).claim(
        free_mib=8192, free_vlans=4, free_slots=2)

    assert got.submitted_filename == hostile


def test_reserved_is_a_distinct_outcome_not_an_error():
    """A job too large for current free memory is holding its place rather than
    being starved by smaller ones behind it. A client that raised here would
    teach an operator the queue is broken when it is working as designed."""
    got = api(ok({"status": "reserved",
                  "blocking_job_id": "22222222-2222-2222-2222-222222222222",
                  "need_mib": 6294})).claim(free_mib=2048, free_vlans=4,
                                            free_slots=2)

    assert isinstance(got, Reserved)
    assert got.need_mib == 6294


def test_idle_is_a_distinct_outcome():
    assert isinstance(api(ok({"status": "idle"})).claim(
        free_mib=1, free_vlans=1, free_slots=1), Idle)


def test_an_unknown_claim_status_is_refused():
    """Better a loud failure than a daemon that treats a status it does not
    understand as 'nothing to do' and quietly stops working."""
    with pytest.raises(ProtocolError, match="unknown claim status"):
        api(ok({"status": "something_new"})).claim(free_mib=1, free_vlans=1,
                                                   free_slots=1)


def test_the_claim_timeout_exceeds_the_server_long_poll():
    """The API long-polls /claim for 20s in production so an idle worker is not
    a busy-loop. A client timeout below that turns every idle claim into what
    looks like a network failure."""
    from sandboxd.api import CLAIM_TIMEOUT
    assert CLAIM_TIMEOUT > 20


# --- cancellation ----------------------------------------------------------

def test_the_heartbeat_is_the_only_cancellation_channel():
    """Dom0 has no inbound listener, so there is nowhere to push to."""
    hb = api(ok({"lease_expires_at": "2026-08-26T10:05:00Z",
                 "cancel_requested": True})).heartbeat("job-1")

    assert hb.cancel_requested is True


# --- retry policy ----------------------------------------------------------

def test_a_transport_failure_is_retried():
    """Dom0 and the platform VM are separate machines, and one restarting is
    ordinary. A blip must not end the daemon."""
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] < 3:
            raise httpx.ConnectError("connection refused")
        return httpx.Response(200, json={"status": "idle"})

    got = api(handler).claim(free_mib=1, free_vlans=1, free_slots=1)

    assert isinstance(got, Idle)
    assert calls["n"] == 3


def test_a_500_is_retried():
    """The platform is up but unhappy -- a restarting worker pool, a database
    that has not finished coming back."""
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] < 2:
            return httpx.Response(503, text="starting")
        return httpx.Response(200, json={"status": "idle"})

    assert isinstance(api(handler).claim(free_mib=1, free_vlans=1,
                                         free_slots=1), Idle)
    assert calls["n"] == 2


def test_a_4xx_is_not_retried():
    """A 4xx means this client and that server disagree about the protocol,
    and repeating the request cannot resolve a disagreement -- it turns a loud
    bug into a quiet loop."""
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(422, text="validation error")

    with pytest.raises(ProtocolError, match="422"):
        api(handler).claim(free_mib=1, free_vlans=1, free_slots=1)

    assert calls["n"] == 1, "a protocol disagreement was retried"


def test_an_auth_failure_is_not_retried():
    """A wrong token will still be wrong on the fourth attempt, and hammering
    an authentication endpoint is how a worker gets rate-limited."""
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(401, text="unauthorized")

    with pytest.raises(ProtocolError, match="401"):
        api(handler).register(total_mib=1, total_vlans=1, total_slots=1,
                              pipelines={"ubuntu": 1})
    assert calls["n"] == 1


# --- the credential boundary ----------------------------------------------

def test_the_worker_token_never_reaches_the_object_store(tmp_path):
    """A presigned URL is already authorised by the signature in its query
    string. Sending the bearer token spends a credential on a request that does
    not need it, and the worker token has no business reaching MinIO."""
    seen = {}

    def store(request):
        seen["headers"] = dict(request.headers)
        return httpx.Response(200, content=b"\x7fELF")

    client = api(ok({}), store=store)
    client.fetch_sample("https://minio/samples/x", tmp_path / "s.bin",
                        expected_sha256=hashlib.sha256(b"\x7fELF").hexdigest())

    assert "authorization" not in {k.lower() for k in seen["headers"]}
    assert "x-worker-id" not in {k.lower() for k in seen["headers"]}


def test_the_worker_channel_does_carry_the_token():
    seen = {}

    def handler(request):
        seen["headers"] = dict(request.headers)
        return httpx.Response(200, json={"status": "idle"})

    api(handler).claim(free_mib=1, free_vlans=1, free_slots=1)

    assert seen["headers"]["authorization"] == "Bearer tok"
    # And ONLY the credential. `X-Worker-Id` used to travel beside it, unbound
    # to it, which is what let any token holder act as any worker.
    assert "x-worker-id" not in seen["headers"]


# --- the sample reaches disk ----------------------------------------------

def test_the_sample_is_written_to_a_dom0_path(tmp_path):
    """It HAS to reach disk: `injector -m writefile -B` takes a Dom0 path and
    there is no stdin form. fake_worker.py says the opposite -- "no business
    keeping malware on disk" -- and that comment will be wrong for the real
    daemon. The honest arrangement is a staging directory the sweep empties."""
    body = b"\x7fELF" + b"\x00" * 100
    dest = tmp_path / "staging" / "job-1" / "sample.bin"

    n = api(ok({}), store=lambda r: httpx.Response(200, content=body)
            ).fetch_sample("https://minio/x", dest,
                           expected_sha256=hashlib.sha256(body).hexdigest())

    assert n == len(body)
    assert dest.read_bytes() == body


def test_a_sample_that_changed_after_admission_is_refused(tmp_path):
    """The check the platform's ETag comparison cannot make.

    That ETag is an MD5 for a single-part upload, so it says two objects have
    the same MD5 -- constructible to order -- and it is read a round trip
    before this download, so the bytes can change after it passed. Hashing what
    actually arrived closes both, because this is the copy that runs.
    """
    body = b"\x7fELF" + b"\x00" * 100
    dest = tmp_path / "staging" / "job-1" / "sample.bin"

    with pytest.raises(SampleMismatch, match="does not match"):
        api(ok({}), store=lambda r: httpx.Response(200, content=body)
            ).fetch_sample("https://minio/x", dest,
                           expected_sha256="00" * 32)


def test_a_refused_sample_does_not_stay_on_dom0(tmp_path):
    """Bytes an attacker chose, which the pipeline has just declined to run.

    The staging sweep would remove them at the next start, which is not soon
    enough to be the answer.
    """
    body = b"\x7fELF" + b"\x00" * 100
    dest = tmp_path / "staging" / "job-1" / "sample.bin"

    with pytest.raises(SampleMismatch):
        api(ok({}), store=lambda r: httpx.Response(200, content=body)
            ).fetch_sample("https://minio/x", dest,
                           expected_sha256="00" * 32)

    assert not dest.exists()


def test_a_lease_with_no_digest_is_refused_rather_than_run(tmp_path):
    """Fail closed. Admission writes `sha256` in the same UPDATE that moves a
    job to `admitted`, so every claimable job has one and a lease without it is
    an impossible state. Running it anyway would detonate bytes that nothing
    can identify afterwards."""
    dest = tmp_path / "staging" / "job-1" / "sample.bin"

    with pytest.raises(SampleMismatch, match="no sha256"):
        api(ok({}), store=lambda r: httpx.Response(200, content=b"x")
            ).fetch_sample("https://minio/x", dest, expected_sha256=None)

    assert not dest.exists()


def test_an_artifact_upload_sends_the_policy_before_the_file(tmp_path):
    """S3 stops reading at the file part, so a policy field after it is never
    seen and the upload is rejected for a missing policy. httpx emits `data=`
    before `files=`, which is the ordering that matters."""
    seen = {}

    def store(request):
        seen["body"] = request.content
        return httpx.Response(204)

    path = tmp_path / "trace.log"
    path.write_bytes(b"events")
    ticket = Ticket(url="https://minio/analysis", expires_in=900,
                    fields={"key": "results/1/trace.log", "policy": "abc",
                            "x-amz-signature": "def"})

    api(ok({}), store=store).upload_artifact(ticket, "trace.log", path)

    body = seen["body"]
    assert body.index(b"policy") < body.index(b"events")
    assert body.index(b"x-amz-signature") < body.index(b"events")


# --- reconcile -------------------------------------------------------------

def test_reconcile_reports_what_was_lost():
    """After a sweep the live list is empty by construction, so everything the
    platform thought this worker held is marked interrupted. That list is the
    only record work was lost, and is worth logging."""
    got = api(ok({"interrupted": ["33333333-3333-3333-3333-333333333333"]})
              ).reconcile([])

    assert got == ["33333333-3333-3333-3333-333333333333"]
