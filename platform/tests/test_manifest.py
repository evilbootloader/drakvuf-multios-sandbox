"""The manifest contract: DRAFT-018.

Every shape below was MEASURED against the unvalidated `manifest: dict` in the
development container on 2026-08-25, and the comment on each says what it did
then. That is the point of the file -- these are not hypothetical inputs, they
are the six things a `dict` actually permitted on the one payload the worker
channel never bounded.
"""

from __future__ import annotations

import json
import uuid

import pytest
from conftest import owner_id

from sandbox_platform import manifest as m

EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def entry(name: str, size: int = 0, sha: str = EMPTY_SHA) -> dict:
    return {"name": name, "size_bytes": size, "sha256": sha}


def valid(**over) -> dict:
    doc = {"schema_version": 1, "artifacts": [entry("trace.log")]}
    doc.update(over)
    return doc


# --- the reader is total ---------------------------------------------------
#
# parse() is the only thing standing between a committed row and the detail
# endpoint, and a committed row cannot be un-committed. Anything it raises on
# is a job nobody can ever look at again.

@pytest.mark.parametrize("artifacts, was", [
    (5,               "TypeError: 'int' object is not iterable -> HTTP 500"),
    (None,            "TypeError: 'NoneType' is not iterable -> HTTP 500"),
    ([["trace.log"]], "TypeError: unhashable type: 'list' -> HTTP 500"),
    ("trace.log",     "HTTP 200 with NINE urls, one per character"),
    ({"trace.log": 1}, "HTTP 200, iterating dict keys, correct by luck"),
])
def test_a_shape_that_used_to_break_the_reader_now_degrades(artifacts, was):
    parsed = m.parse({"artifacts": artifacts})

    assert parsed.error is not None, was
    # Degraded means FEWER capabilities, not looser ones. This is the
    # assertion that keeps the fallback from becoming the bypass.
    assert parsed.artifacts == ()


def test_the_error_is_one_line_an_operator_can_act_on():
    """Not a pydantic dump. This is rendered beside a job that otherwise looks
    fine, answering "what is wrong with this record" -- not "list all fourteen
    ways it differs from the model"."""
    parsed = m.parse({"artifacts": 5})

    assert parsed.error is not None
    assert "\n" not in parsed.error
    assert len(parsed.error) < 200


@pytest.mark.parametrize("raw", [None, "", "not json", "[]", 5, [], "null"])
def test_parse_never_raises(raw):
    assert m.parse(raw) is not None


def test_a_manifest_stored_as_text_is_still_read():
    """psycopg returns jsonb as a dict, but a row written by a migration or at
    a psql prompt can arrive as text."""
    parsed = m.parse(json.dumps(valid()))

    assert parsed.error is None
    assert [a.name for a in parsed.artifacts] == ["trace.log"]


# --- the legacy shape ------------------------------------------------------

def test_the_pre_draft_018_shape_still_reads():
    """Every manifest already written is `{"artifacts": ["trace.log"]}`.

    Rejecting it would send every completed job on the deployment to the
    degraded path on the first restart after this lands -- destroying the
    readability of real evidence to enforce a contract written afterwards.
    """
    parsed = m.parse({"artifacts": ["trace.log", "capture.pcap"]})

    assert parsed.error is None
    assert parsed.legacy is True
    assert [a.name for a in parsed.artifacts] == ["trace.log", "capture.pcap"]


def test_a_legacy_artifact_reports_unknown_size_rather_than_zero():
    """"We do not know this file's size" and "this file is empty" are
    different facts, and capture.pcap is legitimately 0 bytes when a sample
    made no network traffic (#37). Conflating them would misreport a real
    result as a missing one."""
    parsed = m.parse({"artifacts": ["capture.pcap"]})

    assert parsed.artifacts[0].size_bytes is None
    assert parsed.artifacts[0].sha256 is None


def test_a_legacy_name_is_validated_too():
    """The door legacy rows came through never checked them. Routing them
    through the same validator is the whole reason _legacy exists rather than
    a blanket trust-because-old."""
    parsed = m.parse({"artifacts": ["../../samples/other/victim.exe"]})

    assert parsed.error is not None
    assert parsed.artifacts == ()


# --- bounds ----------------------------------------------------------------

def test_an_unbounded_list_is_refused():
    """Measured: 50,000 names cost 11.74s of signing and a 17.92 MB response,
    per request, on a row that is committed forever."""
    with pytest.raises(Exception):
        m.Manifest.model_validate(
            valid(artifacts=[entry(f"f{i}") for i in range(m.MAX_ARTIFACTS + 1)])
        )


def test_a_legacy_list_is_bounded_by_the_same_number():
    """The old shape is read, not trusted: a 50,000-name legacy row degrades
    rather than being honoured because it predates the bound."""
    parsed = m.parse({"artifacts": [f"f{i}" for i in range(m.MAX_ARTIFACTS + 1)]})

    assert parsed.error is not None


def test_hitting_the_cap_is_recorded_rather_than_silent():
    """What makes bounding safe. A reader that knows the list is incomplete is
    in a different position from one that thinks it sees everything."""
    doc = m.Manifest.model_validate(valid(truncated=True))

    assert doc.truncated is True
    assert m.parse(valid(truncated=True)).truncated is True


# --- names, at both doors --------------------------------------------------
#
# The ticket endpoint and /complete take the SAME names. For a while only the
# ticket endpoint validated them, so a worker could request tickets for clean
# names and then declare anything it liked at /complete.

HOSTILE_NAMES = [
    "../../samples/other/victim.exe",
    "..",
    "a/../../b",
    "/etc/passwd",
    "a//b",
    "trailing/",
    "back\\slash",
    "nul\x00byte",
    "bell\x07",
    "x" * (m.MAX_ARTIFACT_NAME + 1),
    "",
]


@pytest.mark.parametrize("name", HOSTILE_NAMES)
def test_a_hostile_name_is_refused_in_the_manifest(name):
    with pytest.raises(Exception):
        m.Manifest.model_validate(valid(artifacts=[entry(name)]))


@pytest.mark.parametrize("name", HOSTILE_NAMES)
def test_the_same_name_is_refused_at_the_ticket_door(name):
    """Parametrised from ONE list so the two doors cannot drift apart."""
    from sandbox_platform.routers.worker import ArtifactRequest

    with pytest.raises(Exception):
        ArtifactRequest.model_validate({"artifacts": {name: 10}})


@pytest.mark.parametrize("name", [
    "50%off.exe",          # a real dropped-file name; % is not encoding here
    "..%2f..%2fetc",       # percent-encoded traversal is not traversal
    'quote".exe',
    "with space.dll",
    "ünïcödé.bin",
    "extracted/nested/dir/payload.dat",
])
def test_an_awkward_but_legitimate_name_is_admitted(name):
    """Byte-exactness is the point of collecting these: `extracted/` is named
    after what the sample wrote, and rewriting it stores real evidence under a
    false name (DRAFT-030)."""
    doc = m.Manifest.model_validate(valid(artifacts=[entry(name)]))

    assert doc.artifacts[0].name == name


# --- documents -------------------------------------------------------------

def test_a_document_must_have_been_uploaded():
    """Claiming one that is not an artifact lights a tab whose content 404s --
    worse than an empty tab, because the operator goes looking for a result
    that was never stored."""
    with pytest.raises(Exception):
        m.Manifest.model_validate(valid(documents=["capa.json"]))


def test_a_document_that_was_uploaded_is_accepted():
    doc = m.Manifest.model_validate(valid(
        artifacts=[entry("trace.log"), entry("capa.json")],
        documents=["capa.json"],
    ))

    assert doc.documents == ["capa.json"]


# --- the model is strict ---------------------------------------------------

def test_an_unknown_field_is_refused_not_discarded():
    """A worker sending a field this does not know is either running against a
    newer contract or malfunctioning. Both are worth a 422."""
    with pytest.raises(Exception):
        m.Manifest.model_validate(valid(unexpected="value"))


def test_the_schema_version_is_required():
    """A versioned contract with an optional version is not one: the first
    incompatible change would have no way to tell the two apart."""
    with pytest.raises(Exception):
        m.Manifest.model_validate({"artifacts": []})


def test_a_negative_size_is_refused():
    with pytest.raises(Exception):
        m.Manifest.model_validate(valid(artifacts=[entry("x", size=-1)]))


def test_a_digest_that_is_not_a_sha256_is_refused():
    for bad in ("", "abc", EMPTY_SHA.upper(), EMPTY_SHA + "0", "g" * 64):
        with pytest.raises(Exception):
            m.Manifest.model_validate(valid(artifacts=[entry("x", sha=bad)]))


def test_an_empty_artifact_is_a_real_result():
    """capture.pcap is 0 bytes when the sample made no network traffic, and
    #37's upload policy starts its content-length-range at 0 for exactly this
    reason. A model that refused it would contradict the store."""
    doc = m.Manifest.model_validate(
        valid(artifacts=[entry("capture.pcap", size=0)])
    )

    assert doc.artifacts[0].size_bytes == 0


# --- through the API -------------------------------------------------------

def _completed(conn, manifest: object) -> uuid.UUID:
    """A committed row, which is the situation parse() exists for: validation
    at the door cannot help what is already stored."""
    return conn.execute(
        "INSERT INTO jobs (target_os, submitted_filename, state, manifest, owner)"
        " VALUES ('ubuntu', 'x.bin', 'completed', %s,"
        "         %s) RETURNING id",
        (json.dumps(manifest), owner_id(conn)),
    ).fetchone()[0]


@pytest.mark.parametrize("artifacts", [5, None, [["x"]], "trace.log"])
def test_a_malformed_row_renders_the_job_instead_of_500ing(client, conn, artifacts):
    """The regression test for rows already on the deployment. Written against
    a direct insert because the API will no longer accept these."""
    job_id = _completed(conn, {"artifacts": artifacts})

    r = client.get(f"/api/v1/jobs/{job_id}")

    assert r.status_code == 200
    detail = r.json()
    # The job is still readable, which is the whole argument for degrading.
    assert detail["submitted_filename"] == "x.bin"
    assert detail["state"] == "completed"
    assert detail["manifest_error"] is not None
    assert detail["artifacts"] == {}
    # Still returned raw -- it is what makes a malformed manifest diagnosable.
    assert detail["manifest"] is not None


def test_a_valid_manifest_still_mints_one_url_per_artifact(client, conn):
    job_id = _completed(conn, valid())

    detail = client.get(f"/api/v1/jobs/{job_id}").json()

    assert detail["manifest_error"] is None
    assert list(detail["artifacts"]) == ["trace.log"]


def test_a_legacy_row_reports_itself_as_legacy(client, conn):
    job_id = _completed(conn, {"artifacts": ["trace.log"]})

    detail = client.get(f"/api/v1/jobs/{job_id}").json()

    assert detail["manifest_error"] is None
    assert detail["manifest_legacy"] is True
    assert list(detail["artifacts"]) == ["trace.log"]


def test_a_string_manifest_no_longer_mints_a_url_per_character(client, conn):
    """Measured before the fix: "trace.log" produced nine presigned URLs and
    reported them as artifacts -- a plausible-looking result page listing nine
    files that do not exist."""
    job_id = _completed(conn, {"artifacts": "trace.log"})

    detail = client.get(f"/api/v1/jobs/{job_id}").json()

    assert detail["artifacts"] == {}


# --- the capability envelope -----------------------------------------------
#
# Defined before any capability exists, because the alternative is defining it
# five times and then migrating five formats.

def envelope(**over) -> dict:
    doc = {
        "schema": "sandbox.capa/1",
        "job_id": str(uuid.uuid4()),
        "produced_at": "2026-08-26T10:00:00Z",
        "producer": {"name": "capa", "version": "7.2.0",
                     "ruleset_version": "v7.2.0-rules"},
        "status": "complete",
        "data": {"capabilities": []},
    }
    doc.update(over)
    return doc


def test_an_envelope_round_trips():
    doc = m.Envelope.model_validate(envelope())

    assert doc.schema_id == "sandbox.capa/1"
    assert doc.producer.ruleset_version == "v7.2.0-rules"
    assert json.loads(m.dump_envelope(doc))["schema"] == "sandbox.capa/1"


def test_the_wire_field_is_schema_not_schema_id():
    """`schema` shadows BaseModel.schema(), so the Python attribute is renamed
    and aliased. The alias is the contract; forgetting by_alias on the way out
    would write a document this same module rejects on the way back in."""
    written = json.loads(m.dump_envelope(m.Envelope.model_validate(envelope())))

    assert "schema" in written
    assert "schema_id" not in written


def test_a_partial_result_must_say_why():
    """The reason this whole type exists. A capa run that timed out 40%
    through produces real findings that read exactly like a clean sample, and
    "partial" with no reason tells a reader that something is missing and
    nothing about what."""
    with pytest.raises(Exception):
        m.Envelope.model_validate(envelope(status="partial"))

    ok = m.Envelope.model_validate(envelope(
        status="partial",
        status_reason="capa timed out after 120s at event 418,000",
    ))
    assert ok.status == "partial"


def test_a_failed_document_must_say_why_too():
    with pytest.raises(Exception):
        m.Envelope.model_validate(envelope(status="failed", status_reason=""))


def test_a_document_whose_payload_we_cannot_model_is_still_readable():
    """Forward compatibility is the point: `data` belongs to the issue that
    produces it, and this repository must be able to read a document from a
    capability it knows nothing about."""
    doc = m.Envelope.model_validate(envelope(
        schema="sandbox.something_unheard_of/3",
        data={"nested": {"arbitrary": [1, 2, {"shape": True}]}},
    ))

    assert doc.data["nested"]["arbitrary"][2]["shape"] is True


@pytest.mark.parametrize("bad", [
    "capa/1", "sandbox.capa", "sandbox.capa/", "sandbox.Capa/1",
    "sandbox./1", "", "sandbox.capa/1.0",
])
def test_an_unrecognisable_schema_id_is_refused(bad):
    """A reader must be able to refuse a document it does not understand
    rather than guess at it, which requires the identifier to be a shape and
    not free text."""
    with pytest.raises(Exception):
        m.Envelope.model_validate(envelope(schema=bad))


def test_a_producer_without_rules_may_report_none():
    """Not every producer has a ruleset. One that does and reports null here
    is a bug in that producer, not in this model."""
    doc = m.Envelope.model_validate(envelope(
        producer={"name": "pefile", "version": "2024.8.26"},
    ))

    assert doc.producer.ruleset_version is None


def test_an_unknown_envelope_field_is_refused():
    with pytest.raises(Exception):
        m.Envelope.model_validate(envelope(confidence=0.9))
