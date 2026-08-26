"""What a run produced: the shape of `results/<job_id>/`.

DRAFT-018 (unpublished).

**Strict at the door, tolerant at the reader**, and the asymmetry is
deliberate. `Manifest` is what a worker must satisfy to write one; `parse()`
is what a reader gets back, and it never raises. A manifest is written once
and read forever, so a row that was valid under an older contract must still
render the job it describes -- the state, the timings and the sample identity
are all still true, and refusing the whole record because one field is the
wrong type destroys evidence to punish a formatting error.

Before this module the manifest was `dict`, unvalidated, and
`routers/jobs.py` minted a presigned URL per element of it. Measured in the
development container 2026-08-25:

    "trace.log"    ->  HTTP 200, nine URLs, one per character
    5 / null       ->  HTTP 500, permanently, on the only view of the job
    50,000 names   ->  11.74s and a 17.92 MB response, on every request

None of which needs a hostile worker: a writer that assigns a string instead
of a list produces the first, and that is a mistake a Python author makes
without noticing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    model_validator,
)

# S3 keys cap at 1024 bytes UTF-8 and `results/<uuid>/` spends 45 of them.
# Refused rather than truncated: a truncated artifact name is a wrong one, and
# `extracted/` names are evidence of what the sample wrote.
MAX_ARTIFACT_NAME = 900

# Above any measured need and stated as a refusal point rather than a natural
# limit -- `extracted/` is named after files the SAMPLE wrote, so the real
# ceiling is however many files a sample chooses to drop. Higher than the
# ticket endpoint's 64-per-call because a worker may legitimately call that
# endpoint several times. `truncated` is what makes bounding this safe: a run
# that hit the cap says so, and a reader that knows the list is incomplete is
# in a different position from one that thinks it is looking at everything.
MAX_ARTIFACTS = 512


def reject_unsafe_name(name: str) -> str:
    """Refuse an artifact name that could escape `results/<job_id>/`.

    **These names are attacker-influenced.** `trace.log` and `capture.pcap` are
    ours, but `extracted/` is named after files the *sample* dropped, so this is
    untrusted input on the same footing as a submitted filename.

    Refuse, never sanitise. Rewriting `../x` to `x` would silently store the
    wrong evidence under a plausible name, and a worker sending one is either
    broken or compromised -- both worth surfacing.

    On percent-encoded traversal (`..%2f..`): it is not a bypass, and the reason
    is worth stating rather than defending against twice. An S3 key is an opaque
    byte string that nothing here resolves as a filesystem path. In the POST
    ticket the key travels in a form field, undecoded; in a presigned GET URL
    boto3 escapes `%` to `%25`, so one decode by the server yields the literal
    name back, not a separator. What *would* traverse is a real `..` path
    component, which is what the component check below refuses.

    `%`, quotes, spaces and unicode are all admitted deliberately -- a dropped
    file really can be called `50%off.exe`, and byte-exactness of that name is
    the point of collecting it.

    **Lives here, not in `routers/worker.py`, because the same names arrive
    through two doors.** The ticket endpoint validated them and the manifest
    did not, so a worker could request tickets for clean names and then declare
    anything it liked. Traversal was not exploitable through that gap -- MinIO
    refuses `..` components itself, `XMinioInvalidResourceName`, verified
    2026-08-25 -- but a guarantee that rests entirely on a dependency's input
    validation is one upgrade away from resting on nothing.
    """
    if not name:
        raise ValueError("artifact name is empty")
    if len(name.encode()) > MAX_ARTIFACT_NAME:
        raise ValueError(f"artifact name exceeds {MAX_ARTIFACT_NAME} bytes")
    if name.startswith("/"):
        raise ValueError(f"artifact name is absolute: {name!r}")
    if "\\" in name:
        # Not a separator on Linux, so this is not a traversal fix. It is
        # refused because a key that means one thing here and another on a
        # Windows reader is ambiguous evidence.
        raise ValueError(f"artifact name contains a backslash: {name!r}")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
        # NUL in particular: harmless in Python, a truncation point in any C
        # layer this key later passes through.
        raise ValueError(f"artifact name contains a control character: {name!r}")
    for part in name.split("/"):
        # "" catches `a//b` and a trailing slash; "." and ".." catch traversal
        # and the prefix itself.
        if part in ("", ".", ".."):
            raise ValueError(f"artifact name escapes the job prefix: {name!r}")
    return name


SafeName = Annotated[str, AfterValidator(reject_unsafe_name)]


# --- what a worker must send ----------------------------------------------

class ArtifactEntry(BaseModel):
    """One file in `results/<job_id>/`.

    **An entry, not a bare name.** The worker knows the size and the digest at
    the moment it declares this -- it has just uploaded the file -- so a bare
    name is the least it could tell us and was, until now, the most it did.
    Recording both lets a detail view show sizes without a HEAD per object and
    lets the total be reconciled against `jobs.results_bytes`.

    **`sha256` is not integrity against a compromised worker**, and should not
    be described as if it were: the same host supplies the file and the digest.
    It detects corruption in transit and loss in the store.
    """

    model_config = ConfigDict(extra="forbid")

    name: SafeName
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class Manifest(BaseModel):
    """The document a worker posts to `/complete`.

    `extra="forbid"` rather than ignore: a worker sending a field this does not
    know is either running against a newer contract or malfunctioning, and both
    are worth a 422 rather than a silent discard.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    artifacts: list[ArtifactEntry] = Field(default_factory=list,
                                           max_length=MAX_ARTIFACTS)
    # Which capability documents this run produced. NOT derived from
    # `artifacts`: "this run produced a capa.json" and "here is a file called
    # capa.json" are different claims, and only the first should light up a
    # tab.
    documents: list[SafeName] = Field(default_factory=list, max_length=32)
    truncated: bool = False
    notes: str | None = Field(default=None, max_length=4096)

    @model_validator(mode="after")
    def _documents_were_uploaded(self) -> Manifest:
        """A document that is not also an artifact cannot be fetched.

        Claiming one would light a tab whose content 404s, which is a worse
        outcome than an empty tab -- the operator goes looking for a result
        that was never stored.
        """
        names = {a.name for a in self.artifacts}
        missing = [d for d in self.documents if d not in names]
        if missing:
            raise ValueError(
                f"documents not present in artifacts: {sorted(missing)}"
            )
        return self


# --- what a reader gets ----------------------------------------------------

@dataclass(frozen=True)
class Artifact:
    """A reader's view. Size and digest are optional because a manifest
    written before they were required still describes a real file."""

    name: str
    size_bytes: int | None = None
    sha256: str | None = None


@dataclass(frozen=True)
class ParsedManifest:
    """Never raises, never partially trusted.

    `error` set means the artifact list could not be established. It does NOT
    mean the job is unreadable: everything else on the row is untouched. And
    degraded means FEWER capabilities, never looser ones -- `artifacts` is
    empty in that case, so no URL is ever minted from a name this module could
    not validate.
    """

    artifacts: tuple[Artifact, ...] = ()
    documents: tuple[str, ...] = ()
    truncated: bool = False
    error: str | None = None
    legacy: bool = False
    raw: dict | None = field(default=None, compare=False)


def _legacy(raw: dict) -> ParsedManifest | None:
    """The pre-DRAFT-018 shape: `{"artifacts": ["trace.log", ...]}`.

    Accepted because every manifest already written is this shape, and the
    alternative is that the first restart after this lands sends every
    completed job on the deployment to the degraded path at once.

    Names are validated here too. That is the point of routing legacy rows
    through this function rather than trusting them for being old: the door
    they came through never checked them.
    """
    names = raw.get("artifacts")
    if not isinstance(names, list):
        return None
    if len(names) > MAX_ARTIFACTS:
        return None
    if not all(isinstance(n, str) for n in names):
        return None
    try:
        for n in names:
            reject_unsafe_name(n)
    except ValueError:
        return None
    return ParsedManifest(
        artifacts=tuple(Artifact(name=n) for n in names),
        legacy=True,
        raw=raw,
    )


def parse(raw: object) -> ParsedManifest:
    """Read a manifest from a job row. Total by construction.

    Order matters: the current contract first, the legacy shape second,
    degraded last. A row that satisfies neither is reported, not raised --
    `routers/jobs.py` renders the job either way.
    """
    if raw is None:
        return ParsedManifest()

    if isinstance(raw, str):
        # psycopg returns jsonb as a dict, but a row written by something else
        # -- a migration, a psql prompt -- can arrive as text.
        try:
            raw = json.loads(raw)
        except ValueError:
            return ParsedManifest(error="manifest is not valid JSON")

    if not isinstance(raw, dict):
        return ParsedManifest(error=f"manifest is {type(raw).__name__}, not an object")

    try:
        m = Manifest.model_validate(raw)
    except ValidationError as exc:
        legacy = _legacy(raw)
        if legacy is not None:
            return legacy
        return ParsedManifest(
            error=_first_error(exc),
            raw=raw,
        )

    return ParsedManifest(
        artifacts=tuple(Artifact(a.name, a.size_bytes, a.sha256)
                        for a in m.artifacts),
        documents=tuple(m.documents),
        truncated=m.truncated,
        raw=raw,
    )


# --- the capability envelope -----------------------------------------------
#
# `capa.json` (DRAFT-019), `static.json` (DRAFT-048), `network.json`
# (DRAFT-049) and `memory.json` (DRAFT-051) all land in the same prefix, and
# each draft specifies its own file. This is what they have in common.
#
# Defined here, before any of them exists, because the alternative is defining
# it five times and then migrating five formats.


class Producer(BaseModel):
    """What generated a document, precisely enough to reproduce it.

    `ruleset_version` is the load-bearing half. capa rules, YARA rules and
    Suricata rules all version independently of this repository, so "capa
    found no capabilities" is not a finding until you know which rules were
    asked. Nullable because not every producer has rules; a producer that does
    and reports null here is a bug in that producer.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=64)
    ruleset_version: str | None = Field(default=None, max_length=64)


class Envelope(BaseModel):
    """The wrapper every capability document shares.

    **`status` is why this exists.** A capa run that hit its timeout 40%
    through the log produces a short list of real findings that reads exactly
    like a clean sample -- and a partial result believed to be complete is
    worse than no result at all. This is the same failure shape the queue
    already fixed once: `queued` is not a failure, and a silent hold with
    correct-looking output is precisely what this architecture exists to
    remove.

    `data` is deliberately unmodelled. What goes inside belongs to the issue
    that produces it; specifying capa's output here would be deciding
    DRAFT-019's design in a module DRAFT-019 does not own. Forward
    compatibility is the point -- this repository must be able to read a
    document whose payload it has no model for.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    # Name and version together -- "sandbox.capa/1" -- so a reader can refuse
    # a document it does not understand rather than guess at it.
    #
    # `schema_id` in Python, `schema` on the wire. Pydantic warns that a field
    # called `schema` shadows BaseModel.schema(), and a shadowed method is the
    # kind of thing that works until something calls it. Dump with
    # `by_alias=True` -- see `dump_envelope`.
    schema_id: str = Field(alias="schema", serialization_alias="schema",
                           pattern=r"^sandbox\.[a-z0-9_]+/\d+$")
    job_id: UUID
    produced_at: datetime
    producer: Producer
    status: Literal["complete", "partial", "failed"]
    # Free text, and it should be specific: "capa timed out after 120s at
    # event 418,000 of an unknown total" is what an operator can act on.
    # Required when the status is not `complete`, because "partial" with no
    # reason tells a reader that something is missing and nothing about what.
    status_reason: str | None = Field(default=None, max_length=4096)
    data: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def _incomplete_says_why(self) -> Envelope:
        if self.status != "complete" and not self.status_reason:
            raise ValueError(
                f"status {self.status!r} requires status_reason"
            )
        return self


def dump_envelope(envelope: Envelope) -> str:
    """Serialise a document for the object store.

    Exists so that `by_alias=True` is not something each producer has to
    remember: a plain `model_dump_json()` writes `schema_id`, which every
    reader -- including this module -- would then reject.
    """
    return envelope.model_dump_json(by_alias=True)


def _first_error(exc: ValidationError) -> str:
    """One line an operator can act on, not a pydantic dump.

    The whole error goes nowhere useful: this is rendered in a UI beside a job
    that otherwise looks fine, and the question it has to answer is "what is
    wrong with this record", not "what are all fourteen ways it differs from
    the model".
    """
    first = exc.errors()[0]
    where = ".".join(str(p) for p in first["loc"]) or "manifest"
    return f"{where}: {first['msg']}"
