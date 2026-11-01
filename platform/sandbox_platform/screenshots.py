"""The filmstrip of one run, from what its manifest says it uploaded. DRAFT-054.

`sandboxd/screenshots.py` writes the frames and the index; this reads them for
the Screenshots tab. Design: `docs/architecture/screenshots.md`.

**The manifest decides which frames exist; the index only adds timing.** A
frame is offered only if the manifest lists it -- `parse` yields nothing from a
manifest it could not validate, so no URL is ever built from an unchecked name
-- and only if its name is exactly `screenshots/<digits>.png`. Every other
name under that prefix is not a frame, whoever uploaded it.

**Never raises.** Like `report.py`: a strip that cannot be read degrades to
frames without timing, or to a sentence saying why there are none. The job
page renders regardless.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import quote
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import manifest as manifest_schema
from . import objects

log = logging.getLogger(__name__)

FRAME_NAME = re.compile(r"^screenshots/(\d{3,6})\.png$")
INDEX_NAME = "screenshots.json"
SCHEMA = "sandbox.screenshots/1"

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# The index lists at most a few hundred frames. Far above that, and refused
# rather than read: the bound is on this process's memory.
MAX_INDEX_BYTES = 1 << 20

# Served inline only below this. A 3840x2160 frame of noise is about 25 MiB of
# PNG, the largest sandboxd can write; anything bigger did not come from it.
MAX_FRAME_BYTES = 32 << 20

# The playback step when a run has frames and no readable index. Labelled as a
# guess on the page: it is sandboxd's default, not something this run said.
FALLBACK_INTERVAL = 2.0


def frame_tick(name: str) -> int | None:
    """The tick a frame name stands for, or None if it is not a frame."""
    m = FRAME_NAME.match(name)
    return int(m.group(1)) if m else None


def frame_url(job_id: UUID, name: str) -> str:
    return f"/api/v1/jobs/{job_id}/screenshot?name={quote(name, safe='')}"


# --- the index -------------------------------------------------------------
#
# Lenient about what it does not use (`extra="ignore"`), strict about the
# types of what it does: these numbers become playback timing and labels.

class _IndexFrame(BaseModel):
    model_config = ConfigDict(extra="ignore")
    tick: int = Field(ge=0, le=999_999)


class _IndexMissed(BaseModel):
    model_config = ConfigDict(extra="ignore")
    tick: int = Field(ge=0, le=999_999)
    reason: str = Field(default="", max_length=500)


class _IndexData(BaseModel):
    model_config = ConfigDict(extra="ignore")
    interval_s: float = Field(gt=0, le=3600)
    ticks: int | None = Field(default=None, ge=0, le=999_999)
    marks: dict[str, float] = Field(default_factory=dict, max_length=16)
    frames: list[_IndexFrame] = Field(default_factory=list, max_length=100_000)
    missed: list[_IndexMissed] = Field(default_factory=list,
                                       max_length=100_000)


@dataclass(frozen=True)
class Index:
    status: str
    status_reason: str | None
    interval: float
    ticks: int | None
    marks: dict
    missed: int


@dataclass(frozen=True)
class LoadedIndex:
    index: Index | None = None
    error: str | None = None


def parse_index(raw: bytes) -> LoadedIndex:
    """Bytes of screenshots.json to an Index, or the reason there is none."""
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        return LoadedIndex(error=f"screenshots.json is not JSON: {exc}")
    try:
        envelope = manifest_schema.Envelope.model_validate(document)
    except ValidationError as exc:
        return LoadedIndex(error="screenshots.json is not a capability "
                                 f"document: {_first(exc)}")
    if envelope.schema_id != SCHEMA:
        return LoadedIndex(error=f"screenshots.json is {envelope.schema_id!r}; "
                                 f"this platform reads {SCHEMA!r}")
    try:
        data = _IndexData.model_validate(envelope.data)
    except ValidationError as exc:
        return LoadedIndex(error=f"screenshots.json did not validate: "
                                 f"{_first(exc)}")
    return LoadedIndex(index=Index(
        status=envelope.status,
        status_reason=envelope.status_reason,
        interval=data.interval_s,
        ticks=data.ticks,
        marks={k: v for k, v in data.marks.items()
               if k in ("trace_start", "trace_end") and v >= 0},
        missed=len(data.missed),
    ))


def _first(exc: ValidationError) -> str:
    e = exc.errors()[0]
    return f"{'.'.join(str(p) for p in e['loc']) or 'document'}: {e['msg']}"


def _read(key: str) -> bytes | None:
    out = bytearray()
    for chunk in objects.chunks(key):
        out += chunk
        if len(out) > MAX_INDEX_BYTES:
            return None
    return bytes(out)


def _fetch(key: str) -> LoadedIndex:
    try:
        raw = _read(key)
    except Exception as exc:  # noqa: BLE001 - the page must render regardless
        log.warning("screenshot index %s could not be read: %s", key, exc)
        return LoadedIndex(error="screenshots.json could not be read from "
                                 "the store")
    if raw is None:
        return LoadedIndex(error=f"screenshots.json is over {MAX_INDEX_BYTES} "
                                 "bytes and was not read")
    return parse_index(raw)


@lru_cache(maxsize=32)
def _load(key: str, sha256: str) -> LoadedIndex:
    """One parsed index per (object, digest) -- the `report._load` shape: a
    retried attempt writes a different digest, so an entry never goes stale."""
    return _fetch(key)


# --- the strip -------------------------------------------------------------

@dataclass(frozen=True)
class Frame:
    tick: int
    name: str
    src: str            # the inline image route
    download: str       # the wrapped ZIP route, as on the Artifacts tab
    elapsed: float | None
    label: str
    mark: str           # "sample started", "trace ended", or ""


@dataclass(frozen=True)
class Strip:
    frames: tuple[Frame, ...] = ()
    # From the index. None when the run uploaded none, which is a host that
    # predates screenshots or has them switched off.
    index: Index | None = None
    # Set when an index was uploaded and could not be read.
    error: str | None = None

    @property
    def interval(self) -> float:
        return self.index.interval if self.index else FALLBACK_INTERVAL

    @property
    def timed(self) -> bool:
        """Whether the labels and playback timing come from the run itself."""
        return self.index is not None


def _label(seconds: float) -> str:
    whole = int(round(seconds))
    return f"{whole // 60}:{whole % 60:02d}"


def for_job(job_id: UUID, manifest: object, key_prefix: str,
            artifacts: dict[str, str], expired: bool = False) -> Strip:
    """The filmstrip of one run.

    `artifacts` is `JobDetail.artifacts` -- name to wrapped download link --
    which is already empty past retention and for a manifest that did not
    validate, so it is the list of what may be offered at all.
    """
    if expired or not artifacts:
        return Strip()
    named = sorted((tick, name) for name in artifacts
                   if (tick := frame_tick(name)) is not None)

    loaded = LoadedIndex()
    entry = next((a for a in manifest_schema.parse(manifest).artifacts
                  if a.name == INDEX_NAME), None)
    if entry is not None:
        key = objects.result_prefix(job_id, key_prefix) + INDEX_NAME
        loaded = _load(key, entry.sha256) if entry.sha256 else _fetch(key)
    index = loaded.index

    interval = index.interval if index else None
    marks = {}
    if index and interval:
        # The first frame at or after each mark: the frame due at tick k is
        # taken at about k * interval, so that is the first one that can show
        # what the mark announces.
        for key_, text in (("trace_start", "sample started"),
                           ("trace_end", "trace ended")):
            at = index.marks.get(key_)
            if at is None:
                continue
            first = next((t for t, _ in named if t * interval >= at), None)
            if first is not None:
                marks.setdefault(first, text)

    frames = tuple(
        Frame(tick=tick, name=name, src=frame_url(job_id, name),
              download=artifacts[name],
              elapsed=tick * interval if interval else None,
              label=_label(tick * interval) if interval else f"#{tick}",
              mark=marks.get(tick, ""))
        for tick, name in named)
    return Strip(frames=frames, index=index, error=loaded.error)


def count(artifacts: dict[str, str]) -> int:
    """Frames among a job's artifacts, for the tab's badge -- names only, no
    read of the store."""
    return sum(1 for name in artifacts if frame_tick(name) is not None)
