# DRAFT-018: The result schema — the manifest, the layout, and the capability envelope

**Status:** Drafted 2026-08-25, **implemented 2026-08-26**. Indexed since the
first pass and never written — `issue-index.md` carried this row from the
beginning with no file behind it. Not published.

> **Built:** `platform/sandbox_platform/manifest.py` (models, shared name
> validator, tolerant `parse()`, capability envelope),
> `platform/tests/test_manifest.py` (76 cases), the reader in
> `routers/jobs.py`, the writer in `routers/worker.py`, and
> `result-schema.md` §3–4. 405 passed, 3 skipped.
>
> **Not built, and deliberately:** `documents` does not yet drive the UI's
> `_filled`. The mapping from a document name to a tab belongs with the
> capability that produces it — there is no `capa.json` to light the Behaviour
> tab with — so wiring it now would be guessing at four issues' output at
> once. The field is specified, validated and stored; the tab wiring lands
> with the first capability. This amends the acceptance criterion below rather
> than quietly dropping it.

**Area:** core/platform
**OS:** ALL
**Milestone:** M4
**Priority:** **P1.** Three of its defects are live in the deployed API today
(evidenced below), and ten drafted capabilities write into a shape nobody has
specified.
**Depends on:** #36 (admission and the worker channel), #37 (the object
store). Both **closed** — this issue is the shape of what they carry.
**Blocks:** DRAFT-019, 048, 049, 051, 053 directly; DRAFT-054 by convention.
**Needs Dom0:** **No.** Platform-side entirely. The worker's side of the
contract lands with `sandboxd` (DRAFT-060), which has no manifest writer yet
and so has nothing to migrate.

# Objective

Give `results/<job_id>/` a specified shape: a validated manifest, a reserved
layout, and one envelope every capability document shares.

# Context

## Two thirds of this issue closed while it sat unwritten

`issue-index.md:360` records what remained of 018 as three things. Two are
done and should stop being carried:

- **Result keying — closed twice.** Issue #3 decided it on 2026-08-09
  (`analysis_id`, SHA-256 as an indexed field), and #37 implemented it on
  2026-08-24 as `objects.py:result_prefix` → `results/<job_id>/`, with
  byte-exact round trips through hostile names in `test_objects.py`.
- **The atomic-publication boundary — closed by #36.** `POST
  /worker/jobs/<id>/complete` sets `state` and `manifest` in one committed
  `UPDATE` (`worker.py:494`), reachable only from `cleaning`. A reader sees
  nothing until that row lands, so there is no directory to catch mid-write.
  `platform.md:315` already says so. **The `KNOWN GAP` this issue carries for
  atomic publication should be struck, not solved.**

The third — which `type_identifiers` are computed, and the
`pefile`/LIEF/`telfhash` dependency it gates — has **moved to DRAFT-048**,
which now owns PE/ELF/APK parsing end to end. This issue defines the *fields*
and leaves the library choice there. Deciding it in both places is how two
documents come to disagree.

What is left is the part nobody wrote down, and it grew: **the manifest has no
shape at all.**

## The manifest is the one unvalidated worker input

Everything else the worker sends is constrained. `ArtifactRequest` bounds its
map to 64 entries and runs every name through `_reject_unsafe_name`
(`worker.py:363`), a careful validator that refuses absolute paths, backslashes,
control characters and `.`/`..` components, and whose docstring reasons
explicitly about percent-encoding. Sizes are `Field(ge=0)`. Submitted filenames
go through `_reject_unsafe_filename`.

The manifest is:

```python
class CompleteRequest(BaseModel):
    manifest: dict
```

And exactly one thing reads it — `jobs.py:400`, in the detail endpoint that
both the JSON API and the UI job view share:

```python
for name in manifest.get("artifacts", []):
    artifacts[name] = objects.presigned_get(
        f"{objects.result_prefix(job_id)}{name}", objects.Audience.BROWSER)
```

That loop mints a **capability per element** of a value with no declared type,
no bound, and no validation, from a row that is already committed.

### Measured, dev container, 2026-08-25

Rows inserted directly into `jobs` with `state='completed'` and the manifest
shown, then read back through `GET /api/v1/jobs/{id}`:

```text
manifest["artifacts"]        result
---------------------------  ------------------------------------------
["trace.log"]   (contract)   HTTP 200   1 URL
"trace.log"     (string)     HTTP 200   9 URLs   ← one per character
5               (int)        HTTP 500   TypeError: 'int' object is not iterable
null                         HTTP 500   TypeError: 'NoneType' object is not iterable
[["trace.log"]] (nested)     HTTP 500   TypeError: unhashable type: 'list'
{"trace.log": 1} (dict)      HTTP 200   1 URL    ← iterates keys, works by luck
[f"f{i}" for i in range(N)]  see below
```

```text
      1 names ->   0.07s    0.00 MB response
   1000 names ->   0.19s    0.35 MB response
  50000 names ->  11.74s   17.92 MB response
```

Three live defects, in order of how much they cost:

1. **A non-iterable `artifacts` permanently 500s the only view of a finished
   job.** The row is committed; there is no other way to read the result; the
   UI page uses the same `_detail`, so it dies identically. `null` is the one
   to notice — `.get("artifacts", [])` does **not** return the default when the
   key is present and null, which is the classic version of this bug.
2. **A string iterates its characters**, minting one presigned URL per
   character and reporting them as artifacts. Not an error anywhere: a
   plausible-looking result page listing nine files that do not exist.
3. **The list is unbounded**, and the work is repeated on every view. 50,000
   names cost 11.74s of signing and a 17.92 MB response *per request*, stored
   permanently in the row. The ticket endpoint caps at 64 names per call; the
   manifest, which describes the same names, caps at nothing.

None of these needs a hostile worker. A `sandboxd` bug that sets `artifacts`
to a string is the whole exploit, and it is a bug a Python writer makes
without noticing.

## Two doors, one guard

The same artifact names arrive twice — once at the ticket endpoint, once in
the manifest — and only the first door is guarded. A worker can request
tickets for clean names and then declare anything it likes.

**This is a defence-in-depth gap, not a live leak, and the draft should say so
plainly.** Traversal through the manifest was probed against MinIO in the dev
container, 2026-08-25, and refused twice over:

```text
key: results/<a>/../../samples/<victim>/victim.exe

curl (normalises the path)   SignatureDoesNotMatch
curl --path-as-is            XMinioInvalidResourceName
                             "Resource name contains bad components such as
                              '..' or '.'"
```

The second is the one that matters: **MinIO refuses `..` in an object name by
decision**, not by accident. The first is incidental — the client collapses the
path before sending, so it no longer matches what was signed.

So the containment claim in `objects.py`'s module docstring — that a sample
escaping into Dom0 "cannot enumerate the bucket, read another job's artifacts,
or reach the history" — currently holds *at the store*, not *at our boundary*.
The fix is one line of reuse: run the manifest's names through the validator
that already exists eight hundred lines away in the same file. A guarantee
that rests entirely on a dependency's input validation is one dependency
upgrade from not resting on anything.

## Ten drafts, no envelope

`capa.json` (DRAFT-019), `static.json` (DRAFT-048), `network.json`
(DRAFT-049), `memory.json` (DRAFT-051), `screenshots/NNN.png` (DRAFT-054) and
the plugin outputs DRAFT-050 audits all land in the same prefix, and each
draft specifies its own file in its own section. Nothing says what they have
in common.

Two properties every one of them needs, which none of them currently declares:

- **What produced this, at what version, with which rules.** capa rules, YARA
  rules and Suricata rules all version independently of our code, and a
  finding without its rule-pack version is not reproducible. "capa found no
  capabilities" means nothing without knowing which ruleset was asked.
- **Whether it finished.** A capa run that hit its timeout 40% through the log
  produces a short list of real findings that reads exactly like a clean
  sample. **A partial result is neither a success nor a failure**, and this is
  the same principle DRAFT-045 already fixed for the queue: `queued` is not a
  failure, and a silent hold with correct-looking output is the failure mode
  this architecture exists to remove. The tab must be able to say "capa
  covered 40% of the trace" rather than showing four findings and a blank.

Fixing this after five capabilities ship means five migrations. Fixing it now
costs one dataclass.

# Dependencies

- **#36** — the worker channel and `CompleteRequest`, which this reshapes.
- **#37** — `result_prefix`, `presigned_get`, and `results_bytes`.
- **#38** — the Artifacts tab, which renders the manifest today.
- **DRAFT-060 (`sandboxd`)** — the writer. It does not exist yet, which is
  precisely why the contract should be written before it does.
- **DRAFT-048** — inherits the `type_identifiers` dependency decision.

# Out of scope

- **The contents of any capability document.** This issue specifies the
  envelope and the reserved layout; what goes in `data` belongs to the issue
  that produces it. Specifying capa's output here would be deciding
  DRAFT-019's design in a document DRAFT-019 does not own.
- **Per-event rows in Postgres.** Settled in the #38 planning: traces live in
  the object store, Postgres holds a summary. Nothing here reopens it.
- **Migrating `$OUTPUTFOLDER/$MD5/`.** `dirwatch` still writes it on Dom0 and
  keeps its F8 collision until `sandboxd` replaces it. That gap is DRAFT-041's
  and stays open; this issue does not touch the running pipeline.
- **A JSON Schema registry, or publishing schemas externally.** Pydantic
  models in one module are the contract. A separate schema language would be a
  second place to be wrong.
- **Signing or hashing the manifest itself.** The worker is authenticated by
  `WORKER_TOKEN`; a compromised worker producing a wrong-but-valid manifest is
  a threat this issue does not claim to address.

# PLAN

1. Replace `manifest: dict` with a validated model, sharing
   `_reject_unsafe_name`. Closes all three live defects.
2. Make the reader total — a manifest that somehow fails validation renders as
   a degraded row, never a 500.
3. Define the reserved layout for `results/<job_id>/`.
4. Define the capability envelope, and record it in `result-schema.md`.
5. Strike the two closed `KNOWN GAP`s and re-point `type_identifiers` at
   DRAFT-048.

# CREATE

## The manifest

```python
_MAX_ARTIFACTS = 512   # see note

class ArtifactEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str                            # validated by _reject_unsafe_name
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    artifacts: list[ArtifactEntry] = Field(max_length=_MAX_ARTIFACTS)
    documents: list[str] = Field(default_factory=list, max_length=32)
    truncated: bool = False
    notes: str | None = Field(default=None, max_length=4096)
```

**`extra="forbid"`, not ignore.** A worker sending a field this does not know
is either running against a newer contract or malfunctioning, and both are
worth a 422 rather than silent discard.

**Entries, not bare names.** The worker knows the size and digest at upload
time — it just uploaded the file. Recording them means the detail view can
show sizes without a HEAD per object, an artifact's integrity is checkable
after the fact, and the manifest can be reconciled against `results_bytes`.
A bare name is the least the worker could tell us and the most it currently
does.

**`_MAX_ARTIFACTS = 512`, above the measured need and stated as such.**
`extracted/` is named after files the sample dropped, so the real ceiling is
however many files a sample writes — unbounded in principle, and 512 is a
deliberate refusal point rather than a natural limit. It is above the ticket
endpoint's 64-per-call because a worker may legitimately call that endpoint
several times. **`truncated` is why this is safe to bound:** a run that hit
the cap says so, and a reader that sees `truncated: true` knows the list is
incomplete rather than knowing nothing.

**`documents` names which capability documents are present.** Not derived from
`artifacts`, because "this run produced a `capa.json`" and "here is a file
called `capa.json`" are different claims, and the UI needs the first to decide
which tabs are filled — the job `catalogue.py:_filled` currently does by
guessing.

## Making the reader total

Validation at the door does not help the rows already committed, and this API
is deployed. So the reader gets a fallback:

```python
try:
    parsed = Manifest.model_validate(raw)
except ValidationError as exc:
    return degraded(raw, exc)      # renders; does not 500
```

**A malformed manifest must still render the job.** The state, timings,
failure reason and sample identity are all in the row and all still true; the
artifact list is the only part in doubt. Returning 500 for the whole job
because one field is the wrong type destroys evidence to punish a formatting
error.

## Reserved layout

```text
results/<job_id>/
  trace.log            DRAKVUF's JSONL event stream        reserved
  preconfig.log        injector output                     reserved
  capture.pcap         tcpdump                             reserved, may be 0 bytes
  manifest.json        this document                       reserved
  <capability>.json    one per capability                  reserved namespace
  memdump/…            plugin output                       prefix
  extracted/…          files the SAMPLE wrote              prefix, untrusted names
  screenshots/…        DRAFT-054                           prefix
```

**Reserved means a worker may not use the name for anything else**, so a
reader can trust `trace.log` is a trace. `extracted/` is the one prefix whose
leaf names are attacker-chosen, and it is called out here so nobody has to
rediscover it — this is the same distinction `_reject_unsafe_name`'s docstring
already draws, promoted to the layout so it is visible before the code is.

**`capture.pcap` may legitimately be zero bytes**, and #37 already accounts for
it: `presigned_artifact_upload`'s `content-length-range` starts at 0, not 1,
because a sample that made no network traffic is a real result. Recorded here
so the next reader does not "fix" it back.

## The capability envelope

```python
class Envelope(BaseModel):
    schema: str            # "sandbox.capa/1" — name and version together
    job_id: UUID
    produced_at: datetime
    producer: Producer     # name, version, ruleset_version | None
    status: Literal["complete", "partial", "failed"]
    status_reason: str | None
    data: dict             # the capability's own shape; not specified here
```

`status` is the load-bearing field, for the reason in Context: partial output
that renders as complete output is worse than no output, because it is
believed. `status_reason` carries "capa timed out after 120s at event
418,000 of an unknown total" — which is what a person actually needs.

`ruleset_version` is nullable because not every producer has one, and required
in the sense that a producer with rules and a null here is a bug.

# TEST

Against the real Postgres and MinIO, per the suite's existing arrangement.

1. **Each of the six measured shapes above.** `["x"]` accepted;
   `"x"`, `5`, `null`, `[["x"]]`, `{"x":1}` refused at `complete` with 422 —
   the three that are currently 500s and the two that currently succeed
   wrongly.
2. **A pre-existing malformed row renders.** Insert each bad shape directly,
   as the probe did, and assert the detail endpoint returns 200 with the job's
   own fields intact and the artifact list marked degraded. This is the
   regression test for the deployed rows, and it must be written against
   direct inserts because the API will no longer accept them.
3. **`_reject_unsafe_name` applies at both doors**, asserted by feeding the
   ticket endpoint's existing refusal cases to `complete` and expecting the
   same refusals. Parametrise from one list so the two cannot drift.
4. **Byte-exact hostile names survive.** `50%off.exe`, a name with quotes,
   spaces and non-ASCII — admitted, stored, and returned identically. The
   escape-on-output rule from DRAFT-045 applies here as it does to filenames,
   and the existing UI browser tests cover the execution half.
5. **`_MAX_ARTIFACTS + 1` is refused**, and a `truncated: true` manifest at
   exactly the cap renders with the flag visible.
6. **A 50,000-name manifest is impossible via the API**, and the pre-existing
   one from the probe renders in bounded time.
7. **The envelope round-trips**, including `status: "partial"` with a reason,
   and a document whose `data` this repository has no model for — forward
   compatibility is the point.
8. **`documents` drives `_filled`**, replacing the current guess.

# DEPLOY

Platform-side only; no Dom0 change and no pipeline change.

```bash
pct exec 102 -- su - platform -s /bin/bash -c 'cd /opt/platform/src && git pull --ff-only'
pct exec 102 -- systemctl restart sandbox-api sandbox-api-browser
```

**No migration.** `manifest` stays `jsonb`; what changes is what is written
into it and how it is read. Existing rows keep working via the degraded path —
which is the reason that path exists rather than a nicety.

**No worker change is required to deploy this**, because no worker writes a
manifest yet: `sandboxd` does not exist and `dirwatch` does not talk to the
API. The contract is being written before its only writer, which is the
cheapest moment it will ever be available.

# Acceptance criteria

- [x] `CompleteRequest.manifest` is a validated model, not `dict`.
- [x] Artifact names go through `_reject_unsafe_name` at both doors, from one
      shared list of cases.
- [x] `artifacts` is bounded, and hitting the bound sets `truncated`.
- [x] No manifest value can produce a 500 from `GET /api/v1/jobs/{id}` or the
      UI job view; malformed rows render degraded.
- [x] The six measured shapes each have a test.
- [x] The reserved layout is documented, including which prefix holds
      attacker-named leaves.
- [x] The envelope exists, carries `status`/`status_reason`/`ruleset_version`,
      and DRAFT-019/048/049/051 are updated to reference it rather than
      specify their own.
- [x] `result-schema.md`'s atomic-publication `KNOWN GAP` is struck as closed
      by #36, and its `type_identifiers` question re-pointed at DRAFT-048.
- [x] `objects.py`'s containment docstring is true at our boundary, not only
      at MinIO's.

# Evidence required

- The probe transcripts above, re-run against the fixed code, showing 422
  where there was 500 and where there was a wrong 200.
- A degraded render of each pre-existing bad row.
- The full suite passing, with the existing manifest tests
  (`test_jobs_api.py:493`, `test_worker_api.py:199,208`) updated rather than
  deleted — they encode the current contract and their diff is the record of
  what changed.
- One capability document — capa's, from DRAFT-019 — validating against the
  envelope, as the first real consumer.

# Security considerations

- **The manifest is attacker-influenced twice over**: `extracted/` leaves are
  named by the sample, and the whole document is written by a host that runs
  malware. Treating it as trusted because it arrives with `WORKER_TOKEN` is
  the mistake this issue exists to prevent — the token authenticates the
  *host*, and the host is the one deliberately exposed to the sample.
- **Traversal is contained at the store, not at our boundary** — evidenced
  above, `XMinioInvalidResourceName`. This issue moves the guarantee to code
  we own. It is not currently exploitable and the acceptance criteria should
  not imply it is.
- **Capability minting is the real amplifier.** Each name costs an HMAC and
  yields a URL that reads one object. Bounding the list bounds both the CPU
  and the number of live capabilities a single row can produce — 11.74s and
  17.92 MB from one committed row is a stored, repeatable cost.
- **Refuse, never sanitise**, consistent with `_reject_unsafe_name` and with
  admission. A rewritten name stores real evidence under a false one.
- **The degraded path must not become a bypass.** It renders the job; it must
  never mint a URL from an unvalidated name. Degraded means *fewer*
  capabilities, not looser ones — worth an explicit test rather than an
  intention.
- **`sha256` per artifact is not integrity against a compromised worker**, and
  the field should not be described as if it were: the same worker supplies
  both file and digest. It detects corruption and store-side loss. Saying so
  in the model's docstring is the difference between a useful field and a
  false guarantee, per the comment rule in CLAUDE.md.

# Documentation changes

- **Rewritten:** `docs/architecture/result-schema.md` — Section 3 becomes the
  specification instead of a list of open questions. Sections 1 and 2 stay:
  §1 is source-verified current Ubuntu behaviour and remains true until
  `sandboxd` lands, and its F8 annotation must not be edited in place.
- **Updated:** `docs/architecture/platform.md` — the bucket layout gains the
  reserved names and the envelope.
- **Updated:** `.github/issue-drafts/issue-index.md` — row 018 loses the two
  closed items; DRAFT-019/048/049/051 rows note the envelope dependency.
- **Updated:** DRAFT-019, 048, 049, 051 — reference the envelope rather than
  each specifying a bare `*.json`.
- **Updated:** `docs/checklists/platform.md` — the manifest contract as a
  checklist item.

# Recovery / rollback

Revert the commit. `manifest` is `jsonb` and unmigrated, so nothing written
under the new model is unreadable by the old code — the old reader ignores
every field except `artifacts`, and under the new model that field is a list
of objects rather than strings, so the old reader would mint URLs from
`ArtifactEntry` dicts and fail.

**That asymmetry is the one thing to notice before deploying:** new manifests
are not backward-readable, so a rollback must be paired with either no
new-format rows or a reader that tolerates both. Given there is no writer yet,
the safe order is to deploy the reader that accepts both shapes first, and the
writer with `sandboxd`.