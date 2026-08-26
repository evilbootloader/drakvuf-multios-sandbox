# Artifact / result schema

> **Superseded in part, 2026-08-26 (DRAFT-018).** This document opened by
> saying "no formal schema is implemented anywhere in this repository yet".
> That was true when written and is no longer: `sandbox_platform/manifest.py`
> now specifies the manifest and the capability envelope, and Sections 3 and 4
> below are the specification rather than a list of open questions.
>
> Section 1 stays as written. It is source-verified behaviour of the Ubuntu
> scripts **as they run on Dom0 today**, and remains true until `sandboxd`
> replaces `dirwatch` — including its `KNOWN GAP` on MD5 keying, which is
> still live in the running system.
>
> Read Section 1 for what the pipeline does now, and Sections 3–4 for what the
> platform specifies.

## 1. Current, source-verified output locations (Ubuntu)

Per `automation/preconfig-ubuntu.sh` and `automation/drakvuf-ubuntu.sh`,
each analysis writes into `$OUTPUTFOLDER/$MD5/` (MD5 of the sample, not
SHA-256):

- `$OUTPUTFOLDER/$MD5/preconfig.log` — `injector` output from network setup
  + sample staging.
- `$OUTPUTFOLDER/$MD5/drakvuf.log` — DRAKVUF's own stdout/stderr.
- DRAKVUF's `-D $OUTPUTFOLDER/$MD5` output directory and `-o json` flag
  imply structured DRAKVUF event output lands there too, in JSON.
- `automation/tcpdump.sh` writes `$OUTPUTFOLDER/$MD5/tcpdump.pcap` (per its
  own argument contract; note `drakvuf-ubuntu.sh` kills tcpdump by
  `ps aux | grep`, not by reading a PID file from this location — a
  reliability gap noted in `docs/checklists/android.md` §2.10 and carried
  into the Ubuntu modernization plan).

> **KNOWN GAP (DRAFT-041) — MD5 keying collides, and the fix was
> deliberately declined on 2026-08-21.** Because the directory is named
> after the sample's *content* digest, two submissions of identical bytes
> under different filenames write to the same place and overwrite each
> other, and a trace-timeout retry re-enters with the same key and truncates
> the previous attempt's logs. Evidenced on Dom0 2026-08-17 as **F8** in
> `docs/runbooks/verify-android-mvp.md`.
>
> A fix existed — `<sha256>/<utime>-<vlan>` per-run directories, on the
> `vlan-lease` branch — and was **not merged**. `<utime>-<vlan>` is a
> synthetic analysis id that exists only because `dirwatch` has no job
> identity; the jobs table in `docs/architecture/platform.md` supplies one,
> and results are keyed `results/<job_id>/`. Merging it would have built the
> filesystem-shaped scheme that design deletes. The gap therefore stays open
> until `sandboxd` lands, and is recorded here so it is not rediscovered as
> a surprise.
>
> **2026-08-24 (#37): the replacement now exists, and the gap is still
> open.** `results/<job_id>/` is implemented and tested in the object store —
> `sandbox_platform/objects.py:result_prefix`, with byte-exact round trips
> through hostile names in `platform/tests/test_objects.py`. So the keying is
> no longer a proposal.
>
> But **nothing analysing samples uses it yet.** `dirwatch` still writes
> `$OUTPUTFOLDER/$MD5/` on Dom0, so both collisions above are live in the
> running system exactly as before. Only `sandboxd` closes this.
>
> DRAFT-044 claims this issue "closes the MD5-collision gap ... as F8". It
> does not, and that sentence should be read as describing the object-store
> layout rather than the pipeline. Recorded here rather than corrected there,
> per the annotate-never-rewrite rule.

The Android checklist's own "Proposed result layout" (§4.1) uses SHA-256
instead of MD5 and a much richer structure — this is Candidate/proposed,
not yet implemented for either OS. Its keying question was settled on
2026-08-09 in favour of neither: result directories are named by
`analysis_id`, with SHA-256 as an indexed field (Section 3).

## 2. Reference point, not a contract: DRAKVUF Sandbox

CERT-Polska's `drakvuf-sandbox` produces JSON-structured, timestamped event
logs plus downloadable pcap/TLS-key/memdump artifacts, with a "JSON
inspector" UI. No formally published, versioned JSON Schema was found for
it during research (see `upstream-drakvuf.md`) — treat its shape as
inspiration only, not something to build against as a stable contract.

## 3. What was open, and where each question went

Everything this section used to carry as pending is now decided somewhere.
Recorded here with its destination so no two documents can answer the same
question differently.

- **Result keying — decided 2026-08-09 (issue #3), implemented 2026-08-24
  (#37).** SHA-256 is the sample key; MD5 survives only as an identifier for
  cross-referencing external corpora, alongside SHA-1. Result directories are
  named by job id — `objects.py:result_prefix` → `results/<job_id>/` — so
  re-submitting a sample cannot collide with its earlier run. See
  `analysis-pipeline.md`, "Sample identification". Migrating the existing
  MD5-keyed Ubuntu output is DRAFT-011's work, not a free rewrite.
- **`status.json` shape — decided.** Field list, state machine, status
  taxonomy and the UI projection live in `analysis-pipeline.md`; this
  document does not restate them. `docs/checklists/android.md` §4.1/§7.3
  carry annotations recording what the shared model took from their
  proposals and what it changed.
- **The atomic-publication boundary — closed by #36, not solved here.**
  `POST /api/v1/worker/jobs/<id>/complete` sets the state and the manifest in
  a single committed `UPDATE`, reachable only from `cleaning`. A reader sees
  nothing until that row lands, so there is no directory for anyone to catch
  mid-write and no temp-then-rename dance to get right. The `KNOWN GAP` this
  document used to carry for it is struck.
- **Which `type_identifiers` are computed — moved to DRAFT-048.** `imphash`
  and `telfhash` need a parsing library (`pefile`/LIEF, `telfhash`), and
  DRAFT-048 now owns PE/ELF/APK parsing end to end. It makes that dependency
  decision; this document defines the fields as nullable and does not
  duplicate the choice.
- **Folding in `capa` — moved to DRAFT-019**, which specifies the run, the
  `2>&1` fix that currently merges stderr into the JSONL stream, and the
  PID-0 exclusion. Its output is a capability document under Section 4.2.

## 4. The specification (DRAFT-018)

Implemented in `platform/sandbox_platform/manifest.py`; the models there are
the contract, and this section is its rationale. There is deliberately no
separate JSON Schema file — a second place to state the same rules is a second
place to be wrong.

### 4.1 Layout

```text
results/<job_id>/
  trace.log            DRAKVUF's JSONL event stream        reserved
  preconfig.log        injector output                     reserved
  capture.pcap         tcpdump                             reserved, may be 0 bytes
  manifest.json        the document below                  reserved
  <capability>.json    one per capability                  reserved namespace
  memdump/…            plugin output                       prefix
  extracted/…          files the SAMPLE wrote              prefix, untrusted names
  screenshots/…        DRAFT-054                           prefix
```

**Reserved means a worker may not use the name for anything else**, so a
reader can trust that `trace.log` is a trace.

**`extracted/` is the one prefix whose leaf names are chosen by the sample.**
Called out in the layout rather than left to be rediscovered in code: those
names are untrusted input on the same footing as a submitted filename, and
`manifest.reject_unsafe_name` is what stands behind them.

**`capture.pcap` may legitimately be zero bytes.** A sample that made no
network traffic is a real result, and #37's upload policy starts its
`content-length-range` at 0 rather than 1 for exactly this reason. Recorded so
that the next reader does not "fix" it back.

### 4.2 The manifest

One committed row, `jobs.manifest`, written once at `/complete`. Bounded by
construction: at most 512 artifacts, `notes` at 4096 characters, unknown
fields refused.

Each artifact is an **entry**, not a bare name — `name`, `size_bytes`,
`sha256`. The worker knows all three at the moment it declares them, having
just uploaded the file, so a bare name was the least it could say and was,
until DRAFT-018, the most it did.

> **`sha256` is not integrity against a compromised worker** and must not be
> described as if it were: the same host supplies both the file and the
> digest. It detects corruption in transit and loss in the store.

`documents` names the capability documents the run produced, and every one
must also appear in `artifacts` — claiming a document that was never uploaded
lights a tab whose content 404s, which is worse than an empty tab.

`truncated` is what makes a bound safe. A run that hit the cap says so, and a
reader that knows the list is incomplete is in a different position from one
that believes it is looking at everything.

**Reading is tolerant, writing is strict.** `manifest.parse()` never raises: a
manifest is written once and read forever, so a row written under an older
contract still renders the job it describes. Degraded means *fewer*
capabilities, never looser ones — a manifest that fails to validate yields an
empty artifact list, so no presigned URL is ever minted from a name that was
not checked.

The pre-DRAFT-018 shape — `{"artifacts": ["trace.log"]}`, a list of bare
names — is read as legacy and reported as such, because every manifest written
before 2026-08-26 has it and rejecting them would have sent every completed
job on the deployment to the degraded path at the first restart.

### 4.3 The capability envelope

Every `<capability>.json` shares one wrapper:

```json
{
  "schema": "sandbox.capa/1",
  "job_id": "…",
  "produced_at": "…",
  "producer": {"name": "capa", "version": "7.2.0",
               "ruleset_version": "v7.2.0-rules"},
  "status": "complete | partial | failed",
  "status_reason": null,
  "data": { }
}
```

**`status` is the load-bearing field.** A capa run that hit its timeout 40%
through the log produces a short list of real findings that reads exactly like
a clean sample — and a partial result believed to be complete is worse than no
result. This is the same failure shape the queue already fixed once: `queued`
is not a failure, and a silent hold with correct-looking output is what this
architecture exists to remove. `status_reason` is required whenever the status
is not `complete`, and should be specific enough to act on.

**`ruleset_version` is why `producer` is a structure rather than a string.**
capa rules, YARA rules and Suricata rules all version independently of this
repository, so "capa found no capabilities" is not a finding until you know
which rules were asked.

**`data` is deliberately unmodelled.** What goes inside belongs to the issue
that produces it. This repository must be able to read a document from a
capability it knows nothing about, and specifying capa's payload here would be
deciding DRAFT-019's design in a document DRAFT-019 does not own.