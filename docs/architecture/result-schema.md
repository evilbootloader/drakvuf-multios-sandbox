# Artifact / result schema

> No formal schema is implemented anywhere in this repository yet. This
> document records (a) what output locations already exist per
> source-verified script behavior, and (b) the design work still pending
> (DRAFT-018, Milestone M4). Section 3 marks which of its questions were
> **decided** by issue #3 on 2026-08-09 and which remain open; everything
> else below Section 2 is undecided.

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

## 3. Design work pending (DRAFT-018)

Two questions this section used to pose were answered elsewhere on
2026-08-09 by issue #3, which owns the job/result state model. They are
recorded here as **decided, not open**, so the two documents cannot answer
them differently:

- **Result keying — decided.** SHA-256 is the sample key; MD5 survives only
  as an identifier for cross-referencing external corpora, alongside SHA-1.
  Result *directories* are named by `analysis_id` rather than by any hash,
  so re-submitting a sample cannot collide with its earlier run. See
  `analysis-pipeline.md`, "Sample identification". Migrating the existing
  MD5-keyed Ubuntu output is DRAFT-011's work, not a free rewrite.
- **`status.json` shape — decided.** Field list, state machine, status
  taxonomy and the UI projection live in `analysis-pipeline.md`; this
  document does not restate them. `docs/checklists/android.md` §4.1/§7.3
  carry annotations recording what the shared model took from their
  proposals and what it changed.

Still genuinely open, and what remains of DRAFT-018:

- The storage layout itself — which artifacts land where inside a result
  directory, and what the atomic-publication boundary is in practice. The
  state model fixes the directory *name* and the temp-then-rename rule; it
  does not fix the contents.
- Which `type_identifiers` are actually computed. `imphash` and `telfhash`
  need a parsing library on Dom0 (`pefile`/LIEF, `telfhash`) that the
  project does not currently depend on; the model defines the fields as
  nullable and leaves the dependency decision here.
- Whether/how to fold in `capa` post-processing output (see
  `upstream-drakvuf.md` — capa v7.2.0 has a native DRAKVUF-log feature
  extractor, which is the cheapest integration path once this schema and
  real logs exist).