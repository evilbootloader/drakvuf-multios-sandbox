# Artifact / result schema

> No formal schema is implemented anywhere in this repository yet. This
> document records (a) what output locations already exist per
> source-verified script behavior, and (b) the design work still pending
> (DRAFT-018, Milestone M4). Do not treat anything below Section 2 as
> decided.

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

The Android checklist's own "Proposed result layout" (§4.1) uses SHA-256
instead of MD5 and a much richer structure — this is Candidate/proposed,
not yet implemented for either OS.

## 2. Reference point, not a contract: DRAKVUF Sandbox

CERT-Polska's `drakvuf-sandbox` produces JSON-structured, timestamped event
logs plus downloadable pcap/TLS-key/memdump artifacts, with a "JSON
inspector" UI. No formally published, versioned JSON Schema was found for
it during research (see `upstream-drakvuf.md`) — treat its shape as
inspiration only, not something to build against as a stable contract.

## 3. Design work pending (DRAFT-018)

Not yet decided:

- Whether to key results by SHA-256 (as the Android checklist proposes) or
  keep MD5 (as the current Ubuntu scripts do) — the Android proposal is the
  better default for a shared schema, but changing Ubuntu's existing keying
  is itself a modernization task, not a free rewrite.
- The OS-independent `status.json` shape (draft field list already exists
  in `docs/checklists/android.md` §7.3 and is referenced from
  `analysis-pipeline.md`'s job/state model section — these two documents
  should converge, not diverge, once DRAFT-008/DRAFT-018 are actually done).
- Whether/how to fold in `capa` post-processing output (see
  `upstream-drakvuf.md` — capa v7.2.0 has a native DRAKVUF-log feature
  extractor, which is the cheapest integration path once this schema and
  real logs exist).