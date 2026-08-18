# Artifact / result schema

> No formal schema is implemented anywhere in this repository yet. This
> document records (a) what output locations already exist per
> source-verified script behavior, and (b) the design work still pending
> (DRAFT-018, Milestone M4). Section 3 marks which of its questions were
> **decided** by issue #3 on 2026-08-09 and which remain open; everything
> else below Section 2 is undecided.

## 1. Current, source-verified output locations (Ubuntu and Android)

**Changed 2026-08-18.** Both pipelines now write into
`$OUTPUTFOLDER/<sha256>/<analysis_id>/`, where `<analysis_id>` is
`<utime>-<vlan>` — one directory per **run**, grouped under the sample's
content hash. The five scripts derive it independently, from arguments
`dirwatch` already passes; no contract changed.

```text
/malware_finished/<os>/
└── <sha256>/                     every run of these bytes
    ├── <utime>-<vlan>/           one run
    │   ├── preconfig.log         injector output: staging, network, (Android) install
    │   ├── drakvuf.log           DRAKVUF's own stdout/stderr
    │   ├── tcpdump.pcap          written by the shared tcpdump.sh
    │   ├── launch-component      Android APK path only
    │   ├── dump/                 -D, fileextractor + the JSON event log
    │   ├── memdump/              --memdump-dir
    │   └── <submitted filename>  moved in by drakvuf-<os>.sh on success
    └── <utime>-<vlan>/           a second run: different name, or a retry
```

The sample keeps the name it was submitted with and sits inside the run
directory rather than beside it under `<sha256>/`, because that name is
precisely what differs between two runs of identical bytes (C5).

> **Why this changed.** It was `$OUTPUTFOLDER/$MD5/` until 2026-08-18 —
> keyed on content alone, so two submissions of identical bytes under
> different names shared one directory and truncated each other's
> `preconfig.log` and `drakvuf.log`, while `dump/` and `memdump/`
> interleaved with nothing recording which run produced what. Recorded as
> **F8** in `docs/runbooks/verify-android-mvp.md`, where it corrupted the
> evidence for one of that runbook's own steps before anyone read it.
>
> It was benign before DRAFT-030 and is not after it: the submitted
> filename is now what the guest executes, and extension dispatch and
> `argv[0]` self-checks are exactly the behaviour that makes two such
> submissions different analyses rather than one repeated.

Two reliability notes that survive the change unaltered: `drakvuf-<os>.sh`
still kills tcpdump by `ps aux | grep` rather than by a PID file from this
location (`docs/checklists/android.md` §2.10, DRAFT-011), and the
directory is still written in place rather than published atomically —
see Section 3.

The Android checklist's own "Proposed result layout" (§4.1) proposed
SHA-256 keying and a much richer structure. The keying half is now
implemented; the richer structure is still Candidate.

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

- **Result keying — decided, and implemented 2026-08-18.** SHA-256 is the
  sample key; MD5 survives only as an identifier for cross-referencing
  external corpora, alongside SHA-1. Result directories are
  `<sha256>/<analysis_id>/`, so re-submitting a sample cannot collide with
  its earlier run. See `analysis-pipeline.md`, "Sample identification",
  and its amendment note for the two ways the implemented layout differs
  from what was decided on 2026-08-09: the directory is **nested** under
  the digest rather than flat, which retires the planned
  `index/by-sha256/` mapping, and `analysis_id` is `<utime>-<vlan>` rather
  than a ULID. Migrating **existing** MD5-keyed output on disk was not
  done and is not planned — old directories are left where they are.
- **`status.json` shape — decided.** Field list, state machine, status
  taxonomy and the UI projection live in `analysis-pipeline.md`; this
  document does not restate them. `docs/checklists/android.md` §4.1/§7.3
  carry annotations recording what the shared model took from their
  proposals and what it changed.

Still genuinely open, and what remains of DRAFT-018:

- **The atomic-publication boundary — still open, and now the larger half.**
  The 2026-08-18 change fixed the directory *name* and the contents are
  what Section 1 records, but nothing publishes them: all three writing
  callbacks write straight into the final path, so a reader can observe a
  half-written run. No one of them can fix it — none knows the other two
  have finished — so it needs an actor owning the whole run
  (`dirwatch`/`cleanup.sh`). The layout is ready for it: the rename target
  is the `<analysis_id>` leaf, staged as `<sha256>/.<analysis_id>.tmp`.
- **Marking retries as retries.** Each attempt now gets its own directory,
  because `dirwatch`'s `goto restart` re-enters `prepare()` and re-stamps
  `utime`. That is an improvement on truncating the previous attempt, but
  nothing records that three directories are three attempts at one
  submission — the `attempt` field exists in the model and is not yet
  emitted (DRAFT-011).
- Which `type_identifiers` are actually computed. `imphash` and `telfhash`
  need a parsing library on Dom0 (`pefile`/LIEF, `telfhash`) that the
  project does not currently depend on; the model defines the fields as
  nullable and leaves the dependency decision here.
- Whether/how to fold in `capa` post-processing output (see
  `upstream-drakvuf.md` — capa v7.2.0 has a native DRAKVUF-log feature
  extractor, which is the cheapest integration path once this schema and
  real logs exist).