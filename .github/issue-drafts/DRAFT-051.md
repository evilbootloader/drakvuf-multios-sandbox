# DRAFT-051: Memory and payload extraction — YARA over dumps, and family configs

**Status:** Drafted 2026-08-25. Not published.
**Area:** enrichment
**OS:** ALL, unevenly — the parser corpora are overwhelmingly Windows.
**Milestone:** M5
**Priority:** P2. Highest analytical value, largest effort, and the only one
carrying an unresolved licence question.
**Depends on:** #37, DRAFT-048 (shares YARA), DRAFT-050 (`procdump2`).
**Needs Dom0:** **No** for processing. **Yes** for `procdump2`.

# Objective

Get the payload out. Scan memory dumps with YARA, repair what looks like an
executable, and extract malware-family configuration.

# Context

## The capability the comparison document says we lack

`Malware Sandbox Capability Comparison — 2026.md` rates DRAKVUF "◐" for config
extraction, against CAPE's "✅ Excellent" — and calls config extraction and
unpacking CAPE's whole reason to exist. That is fair. DRAKVUF produces memory
dumps; it has no opinion about what is in them.

But the raw material is better than the rating suggests. `memdump` captures
the memory regions a process **writes**, which is precisely where an unpacker
puts its decoded payload. We are collecting the right bytes and doing nothing
with them.

## Three separable pieces, increasing in difficulty

1. **YARA over dumps.** Same engine as DRAFT-048, different input. Finds
   family signatures in memory that are absent from the file on disk, which is
   the entire point of packing. Cheap, and worth doing alone.
2. **PE repair.** A dumped region is not a loadable PE: the section table
   reflects memory layout rather than file layout, and the import table is
   resolved addresses rather than names. Repairing enough to run YARA and hand
   it to a person is well-trodden but fiddly.
3. **Config extraction.** Family-specific parsers that pull C2 addresses,
   campaign IDs, mutexes and keys. The highest value and the most work.

## The licence question, which comes first

The parser corpora are the capability; nobody writes their own. The candidates
carry different terms and it is a decision before it is an integration:

- **CAPE's parsers** — CAPE is GPLv3. Vendoring them makes the licence
  question real for this project, which already ships GPL DRAKVUF code but has
  not thought about a second corpus.
- **MalDuck** (CERT Polska), **DC3-MWCP** (US DoD), **RATDecoders**, **MaCo**
  — each with its own terms.

**DRAFT-022 owns this and must answer before code is written.** Discovering a
licence conflict after integration is how a capability gets ripped out.

## Where this is weakest

Config extraction is a **Windows capability** in practice. The corpora target
Windows families overwhelmingly; Linux and Android coverage is thin. That is
not a flaw in the plan, it is the state of the field — worth writing down so
an empty config section on an Android report is understood rather than
debugged.

# Dependencies

- **#37** — the dumps.
- **DRAFT-048** — one YARA integration, two inputs.
- **DRAFT-050** — `procdump2` gives whole-process dumps on Linux and Windows,
  which is better raw material than `memdump`'s regions for some families.
- **DRAFT-022** — the licence decision. Hard blocker on piece 3.

# Out of scope

- **Writing family parsers.** Integrate a corpus; authoring is a research
  activity without end.
- **Full unpacking as CAPE does it.** CAPE's debugger-driven unpacking is a
  different architecture — it hooks and breakpoints inside the guest, which is
  precisely what this project's agentless design refuses.
- **Emulation.** Out of scope here; FLOSS in DRAFT-048 already carries the
  argument about running attacker code on the platform.

# PLAN

1. Settle the licence (DRAFT-022) before anything else.
2. YARA over dumps — independently useful, ships alone.
3. PE repair.
4. One family parser end to end, then the corpus.

# CREATE

## YARA over dumps

Every object under `results/<job_id>/memdump/`, scanned with the DRAFT-048
corpus. Report rule name, the dump it hit, and the offset. A match in memory
that is absent from the file on disk is the single most useful line this
project could add to a report.

## PE repair

Detect a PE header in a dump; rebuild section alignment; reconstruct imports
where the IAT is resolvable. Output a file that loads in a disassembler, marked
**reconstructed** — it is not the original bytes and must never be presented as
though it were.

## Config extraction

Family parsers over dumps and repaired payloads. Output is structured — C2
hosts, ports, campaign and bot identifiers, mutexes, keys — and pinned to the
parser and version that produced it, because a config is an assertion by a
parser rather than an observation.

## Presentation

Memory tab: dumps with their YARA matches, extracted payloads marked
reconstructed, and configs attributed to their parser. Extracted executables
download under #37's `infected` convention — they are live malware, and more
directly so than the submitted sample, which may only have been a dropper.

# TEST

1. **A packed sample whose unpacked payload matches a YARA rule** — the rule
   does not match the file on disk and does match the dump. That single test
   is the whole justification for this issue.
2. **A repaired PE loads** in an independent tool.
3. **A repaired PE is labelled reconstructed** everywhere it appears.
4. **A known family's config extracts**, and its C2 matches what the pcap
   shows the sample contacting — two independent observations agreeing.
5. **A parser crash is contained.** Corpora are third-party code over hostile
   input; one bad parser must not fail the job.
6. **Dumps are streamed.** A memdump set can be gigabytes.
7. **An Android job with no config produces an empty section that says why**,
   not an empty section that implies nothing was found.

# DEPLOY

Post-processing alongside the others. Output `results/<job_id>/memory.json`

> **Wrapped in the DRAFT-018 envelope (added 2026-08-26).** This draft
> specified a bare `*.json`; it is now `sandbox.memory/1` inside the shared envelope —
> `schema`, `job_id`, `produced_at`, `producer` (with `ruleset_version`),
> `status`, `status_reason`, `data`. The payload this draft describes goes in
> `data` and is unchanged. **`status` is not optional decoration:** a run that
> hit its timeout part-way through produces real findings that read exactly
> like a clean sample, and this is the field that tells them apart. See
> `docs/architecture/result-schema.md` §4.3 and
> `sandbox_platform/manifest.py`.
plus repaired payloads as artifacts.

# Acceptance criteria

- [ ] Licence decided and recorded before integration.
- [ ] YARA over dumps, with a demonstrated in-memory-only match.
- [ ] PE repair produces a loadable file, labelled reconstructed.
- [ ] At least one family config extracted and corroborated against the pcap.
- [ ] Parser failures are contained and attributed.
- [ ] Extracted executables served under the `infected` convention.
- [ ] Thin non-Windows coverage stated in the UI, not left as silence.

# Evidence required

- The packed-sample test, both YARA runs.
- A repaired PE opened in an independent tool.
- A config beside the pcap rows that corroborate it.
- The licence decision.

# Security considerations

- **This produces live malware as a download**, more directly than anything
  else in the project — an unpacked, repaired, runnable payload. The
  `infected` convention is load-bearing here, and #37's per-report public
  links make it more so.
- **Third-party parsers over attacker-controlled memory** is a large surface
  run on the credential-holding host. Isolate per parser; a corpus of
  community code is not a trust boundary.
- **A config is an assertion, not an observation.** A sample can plant
  plausible-looking configuration to mislead. Attribute every config to its
  parser and version, and corroborate against the pcap where possible.
- **Memory dumps contain whatever was in guest memory** — including anything
  the analysis itself put there. DRAFT-022's concern applies with more force
  here than to pcaps.
- **PE repair is heuristic.** A reconstructed binary presented as the original
  misleads a reader into conclusions about bytes that never existed.

# Documentation changes

- **New:** the pipeline, the corpus choice and its licence.
- **Updated:** `docs/architecture/result-schema.md` — `memory.json` and
  reconstructed payloads.
- **Updated:** DRAFT-022 with the corpus decision.

# Recovery / rollback

Stop the step. Dumps stay downloadable; the tab renders nothing collected.
