# DRAFT-048: Static analysis of the submitted sample

**Status:** Drafted 2026-08-25. Not published.
**Area:** enrichment
**OS:** ALL — and this is the only capability that works **equally** on all
three, because it reads the submitted bytes rather than a trace.
**Milestone:** M4
**Priority:** P1
**Depends on:** #37 (the object the sample lives in). Pairs with **DRAFT-019**
— both fill #38's Static tab.
**Needs Dom0:** **No.** Never. That is most of the point.

# Objective

Describe the sample without running it: format, structure, strings, and what
YARA makes of it.

# Context

## Why this is the capability that does not depend on the guest

Every dynamic capability is bounded by what DRAKVUF can see on that guest, and
`plugins.h` makes that wildly uneven — 26 of 45 plugins are Windows-only.
Static analysis has no such asymmetry. A PE is a PE whether or not a Windows
guest exists; an APK can be unpacked without an Android clone.

That matters more than it sounds. **Windows has no execution evidence in this
project at all**, so today a Windows submission produces nothing. With this,
it produces a real report before the Windows pipeline exists.

## What the comparison document is pointing at

`Malware Sandbox Capability Comparison — 2026.md` marks DRAKVUF as
"❌/external" for static analysis — the only ❌ in its row. It is accurate:
DRAKVUF is a VMI tracer and has no opinion about file formats. Every other
sandbox in that table pairs dynamic analysis with static, and this is the gap.

## What already exists that this should not duplicate

Admission (#36) already runs libmagic over the first 8 KiB and records
`detected_type`. That is a *routing* check — it exists to reject a PE sent to
an Ubuntu guest — and it is deliberately shallow. This is the deep pass, run
after admission, on the whole object.

`magic_bytes` is capped at 8192 precisely because admission runs in the
credential-holding process on a synchronous path. This runs afterwards, out of
band, and can afford the whole file.

# Dependencies

- **#37** — the sample object and its presigned read.
- **DRAFT-019** — capa. Same tab, and capa's *static* backends could analyse
  the sample here too; keep the two invocations distinct so a failure is
  attributable.

# Out of scope

- **Unpacking and config extraction.** DRAFT-051. Extracting a packed
  payload's configuration is a different job from describing the container.
- **A verdict.** #38 is verdict-free by decision.
- **Writing YARA rules.** Use a curated public set; authoring is its own work.
- **Deobfuscation of scripts.** Real, and separate.

# PLAN

1. Settle the rule corpus and its licence before writing code — see Security.
2. Per-format parsers behind one interface.
3. Strings with enough structure to be useful, not a `strings` dump.
4. Render into #38's Static tab.

# CREATE

## Per format, and honest about which we can do well

| Format | Extract |
|---|---|
| **PE** | Sections, entropy per section, imports, exports, resources, overlay, timestamps, signature presence and validity, packer indicators |
| **ELF** | Sections, segments, symbols, `DT_NEEDED`, static-vs-dynamic, stripped-or-not, entropy |
| **APK** | Manifest, permissions, activities/services/receivers, `minSdk`/`targetSdk`, signing certificate, embedded native libraries per ABI, DEX count |
| **Archives** | Listing, nesting depth, compression ratios, password protection |
| **Everything else** | libmagic's full output, size, entropy, hashes |

**APK is where this pays most.** Android is evidenced end to end but the APK
*launch* path is untested code (CLAUDE.md), so today an APK submission is the
least informative of the three. Its manifest is where the interesting claims
live — permissions requested, components exported — and none of it needs the
guest.

## Strings — FLOSS, not `strings`

**FLOSS** (FLARE Obfuscated String Solver) rather than a flat dump, and the
difference is not cosmetic. `strings` finds what is stored in the clear;
malware that matters usually does not store it in the clear. FLOSS combines
three passes:

- **Static strings** — what `strings` finds, ASCII and UTF-16LE. Windows
  malware keeps most of its interesting strings in the latter, and an
  ASCII-only pass silently misses them.
- **Stack strings and tight strings** — built character by character at
  runtime specifically so a static scan finds nothing.
- **Decoded strings** — recovered by *emulating* the functions FLOSS
  identifies as string decoders. This is where a C2 domain that exists nowhere
  in the file on disk comes from.

Supported formats are **PE, ELF and .NET** — stack and decoded extraction work
on PE and ELF both, so this is one of the few capabilities that serves Ubuntu
as well as Windows. Shellcode is supported explicitly with `--format sc32|sc64`.

**DEX is not supported**, so APK keeps its own path: string-pool extraction
from the DEX, plus whatever the native `.so` libraries yield through the ELF
path above. Worth stating rather than discovering — an APK submission will
have a thinner Strings section than a PE, and that is a property of the tool.

Whatever the source, classify rather than dump: URLs, IP literals, domains,
registry paths, file paths, base64 runs, high-entropy blocks. A wall of
strings is not analysis.

## Hashes

SHA-256 exists from admission. Add **imphash** and **ssdeep**/TLSH: they answer
"have we seen something *like* this" where SHA-256 answers only "have we seen
exactly this". Given #38 already lists every analysis of one digest, fuzzy
hashing is the natural next question and cheap to record now.

## Entropy

Per section and overall. Not a verdict — a packed binary and an encrypted
resource look the same, and plenty of legitimate installers are high-entropy.
Report the number, and let the Static tab show it beside the section table
where it means something.

# TEST

1. **A real PE, ELF and APK each parse** and their fields match what an
   independent tool reports.
2. **A truncated file does not crash the parser** — it produces a partial
   result marked partial. Samples are frequently damaged.
3. **A zip bomb does not exhaust the container.** Nesting depth and expansion
   ratio are bounded, and exceeding either is a recorded refusal.
4. **A malformed PE with a hostile section table** (overlapping, negative
   sizes, absurd counts) is refused rather than trusted. These are handed to
   parsers deliberately.
5. **UTF-16LE strings are found**, proven with a sample whose only URL is
   UTF-16.
5a. **A stack-built string is recovered**, proven with a sample that assembles
   a domain character by character and stores it nowhere. This is what
   separates FLOSS from `strings`, so it is what the test has to show.
5b. **FLOSS is bounded.** A sample crafted to make emulation run long is cut
   off at the wall clock, the partial result is marked partial, and the job
   still completes.
6. **Entropy is reported, never interpreted** — no "packed: yes".
7. **YARA matches render**, and a rule error is a loud failure rather than
   silently zero matches.
8. **A Windows sample produces a full Static tab** with no Windows pipeline
   in existence.

# DEPLOY

A post-processing step alongside DRAFT-019's. Output `results/<job_id>/static.json`.

> **Wrapped in the DRAFT-018 envelope (added 2026-08-26).** This draft
> specified a bare `*.json`; it is now `sandbox.static/1` inside the shared envelope —
> `schema`, `job_id`, `produced_at`, `producer` (with `ruleset_version`),
> `status`, `status_reason`, `data`. The payload this draft describes goes in
> `data` and is unchanged. **`status` is not optional decoration:** a run that
> hit its timeout part-way through produces real findings that read exactly
> like a clean sample, and this is the field that tells them apart. See
> `docs/architecture/result-schema.md` §4.3 and
> `sandbox_platform/manifest.py`.

# Acceptance criteria

- [ ] PE, ELF and APK each produce structured output, verified against an
      independent tool.
- [ ] Strings come from FLOSS — static, stack and decoded — and are
      classified. UTF-16LE covered; a stack-built string demonstrably
      recovered.
- [ ] FLOSS emulation is time- and memory-bounded, in its own process,
      and a timeout yields a partial result rather than a failed job.
- [ ] Fuzzy hashes recorded alongside SHA-256.
- [ ] Every parser is bounded in time and memory, and a hostile input is a
      recorded refusal rather than a crash.
- [ ] Entropy reported without interpretation.
- [ ] YARA runs against a corpus whose licence is recorded.
- [ ] A Windows submission produces a real report.
- [ ] No verdict, no score.

# Evidence required

- Parser output for one real PE, ELF and APK, beside an independent tool's.
- The zip-bomb and malformed-PE refusals, as transcripts.
- A rendered Static tab for all three OS targets.
- The YARA corpus, its version and its licence.

# Security considerations

- **FLOSS emulates the sample's own code**, which is the sharpest item here.
  Its decoded-string pass runs attacker-authored instructions through
  vivisect's emulator on the container that holds the database and
  object-store credentials. It is emulation rather than native execution, so
  the sample is not running on the host — but an emulator is a large parser
  with a program counter, and hostile input can drive it into pathological
  paths. Hard wall-clock and memory limits, in a separate process, are the
  minimum; `--only static` is the fallback if emulation proves unsafe or too
  slow, at the cost of exactly the strings worth having.
- **This is the largest parser surface the project will have**, and it runs on
  the container holding every credential. PE, ELF, DEX, ZIP and archive
  parsers are historically rich in memory-safety bugs, and the input is chosen
  by an adversary. Bound CPU and memory per sample; consider a separate
  process so a parser crash cannot take the API with it.
- **A zip bomb is the cheapest attack here**, and it costs the attacker
  nothing — a 42 KB file that expands to petabytes. Depth and ratio limits are
  not optional.
- **YARA rules are executable input.** A rule corpus is code that runs against
  attacker-controlled data; pin its version, record its provenance, and treat
  updating it as a change worth reviewing rather than a refresh.
- **Licensing.** DRAFT-022 owns this. Public YARA corpora carry varied
  licences and some restrict commercial use; the choice must be recorded
  before rules ship, not after.
- **Fuzzy hashes are a disclosure surface.** ssdeep/TLSH of a sample can be
  compared against a corpus the operator does not control. Harmless for public
  malware, less so for anything submitted in confidence — relevant once #40's
  per-user isolation means submissions belong to someone.

# Documentation changes

- **New:** the format matrix, the bounds, and the YARA corpus provenance.
- **Updated:** `docs/architecture/result-schema.md` — `static.json`.
- **Updated:** `docs/checklists/windows.md` — a Windows submission produces a
  report before the pipeline exists, which changes what "no execution
  evidence" means for a reader.

# Recovery / rollback

Stop running the step. `static.json` is additive and its absence renders as an
empty tab.
