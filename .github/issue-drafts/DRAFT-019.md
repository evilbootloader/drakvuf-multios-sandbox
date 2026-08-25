# DRAFT-019: Integrate capa against DRAKVUF logs

**Status:** Drafted 2026-08-25. **Indexed since the first pass and never
written** — `issue-index.md` has carried this row from the beginning with no
file behind it. Not published.
**Area:** enrichment
**OS:** ALL, unevenly — see "What capa can actually see" below.
**Milestone:** M4
**Priority:** P2 → **raise to P1.** It is the only capability that turns a
syscall trace into something a person can read, and it needs no Dom0.
**Depends on:** DRAFT-018 (result schema). Pairs with **DRAFT-048** — both
fill the Static tab; capa also fills Overview's technique list.
**Needs Dom0:** **No** for the integration. **Yes** once `apimon` is wanted.

# Objective

Run capa over the DRAKVUF log a run already produces, and surface what it
finds: capabilities, and the ATT&CK and MBC techniques its rules carry.

# Context

## Why this one first

Every other capability track needs either a new plugin on Dom0 (DRAFT-050) or
new analysis machinery (DRAFT-049, DRAFT-051). This one consumes **a file we
already write on every single run** and have never once read.

`docs/architecture/result-schema.md` records `drakvuf.log` as "DRAKVUF's own
stdout/stderr". It is more than that: `automation/drakvuf-ubuntu.sh:179` runs
with `-o json`, so it is a JSONL event stream — the same shape DRAKVUF Sandbox
calls `drakmon.log`, which is exactly what capa's extractor consumes.

## What capa's DRAKVUF extractor actually is

Added in **capa v7.2.0**, written by @yelhamer for GSoC, and also shipped into
DRAKVUF Sandbox as a post-processing script. Verified against source
2026-08-25:

- `capa/features/extractors/drakvuf/extractor.py` takes an `Iterator[dict]`.
- `models.py` consumes **two plugins only**: `syscall` and `apimon`.
- Required syscall fields: `Plugin, TimeStamp, PID, PPID, TID, UserName,
  UserId, ProcessName, Method, EventUID, Module, vCPU, CR3, Syscall, NArgs`.
- `helpers.py:index_calls` **skips `call.pid == 0`**, with two reasons given —
  it is the system process, *and* "capa addresses not supporting null pids".
  The second is structural, not a heuristic.

## What capa can actually see, per guest

**`apimon` is Windows-only** (`drakvuf_plugin_os_support` in `plugins.h`). So:

| Guest | capa sees | Missing |
|---|---|---|
| Windows | syscalls + API calls + DLL load/discovery | — |
| Ubuntu | syscalls only | API calls, DLL events |
| Android | syscalls only | as above |

That is roughly half the feature surface on the two targets that are actually
evidenced. **This is worth saying up front rather than discovering after
integration**: capa's rule corpus is heavily Windows-oriented, and a Linux
run producing few matches is the expected result, not a broken integration.

## The defect this exposes

`automation/drakvuf-ubuntu.sh:184`:

```sh
    1>"$OUTPUTFOLDER/$MD5/drakvuf.log" 2>&1
```

**stderr is merged into the JSON stream.** capa parses an iterator of dicts;
interleaved diagnostic lines break it. The same line appears in
`drakvuf-android.sh`. Splitting them is a two-character change with a real
reason, and the sort of thing that otherwise surfaces months later as a
baffling capa failure nobody connects to a shell redirect.

## The PID-0 question, resolved

`ideas.md` carries: *"CAPA exclude also PID=0 for windows, find equivalent for
linux and android."*

- **Linux**: PID 0 is the swapper/idle task. The analogue is direct and capa's
  existing filter covers it.
- **Android**: **the equivalent is not a PID at all.** CLAUDE.md records that
  an idle BlissOS clone generates thousands of events before anything is
  analysed — every binder IPC is an `ioctl()` and every system service runs a
  Looper on `epoll_pwait`/`ppoll`. The noise is *system services*, not the idle
  task, and filtering it means filtering by process name or by ancestry from
  `zygote`, not by PID.

Getting this wrong is not merely noisy. capa scores rules against observed
behaviour; a corpus dominated by `zygote`'s own syscalls will match rules the
*sample* never exercised.

# Dependencies

- **DRAFT-018** — the result schema capa's output is written into.
- **DRAFT-050** — `apimon` on Windows, which doubles what capa sees there.
- **#38** — the Static tab and Overview's technique list render this.

# Out of scope

- **A verdict or score.** capa reports capabilities, not maliciousness, and
  #38's Overview is deliberately verdict-free. `T1059` observed is a fact;
  "malicious" is a judgement this project does not make.
- **Writing capa rules.** Use the upstream corpus.
- **capa's static backends** (PE/ELF analysis of the sample itself). That is
  DRAFT-048, which uses the same tool at a different input.
- **Fixing the `2>&1` in `automation/`** beyond flagging it — that is a
  pipeline change and CLAUDE.md forbids modifying Ubuntu behaviour without an
  explicit request.

# PLAN

1. Confirm the pinned fork's Linux `syscalls` plugin emits `UserName` and
   `UserId`. **Hard dependency, currently unverified.**
2. Separate stderr from the JSON stream.
3. Run capa over a real Ubuntu log; record how many rules match.
4. Decide the Android exclusion from a measured baseline, not a guess.
5. Store `capa.json` per job; render it.

# CREATE

## Where it runs

**On the platform, not on Dom0.** capa reads the log after the run; nothing
about it needs the analysis host, and Dom0 holds no credentials to store
results with. It becomes a step in the same post-processing that #37's
retention and #38's rendering already assume.

## Input

`results/<job_id>/drakvuf.log`, already in the object store. Streamed, not
loaded whole — an Android trace can be hundreds of megabytes and this runs on
the machine holding every credential on the platform.

## Output

`results/<job_id>/capa.json`, listed in the manifest. Plus a summary on the
job row for Overview: matched rule names and the ATT&CK/MBC identifiers their
metadata carries.

**ATT&CK mapping comes free with this.** capa rules carry `att&ck:` and `mbc:`
fields; nothing else in the project needs building to populate a technique
list, which is why this track fills two tabs rather than one.

## The Android exclusion

Not designed in advance. Run capa against an Android trace **unfiltered**,
count matches, then filter and count again. If the difference is small the
exclusion is not worth its risk of dropping real behaviour; if it is large,
the baseline says what to exclude. A filter written from first principles
would be a guess with a number attached.

# TEST

1. **A trace with no `UserName` field fails loudly**, naming the field — the
   dependency is real and its absence must not look like "capa found nothing".
2. **Interleaved stderr does not silently truncate the analysis.** Feed a log
   with diagnostic lines mixed in; assert either clean handling or a clear
   error, never a partial parse reported as a complete one.
3. **PID 0 events are excluded**, and an Ubuntu trace still matches rules.
4. **Android, both ways** — unfiltered and filtered match counts recorded, so
   the exclusion decision rests on a measurement.
5. **A Windows trace with `apimon` matches strictly more than without it**,
   confirming the plugin is worth its cost there.
6. **capa's output round-trips into the manifest** and renders in #38's Static
   tab and Overview technique list.
7. **A malformed log produces a job-level failure**, not a silent empty
   result. "No capabilities found" and "capa could not read this" are
   different answers.

# DEPLOY

A post-processing step on the platform container, run after `complete`.
Rollback is not running it: `capa.json` is additive, and its absence renders
as an empty Static tab rather than a broken job.

# Acceptance criteria

- [ ] capa runs against a real Ubuntu `drakvuf.log` and its matches are
      recorded.
- [ ] `UserName`/`UserId` emission by the fork's Linux syscalls plugin is
      **verified**, not assumed.
- [ ] stderr and the JSON stream are separated, or capa handles the mix
      provably.
- [ ] PID 0 excluded on Linux; the Android exclusion decided **from a measured
      baseline** and its numbers recorded.
- [ ] ATT&CK and MBC identifiers reach the Overview tab.
- [ ] Failure to parse is a loud job failure, never an empty result.
- [ ] No verdict, no score.
- [ ] No `automation/` behaviour change in this issue.

# Evidence required

- capa version and the exact command.
- Match counts for an Ubuntu trace, an Android trace filtered and unfiltered,
  and a Windows trace with and without `apimon`.
- The `UserName` verification, as raw log lines.
- A rendered Static tab and Overview technique list.

# Security considerations

- **capa parses attacker-influenced input** on the platform container, which
  holds the database and object-store credentials. The log's *content* is
  derived from what the sample did — process names, file paths, arguments —
  and a parser bug there is a bug in the highest-value component. Run it with
  the same care as libmagic: bounded input, no shell, no network.
- **A crafted trace could shape capa's output.** A sample that generates
  syscall patterns matching benign rules makes the report say so. capa
  describes observed behaviour; it is not an adversary-resistant classifier,
  and the UI must not present its matches as a verdict.
- **The exclusion filter is a place to hide.** Anything excluded from capa's
  view is behaviour the report will not mention. If Android filtering ends up
  keyed on process name, a sample that names itself `zygote` disappears —
  which is an argument for filtering on ancestry rather than on a string the
  sample controls.

# Documentation changes

- **New:** how capa is invoked, what it sees per guest, and the Android
  exclusion with its measurements.
- **Updated:** `docs/architecture/result-schema.md` — `capa.json` joins the
  artifact set, and `drakvuf.log` is described as a JSONL event stream rather
  than "stdout/stderr".
- **Updated:** `ideas.md`'s PID-0 line, resolved.
- **Updated:** `issue-index.md` — this row finally has a file.

# Recovery / rollback

Stop running the step. Existing `capa.json` objects stay valid; the tab shows
nothing collected, which is the same state every other unfilled tab is in.
