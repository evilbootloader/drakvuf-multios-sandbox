# DRAFT-030: Stop passing untrusted sample filenames through shell-parsed command lines

**Status:** **[#31](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/31) — published and closed 2026-08-19.** Drafted, not published
**Area:** core (shared orchestrator — affects Ubuntu, Android, Windows)
**Milestone:** M1
**Priority:** P1
**Depends on:** None open. Should land **before** DRAFT-014 (sample OS
auto-detection), which widens the range of filenames the orchestrator has
to handle.
**Origin:** `project-assessment.md` → Findings → DRAKVUF-03 (with
DRAKVUF-02)

# Objective

Make `automation/dirwatch.c` handle adversary-chosen sample filenames
safely, by removing them from string-formatted command lines that are
subsequently re-parsed with shell quoting rules.

> **Scope added 2026-08-10 by issue #6, at the maintainer's direction.**
> This draft now also owns the **guest-side** half of filename handling,
> because it is the same input travelling one hop further and splitting it
> across two issues would mean two normalizers.
>
> Issue #6 decided the contract and does not implement it: the sample is
> staged at `<GUEST_STAGING_DIR>/<guest_filename>`, where `guest_filename`
> is the *normalized submitted name*, not the SHA-256 Ubuntu writes today
> (`preconfig-ubuntu.sh:162`, `drakvuf-ubuntu.sh:150`). Three things follow,
> all of them this issue's:
>
> 1. **Write the normalizer.** None exists anywhere in the repository. Rules
>    are specified in `docs/architecture/analysis-pipeline.md`, "Filenames:
>    two namespaces": path separators and NUL stripped, length capped,
>    Windows reserved names (`CON`, `PRN`, trailing dot or space) rejected.
>    It must be reusable by all three pipelines — one implementation, not
>    one per OS.
> 2. **Retrofit Ubuntu's staging and execution paths** to the normalized
>    name, keeping the existing invariant that `preconfig-*` and `drakvuf-*`
>    derive the guest path by the same rule from the same arguments (the
>    drift issue #2 found). **This changes Ubuntu runtime behaviour** and is
>    the first such change since issue #4 — it needs its own benign
>    end-to-end run, not just static checks.
> 3. **Preserve the argv invariant across the hop.** The name may reach the
>    guest only as a single argv element. `injector -m writefile -e` and
>    `drakvuf -e` both satisfy this today, the latter established as
>    execve-direct by issue #2. Android's install path is *not* `execve`, so
>    that finding does not carry over unexamined — re-establish it per OS
>    rather than inheriting it.
>
> Why the guest gets the real name at all, since it is the obvious thing to
> question: extension-driven handler dispatch, `argv[0]` self-checks and APK
> filename assumptions are real evasion behaviour, and a sample renamed to a
> hash exercises none of them. This was demonstrated accidentally on the
> Android guest on 2026-08-10 — a `toybox` binary copied to `probe` reported
> `Unknown command`, because toybox dispatches on `argv[0]`
> (`docs/checklists/android.md`, "Staging directory — execution evidence").
>
> `guest_filename` and `original_filename` are stored as separate fields so
> a reader can see when the two differ; **emitting** them is DRAFT-011's.

# Context

`dirwatch` is the shared orchestrator — it takes the domain, config and
profile as arguments (`dirwatch.c:475-477`) and is used by every OS
pipeline. It is also the first component to touch an untrusted filename:
`ent->d_name`, read straight from `/malware_incoming`.

That filename is then interpolated into command *strings* which are run
through `g_spawn_command_line_sync()`. Five sites:

| Line | Template | Filename source |
|---|---|---|
| `dirwatch.c:567` | `"mv %s/%s %s/%s"` | `ent->d_name` |
| `dirwatch.c:122,176` | `CLONE_CMD` | — (domain/config) |
| `dirwatch.c:124,276` | `CONFIG_CMD` | `start->input` |
| `dirwatch.c:123,296` | `DRAKVUF_CMD` | `start->input` |
| `dirwatch.c:126,186` | `TCPDUMP_CMD` | `start->input` |

`g_spawn_command_line_sync()` does not spawn a shell, so this is not
classic command injection — but it does apply `g_shell_parse_argv()`,
which implements shell-style word splitting and quote handling. The
practical failure modes:

- **A filename containing a space** splits into two arguments. For the
  `mv` at `:567` that means moving the wrong path, or a partial move; for
  `CONFIG_CMD`/`DRAKVUF_CMD` it shifts every subsequent positional
  argument, so `preconfig-ubuntu.sh` receives `$RUNFILE` and
  `$OUTPUTFOLDER` misaligned.
- **A filename containing an unbalanced quote** fails to parse; the spawn
  fails and, at `:567`, the code correctly detects the failed move and
  discards the clone — but the sample stays in `/malware_incoming` and is
  retried on the next scan, indefinitely.
- **A filename beginning with `-`** is passed as an option to `mv`.

The downstream scripts then compound it: every worker script recomputes
the digest with an unquoted expansion — `md5sum $RUNFOLDER/$RUNFILE`
(`preconfig-ubuntu.sh:118`, `drakvuf-ubuntu.sh:118`, `tcpdump.sh:115`) —
so a split filename produces a wrong or empty `MD5`, and therefore a wrong
result directory.

**Related, and already project policy for Android only.**
`docs/checklists/android.md:1008` states "Never include the untrusted
filename directly in a guest shell command", and `:1052` notes "A fixed
guest destination derived only from SHA-256 is safer than using the
uploaded filename." `preconfig-ubuntu.sh:122` does exactly what that rule
forbids, on the Ubuntu path — that half is resolved by DRAFT-027, which
replaces HTTP delivery with a hash-derived destination. This issue covers
the remaining Dom0-side half, in the shared orchestrator.

**Why before DRAFT-014.** Today `dirwatch` handles whatever lands in one
watch folder for one OS. Once auto-detection routes by file type, the
orchestrator is expected to cope with a much wider variety of dropped
files — including archive and APK names that routinely contain spaces.
Fixing the input handling first means the routing work does not inherit a
fragile foundation.

# Dependencies

- None open.
- **Blocks DRAFT-014** (recommended ordering, not a hard technical block).
- Overlaps DRAFT-027 at the guest-side boundary: DRAFT-027 removes the
  filename from the *guest* command; this issue removes it from the *Dom0*
  command lines. Neither supersedes the other.
- Touches the same file as DRAFT-010 (document `dirwatch.c`'s interface).
  DRAFT-010 should land first if it is close, so the documented contract
  reflects the fixed behaviour.

# Out of scope

- Changing `dirwatch`'s 15-argument CLI contract. Issue #4 already
  commits to changing only the *values* passed, not the contract, and
  three worker scripts depend on the current positional order.
- Rewriting `dirwatch.c` in another language. That is an open architecture
  decision (`docs/roadmap/project-roadmap.md`, decisions #1) and
  explicitly gated on DRAFT-010 documenting the current interface first.
- The guest-side filename handling in `preconfig-ubuntu.sh:122` — owned by
  DRAFT-027.
- Renaming samples on arrival as a *product* decision (e.g. normalizing
  everything to its SHA-256). That is a plausible fix and is offered in
  PLAN step 2, but it changes what operators see in `/malware_processing`,
  so it needs its own decision rather than being smuggled in.
- The unquoted `$RUNFOLDER/$RUNFILE` expansions inside the worker scripts.
  Those are real (SC2086 at `preconfig-ubuntu.sh:118`,
  `drakvuf-ubuntu.sh:118`, `tcpdump.sh:115`) but belong to DRAFT-031's
  shellcheck cleanup and DRAFT-011's retrofit, and fixing them without
  fixing this issue would not help.

# PLAN

1. Confirm the exact parsing behaviour of `g_spawn_command_line_sync()` in
   the GLib version installed on Dom0, from its own documentation/source —
   do not rely on this issue's description. The distinction that matters:
   it uses `g_shell_parse_argv()` but does **not** invoke `/bin/sh`.
2. Decide the mechanism. Two viable options, in preference order:
   - **(a) Replace the command-line form with argv-vector spawning.**
     `g_spawn_sync()` takes a `gchar **argv` directly, with no parsing
     step, which removes the entire class. This is the smallest correct
     change for the four `%s`-template call sites.
   - **(b) Replace the `mv` subprocess at `:567` with `rename(2)`/
     `g_rename()`.** Moving a file does not need a subprocess at all, and
     `/malware_incoming` and `/malware_processing` are documented as
     top-level sibling directories, so a rename is expected to work
     without a cross-filesystem copy — confirm that on Dom0 rather than
     assuming it.
3. Decide whether to additionally reject or normalize hostile filenames at
   the watch-folder boundary (leading `-`, path separators, control
   characters, excessive length). Recommendation: reject with a logged
   reason rather than silently normalize, so an operator can see why a
   sample was not processed.
4. Confirm the retry loop's behaviour for a rejected sample. Currently a
   failed move leaves the file in place and it is rescanned every cycle
   (`dirwatch.c:573-589`). A permanently unprocessable filename would spin
   forever; decide whether it is moved aside or logged once.
5. Confirm how the sample's identity reaches the worker scripts after the
   change, since they each recompute the digest from `$RUNFOLDER/$RUNFILE`.

# CREATE

1. Convert the five call sites from formatted command strings to argv
   vectors (PLAN step 2a), or replace the `mv` with a direct rename (2b)
   plus argv vectors for the remaining four.
2. Add the filename admission check from PLAN step 3, with a clear log
   line naming the sample and the reason.
3. Handle the rejected-sample loop per PLAN step 4.
4. Update `docs/architecture/analysis-pipeline.md`'s description of the
   per-sample flow to match.

# TEST

`dirwatch.c` cannot be compiled in the development container — it
`#include`s `<config.h>` and `../xen_helper/xen_helper.h`
(`dirwatch.c:118,120`) and only builds inside a DRAKVUF source tree
(`docs/workflow-ci.md:150-155` records the same constraint). Static review
and a standalone harness are what is available locally:

```bash
# Local: extract the argument-construction logic into a small harness and
# assert the resulting argv for hostile inputs, without Xen:
#   "sample with spaces.exe"
#   "sample'quote.apk"
#   "-rf"
#   "a"*300
#   A/../etc
#   A/B
```

Requires Xen Dom0 — present for manual execution:

```bash
# Build inside the DRAKVUF tree per the documented procedure:
cp automation/dirwatch.c ~/drakvuf/src/dirwatch/
cd ~/drakvuf && ./autogen.sh && ./configure && make -j"$(nproc)"

# Then, with benign fixtures only, drop files named:
#   "benign sample.bin"        -> expect: processed correctly, one result dir
#   "benign'sample.bin"        -> expect: processed or cleanly rejected+logged
#   "-benign.bin"              -> expect: processed or cleanly rejected+logged
# and confirm for each:
#   - exactly one result directory is created, keyed by the correct digest
#   - the sample lands in /malware_processing intact
#   - no clone is leaked (xl list clean afterwards)
#   - the file does not spin in an infinite rescan loop
```

# DEPLOY

Requires manual Dom0 coordination — present, do not execute:

1. `dirwatch` is a compiled binary installed by `make install`; deploying
   means rebuilding DRAKVUF from the tree with the updated source, per
   `docs/drakvuf-on-xen-nested-within-proxmox.md:531,588-596`.
2. Keep the previously installed `dirwatch` binary until the new one has
   processed benign fixtures successfully.
3. Deploy in a no-analysis window; `dirwatch` is the long-running daemon.
4. Rollback: reinstall the previous binary and restart the launcher.

# Acceptance criteria

- [ ] `g_spawn_command_line_sync()`'s parsing behaviour is confirmed from
      GLib's own documentation/source and recorded, not assumed.
- [ ] No untrusted filename is interpolated into a string that is
      subsequently parsed with shell quoting rules.
- [ ] A sample named `benign sample.bin` is processed end-to-end and
      produces exactly one correctly-keyed result directory.
- [ ] A sample with a quote or leading `-` in its name is either processed
      correctly or rejected with a logged reason — never silently
      mishandled and never retried indefinitely.
- [ ] No clone or LV is leaked by any of the hostile-filename cases
      (`xl list` and `lvs` clean afterwards).
- [ ] `docs/architecture/analysis-pipeline.md` describes the corrected
      flow.
- [ ] The fix lives in the shared orchestrator, so it covers the Android
      and Windows pipelines on arrival with no per-OS work.

# Evidence required

- The GLib behaviour citation from PLAN step 1.
- Diff of `dirwatch.c`.
- Local harness output for the hostile-input cases.
- Dom0 transcript of the three benign-fixture drops, with the resulting
  `/malware_finished` listing, `xl list` and `lvs` output.

# Security considerations

- Sample filenames are attacker-controlled input in a malware-analysis
  pipeline. Treating them as trusted format-string arguments is the
  wrong default even where no shell is spawned.
- The realistic impact today is misprocessing and a stuck queue rather
  than Dom0 code execution, because `g_spawn_command_line_sync()` does not
  invoke `/bin/sh`. That should not be relied on as the control — a future
  change to `system()` or a shell-mediated spawn would silently turn this
  into command injection on Dom0 as root.
- Filename admission checks must **log and reject**, never silently
  rename, so that a sample deliberately named to evade processing is
  visible rather than quietly skipped.
- Use benign fixtures only. Do not create test files with hostile names
  inside `/malware_incoming` on a host that is concurrently running real
  analyses.

# Documentation changes

`docs/architecture/analysis-pipeline.md` (per-sample flow and the input
admission rules), `docs/checklists/ubuntu.md` (evidence),
`docs/checklists/android.md` §6.1's anti-pattern list (annotate that the
"no unquoted sample path expansions" gate now has a Dom0-side counterpart
tracked here).

# Recovery / rollback

Previous `dirwatch` binary retained and reinstallable; source reverts from
git. No LVM, network or guest state is modified by this change.