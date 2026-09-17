# DRAFT-052: Per-job plugin selection and trace budget

**Status:** **Completed 2026-09-17**, never published. Landed across `a99a11d`
("Enable plugin selection") and `15c4a20` ("Disable sysret and timeout now can
be selected"). The objective is met: a submitter chooses plugins, timeout and
`--disable-sysret` per job, and the selection reaches the DRAKVUF command line.
**Closed with two criteria unmet, both recorded rather than resolved**, so
nobody reads the close as meaning the acceptance list was ticked:

* **`sandboxd` does not re-validate the selection.** Criterion 1 asked for a
  closed per-OS set checked at the API **and** in the daemon; only the API half
  exists (`routers/jobs.py:509-521`). `stages._trace_options` applies
  `lease.plugins` verbatim and `guests.argv_trace` turns each element into
  `-a <name>`, so a name injected past the API would reach the command line.
  It arrives as argv and cannot become a separate argument, so this is not the
  injection path the Security section worried about — the live cost is a trace
  that completes with an observer silently missing, the same failure
  `parse_plugins_override` warns about for `SANDBOXD_PLUGINS`. **Not carried by
  any other draft.**
* **The `-S` syscall filter was not built at all.** Five criteria rest on it
  (filtering used, lists by subtraction, excluded set recorded and rendered,
  lists generated from the `-r` profile, Android measured three ways), as do
  the measured cost hints and the timed-out-plugin reporting. Every one needs
  DRAFT-050's idle baseline, which has not run. **Reassigned to DRAFT-050**;
  `guests.py:248` and `ideas.md:35` already point at it.

**Area:** core/platform
**OS:** ALL
**Milestone:** M5
**Priority:** P2
**Depends on:** **DRAFT-060 (`sandboxd`) — hard.** DRAFT-050 for the
catalogue's evidence. #38 renders it.
**Needs Dom0:** **Yes.**

# Objective

Let the submitter choose which DRAKVUF plugins run and what the trace budget
is, per job — and make that selection actually take effect.

# Context

## The control exists and does nothing

#38 already renders the picker: plugins for the chosen guest, marked proven or
candidate, behind an advanced disclosure, with the trace timeout and Android's
`--disable-sysret`. It carries a red notice saying — accurately — that the
selection is not sent, not stored and not honoured.

That was deliberate: shipping the control's *shape* lets the catalogue be
reviewed before anything depends on it. This issue makes it real.

## Why it cannot be retrofitted

The plugin list is hard-coded at `drakvuf-<os>.sh:181`, and `dirwatch` invokes
the script on a fixed argument contract with no room for a per-job list. The
options were: pass a variable through the existing `pipeline-<os>.env`
mechanism, or wait for `sandboxd`.

**Waiting was chosen (2026-08-25.)** The scripts are scheduled for retirement,
and adding a contract to code being replaced buys a few weeks of capability in
exchange for changing evidenced Ubuntu behaviour — which CLAUDE.md forbids
without explicit request, and which would then have to be re-evidenced twice.

## Why the trace budget belongs with it

Plugins cost time. `dirwatch` caps the trace at 180s and CLAUDE.md records
that Android needs `-F --disable-sysret` merely to finish — an APK installed
and launched correctly still could not finish drawing inside the window
without them. Enabling `ipt` or `apimon` on top of that is a way to guarantee
a timeout.

So selection without a budget is a trap: the operator ticks three boxes and
gets a trace that ends early, with no indication the choice caused it. The two
ship together or neither does.

`--disable-sysret` deserves surfacing on its own merits. CLAUDE.md: it "costs
syscall return values — an Android trace shows that a sample called
`openat`/`connect`/`execve` and with what arguments, but not whether it
succeeded". That is exactly a per-run decision, and it currently lives in an
env file nobody reads at submission time.

## A better lever than `--disable-sysret`, and it exists

`--disable-sysret` is a blunt instrument: it discards return values for
**every** syscall to escape a noise problem caused by a handful of them.
Android's flood is binder `ioctl()` and Looper `epoll_pwait`/`ppoll`, not
`openat` and `connect`.

The deployed build has the precise tool, confirmed from its own help:

```
-S, --syscall-hooks-list <syscalls filter>
    File with list of syscalls for trap in syscalls plugin
    (trap all if parameter is absent)
```

**"Trap all if parameter is absent" is what we do today**, on every run, on
every guest. Android's noise is not a property of Android; it is the result of
never having passed this flag.

Filtering is strictly better than `--disable-sysret`: keep return values for
the calls that carry meaning, never hook the ones that only generate volume.
CLAUDE.md's note that an Android trace "shows that a sample called
`openat`/`connect`/`execve` and with what arguments, but not whether it
succeeded" describes a cost we may not have to pay.

### Build the list by subtraction, not by curation

Start from the **complete** syscall set for the guest, then remove entries
with a recorded reason. The opposite — assembling an allowlist of "syscalls
malware uses" — decides in advance what is interesting, and everything
unlisted becomes invisible. A denylist is auditable: you can read exactly what
was dropped and why.

### The complete list comes from the profile we already pass

`profiles/linux.json` and `profiles/android.json` are `dwarf2json` output for
**one exact kernel build**, and `automation/drakvuf-ubuntu.sh:178` passes the
matching one as `-r` on every run. They carry the guest kernel's symbol table,
which is where the syscall entry points live — `__x64_sys_*` on modern x86-64
Linux, `Nt*` in a Windows profile. *(The exact prefix needs confirming against
a real profile; the kernel's age decides between `__x64_sys_` and plain
`sys_`.)*

**Generate the list from the profile rather than from a kernel source table**,
and the pinning problem disappears. An externally-sourced list has to be kept
matched to the guest kernel by discipline, and roadmap risk #12 records that
nothing in this project currently links a golden image to anything derived
from it. A list generated from the profile cannot drift from the kernel it
describes, because it shares a source with the symbol resolution DRAKVUF is
already doing — and it regenerates for free whenever the golden image is
rebuilt and its profile regenerated.

That also makes the filter a **build product of the profile**, not a
maintained artifact: same category as the profile itself, same lifecycle, and
`profiles/README.md`'s existing note about untracked host-generated build
products covers it unchanged.

### What gets removed

Only what a **measured idle baseline** shows to be volume without signal —
DRAFT-050 quantifies it. On Android that is expected to be binder `ioctl` and
the Looper polls; on Ubuntu the idle floor is low enough that the list may end
up empty, which is a perfectly good outcome and worth recording as one.

Each exclusion carries a reason, and the excluded set is **shown in the
report**. A filter is a place for behaviour to hide; the answer is not to
avoid filtering but to make what was not watched as visible as what was.

## Why the timeout is fixed at submission

Chosen at upload, and **not adjustable once the trace is running**. Not a UI
simplification — killing DRAKVUF mid-analysis risks inconsistent output, and
offering a "stop now" button would make that a routine action rather than a
timeout's last resort.

**This risk is live today and unexamined.** `dirwatch` already kills the trace
at 180s. Whether any plugin writes only at teardown — flushing a buffer, or
emitting a summary at exit — decides whether a timeout truncates the tail or
loses that plugin's entire output. `memdump` and `fileextractor` write as they
go; `procdump2`, `ipt` and `rootkitmon` are unknown.

**DRAFT-050 must answer it per plugin**, because it changes what a timed-out
job means. A trace that ended early having written everything up to that
moment is a partial result. One that ended early having written nothing for
three of five plugins is a misleading one, and the report has to say which.

# Dependencies

- **DRAFT-060** — the argv-based invocation this needs.
- **DRAFT-050** — turns catalogue standings from inferred to evidenced,
  replaces #38's reasoned "heavy" markers with measured cost, establishes the
  Android idle baseline any syscall filter must be built from, and answers
  whether any plugin writes only at teardown.
- **#38** — the picker.

# Out of scope

- **Per-user policy.** Who may select what is #40's question.
- **Automatic selection by sample type.** Tempting and premature: choosing
  plugins from `detected_type` means an attacker-influenced input steering
  what observes them.

# PLAN

1. Wait for DRAFT-060. Nothing here is buildable before it.
2. Contract and validation first, defaults unchanged, so existing callers are
   provably unaffected.
3. Syscall filter lists generated from the profiles (DRAFT-050's baseline).
4. Cost hints last, once DRAFT-050 has numbers to put in them.

# CREATE

## Contract

`POST /api/v1/jobs` gains an optional block:

```json
{ "plugins": ["syscalls", "procmon"],
  "timeout": 180,
  "disable_sysret": false,
  "syscall_filter": "android-default" }
```

`syscall_filter` names a **server-side list**, never uploaded content. The
file reaches a root DRAKVUF command line as `-S <path>`; letting a submitter
supply its contents would mean writing attacker-chosen data to a path Dom0
then reads as configuration. Named lists, closed set, same rule as everything
else here.

**Validated as a closed set, per target OS**, exactly as `target_os` is. A
plugin name becomes an element of `drakvuf -a <name>` on Dom0; issue #3's
rule — one untrusted routing input, checked against a closed set at one
boundary — applies unchanged. An unknown name is a 422 before any handler runs.

Absent means the per-OS defaults, so every existing caller is unaffected.

## Storage

`jobs.plugins text[]`, `jobs.trace_timeout int`, `jobs.disable_sysret bool`.
Recorded because a report must say what produced it: a trace with `procmon`
and one without are different observations of the same sample, and a reader
comparing two reports needs to know which they have.

## Enforcement

`sandboxd` builds `-a <plugin>` per selected plugin as argv elements. It
refuses names not in the catalogue for that OS — a second check, deliberately,
because the API and the daemon are separate trust domains and the daemon is
the one holding the command line.

## Cost hints

From DRAFT-050's measurements, not estimates. The form warns when a selection
looks likely to exceed the window; it never refuses. A timed-out trace is a
visible, recoverable outcome; a blocked submission is a guess overriding an
analyst.

# TEST

1. **A selected plugin reaches the DRAKVUF command line** and its output
   appears — `procmon` selected, process tree present.
2. **An unselected plugin's output is absent.**
3. **An unknown plugin name is a 422**, and separately, `sandboxd` refuses one
   injected past the API.
4. **A Windows-only plugin is refused for an Ubuntu job**, at both layers.
5. **Absent selection reproduces today's defaults exactly**, per OS.
6. **The selection is recorded and rendered** on the report.
7. **`disable_sysret=false` on Android produces return values** — and takes
   measurably longer, which is the trade being offered.
7b. **A filtered Android trace keeps return values and still finishes** —
   the trade `--disable-sysret` currently forces, avoided. Compare event
   counts and duration against an unfiltered run and against a
   `--disable-sysret` run.
7c. **The excluded syscall list appears in the report.** What was not watched
   is as visible as what was.
7a. **A timed-out trace states which plugins wrote nothing.** Force a timeout
   and assert the report distinguishes "ended early with partial output" from
   "ended early and this plugin produced none of its output".
8. **A hostile plugin name** — `syscalls; rm -rf /`, `--memdump-dir=/etc` —
   is refused, and cannot become a separate argument even if it were not.

# DEPLOY

Platform and Dom0 together — the API accepts the field and `sandboxd` honours
it, and shipping either alone gives a control that lies. Absent selection
reproduces today's defaults, so deployment changes nothing until someone
chooses.

# Acceptance criteria

- [ ] Selection validated against a closed per-OS set at the API **and** in
      `sandboxd`. — **API half only** (`routers/jobs.py:509-521`); the daemon
      applies what the lease carries. See Status.
- [x] Selection reaches the command line as argv elements.
      `guests.argv_trace` emits one `-a <name>` per selected plugin.
- [x] Recorded on the job and shown on the report. `jobs.plugins` (migration
      0010), rendered on the Overview tab.
- [x] Absent selection is byte-identical to today's behaviour.
      `stages._trace_options` reads an empty list as "the measured per-OS
      defaults", never as "no plugins".
- [x] Timeout and `disable_sysret` selectable at submission only; no mid-run
      adjustment is offered. **Without** the measured cost hints — those are
      DRAFT-050's numbers and the form ships with none.
- [ ] A timed-out job reports which plugins produced complete output and
      which did not. — **DRAFT-050.**
- [ ] Syscall filtering via `-S` is used, with lists built by subtraction
      from the complete per-guest set and every exclusion reasoned.
      — **DRAFT-050.**
- [ ] The excluded set is recorded on the job and rendered on the report.
      — **DRAFT-050.**
- [ ] Filter lists are GENERATED from the guest's own `-r` profile, so they
      cannot drift from the kernel they describe. — **DRAFT-050.**
- [ ] Android measured with filter, without, and with `--disable-sysret`,
      so the choice between them rests on numbers. — **DRAFT-050.**
- [x] #38's red "takes no effect" notice removed.

# Evidence required

- A run with `procmon` selected and one without, side by side.
- The two refusals, API and daemon.
- A default-selection run matching today's artifacts.
- An Android run with and without `--disable-sysret`, with timings.

# Security considerations

- **A plugin name becomes part of a root command line on Dom0.** This is the
  most direct untrusted-input-to-command path the project has. Closed set,
  checked twice, delivered as argv. DRAFT-060's `shell=False` rule is what
  makes the second layer meaningful.
- **Selection is a way to make analysis blind.** Someone could disable every
  plugin and produce a report showing nothing. Not a vulnerability while there
  is one operator; it becomes one under #40, and the report must always state
  what ran.
- **Raising the timeout raises the detonation window.** A sample runs longer,
  with network access, on a residential line — DRAFT-057's concern. The cap
  needs a ceiling the submitter cannot exceed.
- **Do not select plugins from `detected_type`.** It is derived from sample
  bytes; letting it choose the observers lets the observed choose them.

# Documentation changes

- **New:** the contract and the per-OS closed set.
- **Updated:** `catalogue.py`, `CLAUDE.md`'s hard-coded plugin note, and #38's
  notice.

# Recovery / rollback

Ignore the columns; `sandboxd` falls back to per-OS defaults. Recorded
selections stay as history.
