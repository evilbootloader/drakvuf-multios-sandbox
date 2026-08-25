# DRAFT-050: Audit all 45 DRAKVUF plugins and evidence the ones that earn it

**Status:** Drafted 2026-08-25. Not published.
**Area:** core
**OS:** ALL, and the answer differs sharply per guest.
**Milestone:** M4
**Priority:** **P0** for the audit itself — three documents were wrong about
this and other work is being planned on top.
**Depends on:** nothing. **Blocks:** DRAFT-052, DRAFT-055, and the Behaviour
tab in #38.
**Needs Dom0:** **Yes**, for the evidence half. The audit half is desk work.

# Objective

Establish, for each of DRAKVUF's 45 plugins: what it collects, which of our
three guests it supports, and whether it earns a place in the pipeline.

# Context

## Why this is P0 rather than housekeeping

We enable four plugins. The build ships 45. Nobody had written down which of
the other 41 could even run on our guests — and when that was finally read
from `src/plugins/plugins.h` on 2026-08-24, **three project documents turned
out to be wrong**:

- `docs/workflow-ci.md` named `apimon`, `procdump`, `regmon`, `socketmon` and
  `rootkitmon` as Linux-applicable. All five are Windows-only. Following that
  list would have meant enabling plugins against Ubuntu that cannot run there.
- `docs/roadmap/project-roadmap.md` risk #8 treated the `lfreijo` fork as
  carrying Linux plugin support wholesale. It carries **two plugins**.
- `docs/architecture/upstream-drakvuf.md` listed the inventory with no OS
  split, which is what allowed the first error.

All three are now annotated. This issue is the systematic pass that stops it
recurring, and the evidence that turns "permitted" into "works here".

## The distinction the matrix does not make

`drakvuf_plugin_os_support[plugin][os]` says DRAKVUF **permits** a plugin for
an OS family. It says nothing about whether it produces useful output against
*our* guests, and the gap is not academic:

- **Ubuntu and Android share only a kernel.** Android's userspace is Bionic,
  ART and binder. A plugin walking `task_struct` may work against Ubuntu and
  fail against BlissOS, or produce output so dominated by binder `ioctl`s that
  it is useless.
- **Windows has no execution evidence at all** in this project. Every Windows
  row starts as a candidate.
- The matrix was read from the **branch tip**, not our pinned
  `52df0bc8044d3033af3259312787560dbb8caa12`.

`docs/checklists/android.md` §0.4 already has the validation-matrix pattern.
This applies it to all 45, against all three.

## What the audit already suggests is worth having

From the matrix, Linux-capable and unused: `procmon`, `procdump2`,
`cpuidmon`, `debugmon`, `ipt`, `hidsim`, `ptracemon`, `ebpfmon`,
`unixsocketmon`, `rebootmon`.

- **`procmon`** is the process tree — the structure every behavioural view
  hangs off, and the single biggest gap in the Behaviour tab.
- **`cpuidmon`** records the sample's own hypervisor checks. That is
  *anti-evasion telemetry*: it turns "the sample did nothing" into "the sample
  looked for a hypervisor, found one, and left" — which is the difference
  between a useless run and a finding. Directly serves `ideas.md`'s "make VMs
  more user computer like".
- **`ptracemon`** catches anti-debugging; **`ebpfmon`** catches eBPF rootkits.

Windows-only and worth the Windows track: `apimon` (which also doubles what
capa sees — DRAFT-019), `regmon`, `socketmon`, `tlsmon` (the project's only
TLS-visibility route), `rootkitmon`.

# Dependencies

None to start. Feeds DRAFT-052, DRAFT-055, DRAFT-019 and #38.

# Out of scope

- **Enabling anything in the pipeline.** This decides and evidences; DRAFT-052
  makes selection per-job. A plugin proven here can be added to the defaults
  as a separate, small change.
- **Writing Linux support for a Windows-only plugin.** Real work, and a
  different issue — with the fork's bus-factor attached.
- **Rendering.** #38 and its capability drafts.

# PLAN

1. Confirm the matrix against the **pinned** commit, not the branch tip.
2. Table all 45: what it collects, per-guest support, verdict.
3. Run each plausible candidate against each guest it claims to support.
4. Record output volume and run-time cost, because both bound DRAFT-052.

# CREATE

## The table

One row per plugin: name, what it collects in one line, Windows / Ubuntu /
Android support from `plugins.h`, verdict (**want** / **no** / **later**),
and reason. A verdict of "no" needs a reason as much as "want" does —
`bsodmon` on Linux is obvious, `spraymon` is not.

## The validation matrix

For each plugin with a **want** verdict, per guest:

| | Starts | Produces output | Output is about the SAMPLE | Cost |
|---|---|---|---|---|

The third column is the one that matters and the easiest to skip. A plugin
that starts cleanly and emits thousands of events about system services has
not been validated — it has been observed running. Android is where this
bites: CLAUDE.md records an idle BlissOS clone generating thousands of events
before anything is analysed.

## The syscall lists

The build supports `-S, --syscall-hooks-list <syscalls filter>` — "trap all if
parameter is absent", which is what every run does today. This audit produces
the per-guest complete syscall lists that filtering needs (DRAFT-052), because
it is already reading each plugin's options and running against each guest.

The complete list is **generated from the guest's own profile** —
`profiles/linux.json` and `profiles/android.json` are `dwarf2json` output for
one exact kernel build and are already passed as `-r` on every run, so their
symbol table is where the syscall entry points are. Deriving the list from the
same file DRAKVUF uses to resolve syscalls means it cannot describe a
different kernel than the one in the clone.

Then the measured idle baseline says what is safe to subtract. Confirm the
symbol prefix against a real profile rather than assuming: `__x64_sys_` on a
modern x86-64 kernel, plain `sys_` on an older one, `Nt*` for Windows.

## Cost, measured not guessed

Each plugin's effect on trace duration and output size, per guest. DRAFT-052
renders a cost hint on the submit form and #38 currently marks `ipt` and
`apimon` heavy **on reasoning, not measurement**. This is where that becomes
a number — including whether any combination cannot finish inside the trace
window.

# TEST

1. **The matrix matches the pinned commit.** If it differs from the branch
   tip, the pinned one governs and the difference is recorded.
2. **Every want-verdict plugin starts** against each guest it claims.
3. **Output is attributable to the sample**, shown by running each plugin
   against an idle clone and against one running a known sample, and diffing.
4. **`cpuidmon` sees a deliberate CPUID probe** — a fixture that queries the
   hypervisor bit and exits.
5. **`procmon` produces a tree** with a known parent/child shape.
6. **Cost is recorded** per plugin per guest, and any combination that cannot
   finish in 180s is named.
7. **Android's noise floor is quantified** — events on an idle clone over the
   trace window, broken down by syscall, which every Android decision needs
   and nobody has measured. This is the input to DRAFT-052's filter list.
8. **Whether any plugin writes only at teardown.** `dirwatch` already kills
   the trace at 180s, so this decides whether a timeout truncates a tail or
   loses a plugin's entire output — and nobody has checked. `memdump` and
   `fileextractor` write as they go; `procdump2`, `ipt` and `rootkitmon` are
   unknown.

# DEPLOY

Nothing deploys. The output is a document plus evidence, feeding other issues.

# Acceptance criteria

- [ ] All 45 tabled with per-guest support and a reasoned verdict.
- [ ] Matrix confirmed against the pinned commit.
- [ ] Every want-verdict plugin validated per guest, including that its output
      concerns the sample.
- [ ] Cost measured, not estimated; #38's heavy markers replaced with numbers.
- [ ] Android's idle noise floor quantified per syscall, and the complete
      per-guest syscall lists produced for DRAFT-052.
- [ ] Teardown-flush behaviour answered per plugin.
- [ ] The three corrected documents cross-reference this audit.

# Evidence required

- The matrix as read from the pinned commit.
- Per-plugin, per-guest transcripts: start, output sample, idle-versus-sample
  diff.
- Timing and output-size table.
- The Android idle baseline.

# Security considerations

- **This runs plugins against live guests on Dom0**, which is ordinary for
  this project, but a plugin never run here before is new code in the
  hypervisor-introspection path. A crash takes the trace, possibly the domain.
- **`ipt` is Intel PT** — hardware tracing with a large output rate. It can
  fill the volume during a single run. Bound it before enabling.
- **More plugins mean more attacker-influenced parsing** in DRAKVUF itself.
  Each plugin is a parser for guest structures the sample can partly control,
  and `rootkitmon` in particular reads structures rootkits deliberately
  corrupt.
- **`hidsim` injects input into the guest.** Harmless to the host, but it
  makes the guest less deterministic — DRAFT-055 owns that.

# Documentation changes

- **New:** the audit table and validation matrix, as the reference the three
  corrected documents point at.
- **Updated:** `docs/architecture/upstream-drakvuf.md`, `docs/workflow-ci.md`,
  `docs/roadmap/project-roadmap.md` — annotations point here.
- **Updated:** `platform/sandbox_platform/catalogue.py` — proven/candidate
  standings become evidenced rather than inferred.

# Recovery / rollback

Nothing to roll back; the pipeline is unchanged by this issue.
