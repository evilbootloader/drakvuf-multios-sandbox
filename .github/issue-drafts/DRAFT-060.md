# DRAFT-060: `sandboxd` — the analysis orchestrator, and argv instead of shell

**Status:** Drafted 2026-08-25. Not published.
**Area:** core/platform
**OS:** ALL
**Milestone:** M2 → gates M7
**Priority:** **P0.** Named in `platform.md` since 2026-08-21, deferred as
"the pass after DRAFT-042–045", and **never given a draft** — while four
issues now depend on it.
**Depends on:** #35 (queue), #36 (API), #37 (object store). Replaces
`dirwatch.c`.
**Blocks:** DRAFT-052 (per-job plugins), DRAFT-059 (multi-file staging),
DRAFT-055 (`hidsim`), and dirwatch retirement.
**Needs Dom0:** **Yes.** This *is* the Dom0 component.

# Objective

Replace `dirwatch.c` and the five worker scripts with one Python daemon that
takes jobs from the platform API and drives an analysis — building every
command as an **argv vector**, never as a shell string.

# Context

## Why this is now the critical path

DRAFT-041 decided Python in 2026-08-21 and the index has carried `sandboxd` as
"deferred" ever since. Meanwhile:

- **DRAFT-052** — per-job plugin selection. The plugin list is hard-coded in
  `drakvuf-<os>.sh:181`; #38 already renders a picker that says, in red, that
  nothing it does takes effect.
- **DRAFT-059** — in-guest extraction and multi-file staging need a step the
  fixed callback contract has no room for.
- **DRAFT-055** — `hidsim` needs a plugin the invocation cannot express.

Three capability tracks are queued behind a component with no design document.

## What the lab cannot do today, and this fixes

**Only one OS can be analysed at a time.** `dirwatch` takes one origin domain
per invocation, so there is one instance per OS (CLAUDE.md:77) — and two
instances cannot run concurrently, because the thread-slot index *is* the
VLAN and the slot array is process-local. Two watchers allocate the same
VLANs and share gateway addresses and isolation rules, "with no symptom but
interference". Both launchers refuse to start if another is running.

So an Ubuntu submission and a Windows submission cannot be analysed in the
same window, on a host with capacity for both. That is not a performance
limit; it is a structural one, and it is invisible from the outside — the
second submission simply waits.

`sandboxd` removes it rather than working around it. One process owning every
clone allocates VLANs from an in-process table, so there is no second
allocator to collide with and no guard to enforce. **Concurrent multi-OS
analysis is a capability this issue delivers**, not a side effect of tidier
code — and it is why DRAFT-036's host-global allocator was dropped rather
than built.

## The argument that makes this a security change, not a rewrite

The current pipeline **builds command strings**. That is not a style
observation; it is a defect class this project has already been bitten by:

- **DRAFT-030** had to quote every expansion in `drakvuf-ubuntu.sh` after
  submitted filenames started reaching it. Before that, a sample named
  `a b.exe` split into two arguments.
- **DRAFT-031** found the shebang on line 104, below the licence header, where
  the kernel never saw it — `execv` failed `ENOEXEC` and GLib silently fell
  back to `/bin/sh`. Five root-run analysis scripts were running under an
  interpreter nobody had chosen.
- **CLAUDE.md** dedicates a section to untrusted filenames never being spliced
  into a guest shell string, because `sample_name_admissible()` admits `"`,
  `$`, backticks and `;`.

Every one of those is the same shape: **text becoming code because something
in the path parses it.** Now consider what DRAFT-059 and DRAFT-052 want to
add — an operator-supplied entry point, and an operator-supplied run command.
Through the current scripts, that is untrusted text entering a shell string
one layer deeper than the bug DRAFT-030 fixed.

`injector`'s own interface is already the right shape:

```
execproc - Run any process using vfork and execve ( -e for the program,
           -f for args )
[LINUX]  (execproc -> execve(const char *file, const char *argv[], ...))
```

`preconfig-android.sh` already exploits this — `-e /system/bin/sh -f -c -f
"$INSTALL_CMD" -f sh -f "$GUEST_SAMPLE"` — so the path arrives as a separate
`execve` element and the guest script refers to `"$1"`, which nothing
re-parses. **`sandboxd` makes that the default rather than the careful
exception.**

## The containment line this draws

An operator-supplied command is untrusted input reaching an execution path, so
the question is *whose* execution path.

- **In the guest** it is unremarkable. The guest is disposable and is already
  running malware chosen by the same person. A command that does something
  hostile there costs one clone.
- **On Dom0** it would be serious. Dom0 holds the worker token, the LVM volume
  group, and reachability to every clone.

With `sandboxd` calling `subprocess` with a list and `shell=False`, the string
reaches the guest as an argument and is never parsed by a shell on Dom0. That
line is the whole security argument, and it is testable.

## The counterweight, stated plainly

**The scripts are execution-evidenced.** Ubuntu end to end; Android on
2026-08-17. They also encode findings that cost real Dom0 sessions: that
`writefile` leaves a file executable so no `chmod` is needed; that Android
needs `-F --disable-sysret` to finish at all; that `am` works where `monkey`
is detected by `isUserAMonkey()` and `app_process64` aborts with exit 134.

CLAUDE.md: *"Do not modify the Ubuntu behavior unless required and explicitly
requested."* This was explicitly requested (2026-08-25). That authorises the
work; it does not excuse losing the evidence. **Behavioural parity with the
current scripts is the acceptance criterion**, not an aspiration — the first
milestone is an Ubuntu run that produces the same artifacts as today.

# Dependencies

- **#35** — the claim query and lease.
- **#36** — the worker channel this is the client of. `fake_worker.py` already
  walks the whole protocol and is the reference.
- **#37** — presigned sample GET, artifact POST.

# Out of scope

- **Retiring `dirwatch.c`.** It stays installed and startable until
  `sandboxd` is evidenced on all three targets, because that is the rollback
  path. The launcher guard extends to cover `sandboxd`, so the two can never
  run at once — see DEPLOY for why coexistence is not on offer.
- **Multi-host.** One analysis host.
- **The capability tracks themselves.** This makes DRAFT-052/055/059
  buildable; it does not build them.
- **Rewriting `clone.pl`.** It is Perl on a fixed 3-argument contract, holds
  no OS-specific value, and works. Leave it.

# PLAN

1. Port the state machine `fake_worker.py` already exercises.
2. Port one pipeline — Ubuntu — and prove parity before touching another.
3. Then Android, then per-job plugins, then run commands.

# CREATE

## Shape

```text
sandboxd
  ├── claim loop        long-poll /worker/claim, honour the lease
  ├── resources         VLAN + memory table, in process
  ├── stages            clone → preconfig → trace → collect → cleanup
  ├── exec              argv only. shell=False. no string ever built
  └── reconcile         on startup, against `xl list` and `ip link`
```

**VLANs come from an in-process table**, which is the whole reason DRAFT-036's
host-global allocator was dropped: one process owning every clone allocates
without coordination. That also removes the constraint that two launchers
cannot run concurrently — one daemon replaces both.

## The execution rule

One function builds every external command, and it takes a list:

```python
def run(argv: list[str], *, timeout: float) -> CompletedProcess:
    # shell=False is the default and is never overridden. A test asserts
    # no call site passes shell=True, because that single keyword is the
    # difference between an argument and a command.
    return subprocess.run(argv, shell=False, timeout=timeout, ...)
```

An operator-supplied run command is a **list of strings** from the API, each
element becoming one `-f` to `injector`. It is never joined, never split, and
never interpolated. The validation is on *shape* — a list, bounded length,
bounded element size, no NUL — rather than on content, because guessing which
guest commands are dangerous is a losing game when the guest is disposable.

## Analysis packages

The entry-point question DRAFT-059 raises generalises, and Cuckoo and CAPE
already named it. A **package** decides how a sample is invoked:

| Sample | Invocation |
|---|---|
| ELF / native | `execproc` the binary |
| APK | `cmd package resolve-activity` + `am start -n` (existing) |
| PE | `execproc` the binary |
| **DLL** | `rundll32 <dll>,<export>` — export chosen by operator or defaulted |
| MSI | `msiexec /i` |
| Script | the interpreter, with the script as an argument |
| **Custom** | operator-supplied argv, no package logic at all |

The package is chosen from the sample's own bytes, as `drakvuf-android.sh`
already does for APK-versus-ELF — a structural test, deliberately **not** the
advisory `detected_type`, which the operator supplied.

## What is ported verbatim, and must be

Every finding in the scripts moves across with its comment: the absent
`chmod`, `-F --disable-sysret` for Android, `am` over `monkey`, the
`sh -c '…' sh "$1"` idiom, the 60s/180s timeouts, `--memdump-dir` spelling.
**A port that loses these re-earns them the hard way.**

# TEST

1. **Ubuntu parity.** The same sample through `sandboxd` and through
   `dirwatch` produces the same artifact set — the milestone that gates
   everything else.
2. **No call site uses `shell=True`.** Asserted over the source, because one
   keyword is the whole containment argument.
3. **A hostile run command reaches the guest as one argv element.** Submit
   `["sh", "-c", "id; echo $(whoami)"]` and assert Dom0 ran no shell — the
   guest saw the string, Dom0 saw a list.
4. **A filename with spaces, quotes and `$` stages and executes correctly** —
   DRAFT-030's regression, in the new implementation.
5. **Startup reconciliation** against a clone `sandboxd` did not create:
   adopted or destroyed, never ignored.
6. **A lease that expires mid-analysis** ends with the clone destroyed and the
   job reported, not orphaned.
7. **Two orchestrators refuse to run at once**, `sandboxd` and `dirwatch`
   both.
8. **Android still finishes**, which is the real test of whether
   `--disable-sysret` and `-F` survived the port.

# DEPLOY

**Cutover, not coexistence.** An earlier draft of this section proposed
running one OS through `sandboxd` while the others stayed on `dirwatch`. That
is impossible, and for exactly the reason the guard exists: both allocate
VLANs from low numbers with no shared state, so they would collide on VLANs,
gateway addresses and isolation rules — and both launchers already refuse to
start when another orchestrator is running.

Giving `sandboxd` a disjoint VLAN range would technically permit it, and is
the wrong move: it means defeating a guard added deliberately, to buy a
transitional convenience, on the machine that runs malware.

So migration is per host and sequential:

```text
stop dirwatch  →  run sandboxd  →  evidence one OS  →  next OS
                       ↓ if anything is wrong
                 stop sandboxd  →  start dirwatch
```

Parity is proven by running the same sample through each **in turn** and
comparing artifacts, not by running them side by side. `dirwatch` stays
installed and startable throughout, which is what makes the rollback arrow
above real — and is why retiring it is deliberately not part of this issue.

Note the sequencing consequence: while `sandboxd` is being evidenced on
Ubuntu, no analysis happens on Android or Windows. That window is the cost of
not weakening the guard, and it is bounded by how long parity takes to
demonstrate.

# Acceptance criteria

- [ ] Ubuntu parity demonstrated artifact-for-artifact against `dirwatch`.
- [ ] Android parity, including that a trace completes.
- [ ] Every external command is an argv list; `shell=False` everywhere and a
      test that enforces it.
- [ ] Operator-supplied run commands reach the guest as argv elements and are
      never parsed by a shell on Dom0.
- [ ] Startup reconciliation handles a clone from a previous life.
- [ ] The concurrency guard covers `sandboxd` and `dirwatch` together,
      and refuses rather than sharing a VLAN range.
- [ ] **Two OS targets analysed concurrently under `sandboxd`** — the
      thing `dirwatch` structurally cannot do, and the clearest
      evidence the in-process allocator replaced the slot index.
- [ ] Every recorded finding in the scripts is carried across with its reason.
- [ ] `clone.pl` unchanged.

# Evidence required

- Side-by-side artifact listings, `dirwatch` versus `sandboxd`, same sample.
- The hostile-run-command test, showing Dom0's process list.
- An Android trace that completes.
- A reconciliation transcript against a deliberately orphaned clone.

# Security considerations

- **This is the component a sample reaches if it escapes the guest.** It holds
  the worker token and can reach every clone. Its blast radius is why the
  token is scoped to `/api/v1/worker/*` and why it holds no object-store
  credential — both properties #36 and #37 established and this must not
  quietly widen.
- **`shell=False` is the containment line and it is one keyword deep.**
  Nothing else in this design prevents operator text from becoming a Dom0
  command. That is why it is a test and not a convention.
- **Operator-supplied commands are trusted to be guest-scoped, not benign.**
  Anyone who can submit can already detonate malware of their choosing; a
  hostile command adds nothing there. The danger is only ever escape upward,
  which argv prevents structurally.
- **Reconciliation can destroy a clone another process owns**, if the guard
  fails. Two orchestrators sharing a host is the failure CLAUDE.md describes
  as having "no symptom but interference".
- **Porting is where a security property gets dropped silently.** The
  `sh -c '…' sh "$1"` idiom looks like an oddity to anyone who does not know
  why it is there; it must arrive with its comment or it will be simplified
  away.

# Documentation changes

- **New:** `sandboxd`'s design — stages, resources, the execution rule.
- **Updated:** `docs/architecture/platform.md` — from proposal to built.
- **Updated:** `docs/architecture/analysis-pipeline.md` — C1–C10 describe a
  per-OS *script* boundary that becomes a per-OS *package* boundary.
- **Updated:** `CLAUDE.md` — `dirwatch.c`'s section, and the concurrency
  constraint, once retirement actually happens.
- **Updated:** `issue-index.md` — `sandboxd` stops being a deferred line.

# Recovery / rollback

`dirwatch` stays installed and runnable throughout. Rollback is stopping
`sandboxd` and starting `dirwatch` — which is why retirement is deliberately
not part of this issue.
