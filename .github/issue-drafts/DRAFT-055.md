# DRAFT-055: `hidsim` — synthetic mouse and keyboard, with no inbound channel

**Status:** Drafted 2026-08-25. Not published.
**Area:** core
**OS:** ALL — `hidsim` is `[VMI_OS_WINDOWS] = 1, [VMI_OS_LINUX] = 1`.
**Milestone:** M5
**Priority:** P2
**Depends on:** DRAFT-050 (validate per guest), DRAFT-052 (the input-mode
choice), DRAFT-060 (enable it), DRAFT-054 (screenshots are how you see it
worked).
**Needs Dom0:** **Yes.**

# Objective

Make the guest look occupied: inject mouse movement and keystrokes during a
run, using a plugin the build already ships.

# Context

## Most of ANY.RUN's interactivity, at a fraction of the cost

The comparison document rates interactive detonation as ANY.RUN's defining
feature. DRAFT-056 covers the full version — a live desktop in the browser —
and that is a real inbound channel into a machine running malware.

`hidsim` gets a large part of the value with **no inbound channel at all**.
DRAKVUF injects the input from outside; nothing connects to the guest, nothing
is exposed, and the attack surface does not change.

## Two distinct things it buys

**Getting past "nobody is home" checks.** A common evasion waits for mouse
movement or a keystroke before doing anything — a sandbox has no user, so the
sample sleeps and the report shows nothing. Synthetic input defeats that
directly. Same family as `ideas.md`'s "make VMs more user computer like", and
it pairs with `cpuidmon` (DRAFT-050): one records that the sample looked for a
hypervisor, the other removes a different tell entirely.

**Clicking through installers.** Many samples wait on a Next button and sit at
the first dialog for the whole trace window — run spent, report empty, nothing
saying why. DRAFT-054's screenshots make that visible; this fixes it.

## What it is not

Not scripted interaction. `hidsim` simulates *activity*, not intent — it
cannot read a dialog and press the right button. A sample needing a specific
sequence still needs DRAFT-056. Worth saying plainly, because "automated
interaction" reads like more than it is.

## It is mutually exclusive with human control

Synthetic input and a person driving the same guest **fight each other**: the
pointer jumps mid-click, keystrokes interleave, and the run becomes neither a
clean automated experiment nor a usable interactive session.

So input is a **three-way choice at submission**, not two independent toggles:

| Mode | What happens |
|---|---|
| **none** (default) | No input. Deterministic, comparable between runs |
| **hidsim** | Synthetic activity. Automated, no inbound channel |
| **interactive** | A human drives it (DRAFT-056). `hidsim` is off |

DRAFT-052 owns the contract; this issue owns the middle row. During an
`interactive` run the operator can still *watch* via noVNC's view-only mode —
what they cannot do is have both hands on the controls at once.

# Dependencies

- **DRAFT-050** — validate it starts and does something on each guest. It is
  `candidate` on all three today.
- **DRAFT-052** — the input-mode field, and per-job enabling.
- **DRAFT-054** — screenshots are the only human-legible evidence it worked.

# Out of scope

- **Scripted or targeted interaction.** DRAFT-056.
- **Recording what was injected as an artifact.** It is a property of the
  configuration, not an observation of the sample.

# PLAN

1. DRAFT-050 validates it starts and produces input, per guest.
2. Measure the added event volume, Android first — that is where it either
   works or drowns the trace.
3. Wire `input_mode` through DRAFT-052.
4. Prove it against a wait-for-input fixture.

# CREATE

Enable `hidsim` as the `input_mode=hidsim` case. Its behaviour is DRAKVUF's;
this issue proves it works here and decides when it runs.

**Default off, deliberately.** Injected input changes what the guest does, so
two runs of the same sample with and without it are not the same experiment.
Fine when chosen; a problem as a silent default nobody accounted for.

# TEST

1. **Input arrives.** A fixture that logs mouse position and keystrokes shows
   movement during the run, on each guest.
2. **A sample waiting on user activity proceeds** where it previously did
   not — a fixture that sleeps until input, run both ways.
3. **Screenshots show it**, which is the human-legible evidence.
4. **The trace is not flooded.** Injected input generates guest activity;
   measure added event volume against the Android noise floor, where it
   matters most.
5. **A run with `input_mode=none` is unchanged**, so the default is inert.
6. **`hidsim` and `interactive` cannot both be selected** — refused at the
   API, not merely discouraged in the UI.
7. **Cost measured** — added run time and output volume, feeding DRAFT-052's
   hints.

# DEPLOY

A plugin selection, so it deploys with DRAFT-052 and needs nothing of its own.
Default off; a run that does not choose it is byte-identical to today.

# Acceptance criteria

- [ ] Validated on all three guests, or its failure recorded per guest.
- [ ] A wait-for-input fixture demonstrably proceeds with it and not without.
- [ ] Default off; the mode is recorded on the job and shown on the report.
- [ ] `hidsim` and `interactive` are mutually exclusive, enforced server-side.
- [ ] Added event volume measured, Android especially.
- [ ] No inbound channel introduced.

# Evidence required

- Input observed inside each guest.
- The wait-for-input fixture, both ways.
- Screenshots from a run where an installer advanced.
- Event-volume comparison.

# Security considerations

- **This adds no exposure**, which is the whole reason it is separate from
  DRAFT-056. Input is injected from Dom0 through DRAKVUF; nothing listens,
  nothing connects.
- **It makes the guest non-deterministic.** Two runs differ, so any comparison
  between runs must account for the mode — hence recording it.
- **Synthetic input is itself a tell.** Perfectly linear mouse movement or
  uniform keystroke timing is detectable, and a sample looking for a *human*
  rather than for *any* input may notice. This defeats the naive check, not
  every check — the honest claim.
- **It can click something consequential.** Blind input in a guest with
  network access might dismiss a warning, accept a prompt, or trigger an
  action with outward effect. On a residential line that is DRAFT-057's
  concern, and an argument for `offline` mode being available alongside.

# Documentation changes

- **New:** what `hidsim` does, what it does not, and the input-mode choice.
- **Updated:** `catalogue.py` — standing moves from candidate to proven per
  guest.
- **Updated:** `ideas.md`'s anti-evasion line, partly answered.

# Recovery / rollback

Do not select it. Nothing else changes.
