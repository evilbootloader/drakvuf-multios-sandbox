---
name: runbook
description: How this project writes, executes, corrects and files runbooks — the EVIDENCE block convention, Candidate labelling, where a fix goes instead of the runbook, why an unexecuted runbook is parked at the repository root, and what to regenerate at commit time. Load before writing a new runbook, filling one in from operator output, correcting a step that turned out to be wrong, or moving one into docs/runbooks/.
---

# Runbooks

## When this matters

Load this before writing a procedure someone will follow on Dom0, before
pasting operator output into an existing one, and before "fixing" a step that
turned out to be wrong — that last one has a specific answer here that is not
the obvious one.

It does not apply to design records (`docs/architecture/`), per-OS progress
(`docs/checklists/`) or deployment facts (`docs/CURRENT-STATE.md`).

## What a runbook is, exactly

**The commands that worked**, in order, with the output they printed and the
date they were run. Someone should be able to follow it top to bottom and end
up with the thing deployed.

The pasted output is what makes it evidence rather than a plan. A procedure
with empty `EVIDENCE` blocks is a *draft*, however carefully written.

**What a runbook is not: a log of everything that happened.** Failed attempts,
dead ends, commands that turned out to be wrong, and tools whose errors mean
something other than what they say all go to `docs/TROUBLESHOOTING.md`, which
is organised symptom-first so it is findable by someone who has only the
symptom.

## The rule that is easy to get wrong

**A wrong step is replaced by the right one. The trap moves to
`docs/TROUBLESHOOTING.md`.** Do not annotate the wrong command in place and
leave both.

Two things stay in the runbook and are never rewritten:

1. **The dated output of the command that worked.** That is the evidence.
2. **A one-line pointer wherever a reader could otherwise repeat the mistake**,
   linking the troubleshooting entry, in the form
   `See [TROUBLESHOOTING](../TROUBLESHOOTING.md#the-heading-slug)` — a real
   anchor, because the next point is that they are checked.

The pointer matters most where a correction marks *surrounding* text as wrong.
Delete the marker without replacing it and the incorrect original stands
unmarked, which is worse than the clutter it removed.

`scripts/check-refs.py` validates those anchors, so a renamed heading fails the
test suite rather than rotting into a dead link.

## Labels that carry meaning

- **`Candidate`** — written but never run on this project's Dom0. Do not treat
  a Candidate command as working, and do not let one into an `EVIDENCE` block.
- **`EVIDENCE <id>`** — a fenced block for real pasted output. Leave it empty
  rather than filling it with a plausible-looking transcript.
- **`FINDING`** — something the execution discovered. These stay: they are
  results, not fixes.
- **`DECISION`** — why a step is shaped the way it is. These stay too.

**A blank `EVIDENCE` block never proves an operation did not happen.** It
proves nobody recorded output. Ask the operator before reporting something as
undone — this produced a wrong review finding on 2026-08-29.

## Why an unexecuted runbook sits at the repository root

`scripts/gen-current-state.py` counts `docs.rglob("*.md")` **off the
filesystem, not off git**. Any new `.md` under `docs/` — tracked or not —
changes the repository-size table and fails
`sandboxd/tests/test_current_state.py` while the file is still untracked.

So a runbook is written at the root, executed, and **moved to
`docs/runbooks/NN-` in the same change that fills its evidence and regenerates**.
That is also the project's rule that a runbook is committed after execution,
not before.

## Filing one, in order

1. Move it: `docs/runbooks/NN-<slug>.md`, numbered oldest to newest.
2. **Correct the status banner.** Banners are written before execution and are
   routinely never updated — runbook 09 carried "NOT YET EXECUTED" while
   containing 44 pasted Dom0 prompts. The generator gives the banner no vote
   and counts pasted host prompts instead, printing ⚠ when the two disagree.
3. If parts were **abandoned rather than left pending**, say so explicitly.
   Nobody should wait for evidence that can never arrive — runbook 12's Parts
   E–G needed a Proxmox host that the runbook itself erased.
4. Regenerate and commit:

       scripts/gen-current-state.py    scripts/gen-doc-index.py
       scripts/check-refs.py

5. Confirm the new row reads `yes` in `CURRENT-STATE.md` §3. If it reads `no`
   against a runbook full of output, the host is missing from
   `_EVIDENCE_HOSTS` in the generator — that is what the migration broke when
   Dom0 stopped being `drakvuf` and became `dom0`.

## Runbooks 01–10 describe a machine that no longer exists

They are correct as dated evidence of the nested Proxmox lab, erased
2026-08-28, and wrong as a description of this host. Do not update them to
match today; `CURRENT-STATE.md` §2a is where that reconciliation lives.

## Related

- `CLAUDE.md` — the short form of these rules.
- `CONTRIBUTING.md` — the full `PLAN → CREATE → TEST → DEPLOY` lifecycle.
- `docs/TROUBLESHOOTING.md` — where fixes go.
- The `dom0-handoff` skill — for the commands a runbook cannot run here.
