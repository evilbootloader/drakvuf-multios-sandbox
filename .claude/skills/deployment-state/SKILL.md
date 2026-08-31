---
name: deployment-state
description: Current state of the DRAKVUF lab — host topology, CPU and memory partition, versions, what is evidenced, and facts that look current in old runbooks but are superseded. Load before asserting, or acting on, any fact about the bare-metal Dom0, the platform DomU, or the analysis guests.
---

# Deployment state

## When this matters

Load this before saying anything concrete about the running lab: how many
cores or how much memory something has, which VM or container is which, what
version of Xen or DRAKVUF is deployed, how a component is started, whether a
capability has ever actually been exercised.

It does **not** apply to questions about the code in this repository. Read the
code for those.

## The problem it solves

Facts about this lab are spread across 30+ documents and 43k lines, much of it
append-only runbook evidence that is accurate *as of its date* and misleading
now. On 2026-08-27 a review produced four confident, wrong statements, each
answerable from something already written down:

- asserted a `dom0_max_vcpus` contradiction that a later line in the same
  runbook had already resolved;
- ran `journalctl -u sandboxd` against a daemon that has no systemd unit;
- read a VM's memory figure as its core count;
- proposed a CPU split for a uniform host that is actually hybrid, with the
  topology already recorded two sections away.

Greping harder is not the fix — every one of those *was* in the repository. The
fix is one file that is read first.

**The 2026-08-28 bare-metal migration made this sharply worse.** Proxmox was
erased; there is no L0, no VM 101, no CT 102, and `qm`/`pct` do nothing. The
Dom0 hostname changed from `drakvuf` to `dom0`, its OS from 22.04 to 24.04, and
the platform went from an LXC container to a Xen PVH DomU. Runbooks 01–10 still
describe the old lab correctly *as dated evidence*, so a value read there is not
wrong — it answers a question about a machine that no longer exists.
`CURRENT-STATE.md` §2a lists every fact that changed in that one day.

## How to use it

1. **Read `docs/CURRENT-STATE.md`.** It has three sections and they carry
   different kinds of trust:
   - **Capabilities** — hand-maintained, one `Confirmed` date per row.
   - **Superseded facts** — values that still look correct in old runbooks.
     Check any surprising number against this table before repeating it.
   - **Derived** — regenerated from the repo by
     `scripts/gen-current-state.py`; trustworthy because a test fails when it
     drifts.

2. **Apply the staleness rule.** A row confirmed more than 30 days ago is a
   hint, not a fact. Say it is unconfirmed and ask, rather than asserting it.
   A row with `—` for a date, or marked `UNCONFIRMED`, has never been checked;
   treat it as unknown and say so.

3. **Prefer a runbook's *latest* word.** Runbooks are append-only, so an
   earlier line and a later line can both be real evidence and disagree. The
   later one wins, and annotations override the block they follow. When two
   values conflict and neither is in the superseded table, say so rather than
   picking one.

4. **Believe `output` over `banner`.** The derived runbook table reports both
   what a document claims about itself and whether host output was ever pasted
   into it. Where they disagree it prints ⚠ — a banner written before
   execution is often never updated.

## Keeping it true

If work in a session establishes a new host fact — an operator pastes `xl info`,
a runbook is executed, a version changes — offer to add or update the row, with
today's date. If a fact in an old document is found to be superseded,
offer to add it to the superseded table. That table only works if it grows.

**Attested is not the same as pasted.** An operator saying a thing ran is a
real fact and belongs in the hand-maintained table with the operator as its
source. It does not change the derived table, which counts pasted host prompts —
so a runbook can correctly read `Executed: no` for work that genuinely happened.
A blank `EVIDENCE` block never proves an operation did not occur; ask.

After any change that adds or renames a file under `docs/`, or a script or
test, run the generators and commit the result — the test suite fails
otherwise:

    scripts/gen-current-state.py    scripts/gen-doc-index.py
    scripts/gen-xen-configs.py      scripts/check-refs.py

**The CPU partition and the lab's host-global values now live in
`sandboxd/config.py`**, which generates `automation/platform.env` and the
`cpus =` lines in `misc/*.cfg`. Change a value there, not in a generated file.