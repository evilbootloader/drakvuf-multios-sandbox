# DRAFT-039: Clean up the VLAN interfaces a failed `network-setup.sh` run leaves behind

**Status:** **Published 2026-08-12 —
[#12](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/12)**
(label `bug`)
**Area:** platform (shared by Ubuntu, Android, Windows)
**Milestone:** M2
**Priority:** P2
**Depends on:** DRAFT-029, landed. Nothing open.
**Origin:** Finding F4 in `docs/runbooks/05-deploy-terminal-chains.md`, step 7,
2026-08-12. Recorded in the source as `KNOWN GAP` at
`automation/network-setup.sh:249`.

# Objective

Make a failed `network-setup.sh` run leave no VLAN sub-interfaces or
addresses behind, without deleting interfaces it did not create.

# Context

DRAFT-029 added a fail-closed `EXIT` trap: on a non-zero exit it flushes
`DRAKVUF_ISOLATION` and installs a bare deny in both directions, so an
aborted run denies rather than permits. **It secures the firewall chain and
nothing else.**

Evidenced while testing exactly that, on Dom0 2026-08-12:

```text
root@drakvuf:~/sandbox_project/automation# sudo ./network-setup.sh 999999
Error: any valid prefix is expected rather than "172.16.256.1/24".
network-setup.sh: FAILED during: addressing xenbr1.256 (exit 1)
network-setup.sh: DRAKVUF_ISOLATION left DENYING all analysis-VLAN traffic; re-run to restore
```

The trap worked. But the run had already created `xenbr1.1` through
`xenbr1.255` and addressed them, and **none of that was removed**. The
subsequent successful `network-setup.sh 2` did not remove them either — the
provisioning loop creates what is missing and never deletes what is extra.
They persisted until the next reboot; the operator cleared them by hand.

DRAFT-029 capped the clone count at 254, which removes *that* trigger. It
does not remove the class: `ip link add`, `ip addr add` and `ip link set up`
(`network-setup.sh:378-392`) are each fatal under `set -eu`, so any
transient failure mid-loop — a name collision, a busy device, an
out-of-memory — leaves the same residue.

## What this is and is not

**It is not a containment gap.** Every isolation rule matches the
`xenbr1.+` wildcard, so strays are covered by the same rules as live slots,
and `DRAKVUF_INPUT` drops clone→Dom0 traffic whatever the slot number. A
stray interface is unreachable and unused, not an opening. This issue is
**P2 for that reason** and should not be described as closing a security
hole.

**It is stale state that will matter later.** Two ways:

- Dom0 accumulates addresses — 255 of them in the evidenced case, on a host
  where `ip -br addr` is a diagnostic an operator reads.
- **DRAFT-036 makes it worse.** If a host-global VLAN allocator ever keys
  "is slot N free?" on whether `xenbr1.N` exists, a stray interface makes
  that answer wrong, and the failure is a slot collision between two
  concurrent watchers — precisely the defect DRAFT-036 exists to prevent.

# The design problem, stated

The obvious fix is wrong, so it is worth writing down why.

The provisioning loop is **idempotent by reuse**: `ip link show "$vlan_if"
|| ip link add …` (`:379-381`). Finding an interface already present is the
normal case on a re-run, not an error. So a trap that deleted every
`xenbr1.*` would also delete interfaces belonging to a clone that is
currently running — catastrophic under DRAFT-036's concurrent watchers, and
wrong even today if an operator re-runs while an analysis is in flight.

Cleanup must therefore distinguish **created by this run** from
**pre-existing**, which means the script has to track what it made.

# Dependencies

- **DRAFT-029** — landed; this extends the trap it introduced.
- **Must not pre-empt DRAFT-036.** This issue may clean up what *this
  process* created. It may not decide who owns a slot, nor introduce any
  cross-process notion of ownership — that is DRAFT-036's, and inventing a
  second answer here is worse than the residue.

# Out of scope

- Removing interfaces created by a *previous* run or another process.
- Any host-global VLAN lifecycle or allocation. DRAFT-036.
- The firewall half of the trap, which works.
- Cleaning up on *success* — a successful run's interfaces are the point.

# PLAN

1. Track created interfaces. When the loop actually creates one (the `||`
   branch at `:379-381`, not the reuse path), append its name to a variable.
   Only names added there are eligible for deletion.
2. Extend `on_exit` to delete exactly those, after the existing firewall
   recovery, and only on a non-zero exit. Same `set +e` discipline: the
   handler already runs with `-e` active, and a failing `ip link del` must
   not abort the rest of the cleanup.
3. Decide what to do about an interface that was created *and then*
   successfully addressed and brought up before a later slot failed. It is
   still this run's, and still unused — recommend deleting it, so the rule
   is "this run created it, this run removes it" with no exceptions to
   reason about.
4. Confirm the ordering: firewall recovery first, interfaces second. If
   deletion fails, the deny rules must already be installed.
5. Consider whether the same tracking should log what it removed. The trap
   already prints one line; a second naming the interface count keeps the
   failure legible in a transcript.

# CREATE

`automation/network-setup.sh` only:

1. A `created_ifaces` accumulator, appended in the create branch.
2. `on_exit` deletes them in reverse order, guarded, after the chain
   recovery.
3. Update the `KNOWN GAP (DRAFT-029 follow-up)` comment at `:249` — it
   describes the gap this issue closes, so leaving it is a defect in the
   change (`CONTRIBUTING.md`, "Comments and historical context", rule 2).
4. Update the header comment block's description of what an aborted run
   leaves behind.

# TEST

In the development container:

```bash
bash -n automation/network-setup.sh
dash -n automation/network-setup.sh
shellcheck automation/network-setup.sh
```

On Dom0 — present for manual execution:

```bash
# Baseline
sudo ./automation/network-setup.sh 2
ip -br link show | grep -c '^xenbr1\.'        # expect 2

# Force a mid-loop failure ABOVE the existing slots, so slots 1-2 are
# pre-existing and 3+ are this run's. This is the case the design turns on.
sudo ip link add link xenbr1 name xenbr1.5 type vlan id 5   # collide deliberately
sudo ./automation/network-setup.sh 8
echo "exit: $?"                               # expect non-zero

ip -br link show | grep '^xenbr1\.'
#   expect: xenbr1.1, xenbr1.2 still present -- NOT created by this run
#   expect: xenbr1.5 still present            -- created externally, not ours
#   expect: xenbr1.3, xenbr1.4, 6, 7, 8 gone  -- created by this run

sudo iptables -S DRAKVUF_ISOLATION            # expect the 2 deny rules
sudo ./automation/network-setup.sh 2          # converge back
sudo ip link del xenbr1.5                     # tidy the fixture
```

The middle assertion is the whole test: **pre-existing interfaces survive a
failed run.** A cleanup that removes everything would pass a naive test and
be wrong.

# DEPLOY

Requires manual Dom0 coordination. Low risk — no firewall or guest state
changes — but run it in a no-analysis window, because the test deliberately
fails a provisioning run and the trap will install deny rules.

# Acceptance criteria

- [ ] A failed run removes every VLAN interface it created, and its
      addresses with them.
- [ ] A failed run removes **no** interface it did not create, evidenced by
      the mixed-ownership test above.
- [ ] Firewall recovery still happens first, and still happens if interface
      deletion fails.
- [ ] A successful run removes nothing.
- [ ] The `KNOWN GAP` comment at `:249` and the header block both describe
      the behaviour that now holds.
- [ ] No cross-process ownership assumption is introduced — DRAFT-036 is not
      pre-empted.
- [ ] `bash -n`, `dash -n` and `shellcheck` clean.

# Evidence required

`ip -br link show` before, during-failure and after, for the mixed-ownership
test; the trap's stderr output; `iptables -S DRAKVUF_ISOLATION` confirming
firewall recovery is unaffected.

# Security considerations

- **This closes no containment gap**, and should not be recorded as doing
  so. Stray interfaces are covered by the same `xenbr1.+` rules as live
  ones.
- The one thing that could *introduce* risk is over-deletion: removing an
  interface under a running clone. The mixed-ownership test exists for that
  and is not optional.
- Ordering matters. If interface deletion ever aborts the handler before the
  deny rules are installed, this change would convert a fail-closed trap
  into a fail-open one — the exact defect DRAFT-029 fixed.

# Documentation changes

`docs/architecture/networking.md` — the "aborted run leaves the chain
denying" section gains what happens to interfaces. `CLAUDE.md`'s
`network-setup.sh` entry if its description mentions cleanup behaviour.

# Recovery / rollback

No persistent state is touched. If the cleanup misbehaves, `network-setup.sh
<n>` re-creates any interface removed in error, and the change is one commit
to revert. Interfaces are not persistent across reboot in any case.