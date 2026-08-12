# DRAFT-038: Verify the installed firewall posture, and settle which netfilter backend this project owns

**Status:** **Published 2026-08-12 —
[#11](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/11)**
(label `enhancement`)
**Area:** platform / security (shared by Ubuntu, Android, Windows)
**Milestone:** M2 (containment closure)
**Priority:** P1
**Depends on:** DRAFT-028 and DRAFT-029, both landed. Nothing open.
**Origin:** Findings F1 and F2′ in `docs/runbooks/deploy-terminal-chains.md`,
from DRAFT-029's deployment on 2026-08-12.

# Objective

Make `network-setup.sh` prove what it installed, and decide which netfilter
backend this project owns — so that a containment claim is a measurement
rather than an assumption.

# Context

Three issues have now hardened the analysis network, each fixing a different
half of the same problem without closing it:

- **DRAFT-028** made provisioning fail loudly when a rule is *rejected*.
- **DRAFT-029** made the chains terminal, so the posture no longer depends
  on `-P FORWARD` / `-P INPUT`.
- Neither checks that what ended up in the kernel is what was intended.
  `network-setup.sh` installs its rules and exits 0.

**The project asserts a containment posture and never reads it back.** Both
findings below surfaced only because a human ran `iptables -S` by hand while
following a runbook. Nothing in the pipeline would have noticed either.

That is NET-01's lesson repeated. NET-01 was a rule that installed cleanly,
appeared in `iptables -S`, and matched nothing — `-o !xenbr0` was stored as
a literal interface name. It went undetected for the entire life of the
project, and no exit-status check could have caught it, because the command
succeeded.

## F1 — two iptables backends are live on Dom0

Measured 2026-08-12, before any provisioning:

```text
root@drakvuf:/home/user# sudo iptables-legacy -S 2>&1 | head
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
root@drakvuf:/home/user# sudo iptables-nft    -S 2>&1 | head -3
# Warning: iptables-legacy tables present, use iptables-legacy to see them
```

`iptables` resolves to `iptables-nft` through `update-alternatives`, so every
rule this project installs lands in nftables. But a **legacy `x_tables`
filter table also exists** — IPv4 only; no equivalent warning appears on the
IPv6 commands — currently holding default-ACCEPT policies and no rules.
`nft list tables` was empty at the same moment.

Three consequences, one already realised:

1. The two backends register at the netfilter hooks independently and are
   both evaluated. A rule in the legacy tables would be **invisible to
   `iptables -S` on this host**, and vice versa. Every containment assertion
   this project has made is a statement about one of two rulesets.
2. **`iptables-save` omits the legacy tables, and says so.** Step 1 of the
   DRAFT-029 runbook captured `/root/iptables-pre-DRAFT-029.rules` with
   exactly that warning on stderr. *The rollback captures taken by every
   runbook in this repository are partial on this host* — and rollback is
   the recovery path each DEPLOY section names. Nothing was lost in practice
   because the legacy tables hold no rules, but the procedure is incomplete
   and nobody knew.
3. Nothing identifies what creates those tables. They survived a reboot that
   left the nft ruleset empty, so something re-establishes them early.

## F2′ — "no containment" and "cannot read containment" look identical

The original F2 recorded an unexplained readback failure. **It was
withdrawn on 2026-08-12 after a one-command test**, and what replaced it is
more useful.

On this host, `iptables -S` reports *any* nonexistent chain as
"incompatible" — verified with the `ip filter` table present and populated:

```text
root@drakvuf:~/sandbox_project# sudo iptables -S NO_SUCH_CHAIN_12345
# Warning: iptables-legacy tables present, use iptables-legacy to see them
iptables v1.8.7 (nf_tables): chain `NO_SUCH_CHAIN_12345' in table `filter' is incompatible, use 'nft' tool.
```

So the message that blocked the first deployment attempt meant one thing:
**the chains did not exist.** The host had rebooted and `network-setup.sh`
had not run since. Nothing re-establishes the firewall at boot — there is
no `iptables-persistent`, no systemd unit; the chains are built by
`run_analysis-*.sh` at launch.

The finding is not the message. It is this:

> **The complete absence of containment presents as a confusing error, and
> confusing errors get rationalised.**

That is not hypothetical. The DRAFT-029 runbook was written up asserting
"filtering has not stopped… the rules are still evaluated" at a moment when
there were no rules, no chains and no VLAN interfaces. The reasoning was
plausible and entirely wrong, and it took the maintainer asking "could the
chains simply not have existed?" to catch it. A verifier does not
rationalise.

It is benign *today* only because the VLAN interfaces are absent at boot
too, so no clone can attach to a network that has no isolation. That is
coincidence, not design, and PLAN step 6 tests whether it holds.

## Why these are one issue

F1 is "there is a ruleset we never look at". F2′ is "when we do look, we
cannot tell empty from broken". Both are failures of the same missing
mechanism, and one verification step closes both.

# Dependencies

- **DRAFT-028**, **DRAFT-029** — landed. This is the third step in the same
  sequence: install correctly → decide terminally → verify.
- **Blocks nothing.** Strengthens DRAFT-013 and every future containment
  claim.
- **Interacts with DRAFT-036**, which will own VLAN allocation host-globally.
  Verification must not assume a single provisioning process.

# Out of scope

- **Changing the containment posture.** This verifies what DRAFT-028/029
  decided; it does not revisit it.
- The `offline` / `simulated` / `controlled-internet` modes — DRAFT-022 and
  roadmap risk #13.
- **Migrating this project to native `nft` syntax.** A real option, and a
  bigger decision than this issue should make in passing. If F1 resolves
  toward "nft only", record it as a separate proposal.
- Dom0 host hardening generally.
- `automation/platform.env`, still unwired (`issue-index.md:403-406`).

# PLAN

1. **Identify what creates the legacy tables**, before deciding anything.
   Candidates on a Xen Dom0: the `vif-*` hotplug scripts, an
   `iptable_filter` module autoload, anything invoking `iptables-legacy`
   directly. Start with `lsmod | grep -E 'ip_tables|iptable_filter'`, a
   boot-time unit inventory, and `grep -rl iptables /etc/xen`.
2. **Decide the backend question** on that evidence — eliminate the legacy
   tables if nothing needs them, or accept them and account for them
   everywhere firewall state is read or saved. Do not leave it open;
   undecided is the current state and it is what made the rollback captures
   partial.
3. **Fix the rollback procedure regardless of that outcome.** Every runbook
   DEPLOY section captures `iptables-save`, which is incomplete here.
4. **Design the verifier around properties, not a rule listing.** A
   hard-coded expected ruleset duplicates `network-setup.sh` and drifts from
   it at the first change — the repo↔host drift issue #2 diagnosed, one file
   over. Assert invariants instead:

   | | Property |
   |---|---|
   | P1 | Every `DRAKVUF_*` chain **exists and holds its expected rule count** — not merely "is readable". This is F2′'s detector, and the distinction is the whole finding |
   | P2 | Exactly one jump into each chain from its parent |
   | P3 | `DRAKVUF_ISOLATION` is terminal in both directions — DRAFT-029's invariant |
   | P4 | No `ACCEPT` precedes any RFC1918 or link-local `DROP` |
   | P5 | The legacy tables contain no rules, or only an explicitly allowed set from step 2 |
   | P6 | The IPv6 chains exist and are terminal |

   P4 would justify the issue alone. Getting it wrong puts a clone on the
   LAN, and the only evidence it currently holds is that a human compared
   two packet counters in a runbook.

   **Read state with `nft`, not `iptables`.** F2′ is precisely a case of the
   compatibility layer being unable to say what is true.
5. **Decide where it lives.** Recommendation: a separate
   `automation/network-verify.sh` rather than more code inside
   `network-setup.sh`. It can then be run standalone by an operator, called
   from `run_analysis-*.sh` after provisioning, and used by CI's self-hosted
   tier (DRAFT-026b) — and a script that verifies itself is the weaker
   arrangement.
6. **Answer the boot-state question F2′ raises.** Confirm no sandbox domain
   can start before provisioning: check `/etc/xen/auto/`, and confirm no
   unit starts a domain at boot. If one can, that is a containment gap in
   its own right and belongs in this issue. If not, record *why* the gap is
   benign, so the next reader does not have to re-derive it.

# CREATE

1. `automation/network-verify.sh` — POSIX, `#!/bin/sh` on line 1, per
   `CONTRIBUTING.md`'s script layout convention. This is the project's own
   work, so it carries no DRAKVUF licence header.
2. Assert P1–P6. Each failure names the property and prints what it saw.
3. Call it from `run_analysis-ubuntu.sh` after `network-setup.sh`, aborting
   on failure exactly as provisioning failure aborts today (`:64`).
4. Update the rollback guidance in `docs/architecture/networking.md` and in
   the runbook pattern, to capture both backends.
5. Record the backend decision from PLAN step 2 in
   `docs/architecture/networking.md`, with its evidence.

# TEST

In the development container:

```bash
bash -n automation/network-verify.sh
dash -n automation/network-verify.sh
shellcheck automation/network-verify.sh
```

On Dom0 — the point of this issue is that it fails when it should, so
**testing it means breaking each property deliberately**:

```bash
sudo ./automation/network-setup.sh 2
sudo ./automation/network-verify.sh          # expect: pass, exit 0

# P1 -- the F2' case: no chains at all, as after a reboot
sudo nft delete table ip filter
sudo ./automation/network-verify.sh          # expect: fail, names P1, says CONTAINMENT ABSENT
sudo ./automation/network-setup.sh 2

# P2 -- duplicate the jump
sudo iptables -I FORWARD 1 -j DRAKVUF_ISOLATION
sudo ./automation/network-verify.sh          # expect: fail, names P2

# P3 -- remove the terminal DROP
sudo iptables -D DRAKVUF_ISOLATION -i xenbr1.+ -j DROP
sudo ./automation/network-verify.sh          # expect: fail, names P3

# P5 -- put a rule in the legacy table
sudo iptables-legacy -A FORWARD -i xenbr1.1 -j ACCEPT
sudo ./automation/network-verify.sh          # expect: fail, names P5

# Restore
sudo ./automation/network-setup.sh 2
sudo iptables-legacy -F FORWARD
sudo ./automation/network-verify.sh          # expect: pass
```

The P1 case is the acceptance test. A verifier that has never been seen to
fail is not evidence of anything, and this is the failure that already
happened once and was talked away.

# DEPLOY

Low risk — the verifier reads state and does not change it. The
`run_analysis-ubuntu.sh` hook can abort a launch that previously proceeded,
so land it only after the verifier has been seen to pass on a healthy host.
Capture `iptables-legacy-save` before any legacy cleanup in PLAN step 2.

# Acceptance criteria

- [ ] What creates the legacy tables is identified and recorded — or the
      dead end is recorded, with what was ruled out.
- [ ] The backend question is decided and written down, not left open.
- [ ] Rollback capture covers both backends, in the docs and in the runbook
      pattern going forward.
- [ ] `network-verify.sh` asserts P1–P6 and exits non-zero on any failure.
- [ ] **P1 distinguishes "absent" from "present but wrong", and says so in
      words an operator cannot rationalise.**
- [ ] Each property has been observed failing, with a transcript.
- [ ] `run_analysis-ubuntu.sh` aborts when verification fails.
- [ ] The boot-state question (PLAN step 6) is answered either way.
- [ ] The verifier is OS-independent — one mechanism for all three
      pipelines, as `network-setup.sh` is.
- [ ] `bash -n`, `dash -n` and `shellcheck` clean.

# Evidence required

`lsmod` and the boot-time inventory from PLAN step 1; the verifier passing
on a healthy host and failing on each induced fault; an `iptables-save` +
`iptables-legacy-save` pair showing the rollback capture is now complete;
the `/etc/xen/auto/` inventory from step 6.

# Security considerations

- **This does not make the lab safer; it makes it checkable.** The posture
  is unchanged. What changes is whether a regression is noticed. Do not
  record it as closing a containment gap.
- **F1 is a real gap in the recovery path today.** Until step 3 lands, the
  rollback captures in existing runbooks restore only the nft half.
- **F2′ is a reasoning failure as much as a tooling one.** The mitigation is
  not "read the error more carefully" — it is to remove the human from the
  loop for this specific judgement.
- P4 is the highest-value assertion: rule order is the difference between a
  clone reaching the Internet and a clone reaching the LAN.
- Do not test with real malware. Benign fixtures and sandbox clones only.

# Documentation changes

`docs/architecture/networking.md` — the backend decision, the verification
properties, corrected rollback guidance. `CLAUDE.md` — add
`network-verify.sh` to the `automation/` inventory.
`docs/checklists/ubuntu.md` — record the verification step.
Roadmap risk register — an entry for the dual-backend finding if step 2 does
not eliminate it.

# Recovery / rollback

The verifier changes no state. The `run_analysis-ubuntu.sh` hook is one `if`
block, revertible alone. If legacy cleanup is performed in PLAN step 2,
capture `iptables-legacy-save` first.
