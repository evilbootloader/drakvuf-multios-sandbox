# DRAFT-028: Make `network-setup.sh` fail loudly, install correct rules, and be idempotent

**Status:** **[#24](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/24) — published and closed 2026-08-19.** Drafted, not published
**Area:** platform / networking (shared by Ubuntu, Android, Windows)
**Milestone:** M2 (containment closure)
**Priority:** P0
**Depends on:** None open. Should land **before** DRAFT-013 (isolation
verification) so the verification measures a fixed implementation rather
than recording a known-broken one.
**Origin:** `project-assessment.md` → Findings → NET-01, NET-04, NET-05

# Objective

Correct the inter-clone isolation rule in `automation/network-setup.sh`,
make the script fail loudly instead of silently when a rule is rejected,
and make repeated invocations idempotent.

# Context

`automation/network-setup.sh` is one of the four **shared** scripts in
`automation/` — it has no OS suffix and takes only a clone count, so it
provisions the analysis network for the Ubuntu, Android and (future)
Windows pipelines alike. Three defects, all source-verified:

**NET-01 — the isolation rule uses pre-2008 iptables negation syntax.**
Line 129:

```bash
iptables -A FORWARD -i xenbr1.$i -o !xenbr0 -j DROP
```

`-o !xenbr0` is the negation form deprecated in iptables 1.4.3 (2008);
current iptables expects `! -o xenbr0` and parses `!xenbr0` as an
interface name. If this rule is rejected on the current Dom0, then **the
only clone-to-clone isolation mechanism in the project is absent** and
nothing reports it — see NET-05.

This must be verified on the real host before being treated as broken. It
is stated here as a defect *hypothesis with a decisive test*, not as an
established fact, per `CLAUDE.md`'s "do not treat Candidate as proven"
rule.

**NET-05 — nothing checks whether any of it worked, and re-runs stack
up.** The script has no `set -e`, no `set -o pipefail`, and checks no exit
status anywhere. Every rule is added with `-A` and nothing is ever
flushed. `automation/run_analysis-ubuntu.sh:5` calls this script on every
launch, so each pipeline start appends another `MASQUERADE` (line 118) and
another per-VLAN `DROP` (line 129). With three OS pipelines eventually
launching on one host, duplication compounds rather than being shared.

**NET-04 — the script does not provision the OVS bridge, though the
documentation says it does.** It calls only `modprobe`, `ip`, `vconfig`
and `iptables`; `xenbr1` is created manually by `ovs-vsctl add-br xenbr1`
in the install guide (`docs/drakvuf-on-xen-nested-within-proxmox.md:421`).
Meanwhile `CLAUDE.md` and `docs/checklists/ubuntu.md:65-67` both describe
it as "provisions the OVS bridge and per-VLAN isolated networks". The
script also uses `vconfig` (line 124), deprecated in favour of
`ip link add link … type vlan`.

# Dependencies

- None open.
- **Blocks DRAFT-013** — isolation verification should measure a corrected
  implementation.
- Related to DRAFT-029 (Dom0 host-service exposure), which adds the
  `INPUT`-chain policy this script has never had. Kept separate: this
  issue fixes what exists; DRAFT-029 adds what is missing.

# Out of scope

- Adding any new isolation policy — specifically the `INPUT`-chain gap
  (NET-02) and the internet-egress question (NET-03). This issue makes the
  existing rules correct, verifiable and repeatable; it does not change
  the intended policy.
- Implementing the `offline`/`simulated`/`controlled-internet` network
  modes proposed in `docs/architecture/networking.md` — M2 design work.
- Creating or managing the `xenbr1` OVS bridge itself. This issue may
  *check* for it and fail clearly if absent, but bridge creation stays a
  documented install step.
- Changing the `172.16.<vlan>.0/24` addressing scheme, which
  `preconfig-ubuntu.sh:122` and `clone-ubuntu.pl:213` both depend on.

# PLAN

1. **Determine empirically whether line 129's rule installs on the current
   Dom0.** This is the pivotal question and it decides the size of the
   change (see TEST). Do not assume either answer.
2. Determine whether `vconfig` is still present and functional on the Dom0
   host, or whether the VLAN interfaces are surviving only because they
   were created once by hand.
3. Decide the idempotence strategy: check-then-add (`iptables -C … ||
   iptables -A …`) versus a dedicated chain that is flushed and rebuilt on
   each run. Recommendation: a dedicated chain (e.g. `DRAKVUF_ISOLATION`)
   jumped to from `FORWARD`, because it makes the pipeline's rules
   inspectable as a unit and removable in one operation — which also gives
   DRAFT-013 something clean to assert against.
4. Decide the failure policy. Recommendation: fail the whole script on any
   rule that does not install, because a silently half-provisioned
   analysis network is worse than no analysis network — it looks working.
5. Confirm no caller depends on the current always-exit-0 behaviour.
   `run_analysis-ubuntu.sh:5` ignores the exit status today, so making the
   script fail loudly also requires the launcher to stop ignoring it.

# CREATE

1. Add `set -Eeuo pipefail` and a `trap` that reports which provisioning
   step failed (matching `docs/checklists/android.md:2244-2245`'s stated
   reliability requirements).
2. Validate the argument: the clone count must be a positive integer, and
   the script must refuse to run with a missing or non-numeric `$1`
   (currently `seq 1 $1` with an empty `$1` silently produces nothing).
3. Replace the line 129 rule with the modern negation form, or with the
   dedicated-chain design from PLAN step 3.
4. Make provisioning idempotent per PLAN step 3 — re-running must converge
   to the same ruleset, not append to it.
5. Replace `vconfig add xenbr1 $i` with `ip link add link xenbr1 name
   xenbr1.$i type vlan id $i`, guarded so an existing interface is not an
   error.
6. Check `xenbr1` exists and is an OVS bridge before proceeding; fail with
   a clear message pointing at the install step if not.
7. Quote every expansion (`shellcheck` currently reports SC2086 at
   `:122,124,125,126,129`).
8. Update `automation/run_analysis-ubuntu.sh:5` to stop discarding the
   exit status.

# TEST

Runs in the development container:

```bash
bash -n automation/network-setup.sh
shellcheck automation/network-setup.sh          # expect: clean, incl. SC2086
bash -n automation/run_analysis-ubuntu.sh
```

Requires Xen Dom0 — present for manual execution, never run from the
development container (`CLAUDE.md` lists `iptables`/`nft`/`ovs-vsctl` as
out of bounds here):

```bash
# PLAN step 1 — the decisive test. Run BEFORE changing anything.
# Does the rule as currently written install at all?
iptables -S FORWARD | grep xenbr1
iptables -t nat -S POSTROUTING | grep MASQUERADE

# Expected if NET-01 is real: no per-VLAN DROP rules present despite the
# script having run. Expected if not: one DROP rule per VLAN.

# Count duplicates (NET-05) — run the script twice, compare:
iptables -S | wc -l
./network-setup.sh 2 && iptables -S | wc -l
./network-setup.sh 2 && iptables -S | wc -l   # must not grow

# After the change, prove isolation actually holds, from two live clones
# on different VLANs (benign, sandbox clones only):
#   clone A (172.16.1.2) -> ping/curl clone B (172.16.2.2)   expect: blocked
#   clone A -> external IPv4                                  expect: per policy
```

Record the before/after `iptables -S` output in full. That output is the
input DRAFT-013 needs.

# DEPLOY

Requires manual Dom0 coordination — present, do not execute:

1. Capture the current full ruleset first: `iptables-save >
   /root/iptables-pre-DRAFT-028.rules` (and `ip6tables-save`).
2. Apply the updated script during a window with no analysis running —
   changing `FORWARD`/NAT rules while a clone is executing a sample is not
   acceptable.
3. Re-run and confirm convergence rather than growth.
4. Rollback: `iptables-restore < /root/iptables-pre-DRAFT-028.rules` plus
   reverting the script. Because the change is rule-level and captured
   beforehand, rollback is complete and immediate.

# Acceptance criteria

- [ ] Recorded evidence from Dom0 showing whether the pre-change rule at
      `network-setup.sh:129` was actually installed — the answer to PLAN
      step 1, either way.
- [ ] The inter-VLAN isolation rule installs successfully on the current
      Dom0, confirmed by `iptables -S`.
- [ ] Running `network-setup.sh` twice in a row produces an identical
      ruleset — no duplicated `MASQUERADE` or `DROP` entries.
- [ ] The script exits non-zero if any rule fails to install, and
      `run_analysis-ubuntu.sh` no longer ignores that exit status.
- [ ] The script refuses to run with a missing or non-numeric clone count.
- [ ] The script fails with a clear message if `xenbr1` is absent, instead
      of proceeding.
- [ ] `shellcheck automation/network-setup.sh` is clean.
- [ ] A live two-clone test shows clone-to-clone traffic blocked, with
      output recorded.
- [ ] `docs/architecture/networking.md` and `docs/checklists/ubuntu.md`
      describe what the script actually does (NET-04), including that the
      OVS bridge is created by a separate documented install step.

# Evidence required

- `iptables -S` / `iptables -t nat -S` before and after.
- The twice-run duplication comparison.
- The two-clone isolation test transcript.
- Static-check output.

# Security considerations

- **This is the project's only existing clone-to-clone isolation control.**
  If PLAN step 1 shows it has never installed, that fact must be recorded
  plainly in `docs/checklists/android.md` §1.3 and the roadmap risk
  register, not quietly fixed — prior analysis runs would have executed
  without the isolation the documentation claims.
- Changing `FORWARD`/NAT rules on a host that also carries management
  traffic is a live-network change. Capture the full ruleset first
  (DEPLOY step 1) and apply only in a no-analysis window.
- Making the script fail loudly is itself a safety improvement: a
  half-provisioned analysis network currently presents as a working one.
- This issue deliberately does **not** change policy. Any tightening
  (blocking Dom0 services, restricting egress) belongs to DRAFT-029 and
  the M2 containment design, so that a rule-correctness change and a
  policy change are never entangled in one deployment.

# Documentation changes

`docs/architecture/networking.md` (correct the `ifconfig` line — DOC-01 —
and the OVS-provisioning claim — NET-04; record the new rule shape),
`docs/checklists/ubuntu.md:65-67` (same correction),
`CLAUDE.md`'s `network-setup.sh` description, and
`docs/checklists/android.md` §1.3 evidence block if PLAN step 1 shows the
isolation rule was never active.

# Recovery / rollback

Full ruleset captured before the change (DEPLOY step 1) and restorable in
one command; the script itself reverts from git. No LVM, Xen domain, or
guest state is touched.