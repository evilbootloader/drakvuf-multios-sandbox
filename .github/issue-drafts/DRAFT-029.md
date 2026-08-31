# DRAFT-029: Make the DRAKVUF chains terminal, so containment does not depend on Dom0's default policies

**Status:** **Published 2026-08-12 —
[#9](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/9)**
(label `bug`)
**Area:** platform / security (shared by Ubuntu, Android, Windows)
**Milestone:** M2 (containment closure)
**Priority:** P0
**Depends on:** DRAFT-028 — **landed 2026-08-11**. Nothing else open.
**Origin:** `project-assessment.md` → Findings → NET-02, plus one finding
made while sweeping this draft on 2026-08-12 (see "The fail-open window").

> **Swept 2026-08-12.** More than half of what this draft originally
> specified is already implemented. The NET-02 Dom0-service half — an
> `INPUT`-chain policy, which no version of `automation/` had ever had —
> was moved into DRAFT-028 at the maintainer's request and deployed on
> 2026-08-11 as the `DRAKVUF_INPUT` chain
> (`automation/network-setup.sh:365-404`; transcript in
> `docs/runbooks/04-deploy-network-isolation.md`). `issue-index.md` recorded
> that re-scope on 2026-08-11; this file did not, and was still presenting
> the closed half as open. The original text is in git history.

# Objective

Make every packet entering or leaving an analysis VLAN reach a terminal
verdict **inside the `DRAKVUF_*` chains**, so the containment posture no
longer depends on what `-P FORWARD` and `-P INPUT` happen to be set to on
the Dom0 host — and so that an aborted `network-setup.sh` run fails closed
instead of open.

# Context

DRAFT-028 built the posture into five dedicated chains and left one thing
open, which it said so explicitly
(`docs/runbooks/04-deploy-network-isolation.md:746`):

> What this deployment does **not** establish, and must not be read as
> establishing: no terminal policy is set on `FORWARD` or `INPUT`
> themselves, so the chains fall through to whatever the host already has.
> That is DRAFT-029.

What the host already has, measured during that deployment
(`docs/runbooks/04-deploy-network-isolation.md:349-354,600-602`):

```
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT          # and the same three for ip6tables
```

## `INPUT` is already terminal — the exposure is `FORWARD` only

This is the part the original draft could not have known, because the
chain it asks for did not exist yet. `DRAKVUF_INPUT` ends with an
unconditional drop:

```
-A DRAKVUF_INPUT -i xenbr1.+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DRAKVUF_INPUT -i xenbr1.+ -j DROP
```

Every packet from a clone to any Dom0 address is therefore decided within
the chain. **`-P INPUT` is irrelevant to clone containment**, and the same
holds for `DRAKVUF_INPUT6` and `DRAKVUF_ISOLATION6`, which drop
unconditionally.

`DRAKVUF_ISOLATION` is the exception. It ends after its four RFC1918 /
link-local drops with no terminal rule — deliberately, and flagged in the
source at `automation/network-setup.sh:358-360`:

```
# No terminal ACCEPT or RETURN follows, deliberately: the chain falls
# through to FORWARD's existing policy. Setting that policy is DRAFT-029's,
# not this issue's.
```

So **clone→Internet is permitted by inheritance.** It works because
`-P FORWARD` is `ACCEPT`; nothing in `automation/` sets that, asserts it,
or would notice it changing. The return path is inherited the same way —
`DRAKVUF_ISOLATION` matches only `-i xenbr1.+`, so Internet→clone replies
fall through to the policy untouched. Anything that flips `-P FORWARD` to
`DROP` (a firewall package, Docker, libvirt, an administrator) silently
kills every analysis clone's network, and the pipeline's only symptom is
samples that observe nothing.

## The design inversion this draft makes

The original text asked for a default-deny policy on the built-in chains.
**That is the wrong instrument**, for three reasons that only became clear
once `DRAKVUF_INPUT` existed:

1. **It buys nothing for `INPUT`.** Clone traffic is already terminally
   dropped. `-P INPUT DROP` would govern only non-clone traffic — which is
   Dom0 host hardening, explicitly out of scope below, and the single most
   effective way to lock an operator out of a headless L1 guest.
2. **`-P FORWARD DROP` is over-broad.** It applies to every forwarding path
   on the host, not just the analysis network. That is a policy decision
   about Dom0, made by a script whose job is provisioning one bridge.
3. **A terminal chain gives the identical guarantee with local blast
   radius**, and preserves what DRAFT-028 built the chains for: the whole
   posture stays readable with `iptables -S DRAKVUF_ISOLATION` and
   removable in a flush.

**Set no policies. Make the chain decide.**

## The fail-open window (found 2026-08-12, while sweeping this draft)

`DRAKVUF_ISOLATION` is flushed at `network-setup.sh:272` and its first rule
is not re-added until `:342`. Between those two lines sit
`ip link set xenbr1 up` (`:285`) and the entire per-clone VLAN loop
(`:292-319`) — `ip link add`, `ip addr add`, `ip link set up`, once per
slot. Under `set -eu` every one of those is fatal.

An abort anywhere in that span exits with the chain **empty, still jumped
to from `FORWARD`, behind `-P FORWARD ACCEPT`** — which is materially worse
than the state before the run, because a populated chain has been replaced
by an inert one. The EXIT trap reports the failing step and restores
nothing.

This is NET-01's shape a second time: a rule that is present, visible in
`iptables -S`, and matches nothing. It is in scope here because it is the
same question — what decides when our chain does not — and because a
terminal chain that can be emptied by a failed `ip addr add` is not
terminal.

Two things bound how bad it is today, and neither survives contact with the
roadmap. `run_analysis-ubuntu.sh` aborts when `network-setup.sh` fails, so
no *new* analysis starts; and today only one pipeline runs, so the script
is not re-run while clones are live. DRAFT-036's concurrent per-OS watchers
end both: launching the Android pipeline re-runs this script while Ubuntu
clones are mid-analysis, putting the flush window underneath running
samples.

The other two chains are not exposed — `DRAKVUF_INPUT` (`:382-404`) and
both IPv6 chains (`:434-448`) create, flush, jump and populate in
contiguous blocks with no `ip` commands between.

# Dependencies

- **DRAFT-028** — landed 2026-08-11. This builds directly on its chain
  structure.
- ~~DRAFT-013~~ — no longer a dependency. The original draft needed it to
  supply a measured inventory of what clones could reach; DRAFT-028's
  deployment produced that (the nine-row matrix with per-rule packet
  counters), and DRAFT-013 has since shrunk to one Android clone boot.
- ~~DRAFT-027~~ — landed inside issue #4 on 2026-08-09. The Apache
  dependency it was waiting on is gone; sample delivery is
  `injector -m writefile`, a VMI operation with no network path.
- **Blocks** nothing. **Does not block** DRAFT-013 — the two are
  independent, and either order works.

# Out of scope

- **Setting `-P INPUT`, `-P FORWARD` or `-P OUTPUT` at all**, in either
  address family. See the design inversion above — this draft's position is
  that `network-setup.sh` must not touch the built-in policies, and that
  position is the deliverable rather than a deferral.
- Dom0 host hardening: which services listen, how Apache and SSH are
  configured, management-interface exposure. This controls reachability
  *from the analysis network* only.
- The `offline` / `simulated` / `controlled-internet` modes. Whether clones
  should reach the Internet **at all** is DRAFT-022's decision and is now
  live (roadmap risk #13: personal operation, residential uplink). This
  draft makes the current deliberate egress *explicit* rather than
  inherited; it does not change it. Wiring `offline` becomes a one-rule
  change once this lands, which is an argument for landing it first.
- Clone-to-clone isolation and the RFC1918 blocks — DRAFT-028's, already
  deployed and counter-verified.
- `automation/platform.env`. `issue-index.md:403-406` proposes that
  DRAFT-028 create it and wire `network-setup.sh`; DRAFT-028 shipped
  without it, and inventing it here would be a second unreviewed decision
  in a security change. Flag, do not implement.

# PLAN

1. Confirm the three policies are still `ACCEPT` on the current Dom0 before
   changing anything — the design rests on not needing them to be, but a
   host that has already been changed is worth knowing about.
2. Add the terminal rules to `DRAKVUF_ISOLATION`, after the existing
   RFC1918 drops. Order is load-bearing: a LAN destination leaves via
   `xenbr0`, so an `-o xenbr0 ACCEPT` placed above the RFC1918 drops would
   accept exactly the traffic those rules exist to block.
3. Close the fail-open window, in two parts:
   - move the flush so it is adjacent to the rule installation, leaving no
     `ip` command inside the gap;
   - make the EXIT trap fail **closed** — on a non-zero exit, flush the
     chain and install a bare deny in both directions, so an aborted run
     denies rather than permits.
4. Confirm the trap cannot itself fail. It runs on every exit path,
   including argument validation before the chain exists, and a trap that
   errors under `set -eu` replaces one silent failure with another.
5. Verify on Dom0 that clone egress still works and that the new rules
   carry non-zero packet counters — an ACCEPT that never matches means the
   ordering is wrong.

# CREATE

`automation/network-setup.sh`, one file:

1. Append to `DRAKVUF_ISOLATION`, after the RFC1918 loop:

   ```sh
   # The intended egress, stated rather than inherited from -P FORWARD.
   iptables -A "$ISOLATION_CHAIN" -i "$ANALYSIS_BRIDGE.+" -o "$UPLINK_BRIDGE" -j ACCEPT

   # The return path. Without it, egress still depends on the policy.
   iptables -A "$ISOLATION_CHAIN" -o "$ANALYSIS_BRIDGE.+" \
       -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

   # Nothing may open a connection TO a clone.
   iptables -A "$ISOLATION_CHAIN" -o "$ANALYSIS_BRIDGE.+" -j DROP

   # Catch-all for clone-originated traffic. Redundant against the first
   # rule in the chain today; it is what makes the chain terminal by
   # construction rather than by the reader checking the rules above.
   iptables -A "$ISOLATION_CHAIN" -i "$ANALYSIS_BRIDGE.+" -j DROP
   ```

2. Relocate `iptables -F "$ISOLATION_CHAIN"` from Section 4 to the head of
   Section 6, immediately above the first `-A`. Chain creation and the
   `FORWARD` jump stay in Section 4 — neither is destructive.
3. Extend `on_exit()` to fail closed, guarded so it is a no-op before the
   chain exists and cannot itself abort.
4. Rewrite the Section 6 comment block: `:358-360` currently states the
   fall-through as deliberate and names this draft as the owner. Leaving it
   is a defect in this change (`CONTRIBUTING.md`, "Comments and historical
   context", rule 2). Same for the header block at `:140-142`, which lists
   the terminal policy as open.
5. Update `docs/architecture/networking.md` with the final posture, and fix
   its stale "Known gap: Android network isolation is unverified" section
   at `:200-207` — it still says §1.3's table has no Actual/Passed values,
   which stopped being true on 2026-08-11.

# TEST

In the development container:

```bash
bash -n automation/network-setup.sh
dash -n automation/network-setup.sh
shellcheck automation/network-setup.sh
```

On Dom0 — present for manual execution, never run from the container:

```bash
# 1. Preconditions, per PLAN step 1.
sudo iptables -S | head -3
sudo ip6tables -S | head -3

# 2. Provision, then read the chain back. Expect the four new rules last,
#    with both ACCEPTs below all four RFC1918 DROPs.
sudo ./network-setup.sh 2
sudo iptables -S DRAKVUF_ISOLATION

# 3. The regression that matters: egress must still work.
#    Boot one benign clone, then from inside it:
#      ping -c1 1.1.1.1                 expect: reply
#      getent hosts google.com          expect: resolves
#      ping -c1 <a LAN host>            expect: no reply
#      ping -c1 172.16.<vlan>.1         expect: no reply (DRAKVUF_INPUT)

# 4. Prove the rules are the reason, not the policy. This is the whole
#    point of the change, and it is the one step that actually tests it.
sudo iptables -P FORWARD DROP
#      re-run the four probes above     expect: identical results
sudo iptables -P FORWARD ACCEPT

# 5. Counters non-zero on both new ACCEPTs -- a rule that never matches
#    means the ordering is wrong.
sudo iptables -vnL DRAKVUF_ISOLATION

# 6. Fail-closed check. Force a failure inside the flush window and
#    confirm the chain denies rather than empties:
sudo ./network-setup.sh 999999   # exhausts VLAN ids / fails in the loop
sudo iptables -S DRAKVUF_ISOLATION   # expect: two DROP rules, not empty
sudo ./network-setup.sh 2            # expect: converges back, exit 0
```

Step 4 is the acceptance test. If the probes change behaviour when the
policy changes, the chain is not terminal and the change has not worked.

# DEPLOY

Lower risk than this draft originally assumed, because the design inversion
removed the lockout mechanism: every new rule is scoped to
`-i`/`-o xenbr1.+`, and no built-in policy is touched. Management
interfaces cannot be matched by any of them.

1. Capture `iptables-save` and `ip6tables-save` beforehand.
2. Apply in a no-analysis window — the script flushes and rebuilds.
3. Keep the Proxmox console to the L1 guest available. Not because this
   change can sever management access, but because TEST step 4 deliberately
   sets `-P FORWARD DROP` on a live host.
4. Rollback: `iptables-restore` from the pre-change capture.

# Acceptance criteria

- [ ] No packet in either direction on an analysis VLAN reaches
      `FORWARD`'s policy: `DRAKVUF_ISOLATION` decides `-i xenbr1.+` and
      `-o xenbr1.+` terminally.
- [ ] Clone egress, DNS and blocked-destination behaviour are **identical**
      with `-P FORWARD ACCEPT` and `-P FORWARD DROP` (TEST step 4).
- [ ] `network-setup.sh` sets no built-in chain policy, in either address
      family.
- [ ] An abort anywhere in the script leaves `DRAKVUF_ISOLATION` denying,
      never empty.
- [ ] Re-running after a failed run converges to the full ruleset and
      exits 0 — the idempotence DRAFT-028 established is not regressed.
- [ ] Both new ACCEPT rules show non-zero packet counters after a benign
      analysis run.
- [ ] The comments at `network-setup.sh:140-142` and `:358-360` describe
      the posture that now holds, and `docs/architecture/networking.md`'s
      stale §1.3 gap section is corrected.
- [ ] `bash -n`, `dash -n` and `shellcheck` are clean.

# Evidence required

- `iptables -S DRAKVUF_ISOLATION` after provisioning.
- `iptables -vnL DRAKVUF_ISOLATION` after a benign run, showing counters.
- The TEST step 4 transcript with both policy settings — this is the
  issue's central evidence, not a supporting detail.
- The TEST step 6 transcript showing the chain denying after a forced
  failure.
- Confirmation that operator access to Dom0 was unaffected throughout.

# Security considerations

- **The change makes current behaviour explicit; it does not make the lab
  safer to detonate real samples in.** Clones still have deliberate
  unrestricted Internet egress. That question is DRAFT-022's, and roadmap
  risk #13 now records why it is live: personal operation over a
  residential line. Landing this draft must not be read as closing it.
- Until this lands, every containment claim carries an unstated premise —
  `-P FORWARD ACCEPT`. That premise is currently true and nothing checks
  it.
- The fail-open window is the more urgent half. It is reachable today by
  any transient `ip` failure, and it becomes routine under DRAFT-036's
  concurrent watchers.
- Do not test with real malware. Benign fixtures and sandbox clones only;
  golden LVs untouched.

# Documentation changes

`docs/architecture/networking.md` — the terminal posture, and the stale
§1.3 gap section at `:200-207`. `docs/checklists/android.md` §1.3 and
`docs/checklists/ubuntu.md` — record that the measured results now hold
independently of host policy. `docs/roadmap/project-roadmap.md` risk #5 —
its "two things remain open" note loses one of them.

# Recovery / rollback

Pre-change `iptables-save` / `ip6tables-save` captures restore the previous
state in one command. No guest, LVM or Xen state is modified. If the new
rules prove wrong, `iptables -F DRAKVUF_ISOLATION` returns the host to
inherited-policy behaviour immediately — which is the pre-change state, not
an outage.