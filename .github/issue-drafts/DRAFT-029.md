# DRAFT-029: Restrict analysis-clone access to Dom0 host services

**Status:** Drafted, not published
**Area:** platform / security (shared by Ubuntu, Android, Windows)
**Milestone:** M2 (containment closure)
**Priority:** P0
**Depends on:** DRAFT-028 (correct and idempotent rule installation) and
DRAFT-013 (measured evidence of what is currently reachable). Strongly
benefits from DRAFT-027 landing first, which removes the single service
the pipeline currently *requires* a clone to reach.
**Origin:** `project-assessment.md` → Findings → NET-02 (with NET-03,
DRAKVUF-01)

# Objective

Add an explicit `INPUT`-chain policy so analysis clones can reach only the
Dom0 services the pipeline actually requires — closing a gap that the
existing `FORWARD`-chain isolation rule cannot cover by construction.

# Context

`automation/network-setup.sh:129` is the project's only isolation rule:

```bash
iptables -A FORWARD -i xenbr1.$i -o !xenbr0 -j DROP
```

It is a `FORWARD`-chain rule, so it governs traffic being *routed through*
Dom0. Packets a clone sends **to a Dom0 address itself** traverse `INPUT`,
not `FORWARD`, and are therefore unaffected — regardless of whether the
rule's syntax is correct (that is DRAFT-028's separate problem). No
`INPUT` policy is set anywhere in `automation/`.

The consequence: every analysis clone — Ubuntu, Android, and any future
Windows clone, since `network-setup.sh` is shared — can reach **every
service listening on every Dom0 address**. Two concrete cases:

1. **The Apache instance serving `/malware_processing`.** Its
   `DocumentRoot` is the in-flight sample directory
   (`docs/drakvuf-on-xen-nested-within-proxmox.md:635-644`). A clone can
   therefore fetch *other analyses' samples* by filename. Today this
   service is not merely reachable but **required**, because
   `preconfig-ubuntu.sh:122` delivers the sample through it — which is why
   DRAFT-027 should land first.
2. **Anything else Dom0 listens on**, including management access on
   whatever addresses Dom0 holds. This is precisely what
   `docs/checklists/android.md:429-436` asks about and leaves unanswered:

   | Test | Expected | Actual | Passed |
   |---|---|---|---:|
   | Reach Xen Dom0 analysis gateway | Only intended service ports | | [ ] |
   | Reach Xen Dom0 management IP | Blocked | | [ ] |

   On the current implementation, neither row can pass — there is no
   mechanism that would make them pass.

This is a containment gap in a malware-analysis sandbox, and it is
OS-independent: it is a property of the Dom0 firewall, not of any guest.

# Dependencies

- **DRAFT-028** — rules must install correctly and idempotently before new
  ones are layered on. Adding policy to a script that silently drops
  rejected rules would produce a policy that is believed active and is
  not.
- **DRAFT-013** — supplies the measured "Actual" column. Write the policy
  against measurements, not assumptions about what Dom0 listens on.
- **DRAFT-027** (strongly recommended first) — while HTTP delivery exists,
  the pipeline *needs* clone→Dom0:80 to work, so the tightest correct
  policy still has a hole in it. After DRAFT-027 there may be no required
  clone→Dom0 service at all, which makes default-deny straightforward.

# Out of scope

- Egress/internet policy (NET-03). Whether clones reach the internet is a
  separate decision belonging to the `offline`/`simulated`/
  `controlled-internet` mode design in `docs/architecture/networking.md`.
  This issue is strictly about **Dom0 as a destination**.
- Clone-to-clone isolation — that is the `FORWARD` rule, owned by
  DRAFT-028.
- IPv6 policy beyond confirming its state. `docs/checklists/android.md:401`
  ("Confirm IPv6 is either isolated or disabled") should be answered by
  DRAFT-013's measurement; implementing an IPv6 ruleset is follow-on work
  if measurement shows it is reachable.
- Hardening Dom0's services themselves (Apache configuration, SSH
  configuration). This issue controls *reachability from the analysis
  network*, not service configuration.
- Any change to `/malware_incoming`, `/malware_processing`,
  `/malware_finished` ownership or permissions.

# PLAN

1. Take DRAFT-013's inventory as input: which Dom0 addresses exist, which
   services listen on them, and which are currently reachable from a
   clone. Do not design against an assumed list.
2. Establish the *required* set. After DRAFT-027, the candidate answer is
   **none** — the clone needs a gateway for routing (NET-03's separate
   question) but no Dom0-hosted service. Confirm this rather than assume
   it; DNS is the likely exception, since `preconfig-ubuntu.sh:122` sets
   `nameserver 172.16.$VLAN.1`, pointing resolution at Dom0.
3. Resolve the DNS question explicitly. If Dom0 runs a resolver for the
   analysis network, it is a required service and must be allowed
   narrowly (UDP/TCP 53 from the analysis VLANs only). If it does not,
   `preconfig-ubuntu.sh`'s `resolv.conf` line is pointing at nothing and
   that is a separate finding worth recording.
4. Decide the enforcement point: a dedicated chain jumped to from `INPUT`
   for traffic arriving on `xenbr1.*`, consistent with DRAFT-028's
   dedicated-chain recommendation, so the pipeline's policy stays
   inspectable and removable as a unit.
5. Decide the default. Recommendation: default-deny for traffic from
   `xenbr1.*` to any Dom0 address, with an explicit allow-list from step
   2/3 — matching `docs/checklists/android.md:1844-1846` ("Default to no
   Internet access. Allow only explicitly required Dom0 analysis
   services").
6. Confirm the policy cannot lock the operator out. Rules must be scoped
   to the analysis VLAN interfaces (`-i xenbr1.*`), never to management
   interfaces.

# CREATE

1. Add the `INPUT`-chain policy to `automation/network-setup.sh`, using
   the chain structure DRAFT-028 establishes.
2. Scope every rule to the analysis VLAN interfaces explicitly.
3. Add the allow-list entries from PLAN steps 2–3, each with a comment
   naming *why* that service is required, so a future reader can tell
   which entries are load-bearing.
4. Add the same default-deny for IPv6 if DRAFT-013's measurement shows the
   analysis network has IPv6 reachability to Dom0.
5. Record the resulting policy in `docs/architecture/networking.md` as the
   containment baseline all three OS pipelines inherit.

# TEST

Runs in the development container:

```bash
bash -n automation/network-setup.sh
shellcheck automation/network-setup.sh
```

Requires Xen Dom0 and two live sandbox clones — present for manual
execution, never run from the development container:

```bash
# Before: what does Dom0 actually listen on, and on which addresses?
ss -tulpn
ip -br addr

# From inside a benign sandbox clone, per docs/checklists/android.md §1.3:
#   -> Dom0 analysis gateway 172.16.<vlan>.1, allowed ports    expect: reachable
#   -> Dom0 analysis gateway, any other port                   expect: blocked
#   -> Dom0 management IP, any port                            expect: blocked
#   -> Proxmox (L0) management IP                              expect: blocked
#   -> another LAN host                                        expect: blocked

# Specifically confirm the cross-sample exposure is closed:
#   -> http://172.16.<vlan>.1/<another analysis's filename>     expect: blocked

# Confirm the operator is not locked out: management access to Dom0 from
# the management network must be unaffected.
```

Fill in `docs/checklists/android.md:429-436`'s table from these results —
that table is this issue's natural evidence record, and it is OS-shared
despite living in the Android checklist (see DRAFT-013's recommended
retitle).

# DEPLOY

Requires manual Dom0 coordination — present, do not execute:

1. Capture `iptables-save` and `ip6tables-save` beforehand.
2. **Have out-of-band access available** (Proxmox console to the L1 VM)
   before applying `INPUT`-chain changes. A mistake here can sever
   management access to Dom0; the console is the recovery path.
3. Apply in a no-analysis window.
4. Verify operator access still works *before* leaving the console.
5. Rollback: `iptables-restore` from the pre-change capture.

# Acceptance criteria

- [ ] The set of Dom0 services that analysis clones are *required* to
      reach is determined and recorded, with the DNS question explicitly
      answered (PLAN step 3).
- [ ] Traffic from `xenbr1.*` to Dom0 addresses is default-deny, with a
      documented allow-list whose entries each state why they exist.
- [ ] A clone cannot reach the Dom0 management address on any port.
- [ ] A clone cannot retrieve another analysis's sample from
      `/malware_processing` over HTTP.
- [ ] `docs/checklists/android.md:429-436`'s isolation table has real
      Actual/Passed values for every row.
- [ ] Operator/management access to Dom0 is confirmed unaffected, with
      evidence.
- [ ] The policy is expressed in the shared `network-setup.sh`, so it
      applies to Ubuntu, Android and Windows clones without per-OS work.
- [ ] `shellcheck automation/network-setup.sh` is clean.

# Evidence required

- `ss -tulpn` and `ip -br addr` from Dom0.
- The completed §1.3 isolation table.
- `iptables -S` before and after.
- Transcript of the cross-sample-exposure test.
- Confirmation of continued operator access.

# Security considerations

- This issue exists to close a containment gap, and it is the kind of
  change that can fail closed on the *operator* rather than the guest.
  Out-of-band console access before applying (DEPLOY step 2) is not
  optional.
- Until this lands, treat every analysis run as having Dom0 services
  reachable from the guest. That is a material caveat on any claim that
  the sandbox is contained, and it should be stated in the roadmap risk
  register rather than left implicit.
- The cross-sample exposure (one analysis reading another's sample) is a
  contamination risk for analysis integrity as well as a containment one —
  a sample that can read the queue can behave differently when it detects
  it is being analysed alongside others.
- Do not test with real malware. Benign fixtures, sandbox clones only,
  golden LVs untouched.

# Documentation changes

`docs/architecture/networking.md` (the containment baseline and its
allow-list), `docs/checklists/android.md` §1.3 (fill in the table — this
is evidence being *added*, not existing evidence rewritten),
`docs/roadmap/project-roadmap.md` risk register (risk #5 can be closed or
rescoped once the table is complete), `docs/checklists/ubuntu.md` (record
that the same policy governs the Ubuntu pipeline).

# Recovery / rollback

Pre-change `iptables-save`/`ip6tables-save` captures restore the previous
state in one command. Out-of-band Proxmox console access is the recovery
path if management connectivity is lost. No guest, LVM or Xen state is
modified.
