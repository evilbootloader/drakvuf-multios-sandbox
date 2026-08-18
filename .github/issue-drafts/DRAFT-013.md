# DRAFT-013: Confirm an Android clone tolerates the isolation rules

**Status:** **Published 2026-08-12 —
[#13](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/13)**
(label `enhancement`)
**Area:** android / security
**Milestone:** M2 (containment closure)
**Priority:** P0 — the last containment unknown before Android automation
starts (Phase 2).
**Depends on:** DRAFT-028 and DRAFT-029, both landed and deployed
2026-08-11/12. DRAFT-037 (#7), closed — the template this boots did not
exist before it.
**Origin:** Roadmap risk #5; `docs/checklists/android.md` "Current blocker".

> **Drafted in full 2026-08-12, after two rounds of re-scoping.** The
> assessment note at `issue-index.md:347` says "NEEDS UPDATE — retitle away
> from Android-only", on the reasoning that the mechanism under test is
> shared. **That is now backwards** and is superseded: DRAFT-028's
> deployment measured the shared mechanism directly, on Ubuntu clones, and
> because `network-setup.sh` matches on interface rather than on anything
> guest-specific, that result transfers. What does not transfer is the
> *guest's reaction*. This issue is Android-only, and smaller than it was.

# Objective

Boot one Android clone on an isolated analysis VLAN under the current
rules, and record two things:

1. whether Android considers the network usable;
2. **the exact steps that give an Android clone the same connectivity an
   Ubuntu clone gets** — so `preconfig-android.sh` (DRAFT-016) is written
   from a measured procedure rather than by translating the Ubuntu script
   and hoping.

The second was added 2026-08-12 at the maintainer's request, and it is the
larger half.

# Connectivity parity with Ubuntu — the real deliverable

`preconfig-ubuntu.sh:206` configures a clone's network with one chain,
injected through `injector -m execproc`:

```sh
sudo ip addr flush dev eth0 &&
sudo ip addr add 172.16.$VLAN.2/24 dev eth0 &&
sudo ip route replace default via 172.16.$VLAN.1 dev eth0 &&
echo 'nameserver $GUEST_NAMESERVER' | sudo tee /etc/resolv.conf
```

Four steps. Establish each one's Android equivalent, by hand, and record it:

| # | Ubuntu | Android equivalent | Confidence |
|---|---|---|---|
| 1 | `ip addr flush dev eth0` | Same tool — BlissOS ships `ip` via toybox | Likely identical; the interface name needs confirming |
| 2 | `ip addr add 172.16.<vlan>.2/24 dev eth0` | Same | Likely identical |
| 3 | `ip route replace default via 172.16.<vlan>.1 dev eth0` | Same | Likely identical |
| 4 | `echo 'nameserver …' > /etc/resolv.conf` | **No equivalent exists** | **Unknown — this is the one to solve** |

**Step 4 is why this issue is worth more than a boot test.** Android's
framework resolver does not read `/etc/resolv.conf`; DNS is per-network
state owned by `netd`, populated from DHCP or from a static IP
configuration, and reached through `ConnectivityService` rather than a file.
Writing that file in an Android guest is very likely a no-op, and a
`preconfig-android.sh` that copies the Ubuntu line would produce a clone
that looks configured and cannot resolve anything.

There is direct evidence the lab already hit this. `docs/checklists/android.md`
§1.4 baked an in-guest DNAT into the golden image, redirecting all DNS to
`172.16.10.1:53` — which is what you write when you cannot set the resolver
and redirect the traffic instead. Issue #7 removed it deliberately, on the
grounds that per-clone resolver configuration belongs to analysis time. That
was the right call and it leaves this question open and unanswered.

Candidate mechanisms, **all unvalidated — establish which works**:

- Static IP configuration through the Settings UI, which has explicit DNS
  fields. Certainly works; the question is whether it can be driven
  non-interactively, since `preconfig-android.sh` cannot click.
- `ndc resolver setnetdns <netid> "" 1.1.1.1` — the `netd` client. Needs the
  netid, obtainable from `dumpsys connectivity` or `ndc network list`.
- `setprop net.dns1 1.1.1.1` — worked before Android 5, widely believed
  obsolete. Cheap to try; do not assume it does anything without checking.
- Leaving DNS to Android and confirming what it does with no DHCP at all.

Whatever works becomes DRAFT-016's implementation, and whatever does not is
worth recording just as much — a list of three things that look right and
are not is exactly what stops the next person repeating them.

## Answered 2026-08-13 — the resolver mechanism exists now because the image was rebuilt

All four candidates above were measured and **all four are dead** on Android
14 (`docs/runbooks/verify-android-isolation.md`, step 7): `/etc/resolv.conf`
and `setprop net.dns1` are no-ops, `ndc resolver` does not exist, and
`cmd ethernet help` returns `No shell command implementation`. The conclusion
was not "look harder" — there is no shell client for `IDnsResolver` on this
release.

The maintainer resolved it by **rebuilding BlissOS with Bliss-Bass
EthernetConfig** integrated as a platform-signed privileged app
(`docs/android_setup_good.md`). It exposes a standalone `main()`:

```sh
CLASSPATH="$(pm path com.example.ethernetconfig | sed 's/^package://')" \
  app_process / com.example.ethernetconfig.network.EthernetConfigurator \
  STATIC eth0 172.16.<vlan>.2 24 172.16.<vlan>.1 1.1.1.1 none
```

which reaches `IEthernetManager.updateConfiguration()` with a
`StaticIpConfiguration` carrying address, prefix, gateway **and DNS**.

**This changes the issue's shape rather than closing it.** Three consequences:

1. **The test target changed.** The measurements in steps 0–7 were taken on
   an image that no longer exists. Step 0's `1844fc0a…` checksum and step 5's
   fingerprint are both stale by design.
2. **The parity matrix may collapse.** If the framework installs the address,
   route and per-network table itself, the five-command chain step 6 measured
   — including the `table eth0` policy-routing line — reduces to one
   invocation. Test with **no** manual `ip` setup, or it is impossible to
   tell which mechanism worked.
3. **`private_dns_mode` is untouched by it**, so step 7b stands unchanged and
   is still the open visibility risk.

The neutral half of this issue — whether Android tolerates the isolation
rules — is **unaffected and still unmeasured**. The rules match on interface,
not on the guest, so the prediction and its falsification conditions carry
over to the rebuilt image verbatim.

## Also establish, because Ubuntu never had to

- **`sudo` — settled 2026-08-12, and it is not a question.** The anchor
  `nano` is launched from the root console (`androidboot.enable_console=1`),
  so anything injected against it already runs as root, and BlissOS ships no
  `sudo` binary at all. **Every one of the four `sudo` invocations in the
  Ubuntu chain must be dropped, not translated.** This is the first concrete
  instance of `CLAUDE.md`'s rule that a per-OS script is written against the
  conformance checklist rather than copied from the Ubuntu file — a copy
  would fail on line one with "sudo: not found", and under
  `injector -m execproc` that failure is invisible, because `injector`
  reports success when it starts the process rather than when the process
  succeeds (see the declined observability change, `issue-index.md`).
- **Which shell?** `injector -m execproc` is execve-direct with no guest
  shell (settled in issue #2), so a `&&` chain needs an explicit
  interpreter. Ubuntu's works because `/bin/sh` is there. Record BlissOS's
  path — `/system/bin/sh`, mksh — and confirm it.
- **Interface name.** `eth0` on Ubuntu. Confirm, do not assume.
- **IPv6 / Neighbour Solicitation.** `DRAKVUF_ISOLATION6` and
  `DRAKVUF_INPUT6` drop all IPv6, so Android's NDP — router solicitations,
  neighbour solicitations, SLAAC — goes nowhere. Android is far more
  IPv6-forward than Ubuntu, so record whether failed v6 provisioning
  affects its verdict on the network. This is the second reading of "NS"
  and it is worth measuring alongside the first.

# Context

Everything about the mechanism is measured. `docs/checklists/android.md`
§1.3's table was filled on 2026-08-11 with a nine-row connectivity matrix
and per-rule packet counters, and DRAFT-029 then made the chains terminal
and re-verified them. Every one of those measurements was taken on an
**Ubuntu** clone.

That is sound for the rules themselves — they match `-i`/`-o xenbr1.+`, not
anything about the guest — but it leaves one question no Ubuntu clone can
answer. Ubuntu does not care whether its gateway responds. **Android does.**
Android runs active connectivity validation and can mark a network
unvalidated, refuse to route traffic over it, or fall back, and the
containment posture deliberately makes the gateway unresponsive to most
things: `DRAKVUF_INPUT` drops everything from a clone to any Dom0 address
except replies to Dom0-initiated traffic.

`network-setup.sh:399-404` names this as the thing to watch, in the source:

> One behaviour to watch after deployment: a guest that probes its gateway
> to decide whether the network is up may conclude it is down. Android's
> first boot after this lands is the case to check.

This issue is that boot.

## The prediction, so the test can falsify it

Stating it in advance, because a test written to confirm what it expects is
worth much less than one that can fail:

**Android is expected to pass**, for three reasons:

1. **Neighbour reachability is L2 and unfiltered.** Android's
   `IpReachabilityMonitor` tracks the default gateway with ARP/NUD, and
   `iptables` does not filter ARP — DRAFT-028 relied on exactly this when it
   confirmed blocking clone→Dom0 costs the pipeline nothing. Dom0 holds
   `172.16.<vlan>.1` on the VLAN interface and will answer ARP.
2. **Validation probes go to the Internet, not to the gateway.** Android's
   `NetworkMonitor` fetches `connectivitycheck.gstatic.com/generate_204` and
   similar. Clones have deliberate NAT egress, so those succeed.
3. **DNS resolves.** The resolver is a public address (`1.1.1.1`), forwarded
   through Dom0 rather than served by it, which is why nothing needs to
   listen on the gateway.

What would falsify it: Android using ICMP echo to the gateway as a liveness
signal, or refusing to bring up a statically-configured interface whose
gateway does not answer ping. Both are dropped by `DRAKVUF_INPUT`.

**If the prediction holds, the fix list is empty and this issue closes on
evidence alone.** If it fails, the decision is a real one — whether to
exempt ICMP-to-gateway from `DRAKVUF_INPUT` for all three OS families, which
would reopen part of what DRAFT-028 closed — and that decision belongs here.

## A trap found while drafting this

`docs/runbooks/rebuild-android-sandbox.md` step 7 restores a disposable
Android clone using `android_test.cfg`, described as "same as
`android_sandbox.cfg` but `name` and `disk`". That inherits
`bridge=xenbr1` — **the bare OVS bridge.**

The isolation rules match `xenbr1.+`. That wildcard matches `xenbr1.1`,
`xenbr1.2` and so on, and deliberately **does not match `xenbr1` itself**
(`network-setup.sh:369-372`). A guest attached to the bare bridge is
therefore covered by no isolation rule at all.

Two consequences:

- **This test must specify `bridge=xenbr1.<vlan>` explicitly**, or it
  measures an unisolated guest and concludes nothing. `clone-ubuntu.pl:229`
  rewrites the vif exactly this way, and `clone-android.pl` will inherit
  the pattern — but the *manual* procedure does not.
- **The 2026-08-11 restore validation ran an Android guest with no
  isolation applied.** Harmless in itself: it was a boot test, no sample
  was involved, and the golden LV was untouched. It is recorded because
  anyone repeating that procedure falls into the same trap, and because it
  is a concrete instance of the gap DRAFT-038 exists to close — nothing
  checked, and nothing would have.

# Dependencies

- **DRAFT-028, DRAFT-029** — landed. Fix before measuring; this measures
  the fixed implementation.
- **DRAFT-037 (#7)** — closed. Supplies the rebuilt template
  (`state/android_sandbox.bak`, anchor PID 3163).
- **Blocks nothing formally**, but it is the last open containment question
  for Android, and `docs/checklists/android.md` names it as the current
  blocker on Phase 2.
- **Does not depend on DRAFT-015/016.** Those automate what this does by
  hand, and this issue's manual procedure is an input to them.

# Out of scope

- **Any change to the isolation rules.** This measures; DRAFT-028/029 own
  the mechanism. If the prediction fails, the fix is a follow-up with its
  own review, not a patch inside this issue.
- **The Internet-egress question.** `docs/checklists/android.md` §1.3's
  `Reach Internet IPv4 | Expected: Blocked` row conflicts with the decided
  policy and is DRAFT-022's, not this issue's. Do not tick or fail it here.
- **Running any sample.** This is a boot test.
- **In-guest log collection as a pipeline feature.** `logcat`/`dumpsys` were
  withdrawn from DRAFT-016/017 by issue #6. Reading them by hand during a
  one-off diagnostic is not that scope returning.
- Writing `clone-android.pl` or `preconfig-android.sh` (DRAFT-015/016).

# PLAN

1. Provision the analysis network and verify it, per the DRAFT-029 runbook.
2. Snapshot the template LV and write a throwaway domain config whose vif
   names **`bridge=xenbr1.<vlan>`**, not `xenbr1`. Confirm the attachment
   before booting the guest — this is the trap above.
3. Zero the chain counters immediately before unpausing, so everything they
   record is attributable to the Android boot.
4. Capture the VLAN with `tcpdump` for the whole boot. This is the primary
   evidence: it shows precisely what Android emitted, in order, without
   needing anything from inside the guest.
5. Configure the guest's network by hand over VNC — static address, gateway
   and resolver. The template deliberately carries no resolver (issue #7)
   and there is no DHCP on the analysis VLAN, so this cannot be skipped.
   **Record the exact steps**: they are the specification
   `preconfig-android.sh` implements in DRAFT-016.
6. Observe and record Android's own verdict on the network.
7. Read the counters and the pcap together. The counters say which rules
   fired; the pcap says what was attempted.
8. Destroy the clone and remove the snapshot. Confirm the golden and
   template LVs are untouched.

# CREATE

No code. The deliverables are evidence and documentation:

1. `docs/runbooks/verify-android-isolation.md` — the transcript.
2. `docs/checklists/android.md` — replace the "Current blocker" row with the
   result, and add the **parity matrix** below as a new subsection, filled.
   That table is what DRAFT-016 is written from:

   | Step | Ubuntu (`preconfig-ubuntu.sh:206`) | Android — measured | Same? |
   |---|---|---|---|
   | privilege | `sudo` prefix on each command | none needed; already root, no `sudo` binary | **No** |
   | interface | `eth0` | | |
   | flush | `ip addr flush dev eth0` | | |
   | address | `ip addr add 172.16.<vlan>.2/24 dev eth0` | | |
   | route | `ip route replace default via 172.16.<vlan>.1 dev eth0` | | |
   | resolver | `echo 'nameserver 1.1.1.1' > /etc/resolv.conf` | | **expected No** |
   | shell for the chain | `/bin/sh` | | |
   | verification | `getent hosts google.com` | `ping -c2 google.com` — **`getent` absent (confirmed 2026-08-12)** | **No** |
3. `docs/architecture/networking.md` — add Android's observed reaction to
   the containment posture section.
4. Roadmap risk #5 — its remaining open half is exactly this; close or
   rescope it.
5. If the prediction fails, a new draft for the fix. Not this issue.

# TEST

Nothing runs in the development container. All of the following is Dom0 or
guest work, presented for manual execution.

```bash
# --- Dom0: network up and verified ---
sudo /root/sandbox_project/automation/network-setup.sh 2
sudo nft list chain ip filter DRAKVUF_ISOLATION     # expect 9 rules
sudo nft list chain ip filter DRAKVUF_INPUT         # expect 2 rules

# --- Dom0: disposable clone on a VLAN sub-interface ---
sudo lvcreate -s -n android_sandbox-13-clone -L32G /dev/vg-root/android_sandbox

# android_isolation_test.cfg = misc/android_sandbox.cfg with:
#   name = "android_isolation_test"
#   disk = [ 'phy:/dev/vg-root/android_sandbox-13-clone,hda,w' ]
#   vif  = [ 'type=ioemu,model=e1000,script=vif-openvswitch,bridge=xenbr1.1' ]
#                                                                    ^^^^^^^
#   NOT bridge=xenbr1 -- the isolation rules do not match the bare bridge.

sudo xl restore -p -e android_isolation_test.cfg \
    /root/sandbox_project/state/android_sandbox.bak

# Confirm the attachment BEFORE unpausing.
sudo xl network-list android_isolation_test
sudo ovs-vsctl show                      # the vif must be on xenbr1.1

# --- Dom0: start capturing, zero the counters, then run the guest ---
sudo tcpdump -ni xenbr1.1 -w /root/draft-013-android-boot.pcap &
sudo iptables -Z DRAKVUF_ISOLATION
sudo iptables -Z DRAKVUF_INPUT
sudo xl unpause android_isolation_test
```

Inside the guest, over VNC — no `adb` on this build, root console available:

```sh
# --- Establish the environment first. No sudo exists; this is already root.
id
ls -l /system/bin/sh; command -v sh mksh toybox ip ndc getprop
ip -br link                       # confirm the interface name

# --- Steps 1-3: the Ubuntu chain minus sudo. Record each exit status.
ip addr flush dev eth0
ip addr add 172.16.1.2/24 dev eth0
ip route replace default via 172.16.1.1 dev eth0
ip -br addr show dev eth0; ip route

# --- Step 4: the resolver. Try in this order, checking after EACH.
cat /etc/resolv.conf 2>/dev/null            # does it even exist?
echo 'nameserver 1.1.1.1' > /etc/resolv.conf
ping -c2 google.com                         # expect: fails -- prove the no-op

setprop net.dns1 1.1.1.1
getprop net.dns1
ping -c2 google.com

ndc network list                            # find the netid
ndc resolver setnetdns <netid> "" 1.1.1.1
ping -c2 google.com

# --- Whatever worked, verify it the way Ubuntu was verified:
ping -c2 1.1.1.1                            # Internet by IP
ping -c2 google.com                         # name resolution
ping -c2 172.16.1.1                         # gateway -- expect FAIL, by design
ping -c2 <a LAN host>                       # expect FAIL, by design
```

Then record from the UI, verbatim:

```text
  - the connectivity status Android reports for the network
  - whether a browser loads a public page
  - whether any "no internet" / "sign in to network" notification appears
  - how long after configuration the verdict settles
```

**Record the failures as carefully as the success.** Which resolver
mechanisms were no-ops is worth as much to DRAFT-016 as the one that worked.

Back on Dom0, after five minutes of settling:

```bash
sudo kill %1                                    # stop tcpdump
sudo iptables -vnL DRAKVUF_ISOLATION --line-numbers
sudo iptables -vnL DRAKVUF_INPUT --line-numbers

# What did Android actually attempt? These are the questions the pcap answers.
tcpdump -nr /root/draft-013-android-boot.pcap arp | head          # NUD/ARP
tcpdump -nr /root/draft-013-android-boot.pcap icmp | head         # gateway pings?
tcpdump -nr /root/draft-013-android-boot.pcap port 53 | head      # DNS
tcpdump -nr /root/draft-013-android-boot.pcap 'dst host 172.16.1.1' | head

# --- Cleanup ---
sudo xl destroy android_isolation_test
sudo lvremove /dev/vg-root/android_sandbox-13-clone
sudo blockdev --getsize64 /dev/vg-root/android          # golden untouched
sudo lvs -a -o lv_name,lv_size vg-root
```

**The `DRAKVUF_INPUT` counter is the interesting number.** It counts what
Android sent to the gateway and had dropped. Zero means Android never
probed it. Non-zero with a validated network means Android probed, was
refused, and did not care — which is the most useful result of all.

# DEPLOY

Not applicable. No code, no infrastructure change. The clone and its
snapshot are created and destroyed within the test.

# Acceptance criteria

- [ ] An Android clone has booted on `xenbr1.<vlan>`, with the attachment
      confirmed before boot rather than assumed.
- [ ] Android's own verdict on the network is recorded verbatim.
- [ ] The pcap shows what Android attempted toward the gateway, and the
      `DRAKVUF_INPUT` counter agrees with it.
- [ ] ARP/NUD to the gateway is confirmed working — the mechanism the
      prediction rests on.

**Connectivity parity — the DRAFT-016 deliverable:**

- [ ] Each of the four Ubuntu chain steps has a recorded Android
      equivalent, or a recorded statement that it has none.
- [ ] **The resolver mechanism is established and demonstrated**, not
      inferred: a name resolves in the guest, and the pcap shows the query
      leaving for `1.1.1.1`.
- [ ] Candidate resolver mechanisms that did **not** work are recorded too,
      with what they did instead.
- [ ] The interface name, shell path and root/`sudo` situation are
      confirmed by observation.
- [ ] The parity matrix below is filled for both OS families, so a reader
      can see where Android and Ubuntu differ rather than inferring it.
- [ ] IPv6 provisioning behaviour is recorded, including whether its failure
      affects Android's verdict.
- [ ] The result is written as a procedure `preconfig-android.sh` can
      implement — a command sequence with expected outputs, not prose.
- [ ] `docs/checklists/android.md`'s "Current blocker" is replaced with the
      result.
- [ ] Roadmap risk #5 is closed or rescoped.
- [ ] Golden and template LVs are byte-identical before and after.
- [ ] If Android fails: the failure mode is characterised precisely enough
      that a fix can be designed without a second boot.

# Evidence required

`xl network-list` and `ovs-vsctl show` proving the VLAN attachment; the
pcap; zeroed-then-read counters for both chains; the guest-side observations
and the exact configuration steps; before/after LV sizes.

# Security considerations

- **No sample runs, benign or otherwise.** This is a boot test.
- Never restore onto the golden or the template LV — always a snapshot, per
  `rebuild-android-sandbox.md` step 7's own warning.
- **The Android guest will reach the Internet during this test**, because
  its validation probes are how it decides the network works. On a
  residential uplink under personal operation (roadmap risk #13) that
  traffic is benign — Google connectivity checks — but it is worth knowing
  that an Android clone generates identifiable outbound traffic at boot,
  before any sample runs. That is an input to DRAFT-022 and to the
  `offline` mode design.
- If the result is that Android needs ICMP to its gateway, **do not simply
  add the exemption.** It reopens part of NET-02 for all three OS families
  and needs its own review.

# Documentation changes

New: `docs/runbooks/verify-android-isolation.md`.
Updated: `docs/checklists/android.md` (Current blocker, §1.3 note, and the
manual configuration steps), `docs/architecture/networking.md`,
`docs/roadmap/project-roadmap.md` risk #5, and
`docs/runbooks/rebuild-android-sandbox.md` — **annotated, not edited** — to
record that its step 7 config attaches to the bare bridge.

# Recovery / rollback

The clone and its snapshot are destroyed by the test. Nothing else is
modified. If the domain wedges, `xl destroy` then `lvremove`; the template
is rebuildable from the golden per DRAFT-037's runbook.