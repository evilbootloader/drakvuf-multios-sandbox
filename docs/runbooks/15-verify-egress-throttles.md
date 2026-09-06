# Runbook — per-clone egress throttles (DRAFT-057 Phase 5)

> **Issue:** DRAFT-057 —
> [#42](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/42).
>
> **Status: EXECUTED on Dom0, 2026-09-05.** Steps 1–11 and 13 ran on this host
> and every `EVIDENCE` block below is pasted output. **Step 12 (`routed`) was
> abandoned, not left pending** — it says so in its own section.
>
> **What this proves:** that a clone's connection rate and parallel-connection
> count are bounded, that neither bound fires on an ordinary benign run, and
> that the throttles leave nothing behind when a job ends. **One thing it does
> not prove:** the byte-rate rule has never been observed dropping a packet —
> see the KNOWN GAP in step 8, which also explains why, and measures the clone's
> egress ceiling at 19 MB/s so the cap is at least known to sit below what a
> guest can produce.
>
> **The one step that could not be repeated later was step 2.** The unthrottled
> baseline existed only until the enforcing rules went in, and the four
> constants were guesses until it was read. It was taken first, and step 3's
> evidence proves it was taken against pre-throttle code.
>
> Design: `.github/issue-drafts/completed/DRAFT-057.md`, "Status 2026-09-05".
> The rules themselves are in `argv_apply`, `sandboxd/egress.py`.

## What this discharges, and what it cannot

| Claim | Outcome | Where |
|---|---|---|
| A per-clone new-connection rate binds | **proven** | step 7 — 51 → 108 drops |
| A per-clone parallel-connection cap binds | **proven** | step 9 — 241 drops, downstream of the rate rule |
| The limits do not break a benign run | **proven** | steps 3 and 6 — all three counters zero |
| Throttles do not survive a job | **proven** | step 10 — chain and hashlimit tables both gone |
| `tor` and `simulated` stay unthrottled | **proven** | step 11 — no chain at all |
| The clone's egress ceiling is above the cap | **proven** | step 8 — 19 MB/s offered against a 6 MB/s cap |
| A per-clone bandwidth cap **fires** | **not shown** | step 8 KNOWN GAP — needs `ESTABLISHED` traffic and a sink |
| The chosen numbers are justified | **partly** | step 4 — three of four rows are bounds, not peaks |
| The same rules under `routed` | **not run** | step 12, abandoned |
| The throttles bound abuse *at a provider* | **no** | there is no provider; see the descope in DRAFT-057 |

`egress-exits.md` §5 tells a prospective host that runs are rate-limited "on
the hypervisor before the tunnel". This runbook is what makes that sentence
true rather than intended.

## Before you start

**This changes the containment posture for `direct` and `routed`.** After step
5 every clone on those modes carries three DROP rules ahead of its permit. The
Ubuntu regression in step 6 is not optional — `CLAUDE.md` requires it after any
change to shared pipeline behaviour, and this is shared across all three OS
families.

**`tor` and `simulated` are deliberately untouched** (maintainer, 2026-09-05).
`argv_apply` returns at `sandboxd/egress.py:577` and `:580` before reaching the
throttles. Step 11 confirms that rather than assuming it.

Have ready:

- A benign fixture that makes outbound connections and a DNS lookup. The
  `curl` + `getent hosts` pair from runbook 13 step 5 is enough. **No malware
  is needed for any step here.**
- A second Dom0 terminal.
- For step 8, a large object to fetch. Use `curl -o /dev/null` so nothing lands
  in the guest filesystem — a scratch file is an artifact a sample could find,
  which this project does not leave behind.
- The `router` DomU from runbook 14 if you want the `routed` confirmation in
  step 12. **Runbook 14 tore it down at its step 11**, so it must be rebuilt
  from that runbook's steps 1–4 first. Steps 2–10 here run under `direct` and
  need no peer.

**A zero counter is also what an empty machine produces.** Runbook 14's step 6
was vacuous twice for exactly that reason. Every read below is paired with a
precondition assert whose output goes in the evidence block, so a reader can
tell a live test from a quiet host without having been there.

---

## Step 1 — the chain before anything changes

```sh
# DOM0
iptables -S DRAKVUF_EGRESS
iptables -S | grep -c DRAKVUF_EGRESS_V
```

Expect the parent chain to exist with no rules, and zero per-VLAN chains if no
job is running.

```text
root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS
-N DRAKVUF_EGRESS
root@dom0:~/drakvuf-multios-sandbox# iptables -S | grep -c DRAKVUF_EGRESS_V
0
```

---

## Step 2 — install the counting ladder, BEFORE the throttles

These rules have **no `-j`**. They match, increment their counters, and fall
through, so they change nothing about what the clone can do. They go in the
parent `DRAKVUF_EGRESS` chain rather than a per-VLAN one because the per-VLAN
chain is created and destroyed with each job, and this measurement has to
outlive several.

`--hashlimit-mode srcip` gives one bucket per clone address, so concurrent
clones do not pollute each other's counts.

```sh
# DOM0 — connection-rate ladder
for r in 5 10 20 50; do
  iptables -w 5 -I DRAKVUF_EGRESS 1 -i xenbr1.+ \
    -m conntrack --ctstate NEW \
    -m hashlimit --hashlimit-above ${r}/sec --hashlimit-burst 40 \
      --hashlimit-mode srcip --hashlimit-name probe_new_${r}
done

# DOM0 — bandwidth ladder, byte mode
for r in 1 3 6 12; do
  iptables -w 5 -I DRAKVUF_EGRESS 1 -i xenbr1.+ \
    -m hashlimit --hashlimit-above ${r}mb/s \
      --hashlimit-mode srcip --hashlimit-name probe_bw_${r}
done

# DOM0 — a bare total, for average throughput over the run
iptables -w 5 -I DRAKVUF_EGRESS 1 -i xenbr1.+
```

Confirm nine rules and no targets:

```sh
# DOM0
iptables -S DRAKVUF_EGRESS
```

```text
root@dom0:/home/user# # DOM0 — connection-rate ladder
for r in 5 10 20 50; do
  iptables -w 5 -I DRAKVUF_EGRESS 1 -i xenbr1.+ \
    -m conntrack --ctstate NEW \
    -m hashlimit --hashlimit-above ${r}/sec --hashlimit-burst 40 \
      --hashlimit-mode srcip --hashlimit-name probe_new_${r}
done
root@dom0:/home/user# for r in 1 3 6 12; do
  iptables -w 5 -I DRAKVUF_EGRESS 1 -i xenbr1.+ \
    -m hashlimit --hashlimit-above ${r}mb/s \
      --hashlimit-mode srcip --hashlimit-name probe_bw_${r}
done
root@dom0:/home/user# iptables -w 5 -I DRAKVUF_EGRESS 1 -i xenbr1.+
root@dom0:/home/user# iptables -S DRAKVUF_EGRESS
-N DRAKVUF_EGRESS
-A DRAKVUF_EGRESS -i xenbr1.+
-A DRAKVUF_EGRESS -i xenbr1.+ -m hashlimit --hashlimit-above 12mb/s --hashlimit-mode srcip --hashlimit-name probe_bw_12
-A DRAKVUF_EGRESS -i xenbr1.+ -m hashlimit --hashlimit-above 6mb/s --hashlimit-mode srcip --hashlimit-name probe_bw_6
-A DRAKVUF_EGRESS -i xenbr1.+ -m hashlimit --hashlimit-above 3mb/s --hashlimit-mode srcip --hashlimit-name probe_bw_3
-A DRAKVUF_EGRESS -i xenbr1.+ -m hashlimit --hashlimit-above 1mb/s --hashlimit-mode srcip --hashlimit-name probe_bw_1
-A DRAKVUF_EGRESS -i xenbr1.+ -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 50/sec --hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-name probe_new_50
-A DRAKVUF_EGRESS -i xenbr1.+ -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 20/sec --hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-name probe_new_20
-A DRAKVUF_EGRESS -i xenbr1.+ -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 10/sec --hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-name probe_new_10
-A DRAKVUF_EGRESS -i xenbr1.+ -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 5/sec --hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-name probe_new_5
```

> **DECISION.** The ladder measures at four thresholds at once instead of
> bisecting across four runs. One benign job then yields the whole curve, and
> the cost of a wrong first guess is zero.

---

## Step 3 — a benign run, unthrottled, with the ladder reading

Zero the counters, run one ordinary Ubuntu job through the UI or the API, and
read them when it finishes.

```sh
# DOM0
iptables -Z DRAKVUF_EGRESS
date -Is                                  # A. when the run started
```

Submit the job. Then, **while it is still running**, prove traffic is actually
flowing — this is the precondition that separates a real measurement from an
idle host:

```sh
# DOM0
iptables -S | grep -c DRAKVUF_EGRESS_V    # B. expect 5 -- see below
iptables -nvxL DRAKVUF_EGRESS | head -4   # C. expect the bare counter climbing
```

**B counts lines, not chains, and 5 is the pre-throttle answer**: one `-N`, one
jump from the parent, and the three rules inside the chain. After step 5 it
becomes 8, because the throttles add three more. A count of 0 means no clone is
running and the measurement would be vacuous.

That also makes B the check for whether the throttles are already live — which
matters if the checkout was pulled before the baseline was taken. Three rules
inside the chain is unthrottled code; six is not, and the run must be redone
against the pre-throttle version. See
[TROUBLESHOOTING](../TROUBLESHOOTING.md#baseline-measured-against-throttled-code).

After the job ends:

```sh
# DOM0
date -Is                                  # D. when it finished
iptables -nvxL DRAKVUF_EGRESS
```

```text
root@dom0:~/drakvuf-multios-sandbox# iptables -Z DRAKVUF_EGRESS
date -Is                                  
2026-09-05T17:06:28+00:00
root@dom0:~/drakvuf-multios-sandbox# iptables -S | grep -c DRAKVUF_EGRESS_V    # B. expect 1, the clone's chain exists
5
root@dom0:~/drakvuf-multios-sandbox# iptables -nvxL DRAKVUF_EGRESS | head -4   # C. expect the bare counter climbing
Chain DRAKVUF_EGRESS (1 references)
    pkts      bytes target     prot opt in     out     source               destination         
       1       69            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0           
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            limit: above 12mb/s mode srcip
root@dom0:~/drakvuf-multios-sandbox# iptables -nvxL DRAKVUF_EGRESS
Chain DRAKVUF_EGRESS (1 references)
    pkts      bytes target     prot opt in     out     source               destination         
      60    21624            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0           
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            limit: above 12mb/s mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            limit: above 6mb/s mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            limit: above 3mb/s mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            limit: above 1mb/s mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 50/sec burst 40 mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 20/sec burst 40 mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 10/sec burst 40 mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 5/sec burst 40 mode srcip

root@dom0:~/drakvuf-multios-sandbox#  date -Is
2026-09-05T17:09:00+00:00

```

Repeat for **Android**, and for **Windows** if its pipeline runs by then. The
three OS families idle very differently, and a constant tuned on Ubuntu alone
is how this project would rediscover the same defect twice.

```text
# Idle host

# Android
root@dom0:~/drakvuf-multios-sandbox# iptables -Z DRAKVUF_EGRESS
date -Is
2026-09-05T17:09:30+00:00
root@dom0:~/drakvuf-multios-sandbox# iptables -S | grep -c DRAKVUF_EGRESS_V    # B. expect 1, the clone's chain exists
5
root@dom0:~/drakvuf-multios-sandbox# iptables -nvxL DRAKVUF_EGRESS | head -4   # C. expect the bare counter climbing
Chain DRAKVUF_EGRESS (1 references)
    pkts      bytes target     prot opt in     out     source               destination         
      30     3221            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0           
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            limit: above 12mb/s mode srcip
root@dom0:~/drakvuf-multios-sandbox# date -Is
2026-09-05T17:11:43+00:00
root@dom0:~/drakvuf-multios-sandbox# iptables -nvxL DRAKVUF_EGRESS
Chain DRAKVUF_EGRESS (1 references)
    pkts      bytes target     prot opt in     out     source               destination         
      30     3221            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0           
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            limit: above 12mb/s mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            limit: above 6mb/s mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            limit: above 3mb/s mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            limit: above 1mb/s mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 50/sec burst 40 mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 20/sec burst 40 mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 10/sec burst 40 mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 5/sec burst 40 mode srcip



# Windows (with full iptables shown because of 5!=1) 

root@dom0:~/drakvuf-multios-sandbox# iptables -Z DRAKVUF_EGRESS
date -Is 
2026-09-05T17:12:41+00:00
root@dom0:~/drakvuf-multios-sandbox# iptables -S | grep -c DRAKVUF_EGRESS_V    # B. expect 1, the clone's chain exists
5
root@dom0:~/drakvuf-multios-sandbox# iptables -nvxL DRAKVUF_EGRESS | head -4   # C. expect the bare counter climbing
Chain DRAKVUF_EGRESS (1 references)
    pkts      bytes target     prot opt in     out     source               destination         
     170    83259            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0           
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            limit: above 12mb/s mode srcip
root@dom0:~/drakvuf-multios-sandbox# iptables -S 
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-N DRAKVUF_EGRESS
-N DRAKVUF_EGRESS_IN
-N DRAKVUF_EGRESS_V2
-N DRAKVUF_INPUT
-N DRAKVUF_ISOLATION
-A INPUT -j DRAKVUF_INPUT
-A FORWARD -m physdev --physdev-out vif145.0 --physdev-is-bridged -j ACCEPT
-A FORWARD -m physdev --physdev-in vif145.0 --physdev-is-bridged -j ACCEPT
-A FORWARD -m physdev --physdev-out vif129.0-emu --physdev-is-bridged -j ACCEPT
-A FORWARD -m physdev --physdev-in vif129.0-emu --physdev-is-bridged -j ACCEPT
-A FORWARD -m physdev --physdev-out vif129.0 --physdev-is-bridged -j ACCEPT
-A FORWARD -m physdev --physdev-in vif129.0 --physdev-is-bridged -j ACCEPT
-A FORWARD -j DRAKVUF_ISOLATION
-A FORWARD -m physdev --physdev-out vif9.0 --physdev-is-bridged -j ACCEPT
-A FORWARD -m physdev --physdev-in vif9.0 --physdev-is-bridged -j ACCEPT
-A DRAKVUF_EGRESS -i xenbr1.+
-A DRAKVUF_EGRESS -i xenbr1.+ -m hashlimit --hashlimit-above 12mb/s --hashlimit-mode srcip --hashlimit-name probe_bw_12
-A DRAKVUF_EGRESS -i xenbr1.+ -m hashlimit --hashlimit-above 6mb/s --hashlimit-mode srcip --hashlimit-name probe_bw_6
-A DRAKVUF_EGRESS -i xenbr1.+ -m hashlimit --hashlimit-above 3mb/s --hashlimit-mode srcip --hashlimit-name probe_bw_3
-A DRAKVUF_EGRESS -i xenbr1.+ -m hashlimit --hashlimit-above 1mb/s --hashlimit-mode srcip --hashlimit-name probe_bw_1
-A DRAKVUF_EGRESS -i xenbr1.+ -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 50/sec --hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-name probe_new_50
-A DRAKVUF_EGRESS -i xenbr1.+ -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 20/sec --hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-name probe_new_20
-A DRAKVUF_EGRESS -i xenbr1.+ -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 10/sec --hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-name probe_new_10
-A DRAKVUF_EGRESS -i xenbr1.+ -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 5/sec --hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-name probe_new_5
-A DRAKVUF_EGRESS -i xenbr1.2 -j DRAKVUF_EGRESS_V2
-A DRAKVUF_EGRESS_V2 -i xenbr1.2 -o xenbr0 -j ACCEPT
-A DRAKVUF_EGRESS_V2 -i xenbr0 -o xenbr1.2 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DRAKVUF_EGRESS_V2 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p tcp -m tcp --dport 9040 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p udp -m udp --dport 9040 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p tcp -m tcp --dport 9053 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p udp -m udp --dport 9053 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p tcp -m tcp --dport 21 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p tcp -m tcp --dport 25 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p tcp -m tcp --dport 80 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p tcp -m tcp --dport 110 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p tcp -m tcp --dport 1337 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p tcp -m tcp --dport 6667 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p tcp -m tcp --dport 38926 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p tcp -m tcp --dport 60000:60010 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p udp -m udp --dport 69 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p udp -m udp --dport 1337 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p udp -m udp --dport 5300 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p udp -m udp --dport 38926 -j DROP
-A DRAKVUF_INPUT -i xenbr1.+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DRAKVUF_INPUT -i xenbr1.+ -j DRAKVUF_EGRESS_IN
-A DRAKVUF_INPUT -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -i xenbr1.+ -o xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 10.0.0.0/8 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 172.16.0.0/12 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 192.168.0.0/16 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 169.254.0.0/16 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -i xenbr1.+ -j DRAKVUF_EGRESS
-A DRAKVUF_ISOLATION -o xenbr1.+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DRAKVUF_ISOLATION -o xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -i xenbr1.+ -j DROP
root@dom0:~/drakvuf-multios-sandbox# # DOM0
date -Is                                  # D. when it finished
iptables -nvxL DRAKVUF_EGRESS
2026-09-05T17:15:14+00:00
Chain DRAKVUF_EGRESS (1 references)
    pkts      bytes target     prot opt in     out     source               destination         
     714   268592            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0           
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            limit: above 12mb/s mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            limit: above 6mb/s mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            limit: above 3mb/s mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            limit: above 1mb/s mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 50/sec burst 40 mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 20/sec burst 40 mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 10/sec burst 40 mode srcip
       0        0            0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 5/sec burst 40 mode srcip

```

---

## Step 4 — choose the constants, and write down both numbers

Read the ladder: the **lowest threshold whose counter stayed at zero** is the
smallest limit a benign run survives. Anything below it fires on ordinary
traffic.

| Constant | Measured peak | Chosen | Margin |
|---|---|---|---|
| new connections/sec | **< 5/sec** — the lowest rung never fired, on any OS | `20/sec` | **> 4×**, lower bound only |
| new-connection burst | not isolated — every rung ran with burst 40 and none fired | `40` | unquantified |
| bandwidth (`mb/s`) | benign **< 1mb/s**; clone's measured **ceiling 19 MB/s** (step 8) | `6mb/s` | > 6× above benign, **3× below the ceiling** |
| parallel connections | **28** (Windows), 12 (Android), 8 (Ubuntu) | `50` | **1.8×** |

Set each guard **above** the measured value, and keep both numbers in the
comment where the constant lives — a limit recorded only as the number chosen
cannot be re-evaluated later.

Totals behind the table, from the bare counter and the two `date -Is` stamps:

| OS | Window | Packets | Bytes | Average |
|---|---|---|---|---|
| Ubuntu | 17:06:28 → 17:09:00, 152 s | 60 | 21,624 | 0.4 pkt/s, 142 B/s |
| Android | 17:09:30 → 17:11:43, 133 s | 30 | 3,221 | 0.2 pkt/s, 24 B/s |
| Windows | 17:12:41 → 17:15:14, 153 s | 714 | 268,592 | 4.7 pkt/s, 1.7 KB/s |

> **FINDING — three of four rows are bounds, not measurements.** Every rung of
> both ladders read zero on all three runs, including the lowest (`5/sec` and
> `1mb/s`). That proves the chosen limits cannot fire on a benign run, which is
> what step 6 needs. It does **not** measure the peak, so the margins above are
> floors: the true headroom is somewhere above 4× and unknown. Rungs at 1/sec,
> 2/sec, 100kb/s and 500kb/s would resolve it. Whether that is worth another
> baseline is a judgement about how much the fixture resembles a real sample —
> `curl` plus `getent` is very quiet, and 60 packets for a whole Ubuntu run
> says so.

> **FINDING — parallel connections is the tight row, and it is the Windows
> row.** 28 against a limit of 50 is 1.8×, where every other margin is at
> least 4×. Two things make it tighter than it looks: the sampling was at 1 Hz,
> so 28 is a sampled peak rather than a true maximum, and the Windows pipeline
> is the least exercised of the three — a guest doing update checks or
> telemetry on a real run will sit higher than one that has barely started.
> **`MAX_PARALLEL_CONNS = 50` is the constant most likely to need raising**,
> and step 9 is where it will show up first.

> **FINDING — the bandwidth cap is a real ceiling, not decoration.** Step 8
> measured what a DRAKVUF-traced clone can actually emit: **19 MB/s**, about
> 150 Mbit/s. `6mb/s` is therefore roughly 3× below the achievable maximum, so
> the rule can bind. That was an open question when these constants were
> guessed — a cap set above what a clone can physically produce would have been
> a promise to a host with nothing behind it.

> **FINDING — the real bound on unreplied UDP is 20 packets/second, not
> `6mb/s`.** An unreplied UDP flow never leaves conntrack's `NEW` state, so
> every datagram of a one-way flood matches the connection-rate rule, which
> sits above the byte rule and takes it at 20/sec — about 28 KB/s. Step 8 has
> the arithmetic. This is *tighter* than the byte cap and it governs exactly
> the patterns `private/egress-exits.md` §4.2 says hosts enforce against, so it
> is worth stating to a host in those terms rather than quoting `6mb/s` and
> letting them infer a ceiling three orders of magnitude looser.

> **FINDING — the `git pull` did not contaminate the baseline.** The clone's
> chain in step 3's evidence carries exactly three rules — the permit, the
> return path and the terminal DROP — with no `hashlimit` and no `connlimit`.
> That is pre-throttle code, so all three runs above measured an unthrottled
> guest. Nothing needs redoing.

> **Two coupling traps worth knowing before you edit anything.**
>
> The byte-mode burst has a floor of roughly one second at the rate: `6mb/s`
> requires at least `6291824b`. Change the rate without the burst and
> **iptables rejects the rule at install time** — a failure that appears on
> Dom0, not in the dev-container test suite.
>
> The packet-mode burst default is **5**, which is far below any real traffic
> pattern. It must stay explicit.

For parallel connections, the ladder does not measure concurrency — there is no
counting rule for it. Sample it **during** the benign run instead, in a second
terminal started before the job is submitted.

`conntrack` is not otherwise used by this project and may not be installed
(`conntrack-tools`); `command -v conntrack` first. **Use the VLAN the job
actually landed on** — step 3's evidence shows `xenbr1.2`, so `172.16.2.0/24`
there, not the `.1` below.

`connlimit` counts conntrack entries per source, not sockets, so entries
lingering in `TIME_WAIT` still count against the limit. Sampling the table
measures exactly the quantity the control uses — and is why the peak reads
higher than "connections open at once" would suggest.

```sh
# DOM0
while true; do
  printf '%s %s\n' "$(date +%T)" \
    "$(conntrack -L -s 172.16.1.0/24 2>/dev/null | wc -l)"
  sleep 1
done | tee /root/conntrack-peak.log


# DOM0
awk '{if ($2 > m) m = $2} END {print "peak concurrent entries:", m}' \
  /root/conntrack-peak.log
```

```text
# Ubuntu
root@dom0:~/drakvuf-multios-sandbox# awk '{if ($2 > m) m = $2} END {print "peak concurrent entries:", m}' \
  /root/conntrack-peak.log
peak concurrent entries: 8


# Android
root@dom0:/home/user# awk '{if ($2 > m) m = $2} END {print "peak concurrent entries:", m}' \
  /root/conntrack-peak.log
peak concurrent entries: 12


# Windows
root@dom0:~/drakvuf-multios-sandbox# awk '{if ($2 > m) m = $2} END {print "peak concurrent entries:", m}' \
  /root/conntrack-peak-windows.log
peak concurrent entries: 28
```

---

## Step 5 — install the throttles

The constants live in the source, so this is a restart rather than a command.
`sandboxd` has **no systemd unit**; source the env file first or it exits at
once and looks like a broken install.

```sh
# DOM0
cd /root/drakvuf-multios-sandbox
git log --oneline -1                      # record what is being deployed
set -a; . /etc/sandboxd/sandboxd.env; set +a
.venv-sandboxd/bin/python -m sandboxd.daemon 2>&1 \
  | tee -a /var/log/sandboxd/$(date +%Y%m%d-%H%M).log
```

Start one `direct` job and confirm the chain has **six** rules — three DROPs,
the permit, the return path, the terminal DROP:

```sh
# DOM0
iptables -S DRAKVUF_EGRESS_V1
```

```text
root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS_V1
-N DRAKVUF_EGRESS_V1
-A DRAKVUF_EGRESS_V1 -i xenbr1.1 -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 20/sec --hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-name dv_v1_new -j DROP
-A DRAKVUF_EGRESS_V1 -i xenbr1.1 -m hashlimit --hashlimit-above 6mb/s --hashlimit-burst 6mb --hashlimit-mode srcip --hashlimit-name dv_v1_bw -j DROP
-A DRAKVUF_EGRESS_V1 -i xenbr1.1 -m conntrack --ctstate NEW -m connlimit --connlimit-above 50 --connlimit-mask 32 --connlimit-saddr -j DROP
-A DRAKVUF_EGRESS_V1 -i xenbr1.1 -o xenbr0 -j ACCEPT
-A DRAKVUF_EGRESS_V1 -i xenbr0 -o xenbr1.1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DRAKVUF_EGRESS_V1 -j DROP
```

> **Cross-reference to fix when this lands.** Runbook 14 step 6, assert A,
> reads *"THREE rules, not 'no chain'"*. That count was correct before the
> throttles and is wrong after them. Update it in the same change that files
> this runbook.

---

## Step 6 — the Ubuntu regression. Do not skip this.

Re-run **the same benign fixture as step 3**, now with the throttles in place.
The comparison is the point: same fixture, same guest, one variable.

```sh
# GUEST
sudo apt install curl -y
curl -m 10 -sS -o /dev/null -w '%{http_code} %{time_total}\n' http://example.com/
getent hosts example.com
```

```text
```

Then confirm the throttle counters are **zero** — a benign run must not touch
them:

```sh
# DOM0
iptables -nvxL DRAKVUF_EGRESS_V1
```

```text
# Needed to install also curl during the run
root@dom0:~/drakvuf-multios-sandbox# iptables -nvxL DRAKVUF_EGRESS_V2
Chain DRAKVUF_EGRESS_V2 (1 references)
    pkts      bytes target     prot opt in     out     source               destination         
       0        0 DROP       0    --  xenbr1.2 *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 20/sec burst 40 mode srcip
       0        0 DROP       0    --  xenbr1.2 *       0.0.0.0/0            0.0.0.0/0            limit: above 6mb/s burst 6mb mode srcip
       0        0 DROP       0    --  xenbr1.2 *       0.0.0.0/0            0.0.0.0/0            ctstate NEW #conn src/32 > 50
     351    38816 ACCEPT     0    --  xenbr1.2 xenbr0  0.0.0.0/0            0.0.0.0/0           
       0        0 ACCEPT     0    --  xenbr0 xenbr1.2  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
       0        0 DROP       0    --  *      *       0.0.0.0/0            0.0.0.0/0         
```

**If any throttle counter is non-zero here, the limit is too tight.** Go back
to step 4 rather than accepting a degraded baseline; a control that fires on
ordinary traffic will be silently worked around later.

### 6a — the legacy launcher path, recorded once and not to be repeated

**Do not use this as a standing regression step.** `run_analysis-ubuntu.sh`
and `dirwatch` are scheduled for retirement (DRAFT-041,
`docs/architecture/automation-files.md`), and the 2026-09-04 assessment's F7
records that the living documents still present them as a live path. Verify
future changes to shared egress code against a **submitted job**, which is what
step 6 does — that is the path that builds a per-VLAN chain and therefore the
only one the throttles exist in.

It is recorded here because it was run (2026-09-06) and because of what it
turned up, not because the next change should run it again.

```sh
# DOM0 -- run once, 2026-09-06. Not a step to repeat.
ALLOW_DIRECT=1 ./automation/run_analysis-ubuntu.sh
```

```sh
# DOM0 -- second terminal, while it runs
iptables -S DRAKVUF_EGRESS       # expect: the wildcard, NOT a _V<n> jump
ip rule show                     # expect: NO 1000-range rule at all
```

```text
root@dom0:~/drakvuf-multios-sandbox# ALLOW_DIRECT=1 ./automation/run_analysis-ubuntu.sh
network-setup.sh: WARNING -- egress mode 'direct': every clone NATs  out xenbr0 with no per-job control. On a residential line  this is the posture DRAFT-057 exists to replace.
network-setup.sh: provisioned 2 VLAN sub-interface(s) on xenbr1
DRAKVUF dirwatch v1.1-git20260806065707+da982ab-1 Copyright (C) 2014-2024 Tamas K Lengyel

root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS       # expect: the wildcard, NOT a _V<n> jump
-N DRAKVUF_EGRESS
-A DRAKVUF_EGRESS -i xenbr1.+ -o xenbr0 -j ACCEPT
root@dom0:~/drakvuf-multios-sandbox# ip rule show                     # expect: NO 1000-range rule at all
0:	from all lookup local
32766:	from all lookup main
32767:	from all lookup default
```

Phase 5 changed nothing on the legacy path: the wildcard installs exactly as
runbook 14 step 9a recorded it on 2026-09-03, and no policy route appears
beside it.

> **FINDING — `ALLOW_DIRECT=1` has no throttles at all, and that is now a
> bigger statement than it used to be.** The three DROP rules live in the
> per-VLAN chain `argv_apply` builds. This path builds no per-VLAN chain: it
> installs one wildcard `-i xenbr1.+ -o xenbr0 -j ACCEPT` in the parent chain
> plus a wildcard MASQUERADE (`network-setup.sh:878`). The output above is the
> whole chain — one rule, no `_V<n>` jump — so a clone launched this way has no
> rate cap, no byte cap and no concurrency cap.
>
> This is consistent with the design: the mode is opt-in per invocation, is
> unreachable from the web UI, and the script's own warning says "no per-job
> control". But that warning was written before Phase 5, and a reader maps
> "no per-job control" to mode selection rather than to the absence of three
> named limits. **Two things now share the word `direct`** — `argv_apply`'s,
> which is throttled, and `ALLOW_DIRECT`'s, which is not — and DRAFT-057 and
> this runbook both describe the throttles as covering "`direct` and `routed`"
> without distinguishing them.
>
> Not a defect to fix here. It needs one sentence in the warning text naming
> what else is off, so the escape hatch states its full cost at the moment
> somebody uses it.

---

## Step 7 — the connection-rate cap binds

Deliberately exceed it. A loop of short-lived connections to distinct ports is
enough; no malware, and nothing written to the guest filesystem.

```sh
# GUEST
for p in $(seq 1 200); do
  (curl -m 2 -s -o /dev/null http://example.com:$p/ &) 
done
```

```sh
# DOM0
iptables -nvxL DRAKVUF_EGRESS_V1 | head -3
cat /proc/net/ipt_hashlimit/dv_v1_new
```

Expect the `dv_v1_new` rule's packet counter to climb.

```text
root@dom0:~/drakvuf-multios-sandbox# iptables -nvxL DRAKVUF_EGRESS_V1 | head -3
Chain DRAKVUF_EGRESS_V1 (1 references)
    pkts      bytes target     prot opt in     out     source               destination         
      51     2949 DROP       0    --  xenbr1.1 *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 20/sec burst 40 mode srcip
root@dom0:~/drakvuf-multios-sandbox# cat /proc/net/ipt_hashlimit/dv_v1_new
0 172.16.1.2:0->0.0.0.0:0 11682313334320 274877906000000 6871947650000
root@dom0:~/drakvuf-multios-sandbox# iptables -nvxL DRAKVUF_EGRESS_V1 | head -3
Chain DRAKVUF_EGRESS_V1 (1 references)
    pkts      bytes target     prot opt in     out     source               destination         
     108     6198 DROP       0    --  xenbr1.1 *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 20/sec burst 40 mode srcip
root@dom0:~/drakvuf-multios-sandbox# cat /proc/net/ipt_hashlimit/dv_v1_new
0 172.16.1.2:0->0.0.0.0:0 12369509777280 274877906000000 6871947650000
```

**The distinction that matters, and it is the same one runbook 13 draws for
`offline`:** the guest must see **timeouts, not resets**. A DROP is silent; a
REJECT would tell the sample it was being filtered.

```text
# Timeout hit (unable to resolve address)
```

---

## Step 8 — the clone's egress ceiling, and why the byte rule did not fire

**The rule matches `-i xenbr1.<vlan>`, which is traffic FROM the clone.** A
download's outbound half is nothing but ACKs, so fetching a large object tests
almost nothing here — the first attempt did exactly that and moved 970 KB at an
average of 58 bytes per packet, the signature of pure ACK traffic. The guest
has to **send**.

`/dev/zero`, not `/dev/urandom`: this measures bytes, not entropy, and urandom
is CPU-bound inside a traced guest.

```sh
# GUEST -- UDP needs no listener, so no sink has to exist. 192.0.2.1 is
# TEST-NET-1, outside RFC1918, so it clears the isolation chain's drops and
# dies upstream. Runbook 14 step 6 uses the same address for the same reason.
dd if=/dev/zero bs=1400 count=1000000 2>/dev/null > /dev/udp/192.0.2.1/9999
```

Read the chain over a known interval while that runs. **The DROP counter is
the measurement**: because these rules drop rather than queue, what they
dropped is what the guest offered.

```sh
# DOM0
iptables -Z DRAKVUF_EGRESS_V2 && sleep 10 && iptables -nvxL DRAKVUF_EGRESS_V2
```

```text
root@dom0:~/drakvuf-multios-sandbox# iptables -nvxL DRAKVUF_EGRESS_V1 
Chain DRAKVUF_EGRESS_V1 (1 references)
    pkts      bytes target     prot opt in     out     source               destination         
       0        0 DROP       0    --  xenbr1.1 *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 20/sec burst 40 mode srcip
       0        0 DROP       0    --  xenbr1.1 *       0.0.0.0/0            0.0.0.0/0            limit: above 6mb/s burst 6mb mode srcip
       0        0 DROP       0    --  xenbr1.1 *       0.0.0.0/0            0.0.0.0/0            ctstate NEW #conn src/32 > 50
   13706   900976 ACCEPT     0    --  xenbr1.1 xenbr0  0.0.0.0/0            0.0.0.0/0           
       0        0 ACCEPT     0    --  xenbr0 xenbr1.1  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
       0        0 DROP       0    --  *      *       0.0.0.0/0            0.0.0.0/0           
root@dom0:~/drakvuf-multios-sandbox# iptables -nvxL DRAKVUF_EGRESS_V1 
Chain DRAKVUF_EGRESS_V1 (1 references)
    pkts      bytes target     prot opt in     out     source               destination         
       0        0 DROP       0    --  xenbr1.1 *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 20/sec burst 40 mode srcip
       0        0 DROP       0    --  xenbr1.1 *       0.0.0.0/0            0.0.0.0/0            limit: above 6mb/s burst 6mb mode srcip
       0        0 DROP       0    --  xenbr1.1 *       0.0.0.0/0            0.0.0.0/0            ctstate NEW #conn src/32 > 50
   15047   970708 ACCEPT     0    --  xenbr1.1 xenbr0  0.0.0.0/0            0.0.0.0/0           
       0        0 ACCEPT     0    --  xenbr0 xenbr1.1  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
       0        0 DROP       0    --  *      *       0.0.0.0/0            0.0.0.0/0      
```

The UDP rerun, two consecutive ten-second windows:

```text
root@dom0:~/drakvuf-multios-sandbox# iptables -Z DRAKVUF_EGRESS_V2 && sleep 10 && iptables -nvxL DRAKVUF_EGRESS_V2
Chain DRAKVUF_EGRESS_V2 (1 references)
    pkts      bytes target     prot opt in     out     source               destination         
  126805 181074808 DROP       0    --  xenbr1.2 *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 20/sec burst 40 mode srcip
       0        0 DROP       0    --  xenbr1.2 *       0.0.0.0/0            0.0.0.0/0            limit: above 6mb/s burst 6mb mode srcip
       0        0 DROP       0    --  xenbr1.2 *       0.0.0.0/0            0.0.0.0/0            ctstate NEW #conn src/32 > 50
     200   285600 ACCEPT     0    --  xenbr1.2 xenbr0  0.0.0.0/0            0.0.0.0/0           
       0        0 ACCEPT     0    --  xenbr0 xenbr1.2  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
       0        0 DROP       0    --  *      *       0.0.0.0/0            0.0.0.0/0           
root@dom0:~/drakvuf-multios-sandbox# iptables -Z DRAKVUF_EGRESS_V2 && sleep 10 && iptables -nvxL DRAKVUF_EGRESS_V2
Chain DRAKVUF_EGRESS_V2 (1 references)
    pkts      bytes target     prot opt in     out     source               destination         
  134921 192660372 DROP       0    --  xenbr1.2 *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 20/sec burst 40 mode srcip
       0        0 DROP       0    --  xenbr1.2 *       0.0.0.0/0            0.0.0.0/0            limit: above 6mb/s burst 6mb mode srcip
       0        0 DROP       0    --  xenbr1.2 *       0.0.0.0/0            0.0.0.0/0            ctstate NEW #conn src/32 > 50
     200   285600 ACCEPT     0    --  xenbr1.2 xenbr0  0.0.0.0/0            0.0.0.0/0           
       0        0 ACCEPT     0    --  xenbr0 xenbr1.2  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
       0        0 DROP       0    --  *      *       0.0.0.0/0            0.0.0.0/0           
```

> **FINDING — the clone's egress ceiling is 19 MB/s.** 181,074,808 and
> 192,660,372 bytes offered in ten seconds: **18.1 and 19.3 MB/s**, about
> 150 Mbit/s. A DRAKVUF-traced guest is not the bottleneck anyone might have
> assumed, and `MAX_EGRESS_RATE = 6mb/s` sits roughly 3× below what a clone can
> produce. The cap can bind, which is what makes it worth having.

> **FINDING — the byte rule cannot fire on unreplied UDP, and the reason is
> conntrack, not iptables.** A UDP flow stays in `NEW` until a packet comes
> back the other way; `192.0.2.1` never answers, so **every** datagram matched
> the connection-rate rule sitting above the byte rule, which took them at
> 20/sec. Exactly **200 packets** passed in each ten-second window — 20/sec to
> the packet — at 1,428 bytes each, so the byte rule only ever saw 28 KB/s.
>
> The consequence is worth stating plainly because it is the opposite of a
> weakness: **for one-way UDP the effective ceiling is 20 packets per second,
> roughly 28 KB/s**, far tighter than `6mb/s`. That is the bound that applies
> to scanning and UDP flooding.

> **KNOWN GAP — the byte rule has never been observed dropping a packet.** It
> installs, it is reachable, and the ceiling above proves it is set below what
> a clone can emit. What has not been shown is it firing. Exercising it needs
> `ESTABLISHED` traffic — a TCP upload with something at the far end receiving
> it — because anything that stays `NEW` is taken by the rate rule first. Not
> attempted here: it needs a sink willing to absorb tens of megabytes, and the
> `routed` peer that would have been the natural one was not rebuilt.

---

## Step 9 — the parallel-connection cap binds

```sh
# GUEST
for i in $(seq 1 120); do (curl -m 30 -s -o /dev/null http://example.com/ &) ; done
```

```sh
# DOM0 -- read the WHOLE chain. `head -4` cuts the output at the byte rule and
# hides the connlimit counter, which is the one this step is about.
conntrack -L -s 172.16.1.0/24 2>/dev/null | wc -l
iptables -nvxL DRAKVUF_EGRESS_V1
```

Expect the count to plateau near the configured ceiling and the connlimit
rule's counter to climb.

**Both the rate rule and the connlimit rule will fire**, because 120 parallel
`curl`s exceed 20/sec as well. The rate rule sits first, so the connlimit
counter registers only what survived it — a non-zero value there is therefore
evidence the concurrency cap binds on its own account, not a side effect.

**Established connections must survive.** The rule matches `--ctstate NEW`, so
it refuses new attempts without severing traffic already in flight. Confirm a
connection opened before the burst is still alive.

```text
root@dom0:~/drakvuf-multios-sandbox# conntrack -L -s 172.16.2.0/24 2>/dev/null | wc -l
73
root@dom0:~/drakvuf-multios-sandbox# iptables -nvxL DRAKVUF_EGRESS_V2 | head -4
Chain DRAKVUF_EGRESS_V2 (1 references)
    pkts      bytes target     prot opt in     out     source               destination         
     298    17178 DROP       0    --  xenbr1.2 *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 20/sec burst 40 mode srcip
       0        0 DROP       0    --  xenbr1.2 *       0.0.0.0/0            0.0.0.0/0            limit: above 6mb/s burst 6mb mode srcip

```

Rerun with the full chain, which is what actually discharges the step:

```text
root@dom0:~/drakvuf-multios-sandbox# conntrack -L -s 172.16.1.0/24 2>/dev/null | wc -l
74
root@dom0:~/drakvuf-multios-sandbox# iptables -nvxL DRAKVUF_EGRESS_V1 
Chain DRAKVUF_EGRESS_V1 (1 references)
    pkts      bytes target     prot opt in     out     source               destination         
     292    16809 DROP       0    --  xenbr1.1 *       0.0.0.0/0            0.0.0.0/0            ctstate NEW limit: above 20/sec burst 40 mode srcip
       0        0 DROP       0    --  xenbr1.1 *       0.0.0.0/0            0.0.0.0/0            limit: above 6mb/s burst 6mb mode srcip
     241    14196 DROP       0    --  xenbr1.1 *       0.0.0.0/0            0.0.0.0/0            ctstate NEW #conn src/32 > 50
     386    41179 ACCEPT     0    --  xenbr1.1 xenbr0  0.0.0.0/0            0.0.0.0/0           
       0        0 ACCEPT     0    --  xenbr0 xenbr1.1  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
       0        0 DROP       0    --  *      *       0.0.0.0/0            0.0.0.0/0
```

> **FINDING — the concurrency cap binds.** 241 packets dropped by the connlimit
> rule, downstream of the 292 the rate rule had already taken. conntrack shows
> 74 entries against a ceiling of 50, which is the expected shape rather than a
> contradiction: `connlimit` refuses *new* connections beyond 50 while closed
> flows linger in the table until their timeout expires. The first attempt at
> this step read `head -4` and cut the connlimit line off entirely, which is
> why the command above prints the whole chain.

---

## Step 10 — nothing survives the job

```sh
# DOM0 — after the job has ended
iptables -S | grep -c DRAKVUF_EGRESS_V     # expect 0
ls /proc/net/ipt_hashlimit/                # expect no dv_v1_* entries
```

The per-VLAN chain is flushed and deleted by `argv_revoke`, which takes the
throttle rules with it — they need no teardown of their own. The hashlimit
tables are reference-counted by the kernel and should disappear with the last
rule naming them.

```text
root@dom0:~/drakvuf-multios-sandbox# iptables -S | grep -c DRAKVUF_EGRESS_V     # expect 0
0
root@dom0:~/drakvuf-multios-sandbox# ls /proc/net/ipt_hashlimit/                # expect no dv_v1_* entries
probe_bw_1   probe_bw_3  probe_new_10  probe_new_5
probe_bw_12  probe_bw_6  probe_new_20  probe_new_50
```

> **FINDING — teardown is clean.** Only the `probe_*` ladder entries remain;
> every `dv_v*` table went with its chain. A stale one would have meant the
> next clone on that VLAN inherited a partly-spent bucket, which is
> cross-sample contamination in the same shape DRAFT-033 removed from the disk
> path.

> **FINDING — the per-VLAN return-path rule is unreachable.** It reads **zero
> packets in every observation in this runbook**, while thousands left and the
> replies plainly arrived. It is not quiet; it cannot match. `DRAKVUF_ISOLATION`
> jumps into `DRAKVUF_EGRESS` only for traffic arriving **on** a clone
> interface:
>
> ```
> -A DRAKVUF_ISOLATION -i xenbr1.+ -j DRAKVUF_EGRESS
> -A DRAKVUF_ISOLATION -o xenbr1.+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
> ```
>
> A reply arrives on `xenbr0` and leaves *to* `xenbr1.<vlan>`, so it never
> matches the jump and is accepted by the isolation chain one line later. The
> rule is harmless redundancy; the comment above it in `sandboxd/egress.py` is
> not, because it attributes a safety property to a rule that is not providing
> it. Keep the rule as defence in depth against that ordering changing, and
> correct the comment to say so.

---

## Step 11 — `tor` and `simulated` are still unthrottled

Deliberate, not an oversight. Confirm it rather than assuming it.

```sh
# DOM0 — with a tor job running
iptables -S DRAKVUF_EGRESS_V1
iptables -t nat -S DRAKVUF_EGRESS_PRE_V1
```

Expect no `hashlimit` and no `connlimit` on either.

```text
# While running TOR and simulated at same time. Only probes exist

root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS
-N DRAKVUF_EGRESS
-A DRAKVUF_EGRESS -i xenbr1.+
-A DRAKVUF_EGRESS -i xenbr1.+ -m hashlimit --hashlimit-above 12mb/s --hashlimit-mode srcip --hashlimit-name probe_bw_12
-A DRAKVUF_EGRESS -i xenbr1.+ -m hashlimit --hashlimit-above 6mb/s --hashlimit-mode srcip --hashlimit-name probe_bw_6
-A DRAKVUF_EGRESS -i xenbr1.+ -m hashlimit --hashlimit-above 3mb/s --hashlimit-mode srcip --hashlimit-name probe_bw_3
-A DRAKVUF_EGRESS -i xenbr1.+ -m hashlimit --hashlimit-above 1mb/s --hashlimit-mode srcip --hashlimit-name probe_bw_1
-A DRAKVUF_EGRESS -i xenbr1.+ -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 50/sec --hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-name probe_new_50
-A DRAKVUF_EGRESS -i xenbr1.+ -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 20/sec --hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-name probe_new_20
-A DRAKVUF_EGRESS -i xenbr1.+ -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 10/sec --hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-name probe_new_10
-A DRAKVUF_EGRESS -i xenbr1.+ -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 5/sec --hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-name probe_new_5
root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS_V1
iptables: No chain/target/match by that name.
root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS_V2
iptables: No chain/target/match by that name.
```

> **This is the gap DRAFT-057 should stop claiming to have closed.** The
> issue's Tor override offers the Phase 5 throttles as the partial mitigation
> for the volunteer-exit-operator objection. With `tor` unthrottled that
> objection stands unmitigated, and the draft says so as of 2026-09-05.

---

## Step 12 — `routed` — NOT RUN, and deliberately so

**Abandoned rather than pending** (maintainer, 2026-09-05). The `router` DomU
was torn down by runbook 14 step 11 and was not rebuilt; nobody should wait for
evidence here.

The judgement behind it: the throttles are Dom0-side, installed by the same
`argv_apply` forwarding path for both modes, and they differ only in the
interface the permit names. `direct` and `routed` build the same six rules
because they are built by the same code, and steps 5–10 exercised that code.

```sh
# DOM0 — with a routed job running
iptables -S DRAKVUF_EGRESS_V1
```

Expect the three DROPs, then `-i xenbr1.1 -o wg0 -j ACCEPT`. **The permit must
still be the only ACCEPT, and it must still name `-o wg0`** — that is the
kill-switch, and the throttles sit above it precisely so they cannot change it.

```text
Not run. See above.
```

> **What that leaves unobserved.** That the throttles coexist with the
> `routed`-only machinery — the policy route, the `ip rule` selector, and the
> `-o wg0` permit — has not been seen on a live tunnel. `sandboxd/tests/`
> asserts the rule set for `routed` including the kill-switch invariant, so
> this is unobserved rather than unchecked, and the distinction belongs in
> DRAFT-057 rather than being quietly rounded up.

---

## Step 13 — remove the counting ladder

```sh
# DOM0
for r in 5 10 20 50; do
  iptables -w 5 -D DRAKVUF_EGRESS -i xenbr1.+ -m conntrack --ctstate NEW \
    -m hashlimit --hashlimit-above ${r}/sec --hashlimit-burst 40 \
      --hashlimit-mode srcip --hashlimit-name probe_new_${r}
done
for r in 1 3 6 12; do
  iptables -w 5 -D DRAKVUF_EGRESS -i xenbr1.+ \
    -m hashlimit --hashlimit-above ${r}mb/s \
      --hashlimit-mode srcip --hashlimit-name probe_bw_${r}
done
iptables -w 5 -D DRAKVUF_EGRESS -i xenbr1.+
iptables -S DRAKVUF_EGRESS                 # expect: back to step 1's output
```

```text
root@dom0:~/drakvuf-multios-sandbox# for r in 5 10 20 50; do
  iptables -w 5 -D DRAKVUF_EGRESS -i xenbr1.+ -m conntrack --ctstate NEW \
    -m hashlimit --hashlimit-above ${r}/sec --hashlimit-burst 40 \
      --hashlimit-mode srcip --hashlimit-name probe_new_${r}
done
root@dom0:~/drakvuf-multios-sandbox# for r in 1 3 6 12; do
  iptables -w 5 -D DRAKVUF_EGRESS -i xenbr1.+ \
    -m hashlimit --hashlimit-above ${r}mb/s \
      --hashlimit-mode srcip --hashlimit-name probe_bw_${r}
done
root@dom0:~/drakvuf-multios-sandbox# iptables -w 5 -D DRAKVUF_EGRESS -i xenbr1.+ 
root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS                 # expect: back to step 1's output
-N DRAKVUF_EGRESS

```

---

## What is left after this

Filed 2026-09-05. The steps above are done; these are not, and they are the
honest remainder rather than a wish list.

1. **Exercise the byte rule.** Step 8's KNOWN GAP. Needs `ESTABLISHED` traffic
   and a sink that will absorb tens of megabytes — the `routed` peer is the
   natural one, which makes this and step 12 a single future session.
2. **`routed` under throttles**, step 12, if that peer is rebuilt.
3. **Decide whether the constants need a second baseline.** Three of four are
   bounds rather than peaks (step 4). Rungs at 1/sec, 2/sec, 100kb/s and
   500kb/s would turn them into measurements. `MAX_PARALLEL_CONNS` at 1.8× over
   a Windows guest that has barely started is the one to watch.
4. **Correct the return-path comment in `sandboxd/egress.py`.** Step 10's
   finding: the rule is unreachable and the comment above it credits it with a
   guarantee `DRAKVUF_ISOLATION` is actually providing.

Anything that went wrong on the way is in `docs/TROUBLESHOOTING.md`, symptom
first — see
[Baseline measured against throttled code](../TROUBLESHOOTING.md#baseline-measured-against-throttled-code),
which came out of this run.