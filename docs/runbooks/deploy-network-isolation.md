# Runbook — deploy and test the DRAFT-028 network isolation

> **Issue:** DRAFT-028 (unpublished). **Status: executed 2026-08-11 on
> L1 / Xen Dom0 by evilbootloader. Steps 0–9 and 8b passed.** Step 10
> (returning Dom0 to master) runs after PR #8 merges.
>
> This file is the execution transcript and is now **append-only** —
> annotate, never edit.
>
> **Headline results.** Step 8's nine-row connectivity matrix passed. Step
> 8b proved the IPv6 gap was live rather than theoretical, with a
> `DRAKVUF_INPUT6` counter of 20 packets to show the rule fired.
>
> **NET-01 is confirmed, by a mechanism the draft did not anticipate.** The
> old `-o !xenbr0` rule was never rejected — it installed cleanly and
> stored `!xenbr0` as a literal interface name, so it matched nothing.
> **Inter-clone isolation has never worked in this project.** See the
> correction in step 2: the first reading of that step was wrong, and the
> answer came from a separate test.

## Read this before you start

**This is a live-network change on a host that carries your management
traffic.** It inserts rules at the head of both `FORWARD` and `INPUT`.

Two things make it safe, and you should confirm both rather than trust
them:

1. Every rule matches `-i xenbr1.+` — the analysis VLAN sub-interfaces
   only. An SSH session arriving on the LAN interface never matches, so it
   cannot be cut by these rules.
2. The full ruleset is captured in step 1 and restorable in one command.

**Do not run this while an analysis is in flight.** `network-setup.sh`
flushes and rebuilds the chains, so a clone mid-trace would briefly lose
its rules. Confirm with `xl list` that no `*-clone` domain exists.

**The change under test is on a branch, not `master`** — step 3 checks out
`draft-028-network-isolation` ([PR #8](https://github.com/evilbootloader/drakvuf-multios-sandbox/pull/8))
and **step 10 puts Dom0 back**. Between those two steps the host is running
unmerged code, so if you stop partway through, jump to step 10 first.

Keep a second terminal open to Dom0 throughout.

## What is being deployed

`automation/network-setup.sh` rewritten. The posture it installs:

```text
clone -> clone            DROP    two independent rules
clone -> LAN / RFC1918    DROP    incl. the router admin interface
clone -> link-local       DROP    incl. 169.254.169.254 metadata
clone -> Dom0 itself      DROP    replies to Dom0-initiated traffic allowed
clone -> Internet         ALLOW   MASQUERADE out the uplink
```

Plus: `set -eu` so a rejected rule aborts, argument validation, a bridge
existence check, `vconfig` replaced by `ip link add … type vlan`, and
three dedicated chains flushed and rebuilt each run so re-launching
converges instead of appending. `run_analysis-ubuntu.sh` now aborts if
provisioning fails.

---

## Step 0 — Preconditions

```bash
sudo xl list                       # expect: no *-clone domains
ps -ef | grep -E 'dirwatch|drakvuf|injector' | grep -v grep   # expect: none
git -C /root/sandbox_project log -1
git -C /root/sandbox_project branch --show-current   # expect: master
git -C /root/sandbox_project status --porcelain      # expect empty
```

Record the branch as well as the commit — step 3 moves off `master` and
step 10 moves back, and knowing where you started is what makes that safe.

```text
Date / operator: 2026-08-11 / evilbootloader
Analyses in flight (must be none): 0
Branch before: (HEAD -> master, origin/master, origin/HEAD)
Deployed commit before: commit 489b3b9b4834b83da0f70eb2a2cc02efcca06606
Working tree clean: clean
```

## Step 1 — Capture the rollback FIRST

Nothing else happens until this file exists.

```bash
sudo iptables-save  > /root/iptables-pre-DRAFT-028.rules
sudo ip6tables-save > /root/ip6tables-pre-DRAFT-028.rules
ls -l /root/iptables-pre-DRAFT-028.rules
ls -l /root/ip6tables-pre-DRAFT-028.rules
```

```text
Rollback file written: yes
Size:
ls -l /root/iptables-pre-DRAFT-028.rules
ls -l /root/ip6tables-pre-DRAFT-028.rules
-rw-r--r-- 1 root root 182 ago 11 19:20 /root/iptables-pre-DRAFT-028.rules
-rw-r--r-- 1 root root 0 ago 11 19:20 /root/ip6tables-pre-DRAFT-028.rules
```

## Step 2 — The NET-01 evidence, before changing anything

**This is the question the old code could not answer, and it is only
answerable now.** The previous rule was written `-o !xenbr0`, the negation
form deprecated in iptables 1.4.3 (2008). Current versions parse `!xenbr0`
as an interface name. Nothing checked the exit status, so if it was being
rejected there has never been any inter-clone isolation — and no analysis
run to date was protected by the mechanism the docs describe.

```bash
sudo iptables -S FORWARD
sudo iptables -t nat -S POSTROUTING
sudo iptables -S FORWARD | grep -c xenbr1 || true
sudo iptables --version
```

Read the output against these two cases:

- **DROP rules present, one per VLAN** → the old syntax was accepted on
  this iptables build. Isolation has been working. NET-01 was a latent
  portability defect, not a live one.
- **No DROP rules, or fewer than the clone count** → the rule was rejected.
  **Inter-clone isolation has never existed on this host.** Record that
  plainly; it changes what past runs were protected by.

Also count the duplicates — `run_analysis-ubuntu.sh` has appended a fresh
`MASQUERADE` on every launch since the beginning (NET-05):

```bash
sudo iptables -t nat -S POSTROUTING | grep -c MASQUERADE
```

```text
iptables version: v1.8.7
FORWARD rules mentioning xenbr1 (count): 0
Per-VLAN DROP rules present?  no
Duplicate MASQUERADE count: 0
Full `iptables -S FORWARD` output:
root@drakvuf:~/sandbox_project# iptables -S FORWARD
-P FORWARD ACCEPT

Full `iptables -t nat -S POSTROUTING` output:
root@drakvuf:~/sandbox_project# iptables -t nat -S POSTROUTING
-P POSTROUTING ACCEPT
```

> **Correction and resolution, 2026-08-11. Read both halves — the first
> reading of this step was wrong, and the eventual answer is worse than
> the draft predicted.**
>
> **The output above does not answer NET-01.** The empty `FORWARD` chain
> looks like proof the old rule was rejected. It is not: **`POSTROUTING`
> was empty too**, and `MASQUERADE` is valid syntax that would have
> installed without complaint. Its absence means only that
> `network-setup.sh` had not run since the host last booted — iptables
> rules are runtime state and nothing in this project persists them. The
> missing DROP rules are explained entirely by the script not having run.
>
> **Answered separately, the same day.** Two attempts were needed:
>
> ```text
> # First attempt, interactively in bash:
> $ sudo iptables -A FORWARD -i xenbr1.1 -o !xenbr0 -j DROP
> bash: !xenbr0: event not found
> ```
>
> That is bash history expansion consuming the `!` before iptables sees
> it — an interactive-shell behaviour. `network-setup.sh` runs under
> `/bin/sh` (dash), which has no history expansion, so reproducing the
> production path means going through `sh`:
>
> ```text
> $ sudo sh -c 'iptables -A FORWARD -i xenbr1.1 -o !xenbr0 -j DROP' ; echo "rc=$?"
> rc=0
> $ sudo iptables -S FORWARD | grep xenbr1
> -A FORWARD -i xenbr1.1 -o !xenbr0 -j DROP
> ```
>
> **The rule was accepted, not rejected — and that is the bad outcome.**
> Compare the rendering against the replacement installed in step 5:
>
> ```text
> old:  -A FORWARD -i xenbr1.1 -o !xenbr0 -j DROP
> new:  -A DRAKVUF_ISOLATION -i xenbr1.+ ! -o xenbr0 -j DROP
> ```
>
> `iptables -S` normalises genuine negation to `! -o xenbr0`. The old rule
> printed `-o !xenbr0`, so `!xenbr0` was stored as a **literal interface
> name** — an interface that has never existed on this host. The rule
> matched nothing, ever.
>
> **NET-01 verdict: confirmed, by a mechanism the draft did not
> anticipate.** DRAFT-028 hypothesised the rule would be *rejected*, and
> reasoned that the missing exit-status check (NET-05) was what let the
> failure pass unnoticed. Reality is worse: the command **succeeded**, the
> rule appears in `iptables -S`, and it is semantically inert. No
> exit-status check would ever have caught it, because there was no error
> to catch. Only a packet counter or a live connectivity test would have —
> which is exactly what step 8 is, and why "fix before measuring" was the
> right order.
>
> **Consequence for the historical record: inter-clone isolation has never
> worked in this project.** Every analysis run before 2026-08-11 had the
> rule present and doing nothing. This must be reflected in
> `docs/checklists/android.md` §1.3 and the roadmap risk register, not
> quietly superseded by the fix.

## Step 3 — Check out the branch under test

Deployment is a checkout, not a copy (issue #4). Do not edit the deployed
scripts in place — that is how the drift issue #2 diagnosed happened.

**This change is on a branch, not `master`.** `git pull` alone would fetch
`master` and leave the old script in place, so the test would silently
measure unchanged code. Fetch and check out the branch explicitly:

```bash
cd /root/sandbox_project

# The deploy key is read-only, which is all fetch needs.
git fetch origin

# First time on this branch:
git checkout -b draft-028-network-isolation origin/draft-028-network-isolation

# If the branch already exists locally from an earlier attempt, use this
# instead, and re-fetch to pick up any new commits:
#   git checkout draft-028-network-isolation
#   git reset --hard origin/draft-028-network-isolation
```

Confirm you are actually on it and the script really changed — a checkout
that silently failed looks identical to one that worked until the rules
come out wrong:

```bash
git -C /root/sandbox_project branch --show-current    # expect: draft-028-network-isolation
git -C /root/sandbox_project log -1 --oneline
git -C /root/sandbox_project status --porcelain       # expect empty
head -1 /root/sandbox_project/automation/network-setup.sh   # expect #!/bin/sh
grep -c DRAKVUF_ISOLATION /root/sandbox_project/automation/network-setup.sh
```

The last command must return a non-zero count. If it returns 0 you are
still on the old script, and everything below would measure the wrong
thing.

```text
Branch after checkout: draft-028-network-isolation
Commit after checkout: 32b1ac1
Working tree clean: yes
DRAKVUF_ISOLATION mentions (must be > 0): 4
```

> **Dom0 is now on an unmerged branch.** Anything that starts an analysis
> before step 10 runs unreviewed code. If you stop partway through this
> runbook, go to step 10 first.

## Step 4 — Failure modes first, while nothing is provisioned

Prove the script refuses bad input before trusting it with good input.
None of these should change any rule.

```bash
cd /root/sandbox_project/automation

sudo ./network-setup.sh          ; echo "exit=$?  (expect 1: usage)"
sudo ./network-setup.sh abc      ; echo "exit=$?  (expect 1: not an integer)"
sudo ./network-setup.sh 0        ; echo "exit=$?  (expect 1: must be >= 1)"
sudo ./network-setup.sh 2 extra  ; echo "exit=$?  (expect 1: usage)"
```

Each must print a `network-setup.sh:` message and exit 1. The old script
exited 0 for all four and silently provisioned nothing.

```text
root@drakvuf:~/sandbox_project/automation# sudo ./network-setup.sh          ; echo "exit=$?  (expect 1: usage)"
network-setup.sh: usage: ./network-setup.sh <number of clone slots>
network-setup.sh: FAILED during: argument validation (exit 1)
exit=1  (expect 1: usage)
root@drakvuf:~/sandbox_project/automation# sudo ./network-setup.sh abc      ; echo "exit=$?  (expect 1: not an integer)"
network-setup.sh: clone count must be a positive integer, got: 'abc'
network-setup.sh: FAILED during: argument validation (exit 1)
exit=1  (expect 1: not an integer)
root@drakvuf:~/sandbox_project/automation# sudo ./network-setup.sh 0        ; echo "exit=$?  (expect 1: must be >= 1)"
network-setup.sh: clone count must be at least 1, got: 0
network-setup.sh: FAILED during: argument validation (exit 1)
exit=1  (expect 1: must be >= 1)
root@drakvuf:~/sandbox_project/automation# sudo ./network-setup.sh 2 extra  ; echo "exit=$?  (expect 1: usage)"
network-setup.sh: usage: ./network-setup.sh <number of clone slots>
network-setup.sh: FAILED during: argument validation (exit 1)
exit=1  (expect 1: usage)
```

## Step 5 — Provision

```bash
sudo ./network-setup.sh 2 ; echo "exit=$? (expect 0)"
```

```text
exit= 0
stdout: exit=0 (expect 0)
```

Now inspect what it built. This output is what DRAFT-013 will assert
against, so capture it in full:

```bash
sudo iptables -S DRAKVUF_ISOLATION
sudo iptables -S DRAKVUF_INPUT
sudo iptables -t nat -S DRAKVUF_NAT
sudo iptables -S FORWARD | head -3     # jump should be at position 1
sudo iptables -S INPUT   | head -3     # jump should be at position 1
ip -br addr show | grep xenbr1
```

Expected `DRAKVUF_ISOLATION`: one clone-to-clone DROP plus four
destination DROPs — five rules, independent of clone count.

```text
DRAKVUF_ISOLATION:
root@drakvuf:~/sandbox_project/automation# sudo iptables -S DRAKVUF_ISOLATION
-N DRAKVUF_ISOLATION
-A DRAKVUF_ISOLATION -i xenbr1.+ ! -o xenbr0 -j DROP
-A DRAKVUF_ISOLATION -d 10.0.0.0/8 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 172.16.0.0/12 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 192.168.0.0/16 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 169.254.0.0/16 -i xenbr1.+ -j DROP

DRAKVUF_INPUT:
root@drakvuf:~/sandbox_project/automation# sudo iptables -S DRAKVUF_INPUT
-N DRAKVUF_INPUT
-A DRAKVUF_INPUT -i xenbr1.+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DRAKVUF_INPUT -i xenbr1.+ -j DROP

DRAKVUF_NAT:
root@drakvuf:~/sandbox_project/automation# sudo iptables -t nat -S DRAKVUF_NAT
-N DRAKVUF_NAT
-A DRAKVUF_NAT -o xenbr0 -j MASQUERADE

FORWARD head:
root@drakvuf:~/sandbox_project/automation# sudo iptables -S FORWARD | head -3     # jump should be at position 1
-P FORWARD ACCEPT
-A FORWARD -j DRAKVUF_ISOLATION

INPUT head:
root@drakvuf:~/sandbox_project/automation# sudo iptables -S INPUT   | head -3     # jump should be at position 1
-P INPUT ACCEPT
-A INPUT -j DRAKVUF_INPUT

VLAN interfaces:
root@drakvuf:~/sandbox_project/automation# ip -br addr show | grep xenbr1
xenbr1           UNKNOWN        fe80::f4f1:81ff:febf:3b4a/64 
xenbr1.1@xenbr1  UP             172.16.1.1/24 fe80::f4f1:81ff:febf:3b4a/64 
xenbr1.2@xenbr1  UP             172.16.2.1/24 fe80::f4f1:81ff:febf:3b4a/64
```

## Step 6 — Idempotence

The defect being fixed: every launch used to append another `MASQUERADE`
and another DROP.

```bash
snap() { sudo iptables-save | grep -v '^#'; }

snap > /tmp/rules-1
sudo ./network-setup.sh 2 >/dev/null && snap > /tmp/rules-2
sudo ./network-setup.sh 2 >/dev/null && snap > /tmp/rules-3

diff /tmp/rules-1 /tmp/rules-2 &&
diff /tmp/rules-2 /tmp/rules-3 &&
echo "CONVERGED: identical rulesets across three runs"
```

`diff` rather than `wc -l`, and `grep -v '^#'` rather than raw output —
both matter:

- A line count catches a ruleset that **grows**, which is the specific
  defect here, but not one that **changes**. A rule replaced by a different
  rule keeps the count identical, and that is exactly what a subtly wrong
  flush-and-rebuild looks like.
- `iptables-save` emits `# Generated by …` and `# Completed on …` lines
  carrying timestamps, so a raw `diff` would report a difference on every
  run regardless of the rules. Stripping comments is what makes the
  comparison mean anything.

```text
Line counts from the first attempt (wc -l method): 29
diff run1 vs run2:
diff run2 vs run3:
CONVERGED printed?
```

> **Method corrected 2026-08-11, during execution.** The step originally
> compared `sudo iptables-save | wc -l` three times. That is a weaker test
> than it looks: it detects growth but not substitution, and the recorded
> result was a single number, which cannot show whether all three runs
> agreed. Re-run with the `diff` form above and record all three outputs.

## Step 7 — Missing-bridge failure

Only if you can afford to take `xenbr1` down briefly. Deleting the bridge
takes its VLAN sub-interfaces with it, so there must still be no analysis
running.

```bash
sudo ovs-vsctl del-br xenbr1
sudo ./network-setup.sh 2 ; echo "exit=$? (expect 1)"

# recreate and re-provision:
sudo ovs-vsctl add-br xenbr1
sudo ./network-setup.sh 2 ; echo "exit=$? (expect 0)"
ip -br addr show | grep xenbr1
```

> **Corrected 2026-08-11, during execution.** This step originally read
> `sudo ip link set xenbr1 down && sudo ip link delete xenbr1 2>/dev/null
> || true`. `xenbr1` is an **OVS** bridge, so `ip link delete` cannot
> remove it — and the trailing `|| true` would have swallowed the failure.
> The bridge would still have been present, `network-setup.sh 2` would have
> exited 0, and a pass would have been recorded for a test that never ran:
> a false pass on the one step whose entire purpose is proving the script
> fails safely. `ovs-vsctl del-br` is the correct removal and is what was
> actually executed.

```text
Message when bridge absent:
root@drakvuf:~/sandbox_project/automation# ovs-vsctl del-br xenbr1
See docs/drakvuf-on-xen-nested-within-proxmox.md.
network-setup.sh: FAILED during: checking xenbr1 exists (exit 1)
exit=1 (expect 0)

Recovered:
root@drakvuf:~/sandbox_project/automation# sudo ovs-vsctl add-br xenbr1
sudo ./network-setup.sh 2 ; echo "exit=$? (expect 0)"
DRAKVUF_NAT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_ISOLATION  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_INPUT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
network-setup.sh: provisioned 2 VLAN sub-interface(s) on xenbr1
exit=0 (expect 0)
```

## Step 8 — Live connectivity matrix

The acceptance test. Two disposable clones, benign, on different VLANs.

Build them from the Ubuntu sandbox template the same way §1.5's restore
validation does — a snapshot LV per clone, a `.cfg` naming its own VLAN
sub-interface. **Do not use the golden domain.**

Give clone A `172.16.1.2/24` gw `172.16.1.1`, clone B `172.16.2.2/24`
gw `172.16.2.1`.

From **inside clone A**, with a short timeout on each so a DROP shows as a
timeout rather than a hang:

| # | Command | Expected |
|---|---|---|
| 1 | `ping -c2 -W2 172.16.2.2` | **blocked** — clone-to-clone |
| 2 | `ping -c2 -W2 172.16.1.1` | **blocked** — Dom0 gateway |
| 3 | `curl -m5 http://172.16.1.1/` | **blocked** — Dom0 services |
| 4 | `ping -c2 -W2 192.168.1.1` | **blocked** — router |
| 5 | `curl -m5 http://192.168.1.1/` | **blocked** — router admin |
| 6 | `curl -m5 https://192.168.1.1/` | **blocked** — router admin |
| 7 | `ping -c2 -W2 192.168.1.<a real LAN host>` | **blocked** — LAN |
| 8 | `curl -m5 -o /dev/null -w '%{http_code}\n' https://1.1.1.1/` | **works** — Internet |
| 9 | `getent hosts example.com` | **works** — DNS via 1.1.1.1 |

Rows 8 and 9 are as important as the blocks: they prove the RFC1918 denial
did not cost Internet access.

From **Dom0**, confirming the `ESTABLISHED,RELATED` exception:

| # | Command | Expected |
|---|---|---|
| 10 | `ping -c2 -W2 172.16.1.2` | **works** — Dom0-initiated, reply allowed back |

```bash
# Used command for configuring networking as replace default route did not work (we should check preconfig-ubuntu.sh as it does not get Internet the analysis VM I think)
NETCFG="sudo ip addr flush dev eth0 && sudo ip addr add 172.16.$VLAN.2/24 dev eth0 && sudo ip route set default via 172.16.$VLAN.1 dev eth0 && echo 'nameserver $GUEST_NAMESERVER' | sudo tee /etc/resolv.conf"
```

```text
 1 clone A -> clone B: No
 2 clone A -> gateway ping: No
 3 clone A -> gateway HTTP: No
 4 clone A -> router ping: NO
 5 clone A -> router :80: No
 6 clone A -> router :443: No 
 7 clone A -> LAN host: No
 8 clone A -> 1.1.1.1 HTTPS: Yes
 9 clone A -> DNS: Yesip a
10 Dom0 -> clone A ping:  Yes

Counter check (which rules actually fired):
user@drakvuf:~$ sudo iptables -L DRAKVUF_ISOLATION -v -n
[sudo] password for user: 
Chain DRAKVUF_ISOLATION (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    3   252 DROP       all  --  xenbr1.+ !xenbr0  0.0.0.0/0            0.0.0.0/0           
    0     0 DROP       all  --  xenbr1.+ *       0.0.0.0/0            10.0.0.0/8          
    0     0 DROP       all  --  xenbr1.+ *       0.0.0.0/0            172.16.0.0/12       
   14  1032 DROP       all  --  xenbr1.+ *       0.0.0.0/0            192.168.0.0/16      
    0     0 DROP       all  --  xenbr1.+ *       0.0.0.0/0            169.254.0.0/16      
user@drakvuf:~$ sudo iptables -L DRAKVUF_INPUT -v -n
Chain DRAKVUF_INPUT (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    2   168 ACCEPT     all  --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
  112 20285 DROP       all  --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0       

```

Then destroy both clones and remove their LVs.

## Step 8b — IPv6 (added 2026-08-11, after the first pass)

Added because step 8's DNS check returned an **AAAA** record, which raised
the question of what a clone could do with IPv6 — and the answer was
"anything", since every rule above is `iptables` and therefore IPv4 only.

**Re-pull first**: this step tests commit `5eb037a`, which is newer than
the one step 3 checked out.

```bash
git -C /root/sandbox_project pull
git -C /root/sandbox_project log -1 --oneline    # expect 5eb037a or later
grep -c DRAKVUF_ISOLATION6 /root/sandbox_project/automation/network-setup.sh
```

First confirm `ip6tables` is actually usable — step 1's
`ip6tables-pre-DRAFT-028.rules` came out **0 bytes**, which is ambiguous
between "no rules" and "command failed":

```bash
command -v ip6tables ip6tables-save
sudo ip6tables -S 2>&1 | head
sysctl net.ipv6.conf.all.disable_ipv6
```

Then re-provision and inspect:

```bash
cd /root/sandbox_project/automation
sudo ./network-setup.sh 2 ; echo "exit=$? (expect 0)"
sudo ip6tables -S DRAKVUF_ISOLATION6
sudo ip6tables -S DRAKVUF_INPUT6
sudo ip6tables -S FORWARD | head -3
sudo ip6tables -S INPUT   | head -3
```

If `ip6tables` is missing **and** IPv6 is not disabled kernel-wide, the
script must now **fail** with a message naming both remedies. That is the
intended behaviour, not a regression — record the message if it happens.

Then the live test. Restore a clone and give it back the IPv6 the
production chain removes, which is exactly what a sample would do:

```bash
D=ubuntu_sandbox-1-clone
P=/root/sandbox_project/profiles/linux.json

sudo /root/sandbox_project/automation/clone-ubuntu.pl \
    ubuntu_sandbox 1 /root/sandbox_project/misc/ubuntu_sandbox.cfg
sudo xl unpause "$D"

sudo injector -r "$P" -d "$D" -i 1415 -m execproc -e /usr/bin/sh -f "-c" \
  -f "{ echo '=== regenerate link-local, as a sample would ==='; sudo ip link set eth0 down; sudo ip link set eth0 up; sleep 3; ip -6 addr show eth0; echo '=== Dom0 gateway link-local ==='; ip -6 route; echo '=== can we reach Dom0 over v6? ==='; ping6 -c2 -W2 -I eth0 fe80::f4f1:81ff:febf:3b4a; echo \"dom0 v6 rc=\$?\"; echo '=== can we reach the Internet over v6? ==='; ping6 -c2 -W2 2606:4700:4700::1111; echo \"internet v6 rc=\$?\"; } > /tmp/v6test 2>&1"

sudo injector -r "$P" -d "$D" -i 1415 -m readfile -e /tmp/v6test -B /tmp/v6test.out
cat /tmp/v6test.out
```

Substitute the real `fe80::` address of `xenbr1.1` from step 5's
`ip -br addr show` output — it is host-specific.

Both `ping6` results must fail. A clone that regenerates its link-local
and still cannot reach Dom0 is the property this section exists to
establish; **the counter on `DRAKVUF_INPUT6` moving is the positive
evidence**, since "unreachable" alone could just mean IPv6 never came up:

```bash
sudo ip6tables -L DRAKVUF_INPUT6 -v -n
sudo ip6tables -L DRAKVUF_ISOLATION6 -v -n
```

```text
ip6tables available? Yes
ip6tables -S output before:
root@drakvuf:~/sandbox_project# command -v ip6tables ip6tables-save
sudo ip6tables -S 2>&1 | head
sysctl net.ipv6.conf.all.disable_ipv6
/usr/sbin/ip6tables
/usr/sbin/ip6tables-save
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT

sysctl disable_ipv6:
net.ipv6.conf.all.disable_ipv6 = 0

network-setup.sh exit after re-pull: 0
DRAKVUF_ISOLATION6: 
-N DRAKVUF_ISOLATION6
-A DRAKVUF_ISOLATION6 -i xenbr1.+ -j DROP

DRAKVUF_INPUT6:
-N DRAKVUF_INPUT6
-A DRAKVUF_INPUT6 -i xenbr1.+ -j DROP

Link-local regenerated on eth0?  yes   (expect: yes, an fe80:: address)
clone -> Dom0 fe80:: (expect fail): 
::1 dev lo proto kernel metric 256 pref medium
fe80::/64 dev eth0 proto kernel metric 100 pref medium
=== can we reach Dom0 over v6? ===
ping6: Warning: source address might be selected on device other than: eth0
PING fe80::f4f1:81ff:febf:3b4a(fe80::f4f1:81ff:febf:3b4a) from :: eth0: 56 data bytes

--- fe80::f4f1:81ff:febf:3b4a ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1028ms
dom0 v6 rc=1

clone -> Internet v6 (expect fail):
=== can we reach the Internet over v6? ===
ping6: connect: Network is unreachable
internet v6 rc=2

DRAKVUF_INPUT6 packet counter: 
   20  2397 DROP       all      xenbr1.+ *       ::/0                 ::/0                

DRAKVUF_ISOLATION6 packet counter:
    0     0 DROP       all      xenbr1.+ *       ::/0                 ::/0                
```

Then destroy the clone and remove its LV.

## Step 9 — One benign end-to-end analysis

Proves `dirwatch` still drives the pipeline with the launcher's new
exit-status check in place.

```bash
sudo /root/sandbox_project/automation/run_analysis-ubuntu.sh
# drop the benign fixture into /malware_incoming/ubuntu/
root@drakvuf:~# sudo /root/sandbox_project/automation/run_analysis-ubuntu.sh
DRAKVUF_NAT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_ISOLATION  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_INPUT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
network-setup.sh: provisioned 2 VLAN sub-interface(s) on xenbr1
DRAKVUF dirwatch v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel
```

```text
Provisioning step exit status: 0
Analysis completed normally: Yes
drakvuf.log line count: 92590
Result directory: /malware_finished/ubuntu/107529d281ee10a684e91342f0bb19df
```

## Step 10 — Return Dom0 to a merged branch

**Do not skip this, and do not leave it for later.** Dom0 is the host that
runs real analyses; leaving it on an unmerged branch means the next run
executes unreviewed code, and nothing about the checkout announces itself.

> **Order matters: merge PR #8 BEFORE running this step.** The commands
> below do `git checkout master && git pull`, which only brings the
> DRAFT-028 commits down once they are *on* master. Run it against an
> unmerged master and Dom0 reverts to the **old** `network-setup.sh` while
> the **new** chains are still installed — the one combination nothing has
> tested, and the one the "test failed" path below exists to clean up.
>
> Check first:
>
> ```bash
> git -C /root/sandbox_project fetch origin
> git -C /root/sandbox_project log origin/master --oneline -1
> ```
>
> If that does not show the DRAFT-028 commits, stop and merge first.

If the test **passed** and PR #8 has been merged:

```bash
cd /root/sandbox_project
git fetch origin
git checkout master
git pull
git branch -d draft-028-network-isolation
git log -1 --oneline                    # should now contain the DRAFT-028 commit
grep -c DRAKVUF_ISOLATION automation/network-setup.sh   # still > 0, now from master
```

If the test **failed**, or the PR is not merged yet:

```bash
cd /root/sandbox_project
git checkout master
git status --porcelain                  # expect empty
head -1 automation/network-setup.sh
```

Then re-run the old provisioning so the host is not left with the new
chains and the old script, which is the one combination nothing has
tested:

```bash
sudo iptables-restore < /root/iptables-pre-DRAFT-028.rules
sudo /root/sandbox_project/automation/network-setup.sh 2
```

```text
Branch after:
Commit after:
PR merged at time of return?   yes / no
Ruleset restored?
```

## Rollback

At any point:

```bash
sudo iptables-restore < /root/iptables-pre-DRAFT-028.rules
cd /root/sandbox_project && git checkout master
```

Complete and immediate, because the full ruleset was captured in step 1
before anything changed and the deployed code is a checkout rather than an
edited copy. No LVM, Xen domain or guest state is touched by any step
except 8, which uses disposable clones.

The one state that does **not** roll back automatically is the branch
checkout — hence step 10.

---

## After execution

1. Record the step 2 answer in `docs/checklists/android.md` §1.3 and the
   roadmap risk register. **If the old rule was never installed, say so
   plainly** — prior analysis runs were not protected by the isolation the
   documentation claimed.
2. Fill §1.3's six-row isolation table from step 8. That table is
   DRAFT-013's deliverable and the Android checklist's `Current blocker`;
   step 8 is most of what it asks for.
3. Update `docs/checklists/ubuntu.md` with the deployment evidence.
4. Publish DRAFT-028 as a GitHub issue and close it with this transcript,
   per `CONTRIBUTING.md`'s two-stage gate.

## Security

Step 8 rows 1–7 are the first direct evidence of clone containment this
project has ever had. Until they are recorded, containment remains
**unverified** — DRAFT-013 — and no non-benign sample should run with
networking enabled.

What this deployment does **not** establish, and must not be read as
establishing: no terminal policy is set on `FORWARD` or `INPUT`
themselves, so the chains fall through to whatever the host already has.
That is DRAFT-029.

> *Annotation appended 2026-08-12 — the record above is unchanged.*
> DRAFT-029 has since been implemented, and answered this differently than
> the sentence anticipates: the built-in policies are still not set, and
> deliberately never will be by `network-setup.sh`. Instead the
> `DRAKVUF_*` chains were made terminal, so nothing falls through in the
> first place. See `docs/architecture/networking.md`, "Why the chains are
> terminal". This deployment's measurements are unaffected — they were
> taken with `-P FORWARD ACCEPT`, and the change makes that irrelevant
> rather than untrue.