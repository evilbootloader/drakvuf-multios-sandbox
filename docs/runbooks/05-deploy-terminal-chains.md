# Runbook — deploy and test the DRAFT-029 terminal chains

> **Issue:** [#9](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/9)
> (DRAFT-029). **PR:** [#10](https://github.com/evilbootloader/drakvuf-multios-sandbox/pull/10),
> branch `draft-029-terminal-chains`.
>
> **Status: executed 2026-08-12 on L1 / Xen Dom0 by evilbootloader. Steps 0
> through 8 passed.** Step 9 (returning Dom0 to `master`) runs after PR #10
> merges.
>
> This file is now the execution transcript and is **append-only** —
> annotate, never edit.
>
> **Headline result.** The acceptance criterion is met: with the new script,
> the four in-guest probes behave identically under `-P FORWARD ACCEPT` and
> `-P FORWARD DROP`. Under the old script the same policy flip took the
> clone's Internet access away (step 2c). Containment no longer depends on
> a policy nothing in `automation/` sets or checks.
>
> **The 2026-08-12 `iptables-nft` "readback failure" was never a failure.**
> Established later the same day: `iptables -S` reports any nonexistent
> chain as "incompatible" on this host, and the chains did not exist because
> the host had rebooted. Steps 0b and 2b were built to diagnose a phantom,
> and the write-up asserted that filtering was still live when in fact there
> was none. Both are corrected in annotations below — F2 withdrawn, F2′
> recorded in its place. F1, two live iptables backends, stands and is
> independent.
>
> **One code change was added mid-run**, from step 7: `network-setup.sh` had
> no upper bound on the clone count, so `999999` built 255 VLAN interfaces
> before failing on the 256th address, and left them behind. Finding F3,
> fixed in this PR; the leftover-interface half is F4 and is not.

## Read this before you start

**This is a live-network change on a host that carries your management
traffic**, and unlike DRAFT-028 it asks you to change a built-in chain
policy by hand in step 5.

Three things make it safe. Confirm them rather than trusting them:

1. Every rule the script installs matches `-i` or `-o xenbr1.+` — the
   analysis VLAN sub-interfaces only. An SSH session arriving on the LAN
   interface never matches, so the script cannot cut it.
2. **Step 5 is different**: `-P FORWARD DROP` is host-wide, not scoped.
   `FORWARD` governs *routed* traffic, so an SSH session terminating on
   Dom0 itself traverses `INPUT` and is unaffected — but if Dom0 routes
   anything else you care about, that stops for the duration of the step.
   Have the Proxmox console to the L1 guest open before you run it.
3. The full ruleset is captured in step 1 and restorable in one command.

**Do not run this while an analysis is in flight.** The script flushes and
rebuilds the chains. Confirm with `xl list` that no `*-clone` domain
exists.

**The change under test is on a branch, not `master`** — step 3 checks out
`draft-029-terminal-chains` and **step 9 puts Dom0 back**. Between those
two steps the host runs unmerged code, so if you stop partway through, jump
to step 9 first.

Keep a second terminal open to Dom0 throughout.

## Reading the chains on this host

**Dom0's `iptables` is `iptables-nft` (v1.8.7), a translation layer over
nftables — not the legacy `iptables` engine.** On 2026-08-12, before any
part of this runbook was deployed, both readback commands failed:

```text
root@drakvuf:/home/user# sudo iptables -S DRAKVUF_ISOLATION
iptables v1.8.7 (nf_tables): chain `DRAKVUF_ISOLATION' in table `filter' is incompatible, use 'nft' tool.

root@drakvuf:/home/user# sudo ip6tables -S DRAKVUF_ISOLATION6
ip6tables v1.8.7 (nf_tables): chain `DRAKVUF_ISOLATION6' in table `filter' is incompatible, use 'nft' tool.
```

Two things this does **not** mean, and they matter for how you read the
rest of this file:

1. **Filtering has not stopped.** nftables is the packet engine. The rules
   live in the kernel's nft ruleset and are still evaluated. `iptables`
   is refusing to *render the chain back to you*, which is a readback
   problem, not an enforcement one.
2. **It is not caused by this branch.** Those commands ran against the
   deployed DRAFT-028 chains, before step 3 checks anything out. Whatever
   the cause, it predates the change under test.

The same commands worked on 2026-08-11 (`04-deploy-network-isolation.md`,
step 5), so something changed on the host in between.

> ## ANNOTATION 2026-08-12 — the two numbered claims above are WRONG
>
> *Appended, not edited: the text above records what was believed at the time,
> and the error in it is the most instructive thing in this runbook.*
>
> **There was no readback failure.** `iptables -S` on this host reports any
> chain that does not exist as "incompatible", so the message meant only that
> **the chains did not exist** — the host had been rebooted and
> `network-setup.sh` had not been run since. Nothing changed between the 11th
> and the 12th.
>
> 1. **"Filtering has not stopped" was false, and dangerously so.** Filtering
>    had stopped completely: no rules, no chains, no VLAN interfaces.
> 2. **"Those commands ran against the deployed DRAFT-028 chains" was false.**
>    They ran post-reboot against nothing, inferred from the order of messages
>    in a conversation rather than from any timestamp.
>
> Both the technical trap and the reasoning error are in TROUBLESHOOTING:
> [chain absent vs unreadable](../TROUBLESHOOTING.md#iptables--s-says-a-chain-is-incompatible-and-the-chain-is-simply-absent),
> [asserting containment without testing](../TROUBLESHOOTING.md#a-containment-claim-was-written-up-without-being-tested).
> Carried into DRAFT-038 as **F2′**, which is why that issue's first
> verification property is "the chain exists and holds the expected rules"
> rather than "the chain is readable".
>
> Steps 0b and 2b were chasing a phantom. They are left in place because what
> they *did* establish is real: F1 (two live iptables backends), and the first
> hard evidence that the `-C` guards work and jumps do not accumulate.

### The host was then rebooted (2026-08-12)

**`network-setup.sh` has not been run since.** Nothing re-creates the
chains at boot — no `iptables-persistent`, no systemd unit; they are built
by `run_analysis-ubuntu.sh` at launch — so the current state is:

- no `DRAKVUF_*` chains in any table;
- no `xenbr1.<n>` VLAN sub-interfaces (the script's own comment notes they
  persist only until reboot);
- `ip_forward` back to the kernel/sysctl default;
- `xenbr1` itself most likely still present, since OVS keeps its bridges in
  a database across reboots — step 0 checks rather than assumes.

**This is good for the test, and it changes the order of this runbook.**

Two consequences. First, the diagnostic cannot run against chains that do
not exist: step 0b keeps only the parts that work on a clean host, and the
chain-reading parts move into step 2, after provisioning re-creates them.

Second — and this is the useful part — **the reboot turns the
incompatibility into a cleanly answerable question.** Provisioning with the
*old* script builds those chains from nothing. If they read back fine, the
incompatibility was accumulated host state and the reboot cleared it. If it
reproduces immediately on freshly-created chains, it is inherent to what
this project writes, and the `-C` guard concern in step 2b.3 becomes live —
which would mean this PR needs a code change before it merges.

There was no cheap way to distinguish those two before the reboot. Now
there is, and it costs one command.

Throughout this runbook, wherever a step says `iptables -S <chain>`, read
the chain with `nft` instead if the iptables form errors:

```bash
sudo nft list chain ip  filter DRAKVUF_ISOLATION
sudo nft list chain ip6 filter DRAKVUF_ISOLATION6
```

The rule *text* differs — nft prints its own syntax — but the ordering and
the verdicts are what every check below actually cares about.

## What is being deployed

`automation/network-setup.sh`. The posture is **unchanged** — that is the
point. What changes is what enforces it:

```text
before:  clone -> Internet   ALLOW   by falling through to -P FORWARD ACCEPT
after:   clone -> Internet   ALLOW   by an explicit rule in DRAKVUF_ISOLATION
```

`DRAKVUF_ISOLATION` goes from five rules to nine — uplink `ACCEPT`,
`ESTABLISHED,RELATED` return `ACCEPT`, then `DROP` in both directions.
`DRAKVUF_ISOLATION6` gains the matching `-o` drop. No built-in policy is
set, in either address family.

Plus the fail-open fix: the flush moves to sit immediately above the rules
that replace it, and `on_exit` now fails **closed**.

**One behaviour change to expect.** A failed run now leaves
`DRAKVUF_ISOLATION` holding two `DROP` rules instead of leaving it empty.
That is deliberate, it is tested in step 7, and it means a failure cuts the
network of any clone running at the time.

---

## Step 0 — Preconditions

```bash
uptime                                   # confirm this is the post-reboot boot
xl list                                  # expect: no *-clone domains
git -C /root/sandbox_project status --porcelain   # expect: empty
git -C /root/sandbox_project branch --show-current   # expect: master
git -C /root/sandbox_project log -1 --oneline
uname -a
iptables --version
```

Then confirm the post-reboot baseline is what this runbook now assumes:

```bash
# The OVS bridge should have survived -- it lives in the OVS database, not
# in the kernel's interface state. If it is gone, network-setup.sh will
# fail with a message naming `ovs-vsctl add-br xenbr1`, which is the fix.
ip link show xenbr1
sudo ovs-vsctl list-br

# These should NOT exist yet. Their absence is the expected post-reboot
# state, not a finding.
ip -br addr show | grep xenbr1 || echo "no VLAN sub-interfaces -- expected"

# EMPTY OUTPUT IS A RESULT here, not a failed command: with nothing
# provisioned there may be no nft tables at all. Echo the exit status so
# "nothing printed" is distinguishable from "the command broke".
sudo nft list tables ; echo "(exit $?)"

# 0 or 1. The reboot resets this unless something sets it persistently;
# network-setup.sh sets it to 1 on every run.
cat /proc/sys/net/ipv4/ip_forward
grep -rn ip_forward /etc/sysctl.conf /etc/sysctl.d/ 2>/dev/null || echo "not set persistently"
```

Neither of the last two is a gate — they are the baseline that makes step 2
legible, so you can say what provisioning *changed* rather than inferring
it.

What to look for:

- **`nft list tables`** — nothing, or only tables belonging to other tools,
  are both fine. A `table ip filter` already present is worth noting: that
  is the table `iptables-nft` writes into, and something else having
  created it is one candidate explanation for the incompatibility in the
  section above.
- **`ip_forward`** — expect `0`. If it is already `1` and no sysctl file
  sets it, something else on the host enabled it.

```text
root@drakvuf:/home/user# uptime                                   # confirm this is the post-reboot boot
 10:47:22 up 26 min,  2 users,  load average: 0,03, 0,04, 0,01
root@drakvuf:/home/user# xl list                                  # expect: no *-clone domains
Name                                        ID   Mem VCPUs	State	Time(s)
Domain-0                                     0  4096     4     r-----      85.1
root@drakvuf:/home/user# git -C /root/sandbox_project status --porcelain   # expect: empty
root@drakvuf:/home/user# git -C /root/sandbox_project branch --show-current   # expect: master
master
root@drakvuf:/home/user# git -C /root/sandbox_project log -1 --oneline
bc199db (HEAD -> master, origin/master, origin/HEAD) Merge pull request #8 from evilbootloader/draft-028-network-isolation
root@drakvuf:/home/user# uname -a
Linux drakvuf 6.8.0-136-generic #136~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Fri Jul  3 16:29:11 UTC  x86_64 x86_64 x86_64 GNU/Linux
root@drakvuf:/home/user# iptables --version
iptables v1.8.7 (nf_tables)
root@drakvuf:/home/user# ip link show xenbr1
4: xenbr1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether d6:6a:64:a6:13:45 brd ff:ff:ff:ff:ff:ff
root@drakvuf:/home/user# sudo ovs-vsctl list-br
xenbr1
root@drakvuf:/home/user# ip -br addr show | grep xenbr1 || echo "no VLAN sub-interfaces -- expected"
xenbr1           DOWN           
root@drakvuf:/home/user# sudo nft list tables ; echo "(exit $?)"
(exit 0)
root@drakvuf:/home/user# cat /proc/sys/net/ipv4/ip_forward
0
root@drakvuf:/home/user# grep -rn ip_forward /etc/sysctl.conf /etc/sysctl.d/ 2>/dev/null || echo "not set persistently"
/etc/sysctl.conf:28:#net.ipv4.ip_forward=1



xenbr1 present?  yes (DOWN, as expected -- network-setup.sh brings it up)
VLAN sub-interfaces present?  none
Tables listed by nft (empty is fine): empty, exit 0
ip_forward (expect 0): 0
Set persistently anywhere?  NO -- /etc/sysctl.conf:28 is `#net.ipv4.ip_forward=1`,
  commented out. Forwarding is off at boot and network-setup.sh sets it each
  run, which is the intended design.
```

> **Two summary lines were corrected against the raw output above before
> this file was committed** (ip_forward read as 1 rather than 0, and the
> commented sysctl line read as active). The terminal output itself is
> untouched.

## Step 0b — Backend identification (BLOCKING)

Added 2026-08-12 after the failure quoted above, then **split when the host
was rebooted**: with no `DRAKVUF_*` chains alive, most of the original
diagnostic has nothing to read. What remains here are the two parts that
work on a clean host — which tooling is in play, and whether `iptables` can
write at all. The chain-reading parts moved to **step 2b**, after
provisioning re-creates them.

**Nothing downstream is trustworthy until this and 2b resolve**, because
every verification in this runbook reads a chain back, and one of the
script's own mechanisms depends on being able to.

### 0b.1 — Which backend, and is there a second ruleset?

```bash
sudo iptables -V
sudo update-alternatives --display iptables 2>/dev/null | head -5

# Two rulesets can be live at once, each invisible to the other tool.
sudo iptables-legacy -S 2>&1 | head
sudo iptables-nft    -S 2>&1 | head -3

sudo nft list tables
```

```text
root@drakvuf:/home/user# sudo iptables -V
iptables v1.8.7 (nf_tables)
root@drakvuf:/home/user# sudo update-alternatives --display iptables 2>/dev/null | head -5
iptables - auto mode
  link best version is /usr/sbin/iptables-nft
  link currently points to /usr/sbin/iptables-nft
  link iptables is /usr/sbin/iptables
  slave iptables-restore is /usr/sbin/iptables-restore
root@drakvuf:/home/user# sudo iptables-legacy -S 2>&1 | head
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
root@drakvuf:/home/user# sudo iptables-nft    -S 2>&1 | head -3
# Warning: iptables-legacy tables present, use iptables-legacy to see them
-P INPUT ACCEPT
-P FORWARD ACCEPT
root@drakvuf:/home/user# sudo nft list tables
root@drakvuf:/home/user# 
```

### 0b.2 — Can `iptables` still write?

A fresh chain isolates the tool from the content. This works on a clean
host — it brings its own chain — which is why it stayed in step 0b.

```bash
sudo iptables -N DRAKVUF_COMPAT_TEST
sudo iptables -A DRAKVUF_COMPAT_TEST -i xenbr1.+ -j DROP
sudo iptables -S DRAKVUF_COMPAT_TEST      # expect: reads back fine
sudo iptables -F DRAKVUF_COMPAT_TEST
sudo iptables -X DRAKVUF_COMPAT_TEST
```

Note that this rule is deliberately one of the ones `network-setup.sh`
installs. If a bare `-i xenbr1.+ -j DROP` in a brand-new chain already
reads back as incompatible, the cause is the interface wildcard or the
backend itself, and step 2b will reproduce it immediately.

```text
root@drakvuf:/home/user# sudo iptables -N DRAKVUF_COMPAT_TEST
root@drakvuf:/home/user# sudo iptables -A DRAKVUF_COMPAT_TEST -i xenbr1.+ -j DROP
root@drakvuf:/home/user# sudo iptables -S DRAKVUF_COMPAT_TEST      # expect: reads back fine
# Warning: iptables-legacy tables present, use iptables-legacy to see them
-N DRAKVUF_COMPAT_TEST
-A DRAKVUF_COMPAT_TEST -i xenbr1.+ -j DROP
root@drakvuf:/home/user# sudo iptables -F DRAKVUF_COMPAT_TEST
root@drakvuf:/home/user# sudo iptables -X DRAKVUF_COMPAT_TEST
root@drakvuf:/home/user# 

Fresh chain readable?  yes
```

### STOP gate for step 0b

| 0b.2 fresh chain readable | Verdict |
|---|---|
| yes | **Proceed to step 1.** The tool works; whether the *content* is readable is step 2b's question. |
| **no** | **Stop.** `iptables` cannot round-trip even its own writes on this host. `network-setup.sh` would abort under `set -eu`, and this PR's fail-closed trap — which also calls `iptables` — could not do its job either. That needs solving before any deployment. |

```text
VERDICT: Working
```

## Step 1 — Capture the rollback FIRST

Do not skip it because DRAFT-028's capture exists — this must be the state
as of *today*.

**Post-reboot this capture is nearly empty**, and that is correct: an empty
ruleset *is* the current state, and restoring it is what returns the host
to "freshly booted, nothing provisioned". It is a smaller safety net than
DRAFT-028's was, so the real recovery here is re-running the old script
from `master` (step 9), not the restore alone.

```bash
sudo iptables-save  > /root/iptables-pre-DRAFT-029.rules
sudo ip6tables-save > /root/ip6tables-pre-DRAFT-029.rules
ls -l /root/iptables-pre-DRAFT-029.rules /root/ip6tables-pre-DRAFT-029.rules
```

Recovery, at any point in this runbook:

```bash
sudo iptables-restore  < /root/iptables-pre-DRAFT-029.rules
sudo ip6tables-restore < /root/ip6tables-pre-DRAFT-029.rules
```

```text
root@drakvuf:/home/user# sudo iptables-save  > /root/iptables-pre-DRAFT-029.rules
# Warning: iptables-legacy tables present, use iptables-legacy-save to see them
root@drakvuf:/home/user# sudo ip6tables-save > /root/ip6tables-pre-DRAFT-029.rules
root@drakvuf:/home/user# ls -l /root/iptables-pre-DRAFT-029.rules /root/ip6tables-pre-DRAFT-029.rules
-rw-r--r-- 1 root root   0 ago 12 10:51 /root/ip6tables-pre-DRAFT-029.rules
-rw-r--r-- 1 root root 182 ago 12 10:51 /root/iptables-pre-DRAFT-029.rules
```

## Step 2 — Provision with the OLD script, from `master`

Added 2026-08-12 because of the reboot. Steps 2b and 2c need the DRAFT-028
chains to exist, and nothing re-creates them at boot.

**Stay on `master`.** This step is deliberately the *old* code — the branch
checkout is step 3. Running the new script here would destroy the
before/after comparison the next two steps exist to produce.

```bash
cd /root/sandbox_project
git branch --show-current        # expect: master -- stop if not
git log -1 --oneline

sudo ./automation/network-setup.sh 2
echo "exit status: $?"           # expect: 0
```

If it fails on the bridge check, `xenbr1` did not survive the reboot after
all; re-create it with `sudo ovs-vsctl add-br xenbr1` and re-run.

```text
root@drakvuf:/home/user# cd /root/sandbox_project
root@drakvuf:~/sandbox_project# git branch --show-current        # expect: master -- stop if not
master
root@drakvuf:~/sandbox_project# git log -1 --oneline
bc199db (HEAD -> master, origin/master, origin/HEAD) Merge pull request #8 from evilbootloader/draft-028-network-isolation
root@drakvuf:~/sandbox_project# sudo ./automation/network-setup.sh 2
network-setup.sh: provisioned 2 VLAN sub-interface(s) on xenbr1
root@drakvuf:~/sandbox_project# echo "exit status: $?"           # expect: 0
exit status: 0

Branch (expect master): master
Exit status: 0
```

## Step 2b — Chain readability, on freshly-created chains (BLOCKING)

This is the step the reboot made worth doing. These chains were built
seconds ago by the old script, from nothing. **Whether the incompatibility
reproduces here separates two very different diagnoses**, and there was no
cheap way to tell them apart before.

### 2b.1 — Is it chain-specific or table-wide?

```bash
sudo iptables -S FORWARD
sudo iptables -S INPUT
sudo iptables -S DRAKVUF_ISOLATION
sudo iptables -S DRAKVUF_INPUT
sudo iptables -t nat -S DRAKVUF_NAT
sudo ip6tables -S FORWARD
sudo ip6tables -S DRAKVUF_ISOLATION6
sudo ip6tables -S DRAKVUF_INPUT6
```

```text
root@drakvuf:~/sandbox_project# sudo iptables -S FORWARD
# Warning: iptables-legacy tables present, use iptables-legacy to see them
-P FORWARD ACCEPT
-A FORWARD -j DRAKVUF_ISOLATION
root@drakvuf:~/sandbox_project# sudo iptables -S INPUT
# Warning: iptables-legacy tables present, use iptables-legacy to see them
-P INPUT ACCEPT
-A INPUT -j DRAKVUF_INPUT
root@drakvuf:~/sandbox_project# sudo iptables -S DRAKVUF_ISOLATION
# Warning: iptables-legacy tables present, use iptables-legacy to see them
-N DRAKVUF_ISOLATION
-A DRAKVUF_ISOLATION -i xenbr1.+ ! -o xenbr0 -j DROP
-A DRAKVUF_ISOLATION -d 10.0.0.0/8 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 172.16.0.0/12 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 192.168.0.0/16 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 169.254.0.0/16 -i xenbr1.+ -j DROP
root@drakvuf:~/sandbox_project# sudo iptables -S DRAKVUF_INPUT
# Warning: iptables-legacy tables present, use iptables-legacy to see them
-N DRAKVUF_INPUT
-A DRAKVUF_INPUT -i xenbr1.+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DRAKVUF_INPUT -i xenbr1.+ -j DROP
root@drakvuf:~/sandbox_project# sudo iptables -t nat -S DRAKVUF_NAT
# Warning: iptables-legacy tables present, use iptables-legacy to see them
-N DRAKVUF_NAT
-A DRAKVUF_NAT -o xenbr0 -j MASQUERADE
root@drakvuf:~/sandbox_project# sudo ip6tables -S FORWARD
-P FORWARD ACCEPT
-A FORWARD -j DRAKVUF_ISOLATION6
root@drakvuf:~/sandbox_project# sudo ip6tables -S DRAKVUF_ISOLATION6
-N DRAKVUF_ISOLATION6
-A DRAKVUF_ISOLATION6 -i xenbr1.+ -j DROP
root@drakvuf:~/sandbox_project# sudo ip6tables -S DRAKVUF_INPUT6
-N DRAKVUF_INPUT6
-A DRAKVUF_INPUT6 -i xenbr1.+ -j DROP

Which errored: NONE. All eight commands succeeded and printed their rules.
Which read back fine: all of them.

The `# Warning: iptables-legacy tables present, use iptables-legacy to see
them` line is a **warning, not an error** -- a different message from
yesterday's `chain ... is incompatible`, which did not appear once. It is
emitted only on the IPv4 commands, because legacy IPv4 tables exist on this
host and legacy IPv6 tables do not. See finding F1 in the STOP gate below.

**The incompatibility did not reproduce.** These chains were built from
nothing minutes earlier by the same script that produced yesterday's
unreadable ones.
```

### 2b.2 — What does the kernel actually hold?

The authoritative view, bypassing the translation layer.

```bash
sudo nft list chain ip  filter DRAKVUF_ISOLATION
sudo nft list chain ip  filter DRAKVUF_INPUT
sudo nft list chain ip  filter FORWARD
sudo nft list chain ip  filter INPUT
sudo nft list chain ip6 filter DRAKVUF_ISOLATION6
sudo nft list chain ip6 filter DRAKVUF_INPUT6
sudo nft list chain ip  nat    DRAKVUF_NAT
```

Expect `DRAKVUF_ISOLATION` to hold five rules and `DRAKVUF_INPUT` two. A
chain that is empty *now*, immediately after a successful provisioning run,
means the script reported success while installing nothing — which is
NET-01's shape and stops this runbook.

```text
root@drakvuf:~/sandbox_project# sudo nft list chain ip  filter DRAKVUF_ISOLATION
table ip filter {
	chain DRAKVUF_ISOLATION {
		iifname "xenbr1.*" oifname != "xenbr0" counter packets 0 bytes 0 drop
		iifname "xenbr1.*" ip daddr 10.0.0.0/8 counter packets 0 bytes 0 drop
		iifname "xenbr1.*" ip daddr 172.16.0.0/12 counter packets 0 bytes 0 drop
		iifname "xenbr1.*" ip daddr 192.168.0.0/16 counter packets 0 bytes 0 drop
		iifname "xenbr1.*" ip daddr 169.254.0.0/16 counter packets 0 bytes 0 drop
	}
}
root@drakvuf:~/sandbox_project# sudo nft list chain ip  filter DRAKVUF_INPUT
table ip filter {
	chain DRAKVUF_INPUT {
		iifname "xenbr1.*" ct state related,established counter packets 0 bytes 0 accept
		iifname "xenbr1.*" counter packets 38 bytes 4442 drop
	}
}
root@drakvuf:~/sandbox_project# sudo nft list chain ip  filter FORWARD
table ip filter {
	chain FORWARD {
		type filter hook forward priority filter; policy accept;
		counter packets 0 bytes 0 jump DRAKVUF_ISOLATION
	}
}
root@drakvuf:~/sandbox_project# sudo nft list chain ip  filter INPUT
table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy accept;
		counter packets 61 bytes 6566 jump DRAKVUF_INPUT
	}
}
root@drakvuf:~/sandbox_project# sudo nft list chain ip6 filter DRAKVUF_ISOLATION6
table ip6 filter {
	chain DRAKVUF_ISOLATION6 {
		iifname "xenbr1.*" counter packets 0 bytes 0 drop
	}
}
root@drakvuf:~/sandbox_project# sudo nft list chain ip6 filter DRAKVUF_INPUT6
table ip6 filter {
	chain DRAKVUF_INPUT6 {
		iifname "xenbr1.*" counter packets 26 bytes 3618 drop
	}
}
root@drakvuf:~/sandbox_project# sudo nft list chain ip  nat    DRAKVUF_NAT
table ip nat {
	chain DRAKVUF_NAT {
		oifname "xenbr0" counter packets 1 bytes 48 masquerade 
	}
}

DRAKVUF_ISOLATION rule count (expect 5): 5
DRAKVUF_INPUT rule count (expect 2): 2
Any chain unexpectedly empty?  no 
```

### 2b.3 — The `-C` guard, and whether jumps accumulate

**This is the part with real consequences.** `network-setup.sh` tests for
its jumps before installing them, at `:333` (FORWARD), `:483` (INPUT) and
the NAT equivalent.

> ⚠️ **QUOTED SOURCE — DO NOT PASTE THIS INTO A SHELL.** `$ISOLATION_CHAIN` is
> internal to `network-setup.sh` and expands to nothing interactively. The
> runnable commands are in the two `bash` blocks below. See
> [TROUBLESHOOTING](../TROUBLESHOOTING.md#invalid-target-name-too-short-after-pasting-a-command-from-a-script).
>
> ```
> iptables -C FORWARD -j "$ISOLATION_CHAIN" 2>/dev/null ||
>     iptables -I FORWARD 1 -j "$ISOLATION_CHAIN"
> ```

`-C` returns 0 when the rule exists and 1 when it does not. **If it instead
*errors* because the chain is incompatible, `2>/dev/null` hides the message
and the `||` branch fires anyway — inserting a second jump on every run.**
That would silently regress the idempotence DRAFT-028 exists to provide,
with no visible symptom.

```bash
sudo iptables -C FORWARD -j DRAKVUF_ISOLATION ; echo "-C FORWARD exit: $?"
sudo iptables -C INPUT   -j DRAKVUF_INPUT     ; echo "-C INPUT   exit: $?"
sudo iptables -t nat -C POSTROUTING -j DRAKVUF_NAT ; echo "-C NAT exit: $?"
```

Now the decisive test, which the reboot makes clean: **provision twice more
and count the jumps.** One run has already happened, so the counts must
still be 1 after three.

```bash
sudo ./automation/network-setup.sh 2
sudo ./automation/network-setup.sh 2

sudo nft list chain ip filter FORWARD  | grep -c DRAKVUF_ISOLATION   # expect 1
sudo nft list chain ip filter INPUT    | grep -c DRAKVUF_INPUT       # expect 1
sudo nft list chain ip nat POSTROUTING | grep -c DRAKVUF_NAT         # expect 1
```

Counts of 3 mean the guards are broken and every launch has been stacking
jumps. Exit 0 or 1 from `-C` with no error text is healthy; anything else
is a finding.

```text
root@drakvuf:~/sandbox_project# iptables -C FORWARD -j "$ISOLATION_CHAIN" 2>/dev/null ||
    iptables -I FORWARD 1 -j "$ISOLATION_CHAIN"
iptables v1.8.7 (nf_tables): Invalid target name (too short)
Try `iptables -h' or 'iptables --help' for more information.
root@drakvuf:~/sandbox_project# ```bash
> ^C
root@drakvuf:~/sandbox_project# sudo iptables -C FORWARD -j DRAKVUF_ISOLATION ; echo "-C FORWARD exit: $?"
DRAKVUF_ISOLATION  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
-C FORWARD exit: 0
root@drakvuf:~/sandbox_project# sudo iptables -C INPUT   -j DRAKVUF_INPUT     ; echo "-C INPUT   exit: $?"
DRAKVUF_INPUT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
-C INPUT   exit: 0
root@drakvuf:~/sandbox_project# sudo iptables -t nat -C POSTROUTING -j DRAKVUF_NAT ; echo "-C NAT exit: $?"
DRAKVUF_NAT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
-C NAT exit: 0
root@drakvuf:~/sandbox_project# sudo ./automation/network-setup.sh 2
DRAKVUF_NAT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_ISOLATION  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_INPUT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_ISOLATION6  all opt    in * out *  ::/0  -> ::/0  
DRAKVUF_INPUT6  all opt    in * out *  ::/0  -> ::/0  
network-setup.sh: provisioned 2 VLAN sub-interface(s) on xenbr1
root@drakvuf:~/sandbox_project# sudo ./automation/network-setup.sh 2
DRAKVUF_NAT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_ISOLATION  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_INPUT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_ISOLATION6  all opt    in * out *  ::/0  -> ::/0  
DRAKVUF_INPUT6  all opt    in * out *  ::/0  -> ::/0  
network-setup.sh: provisioned 2 VLAN sub-interface(s) on xenbr1
root@drakvuf:~/sandbox_project# sudo nft list chain ip filter FORWARD  | grep -c DRAKVUF_ISOLATION   # expect 1
1
root@drakvuf:~/sandbox_project# sudo nft list chain ip filter INPUT    | grep -c DRAKVUF_INPUT       # expect 1
1
root@drakvuf:~/sandbox_project# sudo nft list chain ip nat POSTROUTING | grep -c DRAKVUF_NAT         # expect 1
1

-C FORWARD exit / error: 0
-C INPUT   exit / error: 0
-C NAT     exit / error: 0
Jump counts after three runs (expect 1 / 1 / 1): 1 / 1 / 1
```

### STOP gate for step 2b

| 2b.1 iptables reads chains | 2b.2 rules present | 2b.3 counts all 1 | Verdict |
|---|---|---|---|
| yes | yes | yes | **Proceed.** The incompatibility was accumulated host state and the reboot cleared it. Note that in the results and carry on with `iptables` throughout. |
| **no** | yes | yes | **Proceed with care.** Inherent to what this project writes, but harmless — readback only. Use the `nft` forms for every remaining verification, and open a follow-up for the readback gap. |
| — | yes | **no** | **Stop.** Jumps are accumulating. The `-C` guards need fixing in this PR before it deploys — most likely distinguishing "rule absent" from "command failed" instead of swallowing both. |
| — | **no** | — | **Stop, urgently.** Provisioning reported success and installed nothing. Live security finding, not a deployment blocker. |

```text
VERDICT: row 1 — PROCEED.

iptables read all eight chains without error; all rules present in the
kernel; -C returned 0 on all three jumps; counts 1/1/1 after three
provisioning runs. Idempotence intact, guards working. No code change
needed in PR #10 on account of this.
```

### Findings recorded, neither blocking

**F1 — two iptables backends are live on this host.** `iptables` resolves
to `iptables-nft` (confirmed via `update-alternatives`), and this project's
rules all land in nftables. But `iptables-legacy -S` reports base chains
present, which is why every IPv4 command prints the legacy warning. Right
now those legacy tables hold **only default-ACCEPT policies and no rules**,
so nothing is being filtered invisibly — the finding is that they exist at
all, and that something re-creates them across a reboot.

Why it matters even while benign: the two backends hook netfilter
independently and are evaluated independently. A rule in the legacy tables
would be invisible to `iptables -S` on this host, and vice versa. Every
containment assertion this project makes is currently a statement about one
of two rulesets. Identifying what creates them (Xen's `vif-*` scripts are
the first candidate on a Dom0) is follow-up work, not this PR's.

**F2 — the 2026-08-12 incompatibility is not reproducible and its cause is
unknown.** It cleared on reboot and did not return when the same script
rebuilt the same chains from nothing. No root cause is claimed here;
inventing one would be worse than recording the gap. What is known: it
persisted across at least one day of normal operation, `iptables -S` was
the only thing that noticed, and nothing in the pipeline would have. If it
returns, `nft list chain` is the readback that works.

> **SUPERSEDED 2026-08-12 — F2 as written above is wrong.** It was not
> unexplained and it did not "clear on reboot". `iptables -S` reports any
> nonexistent chain as "incompatible" on this host; the chains simply did
> not exist yet. See the annotation under "Reading the chains on this host"
> for the test that settles it.
>
> **F2′ replaces it, and is a real finding.** "Chain absent" and "chain
> unreadable" produce the same error text here, and *absent* means
> containment is entirely off. Nothing in the pipeline distinguishes the
> two, and a human reading that message as a tooling quirk will proceed
> with no isolation at all. Owned by DRAFT-038.

**Cosmetic, noticed in passing:** `iptables -C` on the nft backend prints
the matched rule to *stdout*, and the script's `2>/dev/null` only silences
stderr — hence the five stray `DRAKVUF_* all opt -- in * out *` lines in
each provisioning run above. Harmless, but it is noise in every transcript.
A one-character fix (`>/dev/null 2>&1`) would remove it. Not taken in this
PR, which does not otherwise touch those lines.

```text
VERDICT:
```

## Step 2c — The inherited-permit evidence, before changing anything

This is what the issue claims is wrong. Capture it while it is still true,
because after step 4 it is not reproducible without a rollback.

```bash
# The three policies. The claim is that clone egress depends on the first.
sudo iptables -S | head -3
sudo ip6tables -S | head -3

# Five rules, ending in a DROP with no terminal ACCEPT below it.
# Use the nft form if these error -- see step 2b.
sudo iptables -S DRAKVUF_ISOLATION
sudo ip6tables -S DRAKVUF_ISOLATION6

sudo nft list chain ip  filter DRAKVUF_ISOLATION
sudo nft list chain ip6 filter DRAKVUF_ISOLATION6
```

Note that `-P FORWARD ACCEPT` in the first command is itself a translated
view. The authoritative form is the base chain's policy in nft:

```bash
sudo nft list chain ip filter FORWARD | head -3    # look for `policy accept`
```

Now the decisive test, with the **old** script still deployed. Boot one
benign clone, confirm it reaches the Internet, then flip the policy:

# I've updated networking on the clone from preconfig.

```bash
sudo iptables -P FORWARD DROP
#   from inside the clone:  ping -c2 1.1.1.1
sudo iptables -P FORWARD ACCEPT
#   from inside the clone:  ping -c2 1.1.1.1
```

**If `iptables -P` errors on this backend**, the nft equivalent is below.
It is a *candidate command, not validated on this host* — check the policy
readback after each one rather than assuming it took:

```bash
sudo nft add chain ip filter FORWARD '{ policy drop; }'
sudo nft list chain ip filter FORWARD | head -3     # confirm it changed
sudo nft add chain ip filter FORWARD '{ policy accept; }'
sudo nft list chain ip filter FORWARD | head -3     # confirm it changed back
```

Confirm the policy is back to `accept` before leaving this step, whichever
tool set it.

**Expected: the first ping fails and the second succeeds.** That is the
defect, demonstrated. If both succeed, the premise is wrong and the rest of
this runbook needs rethinking before you continue — say so rather than
proceeding.

```text
root@drakvuf:~/sandbox_project# sudo iptables -P FORWARD DROP
root@drakvuf:~/sandbox_project# sudo iptables -P FORWARD ACCEPT

Ping with -P FORWARD DROP   (expect: 100% packet loss): 100% packet loss 
Ping with -P FORWARD ACCEPT (expect: replies): replies
```

## Step 3 — Pull PR #10 onto Dom0

Dom0 tracks this repository at `/root/sandbox_project` over a **read-only
deploy key**, so it fetches and checks out — it never pushes, and nothing
here needs write access or `gh` on the host.

The branch is `draft-029-terminal-chains`
([PR #10](https://github.com/evilbootloader/drakvuf-multios-sandbox/pull/10)).
It is **not merged**, so `git pull` on `master` will not bring it down —
that is step 9's command, not this one.

```bash
cd /root/sandbox_project

# Confirm you are starting clean. Anything listed here is local drift and
# must be resolved before continuing -- see CLAUDE.md on never editing
# deployed scripts in place.
git status --porcelain           # expect: empty
git log -1 --oneline             # what is deployed right now

git fetch origin
git checkout -b draft-029-terminal-chains origin/draft-029-terminal-chains
```

If the branch already exists locally from an earlier attempt:

```bash
git checkout draft-029-terminal-chains
git reset --hard origin/draft-029-terminal-chains
```

Verify you have the right code before running any of it:

```bash
git branch --show-current        # expect: draft-029-terminal-chains
git log --oneline -2             # expect: e794045 then 7e068ec
git status --porcelain           # expect: empty

# The change is present in the working tree. Expect 4, not 3: three real
# rules plus one comment at :416 that mentions `-j ACCEPT`. (Corrected
# 2026-08-12 -- the runbook said 3 and the comment was overlooked.)
grep -c 'j ACCEPT' automation/network-setup.sh          # expect: 4
grep -n 'left DENYING' automation/network-setup.sh      # expect: 1 hit, the trap
```

Static checks, on the host rather than trusting CI:

```bash
bash -n automation/network-setup.sh
dash -n automation/network-setup.sh
shellcheck automation/network-setup.sh    # if installed on Dom0
```

```text
root@drakvuf:~/sandbox_project# cd /root/sandbox_project
root@drakvuf:~/sandbox_project# git status --porcelain           # expect: empty
root@drakvuf:~/sandbox_project# git log -1 --oneline             # what is deployed right now
bc199db (HEAD -> master, origin/master, origin/HEAD) Merge pull request #8 from evilbootloader/draft-028-network-isolation
root@drakvuf:~/sandbox_project# git fetch origin
remote: Enumerating objects: 41, done.
remote: Counting objects: 100% (41/41), done.
remote: Compressing objects: 100% (9/9), done.
remote: Total 26 (delta 18), reused 24 (delta 16), pack-reused 0 (from 0)
Unpacking objects: 100% (26/26), 22.97 KiB | 1.64 MiB/s, done.
From github.com:evilbootloader/drakvuf-multios-sandbox
   bc199db..229f7be  master                    -> origin/master
 * [new branch]      draft-029-terminal-chains -> origin/draft-029-terminal-chains
root@drakvuf:~/sandbox_project# git checkout -b draft-029-terminal-chains origin/draft-029-terminal-chains
Branch 'draft-029-terminal-chains' set up to track remote branch 'draft-029-terminal-chains' from 'origin'.
Switched to a new branch 'draft-029-terminal-chains'
root@drakvuf:~/sandbox_project# git checkout draft-029-terminal-chains
Already on 'draft-029-terminal-chains'
Your branch is up to date with 'origin/draft-029-terminal-chains'.
root@drakvuf:~/sandbox_project# git reset --hard origin/draft-029-terminal-chains
HEAD is now at e794045 Make the DRAKVUF chains terminal and fail closed (DRAFT-029, #9)
root@drakvuf:~/sandbox_project# git branch --show-current        # expect: draft-029-terminal-chains
draft-029-terminal-chains
root@drakvuf:~/sandbox_project# git log --oneline -2             # expect: e794045 then 7e068ec
e794045 (HEAD -> draft-029-terminal-chains, origin/draft-029-terminal-chains) Make the DRAKVUF chains terminal and fail closed (DRAFT-029, #9)
7e068ec Record the operating entity and the uplink (DRAFT-022)
root@drakvuf:~/sandbox_project# git status --porcelain           # expect: empty
root@drakvuf:~/sandbox_project# grep -c 'j ACCEPT' automation/network-setup.sh          # expect: 3
4
root@drakvuf:~/sandbox_project# grep -n 'left DENYING' automation/network-setup.sh      # expect: 1 hit, the trap
217:        echo "network-setup.sh: $chain left DENYING all analysis-VLAN traffic; re-run to restore" >&2
root@drakvuf:~/sandbox_project# bash -n automation/network-setup.sh
root@drakvuf:~/sandbox_project# dash -n automation/network-setup.sh
root@drakvuf:~/sandbox_project# shellcheck automation/network-setup.sh    # if installed on Dom0
root@drakvuf:~/sandbox_project# 

Branch: draft-029-terminal-chains
HEAD commit: e794045
'j ACCEPT' count: 4 -- CORRECT. The runbook's "expect 3" was wrong: three
  rules (:434, :440, :491) plus the comment at :416. No defect.
Static checks clean?  yes
```

## Step 4 — Provision

```bash
cd /root/sandbox_project/automation
sudo ./network-setup.sh 2
echo "exit status: $?"

sudo iptables -S DRAKVUF_ISOLATION
sudo ip6tables -S DRAKVUF_ISOLATION6

# nft form, if the above error -- and re-check the jump counts, because a
# broken -C guard (step 2b.3) shows up here as a second jump appearing.
sudo nft list chain ip  filter DRAKVUF_ISOLATION
sudo nft list chain ip6 filter DRAKVUF_ISOLATION6
sudo nft list chain ip  filter FORWARD | grep -c DRAKVUF_ISOLATION   # expect: 1
```

Expect nine rules, in this order — **the two ACCEPTs must be below all four
RFC1918 DROPs**:

```text
-A DRAKVUF_ISOLATION -i xenbr1.+ ! -o xenbr0 -j DROP
-A DRAKVUF_ISOLATION -d 10.0.0.0/8 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 172.16.0.0/12 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 192.168.0.0/16 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 169.254.0.0/16 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -i xenbr1.+ -o xenbr0 -j ACCEPT
-A DRAKVUF_ISOLATION -o xenbr1.+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DRAKVUF_ISOLATION -o xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -i xenbr1.+ -j DROP
```

If an ACCEPT appears above a RFC1918 DROP, **stop** — a clone can reach the
LAN. Roll back with step 1.

```text
root@drakvuf:~/sandbox_project/automation# sudo ./network-setup.sh 2
DRAKVUF_NAT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_ISOLATION  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_INPUT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_ISOLATION6  all opt    in * out *  ::/0  -> ::/0  
DRAKVUF_INPUT6  all opt    in * out *  ::/0  -> ::/0  
network-setup.sh: provisioned 2 VLAN sub-interface(s) on xenbr1
root@drakvuf:~/sandbox_project/automation# echo "exit status: $?"
exit status: 0
root@drakvuf:~/sandbox_project/automation# sudo iptables -S DRAKVUF_ISOLATION
# Warning: iptables-legacy tables present, use iptables-legacy to see them
-N DRAKVUF_ISOLATION
-A DRAKVUF_ISOLATION -i xenbr1.+ ! -o xenbr0 -j DROP
-A DRAKVUF_ISOLATION -d 10.0.0.0/8 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 172.16.0.0/12 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 192.168.0.0/16 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 169.254.0.0/16 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -i xenbr1.+ -o xenbr0 -j ACCEPT
-A DRAKVUF_ISOLATION -o xenbr1.+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DRAKVUF_ISOLATION -o xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -i xenbr1.+ -j DROP
root@drakvuf:~/sandbox_project/automation# sudo ip6tables -S DRAKVUF_ISOLATION6
-N DRAKVUF_ISOLATION6
-A DRAKVUF_ISOLATION6 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION6 -o xenbr1.+ -j DROP
root@drakvuf:~/sandbox_project/automation# sudo nft list chain ip  filter DRAKVUF_ISOLATION
table ip filter {
	chain DRAKVUF_ISOLATION {
		iifname "xenbr1.*" oifname != "xenbr0" counter packets 0 bytes 0 drop
		iifname "xenbr1.*" ip daddr 10.0.0.0/8 counter packets 0 bytes 0 drop
		iifname "xenbr1.*" ip daddr 172.16.0.0/12 counter packets 0 bytes 0 drop
		iifname "xenbr1.*" ip daddr 192.168.0.0/16 counter packets 0 bytes 0 drop
		iifname "xenbr1.*" ip daddr 169.254.0.0/16 counter packets 0 bytes 0 drop
		iifname "xenbr1.*" oifname "xenbr0" counter packets 6 bytes 430 accept
		oifname "xenbr1.*" ct state related,established counter packets 5 bytes 572 accept
		oifname "xenbr1.*" counter packets 0 bytes 0 drop
		iifname "xenbr1.*" counter packets 0 bytes 0 drop
	}
}
root@drakvuf:~/sandbox_project/automation# sudo nft list chain ip6 filter DRAKVUF_ISOLATION6
table ip6 filter {
	chain DRAKVUF_ISOLATION6 {
		iifname "xenbr1.*" counter packets 0 bytes 0 drop
		oifname "xenbr1.*" counter packets 0 bytes 0 drop
	}
}
root@drakvuf:~/sandbox_project/automation# sudo nft list chain ip  filter FORWARD | grep -c DRAKVUF_ISOLATION   # expect: 1
1
root@drakvuf:~/sandbox_project/automation#

Exit status: 0
Rule count: 10 lines from `iptables -S` = 9 rules + the `-N` line. The nft
  output above shows exactly 9 rules, which is the number that matters.
  (The runbook's bare "expect 9" was ambiguous about which it meant;
  corrected 2026-08-12.)
ACCEPTs below all four RFC1918 DROPs?  yes
```

## Step 5 — The acceptance test

The one step that actually tests this change. Boot one benign clone and run
the four probes under **both** policies. The results must be identical.

```bash
# --- with -P FORWARD ACCEPT (current) ---
#   from inside the clone:
#     ping -c2 1.1.1.1            expect: replies
#     getent hosts google.com     expect: resolves
#     ping -c2 <a LAN host>       expect: 100% loss
#     ping -c2 172.16.<vlan>.1    expect: 100% loss

sudo iptables -P FORWARD DROP

# --- with -P FORWARD DROP ---
#   re-run the same four probes    expect: IDENTICAL results

sudo iptables -P FORWARD ACCEPT   # restore before continuing
sudo iptables -S | head -3        # confirm restored
```

**Pass condition: all four probes behave the same under both policies.** If
Internet access dies when the policy flips, the chain is not terminal and
the change has not worked — record what you saw and stop.

```text
root@drakvuf:~/sandbox_project/automation# sudo iptables -P FORWARD DROP
root@drakvuf:~/sandbox_project/automation# sudo iptables -P FORWARD ACCEPT   # restore before continuing
root@drakvuf:~/sandbox_project/automation# sudo iptables -S | head -3        # confirm restored
# Warning: iptables-legacy tables present, use iptables-legacy to see them
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT

                          -P FORWARD ACCEPT    -P FORWARD DROP
ping 1.1.1.1              replies              replies
getent hosts google.com   resolves             resolves
ping <LAN host>           100% packet loss     100% packet loss
ping 172.16.<vlan>.1      100% packet loss     100% packet loss

Identical under both?  yes
Policy restored to ACCEPT?  yes
```

> **Evidence limitation, stated rather than papered over.** The four probes
> run inside the L2 clone, reached through a console with no clipboard, so
> their literal terminal output could not be captured. The table above is
> transcribed by hand and is the weakest evidence in this runbook — which
> matters, because this is the issue's central claim.
>
> **Two independent Dom0-side records corroborate it**, and both are
> mechanically captured rather than transcribed:
>
> 1. **Step 2c versus step 5.** Under the *old* script with
>    `-P FORWARD DROP`, `ping 1.1.1.1` gave 100% packet loss. Under the
>    *new* script with the same policy, it replies. That is the acceptance
>    criterion, and the contrast is recorded in two separate terminal
>    captures.
> 2. **Step 6's packet counters.** Rule 6 (uplink ACCEPT) shows 10 packets
>    and rule 7 (return path) 9 — the pings, counted by the kernel. Rule 4
>    (`192.168.0.0/16` DROP) shows 2 packets: the blocked LAN ping, proving
>    the RFC1918 drops sit *above* the uplink ACCEPT. Ordering is the one
>    property that could not be verified statically, and it is verified
>    here by counter rather than by assertion.
>
> **For future runs on this host**, prefer the differential-counter method
> over transcribing guest output — it is entirely copy-pasteable from Dom0:
>
> ```bash
> sudo iptables -Z DRAKVUF_ISOLATION            # zero the counters
> #   ... run the four probes in the guest ...
> sudo iptables -vnL DRAKVUF_ISOLATION --line-numbers
> ```
>
> Zeroed counters plus a known probe count make each rule's hit count an
> exact, self-evidencing record of what the guest did.

## Step 6 — Counters

An ACCEPT that never matches means the ordering is wrong and something else
is permitting the traffic.

```bash
sudo iptables -vnL DRAKVUF_ISOLATION --line-numbers

# nft form. Counters need `-a` on some builds to be shown at all:
sudo nft -a list chain ip filter DRAKVUF_ISOLATION
```

Both new ACCEPT rules must show non-zero packet counts after step 5.

If neither tool reports counters on this backend, the fallback is
differential: note the numbers before and after a single `ping -c4`, or
skip to step 8 and rely on the end-to-end analysis for evidence that the
ACCEPT path is live. Say which you did.

```text
root@drakvuf:~/sandbox_project/automation# sudo iptables -vnL DRAKVUF_ISOLATION --line-numbers
# Warning: iptables-legacy tables present, use iptables-legacy to see them
Chain DRAKVUF_ISOLATION (1 references)
num   pkts bytes target     prot opt in     out     source               destination         
1        0     0 DROP       all  --  xenbr1.+ !xenbr0  0.0.0.0/0            0.0.0.0/0           
2        0     0 DROP       all  --  xenbr1.+ *       0.0.0.0/0            10.0.0.0/8          
3        0     0 DROP       all  --  xenbr1.+ *       0.0.0.0/0            172.16.0.0/12       
4        2   168 DROP       all  --  xenbr1.+ *       0.0.0.0/0            192.168.0.0/16      
5        0     0 DROP       all  --  xenbr1.+ *       0.0.0.0/0            169.254.0.0/16      
6       10   730 ACCEPT     all  --  xenbr1.+ xenbr0  0.0.0.0/0            0.0.0.0/0           
7        9   900 ACCEPT     all  --  *      xenbr1.+  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
8        0     0 DROP       all  --  *      xenbr1.+  0.0.0.0/0            0.0.0.0/0           
9        0     0 DROP       all  --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0           
root@drakvuf:~/sandbox_project/automation# sudo nft -a list chain ip filter DRAKVUF_ISOLATION
table ip filter {
	chain DRAKVUF_ISOLATION { # handle 3
		iifname "xenbr1.*" oifname != "xenbr0" counter packets 0 bytes 0 drop # handle 32
		iifname "xenbr1.*" ip daddr 10.0.0.0/8 counter packets 0 bytes 0 drop # handle 33
		iifname "xenbr1.*" ip daddr 172.16.0.0/12 counter packets 0 bytes 0 drop # handle 34
		iifname "xenbr1.*" ip daddr 192.168.0.0/16 counter packets 2 bytes 168 drop # handle 35
		iifname "xenbr1.*" ip daddr 169.254.0.0/16 counter packets 0 bytes 0 drop # handle 36
		iifname "xenbr1.*" oifname "xenbr0" counter packets 10 bytes 730 accept # handle 37
		oifname "xenbr1.*" ct state related,established counter packets 9 bytes 900 accept # handle 38
		oifname "xenbr1.*" counter packets 0 bytes 0 drop # handle 39
		iifname "xenbr1.*" counter packets 0 bytes 0 drop # handle 40
	}
}

Uplink ACCEPT packets: Yes
Return-path ACCEPT packets: Yes
```

## Step 7 — Fail closed

Force a failure inside the window that used to fail open, and confirm the
chain denies rather than empties.

```bash
sudo ./network-setup.sh 999999
echo "exit status: $?"            # expect: non-zero

sudo iptables -S DRAKVUF_ISOLATION
sudo nft list chain ip filter DRAKVUF_ISOLATION    # nft form
```

**The trap uses `iptables` too.** If step 0b found writes unreliable, the
fail-closed handler is exactly as affected as the rest of the script — a
chain left empty here rather than denying means the trap could not do its
job, which is a finding about this PR, not about your host.

Expect **exactly two rules**, not an empty chain and not the full nine:

```text
-A DRAKVUF_ISOLATION -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -o xenbr1.+ -j DROP
```

You should also see on stderr:

```text
network-setup.sh: FAILED during: <step> (exit N)
root@drakvuf:~/sandbox_project/automation# sudo ./network-setup.sh 999999
DRAKVUF_NAT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_ISOLATION  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
Error: any valid prefix is expected rather than "172.16.256.1/24".
network-setup.sh: FAILED during: addressing xenbr1.256 (exit 1)
network-setup.sh: DRAKVUF_ISOLATION left DENYING all analysis-VLAN traffic; re-run to restore

We don't check the number of clones

network-setup.sh: DRAKVUF_ISOLATION left DENYING all analysis-VLAN traffic; re-run to restore
```

Then confirm it converges back:

```bash
sudo ./network-setup.sh 2
echo "exit status: $?"            # expect: 0
sudo iptables -S DRAKVUF_ISOLATION | wc -l   # expect: 10 (9 rules + the -N line)
```

`999999` is chosen to fail in the VLAN loop — the exact span that used to
leave the chain empty. If it instead fails during argument validation, the
trap correctly does nothing (there is no chain to secure yet); use a
smaller-but-still-failing value, or temporarily `ip link del xenbr1.2`
between runs to force a mid-loop failure.

```text
root@drakvuf:~/sandbox_project/automation# sudo ./network-setup.sh 999999
DRAKVUF_NAT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_ISOLATION  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
Error: any valid prefix is expected rather than "172.16.256.1/24".
network-setup.sh: FAILED during: addressing xenbr1.256 (exit 1)
network-setup.sh: DRAKVUF_ISOLATION left DENYING all analysis-VLAN traffic; re-run to restore
root@drakvuf:~/sandbox_project/automation# echo "exit status: $?"            # expect: non-zero
exit status: 1
root@drakvuf:~/sandbox_project/automation# ip a  | less -> xenbr1.$i from 1 to 248 (we should put some guards)
root@drakvuf:~/sandbox_project/automation# sudo iptables -S DRAKVUF_ISOLATION
# Warning: iptables-legacy tables present, use iptables-legacy to see them
-N DRAKVUF_ISOLATION
-A DRAKVUF_ISOLATION -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -o xenbr1.+ -j DROP
root@drakvuf:~/sandbox_project/automation# sudo nft list chain ip filter DRAKVUF_ISOLATION    # nft form
table ip filter {
	chain DRAKVUF_ISOLATION {
		iifname "xenbr1.*" counter packets 0 bytes 0 drop
		oifname "xenbr1.*" counter packets 0 bytes 0 drop
	}
}
root@drakvuf:~/sandbox_project/automation# sudo ./network-setup.sh 2
DRAKVUF_NAT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_ISOLATION  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_INPUT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_ISOLATION6  all opt    in * out *  ::/0  -> ::/0  
DRAKVUF_INPUT6  all opt    in * out *  ::/0  -> ::/0  
network-setup.sh: provisioned 2 VLAN sub-interface(s) on xenbr1
root@drakvuf:~/sandbox_project/automation# echo "exit status: $?"            # expect: 0
exit status: 0
root@drakvuf:~/sandbox_project/automation# sudo iptables -S DRAKVUF_ISOLATION | wc -l   # expect: 10 (9 rules + the -N line)
# Warning: iptables-legacy tables present, use iptables-legacy to see them
10
root@drakvuf:~/sandbox_project/automation# 

Exit status of failing run: 1
Rules left in chain (expect 2): 2
Stderr message present?  yes
Converged back on re-run?  YES. 10 is the correct answer -- `iptables -S`
  prints 9 rules plus the `-N` line. The summary line asked for 9 while the
  command comment above said 10; the runbook contradicted itself and has
  been corrected.

FINDING (new, 2026-08-12): the failure exposed a missing guard. See below.
```

### Finding F3 — no upper bound on the clone count

The failure landed at `addressing xenbr1.256`, and the reason is the
addressing scheme rather than anything about VLANs:

```text
Error: any valid prefix is expected rather than "172.16.256.1/24".
```

The slot index is the third octet of `172.16.<slot>.0/24`, so 256 cannot be
expressed. 802.1Q itself would allow 4094. Argument validation checked
"integer" and ">= 1" and had no upper bound at all, so `999999` was
accepted and the script worked its way up to slot 256 before failing.

**Fixed in this PR** at the maintainer's direction: the count is now capped
at 254 — 255 would work arithmetically and is excluded as deliberate margin,
the documented working maximum being 128.

### Finding F4 — interfaces created before a failure are not removed

The same run left `xenbr1.1` … `xenbr1.255` and their addresses on Dom0.
The fail-closed trap secures the firewall chain and nothing else; the
subsequent successful `network-setup.sh 2` does not remove them either, so
they persist until reboot.

**Not a containment gap** — every isolation rule matches the `xenbr1.+`
wildcard, so the strays are covered, and `DRAKVUF_INPUT` drops clone→Dom0
traffic regardless of slot. It is stale state, not exposure.

**Pre-existing, and not fixed here.** The old script did the same; it simply
left the chain empty as well, which was the louder problem. F3 removes the
reachable cause. Cleaning up partial provisioning is follow-up work and is
recorded as a `KNOWN GAP` at `network-setup.sh:249`.

Cleanup used on 2026-08-12:

```bash
ip -br link show | grep -c '^xenbr1\.'          # how many are there
for i in $(seq 3 255); do ip link del "xenbr1.$i" 2>/dev/null; done
ip -br addr show | grep xenbr1                  # expect xenbr1, .1, .2 only
```

## Step 8 — One benign end-to-end analysis

Prove the pipeline still works, not just the firewall.

```bash
cd /root/sandbox_project
sudo ./automation/run_analysis-ubuntu.sh
#   drop a benign fixture into /malware_incoming/ubuntu/
#   wait for completion, then:
ls -la /malware_finished/ubuntu/
wc -l /malware_finished/ubuntu/<id>/drakvuf.log
```

The clone must still reach the Internet and resolve names — that is what
the new ACCEPT rules are for, and a passing step 5 with a failing analysis
here would mean something else broke.

```text
root@drakvuf:~/sandbox_project# ls -la /malware_finished/ubuntu/
total 12
drwxr-xr-x 3 root root 4096 ago 12 11:23 .
drwxr-xr-x 9 root root 4096 ago  9 18:18 ..
drwxr-xr-x 2 root root 4096 ago 12 11:24 107529d281ee10a684e91342f0bb19df
root@drakvuf:~/sandbox_project# wc -l /malware_finished/ubuntu/107529d281ee10a684e91342f0bb19df/drakvuf.log
91080 /malware_finished/ubuntu/107529d281ee10a684e91342f0bb19df/drakvuf.log

Provisioning exit status: 0
Analysis completed normally: Yes
drakvuf.log line count: 91080
Result directory: /malware_finished/ubuntu/107529d281ee10a684e91342f0bb19df/
```

## Step 9 — Return Dom0 to a merged branch

**Do not skip this, and do not leave it for later.** Dom0 runs real
analyses; leaving it on an unmerged branch means the next run executes
unreviewed code, and nothing about the checkout announces itself.

> **Order matters: merge PR #10 BEFORE running this step.** The commands
> below do `git checkout master && git pull`, which only brings the
> DRAFT-029 commits down once they are *on* master. Run it against an
> unmerged master and Dom0 reverts to the **old** `network-setup.sh` while
> the **new** chains are still installed — the one combination nothing has
> tested.
>
> Check first:
>
> ```bash
> git -C /root/sandbox_project fetch origin
> git -C /root/sandbox_project log origin/master --oneline -1
> ```
>
> If that does not show the DRAFT-029 commits, stop and merge first.

If the test **passed** and PR #10 has been merged:

```bash
cd /root/sandbox_project
git fetch origin
git checkout master
git pull
git branch -d draft-029-terminal-chains
git log -1 --oneline                          # should contain the DRAFT-029 commit
grep -c 'j ACCEPT' automation/network-setup.sh   # expect > 0, now from master
```

If the test **failed**, or the PR is not merged yet:

```bash
cd /root/sandbox_project
git checkout master
git status --porcelain                  # expect empty
```

Then restore the old ruleset and re-provision with the old script, so the
host is not left with new chains and an old script:

```bash
sudo iptables-restore  < /root/iptables-pre-DRAFT-029.rules
sudo ip6tables-restore < /root/ip6tables-pre-DRAFT-029.rules
sudo /root/sandbox_project/automation/network-setup.sh 2
sudo iptables -S DRAKVUF_ISOLATION       # expect: back to 5 rules
```

```text
root@drakvuf:~/sandbox_project# cd /root/sandbox_project
root@drakvuf:~/sandbox_project# git fetch origin
\u00e7remote: Enumerating objects: 18, done.
remote: Counting objects: 100% (18/18), done.
remote: Compressing objects: 100% (3/3), done.
remote: Total 8 (delta 5), reused 7 (delta 5), pack-reused 0 (from 0)
Unpacking objects: 100% (8/8), 20.57 KiB | 236.00 KiB/s, done.
From github.com:evilbootloader/drakvuf-multios-sandbox
   e794045..c6abace  draft-029-terminal-chains -> origin/draft-029-terminal-chains
   229f7be..aed37af  master                    -> origin/master
root@drakvuf:~/sandbox_project# git checkout master
Switched to branch 'master'
Your branch is behind 'origin/master' by 5 commits, and can be fast-forwarded.
  (use "git pull" to update your local branch)
root@drakvuf:~/sandbox_project# git pull
\u00e7Updating bc199db..aed37af
Fast-forward
 .github/issue-drafts/DRAFT-022.md         |   87 +++++++++--
 .github/issue-drafts/DRAFT-029.md         |  476 ++++++++++++++++++++++++++++++++++---------------------
 .github/issue-drafts/issue-index.md       |   49 +++++-
 automation/network-setup.sh               |  149 ++++++++++++++++--
 docs/architecture/networking.md           |  116 ++++++++++++--
 docs/roadmap/project-roadmap.md           |    1 +
 docs/runbooks/04-deploy-network-isolation.md |   12 +-
 docs/runbooks/05-deploy-terminal-chains.md   | 1370 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 8 files changed, 2037 insertions(+), 223 deletions(-)
 create mode 100644 docs/runbooks/05-deploy-terminal-chains.md
root@drakvuf:~/sandbox_project# git branch -d draft-029-terminal-chains
Deleted branch draft-029-terminal-chains (was e794045).
root@drakvuf:~/sandbox_project# git log -1 --oneline                          # should contain the DRAFT-029 commit
aed37af (HEAD -> master, origin/master, origin/HEAD) Merge pull request #10 from evilbootloader/draft-029-terminal-chains
root@drakvuf:~/sandbox_project# grep -c 'j ACCEPT' automation/network-setup.sh   # expect > 0, now from master
4
root@drakvuf:~/sandbox_project# sudo iptables-restore  < /root/iptables-pre-DRAFT-029.rules
root@drakvuf:~/sandbox_project# sudo ip6tables-restore < /root/ip6tables-pre-DRAFT-029.rules
root@drakvuf:~/sandbox_project# sudo /root/sandbox_project/automation/network-setup.sh 2
DRAKVUF_NAT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_ISOLATION6  all opt    in * out *  ::/0  -> ::/0  
DRAKVUF_INPUT6  all opt    in * out *  ::/0  -> ::/0  
network-setup.sh: provisioned 2 VLAN sub-interface(s) on xenbr1
root@drakvuf:~/sandbox_project# sudo iptables -S DRAKVUF_ISOLATION       # expect: back to 5 rules
# Warning: iptables-legacy tables present, use iptables-legacy to see them
-N DRAKVUF_ISOLATION
-A DRAKVUF_ISOLATION -i xenbr1.+ ! -o xenbr0 -j DROP
-A DRAKVUF_ISOLATION -d 10.0.0.0/8 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 172.16.0.0/12 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 192.168.0.0/16 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 169.254.0.0/16 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -i xenbr1.+ -o xenbr0 -j ACCEPT
-A DRAKVUF_ISOLATION -o xenbr1.+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DRAKVUF_ISOLATION -o xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -i xenbr1.+ -j DROP
root@drakvuf:~/sandbox_project# 
```

---

## Results summary

Fill in when the run completes.

| Step | What | Result |
|---|---|---|
| 0 | Preconditions + post-reboot baseline | **Pass.** `xenbr1` survived (DOWN), no VLAN sub-interfaces, nft empty, `ip_forward` 0 and not persistent |
| 0b | **Backend STOP gate** (can iptables write?) | **Pass.** `iptables-nft` via alternatives; fresh chain round-tripped cleanly. Legacy tables also present — finding F1 |
| 1 | Rollback captured | **Pass.** 182 B IPv4; IPv6 capture 0 B, correct — no v6 ruleset existed |
| 2 | Provisioned with the OLD script from master | **Pass.** Exit 0, 5 rules |
| 2b | **Chain-readability STOP gate** | **Pass, row 1.** The incompatibility did not reproduce. `-C` returned 0 on all three jumps; counts 1/1/1 after three runs — idempotence intact |
| 2c | Inherited permit demonstrated | **Pass.** `-P FORWARD DROP` → 100% loss; `ACCEPT` → replies. The defect, shown |
| 3 | Branch checked out | **Pass.** `e794045`; `bash -n`/`dash -n`/`shellcheck` clean on the host |
| 4 | Nine rules, correct order | **Pass.** 9 rules, both ACCEPTs below all four RFC1918 DROPs |
| 5 | **Identical under both policies** | **Pass.** All four probes unchanged when `-P FORWARD` flipped. Guest output transcribed, not captured — see the limitation note in that step |
| 6 | Both ACCEPTs have counters | **Pass.** Uplink 10 pkts, return path 9. Rule 4 shows 2 — the blocked LAN ping, proving rule order empirically |
| 7 | Fails closed, converges back | **Pass.** Exactly 2 DROP rules after failure, correct stderr, converges on re-run. Exposed findings F3 and F4 |
| 8 | Benign end-to-end analysis | **Pass.** Exit 0, 91 080 log lines, result `107529d2…` |
| 9 | Dom0 returned to master | **Pending** — waits on PR #10 merging |

**Overall: PASS.** The acceptance criterion is met and no code change was
required on account of the host's condition. One change *was* added in
response to step 7 — the clone-count guard, finding F3.

Two notes carried out of this run that belong to other work:

- Step 8 reused result directory `107529d281ee10a684e91342f0bb19df`, the
  same MD5 as DRAFT-028's run, so the same fixture overwrote the previous
  result. Expected under the current flat MD5-keyed layout; relevant to
  DRAFT-018, which owns replacing it.
- `DRAKVUF_INPUT` and `DRAKVUF_INPUT6` carried non-zero counters (38 and 26
  packets) before any clone booted. That is Dom0's own multicast on the
  freshly-addressed VLAN interfaces meeting the drop rule — expected, and
  worth knowing so step 6's counters are not read as starting from zero.

## Security

Step 5 is the issue's central evidence. Everything else is supporting.

What this deployment does **not** establish: clones still have deliberate
unrestricted Internet egress, and on a residential uplink under personal
operation that is a live question rather than a settled default — see
roadmap risk #13 and DRAFT-022. Making the permit explicit is not the same
as deciding it should exist. **No non-benign sample should run with
networking enabled** on the strength of this runbook passing.

Android's reaction to an unreachable gateway is still untested (DRAFT-013),
and this change does not touch it.

**Added 2026-08-12.** The `iptables-nft` readback failure diagnosed in step 2b is a
containment question until 0b.3 answers it, not merely a tooling
annoyance. Between 2026-08-11 and 2026-08-12 this project could not read
its own firewall chains with the tool that wrote them — and the last time
this repository had a rule it could not verify, the rule had never worked
(NET-01). Do not assume the rules are live because they were live
yesterday; read them with `nft` and confirm.

> **Revised later the same day.** The premise is wrong — the project *could*
> read its chains; there were no chains to read. But the closing instruction
> survives its own reasoning and is worth more than the paragraph it ends:
> **do not assume the rules are live because they were live yesterday.** In
> the actual sequence a reboot removed every rule, the tool said something
> confusing, and the write-up concluded filtering was fine. Reading the
> chains and confirming is exactly what was skipped.
>
> The durable lesson is narrower and harsher than "verify after changes":
> **the absence of containment presents as an error message, and error
> messages get rationalised.** DRAFT-038 exists to make that a machine's
> job rather than a reader's.
