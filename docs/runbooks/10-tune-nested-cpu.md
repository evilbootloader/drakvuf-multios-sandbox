# Nested CPU allocation: is Dom0 starved, and can L0 give it more?

> **Status: written 2026-08-27, NOT YET EXECUTED.** Every `EVIDENCE` block is
> empty and stays empty until an operator pastes real output into it. Per this
> project's convention a runbook is committed *after* execution, so if you are
> reading this in git history with the blocks still empty, it was committed
> early by mistake.
>
> **Every command here is Candidate.** None has been run on this lab. None can
> be run from the development container, which is neither Dom0 nor the Proxmox
> host.
>
> **ANNOTATION 2026-08-29 — never executed, and never will be. Not pending.**
> The question is *"can L0 give Dom0 more CPU?"* **There is no L0.** Proxmox was
> erased on 2026-08-28 (`12-baremetal-trial.md` §A1b) and Dom0 now boots the
> metal, so the premise is gone rather than the answer being outstanding. The
> derived table in `docs/CURRENT-STATE.md` shows this runbook as `Executed: no`,
> which is accurate and will stay that way — read it as *closed*, not as work
> waiting for an operator.
>
> **The underlying question was answered elsewhere, better.** What Dom0 should
> get on bare metal is settled by `dom0_max_vcpus=6` pinned to the first six
> *online* pCPUs (`0,2,4,6,8,10` under `smt=0`) with clones on `12,14`; see
> `CURRENT-STATE.md` §1.2. Whether CPU placement moves throughput at all was
> then measured directly in `12-baremetal-trial.md` §H2 — three placement
> variants inside 0.6% of each other. Both supersede everything below.
>
> **`sandboxd` is not a systemd service.** It runs in the foreground and logs to
> stderr via `logging.basicConfig` (`sandboxd/daemon.py:454`). There is no
> journal to query, so §0.3 starts it under `tee` and every later step reads
> that file.

## Why this runbook exists, and why it may end in "change nothing"

`09-verify-sandboxd-and-console.md` §F7c already measured the Xen layer and
reached a flat conclusion:

    1 clone   Domain-0   99.2 / 99.1 / 99.6 %   of 600% available
    2 clones  Domain-0  196.7 / 198.8 / 195.9 %

One DRAKVUF event loop saturating one core, one per trace, five cores idle
throughout. §F7c states the consequence directly: **"adding Dom0 vCPUs would do
nothing."** That is correct, and this runbook does not set out to overturn it.

What §F7c could not see is the layer beneath it. **`xentop` measures Xen's
opinion of its own CPUs, and Xen's CPUs are KVM vCPUs.** When L0 deschedules
one, Xen is never told: wall time keeps advancing on that pCPU and whatever
vCPU was running there keeps accruing runtime. A Dom0 thread reported at 99.2%
may be receiving substantially less than one physical core.

Dom0 cannot see it either. Its steal accounting is `xen-steal-clock`, which
reports time stolen *by Xen*, not by KVM. **The nesting tax falls in a blind
spot between the two layers, and Part B is the only thing in this document that
can measure it.**

Measure first, and expect to stop. Parts D and E are worth doing only if Part B
finds something.

| Part | Where | What it answers |
|---|---|---|
| 0 | both | Identifiers and shells every later step needs |
| A | Proxmox | What is the Xen VM actually permitted to use? |
| B | both | **Is a Dom0 core a real core?** The decisive measurement |
| C | Proxmox | Are the nested-virt features that make traps cheap switched on? |
| D | Proxmox | Pinning to specific host cores — what `affinity` does and does not do |
| E | Dom0 | Headroom for Dom0's *non*-DRAKVUF work at full concurrency |
| F | both | Two recorded/observed discrepancies to settle |

Three shells, kept open throughout:

- **PVE** — `root@pve1`, the Proxmox host
- **DOM0** — `root@drakvuf`, the Xen VM
- **DOM0-B** — a second Dom0 shell, because §0.3 occupies the first

---

# Part 0 — identifiers and the topology this all turns on

**VM 101 is `drakvuf`, the Xen L1 host** — the one under investigation.
**CT 102 is the platform** (Postgres, MinIO, the API), and is *not* the thing
being throttled. Both from `08-deploy-platform-lxc.md:111` and `:2068`.

## 0.1. The host is hybrid, and that is the whole story

From §F5c of `09-verify-sandboxd-and-console.md`, measured on Proxmox:

    /sys/devices/cpu_core/cpus  ->  0-15    P-cores:  8 physical, SMT, 2 threads each
    /sys/devices/cpu_atom/cpus  -> 16-31    E-cores: 16 physical, no SMT
                                            32 logical CPUs total

VM 101 as it stands: **12 vCPUs, 20 GiB, `affinity: 0-15`,
`cpu: host,flags=-hv-evmcs;-hv-tlbflush`.**

And inside it (`09-verify-sandboxd-and-console.md:2046-2052`):

    dom0_max_vcpus=6 dom0_vcpus_pin    Dom0    -> Xen pCPU 0-5
    cpus = "6-11" in misc/*_sandbox.cfg  clones -> Xen pCPU 6-11
    SANDBOXD_MAX_CLONES=2                       2 clones at a time

> ### The arithmetic that may already answer this runbook
>
> **12 Xen pCPUs are mapped onto 8 physical P-cores.**
>
> 12 vCPU threads against 16 hardware threads is not oversubscription — that
> part is fine. But those 16 threads are **8 physical cores**, so at least four
> cores must carry two Xen pCPUs each, and `affinity: 0-15` is a *set*, not a
> placement: the Linux scheduler chooses freely inside it and re-chooses
> constantly.
>
> So Dom0's saturated DRAKVUF thread can be sharing one physical core's
> execution resources with another Dom0 vCPU or a clone's vCPU — and **Xen
> cannot see it, cannot account for it, and cannot schedule around it**, because
> QEMU presents 12 flat cores and Xen's own `smt=0` is a no-op against a
> topology it was never shown.
>
> §F5d anticipated exactly this in its own note — *"Give Dom0 whole cores, not
> single SMT siblings … F1's problem reintroduced one level down, where Xen
> cannot see it"* — but setting `--affinity 0-15` does not achieve it. Nothing
> currently does. **§D4 is the only mechanism in this document that can.**
>
> Part B measures whether it is actually costing anything before anyone changes
> a line.

Confirm none of this has drifted, in **every PVE shell** used later:

```bash
export XEN_VMID=101
export QPID=$(cat /run/qemu-server/${XEN_VMID}.pid)
echo "xen vmid=${XEN_VMID} qemu pid=${QPID}"

qm list
cat /sys/devices/cpu_core/cpus    # expect 0-15  (P-cores)
cat /sys/devices/cpu_atom/cpus    # expect 16-31 (E-cores)
lscpu -e=CPU,CORE,MAXMHZ | head -20
qm config 101 | grep -E '^(cores|sockets|memory|affinity|cpu|balloon|cpulimit|cpuunits):'
```

Expect `cores: 12`, `affinity: 0-15`. If `cores` has changed, the physical-core
arithmetic above changes with it — redo it before continuing.

EVIDENCE 0.1

```
(paste all of the above)
```

## 0.2. Confirm Dom0's vCPU range (DOM0)

Part B needs one Dom0 vCPU that is idle, and Part E needs to know the
partition. Both come from here.

```bash
xl vcpu-list 0
xl info | grep -E 'nr_cpus|threads_per_core|cores_per_socket'
```

Record the highest Dom0 vCPU number — the examples below use **vCPU 5**,
matching §F7's Dom0-on-0–5 partition. If `xl vcpu-list 0` shows a different
range, substitute throughout.

EVIDENCE 0.2

```
(paste here)
```

## 0.3. Start sandboxd with its output captured (DOM0)

There is no service and no journal. Start it under `tee` so Part E has
something to read. `2>&1` because `basicConfig` writes to stderr.

```bash
mkdir -p /var/log/sandboxd
cd /root/drakvuf-multios-sandbox
set -a; . /etc/sandboxd/sandboxd.env; set +a
.venv-sandboxd/bin/python -m sandboxd.daemon 2>&1 \
  | tee -a /var/log/sandboxd/cputune-$(date +%Y%m%d-%H%M).log
```

**This shell is now occupied.** Use DOM0-B for everything else. Stop it with
Ctrl-C when the runbook is finished; it drains in-flight analyses before
exiting.

Note the exact log path — later steps refer to it as `$SBLOG`. In DOM0-B:

```bash
export SBLOG=$(ls -t /var/log/sandboxd/cputune-*.log | head -1)
echo "$SBLOG"
```

EVIDENCE 0.3

```
(paste the first ~10 lines: sweep summary, register, reconcile)
```

---

# Part A — what L0 permits

## A1. The Xen VM's configuration (PVE)

Read before changing anything. A `cpulimit` nobody remembers setting would
explain a great deal, and costs one command to rule out.

```bash
qm config ${XEN_VMID}
```

Look for, and record even when absent:

| Key | Meaning | What you want here |
|---|---|---|
| `cpulimit` | Hard ceiling in whole-core units, `0` = unlimited (default `0`) | `0`, or ≥ the vCPU count |
| `cpuunits` | Relative weight, cgroup v2 default `100`. **Only bites under host contention** | `100` unless deliberately raised |
| `affinity` | Host cores the VM may use. See Part D — it is not what it looks like | absent for now |
| `cpu` | CPU model | `host` — see C2 |
| `balloon` | `0` disables ballooning | `0` |
| `numa` | NUMA topology exposure | see A2 |
| `sockets` / `cores` | Topology presented to Xen | one socket unless the host is genuinely multi-socket |

A one-line check for the two that silently cap:

```bash
qm config ${XEN_VMID} | grep -E '^(cpulimit|cpuunits|affinity|cpu|balloon|numa|sockets|cores):' \
  || echo "none of cpulimit/cpuunits/affinity set (all at defaults)"
```

EVIDENCE A1

```
(paste both commands here)
```

## A2. Host topology and current thread placement (PVE)

```bash
lscpu -e
numactl --hardware
nproc
```

Then the one that matters — where the vCPU threads actually are:

```bash
for i in 1 2 3; do
  ps -eLo tid,psr,pcpu,comm -p ${QPID} | grep 'CPU .*/KVM'
  echo "--- sample $i ---"
  sleep 1
done
```

`psr` is the host CPU each thread is on. **If `psr` changes between samples,
the Linux scheduler is migrating Xen's pCPUs across host cores** — the specific
problem Part D addresses.

EVIDENCE A2

```
(paste here; state explicitly whether psr was stable across the three samples)
```

---

# Part B — is a Dom0 core a real core?

**The decisive measurement.** Everything after it is conditional on the answer.

## B1. The method, and why it avoids the blind spot

Do not compare benchmark scores across the two machines — different toolchains
and `openssl` builds make that a measurement of compilers. Instead measure the
*same wall-clock window* from both sides:

1. In Dom0, pin a pure userspace busy loop to one Dom0 vCPU for 30 seconds. A
   userspace spin loop generates almost no VM exits, so it should consume very
   close to 30 seconds of real CPU.
2. On Proxmox, read the cumulative CPU time of the QEMU thread backing that
   same vCPU, before and after.
3. Divide. **The ratio is what fraction of a physical core Dom0 actually gets.**

The mapping is stable and 1:1 because `dom0_vcpus_pin` is set: Dom0 vCPU *N* →
Xen pCPU *N* → QEMU thread `CPU N/KVM`. §F7 confirmed the Dom0 half with
`xl vcpu-list`.

**Run with no analyses in flight**, so the number describes the platform rather
than the load. Part E3 repeats it under load.

## B2. Locate the backing thread and read the counter (PVE)

```bash
export VCPU=5
export TID=$(grep -l "^CPU ${VCPU}/KVM$" /proc/${QPID}/task/*/comm | awk -F/ '{print $5}')
export TICK=$(getconf CLK_TCK)
echo "vcpu ${VCPU} -> tid ${TID}, CLK_TCK=${TICK}"

# utime + stime, in clock ticks
export BEFORE=$(awk '{print $14+$15}' /proc/${QPID}/task/${TID}/stat)
echo "before=${BEFORE}"
```

If `TID` comes back empty, the vCPU number is wrong — re-check §0.2.

EVIDENCE B2 (before)

```
(paste the echo lines here)
```

## B3. Run the load (DOM0-B)

Start this within a few seconds of B2.

```bash
taskset -c 5 timeout 30 sh -c 'while :; do :; done'
```

While it runs, from a third shell or immediately after, confirm Xen agrees the
vCPU is pegged:

```bash
xl vcpu-list 0
xentop -b -i 3 -d 1
```

EVIDENCE B3

```
(paste xl vcpu-list and xentop captured during the loop)
```

## B4. Read the counter again and compute (PVE)

Run as soon as the loop finishes.

```bash
export AFTER=$(awk '{print $14+$15}' /proc/${QPID}/task/${TID}/stat)
echo "after=${AFTER}"
awk -v a="$AFTER" -v b="$BEFORE" -v t="$TICK" \
  'BEGIN { s=(a-b)/t; printf "host_seconds=%.2f  ratio=%.3f\n", s, s/30 }'
```

EVIDENCE B4

```
(paste here)
```

## B5. The verdict

| ratio | Reading | Do next |
|---|---|---|
| ≥ 0.95 | Dom0 gets essentially a full physical core. §F7c stands unchallenged. | **Stop.** CPU allocation is not the lever. Part C anyway (three read-only commands), then Part E only if concurrency worries you. |
| 0.80 – 0.95 | Mild tax. Probably scheduler migration rather than contention. | Part C, then Part D2/D3 |
| < 0.80 | Real starvation the Xen-side numbers could never show. | Part A findings, then C, then all of D |

**A ratio meaningfully below 1 would mean §F7c's "the only remaining lever is
fewer events" is incomplete** — not wrong about Xen, but measuring a saturated
thread that was never given a whole core to saturate.

EVIDENCE B5

```
ratio = ______   verdict = ______
```

---

# Part C — the features that make each trap cheap

Attacks the per-event cost §F7c identified, rather than the CPU quantity it
ruled out. **Do this even if Part B says ≥ 0.95** — three read-only commands.

## C1. Nested virtualisation features (PVE)

```bash
for f in nested ept enable_shadow_vmcs enable_apicv; do
    printf '%-20s ' "$f"; cat /sys/module/kvm_intel/parameters/$f 2>/dev/null \
      || echo "(absent -- AMD host? try /sys/module/kvm_amd/parameters/nested)"
done
```

All four should read `Y`. `nested` and `ept` are set by
`docs/drakvuf-on-xen-nested-within-proxmox.md:157`; **the other two are not
mentioned anywhere in this project's setup**, which is the reason to look.

**`enable_shadow_vmcs` is the one that matters most here.** Xen issues
`VMREAD`/`VMWRITE` constantly while handling L2 exits, and without VMCS
shadowing every one of those traps to L0. The KVM documentation recommends it
specifically when an L2 guest is slow, and describes the gain as large on
workloads with many context switches — DRAKVUF trapping every syscall is the
maximal case. It defaults to `Y` where the CPU supports it, so this most likely
confirms rather than fixes. If it reads `N`, it is the single highest-value line
in this document.

If any read `N`, the fix is a module option and a host reboot:

```bash
cat /etc/modprobe.d/kvm-intel.conf
# to change:
echo "options kvm_intel nested=Y ept=Y enable_shadow_vmcs=Y enable_apicv=Y" \
  > /etc/modprobe.d/kvm-intel.conf
update-initramfs -u -k all
# reboot required -- takes the whole lab down, schedule it
```

EVIDENCE C1

```
(paste here)
```

## C2. What Xen actually detected (DOM0-B)

```bash
xl dmesg | grep -Ei 'VMX|SVM|EPT|NPT|HAP|nested|altp2m'
grep -m1 -oE 'vmx|svm' /proc/cpuinfo
xl info | grep -E 'nr_cpus|threads_per_core|cores_per_socket|virt_caps|xen_commandline'
```

EVIDENCE C2

```
(paste here)
```

## C3. Hugepages — deliberately NOT applicable

General nested-Xen tuning advice recommends trying hugepages. **Do not.** This
lab boots `hap_1gb=0 hap_2mb=0` because DRAKVUF needs 4 KB page granularity for
altp2m tracing. Superpages would defeat VMI rather than speed it up, and the
cost in TLB pressure is a price this design pays on purpose.

Recorded here so the next reader does not rediscover the advice and apply it.

---

# Part D — pinning to specific host cores

Two facts about Proxmox's `affinity` decide this part, and both run against the
intuition of the setting's name.

**1. `affinity` is a cpuset on the whole QEMU process, not per-vCPU pinning.**
The documented meaning is "List of host cores used to execute guest processes",
applied at process level. `affinity: 2-9` does not map vCPU 0 to core 2 — it
tells the Linux scheduler that *all* the VM's threads may use cores 2–9, and
leaves it free to shuffle them within that set.

**2. `affinity` is an allowlist, not an exclusion.** It stops Xen's threads
leaving the set. It does nothing to stop other VMs, containers, backup jobs or
host daemons entering it.

## D1. Why this matters more here than in an ordinary VM

Xen believes `dom0_vcpus_pin` has given Dom0 a stable, private pCPU. Underneath,
that pCPU is a QEMU thread the Linux scheduler may migrate across host cores
every few milliseconds. **L0 migration silently undoes L1 pinning:** §F7's
Dom0-on-0–5 / clones-on-6–11 partition sits on top of threads that wander.

For a single-threaded, latency-bound consumer — which §F7c proved the DRAKVUF
event loop is — that costs cache and TLB locality on exactly the bottleneck
thread. This is the one place where the pinning the Xen wiki warns about
("Pinning can have unexpected negative effects just as often as beneficial
ones") has a specific argument in its favour rather than a general hope.

## D2. The affinity is already set — the question is the placement inside it

§F5d set `affinity: 0-15` and it should stay. Confining VM 101 to P-cores is
what makes `cpu: host` honest (§F5b), and widening it to include E-cores would
reintroduce the CPUID-enumeration hazard that change was made to remove. **Do
not widen the affinity to 0-31.**

What is unsolved is *placement within* those 16 threads: 12 Xen pCPUs, 8
physical cores, scheduler's choice. Two ways to fix it, and the choice depends
on whether you want to keep six clone slots.

**Target A — a whole physical core for every Xen pCPU (recommended today).**
Reduce VM 101 to 8 vCPUs and pin them one per physical P-core:

    Xen pCPU 0-5  (Dom0)   -> host CPU 0, 2, 4, 6, 8, 10   physical cores 0-5
    Xen pCPU 6-7  (clones) -> host CPU 12, 14              physical cores 6-7
    host CPU 1,3,5,7,9,11,13,15 (the SMT siblings) left idle

Every Xen pCPU becomes a whole core with no sibling contention, and Xen's
`smt=0` finally describes something true. It caps clones at 2, which is what
`SANDBOXD_MAX_CLONES=2` already does — **so today it costs nothing.** It does
mean raising concurrency later needs this revisited.

```bash
# only if Part B justified it
qm set 101 --cores 8
# and inside Dom0, narrow the clone range to match:
#   misc/*_sandbox.cfg :  cpus = "6-7"     (was "6-11")
```

**Target B — keep 12 vCPUs, give Dom0 the whole cores.** Preserves six clone
slots. Dom0 gets six unshared physical cores; the clones share the remaining
two, which they can afford because §F7c measured them paused ~93% of the time.

    Xen pCPU 0-5  (Dom0)   -> host CPU 0, 2, 4, 6, 8, 10   physical cores 0-5
    Xen pCPU 6-11 (clones) -> host CPU 12,13,14,15,1,3     cores 6,7 + two siblings

Neither target is achievable with `--affinity` alone — both need the per-vCPU
pinning in §D4. `--affinity` can only say *which 16 threads*, never *which
thread each vCPU gets*.

Record the current state before changing anything:

```bash
qm config 101 | grep -E '^(cores|affinity):'
for i in 1 2 3; do
  ps -eLo tid,psr,comm -p ${QPID} | grep 'CPU .*/KVM' | sort -k3 -V
  echo "--- sample $i ---"; sleep 1
done
```

Map each `psr` to its physical core with the §0.1 `lscpu -e` table. **Count how
many physical cores carry two busy vCPU threads** — that number is the problem
D4 removes.

EVIDENCE D2 (current placement)

```
(paste the three samples, and the physical-core sharing count)
```

If you change `--cores`, it takes effect at next VM start:

```bash
qm shutdown ${XEN_VMID} && sleep 30
qm start ${XEN_VMID}
# wait for Dom0 to come up, then re-export QPID -- it changed
export QPID=$(cat /run/qemu-server/${XEN_VMID}.pid)
for i in 1 2 3; do
  ps -eLo tid,psr,comm -p ${QPID} | grep 'CPU .*/KVM'; echo "--- $i ---"; sleep 1
done
```

Every `psr` should still be inside `0-15`.

**To revert a `--cores` change:** `qm set 101 --cores 12`, restart, and put the
clone range in `misc/*_sandbox.cfg` back to `cpus = "6-11"`.

EVIDENCE D2 (after any `--cores` change)

```
(paste the post-restart psr samples)
```

## D3. Make those cores exclusive — cpuset, not isolcpus (PVE)

`affinity: 0-15` stops Xen's threads leaving the P-cores. It does nothing to
stop **other guests** and **host processes** entering them, and those two need
different mechanisms. D3a and D3b are complementary, not alternatives — do both.

**On this host the split is free**, which is the happy consequence of it being
hybrid: give everything that is not VM 101 the **E-cores**, and the P-cores
belong to Xen alone.

```bash
export XEN_CORES="0-15"     # P-cores -- VM 101 only, already set by F5d
export HOST_CORES="16-31"   # E-cores -- Proxmox, CT 102, every other guest
echo "xen=${XEN_CORES}  everything else=${HOST_CORES}"
```

Sixteen E-cores is generous for a Postgres/MinIO container and the Proxmox
daemons, and nothing that matters to a trace runs there.

> **Why not `isolcpus`.** It is treated as deprecated: the isolation is fixed at
> boot and **cannot be changed at runtime**, which on a single-host lab means a
> GRUB edit and a full reboot to try a different split. The kernel's own guidance
> is to use cpusets instead. It also only helps with the *scheduler* — it does
> not stop anything you explicitly pin there. D3c keeps it as a last resort with
> the reasons it might still be wanted.
>
> The 2020 Proxmox forum answer to this question recommends the `cset` utility.
> That advice predates cgroup v2, which Proxmox 8/9 use, and `cset` is largely
> unmaintained. D3a/D3b achieve the same thing with what is already installed.

### D3a. Keep other guests off (cpuset per guest)

```bash
qm list
pct list
```

For every **other** VM — 101 is the one being protected, so exclude it:

```bash
for v in $(qm list | awk 'NR>1 && $1 != 101 {print $1}'); do
    echo "pinning VM $v to ${HOST_CORES}"
    qm set "$v" --affinity "${HOST_CORES}"
done
qm list | awk 'NR>1 {print $1}' | while read -r v; do
    printf '%s: ' "$v"; qm config "$v" | grep affinity || echo '(none)'
done
```

VM 101 should be the only one showing `affinity: 0-15`.

**`pct` has no `affinity` option**, so containers need a cpuset written into
their config directly. The platform LXC is 102:

```bash
cp /etc/pve/lxc/102.conf /etc/pve/lxc/102.conf.bak
echo "lxc.cgroup2.cpuset.cpus: ${HOST_CORES}" >> /etc/pve/lxc/102.conf
pct stop 102 && pct start 102
pct exec 102 -- grep Cpus_allowed_list /proc/self/status
```

The last command should report only `${HOST_CORES}`. Repeat for any other
container. **To revert:** delete the `lxc.cgroup2.cpuset.cpus` line and restart.

### D3b. Keep host services off (systemd CPUAffinity)

`CPUAffinity=` in the `[Manager]` section of `/etc/systemd/system.conf` sets the
affinity of PID 1 **and the default affinity of every process it forks** — so
all Proxmox daemons, backup jobs and timers inherit it. This is the piece that
D2 and D3a cannot do.

```bash
cp /etc/systemd/system.conf /etc/systemd/system.conf.bak
grep -n '^\[Manager\]\|CPUAffinity' /etc/systemd/system.conf

# set it (idempotent):
sed -i '/^#\?CPUAffinity=/d' /etc/systemd/system.conf
sed -i "/^\[Manager\]/a CPUAffinity=${HOST_CORES}" /etc/systemd/system.conf
grep -A2 '^\[Manager\]' /etc/systemd/system.conf
```

Applying it to already-running services needs a reboot of the host. To confirm
without one, check PID 1 after `systemctl daemon-reexec`:

```bash
systemctl daemon-reexec
taskset -pc 1
```

**Two caveats, both worth verifying rather than assuming:**

1. **cgroup v2 cpuset controller can reset it.** There is a known systemd issue
   where enabling the cpuset controller clears the affinity set this way.
   Proxmox 8/9 are cgroup v2, so check that it actually stuck:

   ```bash
   taskset -pc 1
   taskset -pc $(pgrep -o pvedaemon)
   ```

   If PID 1 shows the full core list rather than `${HOST_CORES}`, this mechanism
   is not holding on this host — record that and fall back to D3c.

2. **Kernel threads do not inherit it.** `CPUAffinity=` covers userspace only.
   Kernel worker threads can still run on Xen's cores. For this lab that is
   almost certainly irrelevant — the concern is other *guests*, not kswapd —
   but it is the one thing `isolcpus` does that this does not.

**To revert:** restore `/etc/systemd/system.conf.bak` and reboot.

### D3c. `isolcpus` — last resort only

Reach for it only if Part B measured real contention, D3a/D3b were applied, and
the ratio did not move. Note `rcu_nocbs=` is **redundant**: `nohz_full=` sets it
automatically, and passing both is a common copy-paste error.

```bash
cp /etc/default/grub /etc/default/grub.bak
# append to GRUB_CMDLINE_LINUX_DEFAULT, keeping what is already there:
#   isolcpus=2-13 nohz_full=2-13
nano /etc/default/grub
update-grub
# host reboot required -- takes the whole lab down, schedule it
grep -o 'isolcpus=[^ ]*\|nohz_full=[^ ]*' /proc/cmdline    # after reboot
```

**To revert:** restore `/etc/default/grub.bak`, `update-grub`, reboot.

EVIDENCE D3

```
D3a guests pinned:        ______
D3b `taskset -pc 1`:      ______   (did CPUAffinity survive cgroup v2?)
D3c isolcpus applied:     ______   (expected: no)
```

## D4. True per-vCPU pinning — only if B and D2 justify it

Proxmox has no native per-vCPU pinning. It needs a `post-start` hookscript that
finds each vCPU thread and pins it individually. **Do not write this before Part
B has produced a ratio** — a script that pins vCPUs while leaving the emulator
thread contending with them can be worse than no pinning at all.

Enable snippets on the storage, once:

```bash
pvesm status
pvesm set local --content vztmpl,iso,backup,snippets
mkdir -p /var/lib/vz/snippets
```

Write the hookscript:

```bash
cat > /var/lib/vz/snippets/pin-xen.sh <<'EOF'
#!/usr/bin/env bash
# Per-vCPU pinning for the Xen L1 VM. See docs/runbooks/10-tune-nested-cpu.md D4.
#
# post-start, not pre-start: pre-start runs even when the VM then fails to come
# up, leaving pins for a process that does not exist.
set -euo pipefail

VMID="$1"; PHASE="$2"
[ "$PHASE" = "post-start" ] || exit 0

# EDIT THESE THREE LINES ONLY.
TARGET_VMID="101"                      # drakvuf, the Xen L1 host
#
# One host thread per PHYSICAL P-core -- 0,2,4,... are the first threads of
# cores 0..7; their siblings 1,3,5,... are deliberately left idle so each Xen
# pCPU owns a whole core's execution resources. This is D2 Target A (8 vCPUs).
# For Target B (12 vCPUs) append  1 3 5 7  -- clones then share cores 0-3.
MAP=(0 2 4 6 8 10 12 14)
#
# E-cores. Emulator and iothreads must not sit on a P-core that a vCPU owns.
EMULATOR_CORES="16-31"

[ "$VMID" = "$TARGET_VMID" ] || exit 0

QPID=$(cat "/run/qemu-server/${VMID}.pid")

# vCPU threads: comm is exactly "CPU N/KVM"
for i in "${!MAP[@]}"; do
    tid=$(grep -l "^CPU ${i}/KVM\$" /proc/${QPID}/task/*/comm 2>/dev/null \
          | awk -F/ '{print $5}' || true)
    if [ -z "$tid" ]; then
        echo "pin-xen: no thread for vCPU $i" >&2
        continue
    fi
    taskset --cpu-list --pid "${MAP[$i]}" "$tid" >/dev/null
    echo "pin-xen: vCPU $i (tid $tid) -> host cpu ${MAP[$i]}"
done

# Everything else qemu runs -- emulator, iothreads -- off the vCPU cores, so it
# cannot contend with the thread this whole exercise is about.
for t in /proc/${QPID}/task/*; do
    tid=${t##*/}
    comm=$(cat "$t/comm" 2>/dev/null || true)
    case "$comm" in
        CPU\ *KVM) continue ;;
    esac
    taskset --cpu-list --pid "$EMULATOR_CORES" "$tid" >/dev/null 2>&1 || true
done
echo "pin-xen: non-vCPU threads -> ${EMULATOR_CORES}"
EOF

chmod +x /var/lib/vz/snippets/pin-xen.sh
bash -n /var/lib/vz/snippets/pin-xen.sh && echo "syntax ok"
grep -E '^(TARGET_VMID|MAP|EMULATOR_CORES)=' /var/lib/vz/snippets/pin-xen.sh
```

Confirm `MAP` has one entry per vCPU: 8 entries for D2 Target A, 12 for
Target B. A short `MAP` silently leaves the remaining vCPUs unpinned.

Register and restart:

```bash
qm set ${XEN_VMID} --hookscript local:snippets/pin-xen.sh
qm shutdown ${XEN_VMID} && sleep 30
qm start ${XEN_VMID}
export QPID=$(cat /run/qemu-server/${XEN_VMID}.pid)
```

Verify the pins held and are now one-to-one:

```bash
for i in 1 2 3; do
  ps -eLo tid,psr,comm -p ${QPID} | grep 'CPU .*/KVM' | sort -k3
  echo "--- $i ---"; sleep 1
done
```

Each vCPU thread should sit on its mapped core and **not move between samples**.
Then re-run Part B (§B2–B4) and compare ratios.

**To revert:** `qm set ${XEN_VMID} --delete hookscript`, restart the VM.

Only worth keeping if it buys the end-to-end chain:

    physical core -> QEMU vCPU thread -> Xen pCPU -> Dom0 vCPU

which is only meaningful because `dom0_vcpus_pin` already fixes the right-hand
half.

EVIDENCE D4

```
(the psr table before and after, and the before/after Part B ratio)
```

---

# Part E — Dom0's headroom for everything that is not DRAKVUF

Independent of Part B, and worth reading even if the ratio came back 1.0.

## E1. The arithmetic

From §F7c and §F6d:

    1 core per concurrent trace            (F7c, measured)
    5 concurrent traces before memory caps (F6d)
    6 Dom0 cores
    -> 5 cores of DRAKVUF, 1 core for everything else

"Everything else" is `sandboxd`'s HTTPS polling and its 10-second heartbeats
against a 120-second lease, `tcpdump` writing one pcap per VLAN, xenstore, the
toolstack, and the console relay when enabled.

**That is critically provisioned with no margin**, which sits badly against this
project's standing preference for margin over a measured constant. Both failure
modes are quiet:

- **`tcpdump` dropping packets** corrupts capture evidence and says nothing. A
  pcap missing the C2 callback looks exactly like a sample that made none.
- **A delayed heartbeat** lets the lease lapse; `maintenance.reap` then marks a
  perfectly healthy running job `interrupted`.

## E2. BLOCKER: the lab cannot currently detect packet loss

**Read this before planning the load test — half of E1 is unmeasurable today.**

`tcpdump` prints `N packets dropped by kernel` to **stderr** when it exits.
Both capture paths discard it:

- `automation/tcpdump.sh:129` — `tcpdump -i "xenbr1.$VLAN" ... 1>/dev/null 2>&1`
- `sandboxd` — `stages.py` spawns `guests.argv_tcpdump()` with no
  `stderr_path`, and `proc._sink(None, capture=False)` returns
  `subprocess.DEVNULL` (`sandboxd/proc.py:125-128`)

A capture that dropped 40% of a clone's traffic is byte-for-byte
indistinguishable from one that dropped nothing, on both the legacy and current
paths. **This is not a CPU-tuning issue** — it is true at idle — but it means
the most important symptom in E1 cannot be observed, and no amount of running
analyses will reveal it.

The fix is one argument to `spawn`: give the tcpdump child a `stderr_path` under
the job's result directory. That belongs in its own change with its own review.
**Record it as a finding and raise it separately.**

Interim workaround for this runbook only — watch the kernel's own drop counters
on the VLAN interfaces during the load test, from DOM0-B:

```bash
for i in $(seq 1 5); do
  echo "=== vlan $i ==="
  ip -s link show xenbr1.$i 2>/dev/null | sed -n '3,6p'
done
```

Run it before and after E3 and diff the RX `dropped` column. This measures the
interface, not `tcpdump`'s ring buffer, so it is weaker evidence than the real
fix — say so when recording the result.

EVIDENCE E2 (interface counters, before)

```
(paste here)
```

## E3. Load test at full concurrency

Submit five samples so five analyses run at once. From PVE:

```bash
pct exec 102 -- su - platform -s /bin/bash -c '
  cd /opt/platform/src/platform
  echo "harmless test file" > /tmp/hello.txt
  for i in 1 2 3 4 5; do
    .venv/bin/python submit.py \
        --api https://192.168.1.10:8443 \
        --cacert /etc/sandbox-platform/tls/ca.crt \
        --cert   /etc/sandbox-platform/tls/fake-worker.crt \
        --key    /etc/sandbox-platform/tls/fake-worker.key \
        --target-os ubuntu --file /tmp/hello.txt
  done
'
```

While they run, from DOM0-B:

```bash
xentop -b -i 10 -d 2
xl vcpu-list 0
xl list
```

The distinction that matters in `xl vcpu-list 0`: **five Dom0 vCPUs busy plus
one idle** means the partition is holding and Dom0's own work has its core.
**All six busy** means DRAKVUF has taken the core `sandboxd`, xenstore and the
captures need.

Then check the heartbeat half from DOM0-B — this is what replaces `journalctl`:

```bash
grep -iE 'heartbeat|lease|interrupted|409' "$SBLOG" | tail -40
grep -c 'heartbeat "HTTP/1.1 200 OK"' "$SBLOG"
```

Heartbeats should appear roughly every 10s per running job. Gaps materially
longer than that, or any `interrupted`, are the symptom E1 predicts.

And from PVE, re-run the Part B measurement **under this load** — a ratio that
was 1.0 at idle and drops under five concurrent traces is L0 contention that
only appears when the lab is working, which is the only time it matters:

```bash
# Re-derive both: any VM restart in D2/D4 changed the pid AND the thread ids.
export QPID=$(cat /run/qemu-server/${XEN_VMID}.pid)
export TID=$(grep -l "^CPU ${VCPU}/KVM$" /proc/${QPID}/task/*/comm | awk -F/ '{print $5}')
export TICK=$(getconf CLK_TCK)

export BEFORE=$(awk '{print $14+$15}' /proc/${QPID}/task/${TID}/stat)
sleep 30
export AFTER=$(awk '{print $14+$15}' /proc/${QPID}/task/${TID}/stat)
awk -v a="$AFTER" -v b="$BEFORE" -v t="$TICK" \
  'BEGIN { s=(a-b)/t; printf "loaded host_seconds=%.2f of 30\n", s }'
```

Note this variant measures a vCPU that is *doing real work*, not a spin loop, so
it is not directly comparable to B5's ratio — read it as "did this core get 30
seconds of host CPU during 30 seconds of wall time".

EVIDENCE E3

```
(paste xentop, xl vcpu-list, the SBLOG greps, and the loaded measurement)
```

EVIDENCE E2 (interface counters, after)

```
(paste here, and diff the dropped column against the before)
```

## E4. The lever, and one that is not

**Not scheduler weight.** The Xen wiki's advice to raise Dom0's weight
(`xl sched-credit2 -d 0 -w 512`) assumes Dom0 and the guests compete for the
same pCPUs. After §F7's pinning they do not: Dom0 holds 0–5, clones hold 6–11,
disjoint. **Weight is a no-op in this configuration.** This lab also boots
`sched=credit` (Credit1), so the credit2 form of the command does not apply
either. Confirm both before dismissing it:

```bash
xl sched-credit
xl vcpu-list | awk '{print $1, $3, $NF}'
```

**The lever is the boundary.** If E3 showed all six Dom0 vCPUs busy, either move
it or lower concurrency:

```bash
# option 1: give Dom0 a seventh core, clones lose one
#   edit GRUB_CMDLINE_XEN_DEFAULT: dom0_max_vcpus=7
#   and repin the clones' range in the pipeline config
# option 2: cap concurrency below the core count -- costs nothing memory
#   was not already withholding
grep SANDBOXD_MAX_CLONES /etc/sandboxd/sandboxd.env
```

Option 2 is reversible in one line and needs no reboot. Prefer it.

EVIDENCE E4

```
(record the decision)
```

---

# Part F — discrepancies to settle while you are in there

**F1. `dom0_max_vcpus` — RESOLVED from the repo, confirm only.**
An earlier draft of this runbook flagged `09-verify-sandboxd-and-console.md:735`
(`dom0_max_vcpus=8`) against §F7c's observed `VCPUS 6` as a contradiction. It is
not one: line 735 is the **older** boot line, and line 2046 records the change
to `dom0_max_vcpus=6` with the pinning that §F7 then verified. §F7c's 600%
ceiling is correct. Confirm the live value and move on:

```bash
cat /proc/cmdline
xl info | grep xen_commandline
xl vcpu-list 0 | grep -c Domain-0     # expect 6
```

**F2. `sched=credit`, not Credit2.**
Xen 4.20 defaults to Credit2; this lab explicitly selects Credit1.

```bash
xl info | grep -o 'sched=[a-z0-9]*'
xl cpupool-list
```

If deliberate, record why here so it stops looking like an oversight. If
inherited from the original setup guide, note that changing it is a boot-time
change to an evidenced pipeline and belongs in its own runbook with its own
before/after, not bundled into CPU tuning.

EVIDENCE F

```
(paste here)
```

---

# Shutting down

```bash
# DOM0 (the shell running sandboxd): Ctrl-C, it drains in-flight analyses
# DOM0-B:
ls -la "$SBLOG"
```

Keep `$SBLOG` — it is the evidence for E3.

---

# Decision summary

Fill this in on the way out, so the next reader does not repeat the work:

| Question | Answer | Evidence |
|---|---|---|
| **How many physical P-cores carry two busy vCPU threads?** | | D2 |
| Does Dom0 get a full physical core? (ratio) | | B5 |
| Is `enable_shadow_vmcs` on? | | C1 |
| Was a `cpulimit` / `cpuunits` found? | | A1 |
| Do QEMU vCPU threads migrate across host cores? | | A2 |
| Target A (8 vCPUs) or Target B (12) — which, and why? | | D2 |
| Were the E-cores taken by the host and other guests? | | D3a / D3b |
| Did systemd `CPUAffinity` survive the cgroup v2 cpuset controller? | | D3b |
| Was per-vCPU pinning applied, and did the ratio move? | | D4 |
| Does Dom0 lose heartbeats at 5 concurrent? | | E3 |
| Were all six Dom0 vCPUs busy at 5 concurrent? | | E3 |
| Packet loss — was the stderr blocker raised separately? | | E2 |
| `dom0_max_vcpus` live value (expect 6) | | F1 |

**If Part B returned ≥ 0.95 and C1 was already `Y`, the correct outcome of this
runbook is to change nothing and record that §F7c is confirmed from below.**
That is a result, not a wasted session — it closes the last question the Xen
layer could not answer about itself.

**If Part B returned below 0.95, the first suspect is the top row**, not the
affinity and not the scheduler: 12 Xen pCPUs on 8 physical P-cores, placed by a
scheduler that Xen cannot observe or correct.

---

# Sources

- [Proxmox VE — CPU resource limits](https://pve.proxmox.com/pve-docs/chapter-qm.html#qm_cpu_resource_limits)
- [Proxmox VE — `qm.conf` options](https://pve.proxmox.com/pve-docs/qm.conf.5.html) (`affinity`, `cpulimit`, `cpuunits`, `numa`)
- [Xen Project — Tuning Xen for Performance](https://wiki.xenproject.org/wiki/Tuning_Xen_for_Performance)
- [Linux Kernel — Running nested guests with KVM](https://www.kernel.org/doc/html/latest/virt/kvm/x86/running-nested-guests.html)
- [Throttle a Xen vCPU](https://umhau.github.io/throttle-a-xen-vcpu/)
- [Per-vCPU pinning hookscript](https://gist.github.com/kiler129/215e2c8de853209ca429ad5ed40ce128)
- [Proxmox forum — "Pinning" host to certain cores](https://forum.proxmox.com/threads/pinning-host-to-certain-cores.73392/) (the `cset` answer D3 supersedes)
- [systemd-system.conf(5) — `CPUAffinity=`](https://www.man7.org/linux/man-pages/man5/systemd-system.conf.5.html)
- [systemd #23748 — CPUAffinity reset by the cgroup v2 cpuset controller](https://github.com/systemd/systemd/issues/23748)
- [Red Hat — constraints of `isolcpus=`, `nohz_full=`, `rcu_nocbs=`](https://access.redhat.com/articles/3720611)
- [Improving KVM x86 Nested Virtualization](https://events19.linuxfoundation.org/wp-content/uploads/2017/12/Improving-KVM-x86-Nested-Virtualization-Liran-Alon-Oracle.pdf)
