# Troubleshooting — things that have actually gone wrong

**Every entry below happened.** Nothing here is anticipated, hypothetical, or
copied from upstream documentation. If a failure mode is not in this file, it
has not bitten this project yet.

## How to use this file

**It is organised by symptom, not by subsystem** — by what you saw, not by what
turned out to be wrong. That is the whole point: when something breaks you know
the symptom and nothing else, and every other document here is organised by the
answer.

Each symptom is a `###` heading, so `docs/INDEX.md` carries all of them. Grep
the index for a word from your error and you get the entry and its line number
in one hit.

**What this file is not.** It is not a record of *facts* — for "is this value
still true?" read `docs/CURRENT-STATE.md`, whose §2a/§2b list values that still
look right in old runbooks and are not. It is not a substitute for the
`EVIDENCE` and `FINDING` blocks in `docs/runbooks/`, which are append-only
primary evidence; entries below cite them rather than restate them.

**What stays elsewhere, deliberately.** `CLAUDE.md` keeps its four pitfalls
inline because they are **write-time rules** — things you obey while typing,
not symptoms you look up afterwards. They point here for the full story.

---

# Static checks and the development container

### A script silently used `$PWD` instead of its own directory

**Symptom.** A script in `automation/` resolved repository paths against
wherever it was invoked from. No error, no warning — it simply operated on the
wrong tree.

**Cause.** `${BASH_SOURCE[0]}` evaluates to **empty under `dash`**, and
`automation/` scripts run under `dash`, not `bash`: `dirwatch` spawns them via
`g_spawn_command_line_sync()` and `/bin/sh` is `dash` on Dom0. `SCRIPT_DIR` then
became the empty string, which resolves to the current directory, and execution
continued normally.

**Fix.** Use `$0`. Write POSIX. Check with `dash -n` **as well as** `bash -n` —
`bash -n` alone parses the file happily. `run_analysis-ubuntu.sh` is the one
genuine bash script and uses `$0` too, so the idiom stays uniform.

### `shellcheck automation/*.sh` exits 0 on code with unquoted expansions

**Symptom.** A clean shellcheck run on scripts that contain real SC2086 sites.

**Cause.** `.shellcheckrc` disables `SC1091,SC2086,SC2009` **repository-wide**.
That is a deliberate reviewed baseline (DRAFT-031), not an oversight — the bare
command is what `CLAUDE.md`, `README.md` and `docs/workflow-ci.md` all tell you
to run, and a gate that is red by default gets ignored.

**Fix.** Read `.shellcheckrc` before reading a clean run as clean code. For new
files, check with `shellcheck --norc <file>`, which applies no exemptions. The
cost is stated in that file: a dangerous new unquoted expansion in a
future per-OS script will **not** be caught until DRAFT-011 lands.

### `severity=warning` in `.shellcheckrc` changes nothing

**Symptom.** Setting a severity floor in the rc file has no effect on output or
exit status, while `disable=` in the same file works.

**Cause.** `severity=` is silently ignored by shellcheck 0.11.0 in rc files.
Measured, not assumed. Only the CLI `-S` flag applies a floor.

**Fix.** Nothing to do — this is why the baseline uses blanket `disable=` lines
rather than the cleaner severity floor. Re-test on a shellcheck upgrade; if it
starts working it is strictly better, because it keeps checks live for code
written after the baseline.

### `cd platform && .venv/bin/python -m pytest -q` fails or hangs in the dev container

**Symptom.** The command `CLAUDE.md` documents does not work. Postgres refuses
connections, or MinIO-dependent tests error, or the run is killed on timeout.

**Cause.** The dev container starts with the Postgres cluster **down** and MinIO
**not installed**. Neither comes up on its own, and nothing in the repository
brought them up until `scripts/dev-services.sh` existed.

**Fix.** `scripts/dev-services.sh` first. It is idempotent, starts the cluster,
creates `sandbox_platform_test`, starts MinIO with the right environment, and
**reports** what is still missing (`mc`, Chromium) rather than failing. It
installs nothing from the network — it prints the `curl` command for MinIO
instead.

The `sandboxd` suite needs none of this:
`platform/.venv/bin/python -m pytest sandboxd/tests -q`.

### `test_objects.py::test_the_region_is_enforced` fails right after a services restart

**Symptom.** One platform test expects `400 AuthorizationHeaderMalformed` and
gets `200`. It reads as a code regression in whatever you just changed.

**Cause.** MinIO was restarted **without `MINIO_SITE_REGION`**. The two
credentials alone are enough for it to come up and serve every other test, but
with no site region MinIO accepts a signature scoped to any region — the region
is part of the SigV4 signing scope.

**Fix.** Restart MinIO with `MINIO_SITE_REGION` equal to `S3_REGION`, which
`scripts/dev-services.sh` does. Expect **405 passed, 3 skipped** (the 3 are the
`mc` service-account policy tests). A single `test_objects.py` failure right
after a restart is the environment, not the diff.

**`mc admin config get <alias> region` does not reveal this** — it reports empty
for an env-provided value, which is what made the variable look unset in the
first place. See `platform/minio/provision.sh` and runbook `08` §2351.

*Cost when it bit: a false alarm on a `sandboxd` change that touched no platform
code, 2026-08-26.*

### The platform test suite destroyed job history

**Symptom.** Running the platform suite anywhere other than the dev container.

**Cause.** Its `conn` fixture runs
`TRUNCATE jobs, worker_pipelines, workers RESTART IDENTITY CASCADE`.
`TEST_DATABASE_URL` defaults to `sandbox_platform_test`, which is safe here and
does not exist on the deployment.

**Fix — and the important half.** It was attempted on the deployment
2026-08-25 and failed with 312 errors *because that database does not exist*.
**The correct response is not to create it.** The deployment is verified by the
runbook's `curl` checks and by looking at the UI. Do not run
`playwright install` there either.

---

# Documentation machinery

### `test_current_state.py` fails after you added or removed a file under `docs/`

**Symptom.** A test unrelated to your change goes red, complaining
`docs/CURRENT-STATE.md` is out of date.

**Cause.** `scripts/gen-current-state.py` counts `docs.rglob("*.md")` off the
**filesystem**, not off git. Any new `.md` under `docs/` — tracked or not,
numbered or not — changes the repository-size table.

**Fix.** Run both generators and commit the result:

```
scripts/gen-current-state.py
scripts/gen-doc-index.py
```

This is also why a runbook is **parked at the repository root** until it has
been executed: moving it into `docs/runbooks/` before it is ready would fail the
suite while the file is still untracked.

### A runbook you know was executed shows `Executed: no`

**Symptom.** The derived table in `docs/CURRENT-STATE.md` §3 reports a runbook
as evidence-free while it visibly contains pasted host output.

**Cause.** `_EVIDENCE_HOSTS` in `scripts/gen-current-state.py` is an explicit
list of hostnames whose shell prompts count as evidence. **A host rename
silently invalidates it**, and the 2026-08-28 migration did exactly that: Dom0
stopped being the nested VM `drakvuf` and became bare-metal `dom0`. Until `dom0`
was added, `12-baremetal-trial.md` counted 7 prompts instead of 32 and
`platform-domu.md` counted **zero**.

**Fix.** Add the host to `_EVIDENCE_HOSTS`. Keep it an explicit list — a bare
`root@\S+` would also match prompts quoted inside prose, examples and findings,
which are not evidence of anything.

### A runbook shows `Executed: yes` but its banner says NOT YET EXECUTED

**Symptom.** A ⚠ in the derived table's Note column.

**Cause.** Status banners are written *before* execution and are frequently
never updated. `09-verify-sandboxd-and-console.md` carried its "NOT YET
EXECUTED" header while containing 44 pasted Dom0 prompts. This is why the banner
gets no vote in the generator — pasted prompts decide.

**Fix.** Correct the banner at the source. The ⚠ is deliberately a nag, not a
tolerated state.

### An empty `EVIDENCE` block, and you concluded the operation never happened

**Symptom.** Reporting something as not done because nothing was pasted.

**Cause.** **Attested is not the same as pasted.** A blank `EVIDENCE` block
means nobody recorded output. It never proves the operation did not occur.

**Fix.** Ask the operator. This produced a wrong review finding on 2026-08-29:
`sandboxd` and end-to-end analysis for both Ubuntu and Android were reported as
"not run since the migration" purely from blank blocks, and all of it had in
fact run. The derived table correctly still reads `no` — that is the table
reporting *recorded evidence*, which is its job — but prose must not upgrade
that into a claim about reality.

### `gen-xen-configs.py --check` passed while the files disagreed

**Symptom.** `sandboxd/config.py` says `xenbr1`, `automation/platform.env` says
something else, and `--check` reports them in agreement. The gate built to catch
exactly this drift reported clean.

**Cause. Stale bytecode.** The generator loaded `config.py` with `importlib`,
which validates its `__pycache__` entry on **`(mtime, size)`**. Two things had
to line up, and both are ordinary:

- The edit was **length-preserving** — `xenbr1` → `xenbr9` is the same size, and
  so is `xenbr1` → `xenbr2`, which an operator would plausibly type.
- The edit landed in the **same filesystem-timestamp second** as the previous
  run, which any edit-then-generate script does.

Python then served the previous compilation, and the generator compared old
values against the current files.

**Fix.** The loader now reads the source and `exec`s it, which touches no cache.
`test_the_generator_does_not_serve_stale_bytecode` pins the behaviour with a
deliberately length-preserving probe.

**The general form is worth carrying:** any tool that loads a config file by
path and then reports agreement can report a *false* agreement. Reproduced
2026-08-31 rather than reasoned about — the drift was visible in `git diff` and
the gate said nothing.

### A cross-reference points at a line that moved

**Symptom.** `some-file.py:141` names a line that is now something else.

**Cause.** Nothing checks prose. Both runbook 11 and 12 cited
`scripts/gen-current-state.py:141` for the `docs.rglob` count; editing the
generator moved it to `:155` and nothing went red.

**Fix.** Prefer naming a **section or function** over a line number when the
target is likely to move. `scripts/check-refs.py` gates the resolvable cases.

---

# Dom0 boot, LVM and GRUB

### `grep -rn 'ubuntu-vg'` came back clean while GRUB still used the old name

**Symptom.** After `vgrename ubuntu-vg vg-root`, a grep across `/etc/fstab`,
`/etc/default/grub`, `/boot/grub/grub.cfg` and `/etc/initramfs-tools/` reported
no remaining references. GRUB still referenced the old VG.

**Cause.** **Device-mapper doubles dashes in VG names.** `grub.cfg` contains
`ubuntu--vg-ubuntu--lv`, and the substring `ubuntu-vg` **does not occur anywhere
in it**. The grep was structurally incapable of matching the one file it most
needed to check — a false negative that reads exactly like a clean result.

**Fix.** Always search for **both spellings**:

```bash
grep -rn 'ubuntu--vg\|ubuntu-vg' /etc/fstab /etc/default/grub \
    /boot/grub/grub.cfg /etc/initramfs-tools/
```

The same escaping bites anything reading `kpartx` or `/dev/mapper` output. It is
the strongest practical argument for **a VG name with no dash in it** — which is
why `vg-root` is worth the rename rather than living with `ubuntu-vg`.

*Source: `docs/runbooks/12-baremetal-trial.md` §D1, CORRECTION block.*

### `update-grub` and `update-initramfs` error on a device that no longer exists

**Symptom.**

```
cryptsetup: ERROR: Couldn't resolve device /dev/mapper/ubuntu--vg-ubuntu--lv
cryptsetup: WARNING: Couldn't determine root device
/usr/sbin/grub-probe: error: failed to get canonical path of `/dev/mapper/ubuntu--vg-ubuntu--lv'
```

**Cause.** Stale references to the pre-rename VG. The tools resolve the root
device by name and the name changed under them.

**Cause, more precisely — and it makes the obvious ordering impossible.**
`grub-probe` resolves `/` through the mount table, and `/proc/mounts` still
carries the string captured at mount time. **A live `vgrename` renames the
device-mapper nodes but not the recorded mount source**, so the old name is
unresolvable and the new one is not what the kernel was told. It cannot become
correct until after a reboot — so `update-grub` **cannot succeed before one**.

**Fix. Hand-edit `grub.cfg` to reach a bootable state, reboot, then regenerate.**

```bash
ls -la /dev/mapper/                        # expect vg--root-*, no ubuntu--vg-*
sudo grep -n 'root=' /boot/grub/grub.cfg   # mode 600 -- sudo needed

# only if root= still names the old device:
sudo cp /boot/grub/grub.cfg /boot/grub/grub.cfg.bak
sudo sed -i 's/ubuntu--vg-ubuntu--lv/vg--root-ubuntu--lv/g' /boot/grub/grub.cfg
sudo reboot

# AFTER the reboot, regenerate properly -- both now succeed
sudo update-grub2 && sudo update-initramfs -u -k all
```

Hand-editing a generated file is legitimate here: it is a one-off to reach a
bootable state, and `update-grub` regenerates it cleanly afterwards. With
nothing persisted, the alternative is to press `e` at the GRUB menu, correct
`root=` on the `linux` line, and `Ctrl-X`.

**`update-grub` failing is not itself destructive** — it writes to a temp file
and renames, so the previous `grub.cfg` stays intact. But it still names the old
device, and **the machine drops to an initramfs shell if rebooted as-is.**

**Let `update-initramfs` finish.** It was interrupted with `^C` on the first
attempt, which is worse than not running it: root lives on this VG, so an
initramfs that half-describes it does not boot.

**Two things that made this survivable, worth checking on any host:**
`set root='lvmid/<vg-uuid>/<lv-uuid>'` locates `/boot` by **UUID**, and
`/etc/fstab` uses `dm-uuid-LVM-<uuid>`. Both encode UUIDs, not names, and
survive the rename. Only the `root=` kernel argument uses the mapper name.

### A thin pool that will not activate at boot, long after it was created fine

**Symptom.** `lvcreate` succeeded; the pool refuses to come up on the next boot.

**Cause.** `thin-provisioning-tools` is missing. It provides `thin_check`, and
**LVM refuses to activate a thin pool without it.**

**Fix.** Install it when creating the pool, not when the failure appears — the
gap between the two is a reboot, which is what makes this hard to attribute.

### `thin_pool_autoextend_*` is configured and the pool still filled up

**Symptom.** Autoextend thresholds are set and the pool never grows.

**Cause.** Two independent ways to have a decorative guardrail:

- **`lvm2-monitor.service` is not running.** The `thin_pool_autoextend_*`
  settings are read by `dmeventd`; without the monitor they are inert
  configuration. This is the single most likely way to believe there is a
  guardrail when there is none.
- **The pool owns the whole VG.** Autoextend can only grow into free VG space.
  `-l 100%FREE` leaves it nowhere to go.

**Fix.** `systemctl is-active lvm2-monitor`, and create the pool at `-l 90%FREE`
so ~150 G stays unallocated **deliberately**.

**This is not hypothetical — it is the state of the machine that was replaced.**
`pve-data` took 1.7 T of a 1.82 T VG, leaving 16 G, and that is precisely why
shrinking it was impossible when the migration needed the space. Do not rebuild
the same trap.

### `xl create` fails on a missing block device after `lvcreate -s`

**Symptom.** The snapshot exists in `lvs` and `/dev/vg-root/<clone>` does not.
`lvs -o lv_attr` shows `Vwi---tz-k` — trailing **`k`**, positions 5–6 `--`:
inactive, not open, no `/dev` node.

**Cause.** `lvcreate -s` on a **thin** LV sets the activation-skip flag, so the
new volume is not activated. **Thick snapshots do not behave this way**, so this
does not surface until the first clone on new thin storage.

**Fix.** Either clear the flag at creation or override it at activation:

```bash
lvcreate -s -kn -n ubuntu-1-clone vg-root/ubuntu     # clear at creation
lvchange -ay -K vg-root/ubuntu-1-clone               # or override at activation
```

`clone.pl` uses `-kn`, on top of dropping `-L`.

### `grep /boot/grub/grub.cfg` says Permission denied

**Symptom.** A plain `grep` on `grub.cfg` fails even though the file exists.

**Cause.** `grub.cfg` is mode 0600. Nothing to do with the content.

**Fix.** `sudo`. Worth knowing because it appears mid-sequence in a chain of
real errors and reads like another symptom of the same fault.

### `~/drakvuf` did not exist, but the build continued anyway

**Symptom.**

```
bash: cd: /root/drakvuf: No such file or directory
Directory already configured.
```

**Cause.** Two things at once. The DRAKVUF checkout is at
`/home/user/drakvuf`, not `/root/drakvuf`, and `~` resolves differently under
`sudo`/`root` than for the operator. **The `cd` failed and the following
commands ran in the wrong directory** — chained with `;` or newlines rather than
`&&`, so nothing stopped.

**Fix.** Use absolute paths for the DRAKVUF tree, and chain with `&&` when a
later step is meaningless without an earlier one. The same session shows
`grep -rn … /root/drakvuf/src/` returning "No such file or directory" for the
same reason.

---

# Dom0, Xen and the guests

### Every `DRAKVUF_*` chain vanished and clones are running unfiltered

**Symptom.** `iptables -S DRAKVUF_ISOLATION` reports no such chain, on a host
where it existed minutes ago. Clones that were mid-analysis keep running, with
no inter-clone isolation, no LAN block and no Dom0 protection. Nothing logged
an error, and the pipeline reports nothing wrong — the analyses complete and
look normal.

**Cause. FakeNet-NG was started with its default `LinuxFlushIptables: Yes`.**
That option "flush[es] all `iptables` rules before adding rules for
FakeNet-NG" (its README), which on this host means the entire containment
posture, for every clone currently running, while they run.

Its README promises "the Linux Diverter will restore the old rules as long as
its termination sequence is not interrupted". **That conditional is the whole
trap.** A `kill -9`, an OOM kill, a crash, or a host reset means they are never
restored, and Dom0 comes back with malware VMs on an unfiltered network.

**Fix.** `LinuxFlushIptables: No` in `automation/fakenet.ini`, which is how the
reference config ships. `sandboxd/tests/test_egress.py` asserts it, so this
cannot regress silently. Then re-run `automation/network-setup.sh <clones>` to
rebuild the chains, and treat any clone that was running as contaminated — it
had unrestricted network access for an unknown interval.

**The related setting, same file, different failure.** `DivertTraffic: Yes`
(also FakeNet's default) makes its diverter install a **blanket** `REDIRECT` in
`PREROUTING`, capturing every analysis VLAN rather than the ones running in
`simulated`. A clone submitted as `offline` would then be answered by the fake
Internet — `offline` silently stops meaning offline, and the report shows a
sample talking happily to something it was never supposed to reach. There is no
error to see; it looks exactly like a result. Ships as `No`, also asserted.

### A clone in `tor` or `simulated` reports that nothing would connect

**Symptom.** The analysis completes. The pcap shows the clone sending SYNs, or
DNS queries, and getting nothing back or an instant RST. The report reads as a
sample whose infrastructure is down.

**Cause.** The redirect rules were installed but **nothing is listening on the
port they point at** — tor not started, FakeNet not running, or either bound
somewhere other than expected. A `REDIRECT` to a closed port is refused
immediately, which looks identical to a dead C2.

**This should not reach you**, and if it did, say so: `sandboxd` probes the
listener before offering the mode at all, and probes it again at launch,
falling back to `offline` and recording the reason in `egress_applied`. Check
the report — a run that fell back says so:

```
requested: simulated   applied: offline
reason: simulated responder not listening on 127.0.0.1:38926 at launch
```

If the report shows `applied: simulated` and the traffic still went nowhere,
the listener was up but not answering, which is a FakeNet or tor problem rather
than a firewall one. `journalctl -u tor` and FakeNet's own stdout are the next
stop, not `iptables -S`.

### A clone drops to an initramfs shell with `UNEXPECTED INCONSISTENCY`

**Symptom.**

```
/dev/xvda5: recovering journal
/dev/xvda5 contains a file system with errors, check forced.
Inode 2622029 has an invalid extent node (blk 10518898, lblk 0)
```

Everything else looks right: `root=UUID=…` matches, the device is present,
`blkid` in the initramfs reports the correct UUID and type.

**Cause.** A `.bak` memory image was restored against a **disk it was not saved
from**. The guest's kernel carried in-memory filesystem state — inode cache,
journal position, block allocation — describing a different disk, wrote against
this one, and was `xl destroy`'d without a clean shutdown, repeatedly. The
golden was *not* at fault; `e2fsck` on the origin came back clean.

**Fix. Never restore a `.bak` against a disk it was not saved from.** The
pairing is not advisory. Rebuild the template so image and disk match.

**What this invalidates, and it is the part worth remembering:** every check
that passed beforehand was **memory-only**. `xl restore` resumes RAM;
`vmi-process-list` reads RAM. Neither touches the root filesystem, so a broken
disk stays invisible until `xl create`. Any throughput figure measured against
such a guest describes a degraded guest — the 902 events/sec taken here was
discarded.

**Do not over-attribute to it.** This finding originally also blamed the
corruption for an anomalously low clone CPU figure (1.0%). **Refuted by
measurement**: a rebuilt template on a verified-clean golden, with a matched
memory image, produces the same ~0.8%. The corruption was real and worth fixing
and was not the cause of that number — a reminder that one confirmed fault
happily absorbs blame for unrelated symptoms.

*Source: `docs/runbooks/12-baremetal-trial.md` FINDING D-1.*

### A template's disk drifted away from its saved memory image

**Symptom.** Clones from a template start failing the way FINDING D-1 describes
— `UNEXPECTED INCONSISTENCY` on the root filesystem — some time after a manual
operation on that template.

**Cause.** `misc/*_sandbox.cfg` points at the **template LV, writable**
(`phy:/dev/vg-root/ubuntu_sandbox,hda,`**`w`**). Restoring against that config
and then `xl destroy` **advances the disk while the `.bak` stays where it was**.
That is exactly how D-1's corruption was produced.

**Fix.** Use `misc/*_sandbox.cfg` **only for edits that end in `xl save`**, which
is what re-pairs disk and memory. `clone.pl` never touches it — it rewrites the
`disk=` line to point at the per-clone snapshot, and anything manual should do
the same.

| Operation | Config | Ends in |
|---|---|---|
| Editing the template (anchor swap, network flush) | `misc/*_sandbox.cfg` | **`xl save`** — mandatory |
| Validating a restore | temp cfg on a throwaway snapshot | `xl destroy` + `lvremove` |
| **Measuring** | temp cfg on a throwaway snapshot | `xl destroy` + `lvremove` |

Measuring on a throwaway is also more correct: every run starts from a
byte-identical disk instead of inheriting the previous run's writes.

To check whether a template has already drifted, compare `Data%` against its
value immediately after the last `xl save`:

```bash
sudo lvs -o +data_percent vg-root/ubuntu_sandbox
```

### `preconfig-*.sh` does not build a template — it runs at analysis time

**Symptom.** Following "copy golden → apply preconfig → boot → save state" and
getting a template with no injection anchor.

**Cause.** `preconfig-ubuntu.sh` runs at **analysis** time against a **clone**,
and does two things: stages the sample with `injector -m writefile`, then sets
that clone's VLAN address with `injector -m execproc`. **It never touches the
template.**

**Fix.** What actually makes a template is booting the disk, **starting an
injection anchor**, and `xl save`. The anchor is the whole point — see the
anchor entries under *Guest execution and samples*.

### `xl vcpu-list 0` shows one vCPU with a multi-CPU affinity mask

**Symptom.** Five of Dom0's six vCPUs are pinned 1:1; the sixth keeps the
default mask `0,2,4,6,8,10` and floats. It was observed on pCPU 6 — another
vCPU's pinned core — while pCPU 10 sat unclaimed.

**Cause.** `dom0_vcpus_pin` against a **sparse** online pCPU set. Nested, QEMU
presented 12 flat vCPUs so Xen's pCPUs were contiguous `0–11` and all six pinned
cleanly. On bare metal `smt=0` parks the odd siblings and the sixth pin does not
take. **This is bare-metal-only** — it cannot be reproduced in the old lab.

**Fix.** `xl vcpu-pin 0 5 10`, which does **not** survive reboot; or drop
`dom0_max_vcpus` to 5 so the boot line and reality agree. A floating vCPU can
share a physical core with a pinned one, which is invisible contention.

*Source: `docs/runbooks/12-baremetal-trial.md` FINDING C-1.*

### `cpus = "6-11"` in a guest config gave the clone Dom0's cores

**Symptom.** A clone configured onto what looks like six dedicated CPUs gets
three, all of them shared with Dom0.

**Cause.** Under `smt=0` Xen parks the odd siblings, so `6-11` resolves to
`{6,8,10}` — every one of them inside Dom0's `0,2,4,6,8,10` partition. The range
notation is evaluated against *online* pCPUs, and the online set is not
contiguous.

**Fix. Enumerate P-cores explicitly; ranges are safe only across `16-31`**,
where no sibling is parked. As of 2026-08-31 the partition is Dom0 on all eight
P-cores and guests on E-cores, and it is **generated** — `CLONE_PCPUS` and
`PLATFORM_PCPUS` in `automation/platform.env` are the source, and
`scripts/gen-xen-configs.py` writes them into `misc/*.cfg`. Editing a `cpus =`
line by hand is reverted on the next run.

**Verify the boot line separately.** `dom0_vcpus_pin` hands Dom0 the first N
*online* pCPUs, and nothing in this repository can enforce what
`/etc/default/grub.d/` says. Check with `xl vcpu-list 0` after any change — see
the floating-vCPU entry above.

### A headless box never came back after bridging its NIC

**Symptom.** `netplan apply` on the interface carrying your SSH session, and the
machine is gone.

**Cause.** Two, and the second is the quiet one:

- Bridging the NIC that carries your own session is the riskiest single step in
  the bare-metal build. There is no second path in.
- **With DHCP, the bridge takes a new MAC** unless `macaddress:` pins it to the
  NIC's. The lease changes and the box reconnects at an address nobody is
  watching.

**Fix.** Use **`netplan try`**, which reverts automatically after 120 s unless
confirmed — never `netplan apply` — and give the bridge a **static** address.
Dom0 is `192.168.1.6/24` static for exactly this reason.

**One thing to re-check afterwards:** `sandboxd` dials *out*, so Dom0's own
address appears in no config — but if the mTLS client certificate
`dom0-lab.crt` carries an IP SAN, it now names the wrong address.

### The Xen boot line changed without anyone editing it

**Symptom.** `dom0_mem`, `dom0_max_vcpus` or `smt` differ from what
`/etc/default/grub.d/` says.

**Cause.** `drakvuf-bundle` can rewrite the Xen command line on any
`update-grub`.

**Fix.** Re-read the live boot line after **any** package operation that could
trigger `update-grub`, not just after editing grub config. `CURRENT-STATE.md`
§1.2 carries this as a standing WATCH.

### Admission holds forever — one line per second, no clone, no error

**Symptom.** 170 consecutive admission holds, zero clones for the large job,
smaller jobs completing meanwhile. Nothing in the logs explains it because
**every individual decision is correct**.

**Cause.** Admission is greedy, and greedy admission starves the largest clone.
A Windows clone costs **6294 MiB** (`memory = 6144` plus `DOMAIN_OVERHEAD_MIB`)
against Ubuntu's and Android's 2198 MiB.

**Fix.** Until DRAFT-041's head-of-line reservation lands, **run Windows alone**.
Measured on Dom0 2026-08-20.

### `vmi-process-list -h` and `--help` do not print help

**Symptom.**

```
$ vmi-process-list --help
VMI_ERROR: Could not find a live guest VM or file to use.
VMI_ERROR: Opening a live guest VM requires root access.
Failed to init LibVMI library.
```

**Cause.** There is no help flag. `-h`/`--help` are parsed as *domain arguments*
and the tool tries to open a VM named for them.

**Fix.** Run it **bare** — `vmi-process-list` with no arguments prints the usage
block. This matters beyond convenience: the error above names root access, so
the natural next move is `sudo`, which produces the same output and sends you
looking for a permissions problem that does not exist.

### `VMI_ERROR: No entry in config file for <domain>-N-clone`

**Symptom.** `vmi-process-list` works against a template and fails against a
clone.

**Cause.** Clone domains have **no `/etc/libvmi.conf` stanza** — they are created
per run with generated names. Only the tracked domains are configured.

**Fix.** Pass the profile explicitly with `-j <profile.json>`. This is the same
reason the pipeline passes `-r` to `drakvuf`/`injector` everywhere rather than
relying on `libvmi.conf`, and it is why `pipeline-<os>.env` carries
`KERNEL_PROFILE`.

### `VMI_ERROR: JSON at /root/linux.json couldn't be opened!`

**Symptom.** `vmi-process-list` fails on a domain that DRAKVUF traces fine.

**Cause.** `/etc/libvmi.conf` points at paths that do not exist here —
`/root/linux.json` and `/root/sandbox_project/…`, the **old repository path**.
DRAKVUF is unaffected because it is passed `-r …/profiles/linux.json`
explicitly; `vmi-process-list` resolves through the config file and is not.

**Fix.** Rewrite `/etc/libvmi.conf` against the real checkout. Note the filename
is `linux.json`, **not** `ubuntu.json` — `CURRENT-STATE.md` §1.4 records it as
never renamed in the `linux` → `ubuntu` pass.

### `injector` reported a JSON error and then kept going

**Symptom.**

```
VMI_ERROR: JSON at profiles/android.json couldn't be opened!
VMI_ERROR: Undefined OS type!
Injector starting /system/bin/sh through PID 1 TID: 0
Process startup failed
rc=1
```

**Cause.** The profile path was wrong (relative path, wrong working directory).
**The JSON error is not fatal** — `injector` prints it, continues, attempts the
injection, and fails later for what looks like a different reason.

**Fix.** Read the *first* error, not the last. Use absolute paths for `-r`.

### `injector` returns `STATUS:PrematureBreak` and `rc=124`

**Symptom.**

```
Injector starting /bin/true through PID 1490 TID: 0
[INJECT] TIME:… METHOD:ExecProc STATUS:PrematureBreak
Process startup failed
rc=124
```

**Cause.** `rc=124` is `timeout`'s exit code, not the injector's — the command
was wrapped in `timeout 30` and never returned. `PrematureBreak` means the
injection hit a breakpoint it did not expect, generally an anchor PID that is
not a valid vfork/execve source.

**Fix.** Check `INJECTION_PID` first. The anchor must exist **inside the memory
image**, must be unambiguous, and must belong to the user samples run as. See
the anchor entry below and `docs/runbooks/12-baremetal-trial.md` §D5.1.

`injector --help` documents `-I <injection thread>`, which the Linux path
describes as *"Injects to TGID Thread if ThreadID not specified"*.

### `systemctl stop sandboxd` — `Unit sandboxd.service not loaded`

**Symptom.** systemctl, `journalctl -u sandboxd`, `systemctl status sandboxd`
all report nothing.

**Cause.** **There is no systemd unit for `sandboxd`, anywhere in the repository.**
It runs in the foreground, started by hand.

**Fix.** `docs/CURRENT-STATE.md` §1.2 carries the exact invocation. **Source the
environment file first** — `python -m sandboxd.daemon` on its own exits
immediately, because `Settings.from_env` raises `SystemExit` when any required
variable is unset. That failure looks like a broken install and is not.

This exact mistake — assuming a unit existed — is one of the four wrong
assertions that caused `CURRENT-STATE.md` to be written.

### Admission holds repeat forever and resume after cleanup

**Symptom.**

```
[0] Holding: need 2198 MiB, 1211 available (free 10011, reserved elsewhere 0, host reserve 8800)
```

repeating once per second, continuing **after** a clone was successfully created
and again after cleanup.

**Cause.** Distinct from the Windows starvation entry above: here `free` is
10011 MiB but `available` is computed as 1211 against a `host reserve` of 8800.
The reserve is doing the constraining, not the clone.

**Fix.** Check `SANDBOXD_HOST_RESERVE_MIB` against what the host actually has
before concluding the pool is exhausted. Observed by the operator on the nested
host; **not re-measured since the migration**, where `total_memory` went
20479 → 32605 MiB and the same reserve is a much smaller fraction.

### A test domain on the bare bridge had no isolation at all

**Symptom.** A guest attached to `xenbr1` rather than `xenbr1.<n>` runs
normally, and **no isolation rule applies to it**.

**Cause.** The isolation rules match the `xenbr1.+` wildcard, which matches
`xenbr1.1`, `xenbr1.2` and so on and **deliberately does not match `xenbr1`
itself**. A throwaway config copied from `*_sandbox.cfg` inherits
`bridge=xenbr1` unless the VLAN suffix is added, so it lands on the bare bridge
— uncontained.

**Fix.** Give any test domain a VLAN sub-interface, or run it with no network.
**Nothing checks the attachment**, and nothing would report it — which is the
gap DRAFT-038 exists to close.

Harmless in the run that found it (a boot-and-anchor check, no sample), but
anyone repeating the procedure falls into it the same way.

### A clone got an address, and the sample "chose not to talk"

**Symptom.** An analysis completes, the clone booted and got an address, and the
pcap is empty. It reads as a sample that did nothing interesting.

**Cause. `sandboxd` does not create the network.** `run_analysis-<os>.sh:106,121`
brings the bridge up and runs `network-setup.sh` before launching `dirwatch`.
`sandboxd` replaces the launcher but **not** that call — #41 scoped it out on the
reasoning that "the launcher still does it", which stops being true the moment
you run `sandboxd` instead of the launcher. Nothing in `sandboxd` creates
`xenbr1.<n>`, the `172.16.<n>.1` gateways, or the isolation chains.

**This is a false negative wearing the clothes of a result** — the worst failure
mode a sandbox has, because it produces a clean report.

**Fix.** Bring up `xenbr1` and run `network-setup.sh` before starting
`sandboxd`. **If a previous `dirwatch` era left the interfaces in place it
appears to work**, which is exactly how it goes unnoticed.

**Related sizing trap:** `SANDBOXD_MAX_CLONES` and `network-setup.sh`'s argument
size the same thing from two sides — the VLAN pool and the `xenbr1.<n>`
sub-interfaces. Raise one without the other and a clone gets a VLAN with no
gateway, with the same symptom.

### `xl network-list` — `invalid domain identifier (rc=-6)`

**Symptom.** An `xl` subcommand rejects a domain that is running.

**Cause.** The domain's real name comes from `name =` **inside the `.cfg`**, not
from the filename or from whatever the procedure calls it. On 2026-08-12 the
config said `android_sandbox_test` while the runbook drove
`android_isolation_test`.

**Fix.** Keep the two in agreement, and check with `xl list` rather than
assuming. Harmless when a human notices; in an automated path it is a clone that
never gets checked and reports nothing.

### `lvremove` — `Logical volume ... in use`

**Symptom.** Removing a clone's LV fails immediately after `xl destroy`.

**Cause.** **`xl destroy` returns before the block device is released.** The
domain is gone; the device-mapper node is not yet.

**Fix.** Retry once. `clone.pl` waits for the domain to disappear before its own
`lvremove` for this reason — if the retry is ever needed there, that wait is
what regressed.

### `Invalid target name (too short)` after pasting a command from a script

**Symptom.** A line copied out of `network-setup.sh` produces
`iptables -I FORWARD 1 -j ""` and an error about the target name.

**Cause.** `$ISOLATION_CHAIN` is **internal to the script**. In an interactive
shell it expands to nothing.

**Fix.** Nothing on the host is wrong and **no rule was inserted** — the error
is a paste artifact. Run the script, or set the variable first. Quoted source in
a runbook is not a runnable command; this is why those blocks are marked.

### A `git pull` mid-run gave one sample two different script versions

**Symptom.** One analysis behaves as though its preconfig and its trace step
came from different commits — because they did.

**Cause.** **`dirwatch` spawns the worker scripts per sample, re-reading them
from disk each time.** A pull between the two hands that sample the old
`preconfig-` and the new `drakvuf-`.

**Fix.** Never pull while an analysis is in flight. Confirm the watch
directories are empty and no `dirwatch` is running first.

### Two watchers interfered with each other with no error message

**Symptom.** Clones colliding on VLANs, gateway addresses and isolation rules.
No symptom but the interference itself.

**Cause.** `dirwatch` derives each clone's VLAN from a **process-local**
worker-slot index, so two watchers allocate the same VLANs independently.

**Fix.** Both launchers refuse to start if another is running. A new per-OS
launcher must carry the same guard — this is not optional.

---

# The platform, TLS and the tunnel

### `openssl s_client` reported `Verify return code: 0 (ok)` against plain HTTP

**Symptom.** A TLS verification check passes against a service that is **not
serving TLS at all**.

**Cause.** `Verify return code: 0 (ok)` means *nothing was rejected*. An empty
certificate chain has nothing to reject, so it reports what looks like success.

**Fix.** **Do not use `openssl s_client … | grep 'Verify return'` for this.** The
absent `subject=` and `issuer=` lines are the real signal — grep for those, or
use a `curl` pair that proves https answers and http does not:

```bash
curl -sk -o /dev/null -w "https: %{http_code}\n" https://<host>:9000/minio/health/live
```

*Source: `docs/runbooks/08-deploy-platform-lxc.md` step 19.*

### MinIO started on plain HTTP with `--certs-dir` right there in the argv

**Symptom.** MinIO is launched with `--certs-dir`, starts cleanly, **logs no
reason**, and serves plain HTTP. Indistinguishable from the flag being ignored.

**Cause. The parent directory was not traversable.** `/etc/minio` was
`root:root`, so `minio-user` could not descend into `/etc/minio/certs` no matter
what the certificates' own ownership said.

**Fix.** Check the parent, not just the leaf:

```bash
ls -ld /etc/minio /etc/minio/certs
su -s /bin/sh minio-user -c 'ls -l /etc/minio/certs/'
# if that second command cannot list, MinIO cannot read them either
chown root:minio-user /etc/minio && chmod 750 /etc/minio
```

*Cost three rounds of debugging on 2026-08-23.*

### `mc`: `http: server gave HTTP response to HTTPS client`

**Symptom.** `mc alias set local https://…:9000` fails immediately.

**Cause.** MinIO is still serving plain HTTP on that port. The alias is correct;
the server is not on TLS yet.

**Fix.** Finish the TLS step first. If `mc` instead rejects the *certificate*,
that is a different problem — it does not trust the internal CA. `mc --insecure`
proves that is the only fault; then install `ca.crt` into `~/.mc/certs/CAs/`
rather than leaving `--insecure` in a command someone will copy.

### `curl: (56) OpenSSL SSL_read: … unexpected eof while reading`, exit 56

**Symptom.** `curl --cacert ca.crt https://<platform>:8443/healthz` fails with an
unexpected EOF rather than a TLS error.

**Cause.** Port 8443 is the **mTLS** listener. The server closed the connection
because the client presented no client certificate. The error names EOF, not
authentication, so it reads like a network fault.

**Fix.** Pass `--cert` and `--key` as well. Port 8000 is the browser listener and
takes no client certificate — check which port you are on before debugging TLS.

**The same trap in `httpx`, and it is worth knowing the mechanism.** Under
TLS 1.3 the server completes the handshake **before** validating the client
certificate, so a *rejected* certificate looks like the connection simply
ending. An unexplained EOF from a TLS client is a rejected client certificate
until proven otherwise, not a network fault.

### `cloudflared tunnel ingress validate` says OK, and the site returns a Cloudflare error page

**Symptom.**

```
Validating rules from /etc/cloudflared/config.yml
OK
```

followed by `<title>Cloudflare Tunnel error | … | Cloudflare</title>` from
`curl`.

**Cause.** `validate` checks the **syntax and rule structure** of the config
file. It does not check that the tunnel is connected, that the origin is up, or
that the origin's certificate is acceptable.

**Fix.** Treat `validate` as a linter. Prove the path end to end with `curl`
against the public hostname, and check the tunnel's connection count.

### `{"detail":"invalid access token"}` after Cloudflare Access is configured

**Symptom.** Access lets the request through, and the API rejects the JWT.

**Cause.** The API validates the Access JWT itself against
`ACCESS_TEAM_DOMAIN` and `ACCESS_AUD`. A mismatch in either — or a token minted
for a different application — fails here rather than at the edge.

**Fix.** `systemctl show sandbox-api-browser -p Environment --no-pager` and
compare `ACCESS_AUD` against the application's audience tag.

### A 403 from the artifact path is the PASS, not a failure

**Symptom.** `curl` against `/analysis` with a valid Access token returns 403.

**Cause.** Access let the request through and **MinIO** refused it unsigned.
That is exactly right.

**Fix.** Nothing. The failure to look for is a **302** there, which means the
path rule is not matching and the request reached the API instead.

### `systemctl enable` succeeded and the service never listened

**Symptom.** A unit derived from another by `sed` enables without complaint;
only the original port is listening.

**Cause.** `enable` only creates a symlink, so it succeeds against a unit
systemd cannot start. The `sed` had deleted `--ssl-cert-reqs 2`, which is the
**last** line of a line-continued `ExecStart` — the only one without a trailing
`\`. Removing it left the previous line ending in a backslash with nothing
after it, and systemd rejected the unit.

**Fix. Do not derive one unit from another by text substitution** — the result
depends on line breaks in the original. Write the second unit out in full.
`systemd-analyze verify <unit>` catches this; `enable` never will.

### A drop-in was configured correctly and had no effect

**Symptom.** `systemctl daemon-reload` after adding a drop-in, and the check
still behaves as before — with everything looking correctly configured.

**Cause.** **A drop-in reaches a running process only on restart.**
`daemon-reload` re-reads unit files; it does not re-exec anything.

**Fix.** `systemctl restart`, then confirm with
`systemctl show <unit> -p Environment --no-pager` — and check it did *not* also
land on the neighbouring unit. *Cost a round on 2026-08-24.*

### Restarting one API service left the other running old code

**Symptom.** A Python change appears to have no effect for Dom0 while working in
the browser, or the reverse.

**Cause.** `sandbox-api` (mTLS, used by Dom0) and `sandbox-api-browser` (behind
the tunnel) are **separate processes of the same application**.

**Fix.** Restart both. **Python changes need a restart; Jinja templates do not** —
they reload on their own, so a template-only change that appears not to apply is
a different problem.

### `DATABASE_URL is not set` when running a migration by hand

**Symptom.** The migration runner refuses; the same service starts fine under
systemd.

**Cause.** **`su - platform` is a login shell** and inherits none of the
environment the systemd unit supplies.

**Fix.** Source the unit's environment file explicitly, or use
`systemctl show <unit> -p Environment` to see what it actually gets.

**The dangerous part is what still succeeds.** The `git pull` and the restart
both work, so **the API comes up running code against a schema that has not been
migrated** — `GET /api/v1/jobs/<id>` and the job page then 500, because
`_detail` selects `*` and reads a column that does not exist. A refused
migration is not a stopped deployment.

### `Client sent an HTTP request to an HTTPS server` against the API

**Symptom.** A health check fails with a scheme error, suggesting the API is
misconfigured or down.

**Cause.** The check was pointed at **port 9000, which is MinIO**, not the API —
and MinIO is TLS here. So the error was about the wrong service *and* the wrong
scheme.

**Fix.** 8443 is the mTLS listener (`--ssl-cert-reqs 2`), 8000 is the browser
listener, 9000/9001 are MinIO. Pointing `sandboxd` at 9000 produces a TLS error
that reads like a certificate problem rather than a wrong port.

**What it is not:** evidence the API is down.

### SQL quoting was eaten by an extra shell

**Symptom.** SQL sent through `pct exec` / `su` arrives mangled, and the error
is about something other than what you were testing.

**Cause.** `su - platform -s /bin/bash -c "..."` puts **an extra shell in the
middle** that consumes a level of quoting.

**Fix.** Use `runuser -u platform --`. `pct exec` passes argv, `runuser` passes
argv, and psql receives the SQL as one argument — **no shell ever parses it**.
For the same reason prefer an `information_schema` query over `\d`, whose
backslash has to survive every layer.

### `psql` reported `column "linux" does not exist`

**Symptom.** An `INSERT` intended to test an enum constraint fails with a
completely different error, hiding the result you were testing for.

**Cause.** **Double quotes are identifiers in SQL, not strings.** The shell
quoting was rewritten to escape `"` and the SQL string literals became column
references.

**Fix.** Single quotes inside SQL, and a heredoc rather than `-c` when the shell
quoting gets deep. The expected error was
`invalid input value for enum target_os: "linux"` — which is what the test was
proving.

### Migrations silently re-applied on every run

**Symptom.** The migration runner reports success each time and re-applies
everything it has already applied.

**Cause.** The database was created under the cluster's default **`SQL_ASCII`**
encoding. The container has no UTF-8 locale, so `initdb` defaulted to
`SQL_ASCII` and every database inherited it.

**Fix, and the order is the substance of it.** Encoding must be fixed *before*
any database exists — **a database cannot be re-encoded in place**, and
`template1` on such a cluster is `SQL_ASCII` too:

```bash
su - postgres -c "createdb -O platform -E UTF8 -T template0 sandbox_platform"
```

`-T template0` is required precisely because `template1` lacks the encoding.
Confirm before continuing:

```bash
psql -d postgres -tAc \
  "SELECT pg_encoding_to_char(encoding) FROM pg_database WHERE datname='sandbox_platform'"
# expect: UTF8   -- NOT SQL_ASCII
```

Recovering from this needed a rollback to a container snapshot, not a repair.

### `pip install 'websockets==16.1.1'` — `from versions: none`

**Symptom.**

```
ERROR: Could not find a version that satisfies the requirement websockets==16.1.1
(from versions: none)
```

**Cause.** `from versions: none` means the index returned **no versions at all**,
not that this version is missing — an index or network problem, not a pin
problem. Do not "fix" it by loosening the pin.

**Fix.** `httpx` resolved in the same command, so the index was reachable;
re-run and check the pin against what that Python actually supports.
`sandboxd`'s dependencies belong in a requirements file rather than a
hand-typed pip line copied out of a runbook.

### `proxmox-backup-client restore` — `File exists (os error 17)`

**Symptom.** Creating the target LV and then naming it as the restore target
fails with `EEXIST`.

**Cause.** `restore` **creates** its target file and refuses if the path already
exists. It is create-exclusive — not a permissions or device-type problem, which
is what the error looks like. Pre-creating the LV guarantees the failure, and
deleting it to satisfy the tool leaves nothing to restore *into*.

**Fix.** Use `-` as the target and stream onto the device. That also avoids
needing 64 G of scratch for an intermediate file.

### A backup step that backed up nothing

**Symptom.** A `pg_dump` runs, a container backup runs, and neither contains the
dump.

**Cause.** The dump was redirected to **`/tmp` on the host**, while the backup
captured the *container*. A container backup never sees the host's filesystem —
and `/tmp` is cleared on reboot besides.

**Fix.** Write the dump somewhere the backup actually collects, and verify by
listing the backup's contents rather than by observing that both commands
succeeded.

**The compounding failure is the one to learn from:** this was survivable only
while an earlier part was mandatory. When that part was made *optional* on space
grounds, this step was not revisited — leaving Postgres and MinIO with no backup
at all. **Changing a step from required to optional changes what every later
step assumes.**

### `git pull --ff-only` refused on the deployment

**Symptom.**
`error: Your local changes to the following files would be overwritten by merge`,
naming files nobody edited deliberately.

**Cause.** The deployment checkout accumulated local modifications. Separately,
`git push` from there fails with *"The key you are authenticating with has been
marked as read only"* — the deploy key is intentionally read-only.

**Fix.** The deployment is a **consumer** of the repository, not a place to
commit from. Inspect and discard local changes there rather than merging around
them.

---

# Guest execution and samples

### `can't execute: Permission denied` for a file staged in Android external storage

**Symptom.** `injector -m writefile` succeeds, the file is present, `chmod 755`
appears to work — and `execve` is refused.

**Cause.** Two things, neither of them SELinux:

- `/storage/emulated` is mounted **`noexec`** — a VFS mount option enforced
  before any LSM hook.
- FUSE **synthesizes** the mode, so `chmod` does not stick: `chmod 755` left the
  file `-rw-rw---- root everybody`.

**Fix.** `GUEST_STAGING_DIR=/data/local/tmp` for Android, no subdirectory —
it already exists in the saved image, which the contract requires because
`injector -m writefile` does not create parent directories.

**Do not reach for permissive mode.** Neither cause is reachable by policy, no
`avc` denial is produced, and a permissive guest makes observed malware
behaviour unrepresentative.

**The tell that it worked:** `toybox: Unknown command /data/local/tmp/probe` is
a **successful execution** — toybox's own applet dispatch failing on an
unrecognised `argv[0]`. `execve` failures are reported by the shell instead.

*Source: `docs/checklists/android.md`, "Staging directory".*

### `injector`'s `FILE:` field is the Dom0 path, not the guest destination

**Symptom.** Verifying that a sample landed at `$GUEST_STAGING_DIR/<name>` by
grepping the `[INJECT]` line, and reading
`FILE:"/malware_processing/ubuntu/benign sample.sh"` — the **processing** path.

**Cause.** `injector` writes the **Dom0-side** path into `FILE:`. A
`grep -i writefile` therefore confirms nothing about the guest destination.

**Fix.** The guest destination appears only in `injector`'s own startup line:

```bash
grep -n 'Injector starting' "$LOG"
sed -n 's/^Injector starting \(.*\) through PID .*/[\1]/p' "$LOG"
```

The brackets are deliberate — they make leading and trailing whitespace visible.

**The follow-up grep was worse than ineffective**, and the shape generalises:
`grep -o '/home/carlos/Desktop/[^ "]*'` stops at the first space, so on a sample
named `benign sample.sh` it prints `/home/carlos/Desktop/benign` and **truncates
away the exact property the check exists to test**. Its output was never pasted,
so nothing caught it. A character class excluding space cannot verify a path
that may contain one.

### A sample filename reached the guest as shell metacharacters

**Symptom.** Quote, `$`, backtick or `;` in a submitted filename affecting guest
command construction.

**Cause.** `sample_name_admissible()` rejects only `/` and control characters.
Everything else reaches the guest.

**Fix.** Use the `sh -c '…' sh "$UNSAFE"` idiom so the value arrives as a
separate `execve` element. Sample-derived text may live in guest shell
*variables* and be used quoted; it may **not** reach the guest as text Dom0
pasted into a command. See `sandboxd/guests.py:449`.

### `monkey` aborted with exit 134

**Symptom.**

```
--- monkey ---
Aborted
monkey_rc=134
```

**Cause.** `app_process64` aborting before `main()` for want of the classpath
import. `preconfig-android.sh` carries that import; `drakvuf-android.sh` omitted
it.

**Fix — and it is not "add the import".** With the import added `monkey` does
work, but the `am` wrapper works with **no import at all**, and `monkey` is
rejected on separate grounds: `ActivityManager.isUserAMonkey()` reports its
presence **to the sample**. Use `am`, never `monkey`. It was the wrong mechanism
twice over.

### An APK install "succeeded" in the pipeline and installed nothing

**Symptom.** `pm` and `cmd` threads visibly busy, and **zero** `/data/app/`
writes, no `dex2oat`, no package name anywhere in the trace. A checklist line
recorded "which of the four steps failed: none".

**Cause.** The guest collapsed under introspection overhead. The trace showed
Android declaring its own system apps unresponsive (`AnrMainProcessD`,
`AnrAuxiliaryTas`, an ANR temp file in `dump/`) and `CachedAppOptimi` freezing
app cgroups, against 43,116 syscall events from `system_server` alone in 120 s.

**Fix.** The install path was never at fault: the same APK, same `pm install`
line, on an **untraced** clone succeeded in **3 seconds** and resolved
`org.fdroid.fdroid`. That is a lower bound of **40× overhead** — and a true
lower bound, since the traced install was never observed to finish at all.

**The generalisable lesson:** when an in-guest operation does not complete under
tracing, re-run it untraced before debugging the operation. Also beware that
"package name resolved: `F-Droid.apk`" records a *filename*, not a package name.

### DRAKVUF printed its banner and hung — no syscall breakpoints, no hooks

**Symptom.** DRAKVUF starts, prints its version banner, and then nothing: no
`[SYSCALLS] Syscall table breakpoints set`, no plugin hooks, still running seven
minutes into a 120-second trace.

**Cause. The injection anchor was not schedulable.** `injector` has to catch the
target process **on a vCPU** — it waits for the PID to be scheduled so it can
hijack the register context and vfork/execve from it. A terminal editor sitting
at its prompt is blocked in `read()` on the tty, parked on a wait queue and
never scheduled, so `injector` waits forever and DRAKVUF never gets past
injection. Backgrounding does not help: `nano &` is stopped by `SIGTTIN` the
moment it touches the tty, which is equally unschedulable.

**Fix, and it is currently different per OS:**

| OS | Anchor | State |
|---|---|---|
| **Ubuntu** | **systemd, `INJECTION_PID=1`** | working well — keep it |
| **Android** | **a backgrounded `ping`** (`INJECTION_PID=3251`) | moved back off PID 1 |

**Android could not stay on PID 1.** Android's init does not provide a runtime
environment for `app_process64`, so the APK path had to build one — and the
anchor moved back to a backgrounded `ping` against **127.0.0.1**, chosen so
anchor traffic stays out of `tcpdump.sh`'s per-sample pcaps. `ping` is
self-scheduling and single-threaded, which is what the constraint below asks
for.

That reintroduces the two costs PID 1 had removed for Android: the PID must be
**re-derived after every template re-save**, and it is a process a sample can
see in `ps`.

> **`automation/pipeline-android.env` sets `3251` while the comment block above
> it still argues for PID 1 and says "Both OS families now anchor on their
> init".** The value is right and the comment is stale — do not set Android to
> PID 1 on the strength of it.

**Two anchors failed before this, from opposite directions, and the second is
the non-obvious one:**

| Anchor | Why it failed |
|---|---|
| `nano` (Android, 2026-08-17; Ubuntu, 2026-08-28) | blocked in `read()` on the tty, and saved **STOPPED** after taking `SIGTTIN`. Never scheduled |
| `gedit` (Ubuntu, 2026-08-29) | a GUI event loop **is** schedulable — but only once input arrives, and a restored clone has no keyboard or mouse. It injected only after a click in `vncviewer` |

systemd's `sd-event` loop is woken by timers with **no input at all**, which is
what makes it work where a GUI does not.

**Requirements for any anchor:**

| Requirement | Why |
|---|---|
| **Schedulable without input** | `injector` cannot hijack a process that never runs, and a clone supplies no keyboard or mouse |
| **Single-threaded** | `injector` targets the TGID thread unless `-I` names one; a multi-threaded process makes the target ambiguous |
| **Negligible CPU** | rules out `yes > /dev/null` and other spin loops |
| **Unique process name** | Android has **two** processes named `init` — PID 1 and one before `ueventd` whose PID moves every boot. Never auto-discover by name |
| **Stable across a template rebuild**, or re-derived every time | PID 1 is PID 1 in every image. Any other anchor must be re-read after each `xl save` |

**The failure is silent and unbounded.** `injector` has no timeout and prints
nothing while it waits, and `dirwatch`'s uncounted retry turns that into an
endless clone/hang/kill loop. **A `vmi-process-list` match proves the task
exists; it does not prove it ever runs.**

### A stale `INJECTION_PID` after a template re-save

**Symptom.** `STATUS:PrematureBreak` and a timeout, against a template that
worked yesterday.

**Cause.** The anchor PID is valid **only for the `.bak` it came from**, and
`injector` attaches to whatever PID it is handed with no warning. Android's has
been 3163, 3164, 3174 and now 3251; Ubuntu's went 1415 → 1490 before moving to
PID 1. Injecting into 1309 — a PID from a previous boot — gave exactly this
signature on 2026-08-29.

**Fix.** Re-read the anchor PID after every re-save and write it back to
`pipeline-<os>.env`. **Ubuntu no longer needs this** because PID 1 is stable in
every image; **Android does**, having moved back to a `ping` anchor.

**The template checksum goes stale with it.** After a rebuild, a `sha256`
mismatch against a previously recorded baseline is the **expected** result, not
evidence of corruption — `1844fc0a…` belongs to the pre-EthernetConfig Android
template. Record the new value as the baseline and update it wherever it is
quoted, rather than treating the mismatch as a fault.

### `getent` is not available in the Android guest

**Symptom.** Ubuntu's DNS verification command has no equivalent on BlissOS.

**Cause.** bionic ships no `getent`.

**Fix.** `ping <name>`, which is the **stronger** test anyway: it resolves
through bionic → `netd`, the same path an application takes, and proves
resolution *and* reachability where `getent hosts` proved only the former.

**The cost, accepted 2026-08-29:** `execproc` inherits the anchor's credentials,
so **Ubuntu samples now execute as root** and privilege-escalation behaviour is
no longer observable. To get unprivileged samples back, drop privilege at exec
in `drakvuf-ubuntu.sh` (`setpriv --reuid=$GUEST_USER`) and leave preconfig as
root. Android pays nothing here — its anchor was already root.

*Sources: `automation/pipeline-ubuntu.env:185-205`,
`automation/pipeline-android.env:240-287`.*

### The injection anchor was the wrong process, and nothing warned

**Symptom.** Injection targets a process that is not the intended anchor.

**Cause.** `INJECTION_PID` is a **number captured at save time**, and the anchor
is a backgrounded `nano` — chosen so the string `drakvuf` appears nowhere in the
guest, which is an anti-evasion decision. It exists only inside the memory
image; nothing recreates it on boot.

**Fix.** Three properties, each of which has bitten this project: it must exist
in the saved image, it must be **unambiguous**, and its user must be the user
samples run as (`preconfig-ubuntu.sh` builds a `NETCFG` string using `sudo`).

**Do not build anchor auto-discovery on a process-name grep.** A guest that
happens to run a second `nano` gets the wrong process injected, and `injector`
does not warn.

### An empty `FORWARD` chain read as proof a rule was rejected

**Symptom.** No DROP rules present, taken as evidence that an isolation rule had
been refused by the kernel.

**Cause. `iptables` rules are runtime state and nothing in this project
persists them.** `POSTROUTING` was empty too — and `MASQUERADE` is valid syntax
that would have installed without complaint. The empty chains meant only that
`network-setup.sh` had not run since the host last booted.

**Fix.** Before reading absence as rejection, check whether the provisioning
script has run at all since boot. Absence of a rule is not evidence about the
rule; it is usually evidence about the script.

### `ip link delete` did not remove `xenbr1`, and the test passed anyway

**Symptom.** A teardown step reports success; the bridge is still there.

**Cause.** **`xenbr1` is an OVS bridge**, so `ip link delete` cannot remove it —
and the step ended in `2>/dev/null || true`, which swallowed the failure.

**Why this one matters more than it looks.** The step existed to prove
`network-setup.sh` *fails safely with no bridge*. With the bridge still present
the script exited 0, and **a pass was recorded for a test that never ran** — a
false pass on precisely the check meant to catch unsafe behaviour.

**Fix.** `ovs-vsctl del-br xenbr1`. And do not terminate a teardown step with
`|| true` when the *next* step's meaning depends on the teardown having
happened.

### `iptables-save | wc -l` is a weaker idempotency test than it looks

**Symptom.** A rule count that is stable across three runs, read as proof the
script is idempotent.

**Cause.** A count **detects growth but not substitution** — a run that replaced
one rule with a different one scores identically. And a single recorded number
cannot show whether all three runs agreed.

**Fix.** `diff` the full `iptables-save` output between runs and record all
three.

### A job fails with `sample digest does not match the one admitted`

**Symptom.** The run ends `failed` before any clone is built. The daemon log
carries the expected and actual SHA-256.

**Cause.** The object in the store is not the one admission hashed. Since
2026-08-31 `sandboxd` verifies the digest the lease carries against the bytes
it actually downloads, and refuses rather than detonating something the report
would then misdescribe.

Two ways to get here, and they are not equally innocent:

- **Benign.** MinIO's retention rule expired the object and a different one now
  occupies the key, or an operator overwrote it by hand.
- **Not benign.** The presigned POST issued at submission stays valid for
  `upload_ttl` (900s) and the store permits overwriting, so a submitter can
  replace the sample *after* admission recorded its hash. That is the case this
  check exists for: without it, the trace, the verdict and the SHA-256 all
  describe a file that never ran.

The platform's own claim-time check compares the store's ETag, which for a
single-part upload is an MD5 — it makes the ordinary swap loud, but MD5
collisions are constructible, so it is not the guarantee. The SHA-256 check on
Dom0 is.

**Fix.** Do not retry blindly. Look at whether the job's `created_at` is inside
`upload_ttl` of the failure: if it is, treat it as a deliberate substitution and
keep the row as evidence. Re-submitting produces a fresh job id and a fresh
upload ticket, which is the correct response to the benign cases.

**Do not "fix" it by skipping the check.** A lease that carries no `sha256` is
also refused, deliberately: admission writes that column in the same UPDATE
that moves a job to `admitted`, so a claimable job without one is an impossible
state, and running it would mean detonating bytes nothing can identify
afterwards.

### A job fails with `unusable lease`

**Symptom.** `sandboxd` refuses a claim with `unusable lease: sample name
contains a path separator` (or `job_id is not a UUID`), and does not run it.

**Cause.** The platform sent a `submitted_filename` or `job_id` that cannot be
a single path component. Both become directory and file names under root on
Dom0 — `staging/<job_id>/<filename>` is opened for writing and its parent is
handed to `shutil.rmtree` — and `pathlib` offers no protection: an absolute
name replaces the join outright, and a relative one is not normalised.

The platform validates this at submission and its check is tight, so in
practice this means the two sides disagree about what a lease may say. Treat it
as a platform bug or, if the platform is not the one you deployed, as an
attempt to write outside the staging tree.

**Fix.** Look at the job row on the platform. Note that shell metacharacters in
a filename — `$`, backtick, `"`, `;` — are **admissible and must stay that
way**: a sample really can be called `a$(id).exe` and byte-exact delivery of
that name is part of what is analysed. What makes them safe is the
`sh -c '…' sh "$UNSAFE"` idiom in `guests.py`, not a name filter. Only path
separators, `.`/`..` and control characters are refused.

### The host runs fewer clones than it has VLANs, and capacity keeps dropping

**Symptom.** `capacity: N vlan(s) usable` falls over a daemon's lifetime.
Restarting `sandboxd` restores it, and it falls again.

**Cause.** Working as intended, and the log says which VLAN and why:

```text
vlan 3 withheld after job <id>: cleanup was 'dirty: destroy'
```

Since 2026-08-31 a teardown that did not finish keeps its VLAN out of the pool
instead of handing it to the next sample. Before that, `cleanup_status` was
recorded on the job row, logged, and ignored — a domain that survived
`xl destroy`, an LV that would not release, or egress rules that outlived
their revoke all had their VLAN recycled immediately. `ResourceTable.withhold`
existed for this and had no caller.

**Fix.** Do not raise `SANDBOXD_MAX_CLONES` to compensate — that hands out
more VLANs without fixing the ones stuck. Find the withheld VLAN in the log
and deal with what survived on it:

```sh
xl list | grep -- -3-clone          # a domain that outlived xl destroy
lvs | grep -- -3-clone              # a snapshot LV that would not release
iptables -S DRAKVUF_EGRESS_V3       # egress rules that outlived their revoke
```

A restart is the supported recovery: the startup sweep destroys whatever
survived and re-admits the VLAN. If capacity falls again immediately
afterwards, the teardown is failing repeatably and the log line names the
stage — treat that as the real fault rather than restarting on a schedule.

`dirty: egress` specifically means `iptables -S` still answered for one of
that VLAN's chains after the revoke ran. Note that an emptied but undeleted
chain is harmless and still counts as dirty; that is deliberate, and the
sweep reclaims it.

### A job reported `offline` and the capture shows it reached the Internet

**Symptom.** A report whose Network section reads `offline`, beside a pcap full
of real outbound traffic. `iptables -S DRAKVUF_EGRESS_V<n>` shows no chain for
that VLAN, which looks like confirmation that nothing was installed — and
nothing was.

**Cause.** A **wildcard rule left by an earlier `direct` run**, not a per-job
rule at all. `network-setup.sh <n> direct` writes
`-i xenbr1.+ -o xenbr0 -j ACCEPT` into `DRAKVUF_EGRESS` and a matching
`MASQUERADE` into `DRAKVUF_EGRESS_NAT`. Both name no VLAN, so every delete in
`sandboxd/egress.py::argv_revoke` — all of which name one — missed them, and
nothing removed them. The grant lasted for the host's uptime and applied to
every later job. `offline` was the worst-affected mode, not the safest: it
installs nothing, so it has nothing that could collide with a leftover, and
`argv_apply` returning `[]` means no `iptables -N` fails to warn you.

Fixed 2026-08-31. Look for it on any host that ran `ALLOW_DIRECT=1` before
that date without rebooting since.

**Fix.** `iptables -S DRAKVUF_EGRESS` and read the whole chain, not the
per-VLAN sub-chain. Anything there that does not end in `-j
DRAKVUF_EGRESS_V<n>` applies to every clone. `network-setup.sh` now prints
exactly those lines as a warning on an `offline` run, deletes the legacy pair
by exact spec on that same branch, and `sweep._revoke_egress` deletes it again
at daemon start. Note that a reboot also clears it — there is no
`iptables-persistent` here — so a host that has been restarted since the
`direct` run will look clean and was not.

**Do not fix it with `iptables -F DRAKVUF_EGRESS`.** That takes the per-VLAN
jumps with it and cuts the network of every clone currently under analysis,
mid-trace. Delete the one spec.

### `bash: !xenbr0: event not found`

**Symptom.** An `iptables` rule using a negated interface fails in an
interactive shell.

**Cause.** **Bash history expansion** consuming the `!` before `iptables` sees
it. An interactive-shell behaviour only.

**Fix.** `network-setup.sh` runs under `/bin/sh` (dash), which has no history
expansion, so the production path is unaffected. To reproduce it by hand, go
through `sh -c` rather than typing it into bash — otherwise you are debugging
your shell, not the rule.

### `iptables -S` says a chain is "incompatible", and the chain is simply absent

**Symptom.** An error suggesting a tooling or backend mismatch.

**Cause.** On the nft backend, `iptables -S` reports **any nonexistent chain** as
"incompatible". "Chain absent" and "chain unreadable" produce the same text.

**Fix. This is a containment issue, not a cosmetic one** — *absent* means
isolation is entirely off, and a human reading the message as a tooling quirk
will proceed with no isolation at all. Use `nft list chain` as the readback that
distinguishes them. Owned by DRAFT-038.

*Related cosmetic note: `iptables -C` on the nft backend prints the matched rule
to **stdout**, and `2>/dev/null` only silences stderr — hence stray
`DRAKVUF_* all opt -- in * out *` lines in every provisioning transcript.*

### An analysis left evidence of itself inside the guest

**Symptom.** Scratch files, sockets or marker processes created for the
pipeline's own bookkeeping.

**Cause.** Designing cross-command state as a guest file — for example passing
an installed package name through `/data/local/tmp`.

**Fix.** Carry state in shell variables, derive it from a constant property of
the saved template, or configure it on Dom0. Anything left behind is an evasion
signal to live malware. Same reasoning renamed the injection anchor away from
`drakvuf-anchor` (issue #7) and rejected `monkey` for APK launch, because
`ActivityManager.isUserAMonkey()` reports it to the sample.

---

# Reading the project record itself

### A fact from a runbook turned out to be superseded

**Symptom.** A value read from `docs/runbooks/01`–`10` that no longer describes
this host.

**Cause.** Those ten runbooks describe the **nested Proxmox lab**, erased
2026-08-28. They are correct as dated evidence and wrong as a description of
today. `10-tune-nested-cpu.md` goes further: its premise ("can L0 give Dom0 more
CPU?") no longer exists, so it is **closed, not pending**.

**Fix.** `docs/CURRENT-STATE.md` §2a lists every fact the migration invalidated
in one table. Read it before citing any deployment number from a runbook. Every
fact there carries the date it was last confirmed; over 30 days old is a hint to
re-confirm, not a fact to assert.

### A performance measurement did not reproduce

**Symptom.** Throughput figures from before 2026-08-28 disagreeing with what the
host does now.

**Cause.** Two independent reasons, and it is easy to blame the wrong one.
Dom0 stopped being nested **and** DRAKVUF changed: the rebuilt Dom0 runs
`v1.1-da982ab`, while every pre-migration measurement was taken on
`…+52df0bc8-1`. Different code, different machine, same day.

**Fix.** Treat pre-migration numbers as describing a different system. The
comparison that would have isolated nesting alone is permanently unavailable —
it needed a nested baseline measured after the bare-metal run, on a host that no
longer exists (`12-baremetal-trial.md`, Parts E–G, abandoned).

### An upstream DRAKVUF build passed a casual check and was the wrong binary

**Symptom.** `drakvuf --help` shows `--memdump-disable-*` flags, so the build
looks like it has memdump. Traces against Ubuntu or Android then degrade or
produce nothing, silently.

**Cause.** **Upstream's memdump is Windows-only.** Those flags map to
`VirtualFree`, `VirtualProtect`, `WriteProcessMemory`, `TerminateProcess`,
`CreateThread`, `SetThreadContext` — their presence in `--help` proves nothing
about Linux support. This lab builds `lfreijo/drakvuf` branch `memdump`, which
adds `memdump/linux.cpp`, `memdump/linux.h`, splits `memdump.cpp` into
`win.cpp`/`linux.cpp`, and adds `syscalls/linux.cpp`.

**This actually happened during the migration** — an upstream build passed a
`--help` check.

**Fix.** Check the **version string**, not the flag list:
`drakvuf --version`. And check out the **commit, not the branch head** —
`git reset --hard lfreijo/memdump` gives whatever that branch points at today,
and a different DRAKVUF silently invalidates every comparison.

Those four plugins — `syscalls`, `filetracer`, `fileextractor`, `memdump` — are
exactly the four in every trace command here.

### `libzstd found: NO` and the build succeeded anyway

**Symptom.** DRAKVUF builds cleanly; trace output is written differently than
expected.

**Cause.** `libzstd-dev` was not installed before configuring. Meson reports
`libzstd found: NO` and **carries on**.

**Fix.** Install it before `meson setup`. `check` and `cmake` missing are benign
by contrast — they gate tests only.

### A regenerated `profiles/linux.json` silently does not work

**Symptom.** A freshly generated Linux profile produces no usable introspection.

**Cause.** **`dwarf2json` is pinned to branch `linux_non_canonical_addr4`**, not
a default branch. Building it from `main` produces a tool that emits a profile
which is accepted and does not work.

**Fix.** Use that branch for any regeneration. LibVMI needs no separate rebuild —
`git diff main..memdump -- libvmi` is empty, so the fork does not move that
submodule.

### Reasoning from upstream capability tables gave the wrong answer

**Symptom.** Concluding a DRAKVUF plugin does not support Linux.

**Cause.** Upstream's `drakvuf_plugin_os_support` marks `fileextractor` and
`memdump` as `[VMI_OS_LINUX] = 0`. **This lab builds the `lfreijo/drakvuf`
`memdump` fork**, whose entire purpose is flipping those to 1.

**Fix.** Check the **deployed build's** own evidence — runbooks, `--help`
captures, real trace output — before accepting an upstream capability claim in
either direction. `docs/architecture/upstream-drakvuf.md` carries the read
matrix and the caveat that it was taken from the branch tip, not the pinned
commit.

### A containment claim was written up without being tested

**Symptom.** A runbook stating *"filtering has not stopped"* while filtering had
stopped completely — no rules, no chains, no VLAN interfaces.

**Cause.** Two reasoning errors, and the second is the one worth carrying:

- An error message (`chain ... is incompatible`) was read as a tooling quirk
  rather than tested. One command would have settled it —
  `iptables -S NO_SUCH_CHAIN_12345` returns the same text.
- *"Those commands ran against the deployed chains"* was inferred **from the
  order of messages in a conversation**, not from any timestamp.

**Fix.** Test the interpretation before writing it up, and never offer
reassurance about a security property from an absence of contrary signal. The
true answer here was *"containment is currently absent"*, and the write-up said
the opposite. It took the maintainer to catch it.

**The generalisable form:** verify that a control **exists and holds the
expected rules**, not that it is *readable*. Absence and unreadability produce
identical output here, and only one of them means the lab is unprotected.

### A measured constant was used directly as a resource guard

**Symptom.** A limit set to exactly the measured value.

**Cause.** Treating one measurement of one clone as a distribution.

**Fix.** Set the constant **above** the measurement and keep both numbers
visible in the comment — "measured X, set to Y for margin". The failure modes
are asymmetric: over-reserving costs idle RAM, under-reserving costs an
OOM-killed `xl restore` partway through an analysis. `DOMAIN_OVERHEAD_MIB` is
150 against a measured 112 (`sandboxd/resources.py:58`). A Windows clone's
overhead has never been observed.
