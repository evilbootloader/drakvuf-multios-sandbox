# CI / self-hosted runner design

> **Status: draft, open to change.** Reviewed 2026-08-08, not yet
> implemented — no `.github/workflows/` files exist in this repository
> yet. This is a design document, not a specification frozen in place;
> revise it in place as decisions are validated (or invalidated) on real
> hardware, rather than letting it silently drift from whatever the actual
> workflow files end up doing. Written so a future developer can recreate
> the GitHub Actions CI and the self-hosted runner from this document
> alone, even if the workflow files themselves are lost. Cross-references
> `CLAUDE.md`'s infrastructure boundary, `CONTRIBUTING.md`'s
> `PLAN → CREATE → TEST → DEPLOY` lifecycle, and
> `docs/roadmap/project-roadmap.md`'s milestone sequencing.

## Purpose

Prove, on every pull request, that this repository's own code — the
DRAKVUF/LibVMI build inputs (`automation/dirwatch.c` plus the pinned
upstream source) and the pipeline scripts (`clone-ubuntu.pl` →
`preconfig-ubuntu.sh` → `drakvuf-ubuntu.sh` → `cleanup.sh`) — still
produces a working analysis run against a real Xen Dom0 lab, not just
that the scripts parse. The runner resets to a known-clean **base
snapshot** before every job; that base snapshot already contains Xen and
the fully-installed golden guest VMs (Ubuntu and Android/BlissOS), since
building a guest OS from an installer ISO is a one-time,
mostly-interactive provisioning task, not something a PR's code can
break. What a PR's code *can* break — the DRAKVUF/LibVMI build and the
pipeline scripts — is rebuilt and re-run fresh, from the PR's own
checkout, every single job.

A separate, cheap, GitHub-hosted tier still exists for fast syntax
feedback ahead of the heavy tier.

## CI goals

- Prove DRAKVUF and LibVMI build successfully from the PR's own
  `automation/dirwatch.c` against the pinned `lfreijo/drakvuf` `memdump`
  branch, on every pull request.
- Prove a sandbox VM can be cloned from the pre-installed golden VM,
  restored, and driven through a full benign analysis via the real
  pipeline scripts. *(The `<USER>` question this was originally also meant
  to settle was answered out-of-band on 2026-08-08 — see issue #2 /
  DRAFT-007; the end-to-end proof is still wanted in its own right.)*
- Give the Android pipeline a defined CI path for whenever its scripts
  exist (`docs/checklists/android.md` Phase 2 is 100% unimplemented
  "Candidate" content today).
- Exercise, per guest OS family, the full Linux-applicable DRAKVUF plugin
  set — both `ubuntu` and `android` are Linux-kernel guests, so both get
  the same plugin matrix (see "Plugin matrix" below), not just the four
  plugins `drakvuf-ubuntu.sh` happens to use today.
- Catch syntax/hygiene regressions cheaply before the expensive tier runs
  at all.
- Never execute a real malware sample automatically, from a PR or
  otherwise.
- Prevent repo↔Dom0 drift from recurring. "Ubuntu automation works" is no
  longer an unverified assertion — issue #2 established it by execution on
  2026-08-08 (`ExecProc Status:Success`, ~359k trace records, clean
  `exit_group`), and lines 41-43 and 599-605 below record the same. What
  that verification *found* was that `automation/` had silently diverged
  from the deployed copies, and nothing detects that automatically. Since
  2026-08-09 parity is maintained by a checkout on Dom0 rather than by
  copying, which narrows the window without closing it: an in-place edit to
  a deployed script still goes unnoticed. That is what this tier is for.

## CI architecture

```text
Pull Request
    |
    +--> Level 1: Static checks (GitHub-hosted, ubuntu-latest)
    |       bash -n / shellcheck / perl -c / anti-pattern grep
    |       Runs for ALL PRs, including forks. No privileged access.
    |
    +--> Level 2: Build-and-test (self-hosted, ephemeral)
            Gated to same-repository PRs by default (see "Security
            model" — forks do not get this tier without maintainer
            action). Also runnable manually via workflow_dispatch.
                |
                +--> Runner resets to the clean base snapshot before
                |    the job starts: Ubuntu 22.04 + Xen + the
                |    already-installed golden `ubuntu` and `android`
                |    VMs (with their dwarf2json profiles already
                |    generated and registered in /etc/libvmi.conf)
                |
                +--> Detect which OS family the PR touches
                |    (ubuntu / android / both / neither)
                |
                +--> Install DRAKVUF build dependencies
                +--> Initialize LibVMI (git submodule) + build DRAKVUF
                |    against the PR's own automation/dirwatch.c
                +--> Clone a sandbox VM from the pre-existing golden VM
                |    for the touched OS family, install the injection
                |    anchor, capture saved state
                +--> Provision network-setup.sh topology
                +--> Run the full applicable DRAKVUF plugin matrix
                |    against a benign fixture through the real
                |    per-OS pipeline scripts
                +--> Collect artifacts, clean up, report status
                +--> Runner is reset back to the clean base snapshot
                     for the next job

Push to master
    |
    +--> Same Level 1 + Level 2 suite, as a merge-confirmation run
```

No `pull_request_target` anywhere in this design.

### Why golden VMs are in the base snapshot, but DRAKVUF/LibVMI are not

Everything in the base snapshot is there because rebuilding it per job
would prove nothing about the PR under test and would cost a lot of time:

- **Xen** requires a GRUB change and host reboot to install — not
  something GitHub Actions can drive mid-job, and Xen version churn isn't
  what this CI is trying to catch.
- **The golden `ubuntu`/`android` VMs** are built once, interactively,
  from an installer ISO (`docs/drakvuf-on-xen-nested-within-proxmox.md`'s
  manual VNC-driven install; `docs/android_setup.md` §13, also manual).
  No PR to this repository can change what's inside those guest images —
  they aren't repository content — so rebuilding them per job would only
  re-prove the same installer works, at real cost (BlissOS's install in
  particular has no unattended/scripted path documented anywhere in this
  project, so automating it per-job would mean solving that gap just to
  run CI, not because CI needs it).
- **DRAKVUF and LibVMI**, by contrast, are built directly from files this
  repository tracks (`automation/dirwatch.c`) plus a pinned upstream
  revision — a PR *can* break this build, so it is rebuilt fresh from the
  PR's checkout every job, never cached into the base.
- **The pipeline scripts** (`clone-ubuntu.pl` etc.) are exactly what a PR
  is usually changing, so they always run against a freshly-cloned
  sandbox, never a leftover one.

This puts the line between "one-time provisioning" and "per-job CI work"
exactly where PR-controlled content starts, not one layer higher or
lower.

## GitHub-hosted workflows (Level 1)

Runs on `ubuntu-latest`, needs no privileged access, safe on
`pull_request` including from forks.

**This tier is no longer blocked.** DRAFT-031 landed 2026-08-11 and
`shellcheck automation/*.sh` now exits 0 against the `.shellcheckrc`
baseline, so the gate is green on unmodified working code rather than red
from its first run. Run it **bare** — `.shellcheckrc` is read
automatically, and `severity=` in that file is silently ignored by
shellcheck 0.11.0, so a `-S` flag here would diverge from what developers
run locally. `dash -n` is added alongside `bash -n` because the worker
scripts are interpreted by `/bin/sh`.

```bash
for f in automation/*.sh; do bash -n "$f"; dash -n "$f"; done
shellcheck automation/*.sh          # bare: reads .shellcheckrc, exits 0
perl -c automation/clone-ubuntu.pl

# Anti-pattern checks, same acceptance gates docs/checklists/android.md
# §6.1 already defines for the (not yet written) Android scripts, applied
# here to the existing Ubuntu scripts too:
grep -Rns '<USER>' automation/ && exit 1   # regression guard, see issue #2
grep -Rns 'ps aux.*grep\|ps .*|.*grep' automation/
```

`dirwatch.c` is **not** compiled at this tier — it `#include`s
`<config.h>` and `../xen_helper/xen_helper.h` (`automation/dirwatch.c:118,120`)
and only compiles inside a real DRAKVUF source tree, which needs Xen dev
headers this tier deliberately doesn't have. That compile happens in
Level 2.

The `<USER>` grep now **passes** on `master`: issue #2 was resolved on
2026-08-08 by syncing `automation/` from the tested Dom0 host, so the
placeholder is gone from every script. It stays in the pipeline as a
regression guard against a future half-substituted deployment copy being
committed again.

Worth adding at this tier, given what issue #2 uncovered: a **repo↔host
drift check**. The `<USER>` placeholder was never a production bug — it was
a symptom of `automation/` having silently diverged from what Dom0 actually
ran, which nothing detected for months. A checksum comparison of
`automation/*` against the deployed copies belongs in Level 2 (where a real
Dom0 is available); see `docs/runbooks/verify-user-placeholder.md` for the
`sha256sum` comparison that found it by hand.

No unit test framework (pytest, `Makefile`, `package.json`,
`pyproject.toml`) exists anywhere in this repository as of this session.

## Self-hosted runner architecture

- **Base snapshot contents:** Ubuntu 22.04 LTS + Xen (installed and
  GRUB-configured per `docs/drakvuf-on-xen-nested-within-proxmox.md`),
  running as the L1 VM under Proxmox/KVM, **plus the already-installed
  golden `ubuntu` and `android` guest VMs**, with their `dwarf2json`
  kernel profiles already generated and registered in
  `/etc/libvmi.conf` (`ubuntu`/`android` stanzas — not the `_sandbox`
  ones, since sandboxes are created per job). The installer ISOs stay
  staged on disk too (e.g. `/root/isos/ubuntu-20.04.6-desktop-amd64.iso`,
  `/root/isos/Bliss-v17.8.3-x86_64-UNOFFICIAL-vanilla-20260806.iso` — the
  latter already exists on this project's dev machine at
  `misc/Bliss-v17.8.3-x86_64-UNOFFICIAL-vanilla-20260806.iso`, untracked
  by git per `.gitignore`'s `*.iso` rule) so a golden VM can be rebuilt
  by hand if the base snapshot is ever refreshed. **Not** in the base:
  DRAKVUF, LibVMI, any `_sandbox` VM or its saved state, and the GitHub
  Actions runner's job-scoped state.
- **Hardware / virtualization requirements** (inherited from the project
  regardless of CI): Intel VT-x + EPT (DRAKVUF does not support AMD),
  nested virtualization enabled in `kvm_intel` (`nested=Y`), VMX exposed
  from Proxmox to the Xen Dom0 VM, `dom0_mem=4096M` etc. per the
  documented `GRUB_CMDLINE_XEN_DEFAULT`.
- **Privileges:** the runner needs the same root/sudo access the manual
  procedures already assume — `xl`, `lvcreate`/`lvremove`/`lvs`,
  `ovs-vsctl`, `iptables`, `vmi-process-list`, plus `apt-get install` for
  the DRAKVUF build dependency list.
- **Storage:** `vg-root` already carries the golden `ubuntu`/`android` LVs
  (64 GiB each per the documented `.cfg` files) as part of the base
  snapshot; each job additionally needs room for one `_sandbox` LV per
  touched OS family, cloned from the corresponding golden LV.
- **Networking:** `xenbr0` (uplink) and `xenbr1` (OVS analysis bridge),
  provisioned per-job by `network-setup.sh` exactly as the manual
  procedure does — disposable, job-scoped state, not part of the base.
- **Runner labels (single-host reality, not a fleet):**

  ```yaml
  runs-on:
    - self-hosted
    - linux
    - x64
    - xen-dom0
  ```

## Self-hosted runner provisioning

Two layers: a one-time base-snapshot build (now including the golden
VMs), and a per-job reset-to-that-base mechanism.

### PLAN

1. Decide the snapshot-reset mechanism (leading candidate: a Proxmox VM
   snapshot of the L1 VM itself, since L1 already is a Proxmox-managed
   VM — confirm `qm snapshot`/`qm rollback` timing is acceptable given
   the snapshot now includes two installed guest OS disks, not just a
   bare Ubuntu 22.04 install). Try to create a method to run the restore without access to the full proxmox server, perhaps tailscale + API in proxmox with specific permissions
2. Confirm the ISO staging path is stable across snapshot reverts (baked
   into the snapshot, not fetched per job).

### CREATE — base snapshot (one time; repeat only to refresh the base)

Go back to base snapshot via Proxmox VE API connecting through Tailscale.

Run on **L1 / Xen Dom0 VM** (condensed — see
`docs/drakvuf-on-xen-nested-within-proxmox.md` and
`docs/android_setup.md` for the unabridged versions):

```bash
sudo apt update && sudo apt upgrade
sudo apt install qemu-guest-agent spice-vdagent git -y
# bridge the Proxmox-facing NIC into xenbr0 via Netplan
sudo apt install <path-to-xen-hypervisor-4.20.1-ubuntu-jammy-amd64.deb> -y
# edit /etc/default/grub.d/xen.cfg per the documented GRUB_CMDLINE_XEN_DEFAULT
sudo update-grub2
reboot
sudo xen-detect
sudo xl dmesg | grep -iE "VMX|EPT"
```

Then, still one-time and still mostly the existing manual/interactive
procedure (not newly automated by this design):

```bash
# Golden Ubuntu VM
sudo lvcreate -L64G -n ubuntu vg-root
# write ubuntu.cfg pointing at the staged Ubuntu ISO, xl create it,
# install manually via VNC per docs/drakvuf-on-xen-nested-within-proxmox.md
# then, with the VM shut down:
kpartx -a /dev/vg-root/ubuntu
mount -o ro /dev/mapper/vg--root-ubuntu5 /mnt
./dwarf2json-linux-amd64 linux \
    --system-map /mnt/boot/System.map-<kernel-version> \
    --elf /mnt/usr/lib/debug/boot/vmlinux-<kernel-version> \
    > /root/linux.json
umount /mnt
kpartx -d /dev/vg-root/ubuntu
printf 'ubuntu {\n\tvolatility_ist = "/root/linux.json";\n}\n' | sudo tee -a /etc/libvmi.conf

# Golden Android VM
sudo lvcreate -L64G -n android vg-root
# write android.cfg pointing at the staged BlissOS ISO, xl create it,
# install manually via VNC per docs/android_setup.md §13
# dwarf2json profile for Android is generated on the separate BlissOS
# *build host* (docs/android_setup.md §14), not on Dom0 — copy the
# resulting android.json to Dom0 and register it:
sudo install -o root -g root -m 0600 /tmp/android.json /root/android.json
printf 'android {\n\tvolatility_ist = "/root/android.json";\n}\n' | sudo tee -a /etc/libvmi.conf
```

Install the GitHub Actions runner agent (see "Runner registration").
**Stop here.** Do not build DRAKVUF, create `_sandbox` VMs, or run any
pipeline script as part of the base — that is Level 2 job work, done
fresh every run, using the PR's own code. Snapshot the VM in this exact
state (Xen + both golden VMs + both profiles registered); this snapshot
is what every job resets to.

### TEST

```bash
sudo xen-detect
sudo xl dmesg | grep -iE "VMX|EPT"
sudo xl list                     # base snapshot itself has no running
                                  # domains; boot ubuntu/android manually
                                  # to confirm they still start:
sudo xl create ubuntu.cfg && sudo vmi-process-list ubuntu && sudo xl destroy ubuntu
sudo xl create android.cfg && sudo vmi-process-list android && sudo xl destroy android
which drakvuf && echo "UNEXPECTED: DRAKVUF should not be pre-installed in the base image"
```

### DEPLOY

Register the runner, apply labels, take the base snapshot, and wire the
snapshot-reset mechanism into the runner's job lifecycle before enabling
any Level 2 workflow on `pull_request`.

## Runner registration

Conceptual steps only — no tokens recorded here.

1. From the repository's Settings → Actions → Runners → "New self-hosted
   runner", copy the Linux x64 registration command.
2. Run `config.sh` with `--labels self-hosted,linux,x64,xen-dom0`,
   `--ephemeral` (one job per registration, matching the reset-per-job
   model), and a scoped runner name.
3. Run as a `systemd` service so the supervisor loop (below) can restart
   it cleanly after every reset.
4. Registration tokens are short-lived and per-registration — never
   commit one; re-generate if the runner is re-registered.

## Runner lifecycle

**Ephemeral, reset to the clean base snapshot before every job.** The
base now includes the golden VMs, which makes each reset heavier
(more disk state in the snapshot) but removes an entire class of
per-job risk: a job can never corrupt a golden VM, because it never
writes to one directly — it only clones a `_sandbox` LV from it.

Sequencing (the part that needs care): the runner process cannot revert
its own VM's snapshot mid-job — that would kill the runner process along
with everything else. The reset has to happen from **outside** the VM
being reset, i.e. from L0/Proxmox, between jobs:

```text
1. L0 supervisor (a small script/systemd unit on the Proxmox host, not
   inside the L1 VM) starts the L1 VM from the base snapshot.
2. The --ephemeral GitHub Actions runner agent inside L1 starts, waits
   for one job, runs it to completion (or timeout/cancellation).
3. The ephemeral runner agent exits after that one job.
4. The L0 supervisor detects the agent/VM has finished, reverts the L1
   VM to the base snapshot (qm rollback or equivalent), and loops back
   to step 1 for the next queued job.
```

This supervisor loop does not exist yet and is new CREATE work — it is
not part of the standard GitHub Actions runner installer. Document the
exact chosen mechanism here once built.

## Repository installation

Each Level 2 job checks out the PR branch via `actions/checkout` into the
runner's work directory inside the freshly-reset L1 VM.

**Resolved 2026-08-09 (issue #4).** The checkout no longer has to sit at
any particular path. Every script resolves its own location and derives
repository-owned assets from it, so `actions/checkout`'s work directory
works unchanged and the `$GITHUB_WORKSPACE` stopgap described here is no
longer needed — jobs can invoke `automation/run_analysis-ubuntu.sh`
directly instead of reconstructing the `dirwatch` command line. That was
the point of standardizing on `/root/sandbox_project`: it is the
documented location, not a required one.

Two things a job must still stage into the checkout, because neither is
git-tracked:

- `profiles/linux.json` (and `profiles/android.json` when the Android
  pipeline runs) — see `profiles/README.md`. Cache these in the base
  snapshot and copy or symlink them in; regenerating `dwarf2json` output
  per job would dominate the runtime.
- `state/<origin>.bak` — produced by the base snapshot's sandbox-VM
  creation step, which already ends in `xl save`. Write it to
  `state/<origin>.bak` inside the checkout rather than to
  `/home/user/Documents/`.

Both paths come from `automation/pipeline-ubuntu.env`, so a job that
needs to override them sets `KERNEL_PROFILE` / `SAVED_STATE` rather than
patching scripts.

## Test stages

### `static` (Level 1)

Unchanged from the GitHub-hosted section above. Trigger: `pull_request`
(incl. forks), `push` to `master`.

### `build-and-test` (Level 2 — the main tier)

- **Purpose:** rebuild DRAKVUF/LibVMI from the PR's own code against the
  pre-existing golden VMs, then run a real pipeline test.
- **Runner:** self-hosted, ephemeral, reset per job (see above).
- **Trigger:** `pull_request` for same-repository branches (see "Security
  model"), `push` to `master`, `workflow_dispatch`.
- **Scope detection:** diff the PR against its base to decide whether to
  exercise the `ubuntu`, `android`, or both pipelines — e.g. a path
  filter on `automation/*-ubuntu.sh`/`clone-ubuntu.pl` vs. the (currently
  nonexistent) `*-android.*` scripts. A PR touching only unrelated docs
  can skip both — exact filter rules are implementation detail for when
  the workflow YAML is written.
- **Steps:**

  1. **Install DRAKVUF build dependencies** — the full `apt-get install`
     list from `docs/drakvuf-on-xen-nested-within-proxmox.md`'s
     "Automated analysis setup" section (`bcc bin86 gawk ...
     libvncserver-dev libssl-dev ... libyajl-dev libpixman-1-dev
     libaio-dev ... kpartx python3-dev python3-pip golang ...`), plus
     `sudo pip3 install pefile construct`.
  2. **LibVMI initialization + DRAKVUF build** — mirrors the source
     doc's own "Build DRAKVUF after LibVMI initialization" heading:
     clone `lfreijo/drakvuf`'s `memdump` branch, `git submodule update
     --init --recursive` (this initializes and later builds LibVMI — a
     submodule of the DRAKVUF tree, not a separately-cloned project),
     copy the PR's own `automation/dirwatch.c` into
     `~/drakvuf/src/dirwatch/`, apply the documented idempotent
     `Makefile.am` memdump-backend patch, then `./autogen.sh &&
     ./configure && make -j"$(nproc)" && sudo make install && sudo
     ldconfig`. This single build produces both the DRAKVUF
     binaries/plugins and LibVMI.
  3. **Sandbox VM creation, per touched OS family, from the pre-existing
     golden LV** — `lvcreate` + `dd`-clone from `vg-root/ubuntu` or
     `vg-root/android` (already installed, part of the base snapshot),
     `apt install screen tcpdump vlan openvswitch-switch`
     (**`apache2` dropped 2026-08-09, issue #4** — sample delivery is
     `injector -m writefile` and the pipeline no longer depends on a web
     server; see `docs/architecture/analysis-pipeline.md`),
     `network-setup.sh <n>`, `xl create <os>_sandbox.cfg`, install the
     long-lived injection-anchor process inside the guest, record its
     PID/TGID, `xl save` to capture the `.bak` state — the documented
     sequence, now fast because the golden VM it clones from already
     exists.
  4. **Network provisioning:** `network-setup.sh` (existing script,
     unmodified).
  5. **Plugin matrix + pipeline test:** see "Plugin matrix" and the
     `ubuntu-pipeline`/`android-pipeline` sub-stages below.
  6. **Artifact collection, cleanup, status report.**
- **Expected result:** DRAKVUF/LibVMI build succeeds; the cloned sandbox
  VM restores and passes LibVMI process enumeration; the pipeline test
  completes with the sample confirmed executed.
- **Cleanup:** the ultimate cleanup is the next job's snapshot revert;
  in-job cleanup only needs to avoid the *current* job's own later steps
  tripping over earlier ones.

#### Plugin matrix

Both `ubuntu` and `android` are Linux-kernel guests, so both get the same
Linux-applicable plugin set. Per
`docs/architecture/upstream-drakvuf.md`'s source-verified plugin
inventory (`tklengyel/drakvuf:src/plugins/`): `syscalls`, `filetracer`,
`fileextractor`, `memdump` (already used today), plus `apimon`,
`procdump`, `regmon`, `socketmon`, `rootkitmon`, `ipt`, `ebpfmon`, and any
other plugin confirmed Linux-compatible at implementation time — **not**
`tlsmon`, confirmed by direct source read
(`src/plugins/tlsmon/tlsmon.cpp`, see `docs/architecture/networking.md`)
to hook Windows `ncrypt.dll`/Schannel only. Validate each plugin starts
cleanly against each sandbox VM (mirroring the existing "Plugin
validation matrix" table in `docs/checklists/android.md` §0.4) before
trusting it in the pipeline test.

#### `ubuntu-pipeline` sub-stage

Invoke the existing per-script pipeline (`clone-ubuntu.pl` →
`preconfig-ubuntu.sh` → `drakvuf-ubuntu.sh` → `cleanup.sh`) directly
against a CI-scoped fixture directory
(`$GITHUB_WORKSPACE/.ci-fixtures/{incoming,processing,finished}`, never
the real `/malware_incoming`/etc.) with one benign fixture (see "Test
assets" — does not exist yet). Issue #2's `<USER>` question no longer needs
this stage — it was answered out-of-band on 2026-08-08 — but this is where
an equivalent question would get caught automatically next time, which is
the argument for the repo↔host checksum check above.

#### `android-pipeline` sub-stage

Same shape, but **blocked**: `clone-android.pl`, `preconfig-android.sh`,
`drakvuf-android.sh` don't exist yet (DRAFT-015/016). This sub-stage is a
placeholder in the design, not a runnable job, until those scripts exist.

## Test assets

No benign fixture set exists in this repository —
`docs/checklists/android.md` §6.4's fixture inventory table is entirely
unpopulated. At minimum, one harmless, deterministic Ubuntu-side fixture
(e.g. a small script that writes a known file and exits 0, SHA-256
recorded) is needed before `ubuntu-pipeline` can run at all. Building
this is separate CREATE work, called out as a dependency here rather than
invented in this document. Real malware samples are never used in CI,
under any trigger.

## GitHub Actions triggers

| Trigger | Static (L1) | Build-and-test (L2) |
|---|---:|---:|
| `pull_request`, same-repository branch and triggeded by owneer | Yes | Yes |
| `pull_request`, fork | Yes | **No by default — see Security model** |
| `push` to `master` | Yes | Yes (merge confirmation) |
| `workflow_dispatch` | Yes | Yes |
| `schedule` | No | Future: nightly/weekly endurance only |

## Security model

Running the build-and-test tier **on pull requests**, as requested, means
PR-controlled code (the checked-out branch) runs with root/sudo access on
lab infrastructure that also hosts real malware-analysis work. The
ephemeral, snapshot-reset runner lifecycle contains *persistence* risk
well — nothing a job does survives past the next reset, and a job can
never write to a golden VM directly — but it does not by itself contain
*in-the-moment* risk: a malicious PR branch could still, during its one
job, try to pivot off the L1 VM toward the Proxmox host or the network
while the job runs.

Recommended default, a standard pattern for exactly this situation:
restrict the `pull_request` trigger for the Level 2 workflow to
same-repository PRs — e.g. gate the job on
`github.event.pull_request.head.repo.full_name == github.repository` —
so a fork PR only ever gets the harmless Level 1 static tier
automatically. A maintainer can still run Level 2 against a fork PR's
exact commit deliberately via `workflow_dispatch` with an input for the
PR's ref, after reviewing the diff first. This project is currently
single-operator (`evilbootloader`), so practical exposure today is low,
but the workflow YAML should encode the restriction from the start rather
than relying on "no one else has PR'd yet" as the actual control.

`GITHUB_TOKEN` permissions should be minimal and explicit
(`permissions: { contents: read }` at minimum for both tiers); no
external secrets are needed for anything in this design. If a future
stage needs one, it must never be reachable from a fork-triggered
workflow.

## Artifacts and logs

Upload on failure:

```text
apt/build logs (dependency install, DRAKVUF autogen/configure/make)
config.log
drakvuf.log, DRAKVUF JSON event output
Dump folders of plugins
xl dmesg output, xl list -l output
ip -br addr, ovs-vsctl show, iptables-save (network diagnostics)
cleanup.log
```

Never upload: anything from the real `/malware_incoming`,
`/malware_processing`, `/malware_finished` directories; pcap/memdump
content beyond the CI-fixture scope; `.bak` saved-VM-state files (a
job's own `.bak` is fresh, CI-only state, but per DRAFT-025's security
notes these files can be large and sensitive in general, so treat the
pattern as never-uploaded on principle, not case-by-case).


## Cleanup

Primary cleanup mechanism is the snapshot revert between jobs — stronger
than any in-job cleanup script, since it doesn't depend on the job having
run cleanly enough to reach its own cleanup step, and it's what protects
the golden VMs specifically (a job only ever touches its own cloned
`_sandbox` LV). In-job cleanup (`cleanup.sh`, existing) still runs with
`if: always()` as defense-in-depth within a single job's own steps.

## Failure recovery

If a job fails, the next job still gets a clean base via the snapshot
revert — no manual Dom0 cleanup is required to unblock CI. Manual
intervention is only needed if:

- The snapshot-reset supervisor loop itself breaks (VM won't boot from
  the base snapshot, or the ephemeral runner agent fails to register).
- A job is still "in flight" against real infrastructure when someone
  needs to intervene immediately (`xl destroy <domain>` from L0/L1
  directly, bypassing the job/reset cycle).

```bash
sudo xl list
sudo xl destroy <domain>
sudo systemctl status actions.runner.<repo>.<runner-name>.service
```

## Recreating CI

```text
[ ] Confirm Proxmox host: VT-x/EPT, nested virtualization enabled
[ ] Confirm/create the L1 Xen Dom0 VM
[ ] Install Xen (drakvuf-builds .deb), configure GRUB_CMDLINE_XEN_DEFAULT
[ ] Reboot, verify `xen-detect` and `xl dmesg | grep -iE "VMX|EPT"`
[ ] Stage the Ubuntu + BlissOS installer ISOs at a fixed path
[ ] Manually install the golden `ubuntu` VM, generate/register /root/linux.json
[ ] Manually install the golden `android` VM, copy/register /root/android.json
    (profile generated on the separate BlissOS build host, per docs/android_setup.md §14)
[ ] Install the GitHub Actions self-hosted runner agent (--ephemeral)
[ ] Take the base snapshot: Xen + both golden VMs + both profiles registered
[ ] Build and test the L0 snapshot-reset supervisor loop
[ ] Register the runner with labels: self-hosted, linux, x64, xen-dom0
[ ] Add .github/workflows/ci-static.yml (GitHub-hosted, pull_request+push)
[ ] Add .github/workflows/ci-build-and-test.yml (self-hosted, ephemeral,
    pull_request [same-repo] + push + workflow_dispatch)
[ ] Build at least one benign Ubuntu-side fixture with a recorded SHA-256
[ ] Run the full Level 2 workflow manually once and record the result
    before enabling it automatically on pull_request
[ ] Document branch protection requiring at least Level 1 before merge
```

## Known limitations

- **The snapshot-reset supervisor loop is new infrastructure**, not
  something the GitHub Actions runner installer provides out of the
  box — it needs to be built and hardened before Level 2 can be trusted
  to run unattended on every PR.
- **Base-snapshot refresh is still a manual, interactive process** for
  the golden VMs (no unattended-install automation is proposed here,
  deliberately — see "Why golden VMs are in the base snapshot"). Anyone
  refreshing the base snapshot repeats the existing manual VNC-driven
  install from `docs/drakvuf-on-xen-nested-within-proxmox.md` /
  `docs/android_setup.md` by hand.
- Level 2 build time (DRAKVUF/LibVMI Autotools build + sandbox clone) is
  still nontrivial per job, though far less than rebuilding golden VMs
  would have been — expect at least several minutes to tens of minutes
  until measured on real hardware.
- The `lfreijo/drakvuf` fork (used for the `memdump` branch) is a
  single-maintainer, unmirrored fork (`docs/architecture/upstream-drakvuf.md`,
  DRAFT-024) — if it disappears, Level 2's build step breaks along with
  the manual procedure it mirrors.
- ~~`ubuntu-pipeline`'s result is not fully trustworthy as a regression
  baseline until issue #2 (the `<USER>` placeholder question) is
  resolved one way or the other.~~ Resolved 2026-08-08: the Ubuntu
  pipeline is now execution-evidenced end-to-end and `automation/` matches
  the tested Dom0 host, so it *is* a usable regression baseline. The
  residual risk is drift recurring unnoticed — hence the repo↔host
  checksum check proposed for this tier.
- No benign fixture set exists yet — `ubuntu-pipeline` cannot run at all
  until at least one is created.
- Android's `dwarf2json` profile still depends on the separate,
  multi-hour AOSP/BlissOS build process (`docs/android_setup.md` §1–9) —
  that process is out of scope for this CI design entirely and remains a
  one-time, off-Dom0 step whose output (`android.json`) is copied in
  during base-snapshot provisioning.

## Future CI work

- `android-pipeline` once DRAFT-015/016 land.
- Windows CI once **DRAFT-034** (`docs/checklists/windows.md`) produces a
  baseline — note a Windows golden VM would follow the same "already in the
  base snapshot" pattern established here. *(Was "once the M5 planning
  spike produces a baseline"; Windows is a current target and DRAFT-034 is
  its track head, not a deferred M5 exercise.)*
- `capa` post-processing tests once the result schema (DRAFT-018) and
  real DRAKVUF logs exist.
- Scheduled nightly/weekly endurance runs
  (`docs/checklists/android.md` §6.8's 50-run test).
- Automating the golden-VM install (Ubuntu autoinstall/preseed; a
  scripted or pre-imaged BlissOS path) if base-snapshot refreshes turn
  out to happen often enough that the manual process becomes a
  bottleneck — explicitly deferred, not designed now.
- A proper secrets-management design
  (`docs/roadmap/project-roadmap.md` risk #10) once any workflow actually
  needs one.