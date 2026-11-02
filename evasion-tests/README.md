# Evasion tests — does the sandbox give itself away?

Two searches that run a detection program inside the analysis guests while
DRAKVUF traces them, and record whether it found the sandbox:

- **`rdtsc_search.sh`**, Ubuntu guest: `detector.c`, whose verdict is a **red
  pill**: `sidt; rdtsc; sidt; rdtsc`, detected when the second read is more
  than 100 cycles after the first. It is the test Xen's RDTSC compensation was
  designed and measured against
  ([`rdtsc-poc.md`](../docs/architecture/rdtsc-poc.md)).
- **`alkhaser_search.sh`**, Windows guest: [al-khaser](https://github.com/ayoubfaouzi/al-khaser)
  with `al-khaser.patch`, which gives every check a code and makes the trace
  name each detection. It measured the guest identity
  ([`guest-identity.md`](../docs/architecture/guest-identity.md)).

Each search walks a list of **variants**: builds of Xen with different values
for the compensation's `#define`s. For each one it builds and installs that Xen
on Dom0, reboots into it and runs the tests. A variant with no `#define`s
(`baseline`) tests the Xen `make xen` installs.

> **Status (2026-11-02).** These are the scripts behind the evidence in
> `rdtsc-poc.md` and `guest-identity.md`, run until then from a working
> directory outside this repository on the lab's Dom0 (i9-13900KF). In that
> move they gained `site.conf`, the Dom0-tree mode, the DRAKVUF source check
> and the clone-disk check. **None of those has run on a Dom0 yet.**

---

## 1. What runs where

The search runs on **a second machine**: it reboots Dom0 twice for every
variant that needs a new Xen build. Run it in `tmux` there, because a search
takes hours.

| File | Runs on | Does |
|---|---|---|
| `rdtsc_search.sh`, `alkhaser_search.sh` | your machine | the searches |
| `search_common.sh` | your machine | shared by both: settings, ssh, Dom0 jobs, reboots, variants, Xen and DRAKVUF builds |
| `site.conf.example` | — | the host settings; copy to `site.conf` (not tracked) |
| `variants/*.txt` | — | the variants each search tries by default |
| `rdtsc_rank.py`, `alkhaser_rank.py` | your machine | rank a search's variants, `ranking.txt` |
| `rdtsc_vnc.sh` | your machine | VNC viewers on the test VMs while a search runs (`VNC=1`) |
| `build_al_khaser.sh`, `al-khaser.patch` | your machine | cross-build `build/al-khaser_x64.exe` |
| `benchmark_drakvuf.sh` | Dom0, as root | one test: thin snapshot, `xl restore`, DRAKVUF with the workload injected, teardown |
| `check_sysret_pairing.py` | Dom0 | called by the benchmark after each run |
| `workload-linux.sh`, `workload-windows.cmd` | the guests | the benchmark's workload when run by hand without `WORKLOAD` (the searches inject the detector or al-khaser instead) |
| `detector.c` | the Ubuntu guest | built on Dom0 by `rdtsc_search.sh`, injected by the benchmark |

**A test** is one run of each of two DRAKVUF configurations. `dev-syscalls` is
`syscalls`, `cpuidmon` and `hidsim`. `dev-all` is every plugin. Both use
`--parallel-events --sysret-mode kernel`. With two test VMs the two
configurations run at the same time, one per VM, and swap VMs every test.

---

## 2. Requirements

- **An Intel CPU with VT-x and EPT.** The compensation is VMX code
  (`xen/arch/x86/hvm/vmx/vmx.c`), and DRAKVUF's altp2m needs EPT. On AMD
  there is nothing to test.
- **A Dom0 deployed from this repository**:
  - `make xen` installed Xen with the patches and `rdtsc-poc=1`.
  - `make sandboxd` built `drakvuf/build` and `drakvuf/libvmi`.
  - The guests were installed and saved by `ubuntu_analysis_vm` +
    `setup_hooks_ubuntu` and `windows_analysis_vm` + `modify_windows` +
    `setup_hooks_windows`. That gives `state/*_sandbox.bak`, `profiles/` and
    `INJECTION_PID_WINDOWS` in `sandboxd/config.py`.
  - Dom0 needs `git` and `gcc`, which `make xen` installs.
- **The same commit on both checkouts**, this one and Dom0's. The searches
  compare the Xen patch and the `drakvuf` submodule (§4) and refuse to run if
  they differ. The benchmark itself runs from Dom0's `evasion-tests/`.
- **Root ssh to Dom0 with a key**, no password: the search logs in hundreds of
  times.
- **GRUB that boots Dom0 without Xen, unattended.** Dom0 builds Xen booted on
  its plain kernel, the only boot Xen may be built on. `make xen`'s
  `/etc/default/grub.d/xen.cfg` switches the default entry with one commented
  line (`XEN_OVERRIDE_GRUB_DEFAULT=0`), and the search flips it. Try it once
  by hand before the first search (§7.7).
- **Disk on Dom0** for the output: an al-khaser test writes tens of GB (§7.5).
- **Nothing else using the guests.** Stop `sandboxd` in its terminal; it has
  no systemd unit, and two orchestrators must never share a host. Each reboot
  also takes down the platform DomU.
- On your machine: `bash`, `ssh`/`scp`, `git`, `python3`. For the al-khaser
  build also LLVM (`clang-cl`, `lld-link`, `llvm-ml`) and
  [xwin](https://github.com/Jake-Shadle/xwin), whose `splat` unpacks
  Microsoft's CRT and SDK. Running it means accepting Microsoft's license,
  which is your decision. Optional: TigerVNC's `vncviewer` for `VNC=1`.

---

## 3. Setup

### 3.1 `site.conf`

```bash
# THIS MACHINE, in evasion-tests/
cp site.conf.example site.conf      # then edit it
```

Every host value lives in this file: Dom0's address and key, Dom0's checkout,
the test VMs, the output disk and the build CPUs. `site.conf.example`
documents each. Keep its `VAR=${VAR:-value}` form, so a value given on the
command line still wins.

### 3.2 Test VMs

The benchmark restores the guest's saved state with its own Xen config, onto a
fresh **thin snapshot** of the guest's LV for every run, and destroys both
afterwards. Make one config per test VM on Dom0 from the guest's
`misc/xen-vms/<guest>_sandbox.cfg`. On Dom0, `make` has already added the
identity's lines to that file.

**Never restore onto the origin.** Those templates' `disk` names the golden LV
the saved state belongs to, and a restore onto it advances the disk past the
`.bak` ([TROUBLESHOOTING](../docs/TROUBLESHOOTING.md#a-templates-disk-drifted-away-from-its-saved-memory-image)).
The benchmark refuses a config whose `disk` does not name its `CLONE_NAME`.

```bash
# DOM0, as root. Ubuntu shown; Windows is the same with windows_*. Writes new files only
mkdir -p /root/evasion-tests &&
for n in 1 2; do
    sed -e "s|^name *=.*|name = 'ubuntu_test$n'|" \
        -e "s|/dev/vg-root/ubuntu_sandbox,|/dev/vg-root/ubuntu_sandbox-test$n,|" \
        /root/drakvuf-multios-sandbox/misc/xen-vms/ubuntu_sandbox.cfg > /root/evasion-tests/ubuntu_test$n.cfg &&
    echo "vncdisplay = $((n - 1))" >> /root/evasion-tests/ubuntu_test$n.cfg
done
grep -H -E '^(name|disk|vcpus|memory|vif|vncdisplay|vnclisten)' /root/evasion-tests/ubuntu_test*.cfg
```

Expect each file's `disk` to name `ubuntu_sandbox-test1` or `-test2`, never
`ubuntu_sandbox,`; if a `disk` line is unchanged, the template's differs from
the `sed` and needs editing by hand.

Then check each file. Per VM:

| Line | Must be |
|---|---|
| `name` | its own: the benchmark locks and destroys domains by name |
| `disk` | `/dev/<VG>/<CLONE_NAME>`, the `CLONE_NAME` of its `site.conf` entry |
| `vcpus`, `memory` | **as in the saved state**, or `xl restore` fails with `Unable to restore HVM context` |
| `vif` | VM2 on another bridge or with another MAC: two guests with one MAC on one bridge collide. The tests do not use the network |
| `vncdisplay`, `vnclisten` | 0 and 1 for the two VMs. The templates listen on `127.0.0.1`; see §7.6 |

`site.conf` names them, each with its snapshot name:

```
LINUX_VM1=${LINUX_VM1-CFG=/root/evasion-tests/ubuntu_test1.cfg CLONE_NAME=ubuntu_sandbox-test1}
LINUX_VM2=${LINUX_VM2-CFG=/root/evasion-tests/ubuntu_test2.cfg CLONE_NAME=ubuntu_sandbox-test2}
```

An entry is a list of `benchmark_drakvuf.sh` variables, so it can carry more:
`VG=` for a volume group other than `vg-root`, or `STATE=` for another save.
**An empty `*_VM2` runs the two configurations one after the other on VM1.**
That takes twice as long and needs half the RAM.

### 3.3 The detector

By default `rdtsc_search.sh` copies `detector.c` to Dom0 whenever it changed and
builds it there with `gcc -o <REMOTE_DETECTOR> detector.c`, with no `-O`. The
benchmark writes it into the guest and runs it every 5 s.

- **Only the red pill decides the verdict.** It is the exit status: 0 not
  detected, 1 detected. The other checks only print.
- **Its process name must end in `/detector`.** The parser finds its
  `exit_group` by that.
- **The binary in the evidence of `rdtsc-poc.md` was built on the lab's Dom0
  with flags that were not recorded.** A build of this source is not
  byte-identical to it. Without `-O`, `rdtsc()` stays a function, so both
  reads come from one RIP in the program's own code: the case the
  compensation handles.
- **If Dom0's glibc is newer than the guest's**, the binary will not start in
  the guest. Build it on a machine with the guest's release, copy it to
  `REMOTE_DETECTOR` and set `BUILD_DETECTOR=0`.

### 3.4 al-khaser

```bash
# THIS MACHINE, in evasion-tests/
xwin --accept-license --arch x86_64 splat --output "$HOME/xwin-sdk"     # once; Microsoft's license
XWIN="$HOME/xwin-sdk" ./build_al_khaser.sh
```

The script clones upstream al-khaser at the commit `al-khaser.patch` was made
against, into `build/al-khaser`. It resets that tree every time, applies the
patch and links `build/al-khaser_x64.exe` with a static CRT. `SRC=<dir>`
builds another tree as it is. `alkhaser_search.sh` uploads the binary to Dom0
whenever it changed.

**What the patch adds to al-khaser:**

- Each check gets a code, category × 1000 + its position (5012 is VBOX's
  12th; categories run from TLS 1 to ANALYSIS_TOOLS 15).
- The exit code is the first detection.
- Each detection also ends a thread with its code, and events named
  `al-khaser <code> <start|detected|blocked> <check>` mark progress, so the
  syscall trace has them all.
- Each check runs on its own thread. One that has not returned within 120 s
  (`--check-timeout`) is reported as **blocked** (100000 + code), and the run
  goes on.
- The human-interaction checks are off by default.

`ALKHASER_ARGS` (default `--sleep 1`) passes arguments to al-khaser. The
timing checks would otherwise sleep 600 s each.

### 3.5 First run

1. Get this directory onto Dom0's checkout, at the same commit (§2).
2. On Dom0, as root, run one benchmark by hand to check the VM, the snapshot
   and DRAKVUF:

   ```bash
   # DOM0, as root, sandboxd stopped. Snapshot, restore, 30 s of DRAKVUF, teardown
   cd /root/drakvuf-multios-sandbox/evasion-tests &&
   GUEST=linux CFG=/root/evasion-tests/ubuntu_test1.cfg CLONE_NAME=ubuntu_sandbox-test1 \
       CONFIGS=dev-syscalls DRAKVUF_TIMEOUT=30 ./benchmark_drakvuf.sh
   ```

   Expect a `dev-syscalls: status=0` line and an output directory with one
   log. DRAKVUF there is whatever `drakvuf/build` holds; the searches rebuild
   it first (§4).

3. Then one short search:

   ```bash
   # THIS MACHINE, in evasion-tests/, in tmux
   TESTS=1 ONLY=baseline ./rdtsc_search.sh
   ```

---

## 4. The Xen and the DRAKVUF that get tested

**Xen.** By default a variant changes only `vmx.c` and `vmcs.h`.

1. The search reads the two files from Dom0's `drakvuf/xen` at its pinned
   commit and applies this checkout's `automation/xen-rdtsc-poc.patch` to them.
   It first checks that the patch is identical to Dom0's copy.
2. It writes the variant's values over the `#define`s.
3. It uploads only those two files, keeping the first original of each in
   `REMOTE_STATE/orig/`.

The rest of Dom0's tree stays as `make xen` left it, so the guest identity's
strings in hvmloader and libacpi survive, and so does QEMU's CD-ROM patch.
After a search, Dom0 runs the last variant built. `make xen` puts the shipped
Xen back.

`LOCAL_XEN=<tree>` is for developing the patch itself. It uploads every file
that tree changed from `XEN_BASE` to `REMOTE_XEN`. **A tree like that lacks
the identity's strings**: run `make xen` again before cold-booting or
installing a guest
([`guest-identity.md` §4](../docs/architecture/guest-identity.md#4-why-a-reinstall)).

**DRAKVUF.** Before the first variant, each search does three things:

1. **Compares** Dom0's `drakvuf` and `drakvuf/libvmi` with this checkout's:
   commit, plus a hash of the uncommitted changes to tracked files. It ignores
   untracked files, the nested submodules' own changes (`make xen` patches
   `drakvuf/xen`), and `volatility3`/`dwarf2json`, which `make sandboxd`
   moves and which build no part of DRAKVUF.
2. **Stops on any difference** and prints both sides. Make them equal
   (commit, push, pull on Dom0, or copy the change), or run with
   `DRAKVUF_SOURCE_CHECK=0`.
3. **Builds** on Dom0 with `make -C drakvuf/libvmi -j$(nproc)` and
   `ninja -C drakvuf/build -j$(nproc)`, and logs to `drakvuf-build.log`.

The benchmarks then run that `drakvuf/build/drakvuf` on the libvmi in
`drakvuf/libvmi/libvmi/.libs`. They do not use the copies `make sandboxd`
installed in `/usr/local`, so `sandboxd`'s DRAKVUF is not touched. The
benchmark checks at start that the binary resolves libvmi there.
`BENCH_EXTRA_ENV="DEV_BIN=... DEV_LIBVMI=..."` points the tests at another
build.

---

## 5. Running

```bash
# THIS MACHINE, in evasion-tests/, in tmux
./rdtsc_search.sh                                   # every variant of variants/rdtsc.txt, 3 tests each
TESTS=10 ONLY="baseline pure" ./rdtsc_search.sh     # only those, 10 tests each
START_AT=pure ./rdtsc_search.sh                     # from that variant on
VARIANTS=my-variants.txt ./alkhaser_search.sh
ALKHASER_ARGS='--check TIMING_ATTACKS --sleep 1' DRAKVUF_TIMEOUT=300 TESTS=6 ./alkhaser_search.sh
```

| Variable | Default | |
|---|---|---|
| `TESTS` | 3 | tests per variant |
| `ONLY`, `START_AT`, `VARIANTS` | all, first, `variants/<search>.txt` | which variants |
| `DRAKVUF_TIMEOUT` | 55 (RDTSC), 1000 (al-khaser) | seconds DRAKVUF traces each run |
| `HIDSIM` | al-khaser 0 | 0 drops `hidsim`, so you can use the VMs over VNC. The RDTSC search always runs it |
| `DISABLE_PLUGINS` | `memdump fileextractor` (al-khaser) | their dumps filled Dom0's disk |
| `MIN_RUNS`, `MIN_SYSCALLS` | 8, 50000 (RDTSC) | below these a guest counts as slowed or hung (§7.4) |

**Per variant:**

1. Boot Dom0 without Xen.
2. Upload, build and install Xen. A hung build is retried.
3. Boot back into Xen.
4. Press `xl debug-keys d` once if `xen-rdtsc-poc.service` has not.
5. Run `TESTS` tests.

A variant whose Xen Dom0 already runs goes straight to step 5.

| Step | Time on the lab's Dom0 |
|---|---|
| Two reboots and the Xen build | about 3 min |
| An RDTSC test | about 2.5 min |
| An al-khaser test (two VMs; `DRAKVUF_TIMEOUT` 1500 then, 1000 now) | 28–29 min (run `20261102-003810`) |

**If you stop a search during a build**, Dom0 stays on its plain kernel.
Comment `XEN_OVERRIDE_GRUB_DEFAULT=0` out again in
`/etc/default/grub.d/xen.cfg`, then `update-grub2` and reboot.

---

## 6. Variants and results

### 6.1 Variant files

```text
# comment
baseline
pure                     RDTSC_USER_PURE=1
close1m_lag21m           RDTSC_USER_CLOSE=1000000ULL RDTSC_USER_LAG_MAX=21000000ULL
```

- **Name, then `KEY=VALUE`s.** A key is any `#define` that appears exactly
  once across `vmx.c` and `vmcs.h`.
- **Values** are decimal or `0x` hex, with an optional `U` or `ULL`.
- **A key left out keeps the patch's value.**
- **A misspelt key stops the search** before anything is built.

The ones that matter (`rdtsc-poc.md` §1 and §4 explain them):

| Define | Shipped | |
|---|---|---|
| `RDTSC_USER_CLOSE` | `1000000ULL` | guest run time, in TSC cycles, within which a program's next read is compressed |
| `RDTSC_USER_LAG_MAX` | `30000000ULL` | most TSC cycles a program's timeline may hide |
| `RDTSC_USER_RIP_MAX` | `0x7f0000000000ULL` | below it, a read is in program code (Linux programs) |
| `RDTSC_USER_EXE_LO`, `_HI` | `0x7ff600000000ULL`, `0x7ff800000000ULL` | the range of 64-bit Windows executables |
| `RDTSC_USER_PURE` | 0 | 1: exit-free pairs return the guest's own work (al-khaser's Locky check) |
| `RDTSC_KERNEL_ADJUST` | 0 | 1 compresses kernel reads too, **which freezes Linux guests** ([TROUBLESHOOTING](../docs/TROUBLESHOOTING.md#the-guest-freezes-or-crawls-with-rdtsc-compensation-on)) |

### 6.2 Results

**On your machine**: `<RESULTS_BASE>/rdtsc-search/<timestamp>/` (or
`alkhaser-search/`).

| File | Has |
|---|---|
| `results.csv` | one row per configuration run: verdict, reason, counts (detector false/true, or al-khaser's detected, blocked and last started check) |
| `tests.csv`, `variants.csv` | per test, per variant |
| `ranking.txt` | the variants ranked (`rdtsc_rank.py`, `alkhaser_rank.py`). al-khaser's names each check and what changed against the first variant |
| `WINNERS.txt` | RDTSC: variants with no detection in `TESTS` consecutive tests, with their diff |
| `codes.tsv` | al-khaser: the name of every check code seen |
| `<variant>/` | `variant.diff`, `build.log`, `xen-info.txt`, each test's job log and small files |

**On Dom0**, the full DRAKVUF logs, gzipped, are under
`<REMOTE_OUT_BASE>/<search>/<timestamp>/`.

**Each RDTSC test log** ends with Xen's `RDTSC_POC` dump: per vCPU the
program timeline (`prog_reads`, `prog_compressed`, `prog_max_hidden`, ...) and
the last red-pill-like pairs, each with its host time, guest run time
(`run=`), exits and the delta returned. **The benchmark also writes the
dump** beside each DRAKVUF log as `<log>.rdtsc-diagnostics`.

**Verdicts, RDTSC** (per configuration run):

| Verdict | Meaning |
|---|---|
| `pass` | no detection, and the detector ran at least `MIN_RUNS` times |
| `fail` | detected |
| `unstable` | the guest slowed or hung: the variant broke its clock |
| `none` | no result (no log, DRAKVUF failed, not injected) |

A variant wins with `TESTS` consecutive passing tests.

**Verdicts, al-khaser**:

| Verdict | Meaning |
|---|---|
| `clean` | finished, nothing detected |
| `detected` | some check detected the sandbox or blocked |
| `unfinished` | al-khaser did not finish in time; `last_started` names where |
| `crashed` | it exited with something that is not a code |
| `none` | no result |

---

## 7. Adapting it to your hardware

The defaults are what worked on the lab's Dom0: an i9-13900KF with 32
threads, Dom0 pinned to 6 vCPUs (`XEN_CMDLINE`), 8 GB per guest with 4 vCPUs,
and two test VMs at once. What changes elsewhere:

### 7.1 TSC rate: the compensation's limits are in cycles

`RDTSC_USER_CLOSE` and `RDTSC_USER_LAG_MAX` count **TSC cycles**. Their
shipped values, 1M and 30M, were measured at about 3 GHz: about 0.33 ms of a
program's own run time and 10 ms of hidden time. What they must cover is
time:

- **What a red pill does between its two reads.** The lab's detector under
  `dev-all` ran up to 133k cycles. A 200k limit missed the first run after a
  restore.
- **How long DRAKVUF pauses a vCPU.** Up to 4.7M cycles; a 3M cap missed.

To find your rate:

```bash
# DOM0, booted on Xen
xl dmesg | grep -i 'MHz processor'     # the TSC rate Xen calibrated at boot
xl info | grep cpu_mhz
```

**At a clearly different rate, scale both limits and test around them.**
`variants/rdtsc.txt` has commented lines for a 2.1 GHz TSC. Then read the
`RDTSC_POC` dumps of the passing runs to see the margin left:

- **`run=`** of the logged pairs against `RDTSC_USER_CLOSE`.
- **`prog_max_hidden`** against `RDTSC_USER_LAG_MAX`.

The red pill's 100 cycles and al-khaser's thresholds belong to those programs
and do not scale.

### 7.2 CPU type

- **A VM exit's cost differs by core type.** On a hybrid CPU a guest floats
  over P- and E-cores, so the cost of a pair's exits varies with where it ran.
  That matters to `RDTSC_USER_PURE` (al-khaser's Locky check compares two
  exit-free calls 40–90 cycles apart), not to the run-time limits.
- **`BUILD_CPUS`** pins the Xen build to some CPUs. The lab's i9-13900KF
  crashed `gcc` and `as` at random under full 32-thread builds, and its
  E-cores (`16-31`) built cleanly
  ([TROUBLESHOOTING](../docs/TROUBLESHOOTING.md#make-xen--internal-compiler-error-segmentation-fault-or-the-assemblers-internal-error)).
  Leave it empty on a stable CPU. A list that does not exist on the boot the
  build runs on is ignored with a warning.

### 7.3 RAM and CPUs for two VMs

**Two test VMs at once need two guests' memory and vCPUs beside Dom0's**, plus
DRAKVUF's own threads. Without that room, leave `LINUX_VM2`/`WINDOWS_VM2`
empty: the same tests take twice as long. **A test VM's `vcpus` and `memory`
must match the saved state.** They are not a knob: changing them means saving
the guest again.

### 7.4 Guest speed: when to call a guest slowed

- **The RDTSC search judges stability by counting detector runs.** The
  workload starts the detector 5 s into the run and every 5 s after the
  previous one ends. A healthy 55 s run on the lab's Dom0 has 10, and a guest
  whose clock a variant broke ran it 1–3 times. On slower hardware, run
  `baseline` once and look at `detector_false` in `results.csv`. Set
  `MIN_RUNS` to about 80% of what a healthy run reaches. Below `MIN_SYSCALLS`
  syscall records, the guest counts as hung.
- **al-khaser** finished in 423–433 s under `dev-syscalls` and 583–676 s under
  `dev-all` on the lab's Dom0 (3 checks blocked for 120 s each). A run that
  ends `unfinished` with "ran out of time" needs a larger `DRAKVUF_TIMEOUT`.
  `BENCH_LIMIT` and `BENCH_STALL` follow it.
- **Builds and boots**: `BUILD_LIMIT`/`BUILD_STALL` (a Xen build took 2–3 min)
  and `BOOT_LIMIT` (30 min). Raise `BOOT_LIMIT` for a server whose POST is
  slow.

### 7.5 Storage

- **Volume group.** The guests' LVs, and the thin snapshots the benchmark
  makes from them, are in `vg-root`, as the Makefile creates them. Elsewhere,
  add `VG=<name>` to each VM entry.
- **Output.** `REMOTE_OUT_BASE` takes every DRAKVUF log. An al-khaser test
  writes tens of GB, even with `memdump` and `fileextractor` disabled, and
  this lab's root filesystem filled once. Give it a disk of its own; the lab
  uses a thin LV mounted at `/srv/drakvuf-out`. Logs are gzipped after each
  test.

### 7.6 Network and VNC

- **`VNC=1`** opens a viewer per VM on your machine (`rdtsc_vnc.sh`,
  TigerVNC). The ports come from the cfgs' `vncdisplay`: 5900 and 5901, or
  set `VNC_PORTS`.
- **The templates' `vnclisten = '127.0.0.1'`** keeps VNC off the network.
  Either forward the ports and set `VNC_HOST=127.0.0.1`:

  ```bash
  # THIS MACHINE, left running while the search runs
  ssh -N -L 5900:127.0.0.1:5900 -L 5901:127.0.0.1:5901 root@<dom0>
  ```

  or set `vnclisten` in the test cfgs on a network you trust: VNC there has
  no password.
- **Viewers are view-only while `hidsim` runs**, because your input would mix
  with its own.

### 7.7 Booting without Xen

The search needs Dom0 to boot both ways on its own. Try the switch once, on
Dom0:

```bash
# DOM0, as root, nothing running in the guests. Reboots into the plain kernel
sed -i 's/^#XEN_OVERRIDE_GRUB_DEFAULT=0/XEN_OVERRIDE_GRUB_DEFAULT=0/' /etc/default/grub.d/xen.cfg &&
grep -q '^XEN_OVERRIDE_GRUB_DEFAULT=0' /etc/default/grub.d/xen.cfg && update-grub2 && reboot
```

Expect Dom0 back without Xen: `grep control_d /proc/xen/capabilities` finds
nothing. Then back:

```bash
# DOM0, as root. Reboots into Xen
sed -i 's/^XEN_OVERRIDE_GRUB_DEFAULT=0/#XEN_OVERRIDE_GRUB_DEFAULT=0/' /etc/default/grub.d/xen.cfg &&
grep -q '^#XEN_OVERRIDE_GRUB_DEFAULT=0' /etc/default/grub.d/xen.cfg && update-grub2 && reboot
```

Without Xen, GRUB boots entry 0 of `/etc/default/grub`, which must be a working
plain kernel. If it comes back on Xen anyway, see
[TROUBLESHOOTING](../docs/TROUBLESHOOTING.md#uncommenting-xen_override_grub_default0-still-boots-xen).
If no `RDTSC_POC` appears in `xl dmesg` after a boot, see
[TROUBLESHOOTING](../docs/TROUBLESHOOTING.md#xen-rdtsc-pocservice--dependency-failed-and-no-rdtsc_poc-in-xl-dmesg).