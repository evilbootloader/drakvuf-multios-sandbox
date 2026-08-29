# The `automation/` pipeline, file by file

**Moved out of `CLAUDE.md` on 2026-08-27.** It was 300 of that file's 534
lines — a file-by-file description of code, which Anthropic's own guidance
lists as the first thing to keep *out* of a CLAUDE.md, because a long one
causes the rules that matter to be ignored.

Nothing here was deleted or rewritten in the move. The rules that changed
behaviour stayed behind in `CLAUDE.md`; this is the reference material, kept
because much of it records *why* a thing is the way it is, which reading the
code does not tell you.

For what the lab currently is — versions, capacities, VM ids, what is
evidenced — see `docs/CURRENT-STATE.md`. This file describes the shape of the
code, not the state of the deployment.

---

## Current implementation

Existing Ubuntu automation lives under `automation/` (flat directory, no
subfolders):

- `dirwatch.c` — the orchestrator daemon, a modified version of the
  `dirwatch.c` shipped in the upstream DRAKVUF repository. A `GThreadPool` +
  `inotify` watcher on the incoming-sample folder, launched via a fixed
  15-argument CLI contract that hard-codes a single origin domain per
  invocation. Since issue #3 (2026-08-09) that constraint **is** the
  OS-selection mechanism rather than a gap: the target OS is chosen by the
  submitter, via one incoming directory and one `dirwatch` instance per OS.
  File magic is recorded for identification and mismatch-rejection only —
  it does not route. Since DRAFT-030 (2026-08-15) it spawns every callback
  as an **argv vector**, not a formatted command string, and admits or
  rejects the sample filename before claiming a worker slot; rejected
  samples go to `<out_folder>/rejected/`.
  **`dirwatch.c` is scheduled for retirement (DRAFT-041, 2026-08-21).** It
  is replaced by `sandboxd`, a Python orchestrator that takes work from a
  Postgres queue on a separate platform VM rather than from an `inotify`
  watch, and the five worker scripts below keep their callback contract
  unchanged across the change. Until that lands this file is what runs, and
  it keeps a live constraint: per-OS watchers cannot run concurrently,
  because the thread-slot index *is* the VLAN and the slot array is
  process-local, so two instances collide on VLANs, gateway addresses and
  isolation rules with no symptom but interference. Both launchers refuse to
  start if another is running. See `docs/architecture/platform.md` for the
  replacement and `docs/architecture/analysis-pipeline.md` for the pipeline
  it keeps.
  For each sample it calls back into the worker scripts below, in
  order: `clone.pl` → `preconfig-ubuntu.sh` → `drakvuf-ubuntu.sh` →
  `cleanup.sh`, with `tcpdump.sh` started on a side thread. The preconfig
  phase is guarded by a 60s timeout and the drakvuf-trace phase by a 180s
  timeout; either timeout triggers `cleanup.sh` and a fresh clone retry.
- `platform.env` — sourced config holding the **host-global** values:
  `ANALYSIS_BRIDGE`, `UPLINK_BRIDGE`, `SUBNET_PREFIX`, `VG_NAME`. One Dom0
  has one of each, so these are deliberately *not* per-OS: three pipeline
  files free to disagree about the bridge is not a loud misconfiguration,
  it is a clone attached to a bridge with no isolation rules. Added by
  DRAFT-028b (2026-08-15); sourced by `network-setup.sh` and
  `run_analysis-<os>.sh`. C4 forbids `pipeline-<os>.env` from redefining
  any of these, and the check is a grep — see the file's own header.
  Wiring `cleanup.sh` and `tcpdump.sh` to it is still open (DRAFT-011),
  and the `misc/*.cfg` bridge literals stay literal because a Xen config
  cannot source shell.
- `pipeline-ubuntu.env` — sourced config holding every **per-OS** value the
  scripts below need (sandbox domain, `.cfg`, profile, saved state,
  injection PID, clone count, malware directories, guest user and staging
  dir, resolver). Added in issue #4. Each entry is
  `${NAME:-default}`, so the environment wins — that is how CI overrides
  paths without patching files. A second OS pipeline is a copy of this one
  file plus its own `run_analysis-<os>.sh`. `ANALYSIS_BRIDGE` used to live
  here and moved to `platform.env` in DRAFT-028b; do not restore it.
- `clone.pl` — **shared by all three OS pipelines**, not per-OS. LVM
  copy-on-write snapshot + `xl restore` of the sandbox template's saved
  memory image, producing a disposable clone. The restore path is derived
  via `FindBin` as `<repo root>/state/<origin>.bak`, so the disk snapshot
  and the memory image cannot name different domains. It does **not** read
  `pipeline-<os>.env` — it is Perl, invoked by `dirwatch` with a fixed
  3-argument contract — but it does read `VG_NAME` and `ANALYSIS_BRIDGE`
  from the environment, which `run_analysis-<os>.sh` exports. It read
  `CLONE_LV_SIZE` too until thin snapshots retired it on 2026-08-29.

  *Named `clone-ubuntu.pl` until DRAFT-015 (2026-08-15). It was renamed
  rather than copied to `clone-android.pl` because it holds no OS-specific
  value: everything that varies arrives on the 3-argument contract, is
  derived from it, or comes from the environment. This amends C1/C2 in
  `docs/architecture/analysis-pipeline.md` to "four per-OS files plus the
  shared clone script". Do not add an OS branch to this file — add a
  variable.*
- `preconfig-ubuntu.sh` — stages the sample into the guest via
  `injector -m writefile` (`-B` Dom0 source, `-e` guest destination), then
  configures the clone's network. Two separate injections; delivery
  deliberately runs first and does not need guest networking. No `chmod`
  step: `writefile` leaves the file executable, evidenced on Dom0
  2026-08-09.
- `drakvuf-ubuntu.sh` — runs the DRAKVUF trace (`syscalls`, `filetracer`, `fileextractor`,
  `memdump` 120s timeout, `--memdump-dir`) and kills the per-VLAN `tcpdump`
  process afterward. Executes the staged sample at
  `$GUEST_STAGING_DIR/<submitted filename>`, built by the same rule
  `preconfig-ubuntu.sh` stages to. The leaf was the sample's SHA-256 until
  DRAFT-030 (2026-08-15); it is now the name the sample was submitted
  with, per C5, because extension dispatch and `argv[0]` self-checks are
  real evasion surface that a hash-named file exercises none of.
- `cleanup.sh` — pauses/destroys the clone domain and kills any lingering
  `injector`/`drakvuf` processes for it.
- `tcpdump.sh` — captures traffic on the clone's VLAN sub-interface to a
  per-sample pcap.
- `network-setup.sh` — provisions the per-VLAN isolated networks
  (`172.16.<vlan>.1/24` gateway per VLAN) that `clone.pl` and
  `preconfig-ubuntu.sh` assume already exist. It does **not** create
  `xenbr1`, despite the name: it calls only `modprobe`/`ip`/`iptables`, and
  the OVS bridge comes from a separate one-time install step
  (`ovs-vsctl add-br xenbr1`). Since DRAFT-028 it checks for the bridge and
  fails with a message naming that step. Also since DRAFT-028: `set -eu`
  and an EXIT trap, so a rejected rule aborts instead of half-provisioning
  a network that looks like it works; three dedicated chains
  (`DRAKVUF_NAT`, `DRAKVUF_ISOLATION`, `DRAKVUF_INPUT`) flushed and rebuilt
  each run, so repeated launches converge instead of appending; and
  clone egress narrowed to the Internet only — RFC1918, link-local and
  Dom0 itself are all dropped. `run_analysis-ubuntu.sh` aborts if it fails.
  See `docs/architecture/networking.md` for the full posture.
- `run_analysis-ubuntu.sh` — top-level entry point; sources
  `pipeline-ubuntu.env`, pre-flight checks the `.cfg`/profile/saved state,
  creates the per-OS malware directories, brings `xenbr1` up, runs
  `network-setup.sh`, then launches `dirwatch` with the arguments above.

**Scripts in `automation/` execute under `dash`, not `bash`.** Five of the
six now declare `#!/bin/sh` on line 1, with the DRAKVUF license header
immediately below it (DRAFT-031, 2026-08-11). Write POSIX for these files.

*Until DRAFT-031 the shebang was `#!/bin/bash` on line **104**, below the
licence header, where the kernel never saw it: `execv` failed `ENOEXEC` and
GLib's `g_spawn_*` (how `dirwatch` invokes them) fell back to `/bin/sh`.
The interpreter is unchanged — `/bin/sh` is `dash` — which is exactly why
`#!/bin/sh` was chosen over `#!/bin/bash` when the line moved. Declaring
bash would have switched five root-run analysis scripts to a different
interpreter under cover of a lint fix.*

A bash-only construct does not fail loudly — `${BASH_SOURCE[0]}` evaluates
to empty under dash and the script carries on, which in issue #4 silently
turned `SCRIPT_DIR` into `$PWD`. Use `$0`. `run_analysis-ubuntu.sh` is the
exception and genuinely runs under bash: it is this project's own launcher,
invoked directly by an operator rather than by `dirwatch`, and it keeps
`#!/bin/bash`. It uses `$0` too, so the idiom stays uniform. Check with
`dash -n SCRIPT` as well as `bash -n SCRIPT`.

`shellcheck automation/*.sh` exits 0 as of DRAFT-031, against the baseline
in `.shellcheckrc` — which disables four codes repository-wide, each named
with the issue that owns removing it. Read that file before assuming a
clean run means clean code.

The Xen guest `.cfg` files these scripts reference are tracked under
`misc/`, not `automation/`: `misc/ubuntu.cfg` (golden `ubuntu`),
`misc/ubuntu_sandbox.cfg` (`ubuntu_sandbox`), `misc/android.cfg` (golden
`android`), `misc/android_sandbox.cfg` (`android_sandbox`). These were
renamed from `linux.cfg`/`linux_sandbox.cfg` in issue #1 — those names were
historical and misleading, since the files define Ubuntu domains, not a
generic "linux" one. The Dom0 host's copies were renamed to match on
2026-08-08, so repo and host now agree. An earlier pass this session initially reported
these files as missing entirely; that was wrong — `misc/` had simply not
been checked. Always check for a `misc/` directory before concluding a
referenced file doesn't exist anywhere in this repo.

Android's own files, as of 2026-08-17:

- `pipeline-android.env` and `run_analysis-android.sh` — **exist**
  (DRAFT-015). `GUEST_STAGING_DIR=/data/local/tmp`, `INJECTION_PID=1`
  (`CLONE_LV_SIZE=32G` and `INJECTION_PID=3174` until 2026-08-29).
- `preconfig-android.sh` and `drakvuf-android.sh` — **exist**
  (DRAFT-016, reworked 2026-08-17). `preconfig-android.sh` runs up to
  three injections: `writefile` delivery, one Bliss-Bass EthernetConfig
  call for the network (measured by DRAFT-013,
  `docs/checklists/android.md` §1.6, not Ubuntu's `ip` chain), and — for
  an APK only — `pm install`. `drakvuf-android.sh` then has **two
  execution paths**, selected from the sample's own bytes: an APK
  (ZIP containing `AndroidManifest.xml`) is **launched**, already
  installed, via `cmd package resolve-activity` + `am start -n`; a native
  ELF is `execve`d directly, the Ubuntu shape; anything else is
  `unsupported_type` and is not executed. The selector is a structural
  test, deliberately **not** the state model's advisory `detected_type`,
  and it is repeated in both scripts rather than carried between them —
  they are separate `dirwatch` callbacks with no channel, and a marker
  file is state a sample could read.
- `clone-android.pl` — **will never exist.** The clone step is the shared
  `clone.pl`; see its entry above and C1/C2.

**Why the install is not traced, and why the launch is not `monkey`**
(both settled on Dom0 2026-08-17, `docs/runbooks/07-verify-android-mvp.md`
F2/F3): `pm install` takes 3s untraced and does not finish in 120s under
the trace, and `-t` cannot be raised past `dirwatch`'s 180s timer. Nothing
is lost by installing untraced — an Android application cannot run its own
code during installation. `monkey` was rejected because
`ActivityManager.isUserAMonkey()` reports it to the sample, and because it
reaches `app_process64`, which aborts with exit 134 without the
`/data/system/environ/classpath` import that `am` (a wrapper around the
native `cmd`) does not need.

**Android traces with `-F` and `--disable-sysret`; Ubuntu does not.** This
is a property of the guest, not a preference. DRAKVUF's cost scales with
syscalls *executed*, and Android's baseline rate is structurally far
higher than a Linux desktop's — every binder IPC is an `ioctl()` and every
system service runs a Looper on `epoll_pwait`/`ppoll`, so an idle BlissOS
clone generates thousands of events before anything is analysed. Without
these two options an APK installed and launched correctly and still could
not finish drawing inside the trace window. **`--disable-sysret` costs
syscall return values**: an Android trace shows that a sample called
`openat`/`connect`/`execve` and with what arguments, but not whether it
succeeded or what fd came back. Attempted behaviour is visible, outcomes
are not — set `DISABLE_SYSRET=0` in `pipeline-android.env` when an
analysis needs to tell a successful open from a refused one. Ubuntu is
deliberately left alone: it is evidenced working and does not have the
problem these solve.

**Untrusted filenames must never be spliced into a guest shell string.**
`dirwatch`'s `sample_name_admissible()` rejects only `/` and control
characters, so `"`, `$`, a backtick and `;` are all admissible in a
submitted name — and all are live inside a double-quoted guest shell word.
The `pm install` injection therefore uses the `sh -c '…' sh "$UNSAFE"`
idiom — `-e /system/bin/sh -f -c -f "$INSTALL_CMD" -f sh -f "$GUEST_SAMPLE"`
— so the path arrives as a separate `execve` element and the script refers
to it as `"$1"`, a variable reference nothing re-parses. Sample-derived text
may be held in guest shell *variables* and used quoted, which is what the
launch does with the package name; what it may not do is reach the guest as
text Dom0 pasted into a command.

**Android is execution-evidenced end to end as of 2026-08-17**
(`docs/runbooks/07-verify-android-mvp.md`): `injector` `writefile`/`readfile`
round-trips 12 MB byte-exact, the network injection configures the clone,
a native ELF traces through the execve path, and an APK installs and
launches. What is **not** yet evidenced is the reworked APK path above —
install-in-preconfig and `am start` are implemented but have not run on
Dom0, and no Android step has been re-run since the 2026-08-17 template
re-save (`465aa4d7…`). Treat the APK path as untested code.

**Neither launcher may run while the other does** — `dirwatch` derives each
clone's VLAN from a process-local worker-slot index, so two watchers
allocate the same VLANs and share gateway addresses and isolation rules
with no symptom but interference. Both launchers now refuse to start if
another is running. DRAFT-036 was going to lift the constraint with a
host-global VLAN allocator; DRAFT-041 removed the need for one instead —
a single `sandboxd` owning every clone allocates VLANs from an in-process
table, and the launchers go with `dirwatch`. Until then the guard is the
whole mechanism, so a **Windows watcher must not share Dom0 with a running
Ubuntu or Android watcher** either.

**`automation/` now mirrors the working Dom0 host** as of 2026-08-08: the
tested production scripts were copied in wholesale, resolving the repo↔host
drift that issue #2's verification uncovered. `drakvuf-ubuntu.sh` picked up
`CMD="/home/carlos/Desktop/test"` and `--memdump-dir` (the correct spelling,
confirmed from `drakvuf --help`); `network-setup.sh` picked up
`ip link set xenbr1 up` in place of the deprecated `ifconfig`;
`dirwatch_old.c` was replaced by the host's newer variant (the previous
520-line copy remains in git history at commit `2514168`). `dirwatch.c`,
`preconfig-ubuntu.sh`, `cleanup.sh`, `clone-ubuntu.pl` and `tcpdump.sh` were
already byte-identical to the host and were not touched. Issue #1's rename
was also completed on the host side (`linux_sandbox.cfg` →
`ubuntu_sandbox.cfg`), so `run_analysis-ubuntu.sh` now agrees on both sides
and repo and host no longer diverge anywhere. The earlier
`<USER>` placeholder was a repo-only defect and was never a production bug —
Ubuntu analysis runs do execute their samples, which is now
execution-evidenced (`docs/runbooks/01-verify-user-placeholder.md`).

**Parity is now maintained by a checkout, not by copying (2026-08-09,
issue #4).** Dom0 runs a clone of this repository, pulled over a read-only
deploy key, so the question issue #2 needed a whole runbook to answer is
now one command:

    git -C <dom0 checkout> log -1        # what is deployed
    git -C <dom0 checkout> status --porcelain   # local drift, expect empty

**The checkout is at `/root/drakvuf-multios-sandbox`** — observed on Dom0
2026-08-19. This document said `/root/sandbox_project` until then, and
every runbook under `docs/runbooks/` still does. Those are dated evidence
and are **not** edited; read the path in them as "the Dom0 checkout",
whatever it was called on that date.

Nothing depends on the name. Issue #4's whole point was that every
repository-owned asset resolves from the invoked script's own location, so
the checkout can live anywhere and a wrong path in a document is a
documentation defect rather than a broken deployment. It is recorded here
because a command pasted from these docs will fail, not because the lab
would.

The old `/home/user/drakvuf-tools` checkout is renamed to
`…​.retired-issue4` and kept as the rollback path. Do not edit deployed
scripts in place — that is how the drift issue #2 diagnosed happened.
Change them here, push, and pull on Dom0, never while an analysis is in
flight (`dirwatch` re-reads the worker scripts per sample).

Known issues in the current Ubuntu scripts (do not silently fix — flag and
confirm before changing):

- ~~`run_analysis-ubuntu.sh` hard-codes deployment paths under
  `/home/user/drakvuf-tools/...`~~ — fixed in issue #4 (2026-08-09).
- ~~Both `drakvuf-ubuntu.sh` and `preconfig-ubuntu.sh` hard-code the guest
  username `carlos`~~ — moved to `GUEST_USER` in `pipeline-ubuntu.env` in
  issue #4. Still a fixed value rather than one discovered from the guest;
  that remains open M1 work.
- ~~`clone.pl` still hard-codes `vg-root` and `xenbr1`, and
  `network-setup.sh` the `172.16.<vlan>.0/24` scheme. Neither reads
  `pipeline-ubuntu.env`.~~ — **closed 2026-08-15** across DRAFT-015,
  DRAFT-028b and DRAFT-033. `clone.pl` still reads no config *file* — it is
  Perl on a fixed 3-argument contract — but takes `VG_NAME` and
  `ANALYSIS_BRIDGE` from the environment, which `run_analysis-<os>.sh`
  exports from `platform.env`. `CLONE_LV_SIZE` was the third until thin
  snapshots retired it on 2026-08-29. `network-setup.sh` takes the subnet from
  `SUBNET_PREFIX`. The defaults still reproduce the old literals exactly,
  so an unset variable is not a behaviour change.
- Guest DNS pointed at the clone's gateway, where nothing listens, so name
  resolution failed on every run before 2026-08-09. Now `GUEST_NAMESERVER`
  (default `1.1.1.1`). ~~Android's golden image has the same dead assumption
  baked in as an in-guest DNAT to `172.16.10.1:53`~~ — **fixed 2026-08-11
  (issue #7)**: the Android golden VM was reinstalled and the template
  rebuilt from it, and the DNAT was deliberately not re-applied. No resolver
  is baked into the image at all; per-clone configuration belongs to
  `preconfig-android.sh` at analysis time, as it does for Ubuntu.
  See `docs/architecture/networking.md`.

Do not modify the Ubuntu behavior unless required and explicitly requested.

