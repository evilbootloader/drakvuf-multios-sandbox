# The shell/C launcher pipeline, and what replaced it

**This pipeline no longer exists.** Thirteen files — 4,795 lines of C, Perl,
POSIX shell and sourced environment config — were deleted from `automation/` on
2026-09-15, once `sandboxd` had replaced every one of them. This document is the
record of what they were, what took over each responsibility, and the facts
worth keeping that lived only in their comments.

It is deliberately not deleted. Runbooks 01–15, the issue drafts and the reviews
cite these filenames as dated evidence and are never rewritten, so a reader who
meets `clone.pl` or `dirwatch.c` in a 2026-08 runbook needs somewhere to find
out what happened to it. `scripts/check-refs.py` carries the same thirteen paths
in its `ALLOW_PATHS` set for the same reason.

For what the lab currently is — versions, capacities, what is evidenced — see
`docs/CURRENT-STATE.md`. For the orchestrator that replaced all of this, see
`docs/architecture/platform.md` and the `sandboxd/` module docstrings, which are
where the reasoning now lives.

---

## What replaced what

| Deleted file | Lines | Replaced by | Notes |
|---|---|---|---|
| `dirwatch.c` | 1055 | `sandboxd/daemon.py`, `sandboxd/stages.py` | the watch loop and single-instance guard; the five-callback phase sequence |
| `dirwatch_old.c` | 670 | — | an older copy of the same watcher, kept for comparison and never run |
| `clone.pl` | 615 | `sandboxd/clone.py` | LVM snapshot + `xl restore`, and the config rewrite |
| `cleanup.sh` | 155 | `sandboxd/proc.py`, `sandboxd/sweep.py` | process-group teardown; stray reaping after a dead daemon |
| `tcpdump.sh` | 131 | `sandboxd/guests.py::argv_tcpdump` | spawned by `stages.py` for the trace's lifetime |
| `run_analysis-ubuntu.sh` | 193 | `sandboxd/daemon.py` | entry point, pre-flight, `network-setup.sh` call |
| `run_analysis-android.sh` | 183 | `sandboxd/daemon.py` | same, per-OS differences now a `TargetOs` value |
| `drakvuf-ubuntu.sh` | 195 | `sandboxd/guests.py` | trace argv, plugin list, `-D`/`--memdump-dir` |
| `drakvuf-android.sh` | 357 | `sandboxd/guests.py` | plus the APK-vs-ELF execution split |
| `preconfig-ubuntu.sh` | 229 | `sandboxd/guests.py` | `writefile` delivery, then network configuration |
| `preconfig-android.sh` | 454 | `sandboxd/guests.py` | plus `pm install` and the launcher-component poll |
| `pipeline-ubuntu.env` | 237 | `sandboxd/config.py`, `sandboxd/timing.py` | per-OS paths, PIDs and waits |
| `pipeline-android.env` | 321 | `sandboxd/config.py`, `sandboxd/timing.py` | same |

Three files in `automation/` were **not** deleted and are live:

- **`network-setup.sh`** — `sandboxd/daemon.py::provision_analysis_network`
  executes it at every daemon start, and is now its only caller anywhere. It
  provisions the `xenbr1.<n>` sub-interfaces, the `172.16.<n>.1` gateways and
  the `DRAKVUF_*` chains. Nothing else creates them, so skipping it produces a
  clone with an address nothing routes — which reads as a sample that chose not
  to talk.
- **`platform.env`** — sourced by `network-setup.sh`, and read and rewritten by
  `scripts/gen-xen-configs.py` from `sandboxd/config.py`. Its header describes
  the current contract.
- The egress assets — `torrc`, `fakenet.ini`, `fakenet.service`,
  `fakenet-requirements.txt`, `fakenet-divert-no.patch`,
  `drakvuf-egress.target`. `sandboxd/egress.py` names the first two as operator
  config hints, and `make sandboxd` installs all six.

Added since, 2026-10-21, and not part of the old pipeline: the Xen install
assets **`xen-altp2m-pause-vcpu.patch`**, the 4.20.1 backport of the altp2m
deadlock fix, and **`xen-grub.cfg`**, the GRUB settings that boot it. `make xen`
applies and installs both.

---

## Facts carried out of the deleted files

These are the things the files knew that the code replacing them would have had
to rediscover. Each is now recorded where the current implementation can be read
beside it; this section says which fact went where.

### The 10-second post-destroy settle

`xl destroy` returns **before** the block device is released. Measured on Dom0
2026-08-14: an `lvremove` issued immediately after a destroy reported `Logical
volume in use`, and succeeded on a retry. This is why clone teardown is not
simply destroy-then-remove.

Now at `sandboxd/clone.py`, `DESTROY_SETTLE_SECONDS`, with the measurement in
the comment, and in the inventory at the top of `sandboxd/timing.py`. The
primary dated record is `docs/runbooks/06-verify-android-isolation.md:965`,
annotated at `:996`.

### The `ps aux | grep` wildcard defect

The cleanup script was a **sibling** process, spawned with only `(domid, vlan)`,
so `ps aux | grep` was its only way to find grandchildren it had no handle on.
The pattern it used to find its own capture was:

    ps aux | grep "tcpdump -i xenbr1.$VLAN"

Unanchored, and `.` is a regex metacharacter — so sweeping VLAN 1 also matched
`xenbr1.10` through `xenbr1.19` once there were more than nine clones. One job's
cleanup killing another job's capture, with nothing reporting it. It was carried
as a KNOWN GAP (DRAFT-011) for as long as those scripts existed and was never
fixed; the files were deleted instead.

**This is the entire reason `sandboxd/proc.py::iter_processes` exists.** It
reads `/proc/<pid>/cmdline` and compares argv *elements* for equality — no
pattern, no metacharacter, no substring — and `sandboxd/sweep.py::_kill_strays`
records the same. `.github/workflows/static-checks.yml` now gates on the idiom
rather than merely inventorying it.

### The md5-keyed output directory

`tcpdump.sh` computed `md5sum` of the sample and wrote to
`$OUTPUTFOLDER/$MD5/tcpdump.pcap`; the other scripts used the same layout.
`sandboxd` writes to a **per-job** result directory instead
(`sandboxd/stages.py`, `CAPTURE = "capture.pcap"`).

Per-job rather than md5-keyed, because two submissions of identical bytes are
deliberately separate runs (DRAFT-030) — the same sample submitted twice, or by
two tenants, is two analyses with two sets of evidence, and collapsing them into
one directory is the evidence-mixing DRAFT-036 flagged. A reader meeting the old
`<md5>/` layout in a runbook is looking at the superseded scheme.

The same script's bare `md5sum` also returned an **empty** digest for a filename
containing a space, sending every such pcap to one shared path. DRAFT-030 fixed
the quoting on 2026-08-15.

### The compiled-in phase timers

The C watcher guarded the preconfig phase at 60s and the trace phase at 180s.
Both were **compiled in**, which is why the Android trace was pinned at `-t 150`
and could not be raised. Under `sandboxd` they are configuration
(`sandboxd/timing.py::budgets`), derived from what each phase contains rather
than tabulated, so a guest that legitimately needs longer can have it without
rebuilding the orchestrator.

### The filename admission rule

`sample_name_admissible()` began in the C watcher's inotify admission check
(DRAFT-030, 2026-08-15) and rejects only `/` and control characters — so `"`,
`$`, a backtick and `;` are all admissible in a submitted name, deliberately,
because byte-exact delivery of the name is part of what is being analysed.

It now has **three live copies**, and they must not disagree:

- `platform/sandbox_platform/routers/jobs.py::_reject_unsafe_filename` — the
  submission boundary, and the only one that runs before the bytes are stored
- `sandboxd/naming.py::sample_name_admissible` — before a root-owned `open()`
  on Dom0
- `platform/sandbox_platform/manifest.py::reject_unsafe_name` — every object key

What stops an admissible-but-hostile name doing harm is not this rule but the
`sh -c '…' sh "$UNSAFE"` idiom, which delivers the value as a separate `execve`
element. See the next section.

### Untrusted filenames must never be spliced into a guest shell string

Still true, still live, and still the rule `CLAUDE.md` dedicates a section to.
The Android `pm install` injection was the worked example:

    -e /system/bin/sh -f -c -f "$INSTALL_CMD" -f sh -f "$GUEST_SAMPLE"

so the path arrives as a separate `execve` element and the script refers to it
as `"$1"`, a variable reference nothing re-parses. Sample-derived text may be
held in guest shell *variables* and used quoted; what it may not do is reach the
guest as text Dom0 pasted into a command. `sandboxd/guests.py` builds argv
vectors throughout and `sandboxd/proc.py` passes `shell=False` explicitly.

### Android traces with `-F` and `--disable-sysret`; Ubuntu did not

A property of the guest, not a preference. DRAKVUF's cost scales with syscalls
*executed*, and Android's baseline rate is structurally far higher than a Linux
desktop's — every binder IPC is an `ioctl()` and every system service runs a
Looper on `epoll_pwait`/`ppoll`, so an idle BlissOS clone generates thousands of
events before anything is analysed. Without these two options an APK installed
and launched correctly and still could not finish drawing inside the trace
window.

**`--disable-sysret` costs syscall return values**: an Android trace shows that
a sample called `openat`/`connect`/`execve` and with what arguments, but not
whether it succeeded or what fd came back. Attempted behaviour is visible,
outcomes are not.

Now in `sandboxd/guests.py::default_trace_options`, where Ubuntu also adopted
`--disable-sysret` on a measured 2.06x — read that module for the current
per-guest matrix rather than this paragraph.

### Why the APK install is not traced, and why the launch is not `monkey`

Both settled on Dom0 2026-08-17,
`docs/runbooks/07-verify-android-mvp.md` F2/F3:

- `pm install` takes 3s untraced and does not finish in 120s under the trace,
  and `-t` could not be raised past the watcher's 180s timer. Nothing is lost by
  installing untraced — an Android application cannot run its own code during
  installation.
- `monkey` was rejected because `ActivityManager.isUserAMonkey()` reports it to
  the sample, and because it reaches `app_process64`, which aborts with exit 134
  without the `/data/system/environ/classpath` import that `am` (a wrapper
  around the native `cmd`) does not need.

### The shebang, and why `automation/` is POSIX

Until DRAFT-031 (2026-08-11) the shebang in the worker scripts was
`#!/bin/bash` on line **104**, below the DRAKVUF licence header, where the
kernel never saw it: `execv` failed `ENOEXEC` and GLib's `g_spawn_*` — how the
watcher invoked them — fell back to `/bin/sh`. Five root-run analysis scripts
were being interpreted by `dash` while declaring bash.

The interpreter was left unchanged when the line moved, which is exactly why
`#!/bin/sh` was chosen over `#!/bin/bash`: declaring bash would have switched
five root-run scripts to a different interpreter under cover of a lint fix.

**This still governs `network-setup.sh`**, which declares `#!/bin/sh` and is
interpreted by `dash` on Dom0. A bash-only construct does not fail loudly —
`${BASH_SOURCE[0]}` evaluates to empty under dash and the script carries on,
which in issue #4 silently turned `SCRIPT_DIR` into `$PWD`. Use `$0`, and check
with `dash -n` as well as `bash -n`.

### The shellcheck baseline

`shellcheck automation/*.sh` exits 0, and now covers one file. `.shellcheckrc`
disables **one** code, SC1091, for a runtime-resolved `source` path that is
correct behaviour rather than a defect.

SC2086 and SC2009 were retired on 2026-09-15 **by deletion, not by a fix** —
every site lived in `cleanup.sh` and the per-OS trace scripts. Both checks are
live again for every file, which is a real gain: a new script reintroducing an
unquoted expansion or a `ps aux | grep` is now caught. `.shellcheckrc` records
this.

---

## What the pipeline was

Kept brief, because the code is gone and the runbooks are the evidence.

`dirwatch.c` was a modified copy of the `dirwatch.c` shipped in the upstream
DRAKVUF repository: a `GThreadPool` plus an `inotify` watch on an incoming-sample
folder, launched on a fixed 15-argument CLI contract hard-coding **one origin
domain per invocation**. From issue #3 (2026-08-09) that constraint *was* the
OS-selection mechanism — one incoming directory and one watcher per OS, with the
submitter choosing. File magic was recorded for identification and
mismatch-rejection only; it did not route.

For each sample it called back into the worker scripts in order:

    clone.pl → preconfig-<os>.sh → drakvuf-<os>.sh → cleanup.sh

with `tcpdump.sh` started on a side thread.

`run_analysis-<os>.sh` was the operator-facing entry point: it sourced
`pipeline-<os>.env` and `platform.env`, pre-flight checked the `.cfg`, profile
and saved state, created the malware directories, brought `xenbr1` up, ran
`network-setup.sh`, and launched `dirwatch`.

### The constraint that motivated the replacement

**The two launchers could never run concurrently.** `dirwatch` derived each
clone's VLAN from a process-local worker-slot index (`slots_busy[128]` and
`find_thread()`), so two watchers allocated VLANs 1..N identically and shared
gateway addresses and isolation rules — with no symptom but interference between
two malware analyses. Both launchers refused to start when another was running.

That is why an Ubuntu and a Windows submission could not be analysed in the same
window on a host with capacity for both. DRAFT-036 was going to lift it with a
host-global VLAN allocator; DRAFT-041 removed the need for one instead, because
a single `sandboxd` owning every clone allocates VLANs from one in-process table
and there is no second allocator to coordinate with. See
`sandboxd/resources.py`.

**The guard outlives the source.** `dirwatch` was a compiled binary, and one
left installed on a Dom0 from before the migration still allocates VLANs that
way, so `sandboxd/daemon.py::refuse_if_another_orchestrator_runs` still refuses
to start when it finds one running. Migration is a cutover, not coexistence.

---

## Evidence status at the time of deletion

Stated plainly, because deleting code does not change what was proved with it.

- **Ubuntu was evidenced end to end** under the shell pipeline
  (`docs/runbooks/01-verify-user-placeholder.md`) and remains the evidenced
  path. The port to `sandboxd` was verified against the literal commands these
  scripts ran — parity proved at the desk, by the tests under `sandboxd/tests/`,
  not by a fresh Dom0 run of every case.
- **Android was execution-evidenced end to end on 2026-08-17**
  (`docs/runbooks/07-verify-android-mvp.md`): `injector` `writefile`/`readfile`
  round-tripped 12 MB byte-exact, the network injection configured the clone, a
  native ELF traced through the execve path, and an APK installed and launched.
  The reworked APK path — install-in-preconfig plus `am start` — was implemented
  and **never run on Dom0**, and no Android step had been re-run since the
  2026-08-17 template re-save. That remains true of the `sandboxd`
  implementation of it.
- **Windows had a design contract and no execution evidence**, and still does.

### The Dom0 checkout

Parity has been maintained by a checkout rather than by copying since 2026-08-09
(issue #4). Dom0 runs a clone of this repository pulled over a read-only deploy
key, so what is deployed is one command:

    git -C <dom0 checkout> log -1              # what is deployed
    git -C <dom0 checkout> status --porcelain  # local drift, expect empty

**The checkout is at `/root/drakvuf-multios-sandbox`** — observed on Dom0
2026-08-19. Every runbook under `docs/runbooks/` says `/root/sandbox_project`;
those are dated evidence and are not edited, so read the path in them as "the
Dom0 checkout", whatever it was called on that date.

Nothing depends on the name. Issue #4's whole point was that every
repository-owned asset resolves from the invoked script's own location, so the
checkout can live anywhere and a wrong path in a document is a documentation
defect rather than a broken deployment.

---

## Where the Xen guest configs live

`misc/`, not `automation/`: `misc/ubuntu.cfg` (golden `ubuntu`),
`misc/ubuntu_sandbox.cfg` (`ubuntu_sandbox`), `misc/android.cfg` (golden
`android`), `misc/android_sandbox.cfg` (`android_sandbox`), `misc/windows.cfg`,
and `misc/platform.cfg`.

These were renamed from `linux.cfg`/`linux_sandbox.cfg` in issue #1 — those
names were historical and misleading, since the files define Ubuntu domains and
not a generic "linux" one. The Dom0 copies were renamed to match on 2026-08-08.

`scripts/gen-xen-configs.py` owns **only** the `cpus =` line in
`misc/*_sandbox.cfg` and `misc/platform.cfg`, and the assignment lines in
`automation/platform.env`. Every comment in those files is hand-maintained and
survives a regeneration untouched — which is deliberate, because those comments
carry the reasoning about `altp2m`, `hap` and `viridian` that a generated file
would lose. `sandboxd/tests/test_xen_configs.py` fails until the generated
values agree with `sandboxd/config.py`.

The clone's own config is produced at analysis time by
`sandboxd/clone.py::rewrite_config`, which changes `name=`, `vif=` and `disk=`
and passes everything else through, comments included.
