# Analysis pipeline architecture

> Verified-vs-proposed distinction matters here, same as the checklists:
> the `dirwatch.c` contract below is confirmed by direct source reading
> (2026-08-07). The job/result state model below is **decided** as of
> 2026-08-09 (issue #3 / DRAFT-008) and **implemented nowhere**. "Decided"
> means downstream work builds on it instead of reinventing it; it does not
> mean any script emits it today.

## Current orchestrator: `automation/dirwatch.c`

A modified copy of DRAKVUF's own `dirwatch` tool (upstream lives at
`tklengyel/drakvuf:src/dirwatch/dirwatch.c` — see `upstream-drakvuf.md`).
It is a `GThreadPool` + `inotify` (`IN_CLOSE_WRITE`) watcher on the
incoming-sample folder, invoked with a fixed 15-argument CLI contract:

```
dirwatch <loop(0)|poll(1)> <origin domain> <domain config> <kernel json> \
  <injection pid> <watch folder> <serve folder> <output folder> \
  <max clones> <clone_script> <config_script> <drakvuf_script> \
  <cleanup_script> <tcpdump_script>
```

`automation/run_analysis-ubuntu.sh` invokes it with values resolved from
its own location — `$REPO_ROOT` is the checkout, wherever that is:

```
dirwatch 1 ubuntu_sandbox $REPO_ROOT/misc/ubuntu_sandbox.cfg \
  $REPO_ROOT/profiles/linux.json 1415 \
  /malware_incoming/ubuntu /malware_processing/ubuntu \
  /malware_finished/ubuntu 2 \
  $REPO_ROOT/automation/{clone.pl,preconfig-ubuntu.sh,\
  drakvuf-ubuntu.sh,cleanup.sh,tcpdump.sh}
```

All fourteen values come from `automation/pipeline-ubuntu.env`, a sourced
config file rather than literals in the launcher, so a second OS pipeline
is a copy of that one file plus its own `run_analysis-<os>.sh`. The
15-argument CLI contract itself is unchanged — issue #4 changed only the
values.

Until issue #4 the first four of those were hard-coded deployment paths
(`/home/user/drakvuf-tools/...`, `/root/linux.json`) that matched neither
this repository's layout nor each other's conventions.

> **Scripts in `automation/` run under `dash`, not `bash`.** Five of the
> six carry the DRAKVUF license header *above* the shebang, so
> `#!/bin/bash` lands on line 104 and the kernel never sees it; `execv`
> fails `ENOEXEC` and GLib's `g_spawn_*` falls back to `/bin/sh`. Anything
> written for these scripts must be POSIX — a bash-only construct such as
> `${BASH_SOURCE[0]}` does not fail loudly under dash, it evaluates empty
> and carries on. `run_analysis-ubuntu.sh` is the exception; its shebang
> is on line 1. Recorded here 2026-08-09; the shebang placement itself is
> DRAFT-031's to fix.

### Sample delivery: host-to-guest injection

**Applies to all three OS pipelines.** Ubuntu implements it; Android
(DRAFT-016) and Windows (DRAFT-034) inherit it rather than choosing
again.

The sample is written into the guest by `injector`, from Dom0:

```
injector -r <profile> -d <clone> -i <pid> -m writefile \
    -B <dom0 source path> -e <guest destination path>
```

`-B` is the Dom0 source and `-e` the guest destination — confirmed from
the installed build's own `--help`, captured on Dom0 2026-08-08 and
recorded at `docs/runbooks/verify-user-placeholder.md:154-157`. (`-f` is
**not** part of this: it is accepted only with `-m execproc` or
`-m shellexec`.)

Two properties the destination path must have, on every OS:

1. **No component derived from the submitted filename.** The guest path is
   `<staging dir>/<sha256>`, and the SHA-256 is computed Dom0-side from
   the file's contents. The submitted filename is untrusted and is now
   interpolated into no command string at all.
2. **Identical to what the trace phase executes.** `preconfig-*` and
   `drakvuf-*` derive it by the same rule from the same two `dirwatch`
   arguments, so staging and execution cannot name different files. Issue
   #2 found exactly that drift in the previous design.

Delivery does not require guest networking and runs before it is
configured, which is what leaves an `offline` network mode reachable
(`networking.md`).

#### Historical: HTTP delivery via Apache (removed 2026-08-09)

Until issue #4 / DRAFT-027, the guest fetched its own sample:
`preconfig-ubuntu.sh` injected a shell command running
`wget 'http://172.16.<vlan>.1/<filename>'` against an Apache instance on
the Dom0 analysis gateway whose `DocumentRoot` was `/malware_processing`.

It worked — issue #2 evidenced six successful staged runs — and it was
removed anyway, with no fallback branch, flag, or configuration switch.
Four reasons, recorded so the decision is not relitigated from scratch:

- It required a privileged Dom0 service reachable from every clone, and
  that service's document root was **every other in-flight sample,
  addressable by filename**. Nothing in `automation/` sets an INPUT
  policy (DRAFT-029), so clones could reach it freely.
- It made an `offline` network mode structurally impossible: the guest
  network had to be up *before* the sample could be staged.
- It forced the untrusted filename into a guest shell command, inside a
  single-quoted URL inside `sh -c` — a filename containing `'` escapes
  the quoting.
- It did not generalize. `wget` is reasonable on Ubuntu; Android's shell
  may not provide it usably and Windows would need a third mechanism.

A retained fallback would have been an untested code path whose only
function was to restore that exposure. There are deliberately no
instructions here for re-enabling it.

Per-sample flow: on a new file, `dirwatch` **admits or rejects the filename**,
moves it out of the watch folder with `rename(2)`, then calls back into the
worker scripts in order —
`clone_script → config_script → drakvuf_script → cleanup_script`, with
`tcpdump_script` started on a separate thread. A 60s timeout guards the
preconfig phase and a 180s timeout guards the drakvuf-trace phase; either
timeout triggers `cleanup_script` and a fresh clone retry.

`cleanup_script` also runs when the analysis **succeeds** — corrected
2026-08-15. Until then it ran only on the timeout path, so a normally
completed analysis left its clone running: the domain was torn down lazily
by `clone.pl`, on the next sample that happened to claim the same VLAN
slot. Invisible on a busy queue and permanent on a quiet one, and a
containment defect rather than untidiness, because a finished sample kept
executing with NAT'd egress until something displaced it. Both `dirwatch.c`
and `dirwatch_old.c` carried it, so it came from the upstream tool.

> **`cleanup.sh` still does not remove the clone's LV**, on either path —
> it pauses and destroys the domain only. `clone.pl` removes a stale
> snapshot when it next reuses that name, so the count is bounded by
> `MAX_CLONES` rather than growing without limit, but one snapshot per slot
> persists between runs. That is the state `lvs` shows on an idle Dom0
> (`docs/runbooks/verify-android-isolation.md:975`).

**Every callback is spawned as an argv vector, never as a command string**
(DRAFT-030, 2026-08-15). The five call sites used to build
`g_strdup_printf()` templates and pass them to
`g_spawn_command_line_sync()`, which runs no shell but *does* apply
`g_shell_parse_argv()` — shell word-splitting and quote handling over a
string containing an attacker-chosen filename. A sample named `a b.exe`
split into two arguments and shifted every positional after it, so the
worker scripts silently received `$RUNFILE` and `$OUTPUTFOLDER` misaligned;
an unbalanced quote failed to parse and left the sample to be retried
forever. The 15-argument CLI contract and the callback arities are
unchanged (C9) — only the construction is.

**Filename admission** happens before a worker slot is claimed, so an
unprocessable name costs nothing. Rejected: empty names, `.`/`..`, path
separators, control characters, and names over 200 bytes. **Not** rejected:
a leading `-`, because every consumer prefixes the folder
(`md5sum -- "$RUNFOLDER/$RUNFILE"`) so the byte is never in option
position; and Windows reserved device names, which are a guest-side hazard
that `dirwatch` — not told which OS it serves — cannot judge (DRAFT-034
owns that). A rejected sample is moved to `<out_folder>/rejected/` under
the SHA-256 of its own name, because leaving it in the watch folder would
re-reject and re-log it on every scan. A name that is not safe to path-join
is logged and left untouched rather than moved.

> **The trace-phase headroom is about 55s, and it has been exceeded.**
> `drakvuf-ubuntu.sh` does `sleep 5` then `drakvuf ... -t 120`, so a run
> nominally costs ~125s against the 180s guard — and `-t 120` bounds
> *tracing*, not the writing of `memdump`/`fileextractor` output that
> follows, which has reached ~120 MB beside a 98 MB log for a single
> sample. Two consecutive timeouts were observed on Dom0 2026-08-09, on
> the first runs **after a reboot** — runs before it, and after those two,
> were fine. Most likely the 2.1 GB saved image being read cold from disk
> with an empty page cache, but that is a hypothesis and was not measured.
> The retry path behaved correctly both times.
> Neither `180` nor `120` is configurable today — the first is compiled
> into `dirwatch.c`, the second is a literal in the trace script — so
> tuning the headroom currently means editing code. See
> `docs/runbooks/deploy-repo-relative-paths.md`, D5 observations. Concurrency is
capped by a thread pool sized from the `<max clones>` argument, which this
project's copy validates as 1–128 in `main()` — `dirwatch.c:486-488`
rejects anything outside that range with "Invalid clone count %u (valid
range: 1-128)", and `slots_busy[]` is sized `[128]` to match
(`dirwatch.c:161`). *(Corrected 2026-08-11: this previously said the bound
was "validated 1–128 in upstream" and that this copy "has not been
independently re-verified against that bound". It has been, against the
source in this repository.)*

One origin domain is hard-coded per invocation (`dirwatch.c:472`), so a
`dirwatch` process serves exactly one guest OS. The state model below turns
that constraint into the OS-selection mechanism — one watcher and one
incoming directory per target OS — rather than working around it.

### Clone concurrency: fixed slots today, resource-aware admission needed

Concurrency is currently a fixed count, and that count doubles as the VLAN
allocator:

- `<max clones>` sizes a fixed `GThreadPool` (`dirwatch.c:493`);
- `find_thread()` claims a slot from `slots_busy[128]` by atomic CAS
  (`:195-209`);
- the slot index *becomes* the VLAN — `make_clone(xen, &cloneID,
  threadid + 1, …)` (`:297`) — so slot 0 means VLAN 1, `xenbr1.1` and
  `172.16.1.0/24`.

Two problems follow, both sharpened by the one-watcher-per-OS decision.

**1. A fixed clone count is the wrong unit.** Each watcher would carry its
own independently-set `<max clones>`, with no way to lend capacity to
another. A split like "5 Windows, 3 Ubuntu, 3 Android" sized to be safe
when all three are busy leaves most of the host idle whenever only one OS
is in use; sized to fill the host for one OS, it overcommits when all three
run at once. Raising the numbers cannot fix this, because the caps cannot
observe each other.

Nor would a single shared clone count fix it, because clones are not
interchangeable: `misc/ubuntu_sandbox.cfg:14-15` and
`misc/android_sandbox.cfg:14-15` both pin `memory = maxmem = 2048` with no
ballooning headroom, and a Windows sandbox will need more. **The admissible
quantity is memory, not clones** — a clone should be created when the host
can currently afford *that* clone, whichever OS asked for it. That is also
what makes the arrangement efficient rather than merely safe: one busy OS
can use the whole host.

**2. `slots_busy[]` is process-local, so the VLAN space collides.**

> **KNOWN GAP (DRAFT-036).** Three `dirwatch` instances each allocate from
> their own zero-based array, so all three hand out VLAN 1 first and all
> three clones land on `xenbr1.1` / `172.16.1.0/24` — breaking the per-VLAN
> isolation that `network-setup.sh` exists to provide. A host-global VLAN
> allocator is therefore a **prerequisite** of running per-OS watchers
> concurrently, not a later optimization.

Both point at one change: admission decides whether a clone may be created
from live host state, and VLAN assignment becomes a separate host-global
lease instead of a by-product of a slot index.

Candidate admission rule — **requires testing on Dom0, not validated:**

```text
required  = clone .cfg memory + shadow_memory (32) + per-domain overhead
available = xl info -> free_memory, minus a fixed reserve
admit if    required <= available
```

Dom0 is pinned at `dom0_mem=4096M,max:4096M`
(`docs/drakvuf-on-xen-nested-within-proxmox.md:280`) and so does not
balloon; the reserve exists for Xen's own allocation and for the restore
burst, not for Dom0. `xl restore` reinstates a full memory image, so
admission has to be sized against that peak rather than steady-state
usage — this is the part most likely to be wrong on first attempt and
should be measured before the rule is trusted.

Memory admission on its own is greedy, and greedy admission starves the
largest clone: whenever memory frees up, a smaller job is already eligible
and takes it, so a Windows clone waits for a window that never opens while
Ubuntu and Android run normally. Each individual decision is correct, which
is what makes it hard to see. Admission therefore has to own **queue order**
as well — ordered by `submitted_at`, with a standing reservation for the
oldest job that cannot yet be afforded, so freed memory accumulates toward
it rather than being handed to whoever fits. Per-OS reserved capacity is
not the answer; that is the static partitioning this section exists to
remove.

Three watchers also means three independent `inotify` queues with no
relative ordering, so the ordering cannot come from the watchers. VLAN
leasing, memory reservation and queue order all need the same host-global
authority, which is why DRAFT-036 treats them as one piece of work.

This is exactly what `queued` means in the state model below: a job that is
admissible but waiting for capacity sits there *visibly*, with a showable
reason — `waiting_for_memory`, `waiting_for_vlan`, or
`blocked_by_reservation` when it is held behind a larger job — instead of
being blocked invisibly inside a thread pool.

**Known upstream issue to check for divergence:** `tklengyel/drakvuf` issue
#140 describes a timeout-triggered clone retry failing to find its sample
because it was already moved out of the incoming folder — the same
retry-on-timeout shape this project's `dirwatch.c` uses. Whether this
project's copy already diverged/fixed this has not been checked (DRAFT-010).

## Shared and per-OS code boundary (issue #6 / DRAFT-009)

Which files in `automation/` serve all three OS targets and which are copied
per target. The routing decision above — one `dirwatch` and one incoming
directory per OS — is what makes this load-bearing: with three script sets,
a defect on the shared side is one fix and a defect on the per-OS side is
three.

The test is mechanical rather than editorial: **a file is shared if every
OS-varying value reaches it as an argument.** Each signature below is the
evidence for that file's placement, re-derived from the current sources on
2026-08-10.

### Shared — one copy, invoked identically by every OS pipeline

| File | What it receives | Source |
|---|---|---|
| `dirwatch.c` | domain, config, profile, folders and the five script paths, all `argv`; only the *count* is validated (`argc!=15`) | `:453`, `:470-474` |
| `network-setup.sh` | `$1` = clone-slot count. Nothing else | `:128` |
| `cleanup.sh` | `$1` = clone domain, `$2` = vlan | `:113-114` |
| `tcpdump.sh` | `$1` = vlan, `$2` = run folder, `$3` = input, `$4` = output folder | `:111-114` |

### Per-OS — one copy per target

| File | Ubuntu instance | Invoked as |
|---|---|---|
| `clone.pl` (shared) | `clone.pl` | `<origin> <vlan> <config>` — `CLONE_CMD`, `dirwatch.c:122,175`; the script enforces `@ARGV != 3` (`:169`) |
| `preconfig-*.sh` | `preconfig-ubuntu.sh` | 8 args — `CONFIG_CMD`, `:124,378`; the script reads 7 and ignores `utime` |
| `drakvuf-*.sh` | `drakvuf-ubuntu.sh` | 8 args — `DRAKVUF_CMD`, `:123,398`; same, reads 7 |
| `run_analysis-*.sh` | `run_analysis-ubuntu.sh` | top-level entry point; takes no arguments |
| `pipeline-*.env` | `pipeline-ubuntu.env` | sourced, never executed (`:15-18` states the per-OS-copy decision) |

`tcpdump.sh` is likewise passed a `utime` it ignores (`TCPDUMP_CMD`,
`:126,188`), and `cleanup.sh` and `clone-*.pl` are the two callbacks that
receive neither it nor any run identifier — the constraint recorded under
"Recovery after interruption" below.

### Finding: the shared files hard-code no OS-specific value — only host-global ones

Every value hard-coded inside a shared file is a property of **the host**,
not of a guest OS:

| File | Line | Hard-coded value | Class |
|---|---|---|---|
| `network-setup.sh` | `:139` | `xenbr0` (uplink, `MASQUERADE` target) | host-global |
| `network-setup.sh` | `:144`, `:147-149`, `:169` | `xenbr1` and `xenbr1.<n>` | host-global |
| `network-setup.sh` | `:148` | `172.16.<vlan>.1/24` gateway scheme | host-global |
| `cleanup.sh` | `:118` | `xenbr1.<vlan>` (tcpdump match) | host-global |
| `tcpdump.sh` | `:117` | `xenbr1.<vlan>` (capture interface) | host-global |

This matters more than it looks. It means the shared/per-OS split is
**already correct as a split** — nothing on the shared side needs to learn
about Ubuntu, Android or Windows. What the shared side lacks is a
*host-global* configuration mechanism, which is a different problem from the
one DRAFT-009 was originally written to solve, and one that must not be
solved by giving three per-OS files three copies of the same host value.

`ANALYSIS_BRIDGE` (`pipeline-ubuntu.env:141`) illustrates the trap: it has
exactly **one** consumer in the tree (`run_analysis-ubuntu.sh:49`), while
the bridge name it nominally parameterizes is hard-coded on **11 lines
across 7 files** — `network-setup.sh:144,147,148,149,169`,
`cleanup.sh:118`, `tcpdump.sh:117`, `drakvuf-ubuntu.sh:161`,
`clone.pl:191`, `misc/ubuntu_sandbox.cfg:53` and
`misc/android_sandbox.cfg:58`.
`network-setup.sh`'s own header already says so: *"xenbr0 (uplink) and
xenbr1 (analysis bridge) are project-wide fixed names… Renaming them here
alone is not enough."*

### The values a per-OS pipeline actually needs

| Class | Values | Where they live today |
|---|---|---|
| **Per-run** — already `dirwatch` arguments, no configuration needed | profile path, clone domain ID, injection PID, vlan, run folder, input filename, output folder (+ the ignored `utime`) | `CONFIG_CMD`/`DRAKVUF_CMD` |
| **Per-OS** — genuinely differ by target | sandbox domain, `.cfg`, kernel profile, saved state, the three `/malware_*/<os>` folders, guest staging path, injection PID, the guest network recipe, the guest execution recipe | `pipeline-ubuntu.env`; guest recipes are inline in `preconfig-ubuntu.sh:205` and `drakvuf-ubuntu.sh:150` |
| **Host-global, but sitting in a per-OS file** | `MAX_CLONES` (`:139`), `ANALYSIS_BRIDGE` (`:141`), `WATCH_MODE` (`:124`), and `GUEST_NAMESERVER` (`:119`) as containment *policy* | `pipeline-ubuntu.env` |
| **Host-global, and reachable by no configuration at all** | `vg-root` (`clone.pl:161`), `xenbr1` (`:191`) and the `172.16.<vlan>.0/24` scheme (`network-setup.sh:148`) | hard-coded. `-L64G` was here until DRAFT-015 and is now `CLONE_LV_SIZE` |

The guest network recipe is the least portable line in the pipeline and is
worth naming explicitly. `preconfig-ubuntu.sh:205` assumes `eth0`, `sudo`,
`ip`, and a writable `/etc/resolv.conf` — four assumptions, none of which
hold on Android as written.

### Decisions (issue #6, 2026-08-10)

**1. The guest path is `<staging dir>/<guest_filename>`, on every target.**
The leaf is the *normalized submitted name* defined under "Filenames: two
namespaces" below — not the SHA-256, which is what Ubuntu ships today and is
now a recorded deviation rather than the convention. The staging directory
is a per-OS value and **must already exist in the saved guest image**:
`injector -m writefile` does not create parent directories.

That constraint is the reason staging is flat. Android's checklist proposes
a per-sample directory `/data/local/tmp/drakvuf/<sha256>/`
(`docs/checklists/android.md:1114-1117`), which cannot pre-exist — the
SHA-256 varies per sample — and so needs a `mkdir -p` injection through a
guest shell before delivery (`:1138-1150`). The sample is staged flat into a
fixed, pre-existing directory instead, so delivery stays **one injection
with no guest shell on any target** — which is what keeps an `offline`
network mode reachable.

**There is no per-run guest directory, on any target.** That directory only
existed to hold in-guest collection output, and in-guest collection is
withdrawn — see "No in-guest collection" below. The guest filesystem is
written once, by `writefile`, and never read back.

Both consumers must derive the path by the same rule from the same
arguments — the drift issue #2 found.

Per-target staging directories, each of which must pre-exist in that
target's saved image:

| `target_os` | `GUEST_STAGING_DIR` | Status |
|---|---|---|
| `ubuntu` | `/home/carlos/Desktop` | in use; evidenced by six staged runs (`docs/runbooks/verify-user-placeholder.md`) |
| `android` | `/data/local/tmp` | **decided 2026-08-10**, execution-evidenced on the guest — see `docs/checklists/android.md`, "Staging directory" |
| `windows` | — | DRAFT-034; must satisfy the same two properties (pre-exists, permits the execution method) |

Android's choice is the one that shows what the two properties are worth
testing for. `/storage/self/primary/Download` is writable and visible to the
injection anchor, but sits on a `noexec` FUSE mount where `chmod` is a no-op,
so a staged native sample cannot be executed at all — while `/data/local/tmp`
is exec-capable and already exists, needing no golden-image change. Neither
condition is visible from the path alone, and neither is an SELinux matter.

> **Issue #6 specifies this; it does not implement it.** Ownership assigned
> 2026-08-10: the normalizer, the Ubuntu staging retrofit and the argv
> invariant across the guest hop belong to **DRAFT-030**; emitting
> `guest_filename` and `original_filename` as separate fields belongs to
> **DRAFT-011**, which gains a soft dependency on DRAFT-030 since the field
> is meaningless before a normalized name exists. The normalizer is one
> implementation shared by all three pipelines, not one per OS — splitting
> it is how two normalizers get written.

**2. Host-global values move to `automation/platform.env`.** A new
host-level config sourced by `run_analysis-*.sh`, `network-setup.sh`,
`cleanup.sh` and `tcpdump.sh`, holding the analysis bridge, the uplink
bridge, the `172.16.<vlan>.0/24` prefix and the volume group.
`ANALYSIS_BRIDGE` leaves `pipeline-ubuntu.env`, where it had one consumer
and nine unreachable siblings.

**The clone LV size is not among them — it is per-OS.** `-L64G`
(`clone.pl:326`, from `CLONE_LV_SIZE` since DRAFT-015) sizes an LVM
copy-on-write *exception store*: how
much divergence from the origin a clone may accumulate before the snapshot
is invalidated. That is a function of how much the guest writes during an
analysis, which is a property of the OS image and its workload, not of the
host. Windows will want more, Android likely less. `CLONE_LV_SIZE` belongs
in `pipeline-<os>.env`, with `64G` as Ubuntu's default.

That split costs nothing mechanically, which is itself worth noting:
decision 3 below carries both classes the same way, so a per-OS value and a
host-global one reach `clone-*.pl` through the same path.

A shared script reading a *host-global* config does not make it OS-aware, so
this does not move any file across the boundary — that is the test.
`MAX_CLONES` deliberately stays in the per-OS file: DRAFT-036 replaces it
with host-global admission wholesale, and moving it twice is worse than
moving it once. The `misc/*.cfg` bridge literals stay as they are; a Xen
config is not shell and cannot source anything.

**3. `clone-*.pl` reads its host-global values from the environment.** No
config parser in Perl, and no change to the 3-argument contract:
`run_analysis-*.sh` exports the `platform.env` values, and `dirwatch` spawns
every callback through `g_spawn_command_line_sync` with `envp = NULL`
(`dirwatch.c:178,190,216,380,400`), which inherits the parent environment.
The Perl then reads `$ENV{VG_NAME} // 'vg-root'` and the defaults it carries
today become the fallbacks.

> **Source-reasoned, not execution-evidenced.** The inheritance is GLib's
> documented behaviour for `envp = NULL` and has not been confirmed on Dom0.
> Verify with one run before relying on it — a silently empty `$ENV{VG_NAME}`
> falls back to `vg-root` and looks like success.

**4. No in-guest collection, on any target.** `logcat`, `logd`, `dumpsys`
and `dmesg` are withdrawn from the Android design, and no equivalent may be
introduced for Ubuntu or Windows. Analysis output comes from hypervisor
introspection and the host-side packet capture. The guest filesystem is
written exactly once — the sample, by `writefile` — and never read back.

The reason is not that these tools are installed agents; they ship with the
OS, so by the narrow criterion ("nothing persistent is installed in the
guest") they would pass. It is that a collector running inside the guest
breaks what that criterion protects:

- it is **visible to the sample** in `ps`/`/proc` — a sandbox tell, and a
  real evasion trigger;
- its output file is **writable by the sample**, which can truncate, poison
  or delete it;
- stopping it needs in-guest state (a PID file, a signal), so teardown is
  in-guest too;
- it duplicates inside the trust boundary what introspection already
  provides from outside it.

`injector`'s drakshell remains the one accepted entry, precisely because it
self-terminates *before* the sample executes. Anything that outlives that
point is a different class of thing.

> **The cost is real and is accepted knowingly.** DRAKVUF traces kernel
> syscalls; `logcat` carried Android **framework** semantics —
> ActivityManager, PackageManager, ART, Intent dispatch, permission grants —
> which are userspace Java events and are hard to reconstruct from syscalls.
> Android therefore has less semantic visibility under this decision than
> the checklist previously assumed. Revisiting it means finding an
> *external* source for those events (reading `logd`'s buffers through
> LibVMI, for instance), not re-admitting an in-guest process.

### Conformance checklist for a new OS pipeline

What DRAFT-015/016 (Android) and DRAFT-034 (Windows) are reviewed against.
This is what discharges issue #4's carried-forward criterion — "written
against this same convention" is only checkable if the convention is a list.

Every item is written to be verifiable **from the files**, not from an
assertion, so it stays usable as a review instrument and remains
convertible into a static CI check later (DRAFT-026a) without being one now.

**C1 — Create exactly these four files, and no others.**
`pipeline-<os>.env`, `preconfig-<os>.sh`, `drakvuf-<os>.sh`,
`run_analysis-<os>.sh`. The clone step is **not** among them — it is
shared; see C2.

> **Pending amendment, 2026-08-21 (DRAFT-041).** C1 drops to **three**
> per-OS files when `dirwatch` is retired: `run_analysis-<os>.sh` collapses
> into one host-global launcher, because with a single `sandboxd` there is
> one thread pool, one watch loop and one `network-setup.sh` call, so nothing
> in a launcher varies by OS. This is the second time C1 has moved a file
> from per-OS to shared, and for the same reason as DRAFT-015's: nothing in
> it varied except values. **Not yet applied** — the three launchers still
> exist and are still what runs. A Windows pipeline written today writes
> four files.

> **Pending amendment, 2026-08-26 (#41).** The clone step stops being a
> *script* at all. `automation/clone.pl` is ported into `sandboxd` as a stage,
> so C1's "it is shared; see C2" becomes "it is not a file". #41 had excluded
> the port — *"holds no OS-specific value, and works. Leave it."* — and
> withdrew that on 2026-08-26: `clone.pl:207` joins argv into a string and runs
> it through backticks, as do its `which`, `xl domid` and `cat` calls, making
> it the last shell-string builder in a pipeline whose replacement exists to
> remove them.
>
> **Not yet applied.** `clone.pl` is still what runs, still on its 3-argument
> contract, and stays installed as the rollback path until `sandboxd` is
> evidenced on Dom0. A pipeline written today still calls it.

> **Amended 2026-08-15 (DRAFT-015).** C1 previously required five files,
> including `clone-<os>.pl`. Writing Android's revealed that
> `clone-ubuntu.pl` held exactly one OS-specific value — the `-L64G`
> snapshot size — because everything else already arrives on the
> 3-argument contract, is derived from it, or is host-global. With that
> one value read from `$ENV{CLONE_LV_SIZE}`, a `clone-android.pl` would
> have been a byte-identical copy, so the file was renamed
> `automation/clone.pl` and shared instead. The test in decision 3 is what
> permits this: a shared script reading a per-OS value from the
> environment does not thereby learn about an OS.
>
> The rename was verified against Android before it was made — handed
> `android_sandbox 1 misc/android_sandbox.cfg`, the existing rewrites
> reproduce byte-for-byte the config that
> `docs/runbooks/verify-android-isolation.md` steps 2–3 wrote by hand.

**C2 — Do not copy, fork or special-case a shared file.** `dirwatch.c`,
`clone.pl`, `network-setup.sh`, `cleanup.sh`, `tcpdump.sh`. *(`clone.pl` leaves
this list when #41 lands — see C1's pending amendment. The rule it states does
not change: it becomes a shared stage rather than a shared file, and a
`clone_<os>` branch inside it would fail this check for the same reason a
`clone-<os>.pl` does.)* Needing a
change in one of them is a change to three pipelines at once and takes its
own issue; a `<os>`-suffixed copy of any of them fails this check
outright. `clone-<os>.pl` in particular is now a C2 violation rather than
a C1 requirement — if a target seems to need one, the value that differs
belongs in `pipeline-<os>.env` and the environment, as `CLONE_LV_SIZE`
does.

**C3 — `pipeline-<os>.env` defines**: `SANDBOX_DOMAIN`, `DOMAIN_CONFIG`,
`KERNEL_PROFILE`, `SAVED_STATE`, `TARGET_OS` and the three
`/malware_*/<os>` folders, `GUEST_STAGING_DIR`, `CLONE_LV_SIZE`,
`INJECTION_PID`, `WATCH_MODE`, `MAX_CLONES` — each as `${NAME:-default}`,
so the environment wins and CI can override without patching files.

**C4 — `pipeline-<os>.env` does *not* define** `ANALYSIS_BRIDGE`, the
uplink bridge, the subnet prefix, or `VG_NAME`. Those are host-global
(`platform.env`). A copy here is the exact failure this section exists to
prevent, and it is greppable.

> **Pending amendment, 2026-08-21 (DRAFT-041).** `MAX_CLONES` and
> `WATCH_MODE` migrate from C3 to C4 when `dirwatch` is retired. Both are
> host-global under one `sandboxd` — one pool, one loop — so a per-OS value
> for either has no referent. They are deliberately left in
> `pipeline-<os>.env` until then, because moving them now would mean moving
> them twice; both files say so at the definition. A **per-OS concurrency
> cap** within the host-global pool is a separate, defensible feature and
> must not be smuggled in as "keeping `MAX_CLONES` where it was".

**C5 — Guest path.** `<GUEST_STAGING_DIR>/<guest_filename>`. The staging
directory **pre-exists in that target's saved image** — `writefile` does not
create parents — and `preconfig-*` and `drakvuf-*` derive the path by the
same rule from the same arguments. No component of it derives from the
submitted filename on the Dom0 side.

**C6 — Delivery is one injection, with no guest shell before it.**
`injector -m writefile -B <dom0 source> -e <guest destination>`. `-f` is not
valid with `writefile`. Nothing may require guest networking to be up first;
that is what keeps an `offline` mode reachable.

**C7 — No in-guest collection.** No process started in the guest may outlive
the sample, and no analysis output may be read back off the guest
filesystem. See decision 4.

**C8 — POSIX under `dash`.** `$0`, never `${BASH_SOURCE[0]}` — it evaluates
empty under dash *without stopping*. `dash -n` is as load-bearing as
`bash -n` here.

**C9 — Callback contracts unchanged.** `clone-<os>.pl` takes 3 arguments
and prints a clone domain ID to stdout **only** on success; `preconfig-<os>`
and `drakvuf-<os>` are passed 8 and read the first 7. Diagnostics go to
stderr. Changing any of these is DRAFT-010's, not a new pipeline's.

**C10 — Evidence before acceptance.** `bash -n`, `dash -n`, `shellcheck`,
`perl -c`; plus, on the guest itself, the two properties that cannot be read
off a path — that the staging directory pre-exists, and that it permits that
OS's execution method.

> C10's second half is not a formality. On Android,
> `/storage/self/primary/Download` satisfies "exists and is writable by the
> anchor" and fails "permits execution" — a `noexec` FUSE mount where
> `chmod` is silently a no-op. Neither fact is visible from the path, from
> `ls`, or from SELinux. It took an exec probe.

### Ordering these impose on the backlog

Not preferences. Each is a defect that gets multiplied if the order is
ignored:

- **DRAFT-033 before DRAFT-015.** ~~`clone-ubuntu.pl` is the template
  `clone-android.pl` is written from and it checks no exit status. Copy
  first and the defect exists in three files.~~ **Premise superseded
  2026-08-15, ordering unchanged.** There is no copy: DRAFT-015 renamed the
  file to the shared `clone.pl` (see C1/C2). DRAFT-033's fixes are *more*
  urgent for it, not less — a file with no exit-status checks now serves
  three pipelines instead of one. DRAFT-015 ran first in practice; DRAFT-033
  now lands on `clone.pl`.
- **DRAFT-030 before DRAFT-016.** DRAFT-030 now owns the normalizer and the
  guest-naming retrofit. Writing `preconfig-android.sh` first means writing
  it against SHA-256 staging and rewriting it immediately.
- **DRAFT-031 before either.** The licence-header-above-shebang layout is
  inherited by every copy made before it is fixed.
- **DRAFT-036 before any two watchers run at once** — unchanged, and a
  correctness prerequisite rather than tuning.

> **~~Open:~~ Settled — who creates `platform.env`.** Decision 2 is a code
> change, and issue #6 does not make code changes. Each file's existing
> owner does its own wiring: **DRAFT-028b** creates `platform.env` and wires
> `network-setup.sh`; **DRAFT-033** wires `clone.pl`, whose acceptance
> criteria already require parameterizing the snapshot size; **DRAFT-011**
> wires `cleanup.sh` and `tcpdump.sh`, where it is already fixing the
> `ps | grep` matches.
>
> **Confirmed 2026-08-15, and the first part is done.**
> `automation/platform.env` exists and holds `ANALYSIS_BRIDGE`,
> `UPLINK_BRIDGE`, `SUBNET_PREFIX` and `VG_NAME`; `network-setup.sh` and
> `run_analysis-ubuntu.sh` source it, and `ANALYSIS_BRIDGE` has left
> `pipeline-ubuntu.env`. The other two wirings are still open.
>
> The "b" is not cosmetic: the proposal above justified DRAFT-028 on the
> grounds that it *"is already rewriting that file"*, which stopped being
> true when DRAFT-028 deployed on 2026-08-11. Scope added to landed work
> does not land, so this went to a follow-on numbered on the DRAFT-026a/b
> precedent.

## Decided: OS-independent job/result state model (issue #3, 2026-08-09)

This section is the decided model for all three OS targets. Implementation
is tracked elsewhere: DRAFT-011 (retrofit Ubuntu), DRAFT-018 (storage
layout), DRAFT-015/016 (Android), DRAFT-034 (Windows), DRAFT-035 (job
control channel). No script emits any of this yet.

It replaces two incompatible partial models, neither of which was a
deliberate cross-OS design — see "What this supersedes" at the end.

### Design rules

Three rules produced most of the choices below, and are the thing to apply
when extending the model rather than re-arguing each field:

1. **Every state is entered by an explicit, recorded transition.** A state
   that could only be inferred by guessing how far a script got is not in
   the model. Where a phase boundary sits inside one worker script, the
   script must emit the transition for the state to exist — that is a
   requirement on the implementation, not grounds for dropping the state.
   Where a boundary means nothing to a reader *and* nothing to recovery,
   the states are merged.
2. **OS-independent facts live in `state` and `status`; everything
   OS-shaped lives in `stage`, `failure_reason` and `type_identifiers`,
   scoped by `target_os`.** This is what makes the model OS-independent
   without discarding the per-OS vocabularies that already exist.
3. **Persist intent before acting.** The record of what is about to be
   created is written before the thing is created, so an orphaned clone is
   always attributable to a job.

### Job record

One `status.json` per run, written atomically (temp file + rename). It is
the durable source of truth — not a cache of in-process state — and is the
only file a reader (including the future web platform) needs to open.

| Group | Fields |
|---|---|
| Identity | `schema_version`, `analysis_id` |
| Sample | `sample_sha256`, `sample_sha1`, `sample_md5`, `sample_size`, `original_filename`, `guest_filename`, `detected_type`, `type_identifiers{}` |
| Request | `target_os`, `execution_recipe`, `requested_timeout`, `network_mode` |
| Run | `domain`, `clone_id`, `vlan`, `attempt`, `queue_reason`, `submitted_at`, `started_at`, `finished_at`, `duration_seconds` |
| Control | `cancel_requested_at`, `cancelled_by` |
| State | `state`, `stage`, `status`, `failure_stage`, `failure_reason`, `errors[]`, `cleanup_status` |
| Provenance | `sandbox_version`, `profile_version`, `drakvuf_version` |

`analysis_id` identifies **one run**, not one sample: a ULID, and the name
of the result directory. Submitting the same sample twice produces two
independent records that cannot collide or overwrite each other. Samples
are found by `sample_sha256` through an `index/by-sha256/` mapping, which
is also what gives the web platform an "all runs of this sample" view.

`attempt` exists because one submission can legitimately produce several
clone lifecycles: `dirwatch.c:424-429` retries a timed-out sample on a
*fresh* clone via `goto restart`. Neither superseded model could represent
that, so a retried run was indistinguishable from a first attempt.

`sandbox_version` is the git commit of the automation scripts, per
`docs/checklists/android.md:2373`. `profile_version` identifies the LibVMI
JSON profile the run was traced against — a kernel update that invalidates
the profile is otherwise invisible in the results.

### Sample identification

Computed on the host at `admitted`, from the sample bytes, before any clone
exists. This is **identification, not routing** — see "Target OS selection"
below, which is deliberately not driven by any of it.

Universal, and free (coreutils; no new Dom0 dependency):

```text
sample_sha256   the model's sample key
sample_sha1     cross-referencing external corpora (VirusTotal et al.)
sample_md5      cross-referencing, and the migration bridge (see below)
sample_size     also the admission size cap
```

MD5 is retained as an *identifier* precisely because external services are
keyed by it. It is no longer a *key*: the three scripts computing it today
(`drakvuf-ubuntu.sh:118`, `preconfig-ubuntu.sh:118`, `tcpdump.sh:115`) use
it to name the result directory, and DRAFT-011's retrofit needs both values
present during the transition.

Structural identifiers are **format-scoped**, in `type_identifiers`,
because they do not generalize — `imphash` is a hash of a PE import table
and has no meaning for an APK:

| Format | Identifiers |
|---|---|
| PE | `imphash`, `pe_timestamp`, `authentihash`, signature subject |
| ELF | `telfhash` (the ELF analogue of imphash), `build_id` |
| APK | `package_name`, `version_code`, `signing_cert_sha256` |

For an APK the signing certificate and package name — not a hash of the
file — are the identity that actually tracks a malware family across
repackaged samples, which is why they sit in the same slot rather than
being treated as Android trivia.

> **KNOWN GAP (DRAFT-018):** `imphash` and `telfhash` require a parsing
> library on Dom0 (`pefile`/LIEF, `telfhash`); the project currently has no
> such dependency and this issue does not add one. All `type_identifiers`
> fields are therefore nullable, and *which* are computed is DRAFT-018's
> decision. The four universal values above are unconditional.
> Fuzzy hashes (`ssdeep`, `tlsh`) were considered and deliberately not
> adopted here; they are a corpus-similarity tool, and this project has no
> corpus yet.

### Target OS selection, admission, and untrusted input

`target_os` is a closed enum — `ubuntu`, `android`, `windows` — and is
**derived from which incoming directory the sample landed in**, one
`dirwatch` instance per OS:

```text
/malware_incoming/ubuntu/    -> dirwatch --origin ubuntu_sandbox
/malware_incoming/android/   -> dirwatch --origin android_sandbox
/malware_incoming/windows/   -> dirwatch --origin windows_sandbox
```

> **Amended 2026-08-21 (DRAFT-041).** "One `dirwatch` instance per OS" was
> the *implementation* of the directory rule, not the rule itself, and it is
> being replaced: one `sandboxd` watches every source and `target_os`
> becomes a per-job field instead of a per-process constant. Under the web
> tier the same token arrives as a form field validated against the same
> closed enum at the submission boundary. **The decision below is unchanged
> in every respect that matters** — the OS still comes from the submitter,
> file magic still only reports and never routes, and there is still exactly
> one untrusted routing input, validated in one place. The number of
> processes and the OS-selection mechanism are independent, and only the
> second was ever decided here. See `docs/architecture/platform.md`.

This fits the orchestrator that already exists rather than requiring a new
one: `dirwatch` hard-codes a single origin domain per invocation
(`dirwatch.c:472`), so the target OS is already a property of the launcher.
It is also the strongest available answer to input sanitizing — the OS
token is never parsed out of a filename, a sidecar file, or any other
attacker-influenced byte, so there is no value to validate and nothing to
spoof. A directory outside the enum is simply not watched.

The submitting user chooses the OS by choosing where to submit. For the M7
web platform that is a form field mapping to a directory, validated against
the enum at the submission boundary, where it is the only untrusted routing
input in the system.

Admission checks, all before any clone exists, so a rejection costs no VM:

- size cap → `rejected` / `rejected_size`;
- readable, non-empty → `rejected` / `unreadable`;
- `detected_type` recorded, and an obvious mismatch against `target_os`
  (an APK submitted to `ubuntu/`) → `rejected` / `unsupported_type`.

That last check is the *only* use of file magic in this model. It reports;
it never routes. If detection is unavailable or ambiguous the run proceeds
on the user's choice.

Admission answers *whether the job is valid*. Whether it may **start** is a
separate question answered in `queued`, against live host capacity and
queue order — see "Clone concurrency" above. A job holds in `queued` with
`queue_reason` (`waiting_for_memory`, `waiting_for_vlan`,
`blocked_by_reservation`) until a clone can be afforded, which is why
capacity pressure is a visible, reportable condition here rather than an
invisible stall inside a thread pool. Both capacity and queue order are
host properties, so the wait is shared across all three OS watchers rather
than being per-pipeline.

> `target_os_source` was considered and dropped: with the OS supplied by
> the launcher there is one source and recording it is noise. **Revisit
> only if** DRAFT-014 finds a case where detection cannot disambiguate on
> content alone — Android ELF vs. Linux ELF, or PE32 vs. PE32+ — and only
> with evidence that a provenance field is what resolves it.

### State machine

```text
main path
  received → admitted → queued → cloning → preparing → executing → collecting
                                                                        │
                                                   completed ← cleaning ┘

exits
  admitted           → rejected                 admission failed; no clone made
  queued             → cancelled                cancelled before a clone existed
  cloning…executing  → cleaning → cancelled     cancelled while a clone was running
  cloning…collecting → cleaning → failed        carries failure_stage + failure_reason
  any non-terminal   → cleaning → interrupted   owning process died; recovery sweep
```

`cleaning` runs on every path where a clone was created — failure,
cancellation and the recovery sweep included — so a clone is never left
behind because the job ended badly. It is the one phase that is *not*
cancellable, since interrupting cleanup is how clones leak. Cancelling from
`received`, `admitted` or `queued` skips it because there is nothing to
clean.

Reconciliation with the candidate list this replaces:

- `classified` → renamed **`admitted`**. Classification no longer decides
  anything; admission does.
- `restoring` → **merged into `cloning`**. `clone.pl` performs the
  LVM snapshot and the `xl restore` in a single callback
  (`dirwatch.c:175`), and both fail the same way and recover the same way.
  Rule 1: the boundary is meaningless to a reader and to recovery.
- `monitoring` → **removed**. DRAKVUF starts tracing and executes the
  sample in one invocation (`drakvuf-ubuntu.sh:122`); there is no separate
  phase to enter.
- `stimulating` → **demoted to a `stage`**, not a state. It exists only for
  Android (rule 2).
- `collecting` → **kept**, though today it sits inside the same script as
  `executing`. Unlike `restoring` it changes two things a reader cares
  about: whether artifacts are readable yet, and whether a failure leaves
  results worth preserving. The per-OS script must emit it.
- `cancelled` and `interrupted` → **added**; the candidate list had no
  terminal state for either.

### The same machine against all three OS sequences

The `state` sequence is identical for all three targets. Only `stage`
differs, and only inside `executing` — which is the whole point of keeping
OS shape out of `state`:

| `target_os` | `executing` stages |
|---|---|
| `ubuntu` | `execute` |
| `android` | `install` → `launch` → `stimulate` |
| `windows` | `execute` |

Ubuntu stages one file and runs it; Android installs a package, launches a
component and stimulates exported components
(`docs/checklists/android.md:1169-1178`); Windows executes a PE with no
install step. Nothing else about them differs at the model level, and no
state in the list above is reachable by only one of them.

### Terminal status taxonomy

`status` is closed, small, and OS-independent, because it is what the web
platform switches on:

```text
completed | failed | rejected | cancelled | interrupted
```

Failures are then described on two further axes — `failure_stage` (the
`state` it ended in) and `failure_reason` (the vocabulary, scoped by
`target_os`). This is how the existing per-OS vocabularies are generalized
rather than discarded: every value drafted in
`docs/checklists/android.md:1199-1214` and every row of its failure table
at `:2198-2217` maps onto a triple.

| `failure_reason` | `status` | `failure_stage` | Scope |
|---|---|---|---|
| — (Android's `success`) | `completed` | — | all |
| `unsupported_type` | `rejected` | `admitted` | all |
| `rejected_size` | `rejected` | `admitted` | all |
| `unsupported_abi` | `rejected` | `admitted` | android |
| `clone_failed` | `failed` | `cloning` | all |
| `transfer_failed` | `failed` | `preparing` | all |
| `hash_mismatch` | `failed` | `preparing` | all |
| `injection_failed` | `failed` | `preparing` | all |
| `install_failed` | `failed` | `executing` (`install`) | android |
| `no_launchable_component` | `failed` | `executing` (`launch`) | android |
| `guest_crashed` | `failed` | `executing` | all |
| `guest_rebooted` | `failed` | `executing` | all |
| `plugin_failed` | `failed` | `executing` | all |
| `analysis_timeout` | `failed` | `preparing` or `executing` | all |
| `collection_failed` | `failed` | `collecting` | all |
| `storage_full` | `failed` | `collecting` | all |

`analysis_timeout` carries two possible stages because `dirwatch` has two
timeouts — 60s on preconfig and 180s on the trace (`dirwatch.c:374,394`) —
and which one fired is the useful half of the report.

Three rows of the Android failure table are **not** failures under this
model, and are recorded as resolved rather than mapped:

- *duplicate filename* — no longer possible to collide; `analysis_id` names
  the directory and two submissions of one sample are two records;
- *malicious filename* — handled by the filename rules below;
- *Ctrl+C interruption* — `interrupted`, via the recovery sweep.

`cleanup_failed` is deliberately absent from the table. Cleanup success is
recorded in **`cleanup_status`, independently of `status`**, as
`docs/checklists/android.md:2375` already requires: a leaked clone is an
operator problem, not an analysis result, and must not turn a successful
trace into a failed one — nor be hidden by one.

### Cancellation

A user may stop a running analysis. `cancelled` is a terminal `status` in
its own right and explicitly **not** a `failed` reason — a cancelled run
has no defect to report and must not be presented as an error.

- Cancelling in `received`, `admitted` or `queued` is immediate; no clone
  is ever created.
- Cancelling in `cloning`, `preparing` or `executing` must destroy the
  clone. The primitive already exists: `timer_thread` calls `cleanup()` on
  expiry (`dirwatch.c:240-241`), destroying the clone domain out from under
  the running child, which collapses the current phase. Cancellation
  reuses that path rather than inventing one.
- `cleaning` and the terminal states are not cancellable.
- `cancel_requested_at` and `cancelled_by` are recorded; a cancellation is
  a decision someone made, and the record should say who and when.

> **Required property of any implementation (DRAFT-035).** Triggering the
> timeout path is *not by itself* a cancellation. After it fires,
> `run_drakvuf` falls through to `end:` and re-clones the sample with
> `goto restart` (`dirwatch.c:424-429`), guarded only by `shutting_down`
> (`:425`). A cancel flag must be checked at that same branch. Without it,
> "stop the analysis" produces an unbounded clone/retry loop instead of a
> stop — the opposite of what the user asked for.

### Filenames: two namespaces

The submitted filename is untrusted input and is also behaviourally
significant to the sample. Those two facts are reconciled by using it in
exactly one place:

| Where | Name | Why |
|---|---|---|
| Host result directory | `analysis_id` | Run identity; no untrusted bytes in any Dom0 path |
| Host sample copy | `sample/<sha256>` | Content-addressed; the submitted name is metadata, not a path |
| Guest | `guest_filename` | Malware behaviour is frequently name-dependent |

Inside the guest the sample keeps the name it was submitted with, because
extension-driven handler dispatch, `argv[0]` self-checks and APK filename
assumptions are all real evasion and real behaviour, and a sample renamed
to `test` exercises none of them. That is a deliberate, scoped exception:
the untrusted name is used **inside the disposable clone only, never on
Dom0**.

Two rules make it safe:

- The name must reach the guest as a **single argv element, never through
  a shell-parsed string**. `drakvuf -e` is execve-direct with no guest
  shell — established by issue #2 (`docs/runbooks/verify-user-placeholder.md`)
  — so a name cannot dereference guest-side through that path.
  **This finding is qualified `[LINUX]` at its source.** `injector --help`
  reads `[LINUX] (execproc -> execve(...); 64bit only)`, so it is
  established for Ubuntu and Android and **must not be assumed for
  Windows**: the Windows injection method has not been read, and this rule
  is a security property, not a convenience. Re-establish it per OS before
  relying on it — `docs/checklists/windows.md` carries the same warning.
- `guest_filename` is *normalized, not discarded*: path separators and NUL
  stripped, length capped, Windows reserved names (`CON`, `PRN`, trailing
  dot or space) rejected. It is stored separately from `original_filename`
  so a reader can see when the two differ and why.

> **Superseded 2026-08-10 (issue #6).** This block previously recorded the
> shell-parsed `wget` staging path as a blocker, citing
> `preconfig-ubuntu.sh:122`. **That code is gone** — DRAFT-027 landed inside
> issue #4 on 2026-08-09, and `:122` is now a comment about `$0`. The
> precondition this section was waiting on is met: delivery is
> `injector -m writefile` with `-B` as the Dom0 source and `-e` as the guest
> destination, both single argv elements, no guest shell
> (`preconfig-ubuntu.sh:172-175`). The stale citation is corrected here
> rather than left for DRAFT-032 because issue #6 rewrites this subsection.
>
> **~~KNOWN GAP (issue #6)~~ — implemented 2026-08-15 by DRAFT-030.** Both
> halves are closed, and the first one closed in a way worth reading before
> writing a new pipeline.
>
> 1. **There is no normalizer, by design.** The rule above is achieved by
>    **admission, not transformation**: `dirwatch` rejects a name rather
>    than rewriting it (empty, `.`/`..`, path separators, control
>    characters, over 200 bytes), so every name that reaches a worker
>    script is already safe and needs no transformation anywhere
>    downstream. One check at one boundary, which is what "one
>    implementation, not one per OS" was asking for.
>
>    **The consequence to record rather than discover:**
>    `original_filename` and `guest_filename` are therefore always
>    **equal**. DRAFT-011 should emit that honestly instead of implying two
>    fields that can differ.
>
>    Two rules from the specification above are deliberately *not* enforced
>    at this boundary, and both are stated where they are enforced instead:
>    a leading `-` is admitted, because every consumer path-prefixes the
>    name so it is never in option position; and Windows reserved device
>    names are admitted, because they are a guest-side hazard that
>    `dirwatch` — which is not told which OS it serves — cannot judge.
>    DRAFT-034 owns the second on the Windows pipeline.
>
> 2. **Ubuntu no longer deviates.** `preconfig-ubuntu.sh` stages to
>    `$GUEST_STAGING_DIR/$RUNFILE` and `drakvuf-ubuntu.sh` executes the
>    same path, both derived by the same rule from the same two `dirwatch`
>    arguments. The SHA-256 leaf was correct while the name still passed
>    through a guest shell and became a deviation once it did not.
>
> **A new pipeline should copy this, not work around it.** The safety
> property it rests on is that the name is never *parsed*: `injector -e`
> and `drakvuf -e` each take it as a single argv element. That is
> established for Linux and **must be re-established for Windows** before
> being relied on — see the `[LINUX]` qualification above.

### Recovery after interruption

A job's state must be reconstructable from disk after a host reboot, not
held only in a running process.

- `status.json` is the source of truth, rewritten atomically at every
  transition.
- Per design rule 3, `domain`, `vlan` and `clone_id` are written with
  `state: cloning` **before** `lvcreate`/`xl restore` runs. A clone that
  exists but was never recorded is unattributable, and unattributable
  clones are what fill a volume group.
- On startup, a sweep visits every non-terminal record: if no live process
  owns it, it becomes `interrupted` with `failure_stage` set to the last
  recorded state, and its recorded `domain`/`vlan` are handed to
  `cleanup.sh` — which already takes exactly those two arguments
  (`cleanup.sh:113-114`).

> **Implementation note — the ID carrier.** `dirwatch` passes its per-run
> `utime` to the preconfig, drakvuf and tcpdump callbacks
> (`dirwatch.c:188,378,398`), and the current scripts ignore it
> (`preconfig-ubuntu.sh:111-117` reads only `$1`–`$7`). So an
> `analysis_id` can reach three of the five callbacks with **no** change to
> the 15-argument contract. `clone-*.pl` and `cleanup.sh` receive only
> domain and vlan (`dirwatch.c:175,214`); reaching those needs either a
> vlan-keyed lookup or a contract change, which is DRAFT-010's decision,
> not this model's.

### Presentation projection (M7 web platform)

The model has to tell the UI what to show at each step, not only what
happened at the end. Two mechanisms:

`display_phase` is a coarse projection of `state`, so user-facing copy does
not churn every time an internal state is refined:

| `display_phase` | `state` |
|---|---|
| Queued | `received`, `admitted`, `queued` |
| Preparing | `cloning`, `preparing` |
| Running | `executing` |
| Finishing | `collecting`, `cleaning` |
| Done | `completed`, `failed`, `rejected`, `cancelled`, `interrupted` |

And the per-state contract the UI reads:

| `state` | Artifacts readable | Terminal | Cancellable | Retryable |
|---|---|---|---|---|
| `received`, `admitted`, `queued` | none | no | yes | — |
| `cloning`, `preparing` | none | no | yes | — |
| `executing` | none (still being written) | no | yes | — |
| `collecting` | none (directory not yet renamed) | no | no | — |
| `cleaning` | all | no | no | — |
| `completed` | all | yes | no | yes |
| `failed`, `interrupted` | partial, preserved | yes | no | yes |
| `rejected` | none | yes | no | no (fix the input) |
| `cancelled` | partial, preserved | yes | no | yes |

A job in `queued` also carries `queue_reason`, so the UI can distinguish
"your turn is coming" from "the host is out of memory" — the second is an
operator signal, not a user one, and the two should not render identically.

Artifacts are unreadable before `cleaning` because the result directory is
built at `.<analysis_id>.tmp` and renamed into place only when complete
(the pattern already drafted at `docs/checklists/android.md:1756-1761`).
A reader therefore never observes a half-written run, and needs no locking
to avoid it.

### What this supersedes

- **Ubuntu's implicit model.** MD5-keyed result directories and a
  two-outcome reading of DRAKVUF's return code (`drakvuf-ubuntu.sh:127`).
  Superseded deliberately, not by oversight: it was never a cross-OS
  design, it predates Android and Windows, and it cannot express a
  cancelled, retried, rejected or interrupted run. Ubuntu keeps behaving
  exactly as it does today until DRAFT-011 retrofits it.
- **The MD5-vs-SHA-256 question.** Decided here, once: SHA-256 is the
  sample key; MD5 survives as an identifier only.
  `docs/architecture/result-schema.md` §3 defers to this section rather
  than answering it separately.
- **The candidate field and state lists** previously in this section, per
  the reconciliation notes above.
- **`docs/checklists/android.md` §4.1 and §7.3's proposals** — adopted in
  substance (the `stage` field, the status vocabulary, atomic writes, the
  temp-directory rename) with three changes, annotated in place at those
  sections: the result directory is keyed by `analysis_id` rather than
  SHA-256, `cleanup_status` is separated from `status`, and `stimulate` is
  a stage rather than a state.
- **DRAFT-014's routing premise.** Sample OS detection no longer decides
  where a sample runs; that entry is now a typing and identification
  contract. Its backlog row records the rescope.

## Architecture decision: keep `dirwatch.c` in C, or move to Python?

> **Decided 2026-08-21 (DRAFT-041): Python.** Not because Python is easier —
> that reason is still rejected — but because the work changed. `sandboxd`
> talks HTTP to a platform API, holds a job state machine, uploads to S3 with
> retry and backoff, and cancels; those are libraries in Python and
> hand-written in C. `dirwatch`'s thread pool and `inotify` watcher are most
> of what is lost, and `inotify` stops being how jobs arrive at all. The
> callback-contract constraint below **holds and is the reason the change is
> survivable**: the five worker scripts do not change. See
> `docs/architecture/platform.md`. The paragraph below is kept because its
> four carried requirements are now `sandboxd`'s to satisfy.

Not decided. Per project rules, do not rewrite merely because Python is
easier — the interface/callers above must be fully documented first
(DRAFT-010), and any replacement must preserve the same callback contract
so `clone-*`/`preconfig-*`/`drakvuf-*`/`cleanup.sh`/`tcpdump.sh` scripts
don't all need simultaneous rewrites.

The state model adds four requirements this decision now has to carry,
whichever way it goes: a cancellation check on the retry branch
(`dirwatch.c:425`), state transitions recorded durably rather than held in
the worker struct, a startup sweep that reconciles orphaned records against
live domains, and — per DRAFT-036 — memory-based admission plus a VLAN
lease that is shared between processes rather than a static per-process
array. That last one is the weightiest: `slots_busy[128]` and
`find_thread()` are the parts of this file that would not survive the
change, and they are also what a rewrite would most obviously replace.
None of these is a reason on its own to rewrite, but a C-side
implementation should be costed against all four rather than just the
first.