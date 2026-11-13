# Sample scope — what is the sample's, and what is not

> **Status (2026-11-12): implemented and unit-tested in the development
> container. Not deployed, never run on Dom0, never run against a guest.**
> The post-processing half was **replayed** over the recorded traces of five
> jobs; the DRAKVUF half and the analysis clock have been exercised by no
> trace at all. Every sentence below about what a guest, DRAKVUF or Dom0
> *does* is read from code, and is unverified until the boxes in
> `docs/checklists/windows.md`, "To confirm on Dom0: the sample-scope work",
> and `docs/checklists/ubuntu.md`, "To confirm on Dom0: the sample-scope
> work", are ticked by a transcript.
>
> **What is committed and what is not, as of this writing.** `3857c8b`
> (2026-11-12) carries the first batch of hook removals and pins the drakvuf
> submodule at `9722578`. Everything else here is in the **working tree
> only**: `sandboxd/` (clock, launcher, network scope, followed processes,
> the second batch of `hooks.txt`), the `drakvuf` submodule (38 files changed
> on top of `9722578`, one new), and the `sandboxd/data/cape-community`
> submodule (15 signature files on top of `56243c85`). Nothing in this
> document is a statement about Dom0 — `docs/CURRENT-STATE.md` §1.2 is.

A job's page answers "what did this sample do". Until 2026-11-12 it answered
"what happened in the guest between the injection and `-t`, in the processes
under the injected one, plus everything on the wire". Those are different
questions, and the difference was measured on a benign installer scoring
**Malicious 8.0**.

This document records where the line is drawn, who drew it, and on what
evidence: the launcher, the wire, the processes the sample takes over, the
clock, and what a hook is allowed to cost.

---

## 1. The evidence, and what it does not cover

**Five jobs the operator ran on 2026-11-12**, their recorded traces analysed
in the development container:

| Guest | Sample | What it showed |
|---|---|---|
| Windows | `SteamSetup.exe`, a benign installer | scored Malicious 8.0 with 24 signatures; needs elevation |
| Windows | a malicious `.js` under WScript | `TlsGetValue` alone made `api_spamming` fire — 1.38 M events |
| Windows | a Quasar RAT client | spent its whole window in key derivation, nine hooked calls per round |
| Ubuntu | a shell dropper | — |
| Ubuntu | a static i386 Mirai-family bot | 0 filetracer records against 245k opens; capa did not finish |

Measured on those traces, with the hook list as it was:

- **apimon produced 0.66–2.0 M events per Windows job, and six trivial hooks
  were 61–81 % of them.**
- **The samples started 37, 45 and 63 s into 120–180 s traces.**
- The benign installer scored 8.0 with 24 signatures.

**A replay is the post-processing re-run over the recorded trace.** It
exercises `cape_plugin` and the signatures against records an older DRAKVUF
and an older hook list wrote. It says **nothing** about the DRAKVUF-side
changes (§7.1), the analysis clock (§5), the finish-time dump (§6) or the
hook list's effect on a live guest (§2) — no trace has exercised any of them.

Replay of the same five traces with every post-processing change:

| Job | Before | After |
|---|---|---|
| `SteamSetup.exe` | 8.0, 24 signatures | **2.8**, 8 behavioural signatures |
| the `.js` | 9.0 | 7.0 |
| Quasar | 8.0 | 4.7 |
| the shell dropper | 6.0, 16 signatures | 6.0, 20 signatures |
| the i386 bot | 6.0, 10 signatures | 6.0, 12 signatures — and **8.0** once its process dump is YARA-scanned |

These figures are the operator's analysis of 2026-11-12, recorded here as
given; the traces are not in the repository and this document reproduces no
output from them.

---

## 2. The hook-list policy

**DECISION (operator, 2026-11-12).** An apimon or libmon hook is removed
**only when no capa rule, CAPE signature or `cape_plugin` processing uses
it**. One that something uses is the operator's call, case by case.
**`no-retval` is the accepted middle option**: the hook reports at entry, one
trap instead of two, and keeps its arguments.

**Why a policy at all.** One Dom0 core saturates per trace
(`docs/CURRENT-STATE.md` §1.2, "Capacity"), and the only lever is fewer
events. But the 2026-11-11 decision was "hot functions no longer excluded",
and a hook list trimmed by frequency alone removes exactly the calls a packer
or a loader is recognised by. So frequency nominates a hook; only "nothing
reads it" removes one.

### 2.1 Windows — `sandboxd/data/hooks.txt`

Removed with the operator's approval. **Committed in `3857c8b`:**

| Hook | Why nothing loses it |
|---|---|
| ntdll `RtlAllocateHeap`, `RtlCopyMemory`, `RtlMoveMemory` | only `optional` terms in two capa rules; 70 % of apimon's events on the `SteamSetup.exe` job (the commit's own figure) |
| the 42 ntdll `Zw*` lines that share an address with an `Nt*` line | DRAKVUF printed one record for the pair, the `Nt` one — the `Zw` line never produced a record of its own |

**In the working tree, uncommitted:**

| Hook | Why |
|---|---|
| kernel32 `TlsGetValue`, kernelbase `TlsSetValue` | **the capa rules "get thread local storage value" and "set thread local storage value" no longer match dynamically** — the cost, stated. `TlsGetValue` made `api_spamming` fire on WScript: 1.38 M events in one job |
| ntdll `RtlImageNtHeader`, `RtlImageNtHeaderEx` | capa "access PE header", which the loader made true of every process |
| kernelbase `GetProcessHeap` | its capa rule is `dynamic: unsupported` |
| `memcmp` in msvcrt and ucrtbase | nothing reads it |

`no-retval` added, same working tree: advapi32 and cryptsp
`CryptCreateHash`/`CryptHashData`, advapi32 `CryptGetHashParam`/
`CryptDestroyHash`, bcrypt `BCryptCreateHash`/`BCryptHashData`/
`BCryptFinishHash`/`BCryptDestroyHash`. A RAT spent its whole window in key
derivation, nine hooked calls per round; these are the hooks of that loop.
Something reads them — `encrypted_ioc` filters on `CryptHashData` — so they
stay, at one trap each instead of two.

Three more edits ride in the same uncommitted diff, none of them a removal:

- `LdrGetProcedureAddress`, `…Ex` and `…ForCaller` type `ProcedureName` as
  **`pansi_string`**, a new apimon argument type (§7.1). **On a DRAKVUF that
  does not know the type the name is printed as the raw value**, as any
  unknown type is (`so-hooks-linux.txt`'s header states the rule) — so this
  line and the binary deploy together or the argument stays a pointer.
- `BCryptCreateHash`'s `pbSecret` and `BCryptHashData`'s `pbInput` go from
  `lpcstr` to `buffer[cbSecret]` / `buffer[cbInput]`: the bytes, by their own
  length.
- A `kernelbase.dll,CreateProcessInternalW` line is added, beside the
  `kernel32.dll` ones that were already there.

**The file's size, for anyone meeting an older figure:** 1,403 hook lines
before `3857c8b`, 1,358 at it, **1,352** in the working tree (lines that are
neither blank nor a comment). `CURRENT-STATE.md` §2b has the superseded
counts.

### 2.2 Linux — `sandboxd/data/so-hooks-linux.txt`

**Committed in `3857c8b`:** libc `read`, `write`, `poll`, `ppoll` removed.
Each is a thin wrapper over the syscall of the same name, which the syscalls
plugin — and filetracer, for the first two — already records; the lines
printed pointers only; no signature, Falco rule or Behaviour bucket reads
the libmon record.

**This reverses part of the 2026-11-11 decision** ("hot functions no longer
excluded") **for these four**, and the file's own header says so, with the
figure: 57 % of libmon's calls on an idle desktop, two traps each. The rest
of that decision stands.

### 2.3 What has not been measured

**Event volume before and after, on the same sample, on a live guest.** The
percentages above are shares of recorded traces. What removing a hook does to
a guest's speed — and therefore to how late the sample starts (§5) — is the
point of the exercise and is unmeasured.

---

## 3. The launch is sandboxd's, not the sample's

**DECISION (operator, 2026-11-12).** On Windows the injected

```
cmd.exe /c PING.EXE -n 5 127.0.0.1 >nul & "<sample>"
```

its `conhost.exe` and the `PING` are **`launcher`** processes. They feed no
signature, no summary, no enhanced event and no capa. They **stay in the
process tree and in the call log**.

**Why.** The shell exists because DRAKVUF arms after it injects
(`analysis-pipeline.md`, "Sample execution: the launch delay"). A shell that
creates a suspended process, writes its parameters and resumes it is every
Windows job: **9 of the benign installer's 24 signatures** were the launch's.
Scoring them scores sandboxd.

The rules, in `cape_plugin/launch.py` (one definition, read by
`trace_split.follow_transfers` and `behaviour.mark_launcher`):

1. **A root is a launcher only when it is the launch's shell *and* started
   the wait.** A sample that happens to be `cmd.exe`, or a job launched
   directly (a name `guests._CMD_UNSAFE` refused), marks nothing.
2. **Then so are the wait and the shell's `conhost.exe`.**
3. **The root `cmd.exe` stays the sample for a `.bat` or `.cmd`** — the shell
   runs those in itself, so that process *is* the sample. Its wait and its
   console host are still marked.
4. **A launcher process a sample process injects into stops being one.** It
   runs the sample's code from then on and is scored whole — the split is by
   process, not by time. `trace_split.launcher_followed` lists them.
5. **A launcher is no source of a control transfer** (§4): what the shell does
   to its child is process creation, sandboxd's doing.

The switch is `skip_launcher` in `CapeConfigSection`
(`sandboxd/postprocessing/plugins/plugin_base.py`), default on. Off scores
them as the sample, as before 2026-11-12.

**Linux has no launcher.** The shell `exec`s the sample, so the injected pid
*is* the sample (`launch_seqids` returns nothing without a wait child).

**Unverified:** that a live trace's `conhost.exe` is the shell's child and
its `PING` command line reads as `guests.py` wrote it — both were true of the
three recorded Windows traces.

---

## 4. The wire, and the processes the sample takes over

### 4.1 `network` is the sample's

**DECISION (operator, 2026-11-12).** `capture.pcap` is the clone's whole
interface; `cape_results.json`'s `network` is the sample's share of it.

`cape_plugin/modules.py`, `Network._drop_background`: a pcap-derived entry —
`hosts`, `tcp`, `udp`, `http`, `tls`, `dns`, `domains` — is dropped when
socketmon or unixsocketmon attribute its peer, or its name, **only to
processes outside the sample**. How many went, per kind, is
**`network.background`**.

**What no plugin attributed to anyone stays.** A flow the instrumentation
missed is still on the wire, and dropping it would turn a hooking gap into a
clean report.

**Why.** The three Windows jobs listed 18 hosts and 11 HTTP requests each,
none a sample process's (the method's own docstring) — a browser's, an
updater's and the resolver's traffic, scored as the sample's.

Two details that decide attribution:

- **The owner is socketmon's `OwnerPID` where it has one** (`Network._owner`):
  a kernel-side send runs in whatever process was current, and NetBIOS from
  System was printed with a console host's PID.
- **Only in `scope: sample`.** With `scope: all` nothing is background.

`tlskeys` is **not** cut: tlsmon hooks lsass, whose records name no client,
so the key file is the whole guest's — as the capture it decrypts is.

### 4.2 Injection into an excluded process is followed

**DECISION (operator, 2026-11-12: "If a sample injects to one of the
excluded processes we should follow that").** A process outside the tree
becomes the sample's from the moment a sample process makes it run code
(`cape_plugin/trace_split.py`, `_WindowsEvidence` and `follow_transfers`).

| Counts as a transfer | The record it rests on |
|---|---|
| remote thread | `NtCreateThreadEx` / `NtCreateThread` whose `ProcessHandle` is not the caller's own |
| queued APC | `NtQueueApcThread`, `…Ex`, `…Ex2` on another process's thread |
| thread context set | `NtSetContextThread`, or `NtSetInformationThread(ThreadWow64Context)` for a 32-bit thread |

**The target is resolved from handles procmon saw**: the syscall record
carries a handle, and procmon prints the handle beside the PID it is of
(`NtOpenProcess`, `NtOpenThread`, `NtCreateUserProcess`) until `NtClose`.
A handle the trace never saw opened — duplicated, inherited,
`NtGetNextProcess` — resolves to nothing and is listed in
**`trace_split.transfers_unresolved`** rather than guessed.

**A write or a section mapping alone never counts.** `NtWriteVirtualMemory`
and `NtResumeThread` on another process are every process creation, and an
executable section mapped into another process is csrss's and svchost's daily
work (32–47 and 6 a job in the recorded traces). Neither runs anything by
itself; where one preceded a real transfer, `how` says so.

**Broker-started children are followed only on an exact command-line match**
— an equality, never a guess:

| The sample… | …then this broker creates a process from exactly that command |
|---|---|
| registered a service (`CreateService*` / `ChangeServiceConfig*`, `lpBinaryPathName`) | `services.exe` |
| ran `schtasks /Create … /TR <command>` | the Schedule service's hosts (`svchost.exe`, `taskeng.exe`, `taskhostw.exe`) |
| ran `wmic process call create <command>` | `WmiPrvSE.exe` |

What was followed, and how, is **`trace_split.followed`**.

> **None of these rules fired on the five jobs.** No sample among them
> injected into anything or used a broker. The evidence is synthetic tests
> only (`sandboxd/tests/test_cape_noise.py`); a real injector is on the
> Windows checklist.

**Not followed, and why** — §8.

---

## 5. The analysis clock

**DECISION (the operator asked for it, 2026-11-12).** On Windows, `timeout`
counts **from the sample's start**, not from DRAKVUF's.

**Why.** Arming ~1,350 usermode hooks slows the guest so much that the launch
is not the five seconds its name says: the samples started 37, 45 and 63 s
into their windows, and the installer — past a UAC prompt — was left 8.5 s
(`sandboxd/tests/test_analysis_clock.py`'s opening). `LAUNCH_DELAY` was built
to trade "a few seconds at the end of the window for the whole beginning of
it"; on Windows the trade had become most of the window.

**How** — `sandboxd/guests.py` and `sandboxd/stages.py`:

1. **`-t` is the ceiling**: the job's `timeout` plus `guests.LAUNCH_SLACK`
   (**90 s**, `TraceOptions.launch_slack`). `timing.budgets` raises the trace
   phase guard by the same amount.
2. **sandboxd reads `trace.log` as it is written** (`Analysis._await_trace`,
   every 0.5 s) for the record that says the sample started
   (`guests.sample_start_marker`): **procmon's `NtCreateUserProcess` line
   naming the sample's file**. An executable is the image; a script is an
   argument of its host's command line; the file *name* is in both.
3. **`timeout` seconds after that record is read, sandboxd sends DRAKVUF
   SIGINT** (`proc.Child.interrupt`). **SIGINT and not SIGTERM**: on SIGINT
   DRAKVUF leaves its loop and stops its plugins as it does when `-t` runs
   out; on SIGTERM `main.cpp` returns before `stop_plugins`, so whatever a
   plugin does when it is stopped — §6's dumps among it — never happens.
4. **A sample never seen runs to the ceiling**, and the job's notes say
   `the sample was not seen to start: traced for <timeout+90>s from DRAKVUF's
   start`.

Properties worth knowing before reading a trace's length:

- **The start is when the record was *read***, at most a poll and DRAKVUF's
  output buffer after it was written. That only lengthens the window.
- **A creation that fails starts the clock too** — elevation required, then
  UAC. The sample was run; the retry is inside the window.
- **A name JSON would escape is not looked for**, and a job without `procmon`
  writes no such record: both run to the ceiling with the note.
- **The trace still runs up to `PLUGIN_STOP_WAIT` (30 s) past the interrupt**,
  as it always has past `-t`.
- **Ubuntu and Android keep DRAKVUF's own clock** (`launch_slack` 0, no row in
  `guests._SAMPLE_START`). Their launch `exec`s after a `sleep`, their runs
  are the evidenced ones, and nothing measured a late start there.

**This supersedes the fourth property of the launch delay** as it stood from
2026-10-02 — "`drakvuf -t` is not raised to compensate" — for Windows only.
`analysis-pipeline.md` is corrected in place; `CURRENT-STATE.md` §2b carries
the row. The comment above `LAUNCH_DELAY` in `sandboxd/guests.py` still
argues the old position and is stale for Windows.

**Unverified, all of it.** `_await_trace` has run against a fake child in
`test_analysis_clock.py` and against no DRAKVUF. In particular: that the
marker's three byte strings appear on one line of a real `trace.log` as
`"Plugin":"procmon"`, `"Method":"NtCreateUserProcess"` and the name; that
DRAKVUF flushes that line within seconds rather than a buffer later; and that
a SIGINT'd DRAKVUF exits 0 with its plugins stopped.

---

## 6. What is still running at the end is dumped

**DECISION (operator, 2026-11-12).** `--procdump-new-processes-on-finish` is
passed with `procdump2` on **every guest** (`guests.argv_trace`).

**Why.** Without it only the *injected* process is dumped at the end
(`main.cpp` sets `procdump_on_finish` to the injected pid). On
Windows that is the launch's `cmd.exe` and the sample is its child; on Linux
a bot's workers outlive the process that was injected. So the one process
worth a dump was the one never dumped — a RAT and a bot, 2026-11-12. Every new
process of the guest is dumped; only the sample's are uploaded
(`sandboxd/postprocessing/procdumps`).

> **The caveat, and the first thing to check on Dom0.** In the three Windows
> jobs of 2026-11-12 **not even the injected process was dumped at the end**:
> no finish-time procdump record and no finish-time file exists in any of
> them, only `TerminateProcess` dumps. So whether finish-time dumps complete
> inside `--wait-stop-plugins` (`PLUGIN_STOP_WAIT`, 30 s) at all is
> **unknown**, and this flag asks for more of them. If they do not, the flag
> changes nothing and the fix is elsewhere.

On Linux the fork's procdump2 did not dump at finish at all; §7.1 adds it.

---

## 7. Defects fixed without a specific confirmation

The operator asked for the defects the five traces showed to be fixed. These
are **implemented, unit-tested where the list says so, and unverified on a
guest** — the same status as everything above, without a decision behind each.

### 7.1 The DRAKVUF fork

Uncommitted in the `drakvuf` submodule on top of **`9722578`**, which is
pushed and is what `3857c8b` pins. `9722578` itself has: ebpfmon falls back
to `__sys_bpf`; libmon and procdump2 treat a Linux process as ended at its
last thread.

**syscalls plugin**

| Defect | Fix |
|---|---|
| Linux x64: the 4th syscall argument was read from `rcx` — `renameat2`'s `newpath` printed `H=`, `mmap`'s flags and `openat`'s mode were garbage | read from `r10`; `syscall` puts its return address in `rcx` |
| Windows: `StubSyscall` was compared with `KTHREAD.SystemCallNumber`, which is stale on a thread's first win32k syscall — **`indirect_syscall` fired on every job with a GUI thread** | compared with the service the kernel dispatched, every entry of a folded routine |
| a module no file backs printed `"(null)"` | prints `""`; "could not be looked up" and "unbacked" are now different |
| 27 Linux syscalls printed no arguments (`execve`'s filename, `clone`, `pipe2`, `splice`, `prlimit64`, …) | arguments from the kernel's prototypes. **A failed exec leaves no other trace of what was tried** — procmon's hook is past the binary format's check |
| `prctl(PR_SET_NAME)` printed a pointer | prints the name |

**filetracer, fileextractor, memdump**

| Defect | Fix |
|---|---|
| 32-bit processes were invisible: **0 filetracer records against 245k opens** of the i386 bot | all three also hook the compat dispatcher (`plugins/helpers/linux_compat_syscall.h`, new) |
| fd paths lacked their mount: `/null` for `/dev/null` | mount-aware paths, as the kernel resolves them |
| a relative path said nothing of what it was relative to | a `Cwd` field on relative paths |
| fileextractor "extracted" sockets, pipes and character devices as `unknown_fd_N` | skipped by inode type |
| `--fileextractor-exclude-list` was ignored on Linux | honoured |

**Elsewhere**

- apimon: a new argument type **`pansi_string`** (§2.1).
- Windows: a file name resolved from a handle carries its device —
  `\Device\HarddiskVolume2\…`, the name the kernel keeps for an image.
- Linux procdump2 dumps at finish, as Windows does (§6).

### 7.2 `cape_plugin`

All under `sandboxd/postprocessing/plugins/cape_plugin/` unless named.

- **Syscall origin** (`syscall_origin.py`): a guard that reads `StubSyscall`
  against `Syscall`/`Module`, knows the 32-bit kernel32/KernelBase WoW64
  thunks, and reads `"(null)"` as older DRAKVUF's empty string — so traces
  from before §7.1 stop firing `indirect_syscall` too.
- **An API call is never folded into the kernel record before it**
  (`compare_calls`).
- **`status` is real** for `Nt*`/`Zw*`/`Ldr*` API calls, nt syscalls and
  libc's `-1`.
- **Linux summary and enhanced events**: relative paths resolved against the
  tracked working directory; rename's shape; failed calls; deleted logs under
  `/var/log`.
- **Fork children inherit the parent's name** (`sandboxd/postprocessing/process_tree.py`).
- **Exit codes only for processes that exited.**
- **PE entry point as an RVA** (`static.py`), as the sections' addresses
  beside it are.
- **Network**: socket records use `OwnerPID`; behaviour and wire connections
  are listed once; DNS names asked over a raw socket are recorded
  (`network_map.py`); ICMPv6 housekeeping is not listed (`pcap.py`).
- **capa is bounded**: at most `REPEAT_CAP` (64) identical calls per thread
  are fed, the rest counted. The largest `count()` any rule in
  `sandboxd/data/capa-rules` asks for is 48. `statistics.capa` says whether
  capa completed and over how many calls — an empty `capa_summary` alone
  reads as "no capabilities".
- **Compressed process dumps are YARA-scanned**, and CAPE's own YARA rules are
  loaded (`cape_yara`).
- **Target type and package from the file's own bytes** when libmagic is
  absent (`filetype.py`): until now an empty type fell back to the guest's,
  so a `.js`, a `.sh`, a 32-bit PE and an i386 ELF were all 64-bit
  executables.
- **Process-handle tracking adds `ProcessId`** to calls that carry only a
  handle.
- **Call marks capped at 100 per signature** (`call_marks` holds the total):
  `encrypted_ioc` wrote 56,534 marks into one report.
- **`run`/`on_complete` signature failures are recorded** in
  `statistics.signature_failures`, beside the `on_call` ones.
- **`similarity_match` disabled by default**: it needs a family database that
  is not here and raised on every job.
- **`write_keys` needs a write.**
- **Cut regmon records are rejoined** (`trace_split.joined`).
- **Falco coverage per rule.**
- **Device-named paths are normalised to the drive in the summary**, so the
  file §7.1 now names `\Device\HarddiskVolume2\x` is listed once as `C:\x`.

The result keys these add are in `result-schema.md` §4.1a.

### 7.3 Signatures

In `sandboxd/data/cape-community` (our fork `evilbootloader/community`,
branch `stable`), uncommitted. `falco-rules.md` covers the Falco rule set, not
these, so the Linux list lives here.

**New, Linux:**

| Signature | Note |
|---|---|
| `linux_download_execute_loop` | |
| `linux_exec_format_error_loop` | |
| `linux_masquerade_daemon_name` | |
| `linux_download_spoofed_user_agent` | |
| `linux_download_ip_literal_port` | |
| `linux_self_rename` | |
| `linux_alternative_dns_root` | |
| `linux_dns_resolver_rotation` | |
| `linux_proc_killer_scan` | |
| `linux_process_name_masquerade` | **cannot fire until a guest runs the new DRAKVUF**: it reads the name `prctl(PR_SET_NAME)` now prints |

**Fixed, Linux:** `linux_chmod_then_exec`,
`linux_execution_from_unusual_path`, `linux_daemonize`,
`linux_antidebug_procfs_checks`, `linux_argv0_spoofing`,
`linux_single_instance_lock` (and the shared `ip_kind` helper),
`linux_user_discovery`, `linux_rwx_memory`.

**Fixed, both:** `stealth_network`.

**Fixed, Windows:** `reads_memory_remote_process`, `encrypted_ioc`,
`amsi_enumeration`, `suspicious_ntdll_disk_load`, `dynamic_function_loading`.

---

## 8. Known, and not fixed

| Gap | What it would take |
|---|---|
| **The UAC prompt costs about a minute** on any sample needing elevation | a golden-image setting; the clock (§5) starts at the first, failed creation, so the minute comes out of the window |
| `mountpoint_manager_access` and `discover_registry_mount_points` fire on a real installer | nothing — it is true behaviour. A severity question, to settle against benign-run data |
| **Windows fileextractor names are not device-prefixed**, unlike handle-resolved names elsewhere (§7.1) | `sandboxd/data/fileextractor-exclusions.txt` is anchored on volume-relative names; prefix the names and the list stops matching. Change both together |
| **Children started through COM are not followed**: `IWbemServices::ExecMethod` (PowerShell, a script's `GetObject`), `ITaskService`, `ShellExecute` via explorer or DllHost | a record naming the command. None exists; §4.2's rule is an equality and has nothing to compare |
| `socketcall` is not decoded in the syscalls plugin | by design: network belongs to unixsocketmon. Recorded so an i386 sample's bare `socketcall` records are not read as a defect |
| **python-magic is absent from Dom0's sandboxd environment** — it is in `platform/requirements.txt` only, not `sandboxd/requirements.txt` | `filetype.py` (§7.2) answers instead, knowing far less than libmagic. Adding the dependency also needs the system library (`docs/checklists/platform.md` records that trap for the platform) |
| **`clock_gettime` was 58 % of all syscalls** in the first Linux job: the vDSO fell back to a real syscall (records show `FromModule` `[vdso]`); no `clocksource=` on the Xen or guest command line | a guest setting to test. **Interaction with the RDTSC work is unknown** — the guests keep the `xen` clocksource on purpose (`rdtsc-poc.md` §1.1), so this is not a setting to change by reflex |
| **`-S` syscall filters do not avoid traps** in this fork's dispatcher / kernel-sysret mode: one breakpoint sees every syscall and the filter only decides what is printed | DRAFT-052, `ideas.md` and a comment in `sandboxd/guests.py` assume the filter removes entries, and runbooks 09 and 12 recommend it on that ground — written when each syscall had its own breakpoint. Under the dispatcher hook it removes *records*: the lookup that applies the filter runs inside the trap. Those three are not corrected by this change; `CURRENT-STATE.md` §2b carries the row |
| **Nothing was run under Python 3.12**, Dom0's version; the container has 3.14 | the suite under a 3.12 interpreter before deploying — 3.14's lazy annotations have already hidden one `NameError` from this container (`f373dc6`) |

---

## 9. Where this is checked

- Unit tests, in the development container: `sandboxd/tests/test_analysis_clock.py`,
  `test_cape_noise.py`, `test_cape_signatures_linux.py`,
  `test_cape_signatures_linux_rules.py`, `test_syscall_origin.py`.
- A replay over five recorded traces (§1) — post-processing only.
- **On Dom0: nothing yet.** `docs/checklists/windows.md` and
  `docs/checklists/ubuntu.md` list what to confirm, each with the observable
  that proves it.
- What went wrong on the way is in `docs/TROUBLESHOOTING.md`, symptom-first:
  "A benign program scores Malicious", "Every Windows job fires
  `indirect_syscall`", "The sample did almost nothing in the trace window",
  and the entries beside them.
