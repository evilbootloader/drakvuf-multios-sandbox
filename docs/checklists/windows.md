# Windows DRAKVUF Automated Analysis — Implementation Checklist and Command Log

> **Status: current target. The pipeline has run end to end; this file does
> not yet record how.** Windows is one of the project's three current OS
> targets alongside Ubuntu and Android — not a deferred planning exercise.
>
> **Updated 2026-09-17 (DRAFT-034, closed).** The sentence above used to read
> "the golden VM exists; no automation does", and both halves of that are now
> out of date: `sandboxd` carries the Windows rows, and **a job ran through the
> pipeline — operator-confirmed for 2026-09-05, with no transcript kept.**
> `shellexec` is the working injection mode; `createproc` was tried in
> `25e5fc6` and reverted six minutes later in `48ee57d`.
>
> **2026-11-11: the network step is the exception.** It runs `createproc` from
> `services.exe` (`SANDBOXD_INJECTION_PID_WINDOWS_NETCFG`), because from
> explorer.exe `netsh` needed elevation, failed silently, and no Windows clone
> had an address. The sample still `shellexec`s from explorer.exe.
> TROUBLESHOOTING, "A Windows clone has no network in any egress mode".
>
> **Every box below nevertheless stays unchecked, and that is not an
> oversight.** This file's standard is `android.md`'s — a box is ticked by a
> transcript, not by a report — and what closed DRAFT-034 was a report. The
> specific things still missing are a Windows runbook, the per-plugin
> validation matrix, a verbatim `injector --help` capture of Windows
> injection semantics, the PID/TGID record across three boots (4696 is
> recorded once), and an answer on licensing for clone-per-run. **Until the
> matrix exists, "the job completed" is not "the four plugins produced
> output"** — `syscalls` degrades to silence rather than to an error when the
> symbol JSON is partial.
>
> **Operator-reported 2026-08-21, not yet backed by command output:**
> the golden `windows` domain is installed as a Xen HVM, Microsoft Defender is
> disabled, and the LV has been cloned to `windows_sandbox`.
>
> **Corrected 2026-09-04.** This block previously said `misc/windows_sandbox.cfg`
> did not exist and no PDB had been fetched. Both were overtaken by work on
> 2026-09-01 that landed without a checklist sweep:
>
> - `misc/windows_sandbox.cfg` **exists** (`f0b44a3`), and carries
>   `cpus = "16-27"` — see the note under Project status, because that file is
>   not covered by `scripts/gen-xen-configs.py`.
> - The **kernel GUID has been read**: `windows_symbols.md` at the repository
>   root records a real `vmi-win-guid domid 52` run, PDB GUID
>   `72c69e726c648bc18257af38fa78a2f21`, plus the exact `pdbconv.py` line that
>   would produce `profiles/windows.json`. Whether that conversion was ever
>   run is **not** evidenced — `profiles/` is untracked.
> - That output also reads **64-bit Windows 10**, not the Windows 11 the
>   baseline row below plans for.
> - The guest software build is largely done and is recorded in
>   `.github/issue-drafts/in-progress/DRAFT-020.md`, not here, because none of it is
>   backed by a transcript either.
>
> No Windows *automation* has been built, so the pipeline checklist is still
> empty; the difference from "skeleton only" is that the track is open and
> its design constraints are already fixed (see "Inherited contract" below).
>
> This file intentionally contains no invented commands, configs, or
> evidence — populate it only from real work, following the same discipline
> as `android.md` (Existing vs. Candidate, evidence before checking a box).
>
> **DRAFT-034 is the track head.** It supersedes DRAFT-020's design half;
> the VM-lifecycle question DRAFT-020 existed to answer is closed
> (clone-per-run, by elimination). Roadmap milestone M5 still names this a
> "planning spike" — that framing is what changed, and the roadmap now says
> so.

---

## Project status

| Field | Value |
|---|---|
| Golden domain | TBD |
| Sandbox domain | TBD |
| LibVMI profile | TBD |
| Volume group | TBD |
| Analysis bridge | TBD |
| Saved state | TBD |
| Windows baseline (version/build) | **Direction was Windows 11 first, Windows 10 as fallback** (2026-08-19). What is actually installed reads **64-bit Windows 10** (`windows_symbols.md`, 2026-09-01), so the fallback is what exists. Kernel PDB GUID `72c69e726c648bc18257af38fa78a2f21` |
| VM lifecycle model | clone-per-run (current Ubuntu/Android model) — decided by elimination: snapshot-restore (DRAKVUF Sandbox's model) does not work in the nested Xen-inside-Proxmox setup this project used until 2026-08-28, since `xl save`/`xl restore` leaves the base and cloned disk images read-only. **Not re-tested on bare metal**; the decision stands on its own merits regardless — see roadmap "Architecture decisions needing experiments" |
| Current phase | Phase 0, **with the pipeline already working ahead of the paperwork.** Golden VM installed 2026-08-21, `windows_sandbox.cfg` written 2026-09-01, kernel GUID read 2026-09-01, guest software largely installed (DRAFT-020), `sandboxd` Windows rows landed and **one analysis run end to end 2026-09-05 (operator, no transcript)**. The phase stays 0 because phases here advance on recorded evidence, and none of that run was recorded |
| Current blocker | **Writing down the run that already happened.** A Windows runbook, following `docs/runbooks/07-verify-android-mvp.md`'s shape, is what turns 2026-09-05 from a report into evidence and unblocks every box below. After it: the per-plugin validation matrix (DRAFT-050), the three-boot PID/TGID record for anchor 4696, and licensing for clone-per-run. `profiles/windows.json` must exist — the run needed it — but it is untracked, so nothing here can state which build it covers. *(This row previously read "no execution evidence"; that was true until 2026-09-05. The older note it carried — "no `preconfig-`/`drakvuf-`/`run_analysis-windows` script and no `pipeline-windows.env`" — refers to per-OS script files that no longer exist for any guest; see `docs/architecture/automation-files.md`.)* |

### Concurrency constraint — read before running a Windows analysis

**Read both, but only the second still binds.** Two constraints stacked
here; the first was removed by the 2026-09-15 deletion and the second is the
dangerous one and is still open:

1. `dirwatch` derived each clone's VLAN from a process-local worker-slot
   index, so two watchers collided on VLANs, gateway addresses and isolation
   rules. **This constraint is gone as of 2026-09-15**: there are no
   per-OS launchers, and one `sandboxd` allocates every VLAN from one
   in-process table (`sandboxd/resources.py`), so a Windows job and an Ubuntu
   job on the same host is exactly the case it was built for. The guard that
   remains refuses to start alongside a leftover `dirwatch` binary.
2. Even without the collision, admission is greedy, and greedy admission
   starves the largest clone. A Windows clone costs **6294 MiB** (`memory =
   6144` plus the per-host domain overhead) against Ubuntu's and Android's
   **4246 MiB** (2198 when this was measured; the templates went to
   `memory = 4096` on 2026-08-29 — `CURRENT-STATE.md` §2b). Measured on Dom0
   2026-08-20: 170 consecutive admission holds, zero clones for the large job,
   seven smaller jobs completing meanwhile. **The gap narrowed and the
   starvation did not go away** — a 6294 MiB job still waits behind two 4246s
   on a 20317 MiB pool.

**The failure mode is not an error.** It is one admission-hold line per
second, forever, with no clone and nothing in the logs to explain it. Every
individual decision is correct.

Fixed by DRAFT-041's head-of-line reservation, not before. Until then, run
Windows alone.

### The launch delay, and the one place a filename reaches a guest shell

**Added 2026-10-02, unvalidated on the Windows guest.** The trace no longer
`ShellExecuteEx`es the sample directly. It runs

```
cmd.exe /c C:\Windows\System32\ping.exe -n 5 127.0.0.1 >nul & "<staged sample>"
```

because DRAKVUF arms its plugins *after* injecting, so a sample launched
directly runs its first seconds with nothing hooked — the full reasoning is in
`docs/architecture/analysis-pipeline.md`, "Sample execution: the launch delay".
`ping` rather than `timeout /t`, which aborts with "ERROR: Input redirection is
not supported" when it does not own a console.

Three things that make this guest different from the other two, all of them
consequences of `cmd.exe`:

1. **The injected process is `cmd.exe`, not the sample.** Linux `exec`s, so
   there the sample keeps the injected pid; Windows cannot, so `inject.log`
   reports cmd's pid and name and `report.json`'s `startup.process` resolves
   to it, with the sample as its child. The child's creation is now *inside*
   the traced window, which it was not before.
2. **The staged filename is spliced into a command string.** The only such
   place in `sandboxd/guests.py`: `/c` takes one string it re-parses and `%1`
   in a batch file is substituted before parsing, so the
   `sh -c '…' sh "$1"` idiom the Linux guests use has no equivalent. A name
   containing any of `"%&<>|^!` (`guests._CMD_UNSAFE`) is therefore launched
   the old way — directly, no wrapper, no delay — keeping its bytes and its
   analysis. **A mechanism rather than a quoting trick would close this
   properly**: a process created suspended and resumed after
   `start_plugins()`, which is a change to the fork's injector.
3. **A console window exists** for the trace's duration. Ordinary for Windows,
   and a more plausible parent than the anchor process, but it is a difference
   from the previous behaviour and a sample can see it.

What a run must confirm, and nothing here can: that `ping.exe` is at that path
and reachable from the injected `cmd.exe`, that the sample is created at all
(if the command line is malformed, `cmd` exits and **the trace completes having
run no sample**), and that five pings is longer than arming with `apimon`'s
hooks going in (1,352 lines in the working tree's `hooks.txt`, 2026-11-12).

**The last of those was answered on 2026-11-12, the other way round.** Five
pings were not too short; the launch was far too long. Recorded traces of
three jobs showed the samples starting 37, 45 and 63 s into 120–180 s traces,
because a guest having its hooks placed is slow at everything, the wait
included. Raising `LAUNCH_DELAY` would have made that worse. What changed
instead, **in the working tree and unvalidated on this guest**:

- **The analysis clock starts with the sample.** `-t` is the timeout plus
  `guests.LAUNCH_SLACK` (90 s) and sandboxd interrupts DRAKVUF `timeout`
  seconds after procmon records the sample's creation.
- **`cmd.exe`, its `conhost.exe` and the `ping` are marked `launcher`** and
  scored as sandboxd's, not the sample's — point 1 above, taken to its
  conclusion. A `.bat`/`.cmd` keeps its `cmd.exe` as the sample.
- **Hooks nothing reads were removed**, and the hash-loop hooks report at
  entry only.

`docs/architecture/sample-scope.md` has the decisions; the boxes are below.

### To confirm on Dom0: the sample-scope work

**Added 2026-11-12. Nothing here has run on Dom0 or against this guest.** The
code is in the development container's working tree — not committed, not
deployed; `docs/architecture/sample-scope.md` is its design record. Each box
names the observable that ticks it. A box is ticked by pasted output, as
everywhere in this file.

**Before any of them means anything**, the job must have run on the new
code, and that is three separate deployments: the `drakvuf` submodule rebuilt
(`make sandboxd`; provenance per `CURRENT-STATE.md` §1.2, "DRAKVUF
provenance" — the banner does not say), this repository's `sandboxd/` with
its `hooks.txt`, and the `cape-community` submodule. A job on the old binary
with the new post-processing ticks only the boxes marked *(post-processing)*.

**Where the observables are.** `cape_results.json`, `trace.log.gz`,
`trace.stderr`, `manifest.json` and `procdumps/` are the job's uploaded
artifacts. Dom0's own copy under `/var/lib/sandboxd/results/<job>` is deleted
after upload unless the daemon runs with `SANDBOXD_KEEP_RESULTS=1`, which is
the easier way to look.

**First, because the rest depends on it:**

- [ ] **A finish-time procdump exists at all.** In the three jobs of
  2026-11-12 none did — not even of the injected process — only
  `TerminateProcess` dumps. Observable: a `"Plugin":"procdump"` record with
  `"DumpReason":"FinishAnalysis"` in the trace, and its file in `procdumps/`.
  If there is none, note how long DRAKVUF ran past the end of the trace
  against `--wait-stop-plugins 30` and what `trace.stderr` says: the next
  box cannot pass and the cause is not the new flag.
- [ ] **The sample's own process is dumped at the end**
  (`--procdump-new-processes-on-finish`). Observable: a sample still running
  when the trace ends has a `FinishAnalysis` record naming *its* PID — not
  `cmd.exe`'s — a file in `procdumps/`, an entry in `manifest.json`, and an
  entry under `procdump` in `cape_results.json` with `scanned_size` set.

**The analysis clock:**

- [ ] **The trace ends `timeout` seconds after the sample started.**
  Observable: in `trace.log.gz`, the `TimeStamp` of the last record minus the
  `TimeStamp` of procmon's `NtCreateUserProcess` record naming the sample's
  file is between `timeout` and `timeout` + 30 s (`PLUGIN_STOP_WAIT`) plus a
  few seconds of read lag; `manifest.json`'s `notes` and `trace.stderr` say
  nothing of a sample not seen to start.
- [ ] **DRAKVUF, interrupted, stops its plugins and exits cleanly.**
  Observable: no `drakvuf exited N` in `notes`; `extracted.zip` and the
  finish-time dump are present as on a job that ran to `-t`.
- [ ] **The marker matches a real record.** It is three byte strings on one
  line: `"Plugin":"procmon"`, `"Method":"NtCreateUserProcess"` and the file
  name, with no space after the colons. Observable: the box above passing is
  the proof; a job that always carries `the sample was not seen to start:
  traced for <timeout+90>s` while the sample visibly ran is this failing.
  Check a `.js` or `.ps1` as well as an `.exe` — a script is named in its
  host's command line, not as the image.
- [ ] **A sample that never starts runs to the ceiling and says so.**
  Observable: the note above, on a job whose launch was made to fail.
- [ ] **A job cancelled mid-trace still stops.** `_await_trace` owns the wait
  now. Observable: the clone is gone and the job is `cancelled` within the
  usual grace.

**What the report calls the sample's** *(post-processing)*:

- [ ] **`behavior.processes` marks exactly `cmd.exe`, `conhost.exe` and
  `PING.EXE` as `launcher`**, and nothing else, on an `.exe` job. On a `.bat`
  job the root `cmd.exe` is not marked and the other two are.
- [ ] **A benign GUI installer no longer scores Malicious.** Observable: the
  score and signature list of `SteamSetup.exe` beside the replay's 2.8 and 8
  signatures (`sample-scope.md` §1). A live run differs from the replay by
  the DRAKVUF changes and the hook list, so the number may differ; no
  signature should name a launcher process.
- [ ] **`network.background` is non-empty and no browser or updater host is
  listed** as the sample's, on a job whose sample makes no traffic of its own.
- [ ] **A sample that really injects is followed.** None of the five jobs
  exercised this; the rules have synthetic tests only. Observable:
  `trace_split.followed` names the target with `how`, the target's calls are
  in the call log, and `trace_split.transfers_unresolved` is empty or
  explained. One sample per mechanism: remote thread, queued APC, thread
  context set; and one per broker: a registered service, `schtasks /Create
  /TR`, `wmic process call create`.

**The DRAKVUF fork** (needs the rebuilt binary):

- [ ] **No `indirect_syscall` on a benign GUI program.** It fired on every job
  with a GUI thread. Observable: the signature absent from `SteamSetup.exe`'s
  report, and no syscall record whose `StubSyscall` differs from its service
  on a thread's first win32k call.
- [ ] **A handle-resolved `FileName` carries its device**
  (`\Device\HarddiskVolumeN\…`), **and the summary lists each file once**, as
  `C:\…`. Observable: both forms of one file in the trace, one entry in
  `behavior.summary`.
- [ ] **`LdrGetProcedureAddress`'s `ProcedureName` is printed as text**
  (`pansi_string`), not as a pointer. Observable: an apimon record with a
  function name in that argument. A pointer there means the hook list and the
  binary were deployed apart.
- [ ] **An unbacked module prints `""`, not `"(null)"`.**

**The hook list:**

- [ ] **apimon event volume, before and after, on the same sample.** The
  measurement the removals rest on is shares of recorded traces (0.66–2.0 M
  events a job, six hooks 61–81 % of them). Observable: `apimon` record
  counts for `SteamSetup.exe` under the old list and the new, and the second
  at which the sample starts in each — the figure that says whether the
  guest got faster, which is the point.
- [ ] **Nothing still expected went missing.** Observable: the capa rules
  named in `sample-scope.md` §2.1 as lost are the only ones lost between the
  two runs.

**The environment:**

- [ ] **The first job after deployment runs under Python 3.12 without a
  traceback.** Nothing was run under 3.12; the container has 3.14, whose lazy
  annotations hid a `NameError` from it once already (`f373dc6`).
  Observable: the daemon's stderr for that job, and
  `statistics.signature_failures` in its `cape_results.json`.

Candidate, for the clock box — run against a kept results directory or a
downloaded `trace.log.gz`; unproven here, and `<name>` is the sample's file
name:

```bash
# DOM0 -- Candidate
zcat /var/lib/sandboxd/results/<job>/trace.log.gz \
  | grep -a '"Plugin":"procmon"' | grep -a '"Method":"NtCreateUserProcess"' \
  | grep -aF '<name>'
```

Expect at least one line; the first is the one the clock started on, and its
`TimeStamp` is what to subtract from the last record's. Several are a creation
that failed and was retried (elevation). **No line while the sample visibly
ran means the marker cannot match either** — paste the procmon record that
does name the sample.

### Inherited contract (issue #6, 2026-08-10)

The Windows guest is not designed from scratch. It must satisfy the
conformance checklist **C1–C10** in
`docs/architecture/analysis-pipeline.md`, "Shared and per-OS code
boundary" — no forked copy of any shared code, and per-OS values supplied
as data rather than as branches.

> **C1's file set is superseded (2026-09-15).** It asked for four per-OS
> files; there are none. A guest is a `TargetOs` member plus its rows in
> `sandboxd/guests.py` and `sandboxd/stages.py`. The rule C1 was defending
> is unchanged and is what matters here: **do not add an OS branch to shared
> code — add a value to the per-OS table.**

Four consequences worth knowing before Phase 0 starts, because each closes
off a design option that would otherwise look open:

- **Delivery is decided.** `injector -m writefile`, `-B` Dom0 source, `-e`
  guest destination, one injection, no guest shell beforehand. There is no
  HTTP path to choose and no fallback to build.
- **The staging directory must already exist in the saved image**, and must
  permit the execution method Windows uses. Both need testing on the guest,
  not reading off a path — the Android evidence
  (`docs/checklists/android.md`, "Staging directory") is the worked example
  of a path that satisfies one and silently fails the other.
- **No in-guest collection.** No Windows equivalent of `logcat`/`dmesg` may
  be introduced; output comes from introspection and the pcap.
- **`drakvuf -e` being execve-direct is a `[LINUX]` finding — do not
  inherit it.** Issue #2 established that `-e` invokes no guest shell, so a
  filename cannot dereference guest-side. `injector --help` qualifies that
  as `[LINUX] (execproc -> execve(...); 64bit only)`. Windows execution has
  not been read, and the single-argv rule in
  `docs/architecture/analysis-pipeline.md` is a security property rather
  than a convenience, so it must be re-established against the Windows
  injection method before anything relies on it.
- **`CLONE_LV_SIZE` is per-OS** and Windows is the reason it exists as a
  variable: `-L64G` is hard-coded today and a Windows golden LV is unlikely
  to want it.

`tlsmon` remains the one item where Windows *gains* capability the other
targets lack — it hooks `ncrypt.dll`/Schannel and has no Linux hook path,
making it the project's only working TLS-visibility route (DRAFT-023).

### Status legend

- [ ] Not started
- [x] Completed and evidenced
- `BLOCKED:` Waiting on a dependency or unresolved fault
- `SKIPPED:` Deliberately excluded, with reason recorded

---

# Phase 0 — Planning spike (M5)

- [ ] Select a specific supported Windows baseline (version/build).
  **Direction set 2026-08-19: try Windows 11 first, Windows 10 as the
  fallback.** The exact build still has to be recorded, because §0.1's
  profile step is keyed to one kernel GUID. See §0.2 for the install
  constraints to expect.
- [x] Decide golden-VM lifecycle model — **clone-per-run, decided by
  elimination** (roadmap "Architecture decisions needing experiments" #3;
  the status table above records the same). Snapshot-restore was not viable
  in the nested Xen-inside-Proxmox setup used until 2026-08-28, so there was
  never a Windows-specific choice to make. What remains is confirming clone-per-run
  works against a Windows guest specifically — DRAFT-034, not this item.
- [ ] Determine profile/symbol requirements for the selected baseline.
  **Procedure recorded in §0.1 (Candidate).** It is volatility3's
  `pdbconv.py` keyed on the kernel PDB GUID — not `dwarf2json`, which was
  the open unknown DRAFT-034 raised. What remains for this item is running
  it against the chosen build and settling §0.1's `-r` vs `libvmi.conf`
  question.
- [ ] Determine injector target and plugin compatibility for Windows guests.
- [ ] Scope the first Windows sample type (PE executable, per the roadmap's
  "do not support every sample type in the first milestone" guidance).

---

## §0.1 — Profile toolchain

**Status: Candidate. Nothing below has been run on this project's Dom0.**
Recorded 2026-08-19 from upstream DRAKVUF documentation, which discharges
DRAFT-034 PLAN step 2's requirement to establish this *from primary
sources rather than by analogy* — the answer was genuinely not derivable
from what this repository already does.

**It is neither `dwarf2json` nor `drakpdb`.** Ubuntu and Android profiles
come from `dwarf2json` against kernel DWARF, which has no Windows
equivalent. The Windows path is **volatility3's `pdbconv.py`**, driven by
the kernel's PDB GUID.

Step 1 — get the GUID and kernel filename from the running domain:

```bash
sudo vmi-win-guid name <domain>
# The two fields that matter:
#   PDB GUID:        684da42a30cc450f81c535b4d18944b12
#   Kernel filename: ntkrpamp.pdb
```

Fallback, if `vmi-win-guid` cannot find the kernel in memory — read it off
the disk instead:

```bash
sudo su
kpartx -a /dev/<vg>/<windows lv>
mount -o ro /dev/mapper/<vg>-<lv>p1 /mnt
python3 tools/pdbguid.py /mnt/Windows/System32/ntoskrnl.exe
umount /mnt
kpartx -d /dev/<vg>/<windows lv>
```

Step 2 — generate the profile:

```bash
python3 ~/drakvuf/volatility3/volatility/framework/symbols/windows/pdbconv.py \
    --guid <PDB GUID> -p <kernel filename> -o windows.json
```

Step 3 — **open question, do not copy the upstream step blindly.** Upstream
then registers the profile in `/etc/libvmi.conf`:

```bash
printf "windows11 {\n\tvolatility_ist = \"/root/windows.json\";\n}" >> /etc/libvmi.conf
```

That conflicts with how this project resolves profiles. Clone domains have
no `/etc/libvmi.conf` stanza — the `-r <path>` argument is the only way a
profile is ever resolved here, which is why `sandboxd/stages.py` carries a
per-`TargetOs` profile path (`StageConfig.profiles`) and `sandboxd/guests.py`
passes it through to `drakvuf`/`injector`. Following this project's
convention means placing the output at `profiles/windows.json` and passing
it with `-r`, exactly as Ubuntu and Android do.

**To settle on Dom0:** does `-r <profile.json>` work for a Windows guest,
or does the Windows path require the `volatility_ist` stanza specifically?
If the latter, that is a genuine per-OS divergence and C1–C10 needs an
amendment rather than a workaround.

Also unresolved, and it is PLAN step 4's: the example above is 32-bit
(`ntkrpamp.pdb`, "Multi-processor with PAE"). A 64-bit guest has a
different kernel filename, and `injector --help` labels the Linux
`execproc` path `[LINUX] (execproc -> execve(...); 64bit only)`. Windows
injection semantics are still unread.

## §0.2 — Windows 11 install constraints on Xen

**Status: Candidate, from Qubes OS's Windows-HVM documentation**
(`doc.qubes-os.org`, read 2026-08-19). Qubes runs Windows HVMs on Xen, so
this transfers; it has **not** been reproduced here.

- **Windows 11 is installable as a Xen HVM.** So is 10. Both x64.
- **HVM only — PVH will not work.** Xen's current PVH limitations prevent
  it. The four tracked `misc/*.cfg` are already `builder = "hvm"`.
- **Xen does not support TPM 2.0**, so Windows 11's check must be
  bypassed during setup: `Shift-F10` → `regedit` →
  `HKEY_LOCAL_MACHINE\SYSTEM\Setup` → create key `LabConfig` → add DWORDs
  `BypassTPMCheck`, `BypassSecureBootCheck`, `BypassRAMCheck`, each `1`.
  This is the single most likely thing to waste an install attempt.
- **Memory: 4096 MiB minimum, 6144–8192 recommended** — below that the
  installer crashes. This bears directly on admission: at `memory = 6144`
  a clone costs **6294 MiB** (`+ DOMAIN_OVERHEAD_MIB`), so a 28 GiB host
  with `dom0_mem=8192M` affords three concurrent Windows clones; at 8192
  it affords two. Pick deliberately.
- **Disk: 60 GB minimum.** `CLONE_LV_SIZE` is per-OS precisely for this —
  Android is `32G`, Ubuntu `64G`, and Windows must be at least `60G`.
- **The VM halts after extracting installer files.** Expected, not a
  fault. Cloning the LV *before* the restart is worth doing — it saves
  repeating the bypass above if the install is botched later.
- **Windows 11 24H2 and later may require internet access during setup**,
  even for Pro, and the Microsoft-account bypasses are progressively
  blocked. Relevant here because the golden image build is the one phase
  that legitimately needs egress; clones must not inherit it.

---

No further phases are defined yet — later phases should mirror `android.md`'s
structure (sandbox VM build, automation scripts, sample-type branches,
artifact collection, network containment, testing, reliability) once Phase 0
decisions are made, not before.