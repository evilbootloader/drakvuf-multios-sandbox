# Project assessment — 2026-09-04

> **Scope.** The whole repository as it stands on branch `platform-domu` at
> `28572f7`: code, tests, documentation, the issue backlog and the GitHub
> issues. Read from the development container, so nothing about the running
> host is asserted here that is not already written down.
>
> **Predecessors.** `project-assessment.md` (2026-08-08) reviewed the nested
> Proxmox lab and stands as its own dated artifact.
> `docs/reviews/2026-08-31-post-migration.md` reviewed the bare-metal
> migration. This one reviews the four days since, and re-checks what that
> review handed back.

---

## The one-line answer

**One live defect, and a record that has started drifting again in the same
place and for the same reason as last time — a fast-moving track lands code and
does not sweep the documents that describe it.** Last time it was the platform;
this time it is Windows.

The live defect is **D1**: the Android APK path reads its handoff file before
the guest has written it, so `injector readfile` returns `-ENOENT` and the job
fails — intermittently, clearing on resubmission. Diagnosed 2026-09-04 from a
pasted failure. It is the only item here that costs analyses today, and the
only one that needs code rather than an edit.

The rest is record drift, most of it a few days old and most of it closing with
an edit. Two are more than cosmetic: the Windows guest build is unrecorded
(F1d), and five sites describe an Android injection anchor that was tried and
abandoned (F2).

---

# 1. Where the project actually stands

| | State | Confidence |
|---|---|---|
| Ubuntu pipeline | evidenced end to end, including through the platform | high — runbooks + operator |
| Android pipeline | evidenced end to end, both ELF and APK paths — but the **APK branch fails intermittently** on a fixed-sleep race (D1) | high — operator, 2026-08-29 and 2026-09-04 |
| Platform DomU | serving; Postgres, MinIO, FastAPI, Cloudflare Access | high |
| `sandboxd` | registered and running on bare metal | operator-attested, not pasted |
| Egress `offline` / `tor` / `simulated` | built, declared, evidenced | runbook 13 |
| Egress `routed` | built; kill-switch **proven** against a local peer | runbook 14, unfiled |
| Egress `direct` | built but **not declared** in `config.EXITS` | deliberate |
| Legacy `dirwatch` path | **stale** — operator, 2026-09-04 | see F7 |
| Windows — the guest | **built out.** Golden VM, `windows_sandbox.cfg`, kernel GUID read, software stack installed, **anchor saved in the `.bak`** | operator, 2026-09-04 |
| Windows — the pipeline | **not functional.** No automation scripts, no profile in place, nothing submittable through the platform | operator, 2026-09-04 |

**The Windows guest exists and is substantially prepared; the path from the web
UI to a Windows analysis does not exist.** Nothing below should be read as
saying otherwise. `catalogue.py` still raises rather than inventing options for
Windows, which is the platform correctly refusing to offer a target it cannot
run.

The guest build, as reported by the operator 2026-09-04 and **recorded nowhere
in the repository**:

| | |
|---|---|
| Browser | Chrome |
| Defender | disabled |
| Office | installed, **macros set to run automatically in Word and Excel** |
| .NET Framework | 3.5 and 4.8 binaries |
| .NET runtime | 8.0, x64 and x86 |
| Other | Python 3, 7-Zip |
| Injection anchor | **created, and saved into the `.bak`** |

This is not incidental setup. It is the substance of **DRAFT-020**, whose
scope the issue index restated on 2026-08-25 as *"what software is installed
in the guests — Office, a browser, a PDF reader, the .NET and VC++ runtimes,
and an unpacker that DRAFT-059 hard-depends on"*. That draft is written and
unpublished, and the work it describes is largely done. 7-Zip is the unpacker
DRAFT-059 needs; the macro setting is what makes a maldoc detonate at all
rather than sitting inert behind a security prompt.

## Host facts confirmed this session

The Xen boot line, supplied by the operator 2026-09-04:

```
GRUB_CMDLINE_XEN_DEFAULT="dom0_mem=8192M,max:8192M dom0_max_vcpus=6
dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1
hpet=legacy-replacement smt=0 sched=credit"
```

Two things follow. **`dom0_max_vcpus` is still 6**, so the 2026-08-31 CPU
repartition remains committed and not applied — Dom0 holds `0,2,4,6,8,10`, not
the eight P-cores `config.py` names. The partition stays consistent either way
(clones at `16-27` and the platform at `28-31` overlap neither), so nothing is
broken; it means the machine is still running 10 of 24 online pCPUs and
`SANDBOXD_MAX_CLONES` must not be raised.

**And `no-real-mode edd=off` are absent.** `CURRENT-STATE.md` §1.2 records them
as part of the boot line, *"the last two were added by the bare-metal
install"*, dated 2026-08-28. They are not in the GRUB default today. Either
they were removed since, or the recorded line came from a source that carried
them and `/etc/default/grub` never did. Worth reconciling at the source, since
that row is the one place anyone will look before touching the boot line — and
`CURRENT-STATE.md` already carries a WATCH note that `drakvuf-bundle` can
silently rewrite this line on any `update-grub`.

## What is genuinely healthy

**The test and static-check story is real, not aspirational.** Everything
`CLAUDE.md` documents runs and passes here:

```
417 passed in 13.65s          sandboxd suite
shellcheck automation/*.sh    exit 0
bash -n / dash -n             clean on all 8 shell scripts
perl -c automation/clone.pl   syntax OK
```

The suite re-runs all three generators and `check-refs.py`, so `INDEX.md`,
`CURRENT-STATE.md` §3 and `misc/*.cfg` cannot go stale without a red test.
That machinery works — it caught three bugs in its own authoring pass, and it
is why §3 below is short rather than long.

**The comments are unusually honest, and that is a load-bearing property
here.** Three examples, none of which a project trying to look finished would
write:

- `platform/sandbox_platform/auth.py:16` **retracts** a security claim the
  module previously made, names what contradicted it, and says plainly what
  `leased_job` is and is not worth.
- `platform/sandbox_platform/ui/__init__.py:141` labels its own
  `disable_sysret` checkbox **decorative**, and explains that keeping its
  default aligned is "cosmetic honesty, not wiring".
- `sandboxd/egress.py:645` explains the kill-switch as a property of what the
  rule *says* rather than of a watchdog noticing — and `argv_revoke` deletes
  the policy route first, so teardown cuts the network before it does
  bookkeeping.

This is the project's strongest asset. Most of the findings below are about
places where that standard slipped for a few days, which is a much better
problem than not having the standard.

---

# 2. Re-checking what the 2026-08-31 review handed back

| # | Item | Status |
|---|---|---|
| 1 | `python3 -V` and `xl info` on Dom0 (that review's F9) | **still open** — `config.py` records Python as UNCONFIRMED |
| 2 | `dom0_max_vcpus=6 → 8`, reboot, `xl vcpu-list 0` | **confirmed not done** — the boot line above still reads `=6` |
| 3 | platform DomU to 4096 MiB / 4 vCPU | not verifiable here |
| 4 | Fill `platform-domu.md` EVIDENCE G, then one browser job | **still blank** — all four lines are `______` |
| 5 | Verify `sandboxd` still starts after it took over network provisioning | not recorded |

Item 4 is the one that matters, because it is cheap and it is the only thing
standing between the lab's real state and its recorded state. Four days on, a
reader who trusts the derived table still sees `no` for work the operator has
confirmed happened.

## The DRAKVUF provenance question, partly answered — and not the way it is recorded

That review left **re-confirming DRAKVUF provenance** as a standing
recommendation, because it *"silently qualifies every pre-migration performance
figure"*. The D1 failure output answers part of it for free:

```
DRAKVUF injector v1.1-52df0bc
```

`CURRENT-STATE.md` §1.2 records DRAKVUF as **`v1.1-da982ab`, built from source**
from `lfreijo/drakvuf` branch `memdump`, with provenance flagged
**UNCONFIRMED**. The binary that ran on 2026-09-04 reports **`52df0bc`** — the
packaged pre-migration build.

**This does not fully close the question**, because `injector` and `drakvuf` are
separate binaries and only one may have been rebuilt. It does establish that at
least part of the installed toolchain is not what the record says, which is
enough to stop citing §1.2's build id as settled. `drakvuf --version` and
`injector --version` on Dom0 close it properly, and are one line each.

Its sibling recommendation is unchanged: `automation-files.md` still has 2
headings across 319 lines, so `INDEX.md` still cannot help anyone find anything
in it.

---

# 3. Findings

**D1 is a live defect. F1–F10 are defects in the record.** They are listed
separately because they need different things: D1 needs a code change, and the
F-series mostly needs edits.

## D1 — the APK handoff is read before the guest has written it

**Reported by the operator 2026-09-04**, after the rest of this assessment was
drafted, and **diagnosed the same day from a pasted failure**. An Android APK
analysis fails in preconfig with `injector readfile` exiting 1,
`syscall return code: -2`, `Could not open file in guest`. The same sample
usually succeeds on resubmission.

This qualifies the headline in §1: the Android path is evidenced end to end and
is *also* unreliable on the APK branch. Both are true — ELF and APK completed
through the platform on 2026-08-29, and APK runs since then sometimes do not.

**`-2` is `-ENOENT`, so the injection succeeded.** `injector` attached to the
anchor, ran in the guest, executed the syscall and got a result. The anchor PID
is correct and was scheduled. The handoff file was simply not there yet.

**The cause is a fixed sleep standing in for a completion signal.**
`stages.py:_preconfig` installs the APK with `execproc` — which returns when the
guest shell *starts* — then sleeps `waits.apk_install`, then reads the handoff.
The code says so at `stages.py:631`: *"execproc returns at process START, so
this sleep is the only synchronisation Dom0 has."*

The handoff is created by shell redirection on the install line, but the line
before it is `B=$(pm list packages)` (`guests.py:556`), which talks to the
package service over binder. On a freshly restored clone that service may not be
up: warm it returns at once, cold it blocks. ENOENT means the shell never
reached the redirect inside 20s — intermittent by construction, and cleared by a
resubmit.

**The constant was sized against the wrong variable.** `timing.py` records it as
*"3 seconds MEASURED for a 12 MB APK on 2026-08-17"* — one measurement, on the
nested host that no longer exists, timing the install rather than the package
service's post-restore cold start, which is the part that varies. The 6.7×
margin looks generous against the number it was derived from and is unrelated to
the number that matters.

**The fix has a trap in it, and it is the reason this is worth a paragraph.**
The handoff is written **twice** — `pm install` redirects its own output there
first, deliberately, so a failed install explains itself; `resolve-activity`
overwrites it on success. So polling for the *file* succeeds on the install
diagnostic and passes it on as a component, which `component_is_launchable()`
rejects as "no usable launcher component" — blaming the sample for a Dom0-side
timing fault. That is precisely the misdiagnosis the 2026-08-29 redirect fix
removed, re-entering by a different door. The poll must test **content that
parses as a launchable component**, and on deadline report whatever the handoff
holds, because that is the install diagnostic.

Written up symptom-first in `docs/TROUBLESHOOTING.md`, keyed on the error text.

**Frequency: rare.** The operator could not reproduce it across 11 runs
(2026-09-04). That cuts both ways — it is not costing many analyses, and it
also means **a clean run is not evidence the fix worked**. Only a run that
would have failed proves anything, and those are hard to arrange on purpose.

> **Fixed 2026-09-04, and unverified on Dom0.** `stages._await_component`
> replaces the fixed sleep with a poll for launchable content, reporting the
> two failure modes separately so injector's `-2` survives. `timing.py` records
> what the constant was and why it was wrong, and the APK trace path stops
> skipping the settle, since that exemption rested on the sleep existing. This
> has run against the fake runner only — 417 tests, including two new guards,
> both mutation-checked. It needs one real APK job.

### The false lead, and what it cost

A second failure was offered as the same bug and is not: a `pm install`
execproc exiting 1, carrying **`-i 1`** where the current code sends `-i 3251`.
Android used PID 1 only between `77909eb` (2026-08-29) and `921c04c`
(2026-08-31), so that paste is from a build two commits behind the current one.
It is a **historical** failure from the abandoned init anchor, confirmed by the
operator as coming from older notes.

Worth recording for two reasons. It is corroboration for the revert — the init
anchor did not merely lack a runtime environment for `app_process64` in theory,
it produced failures — and it is a warning about diagnosing from pasted output:
**two errors from the same pipeline can be from different builds**, and the
injection PID in the argv is what distinguishes them. Reading them as one
intermittent fault led straight to a wrong hypothesis about a stale daemon.

> **This review's own first answer was wrong, and the correction is the
> point.** D1 initially read as an anchor-scheduling race — the anchor is a
> `ping` runnable only in bursts, the clone has one vCPU, and nothing waits
> between `xl restore` and the first injection. Coherent, consistent with three
> facts in the tree, and refuted by the first pasted error, because a
> scheduling race does not return `-ENOENT` from a syscall that ran. **One line
> of real output outweighed three plausible inferences**, which is the same
> lesson `docs/reviews/2026-08-31-post-migration.md` §4 recorded from the other
> direction.


## The record defects

Ranked by how much they mislead a reader, not by size. Every one is a
few-minute edit.

## F1 — the Windows setup work of 2026-09-01 landed with no documentation sweep

**Not a claim that the Windows pipeline works — it does not.** This is
narrower: the guest-side setup moved on 2026-09-01, two blockers the checklist
names have been cleared by it, and a third document contradicts the checklist
about which Windows is installed. The track's own summary — *"no automation
does"* — is still right.

**F1a. The checklist names a blocker that no longer exists.**
`docs/checklists/windows.md` header: *"What is **not** done:
`misc/windows_sandbox.cfg` does not exist"*, and the status table's
`Current blocker` row repeats it. The file was committed on **2026-09-01**
(`f0b44a3`, "Windows set up"), one day after the checklist was last touched.

**F1b. A golden config says the file next to it does not exist.**
`misc/windows.cfg:4` —

```
# KNOWN GAP (DRAFT-034): windows_sandbox and misc/windows_sandbox.cfg do not
# exist yet, so nothing clones this domain today.
```

Both halves are false. `CURRENT-STATE.md` §1.4 already records the
`windows_sandbox` LV as created.

**F1c. `windows_symbols.md` is unfiled Dom0 evidence, and no checklist knows it
exists.** Committed 2026-09-01 (`6d0f7bf`), sitting at the repository root. It
contains a real `vmi-win-guid domid 52` run — the kernel was found, the PDB
GUID read (`72c69e726c648bc18257af38fa78a2f21`), and the exact `pdbconv.py`
invocation that would produce `profiles/windows.json` is written down.

Two separate things, and the checklist is wrong about only the first. The
**kernel GUID has been read**, so *"no PDB fetched yet"* as a blocker is
half-cleared: the identifier the fetch keys on now exists and is recorded.
Whether `profiles/windows.json` was ever generated is **not** evidenced —
`profiles/` is untracked, so this container cannot tell, and nothing in the
repository says it was. The honest checklist row is "GUID read 2026-09-01,
profile generation outstanding", not the current "no PDB fetched yet".

It also contradicts the checklist about the baseline: the output reads
**64-bit Windows 10**, while the status table says *"Windows 11 first, Windows
10 as fallback"* with the exact build unrecorded. That is the row a future
profile, anchor and plugin set all key on, so it is worth correcting before
anything is built against it.

**F1d. The guest build is recorded nowhere, though the anchor PID is.** The
software stack in §1 — Chrome, Office with macros on, the .NET runtimes,
Python, 7-Zip, Defender disabled — exists only in the operator's account as of
this review. The **anchor is recorded**: `sandboxd/stages.py:242` carries
`TargetOs.WINDOWS: 4696`, added by `20f51fb` ("Windows set up"), and
`profiles/windows.json` is already named at `:249`. So the code knows more
about the Windows guest than any document does.

Three rows of `CURRENT-STATE.md` §1.4 — the table `CLAUDE.md` sends every
reader to before asserting a deployment fact — still read `—` for Windows:

| Row | Says | Actually |
|---|---|---|
| Golden domain | `—` | `windows`, defined in `misc/windows.cfg` |
| Saved state | `—` | exists, with an anchor in it |
| Injection PID | `—` | **4696**, live in `stages.py:242` |
| LibVMI profile | `—` | GUID read; `profiles/windows.json` already referenced in code |

What is genuinely missing is not the PID but its **provenance**: no checksum
of the `.bak`, and no link to the golden image it was saved from. That is
roadmap risk #12, and Windows has just acquired the first saved state since it
was written. Android hit this twice in August. One `sha256sum` recorded beside
the PID now is the whole mitigation.

> F1a–c are `CONTRIBUTING.md` rule 5 — *"record direction changes as
> first-class edits, and sweep what they invalidate"*. F1d is the older
> failure: the documents all agree with each other, and none of them has heard
> what happened.

## F2 — three documents describe an Android injection anchor that was tried and abandoned

Found while checking F1d, and it is the more serious of the two because it is
in the evidenced path. **The code is correct; the record is not.**

`sandboxd/stages.py:241` —

```python
injection_pids: dict = field(default_factory=lambda: {
    TargetOs.UBUNTU: 1, TargetOs.ANDROID: 3251, TargetOs.WINDOWS: 4696})
```

`automation/pipeline-android.env:304` agrees: `INJECTION_PID="${INJECTION_PID:-3251}"`.
Both orchestrators are consistent, and `3251` is **deliberate**: Android does
not anchor on `init` because that was tried and caused problems, so the anchor
is a backgrounded `ping` — imperfect, acknowledged, and the arrangement the lab
is working with (operator, 2026-09-04).

Three places say otherwise, and one of them argues a safety property from it.

**The comment directly above that dict is false.** `stages.py:233–240` says
*"Both OS families anchor on their init: systemd on Ubuntu, Android's `init` on
Android"*, and builds on it — *"**PID 1 is the only value a template re-save
cannot invalidate**, which removes the re-derivation step that has silently
broken injection twice"*. For Android none of that holds: the anchor is not
init, the value is re-save-fragile, and the re-derivation step the comment says
was removed is still there. `CONTRIBUTING.md` rule 2, in the file that decides
where samples are injected.

**`CURRENT-STATE.md` is wrong twice.** §1.4 records Android's injection PID as
**1** ("anchor `init`, 2026-08-29"). §2b lists `3163`, `3164`, `3174` as
*superseded by* **1** — so the superseded-facts table, the one place kept
specifically to stop this, now supersedes the live value with a stale one.

The history: `77909eb` ("inject through PID 1 on both OSes, not a named
anchor") made the change all three documents describe; `921c04c` restored
`3251` for Android after init proved unworkable. The documents were written
against the first commit and never revisited after the second.

**The reason is not lost — it is recorded in exactly one place, and four
others contradict it.** `automation/pipeline-android.env:289` carries the
reversal in full, dated 2026-08-31: *"Android's init does not provide a runtime
environment for `app_process64`, which the APK path needs, so the anchor moved
back."* It even keeps the case *for* PID 1 above it, marked as superseded,
which is the house standard done properly.

That file is right. These are wrong, and all state it as a premise rather than
in passing:

| | |
|---|---|
| `sandboxd/stages.py:233` | *"Both OS families anchor on their init"*, plus a safety argument from it |
| `sandboxd/guests.py:439` | *"The ANDROID_\* exports are required **because the anchor is PID 1**"* |
| `automation/preconfig-android.sh:228` | the same sentence, in capitals |
| `sandboxd/tests/test_guests.py:182` | the same, as a test docstring |
| `docs/CURRENT-STATE.md` §1.4, §2b | Android's PID recorded as **1**, anchor `init` |

**The last three are not merely stale — they sit on an open technical
question.** The `ANDROID_*` exports were added 2026-08-29 *because* a child of
`init` inherits only four variables and `app_process64` needs a runtime
environment built from nothing. The anchor reverted two days later to a `ping`
started from a booted session, whose environment is not empty. So whether
those exports are still *required*, or now merely redundant, is unverified —
and the test docstring says *"deleting any of these is not a cleanup, it
restores a silent failure"*, measured under the PID-1 anchor.

**Do not remove them on this reasoning.** The correct fix is to correct the
stated premise and keep the behaviour: they may still be needed, the failure
they prevent is silent, and settling it needs a clone rather than an argument.

Two live costs follow from the ping anchor and should be stated rather than
implied: the PID must be re-derived after every template re-save, and it must
not be discovered by name-grep — the index already carries that as a standing
constraint from issue #7, and it applies to this anchor, not to a PID-1 one.

Windows `4696` is the same shape and inherits the same handling. Nothing in
`sandboxd/tests/` pins any of these values.

> **Fixed 2026-09-04, in part.** `stages.py:233` and both `CURRENT-STATE.md`
> rows are corrected, and §2b gains a row for the PID-1 claim itself naming
> the four sites that still carry it. `guests.py`, `preconfig-android.sh` and
> `test_guests.py` are left for the operator, because their premise is
> entangled with the open question above.

## F3 — `misc/windows_sandbox.cfg` sits in the CPU-partition blind spot

It carries `cpus = "16-27"`, and it is the only guest config that no mechanism
covers:

| | `ubuntu_sandbox` | `android_sandbox` | `platform` | **`windows_sandbox`** |
|---|---|---|---|---|
| in `CFG_TARGETS` (regenerated) | yes | yes | yes | **no** |
| provenance comment asserted by test | yes | yes | yes | **no** |
| in the golden "must have no `cpus`" set | — | — | — | **no** |

`scripts/gen-xen-configs.py:93` lists three targets; the generator's own
comment justifies the exclusions by saying the untouched configs *"have no
`cpus =` line and should not acquire one"* — which is true of the three golden
domains it names and not true of this file.
`sandboxd/tests/test_xen_configs.py:95` parameterises over the same three, and
`:142` pins the golden set. `windows_sandbox.cfg` is in neither list.

The value is correct today. The point is that when the partition next moves,
`ubuntu_sandbox` and `android_sandbox` follow `config.py` and this one does
not — and `CURRENT-STATE.md` records that `cpus = "6-11"` silently resolving to
`{6,8,10}`, every core Dom0 holds, has **already happened once**. It is also
the only `.cfg` in `misc/` with no comments at all, in a directory where every
other file explains its own values.

## F4 — `sandboxd/config.py` assigns `EXITS` twice

```
269:  EXITS: dict[str, dict] = {}      # + ~30 lines of "Empty until an exit exists"
335:  EXITS = { "tor-default": {...}, "sim-local": {...} }
```

The first assignment and its comment block are dead. The comment tells a reader
*"To offer Tor, install `automation/torrc` … and add::"* — work that the
assignment 66 lines below has already done. Confirmed at runtime: `config.EXITS`
has two entries.

Functionally harmless; misleading in exactly the module that decides where
malware traffic goes. The surviving guidance (peers are never
submitter-supplied; a `routed` entry must not be added before its kill-switch
capture) is worth keeping — it should move onto the live assignment.

## F5 — the Android checklist says Phase 2 is "not started"

`docs/checklists/android.md`, the file `CLAUDE.md` routes readers to for
per-OS progress:

- header: `Last update | 2026-08-14`
- status: `Current phase | Phase 2 — Android automation scripts (not started, now unblocked)`
- §2.1: `- [ ] Create preconfig-android.sh` · `- [ ] Create drakvuf-android.sh` · `- [ ] Create run_analysis-android.sh`

All three exist in `automation/`, and both sample kinds are evidenced end to
end through the platform (operator, 2026-08-29). The 2026-08-31 pass fixed this
exact defect in `docs/checklists/platform.md` and did not reach here.

The ratio is 73 checked to **394 unchecked** across 3,195 lines. Many of those
are legitimately open (Phases 3.5–3.10, 4.x, the endurance and concurrency
tests). The header rows are not — and they are what a reader reads first.

> `CONTRIBUTING.md` rule 6 predicted this precisely: *"An unchecked box reads
> as live work with no expiry, and that is where this repository's staleness
> actually accumulates."*

## F6 — a closed security gap is still asserted in the protected Ubuntu path

`automation/pipeline-ubuntu.env:153`:

```
# Clone containment is still unverified (KNOWN GAP, DRAFT-013) and the
# inter-clone FORWARD DROP rule may never install at all (KNOWN GAP, DRAFT-028).
```

DRAFT-013 closed as issue #13 on 2026-08-14 (`06-verify-android-isolation.md`);
DRAFT-028 landed 2026-08-11 and closed as #24. Every other DRAFT-013/028
reference in `automation/` is already past tense — this is the last live-voice
one. `CONTRIBUTING.md` rule 2: a comment stating a security guarantee must be
true today or dated.

## F7 — `dirwatch` is stale, and the living documents present it as a live path

**Operator, 2026-09-04.** The repository does not say so anywhere a reader
would find it, and in two places says the opposite.

`README.md:22` offers **"two ways in"** in a table whose `Status` column reads
*"the current path"* for the platform and *"the original path, still present"*
for the watcher — which reads as a supported alternative rather than as
something no longer maintained. `CURRENT-STATE.md` §3's generated table lists
the legacy pipeline beside `sandboxd` with no currency marker at all.

The commit dates say it plainly:

| | last touched |
|---|---|
| `automation/dirwatch.c` | **2026-08-15** |
| `automation/run_analysis-{ubuntu,android}.sh` | 2026-08-31 (egress) |
| `sandboxd/` | 2026-09-02 |

The launchers were carried forward into the egress work; the watcher they
launch has not moved in three weeks, across a host migration and the whole of
DRAFT-057. `docs/architecture/automation-files.md:36` is the one file that says
retirement is scheduled (DRAFT-041, 2026-08-21) — in a document with two
headings across 319 lines, which `INDEX.md` cannot help anyone navigate (F10).

Three consequences worth separating:

- **Several `KNOWN GAP` comments are written in the present tense about a
  stale component.** `automation/pipeline-{ubuntu,android}.env` describe the
  process-local VLAN slot as a live constraint, and the `pgrep` guards in both
  launchers exist to enforce it. They are not wrong — they are guarding
  something that should carry an expiry.
- **`automation/dirwatch_old.c` is 670 lines with no live referent.** Every
  mention outside the runbooks is in `project-assessment.md` (2026-08-08) or
  in drafts asking what to do with it. Its disposition has been an open
  question since DRAFT-010 and is still one.
- **New per-OS work inherits a decision nobody restated.** A Windows launcher
  written from `run_analysis-ubuntu.sh` would carry the `pgrep` guard, the
  15-argument contract and the slot-index VLAN into a path being retired. That
  is a real cost if the Windows pipeline is built next.

The fix is one line in `README.md`'s table and a currency note in
`CURRENT-STATE.md`, not a retirement — retiring it is DRAFT-041's tail and
needs the platform path to cover every case the watcher does.

## F8 — runbook 14 is executed and still parked at the root

`14-verify-routed-egress.md` says **"Status: EXECUTED 2026-09-02 to
2026-09-04"** and carries pasted `root@dom0` output. `CLAUDE.md` says a runbook
at the root is one *"written but not yet fully executed"*. Filing it is a move
into `docs/runbooks/` plus a generator run.

Worth doing carefully, because the runbook is unusually good: step 6 states its
own preconditions as lettered asserts *because it passed on the third attempt*,
the first two having produced `0 packets captured` without testing anything. It
also says plainly what a green run does not prove (the country criterion). That
is the kind of evidence the project exists to accumulate and it should not sit
in the root.

## F9 — four completed issues are still open on GitHub

`docs/checklists/platform.md` marks all four `[x] Completed and evidenced`:

| Issue | Title | Checklist says |
|---|---|---|
| #35 | Job schema and the claim query | done, migrations applied |
| #38 | The web UI | done, autoescape on, ZIP downloads tested |
| #39 | Transport security | done, Tunnel outward, internal CA inward |
| #41 | `sandboxd` — the analysis orchestrator | done, claiming over mTLS |

None has been touched since 2026-08-26. #34 ("decide the analysis platform
architecture") was decided by DRAFT-041 on 2026-08-21 and is also open. The
repo's own rule — *"the repository state is the source of truth for what an
issue still needs to do"* — is being followed inside the repository and not on
GitHub, so the issue list reads as five open P0/P1 items that are finished.

Closing them is a `gh` operation and therefore gated on your approval; I have
not run anything.

## F10 — smaller staleness, listed once

| Where | Says | Actually |
|---|---|---|
| `CLAUDE.md` | *"`docs/` is 43k lines across 30 documents"* | 36 files, 34,826 lines |
| `docs/checklists/windows.md` | a Windows clone costs 6294 MiB "against Ubuntu's and Android's **2198**" | 4246 since 2026-08-29 (`CURRENT-STATE` §2b) |
| `docs/checklists/ubuntu.md` | `Deployed on Dom0 \| /root/sandbox_project` | `/root/drakvuf-multios-sandbox` (§2b) |
| `docs/architecture/automation-files.md` | — | 2 headings / 319 lines; flagged 2026-08-31, unchanged |
| `docs/CURRENT-STATE.md` §1.2 | the Xen boot line ends `… sched=credit no-real-mode edd=off` | those last two are **not** in `GRUB_CMDLINE_XEN_DEFAULT` today (operator, 2026-09-04) |

---

# 4. Backlog health

**The drafting discipline is far ahead of the publication discipline.** 53
draft files, an 1,043-line index that tracks supersession properly, and a
triage pass that struck five drafts as superseded rather than leaving them to
rot. Against that: 9 open GitHub issues, of which 5 are done (F9) and one — #42,
egress — is the only one that reflects live work.

The two genuinely-open tracks are correctly identified as the P0s:

- **#42 / DRAFT-057 — egress.** Four of five phases built and evidenced.
  What remains is a provider, and outreach was refused (`private/outreach/`).
  The design's response to that is right: build against a local peer, prove
  the kill-switch, leave `available_exits` unable to offer what does not exist.
- **DRAFT-034 — Windows.** The track head, unpublished. The guest is
  installed and the pipeline is not started, so this is where the largest
  block of unwritten work sits — and its checklist is currently the least
  reliable guide to it (F1).

**Ten index rows still have no draft file**, and `DRAFT-018` (the result
schema) is the one that is a live dependency: every capability draft writes a
`*.json` into a schema nobody has specified, which the index itself notes *"is
precisely how the outputs drift apart."*

---

# 5. Risks worth restating

Not new; these are the ones that have not moved.

1. **Windows cannot share Dom0 with another watcher**, and the failure mode is
   not an error — it is one admission-hold line per second, forever, measured
   at 170 consecutive holds. Fixed by head-of-line reservation, not landed.
   `windows.md` says "run Windows alone"; nothing enforces it. This lands the
   moment the Windows pipeline is first exercised, so it is the constraint to
   settle *before* that work rather than during it.
2. **The thin pool is one failure domain** for the artifact store, the golden
   images and every clone snapshot. Autoextend is configured; it still cannot
   grow past the VG. Retention is unresolved as *policy*.
3. **The trust boundary is inverted** since the migration: a compromised Dom0
   can read Postgres out of `xl save platform`. Recorded, correctly, as
   authentication rather than containment.
4. **Nothing links a saved sandbox state to the golden image it came from**
   (roadmap risk #12). Realised once on Android, fixed there, still unowned
   generically — and Windows is about to acquire its first saved state.
5. **Dom0's Python version is recorded nowhere** while `websockets==16.1.1` is
   pinned on the strength of a claim made when Dom0 was jammy.
6. **The lab is still on the pre-repartition CPU layout**, confirmed by the
   boot line: 10 of 24 online pCPUs in use, and `SANDBOXD_MAX_CLONES` pinned
   at 2 rather than the 4 the committed partition affords. Not a defect —
   it is one reboot, deferred — but it is a standing gap between what
   `config.py` describes and what the machine runs, and every capacity figure
   in the repository is written against the *committed* side.

---

# 6. Recommended order

Most of §3 closes with an edit. Sequenced by what un-misleads the most:

1. ~~**Fix D1**~~ — **written 2026-09-04, needs a real APK run.** The poll is
   `stages._await_component`; the constants and their history are in
   `timing.py`. Verify with one APK job, and check the trace still fits its
   budget now that the APK path pays the 5s settle it used to skip. Note that
   a passing run proves little — the fault appeared in none of 11 runs before
   the fix.
2. ~~**Correct the Android anchor record**~~ (F2) — **done 2026-09-04.**
   `stages.py:233`, `CURRENT-STATE.md` §1.4/§2b, and the premise-only rewrites
   at `guests.py:439`, `preconfig-android.sh:228` and `test_guests.py:182`.
   The `ANDROID_*` exports are **kept and unchanged**; only the reason given
   for them is corrected, and the open question is now stated in all three
   places. **Settle that question on a clone** — whether they are still
   required under a `ping` anchor — and do not delete them on the argument
   alone, because the failure they prevent reports success.
3. **Record the Windows guest build** (F1d) in `docs/checklists/windows.md` —
   the software stack, Defender, the macro setting — plus a `sha256sum` of the
   `.bak` beside anchor PID 4696, which is the whole mitigation for roadmap
   risk #12 on this target. Note this largely discharges DRAFT-020.
4. **Sweep the rest of the Windows track** (F1a/b/c). Correct the two blocker
   rows, delete the false `KNOWN GAP` in `misc/windows.cfg`, and fold
   `windows_symbols.md` into the checklist as evidence — including that the
   guest is Windows **10**, which changes the baseline row. Keep the headline:
   guest installed, pipeline not built.
5. **Bring `windows_sandbox.cfg` under the generator** (F3) — add it to
   `CFG_TARGETS` and to the parameterised test, and give it the provenance
   comment the test then requires. The one finding with a failure mode rather
   than a readability cost, and cheapest now, before anything depends on it.
6. **Mark `dirwatch` stale where a reader will see it** (F7) — `README.md`'s
   "two ways in" table and `CURRENT-STATE.md` §3. One line each, and worth
   doing *before* the Windows pipeline is written so it is not copied from a
   template already on its way out.
7. **File runbook 14** (F8) and regenerate.
8. **Fix the three remaining stale assertions** — `EXITS` (F4),
   `pipeline-ubuntu.env:153` (F6), and the Android checklist header rows (F5).
9. **Fill `platform-domu.md` EVIDENCE G** and run one browser job. Still the
   highest-value thing that needs the host, and outstanding since 2026-08-31.
10. **Close #34, #35, #38, #39, #41** with a line each pointing at the
    evidence — after you approve the exact `gh` commands.

Everything except 9 can be done here. The reboot to `dom0_max_vcpus=8` is
separate and is a capacity decision, not a correctness one.

---

# 7. What this assessment could not check

Stated so a green reading is not taken for more than it is.

- **Most of the running host.** The boot line was supplied by the operator and
  settles `dom0_max_vcpus`; everything else is unverified — whether the
  platform DomU is at 4096 MiB, whether `sandboxd` still starts since it began
  provisioning the network, and the remaining "as committed, NOT YET APPLIED"
  rows in `CURRENT-STATE.md` §1.
- **Whether `profiles/windows.json` exists.** `profiles/` is untracked, so this
  container cannot see it. `stages.py:249` already names the path; the GUID is
  read; whether the conversion was run is unknown here.
- **The platform test suite.** It needs Postgres and MinIO; `scripts/dev-services.sh`
  reports MinIO present and Postgres down in this container, and installing
  from the network is deliberately the operator's call. The 15 platform test
  files were not exercised — only the 16 sandboxd ones.
- **`dirwatch.c`**, which cannot compile outside a DRAKVUF tree.
- **Whether the operator-attested runs happened.** They are taken as true, per
  the rule this project learned the hard way: absence of a pasted prompt is not
  evidence of absence.
