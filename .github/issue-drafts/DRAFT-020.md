# DRAFT-020: What is installed in the guests — coverage, and not looking like a sandbox

**Status:** Drafted 2026-08-25. Not published.
**Area:** core
**OS:** Windows first, then Ubuntu and Android — the question is the same for
all three.
**Milestone:** M5
**Priority:** **P1.** Two capability tracks already depend on it.
**Depends on:** DRAFT-034 (the Windows baseline exists first). Pairs with
DRAFT-058 (locale) and DRAFT-055 (`hidsim`).
**Needs Dom0:** **Yes** — golden-image work.

> **The index row for this draft is misleading and should be corrected.** It
> reads "Windows baseline selection + clone-per-run confirmation". Baseline
> selection belongs to **DRAFT-034**, which says so explicitly and supersedes
> that half; the VM-lifecycle question is **closed** (clone-per-run, by
> elimination, per the roadmap and `docs/checklists/windows.md`).
>
> What was left unwritten, and what this issue actually is: **what software
> is installed inside the analysis guests.** Maintainer, 2026-08-25.

# Objective

Decide and record what each golden image has installed — so samples can
actually run, and so the guest does not announce itself as a sandbox.

# Context

## Two separate problems, one answer

**Coverage.** A maldoc without Office does nothing. A browser exploit without
a browser does nothing. A .NET loader without the runtime fails at the first
instruction, and a binary built against the Visual C++ redistributables fails
before `main`. In every case the trace is real, the failure is real, and the
report describes **our image** rather than the malware — a false negative
delivered in a confident tone. It is the same failure DRAFT-059 exists to fix
from the packaging side.

**Realism.** A Windows VM with no applications, no documents, no browser
history and a username of `user` is a sandbox, and cheap malware checks for
exactly that. `ideas.md` carries "make VMs more user computer like
(anti-evasion)" and this is most of it. `cpuidmon` (DRAFT-050) tells you the
sample *looked*; `hidsim` (DRAFT-055) removes the "nobody is home" tell;
DRAFT-058 removes the locale tell. This removes the largest one — an
implausibly empty machine.

Both are answered by the same decision, which is why they are one issue.

## Two other drafts already depend on it

- **DRAFT-059** needs an **unpacker in the guest** for in-guest archive
  extraction: 7-Zip on Windows, `unzip` on Ubuntu and Android. That is not a
  realism nicety, it is a hard dependency of a P1 issue, and it is the kind of
  thing that gets discovered at implementation time.
- **DRAFT-058** installs language packs into the same images. Both change the
  golden image, so they should be one rebuild rather than two.

## What this costs, and the constraint it runs into

Every addition enlarges the golden LV, and roadmap risk #12 records that
nothing links a saved state to the image it came from. A rebuild invalidates
`state/<domain>.bak` **and** the anchor `INJECTION_PID` — which issue #7 had
to fix for Android after the golden VM was reinstalled and nothing detected
the conflict.

So: **one deliberate rebuild per OS, with DRAFT-058, and the template re-saved
and its checksum recorded in the same pass.**

# Dependencies

- **DRAFT-034** — the Windows baseline must exist to install anything into.
- **DRAFT-058** — same rebuild.
- **DRAFT-059** — consumes the unpacker this installs.

# Out of scope

- **Full persona simulation** — synthetic email, plausible document contents,
  a browsing history that survives inspection. Real work and much larger; this
  issue does the part that is a package list plus a handful of settings.
- **Anti-anti-VM patching** — hiding CPUID leaves, editing SMBIOS, removing
  hypervisor artifacts. A different and much deeper problem, and `cpuidmon`
  should measure the need before anyone attempts it.
- **Deciding the Windows version.** DRAFT-034.

# PLAN

**Windows first, measured with Pafish, then the same method on the others**
(maintainer, 2026-08-25). Windows is where both problems are worst — the
richest sample types need the most software, and the detection tooling only
exists there.

1. Baseline Pafish run against the current image. **Before any change**, or
   there is nothing to compare against.
2. Settle the package list — coverage first, realism second.
3. Apply the realism settings, which are cheaper and often matter more.
4. One rebuild, together with DRAFT-058's locales.
5. Pafish again. Record which specific checks changed, not only the total.
6. Re-save the template, record the checksum and the new anchor PID.
7. Repeat the *method* on Ubuntu and Android — see the caveat below.

# CREATE

> ## Largely DONE on the golden VM, 2026-09-01 — operator-reported, 2026-09-04
>
> Most of the Windows coverage list below is already installed. Recorded here
> because it was reported verbally and written down nowhere: not in
> `docs/checklists/windows.md`, which still lists blockers this work cleared,
> and not in `docs/CURRENT-STATE.md` §1.4, whose Windows column is mostly `—`.
>
> | Item | State |
> |---|---|
> | Microsoft Office | installed, **macros set to run automatically in Word and Excel** |
> | Chrome | installed |
> | 7-Zip | installed — this is DRAFT-059's hard dependency, so that draft is unblocked |
> | .NET Framework 3.5 and 4.8 | binaries downloaded |
> | .NET runtime 8.0, x64 and x86 | installed |
> | Python 3 | installed |
> | Microsoft Defender | disabled |
> | Injection anchor | created and saved into the `.bak`; PID **4696**, in `sandboxd/stages.py` |
>
> **Still outstanding from the list below:** a PDF reader (Adobe Reader), the
> Visual C++ redistributables, Java, and the whole of "Windows — realism",
> none of which is evidenced.
>
> **The macro setting is the highest-value item here and deserves naming.**
> Without it a maldoc sits behind a security prompt no unattended run can
> answer, so the largest sample class this draft exists to unlock would have
> been inert while appearing to run.
>
> **One thing to do before building on this**, and it is roadmap risk #12:
> nothing links `state/windows_sandbox.bak` to the golden image it came from,
> and no checksum is recorded. Android hit exactly this twice in August. One
> `sha256sum` beside PID 4696 is the whole mitigation, and it is cheapest now.

## Windows — coverage

| Software | Why |
|---|---|
| **Microsoft Office** | Maldocs and macros. The single largest sample class this unlocks |
| **A browser** — Chrome, alongside built-in Edge | Phishing pages, browser exploits, and a profile with history is realism as well as coverage |
| **PDF reader** | Adobe Reader is a heavily targeted parser; without it a malicious PDF is inert |
| **7-Zip** | **Required by DRAFT-059** for in-guest extraction. Also how many samples arrive |
| **.NET runtime(s)** | A large share of commodity malware is .NET and fails instantly without it |
| **Visual C++ redistributables** | The classic "the sample just exits" cause. Cheap to install, expensive to diagnose |
| **Java runtime** | Declining but not gone. Optional — decide from what is actually submitted |

## Windows — realism

Cheaper than the package list and frequently more effective, because these are
what the naive checks read:

- **A plausible username.** Not `user`, `admin`, `sandbox`, `malware` or
  `test`, all of which appear in published sandbox-detection lists.
- **Documents that exist** — a handful in `Documents` and on the Desktop, with
  varied timestamps. An empty profile is a strong tell.
- **Browser history, bookmarks, a saved profile.** A browser installed but
  never used is its own signal.
- **Recent-files / MRU entries**, which follow from actually opening the
  documents once before the template is saved.
- **Disk that looks used**, rather than a near-empty volume.
- **CPU and RAM above the common thresholds.** Checks for ≤2 cores or ≤4 GB
  are widespread; `misc/windows.cfg` is already `vcpus 6` / `memory 6144`,
  which clears both — worth recording as deliberate rather than incidental.
- **Uptime.** Many checks reject a machine minutes out of boot. Clone-per-run
  restores a saved state, so what the guest reports depends on the saved
  state's own uptime — **worth measuring, since it may already be fine or may
  be the most-read tell we have.**

## The Xen PV driver tension, named

PV drivers improve disk and network performance materially, and they are a
**detectable VM artifact** — device names, services, registry keys that
malware enumerates directly.

There is no free answer. Note it, decide it deliberately, and record which way
and why. If they stay, `cpuidmon` and a detection-suite run will say how much
it costs; if they go, measure whether the guest is still fast enough to finish
a trace inside the window.

## Measuring it — Pafish, and what it is not

**Pafish** is the instrument: it runs the checks malware families actually
use — VM artifacts, CPUID and timing, and the generic sandbox tells this issue
targets directly (username, disk size, RAM, CPU count, uptime, mouse activity).
Its output is a readable per-check list, which is what makes a before/after
comparison meaningful rather than a single score.

**It was archived by its author on 2025-08-22 and is no longer maintained.**
That is acceptable, and the reason is worth stating so nobody "fixes" it
later: a frozen tool is a **good ruler and a bad certificate**. It measures
change reliably, because the checks are identical between runs. It cannot tell
you the image is undetectable, because it has known nothing new since 2025.

So: **Pafish for the before/after number; al-khaser as a second, maintained
opinion** with a much larger check set.

**When they disagree, the detection wins — always, whichever tool made it**
(maintainer, 2026-08-25). Not "believe the newer tool". Two reasons:

- **They mostly test different things, not the same things differently.** A
  disagreement is usually one tool checking an artifact the other never looks
  at, so the union of their findings is the real answer and the intersection
  is meaningless. Pafish being archived does not make its existing checks
  wrong — an artifact it detected in 2019 is still an artifact in 2026 if
  nobody removed it.
- **The costs are asymmetric.** A false *detected* costs some wasted hardening
  effort, and you find out when you go looking. A false *clean* means shipping
  an image that malware fingerprints, and **you never find out** — the samples
  simply do nothing and the reports look unremarkable.

So the score is the number of checks flagged by **either** tool, and a check
only counts as fixed when **both** stop flagging it. That rule generalises
past these two: any future detection suite joins the union rather than
replacing an existing one.

`hidsim` (DRAFT-055) interacts here: several of Pafish's generic checks look
for mouse movement and user activity, so a run with input injection should
score differently from one without. Measure both, or the two issues will be
credited with each other's improvements.

## Ubuntu and Android

Same question, smaller answer — and **the method transfers where the tool does
not.** Pafish and al-khaser are Windows-only, and there is no comparable
standard for Linux or Android sandbox detection. So the before/after
discipline carries across; the measuring instrument has to be assembled, or
the honest answer recorded that this is unmeasured on those guests. Ubuntu needs `unzip` for DRAFT-059 and a
plausible home directory; it already runs a desktop. Android has archive
handling built in, and its realism question is different in kind — an
emulator-looking BlissOS install is detected by `Build.FINGERPRINT` and
friends rather than by installed applications, which is out of scope here.

# TEST

1. **A maldoc detonates** on the Windows guest and does nothing on an image
   without Office — the clearest demonstration that coverage is the point.
2. **A .NET sample runs**, where it previously exited immediately.
3. **A sample needing the VC++ redistributables runs.**
4. **DRAFT-059's in-guest extraction works** — the unpacker is present and
   invocable on each guest.
5. **Pafish scores better after than before**, with both runs recorded in
   full. Not a pass/fail — a set of checks that changed, named individually,
   because "12 detected" and "12 detected" can hide a completely different
   twelve.
5a. **Pafish is also the `cpuidmon` fixture** (DRAFT-050). It deliberately
   probes the hypervisor bit, so running it as a *sample* under a trace with
   `cpuidmon` enabled should produce exactly the records that plugin exists to
   make. One binary validates both drafts from opposite directions: Pafish
   says what the guest reveals, `cpuidmon` says that we saw it asking.
6. **Uptime as reported inside a restored clone is measured**, so the decision
   about it rests on a number.
7. **The trace still finishes.** More installed software means more background
   activity; measure the idle noise floor after the rebuild, exactly as
   DRAFT-050 does before it.

# DEPLOY

A golden-image rebuild per OS. **Together with DRAFT-058**, because both touch
the same image and roadmap risk #12 makes every rebuild a moment where the
saved state and anchor PID silently go stale.

The rebuild ends with: template re-saved, checksum recorded, `INJECTION_PID`
re-measured and written to `pipeline-<os>.env`, and the checklist updated —
the sequence issue #7 had to perform for Android after exactly this went
unnoticed.

# Acceptance criteria

- [ ] Package list decided and recorded per OS, with a reason per entry.
- [ ] Realism settings applied and recorded.
- [ ] The PV driver decision made explicitly, either way, with its reason.
- [ ] An unpacker present on all three guests, satisfying DRAFT-059.
- [ ] Pafish and al-khaser both run before and after, all four logs kept, with
      the changed checks named individually rather than only a total.
- [ ] The score is the UNION of their detections; a check counts as fixed only
      when both stop flagging it.
- [ ] Pafish confirmed as a `cpuidmon` fixture — its probes appear in a trace.
- [ ] Idle noise floor re-measured after the rebuild.
- [ ] Template re-saved, checksum and anchor PID recorded in the same pass.
- [ ] The index row corrected — this is not baseline selection.

# Evidence required

- The package list as installed, per OS.
- A maldoc running, and the same maldoc inert on the pre-rebuild image.
- Pafish and al-khaser output, before and after, in full — four logs, so the
  union can be recomputed rather than taken on trust.
- A `cpuidmon` trace of Pafish running as a sample.
- Idle noise floor, before and after.
- The template checksum and anchor PID, recorded together.

# Security considerations

- **Every installed application is attack surface inside the guest**, which is
  the point: Office exists so maldocs detonate. It also means the guest is
  more valuable to escape *from*, and escape containment is unowned —
  `ideas.md`'s "DOM0 isolation if malware escapes" and the roadmap's Proxmox
  firewall prerequisite both remain open.
- **Unpatched software is a deliberate choice with consequences.** An
  exploitable Office or Reader is what makes exploit samples work; it also
  means a sample can gain more than it otherwise would. Record the patch level
  as a property of the image, because a report means something different
  depending on it.
- **Realism data is real-looking data.** Documents and browser history planted
  for realism must contain nothing genuine — no real names, addresses or
  credentials — because they end up in memory dumps, screenshots and
  `extracted/`, which #37 can publish.
- **More installed software means more idle noise**, which competes with the
  syscall filtering DRAFT-052 exists to fix. The two need measuring together
  or one will quietly undo the other.
- **The PV driver decision is a genuine trade**, not an oversight to fix
  later: performance against detectability, and a guest too slow to finish a
  trace produces nothing at all.

# Documentation changes

- **New:** the package list and realism settings per OS, as a build
  specification a rebuild can be repeated from.
- **Updated:** `docs/checklists/windows.md` — installed software joins the
  Phase 0 items.
- **Updated:** `issue-index.md` — this row's title, which currently describes
  DRAFT-034's work.
- **Updated:** `ideas.md`'s anti-evasion line, largely answered.

# Recovery / rollback

Golden images are rebuilt, not edited, so rollback is restoring the previous
image and its saved state — which is exactly why the checksum and anchor PID
must be recorded before the new one is used.
