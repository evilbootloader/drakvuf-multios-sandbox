# Project Assessment — 2026-08-08

> Scope: a full re-derivation of the project's state from the **current**
> repository, documentation, implementation, and GitHub issue/draft state.
> No prior session's issue plan was assumed. Nothing in the backlog was
> modified, created, closed, or published as part of producing this
> document — recommendations only, for review.

## Project focus change recorded in this assessment

**Windows is now a current target, alongside full Ubuntu and Android — not
a deferred M5 planning spike.** Every document in the repository still
describes it as future work:

| Location | Current wording |
|---|---|
| `CLAUDE.md:11,16` | "(planned) Windows analysis guest"; "Windows is a planned future target" |
| `README.md:10,16` | "L2 Windows analysis VM (planned)" |
| `docs/roadmap/project-roadmap.md:11,18,78` | "Windows(planned)"; "no work started at all" |
| `docs/roadmap/project-roadmap.md:161` | M5 = "Windows planning spike … Design only" |
| `docs/checklists/windows.md` | "skeleton only", Phase 0 only |

That framing is now out of date, and it has consequences well beyond
editing three sentences — it changes what "shared" means for most of the
findings below. **Every fix that touches shared code should be specified
once, for three OS families, rather than fixed for Ubuntu and then
re-discovered twice.** This assessment therefore tags every finding with
its OS applicability.

### The de facto shared/per-OS boundary (source-verified)

`automation/` already splits cleanly, which is the strongest available
argument for fixing shared defects once:

| Shared — no OS in the name, no OS-specific logic | Per-OS — one copy per target |
|---|---|
| `dirwatch.c` (orchestrator; takes domain/config/profile as arguments) | `clone-ubuntu.pl` |
| `network-setup.sh` (takes only a clone count) | `preconfig-ubuntu.sh` |
| `cleanup.sh` (takes only `DOMAIN`, `VLAN` — `cleanup.sh:113-114`) | `drakvuf-ubuntu.sh` |
| `tcpdump.sh` (takes only `VLAN` + folders) | `run_analysis-ubuntu.sh` |

So a defect in the left column is a defect in the Ubuntu, Android **and**
Windows pipelines simultaneously. A defect in the right column will be
**copied into two more files** the moment `clone-android.pl` (DRAFT-015)
and a future `clone-windows.pl` are written — which is now imminent for
both. This is exactly what DRAFT-009 ("shared-vs-OS-specific script
boundary") exists to formalize, and with three concurrent targets it stops
being a tidy-up and becomes a prerequisite.

### What Windows-as-current changes in existing material

- **`tlsmon` stops being "Not applicable".**
  `docs/roadmap/project-roadmap.md:90` and risk #4 (`:180`) both record
  tlsmon as not applicable because it hooks Windows `ncrypt.dll`/Schannel
  only (source-verified in `docs/architecture/networking.md:61-64`). With
  a Windows guest in scope, tlsmon becomes the **one** TLS-visibility path
  the project actually has. Risk #4 should be rescoped from "no TLS
  visibility" to "no TLS visibility *on Ubuntu/Android*", and DRAFT-023's
  research spike gains a concrete Windows baseline to compare against.
- **The `lfreijo/drakvuf` fork matters less for Windows.**
  `docs/architecture/upstream-drakvuf.md:31` records `filetracer`,
  `fileextractor`, `memdump`, `syscalls` plus ~30 Windows-oriented plugins
  as present upstream, and the pinned fork commit
  `8dc77880c405914348539fc6e0952c772f8749dc` is titled "Add **Linux**
  support for memdump, filetracer, fileextractor, and syscalls plugins".
  The Windows track therefore leans on upstream `tklengyel/drakvuf`, not
  the single-maintainer fork — which narrows risk #8's blast radius and
  changes what DRAFT-024 needs to pin (two upstreams with different
  bus-factor profiles, not one).
- **Issue #2's settled `-e` semantics are Linux-only.** The evidence
  reads `[LINUX] (execproc -> execve(const char *file, …); 64bit only)`.
  "`-e` is execve-direct, no guest shell" is now recorded in `CLAUDE.md`,
  the Ubuntu checklist, and DRAFT-007 without that qualifier. It must not
  be carried into Windows injection design unverified.
- **The profile toolchain does not carry over.** Ubuntu and Android
  profiles are produced with `dwarf2json` against kernel debug symbols
  (`docs/drakvuf-on-xen-nested-within-proxmox.md:389`;
  `docs/android_setup.md` §14). Nothing in this repository documents how a
  Windows profile is produced. That is an unresolved prerequisite, not an
  adaptation of an existing step.
- **No Windows infrastructure exists yet in-repo.** There is no
  `misc/windows.cfg` / `misc/windows_sandbox.cfg`, no Windows profile, and
  no `windows` LV in `vg-root`. (The four existing `.cfg` files do already
  carry `viridian = 1` — `misc/*.cfg:20-21` — so the Hyper-V-enlightenment
  side of a Windows HVM config is already the house template.)
- **CI grows a third pipeline.** `docs/workflow-ci.md`'s base snapshot
  holds two golden VMs; DRAFT-026 defines `ubuntu-pipeline` and
  `android-pipeline` stages. A `windows-pipeline` stage and a third golden
  VM (with licensing and disk-size implications the Linux guests don't
  have) now belong in that design.

---

## Method and evidence base

Inspected in this order, per the required workflow:

1. Repository tree (`git ls-files`, working tree, `.gitignore`, file modes).
2. Documentation: `README.md`, `CLAUDE.md`, `CONTRIBUTING.md`,
   `docs/roadmap/project-roadmap.md`, all four `docs/checklists/*.md`, all
   five `docs/architecture/*.md`, `docs/workflow-ci.md`,
   `docs/runbooks/01-verify-user-placeholder.md`,
   `docs/drakvuf-on-xen-nested-within-proxmox.md`, `docs/android_setup.md`.
3. Implementation: every file under `automation/`, every `misc/*.cfg`.
4. DRAKVUF/LibVMI integration surface as this repo actually invokes it
   (`drakvuf -r/-e/-a/--memdump-dir`, `injector -r/-m/-e/-f`, the
   `dirwatch` 15-argument contract, `/etc/libvmi.conf` usage).
5. GitHub issues: 4 total (#1, #2 closed; #3, #4 open), bodies and all
   comments read in full.
6. Issue drafts: 10 `DRAFT-*.md` files, plus `issue-index.md` (which also
   carries the title-only DRAFT-009…DRAFT-024 range) and the drafts
   `README.md`.
7. Local static checks re-run for first-hand evidence (`bash -n`,
   `shellcheck`, `perl -c` — results in CI-01 below).

Manual edits found in the working tree, both intentional and both retained
as the starting point for any future change:

| File | Your edit | Verdict |
|---|---|---|
| `.github/issue-drafts/DRAFT-008.md` | `target_os_source` "likely not needed we only need to know target OS of analysis vm" | **Accepted** — with one Windows-related caveat, see Issue #3. |
| `.github/issue-drafts/DRAFT-025.md` | "LibVMI setup shouldn't be needed as the drakvuf program is run with the profile path during automated analysis" | **Accepted, and confirmed by stronger evidence than the draft had.** See PATH-04. |

Neither edit was reverted, rewritten, or "restored" to an earlier version.

---

## Findings

Stable IDs, referenced by the draft review and by any new draft created
from this assessment. **OS** column: `ALL` = one fix serves Ubuntu,
Android and Windows; `U/A/W` = specific to that pipeline.

### PATH — path and configuration consistency

| ID | OS | Summary |
|---|---|---|
| PATH-01 | ALL | Launcher hard-codes a deployment layout |
| PATH-02 | ALL | Clone script hard-codes saved-state path |
| PATH-03 | ALL | Golden `.cfg` files hard-code installer ISO paths |
| PATH-04 | ALL | LibVMI profile delivery is a smaller question than assumed |

**PATH-01 — the launcher hard-codes a deployment layout.** Six `dirwatch`
arguments point at `/home/user/drakvuf-tools/...`
(`automation/run_analysis-ubuntu.sh:5,13,20-24`) plus a bare
`/root/linux.json` (`:14`). *Multi-OS:* `run_analysis-android.sh` and
`run_analysis-windows.sh` will each need the same seven values. Fixing the
convention once (issue #4) is the difference between one edit and three.
*Covered by issue #4.*

**PATH-02 — `clone-ubuntu.pl:253` hard-codes the saved-state path**
(`/home/user/Documents/ubuntu_sandbox.bak`). *Multi-OS:* `CLAUDE.md`
already names `/home/user/Documents/android_sandbox.bak` as the Android
equivalent, and Windows will add a third. *Covered by issue #4.*

**PATH-03 — the golden Xen configs hard-code installer ISO paths.**
`misc/ubuntu.cfg:24` → `file:/home/user/Documents/ubuntu-20.04.6-…iso`;
`misc/android.cfg:25` → `file:/home/user/drakvuf-tools/Bliss-…iso`. A
Windows `.cfg` will add a third ISO path in a third location. Issue #4
lists both in Context but **no acceptance criterion covers `misc/*.cfg`**
— its criteria name only `automation/*.sh`, `clone-ubuntu.pl`,
`profiles/`, `state/`, and docs. Also interacts with
`docs/workflow-ci.md`'s `/root/isos/` staging. *Partially covered by
issue #4 — needs an added criterion, not a new issue.*

**PATH-04 — LibVMI profile delivery is a smaller question than issue #4
assumes.** Your DRAFT-025 annotation is correct, and the evidence is
stronger than the draft states:

- `drakvuf-ubuntu.sh:122` and `preconfig-ubuntu.sh:125` both pass
  `-r "$REKALL"` explicitly; `dirwatch` supplies that value from its
  `json_kernel_path` argument (`dirwatch.c:477`).
- Clone domains are named `<origin>-<vlan>-clone`
  (`clone-ubuntu.pl:157`), e.g. `ubuntu_sandbox-1-clone`. The documented
  `/etc/libvmi.conf` stanzas cover only `ubuntu` and `ubuntu_sandbox`
  (`docs/drakvuf-on-xen-nested-within-proxmox.md:395-396`). **No clone
  domain has a `libvmi.conf` stanza at all** — so the automated path
  demonstrably never resolves its profile through `libvmi.conf`; it could
  not.
- `libvmi.conf` still matters for *manual/diagnostic* tooling
  (`vmi-process-list android`, `docs/checklists/android.md:250,475`) and
  for `docs/workflow-ci.md`'s base snapshot (`:268,278`) — though even
  there the profile can be passed by path
  (`vmi-process-list -j /root/android.json`,
  `docs/checklists/android.md:567`).

*Multi-OS:* this settles the mechanism for all three targets at once, and
is worth settling **before** a Windows profile exists, since the Windows
profile toolchain is undetermined (see focus-change section) and should
not invent a second delivery convention. *Partially covered by issue #4 —
the PLAN step should be narrowed, not expanded.*

### NET — network containment (all findings: `network-setup.sh`, shared by all three OS families)

**NET-01 `[ALL]` — the only inter-clone isolation rule uses pre-2008
iptables negation syntax.** `network-setup.sh:129`:

```bash
iptables -A FORWARD -i xenbr1.$i -o !xenbr0 -j DROP
```

`-o !xenbr0` is the negation form deprecated in iptables 1.4.3; current
iptables expects `! -o xenbr0` and treats `!xenbr0` as an interface name.
The script has no `set -e` and checks no exit status, so if the rule is
rejected it **fails silently and clone-to-clone isolation simply is not
present**. Must be verified on Dom0 (`iptables -S FORWARD`), not asserted
from here. *Not covered by any issue or draft.*

**NET-02 `[ALL]` — the isolation rule cannot cover traffic to Dom0
itself.** Packets from a clone addressed to a Dom0 IP traverse `INPUT`,
not `FORWARD`, so the `:129` rule does not apply regardless of syntax. No
`INPUT` policy is set anywhere in `automation/`. Every analysis clone —
Ubuntu, Android, and any future Windows clone — can reach **every service
listening on every Dom0 address**, including the Apache instance serving
`/malware_processing` (every other in-flight sample, by name) and any
management service. Maps directly onto two unfilled rows of
`docs/checklists/android.md:429-436`. *Not covered — DRAFT-013 would only
measure it, and only for Android.*

**NET-03 `[ALL]` — analysis clones have unrestricted outbound Internet by
default.** `network-setup.sh:118` installs
`iptables -t nat -A POSTROUTING -o xenbr0 -j MASQUERADE`, `:115` enables
`ip_forward`, and `:129` (when it works) drops everything *except* egress
via `xenbr0`. `docs/architecture/networking.md` proposes
`offline`/`simulated`/`controlled-internet` modes, none implemented.
`docs/checklists/android.md:400` ("no Internet access by default") is
unfilled and would fail today. *Design decision — see "Findings
intentionally not drafted".*

**NET-04 `[ALL]` — `network-setup.sh` does not provision the OVS bridge,
despite being documented as doing so.** It calls `vconfig`/`ip`/`iptables`
only; `xenbr1` is created manually via `ovs-vsctl add-br xenbr1`
(`docs/drakvuf-on-xen-nested-within-proxmox.md:421`). `CLAUDE.md` and
`docs/checklists/ubuntu.md:65-67` both say the script "provisions the OVS
bridge". `vconfig` is also deprecated in favour of
`ip link add link … type vlan`. *Documentation defect + reproducibility
gap in the install path — and it is the install path all three OS
families share.*

**NET-05 `[ALL]` — rules are appended, never flushed, not idempotent.**
`run_analysis-ubuntu.sh:5` calls `network-setup.sh` on every launch; each
run appends another `MASQUERADE` and another per-VLAN `DROP`. With three
per-OS launchers all calling the same script, this compounds: starting the
Ubuntu, Android and Windows pipelines on one host triples the duplication
rather than sharing one provisioning pass. *Not covered.*

### DRAKVUF — pipeline / integration

**DRAKVUF-01 `[ALL]` — sample delivery depends on Apache, and that
dependency is historical rather than required.** `preconfig-ubuntu.sh:122`
stages the sample by making the guest fetch it:
`wget 'http://172.16.$VLAN.1/$RUNFILE' -O '/home/$USER/Desktop/test'`,
served by Apache with `DocumentRoot /malware_processing`
(`docs/drakvuf-on-xen-nested-within-proxmox.md:612-652`). Consequences:

- an extra privileged Dom0 service must be reachable from every clone
  (compounds NET-02, and exposes every in-flight sample by filename);
- guest networking must be **up before the sample can be staged**, which
  makes an `offline` network mode structurally impossible on this path;
- it adds `apache2` to the install and to `docs/workflow-ci.md`'s CI base
  snapshot (`:403`).

`injector -m writefile` is the direct replacement, and the project has
already reached that conclusion — for Android only:
`docs/checklists/android.md:1003` ("Prefer `injector -m writefile` if
supported by the installed branch") and `:1876-1878` ("Prefer direct
host-to-guest file injection. Keep HTTP download only as an optional
compatibility path").

**Decision taken during this review (project owner, 2026-08-08): the HTTP
path is removed outright, not retained as a compatibility option.** It is
preserved in documentation as historical context — what the pipeline used
to do and why it changed — with no fallback code path, flag, or
configuration switch. This supersedes the "keep HTTP download only as an
optional compatibility path" line at
`docs/checklists/android.md:1877`, which should be annotated rather than
rewritten. Rationale: a retained fallback is an untested branch whose only
effect is to restore the exposure the change exists to close. Captured in
DRAFT-027.

*Multi-OS — this is the single highest-leverage finding in the
assessment.* The delivery mechanism is about to be written **three times**:
it exists for Ubuntu, is specified-but-unbuilt for Android (DRAFT-016),
and is unwritten for Windows. Deciding it once, now, means Android and
Windows are never built against the HTTP path, and `wget`-vs-`Invoke-
WebRequest`-vs-`curl` guest-side differences never have to be solved at
all. Deciding it after DRAFT-016 lands means rewriting it. *Not covered
for Ubuntu or as a cross-OS decision.*

**DRAKVUF-02 `[ALL]` — the untrusted sample filename is interpolated into
a guest shell command.** `preconfig-ubuntu.sh:122` embeds `$RUNFILE`
inside a single-quoted URL within a string handed to `/usr/bin/sh -c` in
the guest. A filename containing a single quote closes the quoting and
appends attacker-chosen shell text. `docs/checklists/android.md:1008`
already states the rule this violates — "Never include the untrusted
filename directly in a guest shell command" — as an *Android* requirement
only. Impact is guest-side (inside the sandbox), so it is a hardening
defect rather than a containment break. *Multi-OS:* the Android candidate
at `docs/checklists/android.md:1037-1052` builds a `/system/bin/sh -c`
string the same way, and a Windows equivalent would build a
`cmd.exe`/PowerShell string. Same class, three times. *Not covered for
Ubuntu; specified-but-not-enforced for Android.*

**DRAKVUF-03 `[ALL]` — the same filename flows through Dom0-side command
strings that get shell-parsed.** `dirwatch.c:567` builds
`g_strdup_printf("mv %s/%s %s/%s", …)` from `ent->d_name` and runs it via
`g_spawn_command_line_sync()`, which applies `g_shell_parse_argv()`
quoting/word-splitting. Same for `CLONE_CMD`, `CONFIG_CMD`, `DRAKVUF_CMD`,
`TCPDUMP_CMD` (`dirwatch.c:122-126,176,276,296,186`). A filename with a
space moves the wrong file; one with an unbalanced quote fails to parse.
No shell is spawned, so this is not classic command injection, but it is
unreliable handling of adversary-chosen input at the front door.
*Multi-OS:* `dirwatch.c` is the shared orchestrator — one fix covers all
three pipelines, and it must land before OS routing (DRAFT-014) makes
`dirwatch` handle a wider variety of dropped filenames. *Not covered.*

**DRAKVUF-04 `[ALL]` — process discovery by `ps aux | grep` is not
concurrency safe.** Four sites: `drakvuf-ubuntu.sh:130`,
`cleanup.sh:118,124,134`. The tcpdump match is
`"tcpdump -i xenbr1.$VLAN"` — `.` is a regex wildcard and the match is
unanchored, so VLAN 1's cleanup also matches `xenbr1.10`…`xenbr1.19`.
Bounded today (`run_analysis-ubuntu.sh:19` passes 2 clones); latent above
9 — and running three OS pipelines concurrently is exactly what raises the
clone count. Three of the four sites are in `cleanup.sh`, which is shared.
`docs/checklists/android.md:1250` already proposes a "PID-safe capture
pattern". *Partially covered — belongs in DRAFT-011.*

**DRAKVUF-05 `[ALL]` — `clone-ubuntu.pl`'s per-origin lock is commented
out while `dirwatch` runs workers concurrently.** `use Fcntl qw(:flock)`
remains at `:119`, but acquisition and release are disabled
(`:236-241,255-256`) even though the file's own comment says "Only one
clone process may manipulate a particular origin VM at the same time".
`dirwatch` uses a `GThreadPool` sized by the max-clones argument
(`dirwatch.c:494`). `docs/checklists/android.md:2250` lists "Use `flock`
for per-origin and per-launcher locking" as a requirement; §6.7's
concurrency tests are entirely unfilled. *Multi-OS:* `clone-android.pl`
(DRAFT-015) and a future `clone-windows.pl` will be written **from this
file as the template** — `CLAUDE.md` mandates "Before editing a script,
inspect the corresponding Ubuntu implementation". Fixing the template
before it is copied twice is materially cheaper than fixing three copies.
*Not covered.*

**DRAKVUF-06 `[ALL]` — `clone-ubuntu.pl` checks no exit status.**
`lvremove` (`:247`), `lvcreate -s -n $clone -L64G` (`:250`) and
`xl restore` (`:253`) all run in backticks with output discarded or only
printed; failure is detected indirectly, by `xl domid` later returning
nothing. `-L64G` is hard-coded — and a Windows golden LV is unlikely to
want the same size as an Ubuntu or Android one. *Same template-copying
argument as DRAKVUF-05.* *Not covered.*

### CI — continuous integration readiness

**CI-01 `[ALL]` — `shellcheck automation/*.sh` fails today, at `error`
severity.** Re-run in this container (`shellcheck` 0.11.0):

```
$ shellcheck automation/*.sh >/dev/null; echo $?
1
$ shellcheck -f gcc -S error automation/*.sh | cut -d: -f1 | sort -u
automation/cleanup.sh
automation/drakvuf-ubuntu.sh
automation/network-setup.sh
automation/preconfig-ubuntu.sh
automation/tcpdump.sh
```

Cause: SC1128, "The shebang must be on the first line". Five of six
scripts carry the 103-line DRAKVUF license header *before* `#!/bin/bash`
(shebang at line 104); only `run_analysis-ubuntu.sh` has it at line 1.
`bash -n` and `perl -c` pass cleanly. Not a new regression — inherited
from upstream DRAKVUF's `tools/` scripts, and how the tested production
copies are laid out (execution works because both GLib's `g_spawn` and
`bash` fall back to `/bin/sh` on `ENOEXEC`).

Consequence: `docs/workflow-ci.md:139` specifies
`shellcheck automation/*.sh` verbatim as a Level 1 step, so **the static
tier is red on day one against unmodified, working production code**, with
no baseline, severity threshold, or documented suppression. *Multi-OS:*
whatever convention is chosen (move the shebang / relocate the header /
set a severity floor) becomes the house style that `*-android.sh` and
`*-windows.sh` are written to. Deciding it before six more scripts exist
is the cheap moment. *Not covered by DRAFT-026, which assumes the command
passes.*

**CI-02 `[ALL]` — the `<USER>` regression guard fails when it should
pass.** `docs/workflow-ci.md:147`:

```bash
grep -Rns '<USER>' automation/ && exit 1   # regression guard, see issue #2
```

`grep` exits 1 when it finds nothing, `&&` short-circuits, and the
compound's status is 1. GitHub Actions runs `run:` steps as `bash -e {0}`,
so this **fails the step precisely when the repository is clean**.
Verified: `grep -Rns '<USER>' automation/` exits 1 today. Needs
`if grep -q …; then exit 1; fi` or `! grep …`. *Not covered.*

**CI-03 `[ALL]` — the `ps|grep` anti-pattern check enforces nothing.**
`docs/workflow-ci.md:148` runs the grep with no `exit`, and it matches
four live sites (DRAKVUF-04). As written under `bash -e` it passes (grep
found matches → exit 0), inverting the intended meaning. *Not covered.*

**CI-04 `[ALL]` — two near-identical orchestrator sources, no documented
authority.** `automation/dirwatch.c` (665 lines) and
`automation/dirwatch_old.c` (674 lines) differ on 132 lines, almost
entirely formatting and function ordering — `dirwatch_old.c` is not an
older design but a reformatted sibling (the genuinely old 520-line copy is
in history at `2514168`). The install guide copies only `dirwatch.c`
(`docs/drakvuf-on-xen-nested-within-proxmox.md:531`). A Level 2 build step
needs this stated. *Partially covered — belongs in DRAFT-010.*

**CI-05 `[ALL]` — DRAFT-026's base snapshot bakes in a dependency this
assessment recommends removing, and is one golden VM short.**
`docs/workflow-ci.md:403` installs `apache2` as part of the documented
"Recreating CI" procedure; if DRAKVUF-01 lands, the base snapshot,
recreate checklist, and `ubuntu-pipeline` stage all change. Separately,
the base snapshot holds two golden VMs (`:180`) and the workflow defines
`ubuntu-pipeline` + `android-pipeline` — with Windows current it needs a
third golden VM and a `windows-pipeline` stage, with licensing and
disk-size implications the Linux guests don't carry. *Ordering constraint
+ scope gap, not separate work.*

### DOC — documentation carrying already-completed or now-outdated work

Each still presents finished (or superseded) work as outstanding, which
`CONTRIBUTING.md`'s "Issue dependency and cleanup" section says to remove
rather than carry forward.

**DOC-01 `[ALL]`** — `docs/architecture/networking.md:20` still documents
`ifconfig xenbr1 up`. Issue #2's sync replaced it with
`ip link set xenbr1 up` (`network-setup.sh:121`).
`docs/checklists/ubuntu.md:66-69` was updated; `networking.md` was missed.

**DOC-02 `[U]`** — `docs/checklists/ubuntu.md:192-195` lists as open:
"`[ ]` Reconcile `automation/drakvuf-ubuntu.sh` with the deployed Dom0
copy … No draft/issue yet." **This is done** — issue #2 synced
`automation/` wholesale on 2026-08-08, and the same file's Known-issues
section (`:108-130`) records it as resolved. The file contradicts itself.

**DOC-03 `[ALL]`** — `docs/checklists/ubuntu.md:201-203` marks static-check
CI "blocked on Bash being non-functional in this dev container as of
2026-08-07". `CONTRIBUTING.md:52-54` re-verified Bash working on
2026-08-08; the blocker is stale. It also cites DRAFT-012, recorded in
`issue-index.md` as superseded by DRAFT-026.

**DOC-04 `[ALL]`** — `docs/checklists/ubuntu.md:182-185` states the
hard-coded `/home/user/drakvuf-tools/...` known issue without referencing
issue #4, which now owns it.

**DOC-05 `[W]`** — `docs/checklists/windows.md` Phase 0 carries "`[ ]`
Decide golden-VM lifecycle model (clone-per-run vs. snapshot-restore)"
while the same file's status table records the decision as already made
(clone-per-run, by elimination), matching roadmap decision #3.

**DOC-06 `[ALL]`** — `docs/roadmap/project-roadmap.md` is stamped "Last
updated: 2026-08-07" but contains 2026-08-08 content, and its
Current-state section (`:69-71`) still names `misc/linux_sandbox.cfg` /
`misc/linux.cfg`, renamed by issue #1 on both repo and host.

**DOC-07 `[ALL]`** — `README.md:1` and `CLAUDE.md:1` are titled "DRAKVUF
**Android** Automation Project" for a multi-OS repository
(`drakvuf-multios-sandbox`). `README.md`'s layout section also omits
`docs/runbooks/` and `docs/workflow-ci.md`.

**DOC-08 `[ALL]`** — `docs/architecture/analysis-pipeline.md:44-46` says
the thread-pool bound is "validated 1–128 in upstream; this project's copy
has not been independently re-verified". It has been:
`dirwatch.c:488-492` enforces exactly that range.

**DOC-09 `[W]` (new, from the focus change)** — five documents describe
Windows as planned/not-started (table at the top of this file), risk #4
and the reuse table declare `tlsmon` "Not applicable", and roadmap M5 is
"Design only". All are now inconsistent with the stated project focus.

### GOV — backlog mechanics

**GOV-01 — the backlog is thinner than it appears.** Ten draft files
exist, but seven are closed/historical (DRAFT-001…007). Live planning
material: 2 open issues (#3, #4), 1 unpublished draft (DRAFT-026), and 16
title-only entries (DRAFT-009…DRAFT-024) with no acceptance criteria, one
of which (DRAFT-012) is already superseded. Every NET, DRAKVUF and CI
finding above falls outside all of it.

**GOV-02 — the backlog has no Windows implementation track at all.**
DRAFT-020 ("Windows baseline selection + clone-per-run confirmation") is
the only Windows entry, is title-only, and is scoped as a design spike. By
contrast Android has DRAFT-013/015/016/017 plus a 2,478-line checklist.
With Windows current, the imbalance is now a planning gap rather than a
deliberate deferral.

---

## Existing Issue and Draft Review

### Issue #1 — Reconcile `misc/` Xen guest config naming and cross-references (DRAFT-006)

- **Status:** CLOSED (2026-08-08), both repo and host sides.
- **Assessment:** READY / correctly closed.
- **Still required:** Nothing.
- **Already completed:** Rename, all in-repo cross-references, host-side
  `mv`, re-tested analysis run.
- **Problems with current scope:** None.
- **Recommended changes:** **KEEP AS-IS.** One forward note for the
  Windows track: this issue established that `.cfg` filenames must name
  the domain they define, so a Windows config should be `misc/windows.cfg`
  / `misc/windows_sandbox.cfg` from the start.
- **Dependencies:** —
- **Recommended order:** Done.

### Issue #2 — Verify `drakvuf-ubuntu.sh`'s `<USER>` placeholder (DRAFT-007)

- **Status:** CLOSED (2026-08-08); premise refuted.
- **Assessment:** READY / correctly closed, and the most valuable issue in
  the backlog so far — execution evidence, settled `-e` semantics,
  uncovered repo↔host drift.
- **Still required:** Nothing in this issue. Two follow-ups it correctly
  handed off: drift detection (DRAFT-026) and parameterizing `carlos`
  (open M1 — now a three-OS concern: Ubuntu `carlos`, Android has no
  `/home/<user>` concept at all, Windows will use a third shape).
- **Already completed:** All three acceptance criteria + the `automation/`
  sync.
- **Problems with current scope:** Its `-e` conclusion is recorded without
  the `[LINUX]` qualifier the source evidence carries (see focus-change
  section). Not wrong, but over-general once Windows is in scope.
- **Recommended changes:** **KEEP AS-IS**, but when
  `docs/checklists/ubuntu.md` is next edited (DRAFT-032), add the
  Linux-only qualifier so the finding isn't inherited by Windows design.
  Note DOC-02: a task this issue completed is still listed as open at
  `docs/checklists/ubuntu.md:192-195`.
- **Dependencies:** —
- **Recommended order:** Done.

### Issue #3 / DRAFT-008 — Define OS-independent analysis job/result state model

- **Status:** OPEN, published.
- **Assessment:** **READY, with one scope reduction** (your edit) — and
  **materially more important** now that three OS families are current.
  The problem is entirely real: `drakvuf-ubuntu.sh:118` keys results by
  MD5 with a two-outcome model, `android.md` §7.3 proposes SHA-256 with a
  twelve-state machine, Windows has nothing.
- **Still required:** All of it — field list, state machine, per-OS status
  mapping, recovery-after-interruption. This is the issue whose title
  literally promises OS-independence, so Windows must be a first-class
  input to it rather than a later adaptation.
- **Already completed:** Nothing.
- **Problems with current scope:**
  - The published GitHub body still contains `target_os_source` without
    your annotation — issue and draft have diverged.
  - Windows is mentioned only as "the planned Windows pipeline". With
    Windows current, the state machine needs at least one Windows-specific
    state consideration (e.g. PE execution vs. Android's
    install→launch→stimulate sequence, which has no Ubuntu analogue).
  - `docs/architecture/result-schema.md` §3 poses the MD5-vs-SHA-256
    question independently — two documents will answer it unless one
    defers.
- **Recommended changes:** **EDIT EXISTING.**
  - Adopt your `target_os_source` removal in the published body. Your
    reasoning holds under the current architecture: `dirwatch` hard-codes
    one origin domain per invocation (`dirwatch.c:475`), so the target OS
    is a property of the launcher, not a per-sample discovery.
  - Add one sentence, not the field back: if DRAFT-014's auto-detection
    contract has to disambiguate Android ELF from Linux ELF, **or PE32
    from PE32+ for the Windows track**, revisit provenance *then*, with
    evidence. Do not reintroduce it silently.
  - State that this issue owns the MD5→SHA-256 keying decision and
    `result-schema.md` §3 defers to it.
  - Require the state machine to be validated against all three OS
    sequences before acceptance, not two.
- **Dependencies:** None open. Blocks DRAFT-009, DRAFT-011, DRAFT-018, and
  any Windows implementation track.
- **Recommended order:** **1st.** Cheap, unblocks the most, and the cost
  of getting it wrong triples with the third OS.

### Issue #4 / DRAFT-025 — Standardize Xen analysis pipeline paths

- **Status:** OPEN, published.
- **Assessment:** **NEEDS UPDATE.** Sound and well-scoped; three specifics
  have moved.
- **Still required:** `SCRIPT_DIR`/`REPO_ROOT` and `FindBin` resolution,
  `dirwatch` argument values, `profiles/`+`state/` layout, `.gitignore`
  decision, doc updates.
- **Already completed:** The `automation/`↔Dom0 sync (issue #2) means the
  files this issue relocates are now the *tested production* copies — a
  precondition it assumed but could not rely on.
- **Problems with current scope:**
  - PLAN step 2 (LibVMI delivery) is largely settled by your annotation.
    Evidence beyond what the draft states: clone domains have **no**
    `/etc/libvmi.conf` stanza, so the automated path provably resolves
    profiles only through `-r`. What remains is narrower: referenced in
    place vs. copied to a runtime path, and whether `libvmi.conf` stanzas
    are still wanted for `vmi-process-list`.
  - PATH-03: `misc/*.cfg` ISO paths appear in Context, in no acceptance
    criterion.
  - `docs/workflow-ci.md` did not exist when this issue was written and is
    now a major consumer of these paths; not in Documentation changes.
  - The proposed layout (`profiles/`, `state/`) names only `linux.json`
    and `android.json`, and the acceptance criteria name only
    DRAFT-015/016 as downstream consumers. Windows needs a slot in both.
- **Recommended changes:** **EDIT EXISTING.**
  - Narrow PLAN step 2 per your annotation + the clone-stanza evidence.
  - Add an acceptance criterion for `misc/*.cfg` ISO paths (or explicitly
    scope them out — but say which).
  - Add `docs/workflow-ci.md` to Documentation changes.
  - Extend the layout and the final acceptance criterion to three OS
    families, so `profiles/windows.json` / `state/windows_sandbox.bak` /
    `misc/windows*.cfg` inherit the convention rather than needing a
    fourth pass.
  - Note that DRAFT-033 (proposed below) also edits `clone-ubuntu.pl`;
    sequence them.
- **Dependencies:** None open. Soft-blocks DRAFT-026b, DRAFT-015,
  DRAFT-016, and the Windows track.
- **Recommended order:** **2nd.** Ahead of any new per-OS script.

### DRAFT-001 … DRAFT-005 (governance, closed 2026-08-07)

- **Status:** Closed; retained as historical record.
- **Assessment:** READY / complete. DRAFT-003's acceptance criterion about
  removing the pre-reorg checklist is satisfied by a different mechanism
  than planned, and says so.
- **Recommended changes:** **KEEP AS-IS.** Do not publish retroactively.

### DRAFT-006, DRAFT-007 (closed)

- **Status:** Closed as issues #1 and #2.
- **Recommended changes:** **KEEP AS-IS.** Both carry accurate resolution
  sections; DRAFT-007's is the most useful document in the directory.

### DRAFT-026 — GitHub Actions + self-hosted Xen integration runner

- **Status:** Drafted, not published.
- **Assessment:** **NEEDS SPLITTING**, and **NEEDS UPDATE** on five
  concrete points.
- **Still required:** Both tiers are wanted; `docs/workflow-ci.md` is an
  unusually thorough design (security model, Proxmox-API snapshot reset
  over Tailscale, artifact exclusions).
- **Already completed:** Nothing. No `.github/workflows/` exists.
- **Problems with current scope:**
  - **Bundling.** Level 1 needs a YAML file and nothing else. Level 2
    needs a Proxmox API token, Tailscale ACLs, an L0 supervisor loop, a
    rebuilt base snapshot with (now) three golden VMs, and a benign
    fixture set that `docs/checklists/android.md` §6.4 records as
    unpopulated. As one issue, the cheap half waits on the expensive half.
  - **CI-01.** Level 1's `shellcheck automation/*.sh` fails today on five
    of six scripts at error severity; the draft assumes it passes.
  - **CI-02.** The `<USER>` guard fails when the repo is clean.
  - **CI-03.** The `ps|grep` check enforces nothing and its exit-code
    behaviour is inverted relative to intent.
  - **CI-05 / ordering.** The base snapshot installs `apache2`; if
    DRAKVUF-01 lands, that step and `ubuntu-pipeline` change — the
    "don't build CI around behaviour you're about to replace" hazard.
    Separately, the snapshot is now one golden VM short and the workflow
    is missing a `windows-pipeline` stage.
  - **CI-04.** Level 2 compiles `dirwatch.c` from the PR; `dirwatch_old.c`
    has no stated role.
- **Recommended changes:** **SPLIT**, then **EDIT EXISTING** on both
  halves:
  - **DRAFT-026a — static tier.** `ci-static.yml` only. Depends on
    DRAFT-031. Fix both grep constructs. Make the script glob OS-agnostic
    (`automation/*.sh`, `automation/*.pl`) so Android and Windows scripts
    are covered on arrival with no workflow edit. No dependency on
    DRAFT-025, Dom0, Proxmox, or fixtures — landable within days.
  - **DRAFT-026b — self-hosted integration tier.** Everything else.
    Depends on DRAFT-025 (paths), DRAFT-024 (pinned revisions — Level 2
    rebuilds from source with nothing to pin against), DRAFT-027 (so the
    base snapshot isn't built around Apache), and a benign fixture set.
    Add the third golden VM and `windows-pipeline`, defined-but-inactive,
    the same way `android-pipeline` already is.
  - Add DRAFT-024 as a hard dependency; the draft doesn't mention it. Note
    that it now has **two** upstreams to pin with different bus-factor
    profiles (upstream `tklengyel` for the Windows plugins, the
    single-maintainer `lfreijo` fork for Linux/Android).
  - Add the `dirwatch_old.c` disposition (or reference DRAFT-010).
- **Recommended order:** 026a **4th**; 026b **late**.

### Title-only entries, DRAFT-009 … DRAFT-024

Assessed against current state; none has acceptance criteria yet. **OS**
column flags where the three-target focus changes the entry.

| ID | Title (abbrev.) | OS | Assessment | Recommendation |
|---|---|---|---|---|
| 009 | Shared-vs-OS-specific script boundary | ALL | **NEEDS UPDATE — priority should rise sharply** | EDIT: with Android *and* Windows scripts both imminent, this stops being tidy-up and becomes the gate that prevents triplicating DRAKVUF-01/02/05/06. Cite the source-verified 4-shared/4-per-OS split above as its starting point |
| 010 | Document `dirwatch.c` interface + upstream #140 divergence | ALL | NEEDS UPDATE | EDIT: add CI-04 (`dirwatch_old.c` authority); note the `#include <config.h>` / `../xen_helper/` constraint making it DRAKVUF-tree-only; note `dirwatch` hard-codes one origin domain per invocation, so three concurrent OS pipelines means three `dirwatch` processes unless the contract changes |
| 011 | Retrofit Ubuntu structured status output | U → ALL | **PARTIALLY OBSOLETE — scope should shrink, then widen** | EDIT: drop "reconcile with deployed copy" (issue #2 did it); add DRAKVUF-04's PID-safety (3 of 4 sites are in shared `cleanup.sh`, so that part is not Ubuntu-only); dependency on DRAFT-007 is closed |
| 012 | Add static CI | ALL | **FULLY OBSOLETE** | Superseded by DRAFT-026a. Still cited live by `docs/checklists/ubuntu.md:201` and roadmap M1 — DOC-03. DO NOT CREATE |
| 013 | Close Android §1.3 network isolation verification | A → ALL | **NEEDS UPDATE** | EDIT: the mechanism under test is `network-setup.sh`, **shared by all three OS families**, so retitle away from Android-only; record NET-02/NET-03 as expected findings so the test isn't written assuming a pass. Verification stays here; fixes go to DRAFT-028/029 |
| 014 | Sample OS auto-detection contract | ALL | **NEEDS UPDATE** | EDIT: the title-index parenthetical already says "magic/MIME/PE/ELF/APK", so PE was anticipated — but with Windows current this moves from a two-way ELF/APK split to a genuine three-way routing decision, and it is the piece that makes `dirwatch`'s one-domain-per-invocation contract (DRAFT-010) actually limiting |
| 015 | `clone-android.pl` | A | READY | KEEP AS-IS — must follow DRAFT-025's convention and DRAFT-033's error-handling/locking pattern rather than copying today's `clone-ubuntu.pl` verbatim |
| 016 | `preconfig-android.sh` / `drakvuf-android.sh` | A | READY | KEEP AS-IS — **DRAKVUF-01 must be decided first** so Android is not built against the HTTP delivery path |
| 017 | Android sample classification | A | READY | KEEP AS-IS — consumes DRAFT-014 |
| 018 | Artifact/result schema | ALL | READY | KEEP AS-IS — defer MD5/SHA-256 keying to issue #3 |
| 019 | capa integration | ALL | READY | KEEP AS-IS |
| 020 | Windows baseline + clone-per-run | W | **PARTIALLY OBSOLETE, and now under-scoped** | EDIT: the lifecycle decision is resolved (roadmap #3), so drop it (DOC-05). But with Windows current this is no longer a design spike — it needs to become the head of a real Windows track (baseline, profile toolchain, injection anchor, `misc/windows*.cfg`), mirroring what DRAFT-013/015/016/017 are for Android. See GOV-02 and DRAFT-034 below |
| 021 | Licensing review write-up | — | **PARTIALLY OBSOLETE** | EDIT: desk research is written (`docs/architecture/licensing.md`); what remains is real legal review. Retitle to reflect that |
| 022 | Legal/compliance research (Spain/EU) | — | READY | KEEP AS-IS |
| 023 | TLS-visibility spike | A/U → +W | **NEEDS UPDATE** | EDIT: premised on "tlsmon confirmed N/A". With Windows current, tlsmon is **applicable** to the Windows track and becomes the project's only working TLS-visibility path. Rescope to "TLS visibility: adopt tlsmon for Windows; research options for Ubuntu/Android". Roadmap risk #4 and the reuse table (`:90`) need the same correction |
| 024 | Upstream fork mirror + pin documentation | ALL | **READY, priority should rise** | EDIT: raise from P2. DRAFT-026b rebuilds DRAKVUF/LibVMI from source every job with nothing pinned. Now spans **two** upstreams — `tklengyel` (Windows plugins, healthy) and `lfreijo` (Linux/Android, single-maintainer, risk #8) |

---

## Recommended implementation order

Derived from the dependencies above, not from the example chain. Bracketed
tags show which pipelines each item serves.

```
 1. Issue #3   [ALL] job/result state model            design; no deps; unblocks 009/011/018 + Windows
 2. Issue #4   [ALL] path standardization              touches every script; before any new per-OS script
 3. DRAFT-009  [ALL] shared-vs-per-OS script boundary  gate against triplicating DRAKVUF-01/02/05/06
 4. DRAFT-031  [ALL] shellcheck error-severity baseline  prerequisite for any static CI
 5. DRAFT-026a [ALL] static CI tier                    needs 031; cheap, high leverage
 6. DRAFT-032  [ALL] documentation reconciliation      removes completed work; records Windows focus
 7. DRAFT-028  [ALL] network-setup.sh: rule syntax, fail-fast, idempotent
 8. DRAFT-013  [ALL] isolation verification            measure after 028; covers all three, not Android only
 9. DRAFT-029  [ALL] restrict clone access to Dom0 services   needs 013's measurements
10. DRAFT-027  [ALL] replace Apache delivery with injector writefile   before 016 and the Windows track
11. DRAFT-030  [ALL] untrusted filename handling in dirwatch.c   before 014 widens the input surface
12. DRAFT-033  [ALL] clone-*.pl error handling + flock  fix the template before it is copied twice
13. DRAFT-024  [ALL] pin/mirror both DRAKVUF upstreams + LibVMI
14. DRAFT-010  [ALL] document dirwatch.c interface, incl. dirwatch_old.c
15. DRAFT-014  [ALL] sample OS auto-detection contract  now a genuine 3-way routing decision
16. DRAFT-011  [ALL] structured status output          needs #3
17. DRAFT-034  [W]   Windows track head                new; needs #3, #4, 009
18. DRAFT-015/016/017  [A] Android Phase 2             needs 009, 013, 014, 027
19. DRAFT-026b [ALL] self-hosted integration CI        needs #4, 024, 027, 034, fixtures
```

Four ordering points worth stating explicitly:

- **DRAFT-009 early (position 3), not late.** It was drafted when only
  Ubuntu existed and Android was next. With Android and Windows both
  imminent, every shared-code defect fixed after it is fixed once; every
  one fixed before it risks being fixed three times. This is the single
  largest ordering change this assessment recommends.
- **DRAFT-027 before DRAFT-016 and before DRAFT-026b.** The delivery
  mechanism is about to be written for Android and Windows. Deciding it
  after DRAFT-016 lands means rewriting Android's preconfig script; and
  the CI base snapshot installs and configures Apache, so building,
  snapshotting and documenting that before removing it is wasted work.
- **DRAFT-028 before DRAFT-013.** Verifying isolation before fixing a rule
  that may never have installed produces a test record of a known-broken
  state. Fix, then measure, then set policy (029).
- **DRAFT-034 (Windows) after #3/#4/009, not before.** Starting Windows
  implementation ahead of the shared decisions is precisely how the
  three-copies problem happens. The *documentation* half of the focus
  change (DOC-09, inside DRAFT-032) can land immediately and
  independently.

---

## Findings intentionally *not* turned into drafts

| Finding | Why not |
|---|---|
| NET-03 (Internet-by-default) | A **design decision**, not a defect — the current lab deliberately gives clones NAT egress, and `01-verify-user-placeholder.md:55` relies on gateway reachability. The `offline`/`simulated`/`controlled-internet` modes in `docs/architecture/networking.md` are M2 containment-design work spanning all three OS families. Recommend recording observed behaviour in DRAFT-013's test table and deciding modes as part of that design. |
| NET-04 (`vconfig` / OVS provisioning gap) | Split across two owners already: the documentation half is DRAFT-032's; the `vconfig`→`ip link` modernization touches production networking and belongs inside DRAFT-028 rather than as its own unit. |
| DRAKVUF-04 (`ps\|grep` PID safety) | Already anticipated by `docs/checklists/android.md` §2.10 and squarely inside DRAFT-011's "retrofit without behaviour change" scope. Recommend an EDIT to DRAFT-011 (widened to note 3 of 4 sites are in shared `cleanup.sh`), not a new draft. |
| CI-04 (`dirwatch_old.c`) | One-line disposition question; belongs in DRAFT-010, which exists to document exactly this file. |
| CI-05 (Apache in base snapshot / third golden VM) | An ordering constraint and a scope gap in DRAFT-026, not independent work. Handled by the SPLIT + EDIT recommendation. |
| DOC-07, DOC-08 | Folded into DRAFT-032's enumerated list rather than drafted separately. |
| Guest username `carlos` parameterization | Already tracked as open M1 work in `CLAUDE.md`, `docs/checklists/ubuntu.md:204-207`, and issue #2's closing comment. Belongs to DRAFT-009/DRAFT-011. Worth noting it is genuinely three-shaped: Ubuntu has `/home/carlos`, Android has no such concept, Windows a third form — which is an argument for DRAFT-009 landing first. |
| `tlsmon` adoption for Windows | Real and newly-available, but it is a *rescope of DRAFT-023*, not new work. Recommended as an EDIT above. |

---

## Summary counts

| Metric | Count |
|---|---|
| Existing GitHub issues reviewed | **4** (2 open, 2 closed) |
| Existing closed issues reviewed | **2** (#1, #2) |
| Existing drafts reviewed | **10 files** + **16 title-only entries** = **26** |
| Recommend **KEEP AS-IS** | **14** (DRAFT-001…007, 015, 016, 017, 018, 019, 022; issues #1, #2 — counted as 14 distinct items) |
| Recommend **EDIT EXISTING** | **11** (issues #3, #4 + DRAFT-008/025 to match; DRAFT-009, 010, 011, 013, 014, 020, 021, 023, 024) |
| Recommend **SPLIT** | **1** (DRAFT-026 → 026a static / 026b self-hosted) |
| Recommend **MERGE** | **0** |
| **PARTIALLY OBSOLETE** | **4** (DRAFT-011, 020, 021, 023) |
| **FULLY OBSOLETE** | **1** (DRAFT-012, superseded by DRAFT-026) |
| **DUPLICATED** | **0** |
| **BLOCKED** | **4** (DRAFT-009/014 on issue #3; DRAFT-015/016/017 on 009/013/014; DRAFT-026b on #4/024/027; DRAFT-034 on #3/#4/009) |
| **ALREADY IMPLEMENTED** (still listed as open work) | **3** (DOC-02, DOC-03, DOC-05) |
| Findings raised | **29** across PATH/NET/DRAKVUF/CI/DOC/GOV |
| — of which affect **all three** OS pipelines | **22** |
| Findings already covered by an open issue | **2** (PATH-01, PATH-02 → issue #4) |
| Findings partially covered (EDIT, not a new issue) | **6** (PATH-03, PATH-04, DRAKVUF-04, CI-04, CI-05, NET-04) |
| Findings intentionally not drafted | **7** |
| **Genuinely uncovered → new drafts justified** | **8** |

---

## New drafts created

Created after the review above, per the required order (assess → review
backlog → design remaining work → draft). Each was checked against every
open issue, every existing draft, and the current implementation before
being written; each names its originating finding. All are **drafts only**
— nothing published, nothing committed.

Indexed in `.github/issue-drafts/issue-index.md` under "Second batch".

### DRAFT-027 — Replace HTTP/Apache sample delivery with direct guest injection

- **Priority:** P0 · **OS:** ALL
- **Assessment finding:** DRAKVUF-01 (with NET-02, CI-05)
- **Why a new draft was required:** The Android checklist states the
  preference (`:1003`, `:1876-1878`) but no issue or draft owns changing
  the Ubuntu pipeline, and nothing generalizes the decision. Issue #4
  explicitly scopes in-guest paths out.
- **Dependencies:** Issue #4. **Blocks** DRAFT-016 and DRAFT-026b.
- **Recommended order:** 10th overall — but **must precede** DRAFT-016 and
  DRAFT-026b.
- **Note:** incorporates the owner's decision to remove the HTTP path
  rather than retain it as a fallback.

### DRAFT-028 — Make `network-setup.sh` fail loudly, install correct rules, and be idempotent

- **Priority:** P0 · **OS:** ALL
- **Assessment finding:** NET-01, NET-04, NET-05
- **Why a new draft was required:** DRAFT-013 verifies Android isolation;
  nothing owns the shared implementation. The rule may never have
  installed, and the script cannot report that it didn't.
- **Dependencies:** none. **Blocks** DRAFT-013.
- **Recommended order:** 7th — before DRAFT-013.

### DRAFT-029 — Restrict analysis-clone access to Dom0 host services

- **Priority:** P0 · **OS:** ALL
- **Assessment finding:** NET-02
- **Why a new draft was required:** A `FORWARD`-chain rule cannot cover
  traffic to Dom0 itself, so this is not fixable inside DRAFT-028; and
  DRAFT-013 measures rather than remediates. Kept separate from DRAFT-028
  so a rule-correctness change and a policy change are never entangled in
  one Dom0 deployment.
- **Dependencies:** DRAFT-028, DRAFT-013; strongly benefits from
  DRAFT-027.
- **Recommended order:** 9th.

### DRAFT-030 — Stop passing untrusted sample filenames through shell-parsed command lines

- **Priority:** P1 · **OS:** ALL
- **Assessment finding:** DRAKVUF-03 (with DRAKVUF-02)
- **Why a new draft was required:** `docs/checklists/android.md:1008`
  states the rule for Android guest commands only. Nothing covers the
  Dom0-side orchestrator, where the filename first enters the pipeline.
- **Dependencies:** none. Should precede DRAFT-014.
- **Recommended order:** 11th.

### DRAFT-031 — Establish a `shellcheck` baseline that `automation/` actually passes

- **Priority:** P1 · **OS:** ALL
- **Assessment finding:** CI-01
- **Why a new draft was required:** DRAFT-026 specifies
  `shellcheck automation/*.sh` as a gate and assumes it passes. It exits 1
  today at error severity on five of six scripts. The fix touches
  production scripts and the DRAKVUF licence header, so it is not a
  workflow-authoring detail.
- **Dependencies:** none. **Blocks** DRAFT-026a.
- **Recommended order:** 4th.

### DRAFT-032 — Reconcile documentation with issues #1/#2 and the three-OS project focus

- **Priority:** P1 · **OS:** ALL
- **Assessment finding:** DOC-01…DOC-09, NET-04, GOV-02
- **Why a new draft was required:** `CONTRIBUTING.md` requires completed
  work to be removed from open lists rather than carried forward; three
  such items exist, plus statements invalidated by issues #1/#2 and five
  locations still describing Windows as deferred. Bounded and enumerated,
  not an open-ended docs pass.
- **Dependencies:** none — deliberately independent so it can land first.
- **Recommended order:** 6th, but landable at any time.

### DRAFT-033 — Make `clone-ubuntu.pl` fail safely and lock, before it is copied twice

- **Priority:** P1 · **OS:** ALL (template)
- **Assessment finding:** DRAKVUF-05, DRAKVUF-06
- **Why a new draft was required:** The script's own stated safety
  requirement is commented out while `dirwatch` runs concurrent workers,
  and `docs/checklists/android.md:2250` lists locking as a requirement for
  the *Android* port only. `CLAUDE.md` directs new clone scripts to be
  written from this file, so the defect is about to be duplicated twice.
- **Dependencies:** Issue #4 (same file).
- **Recommended order:** 12th — but before DRAFT-015.

### DRAFT-034 — Establish the Windows analysis-guest track

- **Priority:** P1 · **OS:** W
- **Assessment finding:** Project focus change; GOV-02, DOC-09
- **Why a new draft was required:** DRAFT-020 is a title-only design spike
  whose lifecycle question is already resolved. With Windows current, the
  backlog needs a track head equivalent to what DRAFT-013/015/016/017 are
  for Android — and the Windows profile toolchain, injection semantics and
  anchor are genuine unknowns, not adaptations of documented Linux steps.
- **Dependencies:** Issue #3, Issue #4, DRAFT-009, DRAFT-027. Supersedes
  DRAFT-020's remaining half.
- **Recommended order:** 17th — after the shared decisions, and after
  DRAFT-028/029, so the first Windows guest is not built on an
  unverified analysis network.

---

## Final backlog state

```text
Existing open issues reviewed:      2   (#3, #4)
Existing closed issues reviewed:    2   (#1, #2)
Existing drafts reviewed:          26   (10 files + 16 title-only entries)

Existing drafts — KEEP AS-IS:      14
Existing drafts — EDIT EXISTING:   11
Existing drafts — SPLIT:            1   (DRAFT-026 → 026a / 026b)
Existing drafts — MERGE:            0
Existing drafts — PARTIALLY OBSOLETE: 4 (DRAFT-011, 020, 021, 023)
Existing drafts — FULLY OBSOLETE:   1   (DRAFT-012)

New drafts created:                 8   (DRAFT-027 … DRAFT-034)
Findings intentionally not drafted: 7
```

Nothing was published, closed, edited on GitHub, committed, or pushed.

## Where the recommendations were applied

The assessment above was produced first, with no draft modified. The
recommendations were then written into the draft files themselves, on
request:

| Draft | What was added |
|---|---|
| `DRAFT-008.md` | Windows-as-current note on the Objective; blocking relationships in Dependencies; an assessment note under PLAN step 2 recording *why* dropping `target_os_source` holds and the single condition under which DRAFT-014 would revisit it; new PLAN steps 6–7 (validate against three OS sequences; own the MD5/SHA-256 decision); three acceptance criteria. |
| `DRAFT-025.md` | Reserved `profiles/windows.json` / `state/windows_sandbox.bak` slots in the layout diagram; the PATH-04 evidence supporting the LibVMI annotation, with PLAN step 2 narrowed to two concrete questions; repo-size context on PLAN step 3; a new PLAN step 5 for the `misc/*.cfg` ISO paths; four acceptance criteria; a DRAFT-027 caveat in Security considerations; `docs/workflow-ci.md` and `docs/checklists/windows.md` in Documentation changes. |
| `DRAFT-026.md` | A "Recommended split" section; four added dependencies (DRAFT-031, 024, 027, 034) with reasoning; the corrected `<USER>` and `ps\|grep` grep constructs written out in CREATE; three golden VMs and a `windows-pipeline` stage; the `dirwatch_old.c` ambiguity; eight acceptance criteria. |
| `issue-index.md` | The second-batch table for DRAFT-027…034; recommended order; and an "Assessment notes on DRAFT-009 … DRAFT-024" table — those sixteen entries have no draft files, so their corrections wait in the index to be applied when each is drafted in full. |

**Both of your manual annotations were preserved verbatim.** The DRAFT-008
`target_os_source` note and the DRAFT-025 LibVMI note are untouched; the
additions sit around them as supporting evidence and consequences, not as
replacements.

The published bodies of issues #3 and #4 have therefore diverged from their
drafts, deliberately. Reconciling them means `gh issue edit`, which
`CONTRIBUTING.md` gates behind explicit approval — not done.
