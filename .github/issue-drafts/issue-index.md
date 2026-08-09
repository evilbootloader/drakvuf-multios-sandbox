# Issue index

Full draft-title index, first batch (DRAFT-001 through DRAFT-008 — the
scope approved for this session). See `docs/roadmap/project-roadmap.md` for
the complete brainstormed workstream list this was derived from, and for
DRAFT-009 onward (not yet drafted in full, title-index only).

| Draft ID | Title | Area | Milestone | Priority | Depends on | Status |
|---|---|---|---|---|---|---|
| DRAFT-001 | Initialize git repository and commit current baseline | governance | M0 | P0 | — | **Closed** — done 2026-08-07 |
| DRAFT-002 | Add root README.md | governance | M0 | P1 | DRAFT-001 | **Closed** — done 2026-08-07 |
| DRAFT-003 | Reorganize docs/ into roadmap/architecture/checklists, preserving Android checklist evidence verbatim | governance | M0 | P0 | DRAFT-001 | **Closed** — done 2026-08-07 |
| DRAFT-004 | Fix checklist doc-reference and provenance-list defects | governance | M0 | P2 | DRAFT-003 | **Closed** — done 2026-08-07 |
| DRAFT-005 | Add CONTRIBUTING.md capturing PLAN→CREATE→TEST→DEPLOY lifecycle + issue template | governance | M0 | P1 | DRAFT-003 | **Closed** — done 2026-08-07 |
| DRAFT-006 | Reconcile `misc/` Xen guest config naming and cross-references | governance | M0 | P2 | DRAFT-001 | **Closed** — [#1](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/1), done 2026-08-08 |
| DRAFT-007 | Verify `drakvuf-ubuntu.sh`'s `<USER>` placeholder bug against real behavior | ubuntu | M1 | P0 | DRAFT-001 | **Closed** — [#2](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/2), done 2026-08-08; premise refuted (see note below) |
| DRAFT-008 | Define OS-independent analysis job/result state model | core | M0 | P0 | DRAFT-001 | Published — [#3](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/3) |
| DRAFT-025 | Standardize Xen analysis pipeline paths | platform | M0 | P1 | DRAFT-001; informed by DRAFT-006, DRAFT-007 | Published — [#4](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/4) |
| DRAFT-026 | Implement GitHub Actions and self-hosted Xen integration runner | ci | M1 | P1 | DRAFT-001; soft dep. on DRAFT-025; supersedes DRAFT-012; informed by DRAFT-006, DRAFT-007 | Drafted, not published — see `.github/issue-drafts/DRAFT-026.md` |

## Second batch — DRAFT-027 through DRAFT-034

Added 2026-08-08 from the backlog review in `project-assessment.md`. Each
entry names the assessment finding that produced it; none duplicates an
open issue or an existing draft (see that document's "Existing Issue and
Draft Review" for the coverage check). All are **drafted, not published**.

The `OS` column reflects the project's three current targets — Ubuntu,
Android and Windows. `ALL` means one fix serves all three, because the
code it touches is in the shared half of `automation/` (`dirwatch.c`,
`network-setup.sh`, `cleanup.sh`, `tcpdump.sh`) or is a decision the
per-OS scripts inherit.

| Draft ID | Title | Area | OS | Milestone | Priority | Depends on | Origin finding |
|---|---|---|---|---|---|---|---|
| DRAFT-027 | Replace HTTP/Apache sample delivery with direct guest injection | core/platform | ALL | M1 → M2/M3 | P0 | Issue #4; blocks DRAFT-016, DRAFT-026b | DRAKVUF-01 |
| DRAFT-028 | Make `network-setup.sh` fail loudly, install correct rules, and be idempotent | platform/networking | ALL | M2 | P0 | — (blocks DRAFT-013) | NET-01, NET-04, NET-05 |
| DRAFT-029 | Restrict analysis-clone access to Dom0 host services | platform/security | ALL | M2 | P0 | DRAFT-028, DRAFT-013; benefits from DRAFT-027 | NET-02 |
| DRAFT-030 | Stop passing untrusted sample filenames through shell-parsed command lines | core | ALL | M1 | P1 | — (should precede DRAFT-014) | DRAKVUF-03, DRAKVUF-02 |
| DRAFT-031 | Establish a `shellcheck` baseline that `automation/` actually passes | testing | ALL | M1 | P1 | — (blocks DRAFT-026a) | CI-01 |
| DRAFT-032 | Reconcile documentation with current project direction and closed issues #1/#2 | governance/docs | ALL | M0 | P1 | — | DOC-01…DOC-09, NET-04, GOV-02; extended 2026-08-09 by the comment audit (CONF-02/03/04/06/07/08/11/12, DOC-N4/N5/N6, TODO-03) |
| DRAFT-033 | Make `clone-ubuntu.pl` fail safely and lock, before it is copied twice | core/ubuntu | ALL (template) | M1 | P1 | Issue #4 | DRAKVUF-05, DRAKVUF-06 |
| DRAFT-034 | Establish the Windows analysis-guest track (baseline, profile, anchor, configs) | windows | W | M5 → current | P1 | Issue #3, Issue #4, DRAFT-009, DRAFT-027; supersedes DRAFT-020's design half | Focus change; GOV-02, DOC-09 |

### Recommended order for this batch

Interleaved with the existing backlog, per `project-assessment.md`'s
"Recommended implementation order":

```
Issue #3 → Issue #4 → DRAFT-009 → DRAFT-031 → DRAFT-026a → DRAFT-032
        → DRAFT-028 → DRAFT-013 → DRAFT-029 → DRAFT-027 → DRAFT-030
        → DRAFT-033 → DRAFT-024 → DRAFT-010 → DRAFT-014 → DRAFT-011
        → DRAFT-034 → DRAFT-015/016/017 → DRAFT-026b
```

Two ordering constraints are load-bearing rather than preferences:

- **DRAFT-027 before DRAFT-016 and DRAFT-026b.** The sample-delivery
  mechanism is about to be written for Android and Windows, and the CI
  base snapshot currently installs Apache (`docs/workflow-ci.md:403`).
  Deciding delivery afterwards means rewriting both.
- **DRAFT-028 before DRAFT-013.** Verifying isolation before fixing a rule
  that may never have installed only records a known-broken state.

### Recommendations affecting existing entries

Where the recommendations from `project-assessment.md` now live:

| Entry | Recommendation recorded in |
|---|---|
| DRAFT-008 / issue #3 | `DRAFT-008.md` — assessment notes added inline to Objective, Dependencies, PLAN step 2, and Acceptance criteria |
| DRAFT-025 / issue #4 | `DRAFT-025.md` — added to the layout diagram, PLAN steps 2/3/5, Acceptance criteria, Security considerations, Documentation changes |
| DRAFT-026 | `DRAFT-026.md` — new "Recommended split" section, plus fixes in Dependencies, CREATE and Acceptance criteria |
| DRAFT-009 … DRAFT-024 | The "Assessment notes" table at the end of this file — these have no draft files yet, so the corrections wait there |

**Applied to the draft files; not applied to GitHub.** The published bodies
of issues #3 and #4 have therefore diverged from their drafts, deliberately
— the drafts now carry the recommended changes and the issues do not.
Reconciling them is a `gh issue edit` operation, which `CONTRIBUTING.md`
gates behind explicit approval. Nothing has been published, closed,
committed or pushed.

Two carried forward unchanged, for visibility:

- **DRAFT-026 → SPLIT** into `026a` (static tier; no Dom0/Proxmox/fixture
  dependencies, blocked only on DRAFT-031) and `026b` (self-hosted tier).
  The split itself is a structural decision left for review; the four
  design defects behind it (CI-01 … CI-05) have been fixed in the draft.
- **DRAFT-012 → FULLY OBSOLETE**, superseded by DRAFT-026a, but still
  cited as live by `docs/checklists/ubuntu.md:201` and roadmap M1 —
  DRAFT-032 corrects those references.

## Note on DRAFT-007

**Resolution (2026-08-08):** the premise was **wrong**, in the same way
DRAFT-006's was. `<USER>` was never a production bug — the deployed Dom0
copy of `drakvuf-ubuntu.sh` had always been correctly substituted with
`CMD="/home/carlos/Desktop/test"`, and Ubuntu analysis runs have been
executing their samples all along (`ExecProc Status:Success`, ~359k trace
records, clean `exit_group` — see run
`cd22b2c623c0cf35ec4fea588fe61bf6`). It was *this repository's* copy that
carried the unsubstituted placeholder.

What the verification actually uncovered is more useful than what it set out
to check: `automation/` had silently diverged from the deployed Dom0 copies,
undetected. `drakvuf-ubuntu.sh` differed on two lines, not one — the repo
also had `--memdump_dir` (underscore), which the installed build rejects.
Resolved the same day by syncing `automation/` wholesale from the tested
production host; five of the eight files were already byte-identical.
DRAFT-006's outstanding host-side rename (`linux_sandbox.cfg` →
`ubuntu_sandbox.cfg`) was completed at the same time, so issue #1 is now
closed end-to-end as well.

Also settled, and worth carrying into any future work on these scripts:
`drakvuf -e` is **execve-direct**, with no shell in the guest, so a `$USER`
in that argument can never dereference guest-side.

Full transcript: `docs/runbooks/verify-user-placeholder.md`. Recurrence
prevention (a repo↔host checksum check) is folded into DRAFT-026.

## Note on DRAFT-026

Added in this session at the user's request to plan CI implementation.
Not part of the original DRAFT-001–024 batch or DRAFT-025's later
addition — numbered next-available (026) for the same reason DRAFT-025
was. Supersedes DRAFT-012's title-only "Add static CI" scope (see the
remaining title-index below) rather than leaving it as a separate,
never-drafted entry, since Level 1 of this issue's design **is**
DRAFT-012's scope, just designed alongside the heavier self-hosted tier
rather than in isolation. Full design lives in `docs/workflow-ci.md`.

## Note on DRAFT-025

Not part of the original DRAFT-001–024 brainstormed batch — added in a
later session at the user's direct request to standardize repository-owned
asset paths (`automation/`, `misc/`, LibVMI profiles, Xen saved state)
around a canonical `/root/sandbox_project` Dom0 checkout, while explicitly
leaving `/malware_*` runtime data paths untouched. Numbered 025 (next
available) rather than inserted into the 009–024 range so the original
roadmap-derived title index stays intact. See `.github/issue-drafts/DRAFT-025.md`.

## Revision note on DRAFT-006

Originally titled "Commit missing Xen guest `.cfg` files" — that premise
was **wrong**. All four configs (`misc/linux.cfg`, `misc/linux_sandbox.cfg`,
`misc/android.cfg`, `misc/android_sandbox.cfg`) were already tracked in the
repository; the earlier research pass simply missed the `misc/` directory.
DRAFT-006 is revised to the smaller, real gap: the `linux*.cfg` filenames
are misleading (they define `ubuntu`/`ubuntu_sandbox`, not a generic
"linux" domain), and `automation/run_analysis-ubuntu.sh` hard-codes a
deployment path (`/home/user/drakvuf-tools/linux_sandbox.cfg`) that doesn't
match this repo's `misc/` location.

**Resolution (2026-08-08):** Both fixed in commit `ced4e77`, which closed
issue #1 — `misc/linux.cfg`/`misc/linux_sandbox.cfg` renamed to
`misc/ubuntu.cfg`/`misc/ubuntu_sandbox.cfg` and every in-repo reference
updated. The real Dom0 host's copies still need a separate manual rename;
see the issue #1 thread. DRAFT-025 and DRAFT-026 already treat this as
settled ("which #1 already settled") and need no further changes.

## Remaining title-index (DRAFT-009 through DRAFT-024)

Not yet drafted in full — titles only, from `docs/roadmap/project-roadmap.md`:

| Draft ID | Title | Area | Milestone | Priority | Depends on |
|---|---|---|---|---|---|
| DRAFT-009 | Define shared-vs-OS-specific script boundary | core | M0 | P1 | DRAFT-008 |
| DRAFT-010 | Document `dirwatch.c` current interface/callers and check for upstream issue #140 divergence | core | M0 | P1 | — |
| DRAFT-011 | Retrofit Ubuntu pipeline with structured status output (no behavior change) | ubuntu | M1 | P1 | ~~DRAFT-007~~ (closed 2026-08-08), DRAFT-008 |
| DRAFT-012 | ~~Add static CI (`bash -n`, `shellcheck`, `perl -c`) for `automation/*`~~ — superseded by DRAFT-026 | testing | M1 | P1 | DRAFT-001 |
| DRAFT-013 | Close Android §1.3 network isolation verification | android/security | M2 | P0 | Xen Dom0 |
| DRAFT-014 | Decide sample OS auto-detection contract (magic/MIME/PE/ELF/APK) | core | M2 | P1 | DRAFT-008 |
| DRAFT-015 | Implement `clone-android.pl` per checklist §2.5 | android | M3 | P1 | DRAFT-009, DRAFT-013 |
| DRAFT-016 | Implement `preconfig-android.sh` / `drakvuf-android.sh` per checklist §2.7–2.8 | android | M3 | P1 | DRAFT-015 |
| DRAFT-017 | Implement Android sample classification (checklist §2.6) | android | M3 | P1 | DRAFT-014 |
| DRAFT-018 | Define artifact/result schema | core | M4 | P1 | DRAFT-008 |
| DRAFT-019 | Integrate capa against DRAKVUF logs (native v7.2.0 extractor) | enrichment | M4 | P2 | DRAFT-018 |
| DRAFT-020 | Windows baseline selection + clone-per-run confirmation | windows | M5 | P2 | DRAFT-008 |
| DRAFT-021 | Licensing review write-up | governance | M0 | P1 | — |
| DRAFT-022 | Legal/compliance research for networked analysis (Spain/EU) | compliance | M2–M7 | P2 | — |
| DRAFT-023 | TLS-visibility research spike for Linux/Android (tlsmon confirmed N/A) | networking | M2 | P3 | DRAFT-013 |
| DRAFT-024 | Upstream `lfreijo/drakvuf` fork mirror/backup + pin documentation | governance | M0 | P2 | DRAFT-001 |

Note: DRAFT-021's content (the licensing review) and DRAFT-020's premise
(the VM-lifecycle question) were substantially resolved during the same
session that drafted this index — see `docs/architecture/licensing.md` and
`docs/checklists/windows.md` respectively. They remain listed for
completeness and because DRAFT-021 in particular should still go through a
real legal review, not just this desk research.

### Assessment notes on DRAFT-009 … DRAFT-024 (2026-08-08)

From the backlog review in `project-assessment.md`. These entries have no
draft files yet, so the corrections live here — apply them **when each
entry is drafted in full**, rather than drafting from the title and
dependency columns above, which have drifted.

The `OS` column reflects the project's three current targets. Where an
entry was scoped to one OS but the code it governs is shared, that is
called out — the whole point of recording it now is that the correction is
cheap before the draft exists and expensive after.

| ID | OS | Assessment | Apply when drafted |
|---|---|---|---|
| **009** | ALL | **Priority should rise sharply.** Written when only Ubuntu existed and Android was next. With Android *and* Windows scripts both imminent, this is the gate that stops DRAKVUF-01/02/05/06 being fixed three times. | Start from the source-verified split: **shared** = `dirwatch.c`, `network-setup.sh`, `cleanup.sh`, `tcpdump.sh` (no OS suffix, no OS-specific logic — `cleanup.sh:113-114` takes only `DOMAIN`/`VLAN`); **per-OS** = `clone-*`, `preconfig-*`, `drakvuf-*`, `run_analysis-*`. Include the `carlos`/`vg-root`/`xenbr1` parameterization question, which is genuinely three-shaped (Ubuntu has `/home/carlos`, Android has no such concept, Windows a third form). Move to position 3 in the order. |
| **010** | ALL | **NEEDS UPDATE.** | Add CI-04: state whether `dirwatch.c` or `dirwatch_old.c` is authoritative (they differ on 132 lines, almost all formatting; the install guide copies only `dirwatch.c`, `docs/drakvuf-on-xen-nested-within-proxmox.md:531`). Record that the file only compiles inside a DRAKVUF source tree — it `#include`s `<config.h>` and `../xen_helper/xen_helper.h` (`dirwatch.c:118,120`). Record that `dirwatch` hard-codes one origin domain per invocation (`:475`), so three concurrent OS pipelines means three `dirwatch` processes unless the contract changes — which DRAFT-014 will press on. |
| **011** | U → ALL | **PARTIALLY OBSOLETE — shrink, then widen.** | **Remove** the "reconcile with the deployed Dom0 copy" element: issue #2 completed it on 2026-08-08. **Add** DRAKVUF-04 (`ps aux \| grep` PID safety) — 3 of its 4 sites are in shared `cleanup.sh`, so that part is not Ubuntu-only; the `"tcpdump -i xenbr1.$VLAN"` match is unanchored with `.` as a regex wildcard, so VLAN 1 also matches `xenbr1.10`–`19` above 9 clones. Dependency on DRAFT-007 is closed. |
| **012** | ALL | **FULLY OBSOLETE.** Superseded by DRAFT-026a. | Do not draft. Still cited as live by `docs/checklists/ubuntu.md:201` and roadmap M1 — DRAFT-032 fixes those references. |
| **013** | A → ALL | **NEEDS UPDATE — retitle away from Android-only.** The mechanism under test is `network-setup.sh`, shared by all three OS families, so this verifies Ubuntu and Windows containment too. | Depends on DRAFT-028 landing first — otherwise it records a known-broken state. Record NET-02 and NET-03 as *expected findings* so the test is not written assuming a pass: the `FORWARD` rule cannot cover traffic to Dom0 itself (`INPUT` chain, no policy set anywhere), and `MASQUERADE` at `network-setup.sh:118` gives clones unrestricted egress by default. Fixes belong to DRAFT-028/029; this entry stays verification-only. |
| **014** | ALL | **NEEDS UPDATE.** The title parenthetical already anticipates PE, but with Windows current this becomes a genuine three-way routing decision rather than an ELF/APK split. | Note it is the entry that makes `dirwatch`'s one-domain-per-invocation contract actually limiting (see 010). Should follow DRAFT-030, which hardens filename handling before routing widens the input surface. If detection cannot disambiguate a case on content alone, that is the condition under which issue #3's dropped `target_os_source` gets revisited — with evidence. |
| **015** | A | READY. | Must follow issue #4's path convention and **DRAFT-033's** error-handling/locking pattern rather than copying today's `clone-ubuntu.pl` verbatim — `CLAUDE.md` directs new scripts to be written from the Ubuntu implementation, which currently has its `flock` commented out (`:236-241`) and checks no exit status. |
| **016** | A | READY. | **DRAFT-027 must land first** so Android is never built against the HTTP delivery path. `docs/checklists/android.md:1003` already prefers `injector -m writefile`; `:1877`'s "keep HTTP as an optional compatibility path" is superseded — no fallback is to be implemented. |
| **017** | A | READY. | Consumes DRAFT-014. No change. |
| **018** | ALL | READY. | Defer the MD5-vs-SHA-256 keying decision to issue #3, which now owns it; `docs/architecture/result-schema.md` §3 currently poses the same question independently. |
| **019** | ALL | READY. | No change. |
| **020** | W | **PARTIALLY OBSOLETE, and now under-scoped.** | Drop the lifecycle-decision half — resolved by roadmap decision #3 (snapshot-restore is non-viable in this nested setup), though `docs/checklists/windows.md:41` still lists it as open (DOC-05). The remaining half is absorbed by **DRAFT-034**, which is the real Windows track head. Either close this entry into DRAFT-034 or keep it as the baseline-selection sub-task. |
| **021** | — | **PARTIALLY OBSOLETE.** | The desk research is written (`docs/architecture/licensing.md`). Retitle to reflect that what remains is a real legal review, not a write-up. |
| **022** | — | READY. | No change. |
| **023** | U/A → +W | **NEEDS UPDATE — the premise has flipped.** | Currently premised on "tlsmon confirmed N/A". `tlsmon` hooks Windows `ncrypt.dll`/Schannel only (`docs/architecture/networking.md:61-64`) — so with Windows current it is **applicable**, and becomes the project's only working TLS-visibility path. Rescope to "adopt `tlsmon` for Windows; research options for Ubuntu/Android". Roadmap risk #4 and the reuse table (`:90`) need the same correction (DRAFT-032). |
| **024** | ALL | **READY, priority should rise from P2.** | DRAFT-026b rebuilds DRAKVUF/LibVMI from source in every job with nothing pinned to build against. Scope now spans **two** upstreams with different bus-factor profiles: `tklengyel/drakvuf` (Windows-oriented plugin set, healthy) and the single-maintainer `lfreijo` fork (Linux/Android plugin support, risk #8). The Windows track leans mainly on the former — the pinned fork commit `8dc77880…` is titled "Add **Linux** support for memdump, filetracer, fileextractor, and syscalls plugins". Retitle away from `lfreijo`-only. |

Dependency corrections to the table above, once these are drafted:

- **DRAFT-013** gains a dependency on DRAFT-028 (fix before measuring).
- **DRAFT-014** gains a soft dependency on DRAFT-030 (harden filename
  handling before routing widens the input surface).
- **DRAFT-015** gains a dependency on DRAFT-033 (fix the clone template
  before copying it).
- **DRAFT-016** gains a hard dependency on DRAFT-027 (decide delivery
  before writing the second implementation of it).
- **DRAFT-020** is superseded in substance by DRAFT-034.
- **DRAFT-023** gains a dependency on DRAFT-034 for its Windows half.