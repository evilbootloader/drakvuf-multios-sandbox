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