# Issue index

Full draft-title index, first batch (DRAFT-001 through DRAFT-008 — the
scope approved for this session). See `docs/roadmap/project-roadmap.md` for
the complete brainstormed workstream list this was derived from, and for
DRAFT-009 onward (not yet drafted in full, title-index only).

| Draft ID | Title | Area | Milestone | Priority | Depends on | Status |
|---|---|---|---|---|---|---|
| DRAFT-001 | Initialize git repository and commit current baseline | governance | M0 | P0 | — | Open |
| DRAFT-002 | Add root README.md | governance | M0 | P1 | DRAFT-001 | **Closed** — done 2026-08-07 |
| DRAFT-003 | Reorganize docs/ into roadmap/architecture/checklists, preserving Android checklist evidence verbatim | governance | M0 | P0 | DRAFT-001 | **Closed** — done 2026-08-07 |
| DRAFT-004 | Fix checklist doc-reference and provenance-list defects | governance | M0 | P2 | DRAFT-003 | **Closed** — done 2026-08-07 |
| DRAFT-005 | Add CONTRIBUTING.md capturing PLAN→CREATE→TEST→DEPLOY lifecycle + issue template | governance | M0 | P1 | DRAFT-003 | **Closed** — done 2026-08-07 |
| DRAFT-006 | Reconcile `misc/` Xen guest config naming and cross-references | governance | M0 | P2 | DRAFT-001 | Open (revised — see note below) |
| DRAFT-007 | Verify `drakvuf-ubuntu.sh`'s `<USER>` placeholder bug against real behavior | ubuntu | M1 | P0 | DRAFT-001 | Open — requires Xen Dom0 |
| DRAFT-008 | Define OS-independent analysis job/result state model | core | M0 | P0 | DRAFT-001 | Open |

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

## Remaining title-index (DRAFT-009 through DRAFT-024)

Not yet drafted in full — titles only, from `docs/roadmap/project-roadmap.md`:

| Draft ID | Title | Area | Milestone | Priority | Depends on |
|---|---|---|---|---|---|
| DRAFT-009 | Define shared-vs-OS-specific script boundary | core | M0 | P1 | DRAFT-008 |
| DRAFT-010 | Document `dirwatch.c` current interface/callers and check for upstream issue #140 divergence | core | M0 | P1 | — |
| DRAFT-011 | Retrofit Ubuntu pipeline with structured status output (no behavior change) | ubuntu | M1 | P1 | DRAFT-007, DRAFT-008 |
| DRAFT-012 | Add static CI (`bash -n`, `shellcheck`, `perl -c`) for `automation/*` | testing | M1 | P1 | DRAFT-001 |
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