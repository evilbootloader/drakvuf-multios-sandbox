# DRAFT-004: Fix checklist doc-reference and provenance-list defects

**Status:** Closed — done 2026-08-07
**Area:** governance
**Milestone:** M0
**Priority:** P2
**Depends on:** DRAFT-003

# Objective

Fix two small, factual defects found in the Android checklist during the
docs reorg, without altering any evidence or checkbox content.

# Context

1. The checklist's "Source files used for this checklist" section cited
   `automated_drakvuf_on_xen_nested_within.md`, but the real file on disk
   (confirmed by reading `docs/Project-definition.txt` and the file itself)
   is `docs/drakvuf-on-xen-nested-within-proxmox.md`. This was already
   fixed in `CLAUDE.md` earlier in the same session; the checklist's own
   citation still needed the same fix.
2. That same provenance section lists only the four `-ubuntu` scripts from
   `drakvuf-tools.zip` as sources, but checklist §2.9/§2.10 discuss
   `cleanup.sh` and `tcpdump.sh` directly, and `automation/` also contains
   `network-setup.sh` and `dirwatch.c` plus the inherited `LICENSE` — none
   of which were in the original provenance list.

# Dependencies

DRAFT-003 (the file has to exist at its new location first).

# Out of scope

Any other content in the checklist — this is a two-fact correction, not a
general edit pass.

# PLAN

Identify exactly which line needed the filename swap, and draft one
appended note (not a rewrite of the existing list) covering the missing
provenance items.

# CREATE

- Line 2468 of `docs/checklists/android.md`: `automated_drakvuf_on_xen_nested_within.md`
  → `drakvuf-on-xen-nested-within-proxmox.md`.
- Appended a dated provenance note after the original "Source files used
  for this checklist" section, listing `network-setup.sh`, `cleanup.sh`,
  `tcpdump.sh`, `dirwatch.c`, `LICENSE`, and (added in a follow-up edit
  once the `misc/` correction was made) the four tracked Xen guest configs
  under `misc/`.

# TEST

Re-read the affected section after editing to confirm the original list
items are unchanged and only the filename and the appended note differ
from the verbatim copy.

# DEPLOY

Not applicable.

# Acceptance criteria

- [x] Filename citation corrected.
- [x] Provenance note appended without altering original list items.

# Evidence required

The diff between the verbatim copy (DRAFT-003) and the final file — two
localized changes only.

# Security considerations

None.

# Documentation changes

This issue is the documentation fix.

# Recovery / rollback

`git revert` once committed; trivial to undo since the change is two
small, isolated edits.