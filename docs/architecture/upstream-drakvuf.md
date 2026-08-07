# Upstream DRAKVUF — comparison, provenance, and repository strategy

> Research conducted 2026-08-07 via WebSearch/WebFetch against
> `github.com/tklengyel/drakvuf`, `github.com/lfreijo/drakvuf`, and
> `github.com/CERT-Polska/drakvuf-sandbox`. Source URLs are preserved in the
> git history of this research (see the session that produced
> `docs/roadmap/project-roadmap.md`); ask if you need the full citation
> list re-derived.

## Upstream `dirwatch.c` — direct comparison

Confirmed to live at `tklengyel/drakvuf:src/dirwatch/` (`dirwatch.c`,
`distributor.c`, `Makefile.am`) — **not** under `tools/` (that directory
holds `cleanup.sh`, `clone.pl`, `preconfig.sh`, `drakvuf.sh`,
`network-setup.sh`, `tcpdump.sh`, and others, which are the clear ancestors
of this project's own `automation/*.sh`/`*.pl` naming). Upstream `dirwatch`
has the same watch → clone → configure → run → capture → cleanup shape and
essentially the same ~15-argument CLI contract this project's modified copy
uses (see `analysis-pipeline.md`).

**Known upstream bug, unverified against this project's copy:** issue #140
(opened 2016, since closed upstream) describes a timeout-triggered clone
retry failing to find its sample, because the sample was already moved out
of the incoming folder on the first attempt. This project's `dirwatch.c`
has the same retry-on-timeout structure (60s preconfig / 180s drakvuf
timeouts), so it's plausible the same bug class applies — not yet checked
(DRAFT-010).

**Plugins confirmed present in `src/plugins/`:** `filetracer`,
`fileextractor`, `memdump`, `syscalls` (all four used by this project),
plus `tlsmon` and ~30 others (`apimon`, `procdump`, `regmon`, `socketmon`,
`rootkitmon`, `ipt`, `ebpfmon`, etc.). `filetracer` gained Linux support in
upstream DRAKVUF 0.8 (2021-12-21). `injector` is a separate tool, not a
`src/plugins` entry — it injects a short-lived shellcode agent
("drakshell") during setup only, which self-terminates before the sample
runs, preserving the agentless design.

## `lfreijo/drakvuf`, `memdump` branch — provenance

This is an **in-house/personal fork**, not a branch staged for upstream
merge — a GitHub search for issues/PRs referencing "memdump lfreijo"
against `tklengyel/drakvuf` returned zero results. Treat it as internal
work with no upstream safety net, not a tracked open-source contribution.

The pinned commit recorded in `docs/checklists/android.md` §0.1,
`52df0bc8044d3033af3259312787560dbb8caa12`, is the branch tip as of the
last push (2026-05-11) — it is actually a `filetracer` bugfix (an
integer-overflow/UB fix in an ACE-size bounds check), **not** the commit
that adds Linux plugin support. The commit that actually matches this
project's description of the branch ("custom memdump plugin support") is
an earlier one, dated 2026-03-13:
`8dc77880c405914348539fc6e0952c772f8749dc`, titled "Add Linux support for
memdump, filetracer, fileextractor, and syscalls plugins."

**Bus-factor risk:** multi-OS plugin support (the Linux/Android plugin
extensions specifically) depends on this single-maintainer, unmerged
branch. Recommend mirroring/backing it up and documenting exact pinned
commits rather than relying on the fork remaining available (DRAFT-024).

## Repository strategy recommendation

**Recommend a separate, independently-versioned checkout of DRAKVUF with
pinned-revision documentation — not a git submodule, and not vendoring.**
This matches the explicit instruction to not blindly vendor hundreds of
megabytes of upstream history into the automation repository, while still
giving reproducibility (exact commit pinned and recorded, as already
practiced in the checklists' "Record platform versions" sections).
Confirm this via an actual build-from-pinned-revision test before treating
it as settled (see roadmap "Architecture decisions needing experiments").

Do not begin modifying DRAKVUF engine code itself until a stable per-OS
pipeline exists (Milestone M9, deliberately last).

## DRAKVUF Sandbox (CERT-Polska) — what's reusable

See `docs/roadmap/project-roadmap.md`'s reuse-vs-build table for the
condensed verdicts (Flask+RQ+Redis queue: reuse/adapt; TLS visibility via
tlsmon: not applicable — Windows-only; VM lifecycle via snapshot-restore:
not applicable to this project's clone-per-run model, and additionally
confirmed non-viable in this nested Xen-inside-Proxmox setup at all, per
`docs/checklists/windows.md`; capa integration: reuse/adapt, capa v7.2.0
added a native DRAKVUF-log feature extractor).