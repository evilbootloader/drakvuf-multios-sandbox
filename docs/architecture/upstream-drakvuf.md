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
had the same retry-on-timeout structure (60s preconfig / 180s drakvuf
timeouts), so it was plausible the same bug class applied — never checked
(DRAFT-010), and now unreachable: this project's copy was deleted
2026-09-15 and `sandboxd` fetches each sample from the object store per
attempt rather than moving a file out of a watch folder, so a retry cannot
lose its sample this way.

**Plugins confirmed present in `src/plugins/`:** `filetracer`,
`fileextractor`, `memdump`, `syscalls` (all four used by this project),
plus `tlsmon` and ~30 others (`apimon`, `procdump`, `regmon`, `socketmon`,
`rootkitmon`, `ipt`, `ebpfmon`, etc.). `filetracer` gained Linux support in
upstream DRAKVUF 0.8 (2021-12-21). `injector` is a separate tool, not a
`src/plugins` entry — it injects a short-lived shellcode agent
("drakshell") during setup only, which self-terminates before the sample
runs, preserving the agentless design.

> **2026-08-24 — the inventory above has no OS split, and that turned out to
> matter.** `src/plugins/plugins.h` carries the authoritative matrix,
> `drakvuf_plugin_os_support[plugin][os]`, read directly on this date from
> both `tklengyel/main` and `lfreijo/memdump`:
>
> **45 plugins — 16 Linux-capable, 26 Windows-only, 3 Linux-only.**
>
> | | Plugins |
> |---|---|
> | **Both** | `syscalls`, `filetracer`, `fileextractor`\*, `memdump`\*, `procmon`, `procdump2`, `cpuidmon`, `debugmon`, `ipt`, `hidsim`, `libhooktest` |
> | **Linux only** | `ptracemon`, `ebpfmon`, `unixsocketmon`, `rebootmon` |
> | **Windows only** | `apimon`, `procdump`, `regmon`, `socketmon`, `rootkitmon`, `tlsmon`, `codemon`, `exploitmon`, `wmimon`, `rpcmon`, `etwmon`, `clipboardmon`, `windowmon`, `librarymon`, `objmon`, `exmon`, `ssdtmon`, `poolmon`, `bsodmon`, `envmon`, `crashmon`, `delaymon`, `dkommon`, `spraymon`, `callbackmon`, `hidevm`, `memaccessmon`, `filedelete`, `linkmon` |
>
> \* **These two are what the fork actually adds.** Upstream has
> `[VMI_OS_LINUX] = 0` for `fileextractor` and `memdump`; `lfreijo/memdump`
> sets both to 1. Everything else Linux-capable is **already upstream**, so
> the bus-factor exposure is two plugins rather than "Linux/Android plugin
> support" as a whole — see the correction in
> `docs/roadmap/project-roadmap.md` risk #8.
>
> The immediately useful consequence: **`procmon`, `procdump2`, `cpuidmon`,
> **`-a` is restrictive, verified 2026-08-26.** `src/main.cpp:438` enables
> every plugin by default, but the first `-a` calls `disable_all_plugins()`
> (`:167`) and then enables only what is named — so listing four plugins runs
> exactly those four. `-x` (`disable_plugin`, `:143`) excludes one without
> re-listing the rest.
>
> This matters beyond configuration: it means `hidsim` has **never run** in
> this project, so no existing trace contains the synthetic mouse input it
> injects. Had `-a` been additive, every Ubuntu and Android trace would have
> carried randomly-moving-mouse activity that no report attributes to
> anything.
>
> `ipt`, `hidsim`, `ptracemon`, `ebpfmon` and `unixsocketmon` are available to
> Ubuntu and Android today, upstream, and none is enabled.** `procmon` is the
> process tree; `cpuidmon` records the sample's own hypervisor-detection
> attempts; `hidsim` injects synthetic mouse and keyboard input.
>
> Two caveats. This was read from the **branch tip**, not the pinned
> `52df0bc8044d3033af3259312787560dbb8caa12` — the matrix may differ there.
> And the matrix says DRAKVUF **permits** the plugin, not that it produces
> useful output against our guests; that needs the per-guest validation
> matrix pattern from `docs/checklists/android.md` §0.4. DRAFT-050 owns both.

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

**Corrected 2026-08-11 (CONF-11).** This section previously read "Do not
begin modifying DRAKVUF engine code itself until a stable per-OS pipeline
exists (Milestone M9, deliberately last)." That is no longer the project's
direction: **modifying the engine — adding functionality to DRAKVUF, not
just orchestrating it — is near-term intended work.**

This correction is unlike the others in the same pass, and the difference
is worth stating: nothing in the repository contradicted the old sentence.
Ordinary drift leaves a seam — one document disagreeing with another, or
with the code — and here all four locations that stated the M9 constraint
agreed with each other. Only the project's actual direction disagreed with
all of them, so a reader had no signal the constraint was stale and would
have deferred engine work, citing M9 correctly.

Two consequences that change technical statements rather than sequencing:

- **DRAFT-024's purpose changes.** Pinning both upstreams is currently
  justified as bus-factor insurance (roadmap risk #8) at P2. If engine code
  is about to be modified, a pinned revision becomes the baseline those
  changes are diffed from — a prerequisite, not a precaution.
- **DRAFT-010 is moot.** It wanted this project's `dirwatch.c` interface
  documented, and its unresolved `dirwatch.c` / `dirwatch_old.c` authority
  question settled. Both files were deleted 2026-09-15; the authority
  question is answered by neither being authoritative. What survives of the
  interface is recorded in `docs/architecture/automation-files.md`.

Milestones are deliberately **not** renumbered here; the affected drafts
propose their own resequencing.

## DRAKVUF Sandbox (CERT-Polska) — what's reusable

See `docs/roadmap/project-roadmap.md`'s reuse-vs-build table for the
condensed verdicts (Flask+RQ+Redis queue: reuse/adapt; TLS visibility via
tlsmon: Windows-only, therefore **applicable to the Windows track and to
nothing else** — not the blanket "not applicable" this line used to read,
now that Windows is current; VM lifecycle via snapshot-restore:
not applicable to this project's clone-per-run model, and additionally
confirmed non-viable in the nested Xen-inside-Proxmox setup this project used
until 2026-08-28 — not re-tested on bare metal — per
`docs/checklists/windows.md`; capa integration: reuse/adapt, capa v7.2.0
added a native DRAKVUF-log feature extractor).