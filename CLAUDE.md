# DRAKVUF Android Automation Project

## Project purpose

This repository contains automation for a DRAKVUF malware-analysis laboratory.

Architecture:

L0: Proxmox/KVM
└── L1: Xen Dom0 + DRAKVUF
    └── L2: Ubuntu, BlissOS/Android, or (planned) Windows analysis guest

The goal is a sandbox that can watch `/malware_incoming`, determine which
guest OS a dropped sample needs, and launch the matching clone for analysis
under DRAKVUF. Ubuntu automation is mostly done and must remain functional.
Windows is a planned future target.

The current development goal is to add Android/BlissOS automation alongside
the Ubuntu implementation.

## Source documentation

Before making architectural changes, read the relevant documents under `docs/`:

- `docs/Project-definition.txt`
- `docs/drakvuf-on-xen-nested-within-proxmox.md`
- `docs/android_setup.md`
- `docs/roadmap/project-roadmap.md` — the living milestone/dependency-graph
  roadmap across all OS targets; check here first for current sequencing
  and open architecture decisions.
- `docs/checklists/android.md`, `docs/checklists/ubuntu.md`,
  `docs/checklists/windows.md`, `docs/checklists/platform.md` — per-OS
  execution checklists (moved from the single
  `docs/android-drakvuf-automation-checklist.md` file during the 2026-08-07
  docs reorg; that path no longer exists). `android.md` is the current
  source of truth for Android automation progress.
- `docs/architecture/` — analysis-pipeline, networking, result-schema,
  upstream-drakvuf, and licensing write-ups.

Do not silently treat commands labelled "Candidate" in the checklists as proven.
They must be validated before being treated as working commands.

## Current implementation

Existing Ubuntu automation lives under `automation/` (flat directory, no
subfolders):

- `dirwatch.c` — the orchestrator daemon, a modified version of the
  `dirwatch.c` shipped in the upstream DRAKVUF repository. A `GThreadPool` +
  `inotify` watcher on the incoming-sample folder, launched via a fixed
  15-argument CLI contract that hard-codes a single origin domain per
  invocation. Since issue #3 (2026-08-09) that constraint **is** the
  OS-selection mechanism rather than a gap: the target OS is chosen by the
  submitter, via one incoming directory and one `dirwatch` instance per OS.
  File magic is recorded for identification and mismatch-rejection only —
  it does not route. Two things this still needs before per-OS watchers
  can run concurrently are tracked as DRAFT-036: memory-based clone
  admission, and a host-global VLAN allocator (today the thread-slot index
  *is* the VLAN, and the slot array is process-local, so two instances
  would collide). See `docs/architecture/analysis-pipeline.md`.
  For each sample it calls back into the worker scripts below, in
  order: `clone-ubuntu.pl` → `preconfig-ubuntu.sh` → `drakvuf-ubuntu.sh` →
  `cleanup.sh`, with `tcpdump.sh` started on a side thread. The preconfig
  phase is guarded by a 60s timeout and the drakvuf-trace phase by a 180s
  timeout; either timeout triggers `cleanup.sh` and a fresh clone retry.
- `clone-ubuntu.pl` — LVM copy-on-write snapshot + `xl restore` of the golden
  VM's saved memory image, producing a disposable sandbox clone.
- `preconfig-ubuntu.sh` — network-configures the booted clone and stages the
  sample into the guest via `injector`.
- `drakvuf-ubuntu.sh` — runs the DRAKVUF trace (`syscalls`, `filetracer`, `fileextractor`,
  `memdump` 120s timeout, `--memdump-dir`) and kills the per-VLAN `tcpdump`
  process afterward. Executes the staged sample at `/home/carlos/Desktop/test`.
- `cleanup.sh` — pauses/destroys the clone domain and kills any lingering
  `injector`/`drakvuf` processes for it.
- `tcpdump.sh` — captures traffic on the clone's VLAN sub-interface to a
  per-sample pcap.
- `network-setup.sh` — provisions the OVS bridge and per-VLAN isolated
  networks (`172.16.<vlan>.1/24` gateway per VLAN) that `clone-ubuntu.pl` and
  `preconfig-ubuntu.sh` assume already exist.
- `run_analysis-ubuntu.sh` — top-level entry point; brings `xenbr1` up, runs
  `network-setup.sh`, then launches `dirwatch` with the arguments above.

The Xen guest `.cfg` files these scripts reference are tracked under
`misc/`, not `automation/`: `misc/ubuntu.cfg` (golden `ubuntu`),
`misc/ubuntu_sandbox.cfg` (`ubuntu_sandbox`), `misc/android.cfg` (golden
`android`), `misc/android_sandbox.cfg` (`android_sandbox`). These were
renamed from `linux.cfg`/`linux_sandbox.cfg` in issue #1 — those names were
historical and misleading, since the files define Ubuntu domains, not a
generic "linux" one. The Dom0 host's copies were renamed to match on
2026-08-08, so repo and host now agree. An earlier pass this session initially reported
these files as missing entirely; that was wrong — `misc/` had simply not
been checked. Always check for a `misc/` directory before concluding a
referenced file doesn't exist anywhere in this repo.

Android equivalents (`clone-android.pl`, `preconfig-android.sh`,
`drakvuf-android.sh`, `run_analysis-android.sh`) do not exist yet — this is
the Phase 2 gap the checklist tracks. Do not assume they are present.

**`automation/` now mirrors the working Dom0 host** as of 2026-08-08: the
tested production scripts were copied in wholesale, resolving the repo↔host
drift that issue #2's verification uncovered. `drakvuf-ubuntu.sh` picked up
`CMD="/home/carlos/Desktop/test"` and `--memdump-dir` (the correct spelling,
confirmed from `drakvuf --help`); `network-setup.sh` picked up
`ip link set xenbr1 up` in place of the deprecated `ifconfig`;
`dirwatch_old.c` was replaced by the host's newer variant (the previous
520-line copy remains in git history at commit `2514168`). `dirwatch.c`,
`preconfig-ubuntu.sh`, `cleanup.sh`, `clone-ubuntu.pl` and `tcpdump.sh` were
already byte-identical to the host and were not touched. Issue #1's rename
was also completed on the host side (`linux_sandbox.cfg` →
`ubuntu_sandbox.cfg`), so `run_analysis-ubuntu.sh` now agrees on both sides
and repo and host no longer diverge anywhere. The earlier
`<USER>` placeholder was a repo-only defect and was never a production bug —
Ubuntu analysis runs do execute their samples, which is now
execution-evidenced (`docs/runbooks/verify-user-placeholder.md`).

Known issues in the current Ubuntu scripts (do not silently fix — flag and
confirm before changing):

- `run_analysis-ubuntu.sh` hard-codes deployment paths under
  `/home/user/drakvuf-tools/...`, which do not match this repo's
  `automation/` directory name.
- Both `drakvuf-ubuntu.sh` and `preconfig-ubuntu.sh` hard-code the guest
  username `carlos`. This is now consistent between them and matches
  production, but parameterizing it remains open M1 work.

Do not modify the Ubuntu behavior unless required and explicitly requested.

## Development rules

- Make small, reviewable changes.
- Do not create or switch Git branches unless explicitly requested.
- Do not commit changes unless explicitly requested.
- Do not push to remotes unless explicitly requested.
- Before editing a script, inspect the corresponding Ubuntu implementation.
- Prefer parameterization over duplicated hard-coded values.
- Preserve existing interfaces until their callers have been inspected.
- Do not invent `dirwatch`, `injector`, or DRAKVUF command-line options.
  Check the supplied source/help/output first.
- Clearly distinguish:
  - commands validated from project evidence;
  - proposed commands that still require testing on Xen Dom0.
- Comments answer *why*, not *what*, and a comment asserting a security,
  isolation or concurrency guarantee must be true today or say plainly
  that it is not (`KNOWN GAP (DRAFT-NNN)`).
- Update the comments, checklists and cross-references a change touches,
  in the same change. Leaving one describing the pre-change behaviour is
  a defect in the change.
- Never edit dated evidence blocks or the imported source guides in
  place — annotate, and record the discrepancy in the living docs.

The full rationale, with the worked examples behind each rule, is in
`CONTRIBUTING.md`'s "Comments and historical context" section.

## Testing

For shell scripts:

    bash -n SCRIPT
    shellcheck SCRIPT

For Perl scripts:

    perl -c SCRIPT

After changing shared Ubuntu/Android code, verify that Ubuntu behavior has not
changed unintentionally.

## Infrastructure boundary

The development container is NOT Xen Dom0.

Do not assume the following commands can or should execute inside the
development container:

- xl
- drakvuf
- injector
- vmi-process-list
- lvcreate
- lvremove
- lvs
- vgs
- ovs-vsctl
- iptables
- nft

Commands targeting Xen, LVM, OVS, the Android sandbox, or malware samples must
be presented for manual execution unless an explicitly configured remote test
environment is provided.

Never operate on:

- the golden Android LV;
- the saved Android sandbox state;
- real malware samples;

unless explicitly instructed.

## Current Android names

Golden domain: `android`
Sandbox domain: `android_sandbox`
LibVMI profile: `/root/android.json`
Volume group: `vg-root`
Analysis bridge: `xenbr1`
Saved state: `/home/user/Documents/android_sandbox.bak`

## Current Ubuntu names

Golden domain: `ubuntu`
Sandbox domain: `ubuntu_sandbox`
LibVMI profile: `/root/linux.json`
Volume group: `vg-root`
Analysis bridge: `xenbr1`
Saved state: `/home/user/Documents/ubuntu_sandbox.bak`

## Workflow

For substantial changes:

1. Read the relevant checklist section.
2. Inspect all existing callers/callees.
3. Explain the intended change.
4. Implement the smallest useful increment.
5. Run local static checks.
6. Show the diff.
7. Identify commands that must be tested manually on Xen Dom0.
8. Do not mark checklist items complete without evidence.

This is the short version. The full `PLAN → CREATE → TEST → DEPLOY`
lifecycle, human-review gates, and the GitHub issue-drafting workflow are
documented in `CONTRIBUTING.md` — follow it for substantial changes rather
than just this summary.

## Reference

For general guidance on using Claude Code itself (not project-specific
rules, which are the rest of this file), see Anthropic's
[Claude Code best practices](https://code.claude.com/docs/en/best-practices).
