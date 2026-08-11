# DRAKVUF Multi-OS Sandbox

## Project purpose

This repository contains automation for a DRAKVUF malware-analysis laboratory.

Architecture:

L0: Proxmox/KVM
└── L1: Xen Dom0 + DRAKVUF
    └── L2: Ubuntu, BlissOS/Android, or Windows analysis guest

The goal is a sandbox that can watch `/malware_incoming/<os>/`, and launch a
disposable clone of that OS's guest for analysis under DRAKVUF. Ubuntu
automation is mostly done and must remain functional.

**All three OS targets are current.** Ubuntu is evidenced end to end;
Android has evidenced Phase 1 and no scripts yet; Windows has an open track
with a fixed design contract and no execution evidence. Android/BlissOS
automation is the nearest development goal, but shared code should be fixed
once for three OS families rather than for Ubuntu and then re-discovered
twice.

## Source documentation

Before making architectural changes, read the relevant documents under `docs/`:

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
- `docs/runbooks/` — dated execution transcripts. Append-only evidence.
- `docs/workflow-ci.md` — the CI design (DRAFT-026a/b).

**Historical provenance — how the lab was originally built, not
current-state reading.** These are imported source guides, kept verbatim
and deliberately *not* synced with later renames or fixes. Read them for
setup procedure; do not read them for what the project currently supports:

- `docs/Project-definition.txt` — five lines, and both of its claims are now
  wrong. It says the project analyses "ubuntu malware (without network
  connection)": Android Phase 1 is evidenced, Windows is current, and clones
  have unrestricted NAT egress by default. It also points at
  `automated_drakvuf_on_xen_nested_within.md`, a filename that does not
  exist — the file is `drakvuf-on-xen-nested-within-proxmox.md`.
- `docs/drakvuf-on-xen-nested-within-proxmox.md`
- `docs/android_setup.md`

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
- `pipeline-ubuntu.env` — sourced config holding every per-OS value the
  scripts below need (sandbox domain, `.cfg`, profile, saved state,
  injection PID, clone count, malware directories, guest user and staging
  dir, resolver). Added in issue #4. Each entry is `${NAME:-default}`, so
  the environment wins — that is how CI overrides paths without patching
  files. A second OS pipeline is a copy of this one file plus its own
  `run_analysis-<os>.sh`.
- `clone-ubuntu.pl` — LVM copy-on-write snapshot + `xl restore` of the
  sandbox template's saved memory image, producing a disposable clone. The
  restore path is derived via `FindBin` as `<repo root>/state/<origin>.bak`,
  so the disk snapshot and the memory image cannot name different domains.
  It does **not** read `pipeline-ubuntu.env` — it is Perl, invoked by
  `dirwatch` with a fixed 3-argument contract.
- `preconfig-ubuntu.sh` — stages the sample into the guest via
  `injector -m writefile` (`-B` Dom0 source, `-e` guest destination), then
  configures the clone's network. Two separate injections; delivery
  deliberately runs first and does not need guest networking. No `chmod`
  step: `writefile` leaves the file executable, evidenced on Dom0
  2026-08-09.
- `drakvuf-ubuntu.sh` — runs the DRAKVUF trace (`syscalls`, `filetracer`, `fileextractor`,
  `memdump` 120s timeout, `--memdump-dir`) and kills the per-VLAN `tcpdump`
  process afterward. Executes the staged sample at
  `$GUEST_STAGING_DIR/<sha256>`, built by the same rule `preconfig-ubuntu.sh`
  stages to.
- `cleanup.sh` — pauses/destroys the clone domain and kills any lingering
  `injector`/`drakvuf` processes for it.
- `tcpdump.sh` — captures traffic on the clone's VLAN sub-interface to a
  per-sample pcap.
- `network-setup.sh` — provisions the per-VLAN isolated networks
  (`172.16.<vlan>.1/24` gateway per VLAN) that `clone-ubuntu.pl` and
  `preconfig-ubuntu.sh` assume already exist. It does **not** create
  `xenbr1`, despite the name: it calls only `modprobe`/`ip`/`vconfig`/
  `iptables`, and the OVS bridge comes from a separate one-time install
  step (`ovs-vsctl add-br xenbr1`). Running it on a host that never had that
  step does not establish the analysis network.
- `run_analysis-ubuntu.sh` — top-level entry point; sources
  `pipeline-ubuntu.env`, pre-flight checks the `.cfg`/profile/saved state,
  creates the per-OS malware directories, brings `xenbr1` up, runs
  `network-setup.sh`, then launches `dirwatch` with the arguments above.

**Scripts in `automation/` execute under `dash`, not `bash`.** Five of the
six carry the DRAKVUF license header *above* the shebang, so `#!/bin/bash`
sits on line 104 where the kernel never sees it; `execv` fails `ENOEXEC`
and GLib's `g_spawn_*` (how `dirwatch` invokes them) falls back to
`/bin/sh`. Write POSIX for these files. A bash-only construct does not
fail loudly — `${BASH_SOURCE[0]}` evaluates to empty under dash and the
script carries on, which in issue #4 silently turned `SCRIPT_DIR` into
`$PWD`. Use `$0`. `run_analysis-ubuntu.sh` is the exception (line-1
shebang), but uses `$0` too so the idiom is uniform. Check with
`dash -n SCRIPT` as well as `bash -n SCRIPT`.

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

**Parity is now maintained by a checkout, not by copying (2026-08-09,
issue #4).** Dom0 runs a clone of this repository at
`/root/sandbox_project`, pulled over a read-only deploy key, so the
question issue #2 needed a whole runbook to answer is now one command:

    git -C /root/sandbox_project log -1        # what is deployed
    git -C /root/sandbox_project status --porcelain   # local drift, expect empty

The old `/home/user/drakvuf-tools` checkout is renamed to
`…​.retired-issue4` and kept as the rollback path. Do not edit deployed
scripts in place — that is how the drift issue #2 diagnosed happened.
Change them here, push, and pull on Dom0, never while an analysis is in
flight (`dirwatch` re-reads the worker scripts per sample).

Known issues in the current Ubuntu scripts (do not silently fix — flag and
confirm before changing):

- ~~`run_analysis-ubuntu.sh` hard-codes deployment paths under
  `/home/user/drakvuf-tools/...`~~ — fixed in issue #4 (2026-08-09).
- ~~Both `drakvuf-ubuntu.sh` and `preconfig-ubuntu.sh` hard-code the guest
  username `carlos`~~ — moved to `GUEST_USER` in `pipeline-ubuntu.env` in
  issue #4. Still a fixed value rather than one discovered from the guest;
  that remains open M1 work.
- `clone-ubuntu.pl` still hard-codes `vg-root` and `xenbr1`, and
  `network-setup.sh` the `172.16.<vlan>.0/24` scheme. Neither reads
  `pipeline-ubuntu.env`. Open M1 work, gated on DRAFT-009.
- Guest DNS pointed at the clone's gateway, where nothing listens, so name
  resolution failed on every run before 2026-08-09. Now `GUEST_NAMESERVER`
  (default `1.1.1.1`). ~~Android's golden image has the same dead assumption
  baked in as an in-guest DNAT to `172.16.10.1:53`~~ — **fixed 2026-08-11
  (issue #7)**: the Android golden VM was reinstalled and the template
  rebuilt from it, and the DNAT was deliberately not re-applied. No resolver
  is baked into the image at all; per-clone configuration belongs to
  `preconfig-android.sh` at analysis time, as it does for Ubuntu.
  See `docs/architecture/networking.md`.

Do not modify the Ubuntu behavior unless required and explicitly requested.

## Development rules

- Make small, reviewable changes.
- Do not create or switch Git branches unless explicitly requested.
- Do not commit changes unless explicitly requested.
- Do not push to remotes unless explicitly requested.
- Before editing a script, inspect the corresponding Ubuntu implementation.
- **Writing a new per-OS script means satisfying the conformance checklist
  (C1–C10) in `docs/architecture/analysis-pipeline.md`, "Shared and per-OS
  code boundary" — not copying the Ubuntu file and editing it.** The Ubuntu
  implementation is the reference for *shape*, and it still carries known
  defects (no exit-status checks in `clone-ubuntu.pl`, SHA-256 as the guest
  leaf name, the licence header above the shebang). Copying it copies those.
  A defect known in the template is fixed in the template before the copy is
  made.
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

Also check the shell scripts with `dash -n SCRIPT`. They execute under
`dash`, not `bash` — see the note in "Current implementation" — so
`bash -n` alone will accept bash-only syntax that fails silently in
production.

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

Repository-owned paths below are relative to the checkout root, which
resolves at runtime from each script's own location — `/root/sandbox_project`
is the documented Dom0 location, not a required one. `profiles/*.json` and
`state/*.bak` are **not git-tracked**; a fresh checkout has neither. See
`profiles/README.md` and `state/README.md`.

## Current Android names

Golden domain: `android`
Sandbox domain: `android_sandbox`
LibVMI profile: `profiles/android.json`
Volume group: `vg-root`
Analysis bridge: `xenbr1`
Saved state: `state/android_sandbox.bak`
Incoming / processing / finished: `/malware_{incoming,processing,finished}/android`

## Current Ubuntu names

Golden domain: `ubuntu`
Sandbox domain: `ubuntu_sandbox`
LibVMI profile: `profiles/linux.json`
Volume group: `vg-root`
Analysis bridge: `xenbr1`
Saved state: `state/ubuntu_sandbox.bak`
Incoming / processing / finished: `/malware_{incoming,processing,finished}/ubuntu`
Guest staging: `/home/carlos/Desktop/<sha256>`

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
