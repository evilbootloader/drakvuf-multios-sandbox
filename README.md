# DRAKVUF Android Automation Project

Automation for a DRAKVUF malware-analysis laboratory.

```
L0: Proxmox/KVM
└── L1: Xen Dom0 + DRAKVUF/LibVMI
    ├── L2 Ubuntu analysis VM
    ├── L2 Android/BlissOS analysis VM
    └── L2 Windows analysis VM (planned)
```

The goal is a sandbox that can watch `/malware_incoming`, determine which
guest OS a dropped sample needs, and launch the matching clone for analysis
under DRAKVUF. Ubuntu automation is mostly done; Android automation is in
progress; Windows is a planned future target.

## Repository layout

- `automation/` — the Ubuntu automation scripts (`dirwatch.c`,
  `clone-ubuntu.pl`, `preconfig-ubuntu.sh`, `drakvuf-ubuntu.sh`,
  `cleanup.sh`, `tcpdump.sh`, `network-setup.sh`, `run_analysis-ubuntu.sh`).
  See `docs/architecture/analysis-pipeline.md` for how they fit together.
- `misc/` — tracked Xen guest configs: `linux.cfg` (golden `ubuntu`),
  `linux_sandbox.cfg` (`ubuntu_sandbox`), `android.cfg` (golden `android`),
  `android_sandbox.cfg` (`android_sandbox`). Note the `linux*` filenames are
  historical and define the Ubuntu domains, not a generic "linux" one.
- `docs/roadmap/` — the living project roadmap: milestones, dependency
  graph, risk register, architecture decisions still needing experiments.
- `docs/architecture/` — the analysis pipeline, networking, result schema,
  upstream-DRAKVUF strategy, and licensing research write-ups.
- `docs/checklists/` — per-OS implementation checklists with execution
  evidence (`android.md`, `ubuntu.md`, `windows.md`, `platform.md`). These
  track what's actually been done and evidenced, distinct from the roadmap.
- `docs/Project-definition.txt`,
  `docs/drakvuf-on-xen-nested-within-proxmox.md`, `docs/android_setup.md` —
  the original infrastructure setup guides.
- `.github/issue-drafts/` — locally-drafted GitHub issues, reviewed before
  anything is published with `gh`.

## Development lifecycle

This project uses a `PLAN → CREATE → TEST → DEPLOY` lifecycle with human
review gates. See `CONTRIBUTING.md`.

## Testing

```bash
bash -n SCRIPT       # shell scripts
shellcheck SCRIPT
perl -c SCRIPT        # Perl scripts
```

## Infrastructure boundary

Commands targeting Xen, LVM, OVS, the Android sandbox, or malware samples
must be presented for manual execution on the real Xen Dom0 host — they are
never assumed runnable in a generic development environment. See
`CLAUDE.md` for the full list of commands this applies to and the current
Ubuntu/Android naming conventions.

## Working with Claude Code on this repo

This project is developed with Claude Code. `CLAUDE.md` carries the
project-specific rules; see Anthropic's
[Claude Code best practices](https://code.claude.com/docs/en/best-practices)
for general guidance on the tool itself.