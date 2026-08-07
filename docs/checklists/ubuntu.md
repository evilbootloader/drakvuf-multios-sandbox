# Ubuntu DRAKVUF Automated Analysis — Implementation Checklist and Command Log

> **Purpose:** Unlike `android.md`, this checklist does not track a build
> from scratch — the Ubuntu pipeline already exists and is the automation
> the Android work was derived from (see `CLAUDE.md`). This document tracks
> (a) what has been **verified by reading the source** in this repository,
> which is a different category of evidence from **verified by execution**,
> and (b) the modernization work planned for Milestone M1 in
> `docs/roadmap/project-roadmap.md` (structured status output, regression
> testing, hard-coded-value parameterization).
>
> Commands labelled **Existing** come from the current project files.
> Commands labelled **Candidate** are proposed and unvalidated in this
> environment, exactly as in `android.md`.

---

## Project status

| Field | Value |
|---|---|
| Golden domain | `ubuntu` |
| Sandbox domain | `ubuntu_sandbox` |
| LibVMI profile | `/root/linux.json` |
| Volume group | `vg-root` |
| Analysis bridge | `xenbr1` |
| Saved state | `/home/user/Documents/ubuntu_sandbox.bak` |
| Golden Xen config | `misc/linux.cfg` (tracked in this repo; despite the filename it defines the `ubuntu` domain) |
| Sandbox Xen config | `misc/linux_sandbox.cfg` (tracked in this repo; defines `ubuntu_sandbox`) |
| Current phase | M1 — Ubuntu regression baseline (see roadmap) |
| Current blocker | Unverified `<USER>` bug in `drakvuf-ubuntu.sh` (see below) |

### Status legend

- [ ] Not started / not evidenced in this repository
- [x] Completed and evidenced (execution evidence, not just source-reading)
- `BLOCKED:` Waiting on a dependency or unresolved fault
- `SKIPPED:` Deliberately excluded, with reason recorded

---

## Source-verified implementation inventory (2026-08-07)

The following was confirmed by reading every file directly, not by testing
execution. None of the checkboxes below represent execution evidence.

- [x] `automation/dirwatch.c` exists — GThreadPool + inotify orchestrator,
  15-arg CLI contract, 60s preconfig timeout / 180s drakvuf-trace timeout,
  calls back into the scripts below in order.
- [x] `automation/clone-ubuntu.pl` exists — LVM copy-on-write snapshot +
  `xl restore` of `/home/user/Documents/ubuntu_sandbox.bak`, clone naming
  `<origin>-<vlan>-clone`, hard-codes `vg-root` and `xenbr1`.
- [x] `automation/preconfig-ubuntu.sh` exists — configures guest networking
  (`172.16.<VLAN>.2/24`), downloads the sample via `wget`, hard-codes guest
  username `carlos`.
- [x] `automation/drakvuf-ubuntu.sh` exists — runs the DRAKVUF trace
  (`filetracer`, `fileextractor`, 120s timeout, JSON output), kills
  `tcpdump` via `ps aux | grep`.
- [x] `automation/cleanup.sh` exists — pauses/destroys the clone domain,
  SIGINT then SIGKILL for lingering `injector`/`drakvuf` processes.
- [x] `automation/tcpdump.sh` exists — captures the clone's VLAN
  sub-interface to a per-sample pcap.
- [x] `automation/network-setup.sh` exists — provisions the OVS bridge and
  per-VLAN networks (`172.16.<vlan>.1/24` gateway, `iptables` MASQUERADE +
  inter-VLAN DROP).
- [x] `automation/run_analysis-ubuntu.sh` exists — brings `xenbr1` up, runs
  `network-setup.sh 2`, launches `dirwatch` with the arguments above.
- [x] `misc/linux_sandbox.cfg` exists — Xen HVM config for `ubuntu_sandbox`
  (2048MB/1vcpu, `bridge=xenbr1`, `altp2m=2`).

## Known issues (found by source reading, not yet execution-verified)

- [ ] **Verify the `drakvuf-ubuntu.sh` `<USER>` bug.** It hard-codes
  `CMD="/home/<USER>/Desktop/test"` with a literal, unsubstituted `<USER>`
  placeholder, while `preconfig-ubuntu.sh` hard-codes the real username
  `carlos` in the equivalent spot. Until this is checked against real
  behavior, "Ubuntu works" should not be treated as a proven regression
  baseline. Tracked as DRAFT-007.
- [ ] `run_analysis-ubuntu.sh` hard-codes deployment paths under
  `/home/user/drakvuf-tools/...`, which do not match this repo's
  `automation/` directory name — relevant only if run as-is from this
  checkout rather than a host with that exact layout.

## Planned M1 work (not started)

- [ ] Confirm the `<USER>` bug against real execution (DRAFT-007).
- [ ] Document current behavior precisely with execution evidence, not just
  source reading (DRAFT-011).
- [ ] Retrofit structured status output (`status.json`-style, matching the
  shape being defined for `docs/architecture/result-schema.md`) without
  changing existing behavior.
- [ ] Add `bash -n` / `shellcheck` / `perl -c` CI for `automation/*`
  (DRAFT-012) — blocked on Bash being non-functional in this dev container
  as of 2026-08-07; must run on the real host or real CI.
- [ ] Parameterize hard-coded values (`carlos`, `vg-root`, `xenbr1`,
  `/home/user/drakvuf-tools/...`) per `CLAUDE.md`'s "prefer parameterization"
  rule, once the shared-vs-OS-specific script boundary (DRAFT-009) is
  decided.

### Evidence and notes

```text

```