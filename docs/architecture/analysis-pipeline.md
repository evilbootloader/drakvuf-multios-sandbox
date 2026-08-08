# Analysis pipeline architecture

> Verified-vs-proposed distinction matters here, same as the checklists:
> the `dirwatch.c` contract below is confirmed by direct source reading
> (2026-08-07). The job/result state model is a proposed design, not yet
> implemented — tracked as DRAFT-008 in `.github/issue-drafts/`.

## Current orchestrator: `automation/dirwatch.c`

A modified copy of DRAKVUF's own `dirwatch` tool (upstream lives at
`tklengyel/drakvuf:src/dirwatch/dirwatch.c` — see `upstream-drakvuf.md`).
It is a `GThreadPool` + `inotify` (`IN_CLOSE_WRITE`) watcher on the
incoming-sample folder, invoked with a fixed 15-argument CLI contract:

```
dirwatch <loop(0)|poll(1)> <origin domain> <domain config> <kernel json> \
  <injection pid> <watch folder> <serve folder> <output folder> \
  <max clones> <clone_script> <config_script> <drakvuf_script> \
  <cleanup_script> <tcpdump_script>
```

`automation/run_analysis-ubuntu.sh` invokes it with:

```
dirwatch 1 ubuntu_sandbox /home/user/drakvuf-tools/ubuntu_sandbox.cfg \
  /root/linux.json 1415 /malware_incoming /malware_processing \
  /malware_finished 2 <clone-ubuntu.pl> <preconfig-ubuntu.sh> \
  <drakvuf-ubuntu.sh> <cleanup.sh> <tcpdump.sh>
```

Note the deployment paths (`/home/user/drakvuf-tools/...`) don't match this
repo's `automation/`/`misc/` directory names — see the Ubuntu checklist's
"known issues" section. The domain config path in that invocation
(`ubuntu_sandbox.cfg`) corresponds to what's tracked here as
`misc/ubuntu_sandbox.cfg` (renamed from `linux_sandbox.cfg` in issue #1).

Per-sample flow: on a new file, `dirwatch` moves it out of the watch folder,
then calls back into the worker scripts in order —
`clone_script → config_script → drakvuf_script → cleanup_script`, with
`tcpdump_script` started on a separate thread. A 60s timeout guards the
preconfig phase and a 180s timeout guards the drakvuf-trace phase; either
timeout triggers `cleanup_script` and a fresh clone retry. Concurrency is
capped by a thread pool sized from the `<max clones>` argument (validated
1–128 in upstream; this project's copy has not been independently
re-verified against that bound).

**Known upstream issue to check for divergence:** `tklengyel/drakvuf` issue
#140 describes a timeout-triggered clone retry failing to find its sample
because it was already moved out of the incoming folder — the same
retry-on-timeout shape this project's `dirwatch.c` uses. Whether this
project's copy already diverged/fixed this has not been checked (DRAFT-010).

## Proposed: OS-independent job/result state model (DRAFT-008, not implemented)

Not yet designed. Candidate fields and states carried over from the
brainstormed workstream list, for reference only — none of this is decided:

```text
Candidate fields:
  analysis_id, sample_sha256, original_filename, detected_type,
  target_os, target_os_source, execution_recipe, requested_timeout,
  network_mode, sandbox_version, profile_version, domain, clone_id,
  vlan, started_at, finished_at, status, failure_stage

Candidate states:
  received → classified → queued → cloning → restoring → preparing →
  monitoring → executing → stimulating → collecting → cleaning →
  completed | failed
```

This must account for: multi-OS target dispatch (Ubuntu today, Android in
progress, Windows planned — all clone-per-run, see `networking.md` and the
roadmap's resolved VM-lifecycle decision), recovery after interruption or
host reboot, and the existing per-OS status vocabularies already drafted in
`docs/checklists/android.md` §7.3 (`success`, `install_failed`,
`unsupported_type`, etc.) — the OS-independent model should generalize
those, not replace them ad hoc.

## Architecture decision: keep `dirwatch.c` in C, or move to Python?

Not decided. Per project rules, do not rewrite merely because Python is
easier — the interface/callers above must be fully documented first
(DRAFT-010), and any replacement must preserve the same callback contract
so `clone-*`/`preconfig-*`/`drakvuf-*`/`cleanup.sh`/`tcpdump.sh` scripts
don't all need simultaneous rewrites.