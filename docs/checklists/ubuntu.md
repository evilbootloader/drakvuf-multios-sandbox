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
| LibVMI profile | `profiles/linux.json` (untracked; moved from `/root/linux.json` in issue #4) |
| Volume group | `vg-root` |
| Analysis bridge | `xenbr1` |
| Saved state | `state/ubuntu_sandbox.bak` (untracked; moved from `/home/user/Documents/` in issue #4) |
| Golden Xen config | `misc/ubuntu.cfg` (tracked in this repo; renamed from `linux.cfg` in issue #1) |
| Sandbox Xen config | `misc/ubuntu_sandbox.cfg` (tracked in this repo; renamed from `linux_sandbox.cfg` in issue #1) |
| Current phase | M1 — Ubuntu regression baseline (see roadmap) |
| Current blocker | None. Issue #4 deployed and verified end to end on Dom0 2026-08-09 (commit `57713fc`): the pipeline runs from a checkout at any path and delivers samples by injection with `apache2` stopped. Ubuntu is a usable M1 regression baseline |
| Deployed on Dom0 | `/root/sandbox_project`, branch `issue-4-paths-and-delivery`, via a read-only deploy key. `git -C /root/sandbox_project log -1` is now the authoritative answer to "what is running?" |

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
  `xl restore` of the saved state, clone naming `<origin>-<vlan>-clone`,
  hard-codes `vg-root` and `xenbr1`. *(Updated 2026-08-09, issue #4: the
  restore path was `/home/user/Documents/ubuntu_sandbox.bak` and is now
  derived from `FindBin` and the origin argument as
  `<repo root>/state/<origin>.bak`.)*
- [x] `automation/preconfig-ubuntu.sh` exists — configures guest networking
  (`172.16.<VLAN>.2/24`) and stages the sample, hard-codes guest username
  `carlos`. *(Updated 2026-08-09, issue #4 / DRAFT-027: staging was a
  guest-side `wget` against Apache on the gateway and is now
  `injector -m writefile` from Dom0. The guest resolver also changed — see
  `docs/architecture/networking.md`.)*
- [x] `automation/drakvuf-ubuntu.sh` exists — runs the DRAKVUF trace
  (`syscalls`, `filetracer`, `fileextractor`, `memdump` via `--memdump-dir`,
  120s timeout, JSON output), executes `/home/carlos/Desktop/test`, kills
  `tcpdump` via `ps aux | grep`. *(Updated 2026-08-08 to the production
  copy; this line previously described the pre-sync repo version.)*
- [x] `automation/cleanup.sh` exists — pauses/destroys the clone domain,
  SIGINT then SIGKILL for lingering `injector`/`drakvuf` processes.
- [x] `automation/tcpdump.sh` exists — captures the clone's VLAN
  sub-interface to a per-sample pcap.
- [x] `automation/network-setup.sh` exists — provisions the per-VLAN
  networks (`172.16.<vlan>.1/24` gateway, `iptables` MASQUERADE +
  inter-VLAN DROP), brings the bridge up with `ip link set xenbr1 up`.
  *(Updated 2026-08-08 to the production copy, which replaced the
  deprecated `ifconfig xenbr1 up`. Corrected 2026-08-11: this line
  previously said it "provisions the OVS bridge", which it does not —
  `xenbr1` is created by a separate install step, `ovs-vsctl add-br
  xenbr1`. See `docs/architecture/networking.md`.)*
- [x] `automation/run_analysis-ubuntu.sh` exists — sources
  `pipeline-ubuntu.env`, pre-flight checks the `.cfg`/profile/state,
  creates the per-OS malware directories, brings `xenbr1` up, runs
  `network-setup.sh`, launches `dirwatch` with the arguments above.
  *(Updated 2026-08-09, issue #4.)*
- [x] `automation/pipeline-ubuntu.env` exists — the sourced per-OS config
  every other script reads. *(Added 2026-08-09, issue #4.)*
- [x] `misc/ubuntu_sandbox.cfg` exists — Xen HVM config for `ubuntu_sandbox`
  (2048MB/1vcpu, `bridge=xenbr1`, `altp2m=2`).

## Execution evidence — repo-relative paths and injection delivery (2026-08-09)

**Deployed and verified end to end on Dom0**, commit `57713fc`, full
transcript in `docs/runbooks/deploy-repo-relative-paths.md`. This is
execution evidence, not source reading.

- [x] **The pipeline runs from a checkout at any path.** Launched from
  `/tmp` against `/root/sandbox_project`; behaved identically to launching
  from inside the checkout. Closes issue #4's core claim.
- [x] **Sample delivery is host-to-guest injection, with Apache stopped.**
  `preconfig.log` for the benign fixture (sha256 `81cd9ba0…`, md5
  `107529d2…`):

  ```text
  [INJECT] METHOD:WriteFile STATUS:SUCCESS PID:1415
           FILE:"/malware_processing/ubuntu/benign"
  [INJECT] METHOD:ExecProc  STATUS:SUCCESS PID:1415 FILE:"/usr/bin/sh"
           ARGUMENTS:"-c sudo ip addr flush dev eth0 && ... &&
           echo 'nameserver 1.1.1.1' | sudo tee /etc/resolv.conf"
  ```

  followed by an 88,812-line `drakvuf.log`. `apache2` was stopped for the
  duration, which is what proves the dependency is gone rather than idle.
- [x] **Delivery integrity confirmed by `readfile`**, the documented
  inverse of `writefile`: the file pulled back out of the guest hashed
  `81cd9ba0d4802395d3450d3746a1dad1a24bfa46bbb04d03b094c66f82be8d08`,
  identical to the Dom0 source. That injection was a one-off for the
  runbook and is deliberately **not** in `preconfig-ubuntu.sh` — it costs
  a round trip per sample.
- [x] **`writefile` leaves the staged file executable.** `injector --help`
  does not say either way, so the first implementation issued a `chmod`
  injection. Removing it and confirming analyses still trace settled it;
  the step is gone from the repo. Answers DRAFT-027's PLAN step 3.
- [x] **Guest DNS resolves.** `nameserver 1.1.1.1` in place of the
  gateway address that never had a resolver behind it.

Three things the same run surfaced that are **not** fixed:

- `network-setup.sh` is not idempotent — the second launch produced
  `RTNETLINK answers: File exists` and `Error: ipv4: Address already
  assigned`. First execution evidence for **DRAFT-028**, previously
  reasoned from source only.
- A running clone showed `maxmem` unlimited in `xl top`, though all four
  `misc/*.cfg` set `maxmem` equal to `memory`. Undiagnosed, and a
  precondition for **DRAFT-036**'s memory-based admission.
- `drakvuf-ubuntu.sh` hit `dirwatch`'s 180s trace guard on the first two
  runs **after a Dom0 reboot**, then settled; runs before the reboot were
  fine. Probably the 2.1 GB saved image read cold from disk, but
  unmeasured. The retry path worked correctly both times. See the pipeline
  doc's headroom note.

## Known issues

> Mixed evidence categories — read each item's label. The `<USER>` item below
> now carries **Dom0 execution evidence** (2026-08-08, issue #2); the others
> are still source-reading only.

- [x] **Verify the `drakvuf-ubuntu.sh` `<USER>` bug — DONE 2026-08-08, and
  the premise was wrong.** Execution evidence from Dom0 (full transcript in
  `docs/runbooks/verify-user-placeholder.md`) shows the **deployed** copy at
  `/home/user/drakvuf-tools/drakvuf-ubuntu.sh` is correctly substituted with
  `CMD="/home/carlos/Desktop/test"`, and that samples **do** execute:

  ```text
  {"Plugin": "inject", "Method": "ExecProc", "Status": "Success",
   "ProcessName": "/home/carlos/Desktop/test", "InjectedPid": 1688, ...}
  ```

  followed by ~359k trace records attributed to PID 1688 in run
  `/malware_finished/cd22b2c623c0cf35ec4fea588fe61bf6/drakvuf.log`, ending in
  `exit_group ExitStatus 0`. **Production was never broken by this.** The
  defect was that *this repository's* copy was the stale, never-substituted
  one — the repo↔host drift this uncovered, now resolved (see the item
  below). Tracked as DRAFT-007 / [issue #2][i2].

  Also settled, and it constrains any future fix: `-e` is **execve-direct**,
  no guest shell is involved (`injector --help`: "execproc — Run any process
  using vfork and execve"; `[LINUX] execproc -> execve(...)`; confirmed
  against `/home/user/drakvuf/src/injector.cpp:180-185`). A `$USER` in the
  `-e` argument would therefore **never** dereference guest-side; the path
  must be resolved on Dom0. The repo's literal `<USER>` path would fail with
  `ENOENT` if deployed — mechanically certain, never observed, because it
  was never deployed.

- [x] **Repo↔Dom0 drift — RESOLVED 2026-08-08 by syncing `automation/` from
  the tested production host.** Discovered while verifying the item above.
  Three files differed; five were already byte-identical (`dirwatch.c`,
  `preconfig-ubuntu.sh`, `cleanup.sh`, `clone-ubuntu.pl`, `tcpdump.sh`), so
  the drift was narrower than feared.

  | File | Was (repo) | Now (production, tested) |
  |---|---|---|
  | `drakvuf-ubuntu.sh` | `CMD="/home/<USER>/Desktop/test"`; `--memdump_dir` (underscore, trailing `/`) | `CMD="/home/carlos/Desktop/test"`; `--memdump-dir` (hyphen, no slash); `-a syscalls` first in the plugin list |
  | `network-setup.sh` | `ifconfig xenbr1 up` | `ip link set xenbr1 up` |
  | `dirwatch_old.c` | 520-line older variant | host's 674-line variant (previous copy preserved in git history at `2514168`) |

  `--memdump-dir` is the correct spelling, confirmed from the installed
  build's own help: `--memdump-dir <directory>  Where to store memory
  dumps`. The repo's underscore form was wrong and would not have been
  accepted.

  `-a syscalls` is now present in **both** repo and host: it was absent from
  the host copy at the time of run `cd22b2c6…` (which contains no
  `{"Plugin":"syscalls"}` records) and was added as part of this
  reconciliation, then re-tested with a sample.

  `automation/` now mirrors the Dom0 host on every line.

- [x] **Host-side rename `linux_sandbox.cfg` → `ubuntu_sandbox.cfg` — DONE
  2026-08-08.** This was the outstanding *host* half of issue #1: the repo
  had been renamed in commit `ced4e77` but Dom0 still had the old filename,
  so the production `run_analysis-ubuntu.sh` still referenced
  `linux_sandbox.cfg`.

  ```bash
  mv /home/user/drakvuf-tools/linux_sandbox.cfg \
     /home/user/drakvuf-tools/ubuntu_sandbox.cfg
  ```

  `run_analysis-ubuntu.sh` updated to match on both sides and re-tested with
  a fresh analysis run. Issue #1 is now closed end-to-end — repo and host
  agree on the `ubuntu*.cfg` naming.

  **Provenance of the placeholder (historical — resolved by the sync
  above).** `<USER>` was a *documented deploy-time placeholder*, not a typo:
  `docs/drakvuf-on-xen-nested-within-proxmox.md` instructed the operator to
  edit `preconfig.sh` and `drakvuf.sh` and "change `<USER>` to the target
  analysis VM user". The repository had held a **half-substituted pair** —
  `preconfig-ubuntu.sh:119` substituted (`USER="carlos"`),
  `drakvuf-ubuntu.sh:119` not. Both now carry `carlos`, matching production.

  **Hypotheses, and how each was resolved** (runbook:
  `docs/runbooks/verify-user-placeholder.md`):

  | # | Hypothesis | Resolved by | Outcome |
  |---|---|---|---|
  | H1 | The deployed Dom0 copy has `carlos` substituted per the guide; this repo's copy is the stale un-substituted one | R1 | **CONFIRMED** |
  | H2 | The deployed Dom0 copy is byte-identical to this repo's (literal `<USER>`) | R1 + R2 | **REFUTED** |
  | H3 | `drakvuf -e` is shell-mediated **inside the guest**, so the author intended `$USER` to dereference on the analysis VM | R0 | **REFUTED** — `-e` is execve-direct |

  Both readings of "was it meant to be a shell variable?" are now closed:

  - *Dom0-side expansion* — ruled out by source reading. `drakvuf-ubuntu.sh`
    has no `USER=` assignment (unlike `preconfig-ubuntu.sh:119`) and runs on
    Dom0 as root under `dirwatch`, so a bare `$USER` there would expand to
    `root`, not `carlos`.
  - *Guest-side expansion* — ruled out by R0's `--help`/source capture:
    `execproc` is `vfork` + `execve` (`injector.cpp:180-185`) / `execlp`
    (`main.cpp:196`), with no shell in between. `-f` exists precisely
    because a shell must be invoked explicitly, which is why
    `preconfig-ubuntu.sh:120-125` spells out
    `-e /usr/bin/sh -f "-c" -f "<script>"` and the Android candidate at
    `docs/checklists/android.md:1141` uses `-e /system/bin/sh`.
    `drakvuf-ubuntu.sh:122` passes `-e "$CMD"` with no `-f` arguments.
  - And the line as written could not have worked under either reading:
    `<USER>` is not variable syntax in any shell.

[i2]: https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/2
- [x] ~~`run_analysis-ubuntu.sh` hard-codes deployment paths under
  `/home/user/drakvuf-tools/...`~~ — **fixed 2026-08-09 (issue #4).** All
  fourteen `dirwatch` arguments now come from
  `automation/pipeline-ubuntu.env`, with repository-owned assets resolved
  from the script's own location. Static verification only so far; the
  out-of-repo invocation test still needs running on Dom0
  (`docs/runbooks/deploy-repo-relative-paths.md`).

## Planned M1 work

- [x] Confirm the `<USER>` bug against real execution (DRAFT-007 / issue #2)
  — done 2026-08-08; premise refuted, production was never affected. See
  Known issues above and `docs/runbooks/verify-user-placeholder.md`.
- [x] Reconcile `automation/drakvuf-ubuntu.sh` with the deployed Dom0 copy
  (the drift this uncovered — `<USER>`, `-a syscalls`, `--memdump_dir`)
  — done 2026-08-08 as part of issue #2; the production copy was taken as
  authoritative and `automation/` was synced wholesale. See the Known
  issues section above for the file-by-file record.
- [ ] Document current behavior precisely with execution evidence, not just
  source reading (DRAFT-011).
- [ ] Retrofit structured status output (`status.json`-style, matching the
  shape being defined for `docs/architecture/result-schema.md`) without
  changing existing behavior.
- [ ] Add `bash -n` / `shellcheck` / `perl -c` CI for `automation/*`
  (**DRAFT-026a**, the static tier — DRAFT-012 was superseded by it; see
  `.github/issue-drafts/issue-index.md`). Gated on **DRAFT-031**, which
  establishes a baseline the scripts actually pass: `shellcheck` currently
  reports `SC1128` on five of the six, because the licence header sits
  above the shebang. *(The earlier wording here said this was blocked on
  Bash being non-functional in this dev container as of 2026-08-07. That
  blocker is lifted — `bash`, `dash`, `shellcheck` and `perl` were
  re-confirmed working in-container on 2026-08-08, 2026-08-09 and again on
  2026-08-11.)*
- [ ] Parameterize the remaining hard-coded values — `vg-root` and the
  `xenbr1` / `172.16.<vlan>` scheme in `clone-ubuntu.pl` and
  `network-setup.sh` — per `CLAUDE.md`'s "prefer parameterization" rule,
  once the shared-vs-OS-specific script boundary (DRAFT-009) is decided.
  *(Partially done 2026-08-09, issue #4: deployment paths, guest user
  `carlos`, injection PID, clone count and resolver all moved into
  `automation/pipeline-ubuntu.env`. `clone-ubuntu.pl` does not read that
  file — it is Perl, invoked by `dirwatch` with a fixed 3-argument
  contract — so its constants are untouched.)*

### Evidence and notes

**2026-08-08 — `<USER>` placeholder: RESOLVED (issue #2).**

Verdict: **the issue's premise was wrong.** The deployed Dom0 copy is
correctly substituted (`CMD="/home/carlos/Desktop/test"`, sha256
`76bc801b…`) and samples execute normally; this repository's copy
(sha256 `d0a17e4e…`) is the stale one and has additionally drifted on the
`drakvuf` invocation line. Full Dom0 transcript — R0 (`-e` semantics),
R1 (deployed-vs-repo diff), R1b (guest user), R2 (historical run logs) — is
in `docs/runbooks/verify-user-placeholder.md`. R3 was not needed.

Key execution evidence, from
`/malware_finished/cd22b2c623c0cf35ec4fea588fe61bf6/drakvuf.log` (2026-08-07):

```text
{"Plugin": "inject", "TimeStamp": "1786091642.367500", "Method": "ExecProc",
 "Status": "Success", "ProcessName": "/home/carlos/Desktop/test",
 "InjectedPid": 1688, "InjectedTid": 1688}
{"Plugin":"filetracer",...,"PID":1688,"PPID":1415,
 "ProcessName":"/home/carlos/Desktop/test","Syscall":"openat","ThreadName":"test",...}
{"Plugin":"memdump",...,"PID":1692,"PPID":1688,
 "ProcessName":"/home/carlos/Desktop/test","Syscall":"exit_group","ExitStatus":0}
```

~359k trace records attributed to PID 1688. `-e` semantics, from
`injector --help` and `/home/user/drakvuf/src/injector.cpp:180-185`:

```text
execproc - Run any process using vfork and execve ( -e for specifying the
           program, -f for args )
[LINUX] (execproc -> execve(const char *file, const char *argv[],
         const char* envp[]); 64bit only)
```

---

The local, container-side evidence that preceded the Dom0 run is retained
below for provenance. Category: **source-reading + local shell semantics,
NOT execution evidence.** It settles only what this repository's copy does.

```text
$ bash -c 'CMD="/home/<USER>/Desktop/test"; printf "CMD=[%s]\n" "$CMD"'
CMD=[/home/<USER>/Desktop/test]

$ bash -n automation/drakvuf-ubuntu.sh && echo OK
OK
$ bash -n automation/preconfig-ubuntu.sh && echo OK
OK

$ grep -rn "USER" automation/preconfig-ubuntu.sh automation/drakvuf-ubuntu.sh
automation/preconfig-ubuntu.sh:119:USER="carlos"
automation/preconfig-ubuntu.sh:122:ARG2="... -O '/home/$USER/Desktop/test' && chmod +x '/home/$USER/Desktop/test'"
automation/drakvuf-ubuntu.sh:119:CMD="/home/<USER>/Desktop/test"
```

Conclusion: because `CMD` is double-quoted, `<USER>` is neither expanded nor
treated as a redirection — the repository's copy passes the literal string
`/home/<USER>/Desktop/test` to `drakvuf -e`. `drakvuf-ubuntu.sh` contains no
`USER=` assignment of its own.

Environment note: `bash` 5.3.9, `shellcheck` 0.11.0 and `perl` are all
functional in the development container as of 2026-08-08, consistent with
`CONTRIBUTING.md`'s re-verification note (they were not on 2026-08-07).

> **Annotation 2026-08-11 (CONF-12), not a correction of the above.** The
> statement was true when written; the citation is what went stale.
> `CONTRIBUTING.md`'s "re-verification note" was collapsed into a standing
> instruction on 2026-08-09 (audit finding MISS-03), so there is no longer
> a passage under that name to consult. The fact now lives in
> `CONTRIBUTING.md`'s TEST section as a standing instruction to re-verify
> the toolchain rather than as a dated narrative. Re-confirmed working
> again on 2026-08-11 (`bash -n`, `dash -n`, `shellcheck`, `perl -c` all
> run in-container).

Superseded by the Dom0 evidence above. What remains open is *not* the
`<USER>` question but the repo↔host drift it exposed — see
`docs/runbooks/verify-user-placeholder.md`: R0 (`-e` semantics / H3), R1
(deployed-vs-repo diff / H1 vs H2), R2 (historical run logs), R3 (benign
A/B run, only if R1+R2 are inconclusive).