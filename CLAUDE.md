# DRAKVUF Multi-OS Sandbox

Automation for a DRAKVUF malware-analysis laboratory.

```
Dom0: Xen on bare metal + DRAKVUF  →  guests: Ubuntu / BlissOS / Windows
                                   →  platform: a PVH DomU (Postgres, MinIO, API)
```

**Two layers, not three.** Proxmox was erased on 2026-08-28 and Xen boots the
metal. Anything naming `pve1`, VM 101, CT 102, `qm` or `pct` predates that —
see `docs/CURRENT-STATE.md` §2a, which lists every fact the migration
invalidated.

A watcher sees a sample, launches a disposable clone of the right OS, traces it
under DRAKVUF, collects artifacts, destroys the clone.

**All three OS targets are current.** Ubuntu is evidenced end to end; Android
has an evidenced native-ELF path; Windows ran end to end once, operator-
confirmed for 2026-09-05, with **no runbook and no per-plugin validation
behind it** — the weakest of the three, and the one to re-confirm rather than
assert. Fix shared code once for three OS families, not for Ubuntu and then
twice more by rediscovery.

---

## IMPORTANT: read `docs/CURRENT-STATE.md` before asserting any deployment fact

Versions, VM/container ids, CPU and memory capacity, what is evidenced and what
is not, and a **superseded-facts table** listing values that still appear
correct in old runbooks and are not. Every fact carries the date it was last
confirmed; anything over 30 days old is a hint to re-confirm, not a fact to
assert.

This exists because a review asserted a `dom0_max_vcpus` contradiction the
runbooks had already resolved, ran `journalctl` against a daemon that is not a
service, and read a memory figure as a core count — all answerable from
material already written down, none findable quickly.

Its derived half is generated: `scripts/gen-current-state.py`, enforced by
`sandboxd/tests/test_current_state.py`.

## Where things are

| Need | Read |
|---|---|
| **Which document covers a topic** | **`docs/INDEX.md`** — generated, one `path:line — heading` per section. Grep it before grepping the tree |
| Current deployment state | `docs/CURRENT-STATE.md` |
| Sequencing, open decisions | `docs/roadmap/project-roadmap.md` |
| Per-OS progress | `docs/checklists/{android,ubuntu,windows,platform}.md` |
| Orchestration, queue, web tier | `docs/architecture/platform.md` |
| What the deleted launcher pipeline was, and what replaced each file | `docs/architecture/automation-files.md` |
| Other design records | `docs/architecture/` |
| Dated execution evidence | `docs/runbooks/NN-*.md`, numbered oldest to newest |
| Dated project reviews | `docs/reviews/` |
| Full contribution lifecycle | `CONTRIBUTING.md` |
| **Making a change, end to end** | **`docs/DEVELOPING.md`** — the commands, in order, from edit to deployed on both hosts |

**`docs/` is 43k lines across 30 documents**, and the four largest are over
1,000 lines each. `docs/INDEX.md` exists so that finding the right section costs
one grep instead of reading a 3,000-line checklist or guessing at keywords.

### The tree

| | |
|---|---|
| `automation/` | **not the pipeline** — host provisioning and deployment assets: `network-setup.sh` (run by `sandboxd` at every daemon start), host-global `platform.env`, and the egress configs. The shell/C pipeline that lived here was deleted 2026-09-15 |
| `sandboxd/` | **the pipeline**, and the Dom0 orchestrator: clone, preconfig, trace, collect, destroy. Python, with its own tests |
| `misc/` | **the Xen guest `.cfg` files** — golden, `_sandbox` templates, and `platform.cfg`. Not in `automation/` |
| `platform/` | the FastAPI service, migrations, MinIO provisioning, UI, tests |
| `scripts/` | repository tooling: the three generators (`gen-current-state.py`, `gen-doc-index.py`, `gen-xen-configs.py`), `check-refs.py`, `dev-services.sh` |
| `.claude/skills/` | **tracked** — routers to the docs below: `deployment-state`, `runbook`, `dom0-handoff`. The rest of `.claude/` is not |
| `profiles/`, `state/`, `tls/` | LibVMI profiles, saved guest memory images, certificates — **none git-tracked** |

**A runbook is the commands that worked**, in order, with the output they
printed and the date they were run — the procedure for deploying an
environment, a guest or a piece of tooling. Someone should be able to follow it
top to bottom. The pasted output is what makes it evidence rather than a plan.

**Everything that went wrong goes to `docs/TROUBLESHOOTING.md`** — failed
attempts, dead ends, commands that turned out to be wrong, tools whose errors
mean something other than what they say. That file is symptom-first, so it is
findable by someone who has only the symptom. Superseded *facts* still go to
`CURRENT-STATE.md` §2.

So a wrong step is **replaced** by the right one rather than annotated beside
it, and the trap moves to `TROUBLESHOOTING.md`. Two things stay: the dated
output of the command that worked, which is never rewritten, and a one-line
pointer wherever a reader could otherwise repeat the mistake.

**`docs/Project-definition.txt`, `docs/drakvuf-on-xen-nested-within-proxmox.md`
and `docs/android_setup.md` are historical.** Kept verbatim, deliberately not
synced with later renames. Read them for original setup procedure, never for
what the project currently supports.

**Runbooks 01–10 describe the nested Proxmox lab**, which was erased on
2026-08-28. They are correct as dated evidence and wrong as a description of
this host. `CURRENT-STATE.md` §2a lists what changed. A runbook parked at the
repository root is one written but not yet fully executed — it moves to
`docs/runbooks/NN-` when its evidence blocks are filled, because
`gen-current-state.py` counts `docs/**/*.md` off the filesystem and a new file
there fails the test until the generator is re-run.

Commands labelled **Candidate** in the checklists are unproven. Do not treat
them as working until validated.

---

## Non-obvious things that have caused real defects

**Scripts in `automation/` run under `dash`, not `bash`.** Write POSIX. Use
`$0`, never `${BASH_SOURCE[0]}` — it evaluates to empty under dash and the
script carries on, which silently turned `SCRIPT_DIR` into `$PWD`. Check with
`dash -n` as well as `bash -n`. `network-setup.sh` is the only script left
there, and this binds it and the next one written.

**Untrusted filenames must never be spliced into a guest shell string.**
`sample_name_admissible()` rejects only `/` and control characters, so `"`,
`$`, backtick and `;` all reach the guest. Use the `sh -c '…' sh "$UNSAFE"`
idiom so the value arrives as a separate `execve` element. Sample-derived text
may live in guest shell *variables* and be used quoted; it may not reach the
guest as text Dom0 pasted into a command. The rule has **three live copies** —
`routers/jobs.py::_reject_unsafe_filename`, `sandboxd/naming.py::sample_name_admissible`,
`manifest.reject_unsafe_name` — and they must not disagree.

**Never discover a process by matching a rendered command line.** `ps aux |
grep "tcpdump -i xenbr1.$VLAN"` is unanchored and `.` is a wildcard, so vlan 1
also matched `xenbr1.10`–`.19` — one job's cleanup killing another job's
capture, silently. `sandboxd/proc.py::iter_processes` reads `/proc/<pid>/cmdline`
and compares argv **elements** for equality. CI gates on the idiom.

**Two orchestrators must never share a host.** `dirwatch` derived each clone's
VLAN from a process-local worker-slot index, so two collide on VLANs, gateways
and isolation rules with no symptom but interference. `sandboxd` refuses to
start when another `sandboxd` **or** a leftover `dirwatch` binary is running —
the source was deleted 2026-09-15 but a compiled copy on an old Dom0 still
allocates VLANs that way.

**`shellcheck automation/*.sh` exits 0 against the baseline in
`.shellcheckrc`,** which now disables one code (SC1091) over one file.
SC2086 and SC2009 came out when the scripts carrying their findings were
deleted, so both are **live again**. Read that file before reading a clean run
as clean code.

**IMPORTANT: do not modify Ubuntu pipeline behaviour unless explicitly
requested.** It is the evidenced path.

---

## Development rules

- Small, reviewable changes.
- Do not create branches, commit, or push unless asked.
- **Before PUSHING code, ask the operator to security-review it in a new
  session, and wait for them to say it is ready.** Scope is
  `<last-reviewed-sha>..HEAD` plus any dirty tree — not just uncommitted work,
  which this repo commits too fast for. Docs-only pushes are exempt; a push
  containing both is not. `CONTRIBUTING.md`, "Security review gate", has why.
- Inspect the corresponding Ubuntu implementation before editing shared code.
- Adding a guest OS means satisfying the conformance checklist (C1–C10) in
  `docs/architecture/analysis-pipeline.md`. **C1's "four per-OS files" is
  superseded** — a guest is a `TargetOs` member plus rows in
  `sandboxd/guests.py` and `sandboxd/stages.py`. The rule it defended stands:
  add a value to the per-OS table, never a branch to shared code.
- Prefer parameterisation over duplicated literals. Do not add an OS branch to
  shared code — add a variable.
- Preserve interfaces until their callers have been inspected.
- Never invent `injector` or DRAKVUF options. Check source, `--help` or output
  first.
- Distinguish commands validated by project evidence from commands that still
  need testing on Dom0.
- Comments answer *why*. A comment asserting a security, isolation or
  concurrency guarantee must be true today or say plainly that it is not
  (`KNOWN GAP (DRAFT-NNN)`).
- Update the comments, checklists and cross-references a change touches, in the
  same change.

## Testing

```
bash -n SCRIPT && dash -n SCRIPT && shellcheck SCRIPT     # shell
platform/.venv/bin/python -m pytest sandboxd/tests -q     # sandboxd, no infra needed
scripts/dev-services.sh                                   # bring up postgres + minio first
cd platform && .venv/bin/python -m pytest -q              # platform, needs both
```

The sandboxd suite re-runs all three generators and the reference checker
(`--check`), so a stale `docs/CURRENT-STATE.md`, `docs/INDEX.md` or `misc/*.cfg`
fails it, as does a dead cross-reference. Regenerate rather than edit by hand:

```
scripts/gen-current-state.py    scripts/gen-doc-index.py
scripts/gen-xen-configs.py      scripts/check-refs.py
```

**The CPU partition's source of truth is `sandboxd/config.py`**;
`scripts/gen-xen-configs.py` pushes it into `automation/platform.env` and
`misc/*.cfg`, which cannot import Python. Editing an assignment or a `cpus =`
line by hand is reverted on the next run. **Comments in those files are NOT
generated** and are hand-maintained — the generator rewrites values only.

After changing shared Ubuntu/Android code, verify Ubuntu behaviour is unchanged.

**IMPORTANT: never run the platform suite against the deployment.** Its `conn`
fixture runs `TRUNCATE jobs, worker_pipelines, workers RESTART IDENTITY
CASCADE`. `TEST_DATABASE_URL` defaults to `sandbox_platform_test`, so it is safe
here and destroys job history there. It was attempted on the deployment
2026-08-25 and failed with 312 errors because that database does not exist —
**the correct response is not to create it.** The deployment is verified by the
runbook's `curl` checks and by looking at the UI.

The suite wants `mc` on `PATH` (or `MC_BIN`) for the service-account policy
tests, and a browser for `tests/test_ui_browser.py` (`playwright install
chromium`) for the XSS-execution tests. Both skip loudly when absent. Do not run
`playwright install` on the deployment.

## Infrastructure boundary

**The development container is NOT Xen Dom0.** These cannot run here and must
be presented for manual execution: `xl`, `drakvuf`, `injector`,
`vmi-process-list`, `lvcreate`, `lvremove`, `lvs`, `vgs`, `ovs-vsctl`,
`iptables`, `nft`.

**Never operate on** the golden Android LV, the saved Android sandbox state, or
real malware samples unless explicitly instructed.

`profiles/*.json` and `state/*.bak` are not git-tracked; a fresh checkout has
neither. Repository paths resolve at runtime from each script's own location,
so the Dom0 checkout can live anywhere.

## Workflow

Read the relevant checklist → inspect callers and callees → explain the intended
change → implement the smallest useful increment → run local static checks →
show the diff → identify what must be tested on Dom0 → never mark a checklist
item complete without evidence.

`CONTRIBUTING.md` has the full `PLAN → CREATE → TEST → DEPLOY` lifecycle, the
human-review gates and the issue-drafting workflow.