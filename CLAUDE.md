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
has an evidenced native-ELF path; Windows has a design contract and no
execution evidence. Fix shared code once for three OS families, not for Ubuntu
and then twice more by rediscovery.

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
| The `automation/` scripts in detail | `docs/architecture/automation-files.md` |
| Other design records | `docs/architecture/` |
| Dated execution evidence | `docs/runbooks/NN-*.md`, numbered oldest to newest |
| Dated project reviews | `docs/reviews/` |
| Full contribution lifecycle | `CONTRIBUTING.md` |

**`docs/` is 43k lines across 30 documents**, and the four largest are over
1,000 lines each. `docs/INDEX.md` exists so that finding the right section costs
one grep instead of reading a 3,000-line checklist or guessing at keywords.

### The tree

| | |
|---|---|
| `automation/` | the pipeline: `dirwatch.c`, `clone.pl`, and the per-OS `preconfig-`/`drakvuf-`/`run_analysis-` scripts, plus `pipeline-<os>.env` and host-global `platform.env` |
| `misc/` | **the Xen guest `.cfg` files** — golden, `_sandbox` templates, and `platform.cfg`. Not in `automation/` |
| `sandboxd/` | the Dom0 orchestrator, Python, with its own tests |
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
`dash -n` as well as `bash -n`. `run_analysis-ubuntu.sh` is the one genuine
bash script; it uses `$0` too, so the idiom stays uniform.

**Untrusted filenames must never be spliced into a guest shell string.**
`sample_name_admissible()` rejects only `/` and control characters, so `"`,
`$`, backtick and `;` all reach the guest. Use the `sh -c '…' sh "$UNSAFE"`
idiom so the value arrives as a separate `execve` element. Sample-derived text
may live in guest shell *variables* and be used quoted; it may not reach the
guest as text Dom0 pasted into a command.

**The two launchers must never run concurrently.** `dirwatch` derives each
clone's VLAN from a process-local worker-slot index, so two watchers collide on
VLANs, gateways and isolation rules with no symptom but interference. Both
refuse to start if another is running.

**`shellcheck automation/*.sh` exits 0 against the baseline in
`.shellcheckrc`,** which disables four codes repository-wide. Read that file
before reading a clean run as clean code.

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
- Inspect the corresponding Ubuntu implementation before editing a script.
- A new per-OS script means satisfying the conformance checklist (C1–C10) in
  `docs/architecture/analysis-pipeline.md` — **not** copying the Ubuntu file,
  which still carries known defects. Fix a known defect in the template before
  copying it.
- Prefer parameterisation over duplicated literals. Do not add an OS branch to
  shared code — add a variable.
- Preserve interfaces until their callers have been inspected.
- Never invent `dirwatch`, `injector` or DRAKVUF options. Check source, `--help`
  or output first.
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
perl -c SCRIPT                                            # perl
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

**The CPU partition lives in `automation/platform.env`**, and `misc/*.cfg` are
generated from it. Editing a `cpus =` line by hand is reverted on the next run.

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