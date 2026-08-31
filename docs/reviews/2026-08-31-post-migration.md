# Post-migration review — 2026-08-31

> **Scope.** The state of the project after the 2026-08-28 bare-metal
> migration, the state of the running pipeline (`sandboxd` and the platform),
> and what was repaired in this pass. Work ran 2026-08-29 to 2026-08-31.
>
> The earlier root-level `project-assessment.md` (2026-08-08) stands as its own
> dated artifact and is not superseded by this one — it reviewed a different
> machine.

## The one-line answer

**The code kept pace with the migration. The documentation did not, and the
machinery built to detect that drift was itself broken by it.**

Eleven commits on `platform-domu` had already moved `cpus`, memory, the
injection anchor, thin snapshots and `--disable-sysret` onto bare metal, with
the test suite green. Meanwhile `docs/CURRENT-STATE.md` still described a
Proxmox host, and `scripts/gen-current-state.py` — the file whose entire
purpose is catching exactly this — could not see the new hostname.

---

# 1. Pipeline status

| | State | Source |
|---|---|---|
| Dom0 / Xen | bare metal, `total_memory 32605`, Xen 4.20.1, DRAKVUF `v1.1-da982ab` | `12-baremetal-trial.md` C, D |
| platform DomU | **serving** — 5 listeners, cloudflared connected, Access verified | `platform-domu.md` B/C/D/E |
| `sandboxd` | **registered and running** | operator, 2026-08-29 |
| End-to-end analysis | **yes — Ubuntu and Android, through the platform** | operator, 2026-08-29 |
| Android APK install + `am start` | **yes, successful.** Closes the last "implemented but never run" item on the Android track | operator, 2026-08-29 |
| Job history and artifacts from before the migration | **lost** — CT 102's backup key died with the Proxmox host | `12-baremetal-trial.md` |
| Windows | design contract only; golden VM exists, no automation | — |

**The lab works.** That is the headline, and an earlier draft of this review got
it wrong — see §4.

**What is missing is the record, not the capability.** `platform-domu.md`
EVIDENCE G is still blank, so the derived table in `CURRENT-STATE.md` §3
correctly reports runbooks as evidence-free for work that genuinely happened.
Runbook 13 cannot be filed until someone pastes a run into it.

---

# 2. Defects found in the project record

**F1 — the drift detector was blind to the new host.**
`gen-current-state.py` decided "was this executed?" by counting pasted shell
prompts from a hardcoded list of hostnames. The migration renamed Dom0 from
`drakvuf` to `dom0`, so:

| Runbook | counted before | actually present |
|---|---|---|
| `12-baremetal-trial.md` | 7 | **32** |
| `11-pbs-backups.md` | 15 | **19** |
| `platform-domu.md` | **0 → published as "no"** | 4 |

A runbook full of executed output would have been published as evidence-free —
the precise error class that file exists to remove. *Fixed:* hostnames lifted
into a named constant with the liability documented; both filed runbooks now
read `yes`.

**F2 — `CURRENT-STATE.md` contradicted itself.** §1.1–§1.3 described `pve1`,
VM 101 and CT 102, with `total_memory 20479` and `cpus="6-11"` — refuted 36
lines below by the file's own bare-metal recomputation. *Fixed:* §1 restructured
for two layers; new §2a lists the 12 facts the migration invalidated in one day.

**F3–F7 — living docs describing an erased machine.** `CLAUDE.md`, `README.md`,
the roadmap, `docs/architecture/platform.md` and `docs/checklists/platform.md`,
which said "no web-platform work has started" about a platform deployed behind
Cloudflare Access with 14 test files. *Fixed.*

**F8 — `sandboxd` had no requirements file.** Its dependencies existed only as a
hand-typed pip line inside a runbook transcript. *Fixed:* `sandboxd/requirements.txt`.

**F9 — Dom0's Python version is recorded nowhere**, though `websockets==16.1.1`
is pinned on the strength of "Dom0's Python is older" — written when Dom0 was
jammy and is now noble. *Not fixed; needs the host.* Recorded as `UNCONFIRMED`.

## The most significant finding: the trust boundary inverted

Under Proxmox, Dom0 and the platform were **siblings** — two guests of L0.
The platform is now a **DomU of Dom0**.

A compromised Dom0 can `xl save platform` and read Postgres out of the memory
image, or mount `/dev/vg-root/platform` directly. The mTLS between them is still
worth having as an authentication mechanism, but **it is no longer a containment
boundary**, and the "Dom0 → L0" row described a boundary that no longer exists.
The CA signing key on the operator's workstation is now the only secret a full
host compromise does not reach.

Recorded in `docs/architecture/platform.md` as a dated revision, with the old
table preserved rather than deleted.

---

# 3. What was built

| | Why |
|---|---|
| `docs/TROUBLESHOOTING.md` | 83 symptom-first entries. Failure knowledge was scattered across nine kinds of location; the same lesson kept being rediscovered |
| `docs/INDEX.md` + `gen-doc-index.py` | 861 headings with `path:line` and anchors. Answering one question meant reading a 3,000-line checklist or grepping blind |
| `scripts/check-refs.py` | 2,436 references validated — paths, `#anchors`, `path:line` past EOF. Prose was the largest artifact with no verification loop |
| `scripts/check-secrets.sh` + `.githooks/pre-push` | TruffleHog plus project-specific patterns it cannot know about |
| `sandboxd/config.py` | One source of truth for host configuration, generating `platform.env` and the `cpus =` lines |
| `scripts/dev-services.sh` | `CLAUDE.md` documented a test command that could not run here |
| CI: `secrets`, `sandboxd`, `platform` jobs | The suites existed and nothing ran them |
| `.claude/skills/` (tracked) | `runbook`, `dom0-handoff`, `deployment-state` |

**A rule change, at the operator's direction:** runbooks now hold *the commands
that worked*; everything that went wrong goes to `TROUBLESHOOTING.md`. A wrong
step is replaced rather than annotated beside, and a one-line pointer stays
wherever a correction marked surrounding text wrong. Runbook prose fell 17,384 →
17,054 lines while the failure knowledge became findable by symptom.

**Configuration and CPU changes**, committed and **not yet applied** — both need
the host:

- Dom0 → all eight P-cores, clones → `16-27`, platform → `28-31`. Takes the
  machine from 10 of 24 online pCPUs in use to 24. Needs `dom0_max_vcpus=8` and
  a reboot.
- platform DomU to 4096 MiB / 4 vCPU. Costs the fifth concurrent clone
  (`20317 / 4246 = 4`), stated rather than discovered later.
- `sandboxd` now provisions the analysis network at startup, closing F4 from
  runbook 09 at the root: a clone with a VLAN and no gateway produced an empty
  pcap that read as a sample choosing not to talk.

---

# 4. What this review got wrong, and what that shows

**An earlier draft reported `sandboxd` as never started since the migration and
no end-to-end analysis as having run.** Both were false. They were inferred from
blank `EVIDENCE` blocks and the absence of a pasted `root@dom0` prompt.

The operator corrected it: `sandboxd` runs, and both Ubuntu and Android complete
end to end through the platform, including the APK path.

**Absence of evidence was read as evidence of absence** — by a review whose
stated purpose was to stop exactly that class of error, using the very machinery
built to prevent it. The derived table was right to say `no`; it reports
*recorded evidence*, which is its job. The prose was wrong to upgrade that into
a claim about reality.

`CURRENT-STATE.md` now carries the distinction explicitly, and it is the first
rule in both the `runbook` and `dom0-handoff` skills.

**Three gates caught bugs in this pass's own work**, which is the useful
argument for having them:

- `gen-xen-configs.py --check` reported agreement while `config.py` and
  `platform.env` disagreed. `importlib` validates `__pycache__` on
  `(mtime, size)`; a **length-preserving** edit in the same timestamp second
  served stale bytecode. `xenbr1` → `xenbr2` is such an edit.
- `check-secrets.sh` caught the CI service credentials — and the *way* it caught
  them showed it matched `KEY: value` but not `KEY="value"`, so any quoted
  secret would have been missed.
- `check-refs.py` caught a `DRAFT-029` citation broken by compressing runbook 04,
  and stale `INDEX.md` entries after every edit round.

---

# 5. Handed to the operator

Cannot run in the development container. See the `dom0-handoff` skill.

1. **`python3 -V` and `xl info`** — closes F9 and re-dates §1.2.
2. **`dom0_max_vcpus=6` → `8`**, reboot, then `xl vcpu-list 0` to confirm all
   eight pins took. FINDING C-1 records the sixth silently not taking on a
   sparse online set.
3. **`xl shutdown platform && xl create misc/platform.cfg`** for 4096 MiB /
   4 vCPU. Do not raise `SANDBOXD_MAX_CLONES` before the reboot — the memory
   figure moves underfoot, not the cores.
4. **Fill `platform-domu.md` EVIDENCE G**, then one end-to-end job through the
   browser. That is what unparks runbook 13, and it is the only thing standing
   between the lab's real state and its recorded state.
5. **Verify `sandboxd` still starts** now that it provisions the network itself.

---

# 6. Recommendations not taken

**Track `.devcontainer/`.** It holds no secrets, and the roadmap's standing
instruction to "re-verify the toolchain in whatever container you are in before
assuming static checks can run" exists *only* because it is untracked. Left as a
recommendation; `.claude/skills/` was tracked in this pass, the rest of
`.claude/` deliberately not.

**Re-confirm DRAKVUF provenance.** The rebuilt Dom0 runs `v1.1-da982ab`; every
measurement before 2026-08-28 was taken on `…+52df0bc8-1`. Whether those are the
same tree has never been checked, and it silently qualifies every pre-migration
performance figure. One command: `git -C ~/drakvuf log -1`.

**`docs/architecture/automation-files.md` has 2 headings across 319 lines**, so
`INDEX.md` cannot help a reader find anything in it. It needs structure, not
indexing.