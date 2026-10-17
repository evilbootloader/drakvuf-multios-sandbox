# Developing: one change, from edit to deployed

The commands, in order, for taking a change through this repository yourself —
what to read first, what to run, what to commit, and what each of the two hosts
needs before the change is actually live.

**This is procedure, not facts.** Every version, address, VLAN, unit name and
capacity figure lives in `docs/CURRENT-STATE.md` and is deliberately not copied
here; a second place to read them is a second place for them to go stale. Where
this file names a value it is because the *procedure* turns on it, and it says
where the authoritative copy is.

`CONTRIBUTING.md` owns the lifecycle and the review gates — why they exist,
what each one is for. This is the short operational form of the same thing:
what you type.

---

## 0. Orient — three greps, not a reading pass

`docs/` is 43k lines. Do not read it linearly.

```bash
# DEV CONTAINER
grep -n "<topic>" docs/INDEX.md        # which document, and which heading
grep -n "<symptom>" docs/TROUBLESHOOTING.md   # has this already bitten someone?
```

Then, before asserting anything about the deployment, read
`docs/CURRENT-STATE.md` — §1 for what the lab is, §2 for the values that still
look correct in old runbooks and are not. A capability row older than 30 days
is a hint to re-confirm, not a fact to quote.

Three things decide how much of this applies to your change:

| Your change touches | Then |
|---|---|
| `sandboxd/` | Dom0 deploy. Read the Ubuntu implementation before editing anything shared — it is the evidenced path and must not change behaviour unless that is the request |
| `platform/` | DomU deploy, and possibly a migration |
| `docs/` only | No deploy, no security review gate — but the generators still have to be re-run |

---

## 1. Change the code

The rules that are not obvious from reading the tree:

- **Add a value to the per-OS table; never an OS branch to shared code.**
  A guest is a `TargetOs` member plus rows in `sandboxd/guests.py` and
  `sandboxd/stages.py`. `docs/architecture/analysis-pipeline.md` has the
  conformance checklist (C1–C10).
- **Do not hand-edit generated files.** `docs/INDEX.md`, the block between the
  markers in `docs/CURRENT-STATE.md` §3, and the assignment and `cpus =` lines
  in `automation/platform.env` and `misc/*.cfg` are all rewritten by their
  generator. The CPU partition's source of truth is `sandboxd/config.py`.
  Comments in those files *are* hand-maintained — the generator rewrites values
  only.
- **Scripts in `automation/` run under `dash`.** Write POSIX, use `$0` and not
  `${BASH_SOURCE[0]}`, and check with both shells.
- **Untrusted filenames never reach a guest as pasted shell text.** The rule has
  three live copies — `routers/jobs.py`, `sandboxd/naming.py`,
  `manifest.reject_unsafe_name` — and they must not disagree.
- **Never discover a process by matching a rendered command line.**
  `sandboxd/proc.py` compares argv *elements*; CI gates on the idiom.
- Update the comments, checklists and cross-references the change touches, **in
  the same change**. A citation left pointing at text you removed is the same
  defect as a stale comment, one file over.

---

## 2. Test

Run these in this order. The first two are cheap and catch most of it.

### 2.1 Shell — only if you touched a script

```bash
# DEV CONTAINER
bash -n automation/network-setup.sh && dash -n automation/network-setup.sh
shellcheck automation/*.sh
```

`dash -n` is not optional: `bash -n` alone accepts bashisms that fail silently
under `/bin/sh`. Run `shellcheck` bare — it reads `.shellcheckrc` itself, and
that is the form CI runs. The baseline currently disables **one** code
(SC1091) over one file; SC2086 and SC2009 came back when the scripts carrying
their findings were deleted, so a clean run now means more than it used to.

### 2.2 `sandboxd` — needs no infrastructure

```bash
# DEV CONTAINER
platform/.venv/bin/python -m pytest sandboxd/tests -q
```

428 passed in 15s on 2026-09-15. There is no separate sandboxd virtualenv in
the development container; the platform one has what it needs.

**This suite is also the documentation gate.** It re-runs all three generators
with `--check` and the reference checker, so it fails on a stale
`docs/CURRENT-STATE.md`, a stale `docs/INDEX.md`, a drifted `misc/*.cfg`, or a
dead `[link](path#anchor)` anywhere in the repository. When it fails that way,
regenerate — do not edit the generated text:

```bash
# DEV CONTAINER
python3 scripts/gen-current-state.py    # not executable; invoke with python3
scripts/gen-doc-index.py
scripts/gen-xen-configs.py
scripts/check-refs.py
```

### 2.3 `platform` — needs Postgres and MinIO

```bash
# DEV CONTAINER
scripts/dev-services.sh                          # idempotent; installs nothing
cd platform && .venv/bin/python -m pytest -q
```

862 passed, 3 skipped in 88s on 2026-09-15. The three skips are the
service-account policy tests, which want `mc` on `PATH`; the browser XSS tests
want `playwright install chromium`. Both skip loudly rather than failing.

**Never run this suite against the deployment.** Its `conn` fixture runs
`TRUNCATE jobs, worker_pipelines, workers RESTART IDENTITY CASCADE`.
`TEST_DATABASE_URL` defaults to `sandbox_platform_test`, which is why it is
safe here and destroys job history there. It was attempted on 2026-08-25 and
failed because that database does not exist on the DomU — **creating it is not
the correct response.**

### 2.4 Secrets — what the push hook will run

```bash
# DEV CONTAINER
scripts/check-secrets.sh --tree     # working tree only, like the hook
scripts/check-secrets.sh            # tree + full history, like CI
```

Enable the hook once per clone — hooks are not cloned with the repository:

```bash
git config core.hooksPath .githooks
```

### 2.5 What cannot be tested here

The development container is not Dom0 and not the DomU. `xl`, `drakvuf`,
`injector`, `vmi-process-list`, `lvcreate`/`lvremove`/`lvs`/`vgs`, `ovs-vsctl`,
`iptables` and `nft` are all out of reach, and so is anything touching the real
Postgres, MinIO or running API. Write those down as steps for the host instead
of approximating them — CI cannot substitute either, and says so in
`.github/workflows/static-checks.yml`.

CI runs four jobs on push: `static`, `secrets`, `sandboxd`, `platform`. Nothing
in it proves `network-setup.sh` still *executes* — only that it parses.

---

## 3. Commit

```bash
# DEV CONTAINER
git status --short
git diff                      # and `git diff --staged` once you have added
git add -p                    # hunk by hunk; it is how the diff stays reviewable
git commit
```

Subject lines here are imperative sentences describing the effect, not
conventional-commit prefixes — *"Refresh the masthead balance when a job is
charged"*, *"Let create_user.py set a password on an identity that exists"*.
Put the "what it used to do" in the message; the repository explains the
current system, and git explains how it got there.

A runbook is **committed after execution**, not before — see §8.

---

## 4. The gate before push

**If any unpushed commit touches code, a security review runs in a new session
before the push, scoped to `<last-reviewed-sha>..HEAD` plus the working tree if
it is dirty.** Not just uncommitted work: this repository commits too fast for
that to catch anything. Push is the boundary that matters, because Dom0 pulls
this repository and runs it.

Docs-only pushes are exempt. A push containing both docs and code is not.

```bash
# DEV CONTAINER
git log --oneline <last-reviewed-sha>..HEAD     # what the reviewer gets
git push origin master
```

The pre-push hook runs the tree secret scan and refuses the push if it finds
anything. That is the last reversible moment: a secret on the remote needs a
history rewrite *and* a credential rotation, because it has been served to
anyone who fetched.

---

## 5. Deploy — the platform DomU

Checkout `/opt/platform/src`, owned by `platform`; the service reads
`/etc/sandbox-platform/api.env`; two units have existed historically and
`sandbox-api-browser` is the one that serves. Confirm against
`docs/CURRENT-STATE.md` §1.3 before assuming any of that is still true.

### 5.1 Fetch, without starting it

```bash
# PLATFORM DOMU
cd /opt/platform/src
sudo -u platform git status --short          # expect empty
sudo -u platform git branch --show-current
sudo -u platform git fetch origin
sudo -u platform git pull --ff-only
git log --oneline -1
```

> **Check the branch before the pull.** Runbooks 16 and 17 deployed from a
> `platform-domu` branch. As of 2026-09-15 `origin` publishes only `master`,
> and that branch's commits are in it — so a checkout still sitting on
> `platform-domu` has an upstream that no longer exists and `git pull --ff-only`
> will not do what it looks like it did. `git checkout master` first if so.

### 5.2 Dependencies, only if `requirements.txt` changed

```bash
# PLATFORM DOMU
cd /opt/platform/src/platform
sudo -u platform .venv/bin/pip install -r requirements.txt
```

### 5.3 Environment, only if the change added settings

Edit `/etc/sandbox-platform/api.env`, then verify with an **anchored** grep —
an unanchored one also matches a line that was commented out rather than
deleted, and answers 1 against a file that is correct:

```bash
# PLATFORM DOMU
sudo grep -cE '^NEW_SETTING' /etc/sandbox-platform/api.env
```

### 5.4 Stop, migrate, start — in that order

The order is the point. New code that cannot read an old row must not serve
traffic during the migration, and a running listener would do exactly that.

```bash
# PLATFORM DOMU
sudo systemctl stop sandbox-api
systemctl is-active sandbox-api        # expect: inactive

cd /opt/platform/src/platform
sudo -u platform env $(grep -h '^DATABASE_URL=' /etc/sandbox_platform/api.env) \
  .venv/bin/python migrations/run.py --status     # read this before applying
sudo -u platform env $(grep -h '^DATABASE_URL=' /etc/sandbox_platform/api.env) \
  .venv/bin/python migrations/run.py

sudo systemctl start sandbox-api
systemctl is-active sandbox-api
sudo journalctl -u sandbox-api -n 20 --no-pager
```

`--status` first, and read it. **A digest mismatch on an already-applied file
means an applied migration was edited — stop.** The fix is a conversation, not
a re-run: the file and the live database have silently stopped describing the
same schema, and editing cannot reach a database that already ran the original.

Once applied, a migration is immutable. The next change is a new numbered file
with an `ALTER`. No `BEGIN`/`COMMIT` inside one — the runner owns the
transaction so the schema change and its bookkeeping row commit together.

**Back up first when the migration is not reversible**, which is all of them —
there are no down-migrations here, by design:

```bash
# PLATFORM DOMU
sudo -u postgres pg_dump -Fc sandbox_platform \
  > /var/backups/sandbox_platform-pre-NNNN-$(date +%F).dump
```

That dump is the rollback. Job rows and the `manifest` JSON cannot be rebuilt;
MinIO objects can be re-fetched, so they are out of scope — but a restore then
gives you rows pointing at artifacts the lifecycle rule may since have expired.

---

## 6. Deploy — Dom0

Checkout `/root/drakvuf-multios-sandbox`, virtualenv `.venv-sandboxd`,
environment `/etc/sandboxd/sandboxd.env` at mode 600.

```bash
# DOM0
cd /root/drakvuf-multios-sandbox && git pull --ff-only && git log --oneline -1
```

**`git pull` does not touch submodules**, and since 2026-09-26 this repository
has one: `drakvuf/`, the engine from our own fork. A pull that moves the pin
leaves the working tree at the old commit, and a *fresh* checkout leaves
`drakvuf/` an empty directory — neither says anything, so run this whenever the
pin moved:

```bash
# DOM0 -- Candidate: not yet run there
cd /root/drakvuf-multios-sandbox
git submodule update --init --recursive
git -C drakvuf log --oneline -1
```

`--recursive` is required, not tidiness: DRAKVUF carries `xen`, `libvmi`,
`volatility3` and `dwarf2json` of its own, and without them the tree does not
build. Budget ~265 MB. **This is not the tree that built the deployed
binaries** — that is `~/drakvuf`, and `CURRENT-STATE.md` §1.2 keeps the two
apart. Nothing here is compiled or installed by this step.

Dependencies only if `sandboxd/requirements.txt` changed:

```bash
# DOM0
/root/drakvuf-multios-sandbox/.venv-sandboxd/bin/pip install \
  -r /root/drakvuf-multios-sandbox/sandboxd/requirements.txt
```

**capa's rules are not in the repository** (`.gitignore`), and without them
`capa_analysis` logs "capa rules directory is empty or non-existant" and
produces no `ttps.json` — the job still completes. Once per Dom0, and again
whenever the `flare-capa` pin changes major version, at the tag matching that
pin (`v9.4.0` for `flare-capa==9.4.0`; a rules tree from another major
version fails to load with a schema error, not a version message):

```bash
# DOM0 -- Candidate: not yet run there
cd /root/drakvuf-multios-sandbox
git clone --depth 1 --branch v9.4.0 https://github.com/mandiant/capa-rules \
  sandboxd/postprocessing/data/capa-rules
```

The location is `CapaConfigSection.rules_directory`'s default; a different
one is `SANDBOXD_POSTPROCESS_CAPA='{"rules_directory": "/path"}'` in the
environment file.

**The same rules drive the hook lists, and that is a DEV CONTAINER step, not a
Dom0 one.** `sandboxd/data/hooks.txt` and `sandboxd/data/so-hooks-linux.txt`
are generated from capa's `api:` features, so a `flare-capa` major-version bump
means new rules and a stale hook list — a capa rule naming an API we do not
hook can never fire. Re-run it then, and only then; the output is committed:

```bash
# DEV CONTAINER -- needs three inputs, none of them in the repository
git clone --depth 1 --branch v9.4.0 https://github.com/mandiant/capa-rules /tmp/capa-rules
git clone --depth 1 https://github.com/marlersoft/win32json /tmp/win32json
git clone --depth 1 https://github.com/winsiderss/phnt /tmp/phnt
platform/.venv/bin/python scripts/gen-hook-lists.py \
  --rules /tmp/capa-rules --win32json /tmp/win32json --phnt /tmp/phnt
platform/.venv/bin/python scripts/gen-hook-lists.py ... --report   # what did not resolve
```

It is **not** one of the three suite-enforced generators, for that reason. See
its module docstring for why the DLL names come from Microsoft's metadata and
what is deliberately left out.

**vivisect is not a separate install.** The static pass over memory dumps runs
capa's vivisect backend, and vivisect
is a core dependency of `flare-capa`, so the `pip install` above brings it
(1.3.2 with `flare-capa==9.4.0`). The check that the pass has what it imports:

```bash
# DOM0 -- Candidate: not yet run there
/root/drakvuf-multios-sandbox/.venv-sandboxd/bin/python -c "import vivisect, viv_utils, capa.features.extractors.viv.extractor; print('ok')"
```

An `ImportError` there is an incomplete install of `requirements.txt`, not a
pin to add.

**Restarting `sandboxd` means stopping and re-running it.** There is no systemd
unit: `systemctl stop sandboxd` and `journalctl -u sandboxd` both report
nothing, and assuming otherwise is one of the four wrong assertions that caused
`docs/CURRENT-STATE.md` to be written. It runs in the foreground and logs to
stderr, so stop it in its own terminal and start it again:

```bash
# DOM0
cd /root/drakvuf-multios-sandbox
set -a; . /etc/sandboxd/sandboxd.env; set +a
.venv-sandboxd/bin/python -m sandboxd.daemon 2>&1 \
  | tee -a /var/log/sandboxd/$(date +%Y%m%d-%H%M).log
```

Two things that look like a broken install and are not:

- **It exits immediately without the env file sourced.** `Settings.from_env`
  raises `SystemExit` when `SANDBOXD_API`, `WORKER_TOKEN` or
  `SANDBOXD_TOTAL_MIB` is unset — deliberately, because there is no safe
  default for how much memory a Dom0 may hand to clones.
- **It refuses to start if another `sandboxd` or a leftover `dirwatch` binary
  is running.** Two orchestrators on one host allocate the same VLANs with no
  symptom but interference between two live analyses. `pgrep -a dirwatch` and
  stop it.

`sandboxd` provisions the analysis network at every start, so
`network-setup.sh` does not need running by hand — but the bridge itself
(`ovs-vsctl add-br xenbr1`) is still a one-time install step.

### Which host first

| The change | Order |
|---|---|
| Platform only | DomU. Dom0 needs nothing |
| `sandboxd` only | Dom0 |
| Both, compatible | DomU, then restart `sandboxd` |
| The worker protocol or `SANDBOXD_API` itself changes | **Repoint or stop `sandboxd` first.** Taking the endpoint away from a running worker fails as a connection error in a foreground process nobody is watching — see `docs/runbooks/17-deploy-own-identity.md` step 11 |

A new analysis host needs its own credential — tokens are per host, stored as a
sha256, printed once, and `--rotate` cuts a compromised host off immediately:

```bash
# PLATFORM DOMU
cd /opt/platform/src/platform
sudo -u platform DATABASE_URL=postgresql:///sandbox_platform \
  .venv/bin/python create_worker.py <host-name>
```

---

## 7. Verify

The deployment is verified by the runbook's `curl` checks and by looking at the
UI — never by pointing a test suite at it.

1. The API answers, and its startup log is clean.
2. `sandboxd` is claiming: its terminal shows `POST …/api/v1/worker/claim` →
   `200`.
3. **One full analysis.** Submit through the UI, watch it reach a terminal
   state, confirm the balance was drawn down, and open a console session while
   it executes. This is the only acceptance criterion that cannot be checked
   from a development container, and it is the one that matters.

---

## 8. Record what happened

| What you have | Where it goes |
|---|---|
| The commands that worked, with pasted output and a date | a runbook — written at the repository **root**, executed, then moved to `docs/runbooks/NN-` in the same change that fills its `EVIDENCE` blocks |
| A command that turned out to be wrong, a dead end, an error meaning something other than what it says | `docs/TROUBLESHOOTING.md`, symptom-first. **The runbook gets the right command, not both** — plus a one-line pointer wherever a reader could repeat the mistake |
| A value that is now wrong but still appears correct elsewhere | `docs/CURRENT-STATE.md` §2 |
| Work that landed | tick the box in `docs/checklists/` — never without evidence |

A runbook lives at the root until it is executed because
`gen-current-state.py` counts `docs/**/*.md` off the filesystem: a new file
under `docs/` fails `sandboxd/tests/test_current_state.py` until the generator
is re-run. Regenerate and commit in the filing change, then confirm the new row
reads `yes` in §3.

Commands you wrote but have not run on this project's Dom0 are labelled
**Candidate**. They are not working commands until they are evidenced, and a
Candidate must never appear inside an `EVIDENCE` block.

---

## 9. Rollback

| Layer | How |
|---|---|
| Code, either host | `git checkout <previous-sha>` in the checkout, then restart that host's service |
| Schema | restore the `pg_dump` taken in §5.4. There are no down-migrations |
| A DomU environment change | `api.env` is not in git — keep the previous value in the runbook step that changed it |
| A worker credential | `create_worker.py --rotate`; the old token stops working immediately |

---

## Traps that bite during this workflow specifically

- **A clean `shellcheck` is not a clean script.** Read `.shellcheckrc` first.
- **`0–5` is not `0,2,4,6,8,10`.** Under `smt=0` the online P-cores are the
  evens, so a CPU range written for the old nested topology resolves to a
  sparse set overlapping Dom0. Confirm with `xl cpupool-list -c` before
  changing a pinning.
- **`update-grub` can silently rewrite the Xen boot line.** `drakvuf-bundle`
  installs `/etc/default/grub.d/xen.cfg`, which computes Dom0's resources and
  replaces what was set by hand. Re-read `xl info xen_commandline` after any
  `update-grub`, including one run for an unrelated reason.
- **The DomU boots a kernel that lives on Dom0.** `apt upgrade` inside the
  guest updates `/boot` and the modules but not what Xen boots, so the domain
  comes back on the old kernel against new modules. Re-copy procedure:
  `platform-domu.md` §F2.
- **Do not run `playwright install` on the deployment.** 47.7 MB landed there
  once already.
- **A blank `EVIDENCE` block never proves an operation did not happen.** It
  proves nobody recorded output. Ask before reporting something as undone.

## Related

- `CONTRIBUTING.md` — the lifecycle, the review gates, the issue workflow, and
  the comment policy in full.
- `CLAUDE.md` — the same rules in short form, plus the non-obvious things that
  have caused real defects.
- `docs/CURRENT-STATE.md` — every deployment fact this file deliberately does
  not repeat.
- `docs/workflow-ci.md` — what each CI tier is for, and what the unbuilt ones
  would cover.
- `platform/README.md` — migrations and local Postgres/MinIO setup in detail.