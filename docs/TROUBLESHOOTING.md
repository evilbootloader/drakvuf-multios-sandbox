# Troubleshooting — things that have actually gone wrong

**Every symptom below happened.** Nothing here is anticipated or copied from
upstream documentation. If a failure mode is not in this file, it has not
bitten this project yet.

**Causes are diagnosed unless an entry says otherwise.** 

## How to use this file

**It is organised by symptom, not by subsystem** — by what you saw, not by what
turned out to be wrong. That is the whole point: when something breaks you know
the symptom and nothing else, and every other document here is organised by the
answer.

Each symptom is a `###` heading, so `docs/INDEX.md` carries all of them. Grep
the index for a word from your error and you get the entry and its line number
in one hit.

**What this file is not.** It is not a record of *facts* — for "is this value
still true?" read `docs/CURRENT-STATE.md`, whose §2a/§2b list values that still
look right in old runbooks and are not. It is not a substitute for the
`EVIDENCE` and `FINDING` blocks in `docs/runbooks/`, which are append-only
primary evidence; entries below cite them rather than restate them.

**What stays elsewhere, deliberately.** `CLAUDE.md` keeps its four pitfalls
inline because they are **write-time rules** — things you obey while typing,
not symptoms you look up afterwards. They point here for the full story.

---

# Static checks and the development container

### A script silently used `$PWD` instead of its own directory

**Symptom.** A script in `automation/` resolved repository paths against
wherever it was invoked from. No error, no warning — it simply operated on the
wrong tree.

**Cause.** `${BASH_SOURCE[0]}` evaluates to **empty under `dash`**, and
`automation/` scripts run under `dash`, not `bash` — `/bin/sh` is `dash` on
Dom0. `SCRIPT_DIR` then became the empty string, which resolves to the current
directory, and execution continued normally.

**Fix.** Use `$0`. Write POSIX. Check with `dash -n` **as well as** `bash -n` —
`bash -n` alone parses the file happily.

**Still live.** `network-setup.sh` is the only script left in `automation/` and
this applies to it and to the next one written. Originally found when the C
watcher spawned five worker scripts via `g_spawn_command_line_sync()`; those
were deleted 2026-09-15, the trap was not.

### `shellcheck automation/*.sh` exits 0 on code with unquoted expansions

**Symptom.** A clean shellcheck run on scripts that contain real SC2086 sites.

**Cause.** `.shellcheckrc` disabled `SC1091,SC2086,SC2009` **repository-wide**.
That was a deliberate reviewed baseline (DRAFT-031), not an oversight — the
bare command is what `CLAUDE.md`, `README.md` and `docs/workflow-ci.md` all
tell you to run, and a gate that is red by default gets ignored.

**Largely resolved 2026-09-15, and by deletion rather than by a fix.** Every
SC2086 and SC2009 site lived in `cleanup.sh` and the per-OS trace scripts, which
were deleted with the rest of the launcher pipeline, so both codes were removed
from the baseline and are **live again for every file**. Only `SC1091` is still
disabled, for a `source` path `network-setup.sh` builds at runtime — correct
behaviour, not a finding. The general warning stands: read `.shellcheckrc`
before taking a clean run as clean code.

**Fix.** Read `.shellcheckrc` before reading a clean run as clean code. For new
files, check with `shellcheck --norc <file>`, which applies no exemptions. The
cost is stated in that file: a dangerous new unquoted expansion in a
future per-OS script will **not** be caught until DRAFT-011 lands.

### `severity=warning` in `.shellcheckrc` changes nothing

**Symptom.** Setting a severity floor in the rc file has no effect on output or
exit status, while `disable=` in the same file works.

**Cause.** `severity=` is silently ignored by shellcheck 0.11.0 in rc files.
Measured, not assumed. Only the CLI `-S` flag applies a floor.

**Fix.** Nothing to do — this is why the baseline uses blanket `disable=` lines
rather than the cleaner severity floor. Re-test on a shellcheck upgrade; if it
starts working it is strictly better, because it keeps checks live for code
written after the baseline.

### `git push` refused with `SECRET DETECTED`, and the re-run shows nothing

**Symptom.** The pre-push hook prints `SECRET DETECTED in the working tree.
Re-run for detail:` and a `trufflehog filesystem … --exclude-paths=/tmp/tmp.…`
command. Running that command fails on the exclude file, so the finding is
never seen. 2026-10-21, the first push after trufflehog was installed in the
development container — until then the generic pass had been skipped.

**Cause.** Three things in `scripts/check-secrets.sh`:

- trufflehog's output went to `/dev/null`, and the suggested re-run named the
  exclude list's temp file, which the script's `trap` deletes on exit;
- any non-zero exit read as a finding, so a scanner that crashed would have
  produced the same message;
- the finding itself was a false positive: line 226 of
  `misc/Artifacts/source-manifest.xml`, a public git revision in the BlissOS
  repo manifest. Its line names the `ag-github` remote, and the first 20 hex
  digits of the revision match GitHub's OAuth client id format — 14 unverified
  `GitHubOauth2` hits, all on that line. The history scan does not flag it.

**Fix.** The script now prints each finding as detector and `file:line`, plus
the commit for history — never the value, since CI logs the same run. It tells
a scanner failure (`trufflehog FAILED (exit N) … it was not checked`) apart
from exit 183, a finding, and it excludes that manifest from both scans. To see
the raw result by hand, run `trufflehog filesystem . --results=verified,unknown`
without the exclusions.

### `cd platform && .venv/bin/python -m pytest -q` fails or hangs in the dev container

**Symptom.** The command `CLAUDE.md` documents does not work. Postgres refuses
connections, or MinIO-dependent tests error, or the run is killed on timeout.

**Cause.** The dev container starts with the Postgres cluster **down** and MinIO
**not installed**. Neither comes up on its own, and nothing in the repository
brought them up until `scripts/dev-services.sh` existed.

**Fix.** `scripts/dev-services.sh` first. It is idempotent, starts the cluster,
creates `sandbox_platform_test`, starts MinIO with the right environment, and
**reports** what is still missing (`mc`, Chromium) rather than failing. It
installs nothing from the network — it prints the `curl` command for MinIO
instead.

The `sandboxd` suite needs none of this:
`platform/.venv/bin/python -m pytest sandboxd/tests -q`.

### `test_objects.py::test_the_region_is_enforced` fails right after a services restart

**Symptom.** One platform test expects `400 AuthorizationHeaderMalformed` and
gets `200`. It reads as a code regression in whatever you just changed.

**Cause.** MinIO was restarted **without `MINIO_SITE_REGION`**. The two
credentials alone are enough for it to come up and serve every other test, but
with no site region MinIO accepts a signature scoped to any region — the region
is part of the SigV4 signing scope.

**Fix.** Restart MinIO with `MINIO_SITE_REGION` equal to `S3_REGION`, which
`scripts/dev-services.sh` does. Expect **405 passed, 3 skipped** (the 3 are the
`mc` service-account policy tests). A single `test_objects.py` failure right
after a restart is the environment, not the diff.

**`mc admin config get <alias> region` does not reveal this** — it reports empty
for an env-provided value, which is what made the variable look unset in the
first place. See `platform/minio/provision.sh` and runbook `08` §2351.

*Cost when it bit: a false alarm on a `sandboxd` change that touched no platform
code, 2026-08-26.*

### `pull access denied for minio/minio` — CI's platform job dies before pytest

**Symptom.** The `platform` job fails at **Start MinIO** with exit code 125 and
runs in ~48s instead of ~2m. `static`, `secrets` and `sandboxd` are all green.

```
Unable to find image 'minio/minio:RELEASE.2025-09-07T16-13-09Z' locally
docker: Error response from daemon: pull access denied for minio/minio,
repository does not exist or may require 'docker login'
```

**Cause.** **MinIO deleted `minio/minio` from Docker Hub**, between the last
green run on 2026-09-07 and the first red one on 2026-09-15. Nothing in this
repository changed — the image pin has one commit in its whole history.

That message is the generic response to any 401 and would read identically for
a rate limit or an expired login, so diagnose it against the registry rather
than from the text: `hub.docker.com/v2/repositories/minio/minio` answers
`object not found` for the **repository**, not the tag, and `minio/mc` is gone
the same way — while the other 20 repositories in the `minio` namespace are
untouched. A targeted removal, not an outage and not your credentials.

**Fix.** quay.io is MinIO's other official registry and serves the same release
anonymously. One line in `.github/workflows/static-checks.yml`:

```yaml
quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z server /data
```

**`dl.min.io` went with it — every path answers 410.** That was the download
`scripts/dev-services.sh` printed when MinIO was missing, so a rebuilt
development container was given an install command that could not work. It now
points at GitHub's release assets for the same pinned build.

**Do not "fix" this by bumping to a newer release.**
`RELEASE.2025-09-07T16-13-09Z` is the last MinIO release with published
binaries at all; `RELEASE.2025-10-15T17-29-55Z` ships zero assets. Keep CI and
`dev-services.sh` on the same version — a developer whose MinIO differs from
CI's gets failures nobody else can reproduce.

*Cost when it bit: three red runs on 2026-09-15, one of them on `master`.*

### `Recv failure: Connection reset by peer` from 8443

**Symptom.** `curl --cacert ca.crt https://192.168.1.10:8443/healthz` fails with
`curl: (56) Recv failure: Connection reset by peer`. The service is running and
the browser listener on 8000 answers fine, so it reads as the worker channel
being down.

**Cause.** It is not down. **8443 is mutual TLS** — `--ssl-cert-reqs 2` in its
unit — so the server demands a client certificate during the handshake and
resets when the caller offers none. `--cacert` only tells curl whom to *trust*;
it does not present an identity. The reset is the gate working.

**Fix.** Call it the way Dom0 does, with the client certificate:

```bash
curl -sS --cacert /etc/sandboxd/tls/ca.crt \
     --cert /etc/sandboxd/tls/dom0-lab.crt \
     --key  /etc/sandboxd/tls/dom0-lab.key \
     https://192.168.1.10:8443/healthz; echo      # {"status":"ok"}
```

Those paths are Dom0's. On the platform DomU itself there is no client
certificate to present — the CA signing key lives on the workstation and the
platform deliberately holds no ability to mint one — so **this check belongs on
Dom0**, not on the machine serving it.

**The two listeners fail differently, and that is diagnostic.** A reset on 8443
means no client certificate. `Empty reply from server` on 8000 means `http://`
against a TLS listener — a different entry in this file.

*Cost when it bit: one line of a deploy runbook written without `--cert`,
recorded as a failure against a listener that was healthy, 2026-09-10.*

### `ConnectionRefusedError` to `192.168.1.10:8000` from `sandboxd/vnc.py`

**Symptom.** Every trace logs a stack trace ending
`ConnectionRefusedError: [Errno 111] Connect call failed ('192.168.1.10', 8000)`
from `vnc.py:368`. **The analysis itself is unaffected** — `ConsoleSession._run`
and `_start_console` both swallow it, by design: the console is an observer of
the run, not a participant. So this is log noise, not a failed job, and the
clone still runs and the trace still completes.

**Cause.** Decision 3 of #40, deployed 2026-09-06 (`platform-domu.md` §E4a),
rebound the browser listener from `192.168.1.10:8000` to `127.0.0.1:8000`. Dom0
is a different machine, so the DomU's loopback is not reachable from it.
`SANDBOXD_CONSOLE_API` still points at the address that worked the day before.

**Do NOT "fix" it by pointing `SANDBOXD_CONSOLE_API` at 8443.** The connection
would succeed and the console would then **hang forever**, which is strictly
worse — a refusal names its cause in one line, a hang reads as infrastructure
trouble and gets retried. The console relay pairs two sockets in an
**in-process registry**, and the browser end arrives on 8000 via cloudflared.
A worker end on 8443 lands in a different uvicorn process, so the two sides can
never meet and both simply wait. That is F11, Dom0 2026-08-26, and it is the
whole reason `Settings.console_api` exists separately from `Settings.api`.

**Fix, taken 2026-09-10: the listener was rebound to the LAN address**, undoing
decision 3. The console works again and the gate is now `REQUIRE_ACCESS_JWT=1`
alone — the loopback bind was defence in depth behind it. Two things that costs,
both being the pre-2026-09-06 state rather than new: a lost `access.conf`
drop-in becomes a config slip on a LAN socket rather than a loopback one, and
the console's worker end on `:8000` has no `--ssl-ca-certs`, so attaching to a
running clone over the LAN is gated by the bearer token alone.

`SANDBOXD_CONSOLE_ENABLED=0` is the alternative if you would rather keep the
loopback bind than have the console. It is the shipped default.

**One other thing not to do.** Routing the browser's console socket to 8443
through cloudflared would put it on the listener where `auth.visible_to` returns
`TRUE` — any Access user could then open any job's console.

**The real fix** is to move the pairing registry out of process; Postgres
`LISTEN`/`NOTIFY` needs no new dependency, since both listeners already hold a
pool. That is a design change and wants its own draft.

*Cost when it bit: a stack trace on a pre-clone test, 2026-09-07, on a
deployment where the console had already been silently broken for a day —
neither §E4a nor `CURRENT-STATE.md` mentioned the console.*

### `curl` from outside returns the expected status and proves nothing

**Symptom.** You add or change a cloudflared ingress rule for
`sandbox.evilbootloader.com`, verify it with an anonymous `curl` from the
internet, and get the status you were hoping for. The rule looks confirmed.

**Cause.** **Cloudflare Access enforces at the edge, before cloudflared is
reached.** An unauthenticated request never touches your ingress rules at all —
it gets a 302 to the Access login page, and `curl -si … | head -1` shows that
302 whether the rule exists, is broken, or was never applied. Runbook 16's F12
check was written as `curl -si …/api/v1/worker/claim # 404` and would have
returned the same 302 before *and* after the fix.
`08-deploy-platform-lxc.md:1886` had already recorded the caveat — "the 302
only proves **Cloudflare** is doing its job" — against a different check.

**Fix.** Verify from past Access, not in front of it: a browser holding a
session, or its `CF_Authorization` cookie in `curl -b`. Then pick a path whose
statuses discriminate. `/api/v1/worker/claim` is POST-only, so a **GET** gives
three distinguishable answers — **404** the ingress rule answered, **405** the
request reached FastAPI so the rule is not in force, **302** Access bounced it
and the test says nothing. A check that returns the same value on success and
failure is not a check.

*Cost when it bit: caught before it bit, 2026-09-10, while filling EVIDENCE
F12 — but the wrong command sat in two runbooks for fifteen days.*

### `tunnel ingress rule` passes green against rules the tunnel is not serving

**Symptom.** `cloudflared tunnel ingress rule <url>` matches exactly the rule
you just added, `tunnel ingress validate` passes, and traffic still reaches the
origin you thought you had blocked.

**Cause.** Both subcommands read `/etc/cloudflared/config.yml` **from disk**.
They report what the rules on the filesystem would do. The running daemon keeps
the ingress it parsed at startup and picks up changes on SIGHUP, so an edit
that was never reloaded leaves the two permanently disagreeing — with the
diagnostic siding with the file.

**Fix.** `systemctl reload cloudflared || systemctl restart cloudflared`, then
verify through the live tunnel rather than against the config. Treat
`ingress rule` as a syntax and ordering check — which it is good at, including
telling you the matched rule's **0-based** index — and never as proof of what
the tunnel is serving.

### The platform test suite destroyed job history

**Symptom.** Running the platform suite anywhere other than the dev container.

**Cause.** Its `conn` fixture runs
`TRUNCATE jobs, worker_pipelines, workers RESTART IDENTITY CASCADE`.
`TEST_DATABASE_URL` defaults to `sandbox_platform_test`, which is safe here and
does not exist on the deployment.

**Fix — and the important half.** It was attempted on the deployment
2026-08-25 and failed with 312 errors *because that database does not exist*.
**The correct response is not to create it.** The deployment is verified by the
runbook's `curl` checks and by looking at the UI. Do not run
`playwright install` there either.

---

# Documentation machinery

### `test_current_state.py` fails after you added or removed a file under `docs/`

**Symptom.** A test unrelated to your change goes red, complaining
`docs/CURRENT-STATE.md` is out of date.

**Cause.** `scripts/gen-current-state.py` counts `docs.rglob("*.md")` off the
**filesystem**, not off git. Any new `.md` under `docs/` — tracked or not,
numbered or not — changes the repository-size table.

**Fix.** Run both generators and commit the result:

```
scripts/gen-current-state.py
scripts/gen-doc-index.py
```

This is also why a runbook is **parked at the repository root** until it has
been executed: moving it into `docs/runbooks/` before it is ready would fail the
suite while the file is still untracked.

### A runbook you know was executed shows `Executed: no`

**Symptom.** The derived table in `docs/CURRENT-STATE.md` §3 reports a runbook
as evidence-free while it visibly contains pasted host output.

**Cause.** `_EVIDENCE_HOSTS` in `scripts/gen-current-state.py` is an explicit
list of hostnames whose shell prompts count as evidence. **A host rename
silently invalidates it**, and the 2026-08-28 migration did exactly that: Dom0
stopped being the nested VM `drakvuf` and became bare-metal `dom0`. Until `dom0`
was added, `12-baremetal-trial.md` counted 7 prompts instead of 32 and
`platform-domu.md` counted **zero**.

**Fix.** Add the host to `_EVIDENCE_HOSTS`. Keep it an explicit list — a bare
`root@\S+` would also match prompts quoted inside prose, examples and findings,
which are not evidence of anything.

### A runbook shows `Executed: yes` but its banner says NOT YET EXECUTED

**Symptom.** A ⚠ in the derived table's Note column.

**Cause.** Status banners are written *before* execution and are frequently
never updated. `09-verify-sandboxd-and-console.md` carried its "NOT YET
EXECUTED" header while containing 44 pasted Dom0 prompts. This is why the banner
gets no vote in the generator — pasted prompts decide.

**Fix.** Correct the banner at the source. The ⚠ is deliberately a nag, not a
tolerated state.

### An empty `EVIDENCE` block, and you concluded the operation never happened

**Symptom.** Reporting something as not done because nothing was pasted.

**Cause.** **Attested is not the same as pasted.** A blank `EVIDENCE` block
means nobody recorded output. It never proves the operation did not occur.

**Fix.** Ask the operator. This produced a wrong review finding on 2026-08-29:
`sandboxd` and end-to-end analysis for both Ubuntu and Android were reported as
"not run since the migration" purely from blank blocks, and all of it had in
fact run. The derived table correctly still reads `no` — that is the table
reporting *recorded evidence*, which is its job — but prose must not upgrade
that into a claim about reality.

### `gen-xen-configs.py --check` passed while the files disagreed

**Symptom.** `sandboxd/config.py` says `xenbr1`, `automation/platform.env` says
something else, and `--check` reports them in agreement. The gate built to catch
exactly this drift reported clean.

**Cause. Stale bytecode.** The generator loaded `config.py` with `importlib`,
which validates its `__pycache__` entry on **`(mtime, size)`**. Two things had
to line up, and both are ordinary:

- The edit was **length-preserving** — `xenbr1` → `xenbr9` is the same size, and
  so is `xenbr1` → `xenbr2`, which an operator would plausibly type.
- The edit landed in the **same filesystem-timestamp second** as the previous
  run, which any edit-then-generate script does.

Python then served the previous compilation, and the generator compared old
values against the current files.

**Fix.** The loader now reads the source and `exec`s it, which touches no cache.
`test_the_generator_does_not_serve_stale_bytecode` pins the behaviour with a
deliberately length-preserving probe.

**The general form is worth carrying:** any tool that loads a config file by
path and then reports agreement can report a *false* agreement. Reproduced
2026-08-31 rather than reasoned about — the drift was visible in `git diff` and
the gate said nothing.

### A cross-reference points at a line that moved

**Symptom.** `some-file.py:141` names a line that is now something else.

**Cause.** Nothing checks prose. Both runbook 11 and 12 cited
`scripts/gen-current-state.py:141` for the `docs.rglob` count; editing the
generator moved it to `:155` and nothing went red.

**Fix.** Prefer naming a **section or function** over a line number when the
target is likely to move. `scripts/check-refs.py` gates the resolvable cases.

---

# Dom0 boot, LVM and GRUB

### `grep -rn 'ubuntu-vg'` came back clean while GRUB still used the old name

**Symptom.** After `vgrename ubuntu-vg vg-root`, a grep across `/etc/fstab`,
`/etc/default/grub`, `/boot/grub/grub.cfg` and `/etc/initramfs-tools/` reported
no remaining references. GRUB still referenced the old VG.

**Cause.** **Device-mapper doubles dashes in VG names.** `grub.cfg` contains
`ubuntu--vg-ubuntu--lv`, and the substring `ubuntu-vg` **does not occur anywhere
in it**. The grep was structurally incapable of matching the one file it most
needed to check — a false negative that reads exactly like a clean result.

**Fix.** Always search for **both spellings**:

```bash
grep -rn 'ubuntu--vg\|ubuntu-vg' /etc/fstab /etc/default/grub \
    /boot/grub/grub.cfg /etc/initramfs-tools/
```

The same escaping bites anything reading `kpartx` or `/dev/mapper` output. It is
the strongest practical argument for **a VG name with no dash in it** — which is
why `vg-root` is worth the rename rather than living with `ubuntu-vg`.

*Source: `docs/runbooks/12-baremetal-trial.md` §D1, CORRECTION block.*

### `update-grub` and `update-initramfs` error on a device that no longer exists

**Symptom.**

```
cryptsetup: ERROR: Couldn't resolve device /dev/mapper/ubuntu--vg-ubuntu--lv
cryptsetup: WARNING: Couldn't determine root device
/usr/sbin/grub-probe: error: failed to get canonical path of `/dev/mapper/ubuntu--vg-ubuntu--lv'
```

**Cause.** Stale references to the pre-rename VG. The tools resolve the root
device by name and the name changed under them.

**Cause, more precisely — and it makes the obvious ordering impossible.**
`grub-probe` resolves `/` through the mount table, and `/proc/mounts` still
carries the string captured at mount time. **A live `vgrename` renames the
device-mapper nodes but not the recorded mount source**, so the old name is
unresolvable and the new one is not what the kernel was told. It cannot become
correct until after a reboot — so `update-grub` **cannot succeed before one**.

**Fix. Hand-edit `grub.cfg` to reach a bootable state, reboot, then regenerate.**

```bash
ls -la /dev/mapper/                        # expect vg--root-*, no ubuntu--vg-*
sudo grep -n 'root=' /boot/grub/grub.cfg   # mode 600 -- sudo needed

# only if root= still names the old device:
sudo cp /boot/grub/grub.cfg /boot/grub/grub.cfg.bak
sudo sed -i 's/ubuntu--vg-ubuntu--lv/vg--root-ubuntu--lv/g' /boot/grub/grub.cfg
sudo reboot

# AFTER the reboot, regenerate properly -- both now succeed
sudo update-grub2 && sudo update-initramfs -u -k all
```

Hand-editing a generated file is legitimate here: it is a one-off to reach a
bootable state, and `update-grub` regenerates it cleanly afterwards. With
nothing persisted, the alternative is to press `e` at the GRUB menu, correct
`root=` on the `linux` line, and `Ctrl-X`.

**`update-grub` failing is not itself destructive** — it writes to a temp file
and renames, so the previous `grub.cfg` stays intact. But it still names the old
device, and **the machine drops to an initramfs shell if rebooted as-is.**

**Let `update-initramfs` finish.** It was interrupted with `^C` on the first
attempt, which is worse than not running it: root lives on this VG, so an
initramfs that half-describes it does not boot.

**Two things that made this survivable, worth checking on any host:**
`set root='lvmid/<vg-uuid>/<lv-uuid>'` locates `/boot` by **UUID**, and
`/etc/fstab` uses `dm-uuid-LVM-<uuid>`. Both encode UUIDs, not names, and
survive the rename. Only the `root=` kernel argument uses the mapper name.

### A thin pool that will not activate at boot, long after it was created fine

**Symptom.** `lvcreate` succeeded; the pool refuses to come up on the next boot.

**Cause.** `thin-provisioning-tools` is missing. It provides `thin_check`, and
**LVM refuses to activate a thin pool without it.**

**Fix.** Install it when creating the pool, not when the failure appears — the
gap between the two is a reboot, which is what makes this hard to attribute.

### `thin_pool_autoextend_*` is configured and the pool still filled up

**Symptom.** Autoextend thresholds are set and the pool never grows.

**Cause.** Two independent ways to have a decorative guardrail:

- **`lvm2-monitor.service` is not running.** The `thin_pool_autoextend_*`
  settings are read by `dmeventd`; without the monitor they are inert
  configuration. This is the single most likely way to believe there is a
  guardrail when there is none.
- **The pool owns the whole VG.** Autoextend can only grow into free VG space.
  `-l 100%FREE` leaves it nowhere to go.

**Fix.** `systemctl is-active lvm2-monitor`, and create the pool at `-l 90%FREE`
so ~150 G stays unallocated **deliberately**.

**This is not hypothetical — it is the state of the machine that was replaced.**
`pve-data` took 1.7 T of a 1.82 T VG, leaving 16 G, and that is precisely why
shrinking it was impossible when the migration needed the space. Do not rebuild
the same trap.

### `xl create` fails on a missing block device after `lvcreate -s`

**Symptom.** The snapshot exists in `lvs` and `/dev/vg-root/<clone>` does not.
`lvs -o lv_attr` shows `Vwi---tz-k` — trailing **`k`**, positions 5–6 `--`:
inactive, not open, no `/dev` node.

**Cause.** `lvcreate -s` on a **thin** LV sets the activation-skip flag, so the
new volume is not activated. **Thick snapshots do not behave this way**, so this
does not surface until the first clone on new thin storage.

**Fix.** Either clear the flag at creation or override it at activation:

```bash
lvcreate -s -kn -n ubuntu-1-clone vg-root/ubuntu     # clear at creation
lvchange -ay -K vg-root/ubuntu-1-clone               # or override at activation
```

`sandboxd/clone.py::argv_lvcreate` uses `-kn`, on top of dropping `-L`.

### `grep /boot/grub/grub.cfg` says Permission denied

**Symptom.** A plain `grep` on `grub.cfg` fails even though the file exists.

**Cause.** `grub.cfg` is mode 0600. Nothing to do with the content.

**Fix.** `sudo`. Worth knowing because it appears mid-sequence in a chain of
real errors and reads like another symptom of the same fault.

### `update-grub2` exits 0 and `grub.cfg` does not change

**Symptom.** `update-grub2` (or `update-grub`, the same `grub-mkconfig -o
/boot/grub/grub.cfg`) returns 0, and `grub.cfg` keeps its old timestamp and
its old Xen boot line. Run as `grub-mkconfig` to stdout, it prints only:

```
Sourcing file `/etc/default/grub'
Sourcing file `/etc/default/grub.d/xen.cfg'
```

and no menu entry at all — observed 2026-10-20, four lines in total.

**Cause.** `/etc/default/grub.d/xen.cfg` from the drakvuf-builds
`xen-hypervisor` package checks for `drak-find-xen-defaults` and runs `exit 0`
when it is missing. The file is *sourced*, so that `exit` ends `grub-mkconfig`
before it writes anything, with status 0. Removing `xen-hypervisor` to install a
Xen built from source removed `drak-find-xen-defaults` and kept `xen.cfg`, a
conffile, which is exactly this state.

**Fix.** Drop the check from `xen.cfg` — the operator commented it out on
2026-10-21 — or install `automation/xen-grub.cfg` there, which `make xen` does.
**Do not purge `xen-hypervisor` instead**: that deletes `xen.cfg`, and with it
the line that makes GRUB boot Xen by default, so the next boot comes up as plain
Ubuntu. Afterwards `sudo grep -c multiboot2 /boot/grub/grub.cfg` should be
non-zero and the timestamp current.

**Why it went unnoticed.** The old `grub.cfg` kept booting the new Xen, because
its entries load `/xen.gz` and the new package replaced that file. Only a
change to the boot line would have shown it.

### `git apply` of the altp2m fix: `patch failed: xen/arch/x86/mm/altp2m.c:220`

**Symptom.** The patch posted to xen-devel does not apply to the `xen`
submodule at `RELEASE-4.20.1`.

**Cause.** It was written against Xen's development branch, where
`p2m_switch_vcpu_altp2m_by_id()` checks `idx >= d->nr_altp2m`; 4.20.1 checks
`idx >= MAX_ALTP2M`. The change itself is identical.

**Fix.** Apply `automation/xen-altp2m-pause-vcpu.patch`, the 4.20.1 backport,
which is what `make xen` does.

### `~/drakvuf` did not exist, but the build continued anyway

**Symptom.**

```
bash: cd: /root/drakvuf: No such file or directory
Directory already configured.
```

**Cause.** Two things at once. The DRAKVUF checkout is at
`/home/user/drakvuf`, not `/root/drakvuf`, and `~` resolves differently under
`sudo`/`root` than for the operator. **The `cd` failed and the following
commands ran in the wrong directory** — chained with `;` or newlines rather than
`&&`, so nothing stopped.

**Fix.** Use absolute paths for the DRAKVUF tree, and chain with `&&` when a
later step is meaningless without an earlier one. The same session shows
`grep -rn … /root/drakvuf/src/` returning "No such file or directory" for the
same reason.

---

# Dom0, Xen and the guests

### Every `DRAKVUF_*` chain vanished and clones are running unfiltered

**Symptom.** `iptables -S DRAKVUF_ISOLATION` reports no such chain, on a host
where it existed minutes ago. Clones that were mid-analysis keep running, with
no inter-clone isolation, no LAN block and no Dom0 protection. Nothing logged
an error, and the pipeline reports nothing wrong — the analyses complete and
look normal.

**Cause. FakeNet-NG was started with its default `LinuxFlushIptables: Yes`.**
That option "flush[es] all `iptables` rules before adding rules for
FakeNet-NG" (its README), which on this host means the entire containment
posture, for every clone currently running, while they run.

Its README promises "the Linux Diverter will restore the old rules as long as
its termination sequence is not interrupted". **That conditional is the whole
trap.** A `kill -9`, an OOM kill, a crash, or a host reset means they are never
restored, and Dom0 comes back with malware VMs on an unfiltered network.

**Fix.** `LinuxFlushIptables: No` in `automation/fakenet.ini`, which is how the
reference config ships. `sandboxd/tests/test_egress.py` asserts it, so this
cannot regress silently. Then re-run `automation/network-setup.sh <clones>` to
rebuild the chains, and treat any clone that was running as contaminated — it
had unrestricted network access for an unknown interval.

**The related setting, same file, different failure.** `DivertTraffic: Yes`
(also FakeNet's default) makes its diverter install a **blanket** `REDIRECT` in
`PREROUTING`, capturing every analysis VLAN rather than the ones running in
`simulated`. A clone submitted as `offline` would then be answered by the fake
Internet — `offline` silently stops meaning offline, and the report shows a
sample talking happily to something it was never supposed to reach. There is no
error to see; it looks exactly like a result. Ships as `No`, also asserted.

### A clone in `tor` or `simulated` reports that nothing would connect

**Symptom.** The analysis completes. The pcap shows the clone sending SYNs, or
DNS queries, and getting nothing back or an instant RST. The report reads as a
sample whose infrastructure is down.

**Cause.** The redirect rules were installed but **nothing is listening on the
port they point at** — tor not started, FakeNet not running, or either bound
somewhere other than expected. A `REDIRECT` to a closed port is refused
immediately, which looks identical to a dead C2.

**This should not reach you**, and if it did, say so: `sandboxd` probes the
listener before offering the mode at all, and probes it again at launch,
falling back to `offline` and recording the reason in `egress_applied`. Check
the report — a run that fell back says so:

```
requested: simulated   applied: offline
reason: simulated responder not listening on 127.0.0.1:38926 at launch
```

If the report shows `applied: simulated` and the traffic still went nowhere,
the listener was up but not answering, which is a FakeNet or tor problem rather
than a firewall one. `journalctl -u tor` and FakeNet's own stdout are the next
stop, not `iptables -S`.

### A clone drops to an initramfs shell with `UNEXPECTED INCONSISTENCY`

**Symptom.**

```
/dev/xvda5: recovering journal
/dev/xvda5 contains a file system with errors, check forced.
Inode 2622029 has an invalid extent node (blk 10518898, lblk 0)
```

Everything else looks right: `root=UUID=…` matches, the device is present,
`blkid` in the initramfs reports the correct UUID and type.

**Cause.** A `.bak` memory image was restored against a **disk it was not saved
from**. The guest's kernel carried in-memory filesystem state — inode cache,
journal position, block allocation — describing a different disk, wrote against
this one, and was `xl destroy`'d without a clean shutdown, repeatedly. The
golden was *not* at fault; `e2fsck` on the origin came back clean.

**Fix. Never restore a `.bak` against a disk it was not saved from.** The
pairing is not advisory. Rebuild the template so image and disk match.

**What this invalidates, and it is the part worth remembering:** every check
that passed beforehand was **memory-only**. `xl restore` resumes RAM;
`vmi-process-list` reads RAM. Neither touches the root filesystem, so a broken
disk stays invisible until `xl create`. Any throughput figure measured against
such a guest describes a degraded guest — the 902 events/sec taken here was
discarded.

**Do not over-attribute to it.** This finding originally also blamed the
corruption for an anomalously low clone CPU figure (1.0%). **Refuted by
measurement**: a rebuilt template on a verified-clean golden, with a matched
memory image, produces the same ~0.8%. The corruption was real and worth fixing
and was not the cause of that number — a reminder that one confirmed fault
happily absorbs blame for unrelated symptoms.

*Source: `docs/runbooks/12-baremetal-trial.md` FINDING D-1.*

### A template's disk drifted away from its saved memory image

**Symptom.** Clones from a template start failing the way FINDING D-1 describes
— `UNEXPECTED INCONSISTENCY` on the root filesystem — some time after a manual
operation on that template.

**Cause.** `misc/*_sandbox.cfg` points at the **template LV, writable**
(`phy:/dev/vg-root/ubuntu_sandbox,hda,`**`w`**). Restoring against that config
and then `xl destroy` **advances the disk while the `.bak` stays where it was**.
That is exactly how D-1's corruption was produced.

**Fix.** Use `misc/*_sandbox.cfg` **only for edits that end in `xl save`**, which
is what re-pairs disk and memory. `sandboxd/clone.py::rewrite_config` never
touches it — it rewrites the `disk=` line to point at the per-clone snapshot,
and anything manual should do the same.

| Operation | Config | Ends in |
|---|---|---|
| Editing the template (anchor swap, network flush) | `misc/*_sandbox.cfg` | **`xl save`** — mandatory |
| Validating a restore | temp cfg on a throwaway snapshot | `xl destroy` + `lvremove` |
| **Measuring** | temp cfg on a throwaway snapshot | `xl destroy` + `lvremove` |

Measuring on a throwaway is also more correct: every run starts from a
byte-identical disk instead of inheriting the previous run's writes.

To check whether a template has already drifted, compare `Data%` against its
value immediately after the last `xl save`:

```bash
sudo lvs -o +data_percent vg-root/ubuntu_sandbox
```

### `preconfig-*.sh` does not build a template — it runs at analysis time

**Symptom.** Following "copy golden → apply preconfig → boot → save state" and
getting a template with no injection anchor.

**Cause.** The preconfig stage runs at **analysis** time against a **clone**,
and does two things: stages the sample with `injector -m writefile`, then sets
that clone's VLAN address with `injector -m execproc`. **It never touches the
template.** (Was `preconfig-<os>.sh`; now `sandboxd/stages.py`'s preconfig
phase, with the argv in `sandboxd/guests.py`. The trap is unchanged.)

**Fix.** What actually makes a template is booting the disk, **starting an
injection anchor**, and `xl save`. The anchor is the whole point — see the
anchor entries under *Guest execution and samples*.

### `xl vcpu-list 0` shows one vCPU with a multi-CPU affinity mask

**Symptom.** Five of Dom0's six vCPUs are pinned 1:1; the sixth keeps the
default mask `0,2,4,6,8,10` and floats. It was observed on pCPU 6 — another
vCPU's pinned core — while pCPU 10 sat unclaimed.

**Cause.** `dom0_vcpus_pin` against a **sparse** online pCPU set. Nested, QEMU
presented 12 flat vCPUs so Xen's pCPUs were contiguous `0–11` and all six pinned
cleanly. On bare metal `smt=0` parks the odd siblings and the sixth pin does not
take. **This is bare-metal-only** — it cannot be reproduced in the old lab.

**Fix.** `xl vcpu-pin 0 5 10`, which does **not** survive reboot; or drop
`dom0_max_vcpus` to 5 so the boot line and reality agree. A floating vCPU can
share a physical core with a pinned one, which is invisible contention.

*Source: `docs/runbooks/12-baremetal-trial.md` FINDING C-1.*

### `cpus = "6-11"` in a guest config gave the clone Dom0's cores

**Symptom.** A clone configured onto what looks like six dedicated CPUs gets
three, all of them shared with Dom0.

**Cause.** Under `smt=0` Xen parks the odd siblings, so `6-11` resolves to
`{6,8,10}` — every one of them inside Dom0's `0,2,4,6,8,10` partition. The range
notation is evaluated against *online* pCPUs, and the online set is not
contiguous.

**Fix. Enumerate P-cores explicitly; ranges are safe only across `16-31`**,
where no sibling is parked. As of 2026-08-31 the partition is Dom0 on all eight
P-cores and guests on E-cores, and it is **generated** — `CLONE_PCPUS` and
`PLATFORM_PCPUS` in `automation/platform.env` are the source, and
`scripts/gen-xen-configs.py` writes them into `misc/*.cfg`. Editing a `cpus =`
line by hand is reverted on the next run.

**Verify the boot line separately.** `dom0_vcpus_pin` hands Dom0 the first N
*online* pCPUs, and nothing in this repository can enforce what
`/etc/default/grub.d/` says. Check with `xl vcpu-list 0` after any change — see
the floating-vCPU entry above.

### A headless box never came back after bridging its NIC

**Symptom.** `netplan apply` on the interface carrying your SSH session, and the
machine is gone.

**Cause.** Two, and the second is the quiet one:

- Bridging the NIC that carries your own session is the riskiest single step in
  the bare-metal build. There is no second path in.
- **With DHCP, the bridge takes a new MAC** unless `macaddress:` pins it to the
  NIC's. The lease changes and the box reconnects at an address nobody is
  watching.

**Fix.** Use **`netplan try`**, which reverts automatically after 120 s unless
confirmed — never `netplan apply` — and give the bridge a **static** address.
Dom0 is `192.168.1.6/24` static for exactly this reason.

**One thing to re-check afterwards:** `sandboxd` dials *out*, so Dom0's own
address appears in no config — but if the mTLS client certificate
`dom0-lab.crt` carries an IP SAN, it now names the wrong address.

### The Xen boot line changed without anyone editing it

**Symptom.** `dom0_mem`, `dom0_max_vcpus` or `smt` differ from what
`/etc/default/grub.d/` says.

**Cause.** `drakvuf-bundle` can rewrite the Xen command line on any
`update-grub`: its `xen.cfg` sources `drak-find-xen-defaults`, which computes
Dom0's resources. Only while the bundle is installed — removed, the same file
stops `update-grub` from writing anything, see
[`update-grub2` exits 0 and `grub.cfg` does not change](#update-grub2-exits-0-and-grubcfg-does-not-change).

**Fix.** Re-read the live boot line after **any** package operation that could
trigger `update-grub`, not just after editing grub config. `CURRENT-STATE.md`
§1.2 carries this as a standing WATCH.

### Dom0 stops responding while DRAKVUF runs with `--parallel-events`

**Symptom.** Dom0 hangs mid-trace: its vCPUs spin inside Xen and stop
handling interrupts, so SSH, the console and the trace all stop together. Seen
on a Linux HVM guest while a VNC client was connected to it.

**Cause.** A deadlock in Xen 4.20.1's altp2m code. A vm_event response that
switches a vCPU's altp2m view (`VM_EVENT_FLAG_ALTERNATE_P2M`, which DRAKVUF
sends constantly) waits for that vCPU to be descheduled while holding the
altp2m list lock. The vCPU needs the p2m lock to get off its pCPU, and a
log-dirty write fault on a third vCPU holds the p2m lock while it waits for the
altp2m list lock. QEMU tracking dirty VRAM for the VNC client is what produces
the log-dirty faults. Parallel event processing answers far more responses
while other vCPUs run, which is why it shows up there.

**Fix.** Xen with the fix, `automation/xen-altp2m-pause-vcpu.patch` —
installed on Dom0 2026-10-19, procedure `make xen`. The fix is
[posted to xen-devel](https://lists.xenproject.org/archives/html/xen-devel/2026-10/msg01125.html).

### The Windows guest bugchecks `0x1e` within a minute of tracing with all plugins

**Symptom.** `xl dmesg` shows

```
(XEN) d96v2 VIRIDIAN GUEST_CRASH: 0x1e 0xffffffffc0000005 0 0x8 0
```

— `KMODE_EXCEPTION_NOT_HANDLED`, an access violation in kernel mode — on the
Windows 11 23H2 sandbox, with every plugin loaded. DRAKVUF itself usually keeps
running and exits at its timeout; once, 6 s in, it hung instead until killed.

**Cause.** **Not diagnosed.** What is established, 2026-10-20: it happens with
upstream DRAKVUF (`52df0bc8`) on upstream's libvmi **and** on
`evilbootloader/libvmi`, and with the parallel-events build. None of the
recorded `-a syscalls` runs crashed, so another plugin's hook is the suspect —
and the guest also crashed in a run with everything but fileextractor, so not
that one.

**Fix.** None yet. Narrow it by leaving plugins out one at a time (`-x`), and
check `xl dmesg` for `GUEST_CRASH` after every Windows run: the trace log ends
normally and shows nothing.

### Admission holds forever — one line per second, no clone, no error

**Symptom.** 170 consecutive admission holds, zero clones for the large job,
smaller jobs completing meanwhile. Nothing in the logs explains it because
**every individual decision is correct**.

**Cause.** Admission is greedy, and greedy admission starves the largest clone.
A Windows clone costs **6294 MiB** (`memory = 6144` plus `DOMAIN_OVERHEAD_MIB`)
against Ubuntu's and Android's 2198 MiB.

**Fix.** Until DRAFT-041's head-of-line reservation lands, **run Windows alone**.
Measured on Dom0 2026-08-20.

### `vmi-process-list -h` and `--help` do not print help

**Symptom.**

```
$ vmi-process-list --help
VMI_ERROR: Could not find a live guest VM or file to use.
VMI_ERROR: Opening a live guest VM requires root access.
Failed to init LibVMI library.
```

**Cause.** There is no help flag. `-h`/`--help` are parsed as *domain arguments*
and the tool tries to open a VM named for them.

**Fix.** Run it **bare** — `vmi-process-list` with no arguments prints the usage
block. This matters beyond convenience: the error above names root access, so
the natural next move is `sudo`, which produces the same output and sends you
looking for a permissions problem that does not exist.

### `VMI_ERROR: No entry in config file for <domain>-N-clone`

**Symptom.** `vmi-process-list` works against a template and fails against a
clone.

**Cause.** Clone domains have **no `/etc/libvmi.conf` stanza** — they are created
per run with generated names. Only the tracked domains are configured.

**Fix.** Pass the profile explicitly with `-j <profile.json>`. This is the same
reason the pipeline passes `-r` to `drakvuf`/`injector` everywhere rather than
relying on `libvmi.conf`, and it is why `sandboxd/stages.py` carries a
per-`TargetOs` profile path (`StageConfig.profiles`).

### `VMI_ERROR: JSON at /root/linux.json couldn't be opened!`

**Symptom.** `vmi-process-list` fails on a domain that DRAKVUF traces fine.

**Cause.** `/etc/libvmi.conf` points at paths that do not exist here —
`/root/linux.json` and `/root/sandbox_project/…`, the **old repository path**.
DRAKVUF is unaffected because it is passed `-r …/profiles/linux.json`
explicitly; `vmi-process-list` resolves through the config file and is not.

**Fix.** Rewrite `/etc/libvmi.conf` against the real checkout. Note the filename
is `linux.json`, **not** `ubuntu.json` — `CURRENT-STATE.md` §1.4 records it as
never renamed in the `linux` → `ubuntu` pass.

### A trace completed, the sample clearly ran, and its first seconds are missing

**Symptom.** `trace.log` is full of plausible events, the artifact set is
complete, the job is `completed` — and the beginning is not there. No `execve`
of the staged sample. No `openat` of the files it must have read to get
started. Library calls that begin mid-sequence. On a sample that unpacks and
exits quickly, possibly nothing attributable to the sample at all, with no
error anywhere.

**Cause.** **DRAKVUF injects before it arms its plugins.** `main.cpp` runs
`inject_cmd()`, then `start_plugins()`, then `loop()`, and `inject_cmd` returns
as soon as the injected `execve` has returned in the child
(`libinjector/linux/methods/linux_execve.c`, STEP4). Everything the sample does
between those two moments happens with nothing hooked, and nothing reports it:
the trace is not truncated, it just starts late.

This is also why `libmon` adopts already-running processes at startup rather
than waiting for an `exec` — its README says so, and names the residue: "a
process that does its work and exits inside that window is missed".

**Fix.** The sample is launched through a shell that waits
`sandboxd/guests.py::LAUNCH_DELAY` seconds first, so arming finishes while it
sleeps — `/usr/bin/sleep` on Ubuntu, `/system/bin/sleep` on BlissOS,
`ping.exe -n 5 127.0.0.1 >nul` on Windows. See
`docs/architecture/analysis-pipeline.md`, "Sample execution: the launch delay".

If a trace still starts late with the delay in place, the delay is shorter than
arming on this host. **Measure it rather than guessing**: the sample's own
`execve` is now an event in the log (`do_execveat_common`, `FileName` = the
staged path), and the span from the run's first event to that one is what
arming actually cost. Raise `LAUNCH_DELAY`; do not patch a per-guest row.

Two things that are *not* this symptom. A trace with **no** sample events at
all and no `execve` is a failed launch, not a late one — check the anchor PID
entries below. And on the Android APK path there is deliberately no delay: the
traced process is `am`, and the sample is a later zygote fork.

### `injector` reported a JSON error and then kept going

**Symptom.**

```
VMI_ERROR: JSON at profiles/android.json couldn't be opened!
VMI_ERROR: Undefined OS type!
Injector starting /system/bin/sh through PID 1 TID: 0
Process startup failed
rc=1
```

**Cause.** The profile path was wrong (relative path, wrong working directory).
**The JSON error is not fatal** — `injector` prints it, continues, attempts the
injection, and fails later for what looks like a different reason.

**Fix.** Read the *first* error, not the last. Use absolute paths for `-r`.

### `injector` returns `STATUS:PrematureBreak` and `rc=124`

**Symptom.**

```
Injector starting /bin/true through PID 1490 TID: 0
[INJECT] TIME:… METHOD:ExecProc STATUS:PrematureBreak
Process startup failed
rc=124
```

**Cause.** `rc=124` is `timeout`'s exit code, not the injector's — the command
was wrapped in `timeout 30` and never returned. `PrematureBreak` means the
injection hit a breakpoint it did not expect, generally an anchor PID that is
not a valid vfork/execve source.

**Fix.** Check `INJECTION_PID` first. The anchor must exist **inside the memory
image**, must be unambiguous, and must belong to the user samples run as. See
the anchor entry below and `docs/runbooks/12-baremetal-trial.md` §D5.1.

`injector --help` documents `-I <injection thread>`, which the Linux path
describes as *"Injects to TGID Thread if ThreadID not specified"*.

### `systemctl stop sandboxd` — `Unit sandboxd.service not loaded`

**Symptom.** systemctl, `journalctl -u sandboxd`, `systemctl status sandboxd`
all report nothing.

**Cause.** **There is no systemd unit for `sandboxd`, anywhere in the repository.**
It runs in the foreground, started by hand.

**Fix.** `docs/CURRENT-STATE.md` §1.2 carries the exact invocation. **Source the
environment file first** — `python -m sandboxd.daemon` on its own exits
immediately, because `Settings.from_env` raises `SystemExit` when any required
variable is unset. That failure looks like a broken install and is not.

This exact mistake — assuming a unit existed — is one of the four wrong
assertions that caused `CURRENT-STATE.md` to be written.

### Admission holds repeat forever and resume after cleanup

**Symptom.**

```
[0] Holding: need 2198 MiB, 1211 available (free 10011, reserved elsewhere 0, host reserve 8800)
```

repeating once per second, continuing **after** a clone was successfully created
and again after cleanup.

**Cause.** Distinct from the Windows starvation entry above: here `free` is
10011 MiB but `available` is computed as 1211 against a `host reserve` of 8800.
The reserve is doing the constraining, not the clone.

**Fix.** Check `SANDBOXD_HOST_RESERVE_MIB` against what the host actually has
before concluding the pool is exhausted. Observed by the operator on the nested
host; **not re-measured since the migration**, where `total_memory` went
20479 → 32605 MiB and the same reserve is a much smaller fraction.

### A test domain on the bare bridge had no isolation at all

**Symptom.** A guest attached to `xenbr1` rather than `xenbr1.<n>` runs
normally, and **no isolation rule applies to it**.

**Cause.** The isolation rules match the `xenbr1.+` wildcard, which matches
`xenbr1.1`, `xenbr1.2` and so on and **deliberately does not match `xenbr1`
itself**. A throwaway config copied from `*_sandbox.cfg` inherits
`bridge=xenbr1` unless the VLAN suffix is added, so it lands on the bare bridge
— uncontained.

**Fix.** Give any test domain a VLAN sub-interface, or run it with no network.
**Nothing checks the attachment**, and nothing would report it — which is the
gap DRAFT-038 exists to close.

Harmless in the run that found it (a boot-and-anchor check, no sample), but
anyone repeating the procedure falls into it the same way.

### A clone got an address, and the sample "chose not to talk"

**Symptom.** An analysis completes, the clone booted and got an address, and the
pcap is empty. It reads as a sample that did nothing interesting.

**Cause.** The old shell launcher brought the bridge up and ran
`network-setup.sh` before launching the watcher. `sandboxd` replaced the
launcher but, for a time, **not** that call — #41 scoped it out on the
reasoning that "the launcher still does it", which stopped being true the
moment `sandboxd` ran instead. Nothing else creates `xenbr1.<n>`, the
`172.16.<n>.1` gateways, or the isolation chains.

**This is a false negative wearing the clothes of a result** — the worst failure
mode a sandbox has, because it produces a clean report.

**Fixed in `sandboxd`.** `daemon.py::provision_analysis_network` runs
`network-setup.sh` at every daemon start and refuses to start if it fails, so
this cannot recur through the normal path. It is kept here because **if a
previous `dirwatch` era left the interfaces in place it appears to work** — so
a host with stale interfaces and a `sandboxd` that somehow skipped the call
shows no symptom at all. Bring up `xenbr1` first; the script does not create
the OVS bridge.

**Related sizing trap:** `SANDBOXD_MAX_CLONES` and `network-setup.sh`'s argument
size the same thing from two sides — the VLAN pool and the `xenbr1.<n>`
sub-interfaces. Raise one without the other and a clone gets a VLAN with no
gateway, with the same symptom.

### `xl network-list` — `invalid domain identifier (rc=-6)`

**Symptom.** An `xl` subcommand rejects a domain that is running.

**Cause.** The domain's real name comes from `name =` **inside the `.cfg`**, not
from the filename or from whatever the procedure calls it. On 2026-08-12 the
config said `android_sandbox_test` while the runbook drove
`android_isolation_test`.

**Fix.** Keep the two in agreement, and check with `xl list` rather than
assuming. Harmless when a human notices; in an automated path it is a clone that
never gets checked and reports nothing.

### `lvremove` — `Logical volume ... in use`

**Symptom.** Removing a clone's LV fails immediately after `xl destroy`.

**Cause.** **`xl destroy` returns before the block device is released.** The
domain is gone; the device-mapper node is not yet.

**Fix.** Retry once. `sandboxd/clone.py` waits `DESTROY_SETTLE_SECONDS` (10,
measured on Dom0 2026-08-14) before its own `lvremove` for this reason — if the
retry is ever needed there, that wait is what regressed.

### `Invalid target name (too short)` after pasting a command from a script

**Symptom.** A line copied out of `network-setup.sh` produces
`iptables -I FORWARD 1 -j ""` and an error about the target name.

**Cause.** `$ISOLATION_CHAIN` is **internal to the script**. In an interactive
shell it expands to nothing.

**Fix.** Nothing on the host is wrong and **no rule was inserted** — the error
is a paste artifact. Run the script, or set the variable first. Quoted source in
a runbook is not a runnable command; this is why those blocks are marked.

### A `git pull` mid-run gave one sample two different script versions

**Symptom.** One analysis behaves as though its preconfig and its trace step
came from different commits — because they did.

**Cause.** **The C watcher spawned the worker scripts per sample, re-reading
them from disk each time.** A pull between the two handed that sample the old
`preconfig-` and the new `drakvuf-`.

**Applied to the deleted pipeline only.** Those scripts went on 2026-09-15.
`sandboxd` is one long-running process that imports its code once at startup,
so a mid-run pull cannot split a single analysis across two commits — it has no
effect until the daemon is restarted.

**Still don't pull mid-run.** A restart is how the new code takes effect, and
restarting with clones live is its own problem; `sandboxd`'s startup sweep is
what reconciles that, not the pull.

### Two watchers interfered with each other with no error message

**Symptom.** Clones colliding on VLANs, gateway addresses and isolation rules.
No symptom but the interference itself.

**Cause.** `dirwatch` derived each clone's VLAN from a **process-local**
worker-slot index, so two watchers allocated the same VLANs independently.

**Fix, and it is still live.** `sandboxd` allocates every VLAN from one
in-process table (`sandboxd/resources.py`), so two `sandboxd` instances cannot
arise — the single-instance lock refuses the second. And
`daemon.py::refuse_if_another_orchestrator_runs` still refuses to start when it
finds a running `dirwatch`: the source was deleted 2026-09-15, but it was a
compiled binary and one left installed on a Dom0 from before the migration
still allocates VLANs the old way. **Migration is a cutover, not
coexistence.**

---

# The platform, TLS and the tunnel

### `Empty reply from server` from a listener that is running

**Symptom.** `curl: (52) Empty reply from server` against a service that `ss`
shows listening, that `systemctl is-active` calls `active`, and whose log
records no error. Through `cloudflared` the same origin returns `502` — but
only to a caller Access has already authenticated, so an unauthenticated
`curl` at the public hostname shows `302` and looks healthy.

**Cause. The request used `http://` against a listener serving TLS.** uvicorn
started with `--ssl-certfile` reads the plaintext request line as a failed
handshake and closes the connection without replying. There is no error
because, from its side, nothing went wrong.

**Fix.** Match the scheme to the listener rather than guessing:

```bash
curl -sS --cacert /etc/sandbox-platform/tls/ca.crt https://127.0.0.1:8000/healthz
systemctl cat sandbox-api-browser | grep -- --ssl-      # is TLS configured at all?
```

`--cacert` rather than `-k`: it answers the scheme *and* proves the certificate
covers the address dialled, which `-k` deliberately does not.

**Where it bites.** `cloudflared`'s `service:` must carry the same scheme as the
origin. Moving the browser listener to loopback (`platform-domu.md` §E4a) is an
address change, not a scheme change — `service: https://127.0.0.1:8000`, with
`caPool` unchanged, because `tls/issue-cert.sh` puts `IP:127.0.0.1` in every
server certificate it issues.

*Found 2026-09-06, moving the browser listener to loopback for issue #40.*

### `openssl s_client` reported `Verify return code: 0 (ok)` against plain HTTP

**Symptom.** A TLS verification check passes against a service that is **not
serving TLS at all**.

**Cause.** `Verify return code: 0 (ok)` means *nothing was rejected*. An empty
certificate chain has nothing to reject, so it reports what looks like success.

**Fix.** **Do not use `openssl s_client … | grep 'Verify return'` for this.** The
absent `subject=` and `issuer=` lines are the real signal — grep for those, or
use a `curl` pair that proves https answers and http does not:

```bash
curl -sk -o /dev/null -w "https: %{http_code}\n" https://<host>:9000/minio/health/live
```

*Source: `docs/runbooks/08-deploy-platform-lxc.md` step 19.*

### MinIO started on plain HTTP with `--certs-dir` right there in the argv

**Symptom.** MinIO is launched with `--certs-dir`, starts cleanly, **logs no
reason**, and serves plain HTTP. Indistinguishable from the flag being ignored.

**Cause. The parent directory was not traversable.** `/etc/minio` was
`root:root`, so `minio-user` could not descend into `/etc/minio/certs` no matter
what the certificates' own ownership said.

**Fix.** Check the parent, not just the leaf:

```bash
ls -ld /etc/minio /etc/minio/certs
su -s /bin/sh minio-user -c 'ls -l /etc/minio/certs/'
# if that second command cannot list, MinIO cannot read them either
chown root:minio-user /etc/minio && chmod 750 /etc/minio
```

*Cost three rounds of debugging on 2026-08-23.*

### `mc`: `http: server gave HTTP response to HTTPS client`

**Symptom.** `mc alias set local https://…:9000` fails immediately.

**Cause.** MinIO is still serving plain HTTP on that port. The alias is correct;
the server is not on TLS yet.

**Fix.** Finish the TLS step first. If `mc` instead rejects the *certificate*,
that is a different problem — it does not trust the internal CA. `mc --insecure`
proves that is the only fault; then install `ca.crt` into `~/.mc/certs/CAs/`
rather than leaving `--insecure` in a command someone will copy.

### `curl: (56) OpenSSL SSL_read: … unexpected eof while reading`, exit 56

**Symptom.** `curl --cacert ca.crt https://<platform>:8443/healthz` fails with an
unexpected EOF rather than a TLS error.

**Cause.** Port 8443 is the **mTLS** listener. The server closed the connection
because the client presented no client certificate. The error names EOF, not
authentication, so it reads like a network fault.

**Fix.** Pass `--cert` and `--key` as well. Port 8000 is the browser listener and
takes no client certificate — check which port you are on before debugging TLS.

**The same trap in `httpx`, and it is worth knowing the mechanism.** Under
TLS 1.3 the server completes the handshake **before** validating the client
certificate, so a *rejected* certificate looks like the connection simply
ending. An unexplained EOF from a TLS client is a rejected client certificate
until proven otherwise, not a network fault.

### `cloudflared tunnel ingress validate` says OK, and the site returns a Cloudflare error page

**Symptom.**

```
Validating rules from /etc/cloudflared/config.yml
OK
```

followed by `<title>Cloudflare Tunnel error | … | Cloudflare</title>` from
`curl`.

**Cause.** `validate` checks the **syntax and rule structure** of the config
file. It does not check that the tunnel is connected, that the origin is up, or
that the origin's certificate is acceptable.

**Fix.** Treat `validate` as a linter. Prove the path end to end with `curl`
against the public hostname, and check the tunnel's connection count.

### `{"detail":"invalid access token"}` after Cloudflare Access is configured

**Symptom.** Access lets the request through, and the API rejects the JWT.

**Cause.** The API validates the Access JWT itself against
`ACCESS_TEAM_DOMAIN` and `ACCESS_AUD`. A mismatch in either — or a token minted
for a different application — fails here rather than at the edge.

**Fix.** `systemctl show sandbox-api-browser -p Environment --no-pager` and
compare `ACCESS_AUD` against the application's audience tag.

### A 403 from the artifact path is the PASS, not a failure

**Symptom.** `curl` against `/analysis` with a valid Access token returns 403.

**Cause.** Access let the request through and **MinIO** refused it unsigned.
That is exactly right.

**Fix.** Nothing. The failure to look for is a **302** there, which means the
path rule is not matching and the request reached the API instead.

### `systemctl enable` succeeded and the service never listened

**Symptom.** A unit derived from another by `sed` enables without complaint;
only the original port is listening.

**Cause.** `enable` only creates a symlink, so it succeeds against a unit
systemd cannot start. The `sed` had deleted `--ssl-cert-reqs 2`, which is the
**last** line of a line-continued `ExecStart` — the only one without a trailing
`\`. Removing it left the previous line ending in a backslash with nothing
after it, and systemd rejected the unit.

**Fix. Do not derive one unit from another by text substitution** — the result
depends on line breaks in the original. Write the second unit out in full.
`systemd-analyze verify <unit>` catches this; `enable` never will.

### A drop-in was configured correctly and had no effect

**Symptom.** `systemctl daemon-reload` after adding a drop-in, and the check
still behaves as before — with everything looking correctly configured.

**Cause.** **A drop-in reaches a running process only on restart.**
`daemon-reload` re-reads unit files; it does not re-exec anything.

**Fix.** `systemctl restart`, then confirm with
`systemctl show <unit> -p Environment --no-pager` — and check it did *not* also
land on the neighbouring unit. *Cost a round on 2026-08-24.*

### Restarting one API service left the other running old code

**Symptom.** A Python change appears to have no effect for Dom0 while working in
the browser, or the reverse.

**Cause.** `sandbox-api` (mTLS, used by Dom0) and `sandbox-api-browser` (behind
the tunnel) are **separate processes of the same application**.

**Fix.** Restart both. **Python changes need a restart; Jinja templates do not** —
they reload on their own, so a template-only change that appears not to apply is
a different problem.

### `DATABASE_URL is not set` when running a migration by hand

**Symptom.** The migration runner refuses; the same service starts fine under
systemd.

**Cause.** **`su - platform` is a login shell** and inherits none of the
environment the systemd unit supplies.

**Fix.** Source the unit's environment file explicitly, or use
`systemctl show <unit> -p Environment` to see what it actually gets.

**The dangerous part is what still succeeds.** The `git pull` and the restart
both work, so **the API comes up running code against a schema that has not been
migrated** — `GET /api/v1/jobs/<id>` and the job page then 500, because
`_detail` selects `*` and reads a column that does not exist. A refused
migration is not a stopped deployment.

### `Client sent an HTTP request to an HTTPS server` against the API

**Symptom.** A health check fails with a scheme error, suggesting the API is
misconfigured or down.

**Cause.** The check was pointed at **port 9000, which is MinIO**, not the API —
and MinIO is TLS here. So the error was about the wrong service *and* the wrong
scheme.

**Fix.** 8443 is the mTLS listener (`--ssl-cert-reqs 2`), 8000 is the browser
listener, 9000/9001 are MinIO. Pointing `sandboxd` at 9000 produces a TLS error
that reads like a certificate problem rather than a wrong port.

**What it is not:** evidence the API is down.

### SQL quoting was eaten by an extra shell

**Symptom.** SQL sent through `pct exec` / `su` arrives mangled, and the error
is about something other than what you were testing.

**Cause.** `su - platform -s /bin/bash -c "..."` puts **an extra shell in the
middle** that consumes a level of quoting.

**Fix.** Use `runuser -u platform --`. `pct exec` passes argv, `runuser` passes
argv, and psql receives the SQL as one argument — **no shell ever parses it**.
For the same reason prefer an `information_schema` query over `\d`, whose
backslash has to survive every layer.

### `psql` reported `column "linux" does not exist`

**Symptom.** An `INSERT` intended to test an enum constraint fails with a
completely different error, hiding the result you were testing for.

**Cause.** **Double quotes are identifiers in SQL, not strings.** The shell
quoting was rewritten to escape `"` and the SQL string literals became column
references.

**Fix.** Single quotes inside SQL, and a heredoc rather than `-c` when the shell
quoting gets deep. The expected error was
`invalid input value for enum target_os: "linux"` — which is what the test was
proving.

### Migrations silently re-applied on every run

**Symptom.** The migration runner reports success each time and re-applies
everything it has already applied.

**Cause.** The database was created under the cluster's default **`SQL_ASCII`**
encoding. The container has no UTF-8 locale, so `initdb` defaulted to
`SQL_ASCII` and every database inherited it.

**Fix, and the order is the substance of it.** Encoding must be fixed *before*
any database exists — **a database cannot be re-encoded in place**, and
`template1` on such a cluster is `SQL_ASCII` too:

```bash
su - postgres -c "createdb -O platform -E UTF8 -T template0 sandbox_platform"
```

`-T template0` is required precisely because `template1` lacks the encoding.
Confirm before continuing:

```bash
psql -d postgres -tAc \
  "SELECT pg_encoding_to_char(encoding) FROM pg_database WHERE datname='sandbox_platform'"
# expect: UTF8   -- NOT SQL_ASCII
```

Recovering from this needed a rollback to a container snapshot, not a repair.

### `pip install 'websockets==16.1.1'` — `from versions: none`

**Symptom.**

```
ERROR: Could not find a version that satisfies the requirement websockets==16.1.1
(from versions: none)
```

**Cause.** `from versions: none` means the index returned **no versions at all**,
not that this version is missing — an index or network problem, not a pin
problem. Do not "fix" it by loosening the pin.

**Fix.** `httpx` resolved in the same command, so the index was reachable;
re-run and check the pin against what that Python actually supports.
`sandboxd`'s dependencies belong in a requirements file rather than a
hand-typed pip line copied out of a runbook.

### `proxmox-backup-client restore` — `File exists (os error 17)`

**Symptom.** Creating the target LV and then naming it as the restore target
fails with `EEXIST`.

**Cause.** `restore` **creates** its target file and refuses if the path already
exists. It is create-exclusive — not a permissions or device-type problem, which
is what the error looks like. Pre-creating the LV guarantees the failure, and
deleting it to satisfy the tool leaves nothing to restore *into*.

**Fix.** Use `-` as the target and stream onto the device. That also avoids
needing 64 G of scratch for an intermediate file.

### A backup step that backed up nothing

**Symptom.** A `pg_dump` runs, a container backup runs, and neither contains the
dump.

**Cause.** The dump was redirected to **`/tmp` on the host**, while the backup
captured the *container*. A container backup never sees the host's filesystem —
and `/tmp` is cleared on reboot besides.

**Fix.** Write the dump somewhere the backup actually collects, and verify by
listing the backup's contents rather than by observing that both commands
succeeded.

**The compounding failure is the one to learn from:** this was survivable only
while an earlier part was mandatory. When that part was made *optional* on space
grounds, this step was not revisited — leaving Postgres and MinIO with no backup
at all. **Changing a step from required to optional changes what every later
step assumes.**

### `git pull --ff-only` refused on the deployment

**Symptom.**
`error: Your local changes to the following files would be overwritten by merge`,
naming files nobody edited deliberately.

**Cause.** The deployment checkout accumulated local modifications. Separately,
`git push` from there fails with *"The key you are authenticating with has been
marked as read only"* — the deploy key is intentionally read-only.

**Fix.** The deployment is a **consumer** of the repository, not a place to
commit from. Inspect and discard local changes there rather than merging around
them.

### `sandboxd` stopped claiming after the mTLS listener was disabled

**Symptom.** Every queued job stays `queued`. The platform is healthy, the UI
answers, `sandbox-api-browser` is active — and no analysis host picks anything
up. On Dom0, `sandboxd` logs a connection error against `192.168.1.10:8443`
rather than a refusal, so it does not look like an authentication problem.

Worse, there may be nothing to read: `sandboxd` runs in the **foreground** with
no unit, so `journalctl -t sandboxd` is empty and the error is in a terminal
somebody may have closed.

**Cause.** `SANDBOXD_API` pointed at `https://192.168.1.10:8443`, the mTLS
worker listener, because that is what runbook 09 set when 8443 was the worker
channel. Retiring that listener (`systemctl disable --now sandbox-api`) removes
the endpoint the worker was configured to dial. Nothing on the platform side is
wrong; the worker is calling a port that no longer answers.

**Fix.** Repoint the worker **before** disabling the unit, not after, in
`/etc/sandboxd/sandboxd.env` on each analysis host:

```sh
SANDBOXD_API=https://192.168.1.10:8000
```

then stop and re-run `sandboxd` — a `git pull` alone changes nothing, because
it holds its modules in memory. `SANDBOXD_CACERT` stays: 8000 is HTTPS too and
its certificate still has to be verified. `SANDBOXD_CLIENT_CERT` and
`SANDBOXD_CLIENT_KEY` become inert rather than wrong — the browser listener
does not request a client certificate, and `Settings.from_env` only builds one
into the SSL context when both are set.

Hit on 2026-09-15 during
[runbook 17](runbooks/17-deploy-own-identity.md#11-retire-the-mtls-listener),
whose step 11 now repoints the worker first and whose prose used to assert the
opposite — that `sandboxd` reached `:8000` already and was unaffected.

---

# Guest execution and samples

### `can't execute: Permission denied` for a file staged in Android external storage

**Symptom.** `injector -m writefile` succeeds, the file is present, `chmod 755`
appears to work — and `execve` is refused.

**Cause.** Two things, neither of them SELinux:

- `/storage/emulated` is mounted **`noexec`** — a VFS mount option enforced
  before any LSM hook.
- FUSE **synthesizes** the mode, so `chmod` does not stick: `chmod 755` left the
  file `-rw-rw---- root everybody`.

**Fix.** `GUEST_STAGING_DIR=/data/local/tmp` for Android, no subdirectory —
it already exists in the saved image, which the contract requires because
`injector -m writefile` does not create parent directories.

**Do not reach for permissive mode.** Neither cause is reachable by policy, no
`avc` denial is produced, and a permissive guest makes observed malware
behaviour unrepresentative.

**The tell that it worked:** `toybox: Unknown command /data/local/tmp/probe` is
a **successful execution** — toybox's own applet dispatch failing on an
unrecognised `argv[0]`. `execve` failures are reported by the shell instead.

*Source: `docs/checklists/android.md`, "Staging directory".*

### `injector`'s `FILE:` field is the Dom0 path, not the guest destination

**Symptom.** Verifying that a sample landed at `$GUEST_STAGING_DIR/<name>` by
grepping the `[INJECT]` line, and reading
`FILE:"/malware_processing/ubuntu/benign sample.sh"` — the **processing** path.

**Cause.** `injector` writes the **Dom0-side** path into `FILE:`. A
`grep -i writefile` therefore confirms nothing about the guest destination.

**Fix.** The guest destination appears only in `injector`'s own startup line:

```bash
grep -n 'Injector starting' "$LOG"
sed -n 's/^Injector starting \(.*\) through PID .*/[\1]/p' "$LOG"
```

The brackets are deliberate — they make leading and trailing whitespace visible.

**The follow-up grep was worse than ineffective**, and the shape generalises:
`grep -o '/home/carlos/Desktop/[^ "]*'` stops at the first space, so on a sample
named `benign sample.sh` it prints `/home/carlos/Desktop/benign` and **truncates
away the exact property the check exists to test**. Its output was never pasted,
so nothing caught it. A character class excluding space cannot verify a path
that may contain one.

### A sample filename reached the guest as shell metacharacters

**Symptom.** Quote, `$`, backtick or `;` in a submitted filename affecting guest
command construction.

**Cause.** `sample_name_admissible()` rejects only `/` and control characters.
Everything else reaches the guest.

**Fix.** Use the `sh -c '…' sh "$UNSAFE"` idiom so the value arrives as a
separate `execve` element. Sample-derived text may live in guest shell
*variables* and be used quoted; it may **not** reach the guest as text Dom0
pasted into a command. See `sandboxd/guests.py:449`.

### `monkey` aborted with exit 134

**Symptom.**

```
--- monkey ---
Aborted
monkey_rc=134
```

**Cause.** `app_process64` aborting before `main()` for want of the classpath
import. The Android preconfig script carried that import; the Android trace
script omitted it.

**Fix — and it is not "add the import".** With the import added `monkey` does
work, but the `am` wrapper works with **no import at all**, and `monkey` is
rejected on separate grounds: `ActivityManager.isUserAMonkey()` reports its
presence **to the sample**. Use `am`, never `monkey`. It was the wrong mechanism
twice over.

### An APK install "succeeded" in the pipeline and installed nothing

**Symptom.** `pm` and `cmd` threads visibly busy, and **zero** `/data/app/`
writes, no `dex2oat`, no package name anywhere in the trace. A checklist line
recorded "which of the four steps failed: none".

**Cause.** The guest collapsed under introspection overhead. The trace showed
Android declaring its own system apps unresponsive (`AnrMainProcessD`,
`AnrAuxiliaryTas`, an ANR temp file in `dump/`) and `CachedAppOptimi` freezing
app cgroups, against 43,116 syscall events from `system_server` alone in 120 s.

**Fix.** The install path was never at fault: the same APK, same `pm install`
line, on an **untraced** clone succeeded in **3 seconds** and resolved
`org.fdroid.fdroid`. That is a lower bound of **40× overhead** — and a true
lower bound, since the traced install was never observed to finish at all.

**The generalisable lesson:** when an in-guest operation does not complete under
tracing, re-run it untraced before debugging the operation. Also beware that
"package name resolved: `F-Droid.apk`" records a *filename*, not a package name.

### DRAKVUF printed its banner and hung — no syscall breakpoints, no hooks

**Symptom.** DRAKVUF starts, prints its version banner, and then nothing: no
`[SYSCALLS] Syscall table breakpoints set`, no plugin hooks, still running seven
minutes into a 120-second trace.

**Cause. The injection anchor was not schedulable.** `injector` has to catch the
target process **on a vCPU** — it waits for the PID to be scheduled so it can
hijack the register context and vfork/execve from it. A terminal editor sitting
at its prompt is blocked in `read()` on the tty, parked on a wait queue and
never scheduled, so `injector` waits forever and DRAKVUF never gets past
injection. Backgrounding does not help: `nano &` is stopped by `SIGTTIN` the
moment it touches the tty, which is equally unschedulable.

**Fix, and it is currently different per OS:**

| OS | Anchor | State |
|---|---|---|
| **Ubuntu** | **systemd, `INJECTION_PID=1`** | working well — keep it |
| **Android** | **a backgrounded `ping`** (`INJECTION_PID=3251`) | moved back off PID 1 |

**Android could not stay on PID 1.** Android's init does not provide a runtime
environment for `app_process64`, so the APK path had to build one — and the
anchor moved back to a backgrounded `ping` against **127.0.0.1**, chosen so
anchor traffic stays out of the per-sample pcap. `ping` is
self-scheduling and single-threaded, which is what the constraint below asks
for.

That reintroduces the two costs PID 1 had removed for Android: the PID must be
**re-derived after every template re-save**, and it is a process a sample can
see in `ps`.

> **Resolved by deletion, 2026-09-15.** The stale comment block lived in
> `automation/pipeline-android.env`, which set `3251` while the text above it
> still argued for PID 1 and claimed "Both OS families now anchor on their
> init". That file is gone. The value now lives in
> `StageConfig.injection_pids` (`sandboxd/stages.py`) with no contradicting
> text beside it — but the underlying rule is unchanged: **do not put Android
> back on PID 1.**

**Two anchors failed before this, from opposite directions, and the second is
the non-obvious one:**

| Anchor | Why it failed |
|---|---|
| `nano` (Android, 2026-08-17; Ubuntu, 2026-08-28) | blocked in `read()` on the tty, and saved **STOPPED** after taking `SIGTTIN`. Never scheduled |
| `gedit` (Ubuntu, 2026-08-29) | a GUI event loop **is** schedulable — but only once input arrives, and a restored clone has no keyboard or mouse. It injected only after a click in `vncviewer` |

systemd's `sd-event` loop is woken by timers with **no input at all**, which is
what makes it work where a GUI does not.

**Requirements for any anchor:**

| Requirement | Why |
|---|---|
| **Schedulable without input** | `injector` cannot hijack a process that never runs, and a clone supplies no keyboard or mouse |
| **Single-threaded** | `injector` targets the TGID thread unless `-I` names one; a multi-threaded process makes the target ambiguous |
| **Negligible CPU** | rules out `yes > /dev/null` and other spin loops |
| **Unique process name** | Android has **two** processes named `init` — PID 1 and one before `ueventd` whose PID moves every boot. Never auto-discover by name |
| **Stable across a template rebuild**, or re-derived every time | PID 1 is PID 1 in every image. Any other anchor must be re-read after each `xl save` |

**The failure is silent and unbounded.** `injector` has no timeout and prints
nothing while it waits, and the old watcher's uncounted retry turned that into
an endless clone/hang/kill loop. `sandboxd` bounds it — every phase has a
wall-clock budget (`sandboxd/timing.py`) and a job that overruns is torn down
and reported rather than retried forever — but the injection itself is still
silent. **A `vmi-process-list` match proves the task exists; it does not prove
it ever runs.**

### A stale `INJECTION_PID` after a template re-save

**Symptom.** `STATUS:PrematureBreak` and a timeout, against a template that
worked yesterday.

**Cause.** The anchor PID is valid **only for the `.bak` it came from**, and
`injector` attaches to whatever PID it is handed with no warning. Android's has
been 3163, 3164, 3174 and now 3251; Ubuntu's went 1415 → 1490 before moving to
PID 1. Injecting into 1309 — a PID from a previous boot — gave exactly this
signature on 2026-08-29.

**Fix.** Re-read the anchor PID after every re-save and write it back to
`StageConfig.injection_pids` in `sandboxd/stages.py` (was `INJECTION_PID` in
`pipeline-<os>.env` until 2026-09-15). **Ubuntu no longer needs this** because
PID 1 is stable in every image; **Android does**, having moved back to a `ping`
anchor.

**The template checksum goes stale with it.** After a rebuild, a `sha256`
mismatch against a previously recorded baseline is the **expected** result, not
evidence of corruption — `1844fc0a…` belongs to the pre-EthernetConfig Android
template. Record the new value as the baseline and update it wherever it is
quoted, rather than treating the mismatch as a fault.

### `injector readfile` fails with `syscall return code: -2`, but sometimes works

**Symptom.** An Android APK analysis fails in preconfig:

```
Failed at injector readfile -- injector readfile exited 1
  argv: ('injector', ..., '-m', 'readfile',
         '-B', '.../launch-component', '-e', '/data/local/tmp/.pm.tmp')
  syscall return code: -2
  Could not open file in guest
```

Resubmitting the same sample usually works. Observed 2026-09-04.

**It is rare** — not reproduced in 11 consecutive runs (operator, 2026-09-04).
Which also means a clean run does not demonstrate a fix: only a run that would
otherwise have failed does, and those cannot be arranged on demand.

**Check the injection PID in the argv before assuming this entry applies.**
Android's is `3251`. A paste showing **`-i 1`** is from a build between
2026-08-29 (`77909eb`) and 2026-08-31 (`921c04c`), when the anchor was briefly
PID 1 — a different failure, on an abandoned configuration, and not this one.
Two errors from the same pipeline can come from different builds, and the
anchor PID is what tells them apart.

**The injection is NOT the problem, and reading it as one wastes a day.**
`injector` attached to the anchor, ran in the guest, executed the syscall and
got a result back. `-2` is `-ENOENT`. The anchor PID is right, the anchor was
scheduled, and there is no VMI fault here: the handoff file simply was not
there yet.

**Cause. `execproc` returns when the guest shell STARTS, and a fixed sleep is
the only synchronisation Dom0 has** (`sandboxd/stages.py`, the APK branch of
`_preconfig`). The sequence is: install via `execproc`, sleep
`waits.apk_install`, then `readfile` the handoff.

The handoff is created by shell redirection on the install line
(`guests.argv_install_apk`), so it appears the instant that line begins. But the
line before it is `B=$(pm list packages)`, which talks to the package service
over binder — and on a freshly restored clone that service is not necessarily
up. Warm, it returns at once; cold, it blocks. **ENOENT therefore means the
guest shell had not reached the install line before the sleep expired.**

That is why it is intermittent and why a resubmit clears it.

**The wait was sized against the wrong variable.** `timing.py` records
`APK_INSTALL_WAIT` as *"3 seconds MEASURED for a 12 MB APK on 2026-08-17"* —
one measurement, on the nested host that no longer exists, timing the
**install**. It never covered the package service's post-restore cold start,
which is the part that varies.

**Fix.** Poll for the component instead of sleeping a guess — and poll for
**content that parses as a launchable component, not for the file existing.**

The handoff is written **twice**: `pm install` redirects its own output there
first (deliberately, so a failed install explains itself), and
`resolve-activity` overwrites it on success. An existence-poll therefore
succeeds on the install diagnostic and hands it on as if it were a component,
which `component_is_launchable()` rejects as "no usable launcher component" —
blaming the sample for a Dom0-side timing fault. That is the same misdiagnosis
the 2026-08-29 redirect fix existed to remove, arriving by a new route.

On deadline, read whatever the handoff holds and report *that*: it is the
install diagnostic, and it is the most useful thing available.

**Do not "fix" this by re-deriving the anchor PID, reverting the anchor to
PID 1, or raising the sleep.** The first two are answers to a different
failure — the injection worked. The third moves the threshold without removing
it, and the guest gets slower when two clones share the E-cores.

### `getent` is not available in the Android guest

**Symptom.** Ubuntu's DNS verification command has no equivalent on BlissOS.

**Cause.** bionic ships no `getent`.

**Fix.** `ping <name>`, which is the **stronger** test anyway: it resolves
through bionic → `netd`, the same path an application takes, and proves
resolution *and* reachability where `getent hosts` proved only the former.

**The cost, accepted 2026-08-29:** `execproc` inherits the anchor's credentials,
so **Ubuntu samples now execute as root** and privilege-escalation behaviour is
no longer observable. To get unprivileged samples back, drop privilege at exec
in the Ubuntu trace argv (`setpriv --reuid=<guest user>`, now
`sandboxd/guests.py`) and leave preconfig as root. Android pays nothing here —
its anchor was already root.

*Sources: the anchor blocks in `automation/pipeline-ubuntu.env` and
`automation/pipeline-android.env`, both deleted 2026-09-15. The surviving
record is `sandboxd/guests.py` and this entry.*

### The injection anchor was the wrong process, and nothing warned

**Symptom.** Injection targets a process that is not the intended anchor.

**Cause.** `INJECTION_PID` is a **number captured at save time**, and the anchor
is a backgrounded `nano` — chosen so the string `drakvuf` appears nowhere in the
guest, which is an anti-evasion decision. It exists only inside the memory
image; nothing recreates it on boot.

**Fix.** Three properties, each of which has bitten this project: it must exist
in the saved image, it must be **unambiguous**, and its user must be the user
samples run as (the Ubuntu preconfig injection builds its network-configuration
command with `sudo`).

**Do not build anchor auto-discovery on a process-name grep.** A guest that
happens to run a second `nano` gets the wrong process injected, and `injector`
does not warn.

### An empty `FORWARD` chain read as proof a rule was rejected

**Symptom.** No DROP rules present, taken as evidence that an isolation rule had
been refused by the kernel.

**Cause. `iptables` rules are runtime state and nothing in this project
persists them.** `POSTROUTING` was empty too — and `MASQUERADE` is valid syntax
that would have installed without complaint. The empty chains meant only that
`network-setup.sh` had not run since the host last booted.

**Fix.** Before reading absence as rejection, check whether the provisioning
script has run at all since boot. Absence of a rule is not evidence about the
rule; it is usually evidence about the script.

### `ip link delete` did not remove `xenbr1`, and the test passed anyway

**Symptom.** A teardown step reports success; the bridge is still there.

**Cause.** **`xenbr1` is an OVS bridge**, so `ip link delete` cannot remove it —
and the step ended in `2>/dev/null || true`, which swallowed the failure.

**Why this one matters more than it looks.** The step existed to prove
`network-setup.sh` *fails safely with no bridge*. With the bridge still present
the script exited 0, and **a pass was recorded for a test that never ran** — a
false pass on precisely the check meant to catch unsafe behaviour.

**Fix.** `ovs-vsctl del-br xenbr1`. And do not terminate a teardown step with
`|| true` when the *next* step's meaning depends on the teardown having
happened.

### `iptables-save | wc -l` is a weaker idempotency test than it looks

**Symptom.** A rule count that is stable across three runs, read as proof the
script is idempotent.

**Cause.** A count **detects growth but not substitution** — a run that replaced
one rule with a different one scores identically. And a single recorded number
cannot show whether all three runs agreed.

**Fix.** `diff` the full `iptables-save` output between runs and record all
three.

### A job fails with `sample digest does not match the one admitted`

**Symptom.** The run ends `failed` before any clone is built. The daemon log
carries the expected and actual SHA-256.

**Cause.** The object in the store is not the one admission hashed. Since
2026-08-31 `sandboxd` verifies the digest the lease carries against the bytes
it actually downloads, and refuses rather than detonating something the report
would then misdescribe.

Two ways to get here, and they are not equally innocent:

- **Benign.** MinIO's retention rule expired the object and a different one now
  occupies the key, or an operator overwrote it by hand.
- **Not benign.** The presigned POST issued at submission stays valid for
  `upload_ttl` (900s) and the store permits overwriting, so a submitter can
  replace the sample *after* admission recorded its hash. That is the case this
  check exists for: without it, the trace, the verdict and the SHA-256 all
  describe a file that never ran.

The platform's own claim-time check compares the store's ETag, which for a
single-part upload is an MD5 — it makes the ordinary swap loud, but MD5
collisions are constructible, so it is not the guarantee. The SHA-256 check on
Dom0 is.

**Fix.** Do not retry blindly. Look at whether the job's `created_at` is inside
`upload_ttl` of the failure: if it is, treat it as a deliberate substitution and
keep the row as evidence. Re-submitting produces a fresh job id and a fresh
upload ticket, which is the correct response to the benign cases.

**Do not "fix" it by skipping the check.** A lease that carries no `sha256` is
also refused, deliberately: admission writes that column in the same UPDATE
that moves a job to `admitted`, so a claimable job without one is an impossible
state, and running it would mean detonating bytes nothing can identify
afterwards.

### A job fails with `unusable lease`

**Symptom.** `sandboxd` refuses a claim with `unusable lease: sample name
contains a path separator` (or `job_id is not a UUID`), and does not run it.

**Cause.** The platform sent a `submitted_filename` or `job_id` that cannot be
a single path component. Both become directory and file names under root on
Dom0 — `staging/<job_id>/<filename>` is opened for writing and its parent is
handed to `shutil.rmtree` — and `pathlib` offers no protection: an absolute
name replaces the join outright, and a relative one is not normalised.

The platform validates this at submission and its check is tight, so in
practice this means the two sides disagree about what a lease may say. Treat it
as a platform bug or, if the platform is not the one you deployed, as an
attempt to write outside the staging tree.

**Fix.** Look at the job row on the platform. Note that shell metacharacters in
a filename — `$`, backtick, `"`, `;` — are **admissible and must stay that
way**: a sample really can be called `a$(id).exe` and byte-exact delivery of
that name is part of what is analysed. What makes them safe is the
`sh -c '…' sh "$UNSAFE"` idiom in `guests.py`, not a name filter. Only path
separators, `.`/`..` and control characters are refused.

### The host runs fewer clones than it has VLANs, and capacity keeps dropping

**Symptom.** `capacity: N vlan(s) usable` falls over a daemon's lifetime.
Restarting `sandboxd` restores it, and it falls again.

**Cause.** Working as intended, and the log says which VLAN and why:

```text
vlan 3 withheld after job <id>: cleanup was 'dirty: destroy'
```

Since 2026-08-31 a teardown that did not finish keeps its VLAN out of the pool
instead of handing it to the next sample. Before that, `cleanup_status` was
recorded on the job row, logged, and ignored — a domain that survived
`xl destroy`, an LV that would not release, or egress rules that outlived
their revoke all had their VLAN recycled immediately. `ResourceTable.withhold`
existed for this and had no caller.

**Fix.** Do not raise `SANDBOXD_MAX_CLONES` to compensate — that hands out
more VLANs without fixing the ones stuck. Find the withheld VLAN in the log
and deal with what survived on it:

```sh
xl list | grep -- -3-clone          # a domain that outlived xl destroy
lvs | grep -- -3-clone              # a snapshot LV that would not release
iptables -S DRAKVUF_EGRESS_V3       # egress rules that outlived their revoke
```

A restart is the supported recovery: the startup sweep destroys whatever
survived and re-admits the VLAN. If capacity falls again immediately
afterwards, the teardown is failing repeatably and the log line names the
stage — treat that as the real fault rather than restarting on a schedule.

`dirty: egress` specifically means `iptables -S` still answered for one of
that VLAN's chains after the revoke ran. Note that an emptied but undeleted
chain is harmless and still counts as dirty; that is deliberate, and the
sweep reclaims it.

### A job reported `offline` and the capture shows it reached the Internet

**Symptom.** A report whose Network section reads `offline`, beside a pcap full
of real outbound traffic. `iptables -S DRAKVUF_EGRESS_V<n>` shows no chain for
that VLAN, which looks like confirmation that nothing was installed — and
nothing was.

**Cause.** A **wildcard rule left by an earlier `direct` run**, not a per-job
rule at all. `network-setup.sh <n> direct` writes
`-i xenbr1.+ -o xenbr0 -j ACCEPT` into `DRAKVUF_EGRESS` and a matching
`MASQUERADE` into `DRAKVUF_EGRESS_NAT`. Both name no VLAN, so every delete in
`sandboxd/egress.py::argv_revoke` — all of which name one — missed them, and
nothing removed them. The grant lasted for the host's uptime and applied to
every later job. `offline` was the worst-affected mode, not the safest: it
installs nothing, so it has nothing that could collide with a leftover, and
`argv_apply` returning `[]` means no `iptables -N` fails to warn you.

Fixed 2026-08-31. Look for it on any host that ran `ALLOW_DIRECT=1` before
that date without rebooting since.

**Fix.** `iptables -S DRAKVUF_EGRESS` and read the whole chain, not the
per-VLAN sub-chain. Anything there that does not end in `-j
DRAKVUF_EGRESS_V<n>` applies to every clone. `network-setup.sh` now prints
exactly those lines as a warning on an `offline` run, deletes the legacy pair
by exact spec on that same branch, and `sweep._revoke_egress` deletes it again
at daemon start. Note that a reboot also clears it — there is no
`iptables-persistent` here — so a host that has been restarted since the
`direct` run will look clean and was not.

**Do not fix it with `iptables -F DRAKVUF_EGRESS`.** That takes the per-VLAN
jumps with it and cuts the network of every clone currently under analysis,
mid-trace. Delete the one spec.

### FakeNet-NG started, logged its configuration, and bound nothing

**Symptom.** `fakenet -c /etc/fakenet.ini` prints its banner and
`Loaded configuration file: /etc/fakenet.ini`, then nothing. The process stays
up. `ss -ltnp | grep 38926` is empty, `ss -lunp` shows only `systemd-resolved`
on 53. No error, no traceback, exit code still 0 — every check that looks for
the process finds it running.

**Cause.** **The config file had no listener sections.** `Fakenet.parse_config()`
reads only the file passed to `-c`; `fakenet/configs/default.ini` is what it
falls back to when `-c` is *absent*, never something it merges in. Every
section other than `[FakeNet]` and `[Diverter]` is a listener, so a file
carrying only those two produces an empty listener table, and `start()`
iterates it zero times and returns.

Our `automation/fakenet.ini` was written from upstream's `default.ini` on the
belief that unset listeners stay at their defaults, and its header said so.
There is no such thing once `-c` is passed.

**Fix.** The listener sections are in `automation/fakenet.ini` and are not
optional; `sandboxd/tests/test_egress.py::test_fakenet_ini_starts_at_least_one_listener`
fails if they go missing again. Confirm at runtime rather than by reading the
file — `ss -ltnp | grep -E '38926|:80'` and `ss -lunp | grep -E '38926|:53'`
must both return listeners before a `simulated` job is submitted. sandboxd's
own launch probe checks 38926 only, so a missing DNS section would still pass
it.

### The simulated responder is listening, and answers nothing

**Symptom.** FakeNet is up and `ss` shows every port bound, but a clone in
`simulated` gets no reply to anything. `getent hosts` fails, `curl` connects
and closes with an empty response. FakeNet's own log shows either
`Error: 'NoneType' object has no attribute 'isProcessBlackListed'` or a bare
traceback ending in `getOriginalDestPort`, depending on which listener was
hit. Nothing in the report says the responder was broken — it reads as a
sample whose infrastructure was down.

**Cause.** **`DivertTraffic: No` is a path FakeNet-NG v3.5 does not run.** With
it set, `Fakenet.start()` leaves `self.diverter` at `None` and three call sites
dereference it unguarded: `get_top_listener()` asks the diverter for the
original destination port before the taste loop; `DiverterListenerCallbacks` is
constructed with `None` and forwards straight through, and all eight listeners
call `logNbi()` on every transaction; and `DNSListener.parse()` calls
`isProcessBlackListed()` as its first statement, before it decodes the query.
The DNS one is swallowed by a broad `except Exception`, which is why it fails
quietly.

We need `DivertTraffic: No` — its diverter installs a blanket `PREROUTING`
REDIRECT that would answer every analysis VLAN, including clones submitted as
`offline`. So the setting is not negotiable and the patch is not optional.

**Fix.** Apply `automation/fakenet-divert-no.patch` inside the venv FakeNet was
installed into, and re-apply it after any `pip install --upgrade`. Its header
has the command and the reasoning. Verify by asking the responder for something
that cannot exist:

```sh
dig +short @127.0.0.1 totally-not-real-c2.invalid    # expect: 192.0.2.123
```

An answer means the DNS path is whole. Silence with FakeNet running and the
port bound means the patch is not applied.

### `UnboundLocalError: local variable 'fn_addr' referenced before assignment`

**Symptom.** FakeNet exits at startup, before binding anything.

**Cause.** The same untested `DivertTraffic: No` path as above, at its very
first step: `fn_addr` is assigned inside the `diverttraffic == 'yes'` branch
and read outside it, by the loop that hands each listener its bind address.
Upstream issue
[#167](https://github.com/mandiant/flare-fakenet-ng/issues/167).

**Fix.** The first hunk of `automation/fakenet-divert-no.patch`. It binds
`0.0.0.0`, which is also the only correct value here: a `REDIRECT` rewrites the
destination to the **incoming** interface's address — a different gateway for
every VLAN — so a loopback bind would receive nothing from a clone. That
exposure is why `network-setup.sh` DROPs FakeNet's ports on the uplink.

### `SSLError: [SSL: CALLBACK_FAILED]`, with a `getcwd()` FileNotFoundError above it

**Symptom.** Two tracebacks per HTTPS connection. The first is reported as
*ignored*, which makes it easy to skip:

```
Exception ignored in: <bound method SSLWrapper.sni_callback ...>
  File ".../ssl_utils/__init__.py", line 207, in abs_config_path
    abspath = os.path.abspath(path)
  File "<frozen posixpath>", line 420, in abspath
FileNotFoundError: [Errno 2] No such file or directory
```

The second is the consequence — the SNI callback raised, so the handshake is
abandoned:

```
ssl.SSLError: [SSL: CALLBACK_FAILED] callback failed
```

Neither message names a directory, a path, or a configuration key.

**Cause.** **FakeNet's working directory no longer exists, and `cert_dir` was
relative, so it needed one.** Line 420 of CPython 3.12's `posixpath.abspath` is
`cwd = os.getcwd()`, and it sits inside `if not isabs(path):` — so it is
reached only for a relative path, and it fails only when the process's cwd has
been deleted.

Unset, `ProxyListener` falls back to `configs/temp_certs`
(`ProxyListener.py:57`). `SSLWrapper.__init__` resolves that once at startup
and `os.makedirs()` it under whatever directory FakeNet was launched from, so
the process carries a permanent dependency on that path. Every later
`create_cert()` re-resolves it, and the first one after the directory goes away
takes HTTPS down with it. The listener stays up and plaintext keeps working,
which is why this reads as a TLS bug rather than a path bug.

**Fix.** `automation/fakenet.ini` sets `Cert_Dir` to an absolute path in
`[ProxyTCPListener]`. An absolute path takes the `isabs()` branch, `getcwd()`
is never called, and where FakeNet was started stops mattering. FakeNet creates
the directory itself and `shutil.rmtree()`s it on a clean exit, so there is
nothing to provision and nothing in it to preserve.

`sandboxd/tests/test_egress.py` fails if the key goes missing or turns
relative, because nothing else would notice until a sample used TLS.

**The filenames in that directory were sample-controlled until 2026-09-04.**
`create_cert()` builds `os.path.join(cert_dir, "%s.crt" % cn)` where `cn` is
the SNI servername from the clone's own handshake. A `/` survives Python's
server-side SNI decoding — verified 2026-09-01 — so a sample choosing its own
SNI chose part of a path on the hypervisor, in a process running as root there.

Closed by change 6 of `automation/fakenet-divert-no.patch` and by
`automation/fakenet.service`'s `ProtectSystem=strict` / `ReadWritePaths=`.
**Closed in the repository, which is not closed on Dom0** — both halves are
files an operator installs, and a host that has not re-applied the patch and
reinstalled the unit still has the gap and looks no different while it does.
Runbook 13 step 6b's fourth grep answers which state a host is in.

**This entry used to say the gap was bounded because "writes into a directory
that does not exist fail rather than traverse". That reasoning was wrong, and
wrong in the reassuring direction.** It holds only for a parent that does not
exist. `/etc`, `/etc/ssl/certs`, `/root` and `/var/spool` all exist, so a
servername of `../../../../etc/ssl/certs/ca-certificates` traversed into one
of them and rewrote the host trust bundle. Two further things read as limits
and are not: the write happens inside the SNI callback, *before* the handshake
fails on the untrusted certificate, so the `tls-untrusted-cert` caveat never
stood between a sample and the disk; and the 64-character subject CN bound is
longer than that path needs.

It was also left unpatched on the grounds that nothing observed had exploited
it. That is the reasoning to distrust here — the earlier decision was
deliberate and written down, which is what made it reviewable, but "not
exploited by anything observed" is a statement about the samples that have run,
not about the guest-to-hypervisor boundary this lab exists to hold. Found by
the pre-push security review, 2026-09-04.

### `Inadmissible SNI '…'` in FakeNet's journal, once per TLS connection

**Symptom.** `journalctl -u fakenet` carries a warning naming a servername that
looks like a path, a certificate subject, or binary, and the certificate the
clone was served has CN `fakenet.flare` rather than the name it asked for.

**Cause.** Change 6 of `automation/fakenet-divert-no.patch` working. The
servername is chosen by the sample, and this is what a sample trying to name a
file on Dom0 looks like from the outside.

**Fix.** None — this is evidence, and belongs in the report. The connection is
not dropped: an inadmissible name is treated as an absent one, so the handshake
proceeds with the default certificate exactly as it would for a client that
sent no SNI at all.

**Do not "fix" it by relaxing the check.** The one legitimate value it turns
away is an internationalised domain name, which reaches the callback already
decoded out of punycode; the cost there is a certificate CN, on a certificate
no guest trusts anyway.

### The FakeNet patch was re-applied and the new changes are still missing

**Symptom.** `automation/fakenet-divert-no.patch` gains a change, Dom0 pulls,
the patch is re-run, and the old symptom persists exactly. The re-run looks
like a no-op that was already done:

```
patching file fakenet/listeners/ProxyListener.py
Reversed (or previously applied) patch detected!  Skipping patch.
3 out of 3 hunks ignored -- saving rejects to file ProxyListener.py.rej
```

**Cause.** **`patch --forward` skips the whole FILE, not the applied hunk.**
Having recognised the first hunk as already applied, it abandons that file and
every later hunk in it — including the ones that are new. It exits 1 and leaves
`.rej` files, but the message reads as reassurance rather than as failure.

A partly-patched tree therefore survives re-patching unchanged. Confirmed
2026-09-02 by reconstructing a venv carrying changes 1–3 and applying the
five-change patch to it: nothing moved.

The line number in a traceback is the quickest way to tell which changes a venv
has, because each one shifts the ones below it. `remote_sock.setblocking(0)` is
at line 245 in pristine v3.5, at 250 with changes 1–3, and does not exist at
all once change 5 lands.

**Fix.** Reinstall, then patch. Never patch on top of a patch:

```sh
SP="$(/opt/fakenet-ng/bin/python -c 'import fakenet, os; \
    print(os.path.dirname(os.path.dirname(fakenet.__file__)))')"
/opt/fakenet-ng/bin/pip install --no-deps --force-reinstall \
    'git+https://github.com/mandiant/flare-fakenet-ng@v3.5'
patch -p1 --forward -d "$SP" < automation/fakenet-divert-no.patch
```

Then verify by content rather than by the patch's own output, since that output
is what misled in the first place — the three `grep -c` checks are in the patch
header and in runbook 13 step 6b.

### `Hunk #1 FAILED at 137 (different line endings)` on `ssl_utils/__init__.py`

**Symptom.** `fakenet-divert-no.patch` applies to three files and fails the
fourth, change 6 — the SNI fix:

```
patching file fakenet/listeners/ssl_utils/__init__.py
Hunk #1 FAILED at 137 (different line endings).
```

and `grep -c "Inadmissible SNI"` on the installed file is 0. Seen 2026-10-21
in the development container, after the patch's header text was edited.

**Cause.** Upstream's `ssl_utils/__init__.py` has CRLF line endings, so that
hunk's 45 lines end in `\r\n` in the patch. An editor that normalises line
endings when it saves rewrites them as `\n`, anywhere in the file — editing only
the header was enough. The other three files are LF, so their hunks still apply
and the run looks almost right.

**Fix.** Restore the file from git and make the change byte for byte, or with
an editor set to keep line endings. Check before committing:

```sh
grep -c $'\r' automation/fakenet-divert-no.patch    # 45
```

`make sandboxd` fails on the fourth `grep -c` if this slips through, which is
why those counts are hard checks there rather than output to read.

### `OSError: [Errno 9] Bad file descriptor` from FakeNet's proxy, on HTTPS only

**Symptom.** A clone in `simulated` completes a TLS handshake — the guest
reports something like *"Connected but unable to verify the issuer's
authority"*, so it got that far — and FakeNet then prints:

```
  File ".../fakenet/listeners/ProxyListener.py", line 250, in handle
    remote_sock.setblocking(0)
OSError: [Errno 9] Bad file descriptor
```

Plaintext HTTP is fine. Appears only once handshakes start succeeding, so it
shows up *after* the certificate-rejection problem below is understood, never
before.

**Cause.** **`wrap_socket()` detaches the socket it is handed.** CPython builds
the `SSLSocket` with `fileno=sock.fileno()` and then calls `sock.detach()`, so
the original object is left at fd -1 and every later call on it fails.
Reproduced on a loopback handshake 2026-09-01:

```
before wrap: remote_sock.fileno() = 4
after  wrap: remote_sock.fileno() = -1
             ssl_remote_sock.fileno() = 4
```

Upstream goes on using `remote_sock` for `setblocking()` and for the `select()`
in the relay loop. The `recv`/`send` calls inside that loop already branch on
`ssl_remote_sock`, which is why only those two are wrong — and why the bug is
invisible for plaintext, where nothing was ever detached.

**HTTPS through the proxy has therefore never worked in v3.5**, with or without
a trusted CA. It was masked by the certificate rejection below: a client that
refuses the certificate never reaches this line.

**Fix.** Change 5 of `automation/fakenet-divert-no.patch`, which uses the
wrapped socket from that point on. The same hunk also checks
`ssl_remote_sock.pending()` beside `select()`'s readability, because `select()`
polls the raw descriptor and cannot see bytes already decrypted into the SSL
object's buffer — a TLS request larger than `BUF_SZ` would otherwise reach the
listener truncated and silent.

### `ssl.SSLError: SSLV3_ALERT_BAD_CERTIFICATE` from FakeNet, once per connection

**Symptom.** A Python traceback in FakeNet's output every time a clone in
`simulated` opens an HTTPS connection, ending in:

```
  File ".../fakenet/listeners/ProxyListener.py", line 222, in handle
    ssl_remote_sock = self.server.sslwrapper.wrap_socket(remote_sock)
ssl.SSLError: [SSL: SSLV3_ALERT_BAD_CERTIFICATE] sslv3 alert bad certificate
```

Plaintext HTTP through the same proxy works, so it looks like FakeNet's TLS
support is broken.

**Cause.** **It is not FakeNet failing — it is the guest refusing.** That alert
is sent by the *client*; FakeNet's server raised it while receiving the clone's
answer to its certificate. `automation/fakenet.ini` sets `Static_CA: No`, so
FakeNet mints a self-signed certificate from an ephemeral CA the guest's trust
store has never seen, and any client that validates rejects it.

The traceback rather than a message is separate: `wrap_socket()` raises into a
`socketserver` worker thread with no handler, so the default error handler
prints the stack. TLS is the common path for real samples, so unpatched this
fills the log with what reads as a crash.

**Fix.** Two halves, and the first is the one that matters.

*Disclose it.* `simulated` exits must declare `tls-untrusted-cert` alongside
`no-real-internet`. The report then says HTTPS was refused rather than showing
a sample that did nothing — which is the confident false negative DRAFT-057
exists to prevent. Runbook 13 step 7a proves both halves: validation fails,
`--no-check-certificate` succeeds, so the TLS path is sound and only the trust
decision failed.

*Quieten it.* The fourth change in `automation/fakenet-divert-no.patch` catches
the error and logs one line naming the client address.

**Do not install FakeNet's CA in the guest.** It would make HTTPS work, and it
would put a permanently enumerable entry in the trust store — a well-known
sandbox-detection check — as a persistent modification to a golden image.
Trading a disclosed limitation for a detection signal is the wrong direction.

### A firewall rule tested from the host it protects, and the test passed either way

**Symptom.** An uplink DROP is verified by probing the host's own LAN address
from that host. `nc -z -w3 192.168.1.6 38926` reports
`Connection ... succeeded!`, which reads as the rule being absent or broken.

**Cause.** **A host's own address routes over loopback.** `ip route get
192.168.1.6` on that host answers `local ... dev lo`, so the packet arrives on
`lo` and a rule written `-i xenbr0` cannot match it. The probe measured the
loopback path and said nothing about the LAN.

The same probe misleads in the other direction just as easily. `dig +short
@192.168.1.6 example.com` returned `connection refused` on Dom0 on 2026-09-01,
which looks like the guard working — but nothing binds UDP/53 on that host at
all, so `refused` is also exactly what an unfirewalled host returns. Neither
result carried information.

**Fix.** Two checks, and the cheap one first.

On the host, confirm the rule names the interface that actually receives the
traffic — `ip -4 -o addr show` against `iptables -vnL DRAKVUF_INPUT`. A guard
aimed at an interface that never sees LAN traffic is a guard that has never
worked, silently, for every rule sharing that shape.

Then probe from a **different machine** and read the DROP rule's packet
counters afterwards. Rising counters are positive evidence; a timeout alone is
equally consistent with a wrong address or an unplugged cable.

**Do not "fix" it by dropping the port on `lo`.** For FakeNet specifically that
breaks the fake Internet: its proxy hands every tasted connection to
`localhost:80`, so the loopback path is load-bearing.

Related: *An empty `FORWARD` chain read as proof a rule was rejected*, and *A
containment claim was written up without being tested*. Same family — a check
whose passing condition is also its failing condition.

### A `routed` clone gets ICMP host unreachable and the tunnel carries no data

**Symptom.** The tunnel is up and handshaking, `sandboxd` offers the `routed`
exit, `iptables -S DRAKVUF_EGRESS_V1` and `ip route show table 1001` both look
right — and the clone reaches nothing. A capture on the tunnel interface shows
each query followed microseconds later by an ICMP error, on a retry cadence:

```text
18:14:19.942649 IP 10.99.0.1.38119 > 1.1.1.1.53: 7359+ A? ntp.ubuntu.com. (32)
18:14:19.942659 IP 172.16.1.1 > 172.16.1.2: ICMP host 1.1.1.1 unreachable, length 68
18:14:23.988009 IP 10.99.0.1.47447 > 1.1.1.1.53: 23023+ AAAA? api.snapcraft.io. (34)
18:14:23.988020 IP 172.16.1.1 > 172.16.1.2: ICMP host 1.1.1.1 unreachable, length 70
```

`wg show` confirms it: `transfer: 92 B received, 276 B sent` is keepalives and
nothing else.

**Cause.** **`AllowedIPs` is WireGuard's routing table, not a filter.** The
peer is selected by longest-prefix match on the destination, and a destination
matching no peer is rejected at the device with `EHOSTUNREACH` before anything
is encrypted. With `AllowedIPs = 10.99.0.0/24` and `sandboxd`'s `default dev
wg0`, every Internet-bound packet is handed to `wg0` and bounced there — the
kernel then generates the ICMP error, which is why it trails the query by ten
microseconds rather than by a round trip.

The 10-µs gap is the tell. A genuine unreachable from a real router cannot
arrive faster than the path allows.

**Fix.** Widen the Dom0 side to the destinations the exit is meant to carry —
for a full tunnel, `AllowedIPs = 0.0.0.0/0`.

**And set `Table = off` in `[Interface]` in the same edit.** wg-quick's default
`Table = auto` reacts to a `0.0.0.0/0` peer by installing fwmark default-routing
at preferences 32764 and 32765, which captures **Dom0's** traffic rather than
the clone's, on a host you are probably logged into. `sandboxd` installs the
only route this needs, in a per-VLAN table; wg-quick must install none.

Related: *An empty `FORWARD` chain read as proof a rule was rejected*. Both are
a rule set that inspects correctly while the packet dies somewhere the rules do
not describe.

### Dom0's own ICMP errors appear on the tunnel instead of reaching the clone

**Symptom.** In the same capture as above, ICMP errors addressed to the clone
are seen leaving on `wg0` — `172.16.1.1 > 172.16.1.2` — although `172.16.1.2` is
directly connected on `xenbr1.1` and the tunnel is nowhere on that path. The
clone never receives them, so it retries on a fixed cadence instead of failing.

**Cause.** The policy rule selected on source network alone:

```text
1001:	from 172.16.1.0/24 lookup 1001
```

**The VLAN gateway address is inside the subnet it serves.** `172.16.1.1` is in
`172.16.1.0/24`, so the rule matches packets Dom0 *originates* from the gateway
as well as packets it forwards *from* the clone, and table 1001 holds one route:
`default dev wg0`.

`icmp_send` performs an ordinary output route lookup, and `l3mdev_master_ifindex`
returns 0 for an interface that is not in a VRF, so nothing pins the error to the
interface it was provoked on. It goes wherever the rules say — into the tunnel.

**Fix.** Fixed in `sandboxd/egress.py` on 2026-09-03: the rule carries
`iif <clone interface>`, which forwarded traffic satisfies and locally-generated
traffic cannot. Confirm on any host in one command:

```sh
ip route get 172.16.1.2 from 172.16.1.1    # expect: dev xenbr1.1, NOT wg0
```

**Do not fix it by renumbering the gateway out of the subnet.** The clone needs
a gateway inside its own /24 to have a default route at all; the containment
comes from the selector, not from the address plan.

### `module 'OpenSSL.crypto' has no attribute 'X509Extension'`

**Symptom.** FakeNet logs one line and exits before binding anything:

```
09/01/26 08:26:46 AM [           FakeNet]  module 'OpenSSL.crypto' has no attribute 'X509Extension'
```

Preceded by `Error starting ProxyListener listener on port 38926:`, and nothing
in it names pip, a package or a version.

**Cause.** **pyOpenSSL 26.2.0 (2026-05-04) removed
`OpenSSL.crypto.X509Extension`**, along with `X509.add_extension` and
`get_extensions`. They had been deprecated since 23.3.0. FakeNet's
`listeners/ssl_utils` builds the MITM certificate its proxy presents out of
exactly those calls.

It is fatal rather than a degraded-TLS problem because `ProxyListener.start()`
constructs the SSL wrapper for TCP unconditionally, whether or not any sample
ever speaks TLS — and the proxy is the first listener, so nothing else gets as
far as binding.

Upstream's `setup.py` leaves `pyopenssl` unpinned, so a fresh install today
picks up a version that cannot work. 26.x has also deprecated `PKey.generate_key`,
`dump_privatekey`, `X509.sign`, `X509Name` and every mutable method on `X509` —
which is most of the rest of what `ssl_utils` does.

**Fix.** Install from `automation/fakenet-requirements.txt`, which pins
`pyopenssl<26.2`, and install FakeNet itself with `--no-deps` so its own
unpinned list cannot override it. Check with
`/opt/fakenet-ng/bin/pip show pyopenssl` rather than by reading the file.

**The pin is a countdown, not a repair.** The real fix is upstream moving to
`cryptography.x509.CertificateBuilder`. Rewriting certificate generation here
would be a large patch in a security-relevant path to avoid a version
constraint, which is the wrong trade for a lab responder minting throwaway
certificates — but re-check it before moving off v3.5.

### FakeNet exited with `Error starting DNSListener on port 53`

**Symptom.** FakeNet starts, reports one listener failing to bind, and exits 1,
taking every other listener with it.

**Cause.** **`systemd-resolved` already holds port 53 on this host** — its stub
on `127.0.0.53` and `127.0.0.54`, which `ss -lunp` shows. FakeNet's DNS
listener binds `0.0.0.0` and its UDP server sets no `SO_REUSEADDR`, so the
wildcard bind collides with the specific one. Any listener that raises during
start is fatal to the process (`sys.exit(1)`), so one port conflict looks like
FakeNet being broken.

**Fix, applied 2026-09-01.** FakeNet's DNS listener moved to **5300**:
`config.FAKENET_DNS_PORT`, `[DNS Server] Port` in `automation/fakenet.ini`, and
the `fakenet_udp` DROP list in `network-setup.sh`, which must agree —
`sandboxd/tests/test_egress.py` fails when they drift.

Nothing in the guest sees the number. The redirect still **matches** the
clone's `--dport 53` and only rewrites the target, so no preconfig script and
no guest resolver setting changes.

Keep any replacement **below 32768**, outside `ip_local_port_range`. A port
inside it can be held by one of Dom0's own outbound connections at the moment
FakeNet starts, which turns this same fatal bind failure into an intermittent
one. FakeNet's proxy port, 38926, is inside that range — inherited from
upstream and not yet observed to collide, but it is the first thing to check if
`[Errno 98]` ever names 38926 instead.

**Do not disable `systemd-resolved` to free the port.** It is Dom0's resolver;
stopping it to serve a guest breaks name resolution for the hypervisor,
`sandboxd`, and every `git pull` and `apt-get` used to maintain the lab.

### `bash: !xenbr0: event not found`

**Symptom.** An `iptables` rule using a negated interface fails in an
interactive shell.

**Cause.** **Bash history expansion** consuming the `!` before `iptables` sees
it. An interactive-shell behaviour only.

**Fix.** `network-setup.sh` runs under `/bin/sh` (dash), which has no history
expansion, so the production path is unaffected. To reproduce it by hand, go
through `sh -c` rather than typing it into bash — otherwise you are debugging
your shell, not the rule.

### `iptables -S` says a chain is "incompatible", and the chain is simply absent

**Symptom.** An error suggesting a tooling or backend mismatch.

**Cause.** On the nft backend, `iptables -S` reports **any nonexistent chain** as
"incompatible". "Chain absent" and "chain unreadable" produce the same text.

**Fix. This is a containment issue, not a cosmetic one** — *absent* means
isolation is entirely off, and a human reading the message as a tooling quirk
will proceed with no isolation at all. Use `nft list chain` as the readback that
distinguishes them. Owned by DRAFT-038.

*Related cosmetic note: `iptables -C` on the nft backend prints the matched rule
to **stdout**, and `2>/dev/null` only silences stderr — hence stray
`DRAKVUF_* all opt -- in * out *` lines in every provisioning transcript.*

### An analysis left evidence of itself inside the guest

**Symptom.** Scratch files, sockets or marker processes created for the
pipeline's own bookkeeping.

**Cause.** Designing cross-command state as a guest file — for example passing
an installed package name through `/data/local/tmp`.

**Fix.** Carry state in shell variables, derive it from a constant property of
the saved template, or configure it on Dom0. Anything left behind is an evasion
signal to live malware. Same reasoning renamed the injection anchor away from
`drakvuf-anchor` (issue #7) and rejected `monkey` for APK launch, because
`ActivityManager.isUserAMonkey()` reports it to the sample.

---

# The object store — Garage

**Nothing here describes the deployment yet.** It runs MinIO; runbook 18 is the
migration and has not been executed. Every symptom below was met while
rehearsing it in the development container on 2026-10-02/04, and is filed here
because the next person to run `platform/garage/provision.sh` or
`scripts/dev-services.sh OBJECT_STORE=garage` will meet them too.

### `garage key create` ran twice and now two keys have the same name

**Symptom.** `garage key list` shows two entries with the same `Name`, and
`garage key info <name>` refuses with
`InvalidRequest (400): Bad request: 2 matching keys`. Nothing says which id the
application is using.

**Cause. `key create` does not converge** — it mints a new key every time,
name collisions included. Running a provisioning step twice is enough.

**Fix.** Decide which id is live by reading the consumer, not the store:
`grep '^S3_ACCESS_KEY=' /etc/sandbox-platform/api.env`. Delete the other:

```bash
garage -c /etc/garage.toml key list
garage -c /etc/garage.toml key delete <the unused id> --yes
```

`platform/garage/provision.sh` counts keys by name and refuses at two or more
rather than guessing, so this cannot be reached through it.

### `garage bucket info` or `key info` exits 1 and the thing does exist

**Symptom.** A shell `if` built on `garage bucket info X` takes the wrong
branch.

**Cause.** Both commands exit 1 for *absent* **and** for *ambiguous*
(`2 matching keys`), so the status alone does not distinguish "create it" from
"stop and ask a human". They also print `Error: ... (404)` to stdout, which a
pipeline can swallow.

**Fix.** Use `bucket info` as an existence test (one meaning), and parse
`garage key list` for keys — never `key info`.

### `nginx -t` fails with `Address already in use` and the config is fine

**Symptom.** Validating the object store's front before the cutover:

```
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: [emerg] bind() to 192.168.1.10:9000 failed (98: Address already in use)
nginx: configuration file /etc/nginx/nginx.conf test failed
```

**Cause. `nginx -t` binds every `listen` directive** — it is not a
syntax-only check. MinIO still holds port 9000 until the cutover.

**Fix.** Read the first line: `syntax is ok` means the file parsed, including
the `map`, `log_format` and `upstream` blocks that only work because Debian
includes `conf.d/` inside `http {}`. A bind error is the only error to accept
there, and `nginx -t` must come back fully clean after MinIO stops.

### The store refuses a presigned URL with `400`, not `403`

**Symptom.** An expired upload ticket, a tampered POST policy, or an
over-range upload is refused with `400 InvalidRequest` where MinIO answered
`403` or `EntityTooLarge`. A test asserting the old shape fails while the
control plainly works.

**Cause.** Garage classifies these as malformed rather than unauthorised:
`Date is too old`, `Key 'key' has value not allowed in policy`,
`File size does not match policy`.

**Fix.** Assert the property, not the vendor's string —
`platform/tests/test_objects.py` says so at the top, and the four assertions
that were MinIO-shaped now accept both. `sandboxd` never cared: it treats
every 4xx as a permanent refusal.

### A wrong `S3_REGION` seems not to matter

**Symptom.** `head_object` with the wrong region fails, `get_object` with the
same wrong region succeeds, and a presigned URL fails with
`400 AuthorizationHeaderMalformed`.

**Cause. botocore is hiding it.** Garage returns the correct region in its
error body; botocore reads that hint and silently re-signs, so any call with a
response body appears to work. A HEAD has no body to read and a presigned URL
has nobody to retry it.

**Fix.** Treat the presigned failure as authoritative — it is also the
real-world one, since every URL the platform issues is presigned. `s3_region`
in `/etc/garage.toml` must equal `S3_REGION` in `api.env`;
`platform/garage/provision.sh` compares them before it creates anything.

### A setting in `garage.toml` has no effect and nothing complains

**Symptom.** A configuration key is present, spelled slightly wrong, and
silently inert.

**Cause.** Garage ignores unknown configuration keys. Probed 2026-10-03 with
`tls_cert_file`/`tls_key_file` under `[s3_api]`: accepted without comment, and
no TLS. There is no `nginx -t` equivalent for the config file.

**Fix.** Check the value took effect rather than that it was accepted —
`garage -c … status`, `bucket info`, or the behaviour itself. And Garage has no
TLS listener at all: the API binds a plain `TcpListener`, which is why nginx is
in front of it.

### `/health` returns 503 on a store that just started

**Symptom.** `curl http://127.0.0.1:3903/health` → 503, and every write is
refused.

**Cause.** No layout has been applied, so the node holds no data role and
cannot serve. `garage status` shows `NO ROLE ASSIGNED`.

**Fix.**

```bash
node="$(garage -c /etc/garage.toml node id -q | cut -d@ -f1)"
garage -c /etc/garage.toml layout assign -z lab -c 200G "$node"
garage -c /etc/garage.toml layout apply --version 1
```

503-until-layout is why this endpoint replaced `/minio/health/live`: it is a
readiness probe rather than a liveness ping.

### `mc` does nothing useful against Garage

**Symptom.** `mc admin ...` fails against the new store; the three
service-account policy tests skip.

**Cause.** `mc admin` is MinIO's admin plane and Garage has none. Ordinary S3
verbs work; the admin ones do not exist.

**Fix.** The `garage` CLI replaces them for provisioning, and the capabilities
`api-policy.json` withheld are asserted against the TLS front instead —
`platform/tests/test_object_front.py` and `platform/garage/conformance.py`.
Neither needs `mc`.

### The browser upload fails only in the development container

**Symptom.** `test_ui_browser.py`'s two upload tests fail with *"It is on a
different origin to this page, so the browser blocked the upload"*, against a
store that works for every other test.

**Cause.** The page is served from a random localhost port and the upload goes
to another, so it is cross-origin — and Garage has no default CORS rule where
MinIO's own default is `*`.

**Fix.** `scripts/dev-services.sh` sets `AllowedOrigins: ["*"]` on the dev
bucket, and CI does the same. **The deployment must never have it**: there the
upload is same-origin by routing, and `platform/garage/provision.sh` refuses
`*` outright.

### An object's ETag changed after a store migration

**Symptom.** `jobs.sample_etag` no longer matches, or a copied object's ETag
has lost a `-4`-style suffix.

**Cause.** The suffix form is a digest of the original part digests, and part
boundaries are not recoverable — so an object MinIO stored multipart cannot
keep its ETag through a single-part copy. Measured over 3,300 objects: 3,297
identical, 3 changed, all of them large `results/` artifacts, and **no sample**
(a sample arrives by presigned POST, which is always one part).

**Fix.** Accept a changed ETag **only** where the source side had a `-N`
suffix and the sizes match; anything else is a bad copy. Artifact ETags are
recorded nowhere and compared by nothing. Do not verify a copy with
`rclone lsjson --hash`: it reports no hash at all for either store
(rclone 1.60.1), so it compares `null` to `null`.


---

# Reading the project record itself

### A fact from a runbook turned out to be superseded

**Symptom.** A value read from `docs/runbooks/01`–`10` that no longer describes
this host.

**Cause.** Those ten runbooks describe the **nested Proxmox lab**, erased
2026-08-28. They are correct as dated evidence and wrong as a description of
today. `10-tune-nested-cpu.md` goes further: its premise ("can L0 give Dom0 more
CPU?") no longer exists, so it is **closed, not pending**.

**Fix.** `docs/CURRENT-STATE.md` §2a lists every fact the migration invalidated
in one table. Read it before citing any deployment number from a runbook. Every
fact there carries the date it was last confirmed; over 30 days old is a hint to
re-confirm, not a fact to assert.

### A performance measurement did not reproduce

**Symptom.** Throughput figures from before 2026-08-28 disagreeing with what the
host does now.

**Cause.** Two independent reasons, and it is easy to blame the wrong one.
Dom0 stopped being nested **and** DRAKVUF changed: the rebuilt Dom0 runs
`v1.1-da982ab`, while every pre-migration measurement was taken on
`…+52df0bc8-1`. Different code, different machine, same day.

**Fix.** Treat pre-migration numbers as describing a different system. The
comparison that would have isolated nesting alone is permanently unavailable —
it needed a nested baseline measured after the bare-metal run, on a host that no
longer exists (`12-baremetal-trial.md`, Parts E–G, abandoned).

### An upstream DRAKVUF build passed a casual check and was the wrong binary

**Symptom.** `drakvuf --help` shows `--memdump-disable-*` flags, so the build
looks like it has memdump. Traces against Ubuntu or Android then degrade or
produce nothing, silently.

**Cause.** **Upstream's memdump is Windows-only.** Those flags map to
`VirtualFree`, `VirtualProtect`, `WriteProcessMemory`, `TerminateProcess`,
`CreateThread`, `SetThreadContext` — their presence in `--help` proves nothing
about Linux support. This lab builds `lfreijo/drakvuf` branch `memdump`, which
adds `memdump/linux.cpp`, `memdump/linux.h`, splits `memdump.cpp` into
`win.cpp`/`linux.cpp`, and adds `syscalls/linux.cpp`.

**This actually happened during the migration** — an upstream build passed a
`--help` check.

**Fix.** Check the **version string**, not the flag list:
`drakvuf --version`. And check out the **commit, not the branch head** —
`git reset --hard lfreijo/memdump` gives whatever that branch points at today,
and a different DRAKVUF silently invalidates every comparison.

Those four plugins — `syscalls`, `filetracer`, `fileextractor`, `memdump` — are
exactly the four in every trace command here.

### `libzstd found: NO` and the build succeeded anyway

**Symptom.** DRAKVUF builds cleanly; trace output is written differently than
expected.

**Cause.** `libzstd-dev` was not installed before configuring. Meson reports
`libzstd found: NO` and **carries on**.

**Fix.** Install it before `meson setup`. `check` and `cmake` missing are benign
by contrast — they gate tests only.

### A regenerated `profiles/linux.json` silently does not work

**Symptom.** A freshly generated Linux profile produces no usable introspection.

**Cause.** **`dwarf2json` is pinned to branch `linux_non_canonical_addr4`**, not
a default branch. Building it from `main` produces a tool that emits a profile
which is accepted and does not work.

**Fix.** Use that branch for any regeneration. LibVMI needs no separate rebuild —
`git diff main..memdump -- libvmi` is empty, so the fork does not move that
submodule.

### Reasoning from upstream capability tables gave the wrong answer

**Symptom.** Concluding a DRAKVUF plugin does not support Linux.

**Cause.** Upstream's `drakvuf_plugin_os_support` marks `fileextractor` and
`memdump` as `[VMI_OS_LINUX] = 0`. **This lab builds the `lfreijo/drakvuf`
`memdump` fork**, whose entire purpose is flipping those to 1.

**Fix.** Check the **deployed build's** own evidence — runbooks, `--help`
captures, real trace output — before accepting an upstream capability claim in
either direction. `docs/architecture/upstream-drakvuf.md` carries the read
matrix and the caveat that it was taken from the branch tip, not the pinned
commit.

### A containment claim was written up without being tested

**Symptom.** A runbook stating *"filtering has not stopped"* while filtering had
stopped completely — no rules, no chains, no VLAN interfaces.

**Cause.** Two reasoning errors, and the second is the one worth carrying:

- An error message (`chain ... is incompatible`) was read as a tooling quirk
  rather than tested. One command would have settled it —
  `iptables -S NO_SUCH_CHAIN_12345` returns the same text.
- *"Those commands ran against the deployed chains"* was inferred **from the
  order of messages in a conversation**, not from any timestamp.

**Fix.** Test the interpretation before writing it up, and never offer
reassurance about a security property from an absence of contrary signal. The
true answer here was *"containment is currently absent"*, and the write-up said
the opposite. It took the maintainer to catch it.

**The generalisable form:** verify that a control **exists and holds the
expected rules**, not that it is *readable*. Absence and unreadability produce
identical output here, and only one of them means the lab is unprotected.

### A measured constant was used directly as a resource guard

**Symptom.** A limit set to exactly the measured value.

**Cause.** Treating one measurement of one clone as a distribution.

**Fix.** Set the constant **above** the measurement and keep both numbers
visible in the comment — "measured X, set to Y for margin". The failure modes
are asymmetric: over-reserving costs idle RAM, under-reserving costs an
OOM-killed `xl restore` partway through an analysis. `DOMAIN_OVERHEAD_MIB` is
150 against a measured 112 (`sandboxd/resources.py:58`). A Windows clone's
overhead has never been observed.

### Baseline measured against throttled code

**Symptom.** A throttle baseline that reads impossibly low, or counting rules
that stay at zero when the traffic plainly happened. Nothing errors.

**Cause.** The checkout was updated to a commit that adds the throttles before
the unthrottled baseline was taken. `sandboxd` has no systemd unit and holds
its module in memory, so a `git pull` alone changes nothing — but the next
restart makes the throttles live, and a baseline measured afterwards is
calibrating limits against traffic those same limits already shaped.

**Fix.** Check what the clone's chain actually holds while a job is running:

```sh
iptables -S DRAKVUF_EGRESS_V<vlan>
```

Three rules — permit, return path, terminal DROP — is pre-throttle code and
the baseline is sound. Six means the throttles are live; put the two files back
to the pre-throttle commit (`git checkout <sha> -- sandboxd/egress.py
sandboxd/config.py`), restart, re-measure, then `git checkout HEAD --` the same
paths.

**Do not try to salvage a contaminated run by reasoning about it.** The
counting ladder sits in the parent chain and does see packets before the
per-VLAN throttles drop them, which sounds like it should be safe and is not:
TCP adapts to loss, so retransmits inflate some counts while backoff deflates
others.

`iptables -S | grep -c DRAKVUF_EGRESS_V` is the cheap form of the same check —
5 lines pre-throttle, 8 after — and it is why that assert exists in runbook 15
step 3.

### A capa rule that should obviously match produces nothing

**Symptom.** A sample plainly calls `OpenProcess` / `CreateRemoteThread` /
`GetTickCount`, `ttps.json` has no matching TTP, and `apimon.log` contains no
line for that API either. Nothing errored.

**Three separate causes, and they look identical from the outside.**

1. **The API is not in the hook list.** DRAKVUF reports only what it was asked
   to hook. Until 2026-09-27, 811 of the API names capa can match were not in
   `sandboxd/data/hooks.txt` at all. Check with
   `grep -c ',<Function>,' sandboxd/data/hooks.txt`, and regenerate per
   `docs/DEVELOPING.md` 6 if a `flare-capa` bump moved the rules on.

2. **The hook names the wrong DLL, and failing to resolve is SILENT.**
   `libusermode/userhook.cpp:370` logs a failed symbol lookup through
   `PRINT_DEBUG`, which is compiled out of a release build — so a hook on a DLL
   that does not export the symbol produces no error, no warning and no data.
   This is not hypothetical: on Win11 23H2 kernel32 forwards a great many APIs
   into kernelbase, and **51 lines inherited from drakvuf-sandbox still say
   `kernel32.dll`** for functions this guest keeps in kernelbase.
   `scripts/gen-hook-lists.py --report` lists every one, checked against the
   symbol profiles in `profiles/`.

3. **The rule is a `.NET` or ordinal rule, which no call log can satisfy.**
   `Namespace::Method` features are managed calls in JIT'd code, and an ordinal
   (`ws2_32.#1`) can never match because capa's drakvuf extractor passes an
   empty module to `generate_symbols`. .NET is reached only by capa's static
   pass over dumped assemblies, which needs `analyze_memdumps` — currently
   `False`.

4. **The rule wants a `string:` and the argument was not normalised.** capa
   yields an argument value whole, so a DRAKVUF string reaches it as
   `0x7ffc1234:"Xen"` — `substring:` matches that, `string:` and
   `string: /regex/` do not. `capa_processor.normalise_string_arguments` exists
   for this; if a rule with a plain `string:` still will not fire, check the
   argument is actually typed as a string in the hook list, because an untyped
   one arrives as a number and becomes a `Number` feature instead.

5. **On Linux, the call is a glibc IFUNC.** `strcmp`, `strstr`, `memcmp`,
   `strncmp` and `strcasecmp` are `STT_GNU_IFUNC`; their symbol value is a
   resolver, so a hook on the name fires once at process start with no strings
   and never again. There is no name to hook instead — the implementations are
   not in `.dynsym`. Nothing in the hook list can fix this; it needs IFUNC
   support in `libdrakvuf/linux-exports.c`.

**What is NOT the cause:** a malformed hook-list line. That fails loudly and
early — `drakvuf_load_dll_hook_config` rethrows as `Invalid entry on line N`
(`userhook.cpp:1035`) and DRAKVUF does not start at all. If the trace ran, the
list parsed.
