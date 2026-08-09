# Runbook — deploy the repo-relative path layout and injection delivery

> **Issue:** [#4](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/4)
> (DRAFT-025, with DRAFT-027 folded in) · **Milestone:** M0/M1 ·
> **Where it runs:** Xen Dom0 (L1), *not* the development container.
>
> **Status: NOT YET EXECUTED as of 2026-08-09.** Every command in D1–D6 is
> **Candidate** per `CLAUDE.md` — proposed, not validated. Only the
> `injector` *argument shape* used below is evidence-backed, and only from
> `--help` output, not from a successful run. Fill in the evidence blocks
> as you go and record the verdict at the end.
>
> **What changed and why it needs deploying:** the automation no longer
> reads anything from `/home/user/drakvuf-tools` or `/home/user/Documents`,
> and no longer delivers samples over HTTP. Both are file-level changes in
> this repository, but they assume a Dom0 layout that does not exist yet.

## Safety preconditions

- Run as root on Dom0 (`sudo su`).
- **Sandbox clone only.** Never operate on the golden `ubuntu` domain, its
  LV, or the golden Android LV.
- **No real malware.** D5 and D6 use the benign fixture defined in D5.
- Confirm the pipeline is idle before D5 — `/malware_incoming*` empty, no
  `dirwatch` mid-run — so a queued sample is not disturbed.
- **Do not delete the old `~/drakvuf-tools` checkout or the old
  `/home/user/Documents/*.bak` files** until D6 passes. Rollback depends
  on them (see Rollback).

---

## D1 — give Dom0 read-only access, then clone

The repository is **private**, so Dom0 needs a credential. The chosen
mechanism is a **read-only deploy key**: repo-scoped, revocable from the
GitHub UI, and useless for pushing if Dom0 is ever compromised. Dom0
already has outbound network access — it NATs the analysis clones out via
`xenbr0` — so this adds no new egress path, only a key.

Generate the key **on Dom0**, so the private half never crosses a network:

```bash
# Run on L1: Xen Dom0, as root                              [Candidate]
ssh-keygen -t ed25519 -N "" \
    -C "xen-dom0 drakvuf sandbox_project (read-only)" \
    -f /root/.ssh/id_ed25519_sandbox_project
chmod 600 /root/.ssh/id_ed25519_sandbox_project
cat /root/.ssh/id_ed25519_sandbox_project.pub
```

Register the **public** half from a machine that already has `gh` auth —
not from Dom0, which deliberately has no GitHub credential of its own:

```bash
# Run on the development machine                            [Candidate]
# Read-only is gh's default here. Do NOT pass --allow-write.
gh repo deploy-key add ./id_ed25519_sandbox_project.pub \
    --title "xen-dom0 (read-only)"
gh repo deploy-key list
```

Point SSH at that key and clone:

```bash
# Run on L1: Xen Dom0, as root                              [Candidate]
cat >> /root/.ssh/config <<'EOF'
Host github.com
    IdentityFile /root/.ssh/id_ed25519_sandbox_project
    IdentitiesOnly yes
EOF
chmod 600 /root/.ssh/config

ssh -T git@github.com    # expect: "you've successfully authenticated,
                         # but GitHub does not provide shell access"

git clone git@github.com:evilbootloader/drakvuf-multios-sandbox.git \
    /root/sandbox_project
cd /root/sandbox_project
git checkout <the branch under test>
git log --oneline -1
```

The scripts resolve their own location, so `/root/sandbox_project` is the
documented path rather than a required one. If you put it elsewhere,
nothing below changes except the literal paths.

### Updating later, and why the clone matters

```bash
# Run on L1: Xen Dom0, as root                              [Candidate]
git -C /root/sandbox_project fetch origin
git -C /root/sandbox_project pull --ff-only

# What is actually deployed right now:
git -C /root/sandbox_project log -1 --format='%H %cd %s'
# Any local edit that would silently diverge from the repo:
git -C /root/sandbox_project status --porcelain     # expect: empty
```

Those last two commands are the point of using git here rather than
`rsync` or `scp` of a working tree. Issue #2 existed because nobody could
tell whether Dom0's scripts matched the repository's; the answer took a
runbook and a set of recorded SHA-256s to establish. A checkout answers it
in one line, permanently.

> **Never pull while an analysis is in flight.** `dirwatch` spawns the
> worker scripts per sample, re-reading them from disk each time, so a
> pull mid-run can hand one sample the old preconfig and the new trace
> script. Confirm the watch directories are empty and no `dirwatch` is
> running first.

**To revoke:** `gh repo deploy-key delete <id>`, or remove the key in the
GitHub UI under Settings → Deploy keys. Deleting it does not affect the
existing checkout on Dom0 — it only stops future fetches.

```text
D1 EVIDENCE — paste output here

Deploy key fingerprint (ssh-keygen -lf ...pub):
Registered read-only (gh repo deploy-key list output):
ssh -T git@github.com result:
Clone path used:
Branch and commit deployed:
git status --porcelain empty (yes | no):
```

---

## D2 — stage the LibVMI profiles

`profiles/*.json` are no longer git-tracked, so the clone has none. See
`profiles/README.md` for regeneration; if the existing `/root/*.json` are
current, reuse them.

```bash
# Run on L1: Xen Dom0                                       [Candidate]
install -o root -g root -m 0600 \
    /root/linux.json /root/sandbox_project/profiles/linux.json

# Confirm this is the profile the repository was developed against.
sha256sum /root/sandbox_project/profiles/linux.json
# expected per profiles/README.md:
#   cbaf50ede2f1cca3152cf2d2f8e19067081e38a600903ebc92f80805e5f5cda5
```

A mismatch is **not automatically a fault** — it means Dom0's profile was
regenerated against a different kernel build than the one recorded. Decide
which is authoritative before continuing; running with a profile that does
not match the guest kernel produces silently wrong introspection.

```text
D2 EVIDENCE — paste output here

Dom0 profile sha256:
Matches profiles/README.md (yes | no):
If no, which copy is authoritative and why:
```

---

## D3 — stage the saved guest state

`clone-ubuntu.pl` now derives the restore path from its own location and
the origin domain name: `<repo root>/state/<origin>.bak`. For
`ubuntu_sandbox` that is `/root/sandbox_project/state/ubuntu_sandbox.bak`.

**Copy, do not move** — the original is the rollback path.

```bash
# Run on L1: Xen Dom0                                       [Candidate]
cp -a /home/user/Documents/ubuntu_sandbox.bak \
      /root/sandbox_project/state/ubuntu_sandbox.bak

ls -la /root/sandbox_project/state/
```

```text
D3 EVIDENCE — paste output here

Size / mtime of copied .bak:
Free space remaining on the target filesystem:
```

---

## D4 — configure and verify location independence

Edit `automation/pipeline-ubuntu.env` — in particular `INJECTION_PID`,
which is a property of the `.bak` file, not of the repository. The value
committed here (`1415`) is the one evidenced in
`verify-user-placeholder.md`; confirm it still matches this saved state.

```bash
# Run on L1: Xen Dom0                                       [Candidate]
$EDITOR /root/sandbox_project/automation/pipeline-ubuntu.env

# Static checks, same as the dev container runs.
cd /root/sandbox_project
bash -n automation/run_analysis-ubuntu.sh
perl -c automation/clone-ubuntu.pl
```

**The location-independence test.** This is the acceptance evidence for
issue #4's core claim — run it from a directory that is *not* the
checkout:

```bash
# Run on L1: Xen Dom0                                       [Candidate]
cd /tmp
/root/sandbox_project/automation/run_analysis-ubuntu.sh
```

It must behave identically to running it from inside
`/root/sandbox_project/automation/`. A failure naming a path under `/tmp`
means something still resolves against `$PWD`.

Two notes on what this is really testing:

- The launcher pre-flight-checks the `.cfg`, the profile and the `.bak`
  and exits non-zero naming the missing one. Seeing that message with a
  *correct* `/root/sandbox_project/...` path in it is already a partial
  pass — it proves resolution worked.
- The worker scripts are the harder case, because they are executed by
  `dirwatch` rather than by you, and they run under **dash**, not bash
  (their shebangs sit below the DRAKVUF license header). Their resolution
  is exercised only by an actual sample run — D5.

```text
D4 EVIDENCE — paste output here

INJECTION_PID confirmed against this .bak (yes | no | how):
bash -n / perl -c output:
Out-of-repo launch behaved identically (yes | no):
If no, the failing path:
```

---

## D5 — one benign end-to-end run, with Apache stopped

**This is the acceptance evidence for the delivery change.** A run that
merely succeeds proves nothing — the old HTTP path would also have
succeeded. Stopping `apache2` is what proves the dependency is gone
rather than merely unused.

```bash
# Run on L1: Xen Dom0                                       [Candidate]
mkdir -p /tmp/verify-issue4
cat > /tmp/verify-issue4/benign <<'EOF'
#!/bin/sh
# Benign verification sample for issue #4 — no payload, no network.
touch /tmp/drakvuf-verify-issue4
exit 0
EOF
chmod +x /tmp/verify-issue4/benign
sha256sum /tmp/verify-issue4/benign    # this is the guest filename
md5sum    /tmp/verify-issue4/benign    # this keys the result directory

systemctl stop apache2

# In one terminal:
cd /tmp && /root/sandbox_project/automation/run_analysis-ubuntu.sh

# In another:
cp /tmp/verify-issue4/benign /malware_incoming/ubuntu/
```

Confirm, in `/malware_finished/ubuntu/<md5>/`:

```bash
# Run on L1: Xen Dom0                                       [Candidate]
RUN=/malware_finished/ubuntu/<md5>
cat "$RUN/preconfig.log"    # expect writefile, then chmod, then netcfg
grep -c . "$RUN/drakvuf.log"
grep -n 'ExecProc\|Status' "$RUN/drakvuf.log" | head

systemctl start apache2
```

What each line of `preconfig.log` should show, and what a failure looks
like:

| Step | Expected | If it fails |
|---|---|---|
| `writefile` | `STATUS:SUCCESS` | Check `-B`/`-e` order; `-B` is the **Dom0** source. A reversed pair is the defect corrected in `docs/checklists/android.md` |
| `chmod` | `METHOD:ExecProc STATUS:SUCCESS`, `FILE:"/usr/bin/chmod"` | Confirm `/usr/bin/chmod` exists in the guest; on some images it is `/bin/chmod` |
| network | `METHOD:ExecProc STATUS:SUCCESS`, `FILE:"/usr/bin/sh"` | Unchanged from the previous design apart from the resolver |
| `drakvuf.log` | `"Method": "ExecProc", "Status": "Success"` with `ProcessName` = the SHA-256 path | If `ProcessName` is right but the trace is tiny, the x bit did not take — see the `chmod` row |

**Open question this run settles:** whether `injector -m writefile`
preserves or sets the executable bit. The help text does not say, so the
`chmod` injection runs unconditionally. If `preconfig.log` shows the file
already executable before it, record that here and the `chmod` can be
dropped later — do not drop it on assumption.

```text
D5 EVIDENCE — paste output here

Sample sha256 / md5:
apache2 stopped during the run (yes | no):
writefile STATUS:
chmod STATUS:
drakvuf ExecProc Status + ProcessName:
drakvuf.log line count:
Did writefile alone leave the file executable (yes | no | unknown):
```

---

## D6 — confirm delivery integrity, then retire the old paths

```bash
# Run on L1: Xen Dom0                                       [Candidate]
# Dom0-side hash of what was delivered:
sha256sum /malware_processing/ubuntu/<sample>   # or the finished copy
```

The guest-side hash cannot be read after the fact — `cleanup.sh` destroys
the clone. To compare, either add a `readfile` pull before cleanup (
`injector -m readfile -e <guest path> -B <dom0 path>`, the documented
inverse of `writefile`) or accept the `drakvuf.log` `ExecProc Success` on
the SHA-256-named path as sufficient evidence that the delivered bytes
were the right ones. **Decide which and record it** — do not leave the
acceptance criterion silently unmet.

Once D4 and D5 pass:

```bash
# Run on L1: Xen Dom0                                       [Candidate]
# Leave the old checkout in place but make accidental use obvious.
mv /home/user/drakvuf-tools /home/user/drakvuf-tools.retired-issue4
```

> **Check before renaming: `misc/android.cfg` reads its install ISO from
> `/home/user/drakvuf-tools/Bliss-v17.8.3-...iso`.** That path is install
> media, not a repository asset, so issue #4 deliberately did not move it
> — but renaming the directory breaks the golden Android VM's ability to
> reinstall from cdrom. Move the ISO somewhere stable and update
> `misc/android.cfg` first, or leave the directory named as-is. Nothing
> in the analysis pipeline reads it, so this is not urgent; it is just
> easy to break silently and only notice months later.

Do **not** remove `/home/user/Documents/ubuntu_sandbox.bak` or
`/root/linux.json` in this step. They cost disk, not correctness, and
they are the rollback path.

```text
D6 EVIDENCE — paste output here

Integrity method chosen (readfile | ExecProc-only) and why:
Old checkout retired (yes | no):
```

---

## Rollback

File-level and complete; no LVM, Xen, or network state is changed by any
step above.

1. `git -C /root/sandbox_project checkout <previous commit>` — or simply
   stop using the new checkout.
2. `mv /home/user/drakvuf-tools.retired-issue4 /home/user/drakvuf-tools`
   and launch from there. It still has the `/home/user/...` paths and the
   HTTP delivery, and its `.bak` and profile were never moved.
3. `systemctl start apache2` if it was left stopped.

The old and new checkouts read the same `/malware_*` tree, differing only
in the per-OS subdirectory level. A rollback therefore leaves any sample
already sitting in `/malware_incoming/ubuntu/` unwatched — move it up one
level to `/malware_incoming/` before relaunching the old pipeline.

---

## Verdict

```text
Location independence (D4) passed:        (yes | no)
Apache-stopped delivery (D5) passed:      (yes | no)
Delivery integrity (D6) method + result:
Deployed commit:
Date executed:
Executed by:
```