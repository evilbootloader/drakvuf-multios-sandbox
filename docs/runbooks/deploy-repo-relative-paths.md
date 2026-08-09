# Runbook — deploy the repo-relative path layout and injection delivery

> **Issue:** [#4](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/4)
> (DRAFT-025, with DRAFT-027 folded in) · **Milestone:** M0/M1 ·
> **Where it runs:** Xen Dom0 (L1), *not* the development container.
>
> **Status: COMPLETE — executed on Dom0 2026-08-09 by evilbootloader.**
> D1–D6 all passed against commit `57713fc`; the evidence blocks below are
> filled in and the verdict is at the end. Commands in D1–D6 are therefore
> **validated**, not Candidate.
>
> **Outcome in one line:** the pipeline runs from a checkout at
> `/root/sandbox_project`, launched from outside it, delivering samples by
> injection with `apache2` stopped.
>
> Three findings the run produced, beyond passing:
>
> 1. **`writefile` leaves the staged file executable.** The `chmod`
>    injection that shipped in the first draft was removed after a Dom0
>    test confirmed runs still trace without it. This answers DRAFT-027's
>    PLAN step 3, which `injector --help` could not.
> 2. **Delivery integrity is proven by `readfile`**, the documented
>    inverse of `writefile`: the file pulled back out of the guest hashed
>    identically to the Dom0 source. That injection was a one-off for this
>    runbook and is deliberately **not** in `preconfig-ubuntu.sh` — it
>    costs a round trip per sample.
> 3. **`network-setup.sh` is not idempotent, now with evidence.** The
>    second launch produced `RTNETLINK answers: File exists` and
>    `Error: ipv4: Address already assigned`, because every run re-adds the
>    VLAN interfaces and addresses. Harmless here; this is the first
>    execution evidence for **DRAFT-028**, which had been reasoned from
>    source only.
>
> **What changed and why it needed deploying:** the automation no longer
> reads anything from `/home/user/drakvuf-tools` or `/home/user/Documents`,
> and no longer delivers samples over HTTP.

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

# Test the branch BEFORE it merges -- if D4/D5 fail, the fix belongs in
# PR #5 rather than as a follow-up commit on master.
git checkout issue-4-paths-and-delivery
git log --oneline -1     # expect d24b6d0 or later
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

root@drakvuf:~# ssh-keygen -t ed25519 -N "" \
    -C "xen-dom0 drakvuf sandbox_project (read-only)" \
    -f /root/.ssh/id_ed25519_sandbox_project
Generating public/private ed25519 key pair.
Created directory '/root/.ssh'.
Your identification has been saved in /root/.ssh/id_ed25519_sandbox_project
Your public key has been saved in /root/.ssh/id_ed25519_sandbox_project.pub
The key fingerprint is:
SHA256:wObhvOmktcWYnyKAqjlNHmwQXPy1Lzx0m3JQ0GMln6o xen-dom0 drakvuf sandbox_project (read-only)
The key's randomart image is:
...

cat /root/.ssh/id_ed25519_sandbox_project.pub
ssh-ed25519 ... xen-dom0 drakvuf sandbox_project (read-only)

root@drakvuf:~# ssh -T git@github.com    # expect: "you've successfully authenticated,
The authenticity of host 'github.com (140.82.121.3)' can't be established.
ED25519 key fingerprint is SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'github.com' (ED25519) to the list of known hosts.
Hi evilbootloader/drakvuf-multios-sandbox! You've successfully authenticated, but GitHub does not provide shell access.

root@drakvuf:~# git clone git@github.com:evilbootloader/drakvuf-multios-sandbox.git \
    /root/sandbox_project
cd /root/sandbox_project
Cloning into '/root/sandbox_project'...
remote: Enumerating objects: 243, done.
remote: Counting objects: 100% (243/243), done.
remote: Compressing objects: 100% (127/127), done.
remote: Total 243 (delta 129), reused 213 (delta 99), pack-reused 0 (from 0)
Receiving objects: 100% (243/243), 7.98 MiB | 7.65 MiB/s, done.
Resolving deltas: 100% (129/129), done.
root@drakvuf:~/sandbox_project# git checkout issue-4-paths-and-delivery
Branch 'issue-4-paths-and-delivery' set up to track remote branch 'issue-4-paths-and-delivery' from 'origin'.
Switched to a new branch 'issue-4-paths-and-delivery'
root@drakvuf:~/sandbox_project# git log --oneline -1     # expect d24b6d0 or later
57713fc (HEAD -> issue-4-paths-and-delivery, origin/issue-4-paths-and-delivery) Name the branch under test in the deploy runbook
root@drakvuf:~/sandbox_project# git -C /root/sandbox_project fetch origin
git -C /root/sandbox_project pull --ff-only
Already up to date.
root@drakvuf:~/sandbox_project# git -C /root/sandbox_project log -1 --format='%H %cd %s'
57713fcf631b32f5e5a1f87b030a895952e9a4bc Sun Aug 9 16:11:18 2026 +0000 Name the branch under test in the deploy runbook
root@drakvuf:~/sandbox_project# git -C /root/sandbox_project status --porcelain     # expect: empty
root@drakvuf:~/sandbox_project# 


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

root@drakvuf:~/sandbox_project# install -o root -g root -m 0600 \
    /root/linux.json /root/sandbox_project/profiles/linux.json
root@drakvuf:~/sandbox_project# sha256sum /root/sandbox_project/profiles/linux.json
cbaf50ede2f1cca3152cf2d2f8e19067081e38a600903ebc92f80805e5f5cda5  /root/sandbox_project/profiles/linux.json

Dom0 profile sha256: cbaf50ede2f1cca3152cf2d2f8e19067081e38a600903ebc92f80805e5f5cda5
Matches profiles/README.md (yes | no): yes
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

root@drakvuf:~/sandbox_project# cp -a /home/user/Documents/ubuntu_sandbox.bak \
      /root/sandbox_project/state/ubuntu_sandbox.bak

ls -la /root/sandbox_project/state/
total 2089280
drwxr-xr-x 2 root root       4096 ago  9 18:17 .
drwxr-xr-x 9 root root       4096 ago  9 18:13 ..
-rw-r--r-- 1 root root       1778 ago  9 18:13 README.md
-rw-r--r-- 1 root root 2139404813 ago  2 08:44 ubuntu_sandbox.bak

Size / mtime of copied .bak: 

root@drakvuf:~/sandbox_project# stat /root/sandbox_project/state/ubuntu_sandbox.bak 
  File: /root/sandbox_project/state/ubuntu_sandbox.bak
  Size: 2139404813	Blocks: 4178536    IO Block: 4096   regular file
Device: fc00h/64512d	Inode: 1055286     Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2026-08-08 13:16:24.194667070 +0200
Modify: 2026-08-02 08:44:47.748151008 +0200
Change: 2026-08-09 18:17:09.021295301 +0200
 Birth: 2026-08-09 18:17:06.080241081 +0200


Free space remaining on the target filesystem:
root@drakvuf:~/sandbox_project# sudo vgs
  VG      #PV #LV #SN Attr   VSize     VFree   
  vg-root   1   8   3 wz--n- <1022,00g <318,00g

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

root@drakvuf:~/sandbox_project# cd /root/sandbox_project
root@drakvuf:~/sandbox_project# bash -n automation/run_analysis-ubuntu.sh
perl -c automation/clone-ubuntu.pl
automation/clone-ubuntu.pl syntax OK
root@drakvuf:~/sandbox_project# cd /tmp
/root/sandbox_project/automation/run_analysis-ubuntu.sh

Warning: vconfig is deprecated and might be removed in the future, please migrate to ip(route2) as soon as possible!


Warning: vconfig is deprecated and might be removed in the future, please migrate to ip(route2) as soon as possible!

DRAKVUF dirwatch v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel



INJECTION_PID confirmed against this .bak (yes | no | how): yes
bash -n / perl -c output: OK
Out-of-repo launch behaved identically (yes | no): yes
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

Confirm, in `/malware_finished/ubuntu/107529d281ee10a684e91342f0bb19df/`:

```bash
# Run on L1: Xen Dom0                                       [Candidate]
RUN=/malware_finished/ubuntu/107529d281ee10a684e91342f0bb19df
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

**Open question this run settled:** whether `injector -m writefile`
preserves or sets the executable bit. `injector --help` does not say.

**Answered 2026-08-09: it does — no `chmod` is needed.** The step was
removed from `preconfig-ubuntu.sh` on Dom0 and analyses continued to
trace, then removed from the repository to match. The `preconfig.log`
excerpt below with only `WriteFile` and the network `ExecProc` is that
run. This closes DRAFT-027's PLAN step 3.

The `chmod` table row below is kept because it describes what the log
looked like while the step existed, which is what the removal was
measured against.

> If a future sample ever produces a successful `WriteFile` followed by a
> near-empty trace, the staged file's mode is the first thing to check —
> that is the assumption this removal rests on.

```text
D5 EVIDENCE — paste output here

root@drakvuf:/home/user# mkdir -p /tmp/verify-issue4
root@drakvuf:/home/user# cat > /tmp/verify-issue4/benign <<'EOF'
#!/bin/sh
# Benign verification sample for issue #4 \u2014 no payload, no network.
touch /tmp/drakvuf-verify-issue4
exit 0
EOF
root@drakvuf:/home/user# chmod +x /tmp/verify-issue4/benign
root@drakvuf:/home/user# sha256sum /tmp/verify-issue4/benign    # this is the guest filename
81cd9ba0d4802395d3450d3746a1dad1a24bfa46bbb04d03b094c66f82be8d08  /tmp/verify-issue4/benign
root@drakvuf:/home/user# md5sum    /tmp/verify-issue4/benign    # this keys the result directory
107529d281ee10a684e91342f0bb19df  /tmp/verify-issue4/benign
root@drakvuf:/home/user# systemctl stop apache2

# On another terminal

root@drakvuf:/tmp# cd /tmp && /root/sandbox_project/automation/run_analysis-ubuntu.sh

Warning: vconfig is deprecated and might be removed in the future, please migrate to ip(route2) as soon as possible!

RTNETLINK answers: File exists
Error: ipv4: Address already assigned.

Warning: vconfig is deprecated and might be removed in the future, please migrate to ip(route2) as soon as possible!

RTNETLINK answers: File exists
Error: ipv4: Address already assigned.
DRAKVUF dirwatch v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel

# Back on main terminal

root@drakvuf:/home/user# cp /tmp/verify-issue4/benign /malware_incoming/ubuntu/

user@drakvuf:~$ RUN=/malware_finished/ubuntu/107529d281ee10a684e91342f0bb19df
user@drakvuf:~$ cat "$RUN/preconfig.log"    # expect writefile, then chmod, then netcfg
DRAKVUF injector v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel
Injector starting /home/carlos/Desktop/81cd9ba0d4802395d3450d3746a1dad1a24bfa46bbb04d03b094c66f82be8d08 through PID 1415 TID: 0
[INJECT] TIME:1786292642.547019 METHOD:WriteFile STATUS:SUCCESS PID:1415 FILE:"/malware_processing/ubuntu/benign" ARGUMENTS:"" INJECTED_PID:0 INJECTED_TID:0
Process startup success
DRAKVUF injector v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel
Injector starting /usr/bin/chmod through PID 1415 TID: 0
[INJECT] TIME:1786292643.880756 METHOD:ExecProc STATUS:SUCCESS PID:1415 FILE:"/usr/bin/chmod" ARGUMENTS:"+x /home/carlos/Desktop/81cd9ba0d4802395d3450d3746a1dad1a24bfa46bbb04d03b094c66f82be8d08" INJECTED_PID:1641 INJECTED_TID:1641
Process startup success
DRAKVUF injector v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel
Injector starting /usr/bin/sh through PID 1415 TID: 0
[INJECT] TIME:1786292645.320553 METHOD:ExecProc STATUS:SUCCESS PID:1415 FILE:"/usr/bin/sh" ARGUMENTS:"-c sudo ip addr flush dev eth0 && sudo ip addr add 172.16.1.2/24 dev eth0 && sudo ip route replace default via 172.16.1.1 dev eth0 && echo 'nameserver 1.1.1.1' | sudo tee /etc/resolv.conf" INJECTED_PID:1646 INJECTED_TID:1646
Process startup success
user@drakvuf:~$ grep -c . "$RUN/drakvuf.log"
user@drakvuf:~$ grep -n 'ExecProc\|Status' "$RUN/drakvuf.log" | head
grep: /malware_finished/ubuntu/107529d281ee10a684e91342f0bb19df/drakvuf.log: binary file matches


Sample sha256 / md5: 81cd9ba0d4802395d3450d3746a1dad1a24bfa46bbb04d03b094c66f82be8d08 / 107529d281ee10a684e91342f0bb19df
apache2 stopped during the run (yes | no): yes
writefile STATUS: SUCCESS
chmod STATUS: SUCCESS
drakvuf ExecProc Status + ProcessName: SUCCESS
drakvuf.log line count: 88812
Did writefile alone leave the file executable (yes | no | unknown): I've checked removing the chmod from preconfig-ubuntu.sh and successfully work.

184:# 2. Make it executable. drakvuf-ubuntu.sh runs the sample with
185-#    `-m execproc`, which is execve with no guest shell (established in
186-#    issue #2), and execve requires the x bit. Whether writefile already
187-#    sets it is not stated in the injector help, so this runs
188-#    unconditionally -- it is idempotent, and a missing x bit would
189-#    surface later as an opaque empty trace.
190-#
191-#    execproc rather than a shell: argv is passed as separate -f values,
192-#    so there is no command string to escape out of.
193-#injector -r "$REKALL" -d "$DOMAIN" -i "$PID" -m execproc \
194-#    -e "/usr/bin/chmod" \
195-#    -f "+x" \
196-#    -f "$GUEST_SAMPLE" \
197-#    1>>"$LOG" 2>&1
198-#RC=$?
199-
200-#if [ $RC -ne 0 ]; then
201-#    echo "preconfig: chmod injection failed (rc=$RC)" >>"$LOG"
202-#    exit $RC
203-#fi

user@drakvuf:~$ cat "$RUN/preconfig.log"    # expect writefile, then chmod, then netcfg
DRAKVUF injector v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel
Injector starting /home/carlos/Desktop/81cd9ba0d4802395d3450d3746a1dad1a24bfa46bbb04d03b094c66f82be8d08 through PID 1415 TID: 0
[INJECT] TIME:1786293273.933386 METHOD:WriteFile STATUS:SUCCESS PID:1415 FILE:"/malware_processing/ubuntu/benign" ARGUMENTS:"" INJECTED_PID:0 INJECTED_TID:0
Process startup success
DRAKVUF injector v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel
Injector starting /usr/bin/sh through PID 1415 TID: 0
[INJECT] TIME:1786293275.483617 METHOD:ExecProc STATUS:SUCCESS PID:1415 FILE:"/usr/bin/sh" ARGUMENTS:"-c sudo ip addr flush dev eth0 && sudo ip addr add 172.16.2.2/24 dev eth0 && sudo ip route replace default via 172.16.2.1 dev eth0 && echo 'nameserver 1.1.1.1' | sudo tee /etc/resolv.conf" INJECTED_PID:1646 INJECTED_TID:1646
Process startup success

user@drakvuf:~$ grep -n 'ExecProc\|Status' "$RUN/drakvuf.log" | head
grep: /malware_finished/ubuntu/107529d281ee10a684e91342f0bb19df/drakvuf.log: binary file matches

# With noexec bit set on host
root@drakvuf:/home/user# cp /tmp/verify-issue4/benign /tmp/verify-issue4/benign-noexec
chmod 644 /tmp/verify-issue4/benign-noexec        # the decisive difference
sha256sum /tmp/verify-issue4/benign-noexec        # new hash \u2192 new guest path
cp /tmp/verify-issue4/benign-noexec /malware_incoming/ubuntu/
81cd9ba0d4802395d3450d3746a1dad1a24bfa46bbb04d03b094c66f82be8d08  /tmp/verify-issue4/benign-noexec

root@drakvuf:/home/user# grep -n 'ExecProc\|Status' "$RUN/drakvuf.log" | head
11:{"Plugin": "inject", "TimeStamp": "1786302129.762014", "Method": "ExecProc", "Status": "Success", "ProcessName": "/home/carlos/Desktop/81cd9ba0d4802395d3450d3746a1dad1a24bfa46bbb04d03b094c66f82be8d08", "Arguments": "", "InjectedPid": 1725, "InjectedTid": 1725}
872:{"Plugin":"memdump","TimeStamp":"1786302130.920484","PID":1726,"PPID":1725,"TID":1726,"UserId":0,"ProcessName":"/usr/bin/touch","Method":"do_syscall_64","EventUID":"0x133e","Syscall":"exit_group","DumpReason":"Process termination","ExitStatus":0}
883:{"Plugin":"memdump","TimeStamp":"1786302130.934429","PID":1725,"PPID":1415,"TID":1725,"UserId":0,"ProcessName":"/usr/bin/dash","Method":"do_syscall_64","EventUID":"0x134d","Syscall":"exit_group","DumpReason":"Process termination","ExitStatus":0}
2310:{"Plugin":"memdump","TimeStamp":"1786302133.008422","PID":1677,"PPID":1,"TID":1677,"UserId":0,"ProcessName":"/usr/lib/NetworkManager/nm-dispatcher","Method":"do_syscall_64","EventUID":"0x1952","Syscall":"exit_group","DumpReason":"Process termination","ExitStatus":0}
4309:{"Plugin":"memdump","TimeStamp":"1786302135.640128","PID":1673,"PPID":904,"TID":1673,"UserId":1000,"ProcessName":"/usr/libexec/tracker-extract","Method":"do_syscall_64","EventUID":"0x20f0","Syscall":"exit_group","DumpReason":"Process termination","ExitStatus":0}
13129:{"Plugin":"memdump","TimeStamp":"1786302147.449107","PID":1588,"PPID":1577,"TID":1588,"UserId":0,"ProcessName":"/usr/bin/nm-online","Method":"do_syscall_64","EventUID":"0x43f5","Syscall":"exit_group","DumpReason":"Process termination","ExitStatus":1}
20648:{"Plugin":"memdump","TimeStamp":"1786302157.540581","PID":1639,"PPID":904,"TID":1639,"UserId":1000,"ProcessName":"/usr/libexec/tracker-store","Method":"do_syscall_64","EventUID":"0x61d6","Syscall":"exit_group","DumpReason":"Process termination","ExitStatus":0}
35566:{"Plugin":"memdump","TimeStamp":"1786302177.285891","PID":1728,"PPID":1577,"TID":1728,"UserId":0,"ProcessName":"/usr/bin/systemctl","Method":"do_syscall_64","EventUID":"0x9f79","Syscall":"exit_group","DumpReason":"Process termination","ExitStatus":3}
35820:{"Plugin":"memdump","TimeStamp":"1786302177.637439","PID":1577,"PPID":1,"TID":1577,"UserId":0,"ProcessName":"/usr/lib/apt/apt-helper","Method":"do_syscall_64","EventUID":"0xa068","Syscall":"exit_group","DumpReason":"Process termination","ExitStatus":100}
60426:{"Plugin":"memdump","TimeStamp":"1786302210.148393","PID":1750,"PPID":1748,"TID":1750,"UserId":0,"ProcessName":"/usr/bin/dpkg","Method":"do_syscall_64","EventUID":"0xfeb4","Syscall":"exit_group","DumpReason":"Process termination","ExitStatus":0}


```

### Two observations from this run, neither caused by issue #4

Recorded here because this is where they were seen. Both are pre-existing
behaviour that the deployment surfaced, not regressions from it.

**1. `xl top` showed the analysis clone with `maxmem` unlimited.**

All four `misc/*.cfg` set `maxmem` equal to `memory` (2048 for both
sandbox templates, 3000 for both golden VMs), so the configuration grants
a clone no ballooning headroom at all. A running clone reporting no
maximum means the effective value diverges from the config — most likely
in how `xl restore` reconciles the passed config against the settings
inside the saved image, since `clone-ubuntu.pl` copies `maxmem`/`memory`
through verbatim and rewrites only `name=`, `vif=` and `disk=`.

**Not diagnosed.** Confirming it needs `xl list -l <clone>` against the
generated `/tmp/<clone>.config` on Dom0, which was not run.

Why it matters beyond tidiness: **DRAFT-036 item 2 is memory-based clone
admission.** Admission works by reserving what a clone will consume, and
that reservation is meaningless if the clone's ceiling is unbounded at
runtime — one clone can grow into the memory the controller believed it
had reserved for others. Recorded against DRAFT-036 as a precondition.

**2. `drakvuf-ubuntu.sh` timed out on the first two runs after a reboot.**

`dirwatch` guards the trace phase at 180s (`dirwatch.c`), while
`drakvuf-ubuntu.sh` does `sleep 5` then `drakvuf ... -t 120`. Nominal cost
is ~125s, so the headroom is ~55s — and `-t 120` bounds *tracing*, not the
writing of `memdump`/`fileextractor` output afterwards, which for one
earlier run was ~120 MB of dumps beside a 98 MB log.

The trigger was **rebooting Dom0**, not staging the `.bak`: the copy in D3
was followed by successful runs, the machine was rebooted, the next two
runs timed out, and it then settled.

That points at page cache. `cp -a` in D3 read and wrote the 2.1 GB image,
leaving it cached, so the runs straight afterwards found it in memory. A
reboot discards that, and the first `xl restore` has to read the whole
image off disk again. It is still a hypothesis — nothing was measured —
but it is cheap to falsify without another reboot:

```bash
# Run on L1: Xen Dom0                                       [Candidate]
sync && echo 3 > /proc/sys/vm/drop_caches
# then submit one benign sample and watch for the same timeout
```

If that reproduces it, the cause is confirmed and the fix is headroom, not
speed. If it does not, look for something else the reboot resets.

Nothing was lost either time: a trace-phase timeout fires `cleanup.sh` and
retries with a fresh clone, which is the designed behaviour, and it worked.

> **Operational note:** expect the first one or two analyses after a Dom0
> reboot to run slow and possibly time out and retry. Budget for it rather
> than treating it as a fault — or warm the image deliberately with
> `cat state/<origin>.bak > /dev/null` before the first submission.

If it recurs in the steady state, the headroom is the thing to change —
either raise `dirwatch`'s 180s or lower `-t 120` — and that is a
`pipeline-<os>.env` value neither of them is yet.

---

## D6 — confirm delivery integrity, then retire the old paths

```bash
# Run on L1: Xen Dom0                                       [Candidate]
# Dom0-side hash of what was delivered:
sha256sum /malware_processing/ubuntu/benign   # or the finished copy
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

user@drakvuf:~$ sha256sum /malware_processing/ubuntu/benign 
81cd9ba0d4802395d3450d3746a1dad1a24bfa46bbb04d03b094c66f82be8d08  /malware_processing/ubuntu/benign
user@drakvuf:~$ mv /home/user/drakvuf-tools /home/user/drakvuf-tools.retired-issue4


Integrity method chosen (readfile | ExecProc-only) and why: readfile
user@drakvuf:~$ cat  /malware_finished/ubuntu/107529d281ee10a684e91342f0bb19df/preconfig.log 
DRAKVUF injector v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel
Injector starting /home/carlos/Desktop/81cd9ba0d4802395d3450d3746a1dad1a24bfa46bbb04d03b094c66f82be8d08 through PID 1415 TID: 0
[INJECT] TIME:1786293897.553372 METHOD:WriteFile STATUS:SUCCESS PID:1415 FILE:"/malware_processing/ubuntu/benign" ARGUMENTS:"" INJECTED_PID:0 INJECTED_TID:0
Process startup success
DRAKVUF injector v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel
Injector starting /home/carlos/Desktop/81cd9ba0d4802395d3450d3746a1dad1a24bfa46bbb04d03b094c66f82be8d08 through PID 1415 TID: 0
[INJECT] TIME:1786293898.864882 METHOD:ReadFile STATUS:SUCCESS PID:1415 FILE:"/tmp/retrieved-file" ARGUMENTS:"" INJECTED_PID:0 INJECTED_TID:0
Process startup success
DRAKVUF injector v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel
Injector starting /usr/bin/sh through PID 1415 TID: 0
[INJECT] TIME:1786293900.037790 METHOD:ExecProc STATUS:SUCCESS PID:1415 FILE:"/usr/bin/sh" ARGUMENTS:"-c sudo ip addr flush dev eth0 && sudo ip addr add 172.16.1.2/24 dev eth0 && sudo ip route replace default via 172.16.1.1 dev eth0 && echo 'nameserver 1.1.1.1' | sudo tee /etc/resolv.conf" INJECTED_PID:1647 INJECTED_TID:1647
Process startup success
user@drakvuf:~$ sha256sum /tmp/retrieved-file 
81cd9ba0d4802395d3450d3746a1dad1a24bfa46bbb04d03b094c66f82be8d08  /tmp/retrieved-file

Old checkout retired (yes | no): yes -- `/home/user/drakvuf-tools` renamed
to `/home/user/drakvuf-tools.retired-issue4` (the `mv` above). The field
just records that the pre-issue-#4 checkout can no longer be launched by
accident; it is still on disk as the rollback path.

FOLLOW-UP FROM THAT RENAME: `misc/android.cfg` still points its install
cdrom at `file:/home/user/drakvuf-tools/Bliss-v17.8.3-...iso`, which no
longer resolves. Nothing in the analysis pipeline reads it, so nothing is
broken today -- but the golden Android VM cannot be reinstalled from
cdrom until the ISO is moved somewhere stable and that line updated.
Open; not blocking issue #4.
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
Location independence (D4) passed: yes
Apache-stopped delivery (D5) passed: yes
Delivery integrity (D6) method + result: readfile + yes
Deployed commit: 57713fcf631b32f5e5a1f87b030a895952e9a4bc
Date executed: 2026-08-09
Executed by: evilbootloader
```