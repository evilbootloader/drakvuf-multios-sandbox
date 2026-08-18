# Runbook — Android MVP bring-up, and the shared-code changes under it

> **PR:** [#14](https://github.com/evilbootloader/drakvuf-multios-sandbox/pull/14)
> — DRAFT-015, DRAFT-016, DRAFT-028b, DRAFT-030, DRAFT-033, plus the clone
> rename and the clone-teardown fix.
>
> **Status: NOT EXECUTED.** This is a test plan, not a transcript. It
> becomes append-only evidence the moment the first command is run — from
> then on, annotate, never edit.
>
> **Nothing in PR #14 has run on Dom0.** `dirwatch.c` has never even been
> compiled — it needs `<config.h>` and `../xen_helper/xen_helper.h` and only
> builds inside a DRAKVUF tree. Everything else was verified against stub
> harnesses in a development container.

> **ANNOTATION 2026-08-17 — EXECUTED, PARTIALLY.** The two blocks above are
> the pre-execution framing and are left exactly as written. This file is
> now evidence: annotate below, do not edit what is already here.
>
> Steps 0–10, 13 and 14 ran on Dom0 on 2026-08-17 (operator:
> evilbootloader). **Steps 11 and 12 did not run** and their blocks are
> deliberately left empty.
>
> The merge gate passed: `dirwatch.c` compiles, and Ubuntu still analyses
> samples through every changed shared file. Android went further than this
> plan expected — a real 12 MB APK was staged, verified byte-identical,
> installed and launched — but **not once without a human at the guest
> console**. See F1, which is the finding this whole run turns on.

## What this establishes, in order of what it would cost to get wrong

1. **Does the changed `dirwatch.c` compile at all?** Step 1. Nothing below
   it means anything until this passes, and it is the largest body of
   unverified code in the PR.
2. **Is Ubuntu still working?** Steps 4–6. This is the real risk. The PR
   renames a file in Ubuntu's critical path, changes what the guest sees,
   rewrites how every callback is spawned and adds failure paths to the
   clone script — all for Android's benefit. **Ubuntu breaking is the
   expected way this PR fails.**
3. **Does `injector` work against an Android guest at all?** Step 9. No
   `injector` or `drakvuf` operation has ever run against BlissOS. Every
   Android invocation in the repository derives from `--help` captured
   against *Ubuntu*, or from commands typed at a guest console.
4. **Does the Android pipeline analyse a sample?** Steps 10–13.

## Read this before you start

**Stop at the first failure in steps 1–6 and do not continue to Android.**
Steps 7 onward assume a working Ubuntu pipeline as the control. Debugging
Android against a broken shared layer wastes the run.

**Do not pull while an analysis is in flight.** `dirwatch` re-reads the
worker scripts per sample, and this PR renames one of them
(`clone-ubuntu.pl` → `clone.pl`). A pull mid-analysis breaks the next clone.
Stop the launcher first.

**Use benign samples only.** Nothing here needs malware. Steps 4–8 use a
harmless ELF; step 13 uses any APK you would be happy to install.

**Two values in this PR fail silently rather than loudly.** Both have an
explicit check below because "it worked" does not distinguish them:

| Value | Wrong-but-working symptom | Checked at |
|---|---|---|
| `CLONE_LV_SIZE` | Android clone built at 64G instead of 32G — works, over-allocates | Step 10 |
| `INJECTION_PID` | `injector` attaches to the wrong process; no warning | Step 9 |

---

## Step 0 — Baseline, before anything is touched

Everything in step 14 compares against this. Record it even if it looks
uninteresting.

```bash
uptime
xl list
git -C /root/sandbox_project log -1 --oneline
git -C /root/sandbox_project status --porcelain      # expect: empty

sudo lvs -a -o lv_name,lv_size,origin vg-root
sudo blockdev --getsize64 /dev/vg-root/android
sudo blockdev --getsize64 /dev/vg-root/ubuntu
sha256sum /root/sandbox_project/state/android_sandbox.bak
sha256sum /root/sandbox_project/state/ubuntu_sandbox.bak
```

> **Expect leftover clone LVs and possibly running clone domains.** That is
> the defect commit `a66e86e` fixes, not a problem with the baseline. Record
> what is there — step 5 checks it stops happening.

```text
Operator / date: evilbootloader / 2026-08-17
uptime: 08:26:02 up 1 min,  2 users,  load average: 0,70, 0,29, 0,11
xl list (record EVERY domain, not just Domain-0): Domain-0 only
Deployed commit: 8cd4855cb500a223183deff1ef32457a6921cfbe
git status --porcelain (expect empty): ?? misc/android.json
lvs:
  LV                     LSize   Origin        
  android                 32,00g               
  android_sandbox         32,00g               
  lv-root                256,00g               
  ubuntu                  64,00g               
  ubuntu_sandbox          64,00g               
  ubuntu_sandbox-1-clone  64,00g ubuntu_sandbox
Golden ubuntu LV size: 68719476736
Golden android LV size: 34359738368
ubuntu_sandbox.bak sha256: aa9e3b4120b06d4a4409e2f3ce6a59f8868b1fdc83082a6034b64cd476fee4c1
android_sandbox.bak sha256: 516644e223327d5ae5aa17c568240c00127b8d8b88915e70131acf0cd192677c

Clone domains already running at baseline (count): 0
Clone LVs already present at baseline (list): ubuntu_sandbox-1-clone only

OUTPUT OF BRANCH SWITCH
root@drakvuf:~/sandbox_project# git add misc/android.cfg 
root@drakvuf:~/sandbox_project# git commit -m "Android.cfg save"
[master 9b51221] Android.cfg save
 1 file changed, 1 insertion(+), 1 deletion(-)
root@drakvuf:~/sandbox_project# git checkout android-mvp
Branch 'android-mvp' set up to track remote branch 'android-mvp' from 'origin'.
Switched to a new branch 'android-mvp'
root@drakvuf:~/sandbox_project# git log --oneline -1     # expect d24b6d0 or later
8cd4855 (HEAD -> android-mvp, origin/android-mvp) DRAFT-016: add preconfig-android.sh and drakvuf-android.sh
root@drakvuf:~/sandbox_project# git -C /root/sandbox_project fetch origin
root@drakvuf:~/sandbox_project# git -C /root/sandbox_project pull --ff-only
Already up to date.
root@drakvuf:~/sandbox_project# git -C /root/sandbox_project log -1 --format='%H %cd %s'
8cd4855cb500a223183deff1ef32457a6921cfbe Sat Aug 15 11:54:48 2026 +0000 DRAFT-016: add preconfig-android.sh and drakvuf-android.sh
root@drakvuf:~/sandbox_project# git -C /root/sandbox_project status --porcelain     # expect: empty
?? misc/android.json

```

---

## Step 1 — Compile `dirwatch.c`. Do this first.

`dirwatch.c` is the least verified file in the PR: `spawn_argv()`,
`spawn_worker()`, `print_argv()`, `sample_name_admissible()` and the
rejection path are all new, and only the extracted functions have ever been
compiled — against stubs, in a container without glib.

Build it the way the project already builds it, inside the DRAKVUF tree.

```bash
# Adjust to the real checkout. dirwatch.c lives in the DRAKVUF source tree,
# not in this repository's automation/ directory, when it is built.
cp /root/sandbox_project/automation/dirwatch.c \
   /path/to/drakvuf/src/dirwatch/dirwatch.c

cd /path/to/drakvuf
make 2>&1 | tee /tmp/dirwatch-build.log

# Warnings matter here. The new code uses g_rename, g_mkdir_with_parents,
# g_compute_checksum_for_string, g_strescape and iscntrl -- a missing
# include shows up as an implicit-declaration warning, not an error.
grep -nE "warning|error" /tmp/dirwatch-build.log | grep -i dirwatch
```

**Abort condition:** any error, or any implicit-declaration warning naming
`dirwatch.c`. Report the exact text — the includes added were `<ctype.h>`
and `<glib/gstdio.h>`, and a build failure most likely means one of them is
wrong for this glib version.

```text
Build result (pass / fail): pass
Warnings mentioning dirwatch.c: none
glib version (pkg-config --modversion glib-2.0): 2.72.4
Installed binary path and mtime: 
root@drakvuf:/home/user/drakvuf# stat /usr/local/bin/dirwatch
  File: /usr/local/bin/dirwatch
  Size: 107720    	Blocks: 216        IO Block: 4096   regular file
Device: fc00h/64512d	Inode: 15603129    Links: 1
Access: (0755/-rwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2026-08-17 08:34:04.324119812 +0200
Modify: 2026-08-17 08:34:03.100103295 +0200
Change: 2026-08-17 08:34:03.100103295 +0200
 Birth: 2026-08-17 08:34:03.100103295 +0200

```

---

## Step 2 — Static checks on Dom0

These pass in the development container. Running them on Dom0 confirms the
same shellcheck and perl versions agree.

```bash
cd /root/sandbox_project

for f in automation/*.sh; do bash -n "$f" || echo "FAIL bash -n $f"; done
for f in automation/*.sh; do dash -n "$f" || echo "FAIL dash -n $f"; done
shellcheck automation/*.sh ; echo "shellcheck exit=$?"     # expect 0
perl -c automation/clone.pl                                # expect syntax OK

# The new files must be clean WITHOUT the baseline's disables, because
# SC2086 is still disabled repository-wide for DRAFT-011's remaining sites.
shellcheck --norc automation/preconfig-android.sh \
                  automation/drakvuf-android.sh \
                  automation/run_analysis-android.sh
# expect: only SC1091 (sourcing a runtime path) and, for .env files, SC2148

# C4 by grep, not by assertion.
grep -nE '^(VG_NAME|ANALYSIS_BRIDGE|UPLINK_BRIDGE|SUBNET_PREFIX)' \
    automation/pipeline-*.env          # expect: no output

# The rename left nothing behind in live code.
grep -rn "clone-ubuntu" --exclude-dir=.git . \
  | grep -vE "docs/runbooks/|\.github/issue-drafts/|project-assessment\.md"
# expect: only CLAUDE.md's historical note and clone.pl's own header
```

```text
bash -n / dash -n: Correct
shellcheck exit status: 0
perl -c: OK
shellcheck --norc findings:
root@drakvuf:~/sandbox_project# shellcheck --norc automation/preconfig-android.sh \
                  automation/drakvuf-android.sh \
                  automation/run_analysis-android.sh

In automation/preconfig-android.sh line 143:
. "$SCRIPT_DIR/platform.env"
  ^------------------------^ SC1091 (info): Not following: automation/platform.env was not specified as input (see shellcheck -x).


In automation/preconfig-android.sh line 146:
. "$SCRIPT_DIR/pipeline-android.env"
  ^-- SC1091 (info): Not following: automation/pipeline-android.env was not specified as input (see shellcheck -x).


In automation/drakvuf-android.sh line 142:
. "$SCRIPT_DIR/platform.env"
  ^------------------------^ SC1091 (info): Not following: automation/platform.env was not specified as input (see shellcheck -x).


In automation/drakvuf-android.sh line 145:
. "$SCRIPT_DIR/pipeline-android.env"
  ^-- SC1091 (info): Not following: automation/pipeline-android.env was not specified as input (see shellcheck -x).


In automation/drakvuf-android.sh line 280:
TCPDUMPPID=$(ps aux | grep "tcpdump -i $ANALYSIS_BRIDGE.$VLAN" | grep -v grep | awk -F" " '{print $2}')
             ^-- SC2009 (info): Consider using pgrep instead of grepping ps output.


In automation/drakvuf-android.sh line 281:
kill -9 $TCPDUMPPID 1>/dev/null 2>&1
        ^---------^ SC2086 (info): Double quote to prevent globbing and word splitting.

Did you mean: 
kill -9 "$TCPDUMPPID" 1>/dev/null 2>&1


In automation/run_analysis-android.sh line 35:
. "$SCRIPT_DIR/platform.env"
  ^------------------------^ SC1091 (info): Not following: automation/platform.env was not specified as input (see shellcheck -x).


In automation/run_analysis-android.sh line 38:
. "$SCRIPT_DIR/pipeline-android.env"
  ^-- SC1091 (info): Not following: automation/pipeline-android.env was not specified as input (see shellcheck -x).

For more information:
  https://www.shellcheck.net/wiki/SC1091 -- Not following: automation/pipelin...
  https://www.shellcheck.net/wiki/SC2009 -- Consider using pgrep instead of g...
  https://www.shellcheck.net/wiki/SC2086 -- Double quote to prevent globbing ...

C4 grep (expect empty): empty
clone-ubuntu grep: 
root@drakvuf:~/sandbox_project# grep -rn "clone-ubuntu" --exclude-dir=.git . \
  | grep -vE "docs/runbooks/|\.github/issue-drafts/|project-assessment\.md"
^C
root@drakvuf:~/sandbox_project# grep -rn "clone-ubuntu" --exclude-dir=.git .   | grep -vE "docs/runbooks/|\.github/issue-drafts/|project-assessment\.md"
./docs/roadmap/project-roadmap.md:37:| `Bash` non-functional in the dev container (`bwrap: No permissions to create a new namespace`), so `bash -n`/`shellcheck`/`perl -c` could not run there | Lifted. Re-confirmed working in-container on 2026-08-08, 2026-08-09 and 2026-08-11. Current results: `bash -n` and `dash -n` pass on all six `automation/*.sh`; `perl -c` passes on `clone.pl` (named `clone-ubuntu.pl` when those runs were made); `shellcheck` 0.11.0 reports `SC1128` on five of six (licence header above the shebang \u2014 DRAFT-031) |
./docs/checklists/android.md:177:clone-ubuntu.pl
./docs/checklists/android.md:927:git add clone-ubuntu.pl drakvuf-ubuntu.sh preconfig-ubuntu.sh run_analysis-ubuntu.sh
./docs/checklists/android.md:949:> - **DRAFT-033** must land first. `clone-ubuntu.pl` has its per-origin
./docs/checklists/android.md:966:> Also note `clone-ubuntu.pl` hard-codes the Ubuntu saved-state path while
./docs/checklists/android.md:993:- [x] ~~Create `clone-android.pl` from `clone-ubuntu.pl`.~~ Cancelled
./docs/checklists/android.md:1008:# cp -a clone-ubuntu.pl clone-android.pl
./docs/checklists/android.md:1227:> `clone-ubuntu.pl` to the shared `automation/clone.pl` rather than
./docs/checklists/android.md:2554:> **legitimate** markers: `clone-ubuntu.pl`'s stubdomain TODO and \u00a71.3's own
./docs/checklists/android.md:3130:  - `clone-ubuntu.pl`
./docs/architecture/analysis-pipeline.md:504:> `clone-ubuntu.pl` held exactly one OS-specific value \u2014 the `-L64G`
./docs/architecture/analysis-pipeline.md:578:- **DRAFT-033 before DRAFT-015.** ~~`clone-ubuntu.pl` is the template
./CLAUDE.md:114:  *Named `clone-ubuntu.pl` until DRAFT-015 (2026-08-15). It was renamed
./CLAUDE.md:238:`preconfig-ubuntu.sh`, `cleanup.sh`, `clone-ubuntu.pl` and `tcpdump.sh` were
./automation/clone.pl:113:# SHARED BY ALL THREE OS PIPELINES. This file was clone-ubuntu.pl until
root@drakvuf:~/sandbox_project# grep -nE '^(VG_NAME|ANALYSIS_BRIDGE|UPLINK_BRIDGE|SUBNET_PREFIX)' \
    automation/pipeline-*.env          # expect: no output

shellcheck version: 0.8.0
```

---

## Step 3 — Deploy

```bash
# Nothing must be running. This PR renames a worker script.
pgrep -af dirwatch          # expect: no output

cd /root/sandbox_project
git fetch origin
git checkout android-mvp    # or master, once #14 is merged
git log -1 --oneline
git status --porcelain      # expect: empty

ls -l automation/clone.pl           # exists
ls -l automation/clone-ubuntu.pl    # expect: No such file
ls -l automation/platform.env automation/pipeline-android.env \
      automation/run_analysis-android.sh \
      automation/preconfig-android.sh automation/drakvuf-android.sh
```

```text
dirwatch running before deploy (expect none): none
Deployed commit: (already done) 8cd4855
git status --porcelain: ?? misc/android.json
clone.pl present / clone-ubuntu.pl absent: Yes
New files present: Yes
```

---

## Step 4 — Ubuntu regression. This gates the merge.

The single most important step. If Ubuntu no longer analyses a sample, the
PR is wrong regardless of what Android does.

```bash
cd /root/sandbox_project
sudo automation/run_analysis-ubuntu.sh          # leave running, watch stdout
```

In a second terminal, submit one benign sample with an **ordinary** name:

```bash
printf '#!/bin/sh\necho hello\n' > /tmp/benign.sh
sudo cp /tmp/benign.sh /malware_incoming/ubuntu/benign.sh
```

Watch the launcher's output. The spawn lines changed shape in this PR —
they are now `** RUNNING PRECONFIG: [arg] [arg] ...` rather than a single
command string. That is expected and is itself the evidence that argv
spawning is live.

```bash
MD5=$(md5sum -- /tmp/benign.sh | awk '{print $1}')
ls -la "/malware_finished/ubuntu/$MD5/"
head -20 "/malware_finished/ubuntu/$MD5/drakvuf.log"
ls -la "/malware_finished/ubuntu/$MD5/dump" \
       "/malware_finished/ubuntu/$MD5/memdump"
ls -la "/malware_finished/ubuntu/$MD5/tcpdump.pcap"
```

**Abort condition:** no result directory, an empty `drakvuf.log`, or a
`dump`/`memdump` directory that does not exist. Stop and report.

```text
Launcher started cleanly (y/n): y
Spawn lines show [bracketed] argv (y/n): y
Result directory created: y
drakvuf.log first lines: 
root@drakvuf:/home/user# head -20 "/malware_finished/ubuntu/$MD5/drakvuf.log"
1786948765.264361 DRAKVUF v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel
[SYSCALLS] Syscall table breakpoints set
[FILETRACER] Hooked do_syscall_64
[FILEEXTRACTOR-LINUX] Hooked do_syscall_64
[FILETRACER] syscall_cb fired (count=1) rdi=0xffffb3ccc1917f58 rsi=0xe4
[SYSCALLS] linux_cb fired (count=1) trap=do_syscall_64 rdi=0xffffb3ccc1917f58 rsi=0xe4
[FILETRACER] syscall_cb fired (count=2) rdi=0xffffb3ccc12fff58 rsi=0xc
[SYSCALLS] linux_cb fired (count=2) trap=clock_gettime rdi=0xffffb3ccc12fff58 rsi=0xc
[FILETRACER] syscall_cb fired (count=3) rdi=0xffffb3ccc1917f58 rsi=0xe4
[SYSCALLS] linux_cb fired (count=3) trap=brk rdi=0xffffb3ccc1917f58 rsi=0xe4
{"Plugin": "inject", "TimeStamp": "1786948766.100091", "Method": "ExecProc", "Status": "Success", "ProcessName": "/home/carlos/Desktop/benign.sh", "Arguments": "", "InjectedPid": 1721, "InjectedTid": 1721}
{"Plugin":"syscall","TimeStamp":"1786948766.103913","PID":1050,"PPID":904,"TID":1050,"UserId":1000,"ProcessName":"/usr/bin/gnome-shell","Method":"clock_gettime","EventUID":"0x2a","ThreadName":"gnome-shell","Module":"linux","vCPU":0,"CR3":"0xb276000","Syscall":228,"NArgs":0,"Type":"x64"}
{"Plugin":"sysret","TimeStamp":"1786948766.104447","PID":1050,"PPID":904,"TID":1050,"UserId":1000,"ProcessName":"/usr/bin/gnome-shell","Method":"clock_gettime","EventUID":"0x2b","Module":"linux","vCPU":0,"CR3":"0xb276000","Syscall":228,"Ret":"0x0","Info":""}
{"Plugin":"syscall","TimeStamp":"1786948766.113459","PID":1721,"PPID":1415,"TID":1721,"UserId":0,"ProcessName":"/usr/bin/dash","Method":"brk","EventUID":"0x2c","ThreadName":"benign.sh","Module":"linux","vCPU":0,"CR3":"0x76f0000","Syscall":12,"NArgs":1,"Type":"x64","addr":"0x0"}
{"Plugin":"sysret","TimeStamp":"1786948766.113876","PID":1721,"PPID":1415,"TID":1721,"UserId":0,"ProcessName":"/usr/bin/dash","Method":"brk","EventUID":"0x2d","Module":"linux","vCPU":0,"CR3":"0x76f0000","Syscall":12,"Ret":"0x0","Info":""}
{"Plugin":"syscall","TimeStamp":"1786948766.118975","PID":1050,"PPID":904,"TID":1050,"UserId":1000,"ProcessName":"/usr/bin/gnome-shell","Method":"clock_gettime","EventUID":"0x2e","ThreadName":"gnome-shell","Module":"linux","vCPU":0,"CR3":"0xb276000","Syscall":228,"NArgs":0,"Type":"x64"}
{"Plugin":"sysret","TimeStamp":"1786948766.119270","PID":1050,"PPID":904,"TID":1050,"UserId":1000,"ProcessName":"/usr/bin/gnome-shell","Method":"clock_gettime","EventUID":"0x2f","Module":"linux","vCPU":0,"CR3":"0xb276000","Syscall":228,"Ret":"0x0","Info":""}
{"Plugin":"syscall","TimeStamp":"1786948766.122647","PID":445,"PPID":1,"TID":472,"UserId":0,"ProcessName":"/sbin/NetworkManager","Method":"clock_gettime","EventUID":"0x30","ThreadName":"gmain","Module":"linux","vCPU":0,"CR3":"0xad22000","Syscall":228,"NArgs":0,"Type":"x64"}
{"Plugin":"sysret","TimeStamp":"1786948766.122952","PID":445,"PPID":1,"TID":472,"UserId":0,"ProcessName":"/sbin/NetworkManager","Method":"clock_gettime","EventUID":"0x31","Module":"linux","vCPU":0,"CR3":"0xad22000","Syscall":228,"Ret":"0x0","Info":""}
{"Plugin":"syscall","TimeStamp":"1786948766.127883","PID":445,"PPID":1,"TID":472,"UserId":0,"ProcessName":"/sbin/NetworkManager","Method":"inotify_add_watch","EventUID":"0x32","ThreadName":"gmain","Module":"linux","vCPU":0,"CR3":"0xad22000","Syscall":254,"NArgs":3,"Type":"x64","fd":"0xd","pathname":"/etc/NetworkManager/VPN","mask":"0x1002fce"}
dump/ and memdump/ both exist: yes
tcpdump.pcap present and non-empty: yes
Sample moved out of /malware_incoming (y/n): yes
```

---

## Step 5 — The clone is destroyed when the run SUCCEEDS

Commit `a66e86e`. Before it, `cleanup()` ran only on the timeout path, so a
successful analysis left its clone running until the next sample claimed the
same VLAN slot — with NAT'd egress, after the trace and the pcap had both
stopped.

Immediately after step 4 finishes, with the launcher still running and no
sample in flight:

```bash
sudo xl list
```

**Expected:** `Domain-0` alone. Any `ubuntu_sandbox-N-clone` still listed
means the fix did not take.

```bash
# The LV is a separate matter and is EXPECTED to persist -- cleanup.sh
# destroys the domain but never removes the snapshot. clone.pl removes it
# when it next reuses the name, so the count is bounded by MAX_CLONES.
sudo lvs -a -o lv_name,lv_size,origin vg-root | grep clone
```

```text
xl list after a successful analysis (expect Domain-0 only): 
root@drakvuf:/home/user# sudo xl list
Name                                        ID   Mem VCPUs	State	Time(s)
Domain-0                                     0  4096     4     r-----     245.1

Clone LVs remaining (expected: up to MAX_CLONES, bounded):
root@drakvuf:/home/user# sudo lvs -a -o lv_name,lv_size,origin vg-root | grep clone
  ubuntu_sandbox-1-clone  64,00g ubuntu_sandbox
```

---

## Step 6 — The guest sees the submitted filename, and survives a space

DRAFT-030's guest half. Two things at once: the leaf is now the submitted
name rather than the SHA-256, and a name containing a space must survive
every hop.

```bash
sudo cp /tmp/benign.sh "/malware_incoming/ubuntu/benign sample.sh"
```

Watch the preconfig spawn line: the sample name must appear as **one**
bracketed argv element, `[benign sample.sh]`, not as two.

```bash
MD5=$(md5sum -- "/tmp/benign.sh" | awk '{print $1}')
grep -i writefile "/malware_finished/ubuntu/$MD5/preconfig.log" | head -5

# The pcap is the check that matters for the quoting fix: before this PR,
# tcpdump.sh's bare md5sum returned an EMPTY digest for a spaced name and
# the capture went to /malware_finished/ubuntu//tcpdump.pcap.
ls -la "/malware_finished/ubuntu/$MD5/tcpdump.pcap"
ls -la /malware_finished/ubuntu/tcpdump.pcap 2>/dev/null   # expect: absent
```

Confirm the guest path is the name and not a hash:

```bash
grep -o '/home/carlos/Desktop/[^ "]*' \
    "/malware_finished/ubuntu/$MD5/preconfig.log" | head -3
```

```text
Sample name appeared as ONE argv element (y/n): y
writefile -e path recorded in preconfig.log: 
root@drakvuf:/home/user# grep -i writefile "/malware_finished/ubuntu/$MD5/preconfig.log" | head -5
[INJECT] TIME:1786949030.671495 METHOD:WriteFile STATUS:SUCCESS PID:1415 FILE:"/malware_processing/ubuntu/benign sample.sh" ARGUMENTS:"" INJECTED_PID:0 INJECTED_TID:0
Result directory for the spaced sample: /malware_finished/ubuntu/d604a220708aa59433ba410986cd4ffa/
tcpdump.pcap in the right directory (y/n): y
Stray /malware_finished/ubuntu/tcpdump.pcap present? (expect: no): no
```

> **ANNOTATION 2026-08-17 — the guest-path check above uses the wrong line
> and cannot work. See F6.** The commands are left as executed; the
> corrected method is here.
>
> `injector` writes the **Dom0-side** path into the `[INJECT]` line's
> `FILE:` field — which is why the evidence above reads
> `FILE:"/malware_processing/ubuntu/benign sample.sh"`, the *processing*
> path, not the guest destination. `grep -i writefile` therefore confirms
> nothing about `$GUEST_STAGING_DIR/<submitted filename>` (C5).
>
> The follow-up `grep -o '/home/carlos/Desktop/[^ "]*'` is worse than
> ineffective: `[^ "]*` stops at the first space, so on a sample named
> `benign sample.sh` it would print `/home/carlos/Desktop/benign` and
> truncate away the exact property this step exists to test. Its output was
> not pasted above, so nothing caught it.
>
> The guest destination appears only in `injector`'s own startup line.
> Use:
>
> ```bash
> # Both injections, full guest paths, spaces intact:
> grep -n 'Injector starting' "/malware_finished/ubuntu/$MD5/preconfig.log"
>
> # Just the path, bracketed so leading/trailing whitespace is visible:
> sed -n 's/^Injector starting \(.*\) through PID .*/[\1]/p' \
>     "/malware_finished/ubuntu/$MD5/preconfig.log"
> ```
>
> Expected first line: `[/home/carlos/Desktop/benign sample.sh]` — one
> bracketed path containing a space. The second `Injector starting` line is
> the network `execproc` and names `/usr/bin/sh`, which is correct and not
> what this check is about.
>
> Identical for Android: `preconfig-android.sh` writes the same log, and
> the expected value there is `[/data/local/tmp/<submitted filename>]`.
>
> **C5 is therefore still unverified for Ubuntu by this run.** Step 4's
> `drakvuf.log` does carry independent evidence — `"ProcessName":
> "/home/carlos/Desktop/benign.sh"` in the inject line — but that is the
> unspaced sample. The spaced one was never confirmed to reach the guest
> under its full name. Re-run the corrected commands above against the
> existing `d604a220…` result directory; it needs no VM.

---

## Step 7 — `clone.pl` failure paths

DRAFT-033. Each must exit non-zero, print a **named** diagnostic on stderr,
and print **nothing** on stdout. Stdout is the only channel `dirwatch` reads,
so a diagnostic leaking there would be parsed as a domain id.

Stop the launcher first.

```bash
cd /root/sandbox_project

run_case() {                       # prints stdout in quotes so empty is visible
    out=$(sudo env "$@" 2>/tmp/clone-err.txt); rc=$?
    echo "exit=$rc stdout='$out'"; cat /tmp/clone-err.txt
}

# Baseline: a normal clone still works and prints ONLY a domain id.
run_case CLONE_LV_SIZE=64G automation/clone.pl ubuntu_sandbox 1 misc/ubuntu_sandbox.cfg
sudo automation/cleanup.sh <the domid printed> 1
sudo lvremove -f /dev/vg-root/ubuntu_sandbox-1-clone

# Failure paths.
run_case automation/clone.pl ubuntu_sandbox 1              # too few arguments
run_case automation/clone.pl ubuntu_sandbox abc misc/ubuntu_sandbox.cfg
run_case automation/clone.pl ubuntu_sandbox 0 misc/ubuntu_sandbox.cfg
run_case automation/clone.pl ubuntu_sandbox 255 misc/ubuntu_sandbox.cfg
run_case automation/clone.pl no_such_domain 1 misc/ubuntu_sandbox.cfg
run_case automation/clone.pl ubuntu_sandbox 1 /nonexistent.cfg

# Missing saved state -- rename it aside, do NOT delete it.
sudo mv state/ubuntu_sandbox.bak state/ubuntu_sandbox.bak.hold
run_case automation/clone.pl ubuntu_sandbox 1 misc/ubuntu_sandbox.cfg
sudo mv state/ubuntu_sandbox.bak.hold state/ubuntu_sandbox.bak
sha256sum state/ubuntu_sandbox.bak      # must match step 0

# No partial snapshot may survive any of the above.
sudo lvs -a -o lv_name vg-root | grep clone
# And no temporary config either -- previously never unlinked.
ls /tmp/*-clone.config 2>/dev/null      # expect: absent
```

```text
Baseline clone stdout (expect a bare domain id):4
too few arguments        exit / stdout / stderr: 
exit=2 stdout=''
clone.pl: expected 3 arguments, got 2
clone.pl: Usage: clone.pl <origin domain> <vlan> <path/to/domain.cfg>

vlan abc                 exit / stdout / stderr:
root@drakvuf:~/sandbox_project# run_case automation/clone.pl ubuntu_sandbox abc misc/ubuntu_sandbox.cfg
exit=2 stdout=''
clone.pl: vlan must be a positive integer, got: 'abc'
root@drakvuf:~/sandbox_project# run_case automation/clone.pl ubuntu_sandbox 0 misc/ubuntu_sandbox.cfg
exit=2 stdout=''

vlan 0                   exit / stdout / stderr:
root@drakvuf:~/sandbox_project# run_case automation/clone.pl ubuntu_sandbox 0 misc/ubuntu_sandbox.cfg
exit=2 stdout=''
clone.pl: vlan must be a positive integer, got: '0'

vlan 255                 exit / stdout / stderr:
root@drakvuf:~/sandbox_project# run_case automation/clone.pl ubuntu_sandbox 255 misc/ubuntu_sandbox.cfg
exit=2 stdout=''
clone.pl: vlan must be at most 254 (it is the third octet of the gateway address), got: 255

missing origin LV        exit / stdout / stderr:
root@drakvuf:~/sandbox_project# run_case automation/clone.pl no_such_domain 1 misc/ubuntu_sandbox.cfg
exit=3 stdout=''
clone.pl: origin logical volume not found: /dev/vg-root/no_such_domain
clone.pl:   VG_NAME=vg-root. Check `lvs` and the origin domain argument.

missing config           exit / stdout / stderr:
root@drakvuf:~/sandbox_project# run_case automation/clone.pl ubuntu_sandbox 1 /nonexistent.cfg
exit=3 stdout=''
clone.pl: domain config not found: /nonexistent.cfg

missing saved state      exit / stdout / stderr:
root@drakvuf:~/sandbox_project# run_case automation/clone.pl ubuntu_sandbox 1 misc/ubuntu_sandbox.cfg
exit=3 stdout=''
clone.pl: saved memory image not found or unreadable: /root/sandbox_project/automation/../state/ubuntu_sandbox.bak
clone.pl:   Expected <repo root>/state/<origin domain>.bak -- see docs/runbooks/deploy-repo-relative-paths.md

Any stdout on a failure path? (must be NO): no
Partial snapshots left behind (must be none): no
/tmp/*-clone.config left behind (must be none): no
ubuntu_sandbox.bak checksum unchanged: aa9e3b4120b06d4a4409e2f3ce6a59f8868b1fdc83082a6034b64cd476fee4c1
```

---

## Step 8 — Filename admission and the rejected directory

DRAFT-030's Dom0 half. Restart the Ubuntu launcher.

```bash
# Admitted: unusual but safe. Each should analyse normally.
sudo cp /tmp/benign.sh "/malware_incoming/ubuntu/-leading-dash.sh"
sudo cp /tmp/benign.sh "/malware_incoming/ubuntu/quote'name.sh"

# Rejected: a control character in the name.
sudo cp /tmp/benign.sh "$(printf '/malware_incoming/ubuntu/tab\there.sh')"
```

The rejected one should log `** REJECTED SAMPLE: ... name contains a control
character; moved to ...` and be moved to `/malware_finished/ubuntu/rejected/`
under the SHA-256 of its own name.

```bash
ls -la /malware_finished/ubuntu/rejected/
ls -la /malware_incoming/ubuntu/          # the rejected sample must be GONE
```

**Why "gone" matters:** if it is still there, the scan will re-reject and
re-log it every cycle. That loop is what the move exists to stop.

```text
-leading-dash.sh analysed normally (y/n): y
quote'name.sh analysed normally (y/n): y
Rejection log line (paste verbatim): ** REJECTED SAMPLE: "tab\there.sh": name contains a control character; moved to /malware_finished/ubuntu/rejected/7c8f19524ab50d534a7c428cb70a7903873885b8b3c4753a1e69481011f27576
File present in /malware_finished/ubuntu/rejected/ (y/n): y
/malware_incoming/ubuntu/ empty afterwards (y/n): y
Did the rejection repeat on later scans? (must be NO): NO
```

---

## Step 9 — THE ANDROID GATE: does `injector` work against BlissOS at all?

**Do not skip this and do not reorder it.** No `injector` operation has ever
run against an Android guest. If `writefile` does not work here, every
Android step below fails for a reason that has nothing to do with the
scripts.

Stop the Ubuntu launcher. Build a clone by hand.

```bash
cd /root/sandbox_project
sudo env CLONE_LV_SIZE=32G automation/clone.pl \
    android_sandbox 1 misc/android_sandbox.cfg
# -> records the domid; nothing else on stdout

sudo xl unpause android_sandbox-1-clone
sudo xl list
```

Confirm the anchor PID this template actually has, rather than trusting any
document:

```bash
sudo vmi-process-list -n android_sandbox-1-clone \
    -j /root/sandbox_project/profiles/android.json | grep -i nano
```

**`pipeline-android.env` says `INJECTION_PID=3164`.** `docs/checklists/android.md`
§1.5 still says 3163. If the live value is neither, that is a finding — record
it and use the live value for the rest of this runbook.

```bash
PROFILE=/root/sandbox_project/profiles/android.json
DOM=8
PID=3164

printf 'benign probe %s\n' "$(date)" > /tmp/probe.txt

# 1. writefile -- the first injector operation ever attempted on Android.
sudo injector -r "$PROFILE" -d "$DOM" -i "$PID" -m writefile \
    -B /tmp/probe.txt -e /data/local/tmp/probe.txt

# 2. readfile back, to prove it landed intact.
sudo injector -r "$PROFILE" -d "$DOM" -i "$PID" -m readfile \
    -B /tmp/probe.pulled -e /data/local/tmp/probe.txt

sha256sum /tmp/probe.txt /tmp/probe.pulled     # must match
```

**Abort condition:** the hashes differ, or either injection fails. Stop and
report — DRAFT-016's scripts cannot work and the cause is below them.

We need to recreate the image with the process in fg.

```text
Clone created, domid: 8
Clone unpaused and listed (y/n): y
Anchor PID read from the LIVE template:
  matches pipeline-android.env's 3164? (y/n): y
  matches android.md §1.5's 3163?      (y/n): n

writefile result: SUCCESS (but we need to find another anchor PID)
readfile result: SUCCESS (but we need to find another anchor PID on the MAIN GUI)
sha256 of /tmp/probe.txt: 285b19505237567f014010d84cc9897d0263b125da2ed9b5ec55f436610840f6
sha256 of /tmp/probe.pulled: 285b19505237567f014010d84cc9897d0263b125da2ed9b5ec55f436610840f6
IDENTICAL? (y/n): y
```

> **ANNOTATION 2026-08-17 — how this step actually went, and what it cost.**
>
> The first attempt at this step **hung**: `writefile` produced no output and
> never returned, with no error and no success line. That is the symptom
> that opened F1. `injector` waits for the target PID to be scheduled and
> has no timeout, and the anchor — a backgrounded `nano` blocked on a
> console tty read, captured in that state by `xl save` — is never
> scheduled on a freshly restored clone. Every injection recorded above and
> below succeeded **only after a manual `fg` plus keypresses at the guest
> console**. Read every Android PASS in this runbook as human-assisted.
>
> The round-trip was also repeated later, on domid 24, against a **12 MB
> real APK** rather than the text probe this step specifies — a much
> stronger result than planned:
>
> ```text
> [INJECT] TIME:1786964418.366251 METHOD:WriteFile STATUS:SUCCESS PID:3164 FILE:"/home/user/Downloads/F-Droid.apk"
> [INJECT] TIME:1786964441.059037 METHOD:ReadFile  STATUS:SUCCESS PID:3164 FILE:"/tmp/F-Droid.pulled"
> 985f5181d48bb6bafd54083a048b391271e0ab28385881cc41294fb01a222762  /home/user/Downloads/F-Droid.apk
> 985f5181d48bb6bafd54083a048b391271e0ab28385881cc41294fb01a222762  /tmp/F-Droid.pulled
> ```
>
> **The headline answer to this step's question is YES:** `injector`
> `writefile` and `readfile` both work against BlissOS, byte-exact, at
> 12 MB. Nothing below step 9 failed for an introspection reason.
>
> Note for anyone reading `preconfig.log` later: the `[INJECT]` line's
> `FILE:` field records the **Dom0-side** path in both directions. The
> guest path appears only in the `Injector starting …` line — see F6.

---

## Step 10 — The Android clone is 32G, not 64G

Still on the clone from step 9.

```bash
sudo lvs -a -o lv_name,lv_size,origin vg-root | grep android
```

**Expected:** `android_sandbox-1-clone  32,00g  android_sandbox`.

A `64,00g` row means `CLONE_LV_SIZE` never reached the Perl — the clone works
either way, which is exactly why this is checked by size and not by success.

Then check the launcher's own export path, which is what production uses:

```bash
grep -n 'export CLONE_LV_SIZE' automation/run_analysis-android.sh
( . automation/pipeline-android.env; echo "$CLONE_LV_SIZE" )   # expect 32G
```

```text
Clone LV size (expect 32,00g): 32,00g
export line present in run_analysis-android.sh (y/n): y
CLONE_LV_SIZE from the env file: 32G
```

---

## Step 11 — Android network configuration

`preconfig-android.sh`'s second injection. This is the mixed-quoting
sequence: `$VLAN` and `$GUEST_NAMESERVER` expand on Dom0, while `$APK` and
`$(pm path …)` must reach the guest untouched.

Run the script's exact second injection by hand first, so a failure is
attributable. Print the command before running it.

```bash
cd /root/sandbox_project
. automation/platform.env
. automation/pipeline-android.env
VLAN=1

NETCFG='while IFS=" " read -r a n v; do [ "$a" = export ] && export "$n=$v"; done < /data/system/environ/classpath; '
NETCFG="${NETCFG}"'APK="$(pm path com.example.ethernetconfig | sed "s/^package://")"; '
NETCFG="${NETCFG}"'CLASSPATH="$APK" /system/bin/app_process64 / '
NETCFG="${NETCFG}com.example.ethernetconfig.network.EthernetConfigurator STATIC eth0 "
NETCFG="${NETCFG}${SUBNET_PREFIX}.${VLAN}.2 24 ${SUBNET_PREFIX}.${VLAN}.1 ${GUEST_NAMESERVER} none && "
NETCFG="${NETCFG}settings put global private_dns_mode off"

printf '%s\n' "$NETCFG"
```

**Check the printed string before injecting.** `172.16.1.2`, `172.16.1.1`
and `1.1.1.1` must be expanded; `$APK` and `$(pm path …)` must still be
literal. If `$(pm path …)` is missing or `CLASSPATH=` is empty, the Dom0
shell evaluated it — the guest would receive a command that is well-formed
and wrong, and nothing would error.

```bash
sudo injector -r "$PROFILE" -d "$DOM" -i "$PID" -m execproc \
    -e /system/bin/sh -f "-c" -f "$NETCFG"

# Verify from Dom0, not from inside the guest.
sudo xl network-list android_sandbox-1-clone
sudo ovs-vsctl show | grep -A2 vif        # the clone's vif must carry tag: 1
```

```text
NETCFG as printed (paste verbatim):
  Dom0 values expanded? (y/n): y
  $APK and $(pm path ...) still literal? (y/n): y
injector exit status: SUCCESS
Guest reachable at 172.16.1.2 from Dom0? (ping / arp): ping working
vif tag (expect 1): 1
```

---

## Step 12 — Android native ELF, end to end

Restart the pipeline properly.

```bash
cd /root/sandbox_project
sudo automation/run_analysis-android.sh
```

The launcher refuses to start if another `dirwatch` is running — that guard
is new in this PR. If it refuses, confirm the Ubuntu launcher really is
stopped rather than working around it.

Submit a benign native ELF built for the guest's architecture:

```bash
# x86_64, since BlissOS here is x86_64.
printf 'int main(void){return 0;}' > /tmp/benign.c
gcc -static -o /tmp/benign-android /tmp/benign.c
sudo cp /tmp/benign-android /malware_incoming/android/benign-android
```

```bash
MD5=$(md5sum -- /tmp/benign-android | awk '{print $1}')
ls -la "/malware_finished/android/$MD5/"
head -30 "/malware_finished/android/$MD5/drakvuf.log"
```

The trace line should show `-m execproc -e /data/local/tmp/benign-android` —
the direct-execve path, not the shell path.

```text
Launcher started (or refused, with reason): yes
Result directory: /malware_finished/android/4d8c47123ed86f8905c7a45053e1d322
drakvuf.log first lines: 
root@drakvuf:~/sandbox_project# head -30 "/malware_finished/android/$MD5/drakvuf.log"
1786961820.314039 DRAKVUF v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel
[SYSCALLS] Syscall table breakpoints set
[FILETRACER] Hooked do_syscall_64
[FILEEXTRACTOR-LINUX] Hooked do_syscall_64
[FILETRACER] syscall_cb fired (count=1) rdi=0xffffb378c5c33f58 rsi=0xa
[SYSCALLS] linux_cb fired (count=1) trap=do_syscall_64 rdi=0xffffb378c5c33f58 rsi=0xa
[FILETRACER] syscall_cb fired (count=2) rdi=0xffffb378c10a7f58 rsi=0x0
[SYSCALLS] linux_cb fired (count=2) trap=mprotect rdi=0xffffb378c10a7f58 rsi=0x0
[FILETRACER] syscall_cb fired (count=3) rdi=0xffffb378c10a7f58 rsi=0x10f
[SYSCALLS] linux_cb fired (count=3) trap=read rdi=0xffffb378c10a7f58 rsi=0x10f
{"Plugin": "inject", "TimeStamp": "1786961829.525009", "Method": "ExecProc", "Status": "Success", "ProcessName": "/data/local/tmp/benign-android", "Arguments": "", "InjectedPid": 3344, "InjectedTid": 3344}
{"Plugin":"syscall","TimeStamp":"1786961829.538315","PID":3344,"PPID":3164,"TID":3344,"UserId":0,"ProcessName":"/local/tmp/benign-android","Method":"mprotect","EventUID":"0x4154","ThreadName":"benign-android","Module":"linux","vCPU":0,"CR3":"0x2d85002","Syscall":10,"NArgs":3,"Type":"x64","start":"0x4c1000","len":"0x4000","prot":"PROT_READ"}
{"Plugin":"sysret","TimeStamp":"1786961829.539057","PID":3344,"PPID":3164,"TID":3344,"UserId":0,"ProcessName":"/local/tmp/benign-android","Method":"mprotect","EventUID":"0x4155","Module":"linux","vCPU":0,"CR3":"0x2d85002","Syscall":10,"Ret":"0x0","Info":""}
{"Plugin":"filetracer","TimeStamp":"1786961829.542850","PID":1816,"PPID":1613,"TID":1912,"UserId":1000,"ProcessName":"/system/bin/app_process64","Method":"do_syscall_64","EventUID":"0x4156","Syscall":"read","ThreadName":"SensorService","FileName":"/input/event2","FileHandle":183,"count":"24"}
{"Plugin":"syscall","TimeStamp":"1786961829.542850","PID":1816,"PPID":1613,"TID":1912,"UserId":1000,"ProcessName":"/system/bin/app_process64","Method":"read","EventUID":"0x4156","ThreadName":"SensorService","Module":"linux","vCPU":0,"CR3":"0x3cdc7003","Syscall":0,"NArgs":3,"Type":"x64","fd":"0xb7","buf":"0x7f56cf18d260","count":"0x18"}
{"Plugin":"sysret","TimeStamp":"1786961829.543231","PID":1816,"PPID":1613,"TID":1912,"UserId":1000,"ProcessName":"/system/bin/app_process64","Method":"read","EventUID":"0x4157","Module":"linux","vCPU":0,"CR3":"0x3cdc7003","Syscall":0,"Ret":"0x0","Info":""}
{"Plugin":"syscall","TimeStamp":"1786961829.546418","PID":1816,"PPID":1613,"TID":1912,"UserId":1000,"ProcessName":"/system/bin/app_process64","Method":"ppoll","EventUID":"0x4158","ThreadName":"SensorService","Module":"linux","vCPU":0,"CR3":"0x3cdc7003","Syscall":271,"NArgs":0,"Type":"x64"}
{"Plugin":"sysret","TimeStamp":"1786961829.546608","PID":1816,"PPID":1613,"TID":1912,"UserId":1000,"ProcessName":"/system/bin/app_process64","Method":"ppoll","EventUID":"0x4159","Module":"linux","vCPU":0,"CR3":"0x3cdc7003","Syscall":271,"Ret":"0x0","Info":""}
{"Plugin":"filetracer","TimeStamp":"1786961829.549780","PID":1816,"PPID":1613,"TID":1912,"UserId":1000,"ProcessName":"/system/bin/app_process64","Method":"do_syscall_64","EventUID":"0x415a","Syscall":"read","ThreadName":"SensorService","FileName":"/input/event2","FileHandle":183,"count":"24"}
{"Plugin":"syscall","TimeStamp":"1786961829.549780","PID":1816,"PPID":1613,"TID":1912,"UserId":1000,"ProcessName":"/system/bin/app_process64","Method":"read","EventUID":"0x415a","ThreadName":"SensorService","Module":"linux","vCPU":0,"CR3":"0x3cdc7003","Syscall":0,"NArgs":3,"Type":"x64","fd":"0xb7","buf":"0x7f56cf18d260","count":"0x18"}
{"Plugin":"sysret","TimeStamp":"1786961829.549984","PID":1816,"PPID":1613,"TID":1912,"UserId":1000,"ProcessName":"/system/bin/app_process64","Method":"read","EventUID":"0x415b","Module":"linux","vCPU":0,"CR3":"0x3cdc7003","Syscall":0,"Ret":"0x0","Info":""}
{"Plugin":"syscall","TimeStamp":"1786961829.553080","PID":1816,"PPID":1613,"TID":1912,"UserId":1000,"ProcessName":"/system/bin/app_process64","Method":"ppoll","EventUID":"0x415c","ThreadName":"SensorService","Module":"linux","vCPU":0,"CR3":"0x3cdc7003","Syscall":271,"NArgs":0,"Type":"x64"}
{"Plugin":"sysret","TimeStamp":"1786961829.553290","PID":1816,"PPID":1613,"TID":1912,"UserId":1000,"ProcessName":"/system/bin/app_process64","Method":"ppoll","EventUID":"0x415d","Module":"linux","vCPU":0,"CR3":"0x3cdc7003","Syscall":271,"Ret":"0x0","Info":""}
{"Plugin":"filetracer","TimeStamp":"1786961829.556488","PID":1816,"PPID":1613,"TID":1912,"UserId":1000,"ProcessName":"/system/bin/app_process64","Method":"do_syscall_64","EventUID":"0x415e","Syscall":"read","ThreadName":"SensorService","FileName":"/input/event2","FileHandle":183,"count":"24"}
{"Plugin":"syscall","TimeStamp":"1786961829.556488","PID":1816,"PPID":1613,"TID":1912,"UserId":1000,"ProcessName":"/system/bin/app_process64","Method":"read","EventUID":"0x415e","ThreadName":"SensorService","Module":"linux","vCPU":0,"CR3":"0x3cdc7003","Syscall":0,"NArgs":3,"Type":"x64","fd":"0xb7","buf":"0x7f56cf18d260","count":"0x18"}
{"Plugin":"sysret","TimeStamp":"1786961829.556699","PID":1816,"PPID":1613,"TID":1912,"UserId":1000,"ProcessName":"/system/bin/app_process64","Method":"read","EventUID":"0x415f","Module":"linux","vCPU":0,"CR3":"0x3cdc7003","Syscall":0,"Ret":"0x0","Info":""}
{"Plugin":"syscall","TimeStamp":"1786961829.560062","PID":1816,"PPID":1613,"TID":1912,"UserId":1000,"ProcessName":"/system/bin/app_process64","Method":"ppoll","EventUID":"0x4160","ThreadName":"SensorService","Module":"linux","vCPU":0,"CR3":"0x3cdc7003","Syscall":271,"NArgs":0,"Type":"x64"}
{"Plugin":"syscall","TimeStamp":"1786961829.560650","PID":1,"PPID":0,"TID":1,"UserId":0,"ProcessName":"/system/bin/init","Method":"waitid","EventUID":"0x4163","ThreadName":"init","Module":"linux","vCPU":0,"CR3":"0x3f2c005","Syscall":247,"NArgs":0,"Type":"x64"}
{"Plugin":"sysret","TimeStamp":"1786961829.560924","PID":1,"PPID":0,"TID":1,"UserId":0,"ProcessName":"/system/bin/init","Method":"waitid","EventUID":"0x4164","Module":"linux","vCPU":0,"CR3":"0x3f2c005","Syscall":247,"Ret":"0x0","Info":""}
{"Plugin":"filetracer","TimeStamp":"1786961829.564070","PID":1,"PPID":0,"TID":1,"UserId":0,"ProcessName":"/system/bin/init","Method":"do_syscall_64","EventUID":"0x4165","Syscall":"read","ThreadName":"init","FileName":"/input/event2","FileHandle":21,"count":"24"}

Execution path taken (execve direct / shell):
{"Plugin": "inject", "TimeStamp": "1786961829.525009", "Method": "ExecProc", "Status": "Success", "ProcessName": "/data/local/tmp/benign-android", "Arguments": "", "InjectedPid": 3344, "InjectedTid": 3344}

Syscalls observed in the trace (y/n, a few examples): y
tcpdump.pcap present: yes
xl list clean afterwards (y/n): y
```

---

## Step 13 — Android APK. The least verified path in the PR.

`monkey -p <pkg> -c android.intent.category.LAUNCHER 1` is used because
`pm install` does not report which activity to start, and an APK need not
declare a launcher activity at all. DRAFT-016 says to settle this against a
real APK rather than on paper. **This step is that settling.**

Use any APK you are willing to install in a disposable clone.

```bash
sudo cp /path/to/benign.apk /malware_incoming/android/benign.apk
```

```bash
MD5=$(md5sum -- /path/to/benign.apk | awk '{print $1}')
head -40 "/malware_finished/android/$MD5/drakvuf.log"
```

Four things can fail independently here. Record which:

1. The **selector** — did it take the APK path at all? The trace line should
   show `-e /system/bin/sh -f -c -f <the install+launch sequence>`.
2. The **install** — did `pm install` succeed? `filetracer` should show
   `/data/app/<pkg>/` being populated. `execproc` reports success when the
   process *starts*, so the install result is read from the trace, not from
   an exit status.
3. The **package-name diff** — did it resolve a package? If it resolved
   nothing, `monkey` was never run.
4. The **launch** — did `monkey` start anything?

```text
Trace line shows the shell path (y/n): y
pm install evidence in filetracer (/data/app/<pkg>/ populated?): /data/local/tmp/F-Droid.apk
Package name resolved (which one?): F-Droid.apk
monkey output / evidence of a launch: not sure
Which of the four steps failed, if any: none
If the launch failed: does the APK declare a LAUNCHER activity? not sure
```

> If (3) or (4) fails but (1) and (2) succeed, the install path is sound and
> only the launch mechanism needs changing — that is a small fix, and it is
> the outcome this step exists to distinguish.

> **ANNOTATION 2026-08-17 — the block above is the operator's first reading
> and is superseded on three of its five lines.** Left as written; the
> corrections are here. Sample: `F-Droid.apk`, MD5
> `ec6a9a8560924bb833942a7c3256847a`, 12,426,276 bytes.
>
> **What the pipeline run actually produced.** Re-reading its `drakvuf.log`
> against the four questions:
>
> | | Result | Evidence |
> |---|---|---|
> | 1. Selector | **PASS** | injected `Arguments` is the `pm install` + diff + `monkey` sequence through `/system/bin/sh`. The structural ZIP/`AndroidManifest.xml` test works on a real APK. |
> | 2. Install | **DID NOT COMPLETE** | `pm` (2658) and `cmd` (3952) threads busy, but **zero** `/data/app/` writes and no `dex2oat` |
> | 3. Package diff | **NEVER RAN** | sequenced after `pm install` returns, which it never did |
> | 4. Launch | **NEVER HAPPENED** | no `monkey`, no process named for the package; `grep -i fdroid` over the whole log is empty |
>
> So "Which of the four steps failed, if any: none" above is **wrong** — 2,
> 3 and 4 all failed, and the line "Package name resolved: F-Droid.apk"
> records the *filename*, not a package name. No package name appears
> anywhere in that trace.
>
> **Why, and it is not the install path.** The trace shows the guest
> collapsing under introspection overhead: `AnrMainProcessD` (649) and
> `AnrAuxiliaryTas` (628) thread names plus
> `00000037__data_anr_temp_anr_8061245081111330438.txt` in `dump/` — Android
> was declaring its own system apps unresponsive — and `CachedAppOptimi`
> (747) freezing app cgroups, against 43,116 syscall events from
> `system_server` alone in 120 s. See F3.
>
> **Settled by hand instead, on an untraced clone (domid 24).** Same APK,
> same `pm install` line, no DRAKVUF attached:
>
> ```text
> rc=0
> seconds=3
> --- pm output ---
> Success
> --- new packages ---
> package:org.fdroid.fdroid
> ```
>
> **Install: PASS, in 3 seconds. Package diff: PASS**, resolving
> `org.fdroid.fdroid` — so `drakvuf-android.sh`'s before/after diff logic is
> correct. Three seconds untraced against not finishing in 120 traced is a
> **lower bound of 40× overhead**, and the true figure is higher because the
> traced install was never observed to finish.
>
> **Question (4), the launch, settled separately — and `monkey` was the
> wrong mechanism twice over.** As `drakvuf-android.sh` writes it today:
>
> ```text
> --- monkey ---
>   bash arg: -p
>   ...
> Aborted
> monkey_rc=134
> ```
>
> Exit 134 is `app_process64` aborting before `main()` for want of the
> classpath import — already measured and documented at
> `docs/checklists/android.md:833` and
> `docs/runbooks/verify-android-isolation.md:1029`, and already carried by
> `preconfig-android.sh:227`. `drakvuf-android.sh` omits it. That is F2.
>
> With the import added, `monkey` works (`Events injected: 1`,
> `monkey_rc=0`). But so does the alternative, **with no import at all**:
>
> ```text
> --- am wrapper ---
> #!/system/bin/sh
> if [ "$1" != "instrument" ] ; then
>     cmd activity "$@"
> --- am start, NO import ---
> Starting: Intent { cmp=org.fdroid.fdroid/.views.main.MainActivity }
> am_rc=0
> --- processes after am ---
> u0_a313  4329  1613  ... S org.fdroid.fdroid
> ```
>
> `am` is a two-line wrapper around the same native `cmd` binary that makes
> `pm install` work, which is why it needs no ART environment.
> `cmd package resolve-activity --brief -c android.intent.category.LAUNCHER`
> returned `org.fdroid.fdroid/.views.main.MainActivity` with no environment
> either. Both routes launched the app; F-Droid was confirmed on the guest
> GUI.
>
> **DECISION, operator, 2026-08-17: do not use `monkey`.** This closes
> DRAFT-016's open monkey-vs-manifest question. Three reasons, in order of
> weight:
>
> 1. **`monkey` is detectable.** `ActivityManager.isUserAMonkey()` is a
>    public API that returns true for anything launched under it — a
>    one-call check for a sample to go dormant. This is the same
>    anti-evasion reasoning that renamed the anchor away from
>    `drakvuf-anchor` in issue #7.
> 2. **It covers fewer entrypoints, not more.** `monkey` picks one activity
>    matching the category and fires events at it. Enumerating with
>    `pm dump <pkg>` / `dumpsys package <pkg>` and driving each result with
>    `am start -n` / `am broadcast` / `am start-foreground-service` reaches
>    activities, receivers *and* services — including the
>    `BOOT_COMPLETED`-style receivers that malware without any launcher
>    activity relies on, which `monkey` never triggers.
> 3. **It needs the classpath import; `am` does not**, removing the trace
>    path's dependency on the file described in F5.
>
> Proposed replacement for `drakvuf-android.sh`'s APK tail, **not yet
> implemented** — it belongs to DRAFT-016 and needs its own change and
> review:
>
> ```sh
> PKG=$(…existing diff…)
> CMP=$(cmd package resolve-activity --brief -c android.intent.category.LAUNCHER "$PKG" | tail -1)
> case "$CMP" in */*) am start -n "$CMP" ;; esac
> ```
>
> The `case` guard is the answer to this step's last question: an APK need
> not declare a launcher activity, and this form then does nothing rather
> than running `am start -n` on an error string. F-Droid does declare one
> (`.views.main.MainActivity`).

---

## Step 14 — Teardown, and the golden images untouched

```bash
sudo xl list                                    # note anything still running
sudo automation/cleanup.sh <domid> <vlan>       # for each remaining clone
sudo lvremove -f /dev/vg-root/android_sandbox-1-clone

sudo lvs -a -o lv_name,lv_size vg-root
sudo blockdev --getsize64 /dev/vg-root/android
sudo blockdev --getsize64 /dev/vg-root/ubuntu
sha256sum /root/sandbox_project/state/android_sandbox.bak
sha256sum /root/sandbox_project/state/ubuntu_sandbox.bak
```

Compare all four against step 0. **Any difference means a golden image or a
template was written to**, which no part of this PR should ever do.

> `lvremove` may report `Logical volume ... in use` on the first attempt.
> `xl destroy` returns before the block device is released; retry once.
> Record which attempt succeeded — `clone.pl` now waits for the domain to go
> before its own `lvremove`, and this is the check on that.

```text
Domains still running before teardown: none -- cleanup.sh had already
  destroyed android_sandbox-1-clone; `xl list` showed Domain-0 alone
lvremove attempt that succeeded (1st / 2nd): 1st
  "Logical volume "android_sandbox-1-clone" successfully removed"
Golden ubuntu LV size before / after: 64,00g / 64,00g
Golden android LV size before / after: 32,00g / 32,00g
ubuntu_sandbox.bak sha256 before / after: aa9e3b41...4c1 / NOT RE-MEASURED
android_sandbox.bak sha256 before / after:
  516644e223327d5ae5aa17c568240c00127b8d8b88915e70131acf0cd192677c /
  516644e223327d5ae5aa17c568240c00127b8d8b88915e70131acf0cd192677c   IDENTICAL
ALL FOUR IDENTICAL? (y/n): three of four confirmed; see annotation

root@drakvuf:~/sandbox_project# sudo lvs -a -o lv_name,lv_size vg-root
  LV                     LSize
  android                 32,00g
  android_sandbox         32,00g
  lv-root                256,00g
  ubuntu                  64,00g
  ubuntu_sandbox          64,00g
  ubuntu_sandbox-1-clone  64,00g
  ubuntu_sandbox-2-clone  64,00g
```

> **ANNOTATION 2026-08-17 — two deviations from this step as written.**
>
> **1. `blockdev --getsize64` was not re-run; `lvs` was used instead.** The
> LV sizes above are equivalent evidence for the question this step asks
> (was a golden written to), but they are not the same measurement step 0
> recorded, so the comparison is by size in different units rather than
> byte-for-byte. `ubuntu_sandbox.bak`'s checksum was **not** re-measured at
> all — the Ubuntu half of the "goldens untouched" check is therefore
> unproven by this run, even though nothing in steps 4–8 should have
> touched it. Leave it unproven rather than assuming.
>
> **2. `ubuntu_sandbox-2-clone` is new since the step 0 baseline**, which
> listed only `ubuntu_sandbox-1-clone`. This is expected and is not a leak:
> `cleanup.sh` destroys the domain but never removes the snapshot, and
> `clone.pl` removes it when it next reuses the name, so the count is
> bounded by `MAX_CLONES=2`. Steps 4–8 used both slots. Both Ubuntu clone
> LVs are present and no domains are running, which is the intended
> resting state.

---

## Results matrix

| Step | What it proves | Result | Notes |
|---:|---|---|---|
| 0 | Baseline recorded | PASS | 2 pre-existing clone LVs, 0 clone domains |
| 1 | `dirwatch.c` compiles | **PASS** | no warnings naming dirwatch.c; glib 2.72.4 |
| 2 | Static checks agree on Dom0 | PASS | shellcheck 0.8.0 exit 0; C4 grep empty |
| 3 | Deployed, rename landed | PASS | `8cd4855`; `clone.pl` present, `clone-ubuntu.pl` gone |
| 4 | **Ubuntu still analyses** | **PASS** | **merge gate clear** — argv spawn lines, full result dir |
| 5 | Clone destroyed on success | PASS | `Domain-0` alone after a successful run |
| 6 | Submitted name reaches the guest; spaces survive | PASS | one argv element; no stray pcap |
| 7 | `clone.pl` fails loudly, stdout stays clean | PASS | all 6 paths; stdout empty on every failure |
| 8 | Filename admission and rejection | PASS | control char rejected once, not re-scanned |
| 9 | **`injector` works on Android at all** | **PASS**, see **F1** | 12 MB APK round-trip byte-exact — but **human-assisted** |
| 10 | Clone is 32G | PASS | `32,00g`; export at `run_analysis-android.sh:50` |
| 11 | Network config injection | PASS | Dom0 values expanded, guest `$` literal; ping OK; vif tag 1 |
| 12 | Android native ELF traced | PASS | execve-direct path; `PPID:3164` = the anchor |
| 13 | Android APK installed and launched | **PARTIAL** — **F2**, **F3** | selector PASS; install/launch fail in-pipeline, proven by hand |
| 14 | Goldens untouched | PASS (3 of 4 re-measured) | `ubuntu_sandbox.bak` not re-hashed |

## Findings

Record anything that did not match the expectation, whether or not it
blocked the run. Findings from a first bring-up are the point of it.

### F1 — The injection anchor starves. Every Android result here is human-assisted.

**Blocking. Owns the next piece of work.**

`INJECTION_PID=3164` is a backgrounded `nano`, blocked on a console tty read
and captured in that state by `xl save` (`docs/checklists/android.md` §1.4,
`rebuild-android-sandbox.md` step 5: *"Anchor is just a shell process (nano)
running in background"*). `injector` waits for the target PID to be
scheduled onto a vCPU and **has no timeout and prints nothing while
waiting** — so a never-scheduled anchor produces a silent hang, not an
error. Confirmed directly: the hang ends the instant `fg` plus a keypress is
delivered at the guest console, and resumes on the next injection.

Every `injector` invocation in this runbook — steps 9, 11, 12, 13 and every
manual probe — required a `fg` and keypresses. **No Android result here was
obtained unattended.**

*Second symptom, and the one that hides it.* `dirwatch.c`'s
`run_drakvuf()` treats a preconfig timeout as retryable with no attempt
counter: `goto end` → *"failed to execute … creating new clone"* →
`prepare()` → `goto restart`. During step 13 this produced twelve minutes of
clone / hang / SIGKILL / re-clone until a nudge happened to land inside a
60 s window, after which the run "succeeded". The retry loop masked the
defect rather than tolerating it, and on an unattended host it never
terminates.

*Diagnostic chain, for the record.* `preconfig.log` ended in `Killed`;
`dirwatch.c:637` arms a 60 s timer, `timer_thread` fires `cleanup.sh`, and
`cleanup.sh` sends SIGINT then `kill -9` five seconds later. `dash` writes a
child's signal-death message into that child's *redirect target*, which is
why `Killed` appears inside `preconfig.log` and identifies `injector` as
the process that died.

**Fix:** replace the anchor with one that is scheduled on its own and holds
no VT, then re-save the template (`rebuild-android-sandbox.md`). New
`INJECTION_PID` and new `.bak` checksum follow, so
`automation/pipeline-android.env`, `docs/checklists/android.md` §1.4/§1.5
and `verify-android-isolation.md`'s recorded values all move together.

Constraints on the replacement, all evidenced by this run:

- **Must run as root** — see F5.
- **Must be 64-bit** — `injector --help` states the Linux `execproc` path is
  64-bit only.
- **Must not be name-discoverable** as analysis infrastructure (issue #7's
  anti-evasion decision), and auto-discovery must not key on a process-name
  grep (`android.md` §1.4).
- **Should not hold a console VT**, so the guest can sit on the Android GUI —
  see F7.

A candidate that meets all four is `setsid sh -c 'while :; do sleep 5;
done' &` started as root: scheduled every 5 s, writes nothing, logs nothing,
opens no socket. Its one cost is a `sleep` fork per interval (~24 per 120 s
trace). §1.4's original "dedicated 64-bit native process" doing `nanosleep`
in a loop is the cleaner end state.

**Not yet attempted, and worth doing before re-saving:** searching the
*existing* image for an already-scheduled process that also satisfies the
constraints would avoid a re-save entirely. `adbd` was the first candidate
and is now doubted — it blocks in `poll()` with no client attached and can
starve the same way. The continuously-scheduled processes visible in the
step 13 trace (`system_server`/`app_process64` at 43,116 events,
`surfaceflinger` at 13,010) run as uid `system`, which cannot write
`/data/local/tmp` (`shell:shell`, `0771`) under DAC before SELinux is even
consulted. **Acceptance test for any candidate:** three `writefile`s back to
back on a fresh clone with the console untouched, each returning well inside
60 s.

> **RESOLVED 2026-08-17, same day.** The template was re-saved with a
> backgrounded `ping` against loopback as the anchor.
>
> ```text
> anchor PID:        3174   (was 3164)
> saved state sha256: 465aa4d74e7b3a97310b6eaf57e65b6519a231a7e590a5c3237ad1cf4af79b55
>                            (was 516644e2…)
> ```
>
> Loopback rather than a routable target, so nothing reaches the vif and
> `tcpdump.sh`'s per-sample pcaps carry no anchor traffic — see
> `docs/checklists/android.md` §1.4's 2026-08-17 annotation for the full
> constraint list this episode produced.
>
> **Acceptance: three full analyses completed with no console interaction** —
> nine consecutive injections (two per preconfig, one per trace), against
> zero unattended injections under `nano`. Stronger than the three-`writefile`
> test proposed above.
>
> Updated in the same change: `automation/pipeline-android.env` (value **and**
> its comment block), `CLAUDE.md`, `docs/checklists/android.md` §1.4 and
> §1.5 annotations plus the PID table and changelog. The 2026-08-11 evidence
> blocks recording 3163/`nano` are unchanged, as they must be.
>
> **Worth confirming once, since the retry loop is what hid this before:**
> that none of those three runs printed `failed to execute … because of a
> timeout, creating new clone`. A run that starved and then succeeded on
> retry looks identical to one that never starved.

### F2 — `drakvuf-android.sh`'s APK path omits the classpath import (exit 134)

**One line. Already diagnosed elsewhere in this repository.**

`preconfig-android.sh:227` opens its injected command with

```sh
while IFS=" " read -r a n v; do [ "$a" = export ] && export "$n=$v"; done < /data/system/environ/classpath;
```

`drakvuf-android.sh:240-245` builds its APK command without it, so
`monkey` → `app_process64` aborts before `main()` with **exit 134**.
Reproduced exactly (`monkey_rc=134`), and the failure mode was already
recorded on 2026-08-11 at `docs/checklists/android.md:833` and
`docs/runbooks/verify-android-isolation.md:1029` — the latter calling it
*"YES — and it is not optional"*.

This is a defect the project had already found and fixed in one file of a
pair, then reintroduced in the other. Worth noting as a review lesson: the
two Android scripts were written in the same change (DRAFT-016) and were not
diffed against each other for shared preamble.

**Fix superseded by the step 13 decision:** the launch moves to `am start
-n`, which is `cmd activity` and needs no import at all, so the import is
*not* being added to `drakvuf-android.sh`. Only `preconfig-android.sh`'s
EthernetConfig call genuinely needs `app_process64` and therefore the
import.

### F3 — `pm install` cannot complete inside the 120 s trace window

**Design-level. Blocks step 13 in the pipeline even after F1 and F2.**

`drakvuf-android.sh:250` passes `-t 120`, inherited from
`drakvuf-ubuntu.sh`. Measured this run:

| | Time |
|---|---|
| `pm install` of F-Droid, untraced | **3 s** (`rc=0`, `Success`) |
| same install, under `-a syscalls -a filetracer -a fileextractor -a memdump` | **did not finish in 120 s** |

A **lower bound of 40× overhead**, and the real figure is higher since the
traced install was never seen to finish. Corroborated from inside the trace:
Android declared ANRs on its own system apps (`AnrMainProcessD`,
`AnrAuxiliaryTas`, `/data/anr/temp_anr_*.txt` in `dump/`) and
`CachedAppOptimi` was freezing app cgroups.

Because `drakvuf-android.sh:241` separates install from the package diff
with `;` rather than `&&`, the trace simply ended mid-install and questions
3 and 4 never ran. Nothing reported an error.

**Raising `-t` alone does not work.** `dirwatch.c:650` arms a 180 s timer
over the whole drakvuf phase, so any `-t` above it means dirwatch kills the
trace and re-clones — F1's loop again. The two numbers are coupled and must
move together, or not at all.

Options, in the order they look worth trying:

1. **Move `pm install` into `preconfig-android.sh` and trace only the
   launch.** The install is not the behaviour under analysis; the app's
   runtime is. 3 s fits inside preconfig's 60 s budget with room to spare,
   the trace gets dramatically cleaner, and the overhead problem disappears
   rather than being budgeted around. The wrinkle is that the two scripts
   share only dirwatch's 7 arguments — writing the resolved package name to
   a guest file at install time and reading it back in-guest at launch time
   would carry it across without inventing a Dom0 channel.
2. **Narrow the plugin set for the APK path.** `-a syscalls` over every
   process is the obvious cost. Check whether the installed DRAKVUF supports
   restricting it — per-plugin filters already exist
   (`--codemon-filter-executable`, `--fileextractor-exclude-list`,
   `--procmon-envs-list`), so read `drakvuf --help` rather than assuming
   either way.
3. Raise `-t` **and** `dirwatch.c:650` together. Least attractive: it makes
   every Android run slower without making the trace better.

This is DRAFT-016 design work and is deliberately **not** implemented here.

### F4 — `fileextractor` resolves almost no filenames on this guest

34 of the 40 files in `dump/` are named `unknown_fd_N`. Only six carry a
real path (`__kmsg`, `_3214_oom_score_adj`, `_background_cgroup.procs`,
`_data_misc_profiles_cur_0_com.android.rkpdapp_primary.prof…`,
`_data_misc_critical-events_critical_event_log.pb`,
`_data_anr_temp_anr_….txt`).

Result-quality defect specific to Android, independent of F1–F3: an
extracted file whose name is `unknown_fd_112` is close to unusable as
evidence. Not investigated. Belongs with
`docs/architecture/result-schema.md`; needs a comparison against an Ubuntu
run's `dump/` to establish whether this is Android-specific or general.

### F5 — `/data/system/environ/classpath` is `0600 system:system` and exists only inside the saved image

```text
-rw------- 1 system system 3842 2026-08-14 14:07 classpath
```

Two consequences, neither previously written down:

1. **It constrains the anchor to root.** Today's injections read it only
   because `nano` runs as root. If F1's replacement anchor is started as
   anything less privileged, the `while read … < classpath` import reads
   nothing, `app_process64` aborts 134, and
   `preconfig-android.sh`'s network configuration fails **silently** — no
   Dom0-side error, a clone that comes up with no address. This is now a
   precondition on the re-save, not a preference.
2. **Nothing in this repository recreates it.** It is dated 2026-08-14,
   lives only in `android_sandbox.bak`, and is not produced by any tracked
   script. A future template rebuild that forgets it breaks the network
   injection the same silent way. `rebuild-android-sandbox.md` should carry
   a step for it.

### F6 — `injector`'s `[INJECT]` line records the Dom0 path, not the guest path

For both `writefile` and `readfile`, `FILE:` holds the **Dom0-side** path
(`FILE:"/home/user/Downloads/F-Droid.apk"` on a write,
`FILE:"/tmp/F-Droid.pulled"` on a read). The guest path appears only in the
preceding `Injector starting <path> through PID <pid>` line.

Step 6 of this runbook instructs the reader to confirm the guest staging
path by grepping the `[INJECT]` line for `-e`. **That instruction cannot
work as written** — it reads the Dom0 path back and would "confirm" C5
against the wrong value. Anything else that parses `preconfig.log` for the
guest path has the same bug.

**Corrected method** (also annotated in place under step 6):

```bash
grep -n 'Injector starting' "$RESULT_DIR/preconfig.log"

sed -n 's/^Injector starting \(.*\) through PID .*/[\1]/p' \
    "$RESULT_DIR/preconfig.log"
```

The second form brackets the path so a space, or stray whitespace, is
visible. It is space-safe, which the original `grep -o
'/home/carlos/Desktop/[^ "]*'` is not — `[^ "]*` stops at the first space
and silently truncates precisely the filenames step 6 exists to test.

**Scope checked:** `grep -rn "grep -i writefile\|Injector starting"` over
`docs/` and `automation/` finds this method nowhere else. No script parses
`preconfig.log`; it is read by humans only
(`docs/architecture/result-schema.md` §1 describes it correctly as
"`injector` output from network setup + sample staging"). So this is a
defect in **this document**, not in the pipeline.

**Consequence for this run: none, once re-measured — and C5 now holds for
both hard cases.** Run with the corrected method on 2026-08-17:

```text
[/home/carlos/Desktop/quote'name.sh]      # step 8's sample
[/usr/bin/sh]                             # the network execproc, expected
[/home/carlos/Desktop/benign sample.sh]   # step 6's sample, re-measured
```

A single quote and a space both survive Dom0 → `dirwatch` argv →
`injector -e` → guest path, unmangled. That is DRAFT-030's guest half
proven on the two filenames most likely to break it, which the original
`grep -o '/home/carlos/Desktop/[^ "]*'` could not have shown either way.

Getting the second line required resubmitting under **different content** —
see F8.

### F8 — Result directories are keyed by content MD5, so distinct submitted filenames collide and overwrite each other

Found while re-measuring step 6 for F6, and it invalidated that step's
evidence before anyone read it.

Steps 4, 6 and 8 submitted **four** samples — `benign.sh`,
`benign sample.sh`, `-leading-dash.sh`, `quote'name.sh` — all copied from
the same `/tmp/benign.sh`. Identical bytes means identical MD5, and
`$OUTPUTFOLDER/$MD5/` is the result directory, so all four analyses wrote
into `d604a220708aa59433ba410986cd4ffa`. `preconfig-ubuntu.sh` opens the log
with `1>"$LOG"`, truncating, so each run destroyed the previous one's
`preconfig.log`. By the time step 6's guest path was checked, the file
described step 8's sample.

**This was benign before DRAFT-030 and is not now.** Keying on content hash
is deliberate and right for deduplication — the same bytes are the same
malware. But since DRAFT-030 the *submitted filename* is what the guest
executes (C5), and extension dispatch and `argv[0]` self-checks are exactly
the evasion surface that change exists to exercise. Two submissions of
identical bytes under different names are therefore **different analyses
with different guest behaviour**, and today they share one directory where
the second silently overwrites the first's logs.

Only the logs collide destructively. `drakvuf.log` is truncated the same
way; `dump/` and `memdump/` accumulate across runs, which is arguably worse
because artifacts from two analyses interleave with no marker saying which
run produced them.

Not a blocker for a single-sample run, and not fixed here. It belongs with
`docs/architecture/result-schema.md`, which currently documents
`$OUTPUTFOLDER/$MD5/` without noting that the key is not unique per
analysis. Options range from adding the submitted name to the path, to a
per-run subdirectory, to simply refusing a second submission of an
already-analysed digest — each has different implications for the
deduplication the current scheme buys, so it needs a decision rather than a
patch.

**Practical note for anyone re-running steps 4–8:** vary the *content*, not
just the filename, or the evidence overwrites itself.

### F7 — The console VT hides the analysis GUI, and the anchor is why

The Android UI was not visible during step 13 because the framebuffer was
showing the text VT that `androidboot.enable_console=1` provides — which is
where the anchor lives and where it has to be nudged. So "F-Droid did not
appear" was a measurement artefact, not a launch failure: `am start`
launched it and the trace showed the process, and once the GUI VT was in
front the app was visible.

The coupling is the point: the anchor must be in front to be nudged, so the
GUI cannot be. F1's replacement removes both halves at once, and the
re-save should leave the guest sitting on the GUI VT.

## If this runbook needs to be abandoned partway

That is a normal outcome for a first bring-up and is not a failure of the
run. Record how far it got, and **leave the steps that did not run empty
rather than deleting them** — an unfilled block is evidence that something
was not measured, which is different from evidence that it passed.

Steps 1–8 are independently useful even if Android never starts: they cover
every Ubuntu-affecting change in the PR, which is the half that gates the
merge.

---

## Where this run leaves PR #14 (2026-08-17)

**The merge gate is clear.** `dirwatch.c` compiles, and Ubuntu still
analyses samples across the file rename, the argv spawn rewrite, the
submitted-name change and `clone.pl`'s new failure paths — steps 4–8 all
pass, including a spaced filename and the rejection path. That was the
stated way this PR was expected to fail, and it did not.

**Android is further along than "written but unrun", and short of
working.** Every mechanism in the Android pipeline is now
execution-evidenced at least once: `writefile` and `readfile` round-trip
12 MB byte-exact, the clone is 32G, the network injection's mixed quoting
survives Dom0, a native ELF traces through the execve-direct path, an APK
installs in 3 s and launches. None of it ran without a human at the guest
console, and the APK path does not complete inside the pipeline.

**F1 was fixed the same day** — new anchor, new template (`465aa4d7…`,
PID 3174), three unattended analyses. Android now runs without a human at
the guest console, which it could not do when this run started.

**Two things remain between here and a correct unattended Android run**:

1. **F3 — the trace budget for the APK path.** A design decision
   (install-in-preconfig vs. plugin narrowing), not a number to bump. This
   is the next piece of work.
2. **F2 — the launch mechanism**, now decided: `am start -n`, not `monkey`.
   Small change, but it must not be made in isolation from F3, since both
   rewrite the same command construction in `drakvuf-android.sh`.

F4, F5, F6, F7 and F8 do not block a run. F5 became a standing constraint on
the anchor rather than independent work. F6 was a defect in **this
document** and is corrected in place, with C5 re-measured and now proven for
both a spaced and a quoted filename. F8 is a result-schema decision that
predates this PR and was merely exposed by it.

**What is still unmeasured**, and should not be read as passing: Ubuntu's
saved-state checksum after the run (step 14); the full pipeline against the
*new* template — the three unattended analyses proved the anchor, but steps
9–13 as written were all executed against the old `516644e2…` image and
none has been re-run since the re-save; concurrent Ubuntu + Android
operation (forbidden by DRAFT-036 and untested); and whether F4's naming
failure is Android-specific or general.