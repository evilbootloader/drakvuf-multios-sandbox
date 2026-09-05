# Runbook — verify the `drakvuf-ubuntu.sh` `<USER>` placeholder against real behavior

> **Issue:** [#2](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/2)
> (DRAFT-007) · **Milestone:** M1 · **Where it runs:** Xen Dom0 (L1), *not* the
> development container.
>
> **Status: COMPLETE — executed on Dom0 2026-08-08.** R0, R1, R1b and R2 were
> run and their evidence blocks are filled in below; R3 was not needed. See the
> **Final verdict** at the end. Commands in R0–R2 are therefore **validated**;
> the R3 section was never executed and its commands remain **Candidate** per
> `CLAUDE.md`.
>
> **REDACTED 2026-09-04, and the value was not a secret.** The analysis run's
> directory name — an MD5 of the benign test sample — reads
> `REDACTED-RUN-MD5` throughout, here and in `docs/checklists/ubuntu.md`,
> `DRAFT-007.md` and `issue-index.md`, which cite the same run. It tripped
> TruffleHog's `Box` detector, which matches any 32-character alphanumeric
> string, and the pre-push hook refuses on an unverified finding regardless of
> what the value actually is. The placeholder is consistent across all four
> documents, so every cross-reference still resolves to the same run; what is
> lost is only the ability to name that run by its digest.
>
> **Outcome in one line:** the `<USER>` placeholder is a *repository* defect, not
> a production one — the deployed Dom0 copy is correctly substituted and samples
> do execute. The real problem it uncovered is repo↔host drift.
>
> **Scope:** verification only. This runbook does **not** fix the bug — that is
> deliberately deferred (issue #2 "Out of scope"; the fix lands with DRAFT-011).
> Do not edit any deployed script in place while working through it.

## What this answers

`automation/drakvuf-ubuntu.sh:119` sets `CMD="/home/<USER>/Desktop/test"` with a
literal `<USER>`, while `automation/preconfig-ubuntu.sh:119` stages the sample as
user `carlos`. Three hypotheses are open (see `docs/checklists/ubuntu.md`'s
Known-issues section for the full reasoning):

| # | Hypothesis | Consequence if true | Settled by |
|---|---|---|---|
| H1 | The deployed Dom0 copy has `carlos` substituted per `docs/drakvuf-on-xen-nested-within-proxmox.md:660`; this repo's copy is the stale one | Production is fine; repo-staleness defect only | **R1** |
| H2 | The deployed copy is identical to this repo's (literal `<USER>`) | Every past Ubuntu run silently failed to execute its sample | **R1 + R2/R3** |
| H3 | `drakvuf -e` is shell-mediated **inside the guest**, so `$USER` was meant to dereference on the analysis VM | Intent was sound; the eventual fix is a guest-side `$USER` form, not a hard-coded `carlos` | **R0** |

H1/H2 and H3 are independent axes. R0 decides what a correct fix would look
like; R1 decides whether anything is currently broken.

## How to use this

Work **R0 → R1 → R1b → R2 → R3 in order and stop as soon as the verdict is
decided.** The ladder is deliberately cheapest-first: R0–R2 touch no VM at all
and generate no new analysis runs. R3 is the only step that boots a clone, and
it is reached only if R1 and R2 come back inconclusive.

Paste each step's output into its evidence block, then fill in the decision
table at the end.

### Safety preconditions

- Run as root on Dom0 (`sudo su`), as `docs/drakvuf-on-xen-nested-within-proxmox.md:665`
  prescribes.
- **Sandbox clone only.** Never operate on the golden `ubuntu` domain or its LV.
- **No real malware.** R3 uses the purpose-built benign sample defined below.
- Confirm the pipeline is idle before R3 — check `/malware_incoming` is empty and
  no `dirwatch` is mid-run — so a real queued sample isn't disturbed.
- R3's beacon targets the **lab gateway only** (`172.16.<vlan>.1`, the Apache
  instance the pipeline already serves samples from). It never contacts an
  external host.

---

## R0 — settle what `-e` actually does (no VM touched)

**Decides H3.** `CLAUDE.md` forbids inventing DRAKVUF/`injector` option
semantics, so capture the installed tools' own output rather than reasoning from
usage. The question: **is `-e`'s argument `execve`'d directly in the guest, or is
it handed to a shell there?** Only the second reading would let a `$USER` inside
the string dereference on the analysis VM.

```bash
# Run on L1: Xen Dom0
drakvuf --help  2>&1 | tee /tmp/drakvuf-help.txt
drakvuf -h      2>&1 | tee -a /tmp/drakvuf-help.txt
injector --help 2>&1 | tee /tmp/injector-help.txt
injector -h     2>&1 | tee -a /tmp/injector-help.txt

# Extract just the exec-related options.
grep -nE -- '-e|-f|--exec|--args|execproc|inject-method' \
    /tmp/drakvuf-help.txt /tmp/injector-help.txt

# If the pinned lfreijo/drakvuf checkout is present on this host, the source is
# authoritative over --help. Adjust the path to the real checkout location.
grep -rn "execproc" /path/to/drakvuf/src/ | head -40
```

Context for interpreting the result: `preconfig-ubuntu.sh:120-125` has to spell
out `-e /usr/bin/sh -f "-c" -f "<script>"` to obtain shell semantics, and the
Android candidate at `docs/checklists/android.md:1141` does the same with
`-e /system/bin/sh`. Neither would be necessary if `-e` were itself
shell-mediated. `drakvuf-ubuntu.sh:122` passes `-e "$CMD"` with **no** `-f`
arguments. That is inference from usage — R0 is what turns it into evidence.

Note regardless of outcome: `<USER>` is not variable syntax in any shell (a
guest shell would read it as an input redirect from a file named `USER`), so H3
being true would change what the *fix* is, not whether the current line is
defective.

```text
R0 EVIDENCE — paste output here

root@drakvuf:~# # Extract just the exec-related options.
grep -nE -- '-e|-f|--exec|--args|execproc|inject-method' \
    /tmp/drakvuf-help.txt /tmp/injector-help.txt
/tmp/drakvuf-help.txt:11:	 -e <injection_cmd>        The executable to start with injection
/tmp/drakvuf-help.txt:13:	 --exit-injection-thread   Exit injection thread after process injection complete
/tmp/drakvuf-help.txt:15:	                                               : [LINUX]: execproc -> execlp(), linuxshellcode 
/tmp/drakvuf-help.txt:16:	 --write-file <src> <dst>  Copy host file <src> into running VM's path <dst> (writefile injection method)
/tmp/drakvuf-help.txt:18:	 --write-file-timeout <seconds>
/tmp/drakvuf-help.txt:19:	                           write-file timeout (in seconds, default: 0 == no timeout, requires --write-file)
/tmp/drakvuf-help.txt:20:	 -f <args for exec>        Additional args for exec() (requires -m execproc or -m shellexec)
/tmp/drakvuf-help.txt:37:	 -F, --fast-singlestep     Enable fast singlestepping (requires Xen 4.14+)
/tmp/drakvuf-help.txt:40:	 --enable-active-callback-check
/tmp/drakvuf-help.txt:43:	 --fileextractor-timeout <timeout>
/tmp/drakvuf-help.txt:45:	 --fileextractor-max-size-hash <size>
/tmp/drakvuf-help.txt:47:	 --fileextractor-max-size-extract <size>
/tmp/drakvuf-help.txt:49:	 --fileextractor-exclude-list <file name filter>
/tmp/drakvuf-help.txt:57:	 -q, --procmon-envs-list <procmon filter>
/tmp/drakvuf-help.txt:88:	 --memdump-disable-free-vm
/tmp/drakvuf-help.txt:114:	 --procdump-disable-dump-on-finish
/tmp/drakvuf-help.txt:116:	 --procdump-new-processes-on-finish
/tmp/drakvuf-help.txt:122:	 --procdump-exclude-list <file name filter>
/tmp/drakvuf-help.txt:128:	 --codemon-filter-executable <filename>
/tmp/drakvuf-help.txt:130:	 --codemon-log-everything
/tmp/drakvuf-help.txt:138:	 --exploitmon-kernel2user-detect
/tmp/drakvuf-help.txt:153:	 --json-fwpkclnt <path to json>
/tmp/drakvuf-help.txt:155:	 --json-fltmgr <path to json>
/tmp/drakvuf-help.txt:182:	 -e <injection_cmd>        The executable to start with injection
/tmp/drakvuf-help.txt:184:	 --exit-injection-thread   Exit injection thread after process injection complete
/tmp/drakvuf-help.txt:186:	                                               : [LINUX]: execproc -> execlp(), linuxshellcode 
/tmp/drakvuf-help.txt:187:	 --write-file <src> <dst>  Copy host file <src> into running VM's path <dst> (writefile injection method)
/tmp/drakvuf-help.txt:189:	 --write-file-timeout <seconds>
/tmp/drakvuf-help.txt:190:	                           write-file timeout (in seconds, default: 0 == no timeout, requires --write-file)
/tmp/drakvuf-help.txt:191:	 -f <args for exec>        Additional args for exec() (requires -m execproc or -m shellexec)
/tmp/drakvuf-help.txt:208:	 -F, --fast-singlestep     Enable fast singlestepping (requires Xen 4.14+)
/tmp/drakvuf-help.txt:211:	 --enable-active-callback-check
/tmp/drakvuf-help.txt:214:	 --fileextractor-timeout <timeout>
/tmp/drakvuf-help.txt:216:	 --fileextractor-max-size-hash <size>
/tmp/drakvuf-help.txt:218:	 --fileextractor-max-size-extract <size>
/tmp/drakvuf-help.txt:220:	 --fileextractor-exclude-list <file name filter>
/tmp/drakvuf-help.txt:228:	 -q, --procmon-envs-list <procmon filter>
/tmp/drakvuf-help.txt:259:	 --memdump-disable-free-vm
/tmp/drakvuf-help.txt:285:	 --procdump-disable-dump-on-finish
/tmp/drakvuf-help.txt:287:	 --procdump-new-processes-on-finish
/tmp/drakvuf-help.txt:293:	 --procdump-exclude-list <file name filter>
/tmp/drakvuf-help.txt:299:	 --codemon-filter-executable <filename>
/tmp/drakvuf-help.txt:301:	 --codemon-log-everything
/tmp/drakvuf-help.txt:309:	 --exploitmon-kernel2user-detect
/tmp/drakvuf-help.txt:324:	 --json-fwpkclnt <path to json>
/tmp/drakvuf-help.txt:326:	 --json-fltmgr <path to json>
/tmp/injector-help.txt:6:	 -e <inject_file>          File to be injected:
/tmp/injector-help.txt:14:	                             createproc (32 and 64-bit) - Spawn a windows process using CreateProcessW ( use -e for specifying the program )
/tmp/injector-help.txt:15:	                             shellexec (32 and 64-bit) - Spawn a process using ShellExecute ( use -e for specifying the program )
/tmp/injector-help.txt:18:	                             shellcode  - Execute shellcode binary ( use -e for specifying the shellcode binary )
/tmp/injector-help.txt:19:	                             execproc - Run any process using vfork and execve ( -e for specifying the program, -f for args )
/tmp/injector-help.txt:21:	                             readfile - pull a file (specified by guest path -e) from the VM and store it on host path specified by -B
/tmp/injector-help.txt:22:	                             writefile - push a file (specified by host path -B) to the VM and store it on guest path specified by -e
/tmp/injector-help.txt:23:	 -f <args for execproc>    [BOTH] - Arguments specified for exec to include (requires -m execproc or -m shellexec)
/tmp/injector-help.txt:24:	                           [LINUX] (execproc -> execve(const char *file, const char *argv[], const char* envp[]); 64bit only)
/tmp/injector-help.txt:41:	 -e <inject_file>          File to be injected:
/tmp/injector-help.txt:49:	                             createproc (32 and 64-bit) - Spawn a windows process using CreateProcessW ( use -e for specifying the program )
/tmp/injector-help.txt:50:	                             shellexec (32 and 64-bit) - Spawn a process using ShellExecute ( use -e for specifying the program )
/tmp/injector-help.txt:53:	                             shellcode  - Execute shellcode binary ( use -e for specifying the shellcode binary )
/tmp/injector-help.txt:54:	                             execproc - Run any process using vfork and execve ( -e for specifying the program, -f for args )
/tmp/injector-help.txt:56:	                             readfile - pull a file (specified by guest path -e) from the VM and store it on host path specified by -B
/tmp/injector-help.txt:57:	                             writefile - push a file (specified by host path -B) to the VM and store it on guest path specified by -e
/tmp/injector-help.txt:58:	 -f <args for execproc>    [BOTH] - Arguments specified for exec to include (requires -m execproc or -m shellexec)
/tmp/injector-help.txt:59:	                           [LINUX] (execproc -> execve(const char *file, const char *argv[], const char* envp[]); 64bit only)


root@drakvuf:~# grep -rn "execproc" /home/user/drakvuf | head -40
grep: /home/user/drakvuf/src/injector.o: binary file matches
grep: /home/user/drakvuf/src/injector: binary file matches
/home/user/drakvuf/src/main.cpp:196:        "\t                                               : [LINUX]: execproc -> execlp(), linuxshellcode \n"
/home/user/drakvuf/src/main.cpp:201:        "\t -f <args for exec>        Additional args for exec() (requires -m execproc or -m shellexec)\n"
/home/user/drakvuf/src/main.cpp:694:                if (!strncmp(optarg, "execproc", 8))
grep: /home/user/drakvuf/src/main.o: binary file matches
grep: /home/user/drakvuf/src/drakvuf: binary file matches
/home/user/drakvuf/src/injector.cpp:180:        "\t                             execproc - Run any process using vfork and execve ( -e for specifying the program, -f for args )\n"
/home/user/drakvuf/src/injector.cpp:184:        "\t -f <args for execproc>    [BOTH] - Arguments specified for exec to include (requires -m execproc or -m shellexec)\n"
/home/user/drakvuf/src/injector.cpp:185:        "\t                           [LINUX] (execproc -> execve(const char *file, const char *argv[], const char* envp[]); 64bit only)\n"
/home/user/drakvuf/src/injector.cpp:276:                else if (!strncmp(optarg, "execproc", 8))


-e semantics verdict (execve-direct | shell-mediated | unclear): execve-direct
Source consulted (--help | source | both): both
```

---

## R1 — deployed-vs-repo diff (no VM touched)

**Decides H1 vs H2, and satisfies acceptance criterion 1 on its own.**

If this repository is checked out on Dom0:

```bash
# Run on L1: Xen Dom0, from the checkout
diff -u /home/user/drakvuf-tools/drakvuf-ubuntu.sh automation/drakvuf-ubuntu.sh
echo "diff exit status: $?"   # 0 = identical (H2), 1 = they differ (likely H1)
```

If it is **not** checked out there, compare against the recorded hashes instead —
no checkout needed. These are the values for commit `2514168`
(`automation/drakvuf-ubuntu.sh`, git blob `8e151f77`):

```bash
# Run on L1: Xen Dom0
sha256sum /home/user/drakvuf-tools/drakvuf-ubuntu.sh
# repo copy, for comparison:
#   d0a17e4ee92d7d738626b0bd145619abdc8424a5b9d4b7cc882d38cb44ca7102  drakvuf-ubuntu.sh
sha256sum /home/user/drakvuf-tools/preconfig-ubuntu.sh
#   e5a59395e2555e67aa283a990fed0e4f6be0e8ff88aa4386a929d7a10d280d7c  preconfig-ubuntu.sh

# The decisive line either way:
grep -n 'CMD=' /home/user/drakvuf-tools/drakvuf-ubuntu.sh
grep -n 'USER'  /home/user/drakvuf-tools/preconfig-ubuntu.sh
```

**If the deployed copy contains `carlos`** → H1 holds, production was never
broken, the defect is repo staleness alone. Record it and **skip R2 and R3**.
**If it contains the literal `<USER>`** → H2 is live; continue to R2.

```text
R1 EVIDENCE — paste output here

root@drakvuf:~/drakvuf-multios-sandbox# diff -u /home/user/drakvuf-tools/drakvuf-ubuntu.sh automation/drakvuf-ubuntu.sh
--- /home/user/drakvuf-tools/drakvuf-ubuntu.sh	2026-08-07 10:28:26.236865987 +0200
+++ automation/drakvuf-ubuntu.sh	2026-08-08 12:41:34.937000816 +0200
@@ -116,10 +116,10 @@
 RUNFILE=$6
 OUTPUTFOLDER=$7
 MD5=$(md5sum $RUNFOLDER/$RUNFILE | awk -F" " '{print $1}')
-CMD="/home/carlos/Desktop/test"
+CMD="/home/<USER>/Desktop/test"
 
 sleep 5 2>&1
-drakvuf -r $REKALL -d $DOMAIN -i $PID -m execproc -e "$CMD" -D $OUTPUTFOLDER/$MD5 -o json -t 120 -a filetracer -a fileextractor -a memdump --memdump-dir $OUTPUTFOLDER/$MD5 1>$OUTPUTFOLDER/$MD5/drakvuf.log 2>&1
+drakvuf -r $REKALL -d $DOMAIN -i $PID -m execproc -e "$CMD" -D $OUTPUTFOLDER/$MD5 -o json -t 120 -a filetracer -a fileextractor -a memdump -a syscalls --memdump_dir $OUTPUTFOLDER/$MD5/ 1>$OUTPUTFOLDER/$MD5/drakvuf.log 2>&1
 
 RET=$?
 
root@drakvuf:~/drakvuf-multios-sandbox# echo "diff exit status: $?"   # 0 = identical (H2), 1 = they differ (likely H1)
diff exit status: 1


Deployed sha256:
root@drakvuf:~/drakvuf-multios-sandbox# sha256sum /home/user/drakvuf-tools/drakvuf-ubuntu.sh
76bc801b04a332ea042e61e241f44f8b517aa0c20bdeb187998c6ed185716d7f  /home/user/drakvuf-tools/drakvuf-ubuntu.sh
root@drakvuf:~/drakvuf-multios-sandbox# sha256sum /home/user/drakvuf-tools/preconfig-ubuntu.sh
e5a59395e2555e67aa283a990fed0e4f6be0e8ff88aa4386a929d7a10d280d7c  /home/user/drakvuf-tools/preconfig-ubuntu.sh


Deployed CMD= line: 

root@drakvuf:~/drakvuf-multios-sandbox# grep -n 'CMD=' /home/user/drakvuf-tools/drakvuf-ubuntu.sh
119:CMD="/home/carlos/Desktop/test"
root@drakvuf:~/drakvuf-multios-sandbox# grep -n 'USER'  /home/user/drakvuf-tools/preconfig-ubuntu.sh
119:USER="carlos"
122:ARG2="sudo ip addr flush dev eth0 && sudo ip addr add 172.16.$VLAN.2/24 dev eth0 && sudo ip route replace default via 172.16.$VLAN.1 dev eth0 && echo 'nameserver 172.16.$VLAN.1' | sudo tee /etc/resolv.conf && wget 'http://172.16.$VLAN.1/$RUNFILE' -O '/home/$USER/Desktop/test' && chmod +x '/home/$USER/Desktop/test'"

Verdict (H1 deployed-copy-correct | H2 identical-to-repo | other): Different than in the repo, working in Xen host.
```

---

## R1b — confirm the guest user really is `carlos` (read-only)

Cheap sanity check on the *other* half of the pair. If the guest user is not
`carlos`, `preconfig-ubuntu.sh` is broken too and the issue's premise widens.

```bash
# Run on L1: Xen Dom0 — inspect any existing preconfig log
ls -1 /malware_finished/*/preconfig.log | head
grep -n "Desktop/test\|wget\|carlos" /malware_finished/*/preconfig.log | head -20
```

```text
R1b EVIDENCE — paste output here

root@drakvuf:~/drakvuf-multios-sandbox# ls -1 /malware_finished/*/preconfig.log | head
grep -n "Desktop/test\|wget\|carlos" /malware_finished/*/preconfig.log | head -20
/malware_finished/0e0328dc8084e6203c09a3e5ea1539f8/preconfig.log
/malware_finished/1f47ecc10bc008ad26e504897b940f22/preconfig.log
/malware_finished/391c21544cf9a35749b78e485e93f121/preconfig.log
/malware_finished/7485ccb28751684e96ce8b5ef2158559/preconfig.log
/malware_finished/REDACTED-RUN-MD5/preconfig.log
/malware_finished/fa6af27883745503e9182fffd5010b50/preconfig.log
/malware_finished/0e0328dc8084e6203c09a3e5ea1539f8/preconfig.log:3:[INJECT] TIME:1786091110.842379 METHOD:ExecProc STATUS:SUCCESS PID:1415 FILE:"/usr/bin/sh" ARGUMENTS:"-c sudo ip addr flush dev eth0 && sudo ip addr add 172.16.1.2/24 dev eth0 && sudo ip route replace default via 172.16.1.1 dev eth0 && echo 'nameserver 172.16.1.1' | sudo tee /etc/resolv.conf && wget 'http://172.16.1.1/d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e' -O '/home/carlos/Desktop/test' && chmod +x '/home/carlos/Desktop/test'" INJECTED_PID:1634 INJECTED_TID:1634
/malware_finished/1f47ecc10bc008ad26e504897b940f22/preconfig.log:3:[INJECT] TIME:1786091501.709169 METHOD:ExecProc STATUS:SUCCESS PID:1415 FILE:"/usr/bin/sh" ARGUMENTS:"-c sudo ip addr flush dev eth0 && sudo ip addr add 172.16.2.2/24 dev eth0 && sudo ip route replace default via 172.16.2.1 dev eth0 && echo 'nameserver 172.16.2.1' | sudo tee /etc/resolv.conf && wget 'http://172.16.2.1/f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987' -O '/home/carlos/Desktop/test' && chmod +x '/home/carlos/Desktop/test'" INJECTED_PID:1634 INJECTED_TID:1634
/malware_finished/391c21544cf9a35749b78e485e93f121/preconfig.log:3:[INJECT] TIME:1786091365.650859 METHOD:ExecProc STATUS:SUCCESS PID:1415 FILE:"/usr/bin/sh" ARGUMENTS:"-c sudo ip addr flush dev eth0 && sudo ip addr add 172.16.2.2/24 dev eth0 && sudo ip route replace default via 172.16.2.1 dev eth0 && echo 'nameserver 172.16.2.1' | sudo tee /etc/resolv.conf && wget 'http://172.16.2.1/f0fac0f22f107252ea48d5293e51b6760e091988bc5921974b3691f0eb81274f' -O '/home/carlos/Desktop/test' && chmod +x '/home/carlos/Desktop/test'" INJECTED_PID:1634 INJECTED_TID:1634
/malware_finished/7485ccb28751684e96ce8b5ef2158559/preconfig.log:3:[INJECT] TIME:1786091497.889101 METHOD:ExecProc STATUS:SUCCESS PID:1415 FILE:"/usr/bin/sh" ARGUMENTS:"-c sudo ip addr flush dev eth0 && sudo ip addr add 172.16.1.2/24 dev eth0 && sudo ip route replace default via 172.16.1.1 dev eth0 && echo 'nameserver 172.16.1.1' | sudo tee /etc/resolv.conf && wget 'http://172.16.1.1/9a000c64f48cb4fd592ef449f86cf2ac6c67e53e61b439cd6a8e47cf91992878' -O '/home/carlos/Desktop/test' && chmod +x '/home/carlos/Desktop/test'" INJECTED_PID:1634 INJECTED_TID:1634
/malware_finished/REDACTED-RUN-MD5/preconfig.log:3:[INJECT] TIME:1786091635.198324 METHOD:ExecProc STATUS:SUCCESS PID:1415 FILE:"/usr/bin/sh" ARGUMENTS:"-c sudo ip addr flush dev eth0 && sudo ip addr add 172.16.1.2/24 dev eth0 && sudo ip route replace default via 172.16.1.1 dev eth0 && echo 'nameserver 172.16.1.1' | sudo tee /etc/resolv.conf && wget 'http://172.16.1.1/91876d9a8ed450057993efe35f8ee8465a09c0b4ba82f0327b82b91ab072aebd' -O '/home/carlos/Desktop/test' && chmod +x '/home/carlos/Desktop/test'" INJECTED_PID:1634 INJECTED_TID:1634
/malware_finished/fa6af27883745503e9182fffd5010b50/preconfig.log:3:[INJECT] TIME:1786091361.095102 METHOD:ExecProc STATUS:SUCCESS PID:1415 FILE:"/usr/bin/sh" ARGUMENTS:"-c sudo ip addr flush dev eth0 && sudo ip addr add 172.16.1.2/24 dev eth0 && sudo ip route replace default via 172.16.1.1 dev eth0 && echo 'nameserver 172.16.1.1' | sudo tee /etc/resolv.conf && wget 'http://172.16.1.1/1edcc1a739d5cd743df86cf1cc0594df74e86549c5c14556d93fbf2921e7d5cd' -O '/home/carlos/Desktop/test' && chmod +x '/home/carlos/Desktop/test'" INJECTED_PID:1634 INJECTED_TID:1634


Guest username confirmed as: carlos
wget staging step succeeded (yes | no | no data): yes
```

---

## R2 — mine historical evidence before generating any (read-only)

**Can satisfy acceptance criterion 2 with no new analysis run at all.** Past runs
already left `/malware_finished/<md5>/{preconfig.log,drakvuf.log}` on disk;
`drakvuf-ubuntu.sh:118` keys those directories by MD5.

```bash
# Run on L1: Xen Dom0
ls -lt /malware_finished/ | head -20

# Did any past run reference the unsubstituted path?
grep -rn '<USER>' /malware_finished/*/drakvuf.log | head

# Sizes are themselves a signal: a trace where nothing executed tends to be
# much smaller/sparser than one where the sample ran.
wc -l /malware_finished/*/drakvuf.log | sort -n | tail -20

# Inspect one recent trace directly. Candidate greps — adjust once the actual
# JSON shape is known; do not assume these keys exist.
RUN=/malware_finished/REDACTED-RUN-MD5   # pick one from the listing above
head -50 "$RUN/drakvuf.log"
grep -c . "$RUN/drakvuf.log"
grep -n "execve\|ENOENT\|No such file\|Desktop/test" "$RUN/drakvuf.log" | head -30
cat "$RUN/preconfig.log"
ls -la "$RUN"
```

What to look for: evidence the **target process actually ran**, not merely that
DRAKVUF started monitoring. A trace containing only kernel/background syscall
activity with no reference to the staged binary is consistent with H2.

```text
R2 EVIDENCE — paste output here

root@drakvuf:~/drakvuf-multios-sandbox# ls -lt /malware_finished/ | head -20
total 24
drwxr-xr-x 2 root root 4096 ago  7 10:35 REDACTED-RUN-MD5
drwxr-xr-x 2 root root 4096 ago  7 10:33 7485ccb28751684e96ce8b5ef2158559
drwxr-xr-x 2 root root 4096 ago  7 10:32 1f47ecc10bc008ad26e504897b940f22
drwxr-xr-x 2 root root 4096 ago  7 10:31 391c21544cf9a35749b78e485e93f121
drwxr-xr-x 2 root root 4096 ago  7 10:31 fa6af27883745503e9182fffd5010b50
drwxr-xr-x 2 root root 4096 ago  2 10:30 0e0328dc8084e6203c09a3e5ea1539f8
root@drakvuf:~/drakvuf-multios-sandbox# grep -rn '<USER>' /malware_finished/*/drakvuf.log | head
root@drakvuf:~/drakvuf-multios-sandbox# wc -l /malware_finished/*/drakvuf.log | sort -n | tail -20
        5 /malware_finished/0e0328dc8084e6203c09a3e5ea1539f8/drakvuf.log
    87387 /malware_finished/fa6af27883745503e9182fffd5010b50/drakvuf.log
   112459 /malware_finished/391c21544cf9a35749b78e485e93f121/drakvuf.log
   171705 /malware_finished/7485ccb28751684e96ce8b5ef2158559/drakvuf.log
   335857 /malware_finished/1f47ecc10bc008ad26e504897b940f22/drakvuf.log
   359517 /malware_finished/REDACTED-RUN-MD5/drakvuf.log
  1066930 total
root@drakvuf:~/drakvuf-multios-sandbox# RUN=/malware_finished/REDACTED-RUN-MD5   # pick one from the listing above
root@drakvuf:~/drakvuf-multios-sandbox# head -50 "$RUN/drakvuf.log"
1786091640.977137 DRAKVUF v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel
[FILETRACER] Hooked do_syscall_64
[FILEEXTRACTOR-LINUX] Hooked do_syscall_64
[FILETRACER] syscall_cb fired (count=1) rdi=0xffffb3ccc113ff58 rsi=0x9e
[FILETRACER] syscall_cb fired (count=2) rdi=0xffffb3ccc113ff58 rsi=0xcc
[FILETRACER] syscall_cb fired (count=3) rdi=0xffffb3ccc113ff58 rsi=0x101
{"Plugin": "inject", "TimeStamp": "1786091642.367500", "Method": "ExecProc", "Status": "Success", "ProcessName": "/home/carlos/Desktop/test", "Arguments": "", "InjectedPid": 1688, "InjectedTid": 1688}
{"Plugin":"filetracer","TimeStamp":"1786091642.374504","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x263","Syscall":"openat","ThreadName":"test","dirfd":"-100","flags":"0"}
{"Plugin":"filetracer","TimeStamp":"1786091642.375018","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x264","Syscall":"read","ThreadName":"test","FileName":"/kernel/mm/transparent_hugepage/hpage_pmd_size","FileHandle":3,"count":"20"}
{"Plugin":"filetracer","TimeStamp":"1786091642.375204","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x265","Syscall":"close","ThreadName":"test","FileName":"/kernel/mm/transparent_hugepage/hpage_pmd_size","FileHandle":3}
{"Plugin":"fileextractor","TimeStamp":"1786091642.398066","PID":439,"PPID":1,"TID":439,"UserId":115,"ProcessName":"/usr/sbin/avahi-daemon","Method":"do_syscall_64","EventUID":"0x2e8","Reason":"WriteFile","FileName":"unknown_fd_7","Size":1,"DumpFile":"/malware_finished/REDACTED-RUN-MD5/00000000_unknown_fd_7","ProcessName":"avahi-daemon"}
{"Plugin":"filetracer","TimeStamp":"1786091642.398066","PID":439,"PPID":1,"TID":439,"UserId":115,"ProcessName":"/usr/sbin/avahi-daemon","Method":"do_syscall_64","EventUID":"0x2e8","Syscall":"write","ThreadName":"avahi-daemon","FileHandle":7,"count":"1"}
{"Plugin":"filetracer","TimeStamp":"1786091642.399168","PID":439,"PPID":1,"TID":439,"UserId":115,"ProcessName":"/usr/sbin/avahi-daemon","Method":"do_syscall_64","EventUID":"0x2ea","Syscall":"write","ThreadName":"avahi-daemon","FileHandle":7,"count":"1"}
{"Plugin":"filetracer","TimeStamp":"1786091642.399335","PID":439,"PPID":1,"TID":439,"UserId":115,"ProcessName":"/usr/sbin/avahi-daemon","Method":"do_syscall_64","EventUID":"0x2eb","Syscall":"write","ThreadName":"avahi-daemon","FileHandle":7,"count":"1"}
{"Plugin":"filetracer","TimeStamp":"1786091642.399606","PID":439,"PPID":1,"TID":439,"UserId":115,"ProcessName":"/usr/sbin/avahi-daemon","Method":"do_syscall_64","EventUID":"0x2ec","Syscall":"read","ThreadName":"avahi-daemon","FileHandle":6,"count":"10"}
{"Plugin":"filetracer","TimeStamp":"1786091642.400625","PID":439,"PPID":1,"TID":439,"UserId":115,"ProcessName":"/usr/sbin/avahi-daemon","Method":"do_syscall_64","EventUID":"0x2f2","Syscall":"write","ThreadName":"avahi-daemon","FileHandle":7,"count":"1"}
{"Plugin":"filetracer","TimeStamp":"1786091642.400857","PID":439,"PPID":1,"TID":439,"UserId":115,"ProcessName":"/usr/sbin/avahi-daemon","Method":"do_syscall_64","EventUID":"0x2f4","Syscall":"write","ThreadName":"avahi-daemon","FileHandle":7,"count":"1"}
{"Plugin":"filetracer","TimeStamp":"1786091642.401015","PID":439,"PPID":1,"TID":439,"UserId":115,"ProcessName":"/usr/sbin/avahi-daemon","Method":"do_syscall_64","EventUID":"0x2f5","Syscall":"write","ThreadName":"avahi-daemon","FileHandle":7,"count":"1"}
{"Plugin":"filetracer","TimeStamp":"1786091642.401170","PID":439,"PPID":1,"TID":439,"UserId":115,"ProcessName":"/usr/sbin/avahi-daemon","Method":"do_syscall_64","EventUID":"0x2f6","Syscall":"read","ThreadName":"avahi-daemon","FileHandle":6,"count":"10"}
{"Plugin":"memdump","TimeStamp":"1786091642.405171","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x310","Syscall":"clone","DumpReason":"Thread creation with shared memory","Flags":"0xd0f00"}
{"Plugin":"memdump","TimeStamp":"1786091642.406453","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x316","Syscall":"clone","DumpReason":"Thread creation with shared memory","Flags":"0xd0f00"}
{"Plugin":"memdump","TimeStamp":"1786091642.408507","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x321","Syscall":"clone","DumpReason":"Thread creation with shared memory","Flags":"0xd0f00"}
{"Plugin":"filetracer","TimeStamp":"1786091642.421850","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x366","Syscall":"openat","ThreadName":"test","FileName":"/dev/null","dirfd":"-100","flags":"524289"}
{"Plugin":"memdump","TimeStamp":"1786091642.423684","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x370","Syscall":"clone","DumpReason":"Thread creation with shared memory","Flags":"0x5100"}
{"Plugin":"memdump","TimeStamp":"1786091642.424511","PID":1692,"PPID":1688,"TID":1692,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x374","Syscall":"exit_group","DumpReason":"Process termination","ExitStatus":0}
{"Plugin":"filetracer","TimeStamp":"1786091642.426545","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x37f","Syscall":"close","ThreadName":"test","FileHandle":11}
{"Plugin":"filetracer","TimeStamp":"1786091642.427259","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x383","Syscall":"close","ThreadName":"test","FileHandle":10}
{"Plugin":"memdump","TimeStamp":"1786091642.431363","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x39c","Syscall":"clone","DumpReason":"Thread creation with shared memory","Flags":"0x5111"}
{"Plugin":"filetracer","TimeStamp":"1786091642.458015","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x432","Syscall":"close","ThreadName":"test","FileHandle":11}
{"Plugin":"filetracer","TimeStamp":"1786091642.458264","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x433","Syscall":"read","ThreadName":"test","FileHandle":10,"count":"8"}
{"Plugin":"filetracer","TimeStamp":"1786091642.458518","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x434","Syscall":"close","ThreadName":"test","FileHandle":10}
{"Plugin":"filetracer","TimeStamp":"1786091642.458842","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x436","Syscall":"close","ThreadName":"test","FileHandle":3}
{"Plugin":"filetracer","TimeStamp":"1786091642.459280","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x438","Syscall":"close","ThreadName":"test","FileHandle":8}
{"Plugin":"filetracer","TimeStamp":"1786091642.459330","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x439","Syscall":"close","ThreadName":"test","FileName":"/null","FileHandle":9}
{"Plugin":"filetracer","TimeStamp":"1786091642.462324","PID":1693,"PPID":1688,"TID":1693,"UserId":0,"ProcessName":"/usr/bin/base64","Method":"do_syscall_64","EventUID":"0x448","Syscall":"access","ThreadName":"base64","FileName":"/etc/ld.so.preload"}
{"Plugin":"filetracer","TimeStamp":"1786091642.462587","PID":1693,"PPID":1688,"TID":1693,"UserId":0,"ProcessName":"/usr/bin/base64","Method":"do_syscall_64","EventUID":"0x449","Syscall":"openat","ThreadName":"base64","FileName":"/etc/ld.so.cache","dirfd":"-100","flags":"524288"}
{"Plugin":"filetracer","TimeStamp":"1786091642.462777","PID":1693,"PPID":1688,"TID":1693,"UserId":0,"ProcessName":"/usr/bin/base64","Method":"do_syscall_64","EventUID":"0x44a","Syscall":"fstat","ThreadName":"base64","FileName":"/etc/ld.so.cache","FileHandle":3}
{"Plugin":"filetracer","TimeStamp":"1786091642.463155","PID":1693,"PPID":1688,"TID":1693,"UserId":0,"ProcessName":"/usr/bin/base64","Method":"do_syscall_64","EventUID":"0x44c","Syscall":"close","ThreadName":"base64","FileName":"/etc/ld.so.cache","FileHandle":3}
{"Plugin":"filetracer","TimeStamp":"1786091642.463387","PID":1693,"PPID":1688,"TID":1693,"UserId":0,"ProcessName":"/usr/bin/base64","Method":"do_syscall_64","EventUID":"0x44d","Syscall":"openat","ThreadName":"base64","FileName":"/lib/x86_64-linux-gnu/libc.so.6","dirfd":"-100","flags":"524288"}
{"Plugin":"filetracer","TimeStamp":"1786091642.463627","PID":1693,"PPID":1688,"TID":1693,"UserId":0,"ProcessName":"/usr/bin/base64","Method":"do_syscall_64","EventUID":"0x44e","Syscall":"read","ThreadName":"base64","FileName":"/usr/lib/x86_64-linux-gnu/libc-2.31.so","FileHandle":3,"count":"832"}
{"Plugin":"filetracer","TimeStamp":"1786091642.463864","PID":1693,"PPID":1688,"TID":1693,"UserId":0,"ProcessName":"/usr/bin/base64","Method":"do_syscall_64","EventUID":"0x44f","Syscall":"pread64","ThreadName":"base64","FileName":"/usr/lib/x86_64-linux-gnu/libc-2.31.so","FileHandle":3,"count":"784","offset":"64"}
{"Plugin":"filetracer","TimeStamp":"1786091642.464029","PID":1693,"PPID":1688,"TID":1693,"UserId":0,"ProcessName":"/usr/bin/base64","Method":"do_syscall_64","EventUID":"0x450","Syscall":"pread64","ThreadName":"base64","FileName":"/usr/lib/x86_64-linux-gnu/libc-2.31.so","FileHandle":3,"count":"32","offset":"848"}
{"Plugin":"filetracer","TimeStamp":"1786091642.464186","PID":1693,"PPID":1688,"TID":1693,"UserId":0,"ProcessName":"/usr/bin/base64","Method":"do_syscall_64","EventUID":"0x451","Syscall":"pread64","ThreadName":"base64","FileName":"/usr/lib/x86_64-linux-gnu/libc-2.31.so","FileHandle":3,"count":"68","offset":"880"}
{"Plugin":"filetracer","TimeStamp":"1786091642.464355","PID":1693,"PPID":1688,"TID":1693,"UserId":0,"ProcessName":"/usr/bin/base64","Method":"do_syscall_64","EventUID":"0x452","Syscall":"fstat","ThreadName":"base64","FileName":"/usr/lib/x86_64-linux-gnu/libc-2.31.so","FileHandle":3}
{"Plugin":"filetracer","TimeStamp":"1786091642.464681","PID":1693,"PPID":1688,"TID":1693,"UserId":0,"ProcessName":"/usr/bin/base64","Method":"do_syscall_64","EventUID":"0x454","Syscall":"pread64","ThreadName":"base64","FileName":"/usr/lib/x86_64-linux-gnu/libc-2.31.so","FileHandle":3,"count":"784","offset":"64"}
{"Plugin":"filetracer","TimeStamp":"1786091642.464844","PID":1693,"PPID":1688,"TID":1693,"UserId":0,"ProcessName":"/usr/bin/base64","Method":"do_syscall_64","EventUID":"0x455","Syscall":"pread64","ThreadName":"base64","FileName":"/usr/lib/x86_64-linux-gnu/libc-2.31.so","FileHandle":3,"count":"32","offset":"848"}
{"Plugin":"filetracer","TimeStamp":"1786091642.465013","PID":1693,"PPID":1688,"TID":1693,"UserId":0,"ProcessName":"/usr/bin/base64","Method":"do_syscall_64","EventUID":"0x456","Syscall":"pread64","ThreadName":"base64","FileName":"/usr/lib/x86_64-linux-gnu/libc-2.31.so","FileHandle":3,"count":"68","offset":"880"}
{"Plugin":"filetracer","TimeStamp":"1786091642.466383","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x45e","Syscall":"openat","ThreadName":"test","FileName":"/dev/null","dirfd":"-100","flags":"524289"}
{"Plugin":"memdump","TimeStamp":"1786091642.468464","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x46c","Syscall":"clone","DumpReason":"Thread creation with shared memory","Flags":"0x5111"}
{"Plugin":"filetracer","TimeStamp":"1786091642.470447","PID":1693,"PPID":1688,"TID":1693,"UserId":0,"ProcessName":"/usr/bin/base64","Method":"do_syscall_64","EventUID":"0x474","Syscall":"close","ThreadName":"base64","FileName":"/usr/lib/x86_64-linux-gnu/libc-2.31.so","FileHandle":3}
root@drakvuf:~/drakvuf-multios-sandbox# grep -c . "$RUN/drakvuf.log"
359517
root@drakvuf:~/drakvuf-multios-sandbox# grep -n "execve\|ENOENT\|No such file\|Desktop/test" "$RUN/drakvuf.log" | head -30
7:{"Plugin": "inject", "TimeStamp": "1786091642.367500", "Method": "ExecProc", "Status": "Success", "ProcessName": "/home/carlos/Desktop/test", "Arguments": "", "InjectedPid": 1688, "InjectedTid": 1688}
8:{"Plugin":"filetracer","TimeStamp":"1786091642.374504","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x263","Syscall":"openat","ThreadName":"test","dirfd":"-100","flags":"0"}
9:{"Plugin":"filetracer","TimeStamp":"1786091642.375018","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x264","Syscall":"read","ThreadName":"test","FileName":"/kernel/mm/transparent_hugepage/hpage_pmd_size","FileHandle":3,"count":"20"}
10:{"Plugin":"filetracer","TimeStamp":"1786091642.375204","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x265","Syscall":"close","ThreadName":"test","FileName":"/kernel/mm/transparent_hugepage/hpage_pmd_size","FileHandle":3}
20:{"Plugin":"memdump","TimeStamp":"1786091642.405171","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x310","Syscall":"clone","DumpReason":"Thread creation with shared memory","Flags":"0xd0f00"}
21:{"Plugin":"memdump","TimeStamp":"1786091642.406453","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x316","Syscall":"clone","DumpReason":"Thread creation with shared memory","Flags":"0xd0f00"}
22:{"Plugin":"memdump","TimeStamp":"1786091642.408507","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x321","Syscall":"clone","DumpReason":"Thread creation with shared memory","Flags":"0xd0f00"}
23:{"Plugin":"filetracer","TimeStamp":"1786091642.421850","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x366","Syscall":"openat","ThreadName":"test","FileName":"/dev/null","dirfd":"-100","flags":"524289"}
24:{"Plugin":"memdump","TimeStamp":"1786091642.423684","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x370","Syscall":"clone","DumpReason":"Thread creation with shared memory","Flags":"0x5100"}
25:{"Plugin":"memdump","TimeStamp":"1786091642.424511","PID":1692,"PPID":1688,"TID":1692,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x374","Syscall":"exit_group","DumpReason":"Process termination","ExitStatus":0}
26:{"Plugin":"filetracer","TimeStamp":"1786091642.426545","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x37f","Syscall":"close","ThreadName":"test","FileHandle":11}
27:{"Plugin":"filetracer","TimeStamp":"1786091642.427259","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x383","Syscall":"close","ThreadName":"test","FileHandle":10}
28:{"Plugin":"memdump","TimeStamp":"1786091642.431363","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x39c","Syscall":"clone","DumpReason":"Thread creation with shared memory","Flags":"0x5111"}
29:{"Plugin":"filetracer","TimeStamp":"1786091642.458015","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x432","Syscall":"close","ThreadName":"test","FileHandle":11}
30:{"Plugin":"filetracer","TimeStamp":"1786091642.458264","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x433","Syscall":"read","ThreadName":"test","FileHandle":10,"count":"8"}
31:{"Plugin":"filetracer","TimeStamp":"1786091642.458518","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x434","Syscall":"close","ThreadName":"test","FileHandle":10}
32:{"Plugin":"filetracer","TimeStamp":"1786091642.458842","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x436","Syscall":"close","ThreadName":"test","FileHandle":3}
33:{"Plugin":"filetracer","TimeStamp":"1786091642.459280","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x438","Syscall":"close","ThreadName":"test","FileHandle":8}
34:{"Plugin":"filetracer","TimeStamp":"1786091642.459330","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x439","Syscall":"close","ThreadName":"test","FileName":"/null","FileHandle":9}
48:{"Plugin":"filetracer","TimeStamp":"1786091642.466383","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x45e","Syscall":"openat","ThreadName":"test","FileName":"/dev/null","dirfd":"-100","flags":"524289"}
49:{"Plugin":"memdump","TimeStamp":"1786091642.468464","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x46c","Syscall":"clone","DumpReason":"Thread creation with shared memory","Flags":"0x5111"}
56:{"Plugin":"filetracer","TimeStamp":"1786091642.491506","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x4f1","Syscall":"close","ThreadName":"test","FileHandle":15}
57:{"Plugin":"filetracer","TimeStamp":"1786091642.491816","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x4f2","Syscall":"read","ThreadName":"test","FileHandle":7,"count":"32768"}
58:{"Plugin":"filetracer","TimeStamp":"1786091642.491886","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x4f3","Syscall":"write","ThreadName":"test","FileHandle":4,"count":"1375392"}
87:{"Plugin":"filetracer","TimeStamp":"1786091642.497340","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x510","Syscall":"write","ThreadName":"test","FileHandle":4,"count":"1309856"}
88:{"Plugin":"filetracer","TimeStamp":"1786091642.498012","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x511","Syscall":"write","ThreadName":"test","FileHandle":4,"count":"1244320"}
89:{"Plugin":"filetracer","TimeStamp":"1786091642.498234","PID":1688,"PPID":1415,"TID":1688,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x512","Syscall":"read","ThreadName":"test","FileHandle":14,"count":"8"}
98:{"Plugin":"filetracer","TimeStamp":"1786091642.512041","PID":1688,"PPID":1415,"TID":1691,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x568","Syscall":"read","ThreadName":"test","FileHandle":7,"count":"32768"}
99:{"Plugin":"filetracer","TimeStamp":"1786091642.512346","PID":1688,"PPID":1415,"TID":1691,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x569","Syscall":"write","ThreadName":"test","FileHandle":4,"count":"1244320"}
100:{"Plugin":"filetracer","TimeStamp":"1786091642.512503","PID":1688,"PPID":1415,"TID":1691,"UserId":0,"ProcessName":"/home/carlos/Desktop/test","Method":"do_syscall_64","EventUID":"0x56a","Syscall":"write","ThreadName":"test","FileHandle":4,"count":"1240224"}
root@drakvuf:~/drakvuf-multios-sandbox# cat "$RUN/preconfig.log"
DRAKVUF injector v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel
Injector starting /usr/bin/sh through PID 1415 TID: 0
[INJECT] TIME:1786091635.198324 METHOD:ExecProc STATUS:SUCCESS PID:1415 FILE:"/usr/bin/sh" ARGUMENTS:"-c sudo ip addr flush dev eth0 && sudo ip addr add 172.16.1.2/24 dev eth0 && sudo ip route replace default via 172.16.1.1 dev eth0 && echo 'nameserver 172.16.1.1' | sudo tee /etc/resolv.conf && wget 'http://172.16.1.1/91876d9a8ed450057993efe35f8ee8465a09c0b4ba82f0327b82b91ab072aebd' -O '/home/carlos/Desktop/test' && chmod +x '/home/carlos/Desktop/test'" INJECTED_PID:1634 INJECTED_TID:1634
Process startup success
root@drakvuf:~/drakvuf-multios-sandbox# ls -la "$RUN"
total 120928
drwxr-xr-x 2 root    root        4096 ago  7 10:35 .
drwxr-xr-x 8 root    root        4096 ago  2 10:35 ..
-rw-r--r-- 1 root    root     5167467 ago  7 10:36 00000000_unknown_fd_7
-rw-r--r-- 1 root    root      861323 ago  7 10:36 00000001_unknown_fd_4
-rw-r--r-- 1 root    root      566445 ago  7 10:35 00000002_unknown_fd_8
-rw-r--r-- 1 root    root        9583 ago  7 10:35 00000003_unknown_fd_3
-rw-r--r-- 1 root    root       15386 ago  7 10:35 00000004_unknown_fd_10
-rw-r--r-- 1 root    root       23101 ago  7 10:35 00000005_unknown_fd_6
-rw-r--r-- 1 root    root        2896 ago  7 10:35 00000006_unknown_fd_9
-rw-r--r-- 1 root    root     2568424 ago  7 10:35 00000007_unknown_fd_5
-rw-r--r-- 1 root    root        6119 ago  7 10:35 00000008__apparmor_.access
-rw-r--r-- 1 root    root     5135319 ago  7 10:35 00000009_unknown_fd_13
-rw-r--r-- 1 root    root         360 ago  7 10:35 00000010_unknown_fd_14
-rw-r--r-- 1 root    root         240 ago  7 10:35 00000011_unknown_fd_15
-rw-r--r-- 1 root    root         334 ago  7 10:35 00000012__NetworkManager_devices_2.MDVYT3
-rw-r--r-- 1 root    root         192 ago  7 10:35 00000013_unknown_fd_19
-rw-r--r-- 1 root    root          96 ago  7 10:35 00000014_unknown_fd_16
-rw-r--r-- 1 root    root          96 ago  7 10:35 00000015_unknown_fd_17
-rw-r--r-- 1 root    root          50 ago  7 10:35 00000016__system.slice_NetworkManager-dispatcher.service_memory.limit_in_bytes
-rw-r--r-- 1 root    root          80 ago  7 10:35 00000017_unknown_fd_23
-rw-r--r-- 1 root    root          24 ago  7 10:34 00000018_unknown_fd_20
-rw-r--r-- 1 root    root         656 ago  7 10:34 00000019__systemd_journal_streams_.#8:492113tkkL8
-rw-r--r-- 1 root    root          10 ago  7 10:34 00000020__system.slice_apt-daily.service_cgroup.procs
-rw-r--r-- 1 root    root         437 ago  7 10:35 00000021__systemd_journal_streams_.#8:49860VHLJj8
-rw-r--r-- 1 root    root          40 ago  7 10:35 00000022__system.slice_esm-cache.service_memory.limit_in_bytes
-rw-r--r-- 1 root    root       81990 ago  7 10:34 00000023_unknown_fd_12
-rw-r--r-- 1 root    root    10268456 ago  7 10:35 00000024__tmp_clearsigned.message.Frlcuo
-rw-r--r-- 1 root    root         675 ago  7 10:35 00000025__systemd_journal_streams_.#8:50785hYlgW8
-rw-r--r-- 1 root    root          24 ago  7 10:34 00000026_unknown_fd_24
-rw-r--r-- 1 root    root         267 ago  7 10:35 00000027__apparmor_.access
-rw-r--r-- 1 root    root        1997 ago  7 10:35 00000028__apparmor_.access
-rw-r--r-- 1 root    root    98996807 ago  7 10:36 drakvuf.log
-rw-r--r-- 1 root    root         663 ago  7 10:33 preconfig.log
-rw-r--r-- 1 tcpdump tcpdump    11034 ago  7 10:35 tcpdump.pcap


Runs inspected (md5s): REDACTED-RUN-MD5
Any trace showing the staged sample executing (yes | no | inconclusive): yes
Excerpt:
```

---

## R3 — one benign A/B run (only if R1 + R2 were inconclusive) - Not necessary R1 + R2 are conclusive

The A/B design avoids having to know DRAKVUF's exact error wording: run the same
pipeline twice, changing **only** the `CMD` path, and compare. Two independent
observation channels are used, because `cleanup.sh` destroys the clone after each
run and the guest filesystem cannot be inspected afterwards.

### R3.1 — build two benign samples

Each writes a marker file *and* beacons the lab gateway, so execution is
observable from Dom0 even after the clone is gone.

```bash
# Run on L1: Xen Dom0
mkdir -p /tmp/verify-issue2

for LABEL in A B; do
  cat > "/tmp/verify-issue2/benign-$LABEL" <<EOF
#!/bin/sh
# Benign verification sample for issue #2 — no payload, lab gateway only.
touch "/tmp/drakvuf-verify-$LABEL"
GW=\$(ip route | awk '/^default/{print \$3; exit}')
[ -n "\$GW" ] && wget -q -O /dev/null "http://\$GW/EXECUTED-$LABEL"
exit 0
EOF
  chmod +x "/tmp/verify-issue2/benign-$LABEL"
done

# Distinct content => distinct MD5 => distinct /malware_finished/<md5>/ dirs,
# which avoids the two runs colliding on the same output directory.
md5sum /tmp/verify-issue2/benign-A /tmp/verify-issue2/benign-B
```

> If R0 shows `-e` requires a real ELF rather than accepting a `#!` script,
> rebuild these as a small `gcc -static` binary doing the same two actions and
> note the substitution in the evidence block.

### R3.2 — build the control script (never edit the deployed file)

`dirwatch`'s `<drakvuf_script>` is `argv[12]` (`automation/dirwatch.c:484`), so
run B is redirected purely by argument. The deployed script stays untouched, and
the control copy is a temp file that is never committed.

```bash
# Run on L1: Xen Dom0
sed 's|/home/<USER>/Desktop/test|/home/carlos/Desktop/test|' \
    /home/user/drakvuf-tools/drakvuf-ubuntu.sh \
    > /tmp/verify-issue2/drakvuf-ubuntu-control.sh
chmod +x /tmp/verify-issue2/drakvuf-ubuntu-control.sh

# Confirm exactly one line differs.
diff -u /home/user/drakvuf-tools/drakvuf-ubuntu.sh \
        /tmp/verify-issue2/drakvuf-ubuntu-control.sh
```

### R3.3 — run A (deployed script, as-is)

```bash
# Run on L1: Xen Dom0, as root
ip link set xenbr1 up
/home/user/drakvuf-tools/network-setup.sh 2

dirwatch 1 \
    ubuntu_sandbox \
    /home/user/drakvuf-tools/ubuntu_sandbox.cfg \
    /root/linux.json \
    1415 \
    /malware_incoming \
    /malware_processing \
    /malware_finished \
    2 \
    /home/user/drakvuf-tools/clone-ubuntu.pl \
    /home/user/drakvuf-tools/preconfig-ubuntu.sh \
    /home/user/drakvuf-tools/drakvuf-ubuntu.sh \
    /home/user/drakvuf-tools/cleanup.sh \
    /home/user/drakvuf-tools/tcpdump.sh

# In a second shell, once dirwatch is watching:
cp /tmp/verify-issue2/benign-A /malware_incoming/
# Wait for the run to finish (drakvuf trace timeout is 120s; dirwatch's phase
# guard is 180s), then Ctrl-C dirwatch.
```

### R3.4 — run B (control script, `carlos` substituted)

Identical invocation with **one** argument changed — the 12th:

```bash
# Dirwatch is in polling mode from running benign-A

cp /tmp/verify-issue2/benign-B /malware_incoming/
```

### R3.5 — compare

```bash
# Run on L1: Xen Dom0
MD5A=$(md5sum /tmp/verify-issue2/benign-A | awk '{print $1}')
MD5B=$(md5sum /tmp/verify-issue2/benign-B | awk '{print $1}')

# Channel 1 — the DRAKVUF traces themselves.
wc -l /malware_finished/$MD5A/drakvuf.log /malware_finished/$MD5B/drakvuf.log
diff -u /malware_finished/$MD5A/drakvuf.log /malware_finished/$MD5B/drakvuf.log | head -60
grep -n "drakvuf-verify\|EXECUTED-" /malware_finished/$MD5A/drakvuf.log | head
grep -n "drakvuf-verify\|EXECUTED-" /malware_finished/$MD5B/drakvuf.log | head

# Channel 2 — the HTTP beacon, independent of DRAKVUF log wording.
grep -n "EXECUTED-A\|EXECUTED-B" /var/log/apache2/access.log | tail -20

# Channel 2b — the same beacon in the captured pcap.
ls -la /malware_finished/$MD5A/ /malware_finished/$MD5B/
# (use the per-sample pcap written by tcpdump.sh)
tcpdump -r /malware_finished/$MD5B/*.pcap -A 2>/dev/null | grep -c "EXECUTED-B"
```

**Expected under H2:** run A shows no marker, no beacon, and a sparse trace; run
B shows the beacon in Apache's log and the marker in `filetracer`/`syscalls`
output. **Expected under H1/not-a-bug:** both runs behave the same.

```text
R3 EVIDENCE — paste output here

MD5 A / MD5 B:
Run A — beacon in apache log (yes/no):
Run A — marker/exec evidence in drakvuf.log (yes/no):
Run B — beacon in apache log (yes/no):
Run B — marker/exec evidence in drakvuf.log (yes/no):
drakvuf.log line counts (A / B):
Excerpt:
```

### R3.6 — clean up

```bash
rm -rf /tmp/verify-issue2
rm -f /malware_incoming/benign-A /malware_incoming/benign-B
# Keep /malware_finished/<md5>/ for both runs — that is the evidence.
```

---

## Decision table

Fill this in and copy it into `docs/checklists/ubuntu.md`'s "Evidence and notes"
section, replacing the current source-reading-only entry.

| Axis | Outcome | Verdict |
|---|---|---|
| H1 vs H2 (from R1) | deployed copy has `carlos` | Production fine; repo copy stale — repo-staleness defect only |
| H1 vs H2 (from R1) | deployed copy has literal `<USER>` | Continue to R2/R3; production bug likely |
| Execution (R2/R3) | sample demonstrably ran | `<USER>` path is not fatal — investigate why before concluding |
| Execution (R2/R3) | sample demonstrably did not run | **Bug confirmed**; the "Ubuntu works" M1 baseline is invalid |
| Execution (R2/R3) | inconclusive | Record as inconclusive; do **not** tick the checklist item |
| H3 (from R0) | `-e` is execve-direct | Fix must be a literal/parameterized path resolved on Dom0 |
| H3 (from R0) | `-e` is shell-mediated in guest | Fix may legitimately use a guest-side `$USER` form |

```text
FINAL VERDICT

Date run: 2026-08-08
Run by:   project owner, on the real Xen Dom0 host
Steps completed: R0, R1, R1b, R2. R3 skipped — not required, R1+R2 conclusive.

H1/H2:  H1 CONFIRMED, H2 REFUTED.
        The deployed /home/user/drakvuf-tools/drakvuf-ubuntu.sh has
        CMD="/home/carlos/Desktop/test" (sha256 76bc801b...), correctly
        substituted per the setup guide. This repository's copy
        (sha256 d0a17e4e...) is the stale, never-substituted one.
        Production was never broken by the <USER> placeholder.

Execution: CONFIRMED — samples do execute.
        Run REDACTED-RUN-MD5 (2026-08-07) shows
        {"Plugin":"inject","Method":"ExecProc","Status":"Success",
         "ProcessName":"/home/carlos/Desktop/test","InjectedPid":1688}
        followed by ~359k trace lines attributed to PID 1688, ending in
        exit_group ExitStatus 0. R1b confirms the guest user is carlos and
        that the wget staging step succeeded on all six recorded runs.

H3:     REFUTED — -e is execve-direct, no guest shell is involved.
        injector --help: "execproc - Run any process using vfork and execve
        ( -e for specifying the program, -f for args )" and "[LINUX]
        (execproc -> execve(const char *file, const char *argv[],
        const char* envp[]); 64bit only)". drakvuf --help: "[LINUX]:
        execproc -> execlp()". Confirmed against source at
        /home/user/drakvuf/src/{main.cpp:196,injector.cpp:180-185}.
        No shell means no guest-side expansion: a $USER in the -e argument
        would never dereference. Any fix must resolve the path on Dom0.
        Corollary: the repo's literal <USER> path would fail with ENOENT if
        it were ever deployed — mechanically certain from R0, though never
        observed in production because it was never deployed.

NEW FINDING — repo/host drift is wider than the <USER> line.
        The R1 diff shows the two copies differ on TWO lines, not one:
          1. CMD=            <USER> (repo)        vs carlos (deployed)
          2. drakvuf invocation:
             - repo has  -a syscalls        ; deployed does NOT
             - repo has  --memdump_dir  (underscore, trailing slash)
               deployed has --memdump-dir (hyphen,     no slash)
        Corroborated by the trace: run cd22b2c6 contains no
        {"Plugin":"syscalls"} records at all, consistent with the deployed
        copy omitting -a syscalls.
        Deployed file mtime 2026-08-07 10:28, minutes before the recorded
        runs — i.e. the host copy is the newer, working one and this
        repository has never been synced from it.
        Unverified: whether --memdump_dir (underscore) is even accepted by
        this DRAKVUF build. The captured help shows hyphenated memdump
        options (--memdump-disable-free-vm); one line settles it:
            drakvuf --help 2>&1 | grep -i memdump

Follow-up — ALL COMPLETED 2026-08-08, same day:
        1. DONE. automation/ synced wholesale from the tested production
           host. drakvuf-ubuntu.sh, network-setup.sh and dirwatch_old.c
           differed; the reconciliation deliberately KEEPS -a syscalls and
           adds it on the host too, then was re-tested with a sample.
        2. DONE. --memdump-dir (hyphen) confirmed correct from the build's
           own help: "--memdump-dir <directory>  Where to store memory
           dumps". The repo's --memdump_dir was wrong and would have been
           rejected.
        3. DONE. Full audit: dirwatch.c, preconfig-ubuntu.sh, cleanup.sh,
           clone-ubuntu.pl and tcpdump.sh were already byte-identical to the
           host. Drift was confined to the three files above.
        4. BONUS. Issue #1's outstanding host-side rename was completed at
           the same time (linux_sandbox.cfg -> ubuntu_sandbox.cfg), so
           run_analysis-ubuntu.sh now agrees on both sides. Repo and host no
           longer diverge anywhere.

Remaining open, not part of issue #2:
        - Nothing detects this drift automatically. A repo-vs-host checksum
          comparison belongs in DRAFT-026's self-hosted Dom0 CI tier.
        - Parameterizing the hard-coded guest username `carlos` (present in
          both drakvuf-ubuntu.sh and preconfig-ubuntu.sh) remains open M1
          work.
```

## After the run — ALL COMPLETED 2026-08-08

1. [x] Verdict and log excerpts recorded in `docs/checklists/ubuntu.md`;
   Known-issues checkbox ticked and the "Current blocker" row cleared.
2. [x] `docs/roadmap/project-roadmap.md` risk #7 closed, risk #11 (the drift
   this uncovered) opened and closed the same day, M1 row and current-state
   paragraph updated.
3. [x] `CLAUDE.md`'s known-issues bullet rewritten — the verdict did change it.
4. [x] Issue #2 closed as completed with the verdict as a closing comment;
   issue #4's body refreshed; a follow-up note added to the closed issue #1.
   `DRAFT-007.md`, `DRAFT-025.md` and `issue-index.md` updated to match. All of
   it went through `CONTRIBUTING.md`'s Stage-2 gate with explicit approval.
5. [x] No fix was needed — the deployed copy was already correct. What *was*
   needed, syncing `automation/` from the host, was done separately and
   deliberately rather than folded into this verification.

Remaining, deliberately **not** part of this runbook: automated drift
detection (folded into DRAFT-026) and parameterizing the hard-coded guest
username (open M1 work).