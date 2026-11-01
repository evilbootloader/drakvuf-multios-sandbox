# Verify the drop location, subfolder, command line and results cleanup

> **Status: NOT EXECUTED.** Written 2026-11-01, parked at the repository root
> until its EVIDENCE blocks are filled, then filed as `docs/runbooks/NN-…`
> (the `runbook` skill). **Every command below is Candidate.** None has run
> on this project's Dom0.

What this verifies (design: `docs/architecture/analysis-pipeline.md`, "Where
the sample is dropped, and its command line"):

1. A job that chooses nothing runs exactly as before: default folder, no
   `mkdir`, `exec "$1"`.
2. A chosen location and subfolder are where the sample actually runs from,
   on each guest.
3. The subfolder exists before `writefile` lands, and how long that took.
4. Linux arguments arrive as separate argv elements, hostile text included.
5. Windows arguments follow the file name. A command line with a cmd.exe
   metacharacter loses the delay, keeps its bytes, and the job says so. A
   `.ps1` gets the delay too.
6. The form shows the analysis username from the Makefile.
7. A completed job's results directory is deleted on Dom0 after its upload;
   a failed one is kept.

Code: `sandboxd/guests.py` (`resolve_launch`, `argv_make_drop_dir`,
`_linux_launch`, `_windows_launch`, `launch_caveat`), `sandboxd/stages.py`
(`_deliver_into_subdir`), `platform/sandbox_platform/launch.py`.

Use a **benign test binary** that prints its own path and argv, never a real
sample. One per guest:

- Ubuntu and Android: a static ELF.
- Windows: a console `.exe`.

---

## A. Deploy

There is a migration (`0013_launch_options.sql`), so the platform is deployed
with `docs/DEVELOPING.md` §5.4: **stop, migrate, start**, in that order. Run
`--status` first and expect `0013_launch_options.sql` as the only pending
file. Then:

```bash
# PLATFORM DOMU
grep -n '^ANALYSIS_USERNAME=' /etc/sandbox_platform/api.env || echo "unset: the form shows 'user'"
```

`api.env` gains `ANALYSIS_USERNAME` only the next time `make web_sandbox`
renders it. Until then, add the line by hand with the Makefile's
`ANALYSIS_VM_USER`, keeping mode 600.

```bash
# DOM0
cd /root/drakvuf-multios-sandbox && git pull --ff-only && git log --oneline -1
grep -n '^ANALYSIS_USERNAME' sandboxd/config.py
```

**Parts B–E read each job's results on Dom0**, which `sandboxd` now deletes
after a successful upload. Set `SANDBOXD_KEEP_RESULTS=1` in
`/etc/sandboxd/sandboxd.env` for those parts; Part G sets it back.

Then restart `sandboxd` as `DEVELOPING.md` §6 gives it. With the switch set,
the start-up log says `results directories are kept after upload`.

```text
EVIDENCE A
```

---

## B. Nothing chosen is unchanged

Submit the Ubuntu test binary with the Execution fields left alone. When it
completes:

```bash
# DOM0 -- J is the job id
J=<job-id>
grep -c '"/usr/bin/mkdir"' /var/log/sandboxd/*.log || echo "no mkdir injected"
zcat /var/lib/sandboxd/results/$J/syscall.log.gz | grep -m1 do_execveat_common
```

Expect `no mkdir injected`, and the execve's `FileName` under the Desktop
path that CURRENT-STATE §1.4 gives.

```text
EVIDENCE B
```

---

## C. Ubuntu: `/tmp`, a subfolder, hostile arguments

In the form, choose **ubuntu**, **Temp — /tmp**, subfolder `a b/c`, and
arguments:

```text
--name 'two words' '$(id)' ';' "x\"y"
```

The "Runs as" line should read `/tmp/a b/c/<file> --name 'two words' …`. After
the job completes:

```bash
# DOM0
J=<job-id>
zcat /var/lib/sandboxd/results/$J/syscall.log.gz | grep -m1 do_execveat_common
grep -h 'injector writefile\|injector mkdir' /var/log/sandboxd/*.log | tail -5
```

Expect:

- `FileName` = `/tmp/a b/c/<file>`.
- The binary's printed argv shows **five** separate arguments: `--name`,
  `two words`, `$(id)`, `;`, `x"y`. If the `procmon` output carries argv, use
  that; otherwise use the screenshot strip or the binary's own output file.
- The number of `writefile` attempts, which is the measured answer to
  `DROP_DIR_TIMEOUT`.

```text
EVIDENCE C
```

---

## D. Android: a subfolder under `/data/local/tmp`

Choose **android**, subfolder `drop`, arguments `-v 1`. Expect `FileName` =
`/data/local/tmp/drop/<file>` and two arguments. Then submit any benign APK
with arguments set: it should complete, and its notes should read "command
line not passed: an APK is started by its launcher activity".

```text
EVIDENCE D
```

---

## E. Windows: a location, a subfolder, both launch forms

1. Choose **windows**, **ProgramData**, subfolder `Vendor (x86)`, arguments
   `/S /D=C:\x`. Expect the sample under `C:\ProgramData\Vendor (x86)\` and a
   child of `cmd.exe` (the delayed form). The job has no launch note.
2. Same, but arguments `--out "C:\a b"`. Expect the sample started directly,
   with the quote intact in its command line. The job's notes say "started
   without the 5s launch delay".
3. A benign `.ps1` that writes its arguments to a file, arguments
   `-Mode quiet`. Expect `powershell.exe` as a child of `cmd.exe` (the
   delayed form, new for `.ps1` on 2026-11-01), `-Mode quiet` reaching the
   script, and no launch note.

For each:

```bash
# DOM0
J=<job-id>
python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('startup'))" \
  /var/lib/sandboxd/results/$J/report.json
```

```text
EVIDENCE E
```

---

## F. The form

On the deployment's submit page:

- The location select shows `/home/<ANALYSIS_VM_USER>/…` for ubuntu.
- It switches to the `C:\Users\<ANALYSIS_VM_USER>\…` list for windows, and
  to `/data/local/tmp` alone for android.
- A subfolder of `../x` is refused on the page with "not a plain relative
  path".

```text
EVIDENCE F
```

---

## G. Results are deleted after upload

Set `SANDBOXD_KEEP_RESULTS=0` in `/etc/sandboxd/sandboxd.env` and restart
`sandboxd`. The start-up log no longer says `results directories are kept`.
Submit the Ubuntu test binary twice, with nothing chosen. Let the first
complete; cancel the second while it is `executing`, so it ends `cancelled`.

```bash
# DOM0 -- J1 completed, J2 cancelled
ls -d /var/lib/sandboxd/results/<J1> 2>/dev/null || echo "J1 removed after upload"
ls -d /var/lib/sandboxd/results/<J2>
```

Expect the `echo` line for J1, and J2's directory listed. Also check that
J1's artifacts still download from its job page.

```text
EVIDENCE G
```

---

## After execution

- Fill every EVIDENCE block, then move this file to
  `docs/runbooks/NN-verify-launch-options.md`.
- Tick the boxes in `docs/checklists/platform.md` that the evidence supports.
- Update the 2026-11-01 row in `docs/CURRENT-STATE.md` §1.5. Remove
  "Candidate" from each location that Part C, D or E exercised.
- Replace `DROP_DIR_TIMEOUT`'s "UNMEASURED" with the Part C number.
- Leave `SANDBOXD_KEEP_RESULTS=0` as Part G set it.
- Regenerate, per the `runbook` skill.
