# Verify screenshots (DRAFT-054) and the destroy-before-collect order

> **Status: NOT EXECUTED.** Written 2026-10-30, parked at the repository root
> until its EVIDENCE blocks are filled, then filed as `docs/runbooks/NN-…`
> (the `runbook` skill). **Every command below is Candidate** — none has run
> on this project's Dom0.

What this verifies, from DRAFT-054's evidence list and the operator's
2026-10-30 additions:

1. Frames are captured from Dom0, with nothing in the guest, on all three
   guests.
2. Capture does not measurably change the trace.
3. A guest that fails produces frames showing it.
4. Frame timing holds against the 2 s interval.
5. The clone is gone before `collecting`, and the console closes with it.
6. No capture or relay socket outlives its job.
7. The env templates render once, at mode 600, without duplicating lines.
8. The Screenshots tab works on the deployment, and frames download wrapped.

Design: `docs/architecture/screenshots.md`. Code: `sandboxd/screenshots.py`,
`sandboxd/stages.py` (`Analysis.run`), `platform/sandbox_platform/enums.py`
(`CONSOLE_STATES`).

---

## A. Deploy

The platform changed too (the console window), so both hosts are deployed —
platform first, as `docs/DEVELOPING.md` §6 orders it. There is no migration.

```bash
# PLATFORM DOMU
cd /opt/platform/src && sudo -u platform git pull --ff-only && git log --oneline -1
sudo systemctl restart sandbox-api && systemctl is-active sandbox-api
```

Expect `active`.

```bash
# DOM0
cd /root/drakvuf-multios-sandbox && git pull --ff-only && git log --oneline -1
grep -n '^SANDBOXD_SCREENSHOTS_ENABLED' /etc/sandboxd/sandboxd.env || echo "unset: capture is ON by default"
```

**This runbook reads each job's results on Dom0**, which `sandboxd` deletes
after a successful upload unless told to keep them. Set
`SANDBOXD_KEEP_RESULTS=1` in `/etc/sandboxd/sandboxd.env` for the duration,
and set it back to `0` under "After execution".

Then restart `sandboxd` in its own terminal, exactly as `DEVELOPING.md` §6
gives it. With capture on, the start-up log has **no** line saying
`screenshots are off on this host`.

```text
EVIDENCE A
```

---

## B. A filmstrip from each guest

Submit, through the UI, a benign test sample that opens a window at a known
moment — one per guest: Ubuntu, Android, Windows. Note each job id. When each
job has completed:

```bash
# DOM0 -- J is the job id from the UI
J=<job-id>
ls /var/lib/sandboxd/results/$J/screenshots | head -3
ls /var/lib/sandboxd/results/$J/screenshots | wc -l
python3 - /var/lib/sandboxd/results/$J/screenshots.json <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
data = d["data"]
ms = sorted(f["ms"] for f in data["frames"]) or [0]
print("status:", d["status"], "|", d["status_reason"])
print("frames:", len(data["frames"]), "of", data["ticks"], "ticks; interval", data["interval_s"])
print("capture ms: p50", ms[len(ms) // 2], "max", ms[-1])
print("sizes:", sorted({(f["width"], f["height"]) for f in data["frames"]}))
print("marks:", data["marks"])
print("missed:", data["missed"][:5])
EOF
```

What to expect:

- `status: complete`, or `partial` with a reason you can act on.
- Frame numbers `000.png` upward.
- `trace_start` and `trace_end` marks present.

Then open the frames nearest `trace_start / 2` and after it, and look for the
window — `scp` them off Dom0, or use the job's Artifacts tab, where each frame
is a wrapped download.

**What the `capture ms` line answers (Part D):** whether one connection per
frame keeps up with the interval.

```text
EVIDENCE B-ubuntu
```

```text
EVIDENCE B-android
```

```text
EVIDENCE B-windows
```

---

## C. Capture does not disturb the trace

Two runs of the same Ubuntu sample, one with capture and one without. Run the
second with `sandboxd` restarted with capture off, for that run only:

```bash
# DOM0 -- in sandboxd's terminal, after stopping it
cd /root/drakvuf-multios-sandbox
set -a; . /etc/sandboxd/sandboxd.env; set +a
SANDBOXD_SCREENSHOTS_ENABLED=0 .venv-sandboxd/bin/python -m sandboxd.daemon 2>&1 \
  | tee -a /var/log/sandboxd/$(date +%Y%m%d-%H%M).log
```

Expect `screenshots are off on this host` at start-up. After the second job,
restart it normally again. Then compare:

```bash
# DOM0
for J in <job-with-capture> <job-without-capture>; do
  echo "$J $(zcat /var/lib/sandboxd/results/$J/syscall.log.gz | wc -l) syscalls"
done
```

Expect the two counts within ordinary run-to-run variation. Part H of
`12-baremetal-trial.md` measured a 0.6% spread on throughput; a much larger
gap is a finding.

```text
EVIDENCE C
```

---

## D. Frame timing

From Part B's output for each guest:

- **p50 well under 2000 ms** — capture keeps up with the interval.
- **Any `overrun` reasons under `missed`** — frames took longer than the
  interval.
- **Many overruns** — record them as a FINDING. The fallbacks in
  `screenshots.md` §1.3 then become the next step.

```text
EVIDENCE D
```

---

## E. A guest that fails

A Windows run with the default plugin set has been seen to bugcheck
(TROUBLESHOOTING, "The Windows guest bugchecks `0x1e`"). The next one that does
is this test.

```bash
# DOM0
xl dmesg | grep GUEST_CRASH | tail -3
```

Then look at the last frames of that job (Part B commands). Expect the crash
screen.

```text
EVIDENCE E
```

---

## F. The clone is gone before `collecting`; nothing outlives the job

While a job shows `collecting` in the UI:

```bash
# DOM0
xl list | grep -- '-clone' || echo "no clone domains"
```

Expect no clone for that job's VLAN. The job page's console panel should also
be gone at `collecting`. After the job completes:

```bash
# DOM0
ss -tnp | grep '127.0.0.1:59' || echo "nothing connected to a VNC console"
ls -a /var/lib/sandboxd/results | grep '^\.screens-' || echo "no temporary frames left"
```

Expect both `echo` lines.

```text
EVIDENCE F
```

---

## F2. The Screenshots tab, on the deployment

Open a Part B job's **Screenshots** tab in the browser.

- The large frame shows and the thumbnails load.
- **Play** steps through the frames, holding over any gap in the ticks.
- The `sample started` chip appears on the first frame after `trace_start`.
- **download this frame** arrives as a ZIP with the password `infected`, not as
  a PNG.

Then check the route's refusals:

```bash
# PLATFORM DOMU -- J is a Part B job id; <platform-address> is the DomU's LAN address
# (CURRENT-STATE says .10, the Makefile now .12 -- use whichever it is). Expect 200 image/png, then 404.
curl -sk -o /dev/null -w '%{http_code} %{content_type}\n' -b "sandbox_access=<a session cookie>" \
  "https://<platform-address>:8000/api/v1/jobs/$J/screenshot?name=screenshots%2F000.png"
curl -sk -o /dev/null -w '%{http_code}\n' -b "sandbox_access=<a session cookie>" \
  "https://<platform-address>:8000/api/v1/jobs/$J/screenshot?name=trace.stderr"
```

```text
EVIDENCE F2
```

---

## G. The env templates

The next time `make sandboxd` and `make web_sandbox` run — not by hand for this
runbook, since both targets do a great deal more:

```bash
# DOM0
stat -c '%a %U' /etc/sandboxd/sandboxd.env
grep -c '^SANDBOXD_API=' /etc/sandboxd/sandboxd.env
grep -n '@[A-Z_]*@' /etc/sandboxd/sandboxd.env || echo "all placeholders rendered"
```

Expect `600 root`, then `1`, then the `echo` line.

```bash
# PLATFORM DOMU
stat -c '%a %U' /etc/sandbox_platform/api.env
grep -c '^JWT_SIGNING_KEY=' /etc/sandbox_platform/api.env
grep -n '^RETENTION_DAYS=' /etc/sandbox_platform/api.env
```

Expect `600 platform`, then `1`, then `RETENTION_DAYS=` equal to the
Makefile's `S3_RETENTION`. `make web_sandbox` also now runs the store's
`conformance.py` after nginx is up — paste its last lines too.

```text
EVIDENCE G
```

---

## After execution

- Set `SANDBOXD_KEEP_RESULTS=0` again in `/etc/sandboxd/sandboxd.env`, then
  restart `sandboxd`.
- Fill every EVIDENCE block, then move this file to `docs/runbooks/NN-verify-screenshots.md`.
- Tick the boxes in `docs/checklists/platform.md` that the evidence supports.
- Update the two 2026-10-30 rows in `docs/CURRENT-STATE.md` §1.5.
- Regenerate, per the `runbook` skill.
- Move DRAFT-054 to `completed/`, and mark its row Completed in
  `issue-index.md`, once Parts B to F2 are evidenced.
