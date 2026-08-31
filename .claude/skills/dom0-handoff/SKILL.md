---
name: dom0-handoff
description: How to hand work to the operator for execution on Xen Dom0 — which commands cannot run in the development container, how to present them so they are safe to paste, what output to ask back, and the destructive operations that must never be run against the deployment. Load before proposing any xl, drakvuf, injector, lvm, ovs-vsctl or iptables command, or any check that needs a real guest.
---

# Handing work to Dom0

## When this matters

Load this whenever the next useful step needs a machine this container is not.
`CLAUDE.md` lists the binaries that cannot run here; this is the *procedure*
for handing over, which nothing else records.

## The boundary

**The development container is not Xen Dom0.** These cannot run here and must
be presented for manual execution: `xl`, `drakvuf`, `injector`,
`vmi-process-list`, `lvcreate`, `lvremove`, `lvs`, `vgs`, `ovs-vsctl`,
`iptables`, `nft`.

Neither is it the platform DomU. Anything reaching Postgres, MinIO or the
running API belongs there instead, and the two are **not** interchangeable —
since the migration the platform is a *guest of* Dom0, not its sibling.

## How to present a command

Label the shell it runs in, because this project has three and a command pasted
into the wrong one is how real damage happens:

```bash
# DOM0
xl vcpu-list 0
```

Rules that have each cost something:

- **Absolute paths.** `cd ~/drakvuf` failed because the checkout is at
  `/home/user/drakvuf` and `~` differs under `sudo`; the following commands ran
  in the wrong directory because they were chained with newlines, not `&&`.
- **`&&`, not newlines**, when a later command is meaningless if an earlier one
  failed.
- **Never invent an option.** Check `--help`, the source, or existing output
  first. `vmi-process-list -h` is not a help flag — it is parsed as a domain
  name and fails complaining about root access.
- **One purpose per block.** An operator pastes what you give them; a block
  that both diagnoses and changes state cannot be half-run.
- **Say what you expect to see.** "Expect exactly one match; zero or several
  means the injection target is ambiguous, and `injector` will not tell you."

## Starting `sandboxd`

**There is no systemd unit.** `journalctl -u sandboxd` and
`systemctl stop sandboxd` both report nothing, and assuming otherwise is one of
the four wrong assertions that caused `docs/CURRENT-STATE.md` to be written.

**Source the environment file first.** `python -m sandboxd.daemon` on its own
exits immediately — `Settings.from_env` raises `SystemExit` when
`SANDBOXD_API`, `WORKER_TOKEN` or `SANDBOXD_TOTAL_MIB` is unset, deliberately,
because there is no safe default for how much memory a Dom0 may hand to clones.
That failure looks like a broken install and is not. The exact invocation is in
`CURRENT-STATE.md` §1.2.

`sandboxd` now provisions the analysis network at startup, so `network-setup.sh`
no longer has to be run by hand first — but the bridge itself is still a
one-time install step (`ovs-vsctl add-br xenbr1`).

## Never, against the deployment

- **The platform test suite.** Its `conn` fixture runs
  `TRUNCATE jobs, worker_pipelines, workers RESTART IDENTITY CASCADE`. It was
  attempted on 2026-08-25 and failed with 312 errors because
  `sandbox_platform_test` does not exist there — **the correct response is not
  to create it.** Verify the deployment with the runbook's `curl` checks and by
  looking at the UI.
- **`playwright install`.** 47.7 MB landed on the deployment once already.
- **Operating on the golden LVs, the saved `*_sandbox.bak` state, or real
  malware samples** unless explicitly instructed.
- **Restoring a `.bak` against a disk it was not saved from.** The pairing is
  not advisory; it produced silent filesystem corruption that stayed invisible
  until `xl create`, because every earlier check reads only RAM.

## What to ask back

Ask for the **command and its output together**, pasted. A reported result is
not evidence — `docs/CURRENT-STATE.md` §3 counts pasted host prompts precisely
because status banners written before execution are routinely never updated.

Then, if it belongs in the record:

- **Deployment facts** → a `CURRENT-STATE.md` capability row, with today's date.
- **A procedure that worked** → the runbook, via the `runbook` skill.
- **Anything that went wrong** → `docs/TROUBLESHOOTING.md`, symptom first.

**Attested is not pasted.** If the operator says a thing ran, that is a real
fact and belongs in the hand-maintained table attributed to them. It does not
change the derived table, so the runbook can still correctly read
`Executed: no`. Never infer from a blank `EVIDENCE` block that something did
not happen — ask.

## Currently outstanding on Dom0

Kept short and current rather than complete; `CURRENT-STATE.md` is the record.

- `python3 -V` and `xl info` — Dom0's interpreter version is still
  **UNCONFIRMED** after the move from jammy to noble, and `sandboxd`'s
  `websockets` pin rests on it.
- The `dom0_max_vcpus=6` → `8` boot-line change plus reboot, then
  `xl vcpu-list 0` to confirm all eight pins took.
- `xl shutdown platform && xl create misc/platform.cfg` for the 4096 MiB /
  4 vCPU change — memory and vCPU count are boot-time properties.

## Related

- `CLAUDE.md`, "Infrastructure boundary".
- The `deployment-state` skill — before asserting any host fact.
- The `runbook` skill — for filing the evidence that comes back.