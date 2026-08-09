# DRAFT-033: Make `clone-ubuntu.pl` fail safely and lock, before it is copied twice

**Status:** Drafted, not published
**Area:** core / ubuntu (template for Android and Windows clone scripts)
**Milestone:** M1
**Priority:** P1
**Depends on:** Issue #4 / DRAFT-025 — both edit `clone-ubuntu.pl`; land
issue #4 first so the path work and the reliability work do not conflict.
**Origin:** `project-assessment.md` → Findings → DRAKVUF-05, DRAKVUF-06

# Objective

Add exit-status checking and per-origin locking to
`automation/clone-ubuntu.pl`, so that clone failures surface instead of
being inferred, and so concurrent workers cannot manipulate the same
origin VM simultaneously — while it is still one file rather than three.

# Context

`clone-ubuntu.pl` performs the destructive part of the pipeline: it
removes an existing LVM snapshot, creates a new copy-on-write snapshot of
the golden LV, and restores a saved memory image into a fresh Xen domain.
Two source-verified defects.

**DRAKVUF-05 — the per-origin lock is commented out.** The script imports
`Fcntl qw(:flock)` at `:119` and carries the comment "Only one clone
process may manipulate a particular origin VM at the same time" at `:236`
— but the lock acquisition (`:236-241`) and release (`:255-256`) are both
commented out (this was made when testing save/restore functionality, and 
deemed non functional on the current Proxmox -> Xen setup):

```perl
    # Only one clone process may manipulate a particular origin VM
    # at the same time.
    #my $lock_file = "/run/lock/drakvuf-clone-$origin.lock";
    #open(my $lock_fh, '>>', $lock_file) ...
    #flock($lock_fh, LOCK_EX) ...
```

Meanwhile `dirwatch` runs a `GThreadPool` sized by its max-clones argument
(`dirwatch.c:494`), and `run_analysis-ubuntu.sh:19` passes 2. So the
script's own stated safety requirement is disabled in exactly the
configuration it was written for. `docs/checklists/android.md:2250`
independently lists "Use `flock` for per-origin and per-launcher locking"
as a reliability requirement, and §6.7's concurrency tests
(`:2171-2183` — "Confirm domains are unique / LVs are unique / cleanup
does not remove another active clone") are entirely unfilled.

**DRAKVUF-06 — no command's exit status is checked.** Every external call
runs in backticks with its output discarded or merely printed:

| Line | Command | Failure handling |
|---|---|---|
| `:247` | `$lvremove -f /dev/$lvm_vg/$clone` | none |
| `:250` | `$lvcreate -s -n $clone -L64G /dev/$lvm_vg/$origin` | none |
| `:253` | `$xl restore -p -e /tmp/$clone.config …` | stderr printed to STDERR only |

Failure is detected indirectly and late: `dirwatch`'s `make_clone()`
(`dirwatch.c:170-181`) parses the script's stdout for a domain ID, and
`prepare()` (`:206-232`) retries when it does not get one. That works, but
it means a failing `lvcreate` — out of space in `vg-root`, for instance —
produces an opaque retry loop with a one-second sleep
(`dirwatch.c:232`) rather than a diagnosable error. `-L64G` is also
hard-coded, which will not suit a Windows golden LV.

**Why now: this file is a template about to be copied.** `CLAUDE.md`
instructs "Before editing a script, inspect the corresponding Ubuntu
implementation", and DRAFT-015 is `clone-android.pl`. A Windows equivalent
follows. `docs/checklists/android.md:841-872` ("Existing Ubuntu behavior
to review" → "Required Android changes") is explicitly structured as a
port of this file. Fixing the template once costs a fraction of fixing
three copies, and avoids shipping two new scripts with a known-disabled
safety mechanism.

# Dependencies

- **Issue #4 / DRAFT-025** — rewrites `:253`'s hard-coded
  `/home/user/Documents/ubuntu_sandbox.bak` to a `$REPO_ROOT`-relative
  path via `FindBin`, and touches the same region. Land it first.
- **Informs DRAFT-015/DRAFT-016** — the Android clone script should be
  written from the corrected template.
- Related to DRAFT-028: both concern failures that currently pass silently,
  in different layers.

# Out of scope

- Rewriting the clone strategy. LVM copy-on-write + `xl restore` is the
  project's settled model (`docs/roadmap/project-roadmap.md` decision #3
  rules out snapshot-restore entirely in this nested setup).
- Implementing `clone-android.pl` — DRAFT-015.
- Changing the script's stdout contract. `dirwatch.c:170-181` parses the
  printed clone ID; that interface is load-bearing and `CLAUDE.md`
  requires preserving interfaces until callers are inspected. Diagnostics
  go to STDERR, never STDOUT.
- Path standardization (`$lvm_vg`, `$clone_bridge`, the `.bak` path) —
  issue #4.
- Storage preflight checks (free VG space, minimum thresholds) from
  `docs/checklists/android.md` §7.2. Related, but a distinct feature; this
  issue makes existing failures visible rather than adding new checks.
  Recording the failure clearly is the prerequisite for that work.

# PLAN

1. Confirm the current stdout contract precisely by reading
   `dirwatch.c:170-181` and `xen_get_dom_info()`'s parsing, so the change
   cannot break it. Note the failure paths already present: `die "0"` at
   `:169` and `:172`.
2. Decide the lock scope. The commented-out design uses one lock file per
   origin (`/run/lock/drakvuf-clone-$origin.lock`), which is correct for
   the concurrency that exists: multiple workers cloning the *same* golden
   VM. Confirm whether a second, launcher-level lock is also wanted, per
   the android checklist's "per-origin **and** per-launcher" wording.
3. Determine why the lock was disabled. It may have been commented out to
   work around a deadlock or a stale-lock hang, in which case
   reinstating it verbatim reintroduces that. Check git history and ask
   the operator before assuming it was merely unfinished.
4. Decide lock timeout behaviour. A blocking `LOCK_EX` with no timeout can
   hang a `dirwatch` worker indefinitely; `dirwatch`'s own 60s preconfig
   timer (`dirwatch.c:272`) does not cover the clone step, so a hung clone
   has no external timeout at all. Recommendation: non-blocking acquire
   with bounded retry, failing cleanly rather than hanging.
5. Decide how each failure is reported so that `dirwatch` distinguishes
   "retry is worthwhile" (transient) from "retry is futile" (VG full,
   golden LV missing, saved-state file absent). Today it retries
   everything forever.
6. Parameterize the snapshot size (`-L64G`), since the value is per-OS.

# CREATE

1. Reinstate per-origin locking per PLAN steps 2–4, with the timeout
   behaviour decided there — not a verbatim uncomment.
2. Check the exit status of `lvremove`, `lvcreate` and `xl restore`;
   on failure, write a specific diagnostic to STDERR and exit non-zero
   without printing a clone ID to STDOUT.
3. Verify the saved-state file exists and is readable before invoking
   `xl restore`, so a missing `.bak` produces a named error rather than an
   `xl` failure message.
4. Verify the golden LV exists before `lvcreate -s`.
5. Parameterize the snapshot size with the current `64G` as the default.
6. Add `$SIG{__DIE__}`-safe cleanup so a partially-created snapshot is
   removed rather than left behind — a stale `/dev/vg-root/<clone>` blocks
   the next run for the same VLAN.
7. Record the resulting pattern in `docs/checklists/ubuntu.md` as the
   reference implementation DRAFT-015 should follow.

# TEST

Runs in the development container:

```bash
perl -c automation/clone-ubuntu.pl
```

`CLAUDE.md` lists `lvcreate`/`lvremove`/`lvs`/`xl` as commands that must
not run here, so functional testing is Dom0-side. Present for manual
execution:

```bash
# Baseline: normal clone still works and still prints only the domain ID.
./clone-ubuntu.pl ubuntu_sandbox 1 <config>   # stdout: domain ID, nothing else

# Failure paths — each must exit non-zero with a named diagnostic on
# STDERR and print NO clone ID:
#   - saved-state file renamed away        -> expect: named error
#   - non-existent origin LV               -> expect: named error
#   - VG artificially filled (test VG,     -> expect: named lvcreate error
#     never vg-root's real free space)
# After each, confirm no partial snapshot remains:
lvs -a -o lv_name,origin,lv_size,data_percent
xl list

# Concurrency (docs/checklists/android.md §6.7, currently unfilled):
#   launch two clones of the same origin simultaneously
#   -> expect: serialized by the lock, both succeed, unique domains,
#      unique LVs, unique VLANs; neither destroys the other's clone
```

The concurrency test is the one that matters most — it is the scenario the
disabled lock was written for, and it has never been run.

# DEPLOY

Requires manual Dom0 coordination — present, do not execute:

1. Deploy alongside the issue #4 path changes if both are ready; they
   touch adjacent lines.
2. Run the failure-path tests against a **disposable test volume group**,
   never against `vg-root`'s real free space, and never against the golden
   `ubuntu` LV.
3. Run one benign end-to-end analysis before considering it deployed.
4. Keep the previous script until the concurrency test has passed.
5. Rollback: restore the previous file; behaviour returns to today's
   silent-failure model, which is known-working for the happy path.

# Acceptance criteria

- [ ] The reason the lock was originally disabled is established (PLAN
      step 3) and recorded — reinstating it blindly is not acceptable.
- [ ] Per-origin locking is active, with bounded acquisition rather than
      an unbounded block.
- [ ] `lvremove`, `lvcreate` and `xl restore` failures each produce a
      distinct STDERR diagnostic and a non-zero exit.
- [ ] The script prints a clone ID to STDOUT **only** on success —
      `dirwatch`'s existing parsing is unchanged and still works.
- [ ] Missing saved-state file and missing golden LV are detected before
      the destructive step, not after.
- [ ] No partial LVM snapshot survives a failed run (`lvs` clean).
- [ ] The snapshot size is parameterized, defaulting to the current 64G.
- [ ] Two simultaneous clones of the same origin serialize correctly and
      produce unique domains, LVs and VLANs — filling in
      `docs/checklists/android.md` §6.7's concurrency evidence for the
      Ubuntu case.
- [ ] One benign end-to-end analysis completes normally.
- [ ] `docs/checklists/ubuntu.md` records the pattern for DRAFT-015 to
      follow.

# Evidence required

- `perl -c` output.
- Transcript of each failure-path test with its diagnostic and exit code.
- `lvs -a` / `xl list` output after each failure, showing no residue.
- The concurrency test transcript.
- The post-change benign analysis log excerpt.

# Security considerations

- **This script destroys and creates block devices as root.** `lvremove
  -f` at `:247` removes any LV matching the clone name. Every change must
  preserve the invariant that only `<origin>-<vlan>-clone` names are ever
  targeted — never the golden `ubuntu`/`android` LVs, which `CLAUDE.md`
  places off-limits absolutely.
- The failure-path tests must use a disposable test VG. Deliberately
  filling `vg-root` on the real Dom0 to test an error branch would risk
  the golden LVs and any in-flight analysis.
- Reinstating a lock can introduce a hang where there was previously a
  race. A hung clone worker holds a `dirwatch` thread slot indefinitely,
  because the clone step sits outside `dirwatch`'s 60s/180s timers — which
  is precisely why PLAN step 4 requires bounded acquisition.
- Silent failure is itself a security-relevant property here: an analysis
  that proceeds against a stale or partially-restored clone produces
  results attributed to the wrong VM state.

# Documentation changes

`docs/checklists/ubuntu.md` (the reference pattern and the concurrency
evidence), `docs/architecture/analysis-pipeline.md` (clone-step failure
semantics, since `dirwatch`'s retry behaviour depends on them),
`docs/checklists/android.md` §2.5 (annotate that the Ubuntu template it
ports from has changed — annotate, do not rewrite).

# Recovery / rollback

Single-file revert. The previous version's behaviour is the current
production behaviour, so rollback is to a known-working state. No
persistent infrastructure change is made by this issue itself; the risk is
confined to the failure-path testing, which is why it is scoped to a
disposable VG.