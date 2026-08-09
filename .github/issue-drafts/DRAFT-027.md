# DRAFT-027: Replace HTTP/Apache sample delivery with direct guest injection

> **Resolution 2026-08-09 — implemented for Ubuntu as part of issue #4,
> never published as its own issue.** Folded in because issue #4's per-OS
> `/malware_processing/ubuntu` change would otherwise have broken HTTP
> delivery (Apache's `DocumentRoot` is `/malware_processing`); removing
> the dependency was cleaner than working around it.
>
> **PLAN steps 1–2 required no new Dom0 work.** They ask for an
> `injector --help` capture to settle whether `writefile` exists and what
> its arguments are. That capture was already taken during issue #2 and
> is recorded at `docs/runbooks/verify-user-placeholder.md:154-157`:
>
> ```text
> writefile - push a file (specified by host path -B) to the VM and store it on guest path specified by -e
> -f <args for execproc>    [BOTH] - ... (requires -m execproc or -m shellexec)
> ```
>
> This **refutes the candidate command** at
> `docs/checklists/android.md:1068-1079`, which used `-e` for the host
> source and `-f` for the guest destination. Both are wrong: `-e` is the
> guest destination, `-B` is the host source, and `-f` is not read by
> `writefile` at all. DRAFT-016 would have inherited that command
> verbatim. Corrected in place with the original preserved.
>
> **Still open:** PLAN step 3 (does `writefile` set the executable bit?)
> is not answered by `--help`, so a separate `chmod` injection runs
> unconditionally. The Apache-stopped acceptance run is runbook D5 in
> `docs/runbooks/deploy-repo-relative-paths.md` and has not been
> executed. Android and Windows delivery remain unimplemented, as this
> draft always intended.

**Status:** Implemented for Ubuntu 2026-08-09 (via issue #4); not
published as a separate issue
**Area:** core / platform (affects Ubuntu, Android, Windows)
**Milestone:** M1 (decision) → M2/M3 (per-OS implementation)
**Priority:** P0
**Depends on:** Issue #4 (path standardization) for where the delivered
sample is read from; informed by issue #2 (`-e` semantics, Linux-only)
**Origin:** `project-assessment.md` → Findings → DRAKVUF-01 (with NET-02,
CI-05)

# Objective

Deliver samples into the analysis guest by direct host-to-guest injection
instead of having the guest fetch them over HTTP from an Apache server on
the Dom0 analysis gateway. Decide this once for all three OS pipelines,
implement it for Ubuntu, and **remove** the HTTP path rather than
retaining it as a fallback.

# Context

`automation/preconfig-ubuntu.sh:122` stages the sample by instructing the
guest to download it:

```bash
ARG2="... wget 'http://172.16.$VLAN.1/$RUNFILE' -O '/home/$USER/Desktop/test' && chmod +x ..."
```

The server side is Apache, reconfigured with
`DocumentRoot /malware_processing` and `/malware_processing` owned by
`www-data` (`docs/drakvuf-on-xen-nested-within-proxmox.md:612-652`).
`apache2` is installed as part of the documented setup (`:417`) and is
carried into the CI base snapshot design (`docs/workflow-ci.md:403`).

This works — issue #2 produced execution evidence of six successful staged
runs. It is nonetheless the wrong mechanism, for four reasons:

1. **It requires a privileged Dom0 service to be reachable from every
   clone.** Combined with the absence of any `INPUT` policy (DRAFT-029),
   the analysis guest can reach that server freely — and its document root
   is `/malware_processing`, i.e. **every other in-flight sample,
   addressable by filename**.
2. **It makes an offline network mode structurally impossible.**
   `docs/architecture/networking.md` proposes `offline`, `simulated` and
   `controlled-internet` modes. On this path, guest networking must be
   configured and working *before* the sample can be staged, so `offline`
   cannot exist until delivery is replaced.
3. **It forces the untrusted filename into a guest shell command.** The
   `$RUNFILE` interpolation at `:122` sits inside a single-quoted URL
   inside a `/usr/bin/sh -c` string; a filename containing `'` escapes the
   quoting. `docs/checklists/android.md:1008` already forbids exactly this
   ("Never include the untrusted filename directly in a guest shell
   command") — for Android only.
4. **It does not generalize.** `wget` is a reasonable assumption on
   Ubuntu. Android's shell may not provide it usably, and a Windows guest
   would need a third mechanism. Direct injection is the only delivery
   method with the same shape on all three targets.

The project already reached the direct-injection conclusion once, in the
Android checklist, and never applied it to Ubuntu or generalized it:

- `docs/checklists/android.md:1003` — "Prefer `injector -m writefile` if
  supported by the installed branch."
- `docs/checklists/android.md:1876-1878` — "Prefer direct host-to-guest
  file injection. Keep HTTP download only as an optional compatibility
  path. Do not expose `/malware_processing` beyond the isolated analysis
  network."

**Decision recorded for this issue (2026-08-08, project owner): the HTTP
path is removed, not kept as a compatibility option.** It is to be
preserved in documentation as historical context only — how the pipeline
used to work and why it changed — with no fallback code path, no
off-by-default flag, and no configuration switch. This supersedes the
"keep HTTP download only as an optional compatibility path" line in
`docs/checklists/android.md:1877`, which must be annotated accordingly
rather than silently rewritten. A retained fallback would be an untested
code path whose only function is to re-enable the exposure this issue
exists to close.

**Why now, and not later.** The delivery mechanism is about to be written
two more times: `preconfig-android.sh` (DRAFT-016) and a future
`preconfig-windows.sh`. Deciding after DRAFT-016 lands means rewriting it.
The CI base snapshot (DRAFT-026b) also installs and configures Apache; if
that dependency is removed afterwards, the snapshot, the "Recreating CI"
checklist and the `ubuntu-pipeline` stage all have to be redone.

# Dependencies

- Issue #4 / DRAFT-025 — determines the Dom0-side path the sample is read
  from when injected.
- Blocks DRAFT-016 (Android preconfig) — Android must be written against
  the decided mechanism, not retrofitted, and must not inherit the HTTP
  path.
- Blocks DRAFT-026b — the CI base snapshot must not be built around a
  dependency scheduled for removal.
- Enables DRAFT-029 (Dom0 service exposure) and the eventual `offline`
  network mode; both are much harder while delivery needs HTTP.

# Out of scope

- Removing Apache from the Dom0 host itself. `/malware_processing` may
  still be served for unrelated operator convenience. This issue removes
  the **pipeline's dependency** on it; retiring the service is a separate
  operational decision (see DEPLOY step 3).
- Changing the in-guest destination directory convention beyond what
  PLAN step 4 requires, or parameterizing the hard-coded guest username
  `carlos` — open M1 work, tracked via DRAFT-009/DRAFT-011.
- Implementing Android or Windows delivery. This issue decides the
  mechanism for all three and implements it for Ubuntu only.
- Changing `/malware_incoming`, `/malware_processing`,
  `/malware_finished` locations or ownership (confirmed correct; issue #4
  also excludes them).

# PLAN

1. **Verify `writefile` exists and its exact syntax in the installed
   build.** The Android checklist's own wording ("if supported by the
   installed branch") shows this is unconfirmed. Per `CLAUDE.md`'s
   do-not-invent rule, capture the real help/source before writing
   anything:

   ```bash
   injector --help 2>&1 | tee /tmp/injector-help.txt
   grep -rn "writefile" /home/user/drakvuf/src/injector.cpp
   ```

2. Confirm the argument shape — in particular which of `-e`/`-f` carries
   the Dom0 source path and which the guest destination. The candidate at
   `docs/checklists/android.md:1023-1035` assumes `-e <host src>` /
   `-f <guest dst>`; treat that as unvalidated until step 1 confirms it.
3. Confirm whether `writefile` sets the executable bit, or whether a
   separate `chmod` injection is still required on Linux/Android guests.
4. Fix the guest destination convention: a hash-derived path with **no**
   attacker-controlled component (consistent with
   `docs/checklists/android.md:1002`, e.g. `.../<sha256>/sample.bin`).
   This resolves DRAKVUF-02 for Ubuntu as a side effect.
5. Confirm the interaction with `drakvuf-ubuntu.sh:119`'s `CMD` — the
   execution path must match the new staging destination, and issue #2
   established that `-e` is execve-direct with **no guest shell**, so the
   path is resolved Dom0-side and must be exact. That evidence is labelled
   `[LINUX]`; do not assume it holds for a Windows guest.
6. Identify every place the HTTP path is referenced so removal is complete
   rather than partial:

   ```bash
   grep -rns "wget\|http://172\|apache\|www-data\|DocumentRoot" \
       automation/ docs/ misc/
   ```

# CREATE

1. **Delete** the `wget` clause from `automation/preconfig-ubuntu.sh:122`
   and replace it with an `injector -m writefile` call using the validated
   syntax from PLAN step 1, writing to the hash-derived destination from
   step 4. No conditional, no flag, no fallback branch.
2. Keep the network-configuration clause of `ARG2` (still needed for
   analysis-time traffic) but separate it from delivery, so the two are no
   longer coupled and an `offline` mode becomes possible later.
3. If the executable bit is not set by `writefile` (PLAN step 3), issue
   the `chmod` as its own injection with **no** interpolated filename.
4. Update `automation/drakvuf-ubuntu.sh:119`'s `CMD` to the new
   destination in the same commit, so staging and execution cannot drift —
   this is the exact drift class issue #2 uncovered.
5. Record the delivery contract in
   `docs/architecture/analysis-pipeline.md` as applying to **all** OS
   pipelines, so DRAFT-016 and the Windows track inherit it.
6. Record the HTTP mechanism as **history**: a short dated subsection
   stating what it was, that it is removed, and why (guest-reachable Dom0
   service, cross-sample exposure via `DocumentRoot`, blocks `offline`
   mode, does not generalize across guests). No instructions for
   re-enabling it.
7. Annotate `docs/checklists/android.md:1876-1878` to record that the
   "optional compatibility path" line is superseded by this decision —
   annotate, do not rewrite the evidence block.

# TEST

Runs in the development container:

```bash
bash -n automation/preconfig-ubuntu.sh
bash -n automation/drakvuf-ubuntu.sh
shellcheck automation/preconfig-ubuntu.sh automation/drakvuf-ubuntu.sh

# No delivery-path residue anywhere in the automation:
grep -rns "wget\|http://172" automation/     # expect: zero matches
```

Requires Xen Dom0 — present for manual execution, do not run from the
development container (`CLAUDE.md` infrastructure boundary):

```bash
# 1. Capture the real injector interface (PLAN step 1) BEFORE any edit.
injector --help

# 2. One benign fixture end-to-end, sandbox clone only, never the golden LV.
#    Confirm in the result directory:
#      - writefile.log shows STATUS:SUCCESS
#      - the guest-side SHA-256 matches the Dom0-side SHA-256
#      - drakvuf.log still shows ExecProc Status:Success on the new path
#      - the run completes with Apache STOPPED, proving the dependency is
#        gone rather than merely unused:
systemctl stop apache2 && <run one benign analysis> && systemctl start apache2
```

The Apache-stopped run is the acceptance evidence. A run that merely
succeeds proves nothing, since the old path would also succeed.

# DEPLOY

Requires manual Dom0 coordination — present, do not execute:

1. Deploy the updated `preconfig-ubuntu.sh` and `drakvuf-ubuntu.sh`
   **together**; they must not be deployed independently (CREATE step 4).
2. Leave Apache installed and running initially — do not remove the
   service in the same change as the delivery switch.
3. After a recorded clean run with Apache stopped, decide separately
   whether to revert the `DocumentRoot /malware_processing` configuration
   and/or remove the package. That is an operational decision, not part of
   this issue's acceptance.
4. Rollback: redeploy the previous two scripts from git. No infrastructure
   state changes, so rollback is a file-level revert plus one analysis run
   to confirm. Apache is deliberately still present during this window.

# Acceptance criteria

- [ ] `injector`'s real `writefile` interface is captured from the
      installed build and recorded in this issue — not assumed from the
      Android checklist's candidate block.
- [ ] `automation/preconfig-ubuntu.sh` performs no HTTP fetch, and
      `grep -rns 'wget\|http://172' automation/` returns zero matches.
- [ ] No fallback, flag, or configuration switch re-enables HTTP delivery
      anywhere in `automation/`.
- [ ] The guest destination path contains no component derived from the
      untrusted original filename (resolves DRAKVUF-02 for Ubuntu).
- [ ] `automation/drakvuf-ubuntu.sh`'s `CMD` matches the new staging
      destination, changed in the same commit.
- [ ] A benign end-to-end Ubuntu analysis completes successfully **with
      `apache2` stopped**, with the log excerpt recorded.
- [ ] Guest-side and Dom0-side SHA-256 of the delivered file match.
- [ ] The delivery contract is recorded in
      `docs/architecture/analysis-pipeline.md` as applying to all three OS
      pipelines.
- [ ] The HTTP mechanism is documented as historical context only, with no
      re-enablement instructions, and
      `docs/checklists/android.md:1876-1878` is annotated as superseded.
- [ ] `/malware_incoming`, `/malware_processing`, `/malware_finished`
      are unchanged in location, ownership and permissions.

# Evidence required

- `injector --help` output from the Dom0 host.
- Diff of both changed scripts.
- Static-check and grep output from the development container.
- `writefile.log` + `drakvuf.log` excerpts from the Apache-stopped run,
  and the matching SHA-256 pair.

# Security considerations

- **This issue reduces attack surface; it must not expand it.** The point
  is that the guest no longer needs a route to any Dom0 service. Do not
  replace one reachable service with another.
- **No compatibility fallback is retained**, by decision. A retained HTTP
  path would be an untested branch whose only effect is to restore the
  exposure — and untested branches in a malware-analysis pipeline are
  worse than absent ones.
- Injection happens from Dom0 with root privileges against a clone that
  will shortly execute malware. The Dom0-side source path must be the
  already-quarantined sample in `/malware_processing`, read-only, with no
  filename interpolation into any command string.
- Do not run against the golden `ubuntu` LV or real malware. Benign
  fixture, sandbox clone only.

# Documentation changes

`docs/architecture/analysis-pipeline.md` (delivery contract for all OS
pipelines + the historical note), `docs/architecture/networking.md`
(removes the reason the gateway must run a web server),
`docs/checklists/ubuntu.md` (evidence),
`docs/drakvuf-on-xen-nested-within-proxmox.md` (the Apache setup section
becomes historical rather than a required install step),
`docs/workflow-ci.md:403` (drop `apache2` from the base snapshot),
`docs/checklists/android.md` §2.7/§5.2 (annotate `:1877` as superseded —
annotate, do not rewrite).

# Recovery / rollback

Two-file revert plus one confirming analysis run. No LVM, Xen, or network
state is modified. Apache is deliberately left installed and running until
after the change is proven (DEPLOY steps 2–3), so recovery does not depend
on reinstalling anything.
