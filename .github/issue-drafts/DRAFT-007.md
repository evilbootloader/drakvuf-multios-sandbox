# DRAFT-007: Verify `drakvuf-ubuntu.sh`'s `<USER>` placeholder bug against real behavior

**Status:** Open — requires Xen Dom0
**Area:** ubuntu
**Milestone:** M1
**Priority:** P0
**Depends on:** DRAFT-001

# Objective

Confirm whether `automation/drakvuf-ubuntu.sh`'s hard-coded
`CMD="/home/<USER>/Desktop/test"` (a literal, unsubstituted `<USER>`
placeholder) actually breaks sample execution in production, before
Milestone M1 treats "Ubuntu automation works" as a proven regression
baseline.

# Context

Source-reading `automation/drakvuf-ubuntu.sh` and
`automation/preconfig-ubuntu.sh` side by side shows an inconsistency:
`preconfig-ubuntu.sh` hard-codes the real guest username `carlos` when
staging the sample at `/home/$USER/Desktop/test`, but
`drakvuf-ubuntu.sh` — which then tries to *execute* that same path under
DRAKVUF monitoring — hard-codes the literal string `<USER>` (with angle
brackets) instead of `carlos`. If DRAKVUF is told to execute
`/home/<USER>/Desktop/test` verbatim, that path doesn't exist on the guest
(the real file is at `/home/carlos/Desktop/test`), which would mean every
Ubuntu analysis run silently fails to execute the sample while still
producing a `drakvuf.log` that might look superficially normal.

This is exactly the kind of claim `CLAUDE.md` warns against treating as
proven: "Ubuntu automation is working" is asserted in
`docs/Project-definition.txt` and `CLAUDE.md`, but that assertion predates
this source-reading finding and has not been re-verified against it.

# Dependencies

DRAFT-001 (so the verification and its outcome can be committed as
evidence, not just left in conversation).

# Out of scope

- Fixing the bug, if confirmed — that's separate CREATE work (likely part
  of DRAFT-011, Ubuntu modernization), gated on this issue's TEST result.
- Any change to `preconfig-ubuntu.sh` — it appears correct as-is.

# PLAN

Determine, from the real Xen Dom0 host, whether `$USER` inside
`drakvuf-ubuntu.sh` was ever meant to be a shell variable (in which case
the literal `<USER>` is a templating artifact left over from
documentation, and the real deployed copy on Dom0 might already have it
substituted correctly) or whether the copy in this repository is exactly
what's been running in production (in which case every past Ubuntu
analysis may have failed to execute its sample).

# CREATE

Not applicable until the verification below determines whether a fix is
needed.

# TEST

Requires Xen Dom0 — cannot be run in this development container.

```bash
# On the real Dom0 host, compare the deployed copy against this repo's:
diff /home/user/drakvuf-tools/drakvuf-ubuntu.sh automation/drakvuf-ubuntu.sh

# If they match (both have the literal <USER>), run one benign end-to-end
# Ubuntu analysis and inspect whether the sample actually executed:
# - check drakvuf.log for evidence the target process ran (not just that
#   DRAKVUF itself started monitoring);
# - check for a "no such file or directory" condition on the guest side.
```

# DEPLOY

Not applicable — this is verification, not a deployment.

# Acceptance criteria

- [ ] Confirmed: does the real Dom0 deployment match this repo's
  `drakvuf-ubuntu.sh` exactly?
- [ ] Confirmed: does a benign Ubuntu analysis run actually execute the
  staged sample, or silently no-op on the `<USER>` path?
- [ ] Result recorded in `docs/checklists/ubuntu.md`'s "Known issues"
  section with real evidence (log excerpts), replacing the current
  `[ ]`-unverified state.

# Evidence required

`diff` output against the real Dom0 copy; `drakvuf.log` excerpt from one
benign test run showing whether the sample executed.

# Security considerations

None beyond standard care running on the golden/sandbox Ubuntu VMs — use
the sandbox clone, not the golden VM, per `CLAUDE.md`'s "never operate on
the golden LV" rule.

# Documentation changes

Update `docs/checklists/ubuntu.md`'s "Known issues" section with the
verified result once this completes.

# Recovery / rollback

Not applicable — read-only verification, no changes to infrastructure.