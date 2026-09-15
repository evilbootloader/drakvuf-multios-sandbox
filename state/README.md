# Xen saved-state images

`xl save` memory images for the sandbox template domains, one per target
OS, named after the origin domain:

```
state/ubuntu_sandbox.bak
state/android_sandbox.bak     (when the Android template exists)
```

**Not tracked in git** — `.gitignore` excludes `*.bak`, and these are
multi-gigabyte VM memory dumps that can contain in-guest data from
whenever the template was saved. This directory is committed only so a
fresh checkout has somewhere to put them.

## Who reads them

`sandboxd/stages.py` derives the path from the repository root and the
origin domain (`StageConfig.saved_state`):

```python
return self.repo_root / "state" / f"{self.origin(os_)}.bak"
```

That derivation is the point. Before issue #4 the origin was a parameter
while the restore path was a hard-coded `/home/user/Documents/...`
constant, so nothing stopped a clone from getting one domain's disk
snapshot with another domain's memory image. Now the two names come from
the same value and cannot disagree. The Perl clone builder that first
derived it this way (via `FindBin`) was deleted 2026-09-15; the property
was kept deliberately.

`sandboxd/clone.py` pre-checks the path before it creates anything, and
names it in the error — everything checkable without creating state is
checked first, so a missing image costs nothing and says what it is.

## Producing one

Out-of-band, once per sandbox template, and **not** part of an analysis
run. See `docs/checklists/ubuntu.md` and `docs/checklists/android.md` for
the full procedure — in outline, boot the template domain, bring it to
the state every clone should start from (including the long-lived process
whose PID becomes `INJECTION_PID`), then `xl save` it.

Re-saving a template almost certainly changes that PID. Update the entry
for that OS in `StageConfig.injection_pids` (`sandboxd/stages.py`) in the
same change, or every subsequent injection attaches to nothing — **and it
fails silently**, because `injector` attaches to whatever holds the PID.
`docs/CURRENT-STATE.md` §2b lists the values that are valid only for the
`.bak` they were read from.