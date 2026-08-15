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

`automation/clone.pl` derives the path from its own location and
its `<origin domain>` argument:

```perl
my $saved_state = "$FindBin::RealBin/../state/$origin.bak";
```

That derivation is the point. Before issue #4 the origin was a parameter
while the restore path was a hard-coded `/home/user/Documents/...`
constant, so nothing stopped a clone from getting one domain's disk
snapshot with another domain's memory image. Now the two names come from
the same argument and cannot disagree.

`automation/run_analysis-ubuntu.sh` pre-flight checks the same path
(via `SAVED_STATE` in `pipeline-ubuntu.env`) before starting `dirwatch`,
so a missing image fails at launch rather than on the first sample.

## Producing one

Out-of-band, once per sandbox template, and **not** part of an analysis
run. See `docs/checklists/ubuntu.md` and `docs/checklists/android.md` for
the full procedure — in outline, boot the template domain, bring it to
the state every clone should start from (including the long-lived process
whose PID becomes `INJECTION_PID`), then `xl save` it.

Re-saving a template almost certainly changes that PID. Update
`INJECTION_PID` in the matching `automation/pipeline-<os>.env` in the same
change, or every subsequent injection attaches to nothing.