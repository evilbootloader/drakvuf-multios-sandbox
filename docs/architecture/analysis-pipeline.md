# Analysis pipeline architecture

> Verified-vs-proposed distinction matters here, same as the checklists:
> the `dirwatch.c` contract below is confirmed by direct source reading
> (2026-08-07). The job/result state model below is **decided** as of
> 2026-08-09 (issue #3 / DRAFT-008) and **implemented nowhere**. "Decided"
> means downstream work builds on it instead of reinventing it; it does not
> mean any script emits it today.

## Current orchestrator: `automation/dirwatch.c`

A modified copy of DRAKVUF's own `dirwatch` tool (upstream lives at
`tklengyel/drakvuf:src/dirwatch/dirwatch.c` — see `upstream-drakvuf.md`).
It is a `GThreadPool` + `inotify` (`IN_CLOSE_WRITE`) watcher on the
incoming-sample folder, invoked with a fixed 15-argument CLI contract:

```
dirwatch <loop(0)|poll(1)> <origin domain> <domain config> <kernel json> \
  <injection pid> <watch folder> <serve folder> <output folder> \
  <max clones> <clone_script> <config_script> <drakvuf_script> \
  <cleanup_script> <tcpdump_script>
```

`automation/run_analysis-ubuntu.sh` invokes it with:

```
dirwatch 1 ubuntu_sandbox /home/user/drakvuf-tools/ubuntu_sandbox.cfg \
  /root/linux.json 1415 /malware_incoming /malware_processing \
  /malware_finished 2 <clone-ubuntu.pl> <preconfig-ubuntu.sh> \
  <drakvuf-ubuntu.sh> <cleanup.sh> <tcpdump.sh>
```

Note the deployment paths (`/home/user/drakvuf-tools/...`) don't match this
repo's `automation/`/`misc/` directory names — see the Ubuntu checklist's
"known issues" section. The domain config path in that invocation
(`ubuntu_sandbox.cfg`) corresponds to what's tracked here as
`misc/ubuntu_sandbox.cfg` (renamed from `linux_sandbox.cfg` in issue #1).

Per-sample flow: on a new file, `dirwatch` moves it out of the watch folder,
then calls back into the worker scripts in order —
`clone_script → config_script → drakvuf_script → cleanup_script`, with
`tcpdump_script` started on a separate thread. A 60s timeout guards the
preconfig phase and a 180s timeout guards the drakvuf-trace phase; either
timeout triggers `cleanup_script` and a fresh clone retry. Concurrency is
capped by a thread pool sized from the `<max clones>` argument (validated
1–128 in upstream; this project's copy has not been independently
re-verified against that bound).

One origin domain is hard-coded per invocation (`dirwatch.c:472`), so a
`dirwatch` process serves exactly one guest OS. The state model below turns
that constraint into the OS-selection mechanism — one watcher and one
incoming directory per target OS — rather than working around it.

### Clone concurrency: fixed slots today, resource-aware admission needed

Concurrency is currently a fixed count, and that count doubles as the VLAN
allocator:

- `<max clones>` sizes a fixed `GThreadPool` (`dirwatch.c:493`);
- `find_thread()` claims a slot from `slots_busy[128]` by atomic CAS
  (`:195-209`);
- the slot index *becomes* the VLAN — `make_clone(xen, &cloneID,
  threadid + 1, …)` (`:297`) — so slot 0 means VLAN 1, `xenbr1.1` and
  `172.16.1.0/24`.

Two problems follow, both sharpened by the one-watcher-per-OS decision.

**1. A fixed clone count is the wrong unit.** Each watcher would carry its
own independently-set `<max clones>`, with no way to lend capacity to
another. A split like "5 Windows, 3 Ubuntu, 3 Android" sized to be safe
when all three are busy leaves most of the host idle whenever only one OS
is in use; sized to fill the host for one OS, it overcommits when all three
run at once. Raising the numbers cannot fix this, because the caps cannot
observe each other.

Nor would a single shared clone count fix it, because clones are not
interchangeable: `misc/ubuntu_sandbox.cfg:14-15` and
`misc/android_sandbox.cfg:14-15` both pin `memory = maxmem = 2048` with no
ballooning headroom, and a Windows sandbox will need more. **The admissible
quantity is memory, not clones** — a clone should be created when the host
can currently afford *that* clone, whichever OS asked for it. That is also
what makes the arrangement efficient rather than merely safe: one busy OS
can use the whole host.

**2. `slots_busy[]` is process-local, so the VLAN space collides.**

> **KNOWN GAP (DRAFT-036).** Three `dirwatch` instances each allocate from
> their own zero-based array, so all three hand out VLAN 1 first and all
> three clones land on `xenbr1.1` / `172.16.1.0/24` — breaking the per-VLAN
> isolation that `network-setup.sh` exists to provide. A host-global VLAN
> allocator is therefore a **prerequisite** of running per-OS watchers
> concurrently, not a later optimization.

Both point at one change: admission decides whether a clone may be created
from live host state, and VLAN assignment becomes a separate host-global
lease instead of a by-product of a slot index.

Candidate admission rule — **requires testing on Dom0, not validated:**

```text
required  = clone .cfg memory + shadow_memory (32) + per-domain overhead
available = xl info -> free_memory, minus a fixed reserve
admit if    required <= available
```

Dom0 is pinned at `dom0_mem=4096M,max:4096M`
(`docs/drakvuf-on-xen-nested-within-proxmox.md:280`) and so does not
balloon; the reserve exists for Xen's own allocation and for the restore
burst, not for Dom0. `xl restore` reinstates a full memory image, so
admission has to be sized against that peak rather than steady-state
usage — this is the part most likely to be wrong on first attempt and
should be measured before the rule is trusted.

Memory admission on its own is greedy, and greedy admission starves the
largest clone: whenever memory frees up, a smaller job is already eligible
and takes it, so a Windows clone waits for a window that never opens while
Ubuntu and Android run normally. Each individual decision is correct, which
is what makes it hard to see. Admission therefore has to own **queue order**
as well — ordered by `submitted_at`, with a standing reservation for the
oldest job that cannot yet be afforded, so freed memory accumulates toward
it rather than being handed to whoever fits. Per-OS reserved capacity is
not the answer; that is the static partitioning this section exists to
remove.

Three watchers also means three independent `inotify` queues with no
relative ordering, so the ordering cannot come from the watchers. VLAN
leasing, memory reservation and queue order all need the same host-global
authority, which is why DRAFT-036 treats them as one piece of work.

This is exactly what `queued` means in the state model below: a job that is
admissible but waiting for capacity sits there *visibly*, with a showable
reason — `waiting_for_memory`, `waiting_for_vlan`, or
`blocked_by_reservation` when it is held behind a larger job — instead of
being blocked invisibly inside a thread pool.

**Known upstream issue to check for divergence:** `tklengyel/drakvuf` issue
#140 describes a timeout-triggered clone retry failing to find its sample
because it was already moved out of the incoming folder — the same
retry-on-timeout shape this project's `dirwatch.c` uses. Whether this
project's copy already diverged/fixed this has not been checked (DRAFT-010).

## Decided: OS-independent job/result state model (issue #3, 2026-08-09)

This section is the decided model for all three OS targets. Implementation
is tracked elsewhere: DRAFT-011 (retrofit Ubuntu), DRAFT-018 (storage
layout), DRAFT-015/016 (Android), DRAFT-034 (Windows), DRAFT-035 (job
control channel). No script emits any of this yet.

It replaces two incompatible partial models, neither of which was a
deliberate cross-OS design — see "What this supersedes" at the end.

### Design rules

Three rules produced most of the choices below, and are the thing to apply
when extending the model rather than re-arguing each field:

1. **Every state is entered by an explicit, recorded transition.** A state
   that could only be inferred by guessing how far a script got is not in
   the model. Where a phase boundary sits inside one worker script, the
   script must emit the transition for the state to exist — that is a
   requirement on the implementation, not grounds for dropping the state.
   Where a boundary means nothing to a reader *and* nothing to recovery,
   the states are merged.
2. **OS-independent facts live in `state` and `status`; everything
   OS-shaped lives in `stage`, `failure_reason` and `type_identifiers`,
   scoped by `target_os`.** This is what makes the model OS-independent
   without discarding the per-OS vocabularies that already exist.
3. **Persist intent before acting.** The record of what is about to be
   created is written before the thing is created, so an orphaned clone is
   always attributable to a job.

### Job record

One `status.json` per run, written atomically (temp file + rename). It is
the durable source of truth — not a cache of in-process state — and is the
only file a reader (including the future web platform) needs to open.

| Group | Fields |
|---|---|
| Identity | `schema_version`, `analysis_id` |
| Sample | `sample_sha256`, `sample_sha1`, `sample_md5`, `sample_size`, `original_filename`, `guest_filename`, `detected_type`, `type_identifiers{}` |
| Request | `target_os`, `execution_recipe`, `requested_timeout`, `network_mode` |
| Run | `domain`, `clone_id`, `vlan`, `attempt`, `queue_reason`, `submitted_at`, `started_at`, `finished_at`, `duration_seconds` |
| Control | `cancel_requested_at`, `cancelled_by` |
| State | `state`, `stage`, `status`, `failure_stage`, `failure_reason`, `errors[]`, `cleanup_status` |
| Provenance | `sandbox_version`, `profile_version`, `drakvuf_version` |

`analysis_id` identifies **one run**, not one sample: a ULID, and the name
of the result directory. Submitting the same sample twice produces two
independent records that cannot collide or overwrite each other. Samples
are found by `sample_sha256` through an `index/by-sha256/` mapping, which
is also what gives the web platform an "all runs of this sample" view.

`attempt` exists because one submission can legitimately produce several
clone lifecycles: `dirwatch.c:424-429` retries a timed-out sample on a
*fresh* clone via `goto restart`. Neither superseded model could represent
that, so a retried run was indistinguishable from a first attempt.

`sandbox_version` is the git commit of the automation scripts, per
`docs/checklists/android.md:2373`. `profile_version` identifies the LibVMI
JSON profile the run was traced against — a kernel update that invalidates
the profile is otherwise invisible in the results.

### Sample identification

Computed on the host at `admitted`, from the sample bytes, before any clone
exists. This is **identification, not routing** — see "Target OS selection"
below, which is deliberately not driven by any of it.

Universal, and free (coreutils; no new Dom0 dependency):

```text
sample_sha256   the model's sample key
sample_sha1     cross-referencing external corpora (VirusTotal et al.)
sample_md5      cross-referencing, and the migration bridge (see below)
sample_size     also the admission size cap
```

MD5 is retained as an *identifier* precisely because external services are
keyed by it. It is no longer a *key*: the three scripts computing it today
(`drakvuf-ubuntu.sh:118`, `preconfig-ubuntu.sh:118`, `tcpdump.sh:115`) use
it to name the result directory, and DRAFT-011's retrofit needs both values
present during the transition.

Structural identifiers are **format-scoped**, in `type_identifiers`,
because they do not generalize — `imphash` is a hash of a PE import table
and has no meaning for an APK:

| Format | Identifiers |
|---|---|
| PE | `imphash`, `pe_timestamp`, `authentihash`, signature subject |
| ELF | `telfhash` (the ELF analogue of imphash), `build_id` |
| APK | `package_name`, `version_code`, `signing_cert_sha256` |

For an APK the signing certificate and package name — not a hash of the
file — are the identity that actually tracks a malware family across
repackaged samples, which is why they sit in the same slot rather than
being treated as Android trivia.

> **KNOWN GAP (DRAFT-018):** `imphash` and `telfhash` require a parsing
> library on Dom0 (`pefile`/LIEF, `telfhash`); the project currently has no
> such dependency and this issue does not add one. All `type_identifiers`
> fields are therefore nullable, and *which* are computed is DRAFT-018's
> decision. The four universal values above are unconditional.
> Fuzzy hashes (`ssdeep`, `tlsh`) were considered and deliberately not
> adopted here; they are a corpus-similarity tool, and this project has no
> corpus yet.

### Target OS selection, admission, and untrusted input

`target_os` is a closed enum — `ubuntu`, `android`, `windows` — and is
**derived from which incoming directory the sample landed in**, one
`dirwatch` instance per OS:

```text
/malware_incoming/ubuntu/    -> dirwatch --origin ubuntu_sandbox
/malware_incoming/android/   -> dirwatch --origin android_sandbox
/malware_incoming/windows/   -> dirwatch --origin windows_sandbox
```

This fits the orchestrator that already exists rather than requiring a new
one: `dirwatch` hard-codes a single origin domain per invocation
(`dirwatch.c:472`), so the target OS is already a property of the launcher.
It is also the strongest available answer to input sanitizing — the OS
token is never parsed out of a filename, a sidecar file, or any other
attacker-influenced byte, so there is no value to validate and nothing to
spoof. A directory outside the enum is simply not watched.

The submitting user chooses the OS by choosing where to submit. For the M7
web platform that is a form field mapping to a directory, validated against
the enum at the submission boundary, where it is the only untrusted routing
input in the system.

Admission checks, all before any clone exists, so a rejection costs no VM:

- size cap → `rejected` / `rejected_size`;
- readable, non-empty → `rejected` / `unreadable`;
- `detected_type` recorded, and an obvious mismatch against `target_os`
  (an APK submitted to `ubuntu/`) → `rejected` / `unsupported_type`.

That last check is the *only* use of file magic in this model. It reports;
it never routes. If detection is unavailable or ambiguous the run proceeds
on the user's choice.

Admission answers *whether the job is valid*. Whether it may **start** is a
separate question answered in `queued`, against live host capacity and
queue order — see "Clone concurrency" above. A job holds in `queued` with
`queue_reason` (`waiting_for_memory`, `waiting_for_vlan`,
`blocked_by_reservation`) until a clone can be afforded, which is why
capacity pressure is a visible, reportable condition here rather than an
invisible stall inside a thread pool. Both capacity and queue order are
host properties, so the wait is shared across all three OS watchers rather
than being per-pipeline.

> `target_os_source` was considered and dropped: with the OS supplied by
> the launcher there is one source and recording it is noise. **Revisit
> only if** DRAFT-014 finds a case where detection cannot disambiguate on
> content alone — Android ELF vs. Linux ELF, or PE32 vs. PE32+ — and only
> with evidence that a provenance field is what resolves it.

### State machine

```text
main path
  received → admitted → queued → cloning → preparing → executing → collecting
                                                                        │
                                                   completed ← cleaning ┘

exits
  admitted           → rejected                 admission failed; no clone made
  queued             → cancelled                cancelled before a clone existed
  cloning…executing  → cleaning → cancelled     cancelled while a clone was running
  cloning…collecting → cleaning → failed        carries failure_stage + failure_reason
  any non-terminal   → cleaning → interrupted   owning process died; recovery sweep
```

`cleaning` runs on every path where a clone was created — failure,
cancellation and the recovery sweep included — so a clone is never left
behind because the job ended badly. It is the one phase that is *not*
cancellable, since interrupting cleanup is how clones leak. Cancelling from
`received`, `admitted` or `queued` skips it because there is nothing to
clean.

Reconciliation with the candidate list this replaces:

- `classified` → renamed **`admitted`**. Classification no longer decides
  anything; admission does.
- `restoring` → **merged into `cloning`**. `clone-ubuntu.pl` performs the
  LVM snapshot and the `xl restore` in a single callback
  (`dirwatch.c:175`), and both fail the same way and recover the same way.
  Rule 1: the boundary is meaningless to a reader and to recovery.
- `monitoring` → **removed**. DRAKVUF starts tracing and executes the
  sample in one invocation (`drakvuf-ubuntu.sh:122`); there is no separate
  phase to enter.
- `stimulating` → **demoted to a `stage`**, not a state. It exists only for
  Android (rule 2).
- `collecting` → **kept**, though today it sits inside the same script as
  `executing`. Unlike `restoring` it changes two things a reader cares
  about: whether artifacts are readable yet, and whether a failure leaves
  results worth preserving. The per-OS script must emit it.
- `cancelled` and `interrupted` → **added**; the candidate list had no
  terminal state for either.

### The same machine against all three OS sequences

The `state` sequence is identical for all three targets. Only `stage`
differs, and only inside `executing` — which is the whole point of keeping
OS shape out of `state`:

| `target_os` | `executing` stages |
|---|---|
| `ubuntu` | `execute` |
| `android` | `install` → `launch` → `stimulate` |
| `windows` | `execute` |

Ubuntu stages one file and runs it; Android installs a package, launches a
component and stimulates exported components
(`docs/checklists/android.md:1169-1178`); Windows executes a PE with no
install step. Nothing else about them differs at the model level, and no
state in the list above is reachable by only one of them.

### Terminal status taxonomy

`status` is closed, small, and OS-independent, because it is what the web
platform switches on:

```text
completed | failed | rejected | cancelled | interrupted
```

Failures are then described on two further axes — `failure_stage` (the
`state` it ended in) and `failure_reason` (the vocabulary, scoped by
`target_os`). This is how the existing per-OS vocabularies are generalized
rather than discarded: every value drafted in
`docs/checklists/android.md:1199-1214` and every row of its failure table
at `:2198-2217` maps onto a triple.

| `failure_reason` | `status` | `failure_stage` | Scope |
|---|---|---|---|
| — (Android's `success`) | `completed` | — | all |
| `unsupported_type` | `rejected` | `admitted` | all |
| `rejected_size` | `rejected` | `admitted` | all |
| `unsupported_abi` | `rejected` | `admitted` | android |
| `clone_failed` | `failed` | `cloning` | all |
| `transfer_failed` | `failed` | `preparing` | all |
| `hash_mismatch` | `failed` | `preparing` | all |
| `injection_failed` | `failed` | `preparing` | all |
| `install_failed` | `failed` | `executing` (`install`) | android |
| `no_launchable_component` | `failed` | `executing` (`launch`) | android |
| `guest_crashed` | `failed` | `executing` | all |
| `guest_rebooted` | `failed` | `executing` | all |
| `plugin_failed` | `failed` | `executing` | all |
| `analysis_timeout` | `failed` | `preparing` or `executing` | all |
| `collection_failed` | `failed` | `collecting` | all |
| `storage_full` | `failed` | `collecting` | all |

`analysis_timeout` carries two possible stages because `dirwatch` has two
timeouts — 60s on preconfig and 180s on the trace (`dirwatch.c:374,394`) —
and which one fired is the useful half of the report.

Three rows of the Android failure table are **not** failures under this
model, and are recorded as resolved rather than mapped:

- *duplicate filename* — no longer possible to collide; `analysis_id` names
  the directory and two submissions of one sample are two records;
- *malicious filename* — handled by the filename rules below;
- *Ctrl+C interruption* — `interrupted`, via the recovery sweep.

`cleanup_failed` is deliberately absent from the table. Cleanup success is
recorded in **`cleanup_status`, independently of `status`**, as
`docs/checklists/android.md:2375` already requires: a leaked clone is an
operator problem, not an analysis result, and must not turn a successful
trace into a failed one — nor be hidden by one.

### Cancellation

A user may stop a running analysis. `cancelled` is a terminal `status` in
its own right and explicitly **not** a `failed` reason — a cancelled run
has no defect to report and must not be presented as an error.

- Cancelling in `received`, `admitted` or `queued` is immediate; no clone
  is ever created.
- Cancelling in `cloning`, `preparing` or `executing` must destroy the
  clone. The primitive already exists: `timer_thread` calls `cleanup()` on
  expiry (`dirwatch.c:240-241`), destroying the clone domain out from under
  the running child, which collapses the current phase. Cancellation
  reuses that path rather than inventing one.
- `cleaning` and the terminal states are not cancellable.
- `cancel_requested_at` and `cancelled_by` are recorded; a cancellation is
  a decision someone made, and the record should say who and when.

> **Required property of any implementation (DRAFT-035).** Triggering the
> timeout path is *not by itself* a cancellation. After it fires,
> `run_drakvuf` falls through to `end:` and re-clones the sample with
> `goto restart` (`dirwatch.c:424-429`), guarded only by `shutting_down`
> (`:425`). A cancel flag must be checked at that same branch. Without it,
> "stop the analysis" produces an unbounded clone/retry loop instead of a
> stop — the opposite of what the user asked for.

### Filenames: two namespaces

The submitted filename is untrusted input and is also behaviourally
significant to the sample. Those two facts are reconciled by using it in
exactly one place:

| Where | Name | Why |
|---|---|---|
| Host result directory | `analysis_id` | Run identity; no untrusted bytes in any Dom0 path |
| Host sample copy | `sample/<sha256>` | Content-addressed; the submitted name is metadata, not a path |
| Guest | `guest_filename` | Malware behaviour is frequently name-dependent |

Inside the guest the sample keeps the name it was submitted with, because
extension-driven handler dispatch, `argv[0]` self-checks and APK filename
assumptions are all real evasion and real behaviour, and a sample renamed
to `test` exercises none of them. That is a deliberate, scoped exception:
the untrusted name is used **inside the disposable clone only, never on
Dom0**.

Two rules make it safe:

- The name must reach the guest as a **single argv element, never through
  a shell-parsed string**. `drakvuf -e` is execve-direct with no guest
  shell — established by issue #2 (`docs/runbooks/verify-user-placeholder.md`)
  — so a name cannot dereference guest-side through that path.
- `guest_filename` is *normalized, not discarded*: path separators and NUL
  stripped, length capped, Windows reserved names (`CON`, `PRN`, trailing
  dot or space) rejected. It is stored separately from `original_filename`
  so a reader can see when the two differ and why.

> **KNOWN GAP (DRAFT-030, DRAFT-027).** The staging path today is exactly
> the unsafe form this forbids: `preconfig-ubuntu.sh:122` interpolates the
> sample filename into a shell string
> (`… wget 'http://172.16.$VLAN.1/$RUNFILE' -O …`) which `:125` then hands
> to `injector -m execproc -e /usr/bin/sh -f -c`, so the guest *does* get a
> shell and the name *is* parsed by it. Guest-original naming must not be
> implemented on top of this. DRAFT-027 replaces HTTP delivery with
> `injector -m writefile`, which is the change that makes this section
> implementable.

### Recovery after interruption

A job's state must be reconstructable from disk after a host reboot, not
held only in a running process.

- `status.json` is the source of truth, rewritten atomically at every
  transition.
- Per design rule 3, `domain`, `vlan` and `clone_id` are written with
  `state: cloning` **before** `lvcreate`/`xl restore` runs. A clone that
  exists but was never recorded is unattributable, and unattributable
  clones are what fill a volume group.
- On startup, a sweep visits every non-terminal record: if no live process
  owns it, it becomes `interrupted` with `failure_stage` set to the last
  recorded state, and its recorded `domain`/`vlan` are handed to
  `cleanup.sh` — which already takes exactly those two arguments
  (`cleanup.sh:113-114`).

> **Implementation note — the ID carrier.** `dirwatch` passes its per-run
> `utime` to the preconfig, drakvuf and tcpdump callbacks
> (`dirwatch.c:188,378,398`), and the current scripts ignore it
> (`preconfig-ubuntu.sh:111-117` reads only `$1`–`$7`). So an
> `analysis_id` can reach three of the five callbacks with **no** change to
> the 15-argument contract. `clone-*.pl` and `cleanup.sh` receive only
> domain and vlan (`dirwatch.c:175,214`); reaching those needs either a
> vlan-keyed lookup or a contract change, which is DRAFT-010's decision,
> not this model's.

### Presentation projection (M7 web platform)

The model has to tell the UI what to show at each step, not only what
happened at the end. Two mechanisms:

`display_phase` is a coarse projection of `state`, so user-facing copy does
not churn every time an internal state is refined:

| `display_phase` | `state` |
|---|---|
| Queued | `received`, `admitted`, `queued` |
| Preparing | `cloning`, `preparing` |
| Running | `executing` |
| Finishing | `collecting`, `cleaning` |
| Done | `completed`, `failed`, `rejected`, `cancelled`, `interrupted` |

And the per-state contract the UI reads:

| `state` | Artifacts readable | Terminal | Cancellable | Retryable |
|---|---|---|---|---|
| `received`, `admitted`, `queued` | none | no | yes | — |
| `cloning`, `preparing` | none | no | yes | — |
| `executing` | none (still being written) | no | yes | — |
| `collecting` | none (directory not yet renamed) | no | no | — |
| `cleaning` | all | no | no | — |
| `completed` | all | yes | no | yes |
| `failed`, `interrupted` | partial, preserved | yes | no | yes |
| `rejected` | none | yes | no | no (fix the input) |
| `cancelled` | partial, preserved | yes | no | yes |

A job in `queued` also carries `queue_reason`, so the UI can distinguish
"your turn is coming" from "the host is out of memory" — the second is an
operator signal, not a user one, and the two should not render identically.

Artifacts are unreadable before `cleaning` because the result directory is
built at `.<analysis_id>.tmp` and renamed into place only when complete
(the pattern already drafted at `docs/checklists/android.md:1756-1761`).
A reader therefore never observes a half-written run, and needs no locking
to avoid it.

### What this supersedes

- **Ubuntu's implicit model.** MD5-keyed result directories and a
  two-outcome reading of DRAKVUF's return code (`drakvuf-ubuntu.sh:127`).
  Superseded deliberately, not by oversight: it was never a cross-OS
  design, it predates Android and Windows, and it cannot express a
  cancelled, retried, rejected or interrupted run. Ubuntu keeps behaving
  exactly as it does today until DRAFT-011 retrofits it.
- **The MD5-vs-SHA-256 question.** Decided here, once: SHA-256 is the
  sample key; MD5 survives as an identifier only.
  `docs/architecture/result-schema.md` §3 defers to this section rather
  than answering it separately.
- **The candidate field and state lists** previously in this section, per
  the reconciliation notes above.
- **`docs/checklists/android.md` §4.1 and §7.3's proposals** — adopted in
  substance (the `stage` field, the status vocabulary, atomic writes, the
  temp-directory rename) with three changes, annotated in place at those
  sections: the result directory is keyed by `analysis_id` rather than
  SHA-256, `cleanup_status` is separated from `status`, and `stimulate` is
  a stage rather than a state.
- **DRAFT-014's routing premise.** Sample OS detection no longer decides
  where a sample runs; that entry is now a typing and identification
  contract. Its backlog row records the rescope.

## Architecture decision: keep `dirwatch.c` in C, or move to Python?

Not decided. Per project rules, do not rewrite merely because Python is
easier — the interface/callers above must be fully documented first
(DRAFT-010), and any replacement must preserve the same callback contract
so `clone-*`/`preconfig-*`/`drakvuf-*`/`cleanup.sh`/`tcpdump.sh` scripts
don't all need simultaneous rewrites.

The state model adds four requirements this decision now has to carry,
whichever way it goes: a cancellation check on the retry branch
(`dirwatch.c:425`), state transitions recorded durably rather than held in
the worker struct, a startup sweep that reconciles orphaned records against
live domains, and — per DRAFT-036 — memory-based admission plus a VLAN
lease that is shared between processes rather than a static per-process
array. That last one is the weightiest: `slots_busy[128]` and
`find_thread()` are the parts of this file that would not survive the
change, and they are also what a rewrite would most obviously replace.
None of these is a reason on its own to rewrite, but a C-side
implementation should be costed against all four rather than just the
first.