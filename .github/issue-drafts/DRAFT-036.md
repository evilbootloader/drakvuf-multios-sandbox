# DRAFT-036: Replace fixed clone slots with a host-global admission controller — VLAN leases, memory reservation, starvation-free queue

**Status:** **[#33](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/33) — published, OPEN pending Dom0 verification 2026-08-19.** Drafted, not published — see "Publication gate" below.
**Area:** core/platform
**OS:** ALL (shared `dirwatch.c` + `network-setup.sh`)
**Milestone:** M1
**Priority:** P0
**Depends on:** Issue #3 (produced this). Fix shape blocked on DRAFT-010.
Related: DRAFT-028 (`network-setup.sh` idempotency).

# Objective

Three changes to how a clone is allowed to exist, which are one change
because they are the same code:

1. Make VLAN allocation **host-global** instead of per-process. Today it is
   a by-product of a process-local thread-slot index, which means two
   `dirwatch` instances hand out the same VLAN.
2. Admit clones against **available host memory** instead of a fixed
   per-watcher count, so capacity is shared across OS pipelines rather than
   partitioned in advance.
3. Give the queue a **host-global order with anti-starvation**, so that a
   large clone waiting for memory is not overtaken indefinitely by smaller
   ones that keep fitting.

Item 1 is a correctness defect and the reason this is P0. Item 2 is the
efficiency goal that motivated looking. Item 3 is what item 2 breaks if
added on its own.

All three are one change because they need the same thing: a single
host-global, crash-safe admission authority that several `dirwatch`
processes contend on rather than each deciding for itself. A VLAN taken
without it collides; memory admitted without it overcommits (PLAN step 4);
a queue ordered without it starves (PLAN step 5). Building that mechanism
three times — or once for VLANs and not for the rest — is the failure mode
to avoid.

# Context

Issue #3 decided that the target OS is selected by the submitter, via one
incoming directory and one `dirwatch` instance per OS
(`docs/architecture/analysis-pipeline.md`). That decision is sound — it
adopts a constraint `dirwatch` already has — but it turns a
single-process assumption into a multi-process one, and the allocator was
never written for that.

## What the code does today (source-verified 2026-08-09)

Concurrency, slot identity and network identity are one mechanism:

- `<max clones>` sizes a fixed `GThreadPool` (`automation/dirwatch.c:493`).
- `find_thread()` claims a slot by atomic CAS on a **file-scope static**
  array, `static gint slots_busy[128]` (`:161`, `:195-209`).
- The claimed slot index *becomes* the VLAN:
  `make_clone(xen, &cloneID, threadid + 1, &clone_name)` (`:297`). The same
  `threadid + 1` is passed to `cleanup()` (`:241`, `:302`, `:421`) and to
  the preconfig, drakvuf and tcpdump callbacks (`:188`, `:378`, `:398`).
- `automation/network-setup.sh:145-149` provisions VLANs `1..N` from its
  one argument, each with gateway `172.16.$i.1/24` on `xenbr1.$i`.
- `automation/run_analysis-ubuntu.sh:9,20` passes `2` to both
  `network-setup.sh` and `dirwatch`, and the header comment at `:5-8`
  already records that the two must match.

So slot 0 means VLAN 1 means `xenbr1.1` means `172.16.1.0/24`, and the
array that decides it is private to one process.

## Consequence 1: the VLAN space collides across watchers

`slots_busy[]` is zero-initialized in every process. A second `dirwatch`
therefore claims slot 0 first, exactly as the first one did, and both
clones are placed on `xenbr1.1`.

This is not only a naming clash. Because `preconfig-*.sh` assigns the clone
a **fixed** address derived from the VLAN —
`ip addr add 172.16.$VLAN.2/24 dev eth0`
(`automation/preconfig-ubuntu.sh:122`) — two clones sharing a VLAN are
both `172.16.1.2` on one L2 segment. Three concrete failures follow:

- **Isolation.** The two samples are on the same segment with no rule
  between them; inter-clone `DROP` is per-VLAN-interface
  (`network-setup.sh:169`) and cannot separate members of the same VLAN.
  Two malware samples from different pipelines can reach each other.
- **Duplicate address.** Both clones claim `172.16.1.2`. Behaviour is
  whatever ARP resolves last — traffic intended for one sample reaches the
  other, non-deterministically.
- **Evidence mixing.** `tcpdump.sh:117` captures on `xenbr1.$VLAN`, so one
  pcap contains both analyses' traffic and is written to both result
  directories under different names.

What does **not** collide, and should not be listed as a symptom: clone
domain names and their LVs. `clone-ubuntu.pl:167` builds
`"$origin-$vlan-clone"`, and the origin differs per watcher
(`ubuntu_sandbox` vs `android_sandbox`), so the names stay distinct. The
existing comment at `clone-ubuntu.pl:248-251` is correct within a process
and remains correct across processes. The network is the only thing that
collides.

A second launcher also re-runs `network-setup.sh`, which is not idempotent
and appends rules on every invocation (its own `KNOWN GAP (DRAFT-028)`
note, `:123-127`). Whether `vconfig add xenbr1 1` fails or silently
no-ops for an existing sub-interface is untested — see TEST.

## Consequence 2: a fixed clone count is the wrong unit

Each watcher carries its own `<max clones>`, set independently, with no
way to lend capacity to another. A split such as "5 Windows, 3 Ubuntu,
3 Android" sized to be safe when all three are busy leaves most of the
host idle whenever only one OS is in use; sized to fill the host for one
OS, it overcommits when all three run. Raising the numbers cannot fix
this, because the caps cannot observe each other.

A single shared count would not fix it either, because clones are not
interchangeable. `misc/ubuntu_sandbox.cfg:14-15` and
`misc/android_sandbox.cfg:14-15` both pin `memory = maxmem = 2048` with no
ballooning headroom, and a Windows sandbox will want more (the figure is
unknown until DRAFT-034 selects a baseline; there is no `misc/windows*.cfg`
yet). The admissible quantity is **memory**: a clone should be created when
the host can afford *that* clone, whichever pipeline asked for it. That is
also what makes the arrangement efficient rather than merely safe — one
busy OS can use the whole host.

## Consequence 3: memory-only admission starves the largest clone

Fixing consequence 2 naively creates a new failure. "Admit whatever
currently fits" is greedy, and clones are unequal in size, so the largest
one loses systematically: a Windows job needing more than an Ubuntu or
Android clone waits for a window that never opens, because every time
memory frees up a smaller job is already eligible and takes it. Windows
analyses would appear to hang while the other two pipelines run normally —
and nothing in the logs would say why, since each individual admission
decision is correct.

This is not hypothetical for this project specifically: the sizes are
already unequal and about to become more so, and the three pipelines are
expected to be fed concurrently.

The queue also has no host-global order today, and cannot acquire one by
accident. Each `dirwatch` maintains its own `inotify` watch and its own
thread pool, so three watchers means three independent queues with no
relative ordering between them. Whichever happens to check at the moment
memory frees up wins. Ordering has to come from the same authority that
owns the memory reservation — it cannot be bolted on per-watcher.

# Dependencies

- **Issue #3** — decided the per-OS-watcher arrangement that exposes this.
  Already closed out in `docs/architecture/analysis-pipeline.md`.
- **DRAFT-010 (blocking, for the fix only)** — DRAFT-010 owns whether
  `dirwatch` stays in C or is replaced. That determines whether the fix is
  "add a cross-process lease to `dirwatch.c`" or "design the allocator into
  the replacement". The *defect* is established regardless; only PLAN and
  CREATE below wait on it.
- **DRAFT-028** — `network-setup.sh` idempotency and failure handling.
  Sequence them: provisioning VLANs correctly is prerequisite to leasing
  them.
- **DRAFT-034** — supplies the Windows clone's memory figure, which is the
  input that makes the starvation case concrete. The design does not wait
  on it (unequal sizes already exist), but the TEST 9 numbers do.
- **DRAFT-035** — shares the `dirwatch.c:425` branch. Sequence the two so
  the cancellation check and any retry cap land together rather than as
  competing edits to the same six lines.
- **Blocks** any concurrent per-OS watcher, and therefore the point at
  which DRAFT-015/016 (Android scripts) are first run alongside Ubuntu.

# Out of scope

- Choosing between C and Python for `dirwatch` (DRAFT-010).
- Fixing `network-setup.sh`'s idempotency, deprecated `-o !xenbr0` rule, or
  `vconfig` usage (DRAFT-028).
- Dom0-reachability restriction from clones (DRAFT-029).
- Any change to what a clone *does* once created.
- Capping the unbounded retry loop at `dirwatch.c:424-429`. That branch
  belongs to DRAFT-010 (the worker-slot leak around it) and DRAFT-035 (the
  cancellation check on it). This issue only records that PLAN step 5's
  Stage B cannot ship until a cap exists.
- Selecting the Windows clone's memory size — DRAFT-034.

# PLAN

Deliberately thin below step 2 — the mechanism depends on DRAFT-010.

1. **Separate the three roles the slot index currently plays**:
   concurrency limit, worker identity, and network identity. Only the third
   needs to be host-global. Record which callbacks consume which — the
   argument audit is already in `analysis-pipeline.md`'s "ID carrier" note.
2. **Define the VLAN lease.** Requirements, independent of implementation:
   host-global; crash-safe (a watcher killed mid-run must not strand a
   VLAN); bounded by what `network-setup.sh` actually provisioned; and
   releasable by `cleanup.sh`, which today receives the VLAN as `$2` and
   nothing else (`cleanup.sh:113-114`).
3. **Define the memory admission rule.** Candidate, requires measurement:

   ```text
   required  = clone .cfg memory + shadow_memory (32) + per-domain overhead
   available = xl info -> free_memory, minus a fixed reserve
   admit if    required <= available
   ```

   > **Precondition, observed on Dom0 2026-08-09 during issue #4's
   > deployment: a running analysis clone showed `maxmem` unlimited in
   > `xl top`.** This rule assumes a clone's consumption is bounded by its
   > config, and all four `misc/*.cfg` do set `maxmem` equal to `memory`
   > (2048 for the sandbox templates). If the *effective* ceiling is
   > unbounded, `required` above is a guess rather than a bound, and a
   > clone can grow into memory the controller had reserved for another —
   > which converts this from an admission rule into a hint.
   >
   > Likely cause is how `xl restore` reconciles the passed config against
   > the settings inside the saved image; `clone-ubuntu.pl` copies
   > `maxmem`/`memory` through verbatim and rewrites only `name=`, `vif=`
   > and `disk=`. **Not diagnosed** — needs `xl list -l <clone>` compared
   > against the generated `/tmp/<clone>.config`.
   >
   > Settle this before implementing step 3. If clones cannot be capped,
   > this issue needs a different mechanism (a hard `maxmem` set on the
   > clone after restore, or admission against a pessimistic ceiling)
   > rather than a more careful version of the same arithmetic. See
   > `docs/runbooks/deploy-repo-relative-paths.md`, D5 observations.

   Dom0 is pinned at `dom0_mem=4096M,max:4096M`
   (`docs/drakvuf-on-xen-nested-within-proxmox.md:280`) and does not
   balloon, so the reserve covers Xen's own allocation and the restore
   burst, not Dom0. `xl restore` reinstates a full memory image, so
   admission must be sized against that **peak**, not steady state. This is
   the part most likely to be wrong first time.

4. **Serialize the admission decision host-globally.** The rule above is
   check-then-act, so on its own it is a race, and every watcher racing is
   the normal case rather than the unlucky one: each reads `free_memory`,
   each sees enough for one clone, each proceeds, and the host is
   overcommitted by however many watchers were deciding at that moment.
   The failure surfaces late and badly — as a failed or OOM-killed
   `xl restore` partway through a run, not as a refused admission.

   A plain mutex around the check is **not sufficient**. A clone's memory
   does not appear in `xl info` until the domain is actually built, so a
   lock released when `xl restore` is launched leaves the next watcher
   reading a `free_memory` that still counts the in-flight clone's memory
   as free. The reservation therefore has to outlive the lock:

   - hold a host-global lock across *read available → record reservation*;
   - release the lock immediately, so watchers do not serialize on the
     slow part (`xl restore`), only on the decision;
   - subtract outstanding reservations from `free_memory` in every
     subsequent check, until the domain is built and Xen accounts for it;
   - make reservations crash-safe, so a watcher killed between reserving
     and building does not permanently shrink apparent capacity.

   This is the same host-global, crash-safe, releasable-by-`cleanup.sh`
   mechanism step 2 needs for VLANs, and it should be one implementation
   rather than two. That both allocations need it is the strongest argument
   that item 1 and item 2 in the Objective are genuinely one change.
5. **Order the queue host-globally, and make it starvation-free.**
   Ordering key is `submitted_at`, which the job record already carries —
   no new field is needed for FIFO itself.

   The recommended shape, in two stages rather than one:

   - **Stage A — head-of-line reservation (start here).** The oldest
     `queued` job that cannot currently be afforded takes a standing
     reservation, and freed memory accumulates toward it instead of being
     handed to whichever smaller job happens to fit. Nothing smaller is
     admitted while a reservation is outstanding. This cannot starve, is
     simple enough to reason about, and its cost is idle memory during the
     accumulation window.
   - **Stage B — bounded backfill (only once step 5's prerequisite below
     holds).** Let a smaller job run ahead of the reservation when it is
     guaranteed to finish before the reservation could otherwise be
     satisfied. This recovers the idle window Stage A accepts.

   Backfill needs a worst-case completion bound per job. Two of the three
   terms exist: the preconfig phase is capped at 60s and the trace at 180s
   (`dirwatch.c:374`, `:394`), with clone and cleanup time on top.

   > **Prerequisite for Stage B — the third term is currently unbounded.**
   > On timeout, `run_drakvuf` calls `prepare()` and `goto restart`
   > (`dirwatch.c:424-429`) with **no retry counter**, and `prepare()`'s
   > return value is not checked — the `if (prepared)` guard is commented
   > out at `:430-436`. A sample that times out reliably therefore retries
   > indefinitely, holding its worker slot and VLAN. So per-job worst-case
   > runtime has no bound today, and Stage B cannot be made safe until the
   > retry loop gains one. That same branch is where DRAFT-035 must add its
   > cancellation check, and the surrounding cleanup path is DRAFT-010's
   > worker-slot leak — three separate issues meeting at one `goto`, which
   > is itself an argument for settling DRAFT-010 first.

   Do **not** implement per-OS reserved floors as the anti-starvation
   mechanism. Guaranteeing each OS a slice reintroduces exactly the static
   partitioning consequence 2 exists to remove.

6. **Decide where a job waits.** Issue #3 already answers this: a job that
   is admissible but cannot yet be afforded holds in `queued` with
   `queue_reason` (`waiting_for_memory`, `waiting_for_vlan`), visibly,
   rather than blocking inside a thread pool. Extend that vocabulary with
   `blocked_by_reservation` for jobs held behind a larger one, so "waiting
   its turn" and "waiting for the host" are distinguishable in the UI
   rather than both rendering as an unexplained stall.
7. Implement, once DRAFT-010 has settled the language question.

# CREATE

Not started, and deliberately not designed further until DRAFT-010 lands.
Expected to touch `automation/dirwatch.c` (or its replacement),
`automation/cleanup.sh` (lease release), and the `run_analysis-*.sh`
launchers.

# TEST

Static: `bash -n`, `shellcheck`, `perl -c` per `CLAUDE.md`; a C change
needs a Dom0 build.

Behavioural — all require Xen Dom0, none can run in the dev container:

1. **Reproduce the defect first.** Start two `dirwatch` instances against
   different origins, drop one sample into each, and confirm both clones
   receive VLAN 1. Record it before fixing; a fix with no recorded
   pre-state proves nothing.
2. Confirm `172.16.1.2` is assigned twice, and that the two clones can
   reach each other.
3. Confirm one `tcpdump.pcap` contains both samples' traffic.
4. After the fix: same test, distinct VLANs, no duplicate address, one
   capture per analysis, and `iptables -S FORWARD` showing a rule per
   allocated VLAN.
5. Kill a watcher mid-run and confirm its VLAN is reclaimed rather than
   stranded.
6. **Untested question to settle in passing:** does `vconfig add xenbr1 1`
   fail or silently no-op when `xenbr1.1` already exists? A second
   launcher calls it today.
7. Memory admission: fill the host and confirm jobs hold in `queued` with
   `queue_reason=waiting_for_memory` rather than failing a clone; confirm
   the restore peak does not overshoot the reserve.
8. **Race the admission decision deliberately.** Drop samples into all
   three watch directories simultaneously, with the host sized to afford
   exactly one more clone, and confirm exactly one is admitted and the rest
   hold in `queued`. Repeat with the reservation mechanism disabled to
   record the pre-fix behaviour — the point is to show the race exists and
   is closed, not to assert it. Then kill a watcher between reserving and
   `xl restore` and confirm capacity returns.
9. **Starvation test.** Queue one large clone (the Windows sandbox, or an
   Ubuntu config temporarily raised above the others) behind a continuous
   feed of smaller ones, and confirm the large job runs within a bounded
   number of smaller completions rather than never. Record the pre-fix
   behaviour the same way — with greedy admission it should be observably
   starved, which is the evidence that the reservation is doing something.

# DEPLOY

Dom0 only, and behind the same human-review gate as any `automation/`
change. Deploy with DRAFT-028 rather than before it — leasing VLANs that
were never correctly provisioned records a known-broken state.

# Acceptance criteria

- [ ] Two `dirwatch` instances running concurrently never allocate the same
  VLAN, demonstrated by execution evidence, not by inspection.
- [ ] The pre-fix collision is recorded as observed evidence before the fix.
- [ ] A VLAN held by a killed watcher is reclaimed.
- [ ] `cleanup.sh` releases the lease it was given, with no new arguments
  beyond what its callers already pass, or with the contract change
  documented in `analysis-pipeline.md`.
- [ ] Clone creation is gated on available memory, not a per-watcher count,
  and the rule's constants are justified by measurement rather than
  assumption.
- [ ] Concurrent watchers deciding at the same moment cannot both be
  admitted against the same free memory, demonstrated by the deliberate
  race in TEST 8 — and a watcher killed between reserving and building does
  not permanently shrink apparent capacity.
- [ ] VLAN leases, memory reservations and queue ordering use **one**
  host-global mechanism, not three.
- [ ] A large clone queued behind a continuous feed of smaller ones runs
  within a bounded number of smaller completions, demonstrated by TEST 9,
  with the pre-fix starvation recorded first.
- [ ] Anti-starvation is achieved without per-OS reserved capacity, since
  that would reinstate the static partitioning this issue removes.
- [ ] If bounded backfill is implemented, the retry loop at
  `dirwatch.c:424-429` has a cap first; if it is not implemented, the draft
  records that Stage A alone shipped and why.
- [ ] A job that cannot be afforded holds in `queued` with `queue_reason`
  set, per the state model.
- [ ] `analysis-pipeline.md`'s "Clone concurrency" section is updated from
  candidate to measured, and its `KNOWN GAP (DRAFT-036)` note is deleted
  rather than reworded.
- [ ] `run_analysis-*.sh`'s clone-count/VLAN-count coupling comment
  (`:5-8`) is corrected or removed, whichever the fix makes true.

# Evidence required

`xl list`, `ip -d link show type vlan`, `iptables -S FORWARD` and
`ip addr` from inside both clones, captured before and after. Plus `xl
info` output across an admission decision, showing `free_memory` at the
moment a clone was admitted and at the moment one was held.

# Security considerations

This *is* a security issue, not only a resource one. The VLAN collision
defeats the only inter-clone isolation mechanism the pipeline has
(`network-setup.sh:152-154`), and it does so silently — two samples on one
segment look exactly like two samples on two segments in every log the
project currently writes. It compounds the two isolation gaps already
recorded: the inter-clone `DROP` may never install at all (DRAFT-028), and
`FORWARD` cannot cover traffic to Dom0 itself (DRAFT-029). Until this
lands, do not run more than one `dirwatch` instance on a host, and treat
any claim of inter-clone separation as unproven.

Memory admission has a smaller but real security dimension. An unbounded
queue of admitted-but-unaffordable jobs is a local denial of service
against the analysis host — and the unserialized check in PLAN step 4
makes it reachable without any adversary at all, since concurrent watchers
overcommit the host by simply doing their normal work at the same time.
Submitting to all three pipelines at once is enough to trigger it, which
is an ordinary usage pattern rather than an attack.

# Documentation changes

`docs/architecture/analysis-pipeline.md` ("Clone concurrency", and the
C-vs-Python section's fourth requirement), `automation/network-setup.sh`
and `automation/run_analysis-*.sh` header comments, `CLAUDE.md`'s dirwatch
bullet, and `docs/checklists/platform.md`.

# Recovery / rollback

Revert is a code revert plus removing whatever lease state lives outside
the process (a directory or lock file). No LVM, guest image or saved state
is touched. A stranded lease must be manually clearable, and the mechanism
for doing so belongs in `docs/runbooks/`.

# Publication gate

Draft only. Do **not** publish until DRAFT-010 has decided C-vs-Python:
the Objective, Context and Evidence above are settled and source-verified,
but PLAN/CREATE would commit to an approach that decision may invalidate.
Publishing early would put a design in a public issue that we already know
is provisional.