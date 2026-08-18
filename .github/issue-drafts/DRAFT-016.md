# DRAFT-016: Implement `preconfig-android.sh` and `drakvuf-android.sh`

**Status:** Drafted, not published — 2026-08-14
**Area:** android
**Milestone:** M3 (Android MVP)
**Priority:** P1
**Depends on:** DRAFT-015 (hard — `pipeline-android.env`,
`run_analysis-android.sh` and the shared `clone.pl` do not exist),
DRAFT-030 (hard — guest-filename
normalizer, C5), DRAFT-033 (hard — template error handling), DRAFT-011
(soft — the `ps | grep` PID match this must not copy). DRAFT-031 and
DRAFT-037/#7 are landed. DRAFT-013/#13 is landed and supplies the
specification.
**Origin:** `docs/checklists/android.md` §2.7–2.8; specification measured
2026-08-14 in `docs/runbooks/verify-android-isolation.md` and recorded as
§1.6 of the checklist.

> **Retitled on drafting.** The index row reads "Implement
> `preconfig-android.sh` / `drakvuf-android.sh` per checklist §2.7–2.8".
> §2.7–2.8 is no longer the specification for either file: §1.6 supersedes
> §2.7's network half outright, issue #6 withdrew the in-guest collection
> that §2.8's stage list is built around, and issue #4 corrected the
> `injector` argument shape §2.7 still shows as a candidate. The checklist
> sections remain the *requirements* list; the *procedure* now comes from
> §1.6. Both are cited below where they still hold.

> **Two decisions taken while drafting, 2026-08-14.** Recorded here because
> each closes a question the index row left open, and each is argued in full
> below rather than at the point of use.
>
> 1. **The APK path is in scope** — `pm install` + launch, selected against
>    the native-`execve` path by a structural test this script performs
>    itself, not by the advisory `detected_type` field. Section 3.
> 2. **`70-collect` is dropped and C7 stands unamended.** Two ways of
>    collecting guest artifacts were considered and rejected; the reasoning,
>    including the better of the two, is kept so it is not re-proposed
>    blind. Section 4 and the scope corrections.
>
> Settling (2) turned up something wider: the upstream plugin table marks
> `fileextractor` and `memdump` unsupported on Linux, **but this lab does not
> build upstream**, and both are runtime-evidenced working on Linux in the
> deployed fork. Section 4 records the evidence, because reasoning from the
> upstream table would have mis-scoped this issue and will mis-scope
> DRAFT-034 too.

# Objective

Write the two per-OS worker scripts that `dirwatch` calls for an Android
sample: `preconfig-android.sh` (stage the sample into a booted clone, then
configure that clone's network) and `drakvuf-android.sh` (run the trace
against the staged sample, by whichever of the two execution paths the
sample's format calls for). Both must satisfy C1–C10 in
`docs/architecture/analysis-pipeline.md`, "Shared and per-OS code boundary".

# What DRAFT-013 already settled — do not re-derive it

DRAFT-013 (#13) exists so that this issue is written from a measured
procedure rather than by translating `preconfig-ubuntu.sh`. Its output is
the parity matrix at `docs/checklists/android.md` §1.6, filled 2026-08-14.
The result is that **Bliss-Bass EthernetConfig subsumes the entire `ip`
chain**, and the network half of this script is three commands:

```sh
# 1. ART classpath. Measured NOT already present, so required today.
while IFS=' ' read -r action name value; do
    [ "$action" = "export" ] && export "$name=$value"
done < /data/system/environ/classpath

# 2. Address, prefix, gateway AND resolver in one framework call.
#    app_process64, not app_process.
APK="$(pm path com.example.ethernetconfig | sed 's/^package://')"
CLASSPATH="$APK" /system/bin/app_process64 / \
    com.example.ethernetconfig.network.EthernetConfigurator \
    STATIC eth0 172.16.<vlan>.2 24 172.16.<vlan>.1 "$GUEST_NAMESERVER" none

# 3. Force plaintext DNS.
settings put global private_dns_mode off
```

Four facts from that run are inputs here and are not open questions:

- **No `sudo`, no `su -c`.** The guest is already root and ships neither.
- **`/system/bin/sh`**, not `/usr/bin/sh` (`preconfig-ubuntu.sh:209`).
- **`private_dns_mode off` is required, not a tuning knob.** Left at its
  default the clone resolved over DoT to `1.1.1.1:853` and the pcap recorded
  an encrypted stream instead of the domains a sample looked up — silently,
  with nothing failing. Pcap-evidenced both ways.
- **`/etc/resolv.conf` has no Android equivalent.** The resolver is an
  argument to (2); there is no file to write.

# What this issue owns, and what nobody has measured yet

## 1. No `injector` operation has ever run against an Android guest

This is the largest risk in the issue and it is not stated anywhere else, so
it is stated here. Every `injector` invocation in the Android documentation
is either a candidate (`docs/checklists/android.md:1398`, `:1431`, `:1462`)
or derived from `injector --help` captured on Dom0 against **Ubuntu**
(`docs/runbooks/verify-user-placeholder.md:154-157`). The staging-directory
probe that chose `/data/local/tmp` (§2.7, 2026-08-10) was run from a guest
terminal, and DRAFT-013's three commands were run from the guest console.

So this issue is not "port two working scripts". It is the first exercise of
`writefile` **and** `execproc` against a BlissOS guest, and either can fail
for Android-specific reasons that Ubuntu never surfaced — the injection
anchor is a backgrounded `nano` rather than a shell, and `injector` does not
warn when an injection targets the wrong process.

Consequence for sequencing: **the first Dom0 test in this issue is a
single `writefile` of a benign file, verified with `readfile`,** before any
script is written. If that does not work the rest of the issue is moot.

## 2. The single-argv collapse, and a quoting hazard Ubuntu does not have

`injector -m execproc` is execve-direct with no guest shell (issue #2), so
the three commands above must reach the guest as one argument to
`/system/bin/sh -c`. The runbook flags the quoting as the risk
(`verify-android-isolation.md:1140`). It is worth naming the specific trap,
because it fails silently.

`preconfig-ubuntu.sh:206` builds its chain in **double quotes**, and every
`$` in it — `$VLAN`, `$GUEST_NAMESERVER` — is *meant* to expand on Dom0.
Android's sequence needs **mixed** expansion:

| Expands where | Tokens |
|---|---|
| Dom0 (the values `dirwatch` and the env supply) | `$VLAN`, `$GUEST_NAMESERVER` |
| **Guest** (must survive the Dom0 shell untouched) | `$action`/`$name`/`$value`, `$APK`, and the `$(pm path …)` substitution |

Written the Ubuntu way, `$(pm path …)` **runs on Dom0**, where `pm` does not
exist. It expands to the empty string, the injected command becomes
`CLASSPATH= /system/bin/app_process64 …`, and the guest gets a command that
is well-formed and wrong. Nothing errors on the Dom0 side.

Proposed shape — guest-side text single-quoted, Dom0 values the only thing
interpolated. **Untested; the point of the TEST section is to falsify it:**

```sh
# Guest-side expansions stay inside single quotes so they reach the guest
# intact. Only VLAN and GUEST_NAMESERVER interpolate here, and they are the
# only two values Dom0 actually knows.
NETCFG='while IFS=" " read -r a n v; do [ "$a" = export ] && export "$n=$v"; done < /data/system/environ/classpath; '
NETCFG="${NETCFG}"'APK="$(pm path com.example.ethernetconfig | sed "s/^package://")"; '
NETCFG="${NETCFG}"'CLASSPATH="$APK" /system/bin/app_process64 / '
NETCFG="${NETCFG}com.example.ethernetconfig.network.EthernetConfigurator STATIC eth0 "
NETCFG="${NETCFG}172.16.${VLAN}.2 24 172.16.${VLAN}.1 ${GUEST_NAMESERVER} none && "
NETCFG="${NETCFG}settings put global private_dns_mode off"

injector -r "$REKALL" -d "$DOMAIN" -i "$PID" -m execproc \
    -e "/system/bin/sh" \
    -f "-c" \
    -f "$NETCFG" \
    1>>"$LOG" 2>&1
```

Note `${NETCFG}` and not `$NETCFG` in the concatenations: `"$NETCFG172.16…"`
parses as a variable named `NETCFG172` and yields the empty string. That is
the same class of silent failure as the one above, one line away from it.

The inner `sed` uses double quotes deliberately, so the single-quoted
segment survives. This is why the sequence is assembled rather than written
as one literal.

## 3. The execution method — decided 2026-08-14: two paths, selected by type

`drakvuf-ubuntu.sh:154` runs the sample with `-m execproc -e "$CMD"`:
execve-direct, one path, no guest shell. On Android that covers a native ELF
staged in `/data/local/tmp` — which is exactly the property that directory
was chosen for (§2.7, execution probe, 2026-08-10). It does **not** cover an
APK, which is installed by `pm install` and launched by `am start`, both of
which need a guest shell and neither of which is `execve` of the staged file.

**Decided (maintainer, 2026-08-14): implement both, and select between them
on the sample's type.** An Android pipeline that cannot analyse APKs does not
deliver the thing the Android target exists for, so the `pm install` +
`am start` path is in scope here rather than deferred to DRAFT-017.

This does **not** violate C6. C6 constrains *delivery* — one `writefile`, no
guest shell before it — and install happens afterwards, in
`drakvuf-android.sh`, once the trace is already running.

| Sample | Path |
|---|---|
| APK | `pm install` the staged file, then launch it, both through `/system/bin/sh -c` via `execproc` |
| native ELF | `execproc -e "$CMD"` directly, the Ubuntu shape |
| neither | `unsupported_type`, no execution attempted |

### The selector must not be the state model's `detected_type`

`detected_type` is deliberately **advisory** (issue #3), and §2.7 used exactly
that to reject choosing a *staging directory* by type
(`docs/checklists/android.md:1528`): "selecting a staging directory from
`detected_type` would make that field load-bearing when the state model
deliberately keeps it advisory." Selecting the execution method from it has
the same effect — a misidentified APK takes the execve path and fails in a
way that looks like a sample that did nothing.

Both hold at once if the selector is a **structural test this script performs
itself**: an APK is a ZIP whose central directory contains
`AndroidManifest.xml`. That is positive identification of the container
format rather than a heuristic, and it is computed Dom0-side from the file's
own bytes — the same discipline that already keeps the guest destination
independent of the submitted filename.

`detected_type` then keeps the role DRAFT-014 scopes for it — an advisory
admission check, mismatch → `unsupported_type` — and DRAFT-017 refines the
identification without becoming a dependency of the execution path.

Still open, and belonging to CREATE rather than to this decision: **what the
launch step targets.** `pm install` does not tell you which activity to
start, and an APK need not declare a launcher activity at all. `monkey -p
<pkg> 1` is the usual fallback; resolving the component from the manifest
Dom0-side is the alternative. Settle it against a real APK, not on paper.

What this issue must **not** do is invent a `SAMPLE_EXEC_MODE` knob in
`pipeline-android.env`. The execution method is a property of the sample,
not of the pipeline, and putting it in a per-OS config file makes it an
operator setting that is wrong for half the queue.

## 4. What the trace actually sees on Android — and the one thing it does not

Established 2026-08-14 while settling whether this issue needs a collection
stage. It does not, and this section records why, because the reasoning is
what a future reader will want before proposing one again.

### The four plugins this pipeline uses do work on Linux

Upstream `tklengyel/drakvuf`'s `drakvuf_plugin_os_support[]` marks
`FILEEXTRACTOR` and `MEMDUMP` as `[VMI_OS_LINUX] = 0`. **That table is not
this project's build.** `docs/architecture/upstream-drakvuf.md:49-53` records
that the lab builds the `lfreijo/drakvuf` `memdump` fork, and names the
commit whose entire purpose is flipping them: `8dc7788`, *"Add Linux support
for memdump, filetracer, fileextractor, and syscalls plugins."* The deployed
build, `v1.1-git20260511151619+52df0bc8-1`, descends from it.

Evidenced at runtime on Linux, not just claimed —
`docs/runbooks/verify-user-placeholder.md`:

```text
:364  {"Plugin":"fileextractor",…,"Reason":"WriteFile","DumpFile":"…/00000000_unknown_fd_7"}
:373  {"Plugin":"memdump",…,"Method":"do_syscall_64","Syscall":"clone","DumpReason":"Thread creation with shared memory"}
```

`do_syscall_64` is a Linux symbol. Both produced output.

> **That evidence is Ubuntu's, not Android's.** The Android plugin matrix at
> `docs/checklists/android.md:279-283` ticks all four as "Starts / Produces
> events / Guest stable" with an **empty evidence block**, under a command
> labelled "Candidate minimal monitoring run; validate supported options
> first". Per `CLAUDE.md` those ticks are not proof. Re-confirm the four
> against BlissOS during this issue's first trace and fill that block in.

### Coverage for an APK

| Behaviour | Covered by |
|---|---|
| File operations, and the contents of dropped files | `filetracer` + `fileextractor` |
| Process and thread lifecycle, `execve` | `syscalls`, `procmon` |
| Unpacked / decrypted DEX in memory | `memdump`, **partially** — its triggers are syscall-based, so work done purely between syscalls need not land in a dump |
| Network | **the pcap, not DRAKVUF.** `SOCKETMON` is Linux=0 upstream and the fork commit does not mention it. TLS payloads stay opaque — DRAFT-023 already recorded `tlsmon` as N/A here |

### The gap: Binder is recorded and illegible

Android's framework is IPC. `startActivity()`, `getDeviceId()`,
`sendTextMessage()`, a permission request — each reaches the kernel as one
`ioctl(/dev/binder, BINDER_WRITE_READ, …)` carrying an opaque serialized
Parcel. `syscalls` records that the ioctl happened and nothing about what was
asked. Recovering the framework call needs the interface descriptor, the
transaction code and the AIDL layout — a decoder this project does not have.

This matters more on Android than on any other target, because a large class
of Android malware never touches a file or a socket directly: an SMS stealer
Binders to `SmsManager` and is otherwise almost inert at the syscall layer.

**The events are all in the trace. They are unreadable.** That is the honest
limitation of Android analysis under this design, and it is not fixed by
collecting anything off the guest — `logcat` would have shown some of those
events as *framework log lines*, which is why `analysis-pipeline.md`'s
decision 4 named it as the accepted cost — but log scraping recovers a
rendering of the events rather than the events.

Closing it properly means a Binder/Parcel decoder at the engine level.
`upstream-drakvuf.md`'s CONF-11 correction (2026-08-11) records that
modifying DRAKVUF itself is now near-term intended work, so that is a
coherent future draft. **It is not this issue**, and this issue should not
pre-empt it with a partial substitute.

### Two Linux-capable plugins this project has never used

Both are `[VMI_OS_LINUX] = 1` even upstream, so neither depends on the fork:

- **`hidsim`** — human input simulation. §2.8's `50-stimulate` stage has no
  mechanism behind it today; this is one. Relevant to APKs specifically,
  since an installed app that is never interacted with may do nothing.
- **`unixsocketmon`** — Android leans heavily on unix domain sockets
  (`zygote`, `logd`, `netd`, `installd`), so this sees a slice of framework
  activity that Binder decoding would otherwise be needed for.

Neither is adopted here. Recorded so the next person does not re-derive the
plugin table from scratch.

# Context — the two files this is written against

`automation/preconfig-ubuntu.sh` (`:139-214`) and
`automation/drakvuf-ubuntu.sh` (`:126-166`). Per `CLAUDE.md`, these are the
reference for *shape*, not files to copy — they carry known defects, and
three of them land directly in the copies:

| Defect | Site | Owner | Effect here |
|---|---|---|---|
| SHA-256 as the guest leaf name | `preconfig-ubuntu.sh:161-163`, `drakvuf-ubuntu.sh:150-151` | DRAFT-030 | C5 requires `<GUEST_STAGING_DIR>/<guest_filename>`. Ubuntu's SHA-256 is a **recorded deviation, not the model** — do not copy it forward. |
| `ps aux \| grep "tcpdump -i xenbr1.$VLAN"` | `drakvuf-ubuntu.sh:162` | DRAFT-011 (DRAKVUF-04) | Unanchored, and `.` is a regex wildcard: VLAN 1 also matches `xenbr1.10`–`19`. Above 9 clones one sample's script kills another's capture. |
| Unquoted expansions in the `drakvuf` line | `drakvuf-ubuntu.sh:154` | DRAFT-030 restores SC2086 | `.shellcheckrc` disables SC2086 repository-wide, so nothing catches this in a new file either. Quote everything regardless. |
| Licence header above the shebang | fixed | DRAFT-031 | Already fixed; the new files inherit `#!/bin/sh` on line 1. |
| `RET -eq 1` as the "move the sample" condition | `drakvuf-ubuntu.sh:158` | — | §2.8 requires explicit final statuses instead of reading one DRAKVUF return code as success. |

# Scope corrections to §2.7 and §2.8

These checklist items are stale and must not be implemented as written. Each
is annotated in place as part of CREATE.

- **§2.7 "Create a per-analysis guest directory"** — already struck
  2026-08-10 (issue #6). Staging is flat into `/data/local/tmp`.
- **§2.7 "Candidate guest preparation command"** (`:1462`) — superseded with
  it. There is no `mkdir` injection; delivery is one `writefile` (C6).
- **§2.7 "Configure Android networking only when network simulation is
  enabled"** — there is no such switch today, and `offline` mode is a
  design property (`networking.md`), not an implemented flag. Either wire it
  to a real value or drop the conditional; do not ship a branch on a
  variable nothing sets.
- **§2.8 stage list** — was written assuming in-guest collection, which issue
  #6 withdrew (C7). Reconciled stage by stage rather than struck wholesale:

  | Stage | Disposition |
  |---|---|
  | `30-install-or-prepare` | **In scope**, per section 3 above — this is `pm install` for the APK path |
  | `50-stimulate` | **In scope as a question, not a candidate.** The stage had no mechanism behind it; `hidsim` is one and is Linux-capable. Adopt or reject with a reason; do not leave it an empty stage |
  | `60-observe` | Merged into the trace window. There is no separate observation step — DRAKVUF is already running |
  | `70-collect` | **Dropped 2026-08-14.** C7 stands unamended: nothing is read back off the guest, live or offline |

- **`70-collect`'s removal is a decision, not an omission**, and the
  reasoning belongs with it so it is not re-proposed. `fileextractor` works
  on Linux in this build (section 4), so the strongest case for pulling
  artifacts — recovering files the sample dropped — is already served by the
  trace. What is left uncovered is framework state, and that is the Binder
  gap, which `packages.xml`, `logcat` or a snapshot mount patch cosmetically
  without touching. Two alternatives were considered and rejected on
  2026-08-14: a post-trace `logcat -d` pull through `injector`, and an
  offline read of the destroyed clone's LVM snapshot. The second is the
  cleaner of the two — it satisfies *both* halves of C7, since the domain is
  dead and the read happens on Dom0 — and it is recorded here rather than
  lost, because it is the right shape if this is ever revisited. Its cost is
  what ruled it out: `logcat` needs `persist.logd.logpersistd`, which is a
  golden rebuild and a moved anchor PID, and parsing a filesystem last
  written by malware running as root puts attacker-controlled metadata in
  front of a parser — `mount` would put it in front of the **Dom0 kernel**.
  Neither cost buys anything the trace does not already have.
- **§2.8 candidate `drakvuf` command** — carries `-m execproc -e
  /system/bin/sh` with no `-f` arguments, which starts a shell that does
  nothing. It also omits `syscalls` and `memdump`. Use Ubuntu's four
  (`syscalls`, `filetracer`, `fileextractor`, `memdump`), which section 4
  establishes are Linux-capable in this build — but **re-confirm them
  against BlissOS** and fill in §0's plugin matrix, whose ticks are
  currently unevidenced.

# Dependencies

- **DRAFT-015 — hard, and not merely ordering.** It creates
  `pipeline-android.env` and `run_analysis-android.sh`, and renames the clone
  script to a shared `automation/clone.pl` (decided 2026-08-15; there is no
  `clone-android.pl`). `pipeline-android.env` was assigned there by
  `DRAFT-037.md:138,202`). `preconfig-android.sh` sources that env file the
  way `preconfig-ubuntu.sh:137` sources its own, and reads
  `GUEST_STAGING_DIR` from it. There is also nothing to test against without
  a clone script — DRAFT-013's manual snapshot-and-restore is a one-off, not
  a pipeline.
- **DRAFT-030 — hard.** Owns the guest-filename normalizer (C5) and restores
  SC2086. `analysis-pipeline.md:520`: writing this script first means
  writing it against SHA-256 staging and rewriting it immediately.
- **DRAFT-033 — hard, transitively.** It fixes `clone-ubuntu.pl` before
  DRAFT-015 copies it. If DRAFT-015 lands first this issue tests against a
  clone script that checks no exit status.
- **DRAFT-011 — soft.** Owns the `ps | grep` PID matching in shared
  `cleanup.sh`. If it has not landed, `drakvuf-android.sh` still must not
  reproduce `drakvuf-ubuntu.sh:162`; use the recorded PID (§2.8 already
  requires this).
- **DRAFT-017 — not a dependency, but see section 3 above.**
- **DRAFT-036 — not a blocker for writing or testing this**, but Android and
  Ubuntu watchers cannot run *concurrently* until it lands: the thread-slot
  index is the VLAN and the slot array is process-local.

# Out of scope

- `pipeline-android.env`, `run_analysis-android.sh`, and the `clone.pl`
  rename — DRAFT-015.
- Sample classification and `detected_type` — DRAFT-017.
- Emitting the job/result state model — DRAFT-011 owns the schema; this
  issue records stage results in logs, and does not invent a second format.
- **Dropping outbound 853 in `network-setup.sh`.** The Dom0-side alternative
  to `private_dns_mode off` affects all three OS families and is its own
  issue (`verify-android-isolation.md:1086`). Use the guest-side setting.
- Any change to a shared file (C2). Needing one is a separate issue.
- **Any collection off the guest.** `logcat`/`dumpsys`/`dmesg` stay withdrawn
  (issue #6), and the two 2026-08-14 alternatives — a post-trace `logcat -d`
  pull, and an offline read of the destroyed clone's snapshot — are both
  rejected here. See the `70-collect` entry above for the reasoning.
- **A Binder/Parcel decoder.** It is the right fix for the real gap
  (section 4) and it is engine work, not pipeline work.
- Ubuntu behaviour. Nothing in `automation/*ubuntu*` is edited here.

# PLAN

1. **Prove `injector` works against an Android guest at all** — one
   `writefile` of a benign file into `/data/local/tmp`, pulled back with
   `readfile` and compared by hash. This is the issue's gate; if it fails,
   stop and characterise it.
2. Prove the single-argv `execproc` form: `/system/bin/sh -c '<the whole
   thing>'`, delivered by `injector`, producing the same result the console
   produced in DRAFT-013.
3. **Confirm the four plugins against BlissOS** — `syscalls`, `filetracer`,
   `fileextractor`, `memdump` — and fill in §0's plugin matrix, which is
   ticked today with an empty evidence block.
4. Write `preconfig-android.sh` against C1–C10, from `preconfig-ubuntu.sh`'s
   shape and §1.6's procedure.
5. Write `drakvuf-android.sh` with both execution paths and the structural
   APK test that selects between them.
6. Decide `50-stimulate`: adopt `hidsim`, or reject it with a reason.
7. Static checks; then one benign sample of **each** type — an APK and a
   native ELF — end to end through `dirwatch`.
8. Annotate §2.7/§2.8's stale items in the checklist, in this change.

# CREATE

1. `automation/preconfig-android.sh` — new. `#!/bin/sh` on line 1, licence
   header below it, `$0`-derived `SCRIPT_DIR`, sources
   `pipeline-android.env`, reads the first 7 of 8 arguments (C9).
2. `automation/drakvuf-android.sh` — new. Same conventions.
3. `docs/checklists/android.md` — annotate the stale §2.7/§2.8 items listed
   above, and fill their "Evidence and notes" blocks from the test run.
4. `docs/architecture/analysis-pipeline.md` — record Android's C1–C10
   conformance, and the Android row of the staging table as exercised rather
   than decided.
5. `docs/runbooks/` — a new dated transcript for the Dom0 work.

# TEST

Nothing here runs in the development container. All Dom0 work is presented
for manual execution.

Local static checks — all four, on both new files:

```bash
bash -n automation/preconfig-android.sh
dash -n automation/preconfig-android.sh
shellcheck automation/preconfig-android.sh
bash -n automation/drakvuf-android.sh
dash -n automation/drakvuf-android.sh
shellcheck automation/drakvuf-android.sh
```

`dash -n` is load-bearing, not duplicative: these execute under `dash`, and
`bash -n` alone accepts bash-only syntax that then fails silently (C8).

Dom0 — gate first, per PLAN step 2:

```bash
# The gate. Does injector work against this guest at all?
injector -r profiles/android.json -d "$CLONE" -i "$ANCHOR_PID" -m writefile \
    -B /tmp/benign-probe -e /data/local/tmp/benign-probe
injector -r profiles/android.json -d "$CLONE" -i "$ANCHOR_PID" -m readfile \
    -e /data/local/tmp/benign-probe -B /tmp/benign-probe.pulled
sha256sum /tmp/benign-probe /tmp/benign-probe.pulled   # must match
```

Then the single-argv form, checked from Dom0 rather than inferred from the
guest — the pcap is the evidence, as it was for DRAFT-013:

```bash
tcpdump -i xenbr1.1 -w /tmp/android-preconfig.pcap &
# ... run preconfig-android.sh with the real 8-argument list ...
# Expect: SUCCESS from the framework call, exit 0, and plaintext DNS on 53.
tcpdump -r /tmp/android-preconfig.pcap 'port 53 or port 853'
```

Port 853 appearing in that capture means `private_dns_mode off` did not take
effect, whatever the guest reports.

# DEPLOY

Repository change plus a Dom0 pull — `git -C /root/sandbox_project pull`,
never while an analysis is in flight, since `dirwatch` re-reads the worker
scripts per sample. No new host state. `run_analysis-android.sh` does not
exist yet, so nothing launches these automatically on merge; that is the
open ownership question below, not an oversight in DEPLOY.

# Acceptance criteria

- [ ] `injector -m writefile` and `-m readfile` are execution-evidenced
      against an Android guest, with matching hashes. **Gate.**
- [ ] The single-argv `execproc` form is execution-evidenced, and the exact
      working string is recorded verbatim.
- [ ] `preconfig-android.sh` stages a sample to
      `<GUEST_STAGING_DIR>/<guest_filename>` and `drakvuf-android.sh`
      derives the same path by the same rule from the same arguments (C5).
- [ ] Delivery is one injection, with no guest shell before it, and does not
      require guest networking (C6).
- [ ] `private_dns_mode off` is applied on every clone, and a pcap shows
      plaintext DNS on 53 with **no** traffic to 853.
- [ ] The resolver is proven from Dom0 — a query leaves for
      `$GUEST_NAMESERVER` and is answered.
- [ ] Neither script starts a guest process that outlives the sample, and
      neither reads analysis output back off the guest filesystem (C7) —
      **including offline, from the snapshot after the domain is destroyed.**
- [ ] The APK path is exercised: `pm install` lands, the app is launched, and
      the trace shows it running.
- [ ] The native-ELF path still works, and the structural APK test routes
      each sample to the right one.
- [ ] A sample that is neither ends `unsupported_type` without an execution
      attempt.
- [ ] The execution path is selected by the script's own structural test, not
      by `detected_type` — greppable, and the reason is C-checkable.
- [ ] `syscalls`, `filetracer`, `fileextractor` and `memdump` are each
      confirmed to produce events **on BlissOS**, and §0's plugin matrix is
      filled with that evidence rather than left ticked and empty.
- [ ] `50-stimulate` is either implemented with `hidsim` or rejected with a
      recorded reason. It does not ship as an empty stage.
- [ ] `bash -n`, `dash -n` and `shellcheck` are clean on both files (C8/C10).
- [ ] Neither file copies the SHA-256 leaf name, the `ps | grep` PID match,
      or the `RET -eq 1` success test.
- [ ] No shared file was copied, forked or special-cased (C2).
- [ ] One benign APK **and** one benign native ELF each complete end to end
      through `dirwatch`, and the clone is destroyed afterwards.
- [ ] The golden `android` LV and `state/android_sandbox.bak` are unchanged.
- [ ] §2.7/§2.8's superseded items are annotated in the same change.

# Evidence required

The `writefile`/`readfile` hash pair; the verbatim working `sh -c` argv; the
pcap filtered on 53 and 853; `preconfig.log` and `drakvuf.log` from both
end-to-end runs; `pm install`'s result and the launched package; per-plugin
event samples from the BlissOS trace, one line each, for §0's matrix; the
four static-check outputs; before/after checksums of the golden LV and saved
state.

> **`pm install`'s result is harder to capture than it looks**, and it is the
> known `injector` observability gap rather than a new problem. `execproc`
> reports `STATUS:SUCCESS` when it *starts* the process, not what the process
> returned (`issue-index.md`, "Considered and deliberately not taken",
> 2026-08-11) — so a failed install and a successful one look identical from
> Dom0. The maintainer declined the sentinel-file fix for Ubuntu; that
> decision is not reopened here. Read the install result from the trace
> instead: `filetracer` and `syscalls` show whether `/data/app/<pkg>/` was
> populated, which is the observable difference.

# Security considerations

- **A real sample runs in this issue.** Use a benign one. The end-to-end run
  is the first time an Android clone executes submitted content, and
  containment rests on DRAFT-028/029's rules plus the VLAN attachment.
- **The clone must attach to `xenbr1.<vlan>`, never `xenbr1`.** The isolation
  rules match `xenbr1.+`, which does not match the bare bridge — a guest on
  `xenbr1` is covered by no rule at all. `clone-ubuntu.pl:229` rewrites the
  vif correctly and `clone-android.pl` inherits that; any hand-built test
  domain must override `misc/android_sandbox.cfg`'s `bridge=xenbr1`.
- **An Android clone reaches the Internet at boot, before any sample runs** —
  connectivity probes, evidenced in DRAFT-013. That is existing accepted
  posture (DRAFT-022), noted so it is not misread as sample traffic in the
  pcap.
- **Every clone starts with the golden VM's LAN identity (`192.168.1.122`)**
  and ARPs for a residential gateway until the framework call lands
  (finding F4). Containment held, but the network configuration should run
  as early as possible and the ARP noise is expected in every Android pcap.
- Never restore onto the golden or template LV — always a snapshot.
- The submitted filename reaches no shell command string, guest or host.
  That property is why the guest destination is derived Dom0-side.
- **`pm install` runs attacker-supplied input through Android's package
  parser while the guest is live.** That is the intended behaviour under
  analysis and is contained by the clone, but it is a larger in-guest attack
  surface than `execve` of an ELF, and it is the reason the APK path is worth
  its own end-to-end run rather than being assumed from the native one.
- **Nothing in this issue parses the clone's filesystem on Dom0.** The
  rejected snapshot-extraction option would have; a filesystem last written
  by malware running as root is attacker-controlled metadata, and `mount`
  would hand it to the Dom0 kernel. Recorded here so a later change does not
  reintroduce it as a convenience.

# Documentation changes

Updated: `docs/checklists/android.md` (§2.7, §2.8 annotations and evidence
blocks, and §0's plugin matrix — currently ticked with no evidence),
`docs/architecture/analysis-pipeline.md` (C1–C10 conformance record, and
decision 4 annotated with the 2026-08-14 re-examination and why C7 stands),
`docs/architecture/upstream-drakvuf.md` (that the fork's Linux plugin support
is runtime-evidenced on Ubuntu, and whether it holds on BlissOS),
`CLAUDE.md` (the "Android equivalents … do not exist yet" note, once
two of them do). New: a dated runbook. `docs/android_setup.md` and the other
imported guides are not touched.

# Recovery / rollback

Repository-side, `git revert`. Dom0-side, the previous commit is one `git
pull` away and no host state changes, so rollback is the revert plus a pull.
A wedged clone is `xl destroy` then `lvremove`; the template and golden LVs
are never written by either script.

# ~~Open~~ Settled: `run_analysis-android.sh` goes to DRAFT-015

C1 required five files per OS pipeline. This issue owns
`preconfig-android.sh` and `drakvuf-android.sh`. **`run_analysis-android.sh`
(§2.4) was owned by no draft by title** — `DRAFT-025.md:186` refers to it
loosely as "DRAFT-015/016" and `DRAFT-009.md:29` only lists it. Until it
exists, the Android pipeline cannot be launched at all.

Proposed here on 2026-08-14 and **accepted in `DRAFT-015.md` on 2026-08-15**:
it goes to DRAFT-015 with `pipeline-android.env`, since the launcher and the
config file are one unit — and, as that draft adds, the launcher's export is
also how the clone script receives `VG_NAME` and `CLONE_LV_SIZE` under
decision 3, so splitting them would split a variable from its only delivery
mechanism. §2.4's remaining open item — resolving the injection anchor PID
without keying on a process-name grep — is deferred there rather than
implemented; see that draft's section 3.

> **Two of C1's five files are no longer what this section assumed.**
> DRAFT-015 established that the clone script has no per-OS content and
> renamed it to a shared `automation/clone.pl`, amending C1 to four per-OS
> files plus one shared. Android's four are `pipeline-android.env`,
> `run_analysis-android.sh` (both DRAFT-015) and the two this issue owns.
