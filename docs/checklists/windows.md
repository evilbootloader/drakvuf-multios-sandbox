# Windows DRAKVUF Automated Analysis — Implementation Checklist and Command Log

> **Status: current target. The golden VM exists; no automation does.**
> Windows is one of the project's three current OS targets alongside Ubuntu
> and Android — not a deferred planning exercise.
>
> **Operator-reported 2026-08-21, not yet backed by command output:**
> the golden `windows` domain is installed as a Xen HVM, Microsoft Defender is
> disabled, and the LV has been cloned to `windows_sandbox`. The boxes below
> stay unchecked until that is evidenced the way `android.md` evidences its own
> — a transcript, not a report.
>
> **Corrected 2026-09-04.** This block previously said `misc/windows_sandbox.cfg`
> did not exist and no PDB had been fetched. Both were overtaken by work on
> 2026-09-01 that landed without a checklist sweep:
>
> - `misc/windows_sandbox.cfg` **exists** (`f0b44a3`), and carries
>   `cpus = "16-27"` — see the note under Project status, because that file is
>   not covered by `scripts/gen-xen-configs.py`.
> - The **kernel GUID has been read**: `windows_symbols.md` at the repository
>   root records a real `vmi-win-guid domid 52` run, PDB GUID
>   `72c69e726c648bc18257af38fa78a2f21`, plus the exact `pdbconv.py` line that
>   would produce `profiles/windows.json`. Whether that conversion was ever
>   run is **not** evidenced — `profiles/` is untracked.
> - That output also reads **64-bit Windows 10**, not the Windows 11 the
>   baseline row below plans for.
> - The guest software build is largely done and is recorded in
>   `.github/issue-drafts/in-progress/DRAFT-020.md`, not here, because none of it is
>   backed by a transcript either.
>
> No Windows *automation* has been built, so the pipeline checklist is still
> empty; the difference from "skeleton only" is that the track is open and
> its design constraints are already fixed (see "Inherited contract" below).
>
> This file intentionally contains no invented commands, configs, or
> evidence — populate it only from real work, following the same discipline
> as `android.md` (Existing vs. Candidate, evidence before checking a box).
>
> **DRAFT-034 is the track head.** It supersedes DRAFT-020's design half;
> the VM-lifecycle question DRAFT-020 existed to answer is closed
> (clone-per-run, by elimination). Roadmap milestone M5 still names this a
> "planning spike" — that framing is what changed, and the roadmap now says
> so.

---

## Project status

| Field | Value |
|---|---|
| Golden domain | TBD |
| Sandbox domain | TBD |
| LibVMI profile | TBD |
| Volume group | TBD |
| Analysis bridge | TBD |
| Saved state | TBD |
| Windows baseline (version/build) | **Direction was Windows 11 first, Windows 10 as fallback** (2026-08-19). What is actually installed reads **64-bit Windows 10** (`windows_symbols.md`, 2026-09-01), so the fallback is what exists. Kernel PDB GUID `72c69e726c648bc18257af38fa78a2f21` |
| VM lifecycle model | clone-per-run (current Ubuntu/Android model) — decided by elimination: snapshot-restore (DRAKVUF Sandbox's model) does not work in the nested Xen-inside-Proxmox setup this project used until 2026-08-28, since `xl save`/`xl restore` leaves the base and cloned disk images read-only. **Not re-tested on bare metal**; the decision stands on its own merits regardless — see roadmap "Architecture decisions needing experiments" |
| Current phase | Phase 0 — golden VM installed 2026-08-21, `windows_sandbox.cfg` written 2026-09-01, kernel GUID read 2026-09-01, guest software largely installed (DRAFT-020). **No automation exists and no analysis has run** |
| Current blocker | Whether `profiles/windows.json` was generated is unevidenced — the GUID and the `pdbconv.py` line exist, the output is untracked. Then the pipeline itself: no `preconfig-`, `drakvuf-` or `run_analysis-windows` script, and no `pipeline-windows.env` |

### Concurrency constraint — read before running a Windows analysis

**A Windows watcher must not share Dom0 with a running Ubuntu or Android
watcher.** Two constraints stack, and the second is the dangerous one:

1. `dirwatch` derives each clone's VLAN from a process-local worker-slot
   index, so two watchers collide on VLANs, gateway addresses and isolation
   rules. Both existing launchers refuse to start if another is running; a
   Windows launcher must carry the same guard.
2. Even without the collision, admission is greedy, and greedy admission
   starves the largest clone. A Windows clone costs **6294 MiB** (`memory =
   6144` plus the per-host domain overhead) against Ubuntu's and Android's
   **4246 MiB** (2198 when this was measured; the templates went to
   `memory = 4096` on 2026-08-29 — `CURRENT-STATE.md` §2b). Measured on Dom0
   2026-08-20: 170 consecutive admission holds, zero clones for the large job,
   seven smaller jobs completing meanwhile. **The gap narrowed and the
   starvation did not go away** — a 6294 MiB job still waits behind two 4246s
   on a 20317 MiB pool.

**The failure mode is not an error.** It is one admission-hold line per
second, forever, with no clone and nothing in the logs to explain it. Every
individual decision is correct.

Fixed by DRAFT-041's head-of-line reservation, not before. Until then, run
Windows alone.

### Inherited contract (issue #6, 2026-08-10)

The Windows pipeline is not designed from scratch. It must satisfy the
conformance checklist **C1–C10** in
`docs/architecture/analysis-pipeline.md`, "Shared and per-OS code
boundary" — five files and no more, no forked copy of any shared script,
and a `pipeline-windows.env` that defines the per-OS values without
redefining the host-global ones.

Four consequences worth knowing before Phase 0 starts, because each closes
off a design option that would otherwise look open:

- **Delivery is decided.** `injector -m writefile`, `-B` Dom0 source, `-e`
  guest destination, one injection, no guest shell beforehand. There is no
  HTTP path to choose and no fallback to build.
- **The staging directory must already exist in the saved image**, and must
  permit the execution method Windows uses. Both need testing on the guest,
  not reading off a path — the Android evidence
  (`docs/checklists/android.md`, "Staging directory") is the worked example
  of a path that satisfies one and silently fails the other.
- **No in-guest collection.** No Windows equivalent of `logcat`/`dmesg` may
  be introduced; output comes from introspection and the pcap.
- **`drakvuf -e` being execve-direct is a `[LINUX]` finding — do not
  inherit it.** Issue #2 established that `-e` invokes no guest shell, so a
  filename cannot dereference guest-side. `injector --help` qualifies that
  as `[LINUX] (execproc -> execve(...); 64bit only)`. Windows execution has
  not been read, and the single-argv rule in
  `docs/architecture/analysis-pipeline.md` is a security property rather
  than a convenience, so it must be re-established against the Windows
  injection method before anything relies on it.
- **`CLONE_LV_SIZE` is per-OS** and Windows is the reason it exists as a
  variable: `-L64G` is hard-coded today and a Windows golden LV is unlikely
  to want it.

`tlsmon` remains the one item where Windows *gains* capability the other
targets lack — it hooks `ncrypt.dll`/Schannel and has no Linux hook path,
making it the project's only working TLS-visibility route (DRAFT-023).

### Status legend

- [ ] Not started
- [x] Completed and evidenced
- `BLOCKED:` Waiting on a dependency or unresolved fault
- `SKIPPED:` Deliberately excluded, with reason recorded

---

# Phase 0 — Planning spike (M5)

- [ ] Select a specific supported Windows baseline (version/build).
  **Direction set 2026-08-19: try Windows 11 first, Windows 10 as the
  fallback.** The exact build still has to be recorded, because §0.1's
  profile step is keyed to one kernel GUID. See §0.2 for the install
  constraints to expect.
- [x] Decide golden-VM lifecycle model — **clone-per-run, decided by
  elimination** (roadmap "Architecture decisions needing experiments" #3;
  the status table above records the same). Snapshot-restore was not viable
  in the nested Xen-inside-Proxmox setup used until 2026-08-28, so there was
  never a Windows-specific choice to make. What remains is confirming clone-per-run
  works against a Windows guest specifically — DRAFT-034, not this item.
- [ ] Determine profile/symbol requirements for the selected baseline.
  **Procedure recorded in §0.1 (Candidate).** It is volatility3's
  `pdbconv.py` keyed on the kernel PDB GUID — not `dwarf2json`, which was
  the open unknown DRAFT-034 raised. What remains for this item is running
  it against the chosen build and settling §0.1's `-r` vs `libvmi.conf`
  question.
- [ ] Determine injector target and plugin compatibility for Windows guests.
- [ ] Scope the first Windows sample type (PE executable, per the roadmap's
  "do not support every sample type in the first milestone" guidance).

---

## §0.1 — Profile toolchain

**Status: Candidate. Nothing below has been run on this project's Dom0.**
Recorded 2026-08-19 from upstream DRAKVUF documentation, which discharges
DRAFT-034 PLAN step 2's requirement to establish this *from primary
sources rather than by analogy* — the answer was genuinely not derivable
from what this repository already does.

**It is neither `dwarf2json` nor `drakpdb`.** Ubuntu and Android profiles
come from `dwarf2json` against kernel DWARF, which has no Windows
equivalent. The Windows path is **volatility3's `pdbconv.py`**, driven by
the kernel's PDB GUID.

Step 1 — get the GUID and kernel filename from the running domain:

```bash
sudo vmi-win-guid name <domain>
# The two fields that matter:
#   PDB GUID:        684da42a30cc450f81c535b4d18944b12
#   Kernel filename: ntkrpamp.pdb
```

Fallback, if `vmi-win-guid` cannot find the kernel in memory — read it off
the disk instead:

```bash
sudo su
kpartx -a /dev/<vg>/<windows lv>
mount -o ro /dev/mapper/<vg>-<lv>p1 /mnt
python3 tools/pdbguid.py /mnt/Windows/System32/ntoskrnl.exe
umount /mnt
kpartx -d /dev/<vg>/<windows lv>
```

Step 2 — generate the profile:

```bash
python3 ~/drakvuf/volatility3/volatility/framework/symbols/windows/pdbconv.py \
    --guid <PDB GUID> -p <kernel filename> -o windows.json
```

Step 3 — **open question, do not copy the upstream step blindly.** Upstream
then registers the profile in `/etc/libvmi.conf`:

```bash
printf "windows11 {\n\tvolatility_ist = \"/root/windows.json\";\n}" >> /etc/libvmi.conf
```

That conflicts with how this project resolves profiles. Clone domains have
no `/etc/libvmi.conf` stanza — the `-r <path>` argument is the only way a
profile is ever resolved here, which is why `pipeline-<os>.env` carries
`KERNEL_PROFILE` and `dirwatch` passes it through to `drakvuf`/`injector`
(`CLAUDE.md`, "Current implementation"). Following this project's
convention means placing the output at `profiles/windows.json` and passing
it with `-r`, exactly as Ubuntu and Android do.

**To settle on Dom0:** does `-r <profile.json>` work for a Windows guest,
or does the Windows path require the `volatility_ist` stanza specifically?
If the latter, that is a genuine per-OS divergence and C1–C10 needs an
amendment rather than a workaround.

Also unresolved, and it is PLAN step 4's: the example above is 32-bit
(`ntkrpamp.pdb`, "Multi-processor with PAE"). A 64-bit guest has a
different kernel filename, and `injector --help` labels the Linux
`execproc` path `[LINUX] (execproc -> execve(...); 64bit only)`. Windows
injection semantics are still unread.

## §0.2 — Windows 11 install constraints on Xen

**Status: Candidate, from Qubes OS's Windows-HVM documentation**
(`doc.qubes-os.org`, read 2026-08-19). Qubes runs Windows HVMs on Xen, so
this transfers; it has **not** been reproduced here.

- **Windows 11 is installable as a Xen HVM.** So is 10. Both x64.
- **HVM only — PVH will not work.** Xen's current PVH limitations prevent
  it. The four tracked `misc/*.cfg` are already `builder = "hvm"`.
- **Xen does not support TPM 2.0**, so Windows 11's check must be
  bypassed during setup: `Shift-F10` → `regedit` →
  `HKEY_LOCAL_MACHINE\SYSTEM\Setup` → create key `LabConfig` → add DWORDs
  `BypassTPMCheck`, `BypassSecureBootCheck`, `BypassRAMCheck`, each `1`.
  This is the single most likely thing to waste an install attempt.
- **Memory: 4096 MiB minimum, 6144–8192 recommended** — below that the
  installer crashes. This bears directly on admission: at `memory = 6144`
  a clone costs **6294 MiB** (`+ DOMAIN_OVERHEAD_MIB`), so a 28 GiB host
  with `dom0_mem=8192M` affords three concurrent Windows clones; at 8192
  it affords two. Pick deliberately.
- **Disk: 60 GB minimum.** `CLONE_LV_SIZE` is per-OS precisely for this —
  Android is `32G`, Ubuntu `64G`, and Windows must be at least `60G`.
- **The VM halts after extracting installer files.** Expected, not a
  fault. Cloning the LV *before* the restart is worth doing — it saves
  repeating the bypass above if the install is botched later.
- **Windows 11 24H2 and later may require internet access during setup**,
  even for Pro, and the Microsoft-account bypasses are progressively
  blocked. Relevant here because the golden image build is the one phase
  that legitimately needs egress; clones must not inherit it.

---

No further phases are defined yet — later phases should mirror `android.md`'s
structure (sandbox VM build, automation scripts, sample-type branches,
artifact collection, network containment, testing, reliability) once Phase 0
decisions are made, not before.