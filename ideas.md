- Read logd buffer through libvmi - DRAFT-016 and DRAFT-017
- Make vms more user computer like (anti-evasion)
- DOM0 isolation if malware escapes
- CAPA exclude also PID=0 for windows, find equivalentp for linux and android
- ~~Networking through TOR~~ and ~~the VPN provider table~~ — **both decided,
  2026-08-31. Moved to `private/egress-exits.md`** (untracked; this repo is
  going public). Tor is adopted as a selectable mode, with its TCP-only and
  blocked-port limits shown on the report rather than argued about. The
  provider table was deleted rather than corrected: two of its rows were
  wrong in the direction that costs money. Specter is not a research VPN at
  all, and Tor rejects the same ports Mullvad blocks — 25, 135-139, 445 — so
  it was never the free way around them. Letters to candidate hosts went out
  the same day; replies land in `private/outreach/`.

- Keyboard selection

- **`perf` DRAKVUF to find where the per-event cost actually is.** 2026-08-28:
  `--disable-sysret` gave 2.06x (415 -> 856 syscalls/s) and appeared to take Dom0
  off saturation entirely, while four levers that do NOT remove events moved
  nothing (CPU placement, `-F`, compiler hardening — all within 0.6%). Suspicion
  is `drakvuf_check_return_context` and the return-trap machinery around
  `linux_ret_cb` in `src/plugins/syscalls/linux.cpp`: if each syscall entry
  installs a breakpoint at the return address and the return callback frees it,
  disabling sysret removes ~50k altp2m/EPT operations per run rather than 43k
  output events. `perf record` on the drakvuf process settles it. Full series in
  `baremetal-trial.md` Part H.

- **DRAKVUF as a git submodule**, for when we start patching the engine. Point it
  at our OWN fork, not `lfreijo/drakvuf` — we need somewhere to push, and a
  submodule depending on a third party's branch is the fragility that nearly lost
  `52df0bc8` during the bare-metal migration. Note DRAKVUF's own submodules
  include the full **xen** tree (>1 GB), so decide non-recursive-for-reference vs
  recursive-for-building before adding it; this repo is deliberately lean.

- **Syscall filter file (DRAFT-052) — the real throughput lever.** Strictly
  better than `--disable-sysret`: removes syscall *entries* too (the remaining
  ~50k/run) while keeping return values for the calls actually analysed. Blocked
  on a curated list of what detection needs.

- **Measure `-F` on LATENCY, not throughput.** It is measurably flat on
  throughput and the operator consistently reports the guest more responsive with
  it. §F7a and §F7c only ever measured throughput. `vmi.c:2100` shows `-F` swaps
  a singlestep round trip for an altp2m view switch, which is a latency
  optimisation by construction.

- make a jenkins on a laptop with xen and the full stack installed for testing drakvuf

- In windows I've installed Chrome, disabled defender, installed office and set automatic run of macros in word and excel. I've also downloaded .NET Framework binaries (3.5 and 4.8) and .net runtime 8.0 (x64 and x86). Also python3 and 7zip