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

- ~~**DRAKVUF as a git submodule**~~ — **done, 2026-09-26.** Added at `drakvuf/`
  from our OWN fork `evilbootloader/drakvuf`, as this note required, pinned at
  `86a17d0`. Both open questions are now decided: **recursive**, so the tree can
  build rather than only be read.

  Two things this note got wrong, kept here because the estimate is why the idea
  sat unexecuted:

  - **The cost is ~265 MB, not ">1 GB"** — 210 MB of object store (170 MB of it
    xen) plus 55 MB of working trees. DRAKVUF pins xen at `RELEASE-4.20.1`, not
    master, which is the whole difference.
  - **The fork already contains what we feared losing.** Both `da982ab` and
    `52df0bc8` are ancestors of its `main`, so depending on one fork drops
    `lfreijo/drakvuf` without stranding either commit.

  It does **not** reproduce the deployed binaries — `main` is ahead of the source
  `CURRENT-STATE.md` §1.2 credits for them, and Dom0's separate `~/drakvuf` is
  still what built what is running. Repointing the Dom0 build at the submodule is
  its own change, with a runbook.

- **Syscall filter file (DRAFT-052) — the real throughput lever.** Strictly
  better than `--disable-sysret`: removes syscall *entries* too (the remaining
  ~50k/run) while keeping return values for the calls actually analysed. Blocked
  on a curated list of what detection needs.

- **Measure `-F` on LATENCY, not throughput.** It is measurably flat on
  throughput and the operator consistently reports the guest more responsive with
  it. §F7a and §F7c only ever measured throughput. `vmi.c:2100` shows `-F` swaps
  a singlestep round trip for an altp2m view switch, which is a latency
  optimisation by construction.

- **libmon on bionic — the blocker is known and so is the way round it.**
  Measured 2026-09-26: BlissOS's bootstrap linker exports 27 dynamic symbols
  and `_r_debug` is not one, so libmon v1's `try_arm` can never succeed on
  Android (`dl_rendezvous.cpp:268` resolves that symbol at the linker's base).
  Not a struct-layout problem — bionic's `r_debug`/`link_map` match the shape
  `dl_rendezvous_abi.hpp` hardcodes.

  **`rtld_db_dlactivity` IS exported**, which is bionic's `_dl_debug_state`
  and exactly what glibc hides. The two libcs export opposite halves of the
  rendezvous protocol, so the port is not a rewrite:

  - breakpoint `rtld_db_dlactivity` by name instead of reading `r_brk`
  - get `link_map` from `DT_DEBUG` in the main executable's `PT_DYNAMIC` —
    already named as v2 in `dl_rendezvous_abi.hpp`, and more portable than
    either named export

  The v2 `DT_DEBUG` work alone may cover both libcs and make the symbol
  question moot. Worth doing before hand-writing a bionic hook list; the
  Android half of the analysis pipeline currently sees no library calls at
  all.

  **Do not go looking for a ROM that fixes this.** bionic's
  `linker/linker.generic.map` is an explicit allowlist -- 25 `global:` names,
  all `__loader_*` plus `rtld_db_dlactivity`, then `local: *;` -- and
  `_r_debug` is absent from it in AOSP main too, so BlissOS 18 and anything
  later behave exactly as 14 does. Nor is there a glibc Android: no version
  has ever shipped one. The fix is in libmon, not in the guest.

- ~~**read capa-rules and get all the APIs used by the detector**~~ — **done,
  2026-09-27**, as `scripts/gen-hook-lists.py`. Both hook lists are now derived
  from capa's 1,584 `api:` features: `hooks.txt` 302 → ~1,340 lines,
  `so-hooks-linux.txt` 46 → 117. Nothing is invented — Windows DLL names and
  argument lists come from Microsoft's `win32metadata`, the `Nt*`/`Zw*`/`Rtl*`
  native API from `phnt`, and every Linux name is checked against a real glibc
  `.dynsym`.

  **Two follow-ups it exposed:**

  - **51 inherited `hooks.txt` lines look dead on this guest.** They name
    kernel32 for functions that live in kernelbase on Win11 23H2 —
    `CreateProcessInternalW`, `CreateRemoteThread`, `DeviceIoControl`,
    `GetTickCount`. `gen-hook-lists.py --report` lists them. The generated block
    covers the same functions at the right DLL, so nothing is lost, but the dead
    lines should go once a Dom0 run confirms the reading.
  - **capa's 395 .NET features are still unreachable**, and not for the reason
    it looks. They are managed calls, so no export hook sees them; capa gets
    them from its *static* `BACKEND_DOTNET` pass over dumped assemblies, which
    `memdump`'s `AssemblyNative::LoadImage` hook exists to feed. That pass is
    gated behind `analyze_memdumps`, which is **`False` while three places in
    the tree claim it is on** (`plugin_base.py:18`, and `docs/DEVELOPING.md`
    until today). Reconciling that — and deciding whether unsandboxed vivisect
    as root is acceptable — is what unlocks the .NET half of capa.

- **50 Win32 names capa wants are still unhooked.** What is left after
  win32metadata and phnt: .NET hosting (`CLRCreateInstance`,
  `CorBindToRuntime*` → mscoree), a few undocumented internals, callback
  typedefs that are not functions at all, and two capa-rules typos worth
  reporting upstream — `CryptAquireContext` (missing `q`) and the module
  `ntoskrn`.

- make a jenkins on a laptop with xen and the full stack installed for testing drakvuf

- In windows I've installed Chrome, disabled defender, installed office and set automatic run of macros in word and excel. I've also downloaded .NET Framework binaries (3.5 and 4.8) and .net runtime 8.0 (x64 and x86). Also python3 and 7zip