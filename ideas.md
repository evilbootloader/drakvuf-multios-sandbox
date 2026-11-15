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

- **Gaps left in CAPE's network and crypto sections (2026-11-11).** Costed
  while extending `encryptedbuffers` and `network_map` to both systems; the
  AcceptEx peer (`GetAcceptExSockaddrs`, printers' `ppsockaddr`) was the one
  cheap enough to do at once. Estimates, not measurements; each DRAKVUF part
  also needs a Dom0 run.

  - **The cipher and key behind an OpenSSL `EVP_*` call** -- about half a
    day, negligible runtime. A printer for `EVP_EncryptInit_ex`,
    `EVP_DecryptInit_ex` and `EVP_CipherInit_ex`'s `EVP_CIPHER` that reads
    its first fields (`nid`, `block_size`, `key_len`, `iv_len`) and returns
    `key_len` as its `value()`, so the key prints as `buffer[Cipher]`.
    cape_plugin then maps context -> cipher and key, as it does for Windows
    key handles (`EncryptedBuffers._note_key`). Init runs once per
    context. Risk: that is OpenSSL's internal `evp_cipher_st`, believed the
    same from 1.1 to 3.x; check it against the guest's libcrypto. A
    statically linked OpenSSL is not seen, as with every libmon hook.

  - **`EVP_CipherUpdate`** -- a few hours of code; the cost is runtime.
    Direction from `EVP_CipherInit_ex`'s `enc`, then the input printed at
    the call and the output at the return (it often works in place).
    OpenSSL 3's own TLS record layer goes through it, and libmon hooks every
    process that loads libcrypto: each TLS record of every such process
    would print twice, duplicating `SSL_write`/`SSL_read`. Order of
    magnitude: a 100 MB HTTPS download adds ~6,400 breakpoint pairs and
    ~100 MB to trace.log. Only worth it with a libmon option to skip calls
    made from inside libssl (about half a day more of C++); the breakpoints
    still fire, only the printing stops.

  - **Windows receive data that arrives asynchronously** -- 1-2 days, and a
    real runtime cost. An overlapped `WSARecv` returns pending and apimon
    reads an empty buffer at its return; Go's net package and .NET's async
    sockets work this way, so their received data is missed. Fix: state in
    apimon remembering each overlapped receive's `lpOverlapped` -> WSABUF,
    read when the program collects it through
    `GetQueuedCompletionStatus(Ex)`, `GetOverlappedResult(Ex)` or
    `WSAGetOverlappedResult`; locking for parallel events, eviction for what
    is never collected. APC completion routines would still be missed. Go
    and .NET poll `GetQueuedCompletionStatusEx` constantly: two breakpoints
    per call, possibly thousands a second for a busy Go program, which is a
    slowdown and a timing signal for an evasive sample. The kernel routes
    are worse: `IofCompleteRequest` fires for every I/O request on the
    system, and afd.sys internals mean reverse engineering per build.

  - **tcpip.sys `TcpCreateAndAcceptTcbComplete`** (the kernel's accept) --
    1-2 days of reverse engineering on Dom0. The public symbols carry no
    types, so the structure offsets would be found by hand for each Windows
    build and redone after updates. Not recommended now that
    `GetAcceptExSockaddrs` gives AcceptEx's peer.

- In windows I've installed Chrome, disabled defender, installed office and set automatic run of macros in word and excel. I've also downloaded .NET Framework binaries (3.5 and 4.8) and .net runtime 8.0 (x64 and x86). Also python3 and 7zip

- **Gaps left in syscall-origin detection (2026-11-12).** What
  `cape_plugin/syscall_origin.py`, the syscalls plugin's `get_origin`
  (`win.cpp`, `linux.cpp`) and the community's `all/evasive_syscalls.py` do not
  cover yet. Estimates, not measurements. **Nothing of it has run on Dom0:**
  first a clean Ubuntu, Windows and WoW64 run, which should match no new
  signature, then public Hell's Gate / SysWhispers3 PoCs. Then
  `CURRENT-STATE.md`'s DRAKVUF pin row, once the submodule change is committed.

  - **Calls through a register, CFG's dispatch included** -- not doable here.
    At `syscall` the call's target is gone: `call rax` loses it to the stub's
    `mov eax, N`, CFG keeps it in `rax` too, and `call [rbx+8]` depends on
    code the sample wrote. Only something that watches control flow as it
    happens would know: single-stepping (far too slow) or the CPU's Last
    Branch Record, which nothing in DRAKVUF or libvmi reads. An indirect
    syscall made through one is seen only when another service's stub ran it
    (`StubSyscall`).

  - **A stub of the sample's own is matched by bytes** (`mov r10, rcx`, then a
    jmp; `origin.h`, `looks_like_syscall_stub`) -- a few hours to tighten,
    never closed. When the jmp decodes (`e9 rel32`, `ff 25` through a
    readable pointer), require that it lands on ntdll's `syscall`, the stub's
    +0x12: fewer false matches. Decoding the whole function does not close
    it -- the sample can write `push rcx; pop r10` -- and dropping the check
    would flag every wrapper that tail-calls an `Nt*` export.

  - **WoW64: 32-bit indirect and randomized-jumper syscalls** -- 1-2 days,
    and a runtime cost. 32-bit stubs have no `mov r10, rcx` to match by, and
    wow64cpu does not save the `eax` the 32-bit code asked for, while WoW64
    makes syscalls of its own for one 32-bit call. A user-mode hook on
    `wow64!Wow64SystemServiceEx` (`ecx`, the service asked for) compared with
    the 32-bit stub's `mov eax` would do it: a second trap per WoW64 syscall,
    about twice their cost.

  - **A system DLL Windows itself relocated is reported a copy** -- hours,
    after one Dom0 check. "Copy" is a base other than the first mapping seen
    of that path; nothing in the kernel marks the loader's own mapping, and the
    PEB's list is the sample's to write. `_SEGMENT.BasedAddress` is in the
    profile and may be an image's chosen base, but its meaning on 22621 is
    unconfirmed: read it for ntdll in an ordinary process first.

  - **Linux: no frame 1, so no indirect syscalls** -- days to a week, low
    value. A glibc wrapper that is a cancellation point keeps a frame of its
    own, so the word at the stack pointer is not always a return address. It
    takes a `.eh_frame` (DWARF CFI) unwinder in DRAKVUF, and a frame-pointer
    walk for Go. Userland hooks are rare on Linux, so little evades them.

  - **Linux 6.1 and later (Android): no `FromModule`, so no `unbacked`** --
    1-2 days. libdrakvuf walks `mm_struct.mmap`, which became a maple tree
    (`mm_mt`). A maple tree walk would serve every `drakvuf_linux_find_vma`
    caller too: memdump's sizing, libmon's L-14 check. Android has `Caller`
    and `compat_syscall_from_64bit` meanwhile.

  - **`syscall_from_unbacked_memory` fires on UPX-packed static programs** --
    hours. UPX unpacks into anonymous memory. The `UPX!` magic in the file
    behind `mm_struct.exe_file` would tell a packer from shellcode, and so
    the description apart.

  - **A Linux process with no vDSO has no `Bitness`** (`vdso=0` on the
    kernel's command line), so its `int 0x80` is not flagged -- hours. Fall
    back to the ELF class of `mm_struct.exe_file`.

  - **The module caches can go stale** (both systems) -- a missed detection,
    never a false one. A cached file's range unmapped and shellcode placed
    there is reported as the file. Re-reading the VMA on every hit costs a
    walk per syscall; hooking unmaps (`NtUnmapViewOfSection`,
    `NtFreeVirtualMemory`, `munmap`) to drop entries is cheaper.

  - **Per-syscall cost on Windows** -- measure on Dom0 first. Each user-mode
    syscall now reads the stub, `KTHREAD.SystemCallNumber`, the call site
    before frame 1 and the pointer or thunk it goes through: about four small
    reads. If it shows, cache "frame 1 calls the stub" per (process, frame 1,
    frame 0) for frames in files.
- **Calls the compiler removed: inlining and recompilation (2026-11-14).**
  A hook sits at a function's entry, and a compiler may leave no entry to
  reach. Noted here, not fixed (operator, 2026-11-14); the report should not
  be read as "the sample never called X" for any of these.

  - **Go, Rust, C with LTO: a listed function that is absent was inlined or
    dropped.** In `gh` 38 of the 79 functions of `go-hooks.txt` exist. The
    call is still made further down, so the fix is to list what the wrapper
    calls and cannot be inlined into it (`os.rename` under `os.Rename`,
    `syscall.connect` under `net.Dial`, anything marked `//go:noinline` or
    written in assembly) -- hours per family of calls, by reading the
    standard library. The system call is the floor either way.

  - **.NET: the sample's JIT-compiled code inlines small framework methods.**
    The JIT inlines across assemblies whenever the callee's IL is small
    (property getters, thin wrappers such as `File.ReadAllText` over an
    internal reader), and then the framework's precompiled entry -- where
    `scripts/dotnet-index.py` put the hook -- is never called. Framework
    4.x compiles every method optimised at once, so this is always on
    there. Two ways round it, neither built:
    - Hook one level down, at the internal method the wrappers share, which
      is too large to inline. Needs a table "public method -> the internal
      one that does the work"; the index has every internal method already.
    - Stop the inlining in the guest: `COMPlus_JITMinOpts=1` (Framework) /
      `DOTNET_JITMinOpts=1`, or keep .NET 8 code at tier 0 (below), which
      never inlines. A machine-wide environment variable is a registry edit
      on the golden image and a thing a sample can read: an image decision.

  - **.NET 8 recompiles a method after about 30 calls** (tiered compilation:
    call counting, then a background tier-1 compile, 100 ms after start-up
    settles). The new code is elsewhere, the precompiled entry is no longer
    called, and tier 1 may also inline the method into its callers. A
    method is therefore seen for its first calls only -- enough for "did it
    download and from where", not for counting. Options, cheapest first:
    - Keep code in its first tier: `DOTNET_TC_CallCounting=0` (to be
      confirmed on a release runtime; `DOTNET_TieredCompilation=0` is the
      wrong knob, it compiles everything optimised at once, inlining included):
      methods stay in their first tier for ever, precompiled entries stay in
      use and tier-0 code never inlines. Loops still leave tier 0 through
      on-stack replacement (`DOTNET_TC_OnStackReplacement=0` with
      `DOTNET_TC_QuickJitForLoops=1` keeps them), and
      `[MethodImpl(AggressiveOptimization)]` methods skip tiering always.
    - Follow the recompilation. The hook on `CILJit::compileMethod` already
      sees every tier-1 compile with the IL's address and where the new code
      went. A hook line that names a method by its IL (`module,name,il:<rva>`,
      which the index can write: it has every method's IL RVA) would let
      apimon breakpoint each new native entry as it is produced -- for the
      sample's own methods too, which is the "see every call with arguments"
      step the plan left for later. 2-3 days: the address is known only at
      the compiler's return, JIT pages are written to (each write to a page
      with a breakpoint costs a VM pause), and inlining at tier 1 defeats it
      for small methods regardless.
    Both together are the complete answer; the first alone is nearly it.

  - **.NET Framework 32-bit native images are not indexed.** The 64-bit ones
    are (`index_native_image`, checked method by method). The 32-bit ones
    have no PE exception table; their function starts are in the image's own
    runtime-function section (virtual section type 0x21). A day, with the
    same cross-check, once a 32-bit .NET sample matters.

  - **A hook placed through the page cache is not re-checked.** libmon puts
    a breakpoint on the page-cache frame of code the program has not touched
    yet (`drakvuf_linux_file_page_frame`). If the kernel evicts that page
    before the program runs it, the code is read back into another frame and
    the hook is gone, silently; DRAKVUF's copy-on-write handling keeps the
    old frame harmless. Unlikely in a two-minute run on a guest with free
    memory. The certain way is to keep the page-fault hook installed as a
    check, which is the cost this lookup was written to avoid: measure
    first (`[TRAP-STATS]` in a debug build).

- **Second pass: what it does not reach** (the pass itself is written,
  2026-11-14, not run on a guest: `sandboxd/stagehints.py`, the `when:`
  marker in the fork, "Run again with unpacked code hooked" in a finished report's Memory
  and Dropped tabs). It hooks code that
  appears in the sample's *own image* -- unpacked in place, or a program run
  from a memfd. Left out:

  - **Memory the program allocates elsewhere**: a reflectively loaded DLL,
    shellcode in a `VirtualAlloc`/`mmap` region, a hollowed process. 3-4
    days. A hook line names a module and such a region has none. What would
    carry it: a line keyed by the process and the bytes alone
    (`<process image>,<name>,*,when:<hex>`, the page offset of the function
    known from the dump), placed on any executable private page of that
    process whose bytes match at that page offset. The work is the trigger.
    Linux: `mprotect(PROT_EXEC)` and `mmap(PROT_EXEC)` returning, plus the
    page-fault hook already there. Windows: `NtProtectVirtualMemory` and the
    thread-start family (`NtCreateThreadEx`, `NtResumeThread`,
    `NtQueueApcThread`, `NtSetContextThread`); memory allocated RWX, written
    and jumped to with no system call in between has no trigger short of an
    execute trap on the region (the `codemon` plugin's way, a VM exit per
    first execution of a page). On Windows the gain is smaller than it
    sounds: a reflectively loaded PE still calls the system DLLs, which
    apimon hooks in every process -- only code linked *into* the payload
    (a Go or Rust payload, a static CRT) is unseen.
  - **A hook lost to a remap.** A packer that unmaps and maps again after
    the hook was placed takes the frame away; libmon does not place it a
    second time. Keep `when:` entries in the cold list after placing, and
    re-check them on `munmap`/`mremap` of their address. A day.
  - **The first run's trace is not kept** by a job that asked for both
    runs through the API (`second_pass`; the submit form does not offer
    it): one trace on the report. ("Run again" from a finished report is a
    second job, and keeps both.) A sample that only does its work once (a C2 that
    serves a payload once) shows less in the second run than the first
    had. Keeping `first-run/trace.log.gz` as an artifact is an hour; whether
    the report should merge the two is the real question.
  - **End-of-run dumps never ran, until 2026-11-15** (jobs 295f5786,
    831d5f4c). procdump2's wrapper did not pass DRAKVUF's stop to its OS
    part, so a sample still running at the end was never dumped; fixed in
    the fork for Windows and Linux (operator's decision for Ubuntu). Open,
    for a guest run: whether a Windows process blocked in a hard-error
    dialog suspends for the dump.
  - **Obfuscated Go is named by signatures since 2026-11-15**
    (`fetch-flirt-sets.py --go`, `samplehooks.go_sets`). Measured with Go
    1.22.2 on a stripped program built as malware is: 4,067 of its 5,168
    functions named, 24 of the 26 `go-hooks.txt` functions it has, none of
    those wrong (5 wrong names, all compiler-made type-equality helpers).
    Not measured on a garble build: garble leaves the standard library's
    code as it is unless `-literals`, which rewrites the functions that
    have string literals; a release's set names what the build left alone.
    Left: Windows Go programs get Linux sets (a Windows set needs Go's COFF
    object read, `go.o` is COFF for windows/amd64): the functions whose code
    is the same on both are named, the system-facing ones not. 32-bit Go
    has no sets. Two functions alike in bytes and in whom they call
    (`crypto/cipher.NewCBCEncrypter` and `...Decrypter`) are named neither.
  - **zstd dumps** are not read (sandboxd asks procdump2 for gzip), and a
    dump whose image is over 256 MiB is cut there.
  - **A PE image's addresses of itself, without a relocation table**
    (fixed 2026-11-15, job 3a17acfb): a packed image's own directory is the
    packer's, so stagehints also treats any 4 bytes (8 in a 64-bit image)
    holding an address inside the image as moving. Left: an address of
    another module in a hint's first 16 bytes (none seen in Go or C
    prologues), and a value that merely looks like an image address, which
    only costs the marker a few bytes of precision.
