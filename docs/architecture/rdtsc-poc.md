# RDTSC compensation — the guest's TSC without DRAKVUF's time in it

> **Status (2026-11-01): measured on Dom0 with the search tooling outside this
> repository; `make xen` has not installed it yet.** The Xen code is
> `automation/xen-rdtsc-poc.patch`, a squash of the operator's `drakvuf-dev/xen`
> branch `rdtsc-poc` (5fa34725a4, dc30449605, 18aaea8adf). `make xen` applies it
> and puts `rdtsc-poc=1` on the boot line; `automation/xen-rdtsc-poc.service`
> presses the `d` key once per boot. Dom0 runs builds of that branch, installed
> by the search scripts rather than by `make xen`.

DRAKVUF stops a guest vCPU for every trap: a vm_event round trip, an altp2m
switch, a single step. A program that reads the TSC twice around a trapping
instruction sees all of that time, millions of cycles where bare metal shows a
few dozen. That is the oldest red pill there is, and it found every trace.

---

## 1. What it does

With `rdtsc-poc=1`, every RDTSC and RDTSCP of a guest **created with altp2m**
exits to Xen, whatever its `tsc_mode`. Only those guests: they are the ones
DRAKVUF analyses, and the PVH platform DomU would pay an exit per RDTSC for
nothing. The `d` debug key turns the compensation on; until it is pressed the
exits are answered with the plain guest TSC.

Xen then answers each RDTSC by where it comes from:

| Read | Answer |
|---|---|
| **User mode, in a program's own code**: below `0x7f0000000000` (Linux programs, Windows images without ASLR) or `0x7ff600000000`–`0x7ff800000000` (64-bit Windows executables) | On a timeline of its own per vCPU. A read that comes at most `RDTSC_USER_CLOSE` (1M) cycles of **guest run time** after the previous one, with no sleep in between, returns that one plus 10–25 cycles, hiding up to `RDTSC_USER_LAG_MAX` (30M cycles, 10 ms). Any other read returns the guest TSC and catches the timeline up |
| Kernel mode, shared libraries, the vDSO, Windows DLLs (`QueryPerformanceCounter`) | The guest TSC, as is |

**Guest run time** is measured from each VM entry to its VM exit, so Xen's
handling of every exit DRAKVUF causes, the vm_event pauses and the waits for a
pCPU are out of it. Sleep (HLT) is not compressed: the first read after the
vCPU slept returns the guest TSC.

A compressed value is never below the guest's pvclock `tsc_timestamp`; below it
a clock read would wrap decades forward.

### 1.1 Why the kernel keeps the real TSC

The Linux guests run the `xen` clocksource and clockevent: the kernel turns the
TSC into its clock (pvclock) and its timer deadlines into absolute Xen system
time. A kernel TSC behind the real one sets every timer early; the timer fires,
the kernel reads its clock, finds it early, sets it again, and the guest
freezes in timer interrupts. That was measured (2026-11-01): compressing kernel
reads, both guests froze or crawled in every test; compressing program reads
only, they ran at normal speed in every test. `TROUBLESHOOTING.md`, "The guest freezes or
crawls with RDTSC compensation on", has the symptom.

The test samples run do not need the kernel's reads compressed: a red pill
compares its own two reads, both in its own code. Kernel reads between them
(Linux reads the TSC on every return to user mode for its stack offset, and
after emulating a user-mode SIDT for UMIP) do not touch the program timeline.

---

## 2. Evidence

Measured by the operator's search tooling on Dom0, 2026-11-01, Ubuntu guest
under DRAKVUF, with a red pill detector (`rdtsc; sidt; rdtsc`, detected above
100 cycles) run every 5 s for 55 s, in both `dev-syscalls` (syscalls, cpuidmon,
hidsim) and `dev-all` (every plugin) configurations:

| Xen | Detector runs returning "detected" | Guest speed |
|---|---|---|
| Unmodified | every one | normal |
| Kernel reads compressed too | dev-syscalls none, dev-all every one | froze or crawled in every test: one detector run in 55 s |
| **This design, `RDTSC_USER_CLOSE` 1M, `RDTSC_USER_LAG_MAX` 30M** | **0 of 200, twice (10 tests each)** | normal in every test |

What lies between the detector's two reads under `dev-all`: about 1M host
cycles, of which ~700k with the vCPU paused, ~290k in Xen for 24 other exits
and ~60k of guest run time, plus one kernel RDTSC. The tighter limits failed
on that: 200k cycles of run time missed the first run after a restore (the
kernel logs UMIP's warning between the reads), 3M of hidden time missed pauses
of up to 4.7M.

Windows 11, al-khaser under DRAKVUF (`alkhaser_search.sh` outside this
repository): with the Windows executable range, its RDTSC around CPUID check
(14011) passes; without it, nothing on Windows is compressed and that check
detects.

---

## 3. Known gaps

- **al-khaser's Locky check (14010) detects on Windows.** It wants
  `CloseHandle(0)` to take 10 times `GetProcessHeap()`; neither makes a syscall
  on Windows 11, they differ by 40–90 cycles of run time, and a compressed
  pair returns 10–25 cycles either way. `RDTSC_USER_PURE` (in the patch, **off**)
  returns the guest's own work for a pair with no exit between; a model with
  the measured run times passes Locky 972/1000 and keeps the CPUID check and
  the red pill. Not yet measured on the guests.
- **A program timing up to ~0.33 ms of its own work with RDTSC sees almost no
  time pass**, and a busy wait on RDTSC runs up to 10 ms late. Compression
  cannot tell a red pill from a short benchmark.
- **The address ranges are a heuristic.** A Linux library mapped below
  `0x7f0000000000` or in the Windows band is treated as program code; an
  executable elsewhere is not. A sample loaded as a DLL is not covered.
- **The red pill's threshold is lower than bare metal with UMIP**, where the
  kernel's emulation of SIDT alone costs thousands of cycles. Passing it means
  hiding real guest work too, which is why the limits are in run time rather
  than in exits.

---

## 4. Operating it

| | |
|---|---|
| Boot option | `rdtsc-poc=1` (`XEN_CMDLINE`) |
| Turn on | `xl debug-keys d`, once per boot; `xen-rdtsc-poc.service` does it |
| Inspect | `xl debug-keys t; xl dmesg \| grep RDTSC_POC`: per vCPU the program timeline (`prog_reads`, `prog_compressed`, `prog_far`, `prog_slept`, `prog_lag`, `prog_pvclock`, `prog_max_hidden`, `prog_pure`) and the last red pill like pairs, each with host time, stolen time, guest run time, exits and the delta returned |
| Tune | the `#define`s in `xen/arch/x86/hvm/vmx/vmx.c`: `RDTSC_USER_CLOSE`, `RDTSC_USER_LAG_MAX`, `RDTSC_USER_RIP_MAX`, `RDTSC_USER_EXE_LO`/`_HI`, `RDTSC_USER_PURE`, `RDTSC_KERNEL_ADJUST` (1 compresses kernel reads too, which freezes Linux guests) |