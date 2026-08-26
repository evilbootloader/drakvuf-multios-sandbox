"""Every wait in an analysis, in one place, with what measured it.

Issue #41 (DRAFT-060).

**The root fact all of this follows from: `injector -m execproc` returns when
the guest process STARTS, not when it finishes.** Dom0 gets no completion
signal, so every injection that must finish before the next step needs an
explicit wait. The scripts have these scattered across four files as bare
`sleep` calls, two of which carry no explanation at all where they are written.

Collected here because a wait with no stated reason is the first thing someone
tunes down when a pipeline feels slow -- and two of these are load-bearing.

## The inventory, and where each came from

    5s    settle before the trace attaches
          drakvuf-ubuntu.sh:157, drakvuf-android.sh:219.
          What it is REALLY covering: preconfig's network injection is an
          execproc, so it has returned without the guest having finished
          configuring. This sleep is the only thing between that and the
          trace. Neither script says so -- stated here because "settling time"
          reads as superstition and invites deletion.

   20s    APK install (APK_INSTALL_WAIT)
          preconfig-android.sh:384. 3 seconds MEASURED for a 12 MB APK on
          2026-08-17, network configuration included. The margin is the point:
          a preconfig timeout is a clone-and-retry loop, not an error.

    5s    SIGINT -> SIGKILL
          cleanup.sh:146. DRAKVUF flushes and detaches its introspection state
          on SIGINT; killing it outright can leave stealth breakpoints written
          into guest memory.

   10s    after `xl destroy`, before `lvremove`
          clone.pl:405. `xl destroy` returns before the block device is
          released -- measured on Dom0 2026-08-14, where lvremove reported
          "Logical volume in use" and succeeded on a retry.

   30s    flock retry on the clone name
          clone.pl:377. Non-blocking with a bounded retry, never a blocking
          LOCK_EX: nothing upstream imposes a timeout on the clone step, so a
          blocking acquire would hang a worker with no way out.

   60s    the preconfig phase       dirwatch.c:637
  180s    the trace phase           dirwatch.c:653
          Wall-clock guards. Either firing triggers cleanup and a fresh clone.

120/150s  `drakvuf -t`, the trace's own budget.

## What changes under sandboxd

dirwatch's 60 and 180 are **compiled in** -- raising either needs a recompile,
which is why drakvuf-android.sh:314 explains that `-t 150` cannot go higher.
Here they are configuration, so a guest that legitimately needs longer can have
it without rebuilding the orchestrator.

Two waits are new, because dirwatch never did either: fetching the sample from
the object store, and uploading artifacts to it.
"""

from __future__ import annotations

from dataclasses import dataclass

from .guests import SampleKind, TargetOs

# --- individual waits --------------------------------------------------------

# See the module docstring: this covers the network injection having returned
# before the guest finished applying it.
PRE_TRACE_SETTLE = 5.0

# 3s measured for a 12 MB APK (Dom0 2026-08-17); the rest is margin, per the
# project's standing preference to set a guard above the measured value.
APK_INSTALL_WAIT = 20.0

# cleanup.sh's escalation. Also proc.DEFAULT_GRACE.
KILL_GRACE = 5.0

# clone.pl's post-destroy poll.
DESTROY_SETTLE = 10.0

# --- phase budgets -----------------------------------------------------------
#
# Wall-clock guards over a whole stage, distinct from the per-command timeouts
# in clone.py. A phase that overruns means the clone is torn down.

CLONE_BUDGET = 180.0        # lvcreate + xl restore, generous: a busy VG is slow
COLLECT_BUDGET = 300.0      # NEW: artifact upload, which dirwatch never did
FETCH_BUDGET = 300.0        # NEW: sample download from the object store
CLEANUP_BUDGET = 60.0


@dataclass(frozen=True)
class PhaseBudgets:
    """The wall-clock guard for each stage of one job."""

    clone: float
    preconfig: float
    trace: float
    collect: float
    cleanup: float


@dataclass(frozen=True)
class Waits:
    """The deliberate sleeps, as configuration rather than constants.

    `pipeline-android.env` already reads `${APK_INSTALL_WAIT:-20}` from the
    environment, so these were always meant to be tunable per host -- a slower
    Dom0 legitimately needs longer, and a faster one is paying for margin it
    does not need. Hard-coding them also made an analysis untestable without
    really sleeping, which is its own argument.

    The defaults are the measured values above, and lowering one below what was
    measured is how a preconfig starts handing a still-running install to the
    trace.
    """

    settle: float = PRE_TRACE_SETTLE
    apk_install: float = APK_INSTALL_WAIT
    kill_grace: float = KILL_GRACE
    # The post-`xl destroy` poll, used by both the clone builder and the
    # startup sweep. Here with the rest because it is the same kind of thing:
    # a deliberate wait with a measurement behind it.
    destroy_settle: float = DESTROY_SETTLE


DEFAULT_WAITS = Waits()


def _preconfig_waits(os_: TargetOs, kind: SampleKind,
                     waits: Waits = DEFAULT_WAITS) -> float:
    """The waits that MUST fit inside the preconfig budget.

    Not an estimate of how long preconfig takes -- it is the part that is
    unavoidable regardless of how fast the host is, because it is time this
    code spends deliberately sleeping.
    """
    total = 0.0
    if os_ is TargetOs.ANDROID and kind is SampleKind.APK:
        total += waits.apk_install
    return total


def _trace_waits(os_: TargetOs, kind: SampleKind,
                 waits: Waits = DEFAULT_WAITS) -> float:
    if os_ is TargetOs.ANDROID and kind is SampleKind.APK:
        # The APK path skips the settle: preconfig has just spent
        # APK_INSTALL_WAIT seconds installing, so the clone is long since
        # settled, and every second here comes out of a trace budget the launch
        # is already short of.
        return 0.0
    return waits.settle


def budgets(os_: TargetOs, kind: SampleKind, trace_timeout: int,
            waits: Waits = DEFAULT_WAITS) -> PhaseBudgets:
    """Phase guards for one job, derived rather than tabulated.

    **The preconfig and trace budgets are computed from what they contain**,
    which is what turns a margin question into an invariant. dirwatch's 60s
    preconfig guard covers, on the Android APK path: a 12 MB `writefile`, a
    network injection, a `pm install` injection, a deliberate 20s sleep, a
    `readfile` and an `rm`. Nobody has measured the writefile. If it takes 35s
    the phase times out, the clone is destroyed, and the retry does the same
    thing again -- a loop with no error message.

    Rather than record that as a note, the budget is the deliberate waits plus
    headroom, so it cannot be under-set by arithmetic.
    """
    preconfig_floor = _preconfig_waits(os_, kind, waits)
    trace_floor = _trace_waits(os_, kind, waits) + float(trace_timeout)

    return PhaseBudgets(
        clone=CLONE_BUDGET,
        # 3x the deliberate sleeping, floored at dirwatch's 60. The multiplier
        # is headroom for the injections themselves, which are not measured --
        # notably the 12 MB writefile above.
        preconfig=max(60.0, preconfig_floor * 3),
        # The trace's own -t plus the settle, plus 30s for process startup and
        # DRAKVUF's own teardown. dirwatch used a flat 180 against -t 120,
        # leaving 55s unused on Ubuntu and ~20s on the Android APK path.
        trace=trace_floor + 30.0,
        collect=COLLECT_BUDGET,
        cleanup=CLEANUP_BUDGET,
    )
