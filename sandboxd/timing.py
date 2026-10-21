"""Every wait in an analysis, in one place, with what measured it.

Issue #41 (DRAFT-060).

**The root fact all of this follows from: `injector -m execproc` returns when
the guest process STARTS, not when it finishes.** Dom0 gets no completion
signal, so every injection that must finish before the next step needs an
explicit wait.

**These numbers are inherited, and their sources are gone.** They were scattered
across four files of the shell/C launcher pipeline as bare `sleep` calls, two of
which carried no explanation where they were written. That pipeline was deleted
on 2026-09-15 once `sandboxd` had replaced all of it, so this module is now the
only record of what each wait is for. A wait with no stated reason is the first
thing someone tunes down when a pipeline feels slow -- and two of these are
load-bearing.

## The inventory, and what measured each

    5s    the launch delay, and the one wait NOT defined here:
          `guests.LAUNCH_DELAY`, because the guest spends it, not sandboxd.
          The sample waits that long after the injection before its own first
          instruction, because DRAKVUF arms its plugins AFTER injecting
          (`main.cpp`: `inject_cmd()`, `start_plugins()`, `loop()`) and
          whatever the sample does before that is not recorded anywhere. Listed
          here so this inventory stays what it claims to be; the reasoning,
          and how to measure it rather than argue about it, is at the constant.

    5s    settle before the trace attaches
          What it is REALLY covering: preconfig's network injection is an
          execproc, so it has returned without the guest having finished
          configuring. This sleep is the only thing between that and the
          trace. The scripts it came from never said so -- stated here because
          "settling time" reads as superstition and invites deletion.

  <=90s   APK launcher component (APK_COMPONENT_TIMEOUT), a CEILING not a sleep
          Was a fixed 20s sleep. 3 seconds MEASURED for a 12 MB APK on
          2026-08-17, network configuration included -- but the margin was over
          the install, and what actually overran was `pm list packages` waiting
          on the package service after a restore. Jobs failed with `readfile`
          ENOENT. Now polled: preconfig waits for content that parses as a
          launchable component, so a healthy job is FASTER than the old sleep.

    5s    SIGINT -> SIGKILL
          DRAKVUF flushes and detaches its introspection state on SIGINT;
          killing it outright can leave stealth breakpoints written into guest
          memory.

   10s    after `xl destroy`, before `lvremove`
          `xl destroy` returns before the block device is released -- MEASURED
          on Dom0 2026-08-14, where `lvremove` reported "Logical volume in use"
          and succeeded on a retry. This is the single fact behind
          `DESTROY_SETTLE`, and the reason a clone teardown is not simply
          destroy-then-remove.

   30s    flock retry on the clone name
          Non-blocking with a bounded retry, never a blocking LOCK_EX: nothing
          upstream imposes a timeout on the clone step, so a blocking acquire
          would hang a worker with no way out.

   60s    the preconfig phase
  180s    the trace phase
          Wall-clock guards. Either firing triggers cleanup and a fresh clone.

120/150s  `drakvuf -t`, the trace's own budget.

## What changes under sandboxd

The old 60 and 180 were **compiled into the C watcher** -- raising either needed
a recompile, which is why the Android trace was pinned at `-t 150` and could not
go higher. Here they are configuration, so a guest that legitimately needs
longer can have it without rebuilding the orchestrator.

Two waits are new, because the old launcher did neither: fetching the sample
from the object store, and uploading artifacts to it.
"""

from __future__ import annotations

from dataclasses import dataclass

from .guests import PLUGIN_STOP_WAIT, SampleKind, TargetOs

# --- individual waits --------------------------------------------------------

# See the module docstring: this covers the network injection having returned
# before the guest finished applying it.
PRE_TRACE_SETTLE = 5.0

# **Was a fixed 20s sleep. Replaced by a poll on 2026-09-04, because the sleep
# was timing the wrong thing and jobs failed on it.**
#
# Both numbers, per the standing preference to keep the measurement next to the
# guard: 3s was MEASURED for a 12 MB APK (Dom0 2026-08-17, nested host) and 20s
# was the margin over it. The margin was ample for the install and irrelevant to
# the failure: `pm list packages` runs BEFORE the install line and talks to the
# package service over binder, which on a freshly restored clone may not be up
# yet. The handoff is created by the install line's redirect, so a slow package
# service means `readfile` hits `-ENOENT` and the job dies. Intermittent,
# because a warm service returns instantly. See TROUBLESHOOTING, "`injector
# readfile` fails with `syscall return code: -2`".
#
# A ceiling replaces a duration: the poll returns as soon as the component is
# there, so the common case is FASTER than the old sleep, and the 90s is only
# ever spent when something is actually wrong. Generous on purpose -- the cost
# of overshooting is a slow failure, the cost of undershooting is a failed job
# on a healthy sample, which is what we had.
APK_COMPONENT_TIMEOUT = 90.0

# How often to ask. Each attempt is an `injector readfile`, so this is not free;
# 2s keeps the worst case around 45 injections rather than 90.
APK_COMPONENT_POLL = 2.0

# Headroom over the deliberate waits for the injections themselves, none of
# which is measured -- notably the 12 MB `writefile`. Was an implicit `* 3`
# multiplier on the sleep, which stopped meaning anything once the sleep became
# a ceiling that is usually not reached: tripling a 90s ceiling would have given
# a 270s guard for a phase that normally finishes in seconds.
PRECONFIG_INJECTION_HEADROOM = 60.0

# The old cleanup script's escalation, kept. Also proc.DEFAULT_GRACE.
KILL_GRACE = 5.0

# The post-destroy settle. MEASURED on Dom0 2026-08-14: `xl destroy` returns
# before the block device is released, and `lvremove` immediately after it
# reported "Logical volume in use", then succeeded on a retry. Not a guess --
# see the inventory above.
DESTROY_SETTLE = 10.0

# --- phase budgets -----------------------------------------------------------
#
# Wall-clock guards over a whole stage, distinct from the per-command timeouts
# in clone.py. A phase that overruns means the clone is torn down.

CLONE_BUDGET = 180.0        # lvcreate + xl restore, generous: a busy VG is slow
COLLECT_BUDGET = 300.0      # NEW: artifact upload, which the old launcher never did
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

    The per-OS env file this replaced already read `${APK_INSTALL_WAIT:-20}`
    from the environment, so these were always meant to be tunable per host -- a
    slower Dom0 legitimately needs longer, and a faster one is paying for margin
    it does not need. Hard-coding them also made an analysis untestable without
    really sleeping, which is its own argument.

    The defaults are the measured values above, and lowering one below what was
    measured is how a preconfig starts handing a still-running install to the
    trace.
    """

    settle: float = PRE_TRACE_SETTLE
    # A CEILING, not a duration: how long preconfig will wait for the launcher
    # component before giving up. Lowering it does not make a job faster, it
    # only makes a slow guest fail sooner.
    apk_component_timeout: float = APK_COMPONENT_TIMEOUT
    apk_component_poll: float = APK_COMPONENT_POLL
    kill_grace: float = KILL_GRACE
    # The post-`xl destroy` poll, used by both the clone builder and the
    # startup sweep. Here with the rest because it is the same kind of thing:
    # a deliberate wait with a measurement behind it.
    destroy_settle: float = DESTROY_SETTLE


DEFAULT_WAITS = Waits()


def _preconfig_waits(os_: TargetOs, kind: SampleKind,
                     waits: Waits = DEFAULT_WAITS) -> float:
    """The waits that MUST fit inside the preconfig budget.

    **The worst case, not the expected case** -- and that changed on 2026-09-04.
    This used to be time the code spent unconditionally asleep, so it was both.
    The APK wait is now a poll that returns as soon as the component appears, so
    a healthy job spends a fraction of it; the budget still has to accommodate
    the whole ceiling, or `left()` cuts the poll short before its own deadline
    and the phase guard fires instead of the useful error.
    """
    total = 0.0
    if os_ is TargetOs.ANDROID and kind is SampleKind.APK:
        total += waits.apk_component_timeout
    return total


def _trace_waits(os_: TargetOs, kind: SampleKind,
                 waits: Waits = DEFAULT_WAITS) -> float:
    # **The APK path used to skip the settle, and no longer can (2026-09-04).**
    # That exemption rested on preconfig having just spent a fixed 20s
    # installing, so the clone was "long since settled". With the sleep replaced
    # by a poll that returns as soon as the component appears, a fast install
    # now reaches the trace seconds after the guest finished writing the
    # handoff -- exactly the un-settled clone the exemption assumed away.
    #
    # It costs the APK launch `settle` seconds of trace budget, which is the
    # trade the old comment was avoiding. Paying it is the conservative side:
    # the alternative is attaching the trace to a guest that is still applying
    # its network configuration.
    return waits.settle


def budgets(os_: TargetOs, kind: SampleKind, trace_timeout: int,
            waits: Waits = DEFAULT_WAITS) -> PhaseBudgets:
    """Phase guards for one job, derived rather than tabulated.

    **The preconfig and trace budgets are computed from what they contain**,
    which is what turns a margin question into an invariant. The old watcher's
    60s preconfig guard had to cover, on the Android APK path: a 12 MB
    `writefile`, a network injection, a `pm install` injection, a deliberate 20s
    sleep, a `readfile` and an `rm`. Nobody has measured the writefile. If it takes 35s
    the phase times out, the clone is destroyed, and the retry does the same
    thing again -- a loop with no error message.

    Rather than record that as a note, the budget is the deliberate waits plus
    headroom, so it cannot be under-set by arithmetic.
    """
    preconfig_floor = _preconfig_waits(os_, kind, waits)
    trace_floor = _trace_waits(os_, kind, waits) + float(trace_timeout)

    return PhaseBudgets(
        clone=CLONE_BUDGET,
        # The worst-case waiting PLUS headroom for the injections, floored at
        # the old watcher's 60. Additive rather than the former `* 3`: the multiplier
        # made sense against a sleep the phase always spent, and would give a
        # 270s guard now that the 90 is a ceiling a healthy job never reaches.
        # Non-APK jobs are unchanged at 60.
        preconfig=max(60.0, preconfig_floor + PRECONFIG_INJECTION_HEADROOM),
        # The trace's own -t plus the settle, plus 30s for process startup and
        # DRAKVUF's own teardown. The old watcher used a flat 180 against -t 120,
        # leaving 55s unused on Ubuntu and ~20s on the Android APK path.
        # Plus the ceiling DRAKVUF may wait past -t for plugins with a call
        # still injected (`--wait-stop-plugins`): a guard firing inside that
        # wait kills DRAKVUF with the call in flight, the crash it prevents.
        trace=trace_floor + PLUGIN_STOP_WAIT + 30.0,
        collect=COLLECT_BUDGET,
        cleanup=CLEANUP_BUDGET,
    )
