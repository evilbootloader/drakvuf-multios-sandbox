"""Waits and phase budgets: issue #41 (DRAFT-060).

A wait with no stated reason is the first thing someone tunes down when a
pipeline feels slow. These pin the two that are load-bearing, and turn the
Android preconfig margin from a note into an arithmetic invariant.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd import timing as T  # noqa: E402
from sandboxd.guests import SampleKind, TargetOs, default_trace_options  # noqa: E402


def budgets(os_, kind):
    return T.budgets(os_, kind, default_trace_options(os_, kind).timeout)


# --- the deliberate waits fit inside their phase ---------------------------

@pytest.mark.parametrize("os_,kind", [
    (TargetOs.UBUNTU, SampleKind.ELF),
    (TargetOs.ANDROID, SampleKind.ELF),
    (TargetOs.ANDROID, SampleKind.APK),
])
def test_a_phase_budget_exceeds_the_time_it_spends_sleeping(os_, kind):
    """The invariant that replaces a margin note.

    The C watcher's 60s preconfig guard had to cover, on the Android APK path: a 12 MB
    writefile, a network injection, a `pm install` injection, a deliberate 20s
    sleep, a readfile and an rm. Nobody has measured the writefile. If it takes
    35s the phase times out, the clone is destroyed, and the retry does exactly
    the same thing -- a loop with no error message.
    """
    b = budgets(os_, kind)

    assert b.preconfig > T._preconfig_waits(os_, kind), (
        "the preconfig budget does not exceed the time preconfig spends "
        "deliberately asleep"
    )
    assert b.trace > T._trace_waits(os_, kind)


def test_the_android_apk_preconfig_has_real_headroom():
    """The budget must fit the whole component-poll ceiling AND leave room for
    the injections around it -- a 12 MB writefile plus three injections, none
    of them measured. Asserted rather than assumed, because it is the tightest
    phase in the pipeline.

    The ceiling is a worst case a healthy job never reaches, but `left()` is
    keyed on the budget: if the budget did not cover it, the phase guard would
    fire before the poll's own deadline and replace a useful error with a
    timeout."""
    b = budgets(TargetOs.ANDROID, SampleKind.APK)

    headroom = b.preconfig - T.APK_COMPONENT_TIMEOUT
    assert headroom >= 40, f"only {headroom}s for the injections themselves"


def test_a_non_apk_preconfig_budget_did_not_move():
    """The 2026-09-04 poll change is scoped to the Android APK path. Every
    other job keeps the C watcher's 60s guard, and this is what says so."""
    for os_, kind in [(TargetOs.UBUNTU, SampleKind.ELF),
                      (TargetOs.ANDROID, SampleKind.ELF)]:
        assert budgets(os_, kind).preconfig == 60.0


def test_the_trace_budget_covers_drakvufs_own_timeout():
    """`-t` bounds the trace; the phase guard bounds the whole invocation. A
    phase guard below `-t` kills a trace that was going to finish, which reads
    as a sample that did nothing."""
    for os_, kind in [(TargetOs.UBUNTU, SampleKind.ELF),
                      (TargetOs.ANDROID, SampleKind.ELF),
                      (TargetOs.ANDROID, SampleKind.APK)]:
        t = default_trace_options(os_, kind).timeout
        assert budgets(os_, kind).trace > t


def test_the_apk_path_leaves_more_headroom_than_the_c_watcher_did():
    """The C watcher used a flat 180s against `-t 150`, leaving ~20s once process
    startup is counted -- and `-t` could not be raised without a recompile,
    because the 180 is compiled in. Here both are configuration."""
    b = budgets(TargetOs.ANDROID, SampleKind.APK)
    assert b.trace - 150 >= 30


# --- the settle, and where it is skipped -----------------------------------

def test_the_pre_trace_settle_applies_to_the_elf_paths():
    """What it is really covering: preconfig's network injection is an
    execproc, so it returned without the guest having finished configuring.
    This sleep is the only thing between that and the trace."""
    assert T._trace_waits(TargetOs.UBUNTU, SampleKind.ELF) == T.PRE_TRACE_SETTLE
    assert T._trace_waits(TargetOs.ANDROID, SampleKind.ELF) == T.PRE_TRACE_SETTLE


def test_the_apk_path_no_longer_skips_the_settle():
    """**Reversed 2026-09-04, and the reason is the poll.** The exemption rested
    on preconfig having just spent a fixed 20s installing, so the clone was
    "long since settled". The sleep is now a poll that returns as soon as the
    component appears, so a fast install reaches the trace seconds after the
    guest wrote the handoff -- the un-settled clone the exemption assumed away.

    The Android trace script made the old exception; it went with the rest of
    the launcher pipeline on 2026-09-15."""
    assert T._trace_waits(TargetOs.ANDROID, SampleKind.APK) == T.PRE_TRACE_SETTLE


# --- the measured constants -------------------------------------------------

def test_the_component_ceiling_is_well_above_what_was_measured():
    """3 seconds measured for a 12 MB APK on Dom0 2026-08-17, network
    configuration included -- and 20s of margin over it was NOT enough, because
    the margin was over the wrong thing: `pm list packages` waits on the package
    service after a restore, and jobs failed with `readfile` ENOENT.

    The ceiling is now generous on purpose. Overshooting costs a slow failure;
    undershooting costs a failed job on a healthy sample, which is what was
    observed 2026-09-04."""
    assert T.APK_COMPONENT_TIMEOUT > 20


def test_the_component_poll_interval_is_not_a_busy_loop():
    """Each attempt is an `injector readfile` against a live domain, so the
    interval is a real cost, not a formality."""
    assert T.APK_COMPONENT_POLL >= 1.0
    assert T.APK_COMPONENT_POLL < T.APK_COMPONENT_TIMEOUT


def test_the_kill_grace_matches_cleanups_escalation():
    """The old cleanup script sent SIGINT, slept 5, then SIGKILLed. The interval is doing
    real work: DRAKVUF flushes and detaches its introspection state on SIGINT,
    and killing it outright can leave stealth breakpoints in guest memory."""
    from sandboxd import proc
    assert T.KILL_GRACE == proc.DEFAULT_GRACE == 5.0


def test_the_destroy_settle_matches_clone():
    """`xl destroy` returns before the block device is released -- Dom0
    2026-08-14, lvremove reporting "Logical volume in use"."""
    from sandboxd import clone
    assert T.DESTROY_SETTLE == clone.DESTROY_SETTLE_SECONDS


# --- the two waits the C watcher never needed -------------------------------

def test_fetching_and_uploading_have_their_own_budgets():
    """The C watcher never touched an object store: the sample arrived in a watch
    directory and results stayed on local disk. Both are network operations
    now, and a network operation with no timeout is a daemon that stops."""
    b = budgets(TargetOs.UBUNTU, SampleKind.ELF)
    assert b.collect > 0
    assert T.FETCH_BUDGET > 0