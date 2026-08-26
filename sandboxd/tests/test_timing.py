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

    dirwatch's 60s preconfig guard covers, on the Android APK path: a 12 MB
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
    """20s of that budget is a deliberate sleep, so a 60s guard leaves 40s for
    a 12 MB writefile plus three injections. Asserted rather than assumed,
    because it is the tightest phase in the pipeline."""
    b = budgets(TargetOs.ANDROID, SampleKind.APK)

    headroom = b.preconfig - T.APK_INSTALL_WAIT
    assert headroom >= 40, f"only {headroom}s for the injections themselves"


def test_the_trace_budget_covers_drakvufs_own_timeout():
    """`-t` bounds the trace; the phase guard bounds the whole invocation. A
    phase guard below `-t` kills a trace that was going to finish, which reads
    as a sample that did nothing."""
    for os_, kind in [(TargetOs.UBUNTU, SampleKind.ELF),
                      (TargetOs.ANDROID, SampleKind.ELF),
                      (TargetOs.ANDROID, SampleKind.APK)]:
        t = default_trace_options(os_, kind).timeout
        assert budgets(os_, kind).trace > t


def test_the_apk_path_leaves_more_headroom_than_dirwatch_did():
    """dirwatch used a flat 180s against `-t 150`, leaving ~20s once process
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


def test_the_apk_path_skips_the_settle():
    """preconfig has just spent APK_INSTALL_WAIT seconds installing, so the
    clone is long since settled -- and every second here comes out of a trace
    budget the launch is already short of. drakvuf-android.sh:218 makes the
    same exception."""
    assert T._trace_waits(TargetOs.ANDROID, SampleKind.APK) == 0.0


# --- the measured constants -------------------------------------------------

def test_the_apk_wait_is_above_what_was_measured():
    """3 seconds measured for a 12 MB APK on Dom0 2026-08-17, network
    configuration included. The rest is margin, per the project's standing
    preference to set a guard above the measured value."""
    assert T.APK_INSTALL_WAIT > 3


def test_the_kill_grace_matches_cleanups_escalation():
    """cleanup.sh sends SIGINT, sleeps 5, then SIGKILLs. The interval is doing
    real work: DRAKVUF flushes and detaches its introspection state on SIGINT,
    and killing it outright can leave stealth breakpoints in guest memory."""
    from sandboxd import proc
    assert T.KILL_GRACE == proc.DEFAULT_GRACE == 5.0


def test_the_destroy_settle_matches_clone():
    """`xl destroy` returns before the block device is released -- Dom0
    2026-08-14, lvremove reporting "Logical volume in use"."""
    from sandboxd import clone
    assert T.DESTROY_SETTLE == clone.DESTROY_SETTLE_SECONDS


# --- the two waits dirwatch never needed ------------------------------------

def test_fetching_and_uploading_have_their_own_budgets():
    """dirwatch never touched an object store: the sample arrived in a watch
    directory and results stayed on local disk. Both are network operations
    now, and a network operation with no timeout is a daemon that stops."""
    b = budgets(TargetOs.UBUNTU, SampleKind.ELF)
    assert b.collect > 0
    assert T.FETCH_BUDGET > 0