"""Enumerations mirrored from the database.

Issue #36 (DRAFT-043). The authority is migration 0001; these exist so
pydantic can reject a bad value at the HTTP boundary, before a handler runs.
tests/test_api.py asserts they still agree with the database.
"""

from __future__ import annotations

from enum import StrEnum


class TargetOs(StrEnum):
    """The OS a sample is submitted against.

    **This is the only untrusted routing input in the system** (issue #3).
    The submitter chooses it, it is validated against this closed set at
    exactly one boundary, and file magic never selects it -- magic may only
    reject a mismatch.

    Widening this to a free-text field reopens a decision taken deliberately,
    and the database enum would reject the value anyway -- but at the wrong
    layer, as a 500 rather than a 422.
    """

    UBUNTU = "ubuntu"
    ANDROID = "android"
    WINDOWS = "windows"


class JobState(StrEnum):
    """The analysis lifecycle, as specified in analysis-pipeline.md.

    Kept in the same order as the state machine so the progression reads
    top to bottom, with the exits after it.
    """

    RECEIVED = "received"
    ADMITTED = "admitted"
    QUEUED = "queued"
    CLONING = "cloning"
    PREPARING = "preparing"
    EXECUTING = "executing"
    COLLECTING = "collecting"
    CLEANING = "cleaning"
    COMPLETED = "completed"

    REJECTED = "rejected"
    CANCELLED = "cancelled"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


# States in which a clone EXISTS and the sample may be executing. Cancelling
# a job in one of these is a request the worker collects, not an act -- there
# is a domain to tear down first.
RUNNING_STATES = frozenset({
    JobState.CLONING,
    JobState.PREPARING,
    JobState.EXECUTING,
    JobState.COLLECTING,
})

# States in which the worker still OWNS the job and may report on it.
#
# Wider than RUNNING_STATES by exactly one: `cleaning`. The worker is what
# runs cleanup.sh, so it holds the lease throughout -- and a job that reached
# `cleaning` still has to report where it ended up. Using RUNNING_STATES for
# this would let a worker report `cleaning` and then be locked out of saying
# `completed`, stranding every job one step from the end.
LEASED_STATES = RUNNING_STATES | {JobState.CLEANING}

# No clone exists yet, so cancelling is immediate and terminal.
PRE_CLONE_STATES = frozenset({
    JobState.RECEIVED,
    JobState.ADMITTED,
    JobState.QUEUED,
})

TERMINAL_STATES = frozenset({
    JobState.COMPLETED,
    JobState.REJECTED,
    JobState.CANCELLED,
    JobState.FAILED,
    JobState.INTERRUPTED,
})


# Reject reasons, from analysis-pipeline.md's admission list plus the two
# capacity answers DRAFT-042 added. Distinct strings because the web UI
# renders each differently -- "no analysis host has registered" and "no host
# is large enough" are different problems with different fixes, and
# collapsing them into "submission failed" is how an operator loses an hour.
class RejectReason(StrEnum):
    UNREADABLE = "unreadable"
    REJECTED_SIZE = "rejected_size"
    UNSUPPORTED_TYPE = "unsupported_type"
    NO_CAPACITY = "no_capacity"
    NO_WORKERS = "no_workers"