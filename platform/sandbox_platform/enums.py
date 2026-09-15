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


class EgressMode(StrEnum):
    """Where a job's traffic is allowed to go. Authority: migration 0006.

    **The second untrusted routing input in the system**, and the more
    consequential one -- `target_os` picks a guest image, this decides whether
    live malware reaches the Internet and through whose address. Closed set,
    validated at the same single boundary, for the same reasons.

    Which of these a submitter may actually pick is NOT decided here. It is
    whatever the analysis host declared it can provide (`worker_egress`), so a
    mode listed in this enum and offered by no host is unselectable. That is
    what keeps `direct` off the web UI.
    """

    #: No route out at all. On Dom0 this is the absence of a rule rather than a
    #: rule, so it cannot fail to apply.
    OFFLINE = "offline"
    #: A responder on the clone's gateway answers instead of the Internet.
    SIMULATED = "simulated"
    #: Transparently through Tor. **TCP only** -- see the exit's caveats.
    TOR = "tor"
    #: Out through a tunnel to a VPS we rent, with a chosen exit country.
    ROUTED = "routed"
    #: NAT out the analysis host's own uplink. Requires the host to opt in.
    DIRECT = "direct"


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
# runs the cleanup stage, so it holds the lease throughout -- and a job that reached
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
    # No registered host offers the requested way out. Distinct from
    # no_workers for the reason the comment above gives: "no analysis host has
    # registered" and "the host is here but cannot route your sample where you
    # asked" are different problems with different fixes.
    #
    # Rejected rather than silently downgraded. A submitter asked a specific
    # question about where their sample's traffic goes; running it somewhere
    # else and reporting success answers a different question than the one on
    # the report.
    NO_EGRESS = "no_egress"

class Visibility(StrEnum):
    """Who may read a finished analysis besides its owner. Authority: 0007.

    Two values at M1 and no more. Publication is all-or-none to authenticated
    users; roles, groups and sharing with named users are out of scope for #40,
    so a third value here would be a decision taken by accident.

    `auth.visible_to` writes `'public'` as a SQL literal rather than binding
    this, because it is a fragment of a WHERE clause and not a value. The two
    must not drift.
    """

    PRIVATE = "private"
    PUBLIC = "public"
