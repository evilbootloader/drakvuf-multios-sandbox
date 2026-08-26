"""What belongs to sandboxd, and what must never be touched.

Issue #41 (DRAFT-060).

**This module is the whole safety boundary of the startup sweep.** sandboxd
reclaims Dom0 on restart by destroying every clone it finds -- domains, LVM
snapshots, temp configs, capture processes -- because an analysis whose
orchestrator died has no timer watching it, no way to report how far it got,
and a disposable clone is not worth adopting. Retry is already an operator
decision on a NEW job id, so `interrupted` is the correct terminal state and
there is nothing to preserve.

The danger in that sentence is the word "every". These must survive any sweep:

    ubuntu            android            <- golden images
    ubuntu_sandbox    android_sandbox    <- templates the clones come from
    /dev/<vg>/ubuntu_sandbox             <- the LV a snapshot is taken OF
    <repo>/state/*.bak                   <- the saved memory images

Destroying a template means rebuilding it from the golden VM; destroying a
golden image means reinstalling the guest. CLAUDE.md forbids operating on them
at all without explicit instruction.

So the sweep never works from a list of things to spare -- a denylist is one
forgotten name away from deleting a template. It works from a positive match
on the clone grammar below, and anything that does not match is left alone
without needing to be recognised.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# `<origin>-<vlan>-clone`, fixed by clone.pl since the beginning and relied on
# by cleanup.sh, network-setup.sh and the runbooks.
#
# The origin group is deliberately the SAME character class clone.pl validates
# its origin argument against ([A-Za-z0-9._-]), which means it can itself
# contain '-'. So the vlan and the "-clone" suffix are anchored from the RIGHT
# and the origin takes whatever is left: `a-b-3-clone` is origin `a-b`, vlan 3.
# A greedy left-to-right parse would read the origin as `a` and the vlan as
# `b`, fail the integer check, and silently decline to clean up a real clone.
_CLONE = re.compile(r"\A(?P<origin>[A-Za-z0-9._-]+)-(?P<vlan>[0-9]+)-clone\Z")

# 254 because the vlan is the third octet of <prefix>.<vlan>.0/24 -- above it
# there is no gateway. network-setup.sh caps there and clone.pl validates it;
# stated once here so the three cannot drift.
MAX_VLAN = 254
MIN_VLAN = 1


@dataclass(frozen=True)
class CloneName:
    origin: str
    vlan: int

    def __str__(self) -> str:
        return f"{self.origin}-{self.vlan}-clone"


def clone_name(origin: str, vlan: int) -> str:
    """The name clone.pl has always produced. One definition, used by both the
    builder and the sweep, so a clone can never be created under a name the
    sweep would not recognise as its own."""
    if not re.fullmatch(r"[A-Za-z0-9._-]+", origin):
        raise ValueError(
            f"origin domain name may contain only [A-Za-z0-9._-], got {origin!r}"
        )
    if not MIN_VLAN <= vlan <= MAX_VLAN:
        raise ValueError(
            f"vlan must be between {MIN_VLAN} and {MAX_VLAN} "
            f"(it is the third octet of the gateway address), got {vlan}"
        )
    return str(CloneName(origin, vlan))


def parse_clone(name: str) -> CloneName | None:
    """Recognise one of ours, or None.

    None is the safe answer and is what every non-clone gets: a golden image,
    a template, Dom0 itself, an operator's scratch domain. The caller destroys
    only what this returns a value for.
    """
    m = _CLONE.match(name)
    if not m:
        return None
    vlan = int(m.group("vlan"))
    if not MIN_VLAN <= vlan <= MAX_VLAN:
        # `x-999-clone` matches the shape but cannot be one of ours -- nothing
        # can allocate that vlan. Declining to touch it is correct: it is more
        # likely a human's domain named to look like a clone than a clone.
        return None
    return CloneName(m.group("origin"), vlan)


def is_clone(name: str) -> bool:
    return parse_clone(name) is not None