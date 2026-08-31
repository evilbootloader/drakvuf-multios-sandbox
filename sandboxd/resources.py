"""What this host can run at once, and who is holding it.

Issue #41 (DRAFT-060).

Replaces `dirwatch.c`'s `slots_busy[128]` and `find_thread()`. That array is
**process-local**, and the thread-slot index *is* the VLAN -- so two watchers
allocate VLANs 1..N identically and share gateway addresses and isolation
rules, "with no symptom but interference". One `dirwatch` per OS plus a guard
refusing to start a second is the whole reason an Ubuntu and a Windows
submission cannot be analysed in the same window today, on a host with capacity
for both.

**One process owning every VLAN is what removes that**, and it is why
DRAFT-036's host-global allocator was dropped rather than built: with a single
allocator there is no second allocator to coordinate with. Concurrent multi-OS
analysis is a capability this delivers, not a side effect of tidier code.

## What a VLAN is here

Not a slot index that happens to be numbered. VLAN `n` means:

    xenbr1.n          the sub-interface network-setup.sh created
    172.16.n.1        the gateway Dom0 holds on it
    172.16.n.2        the address preconfig gives the clone
    <origin>-n-clone  the domain name clone.pl derives

So a VLAN is **host-global and single-tenant across OS families**. Two clones
cannot share one even if they are different guests, because they would share
the gateway. The clone *name* disambiguates the domain; the VLAN does not
stretch.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from pathlib import Path

from .naming import MAX_VLAN, MIN_VLAN

# misc/<os>_sandbox.cfg's `memory` plus a per-host domain overhead. From
# docs/architecture/platform.md, "Where required_mib comes from".
#
# **The value lives in sandboxd/config.py**, which is where an operator
# tunes this host, and which records why 150 is a guard rather than a
# measurement -- two observations from this lab disagree by an order of
# magnitude. Re-exported here because `required_mib` takes it as a default
# argument and callers pass it by name.
from .config import DOMAIN_OVERHEAD_MIB

_MEMORY = re.compile(r"^\s*memory\s*=\s*(\d+)", re.M)


def required_mib(config: Path, *, overhead: int = DOMAIN_OVERHEAD_MIB) -> int:
    """What one clone of this template costs the host.

    Read from the template's own `.cfg` rather than configured separately: the
    API cannot read Dom0's configs, and a second copy of the number on the
    platform server would recreate exactly the two-files-free-to-disagree
    failure `platform.env` exists to prevent.
    """
    text = config.read_text()
    m = _MEMORY.search(text)
    if not m:
        raise ValueError(
            f"no `memory =` line in {config}; a Xen HVM config must declare "
            f"one and its absence means this is not the file it looks like"
        )
    return int(m.group(1)) + overhead


@dataclass(frozen=True)
class Free:
    """Exactly the three numbers `POST /api/v1/worker/claim` sends.

    Derived from the table rather than tracked alongside it, so what the daemon
    reports and what it can actually satisfy cannot drift.
    """

    mib: int
    vlans: int
    slots: int


@dataclass(frozen=True)
class Held:
    job_id: str
    vlan: int
    mib: int


class Exhausted(RuntimeError):
    """Nothing left. Distinct from a refusal: the caller should not have asked.

    `acquire` returning None is the ordinary "not right now"; this is raised
    only when a caller asks for more than the host could EVER provide, which is
    a configuration error rather than a busy moment.
    """


class ResourceTable:
    """The host's analysis capacity, and who currently holds it.

    Every method takes the lock. sandboxd is one process, but it is not
    single-threaded -- the claim loop, the stage machine and the heartbeat all
    touch this -- and "report free, then allocate" is a read-then-write that is
    wrong by construction without one.
    """

    def __init__(self, *, total_mib: int, vlans, total_slots: int,
                 admitted: bool = False):
        vlan_list = sorted(set(vlans))
        if not vlan_list:
            raise ValueError("no VLANs; network-setup.sh provisions 1..MAX_CLONES")
        for v in vlan_list:
            if not MIN_VLAN <= v <= MAX_VLAN:
                raise ValueError(
                    f"vlan {v} outside {MIN_VLAN}..{MAX_VLAN}; it is the third "
                    f"octet of the gateway address"
                )
        if total_slots < 1:
            raise ValueError("total_slots must be at least 1")
        if total_mib < 1:
            raise ValueError("total_mib must be positive")

        self._total_mib = total_mib
        self._total_slots = total_slots
        # **Only VLANs network-setup.sh actually provisioned.** Handing out a
        # VLAN with no `xenbr1.<n>` and no gateway produces a clone that boots,
        # gets an address nothing routes, and looks like a sample that chose
        # not to talk. run_analysis-*.sh warns that the two numbers must match;
        # taking the range as input makes the mismatch impossible here rather
        # than documented.
        self._all_vlans = tuple(vlan_list)

        # **Withheld until something confirms the VLAN is clean.** A fresh
        # table knows the range network-setup.sh provisioned; it does not know
        # what is still ON those interfaces. Dom0 may be holding a clone from a
        # process that died mid-analysis, its LV, and a tcpdump still writing
        # to xenbr1.<n>.
        #
        # Starting them all available makes `admit()` a no-op and hands the
        # next job a VLAN whose previous domain has not finished dying -- the
        # same failure DRAFT-033 fixed inside clone.pl, where `xl restore`
        # landed on the PREVIOUS sample's snapshot. Cross-sample
        # contamination, not a crash, so nothing reports it.
        #
        # So the sweep admits each VLAN it has actually cleaned, and one it
        # could not clean stays out. The host then reports reduced capacity,
        # which is visible, instead of silently reusing a dirty VLAN.
        #
        # `admitted=True` is for tests and for a caller that has its own reason
        # to trust the range. It is never what the daemon does at startup.
        self._available = list(vlan_list) if admitted else []
        self._held: dict[str, Held] = {}

        # Plain Lock, not RLock, and the discipline that makes that safe:
        # **every public method takes this once and calls no other public
        # method.** Anything needing shared work uses a `_*_locked` helper that
        # assumes the lock is already held -- `_free_locked` is the only one so
        # far.
        #
        # RLock would make a nested call work and hide the design error. A
        # plain Lock turns it into a deadlock, which is a hang rather than an
        # exception -- so this is stated here rather than left to be discovered
        # by a daemon that stopped claiming work for no visible reason.
        self._lock = threading.Lock()

    # -- capacity ----------------------------------------------------------

    @property
    def total(self) -> Free:
        return Free(mib=self._total_mib, vlans=len(self._all_vlans),
                    slots=self._total_slots)

    def free(self) -> Free:
        with self._lock:
            return self._free_locked()

    def _free_locked(self) -> Free:
        used_mib = sum(h.mib for h in self._held.values())
        return Free(
            mib=self._total_mib - used_mib,
            vlans=len(self._available),
            slots=self._total_slots - len(self._held),
        )

    # -- allocation --------------------------------------------------------

    def acquire(self, job_id: str, need_mib: int) -> Held | None:
        """Take memory, a VLAN and a slot together, or take nothing.

        **All three or none.** A partial acquire -- memory reserved, no VLAN --
        would leave the host reporting less capacity than it has, with nothing
        running to explain it, and the next claim would be refused for a
        resource nobody is using.

        Returns None when the host is merely busy. Raises `Exhausted` when the
        request could never be satisfied, because that is a misconfiguration
        and waiting will not fix it.
        """
        if need_mib > self._total_mib:
            raise Exhausted(
                f"job needs {need_mib} MiB; this host has {self._total_mib} MiB "
                f"for clones in total and can never run it"
            )
        with self._lock:
            if job_id in self._held:
                raise ValueError(f"{job_id} already holds {self._held[job_id]}")
            free = self._free_locked()
            if free.mib < need_mib or not self._available or free.slots < 1:
                return None
            vlan = self._available.pop(0)
            held = Held(job_id=job_id, vlan=vlan, mib=need_mib)
            self._held[job_id] = held
            return held

    def release(self, job_id: str) -> Held | None:
        """Give the VLAN back. **Call this AFTER teardown, never before.**

        `dirwatch.c:697` destroys the clone and only then calls
        `release_thread()`, with the reason recorded in place: the slot index
        *is* the VLAN and the clone name, so releasing first lets another job
        begin cloning `<origin>-<vlan>-clone` while this domain is still being
        destroyed. The same ordering holds here for the same reason, and it is
        the caller's to get right -- this method cannot tell whether the domain
        is gone.

        Idempotent: a release for a job that holds nothing is not an error. The
        teardown path runs on the success path, the timeout path and the
        failure path, and making the second call fatal would turn tidy-up into
        a new failure.
        """
        with self._lock:
            held = self._held.pop(job_id, None)
            if held is None:
                return None
            # Back on the END, not the front. A VLAN that has just carried an
            # analysis is the LAST one to reuse: it maximises the gap before
            # its `xenbr1.<n>` and iptables state are reused, so a lingering
            # process or a slow teardown shows up as an idle interface rather
            # than as interference with the next sample.
            self._available.append(held.vlan)
            return held

    def admit(self, vlan: int) -> None:
        """Declare a VLAN clean and available. The sweep's only way in.

        Every VLAN starts withheld (see `__init__`), so nothing is allocatable
        until something has looked at Dom0 and confirmed there is no clone, no
        snapshot LV and no stray capture process on it. A VLAN the sweep could
        not fully clean is simply never admitted, and the host runs at reduced
        capacity until an operator sorts it out -- which is a visible cost,
        where handing it out anyway is an invisible one.

        Idempotent, because the caller is a loop over what it found and calling
        it twice for the same VLAN is not a mistake worth failing on.
        """
        with self._lock:
            if vlan not in self._all_vlans:
                # Not ours to hand out. A clone on a VLAN outside the
                # provisioned range predates a MAX_CLONES change; the sweep
                # still destroys it, but it does not become allocatable --
                # there is no `xenbr1.<n>` and no gateway for it.
                return
            if vlan in self._available:
                return
            if any(h.vlan == vlan for h in self._held.values()):
                raise ValueError(
                    f"vlan {vlan} is held by a live job; admitting it would "
                    f"hand the same gateway to two clones"
                )
            self._available.append(vlan)

    def withhold(self, vlan: int) -> bool:
        """Take a VLAN out of the pool. The counterpart to `admit`.

        For a teardown that did not finish: the domain survived `xl destroy`,
        or the LV would not release. Reusing that VLAN is what DRAFT-033
        describes -- a restore onto the previous sample's snapshot.

        Returns False if a job currently holds it, in which case the caller is
        confused about who owns what and should not be quietly obeyed.
        """
        with self._lock:
            if any(h.vlan == vlan for h in self._held.values()):
                return False
            if vlan in self._available:
                self._available.remove(vlan)
            return True

    # -- inspection ---------------------------------------------------------

    def held(self) -> list[Held]:
        with self._lock:
            return list(self._held.values())

    def holder_of(self, vlan: int) -> Held | None:
        with self._lock:
            for h in self._held.values():
                if h.vlan == vlan:
                    return h
            return None

    def live_job_ids(self) -> list[str]:
        """What `POST /worker/reconcile` is told is still running.

        After a startup sweep this is empty by construction, which is the
        intended answer: everything the previous process held was destroyed, so
        the API marks those jobs interrupted.
        """
        with self._lock:
            return list(self._held)
