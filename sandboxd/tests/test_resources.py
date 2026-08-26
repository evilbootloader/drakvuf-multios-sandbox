"""The resource table: issue #41 (DRAFT-060).

What `dirwatch.c`'s `slots_busy[128]` could not be, because it was
process-local and its index was the VLAN.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd.resources import (  # noqa: E402
    DOMAIN_OVERHEAD_MIB, Exhausted, ResourceTable, required_mib,
)

MISC = ROOT / "misc"


def table(*, total_mib=8192, vlans=range(1, 5), total_slots=4) -> ResourceTable:
    """A table whose VLANs the sweep has already admitted.

    `admitted=True` because most tests here are about allocation, not about
    startup. The withheld-by-default behaviour has its own tests below.
    """
    return ResourceTable(total_mib=total_mib, vlans=vlans,
                         total_slots=total_slots, admitted=True)


# --- required_mib, against the real templates ------------------------------

@pytest.mark.parametrize("cfg", ["ubuntu_sandbox.cfg", "android_sandbox.cfg"])
def test_required_mib_matches_the_documented_worked_example(cfg):
    """docs/architecture/platform.md:216 registers `required_mib: 2198` for
    both Ubuntu and Android. Both templates declare `memory = 2048`, so this is
    2048 + 150 -- and it is checked against the real files so the number in the
    document and the number the daemon sends cannot drift."""
    assert required_mib(MISC / cfg) == 2198


def test_the_overhead_is_above_the_direct_measurement():
    """The figure is contested: 112 MiB measured directly against ~2063 MiB
    consumed for a 2048 MiB clone. Per the project's standing preference the
    guard sits above the measured value -- a guard set below it overcommits the
    host, and the symptom is a clone that fails to restore rather than a number
    anyone reads."""
    assert DOMAIN_OVERHEAD_MIB > 112


def test_a_config_with_no_memory_line_is_refused(tmp_path):
    cfg = tmp_path / "not-a-domain.cfg"
    cfg.write_text("name = 'x'\n")
    with pytest.raises(ValueError, match="memory"):
        required_mib(cfg)


# --- the capability dirwatch structurally cannot deliver -------------------

def test_two_os_families_hold_vlans_at_the_same_time():
    """The headline of #41. `dirwatch` takes one origin per invocation and two
    instances cannot run, because the slot array is process-local and the slot
    index IS the VLAN -- so an Ubuntu and a Windows submission cannot be
    analysed in the same window on a host with capacity for both."""
    t = table(total_mib=16384)

    ubuntu = t.acquire("job-ubuntu", 2198)
    windows = t.acquire("job-windows", 6294)
    android = t.acquire("job-android", 2198)

    assert None not in (ubuntu, windows, android)
    assert len({ubuntu.vlan, windows.vlan, android.vlan}) == 3


def test_a_vlan_is_single_tenant_across_os_families():
    """VLAN n is xenbr1.n, 172.16.n.1 and 172.16.n.2 -- one gateway. Two clones
    cannot share it even as different guests."""
    t = table(vlans=[7])

    first = t.acquire("a", 1024)
    assert first.vlan == 7
    assert t.acquire("b", 1024) is None, "the only VLAN was handed out twice"


# --- allocation is all-or-nothing -----------------------------------------

def test_memory_exhaustion_takes_no_vlan():
    """A partial acquire would leave the host reporting less capacity than it
    has with nothing running to explain it, and the next claim refused for a
    resource nobody is using."""
    t = table(total_mib=4096, vlans=range(1, 5))
    t.acquire("big", 4000)

    before = t.free()
    assert t.acquire("another", 2198) is None
    assert t.free() == before


def test_slot_exhaustion_takes_no_vlan_or_memory():
    t = table(total_mib=65536, vlans=range(1, 9), total_slots=2)
    t.acquire("a", 100)
    t.acquire("b", 100)

    before = t.free()
    assert t.acquire("c", 100) is None
    assert t.free() == before


def test_a_job_larger_than_the_host_is_a_configuration_error():
    """Distinct from busy: waiting will not fix it, so it raises rather than
    returning None and being retried forever."""
    t = table(total_mib=4096)
    with pytest.raises(Exhausted, match="can never run it"):
        t.acquire("windows", 6294)


def test_free_reports_what_claim_would_send():
    """These are exactly the three numbers POST /worker/claim carries, derived
    from the table rather than tracked beside it so they cannot drift from what
    it can actually satisfy."""
    t = table(total_mib=8192, vlans=range(1, 5), total_slots=4)
    assert t.free() == t.total

    t.acquire("a", 2198)

    free = t.free()
    assert (free.mib, free.vlans, free.slots) == (8192 - 2198, 3, 3)


# --- release ordering, which is where the collision lives ------------------

def test_a_vlan_is_not_reusable_until_released():
    t = table(vlans=[1])
    t.acquire("a", 100)

    assert t.acquire("b", 100) is None
    t.release("a")
    assert t.acquire("b", 100) is not None


def test_a_released_vlan_goes_to_the_back_of_the_queue():
    """The VLAN that just carried an analysis is the LAST to reuse. It
    maximises the gap before its xenbr1.<n> and iptables state are reused, so a
    lingering process or a slow teardown shows up as an idle interface rather
    than as interference with the next sample."""
    t = table(vlans=[1, 2, 3])
    first = t.acquire("a", 100)
    t.acquire("b", 100)
    t.release("a")

    assert t.acquire("c", 100).vlan != first.vlan


def test_releasing_twice_is_not_an_error():
    """Teardown runs on the success path, the timeout path and the failure
    path. Making the second call fatal turns tidy-up into a new failure."""
    t = table()
    t.acquire("a", 100)

    assert t.release("a") is not None
    assert t.release("a") is None


def test_a_job_cannot_hold_twice():
    t = table()
    t.acquire("a", 100)
    with pytest.raises(ValueError, match="already holds"):
        t.acquire("a", 100)


# --- only what network-setup.sh provisioned -------------------------------

def test_only_provisioned_vlans_are_handed_out():
    """Handing out a VLAN with no xenbr1.<n> and no gateway produces a clone
    that boots, gets an address nothing routes, and reads as a sample that
    chose not to talk. run_analysis-*.sh warns the two numbers must match;
    taking the range as input makes the mismatch impossible."""
    t = table(vlans=[5, 6])

    got = {t.acquire(f"j{i}", 100).vlan for i in range(2)}

    assert got == {5, 6}
    assert t.acquire("j2", 100) is None


@pytest.mark.parametrize("bad", [0, 255, -1, 1000])
def test_a_vlan_outside_the_gateway_range_is_refused(bad):
    with pytest.raises(ValueError, match="third octet|outside"):
        ResourceTable(total_mib=4096, vlans=[bad], total_slots=1)


def test_an_empty_vlan_range_is_refused():
    with pytest.raises(ValueError, match="no VLANs"):
        ResourceTable(total_mib=4096, vlans=[], total_slots=1)


# --- nothing is usable until the sweep says so -----------------------------
#
# The default is withheld, and that is the whole point of `admit`. An earlier
# version of this table started every VLAN available, which made `admit` a
# no-op in exactly the case it was written for -- dead code with a docstring.

def test_a_fresh_table_hands_out_nothing():
    """A fresh table knows the range network-setup.sh provisioned. It does not
    know what is still ON those interfaces: Dom0 may be holding a clone from a
    process that died mid-analysis, its snapshot LV, and a tcpdump still
    writing to xenbr1.<n>."""
    t = ResourceTable(total_mib=8192, vlans=range(1, 5), total_slots=4)

    assert t.free().vlans == 0
    assert t.acquire("a", 100) is None
    # The memory and slots are real; it is the VLANs that are unproven.
    assert t.free().mib == 8192


def test_the_sweep_admits_what_it_cleaned():
    t = ResourceTable(total_mib=8192, vlans=range(1, 5), total_slots=4)

    for vlan in (1, 2, 3, 4):
        t.admit(vlan)

    assert t.free().vlans == 4
    assert t.acquire("a", 100) is not None


def test_a_vlan_the_sweep_could_not_clean_is_never_handed_out():
    """The reason the default is withheld rather than available.

    If the sweep cannot destroy `ubuntu_sandbox-3-clone` -- a wedged domain, an
    LV that will not release -- then handing VLAN 3 to the next job restores
    onto a snapshot whose previous domain is still alive. That is DRAFT-033's
    cross-sample contamination: not a crash, so nothing reports it.

    Running at reduced capacity is a visible cost. Reusing a dirty VLAN is an
    invisible one.
    """
    t = ResourceTable(total_mib=8192, vlans=[1, 2, 3], total_slots=4)
    t.admit(1)
    t.admit(2)
    # 3 is deliberately not admitted: its clone survived the sweep.

    got = set()
    while (held := t.acquire(f"j{len(got)}", 100)) is not None:
        got.add(held.vlan)

    assert got == {1, 2}
    assert 3 not in got


def test_withhold_takes_a_vlan_back_out():
    """For a teardown that did not finish after the daemon was already
    running -- the domain survived `xl destroy`, or the LV would not
    release."""
    t = table(vlans=[1, 2])

    assert t.withhold(1) is True

    got = {t.acquire(f"j{i}", 100).vlan for i in range(1)}
    assert got == {2}
    assert t.acquire("x", 100) is None


def test_withholding_a_vlan_a_job_holds_is_refused():
    """The caller is confused about who owns what, and should not be quietly
    obeyed: the VLAN would be dropped from the pool while a live analysis is
    still using its gateway."""
    t = table(vlans=[1, 2])
    held = t.acquire("a", 100)

    assert t.withhold(held.vlan) is False


# --- the sweep's hand-back -------------------------------------------------

def test_admitting_a_released_vlan_does_not_double_add_it():
    """`release` already returns the VLAN to the pool, so a later `admit` for
    the same one must be a no-op rather than putting it in twice -- which would
    hand the same gateway to two clones."""
    t = table(vlans=[1, 2])
    t.acquire("a", 100)
    t.release("a")

    t.admit(1)
    t.admit(1)

    assert t.free().vlans == 2
    got = {t.acquire(f"j{i}", 100).vlan for i in range(2)}
    assert got == {1, 2}
    assert t.acquire("x", 100) is None


def test_admitting_a_vlan_outside_the_range_does_not_add_it():
    """A clone found on a VLAN outside the provisioned range predates a
    MAX_CLONES change. The sweep still destroys it; it does not thereby become
    allocatable."""
    t = table(vlans=[1, 2])
    t.admit(9)

    assert t.free().vlans == 2
    assert {t.acquire(f"j{i}", 100).vlan for i in range(2)} == {1, 2}


def test_admitting_a_vlan_a_live_job_holds_is_refused():
    """A sweep that reclaimed a VLAN belonging to a running analysis has
    destroyed a live clone. Better to raise than to hand it out twice."""
    t = table(vlans=[1, 2])
    held = t.acquire("a", 100)

    with pytest.raises(ValueError, match="held by a live job"):
        t.admit(held.vlan)


def test_admitting_an_already_free_vlan_is_idempotent():
    t = table(vlans=[1, 2])
    t.admit(1)
    t.admit(1)
    assert t.free().vlans == 2


# --- concurrency -----------------------------------------------------------

def test_a_vlan_is_never_handed_to_two_threads():
    """The claim loop, the stage machine and the heartbeat all touch this.
    'Report free, then allocate' is a read-then-write that is wrong by
    construction without a lock -- which is the same class of bug as the
    process-local slot array, one scope smaller."""
    t = table(total_mib=1_000_000, vlans=range(1, 51), total_slots=50)
    got = []
    barrier = threading.Barrier(50)

    def claim(i):
        barrier.wait()
        held = t.acquire(f"job-{i}", 100)
        if held:
            got.append(held.vlan)

    threads = [threading.Thread(target=claim, args=(i,)) for i in range(50)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    assert len(got) == 50
    assert len(set(got)) == 50, "a VLAN was handed out twice"


def test_live_job_ids_is_what_reconcile_is_told():
    t = table()
    t.acquire("a", 100)
    t.acquire("b", 100)

    assert sorted(t.live_job_ids()) == ["a", "b"]

    t.release("a")
    assert t.live_job_ids() == ["b"]
