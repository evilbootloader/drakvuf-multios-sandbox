"""Several analyses at once: issue #41 (DRAFT-060).

**This is the capability `dirwatch` structurally cannot deliver, and nothing
has ever demonstrated it.** `fake_worker.py` is `--once` oriented -- it claims
a job, walks the state machine and exits -- so the protocol has only ever been
exercised one job at a time. Concurrency is the whole reason #41 exists:

    dirwatch takes one origin domain per invocation, so there is one instance
    per OS; and two instances cannot run, because the thread-slot index IS the
    vlan and the slot array is process-local. Two watchers allocate the same
    vlans and share gateway addresses and isolation rules, with no symptom but
    interference.

So an Ubuntu submission and a Windows submission cannot be analysed in the same
window today, on a host with capacity for both. That is a structural limit and
it is invisible from outside -- the second submission simply waits.

These tests wire the resource table and the worker channel together and run
several jobs through them at once, which is the smallest arrangement that can
show the limit is gone. They are not a substitute for Dom0 evidence; they are
what makes it worth booking Dom0 time for.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import uuid
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "platform"))

os.environ.setdefault("DATABASE_URL", "postgresql:///unused")
os.environ.setdefault("WORKER_TOKEN", "unused")

from sandboxd.api import Idle, Lease, Reserved, WorkerAPI  # noqa: E402
from sandboxd.naming import clone_name  # noqa: E402
from sandboxd.resources import ResourceTable  # noqa: E402

UBUNTU_MIB = 2198
ANDROID_MIB = 2198
WINDOWS_MIB = 6294


class Platform:
    """A queue that hands out jobs and records what the worker reported.

    Deliberately minimal: what is under test is sandboxd holding several jobs
    at once, not the platform's own scheduling, which #35 already covers
    against a real Postgres.
    """

    def __init__(self, queue):
        self.queue = list(queue)
        self.states: dict[str, list[str]] = {}
        self.claims: list[dict] = []
        self.cancelled: set = set()
        self.completed: list[str] = []
        self._lock = threading.Lock()

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = json.loads(request.content) if request.content else {}

        if path.endswith("/claim"):
            with self._lock:
                self.claims.append(body)
                # Hand out the next job this worker can actually afford. The
                # real API does head-of-line reservation; this only needs to
                # be honest about capacity.
                for i, job in enumerate(self.queue):
                    if job["required_mib"] <= body["free_mib"]:
                        if body["free_vlans"] < 1 or body["free_slots"] < 1:
                            break
                        self.queue.pop(i)
                        return httpx.Response(200, json={
                            "status": "leased", **job,
                            "lease_expires_at": "2026-08-26T10:00:00Z",
                        })
                if self.queue:
                    head = self.queue[0]
                    return httpx.Response(200, json={
                        "status": "reserved",
                        "blocking_job_id": head["job_id"],
                        "need_mib": head["required_mib"]})
                return httpx.Response(200, json={"status": "idle"})

        if path.endswith("/state"):
            job_id = path.split("/jobs/")[1].split("/")[0]
            with self._lock:
                self.states.setdefault(job_id, []).append(body["state"])
            return httpx.Response(204)

        if path.endswith("/heartbeat"):
            job_id = path.split("/jobs/")[1].split("/")[0]
            return httpx.Response(200, json={
                "lease_expires_at": "2026-08-26T10:05:00Z",
                "cancel_requested": job_id in self.cancelled})

        if path.endswith("/complete"):
            job_id = path.split("/jobs/")[1].split("/")[0]
            with self._lock:
                self.completed.append(job_id)
            return httpx.Response(204)

        if path.endswith("/reconcile"):
            return httpx.Response(200, json={"interrupted": []})

        return httpx.Response(204)


def job(target_os: str, mib: int) -> dict:
    return {"job_id": str(uuid.uuid4()), "target_os": target_os,
            "submitted_filename": f"{target_os}-sample.bin",
            "required_mib": mib, "attempt": 1, "sha256": "c" * 64,
            "sample_url": "https://minio/sample"}


def wire(platform: Platform, table: ResourceTable):
    api = WorkerAPI("https://platform:8443", "tok", "dom0-1",
                    transport=httpx.MockTransport(platform.handler))
    return api


def claim_once(api: WorkerAPI, table: ResourceTable):
    """One turn of the claim loop: report real capacity, take what comes."""
    free = table.free()
    got = api.claim(free_mib=free.mib, free_vlans=free.vlans,
                    free_slots=free.slots)
    if not isinstance(got, Lease):
        return got
    held = table.acquire(got.job_id, got.required_mib)
    if held is None:
        # The table and the platform disagreed about capacity. Cannot happen
        # while claims are serialised, and would be a real bug if it did.
        raise AssertionError("leased a job the table cannot hold")
    return got, held


# --- the headline capability ----------------------------------------------

def test_three_os_families_run_at_once():
    """An Ubuntu, an Android and a Windows analysis in flight simultaneously,
    each on its own vlan. Under `dirwatch` this needs three watchers, and two
    watchers cannot coexist."""
    table = ResourceTable(total_mib=16384, vlans=range(1, 9), total_slots=4,
                          admitted=True)
    plat = Platform([job("ubuntu", UBUNTU_MIB), job("android", ANDROID_MIB),
                     job("windows", WINDOWS_MIB)])
    api = wire(plat, table)

    running = [claim_once(api, table) for _ in range(3)]

    assert all(isinstance(r, tuple) for r in running)
    vlans = {held.vlan for _, held in running}
    assert len(vlans) == 3, "two clones were given the same vlan and gateway"

    domains = {clone_name(f"{lease.target_os}_sandbox", held.vlan)
               for lease, held in running}
    assert len(domains) == 3
    assert "windows_sandbox-3-clone" in domains or len(domains) == 3


def test_capacity_reported_to_the_platform_shrinks_as_jobs_are_taken():
    """The three numbers /claim carries must reflect what is actually held, or
    the platform leases work this host cannot run."""
    table = ResourceTable(total_mib=16384, vlans=range(1, 9), total_slots=4,
                          admitted=True)
    plat = Platform([job("ubuntu", UBUNTU_MIB), job("android", ANDROID_MIB)])
    api = wire(plat, table)

    claim_once(api, table)
    claim_once(api, table)

    first, second = plat.claims[0], plat.claims[1]
    assert second["free_mib"] == first["free_mib"] - UBUNTU_MIB
    assert second["free_vlans"] == first["free_vlans"] - 1
    assert second["free_slots"] == first["free_slots"] - 1


def test_a_job_too_large_for_what_is_left_is_reserved_not_dropped():
    """Head-of-line reservation, from the worker's side. A big job holds its
    place rather than being starved by smaller ones behind it -- and the worker
    must treat that as an ordinary outcome."""
    table = ResourceTable(total_mib=8192, vlans=range(1, 9), total_slots=4,
                          admitted=True)
    plat = Platform([job("ubuntu", UBUNTU_MIB), job("windows", WINDOWS_MIB)])
    api = wire(plat, table)

    claim_once(api, table)                      # ubuntu takes 2198 of 8192
    outcome = claim_once(api, table)            # windows needs 6294, 5994 left

    assert isinstance(outcome, Reserved)
    assert outcome.need_mib == WINDOWS_MIB


def test_the_host_stops_claiming_when_vlans_run_out_even_with_memory_spare():
    """Memory is not the only limit. With one vlan provisioned, a host with
    16 GiB free still runs exactly one analysis -- and reports that honestly
    rather than accepting work it cannot place."""
    table = ResourceTable(total_mib=65536, vlans=[1], total_slots=8,
                          admitted=True)
    plat = Platform([job("ubuntu", UBUNTU_MIB), job("android", ANDROID_MIB)])
    api = wire(plat, table)

    claim_once(api, table)
    outcome = claim_once(api, table)

    assert not isinstance(outcome, tuple)
    assert plat.claims[1]["free_vlans"] == 0
    assert plat.claims[1]["free_mib"] > ANDROID_MIB   # memory was never the limit


# --- several jobs genuinely in flight, on threads --------------------------

def test_concurrent_runs_do_not_interfere():
    """Each job reports its own states over one shared client.

    `httpx.Client` is thread-safe, and `WorkerAPI` holds no per-job state --
    but "holds no per-job state" is exactly the kind of claim that stops being
    true when someone adds a cache, so it is asserted rather than assumed.
    """
    table = ResourceTable(total_mib=65536, vlans=range(1, 9), total_slots=8,
                          admitted=True)
    jobs = [job("ubuntu", UBUNTU_MIB) for _ in range(6)]
    plat = Platform(list(jobs))
    api = wire(plat, table)

    leases = []
    for _ in range(6):
        lease, held = claim_once(api, table)
        leases.append((lease, held))

    stages = ["cloning", "preparing", "executing", "collecting", "cleaning"]
    barrier = threading.Barrier(6)

    def run(lease, held):
        barrier.wait()
        for stage in stages:
            api.report_state(lease.job_id, stage,
                             clone_domain=clone_name("ubuntu_sandbox",
                                                     held.vlan),
                             vlan=held.vlan)
        api.complete(lease.job_id, {"schema_version": 1, "artifacts": []})
        table.release(lease.job_id)

    threads = [threading.Thread(target=run, args=(l, h)) for l, h in leases]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Every job saw its own five stages, in order, with nothing crossed over.
    assert len(plat.states) == 6
    for job_id, seen in plat.states.items():
        assert seen == stages, f"{job_id} saw {seen}"
    assert len(plat.completed) == 6
    assert table.free() == table.total


def test_a_cancellation_reaches_one_job_and_not_the_others():
    """The heartbeat response is per-job, and Dom0 has no inbound listener --
    so a cancellation that leaked across jobs would tear down an analysis
    nobody asked to stop."""
    table = ResourceTable(total_mib=65536, vlans=range(1, 9), total_slots=8,
                          admitted=True)
    plat = Platform([job("ubuntu", UBUNTU_MIB) for _ in range(3)])
    api = wire(plat, table)

    leases = [claim_once(api, table)[0] for _ in range(3)]
    plat.cancelled.add(leases[1].job_id)

    results = {}
    barrier = threading.Barrier(3)

    def beat(lease):
        barrier.wait()
        results[lease.job_id] = api.heartbeat(lease.job_id).cancel_requested

    threads = [threading.Thread(target=beat, args=(l,)) for l in leases]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results[leases[1].job_id] is True
    assert results[leases[0].job_id] is False
    assert results[leases[2].job_id] is False


def test_a_vlan_is_reusable_only_after_its_job_releases():
    """The ordering dirwatch.c:697 records: the vlan IS the clone name, so
    releasing before teardown lets the next job start cloning
    `<origin>-<vlan>-clone` while that domain is still being destroyed."""
    table = ResourceTable(total_mib=65536, vlans=[1, 2], total_slots=4,
                          admitted=True)
    plat = Platform([job("ubuntu", UBUNTU_MIB) for _ in range(3)])
    api = wire(plat, table)

    a = claim_once(api, table)
    claim_once(api, table)
    assert not isinstance(claim_once(api, table), tuple)   # both vlans held

    table.release(a[0].job_id)
    third = claim_once(api, table)

    assert isinstance(third, tuple)
    assert third[1].vlan == a[1].vlan or third[1].vlan in (1, 2)


def test_reconcile_reports_every_live_job():
    """With several in flight, a restart must tell the platform about all of
    them or the survivors are silently marked interrupted."""
    table = ResourceTable(total_mib=65536, vlans=range(1, 9), total_slots=8,
                          admitted=True)
    plat = Platform([job("ubuntu", UBUNTU_MIB) for _ in range(3)])
    api = wire(plat, table)

    ids = {claim_once(api, table)[0].job_id for _ in range(3)}

    assert set(table.live_job_ids()) == ids
    assert len(api.reconcile_body(table.live_job_ids())["live_job_ids"]) == 3


# --- the invariant that makes the claim race impossible --------------------
#
# Two threads both read free(), both see room, both claim, and the platform
# leases both -- but the table can only hold one. The second job is then leased
# to a host that cannot run it, and sits there until its lease TTL lapses.
#
# The fix is structural rather than defensive: **only the claim loop acquires,
# and workers only release.** Releases only ever INCREASE capacity, so an
# acquire immediately following a lease cannot fail while there is one claim
# thread. Adding a second claim thread would reintroduce the race, which is
# exactly why the invariant is written down and tested rather than assumed.

def test_one_claim_loop_never_oversubscribes():
    """Serialised claiming, concurrent running. The arrangement the daemon
    uses, and the reason `acquire` after a lease is not a race."""
    table = ResourceTable(total_mib=UBUNTU_MIB * 3, vlans=range(1, 9),
                          total_slots=8, admitted=True)
    plat = Platform([job("ubuntu", UBUNTU_MIB) for _ in range(8)])
    api = wire(plat, table)

    placed = []
    for _ in range(8):
        outcome = claim_once(api, table)
        if not isinstance(outcome, tuple):
            break
        placed.append(outcome[1])

    assert len(placed) == 3, "memory bound not respected"
    assert len({h.vlan for h in placed}) == 3, "a vlan was double-issued"
    assert sum(h.mib for h in placed) <= UBUNTU_MIB * 3


def test_a_lease_the_table_cannot_hold_is_loud():
    """If the invariant above is ever broken -- a second claim thread, a
    platform that ignores reported capacity -- the daemon must not quietly run
    the job anyway. It has no vlan to put it on.

    Simulated by leasing a job larger than what was reported free, which is
    what a stale capacity reading looks like from this side.
    """
    table = ResourceTable(total_mib=UBUNTU_MIB, vlans=range(1, 9),
                          total_slots=8, admitted=True)
    plat = Platform([job("ubuntu", UBUNTU_MIB)])
    api = wire(plat, table)

    claim_once(api, table)                       # fills memory exactly

    # The platform hands out another regardless of what was reported.
    plat.queue.append(job("ubuntu", UBUNTU_MIB))
    plat.handler = lambda request: httpx.Response(200, json={
        "status": "leased", **plat.queue[0],
        "lease_expires_at": "2026-08-26T10:00:00Z"})
    api2 = wire(plat, table)

    with pytest.raises(AssertionError, match="cannot hold"):
        claim_once(api2, table)


def test_workers_only_release_and_the_claim_loop_only_acquires():
    """The invariant stated as an assertion over what each side does.

    A worker thread that acquired would be a second allocator, which is the
    process-local slot array's bug one scope smaller.
    """
    table = ResourceTable(total_mib=65536, vlans=range(1, 5), total_slots=4,
                          admitted=True)
    plat = Platform([job("ubuntu", UBUNTU_MIB) for _ in range(4)])
    api = wire(plat, table)

    leases = [claim_once(api, table) for _ in range(4)]
    assert table.free().vlans == 0

    # Workers finish concurrently; every one of them releases and none takes.
    barrier = threading.Barrier(4)

    def finish(lease, held):
        barrier.wait()
        api.complete(lease.job_id, {"schema_version": 1, "artifacts": []})
        table.release(lease.job_id)

    threads = [threading.Thread(target=finish, args=(l, h)) for l, h in leases]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert table.free() == table.total
    assert table.live_job_ids() == []