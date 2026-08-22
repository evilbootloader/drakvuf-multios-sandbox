"""Queue behaviour, against a real Postgres.

Issue #35 (DRAFT-042).

The numbers are not invented. 6294 MiB is a Windows clone (misc/windows.cfg's
memory = 6144 plus a per-host domain overhead); 2198 is Ubuntu and Android
(2048 + the same). 5082 is what was actually free on Dom0 during the
2026-08-20 measurement -- 12082 total minus a 7000 reserve. Test 1 is that
measurement inverted, so a regression reads as the failure it actually was.
"""

from __future__ import annotations

import threading

import psycopg
import pytest

from conftest import DSN, count_in_state, enqueue, state_of
from sandbox_platform import jobs

WINDOWS_MIB = 6294
SMALL_MIB = 2198
FREE_MIB = 5082          # fits a small job, never a Windows one


# --- the reason this issue exists -----------------------------------------

def test_head_of_line_holds_the_queue(conn):
    """A head that does not fit blocks everything behind it.

    The 2026-08-20 measurement, inverted. Greedy admission returned a smaller
    job here 170 times in a row while the large one never ran.
    """
    big = enqueue(conn, "windows", WINDOWS_MIB)
    small = [enqueue(conn, "ubuntu", SMALL_MIB) for _ in range(12)]

    result = jobs.claim(conn, worker_id="w1", free_mib=FREE_MIB)

    assert isinstance(result, jobs.Reserved)
    assert result.blocking_job_id == big
    assert result.need_mib == WINDOWS_MIB

    # The half that actually matters: nothing behind the head moved. Asserting
    # only "returned Reserved" would pass against an implementation that
    # reserved AND leaked a small job.
    assert count_in_state(conn, "queued") == 13
    assert all(state_of(conn, j) == "queued" for j in small)


def test_head_of_line_releases_when_capacity_allows(conn):
    """Once the head fits it goes FIRST, ahead of older-fitting smaller jobs."""
    big = enqueue(conn, "windows", WINDOWS_MIB)
    for _ in range(12):
        enqueue(conn, "ubuntu", SMALL_MIB)

    result = jobs.claim(conn, worker_id="w1", free_mib=WINDOWS_MIB)

    assert isinstance(result, jobs.Lease)
    assert result.job_id == big
    assert state_of(conn, big) == "cloning"
    assert count_in_state(conn, "queued") == 12


def test_empty_queue_is_idle_not_reserved(conn):
    """Idle and Reserved must stay distinguishable -- see jobs.ClaimResult."""
    assert isinstance(jobs.claim(conn, worker_id="w1", free_mib=FREE_MIB), jobs.Idle)


# --- concurrency ----------------------------------------------------------

def test_one_job_is_never_issued_twice(conn):
    """N workers race for a single queued job; exactly one wins.

    Real threads on separate connections, released together by a barrier. Run
    sequentially this passes against a broken implementation.
    """
    enqueue(conn, "ubuntu", SMALL_MIB)

    workers = 8
    barrier = threading.Barrier(workers)
    results: list[jobs.ClaimResult] = []
    lock = threading.Lock()

    def worker(n: int) -> None:
        with psycopg.connect(DSN, autocommit=True) as c:
            barrier.wait()
            r = jobs.claim(c, worker_id=f"w{n}", free_mib=FREE_MIB)
            with lock:
                results.append(r)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    leases = [r for r in results if isinstance(r, jobs.Lease)]
    assert len(leases) == 1, f"expected exactly one lease, got {len(leases)}"
    assert count_in_state(conn, "cloning") == 1


def test_claim_and_transition_commit_together(conn):
    """A rolled-back claim leaves no trace -- never a lease on a queued job."""
    job = enqueue(conn, "ubuntu", SMALL_MIB)

    with psycopg.connect(DSN) as c:          # NOT autocommit
        jobs.claim(c, worker_id="w1", free_mib=FREE_MIB)
        c.rollback()

    with conn.cursor() as cur:
        cur.execute(
            "SELECT state, lease_owner, attempt FROM jobs WHERE id = %s", (job,)
        )
        state, lease_owner, attempt = cur.fetchone()

    assert (state, lease_owner, attempt) == ("queued", None, 0)


# --- cancellation ---------------------------------------------------------

def test_cancel_queued_is_immediate(conn):
    """The operation DRAFT-040 recorded as unexpressible. One statement."""
    job = enqueue(conn, "ubuntu", SMALL_MIB)

    assert jobs.cancel(conn, job) == "cancelled"
    assert state_of(conn, job) == "cancelled"

    with conn.cursor() as cur:
        cur.execute(
            "SELECT clone_domain, vlan, lease_owner FROM jobs WHERE id = %s", (job,)
        )
        assert cur.fetchone() == (None, None, None)   # no clone ever existed


def test_cancel_running_requests_only(conn):
    """A running job keeps its state; the worker collects the request."""
    enqueue(conn, "ubuntu", SMALL_MIB)
    lease = jobs.claim(conn, worker_id="w1", free_mib=FREE_MIB)
    assert isinstance(lease, jobs.Lease)

    assert jobs.cancel(conn, lease.job_id) == "cancel_requested"
    assert state_of(conn, lease.job_id) == "cloning"

    with conn.cursor() as cur:
        cur.execute("SELECT cancel_requested FROM jobs WHERE id = %s", (lease.job_id,))
        assert cur.fetchone()[0] is True


def test_cancelled_head_does_not_block_the_queue(conn):
    """A cancelled job must stop being the head, not become a permanent one."""
    big = enqueue(conn, "windows", WINDOWS_MIB)
    small = enqueue(conn, "ubuntu", SMALL_MIB)

    jobs.cancel(conn, big)
    result = jobs.claim(conn, worker_id="w1", free_mib=FREE_MIB)

    assert isinstance(result, jobs.Lease)
    assert result.job_id == small


def test_cancel_terminal_job_is_not_an_error(conn):
    job = enqueue(conn, "ubuntu", SMALL_MIB)
    jobs.cancel(conn, job)
    assert jobs.cancel(conn, job) == "not_cancellable"


# --- lease expiry ---------------------------------------------------------

def test_lease_expiry_marks_interrupted_and_frees_nothing(conn):
    """Bookkeeping expires. Nothing on the analysis host is implied freed."""
    enqueue(conn, "ubuntu", SMALL_MIB)
    lease = jobs.claim(conn, worker_id="w1", free_mib=FREE_MIB, lease_seconds=0)
    assert isinstance(lease, jobs.Lease)

    with conn.cursor() as cur:      # pretend a clone was recorded
        cur.execute(
            "UPDATE jobs SET clone_domain = 'ubuntu_sandbox-1-clone', vlan = 1 "
            "WHERE id = %s", (lease.job_id,)
        )

    assert jobs.reap(conn) == [lease.job_id]

    with conn.cursor() as cur:
        cur.execute(
            "SELECT state, failure_reason, clone_domain, vlan FROM jobs WHERE id = %s",
            (lease.job_id,),
        )
        state, reason, domain, vlan = cur.fetchone()

    assert (state, reason) == ("interrupted", "lease_expired")
    # The host's allocation record is untouched: reconciliation against
    # `xl list` decides, not this sweep.
    assert (domain, vlan) == ("ubuntu_sandbox-1-clone", 1)


def test_reconcile_interrupts_only_unlisted_jobs(conn):
    for _ in range(2):
        enqueue(conn, "ubuntu", SMALL_MIB)
    a = jobs.claim(conn, worker_id="w1", free_mib=FREE_MIB)
    b = jobs.claim(conn, worker_id="w1", free_mib=FREE_MIB)
    assert isinstance(a, jobs.Lease) and isinstance(b, jobs.Lease)

    interrupted = jobs.reconcile(conn, worker_id="w1", live_job_ids=[a.job_id])

    assert interrupted == [b.job_id]
    assert state_of(conn, a.job_id) == "cloning"
    assert state_of(conn, b.job_id) == "interrupted"


# --- admission capacity ---------------------------------------------------

def test_no_workers_is_distinct_from_no_capacity(conn):
    """A fresh install refuses submissions, and must say why accurately."""
    assert jobs.capacity_for(conn, "windows").reject_reason == "no_workers"

    jobs.register_worker(
        conn, worker_id="dom0-lab", total_mib=12082, total_vlans=8, total_slots=2,
        pipelines={"ubuntu": SMALL_MIB, "android": SMALL_MIB, "windows": WINDOWS_MIB},
    )
    assert jobs.capacity_for(conn, "windows").reject_reason is None


def test_job_no_host_can_afford_is_rejected_not_queued(conn):
    """Otherwise it sits at the head forever and holds everything behind it."""
    jobs.register_worker(
        conn, worker_id="small-host", total_mib=4096, total_vlans=8, total_slots=2,
        pipelines={"ubuntu": SMALL_MIB, "windows": WINDOWS_MIB},
    )
    assert jobs.capacity_for(conn, "windows").reject_reason == "no_capacity"
    assert jobs.capacity_for(conn, "ubuntu").reject_reason is None


def test_registration_is_idempotent_and_updates_capacity(conn):
    """A worker re-registers on every restart, and its capacity may change."""
    for total in (8192, 12082):
        jobs.register_worker(
            conn, worker_id="dom0-lab", total_mib=total, total_vlans=8,
            total_slots=2, pipelines={"windows": WINDOWS_MIB},
        )
    with conn.cursor() as cur:
        cur.execute("SELECT count(*), max(total_mib) FROM workers")
        assert cur.fetchone() == (1, 12082)


# --- input hostility ------------------------------------------------------

@pytest.mark.parametrize("name", [
    '"; rm -rf / #',
    "$(whoami).sh",
    "`id`.bin",
    "a b\tc.exe",
    "'; DROP TABLE jobs; --",
    "<script>alert(1)</script>.exe",
    "‮exe.txt",              # right-to-left override
])
def test_hostile_filenames_round_trip_byte_exact(conn, name):
    """The name must reach the guest unchanged -- DRAFT-030's reason for
    abandoning hash-named guest files. Storage must not normalise it."""
    job = enqueue(conn, "windows", WINDOWS_MIB, filename=name)
    lease = jobs.claim(conn, worker_id="w1", free_mib=WINDOWS_MIB)

    assert isinstance(lease, jobs.Lease)
    assert lease.job_id == job
    assert lease.submitted_filename == name