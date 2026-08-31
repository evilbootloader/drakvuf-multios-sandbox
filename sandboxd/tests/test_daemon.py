"""The daemon loop: issue #41 (DRAFT-060).

Startup ordering, the claim loop's single-acquirer invariant, and shutdown.
Everything Dom0 and the platform is faked; what is under test is the sequence.
"""

from __future__ import annotations

import hashlib
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd import api as A  # noqa: E402
from sandboxd import config as C  # noqa: E402
from sandboxd import daemon as D  # noqa: E402
from sandboxd import timing as T  # noqa: E402
from sandboxd.api import Idle, Lease, ProtocolError, Reserved  # noqa: E402
from sandboxd.stages import Config  # noqa: E402
from sandboxd.tests.fake import FakeRunner  # noqa: E402

#: The bytes the fake store serves. Its digest is what a lease declares, so
#: the fake's verification passes for the same reason the real one does.
SAMPLE = b"\x7fELF" + b"\x00" * 60

XL_EMPTY = "Name      ID   Mem VCPUs\tState\tTime(s)\nDomain-0   0  4096  4  r----- 1.0\n"
LVS_EMPTY = "  root\n  ubuntu_sandbox\n  android_sandbox\n"


@dataclass
class FakeApi:
    """Records the conversation and hands out a scripted queue."""

    queue: list = field(default_factory=list)
    registered: dict | None = None
    reconciled: list | None = None
    claims: list = field(default_factory=list)
    states: list = field(default_factory=list)
    interrupted: list = field(default_factory=list)
    manifests: list = field(default_factory=list)
    refuse_claim: bool = False

    def register(self, **kw):
        self.registered = kw

    def reconcile(self, live_job_ids):
        self.reconciled = list(live_job_ids)
        return self.interrupted

    def claim(self, *, free_mib, free_vlans, free_slots):
        self.claims.append({"free_mib": free_mib, "free_vlans": free_vlans,
                            "free_slots": free_slots})
        if self.refuse_claim:
            raise ProtocolError("claim refused with 422")
        if not self.queue:
            return Idle()
        return self.queue.pop(0)

    def report_state(self, job_id, state, **extra):
        self.states.append((job_id, state))

    def heartbeat(self, job_id):
        from sandboxd.api import Heartbeat as HB
        return HB(lease_expires_at="2026-08-26T10:05:00Z",
                  cancel_requested=False)

    def fetch_sample(self, url, dest, *, expected_sha256, timeout=None):
        # Verifies like the real one; see the same fake in test_stages.py.
        if not expected_sha256:
            raise A.SampleMismatch("the lease carries no sha256")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(SAMPLE)
        if hashlib.sha256(SAMPLE).hexdigest() != expected_sha256:
            dest.unlink(missing_ok=True)
            raise A.SampleMismatch("sample digest does not match")
        return len(SAMPLE)

    def artifact_tickets(self, job_id, sizes):
        from sandboxd.api import Ticket
        return {n: Ticket(url="https://minio/a", fields={}, expires_in=900)
                for n in sizes}

    def upload_artifact(self, ticket, name, path):
        pass

    def complete(self, job_id, manifest):
        # /complete is what SETS `completed`, together with the manifest, in
        # one committed row -- that is what makes publication atomic. The
        # worker never reports `completed` through /state, and a fake that did
        # not model this let the wrong sequence pass (Dom0 2026-08-26, F3).
        self.states.append((job_id, "completed"))
        self.manifests.append(manifest)


def lease(job_id="j1", os_="ubuntu", mib=2198) -> Lease:
    return Lease(job_id=job_id, target_os=os_, submitted_filename="s.bin",
                 required_mib=mib, attempt=1, sample_url="https://minio/s",
                 sha256=hashlib.sha256(SAMPLE).hexdigest(),
                 lease_expires_at="2026-08-26T10:00:00Z")


def settings(tmp_path, **kw) -> D.Settings:
    base = dict(api="https://p:8443", token="t", worker_id="dom0-1",
                total_mib=16384, vlans=range(1, 5), total_slots=4)
    base.update(kw)
    return D.Settings(**base)


def config(tmp_path) -> Config:
    repo = tmp_path / "repo"
    (repo / "misc").mkdir(parents=True)
    (repo / "state").mkdir(parents=True)
    for os_ in ("ubuntu", "android"):
        (repo / "misc" / f"{os_}_sandbox.cfg").write_text(
            (ROOT / "misc" / f"{os_}_sandbox.cfg").read_text())
        (repo / "state" / f"{os_}_sandbox.bak").write_bytes(b"saved")
    (tmp_path / "cfg").mkdir(exist_ok=True)
    return Config(staging_dir=tmp_path / "staging",
                  results_dir=tmp_path / "results",
                  config_dir=tmp_path / "cfg", repo_root=repo,
                  waits=T.Waits(settle=0.0, apk_install=0.0, destroy_settle=0.0),
                  heartbeat_interval=60.0)


def runner(xl=XL_EMPTY, lvs=LVS_EMPTY) -> FakeRunner:
    r = FakeRunner()
    r.script(("xl", "list"), stdout=xl)
    r.script(("lvs",), stdout=lvs)
    r.script(("xl", "domid"), rc=1, times=1)
    r.script(("lvdisplay", "/dev/vg-root/ubuntu_sandbox"), rc=0)
    r.script(("lvdisplay",), rc=1)
    r.script(("xl", "domid"), rc=0, stdout="42\n")
    return r


def daemon(tmp_path, api=None, r=None, **kw):
    return D.Daemon(settings(tmp_path, **kw), config(tmp_path),
                    r or runner(), api or FakeApi())


# --- startup ordering -------------------------------------------------------

def test_the_sweep_runs_before_registration(tmp_path):
    """Registering first would advertise capacity that stale clones are still
    holding."""
    r = runner()
    api = FakeApi()
    d = daemon(tmp_path, api, r)

    d.start()

    assert r.order_of(("xl", "list")) == 0
    assert api.registered is not None


def test_reconcile_reports_nothing_live_after_a_sweep(tmp_path):
    """Empty by construction: the sweep destroyed everything. Whatever the
    platform thought this host held is marked interrupted, which is true."""
    api = FakeApi(interrupted=["old-job-1", "old-job-2"])
    d = daemon(tmp_path, api)

    d.start()

    assert api.reconciled == []


def test_capacity_is_registered_from_the_templates_own_configs(tmp_path):
    """The API cannot read Dom0's .cfg files, and a second copy of the number
    on the platform would recreate the two-files-free-to-disagree failure
    platform.env exists to prevent."""
    api = FakeApi()
    daemon(tmp_path, api).start()

    assert api.registered["pipelines"] == {"ubuntu": 4246, "android": 4246}
    assert api.registered["total_vlans"] == 4


def test_a_guest_with_no_template_is_not_offered(tmp_path):
    """Windows: no misc/windows_sandbox.cfg and no injection PID. Offering it
    would advertise a pipeline that cannot run."""
    api = FakeApi()
    daemon(tmp_path, api).start()

    assert "windows" not in api.registered["pipelines"]


def test_a_host_with_no_templates_refuses_to_start(tmp_path):
    """Better a refusal than a worker that registers, claims, and fails every
    job it is given."""
    cfg = config(tmp_path)
    for f in (cfg.repo_root / "misc").iterdir():
        f.unlink()

    d = D.Daemon(settings(tmp_path), cfg, runner(), FakeApi())
    with pytest.raises(SystemExit, match="no analysis pipeline"):
        d.start()


# --- what the sweep admits --------------------------------------------------

def test_a_clean_host_admits_every_provisioned_vlan(tmp_path):
    """`clean_vlans` holds only VLANs that HAD something on them, so on a
    freshly-booted host it is empty. Admitting only those would start with zero
    usable capacity -- which an earlier version of this did."""
    table = daemon(tmp_path).start()

    assert table.free().vlans == 4


def test_a_vlan_whose_clone_survived_is_withheld(tmp_path):
    """Reusing it would restore onto a snapshot whose predecessor is still
    alive: DRAFT-033's cross-sample contamination, which is not a crash and so
    goes unreported."""
    stuck = XL_EMPTY + "ubuntu_sandbox-2-clone   7  2048  2  -b---- 3.0\n"
    r = FakeRunner()
    r.script(("xl", "list"), stdout=stuck)          # still there after destroy
    r.script(("lvs",), stdout=LVS_EMPTY)
    r.script(("xl", "domid"), rc=0, stdout="7\n")

    table = daemon(tmp_path, r=r).start()

    assert table.free().vlans == 3
    got = set()
    while (h := table.acquire(f"j{len(got)}", 100)) is not None:
        got.add(h.vlan)
    assert 2 not in got


# --- the claim loop ---------------------------------------------------------

def test_a_lease_is_acquired_and_run(tmp_path):
    api = FakeApi(queue=[lease()])
    d = daemon(tmp_path, api)
    table = d.start()

    d._claim_once(table)
    for t in d._workers:
        t.join(timeout=10)

    assert [s for _, s in api.states][-1] == "completed"
    assert table.free() == table.total, "the vlan was not released"


def test_a_dirty_teardown_does_not_get_its_vlan_back(tmp_path):
    """The VLAN is withheld, not recycled.

    `_teardown` has always reported "dirty: ..." and nothing consumed it, so a
    domain that survived `xl destroy` handed its VLAN straight to the next
    sample -- a restore onto the previous sample's snapshot, which is DRAFT-033.
    `ResourceTable.withhold` was written for this and had no caller.

    Recovery is a restart: the startup sweep destroys what survived and
    re-admits the VLAN. Until then the host is one slot down, which is the
    visible cost `admit` argues is better than the invisible one.
    """
    r = runner()
    r.script(("xl", "destroy"), rc=1)

    api = FakeApi(queue=[lease()])
    d = daemon(tmp_path, api, r=r)
    table = d.start()
    before = table.free().vlans

    d._claim_once(table)
    for t in d._workers:
        t.join(timeout=10)

    assert table.free().vlans == before - 1, (
        "a VLAN whose clone survived teardown went back into the pool")


def test_a_clean_teardown_does_get_its_vlan_back(tmp_path):
    """The other half, so the check above cannot pass by withholding always.

    Withholding on every teardown would drain the pool to nothing within a few
    jobs and stop the host taking work -- safe, and useless.
    """
    api = FakeApi(queue=[lease()])
    d = daemon(tmp_path, api)
    table = d.start()

    d._claim_once(table)
    for t in d._workers:
        t.join(timeout=10)

    assert table.free() == table.total


def test_surviving_egress_chains_withhold_the_vlan(tmp_path):
    """The case the exit codes could not report.

    Most revoke commands fail legitimately, so teardown asks `iptables -S`
    instead: a chain that still answers is a permit the next sample would
    inherit. Scripted to rc=0 here -- the fake's default is rc=1, "no chain by
    that name", which is what a real host says after a successful revoke.
    """
    r = runner()
    r.script(("iptables", "-w", str(C.IPTABLES_WAIT_SECONDS), "-S"), rc=0)

    api = FakeApi(queue=[lease()])
    d = daemon(tmp_path, api, r=r)
    table = d.start()
    before = table.free().vlans

    d._claim_once(table)
    for t in d._workers:
        t.join(timeout=10)

    assert table.free().vlans == before - 1, (
        "a VLAN whose egress chains outlived the revoke was reused")


def test_reserved_is_not_treated_as_a_failure(tmp_path):
    """A job too large for current capacity is holding its place rather than
    being starved by smaller ones behind it."""
    api = FakeApi(queue=[Reserved(blocking_job_id="big", need_mib=6294)])
    d = daemon(tmp_path, api)
    table = d.start()

    assert d._claim_once(table) is None
    assert table.free() == table.total
    assert d._workers == []


def test_the_loop_does_not_claim_with_no_free_vlan(tmp_path):
    """Asking for work this host cannot place wastes a lease: the platform
    hands it over and it sits until the TTL lapses."""
    api = FakeApi(queue=[lease()])
    d = daemon(tmp_path, api, vlans=range(1, 2), total_slots=1)
    table = d.start()
    table.acquire("holding", 100)

    assert d._claim_once(table) is None
    assert api.claims == [], "claimed with nothing to place the job on"


def test_the_reported_capacity_is_what_the_table_holds(tmp_path):
    api = FakeApi(queue=[lease(), lease("j2")])
    d = daemon(tmp_path, api)
    table = d.start()

    d._claim_once(table)
    d._claim_once(table)
    for t in d._workers:
        t.join(timeout=10)

    assert api.claims[1]["free_mib"] == api.claims[0]["free_mib"] - 2198
    assert api.claims[1]["free_vlans"] == api.claims[0]["free_vlans"] - 1


def test_a_job_larger_than_the_host_is_closed_not_crashed_on(tmp_path):
    """Found in review: `Exhausted` escaped the claim loop, which catches only
    ProtocolError -- so one bad row ended the daemon.

    The platform knows both numbers and should not lease such a job, but
    "should not" is not "cannot". Reported rather than left to lapse: the TTL
    would close it eventually with no reason attached.
    """
    api = FakeApi(queue=[lease(mib=99999)])
    d = daemon(tmp_path, api, total_mib=2198)
    table = d.start()

    assert d._claim_once(table) is None
    assert d._workers == []
    assert [s for _, s in api.states] == ["cleaning", "failed"]
    assert table.free() == table.total


def test_a_refused_claim_does_not_end_the_daemon(tmp_path):
    """A 4xx means this client and that server disagree about the protocol.
    Worth logging loudly; not worth exiting over, because the operator's fix is
    a deploy and the daemon should be running when it lands."""
    api = FakeApi(refuse_claim=True)
    d = daemon(tmp_path, api)
    d.start()

    stopper = threading.Timer(0.3, d.stop)
    stopper.start()
    d.run()          # returns rather than raising
    stopper.cancel()

    assert len(api.claims) >= 1


# --- the single-acquirer invariant -----------------------------------------

def test_workers_release_and_only_the_loop_acquires(tmp_path):
    """The invariant that removes the claim race. A worker thread that
    acquired would be a second allocator, which is the process-local slot
    array's bug one scope smaller."""
    api = FakeApi(queue=[lease(f"j{i}") for i in range(4)])
    d = daemon(tmp_path, api)
    table = d.start()

    for _ in range(4):
        d._claim_once(table)
    for t in d._workers:
        t.join(timeout=15)

    assert table.free() == table.total
    assert table.live_job_ids() == []


def test_several_analyses_run_concurrently(tmp_path):
    """#41's headline capability: dirwatch takes one origin per invocation and
    two instances cannot coexist."""
    api = FakeApi(queue=[lease("u1", "ubuntu"), lease("a1", "android"),
                         lease("u2", "ubuntu")])
    d = daemon(tmp_path, api)
    table = d.start()

    for _ in range(3):
        d._claim_once(table)

    assert len(d._workers) == 3
    for t in d._workers:
        t.join(timeout=15)
    assert table.free() == table.total


# --- shutdown ---------------------------------------------------------------

def test_stopping_claims_no_more_work(tmp_path):
    api = FakeApi(queue=[lease() for _ in range(5)])
    d = daemon(tmp_path, api)
    d.start()
    d.stop()

    d.run()

    assert api.claims == []


def test_shutdown_waits_for_an_analysis_in_flight(tmp_path):
    """A clone left running is malware with NAT'd egress and nothing watching
    it, so a shutdown does not abandon one."""
    slow = threading.Event()

    class Slow(FakeApi):
        def fetch_sample(self, url, dest, *, expected_sha256, timeout=None):
            slow.wait(timeout=5)
            return super().fetch_sample(url, dest,
                                        expected_sha256=expected_sha256)

    api = Slow(queue=[lease()])
    d = daemon(tmp_path, api)
    table = d.start()
    d._claim_once(table)

    d.stop()
    started = time.monotonic()
    releaser = threading.Timer(0.2, slow.set)
    releaser.start()
    d._drain()
    releaser.cancel()

    assert time.monotonic() - started >= 0.15, "the analysis was abandoned"
    assert table.free() == table.total


def test_a_worker_error_does_not_take_the_daemon_down(tmp_path):
    """One bad job must not stop the host analysing everything else."""
    class Broken(FakeApi):
        def fetch_sample(self, url, dest, *, expected_sha256, timeout=None):
            raise RuntimeError("boom")

    api = Broken(queue=[lease()])
    d = daemon(tmp_path, api)
    table = d.start()

    d._claim_once(table)
    for t in d._workers:
        t.join(timeout=10)

    # The vlan came back even though the job blew up.
    assert table.free() == table.total


# --- the concurrency guard --------------------------------------------------

def test_a_second_sandboxd_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(D.proc, "iter_processes", lambda: [])
    lock = tmp_path / "sandboxd.lock"

    first = D.refuse_if_another_orchestrator_runs(lock)
    try:
        with pytest.raises(D.AlreadyRunning, match="One orchestrator per host"):
            D.refuse_if_another_orchestrator_runs(lock)
    finally:
        import os
        os.close(first)


def test_a_running_dirwatch_refuses_the_start(tmp_path, monkeypatch):
    """Two orchestrators allocate the same VLANs from low numbers with no
    shared state, so they collide on gateway addresses and isolation rules
    with no symptom but interference between two malware analyses."""
    monkeypatch.setattr(D.proc, "iter_processes",
                        lambda: [(999, ("/usr/local/bin/dirwatch", "1", "u"))])

    with pytest.raises(D.AlreadyRunning, match="dirwatch is running"):
        D.refuse_if_another_orchestrator_runs(tmp_path / "l.lock")


def test_an_editor_with_the_source_open_is_not_a_dirwatch(tmp_path, monkeypatch):
    """Exact program name, not a substring: `grep dirwatch` would match this
    and refuse to start for no reason."""
    monkeypatch.setattr(D.proc, "iter_processes",
                        lambda: [(999, ("/usr/bin/vim", "automation/dirwatch.c"))])

    fd = D.refuse_if_another_orchestrator_runs(tmp_path / "l.lock")
    import os
    os.close(fd)


# --- settings ---------------------------------------------------------------

def test_capacity_has_no_default(tmp_path):
    """Guessing how much memory Dom0 may give clones is how a host
    overcommits, and the symptom is a clone that fails to restore rather than
    a number anyone reads."""
    with pytest.raises(SystemExit, match="SANDBOXD_TOTAL_MIB"):
        D.Settings.from_env({"SANDBOXD_API": "x", "WORKER_TOKEN": "y"})


def test_the_vlan_range_comes_from_max_clones(tmp_path):
    """It MUST match what network-setup.sh provisioned: a vlan with no
    xenbr1.<n> and no gateway produces a clone that boots, gets an address
    nothing routes, and reads as a sample that chose not to talk."""
    s = D.Settings.from_env({
        "SANDBOXD_API": "x", "WORKER_TOKEN": "y",
        "SANDBOXD_TOTAL_MIB": "16384", "SANDBOXD_MAX_CLONES": "6"})

    assert list(s.vlans) == [1, 2, 3, 4, 5, 6]

# --- F11: the console must dial the listener the browser reaches -----------

def test_the_console_dials_its_own_listener(tmp_path):
    """The platform runs TWO uvicorn processes over the same app -- 8443 with
    mutual TLS for the worker channel, 8000 behind cloudflared for the browser
    -- and the relay pairs sockets in an in-process registry.

    A worker on 8443 and a browser on 8000 attach to different registries and
    can never meet. Both wait, and nothing is logged, because each side is
    doing exactly what it should. Observed on Dom0 2026-08-26: "console dialled
    out" with no "console bridged" ever following.
    """
    d = daemon(tmp_path, **{"console_api": "https://192.168.1.10:8000"})
    d.start()

    assert d._cfg.console_api == "https://192.168.1.10:8000"
    assert d._cfg.api_base == "https://p:8443"


def test_an_unset_console_listener_falls_back_and_warns(tmp_path, caplog):
    """Falling back to the worker channel is the behaviour that silently does
    not work, so it says so rather than looking configured.

    `console_enabled=True` is now required to reach the warning at all: the
    console is off unless SANDBOXD_CONSOLE_ENABLED says otherwise, and a host
    that is not opening relay sockets has nothing to be warned about.
    """
    import logging
    with caplog.at_level(logging.WARNING):
        daemon(tmp_path, console_enabled=True).start()

    assert any("SANDBOXD_CONSOLE_API is unset" in r.message
               for r in caplog.records)


def test_the_console_is_off_unless_the_environment_turns_it_on():
    """What it enables is a socket dialled OUT of the machine that runs
    malware, so it fails closed -- including on a typo."""
    base = {"SANDBOXD_API": "https://p:8443", "WORKER_TOKEN": "t",
            "SANDBOXD_TOTAL_MIB": "8192"}

    assert D.Settings.from_env(base).console_enabled is False
    assert D.Settings.from_env(
        {**base, "SANDBOXD_CONSOLE_ENABLED": "ture"}).console_enabled is False
    assert D.Settings.from_env(
        {**base, "SANDBOXD_CONSOLE_ENABLED": "1"}).console_enabled is True
    assert D.Settings.from_env(
        {**base, "SANDBOXD_CONSOLE_ENABLED": "on"}).console_enabled is True


def test_the_console_setting_reaches_the_analysis_config(tmp_path):
    """Settings wins over Config for deployment values, as it does for the API
    base and the worker token."""
    d = daemon(tmp_path, console_enabled=True)
    assert d._cfg.console_enabled is True


def test_the_console_listener_comes_from_the_environment():
    s = D.Settings.from_env({
        "SANDBOXD_API": "https://192.168.1.10:8443",
        "SANDBOXD_CONSOLE_API": "https://192.168.1.10:8000",
        "WORKER_TOKEN": "t", "SANDBOXD_TOTAL_MIB": "8192"})

    assert s.api == "https://192.168.1.10:8443"
    assert s.console_api == "https://192.168.1.10:8000"


# --- the analysis network, provisioned at startup ---------------------------
#
# `sandboxd` replaced `run_analysis-<os>.sh` but not its `network-setup.sh`
# call, so nothing created the VLAN interfaces, gateways or isolation chains.
# The clone then booted, took an address nothing routed, and read as a sample
# that chose not to talk -- a false negative that looks exactly like a result.
# These pin the two properties that matter: it is CALLED, and a failure REFUSES
# to start rather than running an analysis with no isolation.


def _fake_script(tmp_path, rc=0, stderr="") -> Path:
    """A stand-in for network-setup.sh. The real one needs root, iptables and
    Open vSwitch, none of which exist in the development container."""
    script = tmp_path / "network-setup.sh"
    script.write_text(f'#!/bin/sh\nprintf %s "{stderr}" >&2\nexit {rc}\n')
    script.chmod(0o755)
    return script


def test_the_clone_count_is_passed_through_to_the_script(tmp_path):
    """**The argument is the point.** `network-setup.sh N` creates `xenbr1.1..N`
    and the daemon hands out VLANs `1..N`; the two must agree, and until this
    they were two numbers set by hand in two places.
    """
    seen = tmp_path / "argv"
    script = tmp_path / "network-setup.sh"
    script.write_text(f'#!/bin/sh\necho "$@" > {seen}\n')
    script.chmod(0o755)

    D.provision_analysis_network(7, script=script)
    assert seen.read_text().strip() == "7"


def test_a_failure_refuses_to_start_and_says_why(tmp_path):
    """A half-provisioned analysis network is worse than none: it looks like a
    working one, and clones run with no inter-clone isolation and no LAN block.
    """
    script = _fake_script(tmp_path, rc=3, stderr="xenbr1 does not exist")

    with pytest.raises(D.NetworkSetupFailed) as exc:
        D.provision_analysis_network(2, script=script)

    assert "rc=3" in str(exc.value)
    assert "xenbr1 does not exist" in str(exc.value)


def test_a_missing_script_is_named_rather_than_ignored(tmp_path):
    with pytest.raises(D.NetworkSetupFailed) as exc:
        D.provision_analysis_network(2, script=tmp_path / "absent.sh")
    assert "absent.sh" in str(exc.value)


def test_the_shipped_script_path_resolves(tmp_path):
    """The default points at the real `automation/network-setup.sh`. A rename
    would otherwise only surface on Dom0, at startup, in production."""
    assert D.NETWORK_SETUP.is_file(), D.NETWORK_SETUP
    assert D.NETWORK_SETUP.name == "network-setup.sh"
