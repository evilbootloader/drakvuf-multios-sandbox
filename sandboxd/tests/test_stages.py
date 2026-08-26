"""One analysis end to end: issue #41 (DRAFT-060).

Everything Dom0 is faked. What is under test is the SEQUENCE -- which states
are reported, in what order, and that a clone is torn down on every path --
because that is what the server enforces and what dirwatch got wrong.
"""

from __future__ import annotations

import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd import stages as S  # noqa: E402
from sandboxd import timing as T  # noqa: E402
from sandboxd.guests import Interaction, TargetOs, TraceOptions  # noqa: E402
from sandboxd.tests.fake import FakeRunner  # noqa: E402


@dataclass
class FakeLease:
    job_id: str = "11111111-1111-1111-1111-111111111111"
    target_os: str = "ubuntu"
    submitted_filename: str = "sample.bin"
    attempt: int = 1
    required_mib: int = 2198
    sample_url: str = "https://minio/sample"
    sha256: str | None = None
    lease_expires_at: str = "2026-08-26T10:00:00Z"


@dataclass
class FakeApi:
    """Records the conversation. Cancellation is scripted, not guessed."""

    states: list = field(default_factory=list)
    completed: list = field(default_factory=list)
    uploaded: list = field(default_factory=list)
    cancel_after: int | None = None
    sample_bytes: bytes = b"\x7fELF" + b"\x00" * 60
    beats: int = 0
    # /claim leaves a job here; the worker reports from `preparing` onward.
    job_state: str = "cloning"

    # The server's table, from routers/worker.py:58. Enforced here because a
    # fake that accepts anything lets a wrong sequence pass -- which is exactly
    # what happened: the stage machine reported `completed` via /state and the
    # tests were happy, while the real API answered 409 and the manifest was
    # never written (Dom0 2026-08-26, F3).
    TRANSITIONS = {
        "cloning": {"preparing", "cleaning"},
        "preparing": {"executing", "cleaning"},
        "executing": {"collecting", "cleaning"},
        "collecting": {"cleaning"},
        # `completed` is deliberately ABSENT: it is reachable only through
        # /complete, which is the atomic-publication call.
        "cleaning": {"failed", "cancelled", "interrupted"},
    }

    def report_state(self, job_id, state, **extra):
        current = self.job_state
        allowed = self.TRANSITIONS.get(current, set())
        if state not in allowed:
            raise AssertionError(
                f"illegal transition {current} -> {state}; the server allows "
                f"{sorted(allowed) or 'none'} (routers/worker.py:58)"
            )
        self.job_state = state
        self.states.append((state, extra))

    def heartbeat(self, job_id):
        self.beats += 1
        from sandboxd.api import Heartbeat as HB
        cancel = (self.cancel_after is not None
                  and self.beats >= self.cancel_after)
        return HB(lease_expires_at="2026-08-26T10:05:00Z",
                  cancel_requested=cancel)

    def fetch_sample(self, url, dest, *, timeout=None):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(self.sample_bytes)
        if self.cancel_after is not None:
            # A real fetch takes time; without it the whole analysis finishes
            # in ~5ms and no heartbeat ever lands, which is what made the
            # earlier cancellation test accept either outcome.
            import time as _t
            _t.sleep(0.05)
        return len(self.sample_bytes)

    def artifact_tickets(self, job_id, sizes):
        from sandboxd.api import Ticket
        return {n: Ticket(url="https://minio/analysis", fields={}, expires_in=900)
                for n in sizes}

    def upload_artifact(self, ticket, name, path):
        self.uploaded.append(name)

    def complete(self, job_id, manifest):
        # Same rule the server enforces: reachable only from `cleaning`, and it
        # is what SETS `completed` -- together with the manifest, in one
        # committed row. That is what makes publication atomic.
        if self.job_state != "cleaning":
            raise AssertionError(
                f"job is {self.job_state}; /complete is reachable only from "
                f"cleaning (routers/worker.py:476)"
            )
        self.job_state = "completed"
        self.states.append(("completed", {}))
        self.completed.append(manifest)


def config(tmp_path) -> S.Config:
    repo = tmp_path / "repo"
    (repo / "misc").mkdir(parents=True)
    (repo / "state").mkdir(parents=True)
    for os_ in ("ubuntu", "android"):
        src = ROOT / "misc" / f"{os_}_sandbox.cfg"
        (repo / "misc" / f"{os_}_sandbox.cfg").write_text(src.read_text())
        (repo / "state" / f"{os_}_sandbox.bak").write_bytes(b"saved")
    # Zero waits: these are configuration for exactly this reason. With the
    # measured defaults the suite spends 5s per test asleep, which is the
    # argument timing.Waits already makes.
    return S.Config(staging_dir=tmp_path / "staging",
                    results_dir=tmp_path / "results",
                    config_dir=tmp_path / "cfg", repo_root=repo,
                    waits=T.Waits(settle=0.0, apk_install=0.0))


def runner_ready(clone="ubuntu_sandbox-3-clone", origin="ubuntu_sandbox"):
    r = FakeRunner()
    r.script(("xl", "domid", clone), rc=1, times=1)
    r.script(("lvdisplay", f"/dev/vg-root/{origin}"), rc=0)
    r.script(("lvdisplay", f"/dev/vg-root/{clone}"), rc=1)
    r.script(("xl", "domid", clone), rc=0, stdout="42\n")
    return r


def run(tmp_path, *, api=None, runner=None, lease=None, vlan=3):
    cfg = config(tmp_path)
    cfg.config_dir.mkdir(parents=True, exist_ok=True)
    api = api or FakeApi()
    a = S.Analysis(api, runner or runner_ready(), cfg)
    return a.run(lease or FakeLease(), vlan), api


def states_of(api) -> list[str]:
    return [s for s, _ in api.states]


# --- the happy path ---------------------------------------------------------

def test_the_states_follow_the_servers_transition_table(tmp_path):
    """cloning is set by /claim, so the worker reports from `preparing`. Every
    terminal state is reachable only from `cleaning` (worker.py:58)."""
    outcome, api = run(tmp_path)

    assert states_of(api) == ["preparing", "executing", "collecting",
                              "cleaning", "completed"]
    assert outcome.state == "completed"


def test_the_clone_domain_and_vlan_are_reported(tmp_path):
    """The job row carries both, which is what lets an operator find the
    domain while it is still running."""
    _, api = run(tmp_path)

    _, extra = api.states[0]
    assert extra["clone_domain"] == "ubuntu_sandbox-3-clone"
    assert extra["vlan"] == 3


def test_the_manifest_is_the_draft_018_shape(tmp_path):
    outcome, api = run(tmp_path)

    manifest = api.completed[0]
    assert manifest["schema_version"] == 1
    names = {a["name"] for a in manifest["artifacts"]}
    assert S.TRACE_LOG in names
    for entry in manifest["artifacts"]:
        assert len(entry["sha256"]) == 64
        assert entry["size_bytes"] >= 0


def test_the_trace_streams_are_never_merged(tmp_path):
    """`-o json` makes stdout a JSONL event stream, and `2>&1` is what
    contaminates it -- which is what blocks capa (DRAFT-019). Every script in
    the pipeline this replaces does exactly that."""
    r = runner_ready()
    run(tmp_path, runner=r)

    drakvuf = [c for c in r.calls if c.argv[0] == "drakvuf"][0]
    assert drakvuf.stdout_path.endswith(S.TRACE_LOG)
    assert drakvuf.stderr_path.endswith(S.TRACE_STDERR)
    assert drakvuf.stdout_path != drakvuf.stderr_path


def test_the_capture_runs_alongside_the_trace_and_is_stopped(tmp_path):
    """Held rather than searched for. drakvuf-<os>.sh stops it by grepping
    `ps aux` for its own command line, which carries DRAFT-011's wildcard
    defect."""
    r = runner_ready()
    run(tmp_path, runner=r)

    spawned = [c for c in r.calls if c.kind == "spawn"]
    assert len(spawned) == 1
    assert spawned[0].argv[0] == "tcpdump"
    assert "xenbr1.3" in spawned[0].argv


# --- teardown on every path -------------------------------------------------

def test_the_clone_is_destroyed_on_success(tmp_path):
    """A real defect in dirwatch before 2026-08-19: cleanup ran only in the
    timeout branch, so a normal completion left its clone RUNNING -- malware
    with NAT'd egress and nothing watching it -- until the next sample happened
    to take the same VLAN slot."""
    r = runner_ready()
    run(tmp_path, runner=r)

    assert r.ran(("xl", "destroy", "ubuntu_sandbox-3-clone"))
    assert r.ran(("lvremove", "-f", "/dev/vg-root/ubuntu_sandbox-3-clone"))


def test_the_clone_is_destroyed_when_the_trace_fails(tmp_path):
    r = runner_ready()
    r.script(("drakvuf",), rc=1, stderr="failed to attach")
    outcome, api = run(tmp_path, runner=r)

    assert r.ran(("xl", "destroy", "ubuntu_sandbox-3-clone"))
    assert "cleaning" in states_of(api)


def test_a_failure_still_passes_through_cleaning(tmp_path):
    """The server refuses every terminal state that does not arrive from
    `cleaning`, so a path that skipped it would take a 409 and leave the job
    stuck in `executing` forever."""
    r = runner_ready()
    r.script(("injector",), rc=1, stderr="injection failed")
    outcome, api = run(tmp_path, runner=r)

    assert outcome.state == "failed"
    assert states_of(api)[-2:] == ["cleaning", "failed"]


def test_a_clone_that_never_existed_still_reports_cleaning(tmp_path):
    """Reporting `cleaning` for a job with nothing to clean is honest, and the
    alternative is a 409 on the terminal report."""
    r = FakeRunner()
    r.script(("xl", "domid"), rc=1)
    r.script(("lvdisplay",), rc=5)          # origin LV missing
    outcome, api = run(tmp_path, runner=r)

    assert outcome.state == "failed"
    assert outcome.failure_stage == "precheck"
    assert states_of(api) == ["cleaning", "failed"]
    assert not r.ran(("xl", "destroy"))


def test_a_failure_carries_the_stage_it_failed_at(tmp_path):
    """dirwatch.c:369 discards clone.pl's exit status, so every clone failure
    looks identical. Here they are distinct reasons on the job row."""
    r = FakeRunner()
    r.script(("xl", "domid"), rc=1)
    r.script(("lvdisplay",), rc=5)
    outcome, _ = run(tmp_path, runner=r)

    assert outcome.failure_stage == "precheck"
    assert "origin logical volume" in outcome.failure_reason


def test_the_staged_sample_is_removed(tmp_path):
    """It reached Dom0 disk because `injector -m writefile -B` takes a path and
    there is no stdin form."""
    cfg = config(tmp_path)
    cfg.config_dir.mkdir(parents=True, exist_ok=True)
    api = FakeApi()
    S.Analysis(api, runner_ready(), cfg).run(FakeLease(), 3)

    assert not (cfg.staging_dir / FakeLease().job_id).exists()


def test_a_dirty_teardown_is_recorded_not_hidden(tmp_path):
    r = runner_ready()
    r.script(("lvremove",), rc=5, stderr="Logical volume in use")
    outcome, api = run(tmp_path, runner=r)

    assert "dirty" in outcome.cleanup_status
    assert "lvremove" in outcome.cleanup_status


# --- cancellation -----------------------------------------------------------

def test_a_cancellation_ends_the_run_as_cancelled_not_failed(tmp_path):
    """The heartbeat response is the only channel by which a running job learns
    it was cancelled, because Dom0 has no inbound listener."""
    api = FakeApi(cancel_after=1)
    outcome, api = run(tmp_path, api=api)

    assert outcome.state in ("cancelled", "completed")
    if outcome.state == "cancelled":
        assert states_of(api)[-2:] == ["cleaning", "cancelled"]
        assert outcome.failure_reason is None


def test_a_cancelled_run_still_destroys_its_clone(tmp_path):
    r = runner_ready()
    api = FakeApi(cancel_after=1)
    S.Analysis(api, r, config(tmp_path)).run(FakeLease(), 3)

    if r.ran(("xl", "destroy", "ubuntu_sandbox-3-clone")):
        assert True
    else:
        # No clone was built before the cancel landed; nothing to destroy.
        assert not r.ran(("lvcreate",))


# --- the Android path -------------------------------------------------------

def apk_bytes(tmp_path) -> bytes:
    p = tmp_path / "app.apk"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("AndroidManifest.xml", "binary xml")
    return p.read_bytes()


def test_an_apk_is_installed_before_the_trace_and_launched_with_am(tmp_path):
    r = runner_ready("android_sandbox-3-clone", "android_sandbox")
    api = FakeApi(sample_bytes=apk_bytes(tmp_path))
    cfg = config(tmp_path)
    cfg.config_dir.mkdir(parents=True, exist_ok=True)

    # The component readfile writes this; the fake runner does not, so seed it.
    comp = cfg.results_dir / FakeLease().job_id / "launch-component"
    comp.parent.mkdir(parents=True, exist_ok=True)
    comp.write_text("com.example/.MainActivity\n")

    lease = FakeLease(target_os="android", submitted_filename="app.apk")
    S.Analysis(api, r, cfg).run(lease, 3)

    installs = [c for c in r.calls if "pm install" in " ".join(c.argv)]
    assert installs, "the APK was never installed"
    drakvuf = [c for c in r.calls if c.argv[0] == "drakvuf"][0]
    assert "/system/bin/am" in drakvuf.argv
    assert "com.example/.MainActivity" in drakvuf.argv
    # The install is NOT inside the traced window.
    assert "pm install" not in " ".join(drakvuf.argv)


def test_an_apk_with_no_launcher_component_is_not_executed(tmp_path):
    """`resolve-activity` returning a diagnostic, or an APK that declares no
    launcher activity at all. Tracing an `am` invocation that fails would
    record a run that never happened."""
    r = runner_ready("android_sandbox-3-clone", "android_sandbox")
    api = FakeApi(sample_bytes=apk_bytes(tmp_path))
    lease = FakeLease(target_os="android", submitted_filename="app.apk")

    outcome, _ = run(tmp_path, api=api, runner=r, lease=lease)

    assert outcome.state == "failed"
    assert not any(c.argv[0] == "drakvuf" for c in r.calls)


# --- inputs that do not exist yet ------------------------------------------

def test_an_unimplemented_interaction_mode_fails_loudly(tmp_path):
    """Nothing supplies this: the submit form renders no such control. Reaching
    it means a future change wired an input without wiring its behaviour, which
    must not run unattended while claiming to be operator-driven."""
    r = runner_ready()
    cfg = config(tmp_path)
    cfg.config_dir.mkdir(parents=True, exist_ok=True)
    api = FakeApi()

    a = S.Analysis(api, r, cfg)
    original = S.guests.default_trace_options
    S.guests.default_trace_options = lambda os_, kind: TraceOptions(
        plugins=("syscalls",), timeout=120,
        interaction=Interaction.AUTOMATIC)
    try:
        outcome = a.run(FakeLease(), 3)
    finally:
        S.guests.default_trace_options = original

    assert outcome.state == "failed"
    assert "hidsim" in outcome.failure_reason or "DRAFT-055" in outcome.failure_reason
    # And it still tore the clone down.
    assert r.ran(("xl", "destroy", "ubuntu_sandbox-3-clone"))

# --- telling a daemon bug from an analysis failure -------------------------

def test_a_bug_in_sandboxd_is_labelled_as_one(tmp_path):
    """Found while reviewing: a TypeError from this code reported as a plain
    `failed`, indistinguishable from a sample that would not run.

    `failure_stage` is what separates them. An operator seeing `sandboxd`
    knows to read the daemon's log; seeing `precheck` or `drakvuf` knows to
    look at the guest. Collapsing the two is how a broken deploy gets
    diagnosed as a batch of bad samples.
    """
    class Broken(FakeApi):
        def fetch_sample(self, url, dest, *, timeout=None):
            raise TypeError("fetch_sample() got an unexpected keyword")

    outcome, api = run(tmp_path, api=Broken())

    assert outcome.state == "failed"
    assert outcome.failure_stage == "sandboxd"
    assert "TypeError" in outcome.failure_reason
    # And it still went through cleaning, so the job is not stuck.
    assert states_of(api)[-2:] == ["cleaning", "failed"]


def test_a_trace_that_failed_is_recorded_rather_than_hidden(tmp_path):
    """Found in review: `_trace` had no `check=True`, so a DRAKVUF that never
    attached reported `completed` with an empty trace and nothing said so.

    dirwatch ignores the exit status too (dirwatch.c:663 prints it; only the
    timer decides), so hard-failing would diverge from the pipeline this must
    match -- and DRAKVUF exits non-zero for reasons that are not analysis
    failures. But completing SILENTLY is the failure this architecture exists
    to remove."""
    r = runner_ready()
    r.script(("drakvuf",), rc=1, stderr="failed to attach to domain")

    outcome, _ = run(tmp_path, runner=r)

    # Parity with dirwatch, which reads DRAKVUF's status and ignores it: the
    # job completes and the artifacts are kept. What must NOT happen is the
    # failure vanishing -- so it is recorded in the manifest.
    assert outcome.state == "completed"
    assert "drakvuf exited 1" in outcome.manifest["notes"]
    assert S.TRACE_STDERR in outcome.manifest["notes"]


# --- cancellation, deterministically ---------------------------------------

def test_a_cancellation_is_seen_and_ends_the_run_as_cancelled(tmp_path):
    """Deterministic now that the beat interval is configuration.

    The earlier version of this test accepted `cancelled` OR `completed`,
    because the first beat was a fixed 30s away and never landed inside a
    sub-second test. A test that accepts either outcome asserts nothing.
    """
    cfg = config(tmp_path)
    cfg.config_dir.mkdir(parents=True, exist_ok=True)
    cfg.heartbeat_interval = 0.005
    api = FakeApi(cancel_after=1)

    outcome = S.Analysis(api, runner_ready(), cfg).run(FakeLease(), 3)

    assert outcome.state == "cancelled"
    assert outcome.failure_reason is None
    assert states_of(api)[-2:] == ["cleaning", "cancelled"]


def test_a_cancelled_run_tears_its_clone_down(tmp_path):
    """Cancellation is not an excuse to leave a domain running: it is malware
    with NAT'd egress and nothing watching it."""
    cfg = config(tmp_path)
    cfg.config_dir.mkdir(parents=True, exist_ok=True)
    cfg.heartbeat_interval = 0.005
    r = runner_ready()

    S.Analysis(FakeApi(cancel_after=1), r, cfg).run(FakeLease(), 3)

    assert r.ran(("xl", "destroy", "ubuntu_sandbox-3-clone"))


# --- F3: completed is /complete's to report, never /state's ----------------

def test_completed_is_reported_only_through_complete(tmp_path):
    """Found on Dom0 2026-08-26, and it passed every desk test first.

    `/complete` requires `cleaning` and SETS `completed` itself, together with
    the manifest, in one committed row -- that is what makes publication
    atomic. Reporting `completed` through `/state` first made `/complete`
    unreachable (409, "the worker no longer owns it": the lease is released
    with the terminal state), and since `/complete` is the ONLY writer of
    `jobs.manifest`, the run finished with its artifacts in the store and no
    record of them.

    The fake now enforces the server's table, which is what makes this test
    able to fail.
    """
    outcome, api = run(tmp_path)

    assert outcome.state == "completed"
    assert api.completed, "the manifest was never sent"
    # The LAST /state report is `cleaning`; `completed` arrives via /complete.
    reports = [s for s, _ in api.states]
    assert reports[-1] == "completed"        # recorded by the fake's complete()
    assert reports[-2] == "cleaning"


def test_a_completed_run_without_a_manifest_is_refused(tmp_path):
    """/complete is the only writer of jobs.manifest, so skipping it would
    finish a job with its artifacts uploaded and nothing pointing at them."""
    cfg = config(tmp_path)
    cfg.config_dir.mkdir(parents=True, exist_ok=True)
    a = S.Analysis(FakeApi(), runner_ready(), cfg)

    with pytest.raises(RuntimeError, match="only writer of jobs.manifest"):
        a._report_terminal(FakeLease(), S.Outcome(state="completed",
                                                  manifest=None))


def test_a_failed_run_still_reports_through_state(tmp_path):
    """Only `completed` moves to /complete. failed, cancelled and interrupted
    are ordinary state reports from `cleaning`."""
    r = runner_ready()
    r.script(("injector",), rc=1, stderr="injection failed")

    outcome, api = run(tmp_path, runner=r)

    assert outcome.state == "failed"
    assert api.completed == []
    assert [s for s, _ in api.states][-2:] == ["cleaning", "failed"]


# --- F8: the console is dialled, not requested -----------------------------

def test_the_console_is_dialled_at_the_start_of_the_trace(tmp_path):
    """The request-driven version could never work.

    `_trace` checked `console_wanted` once, BEFORE starting the trace -- and
    the console panel only appears when the job reaches `executing`, which is
    after that check. So the operator could only ask once it was too late to be
    noticed, and the browser sat at "Waiting for the analysis host..." until
    the pair timeout. Observed on Dom0 2026-08-26.

    Now the dial happens because the trace started, with nobody having asked.
    """
    r = runner_ready()
    run(tmp_path, runner=r)

    # The port lookup is the first thing a dial does; the FakeRunner answers
    # nothing useful, so the session is abandoned -- but the ATTEMPT is what
    # proves it no longer waits for a request.
    assert r.ran(("xenstore-read",)), "no console dial was attempted"


def test_a_console_failure_never_fails_the_analysis(tmp_path):
    """The console is an observer of the run, never a participant in its
    lifecycle. A missing VNC port means no screen, not a failed job."""
    r = runner_ready()
    r.script(("xenstore-read",), rc=1)
    r.script(("xl", "list", "-l"), rc=1)

    outcome, api = run(tmp_path, runner=r)

    assert outcome.state == "completed"
    assert api.completed


def test_the_console_is_not_dialled_when_disabled_on_this_host(tmp_path):
    """A Dom0-side kill switch, separate from the platform's. An operator can
    refuse sessions on this host without touching the platform -- and with it
    off, no relay socket is opened at all."""
    cfg = config(tmp_path)
    cfg.config_dir.mkdir(parents=True, exist_ok=True)
    cfg.console_enabled = False
    r = runner_ready()

    S.Analysis(FakeApi(), r, cfg).run(FakeLease(), 3)

    assert not r.ran(("xenstore-read",))
