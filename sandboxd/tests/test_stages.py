"""One analysis end to end: issue #41 (DRAFT-060).

Everything Dom0 is faked. What is under test is the SEQUENCE -- which states
are reported, in what order, and that a clone is torn down on every path --
because that is what the server enforces and what the C watcher got wrong.
"""

from __future__ import annotations

import hashlib
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd import api as A  # noqa: E402
from sandboxd import stages as S  # noqa: E402
from sandboxd import timing as T  # noqa: E402
from sandboxd.guests import Interaction, TargetOs, TraceOptions  # noqa: E402
from sandboxd.tests.fake import FakeRunner  # noqa: E402


#: The default sample the fake store serves, and its digest.
#:
#: Kept together because they must agree: `fetch_sample` verifies the bytes it
#: wrote against the digest the lease carries, exactly as the real one does, so
#: a fake that served one and declared the other would fail every test for a
#: reason unrelated to what the test is about.
_ELF = b"\x7fELF" + b"\x00" * 60


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class FakeLease:
    job_id: str = "11111111-1111-1111-1111-111111111111"
    target_os: str = "ubuntu"
    submitted_filename: str = "sample.bin"
    attempt: int = 1
    required_mib: int = 2198
    sample_url: str = "https://minio/sample"
    sha256: str | None = digest(_ELF)
    lease_expires_at: str = "2026-08-26T10:00:00Z"
    plugins: list[str] = field(default_factory=lambda: ["syscalls", "filetracer", "fileextractor", "memdump"])
    timeout: int = 120
    disable_sysret: bool = True


@dataclass
class FakeApi:
    """Records the conversation. Cancellation is scripted, not guessed."""

    states: list = field(default_factory=list)
    completed: list = field(default_factory=list)
    uploaded: list = field(default_factory=list)
    ticket_batches: list = field(default_factory=list)
    cancel_after: int | None = None
    sample_bytes: bytes = _ELF
    beats: int = 0
    # The console dial reads this: the platform pairs the relay only if it
    # matches the job's `lease_owner`, so it comes from the client that took
    # the lease rather than from configuration that could drift.
    worker_id: str = "test-worker"
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

    def fetch_sample(self, url, dest, *, expected_sha256, timeout=None):
        # Verifies like the real one. A fake that accepted the argument and
        # ignored it would let every test pass against a pipeline that had
        # stopped checking, which is the failure this argument exists to stop.
        if not expected_sha256:
            raise A.SampleMismatch("the lease carries no sha256")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(self.sample_bytes)
        if digest(self.sample_bytes) != expected_sha256:
            dest.unlink(missing_ok=True)
            raise A.SampleMismatch(
                f"expected {expected_sha256}, got {digest(self.sample_bytes)}")
        if self.cancel_after is not None:
            # A real fetch takes time; without it the whole analysis finishes
            # in ~5ms and no heartbeat ever lands, which is what made the
            # earlier cancellation test accept either outcome.
            import time as _t
            _t.sleep(0.05)
        return len(self.sample_bytes)

    def artifact_tickets(self, job_id, sizes):
        from sandboxd.api import Ticket
        # Recorded per call: the platform caps `artifacts` at 64 names PER
        # REQUEST, so how the names were split matters as much as which ones.
        self.ticket_batches.append(sorted(sizes))
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
    for os_ in ("ubuntu", "android", "windows"):
        src = ROOT / "misc" / f"{os_}_sandbox.cfg"
        (repo / "misc" / f"{os_}_sandbox.cfg").write_text(src.read_text())
        (repo / "state" / f"{os_}_sandbox.bak").write_bytes(b"saved")
    # Zero waits: these are configuration for exactly this reason. With the
    # measured defaults the suite spends 5s per test asleep, which is the
    # argument timing.Waits already makes.
    return S.Config(staging_dir=tmp_path / "staging",
                    results_dir=tmp_path / "results",
                    config_dir=tmp_path / "cfg", repo_root=repo,
                    waits=T.Waits(settle=0.0, apk_component_timeout=0.0, apk_component_poll=0.0))


def runner_ready(clone="ubuntu_sandbox-3-clone", origin="ubuntu_sandbox"):
    r = FakeRunner()
    r.script(("xl", "domid", clone), rc=1, times=1)
    r.script(("lvdisplay", f"/dev/vg-root/{origin}"), rc=0)
    r.script(("lvdisplay", f"/dev/vg-root/{clone}"), rc=1)
    r.script(("xl", "domid", clone), rc=0, stdout="42\n")
    return r


def run(tmp_path, *, api=None, runner=None, lease=None, vlan=3, plugins=None,
        console_enabled=False):
    cfg = config(tmp_path)
    cfg.plugins = plugins
    # Off by default here as it is in production, so a test that cares about
    # the console has to say so -- and every other test runs the shape a real
    # Dom0 runs, with no relay socket dialled.
    cfg.console_enabled = console_enabled
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
    """The trace is uploaded SPLIT, one `<plugin>.log` per DRAKVUF plugin,
    and `trace.log` itself is not in the manifest.

    Amended 2026-09-19 (result-schema.md 4.1): until then this asserted
    `trace.log` was present, and passed only because the split read a
    filename nothing wrote. The raw stream is the per-plugin logs plus
    parse_errors.log, byte for byte; keeping both would double a trace that
    on its own exceeds the per-job result budget."""
    r = runner_ready()
    r.script(("drakvuf",), stdout=(
        '{"Plugin": "inject", "Method": "ExecProc", "Status": "Success", '
        '"ProcessName": "/tmp/sample.bin", "Arguments": "", '
        '"InjectedPid": 1688, "InjectedTid": 1688}\n'
        '{"Plugin":"filetracer","PID":1688,"EventUID":"0x1","Method":"openat"}\n'))
    outcome, api = run(tmp_path, runner=r)

    manifest = api.completed[0]
    assert manifest["schema_version"] == 1
    names = {a["name"] for a in manifest["artifacts"]}
    assert S.TRACE_LOG not in names
    assert {"inject.log", "filetracer.log", S.TRACE_STDERR} <= names
    for entry in manifest["artifacts"]:
        assert len(entry["sha256"]) == 64
        assert entry["size_bytes"] >= 0


def test_raw_dumps_upload_unless_process_dumps_packed_them(tmp_path):
    """`dumps/` is excluded from the upload only beside a `dumps.zip`.

    process_dumps needs a process tree, which needs procmon, which no
    non-Windows job runs -- so for those the raw directory is all there is.
    The first version of the exclusion was unconditional (2026-09-18), and
    every memory dump of every Ubuntu job would have vanished from the
    manifest with nothing to say so."""
    from sandboxd.postprocessing.paths import DUMPS_DIR, DUMPS_ZIP
    cfg = config(tmp_path)
    job_dir = tmp_path / "results" / "job"
    (job_dir / DUMPS_DIR).mkdir(parents=True)
    (job_dir / DUMPS_DIR / "0x0001.dmp").write_bytes(b"\xde\xad")

    api = FakeApi()
    S.Analysis(api, runner_ready(), cfg)._collect(FakeLease(), job_dir)
    assert api.uploaded == [f"{DUMPS_DIR}/0x0001.dmp"]

    (job_dir / DUMPS_ZIP).write_bytes(b"PK")
    api = FakeApi()
    S.Analysis(api, runner_ready(), cfg)._collect(FakeLease(), job_dir)
    assert api.uploaded == [DUMPS_ZIP]


def test_the_raw_trace_never_uploads_even_when_the_split_left_it(tmp_path):
    """The per-plugin logs are the stream; `trace.log` is what they were
    split from. `split_drakvuf_log` removes it on success, and `_collect`
    skips it regardless -- a failed split must not turn the largest file of
    the job into an upload beside the partial logs it did write. It stays in
    the job directory on Dom0, which nothing removes."""
    cfg = config(tmp_path)
    job_dir = tmp_path / "results" / "job"
    job_dir.mkdir(parents=True)
    (job_dir / S.TRACE_LOG).write_text('{"Plugin":"syscall"}\n' * 100)
    (job_dir / "syscall.log").write_text('{"Plugin":"syscall"}\n')
    (job_dir / S.TRACE_STDERR).write_text("")

    api = FakeApi()
    S.Analysis(api, runner_ready(), cfg)._collect(FakeLease(), job_dir)
    assert api.uploaded == ["syscall.log", S.TRACE_STDERR]
    assert (job_dir / S.TRACE_LOG).exists(), "skipped from the upload, not deleted"


def test_raw_ipt_uploads_unless_compress_ipt_packed_it(tmp_path):
    """The same rule for the other packed pair, `ipt/` and `ipt.zip`."""
    from sandboxd.postprocessing.paths import DUMPS_ZIP, IPT_DIR, IPT_ZIP
    cfg = config(tmp_path)
    job_dir = tmp_path / "results" / "job"
    (job_dir / IPT_DIR).mkdir(parents=True)
    (job_dir / IPT_DIR / "trace.bin").write_bytes(b"\x02\x02")

    api = FakeApi()
    S.Analysis(api, runner_ready(), cfg)._collect(FakeLease(), job_dir)
    assert api.uploaded == [f"{IPT_DIR}/trace.bin"]

    # One pair's zip says nothing about the other's directory.
    (job_dir / DUMPS_ZIP).write_bytes(b"PK")
    api = FakeApi()
    S.Analysis(api, runner_ready(), cfg)._collect(FakeLease(), job_dir)
    assert api.uploaded == [DUMPS_ZIP, f"{IPT_DIR}/trace.bin"]

    (job_dir / IPT_ZIP).write_bytes(b"PK")
    api = FakeApi()
    S.Analysis(api, runner_ready(), cfg)._collect(FakeLease(), job_dir)
    assert api.uploaded == [DUMPS_ZIP, IPT_ZIP]


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


def test_both_plugin_output_directories_exist_before_drakvuf_runs(tmp_path):
    """DRAKVUF does not create them and says nothing when they are missing.

    The Ubuntu trace script created both with one `mkdir -p` and the port to
    `stages.py` dropped it. That stayed invisible because the two plugins fail
    differently: `-D` ends up created anyway, so `dump/` appears and looks like
    proof the output paths work, while `--memdump-dir` does not and `memdump`
    writes nothing. Dom0 2026-08-27: a completed trace with 48 memdump lines in
    trace.log and no memdump directory beside it.

    The shape is what makes it worth a test. The job reports `completed`, the
    manifest lists the artifacts that did survive, and nothing anywhere records
    that a plugin was asked to collect memory and could not -- a silent partial
    loss of evidence, which is the worst way for a sandbox to fail.
    """
    r = runner_ready()
    run(tmp_path, runner=r)

    drakvuf = [c for c in r.calls if c.argv[0] == "drakvuf"][0]
    dump = Path(drakvuf.argv[drakvuf.argv.index("-D") + 1])
    memdump = Path(drakvuf.argv[drakvuf.argv.index("--memdump-dir") + 1])

    assert dump.is_dir(), "-D was passed a path that does not exist"
    assert memdump.is_dir(), (
        "--memdump-dir was passed a path that does not exist; memdump writes "
        "nothing and the trace still reports success"
    )


def test_the_ipt_directory_exists_only_for_a_job_that_chose_ipt(tmp_path):
    """The third output directory, on the same footing as the two above --
    and absent otherwise: compress_ipt runs whenever it exists, and an empty
    `ipt.zip` in every manifest would say IPT ran when it did not."""
    from sandboxd.postprocessing.paths import IPT_DIR, IPT_ZIP
    without = tmp_path / "without"
    r = runner_ready()
    run(without, runner=r, plugins=("syscalls",))
    argv = [c for c in r.calls if c.argv[0] == "drakvuf"][0].argv
    assert "--ipt-dir" not in argv
    assert not any(p.name in (IPT_DIR, IPT_ZIP) for p in without.rglob("*"))

    r = runner_ready()
    _, api = run(tmp_path / "with", runner=r, plugins=("syscalls", "ipt"))
    argv = [c for c in r.calls if c.argv[0] == "drakvuf"][0].argv
    ipt = Path(argv[argv.index("--ipt-dir") + 1])
    assert ipt.name == IPT_DIR
    # Created before DRAKVUF ran, and packed after: the manifest carries the
    # zip, not the directory.
    names = {a["name"] for a in api.completed[0]["artifacts"]}
    assert IPT_ZIP in names
    assert not any(n.startswith(IPT_DIR + "/") for n in names)


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
    """A real defect in the C watcher before 2026-08-19: cleanup ran only in the
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
    """The C watcher discarded the Perl builder's exit status, so every clone failure
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

    lease = FakeLease(target_os="android", submitted_filename="app.apk",
                      sha256=digest(api.sample_bytes))
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
    lease = FakeLease(target_os="android", submitted_filename="app.apk",
                      sha256=digest(api.sample_bytes))

    outcome, _ = run(tmp_path, api=api, runner=r, lease=lease)

    assert outcome.state == "failed"
    assert not any(c.argv[0] == "drakvuf" for c in r.calls)


def test_an_apk_routed_to_ubuntu_fails_instead_of_mixing_two_guests(tmp_path):
    """`_preconfig` branched on `job.kind` alone, while `argv_install_apk`
    hardcodes Android's shell and the handoff comes from `PATHS[target_os]`.

    2026-08-29: an APK submitted against Ubuntu produced
    `injector -r .../linux.json -e /system/bin/sh` with a /home/carlos/Desktop
    handoff, and died at execve with ENOENT one clone and several minutes in.
    A command composed out of two guests' paths cannot succeed and should
    never be built.

    The platform refuses this at submission now (_CONTRADICTS). This is the
    second line, for a job admitted before that rule or by a caller that is
    not the UI."""
    r = runner_ready("ubuntu_sandbox-3-clone", "ubuntu_sandbox")
    api = FakeApi(sample_bytes=apk_bytes(tmp_path))
    lease = FakeLease(target_os="ubuntu", submitted_filename="app.apk",
                      sha256=digest(api.sample_bytes))

    outcome, _ = run(tmp_path, api=api, runner=r, lease=lease)

    assert outcome.state == "failed"
    assert not any("/system/bin/sh" in c.argv for c in r.calls), (
        "Android's shell was sent to a Ubuntu guest"
    )
    assert not any(c.argv[0] == "drakvuf" for c in r.calls)


def test_the_component_readfile_and_its_cleanup_are_checked(tmp_path):
    """Both used to run with `proc.run`'s default `check=False`, which made an
    injector failure indistinguishable from the test above: `dest` never
    appeared, `component` fell back to "" and the run was reported as an APK
    with no launcher activity.

    2026-08-29: that error was raised for an F-Droid APK whose component
    resolved to `org.fdroid.fdroid/.views.main.MainActivity` correctly, by hand,
    in one second. Three rounds of debugging went at the sample because the
    message named the sample. A stage must name the stage that failed.

    The `rm` is checked for a second reason: the comment beside it states that
    the handoff is gone before the sample runs, and unchecked it could leave the
    guest holding exactly the artifact an evasive application looks for --
    silently, on every later analysis."""
    r = runner_ready("android_sandbox-3-clone", "android_sandbox")
    api = FakeApi(sample_bytes=apk_bytes(tmp_path))
    cfg = config(tmp_path)
    cfg.config_dir.mkdir(parents=True, exist_ok=True)
    comp = cfg.results_dir / FakeLease().job_id / "launch-component"
    comp.parent.mkdir(parents=True, exist_ok=True)
    comp.write_text("com.example/.MainActivity\n")

    lease = FakeLease(target_os="android", submitted_filename="app.apk",
                      sha256=digest(api.sample_bytes))
    S.Analysis(api, r, cfg).run(lease, 3)

    by_stage = {c.what: c for c in r.calls}
    assert by_stage["injector rm"].check is True

    # **The readfile is deliberately UNchecked since 2026-09-04, and the
    # property above is preserved by `_await_component` instead.** It polls,
    # because ENOENT is the expected answer while the guest shell is still
    # behind Dom0 -- the fixed sleep it replaced was failing healthy jobs. A
    # readfile that never succeeds is still raised as `injector readfile`,
    # carrying injector's own output, which is what stops it masquerading as an
    # APK with no launcher activity. `test_a_readfile_that_never_succeeds_is_
    # reported_as_a_readfile_failure` is where that now lives.
    assert by_stage["injector readfile"].check is False


def _readfile_prefix(cfg) -> tuple[str, ...]:
    """The argv prefix that matches ONLY the component readfile.

    Every Android injection shares elements 0-6, so the prefix has to run all
    the way to `-m readfile` to avoid also answering the writefile and the
    execproc."""
    return ("injector", "-r", str(cfg.profile(S.TargetOs.ANDROID)),
            "-d", "42", "-i", str(cfg.injection_pids[S.TargetOs.ANDROID]),
            "-m", "readfile")


def test_a_readfile_that_never_succeeds_is_reported_as_a_readfile_failure(tmp_path):
    """**The message that made this bug diagnosable must survive the poll.**

    `_await_component` tolerates a failing readfile because ENOENT is the
    expected answer while the guest shell is still behind Dom0. When the
    deadline expires having never succeeded, it must still fail AS a readfile,
    carrying injector's own words -- `syscall return code: -2`, `Could not open
    file in guest`. Collapsing that into "no usable launcher component" would
    blame the sample for a Dom0-side timing fault, which is the 2026-08-29
    defect arriving by a new route."""
    r = runner_ready("android_sandbox-3-clone", "android_sandbox")
    cfg = config(tmp_path)
    r.script(_readfile_prefix(cfg), rc=1,
             stderr="syscall return code: -2\nCould not open file in guest")
    api = FakeApi(sample_bytes=apk_bytes(tmp_path))
    cfg.config_dir.mkdir(parents=True, exist_ok=True)

    lease = FakeLease(target_os="android", submitted_filename="app.apk",
                      sha256=digest(api.sample_bytes))
    S.Analysis(api, r, cfg).run(lease, 3)

    _, detail = api.states[-1]
    assert "readfile" in str(detail), detail
    assert "-2" in str(detail) or "Could not open file" in str(detail), detail


def test_a_component_that_appears_late_is_waited_for(tmp_path):
    """The whole point of the poll: a guest that is slow to write the handoff
    must not fail a healthy sample. The fixed sleep this replaced did exactly
    that when `pm list packages` waited on the package service after a
    restore."""
    r = runner_ready("android_sandbox-3-clone", "android_sandbox")
    cfg = config(tmp_path)
    cfg.waits = T.Waits(settle=0.0, apk_component_timeout=30.0,
                        apk_component_poll=0.0)
    dest = cfg.results_dir / FakeLease().job_id / "launch-component"

    # Fails twice, then the guest "writes" the handoff and the read succeeds.
    r.script(_readfile_prefix(cfg), rc=1, times=2)

    inner = r.run

    def run(argv, **kw):
        done = inner(argv, **kw)
        if "readfile" in argv and done.ok:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text("com.example/.MainActivity\n")
        return done

    r.run = run
    api = FakeApi(sample_bytes=apk_bytes(tmp_path))
    cfg.config_dir.mkdir(parents=True, exist_ok=True)

    lease = FakeLease(target_os="android", submitted_filename="app.apk",
                      sha256=digest(api.sample_bytes))
    S.Analysis(api, r, cfg).run(lease, 3)

    reads = [c for c in r.calls if c.what == "injector readfile"]
    assert len(reads) == 3, f"gave up after {len(reads)} attempt(s)"
    assert states_of(api)[-1] == "completed", api.states[-1]


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
        def fetch_sample(self, url, dest, *, expected_sha256, timeout=None):
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

    The C watcher ignored the exit status too (it printed the status; only the
    timer decides), so hard-failing would diverge from the pipeline this must
    match -- and DRAKVUF exits non-zero for reasons that are not analysis
    failures. But completing SILENTLY is the failure this architecture exists
    to remove."""
    r = runner_ready()
    r.script(("drakvuf",), rc=1, stderr="failed to attach to domain")

    outcome, _ = run(tmp_path, runner=r)

    # Parity with the C watcher, which read DRAKVUF's status and ignored it: the
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

def test_the_console_is_dialled_without_anyone_asking(tmp_path):
    """The request-driven version could never work.

    `_trace` checked `console_wanted` once, BEFORE starting the trace -- and
    the console panel only appeared when the job reached `executing`, which is
    after that check. So the operator could only ask once it was too late to be
    noticed, and the browser sat at "Waiting for the analysis host..." until
    the pair timeout. Observed on Dom0 2026-08-26.

    Now the dial happens because a clone exists, with nobody having asked.
    """
    r = runner_ready()
    run(tmp_path, runner=r, console_enabled=True)

    # The port lookup is the first thing a dial does; the FakeRunner answers
    # nothing useful, so the session is abandoned -- but the ATTEMPT is what
    # proves it no longer waits for a request.
    assert r.ran(("xenstore-read",)), "no console dial was attempted"


def test_the_console_is_dialled_before_preconfig_not_at_the_trace(tmp_path):
    """**Widened 2026-09-05: the window is the CLONE's life, not the trace's.**

    The relay ends at a VNC port QEMU serves for this domain, so it can open as
    soon as `_clone` returns a domid. Dialling at trace start instead left the
    whole of preconfig invisible -- which is where an injector failure happens,
    and where a screen is worth most.

    Asserted against the ordered call log, because "before preconfig" is the
    entire claim.
    """
    r = runner_ready()
    run(tmp_path, runner=r, console_enabled=True)

    names = [c.argv[0] for c in r.calls]
    assert "xenstore-read" in names, "no console dial was attempted"
    assert "injector" in names, "this run never reached preconfig"
    assert names.index("xenstore-read") < names.index("injector"), \
        "the console was dialled after preconfig had already begun"


def test_the_console_is_stopped_before_the_domain_is_destroyed(tmp_path,
                                                               monkeypatch):
    """**Ordering is the whole of the protection here.**

    A relay outliving its domain is a socket pointed at a clone being torn
    down -- the hazard the old `_trace` finally guarded, which moved to `run`
    when the window moved to the clone's lifetime. Swap those two lines and
    nothing else in this suite notices.

    `ConsoleSession` is replaced rather than driven: the real one starts a
    thread that dials the platform, and what is under test is the ORDER of two
    calls in `run`, not the relay itself.
    """
    events = []
    r = runner_ready()
    r.script(("xenstore-read",), stdout="5901\n")

    class FakeSession:
        def __init__(self, *a, **k):
            pass

        def start(self, port):
            events.append(("start", port))

        def stop(self, timeout: float = 5.0):
            # How many commands had been issued by the time it was stopped.
            events.append(("stop", len(r.calls)))

    monkeypatch.setattr(S.vnc, "ConsoleSession", FakeSession)

    run(tmp_path, runner=r, console_enabled=True)

    assert ("start", 5901) in events, "the console was never started"
    stopped_after = next((n for kind, n in events if kind == "stop"), None)
    assert stopped_after is not None, "the console was never stopped"

    destroyed_at = next(i for i, c in enumerate(r.calls)
                        if c.argv[:2] == ("xl", "destroy"))
    assert stopped_after <= destroyed_at, (
        f"the console was stopped after {stopped_after} commands but the "
        f"domain was destroyed at command {destroyed_at}: the relay outlived "
        f"its clone"
    )


def test_a_console_failure_never_fails_the_analysis(tmp_path):
    """The console is an observer of the run, never a participant in its
    lifecycle. A missing VNC port means no screen, not a failed job."""
    r = runner_ready()
    r.script(("xenstore-read",), rc=1)
    r.script(("xl", "list", "-l"), rc=1)

    outcome, api = run(tmp_path, runner=r, console_enabled=True)

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


# --- artifact tickets are batched to the server's cap -----------------------

def test_tickets_are_requested_in_batches_the_server_will_accept(tmp_path):
    """**`ArtifactRequest.artifacts` is capped at 64 names per call.**

    This asked for all of them in one request, so a run producing more than 64
    files got a 422 -- raised as a ProtocolError with no retry, caught by
    `run`'s `except Exception`, and recorded as `failed`. A completely
    successful analysis was discarded, artifacts and all, and `memdump` alone
    routinely produces more than 64 files.
    """
    from sandboxd.postprocessing.paths import DUMPS_DIR
    job_dir = tmp_path / "results" / "job"
    (job_dir / DUMPS_DIR).mkdir(parents=True)
    for i in range(150):
        (job_dir / DUMPS_DIR / f"0x{i:04x}.dmp").write_bytes(b"\xde\xad" * 8)

    api = FakeApi()
    outcome = S.Analysis(api, runner_ready(), config(tmp_path))._collect(
        FakeLease(), job_dir)

    assert outcome.state == "completed"
    assert len(api.uploaded) == 150, "every artifact must still be uploaded"
    assert not outcome.manifest["truncated"]
    assert len(api.ticket_batches) == 3, "150 names over a 64 cap is 3 calls"
    assert all(len(b) <= S.TICKET_BATCH for b in api.ticket_batches)
    # No name asked for twice: minting CHARGES the job's byte budget, so a
    # duplicated request would over-count it.
    minted = [name for batch in api.ticket_batches for name in batch]
    assert sorted(minted) == sorted(api.uploaded)


def test_a_small_run_still_costs_one_ticket_call(tmp_path):
    """Batching must not turn the common case into a request per artifact."""
    job_dir = tmp_path / "results" / "job"
    job_dir.mkdir(parents=True)
    for name in ("trace.log", "capture.pcap"):
        (job_dir / name).write_bytes(b"x")

    api = FakeApi()
    S.Analysis(api, runner_ready(), config(tmp_path))._collect(
        FakeLease(), job_dir)

    assert len(api.ticket_batches) == 1


def test_the_512_cap_does_not_cut_the_upload_loop_short(tmp_path):
    """`truncated` is already True from MAX_ARTIFACTS on a run this size.
    Testing that flag to decide whether to stop uploading -- which an earlier
    draft of this fix did -- would have sent 64 of 512 and called the rest
    truncated."""
    job_dir = tmp_path / "results" / "job"
    job_dir.mkdir(parents=True)
    for i in range(S.MAX_ARTIFACTS + 10):
        (job_dir / f"f{i:04d}.bin").write_bytes(b"x")

    api = FakeApi()
    outcome = S.Analysis(api, runner_ready(), config(tmp_path))._collect(
        FakeLease(), job_dir)

    assert outcome.manifest["truncated"] is True
    assert len(api.uploaded) == S.MAX_ARTIFACTS


# --- SANDBOXD_PLUGINS reaches the argv (DRAKVUF #108/#517) ------------------

def test_the_plugin_override_replaces_the_set_and_nothing_else(tmp_path):
    """The measurement DRAKVUF #108 asks for: the same workload with and
    without a plugin. Only the `-a` list may move -- the timeout and `-F` are
    measured findings, and an override that quietly changed them would make
    the two runs incomparable, which is the one thing the experiment needs.
    """
    r = runner_ready()
    run(tmp_path, runner=r, plugins=("syscalls",))

    argv = [c for c in r.calls if c.argv[0] == "drakvuf"][0].argv
    plugins = [argv[i + 1] for i, a in enumerate(argv) if a == "-a"]

    assert plugins == ["syscalls"]
    assert "-F" in argv, "fast singlestep is not part of the plugin selection"
    assert argv[argv.index("-t") + 1] == "120"


def test_no_override_leaves_the_measured_default_set(tmp_path):
    """A host that never sets the variable must produce byte-identical argv to
    one built before the knob existed -- #41's parity criterion."""
    r = runner_ready()
    run(tmp_path, runner=r)

    argv = [c for c in r.calls if c.argv[0] == "drakvuf"][0].argv
    plugins = [argv[i + 1] for i, a in enumerate(argv) if a == "-a"]
    assert plugins == ["syscalls", "filetracer", "fileextractor", "memdump"]


# --- a dead dependency: downgrade, or refuse? -------------------------------
#
# Both branches of the 2026-09-02 decision, at the level that implements it.
# `test_egress.py` pins DOWNGRADE_ON_FAILURE as data; these pin that
# `_apply_egress` reads it. Inverting the branch there passed the whole suite
# before these existed.

def _analysis_with(tmp_path, *exits):
    cfg = config(tmp_path)
    cfg.exits = (S.egress.OFFLINE_EXIT, *exits)
    cfg.config_dir.mkdir(parents=True, exist_ok=True)
    return S.Analysis(FakeApi(), runner_ready(), cfg)


def _lease_wanting(name: str):
    lease = FakeLease()
    lease.egress_exit = name
    return lease


def test_a_dead_responder_downgrades_the_job_and_records_why(tmp_path,
                                                             monkeypatch):
    """`tor` and `simulated` move towards LESS egress, and say so.

    The job still completes: the sample runs with no network, and the report
    carries `reason` beside the mode so the empty capture is attributable.
    """
    monkeypatch.setattr(S.egress, "listener_ready", lambda *a, **k: False)

    tor = S.Exit(name="tor-default", mode=S.egress.EgressMode.TOR)
    applied = _analysis_with(tmp_path, tor)._apply_egress(
        _lease_wanting("tor-default"), 3)

    assert applied["mode"] == "offline"
    assert applied["exit"] == "offline"
    assert "reason" in applied and "tor" in applied["reason"]


def test_a_dead_tunnel_refuses_the_job_rather_than_downgrading(tmp_path,
                                                               monkeypatch):
    """`routed` is the exception, and deliberately.

    Its rules already fail closed structurally, so a downgrade buys no safety
    and only decides whether the run is spent -- and an `offline` run spends a
    sample that may check in exactly once. Failing leaves it unexecuted.
    """
    monkeypatch.setattr(S.egress, "tunnel_ready", lambda *a, **k: False)

    routed = S.Exit(name="es-vps-1", mode=S.egress.EgressMode.ROUTED,
                    interface="wg0")
    analysis = _analysis_with(tmp_path, routed)

    with pytest.raises(S.EgressUnavailable) as excinfo:
        analysis._apply_egress(_lease_wanting("es-vps-1"), 3)

    assert "wg0" in str(excinfo.value)


def test_a_healthy_dependency_applies_the_mode_that_was_asked_for(tmp_path,
                                                                  monkeypatch):
    """The absence of `reason` is a positive statement, so it must be absent
    when nothing was downgraded."""
    monkeypatch.setattr(S.egress, "listener_ready", lambda *a, **k: True)

    tor = S.Exit(name="tor-default", mode=S.egress.EgressMode.TOR)
    applied = _analysis_with(tmp_path, tor)._apply_egress(
        _lease_wanting("tor-default"), 3)

    assert applied["mode"] == "tor"
    assert "reason" not in applied
