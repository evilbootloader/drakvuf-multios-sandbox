"""One analysis, start to finish.

Issue #41 (DRAFT-060). The sequence `dirwatch.c:run_drakvuf` drives through
five shell callbacks, as one function with the state reporting the platform
expects.

## The shape the server enforces

`/claim` sets the job to `cloning` before this ever runs, and
`WORKER_TRANSITIONS` (routers/worker.py:58) permits:

    cloning    -> preparing  | cleaning
    preparing  -> executing  | cleaning
    executing  -> collecting | cleaning
    collecting -> cleaning
    cleaning   -> completed | failed | cancelled | interrupted

**Every terminal state is reachable only from `cleaning`.** That is not a
formality: it is the server refusing to record an analysis as finished by a
path that did not tear its clone down. So every exit here goes through
`_teardown`, including the ones that failed before a clone existed -- reporting
`cleaning` for a job with nothing to clean is honest, and the alternative is a
409 on the terminal report and a job stuck in `executing` forever.

## Why the heartbeat is not optional

`LEASE_SECONDS` is 120 and the trace phase alone can run to 180. Without a
heartbeat the lease lapses mid-analysis, the platform's maintenance sweep marks
the job `interrupted`, and this process carries on tracing a job that has
already been written off. The beat also carries the ONLY cancellation signal
that can reach a running job, because Dom0 has no inbound listener.
"""

from __future__ import annotations

import hashlib
import shutil
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import guests, timing
from .clone import CloneBuilder, CloneError, CloneSpec
from .guests import Interaction, Job, SampleKind, TargetOs
from .proc import CommandError

# Well inside LEASE_SECONDS=120. Four beats per lease, so two consecutive
# failures still leave a margin -- a single missed beat on a busy platform must
# not cost an analysis.
HEARTBEAT_INTERVAL = 30.0

# DRAFT-018 bounds a manifest at 512 artifacts. `extracted/` is named after
# files the SAMPLE wrote, so the real ceiling is however many it drops; hitting
# the cap sets `truncated` rather than silently listing a prefix.
MAX_ARTIFACTS = 512

# Reserved names from result-schema.md §4.1.
TRACE_LOG = "trace.log"
TRACE_STDERR = "trace.stderr"
PRECONFIG_LOG = "preconfig.log"
CAPTURE = "capture.pcap"


class Cancelled(Exception):
    """The operator asked for this to stop. Not a failure."""


@dataclass
class Outcome:
    state: str
    failure_stage: str | None = None
    failure_reason: str | None = None
    cleanup_status: str | None = None
    manifest: dict | None = None
    artifacts: list = field(default_factory=list)


class Heartbeat:
    """Extends the lease in the background, and watches for cancellation.

    A thread rather than a beat between stages: the trace is a single blocking
    call that outlives the lease, so nothing else would beat during it.
    """

    def __init__(self, api, job_id: str, interval: float = HEARTBEAT_INTERVAL):
        self._api = api
        self._job_id = job_id
        self._interval = interval
        self._stop = threading.Event()
        self.cancelled = threading.Event()
        # Consecutive failed beats. The lease has room for one missed beat --
        # four fit inside LEASE_SECONDS=120 -- but a run of them means the
        # platform has stopped answering and the lease is lapsing, so carrying
        # on would trace a job already written off as interrupted.
        self.missed = 0
        self._thread: threading.Thread | None = None

    def __enter__(self) -> Heartbeat:
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name=f"heartbeat-{self._job_id[:8]}")
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self._interval)

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                beat = self._api.heartbeat(self._job_id)
            except Exception:
                # Not fatal on its own: the platform may be restarting, and the
                # lease has room for a missed beat. Counted rather than merely
                # flagged, because "one blip" and "the platform is gone" need
                # different answers and a boolean cannot tell them apart.
                self.missed += 1
                continue
            self.missed = 0
            if beat.cancel_requested:
                self.cancelled.set()
                return


@dataclass
class Config:
    """Everything about this Dom0 that an analysis needs."""

    vg: str = "vg-root"
    bridge: str = "xenbr1"
    subnet: str = "172.16"
    staging_dir: Path = Path("/var/lib/sandboxd/staging")
    results_dir: Path = Path("/var/lib/sandboxd/results")
    config_dir: Path = Path("/tmp")
    repo_root: Path = Path("/root/drakvuf-multios-sandbox")
    # Per-host, like pipeline-android.env's ${APK_INSTALL_WAIT:-20}. Lowering
    # one below what was measured is how a preconfig starts handing a
    # still-running install to the trace.
    waits: timing.Waits = field(default_factory=timing.Waits)
    # Well inside LEASE_SECONDS=120, so two consecutive failures still leave
    # margin. Configurable because the lease TTL is, and because a fixed value
    # made cancellation untestable without waiting a real interval.
    heartbeat_interval: float = HEARTBEAT_INTERVAL
    injection_pids: dict = field(default_factory=lambda: {
        TargetOs.UBUNTU: 1415, TargetOs.ANDROID: 3174})
    lv_sizes: dict = field(default_factory=lambda: {
        TargetOs.UBUNTU: "64G", TargetOs.ANDROID: "32G"})
    profiles: dict = field(default_factory=lambda: {
        TargetOs.UBUNTU: "profiles/linux.json",
        TargetOs.ANDROID: "profiles/android.json"})

    def origin(self, os_: TargetOs) -> str:
        return f"{os_.value}_sandbox"

    def domain_config(self, os_: TargetOs) -> Path:
        return self.repo_root / "misc" / f"{self.origin(os_)}.cfg"

    def saved_state(self, os_: TargetOs) -> Path:
        return self.repo_root / "state" / f"{self.origin(os_)}.bak"

    def profile(self, os_: TargetOs) -> Path:
        return self.repo_root / self.profiles[os_]


class Analysis:
    """Runs one job. One instance per job; not reused."""

    def __init__(self, api, runner, config: Config):
        self._api = api
        self._runner = runner
        self._cfg = config

    def run(self, lease, vlan: int) -> Outcome:
        """Drive one analysis and return its terminal outcome.

        Never raises for an analysis failure -- a failure is a result, and the
        caller has a VLAN to release and a job row to close either way. It
        raises only if the platform itself becomes unreachable, which is not
        something this can report.
        """
        os_ = TargetOs(lease.target_os)
        job_dir = self._cfg.results_dir / lease.job_id
        sample = self._cfg.staging_dir / lease.job_id / lease.submitted_filename
        clone = None
        outcome = Outcome(state="failed")

        with Heartbeat(self._api, lease.job_id,
                       self._cfg.heartbeat_interval) as beat:
            try:
                job_dir.mkdir(parents=True, exist_ok=True)

                # 1. Fetch. Before the clone, so a store that is unreachable
                #    costs no VM. Bounded by FETCH_BUDGET rather than by the
                #    HTTP client's default: a sample is bounded by the API's
                #    upload cap, not by anything here, and a stalled download
                #    would otherwise hold a worker slot indefinitely.
                self._api.fetch_sample(lease.sample_url, sample,
                                       timeout=timing.FETCH_BUDGET)
                kind = guests.classify(sample)

                clone = self._clone(os_, vlan, lease)
                job = self._job(lease, os_, kind, clone, vlan, job_dir, sample)

                self._check(beat)
                self._api.report_state(lease.job_id, "preparing",
                                       clone_domain=clone.name, vlan=vlan)
                component = self._preconfig(job, beat)

                self._check(beat)
                self._api.report_state(lease.job_id, "executing")
                self._trace(job, component, beat)

                self._check(beat)
                self._api.report_state(lease.job_id, "collecting")
                outcome = self._collect(lease, job_dir)

            except Cancelled:
                outcome = Outcome(state="cancelled")
            except CloneError as exc:
                outcome = Outcome(state="failed", failure_stage=exc.stage,
                                  failure_reason=str(exc)[:2000])
            except CommandError as exc:
                outcome = Outcome(state="failed", failure_stage=exc.what,
                                  failure_reason=str(exc)[:2000])
            except Exception as exc:  # noqa: BLE001 - a failure is a result
                outcome = Outcome(state="failed",
                                  failure_stage="sandboxd",
                                  failure_reason=f"{type(exc).__name__}: {exc}"[:2000])
            finally:
                # ALWAYS, and always before the terminal report: the server
                # refuses every terminal state that does not arrive from
                # `cleaning`.
                outcome.cleanup_status = self._teardown(clone, vlan, sample)

        self._api.report_state(lease.job_id, "cleaning",
                               cleanup_status=outcome.cleanup_status)
        self._report_terminal(lease, outcome)
        return outcome

    # -- stages -------------------------------------------------------------

    def _clone(self, os_: TargetOs, vlan: int, lease):
        spec = CloneSpec(
            origin=self._cfg.origin(os_), vlan=vlan,
            config=self._cfg.domain_config(os_),
            saved_state=self._cfg.saved_state(os_),
            vg=self._cfg.vg, bridge=self._cfg.bridge,
            lv_size=self._cfg.lv_sizes[os_],
        )
        builder = CloneBuilder(self._runner,
                               config_dir=self._cfg.config_dir,
                               budget=timing.CLONE_BUDGET,
                               settle=self._cfg.waits.destroy_settle)
        return builder.build(spec)

    def _job(self, lease, os_, kind, clone, vlan, job_dir, sample) -> Job:
        # Checked first, and explicitly. Reading `injection_pids[os_]` inline
        # below made a Windows job die on a bare KeyError -- Python evaluates
        # the arguments in order, so the dict lookup won the race against
        # `default_trace_options`, which is the one that explains WHY there is
        # no Windows package. A failure_reason of `KeyError: TargetOs.WINDOWS`
        # tells an operator nothing.
        if os_ not in self._cfg.injection_pids:
            raise NotImplementedError(
                f"no injection PID configured for {os_.value}: it is a "
                f"property of that guest's saved memory image, and re-saving "
                f"the template almost certainly changes it. DRAFT-034 owns the "
                f"Windows guest."
            )
        return Job(
            job_id=lease.job_id, target_os=os_,
            submitted_filename=lease.submitted_filename,
            attempt=lease.attempt, domid=clone.domid, vlan=vlan,
            clone_domain=clone.name, sample_path=sample,
            profile=self._cfg.profile(os_),
            injection_pid=self._cfg.injection_pids[os_],
            result_dir=job_dir,
            options=guests.default_trace_options(os_, kind),
            kind=kind,
        )

    def _preconfig(self, job: Job, beat: Heartbeat) -> str | None:
        """Stage the sample and configure the clone. Returns an APK component.

        The order is deliberate and matches the scripts: delivery FIRST,
        before any network exists, because it does not depend on guest
        networking -- which is what keeps an offline analysis mode reachable.
        """
        log = job.result_dir / PRECONFIG_LOG
        budgets = timing.budgets(job.target_os, job.kind,
                                 job.options.timeout, self._cfg.waits)

        self._runner.run(guests.argv_deliver(job), timeout=budgets.preconfig,
                         what="injector writefile", check=True,
                         stdout_path=log, stderr_path=log.with_suffix(".stderr"))

        self._check(beat)
        self._runner.run(guests.argv_configure_network(job, self._cfg.subnet),
                         timeout=budgets.preconfig,
                         what="injector network configuration", check=True)

        if job.kind is not SampleKind.APK:
            return None

        handoff = f"{guests.PATHS[job.target_os].staging_dir}/.pm.tmp"
        self._runner.run(guests.argv_install_apk(job, handoff),
                         timeout=budgets.preconfig, what="pm install",
                         check=True)

        # execproc returns at process START, so this sleep is the only
        # synchronisation Dom0 has. Returning early would hand a still-running
        # install to the trace, which is the slowdown the split removes.
        self._sleep(self._cfg.waits.apk_install, beat)

        dest = job.result_dir / "launch-component"
        self._runner.run(guests.argv_read_component(job, handoff, dest),
                         timeout=budgets.preconfig, what="injector readfile")
        # Removed before the sample runs: a file in its own staging directory
        # naming its own component is what an evasive application looks for.
        self._runner.run(guests.argv_remove_handoff(job, handoff),
                         timeout=budgets.preconfig, what="injector rm")

        component = dest.read_text().strip() if dest.exists() else ""
        if not guests.component_is_launchable(component):
            raise CommandError("resolve-activity", _no_component(component))
        return component

    def _trace(self, job: Job, component: str | None, beat: Heartbeat) -> None:
        """Run DRAKVUF with the capture alongside it."""
        budgets = timing.budgets(job.target_os, job.kind,
                                 job.options.timeout, self._cfg.waits)

        if job.options.interaction is not Interaction.NONE:
            # DRAFT-055 (hidsim) and DRAFT-056 (VNC). Nothing supplies this
            # yet -- the submit form has no such control -- so reaching here
            # means a future change wired an input without wiring its
            # behaviour, which should fail loudly rather than run unattended
            # while claiming otherwise.
            raise NotImplementedError(
                f"interaction={job.options.interaction.value} is not "
                f"implemented; DRAFT-055 and DRAFT-056 own it"
            )

        capture = job.result_dir / CAPTURE
        tcpdump = self._runner.spawn(
            guests.argv_tcpdump(job, self._cfg.bridge, capture))
        try:
            self._sleep(timing._trace_waits(job.target_os, job.kind,
                                            self._cfg.waits), beat)
            result = self._runner.run(
                guests.argv_trace(job, component),
                timeout=budgets.trace, what="drakvuf",
                # SEPARATE, and there is no merge option. `-o json` makes
                # stdout a JSONL event stream and `2>&1` is what contaminates
                # it -- which is what blocks capa (DRAFT-019).
                stdout_path=job.result_dir / TRACE_LOG,
                stderr_path=job.result_dir / TRACE_STDERR,
            )
            # NOT `check=True`, and the choice is deliberate rather than an
            # omission -- it was one, found in review, which is why it is
            # spelled out.
            #
            # dirwatch reads DRAKVUF's exit status and then ignores it
            # (dirwatch.c:663 prints it; only `start->timer` decides), so
            # failing here would diverge from the pipeline this must match.
            # DRAKVUF also exits non-zero for reasons that are not analysis
            # failures -- a traced process ending oddly, for one.
            #
            # But completing silently after a trace that never attached is the
            # exact failure this architecture exists to remove: correct-looking
            # output with nothing behind it. So the artifacts are kept, the job
            # completes, and the status is RECORDED -- `trace.log` at 0 bytes
            # in the manifest, beside a note naming the exit code, is
            # diagnosable where a bare `completed` is not.
            self._trace_note = None
            if not result.ok:
                self._trace_note = (
                    f"drakvuf exited {result.returncode}"
                    + (" (timed out)" if result.timed_out else "")
                    + f"; see {TRACE_STDERR}"
                )
        finally:
            tcpdump.stop()

    def _collect(self, lease, job_dir: Path) -> Outcome:
        """Upload what the run produced and build its manifest."""
        found = sorted(p for p in job_dir.rglob("*") if p.is_file())
        truncated = len(found) > MAX_ARTIFACTS
        found = found[:MAX_ARTIFACTS]

        entries = []
        for path in found:
            rel = str(path.relative_to(job_dir))
            entries.append({"name": rel, "size_bytes": path.stat().st_size,
                            "sha256": _digest(path)})

        deadline = time.monotonic() + timing.COLLECT_BUDGET
        if entries:
            tickets = self._api.artifact_tickets(
                lease.job_id, {e["name"]: e["size_bytes"] for e in entries})
            uploaded = []
            for entry in entries:
                if time.monotonic() > deadline:
                    # Out of budget with artifacts still to send. The manifest
                    # must describe what was UPLOADED, not what was found:
                    # listing an artifact that never reached the store is a
                    # download link that 404s.
                    truncated = True
                    break
                ticket = tickets.get(entry["name"])
                if ticket is None:
                    continue
                self._api.upload_artifact(ticket, entry["name"],
                                          job_dir / entry["name"])
                uploaded.append(entry)
            entries = uploaded

        manifest = {"schema_version": 1, "artifacts": entries,
                    "documents": [], "truncated": truncated}
        note = getattr(self, "_trace_note", None)
        if note:
            manifest["notes"] = note
        return Outcome(
            state="completed", manifest=manifest,
            artifacts=[e["name"] for e in entries],
        )

    def _teardown(self, clone, vlan: int, sample: Path) -> str:
        """Destroy the clone and remove the sample. Never raises.

        Runs on every path -- success, failure, cancellation -- because a clone
        left running is malware with NAT'd egress and nothing watching it. That
        was a real defect in dirwatch before 2026-08-19: cleanup ran only in
        the timeout branch, so a normal completion left its clone up until the
        next sample happened to take the same VLAN slot.
        """
        problems = []
        if clone is not None:
            for argv, what in (
                (["xl", "pause", clone.name], "pause"),
                (["xl", "destroy", clone.name], "destroy"),
                (["lvremove", "-f", f"/dev/{self._cfg.vg}/{clone.name}"],
                 "lvremove"),
            ):
                try:
                    r = self._runner.run(argv, timeout=timing.CLEANUP_BUDGET,
                                         what=what)
                    if not r.ok and what != "pause":
                        problems.append(what)
                except Exception:
                    problems.append(what)
            clone.config_path.unlink(missing_ok=True)

        # The sample, and the directory it sat in. It reached Dom0 disk because
        # `injector -m writefile -B` takes a path and there is no stdin form.
        try:
            shutil.rmtree(sample.parent, ignore_errors=True)
        except OSError:
            problems.append("staging")

        return "clean" if not problems else "dirty: " + ",".join(problems)

    # -- reporting ----------------------------------------------------------

    def _report_terminal(self, lease, outcome: Outcome) -> None:
        extra = {}
        if outcome.failure_stage:
            extra["failure_stage"] = outcome.failure_stage
        if outcome.failure_reason:
            extra["failure_reason"] = outcome.failure_reason
        self._api.report_state(lease.job_id, outcome.state, **extra)
        if outcome.state == "completed" and outcome.manifest is not None:
            self._api.complete(lease.job_id, outcome.manifest)

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _check(beat: Heartbeat) -> None:
        if beat.cancelled.is_set():
            raise Cancelled()

    @staticmethod
    def _sleep(seconds: float, beat: Heartbeat) -> None:
        """Wait, but notice a cancellation while waiting.

        A plain `sleep(20)` through the APK install would ignore a cancel for
        the whole of it, which is most of the preconfig phase.
        """
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if beat.cancelled.is_set():
                raise Cancelled()
            time.sleep(min(0.5, deadline - time.monotonic()))


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _no_component(got: str):
    from .proc import Completed
    return Completed(
        argv=("cmd", "package", "resolve-activity"), returncode=1, stdout="",
        stderr=f"no usable launcher component (got {got!r}); nothing executed. "
               f"An APK need not declare a launcher activity at all.",
        duration=0.0,
    )