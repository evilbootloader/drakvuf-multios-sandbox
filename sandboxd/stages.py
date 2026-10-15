"""One analysis, start to finish.

Issue #41 (DRAFT-060). The sequence the C watcher drove through five shell
callbacks, as one function with the state reporting the platform expects.

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
import logging
import shutil
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

from . import config, egress, guests, timing, vnc
from .clone import CloneBuilder, CloneError, CloneSpec
from .egress import EgressUnavailable, Exit
from .guests import Interaction, Job, SampleKind, TargetOs, TraceOptions
from .proc import CommandError
from .postprocessing.paths import (DUMPS_DIR, DUMPS_ZIP, EXTRACTED_DIR,
                                   EXTRACTED_ZIP, IPT_DIR, IPT_ZIP)
from .postprocessing.postprocess import postprocess_analysis_dir
from .postprocessing.plugins.plugin_base import load_postprocessing_config

# Well inside LEASE_SECONDS=120: twelve beats per lease, so a run of failures
# on a busy platform is survivable where a single missed beat used to eat a
# quarter of the margin.
#
# Lowered from 30s on 2026-08-26, and the console is why. The beat is the only
# channel that can reach a running job -- Dom0 has no inbound listener -- so
# **one interval is the latency floor for opening a live console** (DRAFT-056)
# and for a cancellation landing. At 30s an operator waited half a minute to
# see a screen; at 10s it is prompt enough to be usable.
#
# The cost is one small row UPDATE per beat per running job. With MAX_CLONES=2
# that is twelve updates a minute, against a Postgres on the same container.
log = logging.getLogger("sandboxd.stages")

HEARTBEAT_INTERVAL = 10.0


def _must_stay_inside(path: Path, root: Path, what: str) -> None:
    """Refuse a path that escaped the directory it was built from.

    `naming` rejects the values that could do this before they are joined, so
    reaching here means either that check was weakened or a new caller built a
    path some other way. Either is worth stopping for: the paths guarded by
    this are handed to `open(..., "wb")` and `shutil.rmtree` as root.

    `resolve()` on both sides, so `..` and any symlink in the staging or
    results tree are settled before the comparison rather than after it.
    """
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(
            f"{what} path escapes its root: {path} is not inside {root}. "
            f"Refusing the job rather than writing outside the tree."
        )

# DRAFT-018 bounds a manifest at 512 artifacts. `extracted/` is named after
# files the SAMPLE wrote, so the real ceiling is however many it drops; hitting
# the cap sets `truncated` rather than silently listing a prefix.
MAX_ARTIFACTS = 2048

# **`ArtifactRequest.artifacts` on the platform is capped at 64 names, and that
# cap is PER CALL rather than per job** -- routers/worker.py says so and invites
# a second call. This module used to ask for all of them in one request, so any
# run producing more than 64 files got a 422, which `_post` raises as a
# ProtocolError with no retry, which `run` records as `failed`. A completely
# successful analysis was thrown away, artifacts and all, and `memdump` alone
# routinely produces more than 64 files.
#
# Must not exceed the server's `max_length`. Lower is safe; higher is the bug
# above.
TICKET_BATCH = 64

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
        # Set when the operator asks for a live console. An Event rather than a
        # flag because the trace is a blocking call: the stage machine waits on
        # this without polling the API itself.
        self.console_wanted = threading.Event()
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
                # lease has room for a missed beat -- four fit inside
                # LEASE_SECONDS=120.
                #
                # **A sustained outage is NOT handled here, deliberately.** A
                # counter of consecutive failures used to be kept, with a
                # comment arguing that "one blip" and "the platform is gone"
                # need different answers -- but nothing ever read it, so the
                # answer was the same either way. Rather than leave a field
                # describing behaviour that does not exist, the honest position
                # is recorded: if the platform stays away the lease lapses,
                # `maintenance.reap` marks the job `interrupted`, and this run
                # traces to the end of its budget and then gets a 409 on its
                # terminal report. Wasteful, bounded, and not silent.
                continue
            if beat.console_requested:
                self.console_wanted.set()
            if beat.cancel_requested:
                self.cancelled.set()
                return


@dataclass
class Config:
    """Everything about this Dom0 that an analysis needs."""

    # **Defaults come from `sandboxd/config.py`, which is where an operator
    # tunes this host.** They were literals here until 2026-08-31, duplicating
    # `automation/platform.env` -- so changing the bridge there moved the shell
    # pipeline and left sandboxd writing the old name into every clone config.
    # A clone on a bridge with no isolation rules looks like a working analysis.
    vg: str = config.VG_NAME
    bridge: str = config.ANALYSIS_BRIDGE
    subnet: str = config.SUBNET_PREFIX
    staging_dir: Path = config.STAGING_DIR
    results_dir: Path = config.RESULTS_DIR
    config_dir: Path = config.CONFIG_DIR
    repo_root: Path = config.DOM0_REPO_ROOT
    ubuntu_injection_pid: int = config.INJECTION_PID_UBUNTU
    windows_injection_pid: int = config.INJECTION_PID_WINDOWS
    android_injection_pid: int = config.INJECTION_PID_ANDROID
    # Per-host, as the Android env file's ${APK_INSTALL_WAIT:-20} already was.
    # Lowering one below what was measured is how a preconfig starts handing a
    # still-running install to the trace -- see `timing.py` for each number and
    # what measured it.
    waits: timing.Waits = field(default_factory=timing.Waits)
    # Well inside LEASE_SECONDS=120, so two consecutive failures still leave
    # margin. Configurable because the lease TTL is, and because a fixed value
    # made cancellation untestable without waiting a real interval.
    heartbeat_interval: float = config.HEARTBEAT_INTERVAL
    # SANDBOXD_PLUGINS. None means "use the measured per-OS defaults", which is
    # what an unset variable gives -- so absence is exactly today's behaviour.
    # A measurement tool for sizing a plugin's cost (DRAKVUF #108) rather than
    # a configuration knob; DRAFT-052 records a real per-job selection and
    # supersedes it. See guests.parse_plugins_override.
    plugins: tuple[str, ...] | None = None

    # --- live console (DRAFT-056), off unless the platform asks -------------
    #
    # `console_enabled` here is a local kill switch, set from
    # SANDBOXD_CONSOLE_ENABLED. The platform has its own CONSOLE_ENABLED and
    # will simply never set console_requested when it is off, so this is a
    # second, Dom0-side "no" -- an operator can refuse sessions on this host
    # without touching the platform.
    #
    # **Off by default, and it really is off**, which it was not until
    # 2026-08-27: the field read `True` with no environment override at all,
    # while the comment below and routers/console.py both said the console was
    # off by default on both sides. A host therefore opened a relay socket per
    # analysis with no way to stop it short of editing this file, and only the
    # platform's own default kept that from reaching anything.
    #
    # DEPLOYMENT NOTE: a Dom0 that was relying on the old hard-coded `True`
    # must now set SANDBOXD_CONSOLE_ENABLED=1 to keep serving consoles.
    console_enabled: bool = config.CONSOLE_ENABLED
    api_base: str = ""
    # The listener the BROWSER reaches -- see Settings.console_api.
    console_api: str = ""
    worker_token: str = ""
    ssl_context: object = None
    # The anchor must be schedulable with no guest input -- `nano`, `gedit` and
    # a SIGTTIN-stopped background job are all not -- and it must be root.
    #
    # **Only Ubuntu anchors on PID 1.** systemd, so samples run as root; that
    # cost was accepted deliberately when the Ubuntu path was built, and is
    # accepted still.
    #
    # Android went to PID 1 on 2026-08-29 and came back on 2026-08-31, because
    # Android's `init` does not provide a runtime environment for
    # `app_process64` and the APK path needs one. So the anchor is a
    # backgrounded `ping` against 127.0.0.1 -- self-scheduling, single-threaded,
    # and aimed at loopback so anchor traffic stays out of the per-sample pcap.
    # The full case, including the argument for PID 1 that it reversed, is in
    # `docs/checklists/android.md` and `docs/TROUBLESHOOTING.md`.
    #
    # **The costs PID 1 removed are therefore live again for Android, and for
    # Windows, which is the same shape.** These PIDs are valid only for the
    # .bak they were read from and must be re-derived after every template
    # re-save; a stale one fails SILENTLY, because `injector` attaches to
    # whatever PID it is handed. Android has been 3163, 3164, 3174 and now
    # 3251.
    #
    # **Windows 4696 was recorded once, not three times.** Android's list above
    # is what makes its current value trustworthy -- the anchor was confirmed
    # stable across re-saves. DRAFT-034 asked for the same three-boot record on
    # Windows and closed without it, so 4696 rests on the single job of
    # 2026-09-05. Treat a Windows trace that produces nothing as a question
    # about this number first.
    #
    # Do not auto-discover either by process-name grep: Android runs two
    # processes named `init`, and the anchor is deliberately unremarkable so
    # the string `drakvuf` appears nowhere a sample can read (issue #7).
    injection_pids: dict = field(default_factory=lambda: {
        os_: pid
        for os_, pid in {
            TargetOs.UBUNTU: config.INJECTION_PID_UBUNTU,
            TargetOs.WINDOWS: config.INJECTION_PID_WINDOWS,
            TargetOs.ANDROID: config.INJECTION_PID_ANDROID,
        }.items()
        if pid
    })
    # `lv_sizes` was dropped 2026-08-29 with CLONE_LV_SIZE. Clones are thin
    # snapshots and inherit the golden LV's size, so there is no per-OS
    # number left to hold -- see clone.argv_lvcreate.
    profiles: dict = field(default_factory=lambda: {
        TargetOs.UBUNTU: "profiles/linux.json",
        TargetOs.ANDROID: "profiles/android.json",
        TargetOs.WINDOWS: "profiles/windows.json"})

    # --- egress (DRAFT-057) -------------------------------------------------
    #
    # What this host can offer, resolved once at startup from `config.EXITS`
    # and `SANDBOXD_ALLOW_DIRECT`. Read per job to match the name the lease
    # carries; a name not in here is refused rather than approximated.
    #
    # Defaults to offline-only, which is also what an unconfigured host gets.
    # That is the correct failure direction: a host that cannot work out what
    # it offers runs samples with no way out, rather than with whichever way
    # out happened to be lying around.
    exits: tuple[Exit, ...] = field(
        default_factory=lambda: (egress.OFFLINE_EXIT,))

    def origin(self, os_: TargetOs) -> str:
        return f"{os_.value}_sandbox"

    def domain_config(self, os_: TargetOs) -> Path:
        return self.repo_root / "misc" / "xen-vms" / f"{self.origin(os_)}.cfg"

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

        # Belt and braces over `api.py`'s grammar check, and cheap.
        #
        # The grammar is what SHOULD make these containable; this asserts that
        # they actually are, on the joined result, which is the thing that gets
        # opened and rmtree'd as root. Two independent mechanisms, for the same
        # reason the isolation chain denies clone-to-clone twice: the property
        # is worth more than either check.
        _must_stay_inside(job_dir, self._cfg.results_dir, "results")
        _must_stay_inside(sample, self._cfg.staging_dir, "staging")
        clone = None
        console = None
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
                # The digest the platform admitted, checked against the bytes
                # that will actually run. `fetch_sample` raises rather than
                # returning on a mismatch, so `classify` below can only ever
                # see the admitted sample.
                self._api.fetch_sample(lease.sample_url, sample,
                                       expected_sha256=lease.sha256,
                                       timeout=timing.FETCH_BUDGET)
                kind = guests.classify(sample)

                clone = self._clone(os_, vlan, lease)
                job = self._job(lease, os_, kind, clone, vlan, job_dir, sample)

                # **Dialled as soon as the domain exists, not at trace start.**
                #
                # The console's window is the CLONE's lifetime, not the trace's
                # (2026-09-05). The relay ends at a VNC port QEMU serves for
                # this domain, so it can be opened the moment `_clone` returns
                # a domid -- which lets an operator watch preconfig, where an
                # injector failure is otherwise only visible as a log line
                # after the fact.
                #
                # Started BEFORE egress is applied deliberately: if a rule fails
                # to install, the screen showing what the guest is doing is
                # exactly what is wanted, and `_start_console` never fails the
                # analysis.
                console = self._start_console(job, beat)

                # 2. Egress, BEFORE the guest's network is configured and long
                #    before the sample runs. Ordered this way so that a clone
                #    never holds an address on a VLAN whose way out has not
                #    been decided -- the window in which it would be routed by
                #    whatever rule happened to be there.
                #
                #    Deliberately AFTER the clone exists: the rules name the
                #    VLAN, and installing them for a clone that then fails to
                #    build would leave a permit with nothing behind it.
                self._check(beat)
                applied = self._apply_egress(lease, vlan)

                self._api.report_state(lease.job_id, "preparing",
                                       clone_domain=clone.name, vlan=vlan,
                                       egress=applied)
                component = self._preconfig(job, beat)

                self._check(beat)
                self._api.report_state(lease.job_id, "executing")
                self._trace(job, component, beat)

                self._check(beat)
                self._api.report_state(lease.job_id, "collecting")


                postprocessing_config = load_postprocessing_config()
                postprocess_analysis_dir(job_dir, postprocessing_config, os_)

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
                # **The console ends before the domain does, on every path.**
                #
                # `_teardown` destroys the clone, and a relay still pointed at
                # its VNC port is a socket into a domain being torn down --
                # which is what the old `_trace` finally protected against when
                # the window was the trace. The hazard moved with the window,
                # so the stop moved with it. Ordering here is the whole of that
                # protection: these two lines must not be swapped.
                if console is not None:
                    console.stop()

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
        )
        builder = CloneBuilder(self._runner,
                               config_dir=self._cfg.config_dir,
                               budget=timing.CLONE_BUDGET,
                               settle=self._cfg.waits.destroy_settle)
        return builder.build(spec)

    def _resolve_exit(self, lease) -> Exit:
        """Match the name the job asked for against what this host declares.

        **Fails closed twice.** A lease naming no exit -- an older platform, or
        a job created before DRAFT-057 -- gets `offline`, because the safe
        reading of "nobody said" is "no way out". A lease naming an exit this
        host does not have is refused outright rather than downgraded: the
        submitter asked a specific question about where their sample's traffic
        goes, and silently answering a different one produces a report whose
        network section means something other than what it says.
        """
        wanted = getattr(lease, "egress_exit", None)
        if not wanted:
            return egress.OFFLINE_EXIT

        for candidate in self._cfg.exits:
            if candidate.name == wanted:
                return candidate

        raise EgressUnavailable(
            f"job asked for exit {wanted!r}, which this host does not offer. "
            f"Available: {', '.join(e.name for e in self._cfg.exits)}. The "
            f"platform should have refused this at submission -- it offers only "
            f"what this host declared, so the two have diverged."
        )

    def _apply_egress(self, lease, vlan: int) -> dict:
        """Install this job's way out, and return what was actually installed.

        The return value goes on the job row and onto the report. It records
        what the host DID, which is not always what was asked for, and the
        difference is the point: DRAFT-057 makes recording the mode a
        correctness requirement, because a report showing no network activity
        means nothing without knowing whether egress existed at all.
        """
        exit_ = self._resolve_exit(lease)
        fallback_reason = None

        # **Re-checked here, not just at startup.** A responder that was up
        # when the host registered can be down by the time a job actually
        # runs -- tor restarted, FakeNet crashed, the operator stopped it.
        # Installing the rules anyway would redirect the clone's traffic to a
        # closed port, and the analysis would complete having observed a sample
        # that "could not connect" when in fact nothing was listening.
        #
        # Falling back to `offline` is the maintainer's decision (2026-08-31)
        # and it only ever moves towards LESS egress. It is recorded rather
        # than silent: the report shows what was requested beside what ran.
        unhealthy = egress.dependency_reason(exit_)
        if unhealthy:
            if exit_.mode in egress.DOWNGRADE_ON_FAILURE:
                fallback_reason = (
                    f"{unhealthy} at launch; ran with no network instead")
                log.warning("job %s: %s", lease.job_id, fallback_reason)
                exit_ = egress.OFFLINE_EXIT
            else:
                # **Fails rather than downgrading, and the difference is
                # deliberate** (2026-09-02, docs/architecture/routed-egress.md).
                #
                # Downgrading is justified for the redirect modes because it
                # only ever moves towards LESS egress. `routed` already fails
                # closed structurally -- nothing in its rules names the uplink
                # -- so nothing escapes either way and a downgrade buys no
                # safety at all. What it would cost is the run: `offline`
                # spends a sample that may only ever check in once, and the
                # report would correctly say it did nothing. Failing leaves the
                # sample unexecuted and re-submittable.
                raise EgressUnavailable(
                    f"job asked for exit {exit_.name!r} ({exit_.mode.value}) "
                    f"and {unhealthy}. Refused rather than downgraded: the "
                    f"submitter asked to reach the Internet from somewhere "
                    f"specific, and running with no network instead answers a "
                    f"different question while spending the sample."
                )

        for argv in egress.argv_apply(vlan, exit_, bridge=self._cfg.bridge,
                                      subnet=self._cfg.subnet):
            # check=True throughout. A partly-installed rule set is the one
            # outcome worse than none: the jumps are added last, so failing
            # here leaves the clone with no egress, which is safe -- but
            # continuing as though the mode were applied would put a sample on
            # a network nobody chose.
            self._runner.run(argv, timeout=timing.CLEANUP_BUDGET,
                             what="egress apply", check=True)

        log.info("job %s: egress %s via %s", lease.job_id, exit_.mode.value,
                 exit_.interface or "no interface (nothing is forwarded)")

        applied = {
            "mode": exit_.mode.value,
            "exit": exit_.name,
            "interface": exit_.interface,
            "country": exit_.country,
            # Rendered on the report so that "no SMTP traffic" and "SMTP was
            # blocked upstream" are different sentences on the page.
            "caveats": list(exit_.caveats),
        }
        if fallback_reason:
            # Present ONLY when something was downgraded, so its absence is a
            # positive statement that the job got what it asked for.
            applied["reason"] = fallback_reason
        return applied

    def _trace_options(self, os_, kind, plugins, timeout, disable_sysret) -> TraceOptions:
        """The measured defaults, unless the job or the host overrides them.

        Three layers, weakest first, and the order is the point:

        1. `guests.default_trace_options(os_, kind)` -- the measured per-OS
           package. It decides the timeout, `-F`, `--disable-sysret` and the
           interaction mode, and NONE of those move below. Only the plugin
           list does.
        2. The job's own selection (DRAFT-052), when it made one.
        3. `SANDBOXD_PLUGINS`, which is a measurement tool and therefore has
           the last word -- see `guests.parse_plugins_override`.

        **An empty selection means "the defaults", not "no plugins".** A job
        queued before migration 0010 has `plugins = NULL`, and the lease
        renders that as `[]`; so does a submitter who ticked nothing. Reading
        either as a literal empty set would run DRAKVUF with no `-a` at all,
        which completes normally and produces a trace containing nothing --
        the silent absence of evidence `parse_plugins_override` warns about
        for the same reason.

        The host override is applied HERE rather than inside
        `guests.default_trace_options` so that function stays pure and keeps
        answering one question: what do the shell scripts do for this guest.
        Mixing a host's environment into it would make the answer depend on
        where it was asked, and #41's acceptance criterion is that the port
        produces the same argv the scripts do.
        """
        options = guests.default_trace_options(os_, kind)
        if plugins:
            options = replace(options, plugins=tuple(plugins))
        if timeout:
            options = replace(options, timeout=timeout)
        if isinstance(disable_sysret, bool):
            options = replace(options, disable_sysret=disable_sysret)
        if self._cfg.plugins is None:
            return options
        return replace(options, plugins=tuple(self._cfg.plugins))

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
                f"the template almost certainly changes it. Re-derive it from "
                f"the new .bak and set it in StageConfig.injection_pids -- "
                f"see the anchor note there."
            )

        return Job(
            job_id=lease.job_id, target_os=os_,
            submitted_filename=lease.submitted_filename,
            attempt=lease.attempt, domid=clone.domid, vlan=vlan,
            clone_domain=clone.name, sample_path=sample,
            profile=self._cfg.profile(os_),
            injection_pid=self._cfg.injection_pids[os_],
            result_dir=job_dir,
            options=self._trace_options(os_, kind, lease.plugins, lease.timeout, lease.disable_sysret),
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

        # **`budgets.preconfig` guards the PHASE, and this deadline is what
        # makes that true.** It was passed as the `timeout=` of each command
        # instead, so the real ceiling was the budget times the number of
        # injections plus the APK sleep -- up to 320s on the Android APK path
        # for a phase whose stated guard is 60s. `PhaseBudgets` calls these
        # "wall-clock guards over a whole stage, distinct from the per-command
        # timeouts in clone.py", and `timing.budgets` argues the value "cannot
        # be under-set by arithmetic"; neither was so while each command got
        # the whole budget to itself.
        #
        # RISK, stated plainly because it has not been measured: the Android
        # APK path must now fit a 12 MB `writefile`, a network injection, a
        # `pm install`, the 20s install wait, a `readfile` and an `rm` inside
        # 60s. The 12 MB writefile has never been timed, and the one evidenced
        # APK run (2026-08-17) completed under the old unbounded behaviour. If
        # this budget proves too tight the symptom is a preconfig timeout,
        # clone teardown and a retry -- the loop `timing.budgets` warns about
        # -- and the fix is to raise the floor in `timing.budgets`, not to
        # restore the per-command timeouts.
        deadline = time.monotonic() + budgets.preconfig

        def left(what: str) -> float:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CommandError(
                    what, _phase_overran("preconfig", what, budgets.preconfig))
            return remaining

        self._runner.run(guests.argv_deliver(job), timeout=left("writefile"),
                         what="injector writefile", check=True,
                         stdout_path=log, stderr_path=log.with_suffix(".stderr"))

        self._check(beat)
        self._runner.run(guests.argv_configure_network(job, self._cfg.subnet),
                         timeout=left("network configuration"),
                         what="injector network configuration", check=True)

        if job.kind is not SampleKind.APK:
            return None

        # **The APK path is Android's, and this used to branch on `kind` ALONE.**
        # `guests.argv_install_apk` hardcodes Android's shell, while the handoff
        # below comes from `PATHS[job.target_os]` -- so an APK submitted against
        # Ubuntu on 2026-08-29 built `injector -r .../linux.json -e
        # /system/bin/sh` with a /home/carlos/Desktop handoff and died at execve
        # with ENOENT, one clone and several minutes in.
        #
        # The platform now refuses that combination at submission
        # (`routers/jobs.py` _CONTRADICTS), which is where it belongs -- this is
        # the second line, for a job admitted before that rule existed or by a
        # caller that is not the UI. Failing loudly beats composing a command
        # out of two guests' paths.
        if job.target_os is not TargetOs.ANDROID:
            raise NotImplementedError(
                f"an APK was routed to {job.target_os.value}: only Android can "
                f"install one, and the install path is Android-specific. The "
                f"submission should have been refused as a detected-type "
                f"contradiction."
            )

        handoff = f"{guests.PATHS[job.target_os].staging_dir}/.pm.tmp"
        self._runner.run(guests.argv_install_apk(job, handoff),
                         timeout=left("pm install"), what="pm install",
                         check=True)

        dest = job.result_dir / "launch-component"
        component = self._await_component(job, handoff, dest, left, beat)
        # Removed before the sample runs: a file in its own staging directory
        # naming its own component is what an evasive application looks for.
        #
        # Checked for the same reason, and one more: the comment above states a
        # guarantee. Unchecked, a failed `rm` leaves the guest holding exactly
        # the artifact this exists to remove, silently, for every subsequent
        # analysis. It is also not plausibly an isolated failure -- the readfile
        # immediately above proves injection works, so an `rm` that fails here
        # means something changed underneath the run and the trace is not worth
        # starting.
        self._runner.run(guests.argv_remove_handoff(job, handoff),
                         timeout=left("rm"), what="injector rm", check=True)
        return component

    def _await_component(self, job: Job, handoff: str, dest: Path,
                         left, beat: Heartbeat) -> str:
        """Read the handoff until it holds a launcher component, or give up.

        **Replaces a fixed sleep that was timing the wrong thing** (2026-09-04).
        `execproc` returns when the guest shell STARTS, so Dom0 had no
        completion signal and slept `APK_INSTALL_WAIT` instead. The install fits
        that easily; `pm list packages`, which runs before it, does not always
        -- it waits on the package service, which a freshly restored clone may
        not have up yet. The handoff is created by the install line's redirect,
        so a slow service means this `readfile` returns `-ENOENT` and a healthy
        sample fails. Intermittently, because a warm service returns at once.

        **Polling for the FILE would be wrong, and quietly so.** The handoff is
        written twice: `pm install` redirects its own output there first, on
        purpose, so a failed install explains itself, and `resolve-activity`
        overwrites it on success. An existence check therefore passes on the
        install diagnostic and hands it on as a component -- rejected downstream
        as "no usable launcher component", blaming the sample for a Dom0-side
        timing fault. That is the misdiagnosis the 2026-08-29 redirect fix
        removed, arriving by a different route. So the predicate is the content:
        `component_is_launchable`, the same one that gates the return value.

        **On expiry the two failures are reported differently, and keeping them
        apart is most of the value here.** A `readfile` that never succeeded is
        reported AS a readfile failure, carrying `injector`'s own output --
        `syscall return code: -2`, `Could not open file in guest`. That message
        is what made this bug diagnosable at all, and collapsing it into "no
        usable launcher component" would have thrown it away. Only when the
        read succeeded and the content is not a component does this report
        `resolve-activity`, which is the honest answer for an APK that declares
        no launcher activity.
        """
        # `check=False` INSIDE the loop, and this is NOT a relaxation of the
        # 2026-08-29 fix that made this checked. That fix existed so a failed
        # injection could not masquerade as an APK with no launcher activity,
        # and the branch below preserves exactly that: the failure is still
        # raised, still named `injector readfile`, still carrying the guest's
        # words. What changed is that ENOENT is now the EXPECTED answer while
        # the guest shell is still behind us, so it must not end the job on the
        # first attempt -- the deadline is what turns "not yet" into a failure.
        argv = guests.argv_read_component(job, handoff, dest)
        deadline = time.monotonic() + self._cfg.waits.apk_component_timeout
        last = ""
        while True:
            self._check(beat)
            done = self._runner.run(argv, timeout=left("readfile"),
                                    what="injector readfile", check=False)
            if done.ok and dest.exists():
                last = dest.read_text().strip()
            if guests.component_is_launchable(last):
                return last
            if time.monotonic() >= deadline:
                if not done.ok:
                    raise CommandError("injector readfile", done)
                raise CommandError("resolve-activity", _no_component(last))
            self._sleep(self._cfg.waits.apk_component_poll, beat)

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
        # **The console is NOT started here**, and has not been since
        # 2026-09-05. It is dialled in `run()` as soon as the clone exists and
        # stopped there before teardown, so its window is the domain's lifetime
        # rather than the trace's -- see the comment at the `_start_console`
        # call. Starting it here would open a second relay for the same job.
        #
        # It is not request-driven either, and never can be. That version could
        # NEVER work: the panel only appeared once the job reached `executing`,
        # so the operator could only ask after the trace had begun -- and the
        # check happened before it. Every request arrived too late and the
        # browser sat at "Waiting for the analysis host..." until the pair
        # timeout (Dom0 2026-08-26, F8).
        #
        # So a relay socket is opened for every analysis whenever the console is
        # enabled on this host. `console_enabled` therefore means "this host
        # opens a relay socket per analysis" rather than "consoles may be
        # requested" -- which is why it is off by default and why turning it on
        # is a deliberate act (SANDBOXD_CONSOLE_ENABLED).
        try:
            # **DRAKVUF does not create these, and says nothing when they are
            # missing.** The Ubuntu trace script created both with a single
            # `mkdir -p` and the port to this module dropped it, which was not
            # visible because the two plugins fail differently: `-D` ends up
            # created anyway, so `dump/` appears and looks like proof the
            # output paths work, while `--memdump-dir` does not and `memdump`
            # writes nothing at all. Measured on Dom0 2026-08-27 -- a completed
            # trace with 48 memdump lines in trace.log and no memdump directory
            # beside it.
            #
            # A silent partial loss of evidence is the worst shape this failure
            # could take: the analysis reports `completed`, the manifest lists
            # the artifacts that did survive, and nothing anywhere records that
            # a plugin was asked to collect memory and could not.
            #
            # `parents=True, exist_ok=True` for the same reason the shell used
            # `-p`: a retry reuses the job directory.
            #
            # The names are `argv_trace`'s, which are the postprocessing
            # package's -- see sandboxd/postprocessing/paths.py. `ipt/` only
            # when the plugin was selected: compress_ipt runs whenever the
            # directory exists, and an empty `ipt.zip` on every job would
            # say IPT ran when it did not.
            subdirs = [EXTRACTED_DIR, DUMPS_DIR]
            if guests.IPT_PLUGIN in job.options.plugins:
                subdirs.append(IPT_DIR)
            for sub in subdirs:
                (job.result_dir / sub).mkdir(parents=True, exist_ok=True)

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
            # The C watcher read DRAKVUF's exit status and then ignored it --
            # it printed the status, but only its own phase timer decided the
            # outcome -- so failing here would diverge from the behaviour this
            # was ported to match.
            # DRAKVUF also exits non-zero for reasons that are not analysis
            # failures -- a traced process ending oddly, for one.
            #
            # But completing silently after a trace that never attached is the
            # exact failure this architecture exists to remove: correct-looking
            # output with nothing behind it. So the artifacts are kept, the job
            # completes, and the status is RECORDED -- a manifest with no
            # `<plugin>.log` in it at all (trace.log itself is split and never
            # uploaded), beside a note naming the exit code, is diagnosable
            # where a bare `completed` is not.
            self._trace_note = None
            if not result.ok:
                self._trace_note = (
                    f"drakvuf exited {result.returncode}"
                    + (" (timed out)" if result.timed_out else "")
                    + f"; see {TRACE_STDERR}"
                )
        finally:
            tcpdump.stop()

    def _start_console(self, job: Job, beat: Heartbeat):
        """Dial out, if a console was asked for. Never fails the analysis.

        The console is an OBSERVER of the run, never a participant in its
        lifecycle -- so every failure here is logged and swallowed. A missing
        VNC port, a relay that refuses, a platform that is down: the trace
        continues regardless, and the operator sees no screen rather than a
        failed job.

        Called unconditionally at the start of the trace when the console is
        enabled -- see the comment at the call site for why waiting for a
        request cannot work.
        """
        if not self._cfg.console_enabled:
            return None
        try:
            port = vnc.resolve_vnc_port(self._runner, job.domid,
                                        job.clone_domain)
            session = vnc.ConsoleSession(
                self._cfg.console_api or self._cfg.api_base,
                self._cfg.worker_token, job.job_id,
                ssl_context=self._cfg.ssl_context,
                # The platform pairs the socket only if this matches the job's
                # `lease_owner`, so it comes from the same client that took the
                # lease rather than from configuration that could drift.
                worker_id=self._api.worker_id)
            session.start(port)
            return session
        except Exception as exc:  # noqa: BLE001 - never fail the analysis
            log.warning("no live console for job %s: %s", job.job_id, exc)
            return None

    def _collect(self, lease, job_dir: Path) -> Outcome:
        """Upload what the run produced and build its manifest."""
        # `dumps/` is left out ONLY when `dumps.zip` exists beside it: that
        # is process_dumps having packed it, and the directory is then a
        # copy. When process_dumps did not run -- no procmon, so no process
        # tree, which is every non-Windows job today -- the raw directory is
        # all there is and it uploads as before. An unconditional exclusion
        # here would drop every memory dump of such a job with nothing in the
        # manifest to say so, the exact failure `_trace`'s mkdir comment
        # describes. `ipt/` and `ipt.zip` are the same pair (compress_ipt).
        packed = {directory for directory, archive in
                  ((DUMPS_DIR, DUMPS_ZIP), (IPT_DIR, IPT_ZIP),
                   (EXTRACTED_DIR, EXTRACTED_ZIP))
                  if (job_dir / archive).exists()}
        # `trace.log` never uploads, split or not. The per-plugin logs ARE the
        # stream (split_drakvuf_log removes the raw file once it has written
        # them), and a raw copy that outlived a failed split would double the
        # largest artifact of the job. It is not lost: the job directory stays
        # on Dom0, and the split's own log line says what went wrong.
        skipped = packed | {TRACE_LOG}
        found = sorted(p for p in job_dir.rglob("*")
                       if p.is_file()
                       and p.relative_to(job_dir).parts[0] not in skipped)
        truncated = len(found) > MAX_ARTIFACTS
        found = found[:MAX_ARTIFACTS]

        entries = []
        for path in found:
            rel = str(path.relative_to(job_dir))
            entries.append({"name": rel, "size_bytes": path.stat().st_size,
                            "sha256": _digest(path)})

        deadline = time.monotonic() + timing.COLLECT_BUDGET
        if entries:
            uploaded = []
            # Tracked separately from `truncated`, which may ALREADY be set by
            # the MAX_ARTIFACTS cap above -- testing that one here would break
            # out after the first batch on any run that produced more than 512
            # files, uploading 64 of them and calling the rest truncated.
            out_of_budget = False
            # Tickets are minted a batch at a time, immediately before that
            # batch is sent, rather than all of them up front. Two reasons, and
            # only the first is about the 64-name cap: minting is also what
            # CHARGES the job's byte budget, so tickets for artifacts that a
            # budget overrun means we never send would be charged for nothing.
            for start in range(0, len(entries), TICKET_BATCH):
                if out_of_budget:
                    break
                batch = entries[start:start + TICKET_BATCH]
                if time.monotonic() > deadline:
                    # Out of budget with artifacts still to send. The manifest
                    # must describe what was UPLOADED, not what was found:
                    # listing an artifact that never reached the store is a
                    # download link that 404s.
                    out_of_budget = True
                    break
                tickets = self._api.artifact_tickets(
                    lease.job_id, {e["name"]: e["size_bytes"] for e in batch})
                for entry in batch:
                    if time.monotonic() > deadline:
                        out_of_budget = True
                        break
                    ticket = tickets.get(entry["name"])
                    if ticket is None:
                        continue
                    self._api.upload_artifact(ticket, entry["name"],
                                              job_dir / entry["name"])
                    uploaded.append(entry)
            truncated = truncated or out_of_budget
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
        was a real defect in the C watcher before 2026-08-19: cleanup ran only
        in the timeout branch, so a normal completion left its clone up until
        the next sample happened to take the same VLAN slot.
        """
        problems = []

        # Egress FIRST, before the domain is destroyed.
        #
        # The clone is paused below and then destroyed, but between the last
        # trace instruction and `xl destroy` it is still running and still
        # holding its address. Removing its way out first shrinks that window
        # to nothing: the sample loses the network before anything else about
        # the teardown can go slowly or fail.
        #
        # Runs even when `clone is None` -- a build that failed part-way may
        # still have left rules, and this is the only place that removes them
        # on the failure path.
        #
        # UNCHECKED, and that is not laziness: every command here fails
        # legitimately when there was nothing to remove, which is the normal
        # case for an `offline` job. `iptables -D` on an absent rule and `-X`
        # on an absent chain both exit 1. What matters is that the chain ends
        # up gone, and `-X` failing because it is already gone is success.
        #
        # Which is exactly why the loop below has to ask separately. Unchecked
        # here means these exit codes carry no signal at all, so "the revoke
        # worked" cannot be inferred from them -- it has to be observed.
        for argv in egress.argv_revoke(vlan, bridge=self._cfg.bridge,
                                       subnet=self._cfg.subnet):
            try:
                self._runner.run(argv, timeout=timing.CLEANUP_BUDGET,
                                 what="egress revoke")
            except Exception:  # noqa: BLE001 - teardown never raises
                log.warning("job cleanup: egress revoke failed on vlan %d: %s",
                            vlan, " ".join(argv))

        # Then ASK whether it worked, rather than assuming it did.
        #
        # The revoke loop above cannot tell us: most of its commands fail on
        # the ordinary path, so its exit codes carry no signal (see
        # `egress.argv_probe_chains`). This used to be left to the startup
        # sweep on the grounds that a leftover chain is unambiguous there --
        # true, but the sweep runs at START, and the VLAN is reused minutes
        # later by this same long-lived process. With the default pool of two
        # slots the gap before reuse is one job.
        #
        # A surviving chain therefore becomes a recorded problem, which
        # withholds the VLAN (daemon._work). That is the same trade `admit`
        # already makes for the sweep: reduced capacity is a visible cost,
        # handing out a contaminated VLAN is an invisible one.
        for argv in egress.argv_probe_chains(vlan, bridge=self._cfg.bridge):
            try:
                probe = self._runner.run(argv, timeout=timing.CLEANUP_BUDGET,
                                         what="egress probe")
            except Exception:  # noqa: BLE001 - teardown never raises
                # Could not ask. Unknown is not clean.
                problems.append("egress")
                break
            if probe.ok:
                # `-S` succeeded, so the chain is still there.
                log.error(
                    "job cleanup: vlan %d still has egress chains after "
                    "revoke (%s). Withholding it: the next sample would "
                    "inherit this one's way out.", vlan, argv[-1])
                problems.append("egress")
                break

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

        # **`completed` is reported BY `/complete`, never by `/state`.**
        #
        # `/complete` requires the job to be `cleaning` and sets `completed`
        # itself, in one committed UPDATE together with the manifest -- that
        # single row is what makes publication atomic, so a half-uploaded
        # result set is never served as finished.
        #
        # Reporting `completed` through `/state` first therefore does two bad
        # things at once: it makes `/complete` unreachable (409, "the worker no
        # longer owns it" -- the lease is released with the terminal state),
        # and because `/complete` is the ONLY writer of `jobs.manifest`, the
        # run finishes with its artifacts in the store and no record of them.
        # Observed on Dom0 2026-08-26, F3.
        if outcome.state == "completed":
            if outcome.manifest is None:
                raise RuntimeError(
                    "a completed run has no manifest; /complete is the only "
                    "writer of jobs.manifest and it cannot be skipped"
                )
            self._api.complete(lease.job_id, outcome.manifest)
            return

        self._api.report_state(lease.job_id, outcome.state, **extra)

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


def _phase_overran(phase: str, what: str, budget: float):
    """A phase deadline reached before its next command could start.

    Shaped as a `Completed` with `timed_out` set so it reads like every other
    timeout the pipeline produces -- the caller is the C watcher's phase guard
    in a new form, and a phase that overruns tears the clone down and retries.
    """
    from .proc import Completed
    return Completed(
        argv=(what,), returncode=None, stdout="",
        stderr=f"the {phase} phase exceeded its {budget:.0f}s budget before "
               f"{what} could run; the clone is being torn down",
        duration=budget, timed_out=True,
    )


def _no_component(got: str):
    from .proc import Completed
    return Completed(
        argv=("cmd", "package", "resolve-activity"), returncode=1, stdout="",
        stderr=f"no usable launcher component (got {got!r}); nothing executed. "
               f"An APK need not declare a launcher activity at all.",
        duration=0.0,
    )
