"""The daemon: sweep, register, claim, run, release.

Issue #41 (DRAFT-060). What the `run_analysis-<os>.sh` launcher and the
`dirwatch` watcher did between them, as one process that owns every clone on
this host. Both were deleted 2026-09-15.

## The shape, and the invariant that holds it together

    sweep ──► register ──► reconcile ──► claim loop ──┬──► worker thread
                                             ▲        ├──► worker thread
                                             └────────┴──► worker thread
                                              release

**One claim thread acquires; worker threads only release.** Releases only ever
INCREASE capacity, so an `acquire` immediately after a lease cannot fail --
which is what removes the race where two claimers both read `free()`, both see
room, and the platform leases a job this host cannot place. A second claim
thread would reintroduce it, which is why the invariant is written here rather
than assumed.

## Why the sweep runs first, and reconcile after it

A clone whose orchestrator died has no timer watching it and no way to report
how far it got. The sweep destroys every one it finds, so `live_job_ids` is
empty by construction and the platform marks whatever it thought this host held
as `interrupted` -- which is true. Registering before the sweep would advertise
capacity that stale clones are still holding.

## Two orchestrators must never share a host

`dirwatch` derived each clone's VLAN from a process-local slot index, so a
second orchestrator allocates the same VLANs and shares gateway addresses and
isolation rules "with no symptom but interference". The launchers refused to
start when another `dirwatch` was running; this refuses to start when either
is. **The guard outlives the source**: `dirwatch` was a compiled binary, and one
left installed on a Dom0 from before migration still allocates VLANs that way,
so `refuse_if_another_orchestrator_runs` still looks for it.
"""

from __future__ import annotations

import fcntl
import logging
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from . import egress, guests, proc, resources, sweep
from .api import Idle, Lease, ProtocolError, Reserved, WorkerAPI
from .guests import TargetOs
from .resources import Exhausted, ResourceTable, required_mib
from .runner import Runner
from .stages import Analysis, Config

log = logging.getLogger("sandboxd")

# Where the single-instance lock lives. A lock file rather than a pidfile: a
# pidfile survives a crash and has to be validated against /proc, where an
# flock is released by the kernel when the holder dies.
LOCK_PATH = Path("/run/lock/sandboxd.lock")

# How long to wait for in-flight analyses on shutdown. Bounded because a hung
# trace must not stop the daemon exiting -- the next start's sweep reclaims
# whatever is left, which is what the sweep is for.
DRAIN_TIMEOUT = 300.0

# An idle claim already long-polls server-side (20s), so this is only the pause
# after a REFUSED claim -- reserved, or a transport failure the API layer
# already retried through.
IDLE_PAUSE = 5.0


class AlreadyRunning(RuntimeError):
    pass


class NetworkSetupFailed(RuntimeError):
    """The analysis network could not be provisioned. Distinct from
    `AlreadyRunning` because the operator action differs: one means stop the
    other orchestrator, the other means fix the network before any job runs.
    """


@dataclass
class Settings:
    """Everything an operator must decide, read from the environment.

    Deliberately no default for capacity. Guessing how much memory Dom0 can
    give clones is how a host overcommits, and the symptom is a clone that
    fails to restore rather than a number anyone reads -- so an unset value is
    a refusal to start, not a fallback.
    """

    api: str
    token: str
    worker_id: str
    total_mib: int
    vlans: range
    total_slots: int
    cacert: str | None = None
    client_cert: tuple[str, str] | None = None

    # **The console dials a DIFFERENT listener from the rest of the channel,
    # and it has to.** The platform runs two uvicorn processes over the same
    # app -- 8443 with mutual TLS for the worker channel, 8000 behind
    # cloudflared for the browser -- and the console relay pairs two sockets
    # in an IN-PROCESS registry. A worker on 8443 and a browser on 8000 attach
    # to two different registries and can never meet: both simply wait
    # (Dom0 2026-08-26, F11).
    #
    # So this points at the browser listener. Everything else stays on 8443.
    console_api: str = ""

    # SANDBOXD_CONSOLE_ENABLED. Off unless an operator turns it on, because
    # what it enables is a relay socket dialled OUT of the malware host on
    # every trace -- the largest deliberate widening of this design's attack
    # surface, and the one thing Dom0 does that is not "poll and hang up".
    console_enabled: bool = False

    @classmethod
    def from_env(cls, env=None) -> Settings:
        env = env if env is not None else os.environ
        missing = [k for k in ("SANDBOXD_API", "WORKER_TOKEN",
                               "SANDBOXD_TOTAL_MIB") if not env.get(k)]
        if missing:
            raise SystemExit(
                f"sandboxd: {', '.join(missing)} must be set. "
                f"SANDBOXD_TOTAL_MIB is how much memory this Dom0 may give to "
                f"clones; there is no safe default for it."
            )

        # MAX_CLONES as the old launcher set it, and it MUST match what
        # network-setup.sh provisioned: a VLAN with no xenbr1.<n> and no
        # gateway produces a clone that boots, gets an address nothing routes,
        # and reads as a sample that chose not to talk.
        max_clones = int(env.get("SANDBOXD_MAX_CLONES", "2"))
        cert = env.get("SANDBOXD_CLIENT_CERT")
        key = env.get("SANDBOXD_CLIENT_KEY")

        # Anything but a recognised true value is false, matching the
        # platform's `config._bool`. A feature flag that turns a capability ON
        # because someone wrote `SANDBOXD_CONSOLE_ENABLED=ture` is worse than
        # one that stays off, and this particular flag opens a socket out of
        # the machine that runs malware.
        console = env.get("SANDBOXD_CONSOLE_ENABLED", "")
        console_enabled = console.strip().lower() in {"1", "true", "yes", "on"}

        return cls(
            api=env["SANDBOXD_API"],
            token=env["WORKER_TOKEN"],
            worker_id=env.get("SANDBOXD_WORKER_ID", os.uname().nodename),
            console_api=env.get("SANDBOXD_CONSOLE_API", ""),
            console_enabled=console_enabled,
            total_mib=int(env["SANDBOXD_TOTAL_MIB"]),
            vlans=range(1, max_clones + 1),
            total_slots=int(env.get("SANDBOXD_MAX_SLOTS", str(max_clones))),
            cacert=env.get("SANDBOXD_CACERT"),
            client_cert=(cert, key) if cert and key else None,
        )


def refuse_if_another_orchestrator_runs(lock_path: Path = LOCK_PATH):
    """Take the single-instance lock, and check for a running `dirwatch`.

    **`dirwatch` is gone from this repository and the check is still correct.**
    Its source was deleted 2026-09-15; the binary it built may still be
    installed on a Dom0 that predates the migration, and running it alongside
    `sandboxd` produces exactly the collision below.

    Both matter and for the same reason: two orchestrators on one host allocate
    the same VLANs from low numbers with no shared state, so they collide on
    gateway addresses and isolation rules with no symptom but interference
    between two malware analyses.

    Giving `sandboxd` a disjoint VLAN range would technically permit
    coexistence and is the wrong move -- it means defeating a guard added
    deliberately, to buy a transitional convenience, on the machine that runs
    malware. Migration is a cutover.
    """
    for pid, argv in proc.iter_processes():
        if pid == os.getpid():
            continue
        # Exact program name, not a substring: `grep dirwatch` would also match
        # an editor with the source open.
        if Path(argv[0]).name == "dirwatch":
            raise AlreadyRunning(
                f"a dirwatch is running (pid {pid}). Its clones use VLANs "
                f"1..MAX_CLONES and so would these -- they would collide on "
                f"gateway addresses and isolation rules, and nothing would "
                f"report it. Stop it first; migration is a cutover, not "
                f"coexistence."
            )

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise AlreadyRunning(
            f"another sandboxd holds {lock_path}. One orchestrator per host."
        ) from None
    # An flock, not a pidfile: the kernel releases it when the holder dies, so
    # a crashed daemon does not leave a lock nobody can prove is stale.
    os.write(fd, f"{os.getpid()}\n".encode())
    return fd


NETWORK_SETUP = Path(__file__).resolve().parents[1] / "automation" / "network-setup.sh"

# Long enough for the slowest observed provisioning run with room to spare, not
# a measured constant: the script's cost is dominated by `iptables` calls that
# scale with the clone count, and no run has been timed. Generous on purpose --
# a timeout here refuses to start a daemon whose network is probably fine.
NETWORK_SETUP_TIMEOUT = 120.0


def provision_analysis_network(max_clones: int, script: Path = NETWORK_SETUP):
    """Create the VLAN interfaces, gateways and isolation chains clones need.

    **`sandboxd` used to skip this, and the symptom was a clean report.**
    The old `run_analysis-<os>.sh` ran `network-setup.sh` before launching
    `dirwatch`; `sandboxd` replaced the launcher but not that call, because #41
    reasoned "the launcher still does it" -- which stopped being true the moment
    `sandboxd` ran instead of the launcher, and is now moot because the launcher
    no longer exists.

    **This is now the only caller of `network-setup.sh` anywhere.** Nothing else
    creates `xenbr1.<n>`, the `172.16.<n>.1` gateways or the `DRAKVUF_*` chains,
    so without this call a clone boots, takes an address nothing routes, and
    **reads as a sample that chose not to talk**. A false negative that looks
    exactly like a result is the worst failure a sandbox has, and if a previous
    `dirwatch` era left the interfaces behind it appears to work.

    **The argument is the point, more than the call.** `max_clones` sizes the
    worker pool and `network-setup.sh`'s argument sizes the VLAN pool; they have
    to agree, and until now they were two numbers set by hand in two places
    (see `Settings.from_env`, which carries the warning). Passing the same value
    makes disagreement unrepresentable.

    Nothing is configured here on purpose. The script sources
    `automation/platform.env` itself, so this cannot become a second source of
    truth for `ANALYSIS_BRIDGE` -- the exact divergence DRAFT-028b removed.

    Safe to run every start: DRAFT-028 made it idempotent and fail-loud. It
    does not create the bridge, and says so clearly when `xenbr1` is missing,
    naming the `ovs-vsctl add-br` install step.
    """
    if not script.is_file():
        raise NetworkSetupFailed(
            f"{script} is missing. It provisions the VLAN interfaces, gateways "
            f"and isolation chains every clone needs; without it a clone gets "
            f"an address nothing routes and the analysis looks empty."
        )

    log.info("provisioning the analysis network for %d clone slot(s)", max_clones)
    result = proc.run([str(script), str(max_clones)],
                      timeout=NETWORK_SETUP_TIMEOUT, what="network-setup.sh")

    if not result.ok:
        # **Refuse to start rather than continue.** A half-provisioned analysis
        # network is worse than none, because it looks like a working one:
        # clones run with no inter-clone isolation, no LAN block and no Dom0
        # protection. The launcher this replaced took the same position.
        raise NetworkSetupFailed(
            f"{script.name} failed (rc={result.returncode}"
            f"{', timed out' if result.timed_out else ''}). Refusing to start: "
            f"a half-provisioned analysis network looks like a working one.\n"
            f"{result.stderr.strip() or result.stdout.strip()}"
        )


class Daemon:
    def __init__(self, settings: Settings, config: Config | None = None,
                 runner=None, api=None):
        self._s = settings
        self._cfg = config or Config()

        # Read once here rather than per job: an unknown plugin name makes
        # DRAKVUF exit, so validating late would report the same
        # misconfiguration once per sample instead of once at startup.
        override = guests.parse_plugins_override(os.environ.get("SANDBOXD_PLUGINS"))
        if override is not None:
            self._cfg.plugins = override
            # WARNING, not INFO. This changes what every analysis on this host
            # records, and nothing writes it down per job -- a trace missing
            # filetracer output is indistinguishable from one where filetracer
            # found nothing. It must be obvious in the log that the host was
            # not running its measured defaults.
            log.warning(
                "SANDBOXD_PLUGINS overrides the plugin set for EVERY job on "
                "this host: %s. This is a measurement tool (DRAKVUF #108); "
                "unset it when the measurement is done.", ", ".join(override))
        # What this host can offer as a way out (DRAFT-057). Resolved once, at
        # construction, for the same reason the plugin list is: a job is not
        # the place to discover that the host's egress configuration is wrong.
        #
        # SANDBOXD_ALLOW_DIRECT is read here rather than in egress.py so that
        # the environment is consulted in one place, and so `available_exits`
        # stays a pure function of its arguments.
        allow_direct = os.environ.get("SANDBOXD_ALLOW_DIRECT", "") == "1"
        self._cfg.exits = tuple(egress.available_exits(allow_direct=allow_direct))
        if allow_direct:
            # WARNING, not INFO, and worth the noise. This is the switch that
            # puts malware on the host's own uplink -- a residential line on
            # this deployment, which is the entire subject of roadmap risk #13.
            # It exists to reproduce pre-DRAFT-057 behaviour for a regression
            # run, not to get a sample online.
            log.warning(
                "SANDBOXD_ALLOW_DIRECT=1: this host now offers 'direct', which "
                "NATs clones out %s with no per-job control. On a residential "
                "uplink that is the posture DRAFT-057 exists to replace. Unset "
                "it when the regression run is done.", self._cfg.bridge)
        log.info("egress exits offered: %s",
                 ", ".join(f"{e.name} ({e.mode.value})" for e in self._cfg.exits))

        self._runner = runner or Runner()
        self._api = api or WorkerAPI(
            settings.api, settings.token, settings.worker_id,
            cacert=settings.cacert, client_cert=settings.client_cert)
        # The console dials out with the SAME credentials the rest of the
        # channel uses -- no separate secret for the relay, because it is the
        # same door on the same LAN (DRAFT-056 §4.4).
        self._cfg.api_base = settings.api
        self._cfg.console_api = settings.console_api or settings.api
        self._cfg.worker_token = settings.token
        self._cfg.console_enabled = settings.console_enabled
        if settings.cacert or settings.client_cert:
            from .tls import ssl_context
            self._cfg.ssl_context = ssl_context(settings.cacert,
                                                settings.client_cert)
        self._table: ResourceTable | None = None
        self._stopping = threading.Event()
        self._workers: list[threading.Thread] = []

    # -- startup ------------------------------------------------------------

    def start(self) -> ResourceTable:
        """Reclaim Dom0, learn what it can afford, and announce it."""
        report = sweep.sweep(self._runner, vg=self._cfg.vg,
                             bridge=self._cfg.bridge,
                             config_dir=self._cfg.config_dir,
                             staging_dir=self._cfg.staging_dir,
                             settle=self._cfg.waits.destroy_settle,
                             # So a capture left behind on a VLAN whose domain
                             # is already gone is still found and killed.
                             vlans=self._s.vlans)
        log.info("%s", report.summary())

        table = ResourceTable(total_mib=self._s.total_mib,
                              vlans=self._s.vlans,
                              total_slots=self._s.total_slots)
        # Every provisioned VLAN except the ones the sweep could not clean.
        #
        # Phrased as "not dirty" rather than "in clean_vlans", and the
        # difference matters: `clean_vlans` holds only VLANs that HAD something
        # on them, so most of the range never appears in either set. A VLAN the
        # sweep found nothing on is clean, and admitting only `clean_vlans`
        # would start a freshly-booted host with zero usable capacity.
        #
        # A VLAN whose clone survived is never admitted: reusing it would
        # restore onto a snapshot whose predecessor is still alive, which is
        # DRAFT-033's cross-sample contamination -- not a crash, so nothing
        # reports it.
        for vlan in self._s.vlans:
            if vlan not in report.dirty_vlans:
                table.admit(vlan)
        if self._cfg.console_enabled and not self._s.console_api:
            log.warning(
                "SANDBOXD_CONSOLE_API is unset, so the console will dial %s -- "
                "the same listener as the worker channel. If the platform runs "
                "a separate browser listener, the two sides land in different "
                "processes and can never pair. Set it to the browser listener "
                "(commonly :8000).", self._s.api)

        free = table.free()
        log.info("capacity: %d vlan(s) usable, %d MiB, %d slot(s)",
                 free.vlans, free.mib, free.slots)
        if report.dirty_vlans:
            log.warning("running at reduced capacity: vlan(s) %s withheld, "
                        "their clones could not be removed",
                        sorted(report.dirty_vlans))

        pipelines = self._pipelines()
        self._api.register(total_mib=self._s.total_mib,
                           total_vlans=len(self._s.vlans),
                           total_slots=self._s.total_slots,
                           pipelines=pipelines,
                           exits=self._cfg.exits)

        # Empty by construction: the sweep destroyed everything. Whatever the
        # platform thought this host held is marked interrupted, which is true.
        interrupted = self._api.reconcile([])
        if interrupted:
            log.warning("%d job(s) were interrupted by this restart: %s",
                        len(interrupted), ", ".join(interrupted))

        self._table = table
        return table

    def _pipelines(self) -> dict:
        """`required_mib` per OS, derived on Dom0 from each template's config.

        The API cannot read Dom0's `.cfg` files, and a second copy of the
        number on the platform would recreate the two-files-free-to-disagree
        failure `platform.env` exists to prevent. A guest whose template is
        absent is simply not offered.
        """
        out = {}
        for os_ in (TargetOs.UBUNTU, TargetOs.ANDROID, TargetOs.WINDOWS):
            cfg = self._cfg.domain_config(os_)
            if not cfg.is_file() or os_ not in self._cfg.injection_pids:
                continue
            try:
                out[os_.value] = required_mib(cfg)
            except (OSError, ValueError) as exc:
                log.warning("not offering %s: %s", os_.value, exc)
        if not out:
            raise SystemExit(
                "sandboxd: no analysis pipeline is available -- "
                f"Read the README for setting up the VMS"
            )
        return out

    # -- the loop -----------------------------------------------------------

    def run(self) -> None:
        table = self._table or self.start()

        while not self._stopping.is_set():
            try:
                outcome = self._claim_once(table)
            except ProtocolError as exc:
                # The API layer already retried transport failures; reaching
                # here means the platform refused the request itself, which
                # repeating cannot fix.
                #
                # Kept ahead of the blanket clause below, and logged without a
                # traceback, because this one is DIAGNOSED: the message names
                # the path and the status, and a stack trace through
                # `_post` would add nothing an operator can act on.
                log.error("claim refused: %s", exc)
                self._stopping.wait(IDLE_PAUSE)
                continue
            except Exception:  # noqa: BLE001 - a bad turn must not end the loop
                # **One bad turn must not end the only claim thread.**
                #
                # Until this clause existed the loop survived `ProtocolError`
                # and nothing else, while the call behind it has several other
                # exits: `api.claim` indexes `target_os`, `required_mib`,
                # `attempt`, `sample_url` and `lease_expires_at` straight out
                # of the response, so a lease missing a field raises
                # `KeyError`; `ResourceTable.acquire` raises `ValueError` when
                # a job id is already held, which is what a replayed lease
                # looks like from here. Either one ended the daemon.
                #
                # That is the expensive failure on this host. There is exactly
                # one claim thread -- the module docstring makes "one claim
                # thread acquires; worker threads only release" load-bearing --
                # so losing it stops every queued analysis, and recovery is not
                # a retry but a restart, whose first act is a sweep that
                # destroys every clone it finds. `_work` one function down
                # already takes this position for a worker ("a worker must not
                # take the daemon down"), and the claim thread has the stronger
                # claim on it, not a weaker one. Same shape as the platform's
                # `maintenance._loop`: "Never let one bad pass kill the loop".
                #
                # `log.exception`, not `log.error`: nobody has decided what
                # this failure means yet, so the traceback is the whole report.
                # `BaseException` is deliberately NOT caught -- SIGINT must
                # still unwind rather than be logged and retried five seconds
                # later.
                log.exception("the claim loop hit an unexpected error; "
                              "pausing %.0fs and continuing", IDLE_PAUSE)
                self._stopping.wait(IDLE_PAUSE)
                continue

            if outcome is None:
                self._stopping.wait(IDLE_PAUSE)

        self._drain()

    def _claim_once(self, table: ResourceTable):
        """One turn. **The only place that acquires.**"""
        free = table.free()
        if free.vlans < 1 or free.slots < 1:
            return None

        got = self._api.claim(free_mib=free.mib, free_vlans=free.vlans,
                              free_slots=free.slots)

        if isinstance(got, Idle):
            return None
        if isinstance(got, Reserved):
            # NOT an error, and must never be logged as one: a job too large
            # for current capacity is holding its place rather than being
            # starved by smaller ones behind it.
            log.info("reserved: job %s needs %d MiB, this host has %d free",
                     got.blocking_job_id, got.need_mib, free.mib)
            return None

        assert isinstance(got, Lease)
        try:
            held = table.acquire(got.job_id, got.required_mib)
        except Exhausted as exc:
            # The platform leased a job this host can NEVER run. It knows both
            # numbers, so it should not -- but "should not" is not "cannot",
            # and letting this escape would end the daemon over one bad row.
            #
            # Reported rather than left to lapse: the lease TTL would close it
            # eventually with no reason attached, and the operator needs to see
            # the mismatch to fix the capacity or the guest.
            log.error("job %s cannot run here: %s", got.job_id, exc)
            self._api.report_state(got.job_id, "cleaning",
                                   cleanup_status="no clone was created")
            self._api.report_state(
                got.job_id, "failed", failure_stage="capacity",
                failure_reason=str(exc))
            return None

        if held is None:
            # Cannot happen with one claim thread -- releases only increase
            # capacity -- so reaching here means that invariant was broken.
            # Loud, because the alternative is running a job with no vlan.
            log.error("leased %s but the table cannot hold it; is a second "
                      "claim loop running?", got.job_id)
            return None

        # Dead threads are dropped before the new one is added. The list used
        # to be append-only, so a daemon that had run N analyses held N Thread
        # objects -- each keeping its `args` alive, and a Lease carries the
        # sample's presigned URL, its submitted filename and its SHA-256. It
        # also made `_drain` walk every job this process had ever run to find
        # the one or two still going.
        self._workers = [t for t in self._workers if t.is_alive()]
        thread = threading.Thread(
            target=self._work, args=(got, held), daemon=False,
            name=f"job-{got.job_id[:8]}")
        self._workers.append(thread)
        thread.start()
        return got

    def _work(self, lease: Lease, held: resources.Held) -> None:
        """One analysis, then release. **Workers never acquire.**"""
        cleanup_status = None
        try:
            outcome = Analysis(self._api, self._runner, self._cfg).run(
                lease, held.vlan)
            cleanup_status = outcome.cleanup_status
            log.info("job %s -> %s (%s)", lease.job_id, outcome.state,
                     outcome.cleanup_status)
        except Exception:  # noqa: BLE001 - a worker must not take the daemon down
            log.exception("job %s ended in an unhandled error", lease.job_id)
        finally:
            # AFTER teardown, never before: the vlan IS the clone name, so
            # releasing early lets the next job begin cloning
            # `<origin>-<vlan>-clone` while this domain is still being
            # destroyed. The C watcher recorded the same ordering.
            if self._table is not None:
                # **A dirty teardown does not get its VLAN back.**
                #
                # `_teardown` has always returned "dirty: destroy,lvremove"
                # and nothing consumed it, so a domain that survived
                # `xl destroy`, an LV that would not release, or egress rules
                # that outlived their revoke all handed the VLAN straight to
                # the next sample. `ResourceTable.withhold` was written for
                # exactly this and had no caller outside its own tests.
                #
                # `cleanup_status is None` means `run()` itself raised, so the
                # teardown's outcome never came back. Unknown is not clean --
                # the same reading `admit` takes of a VLAN the sweep could not
                # confirm.
                #
                # Recovery is a daemon restart: the sweep destroys whatever
                # survived and re-admits the VLAN. Until then the host runs one
                # slot short, which is the visible cost `admit` argues is
                # preferable to the invisible one.
                #
                # Passed to `release` rather than done as a following
                # `withhold` call: those two are separated by a lock release,
                # and the claim thread can take the VLAN in between -- putting
                # a new sample on the dirty VLAN this is trying to hold back.
                clean = cleanup_status == "clean"
                self._table.release(lease.job_id, clean=clean)
                if not clean:
                    log.error(
                        "vlan %d withheld after job %s: cleanup was %r. "
                        "This host is one slot down until it is restarted "
                        "-- the startup sweep is what reclaims it.",
                        held.vlan, lease.job_id,
                        cleanup_status or "never reported")

    # -- shutdown -----------------------------------------------------------

    def stop(self, *_) -> None:
        if not self._stopping.is_set():
            log.info("shutting down: no new work will be claimed")
        self._stopping.set()

    def _drain(self) -> None:
        """Let in-flight analyses finish, bounded.

        Not abandoned: a clone left running is malware with NAT'd egress and
        nothing watching it. Not waited on forever either -- a hung trace must
        not stop the daemon exiting, and the next start's sweep reclaims
        whatever is left. That is what the sweep is for.
        """
        deadline = time.monotonic() + DRAIN_TIMEOUT
        alive = [t for t in self._workers if t.is_alive()]
        if alive:
            log.info("waiting for %d analysis(es) to finish", len(alive))
        for thread in alive:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))

        still = [t.name for t in self._workers if t.is_alive()]
        if still:
            log.warning("exiting with %d analysis(es) still running: %s. "
                        "Their clones will be reclaimed by the next start's "
                        "sweep.", len(still), ", ".join(still))


def main(argv=None) -> int:
    logging.basicConfig(
        level=os.environ.get("SANDBOXD_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    settings = Settings.from_env()

    try:
        refuse_if_another_orchestrator_runs()
    except AlreadyRunning as exc:
        log.error("%s", exc)
        return 1

    # After the lock, deliberately: provisioning rebuilds host-wide iptables
    # chains, and doing that while another orchestrator is mid-analysis would
    # disturb a running clone's isolation.
    try:
        # `len(settings.vlans)`, not a re-read of SANDBOXD_MAX_CLONES: the
        # script must create exactly the VLANs this daemon will hand out, and
        # `vlans` IS that pool. Deriving it from the same object removes the
        # possibility of the two disagreeing.
        provision_analysis_network(len(settings.vlans))
    except NetworkSetupFailed as exc:
        log.error("%s", exc)
        return 1

    daemon = Daemon(settings)
    signal.signal(signal.SIGTERM, daemon.stop)
    signal.signal(signal.SIGINT, daemon.stop)

    daemon.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())