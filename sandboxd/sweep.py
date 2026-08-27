"""Reclaiming Dom0 at startup.

Issue #41 (DRAFT-060).

sandboxd destroys every clone it finds when it starts, rather than adopting
live ones. An analysis whose orchestrator died has no timer watching it and no
way to report how far it got, and the clone is disposable by design. Retry is
already an operator decision on a **new job id**, so `interrupted` is the
correct terminal state for whatever was running and there is nothing worth
keeping. The worker channel already says so: `POST /worker/reconcile` marks
anything absent from `live_job_ids` as interrupted, and after a sweep that list
is empty by construction.

## This is the most destructive code in the daemon

It runs `xl destroy` and `lvremove -f` as root, unattended, at every start. Its
entire safety rests on one predicate, and the predicate is a **positive match**
on the clone grammar `<origin>-<vlan>-clone` (see `naming.py`). Anything that
does not match is left alone without needing to be recognised.

The alternative -- a list of things to spare -- is one forgotten name away from
destroying a template. These must survive every sweep:

    ubuntu   android            golden images; reinstalling one means
                                reinstalling a guest from scratch
    ubuntu_sandbox             templates; rebuilding one means re-saving
    android_sandbox            from the golden VM
    /dev/<vg>/ubuntu_sandbox   the LV a clone snapshot is taken OF
    <repo>/state/*.bak         the saved memory images

CLAUDE.md forbids operating on the golden LV or the saved state at all without
explicit instruction. The predicate is how that restriction is enforced rather
than remembered.

## Order

Processes first, then domains, then LVs. A `drakvuf` still attached holds the
domain; a domain still running holds its LV open, which is what made
`lvremove` report "Logical volume in use" on Dom0 2026-08-14. Each step
removes the reason the next one would fail.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from . import proc
from .clone import CMD_TIMEOUT, DESTROY_SETTLE_SECONDS
from .naming import is_clone, parse_clone

# Only these are killed, and only when their argv names a clone or a clone's
# VLAN interface. A sweep that killed anything else on Dom0 would be a denial
# of service against the host it runs on.
SWEEPABLE = ("drakvuf", "injector", "tcpdump")


@dataclass
class SweepReport:
    """What was reclaimed, so a startup line can say it rather than imply it."""

    processes: list[int] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    lvs: list[str] = field(default_factory=list)
    configs: list[str] = field(default_factory=list)
    # VLANs fully cleaned, and therefore safe to admit into the resource table.
    clean_vlans: set = field(default_factory=set)
    # VLANs whose clone could NOT be fully removed. Deliberately NOT admitted:
    # a wedged domain or an LV that will not release means the next clone on
    # that VLAN would restore onto a snapshot whose predecessor is still alive.
    dirty_vlans: set = field(default_factory=set)

    @property
    def clean(self) -> bool:
        return not self.dirty_vlans

    def summary(self) -> str:
        """What was reclaimed, phrased so a clean host does not read as broken.

        The first version said "0 vlan(s) clean" on a healthy host, because
        `clean_vlans` counts only VLANs that HAD something on them. An operator
        reading that during an incident would reasonably conclude there was no
        usable capacity -- the same confusion that was a real bug in the daemon
        (admitting only `clean_vlans` would have started with zero VLANs).
        """
        found = len(self.domains) + len(self.lvs) + len(self.processes)
        if not found and not self.dirty_vlans:
            return "sweep: nothing to reclaim, Dom0 was already clean"
        parts = [f"sweep: reclaimed {len(self.domains)} domain(s), "
                 f"{len(self.lvs)} LV(s), {len(self.processes)} process(es), "
                 f"{len(self.configs)} file(s)"]
        if self.dirty_vlans:
            parts.append(f"vlan(s) {sorted(self.dirty_vlans)} WITHHELD -- their "
                         f"clones could not be removed")
        return "; ".join(parts)


def argv_xl_list() -> list[str]:
    return ["xl", "list"]


def argv_lvs(vg: str) -> list[str]:
    # --noheadings -o lv_name gives one bare name per line. `lvs` alone emits a
    # header and six columns, which would have to be parsed positionally.
    return ["lvs", "--noheadings", "-o", "lv_name", vg]


def parse_xl_list(text: str) -> list[str]:
    """Domain names from `xl list`.

    Columns are `Name ID Mem VCPUs State Time(s)`, so the name is field 0 of
    every line after the header. A domain name containing a space would break
    that -- and cannot be one of ours, because the clone grammar admits only
    `[A-Za-z0-9._-]`, so such a line is simply never matched.
    """
    names = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Name"):
            continue
        names.append(line.split()[0])
    return names


def parse_lvs(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def sweep(
    runner,
    *,
    vg: str = "vg-root",
    bridge: str = "xenbr1",
    config_dir: Path = Path("/tmp"),
    staging_dir: Path | None = None,
    settle: int = DESTROY_SETTLE_SECONDS,
    vlans=(),
) -> SweepReport:
    """Reclaim every clone on this host. Runs before register and claim.

    `vlans` is the range this host provisioned. It is what lets the stray hunt
    find a capture whose domain is already gone -- see `_kill_strays`.
    """
    report = SweepReport()

    domains = _clone_domains(runner, report)
    lvs = _clone_lvs(runner, vg, report)

    # Every VLAN mentioned by anything found. Each is dirty until its own
    # teardown is confirmed, which is the inverse of the resource table's old
    # behaviour and the reason `admit` exists at all.
    for name in set(domains) | set(lvs):
        parsed = parse_clone(name)
        if parsed:
            report.dirty_vlans.add(parsed.vlan)

    _kill_strays(runner, domains, bridge, report, vlans)

    for name in domains:
        _destroy(runner, name, settle, report)

    for name in lvs:
        _remove_lv(runner, vg, name, report)

    _unlink_configs(config_dir, report)
    if staging_dir is not None:
        _clear_staging(staging_dir, report)

    # A VLAN is clean only if nothing named it survived. Recomputed from what
    # is still present rather than tracked as we go, so a step that silently
    # did nothing cannot leave a VLAN marked clean.
    surviving = set(_clone_domains(runner, None)) | set(_clone_lvs(runner, vg, None))
    still_dirty = set()
    for name in surviving:
        parsed = parse_clone(name)
        if parsed:
            still_dirty.add(parsed.vlan)

    report.clean_vlans = report.dirty_vlans - still_dirty
    report.dirty_vlans = still_dirty
    return report


# --- finding -----------------------------------------------------------------

def _clone_domains(runner, report: SweepReport | None) -> list[str]:
    result = runner.run(argv_xl_list(), timeout=CMD_TIMEOUT, what="xl list")
    if not result.ok:
        # Cannot enumerate, so cannot safely destroy. Returning nothing is the
        # only correct answer: guessing at names would mean acting on a view of
        # Dom0 we do not have.
        return []
    found = [n for n in parse_xl_list(result.stdout) if is_clone(n)]
    if report is not None:
        report.domains = found
    return found


def _clone_lvs(runner, vg: str, report: SweepReport | None) -> list[str]:
    result = runner.run(argv_lvs(vg), timeout=CMD_TIMEOUT, what="lvs")
    if not result.ok:
        return []
    found = [n for n in parse_lvs(result.stdout) if is_clone(n)]
    if report is not None:
        report.lvs = found
    return found


# --- removing ----------------------------------------------------------------

def _kill_strays(runner, domains, bridge: str, report: SweepReport,
                 vlans=()) -> None:
    """`drakvuf`, `injector` and `tcpdump` left over from a dead sandboxd.

    **Exact argv elements, never a regex.** `drakvuf-<os>.sh` finds its own
    capture with `ps aux | grep "tcpdump -i xenbr1.$VLAN"`, where `.` is a
    regex wildcard and the pattern is unanchored -- so sweeping VLAN 1 with
    that would also kill the capture on `xenbr1.10` through `xenbr1.19`. It is
    recorded as a KNOWN GAP (DRAFT-011) in the script; here it simply cannot
    happen, because `xenbr1.1` and `xenbr1.10` are different strings.

    **The interfaces come from the PROVISIONED VLAN range, not from surviving
    domains**, and that is the whole point of `vlans`. A sandboxd that died
    after `xl destroy` completed but before `tcpdump.stop()` leaves a capture
    whose domain no longer exists: derived from `domains`, that VLAN produced
    no interface, matched no process, and the sweep then found nothing on it
    and admitted it as clean. The next job on that VLAN ran with the previous
    job's `tcpdump -i xenbr1.<n>` still writing to the previous job's pcap
    path -- a second sample's traffic recorded into the first sample's
    capture, with nothing anywhere reporting it.

    `vlans` is empty only in tests that predate it; the daemon always passes
    the range it provisioned.
    """
    wanted = set(domains)
    interfaces = {f"{bridge}.{vlan}" for vlan in vlans}
    for name in domains:
        parsed = parse_clone(name)
        if parsed:
            interfaces.add(f"{bridge}.{parsed.vlan}")

    if not wanted and not interfaces:
        return

    for pid, argv in proc.iter_processes():
        program = Path(argv[0]).name
        if program not in SWEEPABLE:
            continue
        # An argument equal to a clone name or to one of its VLAN interfaces.
        # Equality, not containment: `xenbr1.1` must not match `xenbr1.10`.
        if not any(a in wanted or a in interfaces for a in argv[1:]):
            continue
        proc.kill_pid_group(pid)
        report.processes.append(pid)


def _destroy(runner, name: str, settle: int, report: SweepReport) -> None:
    runner.run(["xl", "destroy", name], timeout=CMD_TIMEOUT,
               what=f"xl destroy of {name!r}")

    # `xl destroy` returns before the block device is released -- measured on
    # Dom0 2026-08-14, where lvremove reported "Logical volume in use" and
    # succeeded on a retry. Waiting here is what makes the lvremove reliable,
    # exactly as it is in clone.py.
    deadline = time.monotonic() + settle
    while time.monotonic() < deadline:
        gone = runner.run(["xl", "domid", name], timeout=CMD_TIMEOUT,
                          what="xl domid")
        if not gone.ok or not gone.stdout.strip().isdigit():
            return
        time.sleep(1)


def _remove_lv(runner, vg: str, name: str, report: SweepReport) -> None:
    runner.run(["lvremove", "-f", f"/dev/{vg}/{name}"], timeout=CMD_TIMEOUT,
               what=f"lvremove of {name!r}")


def _unlink_configs(config_dir: Path, report: SweepReport) -> None:
    """The `/tmp/<clone>.config` files clone.py writes.

    Harmless if left -- they are overwritten on the next build -- but they are
    the only durable record of which VLANs were in use, and leaving stale ones
    makes a directory listing lie about what is running.
    """
    if not config_dir.is_dir():
        return
    for path in config_dir.glob("*.config"):
        if is_clone(path.stem):
            path.unlink(missing_ok=True)
            report.configs.append(path.name)


def _clear_staging(staging_dir: Path, report: SweepReport) -> None:
    """Samples written to Dom0 disk for `injector -m writefile -B`.

    They have to be on disk: `writefile` takes a Dom0 path and there is no
    stdin form. So the honest design is a known directory emptied at startup,
    rather than a claim that malware never touches this host's filesystem.
    """
    if not staging_dir.is_dir():
        return
    for path in sorted(staging_dir.rglob("*"), reverse=True):
        try:
            path.unlink() if path.is_file() else path.rmdir()
        except OSError:
            continue
        report.configs.append(str(path))