"""The startup sweep: issue #41 (DRAFT-060).

The first test in this file is the one that matters. Everything else here is
about reclaiming correctly; that one is about not destroying a template, which
costs a rebuild from the golden VM -- or, for a golden image, a guest
reinstall.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd import sweep as S  # noqa: E402
from sandboxd.resources import ResourceTable  # noqa: E402
from sandboxd.tests.fake import FakeRunner  # noqa: E402

# What a real `xl list` looks like on a Dom0 mid-analysis: Dom0 itself, both
# golden images, both templates, and two live clones.
XL_LIST = """\
Name                                        ID   Mem VCPUs\tState\tTime(s)
Domain-0                                     0  4096     4     r-----   12345.6
ubuntu                                       1  2048     2     -b----     100.0
android                                      2  2048     2     -b----      50.0
ubuntu_sandbox                               3  2048     2     -b----      10.0
android_sandbox                              4  2048     2     -b----       9.0
ubuntu_sandbox-1-clone                       7  2048     2     -b----       3.0
android_sandbox-2-clone                      8  2048     2     -b----       2.0
"""

LVS = """\
  root
  swap
  ubuntu
  android
  ubuntu_sandbox
  android_sandbox
  ubuntu_sandbox-1-clone
  android_sandbox-2-clone
"""


def loaded(*, after_domains: str = "", after_lvs: str = "") -> FakeRunner:
    """A host holding two clones, which are gone after the sweep.

    `times=1` on the first pair: the sweep re-reads both at the end to decide
    which VLANs are actually clean, and an unbounded rule would report the
    clones still present and mark every VLAN dirty.
    """
    r = FakeRunner()
    r.script(("xl", "list"), stdout=XL_LIST, times=1)
    r.script(("lvs",), stdout=LVS, times=1)
    r.script(("xl", "domid"), rc=1)          # gone right after destroy
    r.script(("xl", "list"), stdout=after_domains or _xl_without_clones())
    r.script(("lvs",), stdout=after_lvs or _lvs_without_clones())
    return r


def _xl_without_clones() -> str:
    return "\n".join(l for l in XL_LIST.splitlines() if "-clone" not in l) + "\n"


def _lvs_without_clones() -> str:
    return "\n".join(l for l in LVS.splitlines() if "-clone" not in l) + "\n"


# --- THE test ---------------------------------------------------------------

def test_the_sweep_destroys_no_golden_image_and_no_template(tmp_path):
    """The failure this prevents costs a template rebuild from the golden VM,
    or a full guest reinstall. CLAUDE.md forbids operating on the golden LV or
    the saved state at all without explicit instruction.

    Safety is a POSITIVE match on `<origin>-<vlan>-clone`. A list of names to
    spare would be one forgotten entry away from `lvremove -f` on a template.
    """
    r = loaded()

    S.sweep(r, vg="vg-root", config_dir=tmp_path)

    protected = ["Domain-0", "ubuntu", "android",
                 "ubuntu_sandbox", "android_sandbox", "root", "swap"]
    for name in protected:
        assert not r.ran(("xl", "destroy", name)), f"destroyed {name}"
        assert not r.ran(("lvremove", "-f", f"/dev/vg-root/{name}")), \
            f"lvremove'd {name}"


def test_only_the_clones_are_destroyed(tmp_path):
    r = loaded()

    report = S.sweep(r, vg="vg-root", config_dir=tmp_path)

    assert sorted(report.domains) == ["android_sandbox-2-clone",
                                      "ubuntu_sandbox-1-clone"]
    assert sorted(report.lvs) == ["android_sandbox-2-clone",
                                  "ubuntu_sandbox-1-clone"]
    assert r.ran(("xl", "destroy", "ubuntu_sandbox-1-clone"))
    assert r.ran(("lvremove", "-f", "/dev/vg-root/android_sandbox-2-clone"))


def test_dom0_itself_is_never_a_candidate(tmp_path):
    """`Domain-0` is in every `xl list` and destroying it takes the host
    down."""
    r = loaded()
    S.sweep(r, vg="vg-root", config_dir=tmp_path)
    assert not r.ran(("xl", "destroy", "Domain-0"))


# --- parsing ----------------------------------------------------------------

def test_xl_list_parsing_skips_the_header():
    names = S.parse_xl_list(XL_LIST)
    assert "Name" not in names
    assert names[0] == "Domain-0"
    assert "ubuntu_sandbox-1-clone" in names


def test_lvs_parsing_strips_the_indentation():
    """`lvs --noheadings` indents every line by two spaces, so an unstripped
    name never matches the clone grammar and nothing would ever be reclaimed."""
    assert "ubuntu_sandbox-1-clone" in S.parse_lvs(LVS)


def test_an_unreadable_xl_list_reclaims_nothing(tmp_path):
    """Cannot enumerate, so cannot safely destroy. Guessing at names would mean
    acting on a view of Dom0 we do not have."""
    r = FakeRunner()
    r.script(("xl", "list"), rc=1, stderr="xl: command not found")
    r.script(("lvs",), rc=1)

    report = S.sweep(r, vg="vg-root", config_dir=tmp_path)

    assert report.domains == []
    assert not r.ran(("xl", "destroy"))
    assert not r.ran(("lvremove",))


# --- order ------------------------------------------------------------------

def test_processes_die_before_domains_before_lvs(tmp_path):
    """Each step removes the reason the next would fail: a drakvuf still
    attached holds the domain, and a domain still running holds its LV open --
    which is what made lvremove report "Logical volume in use" on Dom0
    2026-08-14."""
    r = loaded()

    S.sweep(r, vg="vg-root", config_dir=tmp_path)

    destroy = r.order_of(("xl", "destroy"))
    lvremove = r.order_of(("lvremove",))
    assert destroy < lvremove


def test_the_settle_wait_is_kept(tmp_path):
    """`xl destroy` returns before the block device is released."""
    r = FakeRunner()
    r.script(("xl", "list"), stdout=XL_LIST, times=1)
    r.script(("lvs",), stdout=LVS, times=1)
    r.script(("xl", "domid"), rc=0, stdout="7\n", times=1)   # still there
    r.script(("xl", "domid"), rc=1)                          # then gone
    r.script(("xl", "list"), stdout=_xl_without_clones())
    r.script(("lvs",), stdout=_lvs_without_clones())

    S.sweep(r, vg="vg-root", config_dir=tmp_path, settle=5)

    assert len(r.find(("xl", "domid"))) >= 2, "the post-destroy poll is gone"


# --- what the resource table is told ----------------------------------------

def test_a_fully_cleaned_vlan_is_reported_clean(tmp_path):
    r = loaded()

    report = S.sweep(r, vg="vg-root", config_dir=tmp_path)

    assert report.clean_vlans == {1, 2}
    assert report.dirty_vlans == set()
    assert report.clean is True


def test_a_vlan_whose_clone_survived_is_reported_dirty(tmp_path):
    """The reason the resource table withholds by default. If the domain will
    not die, the next clone on that VLAN restores onto a snapshot whose
    predecessor is still alive -- DRAFT-033's cross-sample contamination, which
    is not a crash and so goes unreported."""
    survivor = XL_LIST.replace("android_sandbox-2-clone", "android_sandbox-9-clone")
    r = FakeRunner()
    r.script(("xl", "list"), stdout=XL_LIST, times=1)
    r.script(("lvs",), stdout=LVS, times=1)
    r.script(("xl", "domid"), rc=1)
    # Re-read at the end: VLAN 1's clone is gone, VLAN 2's is not.
    r.script(("xl", "list"),
             stdout="\n".join(l for l in XL_LIST.splitlines()
                              if "ubuntu_sandbox-1-clone" not in l) + "\n")
    r.script(("lvs",), stdout=_lvs_without_clones())

    report = S.sweep(r, vg="vg-root", config_dir=tmp_path)

    assert report.clean_vlans == {1}
    assert report.dirty_vlans == {2}
    assert report.clean is False


def test_the_report_feeds_the_resource_table(tmp_path):
    """End to end for the property your question exposed: nothing is
    allocatable until the sweep has confirmed it clean."""
    r = loaded()
    table = ResourceTable(total_mib=8192, vlans=range(1, 5), total_slots=4)
    assert table.free().vlans == 0

    report = S.sweep(r, vg="vg-root", config_dir=tmp_path)
    for vlan in report.clean_vlans:
        table.admit(vlan)

    assert table.free().vlans == 2
    assert table.acquire("job", 2198) is not None


# --- stray processes, and the DRAFT-011 defect ------------------------------

def test_a_capture_on_a_different_vlan_is_not_killed(tmp_path, monkeypatch):
    """The real fix for DRAFT-011. `grep "tcpdump -i xenbr1.$VLAN"` matched
    xenbr1.10 through xenbr1.19 when sweeping VLAN 1, because `.` is a regex
    wildcard and the pattern is unanchored. Exact argv elements cannot."""
    killed = []
    monkeypatch.setattr(S.proc, "kill_pid_group", lambda pid, **kw: killed.append(pid))
    monkeypatch.setattr(S.proc, "iter_processes", lambda: [
        (100, ("/usr/sbin/tcpdump", "-i", "xenbr1.1", "-w", "a.pcap")),
        (101, ("/usr/sbin/tcpdump", "-i", "xenbr1.10", "-w", "b.pcap")),
        (102, ("/usr/sbin/tcpdump", "-i", "xenbr1.19", "-w", "c.pcap")),
    ])
    r = loaded()

    S.sweep(r, vg="vg-root", config_dir=tmp_path)

    assert 100 in killed, "the capture on the swept VLAN survived"
    assert 101 not in killed and 102 not in killed, \
        "a capture on an unrelated VLAN was killed -- the DRAFT-011 defect"


def test_a_drakvuf_on_a_clone_is_killed_and_an_unrelated_one_is_not(
        tmp_path, monkeypatch):
    killed = []
    monkeypatch.setattr(S.proc, "kill_pid_group", lambda pid, **kw: killed.append(pid))
    monkeypatch.setattr(S.proc, "iter_processes", lambda: [
        (200, ("/usr/local/bin/drakvuf", "-d", "ubuntu_sandbox-1-clone")),
        (201, ("/usr/local/bin/drakvuf", "-d", "ubuntu_sandbox")),   # TEMPLATE
        (202, ("/usr/local/bin/injector", "-d", "android_sandbox-2-clone")),
    ])
    r = loaded()

    S.sweep(r, vg="vg-root", config_dir=tmp_path)

    assert sorted(killed) == [200, 202]
    assert 201 not in killed, "a process attached to the TEMPLATE was killed"


def test_an_unrelated_program_is_never_killed(tmp_path, monkeypatch):
    """A sweep that killed anything else on Dom0 would be a denial of service
    against the host it runs on."""
    killed = []
    monkeypatch.setattr(S.proc, "kill_pid_group", lambda pid, **kw: killed.append(pid))
    monkeypatch.setattr(S.proc, "iter_processes", lambda: [
        # Mentions a clone name, but is not one of ours to kill.
        (300, ("/usr/bin/less", "ubuntu_sandbox-1-clone.log")),
        (301, ("/usr/bin/sshd", "-D")),
    ])
    r = loaded()

    S.sweep(r, vg="vg-root", config_dir=tmp_path)

    assert killed == []


# --- files ------------------------------------------------------------------

def test_stale_clone_configs_are_removed_and_others_are_not(tmp_path):
    (tmp_path / "ubuntu_sandbox-1-clone.config").write_text("x")
    (tmp_path / "ubuntu_sandbox.config").write_text("keep me")
    (tmp_path / "unrelated.config").write_text("keep me")

    S.sweep(loaded(), vg="vg-root", config_dir=tmp_path)

    assert not (tmp_path / "ubuntu_sandbox-1-clone.config").exists()
    assert (tmp_path / "ubuntu_sandbox.config").exists()
    assert (tmp_path / "unrelated.config").exists()


def test_the_staging_directory_is_emptied(tmp_path):
    """Samples have to reach Dom0 disk: `injector -m writefile -B` takes a Dom0
    path and there is no stdin form. So the honest design is a known directory
    emptied at startup, not a claim that malware never touches this host."""
    staging = tmp_path / "staging"
    (staging / "job-a").mkdir(parents=True)
    (staging / "job-a" / "sample.bin").write_bytes(b"\x7fELF")

    S.sweep(loaded(), vg="vg-root", config_dir=tmp_path, staging_dir=staging)

    assert list(staging.rglob("*")) == []


def test_a_missing_staging_directory_is_not_an_error(tmp_path):
    S.sweep(loaded(), vg="vg-root", config_dir=tmp_path,
            staging_dir=tmp_path / "nope")