"""The clone stage: issue #41 (DRAFT-060), the port of automation/clone.pl.

Every Dom0 command is faked. What is under test is the argv that WOULD have
run and the order it would have run in -- which is #41's parity criterion
("the same sample produces the same artifact set") proved at the desk, before
any Dom0 time is spent.

The config rewrite is tested against the REAL misc/*.cfg files, because
misc/android_sandbox.cfg records that clone.pl's rewrite "reproduces
byte-for-byte what verify-android-isolation.md step 2 wrote out by hand",
verified 2026-08-15. That gives the port a known-correct output to match
rather than a plausible one.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd import clone as C  # noqa: E402
from sandboxd.naming import clone_name, is_clone, parse_clone  # noqa: E402
from sandboxd.tests.fake import FakeRunner  # noqa: E402

MISC = ROOT / "misc"


def spec(tmp_path, origin="ubuntu_sandbox", vlan=3, **kw) -> C.CloneSpec:
    cfg = tmp_path / f"{origin}.cfg"
    if not cfg.exists():
        cfg.write_text((MISC / f"{origin}.cfg").read_text())
    state = tmp_path / f"{origin}.bak"
    state.write_bytes(b"saved memory image")
    return C.CloneSpec(origin=origin, vlan=vlan, config=cfg,
                       saved_state=state, **kw)


def ready(runner: FakeRunner, clone: str, origin: str) -> FakeRunner:
    """The happy path: no stale domain, origin LV present, no stale clone LV.

    `times=1` on the stale check, deliberately. Rules match first-wins, so an
    unbounded "no such domain" would also answer the `xl domid` AFTER the
    restore -- and the build would then always conclude that the domain it just
    created does not exist.
    """
    runner.script(("xl", "domid", clone), rc=1, times=1)
    runner.script(("lvdisplay", f"/dev/vg-root/{origin}"), rc=0)
    runner.script(("lvdisplay", f"/dev/vg-root/{clone}"), rc=1)
    return runner


# --- the naming boundary ---------------------------------------------------
#
# The sweep destroys everything this says is a clone, so a false positive here
# destroys a template and a false negative leaks one.

@pytest.mark.parametrize("name", [
    "ubuntu_sandbox-1-clone", "android_sandbox-254-clone", "a-b-3-clone",
])
def test_a_clone_is_recognised(name):
    assert is_clone(name)


@pytest.mark.parametrize("name", [
    "ubuntu", "android", "ubuntu_sandbox", "android_sandbox",   # NEVER ours
    "ubuntu_sandbox-clone", "ubuntu_sandbox-0-clone",
    "ubuntu_sandbox-255-clone", "ubuntu_sandbox-1-clone-x",
    "clone", "-1-clone", "ubuntu_sandbox-1a-clone",
])
def test_what_is_not_a_clone_is_left_alone(name):
    """The golden images and the templates are the first four, and they are the
    whole reason this predicate is a positive match rather than a denylist: a
    denylist is one forgotten name away from destroying a template that has to
    be rebuilt from the golden VM."""
    assert not is_clone(name)


def test_an_origin_containing_a_dash_parses_from_the_right():
    """clone.pl admits [A-Za-z0-9._-] in an origin, so the origin can contain
    the separator. A left-to-right parse reads `a-b-3-clone` as origin `a`,
    vlan `b`, fails the integer check, and silently declines to clean up a real
    clone."""
    got = parse_clone("a-b-3-clone")
    assert got is not None
    assert (got.origin, got.vlan) == ("a-b", 3)


@pytest.mark.parametrize("vlan", [0, 255, 1000])
def test_an_impossible_vlan_is_refused(vlan):
    with pytest.raises(ValueError, match="vlan"):
        clone_name("ubuntu_sandbox", vlan)


def test_an_origin_with_a_shell_metacharacter_is_refused():
    """Not an injection defence -- there is no shell in this path -- but a name
    that cannot be a domain should fail where it is written, not as an opaque
    lvcreate error naming a device nobody meant."""
    with pytest.raises(ValueError, match="may contain only"):
        clone_name("ubuntu; rm -rf /", 1)


# --- the config rewrite, against the real templates ------------------------

def test_the_rewrite_matches_the_evidenced_output():
    """misc/android_sandbox.cfg records this exact transformation as verified
    byte-for-byte against a hand-written config on 2026-08-15."""
    s = C.CloneSpec(origin="android_sandbox", vlan=2,
                    config=MISC / "android_sandbox.cfg",
                    saved_state=Path("/nonexistent"), lv_size="32G")

    out = C.rewrite_config((MISC / "android_sandbox.cfg").read_text(), s)

    assert 'name = "android_sandbox-2-clone"' in out
    assert ("vif = [ 'type=ioemu,model=e1000,script=vif-openvswitch,"
            "bridge=xenbr1.2' ]") in out
    assert "disk = [ 'phy:/dev/vg-root/android_sandbox-2-clone,hda,w' ]" in out


def test_the_templates_own_bridge_is_discarded_not_merged():
    """Inheriting `bridge=xenbr1` would put the clone on the trunk with no
    isolation rules -- a clone that looks fine and is not isolated."""
    s = C.CloneSpec(origin="ubuntu_sandbox", vlan=7,
                    config=MISC / "ubuntu_sandbox.cfg",
                    saved_state=Path("/nonexistent"))

    out = C.rewrite_config((MISC / "ubuntu_sandbox.cfg").read_text(), s)
    vif = [l for l in out.splitlines() if l.startswith("vif")][0]

    assert vif.count("bridge=") == 1
    assert "bridge=xenbr1.7" in vif
    assert "script=vif-openvswitch" in vif


def test_the_introspection_settings_survive_untouched():
    """altp2m, hap, shadow_memory and viridian are what make the domain
    traceable at all, and the templates carry comments saying a wrong value
    fails at ANALYSIS time rather than at domain creation. A rewrite that lost
    them would produce a clone that boots and cannot be introspected."""
    s = C.CloneSpec(origin="ubuntu_sandbox", vlan=1,
                    config=MISC / "ubuntu_sandbox.cfg",
                    saved_state=Path("/nonexistent"))

    out = C.rewrite_config((MISC / "ubuntu_sandbox.cfg").read_text(), s)

    for line in ("altp2m = 2", "hap = 1", "shadow_memory = 32", "viridian = 1"):
        assert line in out
    # The comments too: they explain why these must not be changed.
    assert "external mode -- required for stealth breakpoints" in out


def test_an_unparseable_vif_line_fails_loudly():
    s = C.CloneSpec(origin="x", vlan=1, config=Path("/nonexistent"),
                    saved_state=Path("/nonexistent"))
    with pytest.raises(C.CloneError, match="VIF"):
        C.rewrite_config("vif = nonsense\n", s)


# --- argv parity with clone.pl ---------------------------------------------

def test_the_commands_match_what_clone_pl_runs(tmp_path):
    s = spec(tmp_path)
    r = ready(FakeRunner(), s.name, s.origin)
    r.script(("xl", "domid", s.name), rc=0, stdout="42\n")  # after restore

    C.CloneBuilder(r, lock_dir=tmp_path, config_dir=tmp_path).build(s)

    assert r.ran(("lvcreate", "-s", "-n", "ubuntu_sandbox-3-clone",
                  "-L64G", "/dev/vg-root/ubuntu_sandbox"))
    assert r.ran(("xl", "restore", "-p", "-e"))


def test_the_snapshot_size_is_per_os(tmp_path):
    """32G for Android, 64G for Ubuntu: how much divergence from the origin a
    clone may accumulate is a property of the OS image."""
    s = spec(tmp_path, origin="android_sandbox", vlan=2, lv_size="32G")
    r = ready(FakeRunner(), s.name, s.origin)
    r.script(("xl", "domid", s.name), rc=0, stdout="7\n")

    C.CloneBuilder(r, lock_dir=tmp_path, config_dir=tmp_path).build(s)

    assert r.ran(("lvcreate", "-s", "-n", "android_sandbox-2-clone", "-L32G",
                  "/dev/vg-root/android_sandbox"))


def test_an_empty_size_is_refused_rather_than_passed(tmp_path):
    """clone.pl treats an exported-but-empty CLONE_LV_SIZE as unset because
    `-L` with no argument makes lvcreate read the DEVICE PATH as the size."""
    s = spec(tmp_path, lv_size="")
    with pytest.raises(C.CloneError, match="size operand"):
        C.argv_lvcreate(s)


# --- ordering, which is where the contamination bug lived ------------------

def test_a_stale_domain_is_destroyed_before_its_lv_is_removed(tmp_path):
    """DRAFT-033's finding: a destroy that fails leaves the LV open, the
    lvremove then fails too, and before the exit statuses were checked both
    passed silently -- after which `xl restore` landed on the PREVIOUS
    sample's snapshot. Cross-sample contamination, not a crash, so nothing
    reported it."""
    s = spec(tmp_path)
    r = FakeRunner()
    r.script(("xl", "domid", s.name), rc=0, stdout="9\n", times=1)   # stale
    r.script(("xl", "destroy", s.name), rc=0)
    r.script(("xl", "domid", s.name), rc=1, times=1)                 # gone
    r.script(("lvdisplay", f"/dev/vg-root/{s.origin}"), rc=0)
    r.script(("lvdisplay", f"/dev/vg-root/{s.name}"), rc=0)          # stale LV
    r.script(("lvremove", "-f", f"/dev/vg-root/{s.name}"), rc=0)
    r.script(("xl", "domid", s.name), rc=0, stdout="11\n")

    C.CloneBuilder(r, lock_dir=tmp_path, config_dir=tmp_path).build(s)

    destroy = r.order_of(("xl", "destroy"))
    lvremove = r.order_of(("lvremove",))
    lvcreate = r.order_of(("lvcreate",))
    restore = r.order_of(("xl", "restore"))
    assert destroy < lvremove < lvcreate < restore


def test_a_failed_lvremove_stops_the_build(tmp_path):
    """Proceeding would restore onto the previous sample's snapshot."""
    s = spec(tmp_path)
    r = FakeRunner()
    r.script(("xl", "domid", s.name), rc=1)
    r.script(("lvdisplay", f"/dev/vg-root/{s.origin}"), rc=0)
    r.script(("lvdisplay", f"/dev/vg-root/{s.name}"), rc=0)
    r.script(("lvremove",), rc=5, stderr="Logical volume in use")

    with pytest.raises(C.CloneError) as exc:
        C.CloneBuilder(r, lock_dir=tmp_path, config_dir=tmp_path).build(s)

    assert exc.value.stage == "lvm"
    assert "PREVIOUS sample's" in str(exc.value)
    assert not r.ran(("xl", "restore"))


def test_the_settle_wait_after_destroy_is_kept(tmp_path):
    """`xl destroy` returns before the block device is released -- measured on
    Dom0 2026-08-14. The wait is what makes the lvremove reliable, so it is
    polled rather than assumed."""
    s = spec(tmp_path)
    r = FakeRunner()
    r.script(("xl", "domid", s.name), rc=0, stdout="9\n", times=1)
    r.script(("xl", "destroy", s.name), rc=0)
    # Still present on the first poll, gone on the second.
    r.script(("xl", "domid", s.name), rc=0, stdout="9\n", times=1)
    r.script(("xl", "domid", s.name), rc=1, times=1)
    r.script(("lvdisplay", f"/dev/vg-root/{s.origin}"), rc=0)
    r.script(("lvdisplay", f"/dev/vg-root/{s.name}"), rc=1)
    r.script(("xl", "domid", s.name), rc=0, stdout="12\n")

    C.CloneBuilder(r, lock_dir=tmp_path, config_dir=tmp_path).build(s)

    polls = len(r.find(("xl", "domid", s.name)))
    assert polls >= 4, "the post-destroy settle poll is gone"


# --- failure paths that dirwatch could not tell apart ----------------------

def test_a_restore_that_exits_zero_with_no_domain_is_a_failure(tmp_path):
    """`xl restore` can exit 0 and leave no usable domain, so a successful exit
    is not evidence there is anything to trace."""
    s = spec(tmp_path)
    r = ready(FakeRunner(), s.name, s.origin)
    r.script(("xl", "restore"), rc=0)
    r.script(("xl", "domid", s.name), rc=0, stdout="")

    with pytest.raises(C.CloneError) as exc:
        C.CloneBuilder(r, lock_dir=tmp_path, config_dir=tmp_path).build(s)

    assert exc.value.stage == "restore"


def test_a_diagnostic_is_never_mistaken_for_a_domain_id(tmp_path):
    """clone.pl must print nothing but the id because dirwatch parses its
    stdout. The check survives the port: `xl domid` prints its own errors."""
    s = spec(tmp_path)
    r = ready(FakeRunner(), s.name, s.origin)
    r.script(("xl", "domid", s.name), rc=0,
             stdout="libxl: error: cannot find domain\n")

    with pytest.raises(C.CloneError):
        C.CloneBuilder(r, lock_dir=tmp_path, config_dir=tmp_path).build(s)


def test_a_partial_clone_is_torn_down(tmp_path):
    """clone.pl's END block: a half-built clone must not survive to block the
    next run for this vlan."""
    s = spec(tmp_path)
    r = ready(FakeRunner(), s.name, s.origin)
    r.script(("xl", "restore"), rc=1, stderr="restore failed")

    with pytest.raises(C.CloneError):
        C.CloneBuilder(r, lock_dir=tmp_path, config_dir=tmp_path).build(s)

    assert r.ran(("lvremove", "-f", f"/dev/vg-root/{s.name}"))
    assert not (tmp_path / f"{s.name}.config").exists()


def test_each_failure_names_its_stage(tmp_path):
    """The improvement the port gets for free: dirwatch.c passes NULL for
    exit_rc, so clone.pl's separated exit codes are computed and discarded and
    every failure looks like "no id came back"."""
    s = spec(tmp_path)
    s = C.CloneSpec(origin=s.origin, vlan=s.vlan, config=s.config,
                    saved_state=Path("/nonexistent/state.bak"))
    r = ready(FakeRunner(), s.name, s.origin)

    with pytest.raises(C.CloneError) as exc:
        C.CloneBuilder(r, lock_dir=tmp_path, config_dir=tmp_path).build(s)

    assert exc.value.stage == "precheck"
    assert "saved memory image" in str(exc.value)
    assert not r.ran(("lvcreate",))


def test_nothing_is_created_before_the_prechecks_pass(tmp_path):
    """A wrong origin costs nothing and names itself, instead of surfacing as
    an opaque lvcreate error about a device nobody meant."""
    s = spec(tmp_path)
    r = FakeRunner()
    r.script(("xl", "domid", s.name), rc=1)
    r.script(("lvdisplay", f"/dev/vg-root/{s.origin}"), rc=5)

    with pytest.raises(C.CloneError, match="origin logical volume"):
        C.CloneBuilder(r, lock_dir=tmp_path, config_dir=tmp_path).build(s)

    assert not r.ran(("lvcreate",))
    assert not r.ran(("xl", "restore"))


# --- the fake cannot hide the bug it exists to catch -----------------------

def test_the_fake_refuses_a_command_string():
    """A fake that accepted a string would let a test pass while the real code
    built something a shell would re-split -- the exact class of bug #41
    removes, concealed by the tool meant to catch it."""
    with pytest.raises(TypeError, match="list of strings"):
        FakeRunner().run("xl destroy foo", timeout=1)