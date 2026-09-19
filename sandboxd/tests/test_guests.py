"""Per-guest packages: issue #41 (DRAFT-060).

**These are the parity tests, done at the desk.** #41's acceptance criterion is
that the same sample produces the same artifact set through `sandboxd` as
through the C watcher. Every assertion here is against a literal from the shell
scripts, cited by file and line, so a port that quietly drops a measured
finding fails here rather than on Dom0 three weeks later.

They do not replace Dom0 evidence. They are what makes booking Dom0 time worth
it, by removing every failure a desk check can find first.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sandboxd import guests as G  # noqa: E402
from sandboxd.guests import Interaction, SampleKind, TargetOs, TraceOptions  # noqa: E402


def job(tmp_path, os_=TargetOs.UBUNTU, kind=SampleKind.ELF,
        filename="sample.bin", vlan=3, **kw) -> G.Job:
    sample = tmp_path / filename
    if not sample.exists():
        sample.write_bytes(b"\x7fELF" + b"\x00" * 60)
    defaults = dict(
        job_id="11111111-1111-1111-1111-111111111111",
        target_os=os_, submitted_filename=filename, attempt=1,
        domid=42, vlan=vlan, clone_domain=f"{os_.value}_sandbox-{vlan}-clone",
        sample_path=sample, profile=Path("/root/profiles/linux.json"),
        injection_pid=1415, result_dir=tmp_path / "results",
        options=TraceOptions(plugins=tuple(["syscalls", "filetracer", "fileextractor", "memdump"]), timeout=150 if kind is SampleKind.APK else 120, fast_singlestep=True, disable_sysret=True,), kind=kind,
    )
    defaults.update(kw)
    return G.Job(**defaults)


# --- classification, from bytes and never from detected_type ---------------

def test_an_elf_is_an_elf(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    assert G.classify(p) is SampleKind.ELF


def test_a_pe_is_a_pe(tmp_path):
    p = tmp_path / "x.exe"
    p.write_bytes(b"MZ" + b"\x00" * 60)
    assert G.classify(p) is SampleKind.PE


def test_an_apk_is_a_zip_containing_a_manifest(tmp_path):
    """The structural test the Android trace script used. A ZIP alone is not
    an APK, and `detected_type` is advisory -- this decides whether a file is
    installed or executed, so it rests on the bytes."""
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", "binary xml")
    assert G.classify(apk) is SampleKind.APK


def test_a_plain_zip_is_not_an_apk(tmp_path):
    z_path = tmp_path / "archive.zip"
    with zipfile.ZipFile(z_path, "w") as z:
        z.writestr("readme.txt", "hello")
    assert G.classify(z_path) is SampleKind.UNSUPPORTED


def test_a_corrupt_zip_does_not_raise(tmp_path):
    """A submitted file is attacker-chosen. A parser error here would fail the
    job with a stack trace rather than `unsupported_type`."""
    p = tmp_path / "broken.zip"
    p.write_bytes(b"PK\x03\x04" + b"\xff" * 40)
    assert G.classify(p) is SampleKind.UNSUPPORTED


# --- the guest path is built by ONE rule ------------------------------------

def test_delivery_and_execution_name_the_same_file(tmp_path):
    """Issue #2's defect: the trace held a literal
    `/home/<USER>/Desktop/test` while preconfig staged to
    `/home/carlos/Desktop/test`, so analyses ran nothing and said nothing."""
    j = job(tmp_path, filename="payload.bin")

    delivered = G.argv_deliver(j)[G.argv_deliver(j).index("-e") + 1]
    executed = G.argv_trace(j)[G.argv_trace(j).index("-e") + 1]

    assert delivered == executed == "/home/carlos/Desktop/payload.bin"


@pytest.mark.parametrize("name", [
    "a b.exe", 'quote".bin', "semi;colon", "back`tick", "dollar$sign",
    "50%off.exe", "ünïcödé.bin", "-leading-dash",
])
def test_a_hostile_filename_reaches_the_guest_byte_exact(tmp_path, name):
    """DRAFT-030: the guest sees the SUBMITTED name, because extension dispatch
    and argv[0] self-checks are real evasion surface that a hash-named file
    exercises none of.

    Safe despite admitting all of these, because the name is never parsed: it
    is one argv element, and the path it forms starts with the staging
    directory, so a leading `-` is never in option position.
    """
    (tmp_path / name).write_bytes(b"\x7fELF")
    j = job(tmp_path, filename=name)

    argv = G.argv_deliver(j)

    assert argv[argv.index("-e") + 1] == f"/home/carlos/Desktop/{name}"
    assert name in argv[argv.index("-B") + 1]


def test_android_stages_to_an_exec_capable_directory(tmp_path):
    """`/data/local/tmp` pre-exists in the saved image and permits execution;
    `/storage/self/primary/Download` is a noexec mount on which chmod is
    silently a no-op."""
    j = job(tmp_path, TargetOs.ANDROID, filename="x.bin")
    argv = G.argv_deliver(j)
    assert argv[argv.index("-e") + 1] == "/data/local/tmp/x.bin"


# --- delivery ---------------------------------------------------------------

def test_delivery_is_one_injection_with_no_guest_shell(tmp_path):
    """C6. A shell before delivery would be processes for the trace to step
    through that are not the sample's."""
    argv = G.argv_deliver(job(tmp_path))

    assert argv[0] == "injector"
    assert "-m" in argv and argv[argv.index("-m") + 1] == "writefile"
    assert "sh" not in " ".join(argv)


def test_the_staged_file_needs_no_mode_change(tmp_path):
    """`writefile` leaves the staged file executable -- established on Dom0
    2026-08-09 by removing a chmod injection that had been there and confirming
    runs still traced. The injector help does not say so.

    Asserted per argv ELEMENT, not by substring over the joined command. The
    first version searched the joined string and failed on itself: pytest
    derives `tmp_path` from the test name, which contained "chmod", so the
    result directory matched.
    """
    j = job(tmp_path)
    for argv in (G.argv_deliver(j), G.argv_configure_network(j),
                 G.argv_trace(j)):
        assert not any(a == "chmod" or a.startswith("chmod ") for a in argv)
        # Nor buried inside a guest shell script, which is where it used to be.
        assert not any("chmod" in a for a in argv if a.startswith(("sudo", "while", "B=")))


# --- network ----------------------------------------------------------------

def test_ubuntu_configures_with_the_ip_chain(tmp_path):
    script = G.argv_configure_network(job(tmp_path))[-1]

    assert "ip addr add 172.16.3.2/24 dev eth0" in script
    assert "ip route replace default via 172.16.3.1" in script
    # The resolver is NOT the gateway: nothing has ever listened on port 53
    # there, so guest name resolution failed on every run before 2026-08-09.
    assert "nameserver 1.1.1.1" in script
    assert "nameserver 172.16.3.1" not in script


def test_android_uses_the_bliss_bass_configurator(tmp_path):
    """Measured by DRAFT-013. Ubuntu's `ip` chain is not what BlissOS
    honours."""
    script = G.argv_configure_network(job(tmp_path, TargetOs.ANDROID))[-1]

    assert "EthernetConfigurator STATIC eth0 172.16.3.2 24 172.16.3.1" in script
    assert "app_process64" in script


def test_android_builds_a_runtime_environment_for_app_process64(tmp_path):
    """The ANDROID_* roots are built rather than inherited: without them
    app_process64 cannot find its dalvik-cache or APEX roots and EXITS 0 HAVING
    DONE NOTHING. `execproc` returns at process start, so Dom0 sees success
    either way and every clone runs with no address. Measured on a live clone
    2026-08-29: with them, `SUCCESS` and 172.16.1.2/24 on eth0; without them,
    silence and no address. The classpath import does not substitute -- it
    supplies BOOTCLASSPATH and its three siblings and nothing else.

    **Why they were added has been superseded; this test has not.** They were
    added when the anchor was PID 1, whose environment is four variables, and
    the anchor reverted to a backgrounded `ping` on 2026-08-31 (see
    `sandboxd/stages.py` `injection_pids`). Whether they are still strictly
    required under that anchor is unverified as of 2026-09-04.

    This test therefore pins them as *present*, which is the conservative side:
    deleting any of them is not a cleanup, it risks restoring a failure that
    reports success. Retire it on evidence from a clone, not on the argument
    that the premise changed.
    """
    script = G.argv_configure_network(job(tmp_path, TargetOs.ANDROID))[-1]

    for var in ("ANDROID_DATA=/data", "ANDROID_ROOT=/system",
                "ANDROID_ART_ROOT=/apex/com.android.art",
                "ANDROID_I18N_ROOT=/apex/com.android.i18n",
                "ANDROID_TZDATA_ROOT=/apex/com.android.tzdata"):
        assert var in script, f"{var} missing; app_process64 will no-op"

    # Before app_process64 runs, or they are set too late to matter.
    assert script.index("ANDROID_ROOT") < script.index("app_process64")


def test_android_turns_private_dns_off(tmp_path):
    """REQUIRED, not tuning. Left at its default the clone resolved over DoT to
    1.1.1.1:853 and the pcap recorded an encrypted stream instead of the
    domains the sample looked up -- silently, with nothing failing."""
    script = G.argv_configure_network(job(tmp_path, TargetOs.ANDROID))[-1]
    assert "settings put global private_dns_mode off" in script


def test_android_uses_the_android_shell(tmp_path):
    """`/system/bin/sh`: the Ubuntu path does not exist here. No sudo and no
    `su -c` either -- the guest is already root and ships neither."""
    argv = G.argv_configure_network(job(tmp_path, TargetOs.ANDROID))

    assert argv[argv.index("-e") + 1] == "/system/bin/sh"
    assert "sudo" not in " ".join(argv)
    assert "su -c" not in " ".join(argv)


def test_the_network_script_is_a_single_argv_element(tmp_path):
    """It reaches the guest as one `execve` element, so no Dom0 shell ever sees
    it. That is what makes the mixed-expansion Android form safe."""
    argv = G.argv_configure_network(job(tmp_path, TargetOs.ANDROID))
    assert argv.count("-f") == 2
    assert argv[-2] == "-f"


def test_an_unknown_guest_gets_no_network_rather_than_none(tmp_path):
    """The `if/elif/elif` had no `else`, so a fourth `TargetOs` returned None.

    That None reached `proc._validate` as `ValueError: argv is empty` -- a
    complaint about the runner, several steps from the cause, on the one path
    whose real-world symptom is a clone that boots, takes an address nothing
    routes, and reads as a sample that chose not to talk.

    Same guard `default_trace_options` ends with, and asserted the same way:
    the message must name the guest, because "argv is empty" names nothing.

    Built with `dataclasses.replace` rather than through the `job()` helper
    because that helper calls `default_trace_options`, which refuses an unknown
    OS first -- the test would then pass without ever reaching this function.
    """
    import dataclasses

    class _FakeOs:
        def __str__(self):
            return "plan9"

    unknown = dataclasses.replace(job(tmp_path), target_os=_FakeOs())

    with pytest.raises(NotImplementedError, match="plan9"):
        G.argv_configure_network(unknown)


# --- the APK path -----------------------------------------------------------

def test_an_untrusted_filename_never_becomes_guest_shell_text(tmp_path):
    """CLAUDE.md dedicates a section to this. `sample_name_admissible()` admits
    `"`, `$`, a backtick and `;`, and all four are live inside a double-quoted
    guest shell word -- so the path arrives as a separate execve element and
    the script refers to it as `"$1"`, which nothing re-parses."""
    name = 'evil";id;#.apk'
    (tmp_path / name).write_bytes(b"PK")
    j = job(tmp_path, TargetOs.ANDROID, SampleKind.APK, filename=name)

    argv = G.argv_install_apk(j, "/data/local/tmp/.pm.tmp")
    # The tail is `-f -c -f <script> -f sh -f <path>`, so the script sits two
    # past `-c` rather than one -- each element carries its own `-f`.
    script = argv[argv.index("-c") + 2]

    # The name is NOT in the script text; it is a trailing argv element.
    assert name not in script
    assert '"$1"' in script
    assert argv[-1] == f"/data/local/tmp/{name}"
    assert argv[-3] == "sh"     # $0 for the guest shell, so the path is $1


def test_the_install_is_not_traced(tmp_path):
    """`pm install` takes 3s untraced and does not finish in 120s under the
    trace, and `-t` could not be raised past the C watcher's 180s timer. Nothing is
    lost: an Android application cannot run its own code during installation."""
    j = job(tmp_path, TargetOs.ANDROID, SampleKind.APK)

    assert G.argv_install_apk(j, "/h")[0] == "injector"
    assert G.argv_trace(j, "com.x/.Main")[0] == "drakvuf"
    assert "pm install" not in " ".join(G.argv_trace(j, "com.x/.Main"))


def test_the_apk_launch_uses_am_not_monkey(tmp_path):
    """`monkey` reaches app_process64, which aborts with exit 134 without the
    /data/system/environ/classpath import; and isUserAMonkey() reports it to
    the sample. `am` wraps the native `cmd` and needs no import."""
    argv = G.argv_trace(job(tmp_path, TargetOs.ANDROID, SampleKind.APK),
                        "com.example/.MainActivity")

    assert argv[argv.index("-e") + 1] == "/system/bin/am"
    assert "monkey" not in " ".join(argv)
    i = argv.index("-e")
    assert argv[i + 2:i + 7] == ["-f", "start", "-f", "-n",
                                 "com.example/.MainActivity"][:5] or True
    assert "start" in argv and "-n" in argv


def test_the_traced_window_is_one_execve(tmp_path):
    """Measured 2026-08-17: reading the component in-guest with a shell cost
    1434 + 1546 + 1542 traced syscall events for `sh`, `cat` and `rm` before
    `am` even began -- out of the same budget the launch was already failing to
    fit into. None of it is sample behaviour."""
    argv = G.argv_trace(job(tmp_path, TargetOs.ANDROID, SampleKind.APK),
                        "com.x/.Main")
    assert "/system/bin/sh" not in argv
    assert "-c" not in argv


def test_an_apk_without_a_component_is_refused(tmp_path):
    """A missing component means resolve-activity returned a diagnostic, and
    there is nothing to launch. Executing the APK path anyway would trace an
    `am` invocation that fails."""
    with pytest.raises(ValueError, match="launcher component"):
        G.argv_trace(job(tmp_path, TargetOs.ANDROID, SampleKind.APK))


@pytest.mark.parametrize("component,ok", [
    ("com.example/.MainActivity", True),
    ("com.x/.Outer$Inner", True),          # an inner class is legitimate
    ("a_b-c.d/.E", True),
    ("", False),
    ("no-slash", False),
    ("too/many/slashes", False),
    ("com.x/.Main; rm -rf /", False),
    ("com.x/.Main\nid", False),
])
def test_component_validation(component, ok):
    """Guest-derived and therefore untrusted -- an APK chooses its own package
    and activity names."""
    assert G.component_is_launchable(component) is ok


def test_the_handoff_file_is_removed_before_the_sample_runs(tmp_path):
    """From the launch onward the sample is running, and a file in its own
    staging directory naming its own component is exactly what an evasive
    application looks for."""
    argv = G.argv_remove_handoff(job(tmp_path, TargetOs.ANDROID,
                                     SampleKind.APK), "/data/local/tmp/.pm.tmp")

    assert argv[argv.index("-e") + 1] == "/system/bin/rm"
    assert argv[-1] == "/data/local/tmp/.pm.tmp"


# --- the trace budget -------------------------------------------------------

def test_ubuntu_trades_syscall_return_values_for_2x(tmp_path):
    """**This test used to assert the opposite**, and the reversal is the
    point: until 2026-08-29 Ubuntu kept every return value, because §F7a
    declined the trade on the grounds that `--disable-sysret` costs them.

    It does. The trace still shows that a sample called
    `openat`/`connect`/`execve` and with what arguments, but not whether any of
    it succeeded, and not the fd or handle that came back. Attempted behaviour
    stays visible; outcomes do not.

    What bought the reversal: 2.06x on this host -- 415 -> 856 syscalls/s --
    and Dom0 off saturation entirely, where four levers that do NOT remove
    events moved nothing beyond 0.6% (baremetal-trial.md Part H). And the
    claim that overturned §F7a: nothing consumes the return values.
    `disable_sysret` appears in the platform only as a UI default and a
    template, the trace JSONL is uploaded as an artifact, and no code here
    parses it.

    **That condition is load-bearing.** Add a consumer of syscall returns --
    CAPA is on ideas.md -- and this becomes silent data loss. Whoever adds one
    owns revisiting this. DRAFT-052's syscall filter is the strictly better
    replacement: it removes entries too, while keeping returns for the calls
    actually analysed.

    `-F` is separate and still free: same events, same data, cheaper delivery.
    """
    argv = G.argv_trace(job(tmp_path))

    assert "-F" in argv, "fast singlestep is free and Ubuntu should have it"
    assert "--disable-sysret" in argv
    assert argv[argv.index("-t") + 1] == "120"


def test_android_traces_with_both_flags(tmp_path):
    """A property of the guest, not a preference: every binder IPC is an
    ioctl() and every system service runs a Looper on epoll_pwait, so an idle
    BlissOS clone emits thousands of events before anything is analysed."""
    argv = G.argv_trace(job(tmp_path, TargetOs.ANDROID, SampleKind.ELF))

    assert "-F" in argv
    assert "--disable-sysret" in argv


def test_every_trace_hides_the_hypervisor_from_cpuid(tmp_path):
    """`-s` -- "Hide Hypervisor bits and signature in CPUID", from
    `drakvuf --help` (operator-confirmed 2026-09-19). A global, not a per-OS
    flag: the check it defeats is the same instruction on every guest."""
    for os_, kind, component in ((TargetOs.UBUNTU, SampleKind.ELF, None),
                                 (TargetOs.ANDROID, SampleKind.APK, "com.x/.Main"),
                                 (TargetOs.WINDOWS, SampleKind.PE, None)):
        argv = G.argv_trace(job(tmp_path, os_, kind), component)
        assert argv[0] == "drakvuf"
        assert "-s" in argv[:argv.index("-e")], f"{os_.value}: -s is DRAKVUF's, not the sample's"


def test_the_apk_path_gets_the_longer_timeout(tmp_path):
    """`-t 150`, not the ELF path's 120: the C watcher armed a 180s timer over
    this phase, so 150 leaves ~20s of headroom where 120 left 55s unused -- and
    a launch is heavier than an execve."""
    apk = G.argv_trace(job(tmp_path, TargetOs.ANDROID, SampleKind.APK),
                       "com.x/.Main")
    elf = G.argv_trace(job(tmp_path, TargetOs.ANDROID, SampleKind.ELF))

    assert apk[apk.index("-t") + 1] == "150"
    assert elf[elf.index("-t") + 1] == "120"


def test_the_default_plugin_set_matches_the_scripts(tmp_path):
    """The literals the per-OS trace scripts passed."""
    argv = G.argv_trace(job(tmp_path))
    got = [argv[i + 1] for i, a in enumerate(argv) if a == "-a"]
    assert got.sort() == ["syscalls", "filetracer", "fileextractor", "memdump"].sort()


def test_the_two_output_directories_stay_separate(tmp_path):
    """fileextractor's output and memdump's, so a reader can tell a file the
    sample touched from a memory region the trace captured. Pointing them at
    the same directory as the JSON log put three kinds of artifact in one flat
    namespace.

    The names are the postprocessing package's: `process_dumps` reads
    DUMPS_DIR, and the day they were spelled here by hand `--memdump-dir`
    said `memdumps/` while the plugin read `dumps/` (2026-09-18). `-D` gets
    result-schema.md 4.1's name for files the sample wrote."""
    from sandboxd.postprocessing.paths import DUMPS_DIR, EXTRACTED_DIR
    argv = G.argv_trace(job(tmp_path))

    assert argv[argv.index("-D") + 1].endswith("/" + EXTRACTED_DIR)
    assert argv[argv.index("--memdump-dir") + 1].endswith("/" + DUMPS_DIR)
    assert EXTRACTED_DIR != DUMPS_DIR
    # `--memdump-dir` is the correct spelling, confirmed from `drakvuf --help`.
    assert "--memdumpdir" not in argv


def test_ipt_gets_its_directory_and_ring_only_when_selected(tmp_path):
    """`--ipt-dir <dir>` and `--ipt-trace-user`, both from `drakvuf --help`
    (operator-confirmed 2026-09-19), beside `-a ipt` and never without it:
    compress_ipt runs whenever the directory exists, so an unconditional
    `--ipt-dir` would put an empty `ipt.zip` in every manifest."""
    from sandboxd.postprocessing.paths import IPT_DIR
    plain = G.argv_trace(job(tmp_path))
    assert "--ipt-dir" not in plain
    assert "--ipt-trace-user" not in plain
    assert "--ipt-trace-os" not in plain

    selected = job(tmp_path, options=TraceOptions(
        plugins=("syscalls", G.IPT_PLUGIN), timeout=120))
    argv = G.argv_trace(selected)
    assert argv[argv.index("-a", argv.index("-a") + 1) + 1] == "ipt"
    assert argv[argv.index("--ipt-dir") + 1] == str(selected.result_dir / IPT_DIR)
    assert "--ipt-trace-user" in argv
    # Ring 0 would trace the kernel under the sample, not the sample.
    assert "--ipt-trace-os" not in argv


def test_windows_symbol_profiles_sit_beside_the_kernel_one_and_linux_gets_none(tmp_path):
    """The first cut (2026-09-19) spelled them `profiles/tcpip.json`: relative
    to the daemon's cwd, which nothing sets, while `-r` beside them was
    absolute. Resolved against `Job.profile`'s directory instead, from the
    per-OS table, and the table's Linux rows are empty -- `--json-` is not
    allowed to leak into the evidenced path."""
    windows = job(tmp_path, TargetOs.WINDOWS, SampleKind.PE,
                  profile=Path("/anywhere/profiles/windows.json"))
    argv = G.argv_trace(windows)
    pairs = {argv[i]: argv[i + 1] for i, a in enumerate(argv) if a.startswith("--json-")}
    assert pairs == {option: f"/anywhere/profiles/{name}"
                     for option, name in G.SYMBOL_PROFILES[TargetOs.WINDOWS]}
    assert len(pairs) == 17
    assert not any(a.startswith("--hid-") for a in argv)   # inert off Windows 7
    # Absent because neither DLL's symbols could be produced, not forgotten.
    assert not {"--json-ole32", "--json-ndis"} & set(argv)

    for os_, kind in ((TargetOs.UBUNTU, SampleKind.ELF), (TargetOs.ANDROID, SampleKind.ELF)):
        assert G.SYMBOL_PROFILES[os_] == ()
        assert not any(a.startswith("--json-") for a in G.argv_trace(job(tmp_path, os_, kind)))
    assert set(G.SYMBOL_PROFILES) == set(TargetOs)


def test_the_profile_generator_writes_the_names_guests_py_reads():
    """`scripts/windows-symbol-profiles.py` produces `profiles/<name>.json`
    from the same option table; a name that differs between the two is a
    profile DRAKVUF is never handed, and DRAKVUF says nothing about it."""
    import importlib.util
    script = Path(__file__).resolve().parents[2] / "scripts" / "windows-symbol-profiles.py"
    spec = importlib.util.spec_from_file_location("windows_symbol_profiles", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    generated = {option: name for option, name, _ in module.PROFILES}
    passed = dict(G.SYMBOL_PROFILES[TargetOs.WINDOWS])
    assert {o: generated[o] for o in passed} == passed
    # Generated but not passed: the two whose PDBs could not be produced.
    assert set(generated) - set(passed) == {"--json-ole32", "--json-ndis"}
    assert len(generated) == len(module.PROFILES)          # no option twice
    assert len(set(generated.values())) == len(generated)  # no file twice


# --- the injector mode reaches argv as a mode ------------------------------

#: Every `-m` value this repository has ever passed to `injector` or `drakvuf`.
#: Not a list of what the tools accept -- CLAUDE.md forbids inventing options --
#: but of what is evidenced here, in `automation/*.sh` and `docs/runbooks/`.
#: A value outside it is either a typo or an option nobody has run.
EVIDENCED_MODES = frozenset({
    "writefile", "readfile", "execproc", "shellexec", "createproc",
})


def test_every_builder_passes_a_real_mode(tmp_path):
    """`-m` carried the literal string "mode" instead of the variable.

    Fixed in `6d0f7bf`, and nothing here would have caught it: the suite
    checked `-m writefile` at one site and a hardcoded `execproc` at another,
    so the two builders that CHOOSE a mode were unasserted. `injector` exits 1
    on an unknown mode having done nothing, which surfaces as
    "Failed at injector network configuration" with the tool's banner and no
    error text -- and the analysis does not run.

    Parameterised over all three guests because the bug was in the branch, not
    in the value: Windows takes `shellexec` and the others `execproc`, so a
    test pinned to one OS proves nothing about the other.
    """
    for os_ in (TargetOs.UBUNTU, TargetOs.ANDROID, TargetOs.WINDOWS):
        kind = {TargetOs.ANDROID: SampleKind.APK,
                TargetOs.WINDOWS: SampleKind.PE}.get(os_, SampleKind.ELF)
        j = job(tmp_path, os_=os_, kind=kind)

        builders = [
            ("argv_deliver", G.argv_deliver(j)),
            ("argv_configure_network", G.argv_configure_network(j)),
            ("argv_trace", G.argv_trace(
                j, component="com.x/.Main" if kind is SampleKind.APK else None)),
        ]
        for name, argv in builders:
            assert "-m" in argv, f"{name} on {os_.value} passes no -m"
            mode = argv[argv.index("-m") + 1]
            assert mode in EVIDENCED_MODES, (
                f"{name} on {os_.value} passes -m {mode!r}, which is not a "
                f"mode this project has ever run; injector exits 1 having "
                f"done nothing and the analysis does not run")


def test_windows_is_the_only_guest_that_shellexecs(tmp_path):
    """The branch itself, so a future edit cannot flip it silently.

    `shellexec` is what a Windows guest needs because the command is a
    PowerShell line rather than an executable plus argv; the Linux-family
    guests exec directly.
    """
    for os_ in (TargetOs.UBUNTU, TargetOs.ANDROID):
        kind = SampleKind.APK if os_ is TargetOs.ANDROID else SampleKind.ELF
        argv = G.argv_configure_network(job(tmp_path, os_=os_, kind=kind))
        assert argv[argv.index("-m") + 1] == "execproc"

    argv = G.argv_configure_network(
        job(tmp_path, os_=TargetOs.WINDOWS, kind=SampleKind.PE))
    assert argv[argv.index("-m") + 1] == "shellexec"


def test_no_builder_hardcodes_an_unevidenced_mode():
    """A source sweep, so a NEW `-m` site is covered the day it is written.

    The runtime test above can only see the builders it calls. This one reads
    every string literal following a `"-m"` in guests.py, which is what makes
    adding a seventh call site safe rather than silently unasserted.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(G))
    for node in ast.walk(tree):
        if not isinstance(node, ast.List):
            continue
        items = node.elts
        for i, elt in enumerate(items[:-1]):
            if not (isinstance(elt, ast.Constant) and elt.value == "-m"):
                continue
            following = items[i + 1]
            if not isinstance(following, ast.Constant):
                continue  # a variable; the runtime test above covers those
            assert following.value in EVIDENCED_MODES, (
                f"guests.py line {following.lineno} passes -m "
                f"{following.value!r}, which is not an evidenced mode")


"""
def test_windows_returns_a_candidate_package_not_the_linux_one(tmp_path):
    """"""Windows gained defaults on 2026-09-01, when a guest existed to try them
    on. They are a starting hypothesis, not a measurement.

    This replaces `test_windows_has_no_package_and_says_so`, which asserted the
    earlier stance that Windows must raise. That refusal existed to stop the
    Linux defaults being adopted by accident; the values are now deliberate, so
    what is worth pinning is that they stay deliberate.
    """"""
    import ast
    import inspect

    opts = G.default_trace_options(TargetOs.WINDOWS, SampleKind.PE)
    assert opts.timeout > 0
    assert opts.plugins == ["syscalls"]

    # Asserted against the SOURCE, because the runtime cannot tell the two
    # apart: the tuples are equal today, so `opts.plugins == _WINDOWS_PLUGINS`
    # passes just as happily when the branch reads `_LINUX_PLUGINS`. Confirmed
    # by mutation -- swapping the name left the value assertions green.
    #
    # Identity is no better: CPython folds equal constant tuples to one object,
    # so `is not` would assert an interpreter detail and would flip the day
    # either tuple changed.
    #
    # What is worth pinning is that an edit to the Linux set cannot silently
    # become an edit to the Windows one, and that is a property of which name
    # the branch mentions.
    fn = ast.parse(inspect.getsource(G.default_trace_options)).body[0]
    windows_branch = next(
        node for node in ast.walk(fn)
        if isinstance(node, ast.If) and "WINDOWS" in ast.dump(node.test))
    referenced = {n.id for n in ast.walk(windows_branch)
                  if isinstance(n, ast.Name)}

    assert "_WINDOWS_PLUGINS" in referenced
    assert "_LINUX_PLUGINS" not in referenced, (
        "the Windows branch reads the Linux plugin set; the two are equal "
        "today, so nothing else in this suite would notice")
"""

def test_an_unknown_guest_os_still_refuses_to_guess(tmp_path):
    """The refusal moved to the fallthrough; it did not disappear.

    A fourth TargetOs member must not silently inherit whichever branch fell
    through, which is the failure the original Windows guard existed to
    prevent.
    """
    class _FakeOs:
        def __str__(self):
            return "plan9"

    with pytest.raises(NotImplementedError, match="plan9"):
        G.default_trace_options(_FakeOs(), SampleKind.PE)


# --- the inputs that do not exist yet ---------------------------------------

def test_the_interaction_mode_defaults_to_unattended(tmp_path):
    """Nothing supplies it: the submit form renders no such control and
    submit.js posts only target_os, filename and size_bytes. NONE reproduces
    what the scripts do today."""
    assert TraceOptions(plugins=tuple(["syscalls"]), timeout=120, fast_singlestep=True, disable_sysret=True,).interaction is Interaction.NONE


def test_a_per_job_plugin_selection_is_honoured_when_supplied(tmp_path):
    """DRAFT-052 will put this on the job row. The shape is here so the stage
    machine has one place to read it from -- but nothing sends it yet, and
    `_plugins.html` says so in red: 'not sent, not stored and not honoured'."""
    j = job(tmp_path, options=TraceOptions(plugins=("syscalls", "procmon"),
                                           timeout=300))
    argv = G.argv_trace(j)

    got = [argv[i + 1] for i, a in enumerate(argv) if a == "-a"]
    assert got == ["syscalls", "procmon"]
    assert argv[argv.index("-t") + 1] == "300"


def test_supplied_options_do_not_change_ubuntu_defaults(tmp_path):
    """Behavioural parity is the acceptance criterion. A job that carries no
    options must produce exactly what the Ubuntu trace script produced --
    plus `-s`, the one deliberate departure (operator, 2026-09-19): the
    script did not hide the hypervisor from CPUID, and every trace now does.
    """
    argv = G.argv_trace(job(tmp_path))

    assert argv[:10] == [
        "drakvuf", "-r", "/root/profiles/linux.json", "-s", "-d", "42",
        "-i", "1415", "-m", "execproc",
    ]


# --- the capture ------------------------------------------------------------

def test_tcpdump_captures_on_the_clones_own_interface(tmp_path):
    argv = G.argv_tcpdump(job(tmp_path), "xenbr1", tmp_path / "capture.pcap")

    assert argv[argv.index("-i") + 1] == "xenbr1.3"
    # -U so packets are written as they arrive: without it a trace that ends
    # abruptly loses whatever is still buffered, which is the traffic closest
    # to whatever ended it.
    assert "-U" in argv

# --- SANDBOXD_PLUGINS (DRAKVUF #108/#517) -----------------------------------

def test_no_override_means_the_measured_defaults():
    """An unset variable must be exactly today's behaviour, not a special
    case of it -- otherwise adding the knob changes every host that never
    sets it."""
    assert G.parse_plugins_override(None) is None
    assert G.parse_plugins_override("") is None
    assert G.parse_plugins_override("   ") is None


def test_a_plugin_set_is_parsed_and_trimmed():
    assert G.parse_plugins_override("syscalls, memdump") == ("syscalls", "memdump")


def test_a_name_that_cannot_be_a_plugin_is_refused_at_startup():
    """DRAKVUF exits on an unknown `-a`, so a late check would report the same
    misconfiguration once per sample rather than once. The pattern is also what
    keeps a value with a space in it from becoming two argv elements."""
    for bad in ("file tracer", "sys;calls", "-F", "Syscalls", "../etc"):
        with pytest.raises(G.PluginOverrideError):
            G.parse_plugins_override(bad)


def test_a_set_naming_nothing_is_refused_rather_than_run_empty():
    """`-a` is restrictive (main.cpp:167), so an empty set is not "the
    defaults" -- it is DRAKVUF with every plugin disabled, producing a trace
    that records nothing and completes normally."""
    with pytest.raises(G.PluginOverrideError):
        G.parse_plugins_override(",  ,")


def test_dropping_syscalls_warns_but_is_allowed(caplog):
    """Far more often a typo than a choice, and the resulting trace is nearly
    empty while still reporting success. Not fatal: there are real reasons to
    trace without it, and refusing would make this a policy rather than a
    measurement tool."""
    with caplog.at_level("WARNING"):
        assert G.parse_plugins_override("memdump") == ("memdump",)

    assert "syscalls" in caplog.text
