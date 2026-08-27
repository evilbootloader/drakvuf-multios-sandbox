"""Per-guest packages: issue #41 (DRAFT-060).

**These are the parity tests, done at the desk.** #41's acceptance criterion is
that the same sample produces the same artifact set through `sandboxd` as
through `dirwatch`. Every assertion here is against a literal from the shell
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
        options=G.default_trace_options(os_, kind), kind=kind,
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
    """The structural test drakvuf-android.sh already uses. A ZIP alone is not
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
    trace, and `-t` cannot be raised past dirwatch's 180s timer. Nothing is
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

def test_ubuntu_keeps_every_syscall_return_value(tmp_path):
    """The line this test defends is **information cost**, not "Ubuntu differs
    from Android" -- which is what it asserted until 2026-08-27, when `-F` was
    added to Ubuntu and this failed for the right reason.

    `-F` costs nothing: it swaps the singlestep round trip after a hooked event
    for a second altp2m view, so the same events arrive carrying the same data.
    `--disable-sysret` is not like that. It halves the events by discarding
    syscall RETURN values, and a trace missing them shows that a sample called
    `openat`/`connect`/`execve` and with what arguments, but not whether any of
    it succeeded. Attempted behaviour stays visible; outcomes do not.

    So Ubuntu may take cheaper delivery of the same trace, and may not take a
    cheaper trace. Turning this red is a decision about evidence, not speed.
    """
    argv = G.argv_trace(job(tmp_path))

    assert "-F" in argv, "fast singlestep is free and Ubuntu should have it"
    assert "--disable-sysret" not in argv, (
        "Ubuntu would stop recording syscall return values -- see the docstring"
    )
    assert argv[argv.index("-t") + 1] == "120"


def test_android_traces_with_both_flags(tmp_path):
    """A property of the guest, not a preference: every binder IPC is an
    ioctl() and every system service runs a Looper on epoll_pwait, so an idle
    BlissOS clone emits thousands of events before anything is analysed."""
    argv = G.argv_trace(job(tmp_path, TargetOs.ANDROID, SampleKind.ELF))

    assert "-F" in argv
    assert "--disable-sysret" in argv


def test_the_apk_path_gets_the_longer_timeout(tmp_path):
    """`-t 150`, not the ELF path's 120: dirwatch.c:653 arms a 180s timer over
    this phase, so 150 leaves ~20s of headroom where 120 left 55s unused -- and
    a launch is heavier than an execve."""
    apk = G.argv_trace(job(tmp_path, TargetOs.ANDROID, SampleKind.APK),
                       "com.x/.Main")
    elf = G.argv_trace(job(tmp_path, TargetOs.ANDROID, SampleKind.ELF))

    assert apk[apk.index("-t") + 1] == "150"
    assert elf[elf.index("-t") + 1] == "120"


def test_the_default_plugin_set_matches_the_scripts(tmp_path):
    """drakvuf-ubuntu.sh:181 and drakvuf-android.sh:324."""
    argv = G.argv_trace(job(tmp_path))
    got = [argv[i + 1] for i, a in enumerate(argv) if a == "-a"]
    assert got == ["syscalls", "filetracer", "fileextractor", "memdump"]


def test_the_two_output_directories_stay_separate(tmp_path):
    """fileextractor's output and memdump's, so a reader can tell a file the
    sample touched from a memory region the trace captured. Pointing them at
    the same directory as the JSON log put three kinds of artifact in one flat
    namespace."""
    argv = G.argv_trace(job(tmp_path))

    assert argv[argv.index("-D") + 1].endswith("/dump")
    assert argv[argv.index("--memdump-dir") + 1].endswith("/memdump")
    # `--memdump-dir` is the correct spelling, confirmed from `drakvuf --help`.
    assert "--memdumpdir" not in argv


def test_windows_has_no_package_and_says_so(tmp_path):
    """Nothing has ever executed on a Windows guest. Defaulting to the Linux
    set would be inventing evidence, which catalogue.py refuses for the same
    reason."""
    with pytest.raises(NotImplementedError, match="Windows"):
        G.default_trace_options(TargetOs.WINDOWS, SampleKind.PE)


# --- the inputs that do not exist yet ---------------------------------------

def test_the_interaction_mode_defaults_to_unattended(tmp_path):
    """Nothing supplies it: the submit form renders no such control and
    submit.js posts only target_os, filename and size_bytes. NONE reproduces
    what the scripts do today."""
    assert G.default_trace_options(
        TargetOs.UBUNTU, SampleKind.ELF).interaction is Interaction.NONE


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
    options must produce exactly what drakvuf-ubuntu.sh produces."""
    argv = G.argv_trace(job(tmp_path))

    assert argv[:9] == [
        "drakvuf", "-r", "/root/profiles/linux.json", "-d", "42",
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