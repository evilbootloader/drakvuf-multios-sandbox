"""The five host values config.py takes from the environment (2026-11-03).

They were sed-edited into the tracked config.py by `make sandboxd` and
`make setup_hooks_*` until then, which dirtied Dom0's checkout on every deploy
and could leave `INJECTION_PID_WINDOWS = ` with nothing after it. Each case
runs in a fresh interpreter, because config.py reads the environment at import.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

_PROBE = (
    "import sandboxd.config as c; "
    "print(c.DOM0_REPO_ROOT, c.ANALYSIS_USERNAME, c.INJECTION_PID_UBUNTU, "
    "c.INJECTION_PID_WINDOWS, c.INJECTION_PID_ANDROID)"
)


def _probe(env: dict[str, str]) -> subprocess.CompletedProcess:
    clean = {k: v for k, v in os.environ.items() if not k.startswith("SANDBOXD_")}
    return subprocess.run([sys.executable, "-c", _PROBE], cwd=ROOT,
                          env={**clean, **env}, capture_output=True, text=True)


def test_the_defaults_are_a_fresh_checkouts():
    out = _probe({})
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == ["/root/drakvuf-multios-sandbox", "user", "1", "1", "1"]


def test_the_environment_file_overrides_every_one_of_them():
    out = _probe({
        "SANDBOXD_REPO_ROOT": "/srv/checkout",
        "SANDBOXD_ANALYSIS_USERNAME": "carlos",
        "SANDBOXD_INJECTION_PID_UBUNTU": "1",
        "SANDBOXD_INJECTION_PID_WINDOWS": "4696",
        "SANDBOXD_INJECTION_PID_ANDROID": "3251",
    })
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == ["/srv/checkout", "carlos", "1", "4696", "3251"]


def test_an_empty_value_is_the_default_not_a_crash():
    """A rendered `NAME=` line with nothing after it, which is the shape the
    old sed produced when the explorer.exe pipeline matched nothing."""
    out = _probe({"SANDBOXD_INJECTION_PID_WINDOWS": "", "SANDBOXD_REPO_ROOT": ""})
    assert out.returncode == 0, out.stderr
    assert out.stdout.split()[3] == "1"
    assert out.stdout.split()[0] == "/root/drakvuf-multios-sandbox"


def test_a_non_integer_pid_stops_the_daemon_at_import_naming_the_variable():
    out = _probe({"SANDBOXD_INJECTION_PID_WINDOWS": "explorer"})
    assert out.returncode != 0
    assert "SANDBOXD_INJECTION_PID_WINDOWS='explorer' is not an integer" in out.stderr


def test_the_daemon_names_every_host_variable_for_the_generated_list():
    """`scripts/gen-current-state.py` lists what the daemon reads by grepping
    daemon.py for quoted SANDBOXD_* names; config.py is not scanned, so the
    names must appear in daemon.py or the documented list silently loses them."""
    from sandboxd import daemon as D
    text = (ROOT / "sandboxd" / "daemon.py").read_text()
    for var in ("SANDBOXD_REPO_ROOT", "SANDBOXD_ANALYSIS_USERNAME",
                "SANDBOXD_INJECTION_PID_UBUNTU", "SANDBOXD_INJECTION_PID_WINDOWS",
                "SANDBOXD_INJECTION_PID_ANDROID"):
        assert var in D.HOST_VALUE_VARS
        assert f'"{var}"' in text