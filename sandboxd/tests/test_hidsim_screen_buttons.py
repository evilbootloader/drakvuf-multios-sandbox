"""hidsim's `--hid-monitor-gui` on a guest whose windows cannot be walked:
which word of a screen is a button to press (`drakvuf/src/plugins/hidsim/gui/
screen_buttons.cpp`, our fork's).

That file's own test is C++ and needs neither DRAKVUF nor the OCR library, so
it is compiled and run here: DRAKVUF's build has no test target, and a test
nothing runs is not one. Skipped, loudly, where there is no compiler or the
submodule is not checked out.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

GUI = Path(__file__).resolve().parents[2] / "drakvuf" / "src" / "plugins" / "hidsim" / "gui"


def test_the_button_chooser_passes_its_own_test(tmp_path):
    compiler = shutil.which("g++") or shutil.which("clang++")
    if compiler is None:
        pytest.skip("no C++ compiler: screen_buttons_test.cpp was not run")
    if not (GUI / "screen_buttons_test.cpp").is_file():
        pytest.skip("the drakvuf submodule is not checked out: screen_buttons_test.cpp was not run")
    binary = tmp_path / "screen_buttons_test"
    subprocess.run([compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                    str(GUI / "screen_buttons.cpp"), str(GUI / "screen_buttons_test.cpp"), "-o", str(binary)],
                   check=True, capture_output=True, text=True)
    ran = subprocess.run([str(binary)], cwd=tmp_path, capture_output=True, text=True)
    assert ran.returncode == 0, ran.stderr
    assert ran.stdout.strip() == "ok"


def test_the_build_finds_the_ocr_library_and_make_installs_it():
    """Without tesseract the plugin builds and presses nothing, which nothing
    would notice: `make sandboxd` installs it before it configures DRAKVUF."""
    root = GUI.parents[4]
    makefile = (root / "Makefile").read_text()
    install, setup = makefile.index("libtesseract-dev tesseract-ocr-eng"), makefile.index("meson setup build")
    assert install < setup
    meson = GUI.parents[1] / "meson.build"
    if not meson.is_file():
        pytest.skip("the drakvuf submodule is not checked out")
    text = meson.read_text()
    assert "hidsim/gui/screen_buttons.cpp" in text and "config_h.set('HAVE_TESSERACT', 1)" in text
