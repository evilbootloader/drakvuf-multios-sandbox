"""The UI in a real browser. Issue #38.

**These assert what `test_ui.py` structurally cannot.** That file reads the
HTML *source* and checks `<script>` came out as `&lt;script&gt;` -- which is a
statement about bytes. It cannot tell you whether a browser executed anything,
because there is no browser in it.

The property that actually matters is: *a hostile filename does not run.* Only
an engine that parses HTML the way a browser does can answer that, and the two
differ in exactly the cases attackers use -- mXSS, parser quirks, an escape
that is correct in one context and inert in another.

So this file drives Chromium, registers a listener that fails the test if any
dialog opens or any script runs, and then loads pages whose data is hostile.

Requires a browser: `playwright install chromium`. Skipped loudly without one,
because a skipped run leaves the execution question **unanswered** rather than
answered in the affirmative.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

import psycopg
import pytest

pytest.importorskip(
    "playwright.sync_api",
    reason="playwright is not installed; browser-level XSS execution is UNVERIFIED",
)

PLATFORM_DIR = Path(__file__).resolve().parent.parent
DSN = os.environ.get("TEST_DATABASE_URL", "postgresql:///sandbox_platform_test")

# Names that are ADMITTED at submission (test_jobs_api.py) and must render
# inert. The unclosed tags are the interesting ones: they carry no `/`, so
# they survive the sample-filename separator rule, and an unterminated tag
# swallows the markup that follows it -- which is how a name breaks out of a
# template even where closing tags are filtered.
HOSTILE = [
    "<script>alert(1)",
    '"><script>alert(1)',
    "<img src=x onerror=alert(1)>.exe",
    "<!--",
    "</title><script>alert(1)",
    "<svg/onload=alert(1)>",
    "‮exe.txt",
]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server():
    """A real uvicorn, because TestClient is not something a browser can load."""
    port = _free_port()
    env = {
        **os.environ,
        "DATABASE_URL": DSN,
        "WORKER_TOKEN": "browser-test",
        "MAINTENANCE_INTERVAL": "0",
        "S3_INTERNAL_ENDPOINT": os.environ.get(
            "S3_INTERNAL_ENDPOINT", "http://127.0.0.1:9000"),
        "S3_PUBLIC_ENDPOINT": os.environ.get(
            "S3_PUBLIC_ENDPOINT", "http://localhost:9000"),
        "S3_ACCESS_KEY": os.environ.get("S3_ACCESS_KEY", "devroot"),
        "S3_SECRET_KEY": os.environ.get("S3_SECRET_KEY", "devrootpass"),
        "S3_BUCKET": os.environ.get("S3_BUCKET", "analysis"),
        "S3_REGION": os.environ.get("S3_REGION", "eu-central-1"),
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "sandbox_platform.app:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=str(PLATFORM_DIR), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        import httpx
        for _ in range(100):
            try:
                if httpx.get(f"{base}/healthz", timeout=1).status_code == 200:
                    break
            except Exception:
                time.sleep(0.1)
        else:
            pytest.fail("the UI server never became ready")
        yield base
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture
def seed():
    """Insert a job directly, returning its id. Its own connection, because
    the server is a separate process and must see committed rows."""
    made: list[uuid.UUID] = []

    def _seed(filename: str, *, target_os: str = "ubuntu",
              state: str = "completed") -> uuid.UUID:
        with psycopg.connect(DSN, autocommit=True) as c:
            row = c.execute(
                "INSERT INTO jobs (target_os, submitted_filename, state,"
                "                  sha256, size_bytes, detected_type)"
                " VALUES (%s, %s, %s, 'af9c4ea0', 19, 'ASCII text')"
                " RETURNING id",
                (target_os, filename, state),
            ).fetchone()[0]
        made.append(row)
        return row

    yield _seed


@pytest.fixture
def strict_page(page):
    """A page that fails the test if anything executes.

    Three traps, because a payload can fire through any of them:
    `alert`/`confirm`/`prompt` surface as dialogs; a thrown error shows as a
    page error; and a payload that succeeds silently is caught by the
    `__xss` flag it would have to set.
    """
    fired: list[str] = []
    page.on("dialog", lambda d: (fired.append(f"dialog: {d.message}"), d.dismiss()))
    page.on("pageerror", lambda e: fired.append(f"pageerror: {e}"))
    page.add_init_script("window.__xss = false; window.alert = function(){ window.__xss = true; };")
    page.fired = fired
    return page


# --- the property test_ui.py cannot state ----------------------------------

@pytest.mark.parametrize("name", HOSTILE)
def test_a_hostile_filename_does_not_execute(strict_page, server, seed, name):
    """Rendered by a real HTML parser, and nothing runs."""
    job_id = seed(name)

    strict_page.goto(f"{server}/ui/jobs/{job_id}")

    assert strict_page.fired == [], strict_page.fired
    assert strict_page.evaluate("window.__xss") is False
    # No element was created from the payload -- it is text, not markup.
    assert strict_page.locator("script:not([src])").count() == 0
    assert strict_page.locator("img[onerror], svg[onload]").count() == 0


@pytest.mark.parametrize("name", HOSTILE)
def test_the_name_is_visible_exactly_as_submitted(strict_page, server, seed, name):
    """Inert is only half of it. The name must also still BE the name.

    A UI that stripped the payload would pass the execution test above and
    quietly destroy evidence: DRAFT-030 keeps the submitted name byte-exact
    because extension dispatch and argv[0] self-checks are real evasion
    surface, and the report has to show what was actually run.
    """
    job_id = seed(name)

    strict_page.goto(f"{server}/ui/jobs/{job_id}")

    assert name in strict_page.locator("h2.filename").inner_text()


def test_a_hostile_name_is_inert_in_the_history(strict_page, server, seed):
    """The list view renders the same data and is a separate escaping context
    -- an escaping bug that holds on one page and not the other is the shape
    most such bugs take."""
    for name in HOSTILE:
        seed(name)

    strict_page.goto(f"{server}/ui/jobs")

    assert strict_page.fired == [], strict_page.fired
    assert strict_page.evaluate("window.__xss") is False


# --- the shell behaves like a shell ----------------------------------------

def test_tabs_switch_without_a_page_load(strict_page, server, seed):
    """htmx swaps the tab body in place. If it fell back to a full navigation
    the page would still work, so this asserts the mechanism rather than the
    outcome -- otherwise a broken htmx would pass unnoticed."""
    job_id = seed("sample.bin")
    strict_page.goto(f"{server}/ui/jobs/{job_id}")
    strict_page.evaluate("window.__marker = 'still here'")

    strict_page.get_by_role("link", name="Artifacts").click()
    strict_page.wait_for_selector("#tab-body")

    assert strict_page.evaluate("window.__marker") == "still here"
    assert strict_page.fired == [], strict_page.fired


def test_ubuntu_offers_no_registry_tab(strict_page, server, seed):
    """regmon is Windows-only, so the tab could never be filled."""
    job_id = seed("sample.bin", target_os="ubuntu")

    strict_page.goto(f"{server}/ui/jobs/{job_id}")

    assert strict_page.get_by_role("link", name="Registry").count() == 0
    assert strict_page.get_by_role("link", name="Behaviour").count() == 1


def _open_advanced(page):
    """The picker lives behind a collapsed <details>, deliberately: defaults
    are one click and an unusual selection is a deliberate act. Every test
    touching it has to open it first, which is itself the assertion that it
    starts closed."""
    page.get_by_text("Advanced").click()
    page.wait_for_selector("#plugin-picker table", state="visible")


def test_the_picker_starts_collapsed(strict_page, server):
    """Defaults are applied automatically; changing them is opt-in."""
    strict_page.goto(f"{server}/ui/submit")
    assert strict_page.locator("#plugin-picker table").is_visible() is False


def test_windows_offers_no_plugin_marked_proven(strict_page, server):
    """Windows has no execution evidence in this project at all, so the form
    must not claim any. Checked in the browser as well as in the HTML because
    this is what a person actually reads."""
    strict_page.goto(f"{server}/ui/submit")
    _open_advanced(strict_page)
    strict_page.get_by_role("radio", name="windows").check()
    # Wait on the data marker, not on a plugin name: unsupported plugins are
    # listed by name too, so `regmon` is already present in the Ubuntu picker
    # and the wait would return before the swap happened.
    strict_page.wait_for_selector('#plugin-picker [data-os="windows"]')

    body = strict_page.locator("#plugin-picker").inner_text()
    assert "proven" not in body
    assert "candidate" in body


def test_switching_os_reloads_the_catalogue(strict_page, server):
    """The picker is per-OS, so changing the target must change the list --
    Windows gains regmon and tlsmon, Ubuntu gains ptracemon and ebpfmon."""
    strict_page.goto(f"{server}/ui/submit")
    _open_advanced(strict_page)

    strict_page.get_by_role("radio", name="windows").check()
    # Wait on the data marker, not on a plugin name: unsupported plugins are
    # listed by name too, so `regmon` is already present in the Ubuntu picker
    # and the wait would return before the swap happened.
    strict_page.wait_for_selector('#plugin-picker [data-os="windows"]')
    win = strict_page.locator("#plugin-picker").inner_text()

    strict_page.get_by_role("radio", name="ubuntu").check()
    strict_page.wait_for_selector('#plugin-picker [data-os="ubuntu"]')
    ubu = strict_page.locator("#plugin-picker").inner_text()

    assert "tlsmon" in win and "ptracemon" in ubu
    assert win != ubu


def test_a_queued_job_does_not_look_like_a_failure(strict_page, server, seed):
    """The measured failure mode this architecture exists to remove was a
    silent hold with correct-looking logs. Rendering a normal wait in the
    failure colour would be the same mistake wearing the opposite coat."""
    job_id = seed("waiting.bin", state="queued")

    strict_page.goto(f"{server}/ui/jobs/{job_id}")

    colour = strict_page.locator(".state").evaluate(
        "el => getComputedStyle(el).color")
    danger = strict_page.evaluate(
        "getComputedStyle(document.documentElement).getPropertyValue('--red').trim()")
    assert danger not in colour
    assert "Waiting" in strict_page.locator(".note").first.inner_text()

# --- submission, driven by a browser ---------------------------------------
#
# The only test in this project that exercises the submit form the way a
# person does: reserve, upload straight to the object store, admit. submit.js
# is hand-written -- it is the one place Jinja's autoescaping does not cover --
# so it needs a test that runs it rather than reads it.

# The upload leg needs the DEV MinIO to allow this page's origin:
#
#     mc admin config set local api cors_allow_origin='*'
#
# **Production needs no such thing.** #37 path-routes the store at /analysis
# on the API's own hostname, so the browser upload is same-origin and no
# preflight happens. Here the test server binds a random port and MinIO is on
# 9000, which is genuinely cross-origin -- an artefact of the test rig, not of
# the design. Without it these three tests fail with the browser's bare
# "Failed to fetch", which is exactly the confusion submit.js now translates.


def _upload(page, server, name: str, body: bytes = b"\x7fELF" + b"\x00" * 60):
    page.goto(f"{server}/ui/submit")
    page.set_input_files("input[type=file]", {
        "name": name, "mimeType": "application/octet-stream", "buffer": body,
    })
    page.get_by_role("button", name="Submit").click()


def test_submitting_with_no_worker_says_so_plainly(strict_page, server):
    """`no_workers` is the honest answer on a fresh install, and it is not the
    same problem as `no_capacity`.

    Collapsing either into "submission failed" costs an operator an hour
    working out which of two unrelated things is wrong -- one needs sandboxd
    started, the other needs a bigger host.
    """
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("TRUNCATE workers, worker_pipelines CASCADE")

    _upload(strict_page, server, "hello.bin")

    # #result, not .note.danger -- the page already carries a danger note
    # warning that the upload will be detonated, so a bare selector matches
    # before the flow has done anything.
    strict_page.wait_for_selector("#result .note.danger", timeout=20000)
    assert "No analysis host has registered" in \
        strict_page.locator("#result .note").inner_text()
    assert strict_page.fired == [], strict_page.fired


def test_a_full_submission_reaches_the_job_view(strict_page, server):
    """Reserve, upload to MinIO, admit, redirect -- all in the browser.

    The upload leg does not pass through the API at all: the browser POSTs
    straight to the object store under a signed policy. That is the property
    the whole architecture rests on, and this is the only place it is proven
    from a browser rather than from Python.
    """
    import httpx
    httpx.post(f"{server}/api/v1/worker/register",
               headers={"Authorization": "Bearer browser-test",
                        "X-Worker-Id": "browser-worker"},
               json={"worker_id": "browser-worker", "total_mib": 12082,
                     "total_vlans": 8, "total_slots": 2,
                     "pipelines": [{"os": "ubuntu", "required_mib": 2198}]},
               timeout=10)

    _upload(strict_page, server, "hello.bin")

    strict_page.wait_for_url("**/ui/jobs/**", timeout=20000)
    assert strict_page.locator("h2.filename").inner_text() == "hello.bin"
    assert strict_page.locator(".state").first.inner_text() == "queued"
    assert strict_page.fired == [], strict_page.fired


def test_a_filename_the_api_refuses_is_reported_verbatim(strict_page, server):
    """A separator is refused at submission because the name becomes the guest
    staging path. The reason has to reach the page: "invalid" would send
    someone hunting the wrong thing."""
    _upload(strict_page, server, "a/b.bin")

    strict_page.wait_for_selector("#result .note.danger", timeout=20000)
    assert "path separator" in strict_page.locator("#result .note").inner_text()


# --- the form, driven as a person drives it --------------------------------

def test_searching_with_every_filter_on_any_works(strict_page, server, seed):
    """The test that would have caught the 422.

    An HTML <select> on "any" submits `state=` — present and empty — and
    FastAPI refused to parse "" into the enum, so the UNFILTERED search was the
    one case that broke. Reported from the deployment 2026-08-25.

    The source-level tests missed it because they passed either a real value or
    nothing at all. Only submitting the actual form sends an empty one.
    """
    seed("hello.bin")

    strict_page.goto(f"{server}/ui/jobs")
    strict_page.get_by_role("button", name="Search").click()
    strict_page.wait_for_url("**/ui/jobs?**")

    assert "hello.bin" in strict_page.locator("body").inner_text()
    assert "Input should be" not in strict_page.locator("body").inner_text()
    assert strict_page.fired == [], strict_page.fired


def test_searching_with_a_filter_selected_works(strict_page, server, seed):
    seed("linux.bin", target_os="ubuntu")
    seed("win.exe", target_os="windows")

    strict_page.goto(f"{server}/ui/jobs")
    strict_page.select_option("select[name=target_os]", "windows")
    strict_page.get_by_role("button", name="Search").click()
    strict_page.wait_for_url("**target_os=windows**")

    body = strict_page.locator("body").inner_text()
    assert "win.exe" in body and "linux.bin" not in body


# --- the theme toggle ------------------------------------------------------

def _bg(page):
    return page.evaluate("getComputedStyle(document.body).backgroundColor")


def test_the_toggle_forces_light_on_a_dark_system(strict_page, server):
    """The direction that did not work at first.

    The media query alone cannot force light on a dark system, so a toggle
    without an explicit `[data-theme="light"]` rule works one way only — dark
    users could never reach light.
    """
    strict_page.emulate_media(color_scheme="dark")
    strict_page.goto(f"{server}/ui/jobs")
    dark = _bg(strict_page)

    strict_page.click("#theme-toggle")          # auto -> dark
    strict_page.click("#theme-toggle")          # dark -> light

    assert strict_page.locator("html").get_attribute("data-theme") == "light"
    assert _bg(strict_page) != dark


def test_the_toggle_forces_dark_on_a_light_system(strict_page, server):
    strict_page.emulate_media(color_scheme="light")
    strict_page.goto(f"{server}/ui/jobs")
    light = _bg(strict_page)

    strict_page.click("#theme-toggle")          # auto -> dark

    assert strict_page.locator("html").get_attribute("data-theme") == "dark"
    assert _bg(strict_page) != light


def test_the_choice_survives_navigation(strict_page, server, seed):
    """Stored, and applied before the first paint — otherwise every page load
    flashes the wrong theme."""
    seed("x.bin")
    strict_page.emulate_media(color_scheme="dark")
    strict_page.goto(f"{server}/ui/jobs")
    strict_page.click("#theme-toggle")
    strict_page.click("#theme-toggle")          # light

    strict_page.goto(f"{server}/ui/submit")

    assert strict_page.locator("html").get_attribute("data-theme") == "light"


def test_the_third_click_returns_to_following_the_system(strict_page, server):
    """Three states, not two. `auto` is not the same as whichever the system
    currently is — it keeps following when the system changes."""
    strict_page.goto(f"{server}/ui/jobs")

    for _ in range(3):
        strict_page.click("#theme-toggle")

    assert strict_page.locator("html").get_attribute("data-theme") is None
    assert strict_page.locator("#theme-toggle").inner_text() == "auto"
