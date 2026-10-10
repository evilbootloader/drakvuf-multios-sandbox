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
from conftest import owner_id
from sandbox_platform.credentials import hash_refresh_token
import pytest

pytest.importorskip(
    "playwright.sync_api",
    reason="playwright is not installed; browser-level XSS execution is UNVERIFIED",
)

PLATFORM_DIR = Path(__file__).resolve().parent.parent
DSN = os.environ.get("TEST_DATABASE_URL", "postgresql:///sandbox_platform_test")

# Must match the override in `_browser_app.py`: that process authenticates
# as this address, so a job seeded for anyone else is invisible to it.
BROWSER_OWNER = "fixture-owner@example.test"

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
        "S3_ACCESS_KEY": os.environ.get("S3_ACCESS_KEY", "devrootkey"),
        "S3_SECRET_KEY": os.environ.get("S3_SECRET_KEY", "devrootpassphrase"),
        "S3_BUCKET": os.environ.get("S3_BUCKET", "analysis"),
        "S3_REGION": os.environ.get("S3_REGION", "eu-central-1"),
    }
    # `tests/_browser_app.py`, not `sandbox_platform.app` -- see that module.
    # It is the same app with the identity dependency overridden, because a
    # browser cannot present an Access token and every submission would
    # otherwise be a 403.
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "_browser_app:app",
         "--app-dir", str(PLATFORM_DIR / "tests"),
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
            # Resolved rather than spelled out: `owner` is a tenant id since
            # 0009, and this connection is the browser server's own -- the
            # identity may not have been created by anything else yet.
            row = c.execute(
                "INSERT INTO jobs (target_os, submitted_filename, state,"
                "                  sha256, size_bytes, detected_type, owner)"
                " VALUES (%s, %s, %s, 'af9c4ea0', 19, 'ASCII text', %s)"
                " RETURNING id",
                (target_os, filename, state, owner_id(c, BROWSER_OWNER)),
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


"""
def test_windows_offers_no_plugin_marked_proven(strict_page, server):
    """"""Windows has no execution evidence in this project at all, so the form
    must not claim any. Checked in the browser as well as in the HTML because
    this is what a person actually reads.""""""
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
"""

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

    # Provisioned first: the platform resolves the worker id from the token's
    # hash (DRAFT-061), so a `register` with an unknown credential is a 401
    # rather than a worker bringing itself into existence.
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(
            """
            INSERT INTO workers (worker_id, total_mib, total_vlans,
                                 total_slots, token_hash)
            VALUES ('browser-worker', 1, 1, 1, %s)
            ON CONFLICT (worker_id) DO UPDATE SET token_hash = EXCLUDED.token_hash
            """,
            (hash_refresh_token("browser-test"),),
        )

    httpx.post(f"{server}/api/v1/worker/register",
               headers={"Authorization": "Bearer browser-test"},
               json={"total_mib": 12082,
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


# --- live status: the page follows the job ---------------------------------
#
# The SSE endpoint has been correct and tested since #36. What was missing was
# a subscriber, so a job page was a snapshot from the moment it rendered --
# observed against fake_worker 2026-08-25, where the worker walked the whole
# state machine and the page sat on `queued`.
#
# These drive the state directly rather than through fake_worker: migration
# 0002's trigger fires on any UPDATE, so this is the same NOTIFY a real worker
# produces, without a second process to sequence.

def _advance(job_id, state: str) -> None:
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("UPDATE jobs SET state = %s WHERE id = %s", (state, job_id))


def test_the_page_follows_the_job_without_a_reload(strict_page, server, seed):
    """The bug, stated as a test: the state on screen tracks the database.

    The marker is what makes it a test of the mechanism rather than of the
    outcome. A page that reloaded itself on a timer would show the right state
    too, and would lose scroll position, the active tab and any open detail
    every time a job moved.
    """
    job_id = seed("sample.bin", state="queued")
    strict_page.goto(f"{server}/ui/jobs/{job_id}")
    strict_page.wait_for_selector("span.state[data-state='queued']")
    strict_page.evaluate("window.__marker = 'no reload'")

    _advance(job_id, "executing")

    strict_page.wait_for_selector("span.state[data-state='executing']", timeout=10_000)
    assert strict_page.evaluate("window.__marker") == "no reload"
    assert strict_page.fired == [], strict_page.fired


def test_the_wait_note_disappears_when_the_wait_does(strict_page, server, seed):
    """`queued` renders an explanatory note, and a stale one is worse than
    none: "waiting for an analysis host" under a running job describes a
    system that is not doing what it says."""
    job_id = seed("sample.bin", state="queued")
    strict_page.goto(f"{server}/ui/jobs/{job_id}")
    assert "Waiting" in strict_page.locator("p.note").inner_text()

    _advance(job_id, "executing")

    strict_page.wait_for_selector("span.state[data-state='executing']", timeout=10_000)
    assert strict_page.locator("p.note").count() == 0


def test_the_tab_you_are_reading_survives_a_state_change(strict_page, server, seed):
    """A refresh must not throw you back to Overview.

    The active tab lives in the DOM, not the URL: an htmx tab click swaps
    content without navigating, so the address bar alone cannot say what you
    are looking at.
    """
    job_id = seed("sample.bin", state="queued")
    strict_page.goto(f"{server}/ui/jobs/{job_id}")
    strict_page.get_by_role("link", name="Artifacts").click()
    strict_page.wait_for_selector("nav.tabs[data-active='artifacts']")

    _advance(job_id, "executing")

    strict_page.wait_for_selector("span.state[data-state='executing']", timeout=10_000)
    assert strict_page.locator("nav.tabs").get_attribute("data-active") == "artifacts"


def test_the_tab_bar_still_works_after_an_update(strict_page, server, seed):
    """htmx only wires nodes it has processed, and an SSE refresh replaces the
    tab bar with markup htmx has never seen. Without htmx.process the page
    updates exactly once and every tab link then falls back to a full
    navigation -- which still 'works', which is why it needs a test."""
    job_id = seed("sample.bin", state="queued")
    strict_page.goto(f"{server}/ui/jobs/{job_id}")

    _advance(job_id, "executing")
    strict_page.wait_for_selector("span.state[data-state='executing']", timeout=10_000)

    strict_page.evaluate("window.__marker = 'still here'")
    strict_page.get_by_role("link", name="Artifacts").click()
    strict_page.wait_for_selector("nav.tabs[data-active='artifacts']")

    assert strict_page.evaluate("window.__marker") == "still here"


def test_a_finished_job_does_not_reconnect_forever(strict_page, server, seed):
    """The server ENDS the stream on a terminal state, and EventSource's
    response to a closed stream is to reconnect -- so a completed job would
    open a connection every few seconds for as long as the tab is open.

    Costs nothing visible, which is exactly why it would have survived
    review: one idle browser tab quietly holding a database LISTEN and a
    worker slot's worth of connections.
    """
    seen: list[str] = []
    strict_page.on("request", lambda r: seen.append(r.url) if "/events" in r.url else None)

    job_id = seed("done.bin", state="completed")
    strict_page.goto(f"{server}/ui/jobs/{job_id}")
    strict_page.wait_for_timeout(6_000)   # two default retry windows

    assert len(seen) == 1, seen


def test_clicking_a_tab_moves_the_underline(strict_page, server, seed):
    """Pre-existing, found while wiring the live refresh: the tab nav is a
    SIBLING of the tab body, so swapping only the body could never move
    aria-selected. Clicking Artifacts changed the content and left the
    underline on Overview."""
    job_id = seed("sample.bin")
    strict_page.goto(f"{server}/ui/jobs/{job_id}")
    assert strict_page.locator("nav.tabs a[aria-selected='true']").inner_text() == "Overview"

    strict_page.get_by_role("link", name="Artifacts").click()
    strict_page.wait_for_selector("nav.tabs[data-active='artifacts']")

    assert strict_page.locator("nav.tabs a[aria-selected='true']").inner_text() == "Artifacts"


# --- the live console's region survives a tab click ------------------------
#
# DRAFT-056 puts the console ABOVE the tabs precisely so it is not lost on
# every tab change -- "the opposite of what an interactive session needs:
# watch the screen while reading the syscall stream".
#
# The first implementation put it above the tabs but INSIDE the element tab
# clicks replace, which has the same fault: clicking a tab would destroy the
# console div, killing the WebSocket and the canvas mid-session. Caught in
# review before it shipped.

def test_a_tab_click_does_not_destroy_the_status_region(strict_page, server, seed):
    """The console lives in #job-status. Proving that region survives a tab
    click proves an open session survives one.

    Tested by identity, not by presence: a re-rendered element looks identical
    in the DOM but is a different node, and a WebSocket attached to the old one
    is gone. So the test marks the node and checks the MARK survives.
    """
    job_id = seed("sample.bin")
    strict_page.goto(f"{server}/ui/jobs/{job_id}")
    strict_page.wait_for_selector("#job-status")
    strict_page.evaluate(
        "document.getElementById('job-status').__session = 'live socket here'")

    strict_page.get_by_role("link", name="Artifacts").click()
    strict_page.wait_for_selector("nav.tabs[data-active='artifacts']")

    survived = strict_page.evaluate(
        "document.getElementById('job-status').__session")
    assert survived == "live socket here", (
        "the status region was re-rendered by a tab click; a live console "
        "session in it would have been destroyed"
    )


def test_a_tab_click_does_re_render_the_tab_bar(strict_page, server, seed):
    """The other half. The nav must be inside the swapped region or
    aria-selected cannot move -- which was the original underline bug."""
    job_id = seed("sample.bin")
    strict_page.goto(f"{server}/ui/jobs/{job_id}")
    # The NAV, not its container. htmx's default swap is `innerHTML`, so
    # #job-tabs itself persists and only its children are replaced -- marking
    # the container would prove nothing, which is what a first version of this
    # test did.
    strict_page.evaluate("document.querySelector('nav.tabs').__marker = 'original'")

    strict_page.get_by_role("link", name="Artifacts").click()
    strict_page.wait_for_selector("nav.tabs[data-active='artifacts']")

    assert strict_page.evaluate(
        "document.querySelector('nav.tabs').__marker") is None, (
        "the nav was not re-rendered, so aria-selected could not have moved")
    assert strict_page.locator(
        "nav.tabs a[aria-selected='true']").inner_text() == "Artifacts"


# --- the masthead balance follows the charge -------------------------------
#
# Reported from the deployment 2026-09-15, runbook 17 step 12: a job ran to
# completion under the operator's eye, the seconds were drawn down in the
# database, and the number in the masthead did not move until F5. `balance.js`
# fetched once on DOMContentLoaded and nothing called it again.
#
# These spend the balance directly rather than through a worker report, for
# the reason `_advance` exists: the charge and the transition commit together
# in `_charge_for_runtime`, so writing both here is the same pair of facts a
# real run presents, without a second process to sequence.

def _spend(seconds: int) -> None:
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute(
            "UPDATE tenants SET balance_seconds = balance_seconds - %s"
            " WHERE owner = %s",
            (seconds, owner_id(c, BROWSER_OWNER)),
        )


def _quiesce(keep) -> None:
    """Finish every OTHER job in the database.

    The history page is not scoped to one test. Jobs seeded and advanced by
    everything above are still here and still `executing`, and one of them on
    page 1 is enough to keep the list live forever -- so a poll test would be
    asserting against somebody else's liveness rather than its own.
    """
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("UPDATE jobs SET state = 'completed'"
                  " WHERE id <> %s AND state <> 'completed'", (keep,))


def _balance_settles(page) -> str:
    """The masthead balance, once it has arrived.

    It is fetched, not rendered, so the element exists empty for as long as
    the round trip takes -- reading it too early yields "" and every later
    comparison against that passes for the wrong reason.
    """
    page.wait_for_function(
        "() => document.getElementById('balance').textContent !== ''",
        timeout=10_000)
    return page.locator("#balance").inner_text()


def test_the_balance_follows_a_job_finishing_under_the_reader(
        strict_page, server, seed):
    """The bug, stated as a test. A balance that only moves on reload is the
    same fault the live status region was built to remove, one element to the
    left of it."""
    job_id = seed("slow.bin", state="executing")
    strict_page.goto(f"{server}/ui/jobs/{job_id}")
    # Also what creates the tenant row: the balance route upserts on first
    # contact, so _spend has nothing to update until this has been answered.
    before = _balance_settles(strict_page)

    _spend(120)
    _advance(job_id, "completed")

    strict_page.wait_for_function(
        "t => document.getElementById('balance').textContent !== t",
        arg=before, timeout=10_000)
    assert strict_page.locator("#balance").inner_text() != before
    assert strict_page.fired == [], strict_page.fired


def test_the_balance_does_not_refetch_on_an_already_finished_job(
        strict_page, server, seed):
    """The first SSE frame is a snapshot. Opening a finished job would
    otherwise fetch the balance twice on load -- the second time to learn the
    same number, because the charge was in it before the page rendered."""
    seen: list[str] = []
    strict_page.on("request",
                   lambda r: seen.append(r.url) if "/account/balance" in r.url else None)

    job_id = seed("done.bin", state="completed")
    strict_page.goto(f"{server}/ui/jobs/{job_id}")
    _balance_settles(strict_page)
    strict_page.wait_for_timeout(2_000)

    assert len(seen) == 1, seen


def test_the_balance_follows_the_history_poll(strict_page, server, seed):
    """The history page has no SSE -- the NOTIFY channel is per job id, so the
    list polls. The swap is the signal there, and it is self-limiting: the poll
    runs only while a row can still change."""
    job_id = seed("slow.bin", state="executing")
    _quiesce(job_id)
    strict_page.goto(f"{server}/ui/jobs")
    before = _balance_settles(strict_page)

    _spend(90)
    _advance(job_id, "completed")

    strict_page.wait_for_function(
        "t => document.getElementById('balance').textContent !== t",
        arg=before, timeout=15_000)
    assert strict_page.fired == [], strict_page.fired


def test_the_history_poll_stops_when_the_last_job_finishes(
        strict_page, server, seed):
    """`data-live` lived on the #jobs-table wrapper, which `hx-swap="innerHTML"`
    never replaces -- so the trigger filter re-read the value from first render
    every five seconds and a page that once had a running job polled for the
    life of the tab. Costs nothing visible, like the EventSource reconnect
    above, which is exactly why it survived.

    Carried by the fragment, the server's answer reaches the filter. This also
    bounds the balance refetch hung off the same swap.
    """
    seen: list[str] = []
    strict_page.on("request",
                   lambda r: seen.append(r.url) if "/ui/jobs/table" in r.url else None)

    job_id = seed("slow.bin", state="executing")
    _quiesce(job_id)
    strict_page.goto(f"{server}/ui/jobs")
    strict_page.wait_for_selector("[data-live='1']")

    _advance(job_id, "completed")
    strict_page.wait_for_selector("[data-live='0']", timeout=15_000)

    settled = len(seen)
    strict_page.wait_for_timeout(11_000)      # two poll intervals, and a margin

    assert len(seen) == settled, seen[settled:]


# --- the report tabs: sample-chosen text inside inline SVG -------------------

def _seed_report(job_id: uuid.UUID, doc: dict) -> None:
    """Put a report.json behind an existing job: manifest row plus object."""
    import hashlib
    import json

    import boto3
    from botocore.config import Config

    from sandbox_platform import report as report_store

    raw = json.dumps(doc).encode()
    manifest = {"schema_version": 1, "truncated": False, "documents": [],
                "artifacts": [{"name": "report.json", "size_bytes": len(raw),
                               "sha256": hashlib.sha256(raw).hexdigest()}]}
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("UPDATE jobs SET manifest = %s WHERE id = %s",
                  (json.dumps(manifest), job_id))
    s3 = boto3.client(
        "s3",
        endpoint_url=os.environ.get("S3_INTERNAL_ENDPOINT", "http://127.0.0.1:9000"),
        aws_access_key_id=os.environ.get("S3_ACCESS_KEY", "devrootkey"),
        aws_secret_access_key=os.environ.get("S3_SECRET_KEY", "devrootpassphrase"),
        region_name=os.environ.get("S3_REGION", "eu-central-1"),
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}))
    s3.put_object(Bucket=os.environ.get("S3_BUCKET", "analysis"),
                  Key=f"results/{job_id}/report.json", Body=raw)
    # The server is another process with its own cache, keyed by digest, so
    # a fresh document is a fresh entry; this clears ours for symmetry.
    report_store._load.cache_clear()


@pytest.mark.parametrize("name", HOSTILE)
def test_hostile_report_text_does_not_execute(strict_page, server, seed, name):
    """The report's process names, command lines and paths are the sample's,
    and the Behaviour tab draws them inside inline SVG as well as HTML --
    `<svg/onload=...>` inside an `<svg>` is the case a source-level grep for
    `| safe` cannot speak to. Rendered by a real parser, nothing runs, and the
    text is still visible as text."""
    job_id = seed("x.exe", target_os="windows")
    from test_report import sample_report
    doc = sample_report()
    doc["processes"][4]["name"] = name
    doc["processes"][4]["args"] = [name]
    doc["modified_files"][0]["filename"] = name
    doc["ttps"][0]["name"] = name
    _seed_report(job_id, doc)

    for tab in ("overview", "behaviour", "network", "memory"):
        strict_page.goto(f"{server}/ui/jobs/{job_id}?tab={tab}")
        assert strict_page.fired == [], (tab, strict_page.fired)
        assert strict_page.evaluate("window.__xss") is False
        assert strict_page.locator("script:not([src])").count() == 0
        assert strict_page.locator("img[onerror], svg[onload]").count() == 0

    strict_page.goto(f"{server}/ui/jobs/{job_id}?tab=behaviour")
    # The tree shows the basename (a `/` in the payload splits it, as it
    # would any path) and carries the full name on the title, byte-exact.
    pname = strict_page.locator("li#proc-4 .pname").first
    assert pname.get_attribute("title") == name
    assert pname.inner_text() == name.replace("\\", "/").rsplit("/", 1)[-1]
    assert name in strict_page.locator("li#proc-4 .cmd").first.get_attribute("title")
    # The diagram's box for the sample carries the same name as SVG text and
    # links to the tree node, never to anything the sample named.
    box = strict_page.locator("svg.pdiagram a[href='#proc-4']").first
    assert box.locator("g.pnode[data-sample]").count() == 1
    assert name in box.locator("title").first.text_content()
